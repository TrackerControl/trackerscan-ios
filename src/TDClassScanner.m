#import "TDClassScanner.h"
#import "LSApplicationProxy+AltList.h"

#import <dlfcn.h>
#import <spawn.h>
#import <signal.h>
#import <unistd.h>
#import <fcntl.h>
#import <errno.h>
#import <sys/wait.h>
#import <sys/stat.h>
#import <sys/mman.h>
#import <mach/mach.h>
#import <mach/task_info.h>
#import <mach/vm_region.h>
#import <mach/exception_types.h>
#import <mach/thread_status.h>
#import <mach-o/dyld_images.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <libkern/OSByteOrder.h>

// mach_vm.h is marked "unsupported" in the iOS SDK; redeclare the syscalls
// we need. These are available at runtime on every iOS version we target.
typedef uint64_t mach_vm_address_t;
typedef uint64_t mach_vm_size_t;
extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task,
                                            mach_vm_address_t address,
                                            mach_vm_size_t size,
                                            mach_vm_address_t data,
                                            mach_vm_size_t *outsize);
extern kern_return_t mach_vm_region(vm_map_t target_task,
                                    mach_vm_address_t *address,
                                    mach_vm_size_t *size,
                                    vm_region_flavor_t flavor,
                                    vm_region_info_t info,
                                    mach_msg_type_number_t *infoCnt,
                                    mach_port_t *object_name);

extern char **environ;

NSString * const TDScannerErrorDomain = @"TDScannerErrorDomain";

static NSError *tderr(TDScannerError code, NSString *fmt, ...) NS_FORMAT_FUNCTION(2, 3);
static NSError *tderr(TDScannerError code, NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *m = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    return [NSError errorWithDomain:TDScannerErrorDomain code:code
                           userInfo:@{NSLocalizedDescriptionKey: m}];
}

#pragma mark - Signatures

NSArray *TDLoadSignatures(NSString *path, NSError **err) {
    NSData *data = [NSData dataWithContentsOfFile:path options:0 error:err];
    if (!data) return nil;
    id parsed = [NSJSONSerialization JSONObjectWithData:data options:0 error:err];
    if (![parsed isKindOfClass:[NSArray class]]) {
        if (err) *err = tderr(TDScannerErrorSignaturesLoad, @"signatures.json is not a JSON array");
        return nil;
    }
    NSMutableArray *out = [NSMutableArray arrayWithCapacity:[parsed count]];
    for (NSDictionary *d in parsed) {
        if (![d isKindOfClass:[NSDictionary class]]) continue;
        NSString *name = d[@"name"];
        if (!name.length) continue;

        NSString *classRx = d[@"regex"];
        NSString *dylibRx = d[@"dylib"];
        NSString *plistRx = d[@"plist"];
        if (!classRx.length && !dylibRx.length && !plistRx.length) continue;

        NSMutableDictionary *entry = [@{
            @"id": d[@"id"] ?: @0,
            @"name": name,
        } mutableCopy];

        NSRegularExpression *(^compile)(NSString *) = ^NSRegularExpression *(NSString *pat) {
            NSError *rxerr = nil;
            return [NSRegularExpression regularExpressionWithPattern:pat options:0 error:&rxerr];
        };

        if (classRx.length) {
            NSRegularExpression *re = compile(classRx);
            if (re) entry[@"regex"] = re;
        }
        if (dylibRx.length) {
            NSRegularExpression *re = compile(dylibRx);
            if (re) entry[@"dylibRegex"] = re;
        }
        if (plistRx.length) {
            NSRegularExpression *re = compile(plistRx);
            if (re) entry[@"plistRegex"] = re;
        }

        if (!entry[@"regex"] && !entry[@"dylibRegex"] && !entry[@"plistRegex"]) continue;
        [out addObject:entry];
    }
    return out;
}

#pragma mark - App enumeration

NSArray<NSDictionary *> *TDListInstalledUserApps(void) {
    NSMutableArray *apps = [NSMutableArray array];
    NSArray<LSApplicationProxy *> *installed =
        [[LSApplicationWorkspace defaultWorkspace] atl_allInstalledApplications];
    for (LSApplicationProxy *proxy in installed) {
        if (![proxy atl_isUserApplication]) continue;
        NSString *bid = [proxy atl_bundleIdentifier];
        NSString *name = [proxy atl_nameToDisplay];
        NSString *ver = [proxy atl_shortVersionString];
        if (!bid || !name) continue;
        [apps addObject:@{@"bundleID": bid, @"name": name, @"version": ver ?: @""}];
    }
    NSSortDescriptor *s = [NSSortDescriptor sortDescriptorWithKey:@"name"
                                                        ascending:YES
                                                         selector:@selector(localizedCaseInsensitiveCompare:)];
    [apps sortUsingDescriptors:@[s]];
    return apps;
}

#pragma mark - Memory read helpers

static BOOL readTask(task_t task, mach_vm_address_t addr, void *buf, mach_vm_size_t size) {
    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, addr, size, (mach_vm_address_t)buf, &got);
    return (kr == KERN_SUCCESS && got == size);
}

static NSString *readCString(task_t task, mach_vm_address_t addr, size_t maxLen) {
    char buf[1024];
    size_t n = maxLen < sizeof(buf) ? maxLen : sizeof(buf);
    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, addr, n - 1, (mach_vm_address_t)buf, &got);
    if (kr != KERN_SUCCESS) return nil;
    buf[got] = 0;
    return [NSString stringWithUTF8String:buf];
}

#pragma mark - Per-image __objc_classname extraction (from RAM)

// Reads __TEXT,__objc_classname out of the Mach-O header mapped at `headerAddr`
// in `task`. The read goes through mach_vm_read_overwrite, the standard Mach
// memory-inspection API, targeting the suspended child's own address space —
// so whatever mapping the kernel set up for that task is what we see. The
// scanner copies only the __objc_classname strings (a few hundred KB of
// null-terminated symbol names, not code), never reconstructs the Mach-O,
// and never persists any of those bytes.
static NSSet<NSString *> *classNamesForImage(task_t task, mach_vm_address_t headerAddr) {
    struct mach_header_64 hdr;
    if (!readTask(task, headerAddr, &hdr, sizeof(hdr))) return nil;
    if (hdr.magic != MH_MAGIC_64) return nil;

    uint32_t cmdsSize = hdr.sizeofcmds;
    if (cmdsSize == 0 || cmdsSize > 1024 * 1024) return nil;
    void *cmds = malloc(cmdsSize);
    if (!readTask(task, headerAddr + sizeof(hdr), cmds, cmdsSize)) { free(cmds); return nil; }

    int64_t slide = 0;
    BOOL haveSlide = NO;
    uint8_t *p = cmds;
    uint8_t *end = (uint8_t *)cmds + cmdsSize;
    for (uint32_t i = 0; i < hdr.ncmds && p + sizeof(struct load_command) <= end; i++) {
        struct load_command *lc = (struct load_command *)p;
        if (lc->cmdsize == 0 || p + lc->cmdsize > end) break;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *sg = (struct segment_command_64 *)p;
            if (strcmp(sg->segname, SEG_TEXT) == 0) {
                slide = (int64_t)headerAddr - (int64_t)sg->vmaddr;
                haveSlide = YES;
                break;
            }
        }
        p += lc->cmdsize;
    }
    if (!haveSlide) { free(cmds); return nil; }

    NSMutableSet *names = [NSMutableSet set];
    p = cmds;
    for (uint32_t i = 0; i < hdr.ncmds && p + sizeof(struct load_command) <= end; i++) {
        struct load_command *lc = (struct load_command *)p;
        if (lc->cmdsize == 0 || p + lc->cmdsize > end) break;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *sg = (struct segment_command_64 *)p;
            struct section_64 *sects = (struct section_64 *)(sg + 1);
            for (uint32_t j = 0; j < sg->nsects; j++) {
                if (strncmp(sects[j].sectname, "__objc_classname", 16) != 0) continue;
                uint64_t size = sects[j].size;
                if (size == 0 || size > 8 * 1024 * 1024) continue;
                mach_vm_address_t sectAddr = sects[j].addr + slide;
                char *buf = malloc((size_t)size);
                if (!buf) continue;
                if (readTask(task, sectAddr, buf, size)) {
                    size_t off = 0;
                    while (off < size) {
                        size_t len = strnlen(buf + off, (size_t)size - off);
                        if (len == 0) { off++; continue; }
                        NSString *s = [[NSString alloc] initWithBytes:buf + off
                                                               length:len
                                                             encoding:NSUTF8StringEncoding];
                        if (s) [names addObject:s];
                        off += len + 1;
                    }
                }
                free(buf);
            }
        }
        p += lc->cmdsize;
    }
    free(cmds);
    return names;
}

#pragma mark - Spawn-suspended + task_for_pid

// Spawn `execPath` with POSIX_SPAWN_START_SUSPENDED and grab its task port.
// The child never gets to run a single instruction. We never call task_resume
// except briefly (with an exception-port catcher) so dyld can map frameworks;
// the task is killed before any Objective-C +load runs. This is the same
// pattern londek/ipadecrypt and the upstream TrollDecryptJB use to inspect
// an installed app's Mach-O header layout without executing its code.
static int spawnSuspended(NSString *execPath, pid_t *outPid, task_t *outTask) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);

    const char *c_exec = [execPath fileSystemRepresentation];
    char *argv[] = { (char *)c_exec, NULL };
    pid_t pid = 0;
    int rc = posix_spawn(&pid, c_exec, &fa, &attr, argv, environ);

    // Installed extension binaries sometimes ship without +x bits (iOS normally
    // launches them via ExtensionKit, which doesn't rely on the exec bit). A
    // plain posix_spawn then fails with EACCES. Bump the mode once and retry.
    if (rc == EACCES) {
        struct stat st;
        if (stat(c_exec, &st) == 0) {
            mode_t want = st.st_mode | S_IXUSR | S_IXGRP | S_IXOTH;
            if (want != st.st_mode && chmod(c_exec, want) == 0) {
                rc = posix_spawn(&pid, c_exec, &fa, &attr, argv, environ);
            }
        }
    }

    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    if (rc != 0) return rc;

    task_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        kill(pid, SIGKILL);
        int status = 0; waitpid(pid, &status, WNOHANG);
        return EPERM;
    }
    *outPid = pid;
    *outTask = task;
    return 0;
}

static void killTarget(pid_t pid, task_t task) {
    if (task != MACH_PORT_NULL) task_terminate(task);
    if (pid > 0) {
        kill(pid, SIGKILL);
        int status = 0;
        waitpid(pid, &status, WNOHANG);
    }
}

// Walk the target's VM regions looking for an MH_EXECUTE Mach-O header. For a
// suspended-at-spawn process this is the only reliable way to find the main
// executable's load address: dyld hasn't run yet, so dyld_all_image_infos is
// typically empty or incomplete.
static mach_vm_address_t findMainExecBase(task_t task) {
    mach_vm_address_t addr = 0;
    for (;;) {
        mach_vm_size_t sz = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(task, &addr, &sz,
                                          VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info, &infoCnt, &obj);
        if (kr != KERN_SUCCESS) return 0;
        struct mach_header_64 hdr;
        if (readTask(task, addr, &hdr, sizeof(hdr)) &&
            hdr.magic == MH_MAGIC_64 &&
            hdr.filetype == MH_EXECUTE) {
            return addr;
        }
        addr += sz;
    }
}

// Set up a receive-only exception port on the target, resume it briefly so
// dyld can map every LC_LOAD_DYLIB framework into the address space, and
// re-suspend. For future-iOS IPAs dyld aborts at its own minos check and
// raises a Mach exception we catch; for ordinary builds we just time out and
// suspend. Either way the process is frozen again before any Objective-C +load
// runs, so we see only what dyld-as-loader pulled in — not what the app might
// dlopen() at runtime.
static void letDyldMapFrameworks(task_t task) {
    mach_port_t excPort = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &excPort) != KERN_SUCCESS) {
        return;
    }
    if (mach_port_insert_right(mach_task_self(), excPort, excPort,
                               MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        mach_port_mod_refs(mach_task_self(), excPort, MACH_PORT_RIGHT_RECEIVE, -1);
        return;
    }
    task_set_exception_ports(task,
                             EXC_MASK_CRASH | EXC_MASK_BAD_ACCESS |
                             EXC_MASK_BAD_INSTRUCTION | EXC_MASK_SOFTWARE |
                             EXC_MASK_ARITHMETIC | EXC_MASK_BREAKPOINT,
                             excPort, EXCEPTION_DEFAULT, ARM_THREAD_STATE64);

    if (task_resume(task) == KERN_SUCCESS) {
        struct {
            mach_msg_header_t head;
            char body[2048];
        } msg;
        memset(&msg, 0, sizeof(msg));
        (void)mach_msg(&msg.head, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                       0, sizeof(msg), excPort,
                       2000 /* ms */, MACH_PORT_NULL);
        task_suspend(task);
    }

    mach_port_mod_refs(mach_task_self(), excPort, MACH_PORT_RIGHT_RECEIVE, -1);
}

#pragma mark - Walk dyld image list

// Collects __objc_classname strings for every loaded image whose path lives
// under `bundleDir`. Appends those paths to `scannedImagePaths`. Returns nil
// if dyld hasn't populated its image list yet (e.g. the target was killed at
// exec before dyld ran even once).
static NSSet<NSString *> *collectBundleClassNames(task_t task,
                                                  NSString *bundleDir,
                                                  NSMutableArray<NSString *> *scannedImagePaths) {
    struct task_dyld_info dyldInfo;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count) != KERN_SUCCESS) return nil;
    if (dyldInfo.all_image_info_addr == 0) return nil;

    struct dyld_all_image_infos aii;
    if (!readTask(task, dyldInfo.all_image_info_addr, &aii, sizeof(aii))) return nil;
    if (aii.infoArrayCount == 0 || aii.infoArray == NULL) return [NSSet set];

    size_t infoBytes = sizeof(struct dyld_image_info) * aii.infoArrayCount;
    struct dyld_image_info *infos = malloc(infoBytes);
    if (!readTask(task, (mach_vm_address_t)(uintptr_t)aii.infoArray, infos, infoBytes)) {
        free(infos);
        return nil;
    }

    // iOS can report image paths with either the /private-prefixed realpath
    // or the short symlink form. Accept both.
    const char *prefixA = [bundleDir UTF8String];
    size_t prefixLenA = strlen(prefixA);
    NSString *altBundleDir;
    if ([bundleDir hasPrefix:@"/private/"]) {
        altBundleDir = [bundleDir substringFromIndex:[@"/private" length]];
    } else {
        altBundleDir = [@"/private" stringByAppendingString:bundleDir];
    }
    const char *prefixB = [altBundleDir UTF8String];
    size_t prefixLenB = strlen(prefixB);

    NSMutableSet *all = [NSMutableSet set];
    for (uint32_t i = 0; i < aii.infoArrayCount; i++) {
        NSString *path = readCString(task,
                                     (mach_vm_address_t)(uintptr_t)infos[i].imageFilePath,
                                     PATH_MAX);
        if (!path) continue;
        const char *cp = [path UTF8String];
        if (!cp) continue;
        BOOL matches = (strncmp(cp, prefixA, prefixLenA) == 0)
                    || (strncmp(cp, prefixB, prefixLenB) == 0);
        if (!matches) continue;
        [scannedImagePaths addObject:path];
        NSSet *ns = classNamesForImage(task,
                                       (mach_vm_address_t)(uintptr_t)infos[i].imageLoadAddress);
        if (ns) [all unionSet:ns];
    }
    free(infos);
    return all;
}

#pragma mark - Runtime pass (spawn-suspend + RAM scan)

typedef struct {
    NSMutableSet<NSString *>   *classes;       // union of classname strings
    NSMutableArray<NSString *> *paths;         // absolute scanned image paths
    NSString                   *error;         // nil if fully successful
} TDRuntimeScanResult;

static TDRuntimeScanResult runtimeScanBundle(NSString *bundleDir,
                                             NSString *execName) {
    TDRuntimeScanResult r = {
        .classes = [NSMutableSet set],
        .paths = [NSMutableArray array],
        .error = nil,
    };
    NSString *execPath = [bundleDir stringByAppendingPathComponent:execName];
    if (![[NSFileManager defaultManager] fileExistsAtPath:execPath]) {
        r.error = [NSString stringWithFormat:@"main exec missing: %@", execPath];
        return r;
    }

    pid_t pid = 0;
    task_t task = MACH_PORT_NULL;
    int rc = spawnSuspended(execPath, &pid, &task);
    if (rc != 0) {
        r.error = [NSString stringWithFormat:@"posix_spawn(SUSPENDED) %@: %s",
                   execPath, strerror(rc)];
        return r;
    }

    // 1) Read the main exec's Mach-O header before resuming. VM regions are
    //    set up at spawn time, so mach_vm_read against the suspended child
    //    returns whatever the kernel mapped for it — which is enough to
    //    locate and copy the __objc_classname strings.
    mach_vm_address_t mainBase = findMainExecBase(task);
    if (mainBase != 0) {
        NSSet *ns = classNamesForImage(task, mainBase);
        if (ns) {
            [r.classes unionSet:ns];
            [r.paths addObject:execPath];
        }
    }

    // 2) Let dyld briefly map frameworks so LC_LOAD_DYLIBs show up in
    //    dyld_all_image_infos. We catch any exception (e.g. minos-check
    //    abort on a future-iOS IPA) and re-suspend immediately.
    letDyldMapFrameworks(task);

    // 3) Walk dyld_all_image_infos for every image whose path lives inside
    //    the bundle. Adds frameworks + any appex binaries dyld happened to
    //    map (rare — appex mains usually aren't loaded by the host).
    NSSet *byDyld = collectBundleClassNames(task, bundleDir, r.paths);
    if (byDyld) [r.classes unionSet:byDyld];

    killTarget(pid, task);
    return r;
}

#pragma mark - Static on-disk __objc_classname (unencrypted files only)

static void appendClassNamesFromSection(const uint8_t *sectData, uint64_t size, NSMutableSet *names) {
    uint64_t off = 0;
    while (off < size) {
        size_t remaining = (size_t)(size - off);
        size_t len = strnlen((const char *)(sectData + off), remaining);
        if (len == 0) { off++; continue; }
        if (len == remaining) break;
        NSString *s = [[NSString alloc] initWithBytes:sectData + off
                                               length:len
                                             encoding:NSUTF8StringEncoding];
        if (s) [names addObject:s];
        off += len + 1;
    }
}

// Static fallback: parse a Mach-O slice on disk and emit __objc_classname
// strings. Skips any slice whose LC_ENCRYPTION_INFO_64 reports a non-zero
// cryptid — we have no reader for such ranges from outside the target task,
// and strnlen-ing opaque bytes would only emit noise. Host-app main
// binaries and appex mains are handled via the spawn-suspend RAM path;
// this routine is only useful for the non-encrypted framework binaries
// that dyld did not happen to dlopen before we sampled the task.
static BOOL sliceIsEncrypted(const uint8_t *base, size_t size) {
    if (size < sizeof(struct mach_header_64)) return NO;
    struct mach_header_64 hdr;
    memcpy(&hdr, base, sizeof(hdr));
    if (hdr.magic != MH_MAGIC_64) return NO;
    if (hdr.sizeofcmds == 0 || hdr.sizeofcmds > size - sizeof(hdr)) return NO;
    const uint8_t *p = base + sizeof(hdr);
    const uint8_t *end = p + hdr.sizeofcmds;
    for (uint32_t i = 0; i < hdr.ncmds && p + sizeof(struct load_command) <= end; i++) {
        struct load_command lc;
        memcpy(&lc, p, sizeof(lc));
        if (lc.cmdsize == 0 || p + lc.cmdsize > end) break;
        if (lc.cmd == LC_ENCRYPTION_INFO_64 &&
            p + sizeof(struct encryption_info_command_64) <= end) {
            struct encryption_info_command_64 ei;
            memcpy(&ei, p, sizeof(ei));
            return (ei.cryptid != 0 && ei.cryptsize > 0);
        }
        p += lc.cmdsize;
    }
    return NO;
}

static NSSet<NSString *> *diskClassNamesForSlice(const uint8_t *base, size_t size, BOOL *outEnc) {
    if (outEnc) *outEnc = NO;
    if (size < sizeof(struct mach_header_64)) return nil;
    struct mach_header_64 hdr;
    memcpy(&hdr, base, sizeof(hdr));
    if (hdr.magic != MH_MAGIC_64) return nil;
    if (hdr.sizeofcmds == 0 || hdr.sizeofcmds > size - sizeof(hdr)) return nil;
    if (sliceIsEncrypted(base, size)) {
        if (outEnc) *outEnc = YES;
        return nil;
    }
    NSMutableSet *names = [NSMutableSet set];
    const uint8_t *p = base + sizeof(hdr);
    const uint8_t *end = p + hdr.sizeofcmds;
    for (uint32_t i = 0; i < hdr.ncmds && p + sizeof(struct load_command) <= end; i++) {
        struct load_command lc;
        memcpy(&lc, p, sizeof(lc));
        if (lc.cmdsize == 0 || p + lc.cmdsize > end) break;
        if (lc.cmd == LC_SEGMENT_64 && p + sizeof(struct segment_command_64) <= end) {
            struct segment_command_64 sg;
            memcpy(&sg, p, sizeof(sg));
            const uint8_t *sp = p + sizeof(sg);
            for (uint32_t j = 0; j < sg.nsects; j++) {
                if (sp + sizeof(struct section_64) > end) break;
                struct section_64 sect;
                memcpy(&sect, sp, sizeof(sect));
                sp += sizeof(sect);
                if (strncmp(sect.sectname, "__objc_classname", 16) != 0) continue;
                if (sect.size == 0 || sect.size > 8 * 1024 * 1024) continue;
                if (sect.offset + sect.size > size) continue;
                appendClassNamesFromSection(base + sect.offset, sect.size, names);
            }
        }
        p += lc.cmdsize;
    }
    return names;
}

static NSSet<NSString *> *diskClassNamesForFile(NSString *path, BOOL *outEnc) {
    if (outEnc) *outEnc = NO;
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
    if (!data || data.length < 4) return nil;
    const uint8_t *bytes = data.bytes;
    size_t len = data.length;
    uint32_t magic;
    memcpy(&magic, bytes, sizeof(magic));

    if (magic == MH_MAGIC_64) return diskClassNamesForSlice(bytes, len, outEnc);

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        struct fat_header fh;
        if (len < sizeof(fh)) return nil;
        memcpy(&fh, bytes, sizeof(fh));
        uint32_t nfat = (magic == FAT_CIGAM) ? OSSwapInt32(fh.nfat_arch) : fh.nfat_arch;
        if (nfat == 0 || nfat > 16) return nil;
        size_t archOff = sizeof(fh);
        for (uint32_t i = 0; i < nfat; i++) {
            if (archOff + sizeof(struct fat_arch) > len) return nil;
            struct fat_arch fa;
            memcpy(&fa, bytes + archOff, sizeof(fa));
            archOff += sizeof(fa);
            uint32_t cpu = (magic == FAT_CIGAM) ? OSSwapInt32(fa.cputype) : fa.cputype;
            uint32_t off = (magic == FAT_CIGAM) ? OSSwapInt32(fa.offset)  : fa.offset;
            uint32_t sz  = (magic == FAT_CIGAM) ? OSSwapInt32(fa.size)    : fa.size;
            if (cpu != CPU_TYPE_ARM64) continue;
            if ((size_t)off + sz > len) return nil;
            return diskClassNamesForSlice(bytes + off, sz, outEnc);
        }
    }
    if (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
        struct fat_header fh;
        if (len < sizeof(fh)) return nil;
        memcpy(&fh, bytes, sizeof(fh));
        uint32_t nfat = (magic == FAT_CIGAM_64) ? OSSwapInt32(fh.nfat_arch) : fh.nfat_arch;
        if (nfat == 0 || nfat > 16) return nil;
        size_t archOff = sizeof(fh);
        for (uint32_t i = 0; i < nfat; i++) {
            if (archOff + sizeof(struct fat_arch_64) > len) return nil;
            struct fat_arch_64 fa;
            memcpy(&fa, bytes + archOff, sizeof(fa));
            archOff += sizeof(fa);
            uint32_t cpu = (magic == FAT_CIGAM_64) ? OSSwapInt32(fa.cputype) : fa.cputype;
            uint64_t off = (magic == FAT_CIGAM_64) ? OSSwapInt64(fa.offset)  : fa.offset;
            uint64_t sz  = (magic == FAT_CIGAM_64) ? OSSwapInt64(fa.size)    : fa.size;
            if (cpu != CPU_TYPE_ARM64) continue;
            if (off + sz > len) return nil;
            return diskClassNamesForSlice(bytes + off, (size_t)sz, outEnc);
        }
    }
    return nil;
}

#pragma mark - Bundle walk (framework dir names + static fallback + appex enumeration)

typedef struct {
    NSMutableSet<NSString *>   *classes;        // union of classname strings
    NSMutableArray<NSString *> *paths;          // scanned binary paths (static only)
    NSMutableSet<NSString *>   *frameworkNames; // "FBSDKCoreKit", ...
    NSMutableArray<NSString *> *appexPaths;     // abs paths to PlugIns/*.appex and Extensions/*.appex
    NSUInteger                  encryptedBinaries; // binaries we could not read statically
} TDBundleWalkResult;

static void scanFrameworksDir(NSString *fwRoot,
                              NSSet<NSString *> *skipPaths,
                              TDBundleWalkResult *r) {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:fwRoot isDirectory:&isDir] || !isDir) return;

    NSArray *entries = [fm contentsOfDirectoryAtPath:fwRoot error:nil];
    for (NSString *entry in entries) {
        NSString *full = [fwRoot stringByAppendingPathComponent:entry];
        NSString *binPath = nil;
        if ([entry hasSuffix:@".framework"]) {
            NSString *base = [entry stringByDeletingPathExtension];
            [r->frameworkNames addObject:base];
            NSString *cand = [full stringByAppendingPathComponent:base];
            if ([fm fileExistsAtPath:cand]) binPath = cand;
            scanFrameworksDir([full stringByAppendingPathComponent:@"Frameworks"], skipPaths, r);
        } else if ([entry hasSuffix:@".dylib"]) {
            [r->frameworkNames addObject:[entry stringByDeletingPathExtension]];
            binPath = full;
        }
        if (!binPath) continue;
        if ([skipPaths containsObject:binPath]) continue;
        BOOL enc = NO;
        NSSet *ns = diskClassNamesForFile(binPath, &enc);
        if (enc) r->encryptedBinaries++;
        if (ns) {
            [r->classes unionSet:ns];
            [r->paths addObject:binPath];
        }
    }
}

static TDBundleWalkResult bundleStaticWalk(NSString *bundleDir, NSSet<NSString *> *skipPaths) {
    TDBundleWalkResult r = {
        .classes = [NSMutableSet set],
        .paths = [NSMutableArray array],
        .frameworkNames = [NSMutableSet set],
        .appexPaths = [NSMutableArray array],
        .encryptedBinaries = 0,
    };
    NSFileManager *fm = [NSFileManager defaultManager];

    scanFrameworksDir([bundleDir stringByAppendingPathComponent:@"Frameworks"], skipPaths, &r);

    // PlugIns/ (classic NSExtension) and Extensions/ (iOS 18 ExtensionKit).
    NSArray<NSString *> *subdirs = @[@"PlugIns", @"Extensions"];
    for (NSString *sub in subdirs) {
        NSString *plug = [bundleDir stringByAppendingPathComponent:sub];
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:plug isDirectory:&isDir] || !isDir) continue;
        for (NSString *entry in [fm contentsOfDirectoryAtPath:plug error:nil]) {
            if (![entry hasSuffix:@".appex"]) continue;
            NSString *appexDir = [plug stringByAppendingPathComponent:entry];
            [r.appexPaths addObject:appexDir];
            scanFrameworksDir([appexDir stringByAppendingPathComponent:@"Frameworks"], skipPaths, &r);
        }
    }
    return r;
}

#pragma mark - Privacy manifests

typedef struct {
    BOOL                       anyTracking;       // ORed NSPrivacyTracking
    NSMutableSet<NSString *>  *trackingDomains;   // union of NSPrivacyTrackingDomains
    NSUInteger                 manifestCount;
} TDPrivacyScanResult;

static void collectPrivacyManifestsIn(NSString *dir, TDPrivacyScanResult *r, int depth) {
    if (depth > 6) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:dir isDirectory:&isDir] || !isDir) return;
    for (NSString *entry in [fm contentsOfDirectoryAtPath:dir error:nil]) {
        NSString *full = [dir stringByAppendingPathComponent:entry];
        BOOL entryIsDir = NO;
        [fm fileExistsAtPath:full isDirectory:&entryIsDir];
        if (entryIsDir) {
            collectPrivacyManifestsIn(full, r, depth + 1);
            continue;
        }
        if (![entry isEqualToString:@"PrivacyInfo.xcprivacy"]) continue;
        r->manifestCount++;
        NSData *data = [NSData dataWithContentsOfFile:full];
        if (!data) continue;
        id plist = [NSPropertyListSerialization propertyListWithData:data
                                                             options:0
                                                              format:NULL
                                                               error:NULL];
        if (![plist isKindOfClass:[NSDictionary class]]) continue;
        NSNumber *tracking = plist[@"NSPrivacyTracking"];
        if ([tracking isKindOfClass:[NSNumber class]] && tracking.boolValue) {
            r->anyTracking = YES;
        }
        NSArray *domains = plist[@"NSPrivacyTrackingDomains"];
        if ([domains isKindOfClass:[NSArray class]]) {
            for (id d in domains) {
                if ([d isKindOfClass:[NSString class]]) [r->trackingDomains addObject:d];
            }
        }
    }
}

static TDPrivacyScanResult collectPrivacyManifests(NSString *bundleDir) {
    TDPrivacyScanResult r = {
        .anyTracking = NO,
        .trackingDomains = [NSMutableSet set],
        .manifestCount = 0,
    };
    collectPrivacyManifestsIn(bundleDir, &r, 0);
    return r;
}

#pragma mark - Info.plist keys + URL schemes

static NSSet<NSString *> *collectPlistTokens(NSString *bundleDir) {
    NSString *infoPath = [bundleDir stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPath];
    if (!info) return [NSSet set];
    NSMutableSet *tokens = [NSMutableSet setWithArray:[info allKeys]];
    NSArray *urlTypes = info[@"CFBundleURLTypes"];
    if ([urlTypes isKindOfClass:[NSArray class]]) {
        for (NSDictionary *t in urlTypes) {
            if (![t isKindOfClass:[NSDictionary class]]) continue;
            NSArray *schemes = t[@"CFBundleURLSchemes"];
            if ([schemes isKindOfClass:[NSArray class]]) {
                for (id s in schemes) {
                    if ([s isKindOfClass:[NSString class]]) [tokens addObject:s];
                }
            }
        }
    }
    return tokens;
}

#pragma mark - Public entry point

NSDictionary *TDScanBundleID(NSString *bundleID, NSArray *sigs, NSError **err) {
    LSApplicationProxy *proxy = [LSApplicationProxy applicationProxyForIdentifier:bundleID];
    if (!proxy || !proxy.canonicalExecutablePath) {
        if (err) *err = tderr(TDScannerErrorUnknownBundleID, @"unknown bundleID: %@", bundleID);
        return nil;
    }
    NSString *exe = proxy.canonicalExecutablePath;
    NSString *execName = [exe lastPathComponent];
    NSString *bundleDir = [exe stringByDeletingLastPathComponent];
    NSString *version = [proxy atl_shortVersionString] ?: @"";

    // 1) Runtime pass: spawn-suspend main exec + mach_vm_read.
    TDRuntimeScanResult rt = runtimeScanBundle(bundleDir, execName);
    NSString *runtimeError = rt.error;

    // 2) Runtime pass for each PlugIns/*.appex and Extensions/*.appex. Each
    //    appex main is a separate Mach-O that the host-app spawn never
    //    maps, so we repeat the spawn-suspend pass per appex. Some appex
    //    mains cannot exec standalone (they need ExtensionKit); for those
    //    spawnSuspended fails and the static fallback covers what it can.
    NSMutableSet<NSString *> *appexClasses = [NSMutableSet set];
    NSMutableArray<NSString *> *appexPaths = [NSMutableArray array];
    NSUInteger appexCount = 0;
    NSUInteger appexScanned = 0;
    {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray<NSString *> *subdirs = @[@"PlugIns", @"Extensions"];
        for (NSString *sub in subdirs) {
            NSString *plug = [bundleDir stringByAppendingPathComponent:sub];
            BOOL isDir = NO;
            if (![fm fileExistsAtPath:plug isDirectory:&isDir] || !isDir) continue;
            for (NSString *entry in [fm contentsOfDirectoryAtPath:plug error:nil]) {
                if (![entry hasSuffix:@".appex"]) continue;
                NSString *appexDir = [plug stringByAppendingPathComponent:entry];
                appexCount++;
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                                       [appexDir stringByAppendingPathComponent:@"Info.plist"]];
                NSString *appexExec = info[@"CFBundleExecutable"];
                if (!appexExec.length) continue;
                TDRuntimeScanResult ar = runtimeScanBundle(appexDir, appexExec);
                if (!ar.error) appexScanned++;
                [appexClasses unionSet:ar.classes];
                [appexPaths addObjectsFromArray:ar.paths];
            }
        }
    }

    NSMutableSet<NSString *> *runtimeClasses = [NSMutableSet setWithSet:rt.classes];
    [runtimeClasses unionSet:appexClasses];

    // 3) Static pass covers frameworks dyld never dlopen'd and appex mains
    //    where spawn failed. Skip paths we already visited in RAM.
    NSMutableSet *runtimePathSet = [NSMutableSet set];
    NSArray<NSString *> *allRuntimePaths = [rt.paths arrayByAddingObjectsFromArray:appexPaths];
    for (NSString *p in allRuntimePaths) {
        [runtimePathSet addObject:p];
        if ([p hasPrefix:@"/private/"]) {
            [runtimePathSet addObject:[p substringFromIndex:[@"/private" length]]];
        }
    }
    TDBundleWalkResult st = bundleStaticWalk(bundleDir, runtimePathSet);
    TDPrivacyScanResult pr = collectPrivacyManifests(bundleDir);
    NSSet<NSString *> *plistTokens = collectPlistTokens(bundleDir);

    NSMutableSet *allClasses = [NSMutableSet setWithSet:runtimeClasses];
    [allClasses unionSet:st.classes];

    NSMutableDictionary *byID = [NSMutableDictionary dictionary];

    NSMutableDictionary *(^entryFor)(NSDictionary *) = ^NSMutableDictionary *(NSDictionary *sig) {
        NSNumber *sid = sig[@"id"];
        NSMutableDictionary *entry = byID[sid];
        if (!entry) {
            entry = [@{
                @"id": sid,
                @"name": sig[@"name"],
                @"classes": [NSMutableArray array],
                @"sources": [NSMutableSet set],
            } mutableCopy];
            byID[sid] = entry;
        }
        return entry;
    };

    for (NSString *cn in allClasses) {
        NSRange whole = NSMakeRange(0, cn.length);
        BOOL inRuntime = [runtimeClasses containsObject:cn];
        BOOL inStatic = [st.classes containsObject:cn];
        NSString *source = (inRuntime && inStatic) ? @"both" : (inRuntime ? @"runtime" : @"static");
        for (NSDictionary *sig in sigs) {
            NSRegularExpression *re = sig[@"regex"];
            if (!re) continue;
            if ([re numberOfMatchesInString:cn options:0 range:whole] > 0) {
                NSMutableDictionary *entry = entryFor(sig);
                [entry[@"classes"] addObject:cn];
                [entry[@"sources"] addObject:source];
            }
        }
    }

    for (NSString *fwName in st.frameworkNames) {
        NSRange whole = NSMakeRange(0, fwName.length);
        for (NSDictionary *sig in sigs) {
            NSRegularExpression *re = sig[@"dylibRegex"];
            if (!re) continue;
            if ([re numberOfMatchesInString:fwName options:0 range:whole] > 0) {
                [entryFor(sig)[@"sources"] addObject:@"framework"];
            }
        }
    }

    for (NSString *tok in plistTokens) {
        NSRange whole = NSMakeRange(0, tok.length);
        for (NSDictionary *sig in sigs) {
            NSRegularExpression *re = sig[@"plistRegex"];
            if (!re) continue;
            if ([re numberOfMatchesInString:tok options:0 range:whole] > 0) {
                [entryFor(sig)[@"sources"] addObject:@"plist"];
            }
        }
    }

    NSArray *matches = [[byID allValues] sortedArrayUsingDescriptors:@[
        [NSSortDescriptor sortDescriptorWithKey:@"id" ascending:YES]
    ]];
    for (NSMutableDictionary *m in matches) {
        [m[@"classes"] sortUsingSelector:@selector(compare:)];
        NSArray *srcs = [[m[@"sources"] allObjects] sortedArrayUsingSelector:@selector(compare:)];
        m[@"sources"] = srcs;
    }

    NSArray *trackingDomains = [[pr.trackingDomains allObjects]
                                 sortedArrayUsingSelector:@selector(compare:)];

    NSMutableDictionary *out = [@{
        @"bundleID": bundleID,
        @"version": version,
        @"scannedImages": @(allRuntimePaths.count),
        @"candidateImages": @(st.paths.count),
        @"appexCount": @(appexCount),
        @"appexScanned": @(appexScanned),
        @"classCount": @(allClasses.count),
        @"privacyManifests": @(pr.manifestCount),
        @"privacyTracking": @(pr.anyTracking),
        @"trackingDomains": trackingDomains,
        @"matches": matches,
    } mutableCopy];
    if (runtimeError) out[@"runtimeError"] = runtimeError;
    // `encryptedBinaries` counts Mach-Os whose __objc_classname the RAM pass
    // also didn't reach (e.g. a framework dyld never dlopen'd during the
    // brief resume window). The main exec and successfully-spawned appex
    // mains don't contribute: the RAM pass already produced class names
    // for those.
    if (st.encryptedBinaries) out[@"encryptedBinaries"] = @(st.encryptedBinaries);
    return out;
}
