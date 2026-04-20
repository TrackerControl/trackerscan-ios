#import <Foundation/Foundation.h>
#import <stdio.h>
#import "TDClassScanner.h"

static NSString *const kDefaultSigPath = @"/var/jb/usr/share/trackerscan/signatures.json";

static void emitErrorJSON(NSString *msg) {
    NSData *d = [NSJSONSerialization dataWithJSONObject:@{@"error": msg ?: @"unknown"}
                                                options:0
                                                  error:nil];
    fwrite(d.bytes, 1, d.length, stderr);
    fputc('\n', stderr);
}

static int usage(void) {
    fprintf(stderr,
        "trackerscan <bundleID>              scan one app, print JSON to stdout\n"
        "trackerscan --list                  list installed user apps (bundleID\\tname\\tversion)\n"
        "trackerscan --signatures <path> <bundleID>\n"
        "                                    use a custom signatures.json\n");
    return 2;
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc < 2) return usage();

        NSString *sigPath = kDefaultSigPath;
        NSString *bundleID = nil;
        BOOL list = NO;

        int i = 1;
        while (i < argc) {
            const char *a = argv[i];
            if (strcmp(a, "--list") == 0) {
                list = YES; i++;
            } else if (strcmp(a, "--signatures") == 0 && i + 1 < argc) {
                sigPath = [NSString stringWithUTF8String:argv[i + 1]];
                i += 2;
            } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
                usage();
                return 0;
            } else if (a[0] == '-') {
                return usage();
            } else {
                if (bundleID) return usage();
                bundleID = [NSString stringWithUTF8String:a];
                i++;
            }
        }

        if (list) {
            for (NSDictionary *app in TDListInstalledUserApps()) {
                printf("%s\t%s\t%s\n",
                       [app[@"bundleID"] UTF8String],
                       [app[@"name"] UTF8String],
                       [app[@"version"] UTF8String]);
            }
            return 0;
        }

        if (!bundleID) return usage();

        NSError *err = nil;
        NSArray *sigs = TDLoadSignatures(sigPath, &err);
        if (!sigs) {
            emitErrorJSON([NSString stringWithFormat:@"failed to load signatures from %@: %@",
                           sigPath, err.localizedDescription]);
            return 1;
        }

        NSDictionary *result = TDScanBundleID(bundleID, sigs, &err);
        if (!result) {
            emitErrorJSON(err.localizedDescription ?: @"scan failed");
            return 1;
        }

        NSData *out = [NSJSONSerialization dataWithJSONObject:result
                                                      options:NSJSONWritingPrettyPrinted
                                                        error:&err];
        if (!out) {
            emitErrorJSON(err.localizedDescription ?: @"JSON encode failed");
            return 1;
        }
        fwrite(out.bytes, 1, out.length, stdout);
        fputc('\n', stdout);
        return 0;
    }
}
