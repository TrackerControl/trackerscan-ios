# trackerscan

On-device detector for iOS tracking libraries.

`trackerscan` is a command-line tool for jailbroken iOS (rootless,
TrollStore-style) that inspects an installed app and reports which
third-party tracking SDKs it contains. It reads only the Objective-C
class-name strings from each Mach-O's `__TEXT,__objc_classname`
section — a few hundred KB of public symbols the runtime uses at load
time — and matches them against a bundled signature list. It also
aggregates `PrivacyInfo.xcprivacy` and `Info.plist` signals.

Written for independent privacy research on apps the operator owns a
legitimate copy of. Use at own risk.

## Build

Requires [Theos](https://theos.dev) with a rootless toolchain
(`$THEOS` exported):

```sh
make package
# → packages/com.trackerscan.cli_*.deb
```

## Install

```sh
scp packages/com.trackerscan.cli_*.deb iphone:/tmp/
ssh iphone apt-get install -y /tmp/com.trackerscan.cli_*.deb
```

The signature list is installed to
`/var/jb/usr/share/trackerscan/signatures.json` — edit on-device to
extend detections.

## Usage

```sh
trackerscan --list                   # bundleID<TAB>name<TAB>version
trackerscan com.example.app          # JSON report on stdout
trackerscan --signatures ./sigs.json com.example.app
```

Example match:

```json
{
  "bundleID": "com.weather.TWC",
  "classCount": 5999,
  "trackingDomains": ["app-measurement.com", "..."],
  "matches": [
    {"id": 5, "name": "Google AdMob",
     "classes": ["GADMobileAds"],
     "sources": ["plist", "runtime"]}
  ]
}
```

Exit `0` on success; on failure, `{"error": "..."}` on stderr,
non-zero exit.
