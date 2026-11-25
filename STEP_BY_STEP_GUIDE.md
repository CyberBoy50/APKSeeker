# APKSeeker — Step-by-Step Guide

Build the tool one step at a time, test each step before moving on.
Every step below is a function in `test_apkseeker.py` — run the whole
suite with `python run.py test` (139 checks, all passing, including 10
Androguard oracle cross-checks).

Setup first (once):

```
python run.py setup
```

The test APKs live in `test_apks/` and are built by
`build_test_apk.py` — a hand-written AXML writer plus a minimal dex
builder — because there is no Android Studio or SDK on this machine.
Regenerate them any time with `python run.py build-apk`.

## Step 1 — List the archive

**Write:** open the APK as a ZIP (stdlib `zipfile`) and list every
entry with its compressed and uncompressed size.

**Run:**

```
python3 apkseeker.py test_apks/test_bad.apk --list
```

**Expected output** (real run, bad APK):

```
 Archive entries (8)
  AndroidManifest.xml                                4812 bytes (compressed 1252)
  classes.dex                                         535 bytes (compressed 368)
  resources.arsc                                       62 bytes (compressed 64)
  res/xml/network_security_config.xml                1272 bytes (compressed 402)
  lib/armeabi-v7a/liblab.so                            72 bytes (compressed 12)
  lib/arm64-v8a/liblab.so                              72 bytes (compressed 12)
  lib/x86/liblab.so                                    72 bytes (compressed 12)
  lib/x86_64/liblab.so                                 72 bytes (compressed 12)
  Total uncompressed: 6969 bytes
```

**Test it:** the printed list must match a manual `zipfile` listing —
same names, same order, same sizes. The test (`test_step1`) checks
exactly that, for all three fixtures (8, 3 and 1 entries).

## Step 2 — Parse the string pool

**Write:** read the string-pool chunk (type `0x0001`) at the start of
the binary manifest: string count, flags, the offsets table, then each
string — UTF-16 by default, UTF-8 when flag `0x100` is set.

**Run:**

```
python3 apkseeker.py test_apks/test_bad.apk --manifest
```

**Expected output** (first lines of the real run):

```
  Rebuilt manifest — test_apks/test_bad.apk
  <manifest package="com.example.labapp" versionCode="1" versionName="1.0">
    <uses-sdk minSdkVersion="21" targetSdkVersion="28" />
    ...
```

The package name `com.example.labapp` and the permission names only
appear because the pool decoded them — if the pool were wrong, the
whole manifest would be garbage.

**Test it:** the pool must contain the package name, the permission
names (`android.permission.ACCESS_FINE_LOCATION`,
`android.permission.SEND_SMS`), the component names and the android
namespace URI, with no replacement characters. The test
(`test_step2`) also builds a small UTF-8-pool AXML document by hand
and parses it, so both pool encodings are covered.

## Step 3 — Rebuild the elements

**Write:** walk the chunks after the pool — skip the resource-map
chunk (`0x0180`), read start-element records (`0x0102`) with their
20-byte attribute records, nest them on a stack, close them on
end-element records (`0x0103`), and rebuild the element tree. Typed
values: string `0x03`, int-dec `0x10`, int-hex `0x11`, boolean `0x12`,
reference `0x01` (reported raw as `@0x…`).

**Run:**

```
python3 apkseeker.py test_apks/test_bad.apk --manifest
```

**Expected output** (real run, abridged):

```
<manifest package="com.example.labapp" versionCode="1" versionName="1.0">
  <uses-sdk minSdkVersion="21" targetSdkVersion="28" />
  <uses-permission name="android.permission.INTERNET" />
  <uses-permission name="android.permission.ACCESS_FINE_LOCATION" />
  ...
  <application debuggable="true" allowBackup="true"
      usesCleartextTraffic="true" label="LabApp" icon="@0x7f020000">
    <activity name=".MainActivity" exported="true">
      <intent-filter>
        <action name="android.intent.action.MAIN" />
        <category name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    ...
  </application>
</manifest>
```

Note the `icon="@0x7f020000"` — a reference value is reported raw,
never resolved to a guessed name.

**Test it:** the parsed tree must match the source tree the generator
used, element for element and attribute for attribute — the round-trip
test (`test_step3`). It runs for the bad, clean and minimal manifests,
and for the network security config (a second AXML file parsed with
the same code).

## Step 4 — Permissions and components

**Write:** extract every `uses-permission`, flag the dangerous ones
from the curated set (Location and SMS are High, the rest Medium);
classify every activity, activity-alias, service, receiver and
provider — `exported="true"` is exported, an intent-filter child with
`exported` not `"false"` is exported, `exported="false"` is not.
Severity is High when no `android:permission` guards it, Medium when
one does.

**Run:**

```
python3 apkseeker.py test_apks/test_bad.apk
```

**Expected output** (real run, the APK-001/APK-002 lines):

```
[HIGH] [APK-001] Dangerous permission: android.permission.ACCESS_FINE_LOCATION
[MEDIUM] [APK-001] Dangerous permission: android.permission.CAMERA
[HIGH] [APK-001] Dangerous permission: android.permission.SEND_SMS
[MEDIUM] [APK-001] Dangerous permission: android.permission.READ_CONTACTS
[HIGH] [APK-002] Exported activity: .MainActivity
[HIGH] [APK-002] Exported activity: .ShareActivity
[MEDIUM] [APK-002] Exported receiver: .BootReceiver
```

**Test it:** 6 permissions (4 dangerous), 6 components (3 exported:
`.MainActivity` explicit-true, `.ShareActivity` by intent filter,
`.BootReceiver` guarded; `.SecretActivity`, `.SyncService` and
`.LabProvider` not exported). The test (`test_step4`) asserts each
classification and each severity.

## Step 5 — Flags and SDK versions

**Write:** read `android:debuggable` (High when true),
`android:allowBackup` (Medium when true — and when the attribute is
absent, because the Android default is true), `minSdkVersion` and
`targetSdkVersion` (Medium below 30, High below 26 or missing).

**Run:**

```
python3 apkseeker.py test_apks/test_bad.apk
```

**Expected output** (real run):

```
[HIGH] [APK-003] Application is debuggable
[MEDIUM] [APK-004] Application allows backup
[MEDIUM] [APK-005] Old target SDK: 28
```

**Test it:** rebuild a fixture with each flag toggled and assert the
report changes — `debuggable=false` silences APK-003,
`allowBackup=false` silences APK-004, `allowBackup` absent still fires
APK-004 (defaults to true), `targetSdk` 34 silences APK-005,
`targetSdk` 21 or missing fires APK-005 as High. The test
(`test_step5`) does all six toggles.

## Step 6 — Secret-pattern scan

**Write:** decompress the dex, `resources.arsc` and asset bytes and
scan them for Google API keys, AWS keys, generic api-key assignments,
private-key material (Critical), password assignments, bearer/token
values and private URLs/IPs. Report entry name, offset and pattern
name — and never print a full secret: truncate to the first 8
characters plus "…".

**Run:**

```
python3 apkseeker.py test_apks/test_bad.apk
```

**Expected output** (real run, the APK-006 lines):

```
[HIGH] [APK-006] Google API key in classes.dex
    Evidence: Matched at offset 285: AIzaSyBF…
[HIGH] [APK-006] AWS access key in classes.dex
    Evidence: Matched at offset 344: AKIAIOSF…
[HIGH] [APK-006] Password assignment in classes.dex
    Evidence: Matched at offset 366: password…
[MEDIUM] [APK-006] Private URL in classes.dex
    Evidence: Matched at offset 398: https://…
[HIGH] [APK-006] API key assignment in resources.arsc
    Evidence: Matched at offset 4: api_key …
```

The planted secrets are fake markers (`AIzaSyBFAKEKEY…`,
`AKIAIOSFODNN7EXAMPLE`) — they exist only so the scanner has
something true to find.

**Test it:** the planted fake API key is found; rebuild the fixture
without it and assert it is NOT reported (and the same for the AWS
key, the api-key assignment, the password and the private URL). A
synthetic private-key blob is checked as Critical. The test
(`test_step6`) does all of it.

## Step 7 — CLI, report and full run

**Write:** the full command line, the text and JSON reports, and the
exit codes — 0 clean, 1 findings, 2 any Critical (or a `--fail-on`
hit, or an unusable input file).

**Run:**

```
python3 apkseeker.py test_apks/test_bad.apk -o report.txt
echo "exit: $?"
python3 apkseeker.py test_apks/test_clean.apk -o clean.txt
echo "exit: $?"
```

**Expected output** (real run):

```
Findings (20: 0 critical, 11 high, 9 medium, 0 low)
[+] Report saved: report.txt
exit: 1
Findings (0: 0 critical, 0 high, 0 medium, 0 low)
[+] Report saved: clean.txt
exit: 0
```

**Test it:** the saved report is read start to finish — every
expected finding present with the right severity, no full secret
anywhere in it, all 8 entries listed; the JSON report has
`total_findings` 20 and counts `0/11/9/0`; the clean APK reports 0
findings; the minimal APK (no dex) runs without crashing and reports
exactly 1 Low finding. The test (`test_step7`) also checks
`--list`, `--manifest`, `--list-checks`, `--version`, `--min-severity`,
`--fail-on`, the doctor, the menu, and malformed input (non-ZIP,
ZIP without a manifest, truncated AXML, missing file — all clean
errors, exit 2, no traceback).

## Step 8 — Stretch: deep links, native libraries, cleartext

**Write:** (a) deep-link schemes from intent filters — a custom scheme
on an exported activity with no permission is Medium (APK-007);
(b) a native-library listing — every `lib/<abi>/*.so`, grouped by ABI
(APK-009, info only, never a finding); (c) cleartext assessment —
parse `res/xml/network_security_config.xml` with the same AXML parser
(base-config / domain-config `cleartextTrafficPermitted`, certificates
`src="user"`), plus the `usesCleartextTraffic` attribute, and say
clearly when no config file exists.

**Run:**

```
python3 apkseeker.py test_apks/test_bad.apk
```

**Expected output** (real run, the stretch lines):

```
[MEDIUM] [APK-007] Unprotected deep link: labapp://
[HIGH] [APK-008] Cleartext traffic permitted (base-config)
[HIGH] [APK-008] Cleartext traffic permitted (domain-config for api.example.com)
[MEDIUM] [APK-008] User certificates trusted
[MEDIUM] [APK-008] usesCleartextTraffic=true
```

plus, in the report body, the native-library listing (one `.so` per
ABI: `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`).

**Test it:** the deep-link scheme `labapp` with host `share` is
extracted from `.ShareActivity`; 4 ABIs with 1 `.so` each; APK-008
fires 4 times with the right severities (2 High, 2 Medium); the clean
APK has no deep links, no native libraries and no cleartext findings.
The test (`test_step8`) asserts all of it.

## Independent oracle

The test suite cross-checks the parser against **Androguard** (the
real-world Android analysis library), installed in a test venv: the
same fixture APK is parsed by both, and permissions, components,
package, SDK versions, `debuggable` and `allowBackup` must agree —
10 checks, all passing. Androguard expands relative component names
(`.MainActivity` → `com.example.labapp.MainActivity`); the test
resolves APKSeeker's names the same way before comparing. If
Androguard is not available, the oracle checks are skipped with a
clear note and the round-trip test (Step 3) is the oracle instead —
nothing is faked.

Two bugs the oracle caught while building the fixtures, so you know
what to watch for: the minimal dex's Adler32 checksum was computed
before the SHA-1 signature was patched in (Androguard rejected the
dex outright), and the resource-map chunk held the wrong IDs at the
wrong string-pool indices (Androguard renamed the `package`
attribute to `icon`). Both are fixed in `build_test_apk.py` — the
checksum is computed after the signature, and the resource map is
indexed by string-pool index with the real `android.R.attr` IDs.
