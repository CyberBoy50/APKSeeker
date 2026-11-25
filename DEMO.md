# APKSeeker — Demo

A real scan of the lab bad APK (`test_apks/test_bad.apk`), and one
finding explained in full — the exported-component lesson the project
is built around.

## The scan

```bash
python3 apkseeker.py test_apks/test_bad.apk
```

```
============================================================
  APKSeeker v1.2 — Android APK Static Analyzer
  by CyberBoy50
  AUTHORIZED USE ONLY — scan APKs you own or have written
  permission to audit. APKSeeker only reads; it never runs
  code or modifies the APK.
============================================================

  APK: test_apks/test_bad.apk
  Package: com.example.labapp
  Version: 1.0 (code 1)
  Entries: 8 (6969 bytes uncompressed)
  Permissions: 6 requested, 4 dangerous
  Components: 6, 3 exported
  Native libraries: 4 ABI(s)

  SCAN
  APK: test_apks/test_bad.apk
  min severity: (all)   fail on: critical
  Output: apkseeker_report.txt

  Findings (20: 0 critical, 11 high, 9 medium, 0 low)
  [HIGH] [APK-001] Dangerous permission: android.permission.ACCESS_FINE_LOCATION
  [MEDIUM] [APK-001] Dangerous permission: android.permission.CAMERA
  [HIGH] [APK-001] Dangerous permission: android.permission.SEND_SMS
  [MEDIUM] [APK-001] Dangerous permission: android.permission.READ_CONTACTS
  [HIGH] [APK-002] Exported activity: .MainActivity
  [HIGH] [APK-002] Exported activity: .ShareActivity
  [MEDIUM] [APK-002] Exported receiver: .BootReceiver
  [HIGH] [APK-003] Application is debuggable
  [MEDIUM] [APK-004] Application allows backup
  [MEDIUM] [APK-005] Old target SDK: 28
  [HIGH] [APK-006] Google API key in classes.dex
  [HIGH] [APK-006] AWS access key in classes.dex
  [HIGH] [APK-006] Password assignment in classes.dex
  [MEDIUM] [APK-006] Private URL in classes.dex
  [HIGH] [APK-006] API key assignment in resources.arsc
  [MEDIUM] [APK-007] Unprotected deep link: labapp://
  [HIGH] [APK-008] Cleartext traffic permitted (base-config)
  [HIGH] [APK-008] Cleartext traffic permitted (domain-config for api.example.com)
  [MEDIUM] [APK-008] User certificates trusted
  [MEDIUM] [APK-008] usesCleartextTraffic=true

  [+] Report saved: apkseeker_report.txt
  Exit code: 1 (findings, no Critical)
```

The clean APK, for contrast:

```bash
python3 apkseeker.py test_apks/test_clean.apk
# Findings (0: 0 critical, 0 high, 0 medium, 0 low)
# Exit code: 0
```

And the minimal APK (manifest only, no dex — the scanner must not
crash on a missing dex):

```bash
python3 apkseeker.py test_apks/test_minimal.apk
# Findings (1: 0 critical, 0 high, 0 medium, 1 low)
# [LOW] [APK-008] No network security config — cleartext defaults apply
# Exit code: 1
```

## One finding, explained: the exported component (APK-002)

The full finding from the report (`sample_report.txt`):

```
[HIGH] [APK-002] Exported activity: .MainActivity
    Evidence: android:exported=true. No android:permission — any app
    on the device can reach it.
    Location: AndroidManifest.xml
    Fix: Set android:exported=false if no other app needs it, or
    protect it with android:permission so only chosen apps can reach it.
```

### What an exported component is

Every Android app is a set of components — activities (screens),
services (background work), receivers (listeners for system events)
and providers (data). By default a component is private: only the app
itself can use it. Setting `android:exported="true"` opens a door in
the app's wall: any other app on the phone can now call that
component directly, by name, with an intent.

The manifest in the lab APK declares this:

```xml
<activity android:name=".MainActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</activity>
```

That is the app's launcher screen, so it genuinely needs to be
exported — the system itself has to open it. The problem is not that
it is exported; the problem is that it is exported **with no guard**:
there is no `android:permission` on it, so *any* app — including a
malicious one — can launch it, pass it crafted data, and make it do
things the user never asked for.

The second exported activity is worse, because it does not even say
`exported="true"` out loud:

```xml
<activity android:name=".ShareActivity">
    <intent-filter>
        <action android:name="android.intent.action.SEND" />
        <data android:scheme="labapp" android:host="share" />
    </intent-filter>
</activity>
```

Android's rule: an activity with an intent filter is exported by
default unless `exported="false"` is written. So `.ShareActivity` is
open too — and because it handles the custom deep link `labapp://`,
any app on the device can fire that link and land inside it. That is
APK-007 as well: an unprotected deep link on an exported activity.

### Why an unprotected one is a door

An exported component is an entry point the developer did not put a
lock on. The classic attacks are:

- **Intent spoofing** — another app sends a crafted intent to the
  exported activity/service, making it act with the victim app's
  permissions (reading its files, sending its messages, opening its
  private screens).
- **Deep-link hijack** — a malicious app registers the same custom
  scheme, or simply fires the victim's link with hostile data, and
  the victim app trusts the data because "it came from a link".
- **Receiver abuse** — an exported broadcast receiver with no
  permission can be triggered by anyone, for example to start a
  service at boot or to wake the app on demand.

The lab APK shows the safe pattern as well. `.BootReceiver` is
exported, but it carries a guard:

```xml
<receiver android:name=".BootReceiver" android:exported="true"
    android:permission="android.permission.RECEIVE_BOOT_COMPLETED">
```

Only apps holding that permission can send to it — so APKSeeker
reports it as Medium, not High. And `.SecretActivity` is the closed
door: `android:exported="false"`, no finding at all.

### How to close it

1. **Export only what must be open.** A launcher activity must be
   exported; almost nothing else needs to be. Set
   `android:exported="false"` on everything else — Android 12
   actually requires you to write the attribute explicitly, because
   the silent default was burning developers.
2. **Guard what stays open.** Put `android:permission` on the
   component, and define that permission with
   `android:protectionLevel="signature"` so only apps signed with
   your key can hold it.
3. **Do not trust deep-link data.** A custom scheme (`labapp://`) is
   not a security boundary — anyone can fire it. Verify the data,
   and prefer verified App Links (`assetlinks.json`) over a bare
   custom scheme.
4. **Check the report, not the intent.** Run the scanner before
   release: `APK-002` High means "any app on the device can reach
   this" — that is the line to fix first.

## Real-world scan: Markor from F-Droid (v1.2)

The first production APK ever run through APKSeeker — **Markor**
(`net.gsantner.markor` 2026.10.0, versionCode 164), an open-source
notes/text-editor app downloaded from F-Droid. This is the scan that
closed the "lab-only" limit: the tool had only ever seen its own
three hand-built fixtures before.

```bash
curl -o test_apks/markor_164.apk https://f-droid.org/repo/net.gsantner.markor_164.apk
python3 apkseeker.py test_apks/markor_164.apk
```

The APK: 1,732 entries, 11,849,016 bytes (24,692,136 uncompressed),
two dex files (`classes.dex` 9,677,760 bytes + `classes2.dex`
782,724 bytes), a 59,992-byte binary manifest with a UTF-16 string
pool, minSdk 21, targetSdk 35, not debuggable. Scan time: about 12
seconds. The APK itself is **not** in this repo (12 MB binary) —
only the recorded results in `real_apk_scan.json` are. Its SHA-256
is `c29412e02d03e4f0511746a1bcef48c6b73fc1f70c1024fbf04903b0b3f4c485`,
so anyone can verify the download before re-running the scan.

```
  APK: test_apks/markor_164.apk
  Package: net.gsantner.markor
  Version: 2026.10.0 (code 164)
  Entries: 1732 (24692136 bytes uncompressed)
  Permissions: 7 requested, 3 dangerous
  Components: 19, 11 exported
  Native libraries: none

  Findings (17: 0 critical, 10 high, 6 medium, 1 low)
  [MEDIUM] [APK-001] Dangerous permission: android.permission.WRITE_EXTERNAL_STORAGE
  [MEDIUM] [APK-001] Dangerous permission: android.permission.READ_EXTERNAL_STORAGE
  [MEDIUM] [APK-001] Dangerous permission: android.permission.MANAGE_EXTERNAL_STORAGE
  [HIGH] [APK-002] Exported activity: net.gsantner.markor.activity.MainActivity
  [HIGH] [APK-002] Exported activity: net.gsantner.markor.activity.SettingsActivity
  [HIGH] [APK-002] Exported activity: other.writeily.widget.WrWidgetConfigure
  [HIGH] [APK-002] Exported activity: net.gsantner.markor.activity.openeditor.OpenEditorTodoActivity
  [HIGH] [APK-002] Exported activity: net.gsantner.markor.activity.openeditor.OpenEditorQuickNoteActivity
  [HIGH] [APK-002] Exported activity: net.gsantner.markor.activity.openeditor.OpenShareIntoActivity
  [HIGH] [APK-002] Exported activity: net.gsantner.markor.activity.DocumentActivity
  [HIGH] [APK-002] Exported activity-alias: net.gsantner.markor.AliasDocumentProcessText
  [HIGH] [APK-002] Exported receiver: other.writeily.widget.WrMarkorWidgetProvider
  [HIGH] [APK-002] Exported receiver: net.gsantner.markor.widget.TodoWidgetProvider
  [MEDIUM] [APK-002] Exported receiver: androidx.profileinstaller.ProfileInstallReceiver
  [MEDIUM] [APK-004] Application allows backup
  [MEDIUM] [APK-007] Unprotected deep link: markor://
  [LOW] [APK-008] No network security config — cleartext defaults apply

  [+] Report saved: apkseeker_report.txt
  Exit code: 1 (findings, no Critical)
```

What the scan proved, and what it caught:

- **The parser reads a real production manifest.** 59,992 bytes,
  UTF-16 string pool, 19 components, 7 permissions — all parsed
  with no error and no crash. Androguard 4.1.4 agrees on all 7
  permissions, all 19 components (11 activities, 2 services,
  3 receivers, 2 providers), the package, version name/code,
  minSdk 21 and targetSdk 35 (Step 9 runs this oracle on the real
  APK too, when it is present).
- **Multi-dex works.** Both `classes.dex` and `classes2.dex` are
  secret-scanned. Markor has 0 secret hits — a real open-source app
  ships no baked-in keys, which is exactly the expected result, and
  the scan still read every byte of both dex files to confirm it.
- **A real bug, found and fixed.** The first run flagged three
  deep links: `markor://`, `content://` and `file://`. The last two
  are wrong: `content` and `file` are Android system data schemes
  — the standard VIEW open-file flow every document editor
  declares — not app deep links. Flagging them would fire on
  nearly every real file-handling app. v1.2 lists them in the
  deep-links table but no longer fires APK-007 for them; only the
  genuine custom scheme `markor://` is flagged. The lab bad APK
  still reports its 20 findings, unchanged.
- **The findings themselves are plausible, not alarming.** A notes
  app asking for storage permissions, exporting its editor
  activities, and allowing backup is normal for what it does — the
  report is a list of questions for the developer (why is
  `SettingsActivity` exported with no guard?), not a verdict that
  the app is malicious. The one guarded export
  (`ProfileInstallReceiver`, guarded by `android.permission.DUMP`)
  correctly scores Medium, not High.

## The sample report

`sample_report.txt` (and `sample_report.json`) in this repo are the
full saved reports from the bad APK — every entry, permission,
component, flag, deep link, native library, secret hit and finding,
with evidence and a fix for each. Regenerate them with:

```bash
python3 apkseeker.py test_apks/test_bad.apk -o sample_report.txt
python3 apkseeker.py test_apks/test_bad.apk -o sample_report.json --json
```
