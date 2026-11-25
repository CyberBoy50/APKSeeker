# APKSeeker — Android APK Static Analyzer

**APKSeeker** is a cross-platform Python CLI tool that opens an Android
APK (it is just a ZIP file) and audits it statically — no emulator, no
Android SDK, no device needed. It parses the binary
`AndroidManifest.xml` by hand, flags dangerous permissions and exported
components, checks the build flags and target SDK, hunts for hardcoded
secrets in the dex and resources, and reads the network security
config. Everything is read-only: the APK is never modified and nothing
is executed.

- **Author:** CyberBoy50
- **Version:** 1.2
- **Platform:** Windows, macOS and Linux (pure Python, standard
  library only)
- **Dependencies:** none — Python 3.8+ standard library only

## What it does

You give it an APK:

```
python3 apkseeker.py app.apk
```

It then:

1. **Lists the archive** — every entry with its compressed and
   uncompressed size (Step 1).
2. **Parses the binary manifest** — a hand-written AXML parser that
   reads the string pool first (UTF-8 and UTF-16), then the
   start-element records, rebuilding the full element tree with typed
   attribute values (string, int, hex, boolean, reference). The
   resource-map chunk is skipped, and a malformed file is a clean
   error, never a traceback (Step 2, Step 3).
3. **Flags dangerous permissions** — every `uses-permission` is listed
   and checked against a curated dangerous set (location, camera,
   contacts, SMS, storage, microphone, phone, calendar, sensors,
   bluetooth/nearby, notifications). Unknown permissions are reported
   as normal — never guessed (Step 4).
4. **Classifies exported components** — every activity,
   activity-alias, service, receiver and provider: `exported=true` is
   exported; an intent-filter child with `exported` not set to
   `"false"` is exported; `exported="false"` is not exported.
   Severity is High when no `android:permission` guards it, Medium
   when one does (Step 4).
5. **Checks flags and SDK** — `android:debuggable` (High when true),
   `android:allowBackup` (Medium when true — and when the attribute is
   absent, because the Android default is true), `minSdkVersion` and
   `targetSdkVersion` (Medium below 30, High below 26 or missing)
   (Step 5).
6. **Scans for hardcoded secrets** — the decompressed dex, resource
   table and asset bytes are scanned for Google API keys, AWS keys,
   generic api-key assignments, private-key material (Critical),
   password assignments, bearer/token values and private URLs/IPs.
   A matched secret is never printed in full — only its first 8
   characters plus "…" (Step 6).
7. **Stretch checks** — deep-link schemes on exported activities
   (Step 8), every native library grouped by ABI (Step 8), and a
   cleartext assessment from the network security config, parsed with
   the same AXML parser, plus the `usesCleartextTraffic` attribute
   (Step 8).

Findings carry a code (APK-001…APK-009), a severity
(Critical/High/Medium/Low), evidence, a location and a fix. There is
no score or grade — the project spec does not ask for one; the report
is the result.

## The checks

| Code | What it flags | Severity |
|------|---------------|----------|
| APK-001 | Dangerous permission declared | High (Location, SMS) / Medium (rest) |
| APK-002 | Exported component | High unguarded / Medium guarded |
| APK-003 | Application is debuggable | High |
| APK-004 | Application allows backup | Medium |
| APK-005 | Old target SDK (< 30) | Medium (< 30) / High (< 26 or missing) |
| APK-006 | Hardcoded secret in dex / resources | Critical (private key) / High (keys, passwords) / Medium (private URL) / Low (private IP) |
| APK-007 | Unprotected deep link | Medium |
| APK-008 | Cleartext traffic permitted | High (base/domain config) / Medium (user certs, usesCleartextTraffic) / Low (no config at all) |
| APK-009 | Native libraries present | Info only — a listing, not a finding |

## How the binary manifest is parsed

An APK's `AndroidManifest.xml` is not XML text — it is a binary format
(AXML). The file starts with a file header, then a string pool, then
namespace and element chunks:

```
file header (type 0x0003)
  string pool (0x0001) — deduped strings, UTF-8 (flag 0x100) or UTF-16
  resource map (0x0180) — skipped, never trusted
  start namespace (0x0100) / end namespace (0x0101)
  start element (0x0102) — ns, name, attribute records
  end element (0x0103)
  character data (0x0104)
```

The parser reads the pool first, because every element name, attribute
name and string value is an index into it. Each attribute record is 20
bytes: namespace index, name index, raw value, size (8), reserved,
data type, data. The data type decides how the value is read:

| Type | Value | Meaning |
|------|-------|---------|
| 0x03 | string index | text from the pool |
| 0x10 | int | decimal integer |
| 0x11 | int | hexadecimal integer |
| 0x12 | 0 / 1 | boolean |
| 0x01 | int | resource reference, reported raw as `@0x…` |

Defensive parsing throughout: no chunk size is trusted past the end of
the data, every offset is bounds-checked, and a truncated or corrupt
file raises a clean `APKSeekerError` ("Malformed AXML: …") instead of a
traceback. The same parser reads `res/xml/network_security_config.xml`,
so the cleartext assessment uses one code path, not two.

## How to run it

No installation is needed — the tool is standard library only.

```bash
# Direct
python3 apkseeker.py app.apk

# With the launcher (creates a venv on first use)
python3 run.py setup
python3 run.py scan app.apk

# Windows
run.bat setup
run.bat scan app.apk

# macOS / Linux
./run.sh setup
./run.sh scan app.apk
```

### CLI

```
apkseeker.py <apk> [-o/--output report] [--json] [--list] [--manifest]
                   [--min-severity {critical,high,medium,low}]
                   [--fail-on {critical,high,medium,low,none}]
                   [--check] [--skip-check] [--list-checks]
                   [-q/--quiet] [--batch] [-i/--interactive/--menu]
                   [--version] [--no-color]
```

- `--list` — list the archive entries instead of scanning.
- `--manifest` — print the rebuilt manifest as XML.
- `--json` — write the report as JSON instead of text.
- `--min-severity high` — only show findings at that severity or above.
- `--fail-on medium` — exit 2 when a finding at that severity or
  above appears (default: exit 2 on any Critical).
- `--batch` — skip the "Press enter" pause (for scripts and CI).
- `--check` — doctor: check the setup and the test fixtures.
- `--list-checks` — print the nine checks with their severities.

Exit codes: `0` clean, `1` findings, `2` any Critical finding, a
`--fail-on` hit, or an unusable input file (not a ZIP, no manifest,
malformed AXML).

### Menu

Run with no arguments (or `-i` / `--menu`):

```
[1] Scan an APK
[2] Quick scan test APK (bad)
[3] Quick scan clean APK
[4] List archive entries
[5] Show rebuilt manifest
[6] List all checks
[7] Run step tests
[8] Check setup (doctor)
[0] Exit
```

## Real-world scan: Markor from F-Droid

v1.2 scanned a real production APK for the first time: **Markor**
(`net.gsantner.markor` 2026.10.0, versionCode 164), an open-source
notes app downloaded from F-Droid — 1,732 entries, 12 MB, two dex
files (`classes.dex` + `classes2.dex`), a 59,992-byte UTF-16-pool
manifest. Result: **17 findings (0 Critical, 10 High, 6 Medium,
1 Low)** in about 12 seconds — 3 dangerous storage permissions,
11 exported components (10 unguarded), 1 unprotected deep link
(`markor://`), `allowBackup` true, no network security config, and
0 secret hits. Androguard 4.1.4 agrees on all 7 permissions, all 19
components, the package, version, minSdk 21 and targetSdk 35. Full
results in `DEMO.md` and `real_apk_scan.json`; reproduce it with:

```
curl -o test_apks/markor_164.apk https://f-droid.org/repo/net.gsantner.markor_164.apk
python3 apkseeker.py test_apks/markor_164.apk
```

The APK itself is **not** in this repo (12 MB binary) — only the
recorded results are. That scan also fixed a real bug: `content://`
and `file://` were flagged as unprotected deep links, but they are
Android system data schemes (the standard VIEW open-file flow), not
app deep links — they are now listed, not flagged. Only a custom
scheme on an exported activity fires APK-007.

## Test APKs (no Android Studio needed)

There is no Android SDK on this machine, so the fixtures are built by
`build_test_apk.py` — a hand-written AXML *writer* (the inverse of the
parser) plus a minimal `classes.dex` builder:

- `test_apks/test_bad.apk` — 8 entries: dangerous permissions
  (location, SMS, camera, contacts), an exported and a non-exported
  activity, `debuggable` + `allowBackup` true, `targetSdk` 28, a
  planted fake Google API key + private URL in the dex, a custom
  deep-link scheme, one `.so` per ABI, a network security config
  permitting cleartext. Expected: **20 findings (0 Critical, 11 High,
  9 Medium, 0 Low)**.
- `test_apks/test_clean.apk` — 3 entries: one normal permission, no
  exported components, `debuggable`/`allowBackup` false, `targetSdk`
  34, no secrets, no `.so`, no cleartext. Expected: **0 findings**.
- `test_apks/test_minimal.apk` — manifest only, no dex. The scanner
  must cope with a missing dex. Expected: 1 Low finding (no network
  security config — cleartext defaults apply).

Regenerate them any time:

```
python3 run.py build-apk
```

The fixtures are byte-for-byte reproducible: zip entry timestamps
are pinned, so two runs produce identical files (verified by Step 9,
which rebuilds them twice and compares hashes). That is why the
three binary `.apk` files are not in the GitHub push — the push
mechanism accepts UTF-8 text only, and the fixtures regenerate
exactly from the text sources in this repo. Anyone cloning the repo
runs one command and gets the identical fixtures.

## Files

| File | What it is |
|------|-----------|
| `apkseeker.py` | The tool — parser, checks, reports, CLI, menu |
| `build_test_apk.py` | AXML writer + minimal dex builder + fixture trees |
| `test_apkseeker.py` | Step tests (Steps 1–9) + CLI checks + Androguard oracle — 167 checks, all passing (153 without the real APK present; the 14 live re-scan/oracle checks skip with a note) |
| `real_apk_scan.json` | Recorded results of the first real-world scan (Markor from F-Droid) — the numbers Step 9 asserts |
| `run.py` / `run.bat` / `run.sh` | Cross-platform launchers |
| `requirements.txt` | Empty — standard library only |
| `test_apks/` | The three fixture APKs |
| `sample_report.txt` / `sample_report.json` | Sample reports from the bad APK |
| `RESEARCH_CLI_TOOLS.md` | Research: MobSF, Androguard, jadx, Apktool, apkleaks, Quark-Engine, pyaxml, apkanalyzer/aapt2 |
| `RESEARCH_IMPLEMENTATION.md` | Design: AXML layout, typed values, rules, test plan |

## Authorized use

APKSeeker is a **static analyzer for learning and authorized audit
work**. Scan only APKs you own, built yourself, or have written
permission to audit. The lab APKs here are built by the generator in
this repo and contain only fake secrets (`AIzaSyBFAKEKEY…`,
`AKIAIOSFODNN7EXAMPLE`) — they are markers, not real credentials.
Never upload a real app's APK to an untrusted service, and never treat
a clean report as proof an app is safe: static analysis sees what is
declared and what is baked in, not what the code does at runtime.

> DISCLAIMER — AUTHORIZED USE ONLY. This tool was built for ethical, authorized security testing only. You are using it on your own responsibility. The authors are not responsible for how you use it, or for anything that happens because of your use. Only test systems, code, and data you own or have explicit written permission to test — testing anything else may be illegal (for example, PECA 2016 in Pakistan).

The same disclaimer is printed in the banner on every run and written
into the header of every text report and the `disclaimer` field of
every JSON report.

## Author

CyberBoy50 — APKSeeker v1.2. Theme: green (default family theme; the
colour lives in one place, class `C` at the top of `apkseeker.py`).
