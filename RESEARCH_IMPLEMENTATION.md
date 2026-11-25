# APKSeeker — Research: How to Implement It

Design notes from the research (Wed 2026-11-25). Format facts come from the
AXML sources found in the searches (Quark-Engine AxmlReader docs, pyaxml,
the F-Droid manifest parser notes) and Android's `ResourceTypes.h` layout.

## 1. An APK is a ZIP

- Open with stdlib `zipfile`. List every entry with `ZipInfo.filename`,
  `compress_size`, `file_size`. Locate `AndroidManifest.xml` and `classes*.dex`.
- Entries to scan for secrets: every `classes*.dex`, `resources.arsc`, and
  `assets/` + `res/` bytes (decompressed). Report each hit with entry name +
  offset inside that entry.
- A file that is not a ZIP, or a ZIP with no `AndroidManifest.xml`, is a clean
  error, not a traceback.

## 2. Binary AndroidManifest.xml (AXML) — the format

The file is a sequence of chunks. Every chunk starts with `ResChunk_header`:
`type` u16 LE, `headerSize` u16 LE, `size` u32 LE. Walk chunks by `size`;
never trust a size that runs past the end of the data (attacker-supplied
input — a malformed chunk is a clean error, per the F-Droid parser's
defensive rule).

Chunk types (from `ResourceTypes.h`):
- `0x0001` RES_STRING_POOL_TYPE — the string pool
- `0x0002` RES_TABLE_TYPE — resource table (not needed here)
- `0x0003` RES_XML_TYPE — the file header itself
- `0x0180` RES_XML_RESOURCE_MAP_TYPE — pool index → resource id map (skip it;
  attribute names are matched by their pool string, not by resource id)
- `0x0100` START_NAMESPACE / `0x0101` END_NAMESPACE — skip
- `0x0102` START_ELEMENT / `0x0103` END_ELEMENT
- `0x0104` CDATA — skip

### String pool
Header after the chunk header: `stringCount` u32, `styleCount` u32,
`flags` u32, `stringsStart` u32, `stylesStart` u32; then `stringCount` × u32
offsets (relative to `stringsStart`); then the string data.
- `flags & 0x100` (UTF8_FLAG) picks the encoding. AAPT2 emits UTF-8 for most
  resources but manifests are usually UTF-16 — support BOTH.
- UTF-16 string: u16 char-length, that many UTF-16LE code units, u16 null.
- UTF-8 string: length encoded in 1–2 bytes (char count, then byte count),
  then the bytes, then a null byte. (Two length prefixes; read both.)
- A pool index of `0xFFFFFFFF` means "absent" — resolve to None, never crash.

### Start element
`ResXMLTree_node`: `lineNumber` u32, `comment` u32 (a pool index or absent).
Then `ResXMLTree_attrExt`: `ns` u32, `name` u32 (pool indices),
`attributeStart` u16, `attributeSize` u16, `attributeCount` u16,
`idIndex` u16, `classIndex` u16, `styleIndex` u16.
Then `attributeCount` × `ResXMLTree_attribute`: `ns` u32, `name` u32,
`rawValue` u32, `size` u16, `res0` u8, `dataType` u8, `data` u32.
Resolve an attribute's value by `dataType`:
- `0x03` TYPE_STRING — `data` is a string-pool index.
- `0x10` TYPE_INT_DEC — `data` is the integer.
- `0x11` TYPE_INT_HEX — `data` is the integer (print as hex).
- `0x12` TYPE_INT_BOOLEAN — non-zero is true.
- `0x01` TYPE_REFERENCE — `data` is a resource id (`@0x…`); not resolvable
  without `resources.arsc` — report the raw `@0x…` value and say so.
- Any other type — report the raw value, never crash.
Rebuild a tree: START_ELEMENT pushes, END_ELEMENT pops; keep the element's
namespace-stripped name, its attributes (dict name → typed value), and its
children. The manifest root is `<manifest>` with `package`, `versionCode`,
`versionName`; inside it: `<uses-sdk>`, `<uses-permission>` /
`<uses-permission-sdk-23>` / `<uses-permission-sdk-m>`, `<application>` with
`<activity>` / `<activity-alias>` / `<service>` / `<receiver>` / `<provider>`
children, each possibly holding `<intent-filter>` with `<action>`, `<category>`
and `<data android:scheme/host/path>` children.

## 3. Permissions — dangerous classification

Ship a curated dangerous-permission set (Android `dangerous` protection level):
- Location: `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION`,
  `ACCESS_BACKGROUND_LOCATION`
- Camera: `CAMERA`
- Contacts: `READ_CONTACTS`, `WRITE_CONTACTS`, `GET_ACCOUNTS`
- SMS: `SEND_SMS`, `READ_SMS`, `RECEIVE_SMS`, `RECEIVE_WAP_PUSH`, `RECEIVE_MMS`
- Storage: `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`,
  `MANAGE_EXTERNAL_STORAGE`, `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`,
  `READ_MEDIA_AUDIO`
- Microphone: `RECORD_AUDIO`
- Phone: `READ_PHONE_STATE`, `READ_PHONE_NUMBERS`, `CALL_PHONE`,
  `READ_CALL_LOG`, `WRITE_CALL_LOG`, `PROCESS_OUTGOING_CALLS`
- Calendar: `READ_CALENDAR`, `WRITE_CALENDAR`
- Sensors: `BODY_SENSORS`, `ACTIVITY_RECOGNITION`
- Bluetooth/nearby: `BLUETOOTH_CONNECT`, `BLUETOOTH_SCAN`, `NEARBY_WIFI_DEVICES`
- Notifications: `POST_NOTIFICATIONS`
Everything else is reported as normal (or "unknown/other" when it matches no
known list — never call an unknown permission safe or dangerous by guessing).
Severity: each dangerous permission is a finding (Medium; High when several
dangerous permissions combine — e.g. location + SMS + contacts together is
worth one extra High "broad dangerous permission set" note, or keep it simple:
one finding per dangerous permission at Medium, and location/SMS at High).
Keep the mapping in one dict so it is easy to extend.

## 4. Exported components — the rule

For each of `activity`, `activity-alias`, `service`, `receiver`, `provider`:
- `android:exported="true"` → exported.
- An `<intent-filter>` child exists AND `android:exported` is not `"false"`
  → exported (Android 12+ requires an explicit `exported` when a filter
  exists; older apps default to true when a filter exists — the PDF's rule).
- No filter and no `exported` → not exported.
- `android:exported="false"` → not exported, even with a filter.
Severity: exported component is High when it has no `android:permission`
protection (any app can reach it); Medium when a permission guards it.
Report component name (the `android:name` attribute), type, and the reason
it counts as exported (explicit true / filter without false).

## 5. Flags and SDK versions

- `<application android:debuggable="true">` → High finding (a debuggable app
  can be attached to and inspected on a device). Default false.
- `<application android:allowBackup="true">` → Medium finding (app data can
  be pulled off with `adb backup`). NOTE: the Android default is TRUE when the
  attribute is absent — report "not set (defaults to true)" as a finding too,
  and say so explicitly.
- `<uses-sdk android:minSdkVersion="…" android:targetSdkVersion="…">` —
  integers. Report both. Flag targetSdkVersion below 30 (Android 11) as Medium
  ("old target SDK — misses newer platform protections"); below 26 as High.
  Also flag `android:targetSdkVersion` missing entirely.
- Also report `<application android:usesCleartextTraffic="true">` here
  (Medium; it belongs with the cleartext assessment in §8).

## 6. Secret-pattern scan

Patterns (regex, each with a name + severity), run over the decompressed bytes
of every `classes*.dex`, `resources.arsc`, `assets/*` and `res/*` entry:
- Google API key `AIza[0-9A-Za-z_-]{35}` (High)
- AWS access key `AKIA[0-9A-Z]{16}` (High)
- Generic API key assignments `(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][0-9A-Za-z_\-]{16,}['"]` (High)
- Private key material `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----` (Critical)
- Password assignment `(?i)(password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]` (High)
- Bearer/token `(?i)(bearer|token)\s+['"]?[0-9A-Za-z_\-\.]{16,}` (Medium)
- Private URLs: `https?://(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)[^\s'"]+`
  and `https?://[a-z0-9\-]+\.(internal|local|corp|lan)\b[^\s'"]*` (Medium)
- Hardcoded IP `https?://\d{1,3}(\.\d{1,3}){3}(:\d+)?[^\s'"]*` (Low)
Report each hit with entry name, offset, the matched text (truncated, and
NEVER print a full private key — truncate secrets to the first 8 chars +
"…"), and the pattern name. A planted fake key must be found; removing it
must silence the rule (PDF Step 6 test).

## 7. Stretch items

- **Deep links:** from each exported activity's intent filters, collect
  `<data android:scheme="…">` (+ host/path). Report each scheme; flag a custom
  scheme on an exported activity with no permission as Medium ("unprotected
  deep link — any app can open it"). `http`/`https` schemes are normal.
- **Native libraries:** every `lib/<abi>/*.so` entry, grouped by ABI folder
  (`armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`, `armeabi`). Report the count
  per ABI and the file list. (No disassembly — listing only.)
- **Cleartext traffic:** parse `res/xml/network_security_config.xml` with the
  SAME AXML parser (it is binary AXML in a built APK). Report
  `<base-config cleartextTrafficPermitted="true">` (High),
  `<domain-config cleartextTrafficPermitted="true">` per domain (High),
  `<certificates src="user">` (Medium — user CAs trusted), and the absence of
  a config file together with `usesCleartextTraffic` not false (Low note:
  "no network security config — cleartext defaults apply"). If the config file
  is absent entirely, say so and assess from the application attribute only.

## 8. Test APK — no Android Studio here

This VM has no Android Studio and no Android SDK. Build the fixture APK with
a generator script (`build_test_apk.py`) in the repo:
- **AXML writer (the inverse of the parser):** takes a small element tree
  (dicts) and writes a binary manifest — string pool first (UTF-16, deduped
  strings, offsets), then a resource-map chunk (optional; write it — the
  parser must skip it), then start/end element chunks with typed attribute
  values (string / int / boolean). The parser is tested by ROUND-TRIP:
  build manifest from a source tree → parse → compare element names,
  attributes and structure with the source.
- **Minimal classes.dex:** hand-built dex — magic `dex\n035\0`, header
  (checksum, signature, file_size, header_size=0x70, endian_tag, string_ids
  size/off, type/proto/field/method/class counts 0, data size/off), a string
  pool holding the planted secret strings, and the string data section. The
  secret scanner reads bytes, so the dex only needs the strings present; the
  header makes it structurally a dex. (Do NOT claim it is a runnable dex.)
- **Two fixtures:** `test_bad.apk` (dangerous permissions incl. location +
  SMS + camera, one exported + one non-exported activity, debuggable true,
  allowBackup true, old targetSdk 28, a planted fake API key + a private URL
  in the dex, a custom deep-link scheme, one .so per ABI folder, a network
  security config permitting cleartext) and `test_clean.apk` (one normal
  permission, no exported components, debuggable false, allowBackup false,
  targetSdk 34, no secrets, no .so, no cleartext). Also a `test_minimal.apk`
  (manifest only, no dex) to prove the scanner handles a missing dex.
- **Independent oracle (test-only):** `pip install androguard` in a test venv
  and cross-check the parser's permissions/components/flags on the fixture
  APK against Androguard's output. If Androguard cannot be installed here,
  the round-trip test is the oracle — say so in the report, do not fake it.

## 9. Interface (same family as SSTIProbe / RBACLens / PipeSentry / MemSeeker)

- TraceRecon colour class + clear/sep/header/ok/warn/err/info helpers,
  LEGAL DISCLAIMER + box in the banner, Gobuster-style SCAN config block,
  numbered menu with `[?] Select option:` prompt, `--batch`, `-q`, `--version`,
  `--no-color`, `-i/--interactive/--menu`.
- CLI: `apkseeker.py <apk> [-o/--output report] [--json] [--list] [--manifest]
  [--min-severity {critical,high,medium,low}] [--fail-on {critical,high,medium,low,none}]
  [--check] [--skip-check] [--list-checks] [-q/--quiet] [--batch]
  [-i/--interactive/--menu] [--version] [--no-color]`.
  Exit codes: 0 clean, 1 findings, 2 any Critical (or --fail-on hit).
  Severity per finding (Critical/High/Medium/Low) — NO score/grade (the PDF
  does not ask for one; follow the PDF).
- Menu: [1] Scan an APK [2] Quick scan test APK (bad) [3] Quick scan clean APK
  [4] List archive entries [5] Show rebuilt manifest [6] List all checks
  [7] Run step tests [8] Check setup (doctor) [0] Exit.
- `run.py` launcher (venv auto-create + install; commands: setup, scan, test,
  doctor, build-apk (regenerates the fixtures), menu) + `run.bat` (Windows —
  must actually run the tool) + `run.sh`. requirements.txt: stdlib only
  (empty/comment-only). Cross-platform: pure Python, Windows/macOS/Linux.
- Author "CyberBoy50" ONLY everywhere in the tool and docs — no real names
  anywhere (student Jasia Jabeen and instructor Abdul Mannan go only in the
  REPORT document, like the other tools).
- Finding codes (family pattern): APK-001 dangerous permission, APK-002
  exported component, APK-003 debuggable, APK-004 allowBackup, APK-005 old
  target SDK, APK-006 hardcoded secret, APK-007 unprotected deep link,
  APK-008 cleartext traffic, APK-009 native library note (info-level, not a
  finding — list it, don't score it).
