# APKSeeker — Research: Similar Tools on the Internet / GitHub

Researched Wed 2026-11-25, before building. Sources are the web searches run
that day; claims below come only from those results and the tools' own pages.

## Name check (GitHub, search_repositories, `in:name`)

The PDF's name **APKScan is TAKEN** (same name, same domain):
- `LucasFaudman/apkscan` — "Scan for secrets, endpoints, and other sensitive
  data after decompiling and deobfuscating Android files" (312 stars, PyPI
  `apkscan` v0.4.0, MIT). It decompiles with JADX / APKTool / CFR / Procyon /
  Krakatau / Fernflower (via enjarify-adapter) and scans with JSON secret-locator
  rules. There is also a Docker image `devrvk/apkscan-docker` (Semgrep + JADX).

First batch of alternatives — ALL taken in the same/adjacent domain:
- APKLens (6) — incl. a zero-dependency APK static-analysis skill and an
  offline Android inspection CLI; DroidLens (16) — incl. `Pha4tom/DroidLens`,
  an on-device APK analyzer/decompiler with custom AXML/ARSC parsing;
  APKProbe (4) — incl. an Android APK static security analyzer and an APK
  decompiler + secrets scanner; DroidScope (14) — incl. `decaf-project/
  Droidscope`, a dynamic analysis platform for Android; ManifestLens (4).

Second batch — **FREE (0 results): APKSeeker, DroidXray**. Taken: DexLens (9),
APKHound (1 — APK binary tool), DroidScan (11), ApkEye (1), DexSeeker (1).

## 1. MobSF — Mobile Security Framework (the big one)

- All-in-one automated static + dynamic analysis for Android, iOS and Windows
  apps, from binaries or source. Static: permissions, exported components,
  insecure crypto and network config, hardcoded secrets — surfaced in a web UI
  with a REST API. Dynamic module captures app HTTP traffic.
- v4.6.4 (31 Oct 2026), GPL-3.0, Docker: `opensecurity/
  mobile-security-framework-mobsf`. The most common first pass for a full
  assessment.
- Limits: a heavy server (Docker, web UI, database) — not a small CLI; needs a
  server and a browser; it is a framework, not a tool you run with one command
  on a file.
- What APKSeeker takes from it: the finding set (permissions, exported
  components, secrets, network config) and the severity-per-issue report.
  What APKSeeker does differently: a single small Python CLI, zero dependencies,
  no server, no Docker, no Java — and it parses the binary manifest by hand
  instead of delegating to a framework.

## 2. Androguard — Python analysis of APKs and DEX

- Python library + CLI to parse DEX/APK graphs, list permissions and exported
  components, and script custom static checks. v4.1.4 (5 June 2026), Apache-2.0.
  "The foundation many other tools build on."
- Limits: a library you program against, not a ready findings report; needs
  installing (`pip install androguard`) with its own dependencies; it does the
  parsing for you, which is exactly the skill the PDF wants the student to
  learn by hand.
- What APKSeeker takes from it: the same parsing targets (manifest, dex, ARSC).
  What APKSeeker does differently: hand-written AXML parser (stdlib only), a
  ready report with severity, and a menu — no library to learn first.
- Test-only role: Androguard can serve as an independent oracle in the test
  suite (parse the fixture APK with it and compare against our parser's output).

## 3. jadx — DEX-to-Java decompiler

- Decompiles DEX bytecode into readable Java, GUI + CLI, with a deobfuscator.
  v1.5.6 (10 July 2026), Apache-2.0, ~49k stars. "The fastest way to read what
  a method does."
- Limits: Java tool (needs a JRE); it decompiles code, it does not produce a
  security findings report; it does not parse the manifest into findings.
- What APKSeeker takes from it: nothing structural — decompilation is out of
  scope for this PDF (the secret scan reads dex bytes directly).

## 4. Apktool — decode resources and manifest, rebuild

- Decodes resources and AndroidManifest.xml into near-original form, exposes
  smali/baksmali bytecode, and rebuilds the APK after modification. v3.0.3
  (20 July 2026), Apache-2.0, 25,935 stars. The tool for inspecting resources,
  layouts and assets, or patching an app in a lab.
- Limits: Java tool; a decoder/rebuilder, not a findings scanner; no severity,
  no secret scan, no report.
- What APKSeeker takes from it: the idea that the manifest and resources are
  decodable to a readable form — APKSeeker rebuilds the manifest structure
  in-memory and reports from it.

## 5. apkleaks (dwisiswant0/apkleaks, 6,353 stars)

- Scanning APK file for URIs, endpoints & secrets.
- Limits: secret/endpoint scanning only — no manifest parsing, no permissions,
  no exported components, no flags/SDK, no report with severity.
- What APKSeeker takes from it: the secret-pattern idea (URIs, endpoints, keys).
  What APKSeeker does differently: the full manifest analysis around the secret
  scan, plus severity and a saved report.

## 6. Quark-Engine — obfuscation-aware scoring

- Matches an app's call graph against suspicious-behaviour rules (crypto
  misuse, dynamic dex loading, C2 calls) with confidence scores. Has its own
  `AxmlReader` that parses binary AXML (string pool, then start-element
  records) into an ElementTree — the same two-step parse the PDF requires.
- Limits: a scoring engine with its own rule set and backends (Rizin/Radare2
  for one backend); heavy for a student tool; it scores behaviour, it does not
  do the manifest-findings report the PDF asks for.
- What APKSeeker takes from it: the AXML chunk-walking approach and the
  confidence that a pure-Python AXML reader is a proven design.

## 7. pyaxml — AXML parse/write library

- Rust implementation with a Python wrapper (`pyaxml`): `axml2xml` (decode a
  binary AXML or a manifest from an APK), `xml2axml` (encode back), `arsc2xml`.
  Also exposes the string pool as JSON.
- Limits: a library/CLI for converting AXML, not a security scanner; needs a
  compiled Rust extension (maturin/PyO3 wheels).
- What APKSeeker takes from it: the format knowledge (its commands prove the
  round-trip is well understood). What APKSeeker does differently: parse + assess
  in one zero-dependency tool.

## 8. apkanalyzer / aapt2 / Android Studio APK Analyzer

- Official CLI (and Android Studio GUI) for inspecting APK contents, manifest,
  DEX and resource size. `aapt2 dump xmltree` / `apkanalyzer manifest` show the
  manifest; the Studio analyzer shows entries and sizes.
- Limits: part of the Android SDK (needs Android Studio / build-tools
  installed); inspection only, no findings, no severity, no secret scan.
- What APKSeeker takes from it: the inspection surface (entries, sizes,
  manifest tree) as the baseline every analyzer shows.

## 9. Frida / objection / ANY.RUN / VirusTotal / Droidwatch

- Frida: runtime instrumentation (hooks methods, bypasses pinning/root
  detection) — dynamic, needs a device/emulator. objection: runtime exploration
  built on Frida. ANY.RUN: interactive Android sandbox (since Mar 2025).
  VirusTotal: multi-engine reputation ("has anyone seen this file?").
  Droidwatch: hosted static analysis report without executing the sample.
- All out of scope for this PDF: the tool is STATIC analysis of a file, no
  device, no execution, no hosted service.

## Comparison table

| Tool | Manifest parse (hand) | Permissions + dangerous | Exported comps | Flags + SDK | Secret scan | Deep links | .so list | Cleartext | Report + severity | Zero-dep CLI | Needs Java/Docker |
|---|---|---|---|---|---|---|---|---|---|---|---|
| MobSF | yes (framework) | yes | yes | yes | yes | yes | yes | yes | yes (web UI) | no | yes (Docker) |
| Androguard | yes (library) | yes | yes | yes | via scripts | via scripts | yes | no | no | no | no |
| jadx | no (decompile) | no | no | no | no | no | no | no | no | no | yes (Java) |
| Apktool | yes (decode) | no | no | no | no | no | no | no | no | no | yes (Java) |
| apkleaks | no | no | no | no | yes | no | no | no | no | yes | no |
| APKscan (LucasFaudman) | no (decompiles) | no | no | no | yes | no | no | no | yes | no | yes (decompilers) |
| Quark-Engine | yes (AxmlReader) | partial | no | no | no | no | no | no | scores | no | optional |
| pyaxml | yes (convert) | no | no | no | no | no | no | no | no | no | no (Rust ext) |
| **APKSeeker (planned)** | **yes (own parser)** | **yes** | **yes** | **yes** | **yes** | **yes** | **yes** | **yes** | **yes (text+JSON)** | **yes** | **no** |

## What APKSeeker adds over everything found

1. **Hand-written binary-manifest parser, zero dependencies** — string pool +
   start-element records in pure Python stdlib, the exact skill the PDF grades.
   No Androguard, no Java, no Docker, no decompiler to install.
2. **Manifest findings + secret scan in one small CLI** — permissions (with
   dangerous classification), exported components (with the intent-filter
   rule), debuggable/allow-backup/SDK flags, and a dex/resource secret scan,
   each finding with severity, in one report.
3. **All three stretch items in v1.0** — deep-link schemes, native .so listing
   by architecture, cleartext-traffic assessment from the network security
   config.
4. **Menu + full CLI + text/JSON reports** — same interface family as
   SSTIProbe / RBACLens / PipeSentry / MemSeeker.
5. **Cross-platform** — pure Python, runs on Windows, macOS and Linux with no
   native tools (per the user's standing rule for these tools).
6. **Lab-built test APK** — the fixture APK is built by a generator script in
   the repo (hand-written AXML builder + minimal dex), so no Android Studio
   is needed to test; Androguard (test-only) cross-checks the parser.
