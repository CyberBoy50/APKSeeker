#!/usr/bin/env python3
"""APKSeeker step tests — one function per PDF build-plan step.

Step 1 — list the archive (entry names + sizes vs a manual listing)
Step 2 — parse the string pool (package + permission names in it)
Step 3 — rebuild the elements (round-trip vs the generator's tree)
Step 4 — permissions and components (exported vs non-exported)
Step 5 — flags and SDK versions (toggle each flag, report must change)
Step 6 — secret-pattern scan (planted key found; removed key silent)
Step 7 — CLI, report and full run (bad APK end to end, clean APK 0)
Step 8 — stretch: deep links, .so listing, cleartext assessment
Plus: CLI bits, malformed-input handling, UTF-8 pools, and the
Androguard oracle (test-only, skipped if Androguard is unavailable).

Run:  python3 test_apkseeker.py     (exit 0 when all checks pass)
       python run.py test
"""
import copy
import json
import os
import struct
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import apkseeker
import build_test_apk

BAD_APK = os.path.join(HERE, "test_apks", "test_bad.apk")
CLEAN_APK = os.path.join(HERE, "test_apks", "test_clean.apk")
MINIMAL_APK = os.path.join(HERE, "test_apks", "test_minimal.apk")

PASSED = 0
FAILED = 0
FAILURES = []


def check(name, condition, detail=""):
    """One check: count it, print it, remember failures."""
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print("  [PASS] %s" % name)
    else:
        FAILED += 1
        FAILURES.append(name)
        print("  [FAIL] %s%s" % (name, (" — " + detail) if detail else ""))


def step(title):
    print("\n== %s ==" % title)


def _manifest_bytes(apk_path):
    with zipfile.ZipFile(apk_path) as zf:
        return zf.read("AndroidManifest.xml")


def _pool_chunk(data):
    """Locate the string-pool chunk; returns (offset, size)."""
    off = 8
    while off < len(data):
        ctype, _h, size = struct.unpack_from("<HHI", data, off)
        if ctype == 0x0001:
            return off, size
        off += size
    raise AssertionError("no string pool chunk found")


def _expected_value(kind, value):
    """What the parser should return for one generator attribute."""
    if kind == "ref":
        return "@0x%08x" % value
    return value


def _tree_matches(parsed, source, path="root"):
    """Deep-compare a parsed Element tree with the generator's tree."""
    if parsed.name != source["name"]:
        return False, "%s: name %r != %r" % (path, parsed.name, source["name"])
    expected_attrs = {}
    for _ns, name, value in source.get("attrs", []):
        kind, val = value
        expected_attrs[name] = _expected_value(kind, val)
    if parsed.attrs != expected_attrs:
        return False, "%s: attrs %r != %r" % (path, parsed.attrs, expected_attrs)
    if (parsed.text or None) != (source.get("text") or None):
        return False, "%s: text %r != %r" % (
            path, parsed.text, source.get("text"))
    if len(parsed.children) != len(source.get("children", [])):
        return False, "%s: %d children != %d" % (
            path, len(parsed.children), len(source.get("children", [])))
    for i, (child, src_child) in enumerate(
            zip(parsed.children, source.get("children", []))):
        ok, why = _tree_matches(child, src_child, "%s/%s" % (path, src_child["name"]))
        if not ok:
            return False, why
    return True, ""


def _build_variant(manifest_tree, dex_strings=None, extra_entries=None,
                   name="variant.apk"):
    """Build a throwaway APK from a (possibly mutated) manifest tree."""
    tmp = tempfile.mkdtemp(prefix="apkseeker_test_")
    path = os.path.join(tmp, name)
    build_test_apk._write_apk(path, manifest_tree, dex_strings, extra_entries)
    return path


def _analyze(path):
    apk = apkseeker.load_apk(path)
    return apkseeker.analyze_apk(apk)


def _findings(analysis, code=None, severity=None):
    out = analysis.findings
    if code:
        out = [f for f in out if f.code == code]
    if severity:
        out = [f for f in out if f.severity == severity]
    return out


# --- Step 1: list the archive ----------------------------------------------
def test_step1():
    step("Step 1 — List the archive")
    apk = apkseeker.load_apk(BAD_APK)
    with zipfile.ZipFile(BAD_APK) as zf:
        infos = zf.infolist()
    check("entry count matches the zip listing",
          len(apk.entries) == len(infos),
          "%d vs %d" % (len(apk.entries), len(infos)))
    names_match = [e.name for e in apk.entries] == [i.filename for i in infos]
    check("entry names match, in order", names_match)
    sizes_match = all(
        e.file_size == i.file_size and e.compress_size == i.compress_size
        for e, i in zip(apk.entries, infos))
    check("compressed + uncompressed sizes match", sizes_match)
    check("manifest entry found", apk.entry("AndroidManifest.xml") is not None)
    check("classes.dex entry found", len(apk.dex_entries()) == 1)
    check("8 entries in the bad APK", len(apk.entries) == 8,
          str(len(apk.entries)))
    check("3 entries in the clean APK",
          len(apkseeker.load_apk(CLEAN_APK).entries) == 3)
    check("1 entry in the minimal APK",
          len(apkseeker.load_apk(MINIMAL_APK).entries) == 1)


# --- Step 2: parse the string pool ------------------------------------------
def test_step2():
    step("Step 2 — Parse the string pool")
    data = _manifest_bytes(BAD_APK)
    off, size = _pool_chunk(data)
    pool = apkseeker.parse_string_pool(data, off, size)
    check("pool is non-empty", len(pool) > 0, str(len(pool)))
    check("package name in the pool", "com.example.labapp" in pool)
    check("permission names in the pool",
          "android.permission.ACCESS_FINE_LOCATION" in pool
          and "android.permission.SEND_SMS" in pool)
    check("component names in the pool",
          ".MainActivity" in pool and ".ShareActivity" in pool)
    check("android namespace URI in the pool",
          "http://schemas.android.com/apk/res/android" in pool)
    check("pool decodes without replacement chars",
          all("\ufffd" not in s for s in pool))
    # UTF-8 pool branch: build a minimal UTF-8 AXML by hand and parse it.
    utf8_doc = _build_utf8_axml()
    root = apkseeker.parse_axml(utf8_doc)
    check("UTF-8 pool parses", root.name == "manifest")
    check("UTF-8 pool package value",
          root.attr("package") == "com.example.utf8",
          str(root.attr("package")))
    check("UTF-8 pool permission value",
          root.find_child("uses-permission").attr("name")
          == "android.permission.INTERNET")


def _build_utf8_axml():
    """A minimal AXML document with a UTF-8 string pool (test-only)."""
    strings = ["manifest", "package", "com.example.utf8",
               "uses-permission", "name", "android.permission.INTERNET"]
    index = {s: i for i, s in enumerate(strings)}

    def utf8_len(n):
        if n < 0x80:
            return bytes([n])
        return bytes([0x80 | (n >> 8), n & 0xFF])

    blobs, offsets, pos = [], [], 0
    for text in strings:
        offsets.append(pos)
        raw = text.encode("utf-8")
        blob = utf8_len(len(text)) + utf8_len(len(raw)) + raw + b"\x00"
        while len(blob) % 4:
            blob += b"\x00"
        blobs.append(blob)
        pos += len(blob)
    data = b"".join(blobs)
    count = len(strings)
    strings_start = 28 + 4 * count
    pool = struct.pack("<HHIIIIII", 0x0001, 28,
                       28 + 4 * count + len(data),
                       count, 0, 0x100, strings_start, 0)
    pool += b"".join(struct.pack("<I", o) for o in offsets) + data

    def start_elem(name, attrs):
        # attrs: [(name, type, data)] — type 0x03 string, 0x12 bool.
        body = struct.pack("<II", 0, 0xFFFFFFFF)
        body += struct.pack("<IIHHHHHH", 0xFFFFFFFF, index[name],
                            20, 20, len(attrs), 0xFFFF, 0xFFFF, 0xFFFF)
        for aname, atype, aval in attrs:
            raw = aval if atype == 0x03 else 0xFFFFFFFF
            body += struct.pack("<IIIHBBI", 0xFFFFFFFF, index[aname],
                                raw, 8, 0, atype, aval)
        # size = 8-byte chunk header + body (body already holds the
        # 8-byte node header: lineNumber + comment).
        return struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + body

    def end_elem(name):
        body = struct.pack("<II", 0, 0xFFFFFFFF)
        body += struct.pack("<II", 0xFFFFFFFF, index[name])
        return struct.pack("<HHI", 0x0103, 16, 8 + len(body)) + body

    body = pool
    body += start_elem("manifest", [("package", 0x03, index["com.example.utf8"])])
    body += start_elem("uses-permission",
                       [("name", 0x03, index["android.permission.INTERNET"])])
    body += end_elem("uses-permission")
    body += end_elem("manifest")
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


# --- Step 3: rebuild the elements -------------------------------------------
def test_step3():
    step("Step 3 — Rebuild the elements (round-trip)")
    apk = apkseeker.load_apk(BAD_APK)
    ok, why = _tree_matches(apk.manifest, build_test_apk.BAD_MANIFEST)
    check("bad manifest round-trips exactly", ok, why)
    apk2 = apkseeker.load_apk(CLEAN_APK)
    ok, why = _tree_matches(apk2.manifest, build_test_apk.CLEAN_MANIFEST)
    check("clean manifest round-trips exactly", ok, why)
    apk3 = apkseeker.load_apk(MINIMAL_APK)
    ok, why = _tree_matches(apk3.manifest, build_test_apk.MINIMAL_MANIFEST)
    check("minimal manifest round-trips exactly", ok, why)
    # The network security config (a second AXML file) round-trips too.
    config = apk.config
    ok, why = _tree_matches(config, build_test_apk.BAD_CONFIG)
    check("network security config round-trips exactly", ok, why)
    check("config domain text captured",
          config.find_all("domain")[0].text == "api.example.com")
    # The resource-map chunk was skipped, not misread.
    check("reference attribute resolved as @0x…",
          apk.manifest.find_child("application").attr("icon") == "@0x7f020000")
    # Rebuilt XML text contains every element name.
    xml = apkseeker.element_to_xml(apk.manifest)
    for name in ("manifest", "uses-sdk", "uses-permission", "application",
                 "activity", "intent-filter", "service", "receiver",
                 "provider"):
        check("rebuilt XML contains <%s>" % name, "<%s" % name in xml)


# --- Step 4: permissions and components --------------------------------------
def test_step4():
    step("Step 4 — Permissions and components")
    analysis = _analyze(BAD_APK)
    perms = dict((n, (d, g)) for n, d, g in analysis.permissions)
    check("6 permissions extracted", len(analysis.permissions) == 6,
          str(len(analysis.permissions)))
    check("INTERNET is normal",
          perms["android.permission.INTERNET"] == (False, "normal"))
    check("FINE_LOCATION is dangerous (Location)",
          perms["android.permission.ACCESS_FINE_LOCATION"]
          == (True, "Location"))
    check("CAMERA is dangerous (Camera)",
          perms["android.permission.CAMERA"] == (True, "Camera"))
    check("SEND_SMS is dangerous (SMS)",
          perms["android.permission.SEND_SMS"] == (True, "SMS"))
    check("4 APK-001 findings", len(_findings(analysis, "APK-001")) == 4)
    check("location + SMS findings are High",
          sorted(f.severity for f in _findings(analysis, "APK-001"))
          == ["high", "high", "medium", "medium"])
    comps = dict(((c["type"], c["name"]), c) for c in analysis.components)
    check("6 components found", len(analysis.components) == 6,
          str(len(analysis.components)))
    check("MainActivity exported (explicit true)",
          comps[("activity", ".MainActivity")]["exported"] is True)
    check("ShareActivity exported (filter, no false)",
          comps[("activity", ".ShareActivity")]["exported"] is True)
    check("SecretActivity NOT exported (explicit false)",
          comps[("activity", ".SecretActivity")]["exported"] is False)
    check("SyncService NOT exported",
          comps[("service", ".SyncService")]["exported"] is False)
    check("BootReceiver exported but guarded",
          comps[("receiver", ".BootReceiver")]["exported"] is True
          and comps[("receiver", ".BootReceiver")]["permission"]
          == "android.permission.RECEIVE_BOOT_COMPLETED")
    check("LabProvider NOT exported",
          comps[("provider", ".LabProvider")]["exported"] is False)
    check("3 APK-002 findings", len(_findings(analysis, "APK-002")) == 3)
    check("unguarded exported components are High",
          sorted(f.severity for f in _findings(analysis, "APK-002"))
          == ["high", "high", "medium"])


# --- Step 5: flags and SDK versions ------------------------------------------
def test_step5():
    step("Step 5 — Flags and SDK versions (toggle each flag)")
    analysis = _analyze(BAD_APK)
    check("debuggable true reported",
          analysis.flags["debuggable"] is True)
    check("allowBackup true reported",
          analysis.flags["allow_backup"] is True)
    check("targetSdk 28 reported", analysis.flags["target_sdk"] == 28)
    check("minSdk 21 reported", analysis.flags["min_sdk"] == 21)
    check("APK-003 fires on debuggable",
          len(_findings(analysis, "APK-003")) == 1)
    check("APK-004 fires on allowBackup",
          len(_findings(analysis, "APK-004")) == 1)
    check("APK-005 fires on targetSdk 28",
          len(_findings(analysis, "APK-005")) == 1)

    def variant(mutate, name):
        tree = copy.deepcopy(build_test_apk.BAD_MANIFEST)
        mutate(tree)
        path = _build_variant(tree, build_test_apk.BAD_DEX_STRINGS,
                              [("resources.arsc",
                                build_test_apk.BAD_ARSC_STRINGS)],
                              name=name)
        return _analyze(path)

    def set_app_attr(tree, attr, value):
        app = [c for c in tree["children"] if c["name"] == "application"][0]
        for i, (ns, aname, _v) in enumerate(app["attrs"]):
            if aname == attr:
                app["attrs"][i] = (ns, aname, value)
                return
        app["attrs"].append((build_test_apk.ANDROID_NS, attr, value))

    def drop_app_attr(tree, attr):
        app = [c for c in tree["children"] if c["name"] == "application"][0]
        app["attrs"] = [a for a in app["attrs"] if a[1] != attr]

    a = variant(lambda t: set_app_attr(t, "debuggable", ("bool", False)),
                "no_debug.apk")
    check("debuggable=false silences APK-003",
          len(_findings(a, "APK-003")) == 0)
    a = variant(lambda t: set_app_attr(t, "allowBackup", ("bool", False)),
                "no_backup.apk")
    check("allowBackup=false silences APK-004",
          len(_findings(a, "APK-004")) == 0)
    a = variant(lambda t: drop_app_attr(t, "allowBackup"),
                "no_backup_attr.apk")
    found = _findings(a, "APK-004")
    check("allowBackup absent still fires (defaults to true)",
          len(found) == 1 and "defaults it to true" in found[0].evidence,
          found[0].evidence if found else "no finding")
    a = variant(lambda t: [c for c in t["children"]
                          if c["name"] == "uses-sdk"][0]["attrs"].__setitem__(
                              1, (build_test_apk.ANDROID_NS,
                                  "targetSdkVersion", ("int", 34))),
                "sdk34.apk")
    check("targetSdk 34 silences APK-005",
          len(_findings(a, "APK-005")) == 0)
    a = variant(lambda t: [c for c in t["children"]
                          if c["name"] == "uses-sdk"][0]["attrs"].__setitem__(
                              1, (build_test_apk.ANDROID_NS,
                                  "targetSdkVersion", ("int", 21))),
                "sdk21.apk")
    found = _findings(a, "APK-005")
    check("targetSdk 21 fires APK-005 as High",
          len(found) == 1 and found[0].severity == "high")
    a = variant(lambda t: [c for c in t["children"]
                          if c["name"] == "uses-sdk"][0].__setitem__(
                              "attrs", [a2 for a2 in
                                        [c for c in t["children"]
                                         if c["name"] == "uses-sdk"][0]["attrs"]
                                        if a2[1] != "targetSdkVersion"]),
                "no_target.apk")
    found = _findings(a, "APK-005")
    check("targetSdk missing fires APK-005 as High",
          len(found) == 1 and found[0].severity == "high")


# --- Step 6: secret-pattern scan ----------------------------------------------
def test_step6():
    step("Step 6 — Secret-pattern scan")
    analysis = _analyze(BAD_APK)
    hits = analysis.secret_hits
    check("5 secret hits in the bad APK", len(hits) == 5, str(len(hits)))
    patterns = sorted(h[2] for h in hits)
    check("Google API key found",
          "Google API key" in patterns, str(patterns))
    check("AWS access key found", "AWS access key" in patterns)
    check("API key assignment found (resources.arsc)",
          "API key assignment" in patterns)
    check("password assignment found", "Password assignment" in patterns)
    check("private URL found", "Private URL" in patterns)
    google = [h for h in hits if h[2] == "Google API key"][0]
    check("Google key hit is in classes.dex",
          google[0] == "classes.dex", str(google))
    check("no full secret is ever shown",
          all(len(h[4]) <= 9 for h in hits),
          str([h[4] for h in hits]))
    check("secret severities: 4 High + 1 Medium",
          sorted(h[3] for h in hits) == ["high"] * 4 + ["medium"])
    # Remove the planted keys and rebuild: the rules must go silent.
    clean_strings = [s for s in build_test_apk.BAD_DEX_STRINGS
                     if "AIza" not in s and "AKIA" not in s
                     and "password" not in s and "10.0.0.5" not in s]
    clean_arsc = b"\x02\x00\x00\x00CleanApp resources\x00"
    path = _build_variant(
        copy.deepcopy(build_test_apk.BAD_MANIFEST), clean_strings,
        [("resources.arsc", clean_arsc),
         ("res/xml/network_security_config.xml",
          build_test_apk.build_axml(build_test_apk.BAD_CONFIG))],
        name="no_secrets.apk")
    analysis2 = _analyze(path)
    check("removed Google key is NOT reported",
          not [h for h in analysis2.secret_hits
               if h[2] == "Google API key"])
    check("removed AWS key is NOT reported",
          not [h for h in analysis2.secret_hits
               if h[2] == "AWS access key"])
    check("removed api-key assignment is NOT reported",
          not [h for h in analysis2.secret_hits
               if h[2] == "API key assignment"])
    check("removed password is NOT reported",
          not [h for h in analysis2.secret_hits
               if h[2] == "Password assignment"])
    check("removed private URL is NOT reported",
          not [h for h in analysis2.secret_hits
               if h[2] == "Private URL"])
    check("no APK-006 findings at all after removal",
          len(_findings(analysis2, "APK-006")) == 0)
    # A private-key blob is Critical (synthetic, not in the fixtures).
    key_dex = build_test_apk.BAD_DEX_STRINGS + [
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA"]
    path = _build_variant(copy.deepcopy(build_test_apk.BAD_MANIFEST),
                          key_dex, name="privkey.apk")
    analysis3 = _analyze(path)
    found = [f for f in _findings(analysis3, "APK-006")
             if "Private key" in f.title]
    check("private-key material is Critical",
          len(found) == 1 and found[0].severity == "critical")


# --- Step 7: CLI, report and full run ------------------------------------------
def test_step7():
    step("Step 7 — CLI, report and full run")
    out_txt = os.path.join(tempfile.mkdtemp(), "report.txt")
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "apkseeker.py"), BAD_APK,
         "-o", out_txt, "--no-color"],
        capture_output=True, text=True)
    check("bad APK CLI exits 1 (findings, no Critical)",
          proc.returncode == 1, str(proc.returncode))
    check("text report file written", os.path.isfile(out_txt))
    text = open(out_txt, encoding="utf-8").read()
    check("text report is v1.1 and carries the disclaimer",
          text.startswith("APKSeeker v1.1")
          and apkseeker.DISCLAIMER in " ".join(text.split()))
    for needle in ("APK-001", "APK-002", "APK-003", "APK-004", "APK-005",
                   "APK-006", "APK-007", "APK-008",
                   "com.example.labapp", "targetSdkVersion: 28"):
        check("report contains %s" % needle, needle in text)
    check("report never shows a full secret",
          "AIzaSyBFAKEKEY" not in text and "AKIAIOSFODNN7EXAMPLE" not in text)
    check("report lists all 8 entries", "lib/x86_64/liblab.so" in text)
    out_json = os.path.join(tempfile.mkdtemp(), "report.json")
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "apkseeker.py"), BAD_APK,
         "-o", out_json, "--json", "--no-color", "-q"],
        capture_output=True, text=True)
    check("JSON report CLI exits 1", proc.returncode == 1)
    data = json.load(open(out_json))
    check("JSON total_findings is 20", data["total_findings"] == 20,
          str(data["total_findings"]))
    check("JSON counts are 0/11/9/0",
          data["counts"] == {"critical": 0, "high": 11, "medium": 9,
                             "low": 0},
          str(data["counts"]))
    check("JSON has all 9 check sections",
          len(data["findings"]) == 20 and len(data["permissions"]) == 6)
    check("JSON report carries the disclaimer",
          data.get("disclaimer", "").startswith(
              "DISCLAIMER — AUTHORIZED USE ONLY.")
          and data["disclaimer"].endswith("PECA 2016 in Pakistan)."))
    out_clean = os.path.join(tempfile.mkdtemp(), "clean.txt")
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "apkseeker.py"), CLEAN_APK,
         "-o", out_clean, "--no-color"],
        capture_output=True, text=True)
    check("clean APK CLI exits 0", proc.returncode == 0,
          str(proc.returncode))
    clean_text = open(out_clean, encoding="utf-8").read()
    check("clean report says 0 findings",
          "Findings (0:" in clean_text)
    out_min = os.path.join(tempfile.mkdtemp(), "min.txt")
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "apkseeker.py"), MINIMAL_APK,
         "-o", out_min, "--no-color"],
        capture_output=True, text=True)
    check("minimal APK (no dex) exits 1, no crash",
          proc.returncode == 1, str(proc.returncode))
    check("minimal APK has exactly 1 finding (Low cleartext note)",
          "Findings (1: 0 critical, 0 high, 0 medium, 1 low)"
          in open(out_min, encoding="utf-8").read())


# --- Step 8: stretch items ------------------------------------------------------
def test_step8():
    step("Step 8 — Stretch: deep links, .so listing, cleartext")
    analysis = _analyze(BAD_APK)
    check("1 deep link extracted", len(analysis.deep_links) == 1,
          str(len(analysis.deep_links)))
    scheme, host, activity, exported, _guard = analysis.deep_links[0]
    check("deep-link scheme is labapp", scheme == "labapp", str(scheme))
    check("deep-link host is share", host == "share", str(host))
    check("deep-link activity is .ShareActivity",
          activity == ".ShareActivity")
    check("deep-link activity is exported", exported is True)
    check("APK-007 fires once (unprotected deep link)",
          len(_findings(analysis, "APK-007")) == 1)
    check("4 ABIs of native libraries",
          sorted(analysis.native_libs) == ["arm64-v8a", "armeabi-v7a",
                                           "x86", "x86_64"],
          str(sorted(analysis.native_libs)))
    check("1 .so per ABI",
          all(len(v) == 1 for v in analysis.native_libs.values()))
    check("APK-009 is info-only (no finding)",
          len(_findings(analysis, "APK-009")) == 0)
    check("APK-008 fires 4 times (cleartext)",
          len(_findings(analysis, "APK-008")) == 4)
    titles = sorted(f.title for f in _findings(analysis, "APK-008"))
    check("cleartext: base + domain + user certs + usesCleartextTraffic",
          titles == ["Cleartext traffic permitted (base-config)",
                     "Cleartext traffic permitted (domain-config for "
                     "api.example.com)",
                     "User certificates trusted",
                     "usesCleartextTraffic=true"],
          str(titles))
    check("cleartext severities: 2 High + 2 Medium",
          sorted(f.severity for f in _findings(analysis, "APK-008"))
          == ["high", "high", "medium", "medium"])
    clean = _analyze(CLEAN_APK)
    check("clean APK: no deep links", len(clean.deep_links) == 0)
    check("clean APK: no native libraries", clean.native_libs == {})
    check("clean APK: no cleartext findings",
          len(_findings(clean, "APK-008")) == 0)


# --- CLI bits + malformed input --------------------------------------------------
def test_cli_bits():
    step("CLI bits and malformed input")
    here = HERE

    def run_cli(*args):
        return subprocess.run(
            [sys.executable, os.path.join(here, "apkseeker.py")]
            + list(args) + ["--no-color"],
            capture_output=True, text=True)

    proc = run_cli("--version")
    check("--version prints 1.1",
          proc.returncode == 0 and "APKSeeker v1.1" in proc.stdout)
    proc = run_cli("--list-checks")
    check("banner carries the disclaimer",
          apkseeker.DISCLAIMER in " ".join(proc.stdout.split()))
    check("--list-checks lists 9 checks",
          proc.returncode == 0 and proc.stdout.count("APK-00") == 9,
          str(proc.stdout.count("APK-00")))
    proc = run_cli(BAD_APK, "--list")
    check("--list shows 8 entries",
          proc.returncode == 0 and "Archive entries (8)" in proc.stdout)
    proc = run_cli(BAD_APK, "--manifest")
    check("--manifest shows the rebuilt XML",
          proc.returncode == 0 and "<manifest" in proc.stdout
          and "com.example.labapp" in proc.stdout)
    proc = run_cli(BAD_APK, "--min-severity", "high", "-q",
                   "-o", os.path.join(tempfile.mkdtemp(), "r.txt"))
    check("--min-severity high still exits 1",
          proc.returncode == 1, str(proc.returncode))
    proc = run_cli(BAD_APK, "--fail-on", "medium", "-q",
                   "-o", os.path.join(tempfile.mkdtemp(), "r.txt"))
    check("--fail-on medium exits 2", proc.returncode == 2,
          str(proc.returncode))
    proc = run_cli(BAD_APK, "--fail-on", "none", "-q",
                   "-o", os.path.join(tempfile.mkdtemp(), "r.txt"))
    check("--fail-on none exits 1", proc.returncode == 1,
          str(proc.returncode))
    proc = run_cli(CLEAN_APK, "--fail-on", "low", "-q",
                   "-o", os.path.join(tempfile.mkdtemp(), "r.txt"))
    check("clean APK --fail-on low still exits 0",
          proc.returncode == 0, str(proc.returncode))
    proc = run_cli("--check")
    check("doctor exits 0", proc.returncode == 0, proc.stdout[-200:])
    # Malformed input: not a zip, zip without a manifest, truncated AXML.
    bad_file = os.path.join(tempfile.mkdtemp(), "notapk.apk")
    open(bad_file, "wb").write(b"this is not a zip file at all")
    proc = run_cli(bad_file, "-q")
    check("non-ZIP file is a clean error (exit 2, no traceback)",
          proc.returncode == 2 and "Traceback" not in proc.stderr
          and "Not a ZIP" in (proc.stdout + proc.stderr),
          proc.returncode)
    empty_zip = os.path.join(tempfile.mkdtemp(), "empty.apk")
    with zipfile.ZipFile(empty_zip, "w") as zf:
        zf.writestr("README.txt", "nothing here")
    proc = run_cli(empty_zip, "-q")
    check("ZIP without a manifest is a clean error (exit 2)",
          proc.returncode == 2 and "No AndroidManifest.xml"
          in (proc.stdout + proc.stderr))
    trunc = os.path.join(tempfile.mkdtemp(), "trunc.apk")
    with zipfile.ZipFile(trunc, "w") as zf:
        zf.writestr("AndroidManifest.xml",
                    _manifest_bytes(BAD_APK)[:100])
    proc = run_cli(trunc, "-q")
    check("truncated manifest is a clean error (exit 2, no traceback)",
          proc.returncode == 2 and "Traceback" not in proc.stderr)
    missing = run_cli(os.path.join(tempfile.mkdtemp(), "nope.apk"), "-q")
    check("missing file is a clean error (exit 2)",
          missing.returncode == 2 and "No such file" in
          (missing.stdout + missing.stderr))
    # Menu smoke test: option 6 (checks) then 0 (exit).
    proc = subprocess.run(
        [sys.executable, os.path.join(here, "apkseeker.py"), "--menu"],
        input="6\n\n0\n", capture_output=True, text=True)
    check("menu: option 6 lists checks, option 0 exits cleanly",
          proc.returncode == 0 and "APK-001" in proc.stdout)
    proc = subprocess.run(
        [sys.executable, os.path.join(here, "apkseeker.py"), "--menu"],
        input="3\n\n", capture_output=True, text=True)
    check("menu: option 3 scans the clean APK (exit 0)",
          proc.returncode == 0 and "0 findings" in proc.stdout)


# --- Androguard oracle (test-only) ----------------------------------------------
def _find_androguard_python():
    """A Python with androguard installed, or None."""
    for cand in ("/tmp/agvenv/bin/python", sys.executable):
        try:
            proc = subprocess.run(
                [cand, "-c", "import androguard; print('ok')"],
                capture_output=True, text=True, timeout=60)
            if proc.returncode == 0 and "ok" in proc.stdout:
                return cand
        except (OSError, subprocess.TimeoutExpired):
            continue
    return None


def test_androguard_oracle():
    step("Androguard oracle (test-only)")
    ag = _find_androguard_python()
    if ag is None:
        print("  [SKIP] Androguard not installed here — the round-trip "
              "test (Step 3) is the oracle instead.")
        return
    script = (
        "import json, sys\n"
        "from androguard.misc import AnalyzeAPK\n"
        "a, d, dx = AnalyzeAPK(sys.argv[1])\n"
        "app = a.get_android_manifest_xml()\n"
        "ns = '{http://schemas.android.com/apk/res/android}'\n"
        "application = app.find('application')\n"
        "out = {\n"
        "  'permissions': sorted(a.get_permissions()),\n"
        "  'activities': sorted(a.get_activities()),\n"
        "  'services': sorted(a.get_services()),\n"
        "  'receivers': sorted(a.get_receivers()),\n"
        "  'providers': sorted(a.get_providers()),\n"
        "  'min_sdk': a.get_min_sdk_version(),\n"
        "  'target_sdk': a.get_target_sdk_version(),\n"
        "  'debuggable': application.get(ns + 'debuggable'),\n"
        "  'allow_backup': application.get(ns + 'allowBackup'),\n"
        "  'package': a.get_package(),\n"
        "}\n"
        "print(json.dumps(out))\n"
    )
    proc = subprocess.run(
        [ag, "-c", script, BAD_APK],
        capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        print("  [SKIP] Androguard failed on the fixture: %s"
              % (proc.stderr.strip().splitlines() or ["?"])[-1])
        return
    oracle = json.loads(proc.stdout)
    analysis = _analyze(BAD_APK)
    # Androguard expands relative component names (".MainActivity") to
    # fully qualified ones ("com.example.labapp.MainActivity"); the
    # manifest writes them relative, and APKSeeker reports them as
    # written. Resolve ours the same way before comparing.
    package = oracle["package"]

    def resolve(name):
        if name.startswith("."):
            return package + name
        if "." not in name:
            return package + "." + name
        return name

    ours_perms = sorted(n for n, _d, _g in analysis.permissions)
    check("oracle: permissions match Androguard",
          ours_perms == oracle["permissions"],
          "%r vs %r" % (ours_perms, oracle["permissions"]))
    ours_acts = sorted(resolve(c["name"]) for c in analysis.components
                       if c["type"] == "activity")
    check("oracle: activities match Androguard",
          ours_acts == oracle["activities"],
          "%r vs %r" % (ours_acts, oracle["activities"]))
    ours_svcs = sorted(resolve(c["name"]) for c in analysis.components
                       if c["type"] == "service")
    check("oracle: services match Androguard",
          ours_svcs == oracle["services"],
          "%r vs %r" % (ours_svcs, oracle["services"]))
    ours_recv = sorted(resolve(c["name"]) for c in analysis.components
                       if c["type"] == "receiver")
    check("oracle: receivers match Androguard",
          ours_recv == oracle["receivers"],
          "%r vs %r" % (ours_recv, oracle["receivers"]))
    ours_prov = sorted(resolve(c["name"]) for c in analysis.components
                       if c["type"] == "provider")
    check("oracle: providers match Androguard",
          ours_prov == oracle["providers"],
          "%r vs %r" % (ours_prov, oracle["providers"]))
    check("oracle: targetSdk matches Androguard (28)",
          analysis.flags["target_sdk"] == int(oracle["target_sdk"]),
          str(oracle["target_sdk"]))
    check("oracle: minSdk matches Androguard (21)",
          analysis.flags["min_sdk"] == int(oracle["min_sdk"]))
    check("oracle: package matches Androguard",
          apkseeker.load_apk(BAD_APK).manifest.attr("package")
          == oracle["package"])
    check("oracle: debuggable matches Androguard",
          str(analysis.flags["debuggable"]).lower()
          == str(oracle["debuggable"]).lower(),
          str(oracle["debuggable"]))
    check("oracle: allowBackup matches Androguard",
          str(analysis.flags["allow_backup"]).lower()
          == str(oracle["allow_backup"]).lower(),
          str(oracle["allow_backup"]))


def main():
    global PASSED, FAILED
    print("APKSeeker step tests — %s" % BAD_APK)
    for fn in (test_step1, test_step2, test_step3, test_step4, test_step5,
               test_step6, test_step7, test_step8, test_cli_bits,
               test_androguard_oracle):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - one bad step must not
            import traceback      # hide the rest of the suite
            FAILED += 1
            FAILURES.append(fn.__name__)
            print("  [FAIL] %s raised %s: %s"
                  % (fn.__name__, type(exc).__name__, exc))
            traceback.print_exc()
    print("\n" + "=" * 58)
    print("PASSED: %d   FAILED: %d" % (PASSED, FAILED))
    if FAILED:
        print("FAILED CHECKS:")
        for name in FAILURES:
            print("  - %s" % name)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
