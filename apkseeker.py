#!/usr/bin/env python3
"""
APKSeeker — Android APK Static Analyzer
PNY Trainings, Mobile Security — Final Project

WHAT IT DOES
  You give it an APK file. It opens the archive, lists every entry,
  parses the binary AndroidManifest.xml by hand — string pool first,
  then start-element records — to extract permissions, exported
  activities, services, receivers and providers, the debuggable and
  allow-backup flags and the SDK versions, and then scans the dex and
  resource bytes for hardcoded secret patterns (API keys, private URLs,
  passwords). Every finding carries a severity, and the report is
  printed and saved to a file.

  An APK is a zip file with a binary manifest inside. This tool learns
  to read both — at the byte level, with nothing installed: no
  Androguard, no Java, no Docker, no decompiler. Pure Python, standard
  library only, and it runs on Windows, macOS and Linux.

THE 6 MUST-HAVE FEATURES (PDF) — all in this file:
  1. Open the APK as a zip archive; list every entry with compressed
     and uncompressed size
     -> list_entries()
  2. Parse the binary manifest string pool and start-element records
     to recover element names and attribute values
     -> parse_axml() + parse_string_pool()
  3. Extract all requested permissions; flag the dangerous ones
     (location, camera, contacts, SMS, storage, ...)
     -> analyze_permissions() + DANGEROUS_PERMISSIONS
  4. Detect exported components — exported=true, or an intent filter
     present without exported=false
     -> analyze_components() + exported_reason()
  5. Report the debuggable flag, the allow-backup flag and the
     target SDK version
     -> analyze_flags()
  6. Scan dex and resource bytes for hardcoded secret patterns;
     report each hit with its location, saved to a report file
     -> scan_secrets() + SECRET_PATTERNS + write_report()

STRETCH ITEMS (PDF — "if you finish early") — all in this file:
  * Deep-link scheme extraction from intent filters, with a note on
    unprotected schemes
    -> analyze_deeplinks()
  * Native library listing — every .so file with its architecture
    folder
    -> analyze_native_libs()
  * Cleartext traffic assessment from the network security
    configuration when present
    -> analyze_cleartext() (parses res/xml/network_security_config.xml
       with the SAME AXML parser)

INSTALL — the analyzer needs NOTHING installed:
  plain Python 3 is enough (standard library only). No pip, no venv,
  no Android Studio, no SDK. It runs on Windows, macOS and Linux:
    python3 apkseeker.py test_apks/test_bad.apk

USAGE — three ways, same tool:
  Menu (SSTIProbe / TraceRecon style — default when run with no args):
    python run.py menu
    python3 apkseeker.py --menu
      [ 1] Scan an APK (enter path)
      [ 2] Quick scan: test APK (bad — full of findings)
      [ 3] Quick scan: test APK (clean — 0 findings)
      [ 4] List archive entries
      [ 5] Show rebuilt manifest
      [ 6] List all checks
      [ 7] Run the step tests
      [ 8] Check setup (doctor)
      [ 0] Exit
      [ ? ] Select option :

  Interactive prompts (option 1 in the menu asks the same questions):
    python3 apkseeker.py -i
      [?] ENTER APK PATH: test_apks/test_bad.apk

  With arguments (for scripts / demo):
    python3 apkseeker.py test_apks/test_bad.apk
    python3 apkseeker.py test_apks/test_bad.apk --json -o report.json
    python3 apkseeker.py test_apks/test_bad.apk --list
    python3 apkseeker.py test_apks/test_bad.apk --manifest
    python3 apkseeker.py test_apks/test_bad.apk --min-severity high
    python3 apkseeker.py test_apks/test_bad.apk --fail-on critical
    python3 apkseeker.py --list-checks
    python3 apkseeker.py --version
    python3 apkseeker.py test_apks/test_bad.apk --no-color
    python3 apkseeker.py test_apks/test_bad.apk --batch
    python3 apkseeker.py test_apks/test_bad.apk -q   # quiet
"""

import argparse
import json
import os
import re
import struct
import sys
import zipfile
from datetime import datetime

VERSION = "1.0"
AUTHOR = "CyberBoy50"
QUIET = False

# Tunables (change here, nowhere else).
MAX_MANIFEST_SIZE = 4 * 1024 * 1024   # a manifest bigger than this is refused
MAX_SECRET_HITS = 50                  # per pattern, per entry (flood guard)
SECRET_SHOW = 8                       # chars of a secret ever shown, then "…"
DEFAULT_OUTPUT = "apkseeker_report.txt"

# --- Colours (ANSI: works on Kali/macOS/Windows 10+ terminals) ----------
try:
    import colorama

    colorama.init()
except Exception:  # noqa: BLE001 - colour is cosmetic, never fatal
    pass


# --- Colours, TraceRecon style: one class, short names ------------------
class C:
    RST = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[1;31m"
    GRN = "\033[1;32m"
    YEL = "\033[1;33m"
    BLU = "\033[1;34m"
    MAG = "\033[1;35m"
    CYN = "\033[1;36m"
    WHT = "\033[1;37m"


RED = C.RED
GREEN = C.GRN
YELLOW = C.YEL
CYAN = C.CYN
BOLD = C.BLD
RESET = C.RST


def clear():
    """Clear the screen — GhostTrack / TraceRecon pattern."""
    os.system("cls" if os.name == "nt" else "clear")


def sep(color=C.GRN, char="─", width=58):
    """A rule line, TraceRecon style."""
    print(f"{color}{char * width}{C.RST}")


def header(title, color=C.GRN):
    """A titled section header with rule lines above and below."""
    sep(color)
    print(f"{color} {title}{C.RST}")
    sep(color)


def ok(msg):
    """[+] success line: ' [+] message' — white brackets, green plus."""
    print(f" {C.WHT}[{C.GRN}+{C.WHT}]{C.RST} {msg}")


def warn(msg):
    """[!] warning line, yellow."""
    print(f" {C.WHT}[{C.YEL}!{C.WHT}]{C.RST} {C.YEL}{msg}{C.RST}")


def err(msg):
    """[x] error line, red."""
    print(f" {C.WHT}[{C.RED}x{C.WHT}]{C.RST} {C.RED}{msg}{C.RST}")


def info(label, value, label_color=C.WHT, val_color=C.GRN):
    """One aligned field — TraceRecon style (label 22 chars)."""
    print(f" {label_color}{label:<22}{C.RST}: {val_color}{value}{C.RST}")


BANNER = r"""
    _    ____  _  __ ____            _
   / \  |  _ \| |/ /|  _ \ ___  ___ | | _____ _ __
  / _ \ | |_) | ' / | |_) / _ \/ _ \| |/ / _ \ '__|
 / ___ \|  __/| . \ |  __/  __/  __/|   <  __/ |
/_/   \_\_|   |_|\_\|_|   \___|\___||_|\_\___|_|

              by CyberBoy50
     APK STATIC ANALYZER  |  AUTHORIZED USE ONLY
 ==================================================
"""


class APKSeekerError(Exception):
    """A clean, user-facing failure: no traceback, just the message."""


# --- Severity ------------------------------------------------------------
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                  "low": "LOW", "info": "INFO"}
SEVERITY_COLOR = {"critical": C.RED, "high": C.RED, "medium": C.YEL,
                  "low": C.CYN, "info": C.DIM}


def sev_color(severity):
    """Colour for a severity (red for critical/high, yellow for medium)."""
    return SEVERITY_COLOR.get(severity, C.WHT)


# --- Binary AXML parser ----------------------------------------------------
# Chunk types (Android ResourceTypes.h).
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104

# Typed-value data types.
TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

UTF8_FLAG = 0x100
ABSENT = 0xFFFFFFFF
ANDROID_NS = "http://schemas.android.com/apk/res/android"


class Element:
    """One rebuilt XML element: name, attributes, children, text."""

    __slots__ = ("name", "attrs", "children", "text")

    def __init__(self, name):
        self.name = name
        self.attrs = {}      # local attribute name -> typed value
        self.children = []   # child Elements, in document order
        self.text = None     # CDATA text, if any

    def attr(self, name, default=None):
        """Attribute value by local name (namespace stripped)."""
        return self.attrs.get(name, default)

    def find_all(self, name):
        """All descendant elements with this name (depth-first)."""
        found = []
        for child in self.children:
            if child.name == name:
                found.append(child)
            found.extend(child.find_all(name))
        return found

    def find_child(self, name):
        """First direct child with this name, or None."""
        for child in self.children:
            if child.name == name:
                return child
        return None

    def __repr__(self):
        return "<Element %s attrs=%d children=%d>" % (
            self.name, len(self.attrs), len(self.children))


def _read_u16(data, off):
    if off + 2 > len(data):
        raise APKSeekerError("AXML: truncated data (u16 at %d)" % off)
    return struct.unpack_from("<H", data, off)[0]


def _read_u32(data, off):
    if off + 4 > len(data):
        raise APKSeekerError("AXML: truncated data (u32 at %d)" % off)
    return struct.unpack_from("<I", data, off)[0]


def _read_chunk_header(data, off):
    """Read a ResChunk_header; returns (type, header_size, size)."""
    if off + 8 > len(data):
        raise APKSeekerError(
            "AXML: truncated chunk header at offset %d" % off)
    ctype, header_size, size = struct.unpack_from("<HHI", data, off)
    if header_size < 8:
        raise APKSeekerError(
            "AXML: chunk header size %d too small at offset %d"
            % (header_size, off))
    if size < header_size:
        raise APKSeekerError(
            "AXML: chunk size %d smaller than its header at offset %d"
            % (size, off))
    if off + size > len(data):
        raise APKSeekerError(
            "AXML: chunk at offset %d claims size %d past the end of "
            "the file (%d bytes)" % (off, size, len(data)))
    return ctype, header_size, size


def _decode_utf8_length(data, off):
    """Read one AXML UTF-8 length prefix; returns (value, new_offset).

    Lengths are 1 byte when the top bit is clear, else 2 bytes
    (top bit set, low 7 bits are the high part of the value).
    """
    if off >= len(data):
        raise APKSeekerError("AXML: truncated UTF-8 length at %d" % off)
    first = data[off]
    if first & 0x80:
        if off + 1 >= len(data):
            raise APKSeekerError("AXML: truncated UTF-8 length at %d" % off)
        return ((first & 0x7F) << 8) | data[off + 1], off + 2
    return first, off + 1


def parse_string_pool(data, off, size):
    """Parse a string-pool chunk body; returns the list of strings.

    `off` points at the chunk header; `size` is the whole chunk size.
    Supports both UTF-16 (default) and UTF-8 (flags & 0x100) pools.
    """
    if size < 28:
        raise APKSeekerError("AXML: string pool chunk too small (%d)" % size)
    string_count = _read_u32(data, off + 8)
    style_count = _read_u32(data, off + 12)
    flags = _read_u32(data, off + 16)
    strings_start = _read_u32(data, off + 20)
    # styles_start = _read_u32(data, off + 24)  # unused here
    if strings_start < 28 + 4 * string_count or strings_start > size:
        raise APKSeekerError(
            "AXML: string pool stringsStart %d out of range (chunk %d)"
            % (strings_start, size))
    offsets_base = off + 28
    data_base = off + strings_start
    pool = []
    for i in range(string_count):
        rel = _read_u32(data, offsets_base + 4 * i)
        start = data_base + rel
        if start >= off + size:
            raise APKSeekerError(
                "AXML: string %d offset %d past the pool end" % (i, rel))
        if flags & UTF8_FLAG:
            # UTF-8: char-count prefix, byte-count prefix, bytes, null.
            _chars, pos = _decode_utf8_length(data, start)
            byte_len, pos = _decode_utf8_length(data, pos)
            end = pos + byte_len
            if end > off + size:
                raise APKSeekerError(
                    "AXML: string %d runs past the pool end" % i)
            raw = data[pos:end]
            try:
                pool.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                pool.append(raw.decode("utf-8", errors="replace"))
        else:
            # UTF-16: u16 char-count, that many UTF-16LE units, u16 null.
            char_len = _read_u16(data, start)
            byte_len = char_len * 2
            end = start + 2 + byte_len
            if end + 2 > off + size:
                raise APKSeekerError(
                    "AXML: string %d runs past the pool end" % i)
            raw = data[start + 2:end]
            try:
                pool.append(raw.decode("utf-16-le"))
            except UnicodeDecodeError:
                pool.append(raw.decode("utf-16-le", errors="replace"))
    if style_count:
        # Styles exist in some pools; they sit after the strings and we
        # do not need them — the pool is still valid without them.
        pass
    return pool


def _pool_string(pool, index):
    """Resolve a pool index; ABSENT (0xFFFFFFFF) means 'no value'."""
    if index == ABSENT:
        return None
    if index >= len(pool):
        raise APKSeekerError(
            "AXML: string pool index %d out of range (%d strings)"
            % (index, len(pool)))
    return pool[index]


def _resolve_typed_value(pool, data_type, data, raw_value):
    """Turn a Res_value (dataType + data) into a Python value."""
    if data_type == TYPE_STRING:
        if data == ABSENT and raw_value != ABSENT:
            return _pool_string(pool, raw_value)
        return _pool_string(pool, data)
    if data_type == TYPE_INT_BOOLEAN:
        return bool(data != 0)
    if data_type == TYPE_INT_DEC:
        return data
    if data_type == TYPE_INT_HEX:
        return data  # callers print it as hex when they know it is a hex
    if data_type == TYPE_REFERENCE:
        return "@0x%08x" % data
    # Any other type: report the raw integer, never crash.
    return data


def parse_axml(data):
    """Parse binary AXML bytes into an Element tree (the root element).

    Walks the chunk list: file header, string pool, then start/end
    element (and namespace/CDATA) chunks. Unknown chunk types are
    skipped by their size; malformed data raises APKSeekerError.
    """
    if len(data) > MAX_MANIFEST_SIZE:
        raise APKSeekerError(
            "AXML: manifest is %d bytes — over the %d-byte safety limit"
            % (len(data), MAX_MANIFEST_SIZE))
    if len(data) < 8:
        raise APKSeekerError("AXML: file too small (%d bytes)" % len(data))
    ctype, header_size, size = _read_chunk_header(data, 0)
    if ctype != RES_XML_TYPE:
        raise APKSeekerError(
            "AXML: bad file type 0x%04x — not a binary AndroidManifest.xml"
            % ctype)
    if size > len(data):
        raise APKSeekerError(
            "AXML: file header claims %d bytes, file has %d"
            % (size, len(data)))
    pool = None
    root = None
    stack = []
    off = header_size
    end = size
    while off < end:
        ctype, cheader, csize = _read_chunk_header(data, off)
        body = off + cheader
        if ctype == RES_STRING_POOL_TYPE:
            pool = parse_string_pool(data, off, csize)
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            if pool is None:
                raise APKSeekerError(
                    "AXML: start element before the string pool")
            if csize < 16 + 20:
                raise APKSeekerError(
                    "AXML: start-element chunk too small (%d)" % csize)
            # body points past the 16-byte ResXMLTree_node, at the
            # ResXMLTree_attrExt: ns, name, attributeStart, attributeSize,
            # attributeCount, idIndex, classIndex, styleIndex.
            ns_idx = _read_u32(data, body + 0)
            name_idx = _read_u32(data, body + 4)
            attr_start = _read_u16(data, body + 8)
            attr_size = _read_u16(data, body + 10)
            attr_count = _read_u16(data, body + 12)
            # idIndex, classIndex, styleIndex follow — not needed here.
            if attr_size < 20:
                raise APKSeekerError(
                    "AXML: attribute size %d too small" % attr_size)
            name = _pool_string(pool, name_idx)
            if name is None:
                raise APKSeekerError("AXML: element with no name")
            elem = Element(name)
            attrs_base = body + attr_start
            for i in range(attr_count):
                aoff = attrs_base + i * attr_size
                if aoff + 20 > off + csize:
                    raise APKSeekerError(
                        "AXML: attribute %d runs past its element" % i)
                a_ns = _read_u32(data, aoff)
                a_name = _read_u32(data, aoff + 4)
                a_raw = _read_u32(data, aoff + 8)
                a_size = _read_u16(data, aoff + 12)
                # a_res0 = data[aoff + 14] (unused)
                a_type = data[aoff + 15]
                a_data = _read_u32(data, aoff + 16)
                if a_size < 8:
                    raise APKSeekerError(
                        "AXML: attribute value size %d too small" % a_size)
                attr_name = _pool_string(pool, a_name)
                if attr_name is None:
                    continue
                # Strip the android namespace: "android:name" -> "name".
                # (The pool string itself is just "name"; the namespace
                # is a separate index, so the name is already local.)
                _ = a_ns
                elem.attrs[attr_name] = _resolve_typed_value(
                    pool, a_type, a_data, a_raw)
            if stack:
                stack[-1].children.append(elem)
            else:
                if root is not None:
                    raise APKSeekerError(
                        "AXML: two root elements — malformed document")
                root = elem
            stack.append(elem)
        elif ctype == RES_XML_END_ELEMENT_TYPE:
            if not stack:
                raise APKSeekerError(
                    "AXML: end element with nothing open at %d" % off)
            stack.pop()
        elif ctype == RES_XML_CDATA_TYPE:
            # Character data: a ResStringPool_ref (u32) right after the
            # 16-byte node (body already points past it).
            if stack and csize >= 20:
                ref = _read_u32(data, body + 0)
                text = _pool_string(pool, ref)
                if text is not None:
                    if stack[-1].text:
                        stack[-1].text += text
                    else:
                        stack[-1].text = text
        # Anything else (resource map, namespaces, tables, CDATA handled
        # above, unknown chunks) is skipped by its size.
        off += csize
    if pool is None:
        raise APKSeekerError("AXML: no string pool found")
    if root is None:
        raise APKSeekerError("AXML: no root element found")
    if stack:
        raise APKSeekerError(
            "AXML: %d element(s) left unclosed" % len(stack))
    return root


def element_to_xml(elem, indent=0):
    """Render a rebuilt Element tree as readable XML text."""
    pad = "  " * indent
    parts = []
    attr_text = ""
    for name, value in elem.attrs.items():
        if isinstance(value, bool):
            shown = "true" if value else "false"
        elif isinstance(value, str):
            shown = value
        else:
            shown = str(value)
        attr_text += ' %s="%s"' % (name, shown)
    if not elem.children and elem.text is None:
        parts.append("%s<%s%s />" % (pad, elem.name, attr_text))
    else:
        parts.append("%s<%s%s>" % (pad, elem.name, attr_text))
        if elem.text is not None:
            parts.append("%s  %s" % (pad, elem.text))
        for child in elem.children:
            parts.append(element_to_xml(child, indent + 1))
        parts.append("%s</%s>" % (pad, elem.name))
    return "\n".join(parts)


# --- APK loading -----------------------------------------------------------
class ApkEntry:
    """One zip entry: name, compressed size, uncompressed size, bytes."""

    __slots__ = ("name", "compress_size", "file_size", "data")

    def __init__(self, name, compress_size, file_size, data=None):
        self.name = name
        self.compress_size = compress_size
        self.file_size = file_size
        self.data = data  # decompressed bytes, or None until read

    def __repr__(self):
        return "<ApkEntry %s %d bytes>" % (self.name, self.file_size)


class Apk:
    """A loaded APK: its entries, its parsed manifest, its config."""

    def __init__(self, path):
        self.path = path
        self.entries = []          # ApkEntry, in archive order
        self.manifest_data = None  # raw binary AndroidManifest.xml bytes
        self.manifest = None       # parsed Element tree root
        self.config = None         # parsed network-security-config tree
        self.config_present = False

    def entry(self, name):
        """The entry with this exact name, or None."""
        for entry in self.entries:
            if entry.name == name:
                return entry
        return None

    def dex_entries(self):
        """All classes*.dex entries."""
        base = os.path.basename
        return [e for e in self.entries
                if base(e.name).startswith("classes")
                and e.name.endswith(".dex")]

    def secret_scan_entries(self):
        """Entries the secret scan reads: dex + arsc + assets + res."""
        out = []
        for entry in self.entries:
            name = entry.name
            if (name.endswith(".dex")
                    or name == "resources.arsc"
                    or name.startswith("assets/")
                    or name.startswith("res/")):
                out.append(entry)
        return out


def load_apk(path):
    """Open an APK, list its entries, parse its manifest (+ config).

    Raises APKSeekerError with a clean message for a missing file, a
    non-ZIP file, or a ZIP without AndroidManifest.xml.
    """
    if not os.path.isfile(path):
        raise APKSeekerError("No such file: %s" % path)
    apk = Apk(path)
    try:
        zf = zipfile.ZipFile(path, "r")
    except zipfile.BadZipFile:
        raise APKSeekerError(
            "Not a ZIP/APK file: %s (bad zip header)" % path)
    with zf:
        for info in zf.infolist():
            apk.entries.append(ApkEntry(
                info.filename, info.compress_size, info.file_size))
        manifest_entry = apk.entry("AndroidManifest.xml")
        if manifest_entry is None:
            raise APKSeekerError(
                "No AndroidManifest.xml in %s — not an APK" % path)
        apk.manifest_data = zf.read("AndroidManifest.xml")
        for entry in apk.entries:
            entry.data = None  # read lazily, only when scanned
        # Read the manifest + config bytes now (they are small).
        manifest_entry.data = apk.manifest_data
        config_entry = apk.entry("res/xml/network_security_config.xml")
        if config_entry is not None:
            apk.config_present = True
            config_entry.data = zf.read(config_entry.name)
    try:
        apk.manifest = parse_axml(apk.manifest_data)
    except APKSeekerError as exc:
        raise APKSeekerError("AndroidManifest.xml: %s" % exc)
    if apk.config_present:
        try:
            apk.config = parse_axml(
                apk.entry("res/xml/network_security_config.xml").data)
        except APKSeekerError as exc:
            # A broken config file is reported, not fatal: the manifest
            # findings still stand, and the cleartext check says so.
            apk.config = None
            apk.config_error = str(exc)
    return apk


def read_entry_bytes(zf_path, entry):
    """Decompressed bytes of one entry (read on demand)."""
    if entry.data is not None:
        return entry.data
    with zipfile.ZipFile(zf_path, "r") as zf:
        entry.data = zf.read(entry.name)
    return entry.data


# --- Findings --------------------------------------------------------------
class Finding:
    """One finding: code, severity, title, evidence, fix, location."""

    __slots__ = ("code", "severity", "title", "evidence", "fix", "location")

    def __init__(self, code, severity, title, evidence, fix, location=""):
        self.code = code
        self.severity = severity
        self.title = title
        self.evidence = evidence
        self.fix = fix
        self.location = location

    def to_dict(self):
        return {"code": self.code, "severity": self.severity,
                "title": self.title, "evidence": self.evidence,
                "fix": self.fix, "location": self.location}

    def __repr__(self):
        return "<Finding %s %s %s>" % (
            self.code, self.severity, self.title)


class Analysis:
    """Everything one scan learned about an APK."""

    def __init__(self, apk):
        self.apk = apk
        self.findings = []
        self.permissions = []      # (name, dangerous?, group)
        self.components = []       # dicts: type, name, exported, reason, perm
        self.flags = {}            # debuggable, allow_backup, min/target sdk
        self.deep_links = []       # (scheme, host, activity, exported, perm)
        self.native_libs = {}      # abi -> [file names]
        self.secret_hits = []      # (entry, offset, pattern, severity, shown)
        self.notes = []            # info lines (APK-009, no-config note, ...)


# --- Check catalogue (APK-001 ... APK-009) ---------------------------------
CHECKS = [
    ("APK-001", "Dangerous permission requested",
     "A permission with Android 'dangerous' protection level is "
     "requested. Location and SMS are High; the rest are Medium."),
    ("APK-002", "Exported component",
     "A component is exported — exported=true, or an intent filter "
     "without exported=false. High when no android:permission guards "
     "it, Medium when one does."),
    ("APK-003", "Application is debuggable",
     "android:debuggable=true lets anyone attach a debugger and "
     "inspect the running app. High."),
    ("APK-004", "Application allows backup",
     "android:allowBackup=true lets app data be pulled off with "
     "adb backup. The Android default is true when the attribute is "
     "absent, so 'not set' counts too. Medium."),
    ("APK-005", "Old target SDK version",
     "targetSdkVersion below 30 misses newer platform protections "
     "(Medium); below 26 or missing entirely (High)."),
    ("APK-006", "Hardcoded secret in dex / resources",
     "An API key, password, private key or private URL baked into "
     "the code. Private keys are Critical; keys and passwords High; "
     "private URLs Medium; hardcoded IPs Low."),
    ("APK-007", "Unprotected deep link",
     "A custom URL scheme on an exported activity with no permission "
     "— any app on the device can open it. Medium."),
    ("APK-008", "Cleartext traffic permitted",
     "HTTP (not HTTPS) traffic is allowed — by the network security "
     "config (base/domain config) or by usesCleartextTraffic. "
     "Base/domain config: High; user CAs / usesCleartextTraffic: "
     "Medium; no config file at all: Low."),
    ("APK-009", "Native libraries present",
     "Info only — every lib/<abi>/*.so listed by architecture. "
     "Native code is not a finding by itself."),
]


def list_checks():
    """Return the check catalogue (code, title, description)."""
    return CHECKS


# --- Permissions -----------------------------------------------------------
# Android 'dangerous' protection level, grouped. Keep it in one dict so
# it is easy to extend. Anything not listed here is reported as normal
# (or "unknown" when it is not a known Android permission at all —
# never guessed as safe or dangerous).
DANGEROUS_PERMISSIONS = {
    "android.permission.ACCESS_FINE_LOCATION": "Location",
    "android.permission.ACCESS_COARSE_LOCATION": "Location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Location",
    "android.permission.CAMERA": "Camera",
    "android.permission.READ_CONTACTS": "Contacts",
    "android.permission.WRITE_CONTACTS": "Contacts",
    "android.permission.GET_ACCOUNTS": "Contacts",
    "android.permission.SEND_SMS": "SMS",
    "android.permission.READ_SMS": "SMS",
    "android.permission.RECEIVE_SMS": "SMS",
    "android.permission.RECEIVE_WAP_PUSH": "SMS",
    "android.permission.RECEIVE_MMS": "SMS",
    "android.permission.READ_EXTERNAL_STORAGE": "Storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Storage",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "Storage",
    "android.permission.READ_MEDIA_IMAGES": "Storage",
    "android.permission.READ_MEDIA_VIDEO": "Storage",
    "android.permission.READ_MEDIA_AUDIO": "Storage",
    "android.permission.RECORD_AUDIO": "Microphone",
    "android.permission.READ_PHONE_STATE": "Phone",
    "android.permission.READ_PHONE_NUMBERS": "Phone",
    "android.permission.CALL_PHONE": "Phone",
    "android.permission.READ_CALL_LOG": "Phone",
    "android.permission.WRITE_CALL_LOG": "Phone",
    "android.permission.PROCESS_OUTGOING_CALLS": "Phone",
    "android.permission.READ_CALENDAR": "Calendar",
    "android.permission.WRITE_CALENDAR": "Calendar",
    "android.permission.BODY_SENSORS": "Sensors",
    "android.permission.ACTIVITY_RECOGNITION": "Sensors",
    "android.permission.BLUETOOTH_CONNECT": "Bluetooth / nearby",
    "android.permission.BLUETOOTH_SCAN": "Bluetooth / nearby",
    "android.permission.NEARBY_WIFI_DEVICES": "Bluetooth / nearby",
    "android.permission.POST_NOTIFICATIONS": "Notifications",
}

# Groups that are High on their own; every other dangerous group is Medium.
HIGH_DANGEROUS_GROUPS = {"Location", "SMS"}

# Permissions Android itself defines (a small known set, used only to
# tell "normal Android permission" from "unknown permission" — an
# unknown one is reported as-is, never classified either way).
KNOWN_NORMAL_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.SET_WALLPAPER",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.NFC",
    "android.permission.FLASHLIGHT",
    "android.permission.MODIFY_AUDIO_SETTINGS",
    "android.permission.INSTALL_SHORTCUT",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
}


def manifest_permissions(manifest):
    """All requested permission names, in manifest order.

    Reads <uses-permission>, <uses-permission-sdk-23> and
    <uses-permission-sdk-m> elements (their android:name attribute).
    """
    names = []
    for tag in ("uses-permission", "uses-permission-sdk-23",
                "uses-permission-sdk-m"):
        for elem in manifest.find_all(tag):
            name = elem.attr("name")
            if isinstance(name, str) and name and name not in names:
                names.append(name)
    return names


def analyze_permissions(analysis):
    """APK-001: classify every requested permission."""
    for name in manifest_permissions(analysis.apk.manifest):
        group = DANGEROUS_PERMISSIONS.get(name)
        if group:
            dangerous = True
            severity = "high" if group in HIGH_DANGEROUS_GROUPS else "medium"
            analysis.findings.append(Finding(
                "APK-001", severity,
                "Dangerous permission: %s" % name,
                "Protection level 'dangerous' (%s). Declared in "
                "AndroidManifest.xml." % group,
                "Remove the permission if the app does not need it; if "
                "it does, request it at runtime and explain why.",
                "AndroidManifest.xml"))
        else:
            dangerous = False
        analysis.permissions.append(
            (name, dangerous, group or "normal"))


# --- Exported components ---------------------------------------------------
COMPONENT_TYPES = ("activity", "activity-alias", "service", "receiver",
                   "provider")


def exported_reason(elem):
    """Why a component counts as exported (or None when it does not).

    PDF rule: exported=true -> exported; an intent-filter child exists
    AND exported is not "false" -> exported; exported="false" -> not
    exported, even with a filter.
    """
    exported = elem.attr("exported")
    has_filter = elem.find_child("intent-filter") is not None
    if exported is True:
        return "android:exported=true"
    if exported is False:
        return None
    if has_filter:
        return "intent-filter present, android:exported not set to false"
    return None


def analyze_components(analysis):
    """APK-002: walk every component and apply the exported rule."""
    app = analysis.apk.manifest.find_child("application")
    if app is None:
        return
    for ctype in COMPONENT_TYPES:
        for elem in app.find_all(ctype):
            name = elem.attr("name") or "(unnamed)"
            reason = exported_reason(elem)
            guard = elem.attr("permission")
            analysis.components.append({
                "type": ctype, "name": name,
                "exported": reason is not None,
                "reason": reason or "not exported",
                "permission": guard,
            })
            if reason is None:
                continue
            if guard:
                severity = "medium"
                fix = ("Keep the android:permission guard, and check the "
                       "guarded permission is not itself granted to "
                       "untrusted apps.")
            else:
                severity = "high"
                fix = ("Set android:exported=false if no other app needs "
                       "it, or protect it with android:permission so only "
                       "chosen apps can reach it.")
            analysis.findings.append(Finding(
                "APK-002", severity,
                "Exported %s: %s" % (ctype, name),
                "%s. %s." % (reason,
                             ("Guarded by android:permission=%s" % guard)
                             if guard else
                             "No android:permission — any app on the "
                             "device can reach it"),
                fix,
                "AndroidManifest.xml"))


# --- Flags and SDK versions ------------------------------------------------
def analyze_flags(analysis):
    """APK-003 / APK-004 / APK-005: debuggable, allowBackup, SDK."""
    manifest = analysis.apk.manifest
    app = manifest.find_child("application")
    uses_sdk = manifest.find_child("uses-sdk")
    debuggable = app.attr("debuggable") is True if app is not None else False
    allow_backup_attr = app.attr("allowBackup") if app is not None else None
    min_sdk = uses_sdk.attr("minSdkVersion") if uses_sdk is not None else None
    target_sdk = (uses_sdk.attr("targetSdkVersion")
                  if uses_sdk is not None else None)
    analysis.flags = {
        "debuggable": debuggable,
        "allow_backup": allow_backup_attr,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
    }
    if debuggable:
        analysis.findings.append(Finding(
            "APK-003", "high", "Application is debuggable",
            "android:debuggable=true in <application>.",
            "Set android:debuggable=false in the release build (or "
            "remove the attribute — release builds default to false).",
            "AndroidManifest.xml"))
    if allow_backup_attr is True:
        analysis.findings.append(Finding(
            "APK-004", "medium", "Application allows backup",
            "android:allowBackup=true in <application> — app data can "
            "be pulled off with 'adb backup'.",
            "Set android:allowBackup=false unless backup is a feature "
            "users need.",
            "AndroidManifest.xml"))
    elif allow_backup_attr is None:
        analysis.findings.append(Finding(
            "APK-004", "medium",
            "allowBackup not set (defaults to true)",
            "No android:allowBackup attribute — Android defaults it to "
            "true, so app data can be pulled off with 'adb backup'.",
            "Set android:allowBackup=false explicitly.",
            "AndroidManifest.xml"))
    if target_sdk is None:
        analysis.findings.append(Finding(
            "APK-005", "high", "targetSdkVersion is missing",
            "No android:targetSdkVersion in <uses-sdk>.",
            "Set android:targetSdkVersion to a current API level.",
            "AndroidManifest.xml"))
    elif isinstance(target_sdk, int):
        if target_sdk < 26:
            analysis.findings.append(Finding(
                "APK-005", "high",
                "Old target SDK: %d" % target_sdk,
                "android:targetSdkVersion=%d (Android 8.0 is API 26) — "
                "the app misses years of platform protections." % target_sdk,
                "Raise android:targetSdkVersion to a current API level.",
                "AndroidManifest.xml"))
        elif target_sdk < 30:
            analysis.findings.append(Finding(
                "APK-005", "medium",
                "Old target SDK: %d" % target_sdk,
                "android:targetSdkVersion=%d (Android 11 is API 30) — "
                "the app misses newer platform protections." % target_sdk,
                "Raise android:targetSdkVersion to a current API level.",
                "AndroidManifest.xml"))


# --- Secret-pattern scan ---------------------------------------------------
# Each entry: (name, bytes-regex, severity). Ordered most-severe first —
# when two patterns match overlapping bytes, the first one wins.
SECRET_PATTERNS = [
    ("Private key material",
     rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "critical"),
    ("Google API key",
     rb"AIza[0-9A-Za-z_\-]{35}", "high"),
    ("AWS access key",
     rb"AKIA[0-9A-Z]{16}", "high"),
    ("API key assignment",
     rb"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"][0-9A-Za-z_\-]{16,}['\"]",
     "high"),
    ("Password assignment",
     rb"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]", "high"),
    ("Private URL",
     rb"https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)[^\s'\"]+",
     "medium"),
    ("Private hostname URL",
     rb"https?://[a-z0-9\-]+\.(?:internal|local|corp|lan)\b[^\s'\"]*",
     "medium"),
    ("Bearer / token",
     rb"(?i)(?:bearer|token)\s+['\"]?[0-9A-Za-z_\-\.]{16,}", "medium"),
    ("Hardcoded IP URL",
     rb"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?[^\s'\"]*", "low"),
]

_COMPILED_PATTERNS = [
    (name, re.compile(pattern), severity)
    for name, pattern, severity in SECRET_PATTERNS
]


def _truncate_secret(match_bytes):
    """Show at most the first 8 chars of a secret, then '…'.

    A full secret must never land in the terminal or the report.
    """
    try:
        text = match_bytes.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - display only, never fatal
        text = repr(match_bytes)
    if len(text) <= SECRET_SHOW:
        return text
    return text[:SECRET_SHOW] + "…"


def scan_secrets(analysis):
    """APK-006: scan dex + arsc + assets/res bytes for secret patterns.

    Overlapping matches are de-duplicated per entry: patterns run
    most-severe first, and a match that overlaps one already recorded
    is skipped (so one URL does not fire both the private-URL and the
    hardcoded-IP rule).
    """
    apk = analysis.apk
    for entry in apk.secret_scan_entries():
        try:
            data = read_entry_bytes(apk.path, entry)
        except (KeyError, zipfile.BadZipFile, OSError) as exc:
            analysis.notes.append(
                "Could not read %s for the secret scan: %s"
                % (entry.name, exc))
            continue
        taken = []  # (start, end) spans already claimed in this entry
        for name, pattern, severity in _COMPILED_PATTERNS:
            count = 0
            for match in pattern.finditer(data):
                if count >= MAX_SECRET_HITS:
                    break
                start, end = match.span()
                if any(start < e and end > s for s, e in taken):
                    continue
                taken.append((start, end))
                count += 1
                shown = _truncate_secret(match.group(0))
                analysis.secret_hits.append(
                    (entry.name, start, name, severity, shown))
                analysis.findings.append(Finding(
                    "APK-006", severity,
                    "%s in %s" % (name, entry.name),
                    "Matched at offset %d: %s" % (start, shown),
                    "Move the secret out of the app — use a server-side "
                    "proxy, the Android Keystore, or a secrets manager; "
                    "never ship keys in the APK.",
                    "%s @ offset %d" % (entry.name, start)))


# --- Stretch: deep links ---------------------------------------------------
def analyze_deeplinks(analysis):
    """APK-007: deep-link schemes from intent filters.

    A custom scheme on an exported activity with no permission is an
    unprotected deep link (Medium). http/https schemes are normal and
    are listed without a finding.
    """
    app = analysis.apk.manifest.find_child("application")
    if app is None:
        return
    exported = {}
    for comp in analysis.components:
        exported[(comp["type"], comp["name"])] = comp
    for ctype in ("activity", "activity-alias"):
        for elem in app.find_all(ctype):
            name = elem.attr("name") or "(unnamed)"
            comp = exported.get((ctype, name), {})
            is_exported = comp.get("exported", False)
            guard = comp.get("permission")
            for filt in elem.find_all("intent-filter"):
                for data in filt.find_all("data"):
                    scheme = data.attr("scheme")
                    if not isinstance(scheme, str) or not scheme:
                        continue
                    host = data.attr("host")
                    analysis.deep_links.append(
                        (scheme, host, name, is_exported, guard))
                    if scheme in ("http", "https"):
                        continue
                    if is_exported and not guard:
                        analysis.findings.append(Finding(
                            "APK-007", "medium",
                            "Unprotected deep link: %s://" % scheme,
                            "Exported %s %s handles scheme '%s://'%s — "
                            "any app on the device can open it, with no "
                            "permission check."
                            % (ctype, name, scheme,
                               (" (host %s)" % host) if host else ""),
                            "Protect the activity with android:permission, "
                            "verify the link (App Links with assetlinks.json) "
                            "instead of a bare custom scheme, or set "
                            "android:exported=false.",
                            "AndroidManifest.xml"))


# --- Stretch: native libraries ----------------------------------------------
def analyze_native_libs(analysis):
    """APK-009 (info): every lib/<abi>/*.so, grouped by ABI folder."""
    for entry in analysis.apk.entries:
        if entry.name.startswith("lib/") and entry.name.endswith(".so"):
            parts = entry.name.split("/")
            abi = parts[1] if len(parts) > 2 else "(unknown ABI)"
            analysis.native_libs.setdefault(abi, []).append(entry.name)
    for abi in sorted(analysis.native_libs):
        analysis.notes.append(
            "Native libraries (%s): %d file(s) — %s"
            % (abi, len(analysis.native_libs[abi]),
               ", ".join(sorted(analysis.native_libs[abi]))))


# --- Stretch: cleartext traffic ----------------------------------------------
def analyze_cleartext(analysis):
    """APK-008: cleartext assessment from the network security config.

    The config file (res/xml/network_security_config.xml) is parsed
    with the SAME AXML parser. Also reads the application
    android:usesCleartextTraffic attribute. When no config file exists
    at all, the assessment falls back to that attribute.
    """
    apk = analysis.apk
    app = apk.manifest.find_child("application")
    uses_cleartext = app.attr("usesCleartextTraffic") if app is not None else None
    if not apk.config_present:
        analysis.notes.append(
            "No network security config file "
            "(res/xml/network_security_config.xml) in the APK.")
        # Only a Low note when the app has NOT explicitly opted out of
        # cleartext (usesCleartextTraffic=false means it did opt out).
        if uses_cleartext is not False:
            analysis.findings.append(Finding(
                "APK-008", "low",
                "No network security config — cleartext defaults apply",
                "No res/xml/network_security_config.xml, and "
                "android:usesCleartextTraffic is not false — cleartext "
                "traffic is governed by the platform default, not by an "
                "explicit policy.",
                "Add a network security config that forbids cleartext, "
                "or set android:usesCleartextTraffic=false.",
                "AndroidManifest.xml"))
        return
    if getattr(apk, "config_error", None):
        analysis.notes.append(
            "Network security config present but unparsable: %s"
            % apk.config_error)
        return
    config = apk.config
    base = config.find_child("base-config")
    if base is not None and base.attr("cleartextTrafficPermitted") is True:
        analysis.findings.append(Finding(
            "APK-008", "high",
            "Cleartext traffic permitted (base-config)",
            "<base-config cleartextTrafficPermitted=\"true\"> in the "
            "network security config — cleartext is allowed for every "
            "host by default.",
            "Set cleartextTrafficPermitted=false in <base-config>, or "
            "remove the attribute.",
            "res/xml/network_security_config.xml"))
    for domain_cfg in config.find_all("domain-config"):
        if domain_cfg.attr("cleartextTrafficPermitted") is True:
            domains = []
            for domain in domain_cfg.find_all("domain"):
                if domain.text:
                    domains.append(domain.text)
            analysis.findings.append(Finding(
                "APK-008", "high",
                "Cleartext traffic permitted (domain-config%s)"
                % ((" for " + ", ".join(domains)) if domains else ""),
                "<domain-config cleartextTrafficPermitted=\"true\"> in "
                "the network security config.",
                "Set cleartextTrafficPermitted=false for the domain, or "
                "serve it over HTTPS.",
                "res/xml/network_security_config.xml"))
    for certs in config.find_all("certificates"):
        if certs.attr("src") == "user":
            analysis.findings.append(Finding(
                "APK-008", "medium",
                "User certificates trusted",
                "<certificates src=\"user\"> in the network security "
                "config — certificates the user installed (for example "
                "a proxy CA) are trusted, so traffic can be intercepted.",
                "Trust only system certificates (src=\"system\"), unless "
                "user CAs are a deliberate debugging choice.",
                "res/xml/network_security_config.xml"))
    if uses_cleartext is True:
        analysis.findings.append(Finding(
            "APK-008", "medium",
            "usesCleartextTraffic=true",
            "android:usesCleartextTraffic=true in <application> — the "
            "app opts into cleartext traffic.",
            "Set android:usesCleartextTraffic=false.",
            "AndroidManifest.xml"))


# --- Full analysis -----------------------------------------------------------
def analyze_apk(apk):
    """Run every check on a loaded APK; returns the Analysis."""
    analysis = Analysis(apk)
    analyze_permissions(analysis)
    analyze_components(analysis)
    analyze_flags(analysis)
    scan_secrets(analysis)
    analyze_deeplinks(analysis)
    analyze_native_libs(analysis)
    analyze_cleartext(analysis)
    return analysis


def count_by_severity(findings):
    """{severity: count} for a findings list."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
    return counts


def filter_findings(findings, min_severity):
    """Findings at or above a minimum severity (display filter only)."""
    level = SEVERITY_ORDER.get(min_severity, 0)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= level]


def exit_code_for(findings, fail_on):
    """0 clean, 1 findings, 2 any Critical (or --fail-on hit)."""
    if not findings:
        return 0
    counts = count_by_severity(findings)
    if counts["critical"] > 0:
        return 2
    if fail_on and fail_on != "none":
        level = SEVERITY_ORDER.get(fail_on, 0)
        for finding in findings:
            if SEVERITY_ORDER.get(finding.severity, 0) >= level:
                return 2
    return 1


# --- Reports -----------------------------------------------------------------
def manifest_summary(apk):
    """Package / version / SDK lines for the report header."""
    manifest = apk.manifest
    app = manifest.find_child("application")
    uses_sdk = manifest.find_child("uses-sdk")
    return {
        "package": manifest.attr("package"),
        "version_code": manifest.attr("versionCode"),
        "version_name": manifest.attr("versionName"),
        "min_sdk": uses_sdk.attr("minSdkVersion") if uses_sdk else None,
        "target_sdk": uses_sdk.attr("targetSdkVersion") if uses_sdk else None,
        "application_label": app.attr("label") if app else None,
    }


def build_text_report(apk, analysis, shown_findings=None):
    """The full text report (also what the terminal prints)."""
    if shown_findings is None:
        shown_findings = analysis.findings
    counts = count_by_severity(analysis.findings)
    summary = manifest_summary(apk)
    lines = []
    lines.append("APKSeeker v%s — Android APK Static Analyzer" % VERSION)
    lines.append("by %s — AUTHORIZED USE ONLY" % AUTHOR)
    lines.append("=" * 58)
    lines.append("APK: %s" % apk.path)
    lines.append("Scanned: %s"
                 % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("")
    lines.append("Manifest")
    lines.append("-" * 58)
    lines.append("Package: %s" % summary["package"])
    lines.append("Version: %s (code %s)"
                 % (summary["version_name"], summary["version_code"]))
    lines.append("minSdkVersion: %s   targetSdkVersion: %s"
                 % (summary["min_sdk"], summary["target_sdk"]))
    if summary["application_label"]:
        lines.append("Application label: %s" % summary["application_label"])
    lines.append("")
    lines.append("Archive entries (%d)" % len(apk.entries))
    lines.append("-" * 58)
    total_size = 0
    for entry in apk.entries:
        total_size += entry.file_size
        lines.append("  %-44s %10d bytes (compressed %d)"
                     % (entry.name, entry.file_size, entry.compress_size))
    lines.append("  Total uncompressed size: %d bytes" % total_size)
    lines.append("")
    lines.append("Permissions (%d requested, %d dangerous)"
                 % (len(analysis.permissions),
                    sum(1 for _n, d, _g in analysis.permissions if d)))
    lines.append("-" * 58)
    for name, dangerous, group in analysis.permissions:
        tag = "DANGEROUS (%s)" % group if dangerous else "normal"
        lines.append("  %-52s %s" % (name, tag))
    lines.append("")
    lines.append("Components (%d, %d exported)"
                 % (len(analysis.components),
                    sum(1 for c in analysis.components if c["exported"])))
    lines.append("-" * 58)
    for comp in analysis.components:
        status = "EXPORTED (%s)" % comp["reason"] if comp["exported"] \
            else "not exported"
        guard = (" [permission: %s]" % comp["permission"]
                 if comp["permission"] else "")
        lines.append("  %-10s %-40s %s%s"
                     % (comp["type"], comp["name"], status, guard))
    lines.append("")
    lines.append("Flags")
    lines.append("-" * 58)
    lines.append("  debuggable: %s" % analysis.flags.get("debuggable"))
    backup = analysis.flags.get("allow_backup")
    lines.append("  allowBackup: %s%s"
                 % (backup, " (not set — Android defaults to true)"
                    if backup is None else ""))
    lines.append("  minSdkVersion: %s   targetSdkVersion: %s"
                 % (analysis.flags.get("min_sdk"),
                    analysis.flags.get("target_sdk")))
    lines.append("")
    if analysis.deep_links:
        lines.append("Deep links (%d)" % len(analysis.deep_links))
        lines.append("-" * 58)
        for scheme, host, activity, exported, _guard in analysis.deep_links:
            lines.append("  %s://%s  (activity %s, %s)"
                         % (scheme, host or "",
                            activity, "exported" if exported else "private"))
        lines.append("")
    if analysis.native_libs:
        lines.append("Native libraries")
        lines.append("-" * 58)
        for abi in sorted(analysis.native_libs):
            lines.append("  %s: %d file(s)"
                         % (abi, len(analysis.native_libs[abi])))
            for name in sorted(analysis.native_libs[abi]):
                lines.append("    %s" % name)
        lines.append("")
    if analysis.secret_hits:
        lines.append("Secret scan hits (%d)" % len(analysis.secret_hits))
        lines.append("-" * 58)
        for entry_name, offset, pattern, severity, shown in analysis.secret_hits:
            lines.append("  [%s] %s — %s @ offset %d: %s"
                         % (SEVERITY_LABEL[severity], pattern,
                            entry_name, offset, shown))
        lines.append("")
    for note in analysis.notes:
        lines.append("Note: %s" % note)
    if analysis.notes:
        lines.append("")
    lines.append("Findings (%d: %d critical, %d high, %d medium, %d low)"
                 % (len(analysis.findings), counts["critical"],
                    counts["high"], counts["medium"], counts["low"]))
    lines.append("-" * 58)
    if not shown_findings:
        lines.append("  No findings at this severity — the APK looks clean.")
    for finding in shown_findings:
        lines.append("[%s] [%s] %s"
                     % (SEVERITY_LABEL[finding.severity],
                        finding.code, finding.title))
        lines.append("    Evidence: %s" % finding.evidence)
        if finding.location:
            lines.append("    Location: %s" % finding.location)
        lines.append("    Fix: %s" % finding.fix)
        lines.append("")
    if len(shown_findings) != len(analysis.findings):
        lines.append("(%d finding(s) hidden by --min-severity; the count "
                     "above is the full total.)"
                     % (len(analysis.findings) - len(shown_findings)))
    lines.append("End of report — APKSeeker v%s by %s" % (VERSION, AUTHOR))
    return "\n".join(lines) + "\n"


def build_json_report(apk, analysis, shown_findings=None):
    """The same report as JSON (machine-readable)."""
    if shown_findings is None:
        shown_findings = analysis.findings
    summary = manifest_summary(apk)
    return {
        "tool": "APKSeeker",
        "version": VERSION,
        "author": AUTHOR,
        "apk": apk.path,
        "scanned": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "manifest": summary,
        "entries": [
            {"name": e.name, "compressed_size": e.compress_size,
             "uncompressed_size": e.file_size}
            for e in apk.entries
        ],
        "permissions": [
            {"name": name, "dangerous": dangerous, "group": group}
            for name, dangerous, group in analysis.permissions
        ],
        "components": analysis.components,
        "flags": analysis.flags,
        "deep_links": [
            {"scheme": s, "host": h, "activity": a,
             "exported": e, "permission": g}
            for s, h, a, e, g in analysis.deep_links
        ],
        "native_libs": analysis.native_libs,
        "secret_hits": [
            {"entry": e, "offset": o, "pattern": p,
             "severity": s, "match": m}
            for e, o, p, s, m in analysis.secret_hits
        ],
        "notes": analysis.notes,
        "findings": [f.to_dict() for f in shown_findings],
        "counts": count_by_severity(analysis.findings),
        "total_findings": len(analysis.findings),
    }


def write_report(apk, analysis, output, as_json, shown_findings=None):
    """Write the report file; returns the path written."""
    if as_json:
        text = json.dumps(
            build_json_report(apk, analysis, shown_findings), indent=2)
    else:
        text = build_text_report(apk, analysis, shown_findings)
    with open(output, "w", encoding="utf-8") as fh:
        fh.write(text)
    return output


# --- Terminal output ---------------------------------------------------------
def print_config(apk_path, output, as_json, min_severity):
    """Gobuster-style SCAN config block before each scan."""
    if QUIET:
        return
    sep()
    print(f" {C.WHT}[ {C.GRN}SCAN {C.WHT}] {C.GRN}APKSeeker v{VERSION}"
          f"{C.RST}")
    sep()
    info("APK", apk_path)
    info("Output", "%s (%s)" % (output, "JSON" if as_json else "text"))
    info("Min severity", min_severity)
    sep()


def print_findings(analysis, shown_findings):
    """Print the findings section to the terminal."""
    if QUIET:
        return
    counts = count_by_severity(analysis.findings)
    header("Findings (%d: %d critical, %d high, %d medium, %d low)"
           % (len(analysis.findings), counts["critical"], counts["high"],
              counts["medium"], counts["low"]))
    if not shown_findings:
        ok("No findings at this severity — the APK looks clean.")
        return
    for finding in shown_findings:
        color = sev_color(finding.severity)
        print(f" {C.WHT}[{color}{SEVERITY_LABEL[finding.severity]}"
              f"{C.WHT}] {C.GRN}[{finding.code}]{C.RST} {finding.title}")
        print(f"      {C.DIM}Evidence: {finding.evidence}{C.RST}")
        if finding.location:
            print(f"      {C.DIM}Location: {finding.location}{C.RST}")
        print(f"      {C.DIM}Fix: {finding.fix}{C.RST}")
    if len(shown_findings) != len(analysis.findings):
        warn("%d finding(s) hidden by --min-severity."
             % (len(analysis.findings) - len(shown_findings)))


def print_summary_sections(apk, analysis):
    """Print the non-finding sections (entries, permissions, ...) briefly."""
    if QUIET:
        return
    summary = manifest_summary(apk)
    header("Manifest")
    info("Package", str(summary["package"]))
    info("Version", "%s (code %s)"
         % (summary["version_name"], summary["version_code"]))
    info("minSdk / targetSdk", "%s / %s"
         % (summary["min_sdk"], summary["target_sdk"]))
    info("Entries", "%d (%d bytes uncompressed)"
         % (len(apk.entries),
            sum(e.file_size for e in apk.entries)))
    info("Permissions", "%d requested, %d dangerous"
         % (len(analysis.permissions),
            sum(1 for _n, d, _g in analysis.permissions if d)))
    info("Components", "%d, %d exported"
         % (len(analysis.components),
            sum(1 for c in analysis.components if c["exported"])))
    info("Deep links", str(len(analysis.deep_links)))
    info("Native libraries",
         str(sum(len(v) for v in analysis.native_libs.values())))
    info("Secret hits", str(len(analysis.secret_hits)))
    for note in analysis.notes:
        warn("Note: %s" % note)


def print_entries(apk):
    """--list: every archive entry with compressed/uncompressed size."""
    header("Archive entries (%d)" % len(apk.entries))
    total = 0
    for entry in apk.entries:
        total += entry.file_size
        print("  %-44s %10d bytes (compressed %d)"
              % (entry.name, entry.file_size, entry.compress_size))
    sep()
    info("Total uncompressed", "%d bytes" % total)


def print_manifest(apk):
    """--manifest: the rebuilt manifest as readable XML text."""
    header("Rebuilt AndroidManifest.xml")
    print(element_to_xml(apk.manifest))
    sep()


def print_checks():
    """--list-checks: the check catalogue."""
    header("APKSeeker checks (%d)" % len(CHECKS))
    for code, title, desc in CHECKS:
        print(f" {C.WHT}[{C.GRN}{code}{C.WHT}]{C.RST} {title}")
        print(f"      {C.DIM}{desc}{C.RST}")


# --- Doctor ------------------------------------------------------------------
def doctor():
    """Check the setup: Python, stdlib, fixtures, write access."""
    print_banner()
    header("Doctor — check setup")
    problems = 0
    info("Platform", "%s (%s)" % (sys.platform, os.name))
    ok("Python %s" % sys.version.split()[0])
    try:
        import zipfile as _zf  # noqa: F401 - availability check
        ok("zipfile (standard library) available.")
    except ImportError:
        err("zipfile is missing — the tool cannot open APKs.")
        problems += 1
    here = os.path.dirname(os.path.abspath(__file__))
    for label, rel in (
            ("bad test APK", "test_apks/test_bad.apk"),
            ("clean test APK", "test_apks/test_clean.apk"),
            ("minimal test APK", "test_apks/test_minimal.apk"),
            ("fixture generator", "build_test_apk.py"),
            ("step tests", "test_apkseeker.py")):
        full = os.path.join(here, rel)
        if os.path.isfile(full):
            ok("%s: %s" % (label, rel))
        else:
            warn("%s missing: %s" % (label, rel))
            problems += 1
    try:
        probe = os.path.join(here, ".doctor_write_test")
        with open(probe, "w") as fh:
            fh.write("ok")
        os.remove(probe)
        ok("Can write report files here.")
    except OSError as exc:
        err("Cannot write report files here: %s" % exc)
        problems += 1
    sep()
    if problems:
        err("Doctor: %d problem(s) found (see [!] lines)." % problems)
        return 1
    ok("Doctor: all good. Try: python3 apkseeker.py --menu")
    return 0


# --- Scanning ------------------------------------------------------------------
def do_scan(args):
    """Load an APK, analyze it, print and save the report."""
    try:
        apk = load_apk(args.apk)
    except APKSeekerError as exc:
        err(str(exc))
        return 2
    print_config(args.apk, args.output, args.json, args.min_severity)
    analysis = analyze_apk(apk)
    shown = filter_findings(analysis.findings, args.min_severity)
    print_summary_sections(apk, analysis)
    print_findings(analysis, shown)
    try:
        write_report(apk, analysis, args.output, args.json, shown)
    except OSError as exc:
        err("Could not write the report: %s" % exc)
        return 2
    if not QUIET:
        ok("Report saved: %s" % args.output)
    return exit_code_for(analysis.findings, args.fail_on)


def do_list(args):
    """--list: open the APK and list its entries (no analysis)."""
    try:
        apk = load_apk(args.apk)
    except APKSeekerError as exc:
        err(str(exc))
        return 2
    print_banner()
    print_entries(apk)
    return 0


def do_manifest(args):
    """--manifest: open the APK and print the rebuilt manifest."""
    try:
        apk = load_apk(args.apk)
    except APKSeekerError as exc:
        err(str(exc))
        return 2
    print_banner()
    print_manifest(apk)
    return 0


def fixture_path(name):
    """Absolute path of a test fixture APK."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "test_apks", name)


def quick_scan(args, fixture, label):
    """Menu options 2/3: scan a built-in test APK."""
    path = fixture_path(fixture)
    if not os.path.isfile(path):
        err("Test APK missing: %s — run: python run.py build-apk" % path)
        return 2
    args.apk = path
    if not QUIET:
        print(f"\n{C.WHT}[ {C.GRN}*{C.WHT}] {C.GRN}Quick scan: {label}"
              f"{C.RST}")
    return do_scan(args)


# --- Menu ----------------------------------------------------------------------
def print_banner():
    if not QUIET:
        print(f"{C.GRN}{BANNER}{C.RST}")
        print(f"{C.WHT}  APKSeeker v{VERSION} — Android APK static analyzer"
              f"{C.RST}")
        print(f"{C.YEL}  AUTHORIZED USE ONLY — only analyze APKs you built "
              f"or have written permission to test.{C.RST}")
        print(f"{C.DIM}  Scanning someone else's app without permission is "
              f"unauthorized access (PECA 2016).{C.RST}")
        print()


def show_menu():
    clear()
    print_banner()
    print(f" {C.WHT}[ {C.GRN}1 {C.WHT}] {C.GRN}Scan an APK "
          f"(enter path){C.RST}")
    print(f" {C.WHT}[ {C.GRN}2 {C.WHT}] {C.GRN}Quick scan: test APK "
          f"(bad — full of findings){C.RST}")
    print(f" {C.WHT}[ {C.GRN}3 {C.WHT}] {C.GRN}Quick scan: test APK "
          f"(clean — 0 findings){C.RST}")
    print(f" {C.WHT}[ {C.GRN}4 {C.WHT}] {C.GRN}List archive entries"
          f"{C.RST}")
    print(f" {C.WHT}[ {C.GRN}5 {C.WHT}] {C.GRN}Show rebuilt manifest"
          f"{C.RST}")
    print(f" {C.WHT}[ {C.GRN}6 {C.WHT}] {C.GRN}List all checks"
          f"{C.RST}")
    print(f" {C.WHT}[ {C.GRN}7 {C.WHT}] {C.GRN}Run the step tests"
          f"{C.RST}")
    print(f" {C.WHT}[ {C.GRN}8 {C.WHT}] {C.GRN}Check setup (doctor)"
          f"{C.RST}")
    print(f" {C.WHT}[ {C.RED}0 {C.WHT}] {C.RED}Exit{C.RST}")
    print()


def ask_interactive(label, default):
    """One [?] prompt with a default (Enter keeps the default)."""
    try:
        value = input(f"{C.WHT}\n [ ? ] {C.GRN}{label}{C.WHT} "
                      f"[{default}]: {C.GRN}").strip()
    except KeyboardInterrupt:
        print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
        raise
    print(C.RST, end="")
    return value or default


def menu_loop(args):
    """Numbered menu loop. Returns 0 on clean exit."""
    while True:
        show_menu()
        try:
            choice = input(
                f"{C.WHT}\n [ ? ] {C.GRN}Select option{C.WHT} : "
                f"{C.GRN}").strip()
            print(C.RST, end="")
            if choice == "0":
                print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
                return 0
            if choice == "1":
                args.apk = ask_interactive(
                    "ENTER APK PATH", fixture_path("test_bad.apk"))
                return do_scan(args)
            if choice == "2":
                args.output = args.output or DEFAULT_OUTPUT
                return quick_scan(args, "test_bad.apk",
                                  "test APK (bad)")
            if choice == "3":
                args.output = args.output or DEFAULT_OUTPUT
                return quick_scan(args, "test_clean.apk",
                                  "test APK (clean)")
            if choice == "4":
                args.apk = ask_interactive(
                    "ENTER APK PATH", fixture_path("test_bad.apk"))
                return do_list(args)
            if choice == "5":
                args.apk = ask_interactive(
                    "ENTER APK PATH", fixture_path("test_bad.apk"))
                return do_manifest(args)
            if choice == "6":
                print_banner()
                print_checks()
            elif choice == "7":
                return run_step_tests()
            elif choice == "8":
                return doctor()
            else:
                err("Please input a number from the menu (0-8).")
                import time as _time
                _time.sleep(1)
                continue
        except ValueError:
            err("Please input a number from the menu (0-8).")
            import time as _time
            _time.sleep(1)
            continue
        except KeyboardInterrupt:
            print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
            return 0
        input(f"\n{C.WHT}[ {C.GRN}+ {C.WHT}] {C.GRN}Press enter to "
              f"continue{C.RST}")
    return 0


def run_step_tests():
    """Menu option 7: run the step-test suite in a subprocess."""
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    test_file = os.path.join(here, "test_apkseeker.py")
    if not os.path.isfile(test_file):
        err("Step tests missing: %s" % test_file)
        return 2
    return subprocess.run(
        [sys.executable, test_file]).returncode


# --- CLI -----------------------------------------------------------------------
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="apkseeker",
        description="APKSeeker v%s — Android APK static analyzer "
                    "(hand-written AXML parser, zero dependencies)."
                    % VERSION)
    parser.add_argument("apk", nargs="?", default=None,
                        help="APK file to analyze")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
                        help="report file (default: %(default)s)")
    parser.add_argument("--json", action="store_true",
                        help="write the report as JSON instead of text")
    parser.add_argument("--list", action="store_true",
                        help="list archive entries only (no analysis)")
    parser.add_argument("--manifest", action="store_true",
                        help="print the rebuilt manifest only (no analysis)")
    parser.add_argument("--min-severity",
                        choices=["critical", "high", "medium", "low"],
                        default="low",
                        help="only display findings at or above this "
                             "severity (default: low)")
    parser.add_argument("--fail-on",
                        choices=["critical", "high", "medium", "low", "none"],
                        default="critical",
                        help="exit 2 when a finding at or above this "
                             "severity exists (default: critical)")
    parser.add_argument("--check", action="store_true",
                        help="doctor: check the setup and exit")
    parser.add_argument("--skip-check", action="store_true",
                        help="(accepted for family parity; no-op)")
    parser.add_argument("--list-checks", action="store_true",
                        help="list all checks and exit")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="quiet: no banner, no progress, report only")
    parser.add_argument("--batch", action="store_true",
                        help="never ask, never show the menu — run the "
                             "scan straight away")
    parser.add_argument("-i", "--interactive", "--menu", action="store_true",
                        dest="menu",
                        help="open the numbered menu")
    parser.add_argument("--version", action="store_true",
                        help="print the version and exit")
    parser.add_argument("--no-color", action="store_true",
                        help="disable coloured output")
    return parser.parse_args(argv)


def main(argv=None):
    global QUIET
    args = parse_args(argv)
    if args.no_color:
        for name in ("RST", "BLD", "DIM", "RED", "GRN", "YEL", "BLU",
                     "MAG", "CYN", "WHT"):
            setattr(C, name, "")
    if args.version:
        print("APKSeeker v%s by %s" % (VERSION, AUTHOR))
        return 0
    if args.quiet:
        QUIET = True
    try:
        if args.check:
            return doctor()
        if args.list_checks:
            print_banner()
            print_checks()
            return 0
        if args.list and args.apk:
            return do_list(args)
        if args.manifest and args.apk:
            return do_manifest(args)
        # --batch (or --quiet): never ask, never show the menu.
        if args.batch or args.quiet:
            args.apk = args.apk or fixture_path("test_bad.apk")
            return do_scan(args)
        # Menu mode: --menu / -i, or no arguments at all.
        if args.menu or not args.apk:
            return menu_loop(args)
        # Args given but something missing: ask only for the missing part.
        print_banner()
        if not args.apk:
            args.apk = ask_interactive(
                "ENTER APK PATH", fixture_path("test_bad.apk"))
        return do_scan(args)
    except KeyboardInterrupt:
        print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
