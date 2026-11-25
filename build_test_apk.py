#!/usr/bin/env python3
"""Build the lab test APKs for APKSeeker.

No Android Studio here — the fixtures are built by hand:
  * a hand-written AXML WRITER (the inverse of apkseeker.py's parser):
    takes a small element tree and writes a binary AndroidManifest.xml
    (deduped UTF-16 string pool, an optional resource-map chunk the
    parser must skip, start/end element chunks with typed values);
  * a minimal classes.dex (magic + header + string pool holding the
    planted secret strings + a map list). It is structurally a dex
    (header, string ids, data, map) — it is NOT claimed to be runnable;
  * a network security config as binary AXML (same writer).

Re-run any time with:  python run.py build-apk
                         python3 build_test_apk.py

Fixtures written to test_apks/:
  test_bad.apk     — dangerous permissions, exported components,
                     debuggable + allowBackup, old target SDK, planted
                     secrets, a custom deep-link scheme, .so files,
                     a cleartext-permitting network security config.
  test_clean.apk   — one normal permission, nothing exported, flags off,
                     target SDK 34, no secrets, no .so, no cleartext.
  test_minimal.apk — manifest only, no dex at all (the scanner must cope).
"""

import hashlib
import os
import struct
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "test_apks")

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# --- AXML chunk types (ResourceTypes.h) ----------------------------------
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101

# Real android.R.attr resource IDs for the attributes the fixtures use
# (verified against Androguard's public SYSTEM_RESOURCES table).
# Only attributes in the android namespace have one; "package",
# "versionCode" etc. are covered too where they exist.
ANDROID_ATTR_IDS = {
    "label": 0x01010001,
    "icon": 0x01010002,
    "name": 0x01010003,
    "permission": 0x01010006,
    "debuggable": 0x0101000F,
    "exported": 0x01010010,
    "authorities": 0x01010018,
    "scheme": 0x01010027,
    "host": 0x01010028,
    "minSdkVersion": 0x0101020C,
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    "targetSdkVersion": 0x01010270,
    "allowBackup": 0x01010280,
    "usesCleartextTraffic": 0x010104EC,
}
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104

TYPE_STRING = 0x03
TYPE_REFERENCE = 0x01
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

ABSENT = 0xFFFFFFFF


def uleb128(n):
    """Encode a small non-negative int as unsigned LEB128."""
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


class AXMLWriter:
    """Turn a small element tree into binary AXML (UTF-16 string pool).

    A tree node is a dict:
        {"name": "manifest",
         "attrs": [(ns_or_None, "name", ("string"|"int"|"bool"|"hex"|"ref", value))],
         "children": [...],
         "text": "optional character data or None"}
    """

    def __init__(self):
        self.strings = []
        self.index = {}

    def s(self, text):
        """Add a string to the pool (deduped) and return its index."""
        if text not in self.index:
            self.index[text] = len(self.strings)
            self.strings.append(text)
        return self.index[text]

    def _collect(self, node):
        self.s(node["name"])
        for ns, name, _value in node.get("attrs", []):
            if ns:
                self.s(ns)
            self.s(name)
            _kind, val = _value
            if _kind == "string":
                self.s(val)
        if node.get("text"):
            self.s(node["text"])
        for child in node.get("children", []):
            self._collect(child)

    def _pool_chunk(self):
        # String data: u16 char-count, UTF-16LE units, u16 null, padded to 4.
        blobs = []
        offsets = []
        pos = 0
        for text in self.strings:
            offsets.append(pos)
            encoded = text.encode("utf-16-le")
            blob = struct.pack("<H", len(text)) + encoded + struct.pack("<H", 0)
            while len(blob) % 4:
                blob += b"\x00"
            blobs.append(blob)
            pos += len(blob)
        data = b"".join(blobs)
        count = len(self.strings)
        strings_start = 28 + 4 * count
        header = struct.pack(
            "<HHIIIIII",
            RES_STRING_POOL_TYPE, 28, 28 + 4 * count + len(data),
            count, 0, 0, strings_start, 0,
        )
        return header + b"".join(struct.pack("<I", o) for o in offsets) + data

    def _chunk_header(self, ctype, header_size, size):
        return struct.pack("<HHI", ctype, header_size, size)

    def _namespace_chunk(self, ctype, prefix, uri):
        body = struct.pack(
            "<II", 0, ABSENT,  # lineNumber, comment
        ) + struct.pack("<II", self.s(prefix), self.s(uri))
        # size = 8-byte chunk header + the body (node + prefix + uri).
        return self._chunk_header(ctype, 16, 8 + len(body)) + body

    def _element_chunks(self, node):
        out = bytearray()
        name_idx = self.s(node["name"])
        attrs = node.get("attrs", [])
        attr_size = 20
        # size = 16-byte node (chunk header included) + attrExt (20)
        # + one 20-byte attribute record per attribute.
        start_size = 16 + 20 + attr_size * len(attrs)
        out += self._chunk_header(RES_XML_START_ELEMENT_TYPE, 16, start_size)
        out += struct.pack("<II", 0, ABSENT)  # lineNumber, comment
        out += struct.pack(
            "<IIHHHHHH",
            ABSENT, name_idx, 20, attr_size, len(attrs),
            0xFFFF, 0xFFFF, 0xFFFF,  # idIndex, classIndex, styleIndex
        )
        for ns, name, value in attrs:
            kind, val = value
            ns_idx = self.s(ns) if ns else ABSENT
            name_idx_a = self.s(name)
            if kind == "string":
                data_idx = self.s(val)
                out += struct.pack(
                    "<IIIHBBI",
                    ns_idx, name_idx_a, data_idx, 8, 0, TYPE_STRING, data_idx,
                )
            elif kind == "int":
                out += struct.pack(
                    "<IIIHBBI",
                    ns_idx, name_idx_a, ABSENT, 8, 0, TYPE_INT_DEC, val,
                )
            elif kind == "hex":
                out += struct.pack(
                    "<IIIHBBI",
                    ns_idx, name_idx_a, ABSENT, 8, 0, TYPE_INT_HEX, val,
                )
            elif kind == "bool":
                out += struct.pack(
                    "<IIIHBBI",
                    ns_idx, name_idx_a, ABSENT, 8, 0, TYPE_INT_BOOLEAN,
                    1 if val else 0,
                )
            elif kind == "ref":
                out += struct.pack(
                    "<IIIHBBI",
                    ns_idx, name_idx_a, ABSENT, 8, 0, TYPE_REFERENCE, val,
                )
            else:  # pragma: no cover - guarded by the generator only
                raise ValueError("unknown attribute kind: %r" % (kind,))
        if node.get("text"):
            text_idx = self.s(node["text"])
            out += self._chunk_header(RES_XML_CDATA_TYPE, 16, 20)
            out += struct.pack("<II", 0, ABSENT)
            out += struct.pack("<I", text_idx)
        for child in node.get("children", []):
            out += self._element_chunks(child)
        out += self._chunk_header(RES_XML_END_ELEMENT_TYPE, 16, 24)
        out += struct.pack("<II", 0, ABSENT)
        out += struct.pack("<II", ABSENT, name_idx)
        return bytes(out)

    def build(self, root, with_resource_map=True):
        """Return the complete binary AXML document for `root`."""
        self._collect(root)
        self.s(ANDROID_NS)
        self.s("android")
        body = bytearray()
        body += self._pool_chunk()
        if with_resource_map:
            # The resource map is indexed by STRING-POOL index: entry i
            # holds the Android resource ID of the attribute whose name
            # is pool string i, or 0 when that string is not an Android
            # attribute. Getting this wrong corrupts other readers: a
            # stray ID at the wrong index makes Androguard rename the
            # attribute (it once turned "package" into "icon" because
            # index 1 wrongly held the icon ID 0x01010002). IDs below
            # are the real android.R.attr values.
            ids = [ANDROID_ATTR_IDS.get(s, 0) for s in self.strings]
            body += self._chunk_header(
                RES_XML_RESOURCE_MAP_TYPE, 8, 8 + 4 * len(ids)
            )
            for rid in ids:
                body += struct.pack("<I", rid)
        body += self._namespace_chunk(
            RES_XML_START_NAMESPACE_TYPE, "android", ANDROID_NS
        )
        body += self._element_chunks(root)
        body += self._namespace_chunk(
            RES_XML_END_NAMESPACE_TYPE, "android", ANDROID_NS
        )
        total = 8 + len(body)
        return self._chunk_header(RES_XML_TYPE, 8, total) + bytes(body)


def build_axml(root, with_resource_map=True):
    """Convenience: build binary AXML from one element tree."""
    return AXMLWriter().build(root, with_resource_map=with_resource_map)


# --- Minimal dex -----------------------------------------------------------
def build_dex(strings):
    """Build a structurally valid minimal dex holding `strings`.

    Layout: header (0x70) -> string_ids -> string_data items -> map_list.
    Only the string pool carries content; there are no types, methods or
    classes. The secret scanner reads raw bytes, so the planted strings
    only need to be present — the header/map make the file a real dex
    shape rather than a bare blob. NOT claimed to be runnable.
    """
    items = []
    for text in strings:
        encoded = text.encode("utf-8")
        items.append(uleb128(len(text)) + encoded + b"\x00")
    n = len(strings)
    ids_off = 0x70
    data_off = ids_off + 4 * n
    offsets = []
    pos = data_off
    for item in items:
        offsets.append(pos)
        pos += len(item)
    map_off = pos
    map_entries = [
        (0x0000, 1, 0),          # header
        (0x0001, n, ids_off),    # string ids
        (0x1000, 1, map_off),    # map list
        (0x2002, n, data_off),   # string data
    ]
    map_list = struct.pack("<I", len(map_entries))
    for mtype, size, off in map_entries:
        map_list += struct.pack("<HHII", mtype, 0, size, off)
    file_size = map_off + len(map_list)
    data_size = file_size - data_off

    header = bytearray()
    header += b"dex\n035\x00"
    header += b"\x00\x00\x00\x00"              # checksum (patched below)
    header += b"\x00" * 20                     # signature (patched below)
    header += struct.pack(
        "<I", file_size,
    )
    header += struct.pack(
        "<IIIIIIII",
        0x70, 0x12345678, 0, 0, map_off, n, ids_off, 0,
    )
    header += struct.pack(
        "<IIIIIIIIIII",
        0, 0, 0, 0, 0, 0, 0, 0, 0, data_size, data_off,
    )
    assert len(header) == 0x70, len(header)
    body = bytes(header)
    body += b"".join(struct.pack("<I", o) for o in offsets)
    body += b"".join(items)
    body += map_list
    assert len(body) == file_size, (len(body), file_size)
    # Patch the signature first (SHA-1 of everything after it), then
    # the checksum (adler32 of everything after it, signature included).
    # Computing the checksum before the signature lands gives a wrong
    # value — strict dex readers (e.g. Androguard) reject the file.
    signature = hashlib.sha1(body[32:]).digest()
    body = body[:12] + signature + body[32:]
    checksum = zlib.adler32(body[12:]) & 0xFFFFFFFF
    body = body[:8] + struct.pack("<I", checksum) + body[12:]
    return body


# --- Fixture trees ---------------------------------------------------------
def _attr(name, kind, value):
    return (ANDROID_NS, name, (kind, value))


def _plain_attr(name, kind, value):
    return (None, name, (kind, value))


BAD_MANIFEST = {
    "name": "manifest",
    "attrs": [
        _plain_attr("package", "string", "com.example.labapp"),
        _plain_attr("versionCode", "int", 1),
        _plain_attr("versionName", "string", "1.0"),
    ],
    "children": [
        {"name": "uses-sdk", "attrs": [
            _attr("minSdkVersion", "int", 21),
            _attr("targetSdkVersion", "int", 28),
        ], "children": []},
        {"name": "uses-permission", "attrs": [
            _attr("name", "string", "android.permission.INTERNET"),
        ], "children": []},
        {"name": "uses-permission", "attrs": [
            _attr("name", "string", "android.permission.ACCESS_FINE_LOCATION"),
        ], "children": []},
        {"name": "uses-permission", "attrs": [
            _attr("name", "string", "android.permission.CAMERA"),
        ], "children": []},
        {"name": "uses-permission", "attrs": [
            _attr("name", "string", "android.permission.SEND_SMS"),
        ], "children": []},
        {"name": "uses-permission", "attrs": [
            _attr("name", "string", "android.permission.READ_CONTACTS"),
        ], "children": []},
        {"name": "uses-permission", "attrs": [
            _attr("name", "string", "android.permission.ACCESS_NETWORK_STATE"),
        ], "children": []},
        {"name": "application", "attrs": [
            _attr("debuggable", "bool", True),
            _attr("allowBackup", "bool", True),
            _attr("usesCleartextTraffic", "bool", True),
            _attr("label", "string", "LabApp"),
            _attr("icon", "ref", 0x7F020000),
        ], "children": [
            {"name": "activity", "attrs": [
                _attr("name", "string", ".MainActivity"),
                _attr("exported", "bool", True),
            ], "children": [
                {"name": "intent-filter", "attrs": [], "children": [
                    {"name": "action", "attrs": [
                        _attr("name", "string", "android.intent.action.MAIN"),
                    ], "children": []},
                    {"name": "category", "attrs": [
                        _attr("name", "string", "android.intent.category.LAUNCHER"),
                    ], "children": []},
                ]},
            ]},
            {"name": "activity", "attrs": [
                _attr("name", "string", ".ShareActivity"),
            ], "children": [
                {"name": "intent-filter", "attrs": [], "children": [
                    {"name": "action", "attrs": [
                        _attr("name", "string", "android.intent.action.SEND"),
                    ], "children": []},
                    {"name": "category", "attrs": [
                        _attr("name", "string", "android.intent.category.DEFAULT"),
                    ], "children": []},
                    {"name": "data", "attrs": [
                        _attr("scheme", "string", "labapp"),
                        _attr("host", "string", "share"),
                    ], "children": []},
                ]},
            ]},
            {"name": "activity", "attrs": [
                _attr("name", "string", ".SecretActivity"),
                _attr("exported", "bool", False),
            ], "children": [
                {"name": "intent-filter", "attrs": [], "children": [
                    {"name": "action", "attrs": [
                        _attr("name", "string", "android.intent.action.VIEW"),
                    ], "children": []},
                ]},
            ]},
            {"name": "service", "attrs": [
                _attr("name", "string", ".SyncService"),
                _attr("exported", "bool", False),
            ], "children": []},
            {"name": "receiver", "attrs": [
                _attr("name", "string", ".BootReceiver"),
                _attr("exported", "bool", True),
                _attr("permission", "string", "android.permission.RECEIVE_BOOT_COMPLETED"),
            ], "children": [
                {"name": "intent-filter", "attrs": [], "children": [
                    {"name": "action", "attrs": [
                        _attr("name", "string", "android.intent.action.BOOT_COMPLETED"),
                    ], "children": []},
                ]},
            ]},
            {"name": "provider", "attrs": [
                _attr("name", "string", ".LabProvider"),
                _attr("exported", "bool", False),
                _attr("authorities", "string", "com.example.labapp.provider"),
            ], "children": []},
        ]},
    ],
}

BAD_CONFIG = {
    "name": "network-security-config",
    "attrs": [],
    "children": [
        {"name": "base-config", "attrs": [
            _plain_attr("cleartextTrafficPermitted", "bool", True),
        ], "children": [
            {"name": "trust-anchors", "attrs": [], "children": [
                {"name": "certificates", "attrs": [
                    _plain_attr("src", "string", "system"),
                ], "children": []},
            ]},
        ]},
        {"name": "domain-config", "attrs": [
            _plain_attr("cleartextTrafficPermitted", "bool", True),
        ], "children": [
            {"name": "domain", "attrs": [
                _plain_attr("includeSubdomains", "bool", True),
            ], "children": [], "text": "api.example.com"},
            {"name": "trust-anchors", "attrs": [], "children": [
                {"name": "certificates", "attrs": [
                    _plain_attr("src", "string", "user"),
                ], "children": []},
            ]},
        ]},
    ],
}

# Planted secrets — FAKE values for the lab only (never real keys).
GOOGLE_KEY = "AIza" + "SyBFAKEKEY1234567890abcdefghijklmno"  # AIza + 35
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"                              # AKIA + 16
assert len(GOOGLE_KEY) == 39, len(GOOGLE_KEY)
assert len(AWS_KEY) == 20, len(AWS_KEY)

BAD_DEX_STRINGS = [
    "Lcom/example/labapp/MainActivity;",
    "Landroid/app/Activity;",
    "Lcom/example/labapp/ApiClient;",
    "https://api.example.com/v1/sync",
    "api_key=" + GOOGLE_KEY,
    "aws_access_key_id=" + AWS_KEY,
    'password = "hunter2-secret-99"',
    "https://10.0.0.5:8080/api/v1",
    "Lcom/example/labapp/SyncService;",
    "LabApp sync complete",
]

BAD_ARSC_STRINGS = (
    b"\x02\x00\x00\x00"  # tiny fake arsc header bytes
    b'api_key = "AKSEEKER-FAKE-KEY-9876543210"\x00'
    b"LabApp resources\x00"
)

CLEAN_MANIFEST = {
    "name": "manifest",
    "attrs": [
        _plain_attr("package", "string", "com.example.cleanapp"),
        _plain_attr("versionCode", "int", 1),
        _plain_attr("versionName", "string", "1.0"),
    ],
    "children": [
        {"name": "uses-sdk", "attrs": [
            _attr("minSdkVersion", "int", 26),
            _attr("targetSdkVersion", "int", 34),
        ], "children": []},
        {"name": "uses-permission", "attrs": [
            _attr("name", "string", "android.permission.INTERNET"),
        ], "children": []},
        {"name": "uses-permission", "attrs": [
            _attr("name", "string", "android.permission.ACCESS_NETWORK_STATE"),
        ], "children": []},
        {"name": "application", "attrs": [
            _attr("debuggable", "bool", False),
            _attr("allowBackup", "bool", False),
            _attr("usesCleartextTraffic", "bool", False),
            _attr("label", "string", "CleanApp"),
        ], "children": [
            {"name": "activity", "attrs": [
                _attr("name", "string", ".MainActivity"),
                _attr("exported", "bool", False),
            ], "children": []},
        ]},
    ],
}

CLEAN_DEX_STRINGS = [
    "Lcom/example/cleanapp/MainActivity;",
    "Landroid/app/Activity;",
    "https://api.example.com/v1/sync",
    "CleanApp started",
]

MINIMAL_MANIFEST = {
    "name": "manifest",
    "attrs": [
        _plain_attr("package", "string", "com.example.minimal"),
        _plain_attr("versionCode", "int", 1),
        _plain_attr("versionName", "string", "1.0"),
    ],
    "children": [
        {"name": "uses-sdk", "attrs": [
            _attr("minSdkVersion", "int", 26),
            _attr("targetSdkVersion", "int", 34),
        ], "children": []},
        {"name": "application", "attrs": [
            _attr("debuggable", "bool", False),
            _attr("allowBackup", "bool", False),
            _attr("label", "string", "MinimalApp"),
        ], "children": [
            {"name": "activity", "attrs": [
                _attr("name", "string", ".MainActivity"),
                _attr("exported", "bool", False),
            ], "children": []},
        ]},
    ],
}

FAKE_SO = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64


def _write_apk(path, manifest_tree, dex_strings=None, extra_entries=None):
    """Assemble one APK zip from a manifest tree + optional dex + extras.

    Zip entry timestamps are pinned to 1980-01-01 so the output is
    byte-for-byte reproducible: running `python run.py build-apk`
    twice produces identical files, and anyone cloning the repo can
    verify the fixtures match the generator exactly (md5sum). The
    scanner reads entry contents, never timestamps, so the pinned
    date changes nothing about a scan.
    """
    fixed_date = (1980, 1, 1, 0, 0, 0)

    def _add(zf, name, data):
        info = zipfile.ZipInfo(name, date_time=fixed_date)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o600 << 16
        zf.writestr(info, data)

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        _add(zf, "AndroidManifest.xml", build_axml(manifest_tree))
        if dex_strings is not None:
            _add(zf, "classes.dex", build_dex(dex_strings))
        for name, data in (extra_entries or []):
            _add(zf, name, data)


def build_all(out_dir=OUT_DIR):
    """(Re)generate all three fixtures. Returns the paths written."""
    os.makedirs(out_dir, exist_ok=True)
    bad = os.path.join(out_dir, "test_bad.apk")
    clean = os.path.join(out_dir, "test_clean.apk")
    minimal = os.path.join(out_dir, "test_minimal.apk")
    _write_apk(
        bad, BAD_MANIFEST, BAD_DEX_STRINGS,
        extra_entries=[
            ("resources.arsc", BAD_ARSC_STRINGS),
            ("res/xml/network_security_config.xml", build_axml(BAD_CONFIG)),
            ("lib/armeabi-v7a/liblab.so", FAKE_SO),
            ("lib/arm64-v8a/liblab.so", FAKE_SO),
            ("lib/x86/liblab.so", FAKE_SO),
            ("lib/x86_64/liblab.so", FAKE_SO),
        ],
    )
    _write_apk(
        clean, CLEAN_MANIFEST, CLEAN_DEX_STRINGS,
        extra_entries=[("resources.arsc", b"\x02\x00\x00\x00CleanApp resources\x00")],
    )
    _write_apk(minimal, MINIMAL_MANIFEST)
    return [bad, clean, minimal]


if __name__ == "__main__":
    for path in build_all():
        print("wrote %s (%d bytes)" % (path, os.path.getsize(path)))
