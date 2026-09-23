#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Generate the UTS 46 revision 35 / Unicode 17.0.0 tables for ouro-jail.

Regenerate (from the repository root) with:

    mkdir -p /tmp/ucd17 && for f in idna/IdnaMappingTable.txt ucd/UnicodeData.txt \
        ucd/DerivedNormalizationProps.txt ucd/extracted/DerivedCombiningClass.txt \
        ucd/extracted/DerivedGeneralCategory.txt ucd/extracted/DerivedBidiClass.txt \
        ucd/extracted/DerivedJoiningType.txt; do \
      curl -fsSL -o /tmp/ucd17/$(basename $f) https://www.unicode.org/Public/17.0.0/$f; done
    uv run crates/ouro-jail/data/gen_uts46_tables.py /tmp/ucd17 \
        crates/ouro-jail/data/uts46_unicode17_tables.rs

The output must be byte-identical to the checked-in file. Every input is
pinned by URL and SHA-256 below; a mismatch aborts, so the output can only
ever be the tables of exactly these files. The output is Rust source that
`crates/ouro-jail/src/network/unicode.rs` includes. It carries no behaviour:
only ranges and mappings copied from the pinned files.

Normative data used:
  IdnaMappingTable.txt          UTS 46 section 5 (status and mapping)
  UnicodeData.txt               canonical decompositions (NFC)
  DerivedNormalizationProps.txt Full_Composition_Exclusion (NFC)
  DerivedCombiningClass.txt     Canonical_Combining_Class (NFC; virama = 9)
  DerivedGeneralCategory.txt    General_Category=Mark (validity criterion 6)
  DerivedBidiClass.txt          Bidi_Class (RFC 5893 via CheckBidi)
  DerivedJoiningType.txt        Joining_Type (RFC 5892 A.1 via CheckJoiners)
"""

import hashlib
import sys
from pathlib import Path

BASE = "https://www.unicode.org/Public/17.0.0/"
PINS = {
    "IdnaMappingTable.txt": (
        BASE + "idna/IdnaMappingTable.txt",
        "87f05505dc026fdb2bff16132bdc68a8014675836882a9a2b1844540ad3be382",
    ),
    "UnicodeData.txt": (
        BASE + "ucd/UnicodeData.txt",
        "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c",
    ),
    "DerivedNormalizationProps.txt": (
        BASE + "ucd/DerivedNormalizationProps.txt",
        "71fd6a206a2c0cdd41feb6b7f656aa31091db45e9cedc926985d718397f9e488",
    ),
    "DerivedCombiningClass.txt": (
        BASE + "ucd/extracted/DerivedCombiningClass.txt",
        "191463abfbd202703c6fd6776a92a23ac44ec65e0476a7f95aa91ca492cef29b",
    ),
    "DerivedGeneralCategory.txt": (
        BASE + "ucd/extracted/DerivedGeneralCategory.txt",
        "d62e5bab70ca74f099343f71224fa051cb1fdd61a1ab45c0488c44cfc0b6102e",
    ),
    "DerivedBidiClass.txt": (
        BASE + "ucd/extracted/DerivedBidiClass.txt",
        "4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4",
    ),
    "DerivedJoiningType.txt": (
        BASE + "ucd/extracted/DerivedJoiningType.txt",
        "f39ebe974825d6736aee15582250307aa532b2cfab3caf3f86bd23fddc9c5c4d",
    ),
}

MAX = 0x10FFFF


def load(ucd, name):
    data = (ucd / name).read_bytes()
    url, pin = PINS[name]
    actual = hashlib.sha256(data).hexdigest()
    if actual != pin:
        sys.exit(f"{name}: sha256 {actual} does not match the pin {pin}")
    return data.decode("utf-8")


def rows(text):
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            yield [field.strip() for field in line.split(";")]


def span(field):
    if ".." in field:
        lo, hi = field.split("..")
        return int(lo, 16), int(hi, 16)
    value = int(field, 16)
    return value, value


def missing_lines(text):
    for raw in text.splitlines():
        if raw.startswith("# @missing:"):
            body = raw[len("# @missing:"):].strip()
            rng, value = [part.strip() for part in body.split(";")]
            yield span(rng), value


def compress(values, keep):
    """Turns a dense per-code-point list into (lo, hi, value) runs for kept values."""
    out = []
    lo = 0
    for cp in range(1, MAX + 2):
        if cp == MAX + 1 or values[cp] != values[lo]:
            if keep(values[lo]):
                out.append((lo, cp - 1, values[lo]))
            lo = cp
    return out


STATUS = {"valid": 0, "ignored": 1, "mapped": 2, "deviation": 3, "disallowed": 4}


def idna_table(text):
    status = [None] * (MAX + 1)
    mapping = [None] * (MAX + 1)
    for fields in rows(text):
        lo, hi = span(fields[0])
        kind = fields[1]
        if kind not in STATUS:
            sys.exit(f"unknown IDNA status {kind!r}")
        target = None
        if kind in ("mapped", "deviation"):
            target = "".join(chr(int(cp, 16)) for cp in fields[2].split())
        elif kind == "ignored":
            target = ""
        for cp in range(lo, hi + 1):
            if status[cp] is not None:
                sys.exit(f"U+{cp:04X} listed twice")
            status[cp] = STATUS[kind]
            mapping[cp] = target
    gaps = [cp for cp in range(MAX + 1) if status[cp] is None]
    if gaps:
        sys.exit(f"IDNA table does not cover {len(gaps)} code points, first U+{gaps[0]:04X}")
    strings = {}
    runs = []
    lo = 0
    for cp in range(1, MAX + 2):
        if (
            cp == MAX + 1
            or status[cp] != status[lo]
            or mapping[cp] != mapping[lo]
        ):
            target = mapping[lo]
            index = 0
            if status[lo] in (STATUS["mapped"], STATUS["deviation"]):
                index = strings.setdefault(target, len(strings))
            runs.append((lo, cp - 1, status[lo], index))
            lo = cp
    return runs, sorted(strings.items(), key=lambda item: item[1])


def canonical_decompositions(text):
    decomp = {}
    for fields in rows(text):
        cp = int(fields[0], 16)
        value = fields[5]
        if value and not value.startswith("<"):
            parts = [int(part, 16) for part in value.split()]
            if not 1 <= len(parts) <= 2:
                sys.exit(f"U+{cp:04X}: canonical decomposition of length {len(parts)}")
            decomp[cp] = parts
    return decomp


def full_composition_exclusion(text):
    excluded = set()
    for fields in rows(text):
        if len(fields) >= 2 and fields[1] == "Full_Composition_Exclusion":
            lo, hi = span(fields[0])
            excluded.update(range(lo, hi + 1))
    return excluded


def dense(text, default, convert):
    values = [default] * (MAX + 1)
    for (lo, hi), value in missing_lines(text):
        for cp in range(lo, hi + 1):
            values[cp] = convert(value)
    for fields in rows(text):
        lo, hi = span(fields[0])
        for cp in range(lo, hi + 1):
            values[cp] = convert(fields[1])
    return values


BIDI_LONG = {
    "Left_To_Right": "L",
    "Right_To_Left": "R",
    "Arabic_Letter": "AL",
    "European_Terminator": "ET",
    "Boundary_Neutral": "BN",
}
# The classes RFC 5893 names; every other class is `Other` (not admitted).
BIDI = {"L": 1, "R": 2, "AL": 3, "AN": 4, "EN": 5, "ES": 6, "CS": 7, "ET": 8,
        "ON": 9, "BN": 10, "NSM": 11}
BIDI_OTHER = {"B", "S", "WS", "LRE", "LRO", "RLE", "RLO", "PDF", "LRI", "RLI", "FSI", "PDI"}
JOINING_LONG = {"Non_Joining": "U"}
JOINING = {"U": 0, "L": 1, "D": 2, "R": 3, "T": 4, "C": 5}


def bidi_value(value):
    value = BIDI_LONG.get(value, value)
    if value in BIDI:
        return BIDI[value]
    if value in BIDI_OTHER:
        return 0
    sys.exit(f"unknown Bidi_Class value {value!r}")


def joining_value(value):
    value = JOINING_LONG.get(value, value)
    if value not in JOINING:
        sys.exit(f"unknown Joining_Type value {value!r}")
    return JOINING[value]


def rust_str(value):
    return '"' + "".join(
        ch if 0x20 <= ord(ch) < 0x7F and ch not in '"\\' else f"\\u{{{ord(ch):x}}}"
        for ch in value
    ) + '"'


def main():
    ucd = Path(sys.argv[1])
    output = Path(sys.argv[2])
    texts = {name: load(ucd, name) for name in PINS}

    runs, strings = idna_table(texts["IdnaMappingTable.txt"])
    decomp = canonical_decompositions(texts["UnicodeData.txt"])
    excluded = full_composition_exclusion(texts["DerivedNormalizationProps.txt"])
    ccc = dense(texts["DerivedCombiningClass.txt"], 0,
                lambda v: 0 if v == "Not_Reordered" else int(v))
    gc = dense(texts["DerivedGeneralCategory.txt"], "Cn", lambda v: v)
    bidi = dense(texts["DerivedBidiClass.txt"], 1, bidi_value)
    joining = dense(texts["DerivedJoiningType.txt"], 0, joining_value)

    compositions = []
    for cp, parts in decomp.items():
        if len(parts) == 2 and cp not in excluded:
            compositions.append((parts[0], parts[1], cp))
    compositions.sort()

    out = []
    w = out.append
    w("// @generated by gen_uts46_tables.py. Do not edit by hand.\n")
    w("//\n// UTS 46 revision 35 over Unicode 17.0.0. Inputs, pinned by SHA-256:\n")
    for name, (url, pin) in PINS.items():
        w(f"//   {url}\n//     sha256 {pin}\n")
    w("//\n// Unicode data (c) Unicode, Inc., used under the Unicode License v3;\n")
    w("// see https://www.unicode.org/terms_of_use.html.\n\n")
    w('/// The Unicode version every table below was generated from.\n')
    w('pub(super) const UNICODE_VERSION: &str = "17.0.0";\n')
    w('/// The UTS 46 revision whose mapping table is below.\n')
    w("pub(super) const UTS46_REVISION: u32 = 35;\n")
    w("/// SHA-256 of the IdnaMappingTable.txt the IDNA runs came from.\n")
    w(f'pub(super) const IDNA_TABLE_SHA256: &str = "{PINS["IdnaMappingTable.txt"][1]}";\n\n')

    w("/// IDNA status runs `(first, last, status, mapping index)`, covering every\n")
    w("/// code point exactly once. Status: 0 valid, 1 ignored, 2 mapped,\n")
    w("/// 3 deviation, 4 disallowed.\n")
    w(f"pub(super) static IDNA_RUNS: [(u32, u32, u8, u16); {len(runs)}] = [\n")
    for lo, hi, status, index in runs:
        w(f"    (0x{lo:X}, 0x{hi:X}, {status}, {index}),\n")
    w("];\n\n")
    w("/// Mapping values for `mapped` and `deviation` runs.\n")
    w(f"pub(super) static IDNA_MAPPINGS: [&str; {len(strings)}] = [\n")
    for value, _ in strings:
        w(f"    {rust_str(value)},\n")
    w("];\n\n")

    ccc_runs = compress(ccc, lambda v: v != 0)
    w("/// Nonzero Canonical_Combining_Class runs `(first, last, class)`.\n")
    w(f"pub(super) static CCC_RUNS: [(u32, u32, u8); {len(ccc_runs)}] = [\n")
    for lo, hi, value in ccc_runs:
        w(f"    (0x{lo:X}, 0x{hi:X}, {value}),\n")
    w("];\n\n")

    items = sorted(decomp.items())
    w("/// Canonical decompositions `(code point, first, second or 0)`, one level.\n")
    w(f"pub(super) static CANONICAL_DECOMPOSITIONS: [(u32, u32, u32); {len(items)}] = [\n")
    for cp, parts in items:
        second = parts[1] if len(parts) == 2 else 0
        w(f"    (0x{cp:X}, 0x{parts[0]:X}, 0x{second:X}),\n")
    w("];\n\n")

    w("/// Primary composites `(first, second, composite)`, sorted by pair.\n")
    w(f"pub(super) static COMPOSITIONS: [(u32, u32, u32); {len(compositions)}] = [\n")
    for first, second, cp in compositions:
        w(f"    (0x{first:X}, 0x{second:X}, 0x{cp:X}),\n")
    w("];\n\n")

    marks = compress([1 if v in ("Mn", "Mc", "Me") else 0 for v in gc], lambda v: v == 1)
    w("/// General_Category=Mark (Mn, Mc, Me) runs.\n")
    w(f"pub(super) static MARK_RUNS: [(u32, u32); {len(marks)}] = [\n")
    for lo, hi, _ in marks:
        w(f"    (0x{lo:X}, 0x{hi:X}),\n")
    w("];\n\n")

    bidi_runs = compress(bidi, lambda v: v != 1)
    w("/// Bidi_Class runs other than L: 2 R, 3 AL, 4 AN, 5 EN, 6 ES, 7 CS, 8 ET,\n")
    w("/// 9 ON, 10 BN, 11 NSM, 0 any class RFC 5893 does not name. Absent is L.\n")
    w(f"pub(super) static BIDI_RUNS: [(u32, u32, u8); {len(bidi_runs)}] = [\n")
    for lo, hi, value in bidi_runs:
        w(f"    (0x{lo:X}, 0x{hi:X}, {value}),\n")
    w("];\n\n")

    joining_runs = compress(joining, lambda v: v != 0)
    w("/// Joining_Type runs: 1 L, 2 D, 3 R, 4 T, 5 C. Absent is U.\n")
    w(f"pub(super) static JOINING_RUNS: [(u32, u32, u8); {len(joining_runs)}] = [\n")
    for lo, hi, value in joining_runs:
        w(f"    (0x{lo:X}, 0x{hi:X}, {value}),\n")
    w("];\n")

    output.write_text("".join(out))
    print(f"idna runs {len(runs)}, mappings {len(strings)}, ccc {len(ccc_runs)}, "
          f"decompositions {len(items)}, compositions {len(compositions)}, "
          f"marks {len(marks)}, bidi {len(bidi_runs)}, joining {len(joining_runs)}")


if __name__ == "__main__":
    main()
