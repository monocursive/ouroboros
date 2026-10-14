#!/usr/bin/env python3
"""Check every relative Markdown link and heading anchor in the specifications.

Documentation contract only: a green run says the documents point at files and
headings that exist, nothing more. A link to an evidence archive retired from
HEAD counts as resolved only when its `<file>.retired.json` record sits where
the file was (docs/benchmarks/README.md); the record names the git blobs that
still hold it. Run from the repository root.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS = [ROOT / "README.md", ROOT / "north-star.md", *sorted((ROOT / "docs").rglob("*.md"))]
LINK = re.compile(r"\]\(([^)\s]+)\)")
HEADING = re.compile(r"^(#{1,6})\s+(.*)$")


def anchors(path: pathlib.Path) -> set[str]:
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        m = HEADING.match(line)
        if not m:
            continue
        h = m.group(2).strip().lower()
        h = re.sub(r"[`*_\[\]()]", "", h)
        h = re.sub(r"[^\w\- ]", "", h).replace(" ", "-")
        out.add(h)
    return out


def retired(path: pathlib.Path) -> bool:
    record = path.with_name(path.name + ".retired.json")
    if not record.is_file():
        return False
    data = json.loads(record.read_text(encoding="utf-8"))
    return (data.get("schema") == "ouro.evidence.retired-archive/1"
            and (ROOT / data.get("archive", "")).resolve() == path)


def main() -> int:
    problems = 0
    retired_links = 0
    for doc in DOCS:
        base = doc.parent
        for m in LINK.finditer(doc.read_text(encoding="utf-8")):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path, _, frag = target.partition("#")
            resolved = (base / path).resolve() if path else doc.resolve()
            rel = doc.relative_to(ROOT)
            if not resolved.exists() and retired(resolved):
                retired_links += 1
                continue
            if not resolved.exists():
                print(f"MISSING   {rel} -> {target}")
                problems += 1
                continue
            if frag and resolved.suffix == ".md" and frag not in anchors(resolved):
                print(f"NO ANCHOR {rel} -> {target}")
                problems += 1
    checked = len(DOCS)
    print(f"Checked {checked} documents; {problems} broken links or anchors; "
          f"{retired_links} links to archives retired from HEAD.")
    print("Document contract only; no runtime behavior is tested.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
