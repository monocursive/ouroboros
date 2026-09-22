#!/usr/bin/env python3
"""Check every relative Markdown link and heading anchor in the specifications.

Documentation contract only: a green run says the documents point at files and
headings that exist, nothing more. Run from the repository root.
"""
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


def main() -> int:
    problems = 0
    for doc in DOCS:
        base = doc.parent
        for m in LINK.finditer(doc.read_text(encoding="utf-8")):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path, _, frag = target.partition("#")
            resolved = (base / path).resolve() if path else doc.resolve()
            rel = doc.relative_to(ROOT)
            if not resolved.exists():
                print(f"MISSING   {rel} -> {target}")
                problems += 1
                continue
            if frag and resolved.suffix == ".md" and frag not in anchors(resolved):
                print(f"NO ANCHOR {rel} -> {target}")
                problems += 1
    checked = len(DOCS)
    print(f"Checked {checked} documents; {problems} broken links or anchors.")
    print("Document contract only; no runtime behavior is tested.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
