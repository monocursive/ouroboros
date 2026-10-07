#!/usr/bin/env python3
"""Pin ledger wire/storage schemas and their golden fixtures at milestone 2.

This verifies contract bytes, not runtime conformance. Regeneration is an
explicit reviewed contract change; a matching hash is not a compatibility claim.
"""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = "milestone-2-contracts.json"


def contracts(root):
    if (root / "fixtures").is_symlink():
        raise ValueError("contract fixture directory must not be a symlink")
    paths = sorted([*root.glob("*.schema.json"), *root.glob("fixtures/*")])
    result = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"contract must be a regular file: {path}")
        result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not result:
        raise ValueError("no ledger contracts found")
    return {"schema": "ouro.ledger.contract-freeze/1", "milestone": 2, "sha256": result}


def check(root=ROOT):
    manifest = root / MANIFEST
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError("contract freeze manifest must be a regular file")
    expected = json.loads(manifest.read_text())
    actual = contracts(root)
    if expected != actual:
        before, after = expected.get("sha256", {}), actual["sha256"]
        changed = sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))
        raise ValueError("ledger contract freeze drift: " + ", ".join(changed or ["manifest identity"]))
    return len(actual["sha256"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate for an explicit reviewed contract revision")
    args = parser.parse_args()
    if args.write:
        (ROOT / MANIFEST).write_text(json.dumps(contracts(ROOT), indent=2, sort_keys=True) + "\n")
    print(f"ledger milestone-2 contract freeze: {check()} files match")
