#!/usr/bin/env python3
"""Export result evidence, excluding credentials, caches and build products."""
import argparse
import json
from pathlib import Path
import shutil
import tarfile

from agentbench_v2 import scrub, sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--key-file", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    key = args.key_file.read_text().strip()
    stage = args.root / "export-stage"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()
    skip = {"home", "state", "ouro-config", ".git", "node_modules", "__pycache__",
            ".claude", ".codex", ".npm", ".config", ".cache", ".local"}
    suffixes = {".json", ".ndjson", ".jsonl", ".txt", ".log", ".diff", ".yaml",
                ".yml", ".toml", ".py", ".c", ".md", ".sh"}
    manifest = []
    for path in sorted((args.root / "results").rglob("*")):
        rel = path.relative_to(args.root / "results")
        if not path.is_file() or path.suffix not in suffixes or skip & set(rel.parts):
            continue
        if path.name in {"auth.json", "mxc-private.json"} or path.is_symlink():
            continue
        if path.stat().st_size > 64 * 1024 * 1024:
            raise RuntimeError("Unexpectedly large evidence file: " + str(rel))
        text = scrub(path.read_text(errors="replace"), key)
        if key and key in text:
            raise RuntimeError("Credential redaction failed")
        dest = stage / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
        manifest.append({"path": str(rel), "sha256": sha(dest), "bytes": dest.stat().st_size})
    # Record the exact installed harness; individual metadata hashes identify
    # which version ran. Archive snapshots before deploying a newer harness.
    for path in sorted((args.root / "harness").glob("*")):
        if path.is_file() and path.suffix in suffixes:
            dest = stage / "installed-harness" / path.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(scrub(path.read_text(errors="replace"), key))
            manifest.append({"path": str(dest.relative_to(stage)), "sha256": sha(dest),
                             "bytes": dest.stat().st_size})
    (stage / "export-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    with tarfile.open(args.output, "w:gz") as tar:
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                tar.add(path, arcname=str(path.relative_to(stage)), recursive=False)
    print(json.dumps({"files": len(manifest), "archive": str(args.output), "sha256": sha(args.output)}))


if __name__ == "__main__":
    main()
