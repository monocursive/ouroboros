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
    p.add_argument("--auth-file", type=Path)
    args = p.parse_args()
    key = args.key_file.read_text().strip()
    auth_path = args.auth_file or args.root / 'auth/codex/auth.json'
    if not auth_path.exists(): auth_path = Path.home() / '.codex/auth.json'
    tokens = json.loads(auth_path.read_text()).get('tokens', {}) if auth_path.exists() else {}
    # Include newly rotated grants without exporting private provider sources.
    for path in (args.root / 'private').glob('*.json'):
        try:
            document = json.loads(path.read_text())
            if isinstance(document.get('tokens'), dict): document = document['tokens']
            for field in ('access_token', 'refresh_token', 'id_token', 'account_id'):
                if isinstance(document.get(field), str): tokens[str(path.name) + field] = document[field]
        except (ValueError, OSError): pass
    def redact(text):
        text = scrub(text, key)
        for name, value in tokens.items():
            if isinstance(value, str) and value:
                text = text.replace(value, '<CODEX_ACCOUNT_ID>' if name.endswith('account_id') else '<CODEX_OAUTH_TOKEN>')
        return text
    stage = args.root / "export-stage"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()
    skip = {"home", "state", "ouro-config", ".git", "node_modules", "__pycache__",
            ".claude", ".codex", ".npm", ".config", ".cache", ".local"}
    suffixes = {".json", ".ndjson", ".jsonl", ".txt", ".log", ".diff", ".yaml",
                ".yml", ".toml", ".py", ".c", ".md", ".sh", ".csv", ".strace"}
    manifest = []
    for path in sorted((args.root / "results").rglob("*")):
        rel = path.relative_to(args.root / "results")
        if not path.is_file() or path.suffix not in suffixes or skip & set(rel.parts):
            continue
        if path.name in {"auth.json", "mxc-private.json"} or path.is_symlink():
            continue
        if path.stat().st_size > 64 * 1024 * 1024:
            raise RuntimeError("Unexpectedly large evidence file: " + str(rel))
        original = path.read_text(errors="replace")
        text = redact(original)
        if key and key in text:
            raise RuntimeError("Credential redaction failed")
        dest = stage / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
        manifest.append({"path": str(rel), "sha256": sha(dest), "bytes": dest.stat().st_size,
                         'original_sha256': sha(path), 'redacted': original != text})
    # Record the exact installed harness; individual metadata hashes identify
    # which version ran. Archive snapshots before deploying a newer harness.
    for path in sorted((args.root / "harness").glob("*")):
        if path.is_file() and path.suffix in suffixes:
            dest = stage / "installed-harness" / path.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(redact(path.read_text(errors="replace")))
            manifest.append({"path": str(dest.relative_to(stage)), "sha256": sha(dest),
                             "bytes": dest.stat().st_size})
    # Agent receipts refer to attempt journals outside results. Keep the exact
    # journals, with the same redaction as the rest of the export.
    ids = set()
    for receipt_path in (stage).rglob('jail.json'):
        try:
            attempt = json.loads(receipt_path.read_text()).get('attempt_id')
        except ValueError:
            continue
        if isinstance(attempt, str) and attempt.startswith('att_'):
            ids.add(attempt)
    for launches in stage.rglob('launches.ndjson'):
        for line in launches.read_text().splitlines():
            try:
                attempt = json.loads(line).get('receipt', {}).get('attempt_id')
            except ValueError:
                continue
            if isinstance(attempt, str) and attempt.startswith('att_'):
                ids.add(attempt)
    found = set()
    bases = [args.root / 'data-v2', args.root / 'data'] + list((args.root / 'runs').glob('*/data'))
    for base in bases:
        for attempt in sorted(ids):
            source = base / 'attempts' / attempt / 'trace.ndjson'
            if not source.is_file() or source.is_symlink():
                continue
            if source.stat().st_size > 64 * 1024 * 1024:
                raise RuntimeError('Unexpectedly large journal')
            dest = stage / 'attempt-journals' / attempt / 'trace.ndjson'
            dest.parent.mkdir(parents=True, exist_ok=True)
            original = source.read_text(errors='replace')
            sanitized = redact(original)
            dest.write_text(sanitized)
            manifest.append({'path': str(dest.relative_to(stage)), 'sha256': sha(dest), 'bytes': dest.stat().st_size,
                             'original_sha256': sha(source), 'redacted': original != sanitized})
            found.add(attempt)
    (stage / 'journal-export-coverage.json').write_text(json.dumps({'referenced': sorted(ids), 'exported': sorted(found), 'missing': sorted(ids-found)}, indent=2)+'\n')
    (stage / "export-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    with tarfile.open(args.output, "w:gz") as tar:
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                tar.add(path, arcname=str(path.relative_to(stage)), recursive=False)
    print(json.dumps({"files": len(manifest), "archive": str(args.output), "sha256": sha(args.output)}))


if __name__ == "__main__":
    main()
