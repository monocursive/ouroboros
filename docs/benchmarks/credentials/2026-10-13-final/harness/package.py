#!/usr/bin/env python3
"""Seal audited credential evidence with per-file and archive hashes."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('--interim', action='store_true', help='Seal explicitly incomplete results; never present them as a full rerun')
    args = p.parse_args()
    root = args.root.resolve()
    pattern = json.loads((root / 'analysis/pattern-audit.json').read_text())
    exact = json.loads((root / 'analysis/credential-audit.json').read_text())
    summary = json.loads((root / ('analysis/interim-vps-pi-summary.json' if args.interim else 'analysis/summary.json')).read_text())
    assert not pattern['hits'] and not exact['actual_credential_hits']
    assert summary['verified_scored_receipts'] == summary['scored_calls']
    if args.interim:
        assert summary['interim'] and summary['scored_calls'] < 42
    else:
        assert not summary['interim'] and summary['scored_calls'] == 42
    files = []
    for path in sorted(root.rglob('*')):
        if '__pycache__' in path.parts or path.name == 'SHA256SUMS':
            continue
        assert not path.is_symlink(), path
        if not path.is_file():
            continue
        assert not path.name.startswith('._') and path.name != '.DS_Store', path
        files.append(path)
    hashes = {str(path.relative_to(root)): sha(path) for path in files}
    manifest = root / 'SHA256SUMS'
    manifest.write_text(''.join(h + '  ' + name + '\n' for name, h in hashes.items()))
    files.append(manifest)
    hashes['SHA256SUMS'] = sha(manifest)
    archive = root.parent / (root.name + ('-interim-evidence.tar.gz' if args.interim else '-evidence.tar.gz'))
    with tarfile.open(archive, 'w:gz') as tar:
        for path in files:
            tar.add(path, arcname=str(path.relative_to(root)), recursive=False)
    verified = 0
    with tarfile.open(archive) as tar:
        for member in tar:
            assert member.isfile() and not Path(member.name).is_absolute() and '..' not in Path(member.name).parts
            assert hashlib.sha256(tar.extractfile(member).read()).hexdigest() == hashes[member.name]
            verified += 1
    assert verified == len(files)
    result = {'schema': 'credential-evidence-bundle/1', 'root': str(root),
              'archive': str(archive), 'archive_bytes': archive.stat().st_size,
              'archive_sha256': sha(archive), 'root_manifest_sha256': sha(manifest),
              'files': len(files), 'uncompressed_bytes': sum(path.stat().st_size for path in files),
              'all_archive_members_hash_verified': True, 'credential_audits_pass': True}
    result['interim'] = args.interim
    result['scored_calls_retained'] = summary['scored_calls']
    result['expected_complete_scored_calls'] = 42
    Path(str(archive) + '.manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
