#!/usr/bin/env python3
"""Audit retained evidence and nested tar members without printing secret values."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('--private-values', type=Path, required=True)
    a = p.parse_args()
    values = {v.encode() for v in json.loads(a.private_values.read_text()).values()
              if isinstance(v, str) and v}
    exact, patterns, files = [], [], []
    rules = {
        'anthropic_key': rb'sk-ant-(?:usr|api)[A-Za-z0-9_-]{20,}',
        'openai_key': rb'sk-(?:proj-)?[A-Za-z0-9_-]{40,}',
        'jwt': rb'eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}',
        'private_key': rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    }

    def scan(name, data, depth=0):
        files.append({'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
        if any(v in data for v in values):
            exact.append(name)
        for key, pattern in rules.items():
            if re.search(pattern, data):
                patterns.append({'path': name, 'kind': key})
        if name.endswith('.tar.gz'):
            assert depth < 4, 'Unexpected archive nesting'
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as t:
                for member in t:
                    assert member.isfile(), name
                    assert not Path(member.name).is_absolute() and '..' not in Path(member.name).parts
                    scan(name + '::' + member.name, t.extractfile(member).read(), depth + 1)

    for path in sorted(a.root.rglob('*')):
        if not path.is_file() or '__pycache__' in path.parts:
            continue
        if path.name == 'SHA256SUMS' or path.parent == a.root / 'analysis' and path.name in {
                'credential-audit.json', 'pattern-audit.json'}:
            continue
        assert not path.is_symlink(), path
        scan(str(path.relative_to(a.root)), path.read_bytes())
    a.root.joinpath('analysis').mkdir(exist_ok=True)
    (a.root / 'analysis/credential-audit.json').write_text(json.dumps({
        'schema': 'exact-credential-evidence-audit/1', 'distinct_private_values': len(values),
        'checked_files_and_archive_members': len(files), 'actual_credential_hits': exact,
        'actual_values_retained': False, 'checks': files}, indent=2) + '\n')
    (a.root / 'analysis/pattern-audit.json').write_text(json.dumps({
        'schema': 'credential-pattern-evidence-audit/1', 'checked_files_and_archive_members': len(files),
        'pattern_names': list(rules), 'hits': patterns}, indent=2) + '\n')
    print(json.dumps({'checked': len(files), 'exact_hits': len(exact), 'pattern_hits': len(patterns)}))
    if exact or patterns:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
