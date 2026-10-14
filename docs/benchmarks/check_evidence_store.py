#!/usr/bin/env python3
"""Stop the evidence store from growing by accident (docs/benchmarks/README.md).

Fails when:
- a tracked file is larger than 5 MiB and is not listed in
  `evidence-store-allowlist.toml` under `large_files`;
- a corpus directory under docs/benchmarks (the outermost directory whose name
  starts with a date, YYYY-MM-DD) has no `bundle.json` and is not listed under
  `corpora_without_bundle`;
- a `bundle.json` is malformed or its `root_manifest_sha256` is not the
  SHA-256 of the corpus's SHA256SUMS;
- an allowlist entry no longer names a large file or an unbundled corpus
  (the list only shrinks).

Tracked files come from the git index, not the work tree, so the check behaves
the same in sparse and full checkouts; the allowlist is read from the work
tree. Run from anywhere inside the repository.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tomllib

if not __debug__:
    raise SystemExit('check_evidence_store.py must not run with python -O: its checks are gates')

LIMIT = 5 * 1024 * 1024
ROOT = 'docs/benchmarks/'
ALLOWLIST = 'docs/benchmarks/evidence-store-allowlist.toml'
DATED = re.compile(r'^\d{4}-\d{2}-\d{2}')
HEX64 = re.compile(r'^[0-9a-f]{64}$')


def corpora(paths):
    """Outermost date-named directories under docs/benchmarks."""
    found = set()
    for path in paths:
        if not path.startswith(ROOT):
            continue
        parts = path[len(ROOT):].split('/')[:-1]
        for depth, name in enumerate(parts):
            if DATED.match(name):
                found.add(ROOT + '/'.join(parts[:depth + 1]))
                break
    return found


def bundle_problems(corpus, read):
    """read(path) -> bytes or None for a tracked file."""
    raw = read(corpus + '/bundle.json')
    try:
        bundle = json.loads(raw)
    except ValueError:
        return [f'{corpus}/bundle.json is not JSON']
    if not isinstance(bundle, dict):
        return [f'{corpus}/bundle.json is not an object']
    problems = []
    url = bundle.get('url')
    if not isinstance(url, str) or not url.startswith('https://'):
        problems.append(f'{corpus}/bundle.json: url must be an https URL')
    for key in ('sha256', 'root_manifest_sha256'):
        if not isinstance(bundle.get(key), str) or not HEX64.match(bundle[key]):
            problems.append(f'{corpus}/bundle.json: {key} must be 64 lowercase hex digits')
    for key in ('bytes', 'files'):
        if type(bundle.get(key)) is not int or bundle[key] <= 0:
            problems.append(f'{corpus}/bundle.json: {key} must be a positive integer')
    manifest = read(corpus + '/SHA256SUMS')
    if manifest is None:
        problems.append(f'{corpus}: a bundled corpus keeps its SHA256SUMS in git')
    elif hashlib.sha256(manifest).hexdigest() != bundle.get('root_manifest_sha256'):
        problems.append(f'{corpus}/bundle.json: root_manifest_sha256 is not the SHA-256 of SHA256SUMS')
    return problems


def check(sizes, read, allowlist):
    """sizes: {path: bytes} of tracked files; read(path) -> bytes or None."""
    problems = []
    large = {path for path, size in sizes.items() if size > LIMIT}
    allowed = set(allowlist.get('large_files', []))
    for path in sorted(large - allowed):
        problems.append(f'{path}: {sizes[path]} bytes is over 5 MiB and not in {ALLOWLIST}; '
                        'publish it as a release asset and record a bundle.json instead')
    for path in sorted(allowed - large):
        problems.append(f'{ALLOWLIST}: large_files entry {path} is no longer a tracked file over 5 MiB; remove it')
    found = corpora(sizes)
    exempt = set(allowlist.get('corpora_without_bundle', []))
    for corpus in sorted(found):
        if corpus + '/bundle.json' in sizes:
            problems.extend(bundle_problems(corpus, read))
        elif corpus not in exempt:
            problems.append(f'{corpus}: a new evidence corpus needs a bundle.json (docs/benchmarks/README.md)')
    for corpus in sorted(exempt - found):
        problems.append(f'{ALLOWLIST}: corpora_without_bundle entry {corpus} is not a corpus directory; remove it')
    for corpus in sorted(exempt & found):
        if corpus + '/bundle.json' in sizes:
            problems.append(f'{ALLOWLIST}: {corpus} now has a bundle.json; remove it from corpora_without_bundle')
    return problems


def index(repo):
    listing = subprocess.run(['git', '-C', str(repo), 'ls-files', '-s', '-z'], check=True,
                             capture_output=True).stdout
    oids = {}
    for record in filter(None, listing.split(b'\0')):
        meta, path = record.split(b'\t', 1)
        mode, oid, _ = meta.decode().split(' ')
        if mode != '160000':
            oids[path.decode()] = oid
    batch = subprocess.run(['git', '-C', str(repo), 'cat-file', '--batch-check=%(objectsize)'],
                           input=''.join(oid + '\n' for oid in oids.values()).encode(),
                           check=True, capture_output=True).stdout.decode().split()
    sizes = dict(zip(oids, map(int, batch)))

    def read(path):
        if path not in oids:
            return None
        return subprocess.run(['git', '-C', str(repo), 'cat-file', 'blob', oids[path]], check=True,
                              capture_output=True).stdout

    return sizes, read


def main():
    repo = pathlib.Path(__file__).resolve().parents[2]
    sizes, read = index(repo)
    allowlist = tomllib.loads((repo / ALLOWLIST).read_text(encoding='utf-8'))
    problems = check(sizes, read, allowlist)
    for problem in problems:
        print(problem)
    print(f'Checked {len(sizes)} tracked files and {len(corpora(sizes))} evidence corpora; '
          f'{len(problems)} problem(s).')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
