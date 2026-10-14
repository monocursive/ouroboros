#!/usr/bin/env python3
"""Prove that a committed evidence archive duplicates the tracked tree beside it.

`prove ARCHIVE[+PART...]...` streams each archive from git objects, hashes every
member, finds the tracked directory it was made from and writes
`<archive>.retired.json` beside it: the archive's own bytes, SHA-256 and git
blob ids, and the member-by-member comparison. A member counts as identical
only when the tracked file at the same path has the same git blob id and the
same SHA-256. Writing a record does not remove anything; it is the evidence a
removal from HEAD needs.

`verify` re-derives every recorded proof from the archive blobs (still in git
history) and the tracked tree, and fails if any number or digest differs. It
needs a clone with full history; CI's shallow checkout cannot run it.

Run from anywhere inside the repository.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import posixpath
import subprocess
import sys
import tarfile

if not __debug__:
    raise SystemExit('retired_archives.py must not run with python -O: its checks are gates')

SCHEMA = 'ouro.evidence.retired-archive/1'


def git(repo, *args):
    result = subprocess.run(['git', '-C', str(repo), *args], capture_output=True)
    if result.returncode != 0:
        raise SystemExit(f'git {" ".join(args)}: {result.stderr.decode().strip()}')
    return result.stdout


class Blobs:
    """Reads the concatenation of several committed blobs as one stream,
    hashing each blob and the whole as they pass."""

    def __init__(self, repo, oids):
        self.pending = [['git', '-C', str(repo), 'cat-file', 'blob', oid] for oid in oids]
        self.process = None
        self.sha256 = hashlib.sha256()
        self.bytes = 0
        self.part_sha256 = []

    def read(self, size=-1):
        while True:
            if self.process is None:
                if not self.pending:
                    return b''
                self.process = subprocess.Popen(self.pending.pop(0), stdout=subprocess.PIPE)
                self.part_sha256.append(hashlib.sha256())
            data = self.process.stdout.read(size if size and size > 0 else 1 << 20)
            if data:
                self.sha256.update(data)
                self.part_sha256[-1].update(data)
                self.bytes += len(data)
                return data
            self.process.stdout.close()
            if self.process.wait() != 0:
                raise SystemExit('git cat-file failed while reading an archive blob')
            self.process = None


def tracked(repo, commit, prefix):
    """{path: (mode, blob id)} for every file under prefix at commit."""
    out = git(repo, 'ls-tree', '-r', '-z', '--full-tree', commit, '--', prefix)
    entries = {}
    for record in filter(None, out.split(b'\0')):
        meta, path = record.split(b'\t', 1)
        mode, _, oid = meta.decode().split(' ')
        entries[path.decode()] = (mode, oid)
    return entries


def blob_sha256(repo, oids):
    process = subprocess.Popen(['git', '-C', str(repo), 'cat-file', '--batch'],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    digests = {}
    for oid in oids:
        process.stdin.write(oid.encode() + b'\n')
        process.stdin.flush()
        size = int(process.stdout.readline().split()[2])
        digests[oid] = hashlib.sha256(process.stdout.read(size)).hexdigest()
        process.stdout.read(1)
    process.stdin.close()
    process.stdout.close()
    if process.wait() != 0:
        raise SystemExit('git cat-file --batch failed')
    return digests


def git_blob_id(data):
    return hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest()


def members(stream):
    """[(name, kind, blob id, sha256)] in archive order; hard links resolved."""
    out, seen = [], {}
    with tarfile.open(fileobj=stream, mode='r|*') as archive:
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            if member.isdir():
                continue
            if member.isfile():
                data = archive.extractfile(member).read()
                seen[name] = (git_blob_id(data), hashlib.sha256(data).hexdigest())
                out.append((name, 'file', *seen[name]))
            elif member.issym():
                data = member.linkname.encode()
                out.append((name, 'symlink', git_blob_id(data), hashlib.sha256(data).hexdigest()))
            elif member.islnk():
                out.append((name, 'file', *seen[member.linkname.removeprefix('./')]))
            else:
                out.append((name, 'other', None, None))
    return out


def choose_root(listing, files, home):
    """The tracked directory that holds the most members byte-for-byte; ties go
    to the one nearest the archive."""
    by_name = collections.defaultdict(list)
    for path in files:
        by_name[posixpath.basename(path)].append(path)
    votes = collections.Counter()
    for name, *_ in listing:
        for path in by_name.get(posixpath.basename(name), []):
            if path == name or path.endswith('/' + name):
                votes[path[:len(path) - len(name)].rstrip('/')] += 1

    def score(root):
        same = sum(1 for name, _, oid, _ in listing if files.get(posixpath.join(root, name), (None, None))[1] == oid)
        return same, len(posixpath.commonpath([root, home])) if root else 0

    candidates = [root for root, _ in votes.most_common(6)]
    return max(candidates, key=score) if candidates else None


def compare(repo, listing, files, root):
    paths = {name: posixpath.join(root, name) for name, *_ in listing}
    digests = blob_sha256(repo, sorted({files[p][1] for p in paths.values() if p in files}))
    identical, differing, untracked = 0, [], []
    for name, kind, oid, sha in listing:
        entry = files.get(paths[name])
        if kind == 'other' or entry is None:
            untracked.append(name)
        elif (entry[0] == '120000') != (kind == 'symlink') or entry[1] != oid or digests[entry[1]] != sha:
            differing.append(name)
        else:
            identical += 1
    return identical, sorted(differing), sorted(untracked)


def read_archive(repo, commit, parts):
    """The archive's identity and member listing, from the blobs at commit."""
    oids = [git(repo, 'rev-parse', f'{commit}:{part}').decode().strip() for part in parts]
    stream = Blobs(repo, oids)
    listing = members(stream)
    # Drain trailing padding so the digests cover every byte of every part.
    while stream.read():
        pass
    identity = {
        'archive': parts[0] if len(parts) == 1 else parts[0].rsplit('.part', 1)[0],
        'parts': [{'path': p, 'bytes': int(git(repo, 'cat-file', '-s', o)), 'sha256': h.hexdigest(), 'git_blob': o}
                  for p, o, h in zip(parts, oids, stream.part_sha256)],
        'bytes': stream.bytes,
        'sha256': stream.sha256.hexdigest(),
    }
    return identity, listing


def proof(repo, commit, parts, identity, listing, root=None):
    """Member-by-member comparison of listing with the tree at commit."""
    corpus = '/'.join(parts[0].split('/')[:3])
    files = tracked(repo, commit, corpus)
    if root is None:
        root = choose_root(listing, files, posixpath.dirname(parts[0]))
    if root is None:
        raise SystemExit(f'{parts[0]}: no member matches a tracked path under {corpus}')
    identical, differing, untracked = compare(repo, listing, files, root)
    kinds = collections.Counter(kind for _, kind, *_ in listing)
    return {
        'schema': SCHEMA,
        **identity,
        'members': dict(sorted(kinds.items())),
        'duplicate_of': root + '/',
        'members_identical': identical,
        'members_differing': differing,
        'members_without_tracked_file': untracked,
        'member_listing_sha256': hashlib.sha256(''.join(
            f'{sha or "-"}  {name}\n' for name, _, _, sha in sorted(listing)).encode()).hexdigest(),
    }


def record_path(repo, archive):
    return pathlib.Path(repo) / (archive + '.retired.json')


def prove(repo, commit, specs):
    for spec in specs:
        parts = spec.split('+')
        result = proof(repo, commit, parts, *read_archive(repo, commit, parts))
        complete = (not result['members_differing'] and not result['members_without_tracked_file']
                    and result['members_identical'] == sum(result['members'].values()))
        if not complete:
            print(f'NOT A DUPLICATE {result["archive"]}: {len(result["members_differing"])} differing, '
                  f'{len(result["members_without_tracked_file"])} without a tracked file; no record written')
            continue
        added = git(repo, 'log', '--diff-filter=A', '--format=%H', '-1', commit, '--', parts[0]).decode().strip()
        result.update(added_in=added, proved_at=git(repo, 'rev-parse', commit).decode().strip())
        target = record_path(repo, result['archive'])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(result, indent=2) + '\n')
        print(f'DUPLICATE {result["archive"]}: {result["members_identical"]} members identical to '
              f'{result["duplicate_of"]}; wrote {target.name}')


def verify(repo, commit):
    names = git(repo, 'ls-tree', '-r', '-z', '--name-only', commit, '--', 'docs/benchmarks').split(b'\0')
    problems = 0
    for name in (n.decode() for n in names if n.endswith(b'.retired.json')):
        recorded = json.loads(git(repo, 'show', f'{commit}:{name}'))
        if recorded.get('schema') != SCHEMA or name != recorded['archive'] + '.retired.json':
            print(f'BAD RECORD {name}')
            problems += 1
            continue
        parts = [part['path'] for part in recorded['parts']]
        root = recorded['duplicate_of'].rstrip('/')
        # Re-derive the proof as made (archive and tree at proved_at), then ask
        # whether the tree under test still holds every member.
        identity, listing = read_archive(repo, recorded['proved_at'], parts)
        derived = proof(repo, recorded['proved_at'], parts, identity, listing, root)
        current = proof(repo, commit, parts, identity, listing, root)
        expected = {k: v for k, v in recorded.items() if k not in ('added_in', 'proved_at')}
        if derived != expected:
            print(f'MISMATCH {name}: the archive at {recorded["proved_at"]} does not derive the recorded proof')
            problems += 1
        elif current['members_differing'] or current['members_without_tracked_file']:
            print(f'DIVERGED {name}: the tree at {commit} no longer holds every member '
                  f'({len(current["members_differing"])} differing, '
                  f'{len(current["members_without_tracked_file"])} missing)')
            problems += 1
        else:
            print(f'OK {name}: {recorded["members_identical"]} members still identical in {recorded["duplicate_of"]}')
    print(f'{problems} problem(s).')
    return 1 if problems else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--repo', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[2])
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prove')
    p.add_argument('--commit', default='HEAD')
    p.add_argument('archives', nargs='+', help='repository-relative path; join split parts with +')
    v = sub.add_parser('verify')
    v.add_argument('--commit', default='HEAD', help='tree that must still hold every member')
    args = parser.parse_args()
    if args.command == 'prove':
        prove(args.repo, args.commit, args.archives)
        return 0
    return verify(args.repo, args.commit)


if __name__ == '__main__':
    sys.exit(main())
