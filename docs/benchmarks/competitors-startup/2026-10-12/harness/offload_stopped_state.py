#!/usr/bin/env python3
"""Privately archive stopped benchmark working state; verify every byte first.

Bin, authentication and harness directories are retained on the host. The
private archive must stay outside the public result tree and repository.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--host', required=True)
p.add_argument('--base', required=True)
p.add_argument('--private-archive', type=Path, required=True)
p.add_argument('--record', type=Path, required=True)
p.add_argument('--paths', nargs='+', required=True)
a = p.parse_args()
assert all(part in ['runs', 'results', 'src', 'proxy/data'] for part in a.paths)
assert a.base.startswith('/home/') and all(c.isalnum() or c in '/-_' for c in a.base)
assert not a.private_archive.exists()

inventory_code = '''import hashlib,json,os,stat,subprocess
from pathlib import Path
base=Path(BASE)
rows={}
active=[]
for line in subprocess.check_output(['ps','-u',str(os.getuid()),'-o','pid=,command='],text=True).splitlines():
 if str(base) in line and 'python3 -' not in line:
  active.append(line.split(None,1)[0])
assert not active, ('benchmark working state is still active',active)
for relative in PATHS:
 root=base/relative
 assert root.exists(),root
 for path in [root,*root.rglob('*')]:
  meta=path.lstat()
  row={'mode':stat.S_IMODE(meta.st_mode),'uid':meta.st_uid,'gid':meta.st_gid}
  if path.is_symlink(): row.update(kind='symlink',target=os.readlink(path))
  elif path.is_dir(): row.update(kind='directory')
  elif path.is_file():
   h=hashlib.sha256()
   with path.open('rb') as file:
    for block in iter(lambda:file.read(1<<20),b''): h.update(block)
   row.update(kind='file',bytes=meta.st_size,sha256=h.hexdigest())
  else: raise RuntimeError('unexpected special file '+str(path))
  rows[str(path.relative_to(base))]=row
print(json.dumps(rows))
'''.replace('BASE', repr(a.base)).replace('PATHS', repr(a.paths))

def inventory():
    return json.loads(subprocess.check_output(['ssh', a.host, 'python3', '-'], input=inventory_code.encode()))

before = inventory()
a.private_archive.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
fd = os.open(a.private_archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as output:
    subprocess.run(['ssh', a.host, 'tar', '-C', a.base, '-czf', '-', *a.paths], stdout=output, check=True)
seen = set()
with tarfile.open(a.private_archive) as archive:
    for member in archive:
        name = member.name.rstrip('/')
        expected = before[name]
        assert member.mode == expected['mode'], name
        assert member.uid == expected['uid'] and member.gid == expected['gid'], name
        if expected['kind'] == 'directory': assert member.isdir(), name
        elif expected['kind'] == 'symlink': assert member.issym() and member.linkname == expected['target'], name
        else:
            assert member.isfile() or member.islnk(), name
            h = hashlib.sha256()
            with archive.extractfile(member) as file:
                for block in iter(lambda: file.read(1 << 20), b''): h.update(block)
            assert h.hexdigest() == expected['sha256'], name
        seen.add(name)
assert seen == set(before)
assert inventory() == before, 'source changed while being archived'
# The private local archive is verified; only the selected stopped working
# directories are reclaimed. The original executables and login caches stay.
remove_code = 'import shutil\nfrom pathlib import Path\nbase=Path(%r)\nfor name in %r: shutil.rmtree(base/name)\n' % (a.base, a.paths)
subprocess.run(['ssh', a.host, 'python3', '-'], input=remove_code.encode(), check=True)
h = hashlib.sha256()
with a.private_archive.open('rb') as file:
    for block in iter(lambda: file.read(1 << 20), b''): h.update(block)
record = {'host': a.host, 'base': a.base, 'paths': a.paths,
          'entries_verified': len(before), 'source_bytes': sum(r.get('bytes', 0) for r in before.values()),
          'private_archive': str(a.private_archive), 'archive_bytes': a.private_archive.stat().st_size,
          'archive_sha256': h.hexdigest(), 'verified_before_removal': True,
          'private_archive_exported': False, 'executables_and_authentication_retained': True,
          'restore': 'Upload the private archive and extract with tar -xzf ARCHIVE -C ' + a.base}
a.record.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
