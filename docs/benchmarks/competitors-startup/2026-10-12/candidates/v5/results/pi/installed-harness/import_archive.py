#!/usr/bin/env python3
"""Import a sanitized export, verify it, and retain any changed prior files."""
import argparse,hashlib,json,shutil,tarfile
from pathlib import Path
def main():
 p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('destination',type=Path);a=p.parse_args();changed=[];new=0
 with tarfile.open(a.archive) as tar:
  for member in tar.getmembers():
   rel=Path(member.name)
   assert member.isfile() and not rel.is_absolute() and '..' not in rel.parts,member.name
   data=tar.extractfile(member).read();dest=a.destination/rel
   if dest.exists() and dest.read_bytes()!=data:
    old=a.destination/'import-history'/hashlib.sha256(dest.read_bytes()).hexdigest()/rel
    old.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(dest,old);changed.append(member.name)
   elif not dest.exists():new+=1
   dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
 manifest=json.loads((a.destination/'export-manifest.json').read_text())
 for row in manifest:
  path=a.destination/row['path'];assert path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()==row['sha256'],row['path']
 print(json.dumps({'archive_sha256':hashlib.sha256(a.archive.read_bytes()).hexdigest(),'files':len(manifest),'new':new,'changed_preserved':changed}))
if __name__=='__main__':main()
