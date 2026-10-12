#!/usr/bin/env python3
"""Create and verify the saved-evidence bundle, with no digest cycles."""
import argparse,hashlib,json,tarfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('--bundle',type=Path,required=True);a=p.parse_args();root=a.root.resolve();bundle=a.bundle.resolve();assert not bundle.is_relative_to(root)
for name in ['README.md','analysis/final/evidence-verification.json','analysis/final/validation.json']:assert (root/name).is_file(),name
for name,key in [('credential-audit.json','actual_credential_hits'),('pattern-audit.json','hits')]:assert not json.loads((root/'analysis'/name).read_text())[key]
files=[]
for path in sorted(root.rglob('*')):
 if not path.is_file():continue
 assert not path.is_symlink(),path
 rel=str(path.relative_to(root));assert '__pycache__' not in path.parts and not path.name.startswith('._') and path.name!='.DS_Store',rel
 if rel=='SHA256SUMS':continue
 assert '\n' not in rel and '\r' not in rel
 files.append({'path':rel,'sha256':hashlib.file_digest(path.open('rb'),'sha256').hexdigest(),'bytes':path.stat().st_size})
(root/'SHA256SUMS').write_text(''.join(r['sha256']+'  '+r['path']+'\n' for r in files))
expected={r['path']:r['sha256'] for r in files};expected['SHA256SUMS']=hashlib.file_digest((root/'SHA256SUMS').open('rb'),'sha256').hexdigest()
with tarfile.open(bundle,'w:gz',format=tarfile.PAX_FORMAT) as tar:
 for name in sorted(expected):tar.add(root/name,arcname=root.name+'/'+name,recursive=False)
with tarfile.open(bundle) as tar:
 members=tar.getmembers();assert len(members)==len(expected)
 for member in members:
  assert member.isfile() and member.name.startswith(root.name+'/')
  name=member.name[len(root.name)+1:];assert hashlib.sha256(tar.extractfile(member).read()).hexdigest()==expected[name],name
summary={'schema':'startup-evidence-bundle/1','root':str(root),'bundle':str(bundle),'files':len(expected),'uncompressed_bytes':sum(r['bytes'] for r in files)+(root/'SHA256SUMS').stat().st_size,'archive_bytes':bundle.stat().st_size,'archive_sha256':hashlib.file_digest(bundle.open('rb'),'sha256').hexdigest(),'root_manifest_sha256':expected['SHA256SUMS'],'all_members_hash_verified':True,'no_symlinks_or_appledouble':True}
manifest=bundle.with_name(bundle.name+'.manifest.json');manifest.write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
