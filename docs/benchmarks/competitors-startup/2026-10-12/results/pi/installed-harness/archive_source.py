#!/usr/bin/env python3
"""Save the frozen workspace plus final patch, excluding bulky competitor evidence."""
import hashlib,io,json,subprocess,sys,tarfile
from pathlib import Path
root=Path(sys.argv[1]).resolve();baseline='ac1263a0961d5e676c2a03e516848a9fd00dde9b';modified=json.loads((root/'source-files.json').read_text());excluded=['docs/benchmarks/competitors/','docs/benchmarks/competitors-after/','docs/benchmarks/competitors-startup/'];archive=root/'archives/source-final.tar.gz';files=[]
proc=subprocess.Popen(['git','archive','--format=tar',baseline],stdout=subprocess.PIPE)
with tarfile.open(fileobj=proc.stdout,mode='r|') as source,tarfile.open(archive,'w:gz',format=tarfile.PAX_FORMAT) as dest:
 for member in source:
  if any(member.name.startswith(x) for x in excluded):continue
  if member.name.startswith('docs/benchmarks/') and '/results/' in member.name and not member.name.startswith('docs/benchmarks/jail/results/release-preview-2026-10-10/'):
   continue
  if not member.isfile():
   dest.addfile(member);continue
  data=Path(member.name).read_bytes() if member.name in modified else source.extractfile(member).read();member.size=len(data);dest.addfile(member,io.BytesIO(data));files.append({'path':member.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'patched':member.name in modified})
 assert proc.wait()==0
with tarfile.open(archive) as tar:
 actual={m.name:hashlib.sha256(tar.extractfile(m).read()).hexdigest() for m in tar if m.isfile()}
assert actual=={r['path']:r['sha256'] for r in files}
assert {r['path']:r['sha256'] for r in files if r['patched']}==modified
proof={'schema':'benchmark-source-archive/1','baseline_commit':baseline,'archive':str(archive.relative_to(root)),'archive_sha256':hashlib.file_digest(archive.open('rb'),'sha256').hexdigest(),'archive_bytes':archive.stat().st_size,'excluded_artifact_roots':excluded,'other_exclusions':'Historical docs/benchmarks/**/results datasets, except the release-preview-2026-10-10 fixture required by portable Rust tests. All source/scripts are retained.','all_tracked_build_and_test_sources_preserved':True,'build_environment':{'OURO_BUILD_REVISION':baseline,'OURO_BUILD_DIRTY':'true','rust':'1.98.1','release_opt_level':'3'},'files':files,'all_member_hashes_verified':True,'release_provenance_claim':False};(root/'analysis/source-archive.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps({k:v for k,v in proof.items() if k!='files'}))
