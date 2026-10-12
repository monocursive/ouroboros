#!/usr/bin/env python3
"""Bind the selected final executables and validation without modifying raw logs."""
import hashlib,json,re,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve()
records=[]
for path in sorted((root/'binaries').rglob('*')):
 if path.is_file():records.append({'path':str(path.relative_to(root)),'bytes':path.stat().st_size,'sha256':hashlib.file_digest(path.open('rb'),'sha256').hexdigest()})
(root/'analysis/binaries.json').write_text(json.dumps(records,indent=2)+'\n')
validation={'schema':'startup-validation/1','release_readiness_claim':False,'reference_host_conformance_claim':False,'hosts':{}}
for host in ['vps','pi']:
 base=root/'results'/host;doctor=json.loads((base/'validation/doctor-after.json').read_text());binary=root/'binaries'/host/'ouro-jail-after'
 assert hashlib.file_digest(binary.open('rb'),'sha256').hexdigest()==doctor['binaries']['ouro-jail']['sha256']
 logs=['unit-tests.log','ordinary_file_hints.log','shared_status_and_readonly.log']+(['security-observer-tests.log'] if host=='vps' else ['observer-backend-tests.log'])
 summaries={}
 for name in logs:
  path=base/'validation'/name;raw=path.read_text();rows=[{'passed':int(m[1]),'failed':int(m[2]),'ignored':int(m[3])} for m in re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored',raw)]
  assert rows and all(r['failed']==0 for r in rows),(host,name)
  summaries[name]={'source':str(path.relative_to(root)),'sha256':hashlib.file_digest(path.open('rb'),'sha256').hexdigest(),'summaries':rows,'passed':sum(r['passed'] for r in rows),'ignored':sum(r['ignored'] for r in rows)}
 assert summaries['unit-tests.log']['passed']==567
 assert 'Finished' in (base/'validation/clippy.log').read_text()
 validation['hosts'][host]={'final_validation':summaries,'clippy':'passed with -D warnings','broader_pi_baseline_limits': 'analysis/pi-validation-comparison.json and candidate archives; not a complete host conformance pass' if host=='pi' else None}
(root/'analysis/final/validation.json').write_text(json.dumps(validation,indent=2)+'\n')
frozen={}
old=root.parents[1]/'competitors-after/2026-10-11/results'
for host in ['vps','pi','mac']:
 current=json.loads((root/'results'/host/'host-provenance-final.json').read_text())['bin_hashes'];before=json.loads((old/host/'host-provenance-final.json').read_text())['bin_hashes']
 names=[n for n in before if n.split('/')[-1] in ['claude','codex','opencode','greywall','greyproxy','lxc-exec','openshell','openshell-gateway']]
 checks={n:{'before':before[n],'after':current.get(n),'equal':before[n]==current.get(n)} for n in names};assert checks and all(v['equal'] for v in checks.values()),(host,checks)
 frozen[host]=checks
(root/'analysis/final/frozen-executable-checks.json').write_text(json.dumps(frozen,indent=2)+'\n')
print(json.dumps({'binary_records':len(records),'final_unit_tests_per_linux_host':567,'frozen_tools_hosts':list(frozen)}))
