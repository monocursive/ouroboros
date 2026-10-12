#!/usr/bin/env python3
"""Scan public artifacts and archive members without printing matched values."""
import json,re,sys,tarfile
from pathlib import Path
root=Path(sys.argv[1]).resolve();patterns={
 'anthropic_key':re.compile(rb'\bsk-ant-(?:api|usr)-[A-Za-z0-9_-]{20,}'),
 'openai_key':re.compile(rb'\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{35,}'),
 'jwt':re.compile(rb'\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}'),
 'private_pem':re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]')}
hits=[];checked=0
def check(name,data):
 global checked
 checked+=1
 for kind,pattern in patterns.items():
  if pattern.search(data):hits.append({'path':name,'kind':kind})
for path in sorted(root.rglob('*')):
 if not path.is_file() or '__pycache__' in path.parts or path.name=='pattern-audit.json':continue
 if path.name.endswith('.tar.gz'):
  with tarfile.open(path) as tar:
   for member in tar:
    if member.isfile():check(str(path.relative_to(root))+':'+member.name,tar.extractfile(member).read())
 else:check(str(path.relative_to(root)),path.read_bytes())
result={'schema':'credential-pattern-audit/1','items_checked':checked,'patterns':list(patterns),'hits':hits,'matched_values_retained':False};(root/'analysis/pattern-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result));raise SystemExit(bool(hits))
