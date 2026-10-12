#!/usr/bin/env python3
"""Verify frozen prompts, checkers, workloads and client arguments, with provenance."""
import ast,hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve();old=root.parents[1]/'competitors-after/2026-10-11/results';records=[]
def digest(data):return hashlib.sha256(data).hexdigest()
def node(text,name):
 tree=ast.parse(text)
 for n in tree.body:
  if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name==name:return ast.dump(n,include_attributes=False)
  if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets):return ast.dump(n.value,include_attributes=False)
 raise AssertionError(name)
for host in ['vps','pi','mac']:
 a=old/host/'installed-harness';b=root/'results'/host/'installed-harness'
 for name in ['workflow_fixture.py','workload.c','syscalls.c','payload.py']:
  before=(a/name).read_bytes();after=(b/name).read_bytes();assert before==after,(host,name)
  records.append({'host':host,'input':name,'before_sha256':digest(before),'after_sha256':digest(after),'identical':True})
 for file,names in [('agentbench.py',['TASKS','make_task_dir']),('agentbench_v2.py',['SEED','HOSTS','independent_check','execute'])]:
  before=(a/file).read_text();after=(b/file).read_text()
  for name in names:
   x=node(before,name);y=node(after,name);assert x==y,(host,file,name);records.append({'host':host,'input':file+':'+name,'ast_sha256':digest(x.encode()),'identical':True})
 before=(a/'agentbench_v2.py').read_text();after=(b/'agentbench_v2.py').read_text()
 def args(text):return text[text.index('    prompt = TASKS['):text.index('    env = dict(os.environ)')]
 assert args(before)==args(after),host
 records.append({'host':host,'input':'agentbench_v2.py:client arguments/models/turn cap','sha256':digest(args(after).encode()),'identical':True,'whole_file_identical':before==after,'non_input_difference':'VPS first-after snapshot predates inactive Darwin/Homebrew grant and appending already-present /usr/sbin:/sbin to PATH; native Linux argv/models/prompts/checkers unchanged' if before!=after else None})
(root/'analysis/final/frozen-inputs.json').write_text(json.dumps({'schema':'frozen-benchmark-inputs/1','checks':records},indent=2)+'\n');print(json.dumps({'frozen_input_checks':len(records),'all_equal':True}))
