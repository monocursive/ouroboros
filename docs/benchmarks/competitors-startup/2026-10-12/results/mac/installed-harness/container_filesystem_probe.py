#!/usr/bin/env python3
"""RO-workspace policy check with world-writable owner/Docker positive controls."""
import argparse,json,hashlib
from pathlib import Path
from openshell_perf_v2 import run,IMAGE
POLICY='version: 1\nfilesystem_policy:\n  include_workdir: false\n  read_only: [/usr, /bin, /lib, /lib64, /etc, /proc, /dev, /work]\n  read_write: [/tmp, /home/agent]\n'
CODE="import pathlib,json\nfor name in ['/work/readonly-canary','/tmp/writable-canary']:\n try:\n  pathlib.Path(name).write_text('owned-fixture');print(json.dumps({'path':name,'wrote':True}))\n except OSError as e:print(json.dumps({'path':name,'wrote':False,'errno':e.errno}))"
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('Evidence exists')
 a.out.mkdir(parents=True);(a.out/'policy.yaml').write_text(POLICY);rows=[]
 for tool in ['docker','openshell']:
  cmd=['docker','run','--rm','--user','1000:1000',IMAGE] if tool=='docker' else ['openshell','sandbox','create','--no-keep','--no-tty','--from',IMAGE,'--policy',str(a.out/'policy.yaml'),'--']
  rows.append(dict(run(cmd+['/usr/bin/python3','-c',CODE],timeout=180),tool=tool))
 (a.out/'filesystem.json').write_text(json.dumps(rows,indent=2)+'\n')
 (a.out/'metadata.json').write_text(json.dumps({'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},indent=2)+'\n')
 print(json.dumps([{'tool':r['tool'],'exit':r['exit'],'stdout':r['stdout'][-450:],'stderr':r['stderr'][-300:]} for r in rows]))
if __name__=='__main__':main()
