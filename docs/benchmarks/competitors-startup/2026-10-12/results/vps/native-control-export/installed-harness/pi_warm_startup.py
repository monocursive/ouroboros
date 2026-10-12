#!/usr/bin/env python3
"""Retain a normal warm-start attempt for every client on an unavailable host."""
import argparse,json,os
from pathlib import Path
from openshell_agent_v2 import credentials
from agentbench_v2 import execute,write
def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--key-file',type=Path,required=True);p.add_argument('--auth-file',type=Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('Evidence exists')
 a.out.mkdir(parents=True);env=credentials(a);key=a.key_file.read_text().strip()
 policy=a.root/'results/openshell-v2-smoke/policy.yaml';rows=[]
 for agent in ['claude','opencode','codex']:
  name='bench-pi-'+agent;provider='benchmark-codex-v3' if agent=='codex' else 'benchmark-anthropic-v2'
  argv=['openshell','sandbox','create','--name',name,'--detach','--from','ouro-comparison-agents-v2:20261011','--policy',str(policy),'--provider',provider]
  if agent=='codex':argv+=['--env','BENCH_CODEX_ROUTING_ACCOUNT_ID='+env['CODEX_AUTH_ACCOUNT_ID']]
  argv+=['--','/bin/sleep','300'];r=execute(argv,a.root,env,180)
  r['argv']=[v.replace(env['CODEX_AUTH_ACCOUNT_ID'],'<CODEX_ACCOUNT_ID>') for v in argv];r['agent']=agent
  write(a.out/(agent+'-create.json'),r,key)
  log=execute(['openshell','logs',name,'-n','100'],a.root,env,30);write(a.out/(agent+'-startup.log'),log,key)
  cleanup=execute(['openshell','sandbox','delete',name],a.root,env,60);write(a.out/(agent+'-delete.json'),cleanup,key)
  rows.append({'agent':agent,'ready':r['exit']==0,'exit':r['exit'],'elapsed_ms':r['elapsed_ms']})
 write(a.out/'availability.json',rows,key);print(json.dumps(rows))
if __name__=='__main__':main()
