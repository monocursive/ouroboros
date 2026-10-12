#!/usr/bin/env python3
"""Operator credential update using a still-valid cache and its actual expiry."""
import argparse,base64,datetime,json,os,subprocess
from pathlib import Path
from agentbench_v2 import write
def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--auth-file',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--fresh',action='store_true');p.add_argument('--provider-name',default='benchmark-codex-v2');a=p.parse_args()
 if a.out.exists():raise SystemExit('Evidence exists')
 a.out.mkdir(parents=True);tokens=json.loads(a.auth_file.read_text())['tokens'];env=dict(os.environ)
 for k,v in tokens.items():
  if isinstance(v,str):env['CODEX_AUTH_'+k.upper()]=v
 jwt=json.loads(base64.urlsafe_b64decode(tokens['access_token'].split('.')[1]+'==='))
 expiry=datetime.datetime.fromtimestamp(jwt['exp'],datetime.timezone.utc).isoformat()
 assert jwt['exp']>datetime.datetime.now(datetime.timezone.utc).timestamp()
 prefix=['openshell','provider','create','--name',a.provider_name,'--type','benchmark-codex-agent'] if a.fresh else ['openshell','provider','update',a.provider_name]
 argv=prefix+ [part for k in ('access_token','refresh_token','account_id','id_token') for part in ('--credential','CODEX_AUTH_'+k.upper())]
 if not a.fresh:argv+=['--credential-expires-at','CODEX_AUTH_ACCESS_TOKEN='+expiry,'-o','json']
 proc=subprocess.run(argv,env=env,capture_output=True,text=True,timeout=90)
 def sanitize(s):
  for v in tokens.values():
   if isinstance(v,str) and v:s=s.replace(v,'<CODEX_TOKEN>')
  return s
 write(a.out/'update.json',{'argv':argv,'exit':proc.returncode,'stdout':sanitize(proc.stdout),'stderr':sanitize(proc.stderr),'cached_access_expiry':expiry})
 if proc.returncode==0 and a.fresh:
  expcmd=['openshell','provider','update',a.provider_name,'--credential-expires-at','CODEX_AUTH_ACCESS_TOKEN='+expiry,'-o','json']
  expstep=subprocess.run(expcmd,env=env,capture_output=True,text=True,timeout=90)
  write(a.out/'expiry-update.json',{'argv':expcmd,'exit':expstep.returncode,'stdout':sanitize(expstep.stdout),'stderr':sanitize(expstep.stderr)})
  if expstep.returncode:raise SystemExit(expstep.returncode)
  cmd=['openshell','provider','refresh','configure',a.provider_name,'--credential-key','CODEX_AUTH_ACCESS_TOKEN','--strategy','oauth2-refresh-token','--material','client_id=app_EMoamEEZ73f0CkXaXp7hrann','--secret-material-env','refresh_token=CODEX_AUTH_REFRESH_TOKEN']
  step=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=90)
  write(a.out/'refresh-configure.json',{'argv':cmd,'exit':step.returncode,'stdout':sanitize(step.stdout),'stderr':sanitize(step.stderr)})
  if step.returncode:raise SystemExit(step.returncode)
 raise SystemExit(proc.returncode)
if __name__=='__main__':main()
