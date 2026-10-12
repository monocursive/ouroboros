#!/usr/bin/env python3
"""Independent container egress probe with reachable Docker positive controls."""
import argparse,json,platform,time
from pathlib import Path
from openshell_perf_v2 import Canary,run,IMAGE

def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('Evidence exists')
 a.out.mkdir(parents=True)
 c=Canary();name='bench-egress-v3';dname='bench-egress-docker'
 host='host.docker.internal' if platform.system()=='Darwin' else run(['docker','network','inspect','bridge','--format','{{(index .IPAM.Config 0).Gateway}}'])['stdout'].strip()
 code="import socket,sys,json\ntry:\n s=socket.create_connection((sys.argv[1],int(sys.argv[2])),2);s.sendall(b'probe');print(json.dumps({'probe':'tcp','allowed':s.recv(16)==b'canary'}))\nexcept OSError as e:\n print(json.dumps({'probe':'tcp','allowed':False,'error':str(e)}))"
 rows=[]
 try:
  rows.append(dict(run(['docker','run','--detach','--user','1000:1000','--name',dname,IMAGE,'sleep','300']),phase='setup',tool='docker-warm'))
  rows.append(dict(run(['openshell','sandbox','create','--name',name,'--detach','--from',IMAGE,'--','sleep','300']),phase='setup',tool='openshell-warm'))
  for rep in range(3):
   for tool,prefix in [('docker-run',['docker','run','--rm','--user','1000:1000',IMAGE]),('docker-warm',['docker','exec',dname]),('openshell-ephemeral',['openshell','sandbox','create','--no-keep','--no-tty','--from',IMAGE,'--']),('openshell-warm',['openshell','sandbox','exec','-n',name,'--no-tty','--'])]:
    before=len(c.hits);r=run(prefix+['/usr/bin/python3','-c',code,host,str(c.port)],timeout=180);time.sleep(.2)
    rows.append(dict(r,phase='probe',tool=tool,repetition=rep,destination=host,host_accepts=len(c.hits)-before))
 finally:
  rows.append(dict(run(['openshell','sandbox','delete',name]),phase='teardown',tool='openshell-warm'))
  rows.append(dict(run(['docker','rm','--force',dname]),phase='teardown',tool='docker-warm'))
  c.close()
  (a.out/'egress.json').write_text(json.dumps(rows,indent=2)+'\n')
 print(json.dumps([{'tool':r['tool'],'hits':r['host_accepts']} for r in rows if r['phase']=='probe']))
if __name__=='__main__':main()
