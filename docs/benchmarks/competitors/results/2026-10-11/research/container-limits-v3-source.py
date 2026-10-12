#!/usr/bin/env python3
"""Bounded runtime resource checks with Docker controls, no agent/API usage."""
import argparse,json
from pathlib import Path
from openshell_perf_v2 import run,IMAGE
MEM="import json;print(json.dumps({'started':True}),flush=True);b=bytearray(192*1024*1024);print(json.dumps({'allocated':len(b)}),flush=True)"
CPU="import time,json;s=time.process_time();w=time.monotonic()\nwhile time.process_time()-s<.3:\n for i in range(10000):v=i*i\nprint(json.dumps({'cpu_s':time.process_time()-s,'wall_s':time.monotonic()-w}))"
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('Evidence exists')
 a.out.mkdir(parents=True);rows=[]
 for mode in ['memory','cpu']:
  for tool,limited in [('docker',False),('docker',True),('openshell',False),('openshell',True)]:
   if tool=='docker':cmd=['docker','run','--rm','--user','1000:1000']+(['--memory','128m','--memory-swap','128m'] if limited and mode=='memory' else ['--cpus','0.5'] if limited else [])+[IMAGE]
   else:cmd=['openshell','sandbox','create','--no-keep','--no-tty','--from',IMAGE]+(['--memory','128Mi'] if limited and mode=='memory' else ['--cpu','500m'] if limited else [])+['--']
   r=run(cmd+['/usr/bin/python3','-c',MEM if mode=='memory' else CPU],timeout=180)
   rows.append(dict(r,tool=tool,resource=mode,limited=limited))
 (a.out/'limits.json').write_text(json.dumps(rows,indent=2)+'\n')
 print(json.dumps([{'tool':r['tool'],'resource':r['resource'],'limited':r['limited'],'exit':r['exit'],'stdout':r['stdout'][-300:]} for r in rows]))
if __name__=='__main__':main()
