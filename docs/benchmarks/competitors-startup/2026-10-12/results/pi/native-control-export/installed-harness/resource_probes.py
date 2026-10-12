#!/usr/bin/env python3
"""Bounded resource probes; unsupported ceilings are explicitly distinguished."""
import argparse
import json
from suite import Suite

PAYLOAD = '''import os,time,json,sys
mode=sys.argv[1]
if mode=='wall':
 print(json.dumps({'probe':'wall','started':True}),flush=True)
 time.sleep(3)
 print(json.dumps({'probe':'wall','completed':True}),flush=True)
elif mode=='memory':
 print(json.dumps({'probe':'memory','started':True}),flush=True)
 data=bytearray(96*1024*1024)
 for i in range(0,len(data),4096): data[i]=1
 print(json.dumps({'probe':'memory','allocated_bytes':len(data)}),flush=True)
 time.sleep(.2)
elif mode=='pids':
 children=[]; error=None
 for i in range(32):
  try: pid=os.fork()
  except OSError as e: error=e.errno; break
  if pid==0: time.sleep(.8); os._exit(0)
  children.append(pid)
 print(json.dumps({'probe':'pids','forks':len(children),'errno':error}),flush=True)
 for pid in children: os.waitpid(pid,0)
elif mode=='cpu':
 before=time.monotonic(); start=time.process_time(); counter=0
 while time.process_time()-start<.2:
  for i in range(10000): counter+=i
 print(json.dumps({'probe':'cpu','cpu_s':time.process_time()-start,'wall_s':time.monotonic()-before}),flush=True)
else: print(json.dumps({'probe':'admission','executed':True}),flush=True)
'''

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--root',type=__import__('pathlib').Path,required=True)
 p.add_argument('--out',type=__import__('pathlib').Path,required=True)
 args=p.parse_args()
 if (args.out/'launches.ndjson').exists(): raise SystemExit('Refusing to overwrite evidence')
 s=Suite(args.root.resolve(),args.out.resolve(),0,0,['direct','ouro-jail','greywall','mxc'])
 payload=s.work/'resource_payload.py';payload.write_text(PAYLOAD)
 base_command=s.command
 active=[]
 current=''
 def command(tool,argv):
  cmd=base_command(tool,argv)
  if tool=='ouro-jail':
   pos=cmd.index('--');cmd[pos:pos]=[part for limit in active for part in ('--limit',limit)]
  elif tool=='mxc' and current=='wall':
   cfg=__import__('pathlib').Path(cmd[1]);v=json.loads(cfg.read_text());v['process']['timeout']=1000;cfg.write_text(json.dumps(v))
  return cmd
 s.command=command
 rows=[]
 try:
  (s.out/'metadata.json').write_text(json.dumps(s.metadata(),indent=2)+'\n')
  for tool in s.tools:
   pre=s.run(tool,s.payload_command('python'),'preflight','python')
   if pre['exit'] or not pre['records']:
    rows.append({'tool':tool,'status':'unavailable','preflight_sequence':pre['sequence']});continue
   for mode,limits in [('wall',['wall=1s']),('memory',['mem=64MiB','swap=0']),('pids',['pids=16']),('cpu',['cpu=25']),('storage',['storage=8MiB']),('inodes',['inodes=64'])]:
    if mode in ('storage','inodes') and tool!='ouro-jail': continue
    current=mode;active=limits if tool=='ouro-jail' else []
    row=s.run(tool,[s.python,str(payload),mode],'resource',mode)
    rows.append({'tool':tool,'resource':mode,'requested_ceiling':limits if tool=='ouro-jail' else (['timeout=1000ms'] if tool=='mxc' and mode=='wall' else []),
                 'ceiling_supported':tool=='ouro-jail' or (tool=='mxc' and mode=='wall'),
                 'sequence':row['sequence'],'exit':row['exit'],'elapsed_ms':row['elapsed_ms'],
                 'records':row['records'],'stderr':row['stderr'],'receipt':row.get('receipt')})
   active=[]
   print(tool,'resource probes complete',flush=True)
  (s.out/'resources.json').write_text(json.dumps(rows,indent=2)+'\n')
 finally:s.close()

if __name__=='__main__':main()
