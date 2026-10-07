#!/usr/bin/env python3
"""Live, synthetic two-host acceptance. No provider credentials or real user tree."""
import hashlib, json, os, pathlib, shlex, subprocess, sys, time
OUT=pathlib.Path(sys.argv[1]); OUT.mkdir(parents=True,exist_ok=True)
NODES={
 'vps':dict(remote='ubuntu@37.59.114.70',home='/home/ubuntu',cache='/home/ubuntu/ouro-ledger-storage-20261004-r1',opts=[]),
 'pi':dict(remote='monocursive@100.83.203.10',home='/home/monocursive',cache='/home/monocursive/ouro-ledger-pruning-20261005-pi-r1',opts=['-S','/tmp/ouro-all-pi.sock'])}
for name,node in NODES.items():
 node['base']=node['home']+'/ouro-fleet-lab-20261007'
 node['ledger']=node['cache']+'/target/release/ouro-ledger'
 node['unit']='ouro-fleet-lab-'+name

def ssh(name,cmd,check=True,input=None):
 n=NODES[name]
 return subprocess.run(['ssh',*n['opts'],'-o','ConnectTimeout=10',n['remote'],cmd],input=input,capture_output=True,text=True,timeout=210,check=check)

def cli(args,check=True):
 n=NODES['vps']; command=shlex.join([n['cache']+'/target/release/ouro','fleet','--config',n['base']+'/node.json',*args])
 r=ssh('vps',command,False)
 if check and r.returncode: raise AssertionError((args[:4],r.returncode,r.stdout,r.stderr))
 return json.loads(r.stdout) if check else r

def save(name,obj): (OUT/(name+'.json')).write_text(json.dumps(obj,indent=2)+'\n')
def poll(fn,seconds=40):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  try:
   result=fn()
   if result: return result
  except (AssertionError,subprocess.CalledProcessError,json.JSONDecodeError): pass
  time.sleep(.2)
 raise AssertionError('condition timed out')

def file(name,path):
 r=ssh(name,shlex.join(['cat',path]),False)
 return r.stdout if r.returncode==0 else None

def touch(name,path): ssh(name,shlex.join(['touch',path]))
def systemctl(name,action,unit):
 ssh(name,'export XDG_RUNTIME_DIR=/run/user/$(id -u); '+shlex.join(['systemctl','--user',action,unit]))
def status(job): return cli(['status',job,'--json'])
def terminal(job):
 r=status(job)
 return r if not r.get('stale') and r.get('state') in ['exited','refused','killed','outcome_unknown'] else None

def restart_worker(name):
 systemctl(name,'restart',NODES[name]['unit'])
 poll(lambda: all(r['rpc']=='ready' for r in cli(['doctor','--json'])))

def kill_owner(name,row):
 p=row['owner']; code='''import os,signal,json,sys\np=json.loads(sys.argv[1]); fd=os.pidfd_open(p['pid']); stat=open('/proc/%s/stat'%p['pid']).read().rsplit(')',1)[1].split(); boot=open('/proc/sys/kernel/random/boot_id').read().strip(); assert p['birth']==f"boot:{boot}:start:{stat[19]}"; signal.pidfd_send_signal(fd,signal.SIGKILL); os.close(fd)'''
 ssh(name,shlex.join(['python3','-c',code,json.dumps(p)]))

def writer_unit(name):
 return 'ouro-ledger-writer-'+hashlib.sha256((NODES[name]['base']+'/data').encode()).hexdigest()[:32]+'.service'

def kill_writer(name):
 ssh(name,'export XDG_RUNTIME_DIR=/run/user/$(id -u); '+shlex.join(['systemctl','--user','kill','--signal=KILL',writer_unit(name)]))

def start_writer(name):
 n=NODES[name]
 ssh(name,'export XDG_RUNTIME_DIR=/run/user/$(id -u); '+shlex.join([n['ledger'],'--data-dir',n['base']+'/data','serve','--detach']))

def main():
 for name,n in NODES.items():
  ssh(name,'umask 077; mkdir -p '+shlex.quote(n['base']+'/config/launch')+'; cat > '+shlex.quote(n['base']+'/config/launch/fleet-fixture.toml'),input='name = "fleet-fixture"\njail = "tool"\nstate_var = "FIX_HOME"\n')

 selected=os.environ.get('OURO_PROBE_NODES','vps,pi').split(',')
 summary=json.loads((OUT/'summary.json').read_text()) if (OUT/'summary.json').exists() else []
 summary=[row for row in summary if row['node'] not in selected]
 for node in selected:
  for case in ['tool','none','lost-reply','owner-death','strict-writer','best-effort-writer']:
   name=node+'-'+case
   request=os.environ['OURO_PROBE_ID']+'-'+name
   profile='none' if case=='none' else 'tool'
   evidence='best-effort' if case=='best-effort-writer' else 'strict'
   script='printf x >> executions; if read value; then exit 9; fi; printf eof > stdin-status; printf eof; printf "%05000d" 0; '
   if profile=='tool': script+='printf synthetic-vendor-content > "$FIX_HOME/session"; '
   script+='touch started; while [ ! -f finish ]; do sleep 0.05; done; touch finished'
   args=['run','--request-id',request,'--on',node,'--jail',profile,'--evidence',evidence,'--limit','wall=90s','--capture','stdout','--capture-limit','64','--json']
   if profile=='tool': args+=['--launch','fleet-fixture']
   args+=['--','/bin/sh','-c',script]
   if case=='none':
    n=NODES[node];ssh(node,shlex.join(['mv',n['base']+'/config/launch/fleet-fixture.toml',n['base']+'/fleet-fixture.disabled']))
   if case=='lost-reply':
    n=NODES['vps']; command=shlex.join([n['cache']+'/target/release/ouro','fleet','--config',n['base']+'/node.json',*args])+' | head -c 0'
    lost=ssh('vps',command,False); assert not lost.stdout
   row=cli(args); assert row.get('run_id'), row
   job=row['job_id']; workspace=row['workspace']
   poll(lambda:file(node,workspace+'/started') is not None)
   admitted=poll(lambda:(r if (r:=status(job)).get('state')=='running' else None))
   assert admitted['child_protection']==('unprotected' if profile=='none' else 'enforced'),admitted
   assert file(node,workspace+'/executions')=='x'
   assert file(node,workspace+'/stdin-status')=='eof'
   save(name+'-admitted',admitted)
   attempt=NODES[node]['base']+'/data/attempts/'+admitted['attempt_id']
   if profile=='tool': assert file(node,attempt+'/vendor-state/session')=='synthetic-vendor-content'
   if case in ['tool','none']:
    # The submitting SSH session has already disconnected. Restart the whole
    # OTP worker VM and require the identical Rust owner birth and one child.
    restart_worker(node)
    after=status(job); assert after['owner']==admitted['owner'] and after['run_id']==admitted['run_id']
    assert file(node,workspace+'/executions')=='x'
    save(name+'-reattached',after)
    touch(node,workspace+'/finish')
   elif case=='lost-reply': touch(node,workspace+'/finish')
   elif case=='owner-death': kill_owner(node,admitted)
   else:
    kill_writer(node)
    if case=='best-effort-writer':
     touch(node,workspace+'/finish');poll(lambda:file(node,workspace+'/finished') is not None)
    else: time.sleep(.3)
    start_writer(node)
   final=poll(lambda:terminal(job),60)
   assert final['child_protection']==admitted['child_protection']
   if case in ['owner-death','strict-writer']:
    assert final['state']=='outcome_unknown' and final['settlement']=='unknown',final
   elif case=='best-effort-writer':
    assert final['evidence_health']=='degraded',final
    assert final['state'] in ['exited','outcome_unknown']
   else:
    assert final['state']=='exited' and final['outcome']['code']==0,final
    assert final['capture']['stdout']['stored_bytes']==64 and final['capture']['stdout']['truncated']
    assert final['capture']['stderr']['state']=='not_captured'
   state=poll(lambda:json.loads(value) if (value:=file(node,attempt+'/jail-state.json')) and json.loads(value).get('state_cleanup')==('complete' if profile=='tool' else 'not_needed') else None)
   receipt=json.loads(file(node,attempt+'/jail.json'))
   assert receipt['lifetime']['tree_empty'] is True and receipt['lifetime']['integrity']=='verified',receipt
   save(name+'-jail-receipt',receipt)
   if profile=='tool': assert file(node,attempt+'/vendor-state/session') is None
   retry=cli(args);assert retry['run_id']==admitted['run_id'] and retry['owner']==admitted['owner']
   assert file(node,workspace+'/executions')=='x'
   changed=list(args);changed[changed.index('--capture-limit')+1]='63';assert cli(changed,False).returncode!=0
   save(name+'-final',final);save(name+'-jail-state',state)
   if case=='none':
    n=NODES[node];ssh(node,shlex.join(['mv',n['base']+'/fleet-fixture.disabled',n['base']+'/config/launch/fleet-fixture.toml']))
   summary.append({'node':node,'case':case,'request_id':request,'job_id':job,'run_id':final['run_id'],'state':final['state'],'single_execution':True,'tree_empty':True,'state_cleanup':state['state_cleanup']})
   save('summary',summary)
   print(name,'PASS',final['state'],flush=True)
 print('TWO-NODE ACCEPTANCE PASS',len(summary),'scenarios',flush=True)

if __name__ == "__main__": main()
