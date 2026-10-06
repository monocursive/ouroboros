import os,json,pathlib,subprocess,tempfile,shutil,hashlib
root=pathlib.Path(tempfile.mkdtemp(prefix='rp-',dir=pathlib.Path.home()))
source=pathlib.Path('/home/ouro-ci/rp-vjxqkx4k/bin')
for name in ['bin','config','data','workspace']:(root/name).mkdir(mode=0o700)
for name in ['ouro-ledger','ouro-jail']:
 shutil.copyfile(pathlib.Path('/home/ouro-ci/retention-native-ledger') if name=='ouro-ledger' else source/name,root/'bin'/name);(root/'bin'/name).chmod(0o700)
data=root/'data';config=root/'config'/'config.toml';config.write_text('[ledger]\nretain="23d"\ncapture_retain="2d"\n');config.chmod(0o600)
env=dict(os.environ,OURO_CONFIG_DIR=str(root/'config'),PATH='/usr/local/bin:/usr/bin:/bin',XDG_RUNTIME_DIR=f'/run/user/{os.getuid()}',DBUS_SESSION_BUS_ADDRESS=f'unix:path=/run/user/{os.getuid()}/bus')
base=[str(root/'bin'/'ouro-ledger'),'--data-dir',str(data)]
unit='ouro-ledger-writer-'+hashlib.sha256(os.fsencode(data.resolve())).hexdigest()[:32]+'.service'
def call(label,args):
 p=subprocess.run(base+args,env=env,capture_output=True,timeout=90)
 (root/(label+'.stdout')).write_bytes(p.stdout);(root/(label+'.stderr')).write_bytes(p.stderr)
 assert p.returncode==0,(label,p.returncode,p.stderr.decode())
 return json.loads(p.stdout)
try:
 runargs=['run','--request-id','retention-policy-detached','--jail-bin',str(root/'bin'/'ouro-jail'),'--workspace',str(root/'workspace'),'--jail','tool','--io','batch','--detach','--capture','stdout','--capture-limit','8','--json','--','/bin/sh','-c','printf x >> executions; printf retained-output']
 first=call('launch',runargs);run=first['run_id']
 settled=call('wait',['wait',run,'--timeout','30','--json'])
 assert settled['state']=='settled' and settled['outcome']['kind']=='exited' and settled['outcome']['code']==0,settled
 again=call('replay',runargs);assert again['run_id']==run
 assert (root/'workspace'/'executions').read_bytes()==b'x'
 assert settled['capture']['stdout']['stored_bytes']==8 and settled['capture']['stdout']['truncated'] is True,settled['capture']
 doctor=call('doctor',['doctor','--json']);assert doctor['retention']=={'retain_days':23,'capture_retain_days':2},doctor
 plan=call('gc-plan',['gc','--dry-run','--json'])
 assert plan['retain_days']==23 and plan['capture_retain_days']==2,plan
 assert not plan['runs'][0]['candidate'] and not plan['runs'][0]['captures_candidate']
 config.write_text('[ledger]\nretain="24d"\ncapture_retain="3d"\n')
 again=call('running-policy',['gc','--dry-run','--json']);assert again['retain_days']==23 and again['capture_retain_days']==2
 verified=call('verify',['verify',run,'--json']);assert verified[0]['local_consistency']
 (root/'result.json').write_text(json.dumps({'passed':True,'doctor_reports_writer_policy':True,'run_id':run,'configured_history_days':23,'configured_capture_days':2,'one_execution':True,'captured_bytes':8,'truncated':True,'recent_history_and_captures_preserved':True,'running_policy_unchanged_after_file_edit':True,'binary_sha256':{name:hashlib.sha256((root/'bin'/name).read_bytes()).hexdigest() for name in ['ouro-ledger','ouro-jail']}},indent=2)+'\n')
finally:
 p=subprocess.run(['systemctl','--user','stop',unit],env=env,capture_output=True,timeout=20)
 (root/'cleanup.exit').write_text(str(p.returncode)+'\n')
 print(root,flush=True)
