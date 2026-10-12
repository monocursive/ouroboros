#!/usr/bin/env python3
"""Verify Pi failures against the entire baseline product implementation.

Compilation and diagnostics only; no scored runs overlap this script. Current
source is restored in finally, and neither release binary is overwritten.
"""
import hashlib,json,os,subprocess,tarfile
from pathlib import Path
root=Path.home()/'bench-ouro-startup-native-final';source=root/'src';out=root/'results/validation'
names=['crates/ouro-jail/src/platform/linux/fs.rs','crates/ouro-jail/src/platform/linux/platform.rs','crates/ouro-jail/src/platform/linux/probe.rs','crates/ouro-jail/src/platform/linux/tracer/mod.rs']
saved={name:(source/name).read_bytes() for name in names}
env=dict(os.environ,PATH=str(Path.home()/'.cargo/bin')+':'+os.environ['PATH'],OURO_CONFORMANCE='1',OURO_BUILD_REVISION='ac1263a0961d5e676c2a03e516848a9fd00dde9b',OURO_BUILD_DIRTY='false',OURO_FIXTURE_BIN=str(root/'bin/ouro-fixture'),OURO_JAIL_BIN=str(root/'bin/ouro-jail-before'),CARGO_BUILD_JOBS='2',XDG_RUNTIME_DIR='/run/user/'+str(os.getuid()),DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/'+str(os.getuid())+'/bus')
rows=[]
try:
 with tarfile.open(root/'baseline-product-delta.tar.gz') as tar:
  assert set(tar.getnames())==set(names)
  for name in names:(source/name).write_bytes(tar.extractfile(name).read())
 hashes={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in names}
 for suite in ['j5_boundary_linux','j4_loss_linux','observer_j4_linux','observer_regression_linux','review_linux']:
  log=out/(suite+'-baseline-source.log')
  with log.open('wb') as file:
   run=subprocess.run(['systemd-run','--user','--scope','--quiet','-p','Delegate=yes','cargo','+1.98.1','test','--locked','-p','ouro-jail','--test',suite,'--','--test-threads=1'],cwd=source,env=env,stdout=file,stderr=subprocess.STDOUT)
  rows.append({'suite':suite,'exit':run.returncode,'baseline_source_hashes':hashes})
  print(suite,run.returncode,flush=True)
finally:
 for name,data in saved.items():(source/name).write_bytes(data)
 assert all((source/name).read_bytes()==data for name,data in saved.items())
 (out/'baseline-failure-comparison.json').write_text(json.dumps({'runs':rows,'current_source_restored':True,'current_source_hashes':{name:hashlib.sha256(data).hexdigest() for name,data in saved.items()}},indent=2)+'\n')
env.update(OURO_BUILD_DIRTY='true',OURO_JAIL_BIN=str(root/'bin/ouro-jail'))
with (out/'r13-current-confirmation.log').open('wb') as file:
 run=subprocess.run(['systemd-run','--user','--scope','--quiet','-p','Delegate=yes','cargo','+1.98.1','test','--locked','-p','ouro-jail','--test','observer_regression_linux','r13_a_stalled','--','--test-threads=1','--nocapture'],cwd=source,env=env,stdout=file,stderr=subprocess.STDOUT)
print('r13_current_confirmation',run.returncode,flush=True)
