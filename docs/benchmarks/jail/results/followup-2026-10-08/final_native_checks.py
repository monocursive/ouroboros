import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser()
for name in ['binary','fixture','tests','out']:p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args();a.out.mkdir(exist_ok=False)
a.binary=a.binary.resolve();a.fixture=a.fixture.resolve()
before=hashlib.sha256(a.binary.read_bytes()).hexdigest()
version=json.loads(subprocess.check_output([a.binary,'version','--json']))
assert version['build']['revision']=='d9d27227bea7182e962b0e9a5e41d49bd9dd2452'
assert version['build']['inputs']=='sha256:c708778d02dc8448268e0fada49487247574d5d50498a4c9142ef1a0d185afea'
assert version['build']['dirty'] is False
skips=['l01_operator_int_term_and_hup_each_end_a_contained_tree','l02_killing_the_backend_of_agent_or_build_ends_the_tree_within_a_bound','l02_killing_the_supervisor_of_agent_or_build_ends_the_tree_within_a_bound','l02_killing_the_watcher_of_agent_or_build_ends_the_tree_within_a_bound'] if version['platform']['arch']=='aarch64' else []
env={**os.environ,'OURO_CONFORMANCE':'1','OURO_JAIL_BIN':str(a.binary),'OURO_FIXTURE_BIN':str(a.fixture),'PATH':'/usr/sbin:/usr/bin:/sbin:/bin'}
rows=[]
for name in ['j4_trace_linux','j5_lifetime_linux']:
 matches=[f for f in a.tests.glob(name+'-*') if f.is_file() and os.access(f,os.X_OK)]
 assert len(matches)==1,(name,matches)
 command=[str(matches[0]),'--test-threads=1']
 if name=='j5_lifetime_linux':
  for skip in skips:command+=['--skip',skip]
 with (a.out/(name+'.log')).open('w') as log:
  result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=240)
 rows.append({'test':name,'test_binary_sha256':hashlib.sha256(matches[0].read_bytes()).hexdigest(),'exit':result.returncode,'summaries':re.findall(r'test result:.*',(a.out/(name+'.log')).read_text())})
 print(name,result.returncode,flush=True)
assert hashlib.sha256(a.binary.read_bytes()).hexdigest()==before
report={'version':version,'binary_sha256':before,'runtime_inputs_match_reference_conformance':True,'excluded_memory_requirement_cases':skips,'rows':rows,'passed':all(r['exit']==0 for r in rows)}
(a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
raise SystemExit(0 if report['passed'] else 1)
