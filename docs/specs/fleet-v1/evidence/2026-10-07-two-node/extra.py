#!/usr/bin/env python3
"""Live reader, capability, unavailable-worker and cancellation checks."""
import json, pathlib, shlex, time
import probe as p

rows=json.loads((p.OUT/'summary.json').read_text())
job=next(r['job_id'] for r in rows if r['node']=='pi' and r['case']=='tool')
for verb in [['show','--with-transcript'],['verify'],['query','--execs','--limit','3'],['tail']]:
 reply=p.cli(['ledger',job,*verb]); assert reply['exit_code']==0,reply
 p.save('reader-'+verb[0],reply)
for flags in [['show','--data-dir','/tmp'],['query','--run','run-other','--execs']]:
 assert p.cli(['ledger',job,*flags],False).returncode!=0
wait=p.cli(['wait',job,'--timeout','5','--json']);assert wait['state']=='exited'
p.save('wait-complete',wait)
# The Pi lacks a memory controller: placement must refuse before execution.
refused=p.cli(['run','--request-id','extra-memory-unavailable','--on','pi','--jail','tool','--limit','mem=64MiB','--json','--','/bin/true'],False)
assert refused.returncode!=0 and 'no_eligible_worker' in refused.stderr
p.save('capability-refusal',{'exit_code':refused.returncode,'reason':refused.stderr.strip()})

args=['run','--request-id','extra-unavailable-r1','--on','pi','--jail','tool','--launch','fleet-fixture','--limit','wall=120s','--json','--','/bin/sh','-c','printf x >> executions; touch started; sleep 100; touch unexpected-completion']
row=p.cli(args);assert row.get('run_id'),row
job=row['job_id'];workspace=row['workspace']
p.poll(lambda:p.file('pi',workspace+'/started') is not None)
before=p.poll(lambda:r if (r:=p.status(job)).get('state')=='running' else None)
p.systemctl('pi','stop',p.NODES['pi']['unit'])
try:
 stale=p.status(job);assert stale['stale'] and stale['reachability']=='unreachable',stale
 assert stale['last_observed']['run_id']==before['run_id'] and 'state' not in stale
 replay=p.cli(args);assert replay['job_id']==job and replay['worker']=='pi' and replay['admission']=='unconfirmed',replay
 assert p.file('pi',workspace+'/executions')=='x'
 assert p.file('pi',f"/proc/{before['owner']['pid']}/stat") is not None
 p.save('worker-unavailable',stale);p.save('unavailable-replay',replay)
finally:
 n=p.NODES['pi'];src=n['home']+'/ouro-fleet-20261007-r1';base=n['base']
 command=['systemd-run','--user','--unit',n['unit'],'--collect','--property=Delegate=yes','--setenv=OURO_CONFIG_DIR='+base+'/config','/usr/bin/elixir','--erl','+S 2:2 -proto_dist inet_tls -start_epmd false -epmd_module Elixir.Ouroboros.Cluster.Epmd -ssl_dist_optfile '+base+'/credentials/ssl_dist.conf','-pa',src+'/fleet/_build/dev/lib/ouro_fleet/ebin',src+'/fleet/scripts/node.exs',base+'/node.json']
 p.ssh('pi','export XDG_RUNTIME_DIR=/run/user/$(id -u); '+shlex.join(command))
p.poll(lambda:all(r['rpc']=='ready' for r in p.cli(['doctor','--json'])))
after=p.status(job);assert after['owner']==before['owner'] and after['run_id']==before['run_id'] and after['state']=='running',after
p.save('worker-returned',after)
cancel=p.cli(['kill',job,'--json']);p.save('cancel-request',cancel)
final=p.poll(lambda:p.terminal(job));assert final['state']=='killed' and final['outcome']['kind']=='signaled',final
assert p.file('pi',workspace+'/executions')=='x' and p.file('pi',workspace+'/unexpected-completion') is None
p.save('cancel-final',final)
p.save('extra-summary',{'routed_readers':True,'selector_override_refused':True,'wait':True,'missing_memory_capability_refused':True,'worker_unavailable_preserves_observation':True,'no_replacement_or_second_child':True,'reattached_same_owner':True,'cancel_observed_signal':True})
print('EXTRA ACCEPTANCE PASS',flush=True)
