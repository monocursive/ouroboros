#!/usr/bin/env python3
"""Raw wall-clock samples, exact build metadata, and successful/failed exit counts."""
import argparse
import json
import math
import os
import pathlib
import platform
import random
import statistics
import subprocess
import tempfile
import time

parser=argparse.ArgumentParser()
parser.add_argument('--binary',type=pathlib.Path,required=True)
parser.add_argument('--out',type=pathlib.Path,required=True)
parser.add_argument('--samples',type=int,default=30)
parser.add_argument('--warmup',type=int,default=5)
args=parser.parse_args()
assert 5 <= args.samples <= 1000
binary=args.binary.resolve()
version=json.loads(subprocess.check_output([str(binary),'version','--json']))
with tempfile.TemporaryDirectory(prefix='ouro-bench-') as directory:
    root=pathlib.Path(directory); work=root/'work'; work.mkdir(); config=root/'config'; config.mkdir()
    env=os.environ|{'OURO_CONFIG_DIR':str(config),'OURO_DATA_DIR':str(root/'data')}
    cases=[('direct_true',['/usr/bin/true'],0),('version',[str(binary),'version','--json'],0)]
    if platform.system()=='Linux':
        for profile in ['tool','agent']:
            for observe in ['off','on']:
                cases.append((f'{profile}_{observe}_true',[str(binary),'run','--workspace',str(work),'--profile',profile,'--observe',observe,'--','/usr/bin/true'],0))
        cases.append(('direct_100_writes',['/bin/sh','-c','i=0; while [ "$i" -lt 100 ]; do printf x > item; i=$((i+1)); done'],0))
        cases.append(('tool_observed_100_writes',[str(binary),'run','--workspace',str(work),'--profile','tool','--observe','on','--','/bin/sh','-c','i=0; while [ "$i" -lt 100 ]; do printf x > item; i=$((i+1)); done'],0))
    else:
        cases.append(('macos_contained_refusal',[str(binary),'run','--workspace',str(work),'--profile','tool','--','/usr/bin/true'],125))
    rows=[{'case':name,'argv':command,'expected_exit':expected,'exit_counts':{},'errors':[],'flags':[],'receipts':[],'samples_ms':[]} for name,command,expected in cases]
    rng=random.Random(20260928)
    order=[]
    started=time.time()
    load_before=os.getloadavg()
    for iteration in range(args.warmup+args.samples):
        indices=list(range(len(cases)));rng.shuffle(indices)
        if iteration >= args.warmup: order.append([cases[i][0] for i in indices])
        for index in indices:
            name,command,expected=cases[index];row=rows[index]
            start=time.perf_counter_ns(); result=subprocess.run(command,env=env,cwd=work,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=30)
            elapsed=(time.perf_counter_ns()-start)/1e6
            if iteration < args.warmup: continue
            row['samples_ms'].append(elapsed)
            code=str(result.returncode); row['exit_counts'][code]=row['exit_counts'].get(code,0)+1
            flag = None
            if platform.system()=='Linux' and command[:2]==[str(binary),'run']:
                attempt=max((root/'data/attempts').iterdir(),key=lambda p:p.stat().st_mtime_ns)
                receipt=json.loads((attempt/'jail.json').read_text())
                fact={'attempt':attempt.name,'outcome':receipt['outcome'],'tree_empty':receipt['lifetime']['tree_empty'],'coverage':receipt['coverage'],'errors':receipt['errors']}
                row['receipts'].append(fact)
                if '_off_' in name and result.returncode==1 and receipt['outcome']['kind']=='unknown' and [e['code'] for e in receipt['errors']]==['exec_unconfirmed']:
                    flag='exec_unconfirmed: invocation timing only; target execution is not established'
                elif result.returncode==0:
                    assert receipt['outcome']['kind']=='exited' and receipt['outcome']['code']==0,fact
                assert fact['tree_empty'] is True,fact
                if '_on_' in name or 'observed' in name:
                    assert all(not value['gaps'] for value in receipt['coverage'].values()),fact
            if flag: row['flags'].append(flag)
            elif result.returncode != expected: row['errors'].append(result.stderr.decode(errors='replace')[:1000])
    for row in rows:
        samples=row['samples_ms']; ordered=sorted(samples)
        row.update(median_ms=statistics.median(samples),p95_ms=ordered[math.ceil(.95*len(ordered))-1],mean_ms=statistics.mean(samples))
        print(row['case'],round(row['median_ms'],3),'ms median',row['exit_counts'],flush=True)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps({'host':platform.uname()._asdict(),'build':version,'started_unix':started,'finished_unix':time.time(),'load_before':load_before,'load_after':os.getloadavg(),'samples':args.samples,'warmup':args.warmup,'seed':20260928,'rounds':order,'rows':rows},indent=2)+'\n')
    if any(r['errors'] for r in rows): raise SystemExit('benchmark has unexpected exits; timings are not success measurements')
