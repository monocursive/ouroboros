#!/usr/bin/env python3
"""Recompute descriptive summaries without modifying any raw evidence."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics

def stats(values):
    if not values: return None
    ordered=sorted(values)
    return {'n':len(values),'median':statistics.median(values),'p95_nearest_rank':ordered[math.ceil(.95*len(values))-1],
            'min':ordered[0],'max':ordered[-1]}

def audit(path):
    rows=[json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    result={'source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'rows':len(rows),'table':{}}
    if path.name in ('launches.ndjson','openshell-launches.ndjson'):
        summary_path=path.with_name('summary.json')
        summary=json.loads(summary_path.read_text()) if summary_path.exists() else {}
        if not isinstance(summary, dict):
            summary = {}
        if 'performance' in summary: summary=summary['performance']
        if not summary:
            other=path.with_name('openshell-summary.json')
            if other.exists(): summary=json.loads(other.read_text())
        invalid=set(summary.get('invalid_sequences',[]))
        reference=summary.get('reference',{})
        if not reference:
            for r in rows:
                if r.get('phase')=='reference' and r.get('records'):
                    reference[r['case']]={k:r['records'][0].get(k) for k in ('workload','count','checksum')}
        for tool,case in sorted({(r['tool'],r['case']) for r in rows if r.get('phase')=='measurement'}):
            sample=[r for r in rows if r.get('phase')=='measurement' and r['tool']==tool and r['case']==case]
            valid=[]
            for r in sample:
                rec=r.get('records',[])
                ok=r.get('exit')==0 and not r.get('timeout') and r['sequence'] not in invalid and len(rec)==1
                ok=ok and case in reference and all(rec[0].get(k)==v for k,v in reference[case].items())
                if tool in ('ouro-jail','ouro-before','ouro-obs-off'):
                    receipt=r.get('receipt',{})
                    ok=ok and receipt.get('lifetime',{}).get('tree_empty') is True and receipt.get('outcome',{}).get('kind')=='exited' and all(not c.get('gaps') for c in receipt.get('coverage',{}).values())
                if ok:valid.append(r)
            key=tool+'/'+case
            result['table'][key]={'attempted':len(sample),'valid':len(valid),'invalid_sequences':[r['sequence'] for r in sample if r not in valid],
                'elapsed_ms':stats([r['elapsed_ms'] for r in valid]),
                'work_ms':stats([r['records'][0]['payload_ns']/1e6 for r in valid if r['records'][0].get('payload_ns') is not None])}
        result['validation']='exit, no timeout, reference count/checksum, invalid-sequence exclusions, Ouro lifetime/outcome/coverage'
    else:
        for agent,mode in sorted({(r['agent'],r['mode']) for r in rows}):
            sample=[r for r in rows if r['agent']==agent and r['mode']==mode]
            explicit=all('success' in r for r in sample)
            ok=[r for r in sample if r.get('success')] if explicit else [r for r in sample if r.get('exit')==0 and r.get('checker',{}).get('tests_pass')]
            result['table'][agent+'/'+mode]={'attempted':len(sample),'success':len(ok),'explicit_independent_verdict':explicit,
                'elapsed_ms_successful':stats([r['elapsed_ms'] for r in ok]),
                'tasks':{task:{'attempted':sum(r['task']==task for r in sample),'success':sum(r['task']==task for r in ok)} for task in sorted({r['task'] for r in sample})}}
        result['validation']='recorded independent verdict' if all('success' in r for r in rows) else 'legacy checker; not equal to final independent protocol'
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('root',type=Path)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    result={}
    for name in ('launches.ndjson','openshell-launches.ndjson','agent-runs.ndjson','openshell-agent-runs.ndjson'):
        for path in sorted(args.root.rglob(name)):
            result[str(path.relative_to(args.root))]=audit(path)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps({'schema':'benchmark-audit/1','p95_method':'nearest rank, ceil(.95*n)-1',
        'note':'All datasets retained. Selection of valid final protocols is declared separately; pilots are not comparative results.',
        'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'datasets':result},indent=2)+'\n')
    print(json.dumps({'datasets':len(result),'out':str(args.out)}))

if __name__=='__main__':main()
