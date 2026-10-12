#!/usr/bin/env python3
"""Select fixed final protocols and derive tables from raw evidence."""
import argparse,csv,hashlib,json,statistics
from pathlib import Path
from audit_results import audit

AGENTS=['claude','opencode','codex']
TOOLS=['direct','ouro','mxc','greywall']
CASES=['noop','python','git','reads','writes','spawn','cpu']

def native_dataset(host,agent,mode):
 if agent=='opencode':
  if mode=='mxc' and host in ('pi','mac'):return 'v6-opencode-mxc'
  return 'v5-opencode'
 if host=='mac':return 'v4-codex' if agent=='codex' else 'v2-agents'
 return 'v4-agents'

def main():
 p=argparse.ArgumentParser();p.add_argument('root',type=Path);a=p.parse_args();root=a.root
 out=root/'analysis';out.mkdir(exist_ok=True)
 selected={'schema':'selected-benchmark/1','native_agents':[],'container_agents':[],'performance':[],'workflows':[],'selection':[]}
 tables=[]
 def readrows(host,dataset):
  f=root/(host+'-final')/dataset/'agent-runs.ndjson'
  return f,[json.loads(l) for l in f.read_text().splitlines() if l.strip()]
 for host in ('vps','pi','mac'):
  for agent in AGENTS:
   for mode in TOOLS:
    if host=='mac' and mode=='ouro':continue
    dataset=native_dataset(host,agent,mode);f,rows=readrows(host,dataset)
    rows=[r for r in rows if r['agent']==agent and r['mode']==mode]
    assert len(rows)==6,(host,agent,mode,len(rows))
    ok=[r for r in rows if r['success']]
    entry={'host':host,'agent':agent,'mode':mode,'attempted':len(rows),'passed':len(ok),'median_success_ms':statistics.median([r['elapsed_ms'] for r in ok]) if ok else None,'source':str(f.relative_to(root)), 'exit_counts':{str(n):sum(r['exit']==n for r in rows) for n in set(r['exit'] for r in rows)}}
    selected['native_agents'].append(entry)
    selected['selection'].append({'source':entry['source'],'filter':{'agent':agent,'mode':mode},'sha256':hashlib.sha256(f.read_bytes()).hexdigest()})
  for dataset in ('workflow-v2-final',):
   f,rows=readrows(host,dataset)
   assert len(rows)==(9 if host=='mac' else 12),(host,dataset,len(rows))
   for r in rows:selected['workflows'].append({'host':host,'class':'native','agent':r['agent'],'mode':r['mode'],'success':r['success'],'exit':r['exit'],'elapsed_ms':r['elapsed_ms'],'checker':r.get('checker'), 'source':str(f.relative_to(root)), 'artifact':r['artifact']})
  datasets=['openshell-v'+('3' if agent=='codex' else '2')+'-'+agent+'-final' for agent in AGENTS] if host=='vps' else ['openshell-v2-final']
  for dataset in datasets:
   f,rows=readrows(host,dataset)
   for agent in sorted(set(r['agent'] for r in rows)):
    for mode in ('docker','openshell-ephemeral','openshell-warm'):
     if host=='pi' and mode=='openshell-warm':
      availability=root/'pi-final/openshell-warm-availability/availability.json'
      init=next(r for r in json.loads(availability.read_text()) if r['agent']==agent)
      assert init['ready'] is False
      selected['container_agents'].append({'host':host,'agent':agent,'mode':mode,'attempted':0,'passed':0,'median_success_ms':None,'median_inner_ms':None,'source':str(availability.relative_to(root)),'status':'unavailable at startup','startup_attempted':1})
      continue
     batch=[r for r in rows if r['agent']==agent and r['mode']==mode];assert len(batch)==6,(host,dataset,agent,mode,len(batch))
     ok=[r for r in batch if r['success']]
     selected['container_agents'].append({'host':host,'agent':agent,'mode':mode,'attempted':len(batch),'passed':len(ok),'median_success_ms':statistics.median([r['elapsed_ms'] for r in ok]) if ok else None,'median_inner_ms':statistics.median([r['container_result']['work_ms'] for r in ok]) if ok else None,'source':str(f.relative_to(root))})
   selected['selection'].append({'source':str(f.relative_to(root)),'filter':'all','sha256':hashlib.sha256(f.read_bytes()).hexdigest()})
  datasets=['openshell-workflow-v'+('3' if agent=='codex' else '2')+'-'+agent+'-final' for agent in AGENTS] if host=='vps' else ['openshell-workflow-v2-final']
  for dataset in datasets:
   f,rows=readrows(host,dataset)
   assert len(rows)==(3 if host=='vps' else 6 if host=='pi' else 9)
   for r in rows:selected['workflows'].append({'host':host,'class':'container','agent':r['agent'],'mode':r['mode'],'success':r['success'],'exit':r['exit'],'elapsed_ms':r['elapsed_ms'],'source':str(f.relative_to(root)),'artifact':r['artifact']})
  for dataset,filename,kind in [('perf-v2-final' if host=='mac' else 'perf-v3-folder-deny','launches.ndjson','native'),('openshell-perf-v2-final','openshell-launches.ndjson','container')]:
   f=root/(host+'-final')/dataset/filename
   audited=audit(f)
   selected['selection'].append({'source':str(f.relative_to(root)),'filter':'measurement; Ouro obs-off excluded from headline','sha256':hashlib.sha256(f.read_bytes()).hexdigest()})
   for key,v in audited['table'].items():
    tool,case=key.split('/')
    if tool=='ouro-obs-off':continue
    assert v['attempted']==30 and v['valid']==30,(host,dataset,key,v['valid'])
    selected['performance'].append(dict(host=host,kind=kind,tool=tool,case=case,source=str(f.relative_to(root)),**v))
 (out/'selected-results.json').write_text(json.dumps(selected,indent=2)+'\n')
 for kind,keys in [('native_agents',['host','agent','mode','attempted','passed','median_success_ms','source']),('container_agents',['host','agent','mode','attempted','passed','median_success_ms','median_inner_ms','source'])]:
  with (out/(kind.replace('_','-')+'.csv')).open('w',newline='') as f:
   w=csv.DictWriter(f,keys,extrasaction='ignore');w.writeheader();w.writerows(selected[kind])
 with (out/'performance.csv').open('w',newline='') as f:
  keys=['host','kind','tool','case','attempted','valid','median_ms','p95_ms','work_median_ms','source'];w=csv.DictWriter(f,keys);w.writeheader()
  for r in selected['performance']:
   w.writerow({k:r.get(k) for k in keys[:6]}|{'median_ms':r['elapsed_ms']['median'],'p95_ms':r['elapsed_ms']['p95_nearest_rank'],'work_median_ms':r['work_ms']['median'] if r['work_ms'] else None,'source':r['source']})
 # Markdown fragments are generated, never hand-transcribed timings.
 for host in ('vps','pi','mac'):
  for kind,tools in [('native',['direct','mxc','ouro-jail','greywall']),('container',['docker-run','docker-warm','openshell-ephemeral','openshell-warm'])]:
   lines=['| Workload | '+' | '.join(tools)+' |','|---|'+'---:|'*len(tools)]
   for case in CASES:
    vals=[]
    for tool in tools:
     row=next((r for r in selected['performance'] if r['host']==host and r['kind']==kind and r['tool']==tool and r['case']==case),None)
     vals.append(('%.1f / %.1f'%(row['elapsed_ms']['median'],row['elapsed_ms']['p95_nearest_rank'])) if row else 'unavailable')
    lines.append('| '+case+' | '+' | '.join(vals)+' |')
   tables.append('### '+host+' '+kind+'\n\n'+'\n'.join(lines))
 (out/'performance-tables.md').write_text('\n\n'.join(tables)+'\n')
 print(json.dumps({'native_rows':sum(r['attempted'] for r in selected['native_agents']),'container_rows':sum(r['attempted'] for r in selected['container_agents']),'workflow_rows':len(selected['workflows']),'performance_buckets':len(selected['performance'])}))
if __name__=='__main__':main()
