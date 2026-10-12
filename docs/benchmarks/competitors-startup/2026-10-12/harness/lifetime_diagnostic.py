#!/usr/bin/env python3
"""Unscored interleaved lifetime canaries; retain every strict-evidence failure."""
import argparse,json,random,time
from pathlib import Path
from suite_paired import Suite
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--rounds',type=int,default=30);a=p.parse_args();s=Suite(a.root,a.root/'results/lifetime-diagnostic',0,0,['ouro-before','ouro-jail']);rng=random.Random(20261011);rows=[]
try:
 for n in range(a.rounds):
  tools=['ouro-before','ouro-jail'];rng.shuffle(tools)
  for tool in tools:
   marker=s.work/f'{tool}-{n}.heartbeat';row=s.run(tool,[s.python,str(s.payload),'lifecycle',str(marker)],'excluded-lifetime-diagnostic','detached_after_root_exit',n)
   before=marker.stat().st_size if marker.exists() else 0;time.sleep(.3);after=marker.stat().st_size if marker.exists() else 0
   r={'round':n,'tool':tool,'sequence':row['sequence'],'exit':row['exit'],'tree_empty':row.get('receipt',{}).get('lifetime',{}).get('tree_empty'),'bytes_at_return':before,'bytes_after_300ms':after,'observer_gaps':row.get('receipt',{}).get('observer',{}).get('gaps'),'stderr':row['stderr']};rows.append(r)
   if not r['tree_empty']:time.sleep(3.1)
  print('round',n,'complete',flush=True)
 out={'schema':'unscored-lifetime-diagnostic/1','excluded_from_timing_and_model_scores':True,'settings_changed':False,'rows':rows,'counts':{tool:{'calls':sum(r['tool']==tool for r in rows),'exit_nonzero':sum(r['tool']==tool and r['exit']!=0 for r in rows),'gaps':sum(r['tool']==tool and bool(r['observer_gaps']) for r in rows),'tree_not_empty':sum(r['tool']==tool and not r['tree_empty'] for r in rows),'heartbeat_survived':sum(r['tool']==tool and r['bytes_after_300ms']>r['bytes_at_return'] for r in rows)} for tool in ['ouro-before','ouro-jail']}}
 (a.root/'results/lifetime-diagnostic/summary.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['counts']))
finally:s.close()
