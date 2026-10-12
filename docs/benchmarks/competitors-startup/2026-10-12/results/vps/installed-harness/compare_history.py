#!/usr/bin/env python3
"""Historical first-after comparisons; distinct from contemporaneous paired proof."""
import csv,json,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve();before_root=root.parents[1]/'competitors-after/2026-10-11'
a=json.loads((before_root/'analysis/final/selected-results.json').read_text());b=json.loads((root/'analysis/final/selected-results.json').read_text());out=root/'analysis/history';out.mkdir(parents=True,exist_ok=True)
allrows={}
for category in ['native_agents','container_agents','workflows','performance']:
 def key(r):
  if category=='performance':return r['host'],r.get('kind',r.get('class')),r['tool'],r['case']
  if category=='workflows':return r['host'],r.get('kind',r.get('class')),r['agent'],r['mode']
  return r['host'],r['agent'],r['mode']
 old={key(r):r for r in a[category]};rows=[]
 for r in b[category]:
  if r.get('tool')=='ouro-before':continue
  k=key(r);previous=old.get(k)
  item={'host':r['host'],'kind':r.get('kind',r.get('class')),'tool':r.get('tool',r.get('mode')),'agent':r.get('agent'),'case':r.get('case'),'baseline_available':previous is not None,'before_source':previous.get('source') if previous else None,'after_source':r['source']}
  if category=='performance':item.update(before_median_ms=previous['elapsed_ms']['median'] if previous else None,after_median_ms=r['elapsed_ms']['median'],before_p95_ms=previous['elapsed_ms']['p95_nearest_rank'] if previous else None,after_p95_ms=r['elapsed_ms']['p95_nearest_rank'])
  elif category=='workflows':item.update(before_success=previous['success'] if previous else None,after_success=r['success'],before_exit=previous['exit'] if previous else None,after_exit=r['exit'])
  else:item.update(before_attempted=previous['attempted'] if previous else None,before_passed=previous['passed'] if previous else None,after_attempted=r['attempted'],after_passed=r['passed'])
  rows.append(item)
 with (out/(category.replace('_','-')+'-first-after-to-final.csv')).open('w',newline='') as f:
  w=csv.DictWriter(f,list(rows[0]));w.writeheader();w.writerows(rows)
 allrows[category]=rows
(out/'first-after-to-final.json').write_text(json.dumps({'schema':'historical-benchmark-comparison/1','baseline_root':str(before_root.relative_to(root.parents[1])),'baseline_source':'ac1263a','note':'Historical cohorts. Environment/time/provider and image availability can differ. Use analysis/paired for causally stronger contemporaneous old/new Ouro comparisons.','comparisons':allrows},indent=2)+'\n')
print(json.dumps({k:len(v) for k,v in allrows.items()}))
