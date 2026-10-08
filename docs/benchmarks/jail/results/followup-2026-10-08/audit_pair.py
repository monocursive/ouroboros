import json,gzip,hashlib,sys
from pathlib import Path
sys.path.insert(0,'docs/benchmarks/jail')
from summarize_observer_pair import analyze
p=Path(sys.argv[1])
r=json.loads((p/'result.json').read_text()); a=analyze(r)
assert a==json.loads((p/'analysis.json').read_text())
counts={'traces':0,'events':0,'receipts':0,'fs_write_events':0}
for row in r['rows']:
 d=p/row['name']; receipt=json.loads((d/'jail.json').read_text()); counts['receipts']+=1
 assert receipt['lifetime']['tree_empty'] is True and receipt['lifetime']['integrity']=='verified'
 assert receipt['state_cleanup']=='complete' and receipt['outcome']['code']==0
 digest=hashlib.sha256(); write_count=0
 with gzip.open(d/'trace.ndjson.gz','rb') as f:
  for line in f:
   digest.update(line);event=json.loads(line)
   assert event['attempt_id']==receipt['attempt_id']
   counts['events']+=1
   if event['operation'] in ['fs.create','fs.rename','fs.unlink']:write_count+=1
 assert digest.hexdigest()==row['trace_sha256']
 assert write_count==receipt['coverage']['fs.write']['observed_count']==r['rounds']*3
 counts['fs_write_events']+=write_count; counts['traces']+=1
(p/'verification.json').write_text(json.dumps({'verified':True,'checks':['complete paired inventory','all retained trace digests','attempt attribution','exact create/rename/unlink count','verified cleanup','identical recomputed summary'],**counts},indent=2)+'\n')
print(counts)
