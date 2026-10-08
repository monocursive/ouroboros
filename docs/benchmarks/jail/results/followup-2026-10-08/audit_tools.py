# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0", "rfc3339-validator==0.1.4", "rfc8785==0.1.4"]
# ///
import json,gzip,runpy,hashlib
from pathlib import Path
contract=runpy.run_path('docs/specs/jail-v1/validate_contract.py')
validators=contract['build_validators'](contract['load_schemas'](contract['ROOT']))
root=Path('evidence/jail-next-20261008/export');rows=[]
for directory in [root/'pi/tools-clean',root/'pi/tools-final',root/'vps/tools-final']:
 result=json.loads((directory/'result.json').read_text());assert result['status']=='passed' and len(result['rows'])==7
 for row in result['rows']:
  assert row['passed'];d=directory/row['case'];receipt=json.loads((d/'jail.json').read_text());count=0;digest=hashlib.sha256()
  with gzip.open(d/'trace.ndjson.gz','rb') as stream:
   for line in stream:
    digest.update(line);event=json.loads(line)
    validators['jail-event'].validate(event)
    contract['assert_clean'](contract['semantic_event'](event),str(d))
    assert event['attempt_id']==receipt['attempt_id'];count+=1
  rows.append({'trial':str(d.relative_to(root)),'events':count,'uncompressed_trace_sha256':digest.hexdigest()})
report={'verified':True,'trials':len(rows),'events':sum(r['events'] for r in rows),'rows':rows}
(root/'opencode-tools-audit.json').write_text(json.dumps(report,indent=2)+'\n');print({k:v for k,v in report.items() if k!='rows'})
