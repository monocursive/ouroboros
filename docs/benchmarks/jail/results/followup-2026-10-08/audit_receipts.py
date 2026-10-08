# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0", "rfc3339-validator==0.1.4", "rfc8785==0.1.4"]
# ///
import json,runpy
from pathlib import Path
contract=runpy.run_path('docs/specs/jail-v1/validate_contract.py')
validators=contract['build_validators'](contract['load_schemas'](contract['ROOT']))
root=Path('evidence/jail-next-20261008/export');count=0; containment={}
for path in root.rglob('*.json'):
 value=json.loads(path.read_text())
 if not isinstance(value,dict) or value.get('schema')!='ouro.jail.receipt/1':continue
 validators['jail-receipt'].validate(value)
 contract['assert_clean'](contract['semantic_receipt'](value),str(path))
 containment[value['containment']]=containment.get(value['containment'],0)+1
 assert value['lifetime']['tree_empty'] is True
 assert value['lifetime']['integrity']=='verified'
 assert value['state_cleanup']==('not_needed' if value['containment']=='none' else 'complete')
 count+=1
out={'receipts':count,'schema_and_semantics_valid':True,'verified_empty_trees':count,'containment_counts':containment,'cleanup_complete_or_explicitly_not_needed':count}
(root/'receipt-audit.json').write_text(json.dumps(out,indent=2)+'\n');print(out)
