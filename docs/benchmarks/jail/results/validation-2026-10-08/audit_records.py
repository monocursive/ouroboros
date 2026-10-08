# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0", "rfc3339-validator==0.1.4", "rfc8785==0.1.4"]
# ///
"""Run from the repository root, passing this evidence directory as argv[1]."""
import gzip
import json
from pathlib import Path
import runpy
import sys

root = Path(sys.argv[1]).resolve()
contract = runpy.run_path('docs/specs/jail-v1/validate_contract.py')
validators = contract['build_validators'](contract['load_schemas'](contract['ROOT']))
counts = {'receipts': 0, 'traces': 0, 'events': 0, 'enforced_receipts': 0, 'refused_receipts': 0}
for path in sorted(root.rglob('*.json')):
    record = json.loads(path.read_text())
    if not isinstance(record, dict) or record.get('schema') != 'ouro.jail.receipt/1':
        continue
    validators['jail-receipt'].validate(record)
    contract['assert_clean'](contract['semantic_receipt'](record), str(path))
    counts['receipts'] += 1
    if record['containment'] == 'enforced':
        assert record['phase'] == 'settled', path
        assert record['lifetime']['tree_empty'] is True, path
        assert record['lifetime']['integrity'] == 'verified', path
        assert record['state_cleanup'] == 'complete', path
        counts['enforced_receipts'] += 1
    else:
        assert record['phase'] == 'refused', (path, record['phase'])
        counts['refused_receipts'] += 1
for path in sorted(root.rglob('*trace.ndjson*')):
    receipt_path = path.with_name(path.name.replace('trace.ndjson.gz', 'jail.json').replace('trace.ndjson', 'jail.json'))
    receipt = json.loads(receipt_path.read_text())
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rb') as stream:
        for line in stream:
            event = json.loads(line)
            validators['jail-event'].validate(event)
            contract['assert_clean'](contract['semantic_event'](event), str(path))
            assert event['attempt_id'] == receipt['attempt_id'], path
            counts['events'] += 1
    counts['traces'] += 1
print(json.dumps({'schema': 'ouro.jail.validation-record-audit/1', 'valid': True,
                  'checks': ['frozen receipt and event schemas', 'receipt and event semantics',
                             'trace attempt attribution', 'enforced attempt cleanup and tree integrity'],
                  **counts}, indent=2))
