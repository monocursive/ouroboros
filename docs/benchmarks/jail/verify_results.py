# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0", "rfc3339-validator==0.1.4", "rfc8785==0.1.4"]
# ///
"""Validate saved live receipts/events and bind learning output to its receipt."""
import hashlib
import json
from pathlib import Path
import runpy
import tomllib

root = Path(__file__).resolve().parent
contract = runpy.run_path(str(root.parents[1]/'specs/jail-v1/validate_contract.py'))
validators = contract['build_validators'](contract['load_schemas'](contract['ROOT']))
results = root/'results'
receipts = (sorted((results/'ouro-linux-acceptance').glob('*.json'))
            + sorted((results/'agent').glob('*-jail.json'))
            + sorted((results/'linux-followup/acceptance').glob('*.json')))
assert receipts, 'no live receipts'
for path in receipts:
    value = json.loads(path.read_text())
    validators['jail-receipt'].validate(value)
    contract['assert_clean'](contract['semantic_receipt'](value), path.name)
events = 0
for path in (results/'agent').glob('*-trace.ndjson'):
    with path.open() as stream:
        for line in stream:
            value = json.loads(line)
            validators['jail-event'].validate(value)
            contract['assert_clean'](contract['semantic_event'](value), path.name)
            events += 1
proposal_path = results/'agent/learned.toml'
if proposal_path.exists():
    proposal = tomllib.loads(proposal_path.read_text())
    from jsonschema import Draft202012Validator
    schema = json.loads((contract['ROOT']/'learned-policy.schema.json').read_text())
    Draft202012Validator(schema).validate(proposal)
    receipt = (results/'agent/learn-jail.json').read_bytes()
    assert proposal['provenance']['receipt_digest']=='sha256:'+hashlib.sha256(receipt).hexdigest()
    assert all(grant in proposal['provenance']['evidence'] for grant in proposal['read_only']+proposal['network_allow'])
mac = json.loads((results/'macos.json').read_text())
linux = json.loads((results/'linux.json').read_text())
assert mac['build']['build']['inputs']==linux['build']['build']['inputs']
for result in [mac,linux]:
    for row in result['rows']:
        assert not row['errors'] and len(row['samples_ms'])==result['samples'], row['case']
followup = results/'linux-followup'
if (followup/'k17.json').exists():
    from performance import evaluate
    summary_raw = (followup/'perf/summary.json').read_bytes()
    expected = evaluate(json.loads(summary_raw))
    expected['summary_sha256'] = hashlib.sha256(summary_raw).hexdigest()
    assert json.loads((followup/'k17.json').read_text()) == expected, 'K17 verdict drift'
    builds = [json.loads((followup/p).read_text()) for p in ('build.json', 'macos/build.json')]
    assert builds[0]['build']['inputs'] == builds[1]['build']['inputs'], 'follow-up source mismatch'
    host = json.loads(summary_raw)['host']
    assert host['jail']['version'] == builds[0], 'benchmark build mismatch'
    checksums = {Path(path).name: digest for digest, path in
                 (line.split() for line in (followup/'post-suite-binaries.sha256').read_text().splitlines())}
    assert host['jail']['sha256'] == checksums['ouro-jail'], 'benchmark jail mismatch'
    assert host['fixture']['sha256'] == checksums['ouro-fixture'], 'benchmark fixture mismatch'
    print(f"K17 recorded verdict: {expected['verdict']} (summary digest and budgets verified)")
print(f'PASS: {len(receipts)} live receipts, {events} live events, learning provenance when present, and benchmark sample counts/source digests')
