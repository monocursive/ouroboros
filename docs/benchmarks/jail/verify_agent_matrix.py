# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0", "rfc3339-validator==0.1.4", "rfc8785==0.1.4"]
# ///
"""Verify retained matrix evidence, including honestly recorded failed attempts."""
import argparse
import gzip
import hashlib
import json
import math
from pathlib import Path
import runpy

from agent_matrix import PROMPTS, receipt_problems, summarize


def verify_inventory(result, require_complete=True):
    if result.get('active_trial'):
        raise ValueError('a trial is still active or was interrupted')
    arms = result.get('arms', ['direct', 'off', 'on'])
    tasks = result.get('tasks', list(PROMPTS))
    if (not isinstance(result['rounds'], int) or not 1 <= result['rounds'] <= 30
            or not arms or len(arms) != len(set(arms))
            or not set(arms) <= {'direct', 'off', 'on'}
            or not tasks or len(tasks) != len(set(tasks)) or not set(tasks) <= set(PROMPTS)):
        raise ValueError('invalid or unbounded matrix parameters')
    expected = {f'{i:02d}-{task}-{arm}' for i in range(result['rounds'])
                for task in tasks for arm in arms}
    names = [row['name'] for row in result['rows']]
    if len(names) != len(set(names)) or not set(names) <= expected:
        raise ValueError('duplicate or unexpected trial inventory')
    complete = set(names) == expected
    if require_complete and not complete:
        raise ValueError('incomplete trial inventory')
    for row in result['rows']:
        if row['name'] != f"{row['iteration']:02d}-{row['task']}-{row['arm']}":
            raise ValueError('trial labels contradict the inventory')
        if (row['passed'] != (not row['problems']) or not math.isfinite(row['seconds'])
                or row['seconds'] <= 0):
            raise ValueError('trial verdict contradicts its evidence')
        if row['exit'] != 0 and row['passed']:
            raise ValueError('failed CLI labelled successful')
    expected_status = 'passed' if complete and all(r['passed'] for r in result['rows']) else 'failed'
    if (result['status'] == 'blocked' and result.get('blocked_reason', '').startswith('provider_rate_limit')
            and result['rows'] and result['rows'][-1].get('provider_rate_limited') is True):
        expected_status = 'blocked'
    if result['status'] != expected_status or result['summary'] != summarize(result['rows']):
        raise ValueError('summary or final verdict drift')
    return {'complete': complete, 'planned_trials': len(expected), 'recorded_trials': len(names)}


def verify_trial_files(directory, row, allow_missing_greetings=False):
    required = ['stdout.txt', 'stderr.txt']
    if row['arm'] != 'direct':
        required += ['jail.json', 'trace.ndjson.gz']
    if row['task'] == 'repair':
        required += ['judge-jail.json', 'judge.txt', 'numbers_task.py']
    elif row['passed'] and not allow_missing_greetings:
        required += ['greeting.txt']
    missing = [name for name in required if not (directory / name).is_file()]
    if missing:
        raise ValueError(f'missing retained trial evidence in {directory}: {missing}')
    if row['task'] == 'greeting' and row['passed']:
        if not (directory / 'greeting.txt').is_file():
            return False
        if (directory / 'greeting.txt').read_bytes() != b'hello\n':
            raise ValueError('passing greeting has incorrect contents')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--inputs', required=True)
    parser.add_argument('--allow-incomplete', action='store_true', help='Validate retained failures without claiming a completed matrix.')
    parser.add_argument('--allow-missing-greetings', action='store_true',
                        help='Audit legacy runs that checked greetings live but did not retain them; report missing artifacts.')
    args = parser.parse_args()
    result = json.loads((args.directory / 'result.json').read_text())
    inventory = verify_inventory(result, require_complete=not args.allow_incomplete)
    if result['build']['build']['inputs'] != args.inputs:
        raise ValueError('source input mismatch')
    contract_path = Path(__file__).resolve().parents[2] / 'specs/jail-v1/validate_contract.py'
    contract = runpy.run_path(str(contract_path))
    validators = contract['build_validators'](contract['load_schemas'](contract['ROOT']))
    counts = {'receipts': 0, 'events': 0, 'trials': len(result['rows'])}
    missing_greetings = []
    for row in result['rows']:
        directory = args.directory / row['name']
        if not verify_trial_files(directory, row, args.allow_missing_greetings):
            missing_greetings.append(row['name'])
        for name in ['jail.json', 'judge-jail.json']:
            path = directory / name
            if not path.exists():
                if name == 'jail.json' and row['arm'] != 'direct':
                    raise ValueError('missing attempt receipt')
                continue
            receipt = json.loads(path.read_text())
            validators['jail-receipt'].validate(receipt)
            contract['assert_clean'](contract['semantic_receipt'](receipt), str(path))
            counts['receipts'] += 1
            if name == 'jail.json':
                if (receipt['attempt_id'] != row['attempt_id']
                        or receipt['outcome'] != row['outcome']):
                    raise ValueError('receipt contradicts trial attribution or outcome')
                if row['passed'] and receipt_problems(receipt, row['arm']):
                    raise ValueError('passing trial has a failed receipt')
            elif row['passed']:
                if (receipt['phase'] != 'settled' or receipt['containment'] != 'enforced'
                        or receipt['outcome']['kind'] != 'exited'
                        or receipt['outcome']['code'] != 0
                        or receipt['lifetime']['tree_empty'] is not True
                        or receipt['state_cleanup'] != 'complete'):
                    raise ValueError('passing repair has a failed judge receipt')
        trace = directory / 'trace.ndjson.gz'
        if trace.exists():
            digest = hashlib.sha256()
            receipt = json.loads((directory / 'jail.json').read_text())
            with gzip.open(trace, 'rb') as stream:
                for line in stream:
                    digest.update(line)
                    event = json.loads(line)
                    validators['jail-event'].validate(event)
                    contract['assert_clean'](contract['semantic_event'](event), str(trace))
                    if event['attempt_id'] != receipt['attempt_id']:
                        raise ValueError('event attributed to another attempt')
                    counts['events'] += 1
            if digest.hexdigest() != row['trace_sha256']:
                raise ValueError('trace digest mismatch')
    print(json.dumps({'evidence_valid': True, 'matrix_status': result['status'], **inventory, **counts,
                      'fixture_evidence_complete': not missing_greetings,
                      'missing_greeting_artifacts': missing_greetings}))


if __name__ == '__main__':
    main()
