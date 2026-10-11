#!/usr/bin/env python3
"""Validate inherited Mach exception evidence without claiming workload lifetime."""
import argparse
import hashlib
import json
from pathlib import Path

from macos_ptrace_lifetime_summary import identity, require, validate_snapshot

CASES = ('root', 'fork', 'setsid', 'double-fork', 'spawn-group', 'spawn-session',
         'clear-exception', 'breakpoint-control')
SOURCES = {'macos_mach_lifetime.c', 'macos_mach_lifetime.py', 'macos_ptrace_lifetime.c',
           'macos_ptrace_lifetime.py', 'macos_native.c', 'macos_native.py', 'macos_es.py'}
MASK = (1 << 6) | (1 << 7) | (1 << 8)
BEHAVIOR = (1 << 31) | 4  # MACH_EXCEPTION_CODES | EXCEPTION_IDENTITY_PROTECTED


def state(events, role, phase):
    found = [r for r in events if r.get('kind') == 'exception_state'
             and r['role'] == role and r['phase'] == phase]
    require(len(found) == 1 and found[0]['rc'] == 0, 'kernel exception-state inspection missing')
    return found[0]['live_mask'], found[0]['dead_mask']


def summarize(result, sources, after):
    require(result['schema'] == 'ouro.jail.macos-mach-lifetime/1'
            and result['status'] == 'experiment_complete', 'incomplete experiment')
    require(result['native_execution_ready'] is False and result['lifetime_contract_verified'] is False,
            'unsupported lifetime or native readiness claim')
    require(result['actor_uid'] == result['actor_euid'] == 501, 'ordinary guest user scope changed')
    require(result['settings']['virtualized'] is True
            and result['settings']['sip'] == 'System Integrity Protection status: disabled.'
            and result['settings']['approved_entitlement'] is False, 'development VM scope missing')
    require(result['fatal_port_size_query'] == {'rc': -1, 'errno': 2, 'size': 0, 'port_requested': False},
            'absent fatal-port interface observation changed')
    require(set(result['source_sha256']) == set(after['source_sha256']) == SOURCES,
            'source inventory missing')
    for name, expected in result['source_sha256'].items():
        require(hashlib.sha256((sources / name).read_bytes()).hexdigest() == expected == after['source_sha256'][name],
                'tested source mismatch: ' + name)
    require(set(result['binary_sha256']) == {'mach-research', 'native-fixture'}
            and result['binary_sha256'] == after['binary_sha256'], 'measured binary mismatch')
    cases = result['cases']
    samples = {r['sample'] for r in cases}
    require(samples and samples == set(range(1, max(samples) + 1)) and max(samples) <= 3,
            'invalid bounded sample matrix')
    expected = {(sample, case) for sample in samples for case in CASES}
    actual = [(r['sample'], r['case']) for r in cases]
    require(len(actual) == len(set(actual)) and set(actual) == expected, 'missing or duplicate trial')
    for row in cases:
        require(row['lifetime_contract_verified'] is False and row['cleanup_verified'] is True
                and 'error' not in row, 'invalid trial or incomplete cleanup')
        case = row['case']
        known = row['fixture_processes']
        roles = {'root'} if case in ('root', 'breakpoint-control') else {'root', 'late-child'}
        require(len(known) == len(roles) and {r['role'] for r in known} == roles
                and len({identity(r) for r in known}) == len(known), 'fixture identity mismatch')
        identity(row['custodian'])
        require(row['installed_mask'] == MASK
                and any(r.get('kind') == 'handler_construct' and r['rc'] == 0
                        and r['flags'] == (0x8000 | 0x10) for r in row['custodian_events'])
                and any(r.get('kind') == 'exception_installed' and r['rc'] == 0
                        and r['mask'] == MASK and r['behavior'] == BEHAVIOR for r in row['custodian_events']),
                'supported handler installation missing')
        require(set(row['after']) == set(row['after_runner_cleanup']) == roles,
                'independent snapshots missing')
        validate_snapshot(row['custodian_after'], row['custodian'])
        for member in known:
            validate_snapshot(row['after'][member['role']], member)
            validate_snapshot(row['after_runner_cleanup'][member['role']], member)
        require(not any(s['alive'] for s in row['after_runner_cleanup'].values()),
                'fixture survived emergency cleanup')
        events = row['workload_events']
        require(state(events, 'root', 'before_owner_loss') == (MASK, 0), 'root did not inherit live handler')
        received = [r for r in row['custodian_events'] if r.get('kind') == 'exception_message']
        if case == 'breakpoint-control':
            require(row['custodian_after']['alive'] is True
                    and row['after']['root']['alive'] is False
                    and row['fixture_empty_before_runner_cleanup'] is True,
                    'breakpoint control is not an owner-death trial')
            require(len(received) == 1 and received[0]['rc'] == 0 and received[0]['id'] > 0
                    and any(r.get('kind') == 'breakpoint_requested' for r in events),
                    'live exception-delivery control missing')
        else:
            require(row['custodian_after']['alive'] is False
                    and row['fixture_empty_before_runner_cleanup'] is False
                    and all(r['alive'] for r in row['after'].values()), 'owner-death survivor counterexample lost')
            require(received == [], 'normal syscall control unexpectedly delivered an exception')
            require(set(row['heartbeat_before']) == set(row['heartbeat_after']) == {r + '.heartbeat' for r in roles}
                    and all(row['heartbeat_after'][name] > size for name, size in row['heartbeat_before'].items()),
                    'surviving workload progress missing')
            require(state(events, 'root', 'after_owner_loss') == (0, MASK), 'dead root handler inspection missing')
            if 'late-child' in roles:
                if case == 'clear-exception':
                    require(state(events, 'late-child', 'before_clear') == (MASK, 0)
                            and any(r.get('kind') == 'clear_exception' and r['rc'] == 0 for r in events)
                            and state(events, 'late-child', 'before_owner_loss') == (0, 0)
                            and state(events, 'late-child', 'after_owner_loss') == (0, 0),
                            'workload handler-removal counterexample missing')
                else:
                    require(state(events, 'late-child', 'before_owner_loss') == (MASK, 0)
                            and state(events, 'late-child', 'after_owner_loss') == (0, MASK),
                            'inherited child handler inspection missing')
    return {'trials': len(cases), 'samples_per_case': len(samples),
            'scope': 'ordinary user in SIP-disabled macOS VM; known fixture identities',
            'native_execution_ready': False, 'lifetime_contract_verified': False,
            'owner_death_trials': sum(r['case'] != 'breakpoint-control' for r in cases),
            'owner_death_known_process_survivors': sum(len(r['fixture_processes']) for r in cases if r['case'] != 'breakpoint-control'),
            'breakpoint_delivery_controls': len(samples),
            'cases': {case: {'trials': len(samples), 'purpose': 'exception delivery' if case == 'breakpoint-control' else 'owner death',
                             'known_fixture_empty': sum(r['fixture_empty_before_runner_cleanup'] for r in cases if r['case'] == case)}
                      for case in CASES},
            'remaining_gates': ['handler death does not stop normal execution',
                                'workload can clear inherited handler',
                                'fatal-port sysctl absent on tested release kernel',
                                'normal SIP, signing and full native qualification']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results', type=Path)
    parser.add_argument('--after-hashes', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    raw = args.results.read_bytes()
    summary = summarize(json.loads(raw), args.results.parent / 'tested-source',
                        json.loads(args.after_hashes.read_text()))
    summary['results_sha256'] = hashlib.sha256(raw).hexdigest()
    args.out.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({'trials': summary['trials'], 'native_execution_ready': False}))


if __name__ == '__main__':
    main()
