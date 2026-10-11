#!/usr/bin/env python3
"""Validate debugger-death mechanism evidence without claiming native readiness."""
import argparse
import hashlib
import json
from pathlib import Path

CASES = ('registered_death', 'registered_stop', 'fork', 'setsid', 'double-fork',
         'spawn-group', 'spawn-session', 'deny-attach')
REGISTERED = {'root', 'plain', 'stubborn', 'setsid', 'double-fork'}
SOURCES = {'macos_ptrace_lifetime.c', 'macos_ptrace_lifetime.py', 'macos_native.c',
           'macos_native.py', 'macos_es.py'}


def require(value, message):
    if not value:
        raise ValueError(message)


def identity(row):
    token = row['audit_token']
    require(len(token) == 8 and (token[5], token[7]) == (row['pid'], row['pidversion']),
            'audit-token identity mismatch')
    return row['pid'], row['pidversion'], row['uniqueid']


def validate_snapshot(row, member):
    require(row['pid'] == member['pid'], 'snapshot PID mismatch')
    same = row['unique_bytes'] == 56 and row['uniqueid'] == member['uniqueid']
    alive = same and row['bsd_bytes'] == 136 and row['status'] != 5
    require(type(row['alive']) is bool and row['same_process'] is same
            and row['alive'] is alive, 'snapshot liveness mismatch')
    if same:
        require(row['pidversion'] == member['pidversion'], 'snapshot PID version mismatch')


def summarize(result, sources, after):
    require(result['schema'] == 'ouro.jail.macos-ptrace-lifetime/1'
            and result['status'] == 'experiment_complete', 'incomplete mechanism experiment')
    require(result['native_execution_ready'] is False and result['lifetime_contract_verified'] is False,
            'unsupported native readiness claim')
    require(result['settings']['virtualized'] is True
            and result['settings']['sip'] == 'System Integrity Protection status: disabled.'
            and result['settings']['approved_entitlement'] is False, 'development VM scope missing')
    require(result['actor_uid'] == 0 and result['actor_euid'] == 0, 'root control scope changed')
    require(set(result['source_sha256']) == set(after['source_sha256']) == SOURCES,
            'tested source inventory missing')
    require(set(result['binary_sha256']) == {'ptrace-research', 'native-fixture'},
            'measured binary inventory missing')
    for name, expected in result['source_sha256'].items():
        actual = hashlib.sha256((sources / name).read_bytes()).hexdigest()
        require(actual == expected == after['source_sha256'][name], 'tested source mismatch: ' + name)
    require(result['binary_sha256'] == after['binary_sha256'], 'measured binary changed')
    cases = result['cases']
    samples = {row['sample'] for row in cases}
    require(samples and samples == set(range(1, max(samples) + 1)), 'noncontiguous samples')
    expected = {(sample, case) for sample in samples for case in CASES}
    actual = [(row['sample'], row['case']) for row in cases]
    require(len(actual) == len(set(actual)) and set(actual) == expected, 'missing or duplicate trial')
    for row in cases:
        require(row['lifetime_contract_verified'] is False and row['cleanup_verified'] is True
                and 'error' not in row, 'invalid trial or incomplete cleanup')
        case = row['case']
        known = row['fixture_processes']
        roles = {r['role'] for r in known}
        require(roles == (REGISTERED if case.startswith('registered') else {'root', 'late-child'})
                and len(known) == len(roles), 'unexpected fixture membership')
        require(len({identity(r) for r in known}) == len(known), 'duplicate process identity')
        identity(row['tracer'])
        registered = row['registered_members']
        expected_registered = known if case.startswith('registered') else [r for r in known if r['role'] == 'root']
        require({identity(r) for r in registered} == {identity(r) for r in expected_registered},
                'registration membership mismatch')
        attaches = row['attach_events']
        require(len(attaches) == len(registered)
                and {(r['pid'], r['pidversion']) for r in attaches} == {(r['pid'], r['pidversion']) for r in registered}
                and all(r['rc'] == 0 and r['errno'] == 0 for r in attaches), 'successful registration absent')
        require([r for r in row['tracer_events'] if r.get('kind') == 'attach'] == attaches
                and any(r.get('kind') == 'tracer_ready' and r['attached_count'] == len(registered)
                        for r in row['tracer_events']), 'tracer readiness evidence missing')
        require(set(row['after']) == roles and set(row['after_runner_cleanup']) == roles,
                'independent snapshots missing')
        validate_snapshot(row['tracer_after'], row['tracer'])
        for member in known:
            validate_snapshot(row['after'][member['role']], member)
            validate_snapshot(row['after_runner_cleanup'][member['role']], member)
        require(not any(r['alive'] for r in row['after_runner_cleanup'].values()), 'fixture survived emergency cleanup')
        if case == 'registered_death':
            require(row['tracer_after']['alive'] is False
                    and row['fixture_empty_before_runner_cleanup'] is True
                    and not any(r['alive'] for r in row['after'].values()), 'registered-member death proof absent')
        elif case == 'registered_stop':
            require(row['tracer_after']['alive'] is True
                    and row['tracer_after']['status'] == 4
                    and row['fixture_empty_before_runner_cleanup'] is False
                    and all(r['alive'] for r in row['after'].values()), 'paused-debugger counterexample lost')
            require(all(row['heartbeat_after'][name] > size
                        for name, size in row['heartbeat_before'].items())
                    and len(row['heartbeat_before']) == 4, 'paused-debugger workload progress missing')
        else:
            require(row['tracer_after']['alive'] is False and row['after']['root']['alive'] is False
                    and row['after']['late-child']['alive'] is True
                    and row['fixture_empty_before_runner_cleanup'] is False, 'late-fork survivor counterexample lost')
            name = 'late-child.heartbeat'
            require(row['heartbeat_after'][name] > row['heartbeat_before'][name], 'surviving child did not execute work')
            if case == 'deny-attach':
                require(any(r.get('kind') == 'deny_attach' and r['rc'] == 0 for r in row['workload_events']),
                        'child deny-attach probe missing')
    return {'trials': len(cases), 'samples_per_case': len(samples),
            'scope': 'known fixture processes in a SIP-disabled macOS VM, root control',
            'native_execution_ready': False, 'lifetime_contract_verified': False,
            'cases': {case: {'trials': len(samples), 'known_fixture_empty': sum(
                r['fixture_empty_before_runner_cleanup'] for r in cases if r['case'] == case)} for case in CASES},
            'remaining_gates': ['kernel protection is not inherited across fork/spawn',
                                'stopped debugger leaves workloads running',
                                'ordinary guest user attachment was denied',
                                'normal SIP and signing/authorization qualification',
                                'full containment, evidence and real-agent compatibility']}


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
