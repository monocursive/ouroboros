#!/usr/bin/env python3
"""Validate XPC and launchd recovery evidence; never certify native lifetime."""
import argparse
import hashlib
import json
from pathlib import Path

from macos_ptrace_lifetime_summary import identity, require, validate_snapshot

ROLES = {'root', 'plain', 'stubborn', 'setsid', 'double-fork', 'spawn-group', 'spawn-session'}
XPC_CASES = ('host-death', 'service-death', 'both-death', 'host-stop', 'service-stop')
RECOVERY_CASES = ('custodian-death', 'custodian-stop')
COMMON_SOURCES = {'macos_native.c', 'macos_native.py', 'macos_ptrace_lifetime.py', 'macos_es.py'}


def provenance(result, source_dir, after, kind):
    require(result['schema'] == 'ouro.jail.macos-' + kind + '/1'
            and result['status'] == 'experiment_complete', 'incomplete experiment')
    require(result['native_execution_ready'] is False and result['lifetime_contract_verified'] is False,
            'unsupported native readiness or lifetime claim')
    settings = result['settings']
    require(settings['virtualized'] is True and settings['sip'] == 'System Integrity Protection status: disabled.'
            and settings['approved_entitlement'] is False, 'isolated development VM scope missing')
    uid = 501 if kind == 'xpc-lifetime' else 0
    require(result['actor_uid'] == result['actor_euid'] == uid, 'research actor scope changed')
    names = COMMON_SOURCES | ({'macos_xpc_lifetime.c', 'macos_xpc_lifetime.py'} if kind == 'xpc-lifetime'
                              else {'macos_launchd_recovery.py'})
    require(set(result['source_sha256']) == set(after['source_sha256']) == names, 'source inventory changed')
    for name in names:
        require(hashlib.sha256((source_dir / name).read_bytes()).hexdigest()
                == result['source_sha256'][name] == after['source_sha256'][name], 'tested source mismatch: ' + name)
    binaries = {'host', 'worker', 'native-fixture'} if kind == 'xpc-lifetime' else {'native-fixture'}
    require(set(result['binary_sha256']) == binaries and result['binary_sha256'] == after['binary_sha256'],
            'measured binaries changed')


def matrix(result, requested):
    cases = result['cases']
    samples = {r['sample'] for r in cases}
    require(samples and samples == set(range(1, max(samples) + 1)) and max(samples) <= 3,
            'invalid bounded samples')
    actual = [(r['sample'], r['case']) for r in cases]
    require(len(actual) == len(set(actual)) and set(actual) == {(s, c) for s in samples for c in requested},
            'missing or duplicate trial')
    return len(samples)


def membership(row):
    require(row['lifetime_contract_verified'] is False and row['cleanup_verified'] is True and 'error' not in row,
            'unsupported claim or incomplete cleanup')
    known = row['fixture_processes']
    require(len(known) == 7 and {r['role'] for r in known} == ROLES
            and len({identity(r) for r in known}) == 7, 'fixture membership changed')
    require(all(r['audit_token'][1] == r['audit_token'][3] == 501 for r in known), 'fixture UID changed')
    require(set(row['after']) == ROLES, 'before-cleanup snapshots missing')
    for r in known:
        validate_snapshot(row['after'][r['role']], r)
    return known


def progress(row):
    names = {r + '.heartbeat' for r in ROLES - {'root'}}
    require(set(row['heartbeat_before']) == set(row['heartbeat_after']) == names
            and all(row['heartbeat_after'][n] > row['heartbeat_before'][n] for n in names),
            'surviving workload progress missing')
    require(row['exec_marker_created'] is True
            and row['exec_probe'] == {'spawn_errno': 0, 'reaped': True, 'wait_status': 0},
            'post-fault execution control missing')


def xpc_summary(result, sources, after):
    provenance(result, sources, after, 'xpc-lifetime')
    require(result['launch_services'] is True and type(result['join_existing_session']) is bool,
            'LaunchServices application scope missing')
    require(result['signing'] == {'identity': '-', 'approved_profile': False, 'signature_verified': True}
            and after['signature_verify_after'] == {'OuroXPCResearch.app': 0,
                'OuroXPCResearch.app/Contents/XPCServices/Worker.xpc': 0}, 'ad-hoc signature verification missing')
    duration, requested = result['observation_seconds'], result['requested_cases']
    require((duration == 2 and requested == list(XPC_CASES))
            or (duration == 8 and requested == ['host-death', 'both-death']), 'observation matrix changed')
    samples = matrix(result, requested)
    coalitions = []
    for row in result['cases']:
        known = membership(row)
        anchors = row['anchors']
        require(set(anchors) == set(row['anchors_after']) == {'host', 'service'}, 'custodian identities missing')
        members = known + list(anchors.values())
        require(len({identity(r) for r in members}) == 9, 'duplicate fixture/custodian identity')
        require(all(r['coalition_bytes'] == 40 and r['coalitions'] == anchors['host']['coalitions'] for r in members),
                'per-application coalition membership missing')
        coalitions.append(tuple(anchors['host']['coalitions']))
        host_asid, service_asid = (anchors[r]['audit_token'][6] for r in ('host', 'service'))
        require((host_asid == service_asid) is result['join_existing_session']
                and all(r['audit_token'][6] == service_asid for r in known), 'audit-session setting not observed')
        require(set(row['after_runner_cleanup']) == ROLES | {'host', 'service'}, 'cleanup inventory missing')
        for r in members:
            validate_snapshot(row['after_runner_cleanup'][r['role']], r)
        require(all(r['alive'] is False for r in row['after_runner_cleanup'].values()), 'emergency cleanup incomplete')
        case = row['case']
        faulted = ['host', 'service'] if case == 'both-death' else [case.split('-')[0]]
        stopped = case.endswith('stop')
        require(row['faulted'] == faulted and row['signal'] == (17 if stopped else 9), 'lifecycle fault changed')
        for role, member in anchors.items():
            observed = row['anchors_after'][role]
            validate_snapshot(observed, member)
            dead = not stopped and (role in faulted or case == 'host-death')
            require(observed['alive'] is (not dead), 'XPC owner/service lifecycle control missing')
            if stopped and role in faulted:
                require(observed['status'] == 4, 'custodian was not stopped')
        require(all(r['alive'] is True for r in row['after'].values())
                and row['fixture_empty_before_runner_cleanup'] is False, 'survivor counterexample lost')
        require(duration * 1000 <= row['observation_ms'] < 11000, 'observation duration invalid')
        offsets = [200, 500, 1000, 2000] + ([4000, 8000] if duration == 8 else [])
        require(len(row['checkpoints']) == len(offsets)
                and all(c['elapsed_ms'] >= o for c, o in zip(row['checkpoints'], offsets)), 'timed checkpoints missing')
        require(any(e.get('kind') == 'spawn' and e['rc'] == 0 for e in row['service_events'])
                and any(e.get('ready') is True for e in row['workload_events']), 'workload startup control missing')
        progress(row)
    require(len(set(coalitions)) == len(coalitions), 'LaunchServices trials reused an application coalition')
    return {'trials': len(result['cases']), 'samples_per_case': samples,
            'join_existing_session': result['join_existing_session'], 'observation_seconds': duration,
            'known_workload_survivors': len(result['cases']) * 7,
            'post_fault_exec_controls': len(result['cases']), 'native_execution_ready': False,
            'lifetime_contract_verified': False,
            'scope': 'LaunchServices app, ad-hoc signature, ordinary user in SIP-disabled development VM'}


def recovery_summary(result, sources, after):
    provenance(result, sources, after, 'launchd-recovery')
    samples = matrix(result, RECOVERY_CASES)
    for row in result['cases']:
        known = membership(row)
        custodians = row['custodians']
        crash = row['case'] == 'custodian-death'
        require(len(custodians) == (2 if crash else 1)
                and all(r['uid'] == r['euid'] == r['audit_token'][1] == 0 for r in custodians),
                'root recovery generation missing')
        require(len({identity(r) for r in known + custodians}) == len(known + custodians), 'duplicate process identity')
        validate_snapshot(row['custodian_after'], custodians[0])
        require(row['custodian_after']['alive'] is (not crash) and row['signal'] == (9 if crash else 17),
                'custodian fault missing')
        require(3000 <= row['observation_ms'] < 10000, 'recovery checkpoint invalid')
        keys = {r['role'] + ':' + str(r['uniqueid']) for r in known + custodians}
        require(set(row['after_runner_cleanup']) == keys, 'cleanup identity inventory changed')
        for r in known + custodians:
            observed = row['after_runner_cleanup'][r['role'] + ':' + str(r['uniqueid'])]
            validate_snapshot(observed, r)
            require(observed['alive'] is False, 'emergency cleanup incomplete')
        require(row['known_empty_before_runner_cleanup'] is crash
                and all(r['alive'] is (not crash) for r in row['after'].values()), 'recovery/stop outcome changed')
        if crash:
            recovery = row['recovery']
            require(recovery is not None and recovery['known_processes'] == 7
                    and recovery['lifetime_contract_verified'] is False
                    and set(recovery['after']) == ROLES, 'automatic closed-set recovery evidence missing')
            for member in known:
                validate_snapshot(recovery['after'][member['role']], member)
            require(all(r['alive'] is False for r in recovery['after'].values())
                    and any(e.get('kind') == 'known_recovery_complete' and e['known_processes'] == 7
                            for e in row['custodian_events']), 'replacement custodian did not finish recorded recovery')
        else:
            require(row['custodian_after']['status'] == 4 and row['recovery'] is None,
                    'paused-custodian counterexample missing')
            progress(row)
    return {'trials': len(result['cases']), 'samples_per_case': samples, 'known_crash_recovery_controls': samples,
            'paused_custodian_survivors': samples * 7, 'native_execution_ready': False,
            'lifetime_contract_verified': False,
            'scope': 'temporary system launchd jobs; root recovery of seven recorded guest UID-501 identities',
            'remaining_gates': ['stopped custodian is not restarted', 'late unregistered descendants are not covered',
                                'no atomic immutable tree drain', 'normal SIP and full native qualification']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    raw = args.results.read_bytes(); result = json.loads(raw)
    after = json.loads((args.results.parent / 'after-hashes.json').read_text())
    summarize = xpc_summary if result['schema'] == 'ouro.jail.macos-xpc-lifetime/1' else recovery_summary
    summary = summarize(result, args.results.parent / 'tested-source', after)
    summary['results_sha256'] = hashlib.sha256(raw).hexdigest()
    args.out.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({'trials': summary['trials'], 'native_execution_ready': False}))


if __name__ == '__main__':
    main()
