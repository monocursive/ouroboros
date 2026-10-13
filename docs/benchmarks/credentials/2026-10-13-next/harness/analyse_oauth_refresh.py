#!/usr/bin/env python3
"""Independently evaluate completed native OAuth fixtures, including failures."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def read(root, filename):
    return json.loads((root / filename).read_text())


def evaluate(root):
    result, meta = read(root, 'result.json'), read(root, 'metadata.json')
    actor, final = read(root, 'oauth-client-identity.json'), read(root, 'oauth-client-final.json')
    clients, oracle = read(root, 'oauth-client-requests.json'), read(root, 'oracle.json')
    controls = read(root, 'controls.json')
    resources = [v for v in oracle['events'] if v['kind'] == 'resource']
    grants = [v for v in oracle['events'] if v['kind'] == 'grant']
    successful = [v for v in grants if v['accepted'] and not v['response_deliberately_lost']]
    native_grants = [v for v in successful if v['unix'] >= actor['started_unix']]
    checks = {}
    checks['execution_completed'] = result['status'] == 'completed' and result['actor_exit'] == 0
    checks['same_captured_handle_and_process'] = (
        actor['pid'] == final['pid'] and final['key_sha256_unchanged']
        and not actor['refresh_is_owned_by_client'] and not final['refresh_is_owned_by_client']
        and all(v['pid'] == actor['pid'] for v in clients))
    checks['opaque_handle_in_client'] = not actor['credential_variable_contains_fixture_access']
    checks['actual_clock_and_expiry'] = (
        not meta['real_clock_modified'] and not meta['forced_expiry_metadata']
        and not oracle['real_clock_modified'] and not oracle['forced_expiry_metadata']
        and meta['initial_expiry_unix'] == oracle['access_expiries']['0']
        and all(0 <= v['expires_at'] - v['unix'] <= meta['lifetime_seconds'] for v in successful))
    checks['multiple_native_refresh_cycles'] = len(native_grants) >= 3
    checks['no_refresh_grant_replay'] = (
        len(grants) == len(successful)
        and [v['prior_generation'] for v in grants] == list(range(len(grants)))
        and [v['issued_generation'] for v in grants] == list(range(1, len(grants) + 1)))
    checks['no_manual_rotation'] = meta['manual_rotation_calls'] == result['manual_rotation_calls'] == 0
    checks['full_observation_window'] = final['runtime_seconds'] >= meta['actor_seconds'] - 1
    checks['positive_initial_authentication'] = bool(resources and resources[0]['accepted']
                                                   and resources[0]['generation'] == 0)
    checks['all_client_requests_authenticated'] = bool(clients) and all(
        v.get('status') == 200 and v.get('accepted') for v in clients)
    by_id = Counter(v['request_id'] for v in resources)
    client_ids = [v['request_id'] for v in clients]
    checks['complete_independent_upstream_correlation'] = (
        len(clients) == len(resources) == final['requests']
        and len(set(client_ids)) == len(client_ids)
        and set(client_ids) == set(by_id) and all(v == 1 for v in by_id.values())
        and all(v['accepted'] and not v['expired_token']
                and v['client_pid_claim'] == str(actor['pid']) for v in resources))
    checks['concurrent_client_workload'] = final['concurrency_bursts'] == 4 and sum(
        v['label'] == 'concurrent' for v in clients) == 48
    crossed = []
    for generation, expiry in oracle['access_expiries'].items():
        if actor['started_unix'] <= expiry < final['completed_unix']:
            later = [v for v in resources if expiry <= v['unix'] <= expiry + 15
                     and v['accepted'] and v['generation'] > int(generation)]
            crossed.append({'generation': int(generation), 'actual_expiry_unix': expiry,
                            'later_valid_generation_observed': bool(later)})
    checks['continued_authentication_across_actual_expiries'] = (
        len(crossed) >= 2 and all(v['later_valid_generation_observed'] for v in crossed))
    checks['actor_and_issuer_bytes_match_metadata'] = all(
        hashlib.sha256((root / filename).read_bytes()).hexdigest() == meta[key]
        for filename, key in [('oauth_actor.py', 'actor_sha256'), ('oauth_fixture.py', 'issuer_sha256'),
                              ('matched_oauth_refresh.py', 'harness_sha256')])
    details = {}
    if meta['mode'] == 'ouro':
        receipt, policy = read(root, 'jail.json'), read(root, 'policy.json')
        trace = [json.loads(v) for v in (root / 'trace.ndjson').read_text().splitlines()]
        active = {'exec', 'fs.write', 'fs.deny', 'net', 'limits', 'proxy.net'}
        checks['ouro_strict_isolation_observation_settlement'] = (
            receipt['phase'] == 'settled' and receipt['containment'] == 'enforced'
            and receipt['exec_observed'] and receipt['policy']['evidence'] == 'strict'
            and receipt['policy']['observe'] == 'on' and receipt['observer']['attached']
            and receipt['observer']['backend'] == 'ptrace' and not receipt['observer']['gaps']
            and receipt['lifetime']['tree_empty'] and receipt['lifetime']['integrity'] == 'verified'
            and receipt['state_cleanup'] == 'complete'
            and all(receipt['coverage'][k]['status'] == 'active'
                    and not receipt['coverage'][k]['gaps'] for k in active)
            and all(not v['gaps'] for v in receipt['coverage'].values()))
        sequences = {}
        contiguous = True
        for event in trace:
            source, seq = event['source'], event['source_seq']
            contiguous &= seq == sequences.get(source, 0) + 1
            sequences[source] = seq
        checks['ouro_evidence_correlated'] = (
            policy['policy_digest'] == receipt['policy']['digest'] and bool(trace) and contiguous
            and all(v['attempt_id'] == receipt['attempt_id'] for v in trace))
        details['trace_events'] = len(trace)
        details['trace_sources'] = sequences
        details['denied_proxy_reasons'] = dict(Counter(
            v['fields'].get('reason') for v in trace
            if v['source'] == 'proxy' and v['decision'] == 'deny'))
        details['native_refresh_transitions'] = dict(Counter(
            v['fields'].get('transition') for v in trace
            if v['fields'].get('transition') in {'refresh_started', 'refreshed', 'refresh_failed'}))
    else:
        fences = read(root, 'container-fences.json')
        workload = [v for v in fences if v['user'] == '1000:1000']
        supervisor = [v for v in fences if v['user'] == '65534:65534']
        checks['openshell_configured_container_fences'] = (
            len(fences) == 2 and len(workload) == len(supervisor) == 1
            and workload[0]['image'] == meta['image_id']
            and workload[0]['host_config']['NetworkMode'] == 'none'
            and supervisor[0]['host_config']['NetworkMode'] == 'host'
            and all(v['running'] and v['host_config']['CapDrop'] == ['ALL']
                    and not v['host_config']['CapAdd']
                    and 'no-new-privileges:true' in v['host_config']['SecurityOpt'] for v in fences))
        cleanup = [v for v in controls if v['label'] in
                   {'sandbox-delete', 'provider-delete', 'profile-delete'}]
        checks['openshell_owned_resources_removed'] = len(cleanup) == 3 and all(
            v['exit'] == 0 for v in cleanup)
        checks['openshell_gateway_tls_verification_kept'] = not meta['gateway_tls_verification_disabled']
        details['observability_scope'] = ('Native container fences and independent upstream/client '
            'correlation. Common OCSF/native refresh log verification remains separate.')
    return {'mode': meta['mode'], 'all_checks_pass': all(checks.values()), 'checks': checks,
            'successful_native_rotations': len(native_grants), 'requests': len(clients),
            'actual_expiry_boundaries': crossed, 'grant_events': grants,
            'client_status_counts': dict(Counter(str(v.get('status')) for v in clients)),
            'metadata': meta, 'details': details,
            'evidence_sha256': {f.name: hashlib.sha256(f.read_bytes()).hexdigest()
                                for f in root.iterdir() if f.is_file()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('roots', type=Path, nargs=2)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    evaluations = []
    for root in args.roots:
        try:
            evaluations.append(evaluate(root))
        except (OSError, ValueError, KeyError, TypeError) as error:
            evaluations.append({'root': str(root), 'all_checks_pass': False,
                                'verification_error_class': type(error).__name__})
    metas = [v.get('metadata') for v in evaluations]
    matched = all(metas) and all(metas[0][k] == metas[1][k] for k in
        ['actor_sha256', 'issuer_sha256', 'host', 'lifetime_seconds', 'refresh_before_seconds',
         'actor_seconds', 'lost_response_generation', 'real_clock_modified', 'forced_expiry_metadata'])
    result = {'schema': 'matched-native-oauth-refresh-analysis/1', 'matched_fixture': bool(matched),
              'all_checks_pass': bool(matched and all(v['all_checks_pass'] for v in evaluations)),
              'synthetic_feature_proof_only': True, 'real_provider_expiry_proof': False,
              'scored_performance': False, 'products': evaluations,
              'remaining': ['uncertain rotating-grant response loss', 'TLS/WSS duplex revocation',
                            'common native observability verification', 'real-provider natural expiry']}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'all_checks_pass': result['all_checks_pass'], 'matched_fixture': bool(matched),
                      'products': [{k:v[k] for k in ['mode', 'all_checks_pass', 'successful_native_rotations',
                                                   'client_status_counts'] if k in v} for v in evaluations]}))
    return 0 if result['all_checks_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
