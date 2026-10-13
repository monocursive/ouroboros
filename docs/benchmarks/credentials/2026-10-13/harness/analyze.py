#!/usr/bin/env python3
"""Offline verification and credential compatibility analysis from saved files."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import random
import statistics


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')


def percentile(values, q):
    v = sorted(values)
    x = (len(v) - 1) * q
    low = int(x)
    return v[low] + (v[min(low + 1, len(v) - 1)] - v[low]) * (x - low)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('--hosts', default='vps,pi', help='Use a subset only for an explicitly interim analysis')
    p.add_argument('--allow-partial', action='store_true', help='Write explicitly interim evidence while credential input is pending')
    args = p.parse_args()
    root = args.root.resolve()
    previous = root.parent / '2026-10-12'
    summary = {'schema': 'credential-benchmark-analysis/1', 'hosts': {},
               'historical_client_latency_is_not_a_causal_comparison': True,
               'automatic_oauth_refresh': 'configured and synthetic fixtures exercised',
               'native_mac_vault': 'not exercised', 'expected_scored_calls_per_host': 21,
               'interim': args.allow_partial}
    compare = []
    receipt_checks = []
    bindings = []
    for host in args.hosts.split(','):
        data = root / 'results' / host
        manifest = json.loads((data / 'export-manifest.json').read_text())
        for entry in manifest:
            assert sha(data / entry['path']) == entry['sha256'], entry['path']
        journals = json.loads((data / 'journal-export-coverage.json').read_text())
        assert not journals['missing'], (host, journals['missing'])
        after = rows(data / 'vault-native/agent-runs.ndjson')
        workflow = rows(data / 'vault-workflow/agent-runs.ndjson')
        if args.allow_partial:
            assert len(after) <= 18 and len(workflow) <= 3
        else:
            assert len(after) == 18 and len(workflow) == 3, (host, len(after), len(workflow))
        old_small_path = previous / 'results' / host / 'vault-native/agent-runs.ndjson'
        old_flow_path = previous / 'results' / host / 'vault-workflow/agent-runs.ndjson'
        old_rows = [r for f in [old_small_path, old_flow_path] for r in rows(f) if r['mode'] == 'ouro']
        old = {(r['agent'], r['task'], r['repetition']): r for r in old_rows}
        metadata = json.loads((data / 'vault-native/metadata.json').read_text())
        before_metadata = json.loads((previous / 'results' / host / 'vault-native/metadata.json').read_text())
        for binary in ['claude', 'opencode', 'codex', 'ouro-jail']:
            current = metadata['bins'][binary]['sha256']
            baseline = before_metadata['bins'][binary]['sha256']
            if binary != 'ouro-jail': assert current == baseline, (host, binary)
            bindings.append({'host': host, 'binary': binary, 'before_sha256': baseline, 'after_sha256': current, 'unchanged': current == baseline})
        assert metadata['seed'] == before_metadata['seed']
        assert metadata['schedule'] == before_metadata['schedule']
        for key in ['wall_seconds', 'codex_model', 'anthropic_model', 'fixtures_sha256']:
            assert metadata[key] == before_metadata[key], (host, key)
        flow_metadata = json.loads((data / 'vault-workflow/metadata.json').read_text())
        before_flow_metadata = json.loads((previous / 'results' / host / 'vault-workflow/metadata.json').read_text())
        for key in ['seed', 'schedule', 'wall_seconds', 'codex_model', 'anthropic_model', 'fixtures_sha256']:
            assert flow_metadata[key] == before_flow_metadata[key], (host, 'workflow', key)
        exposure = {'runs': 0, 'snapshots': 0, 'readable_process_environments': 0,
                    'unreadable_process_environments': 0, 'files_checked': 0, 'hits': []}
        for row in after + workflow:
            lane = 'vault-workflow' if row in workflow else 'vault-native'
            run = data / lane / row['artifact']
            receipt = json.loads((run / 'jail.json').read_text())
            proof = json.loads((run / 'credential-exposure.json').read_text())
            before = old[(row['agent'], row['task'], row['repetition'])]
            before_lane = 'vault-workflow' if row in workflow else 'vault-native'
            before_receipt = json.loads((previous / 'results' / host / before_lane / before['artifact'] / 'jail.json').read_text())
            before_stderr = (previous / 'results' / host / before_lane / before['artifact'] / 'stderr.log').read_text()
            for key in ['snapshots', 'readable_process_environments', 'unreadable_process_environments', 'files_checked']:
                exposure[key] += proof[key]
            exposure['runs'] += 1
            exposure['hits'].extend({'artifact': str(run.relative_to(root)), 'kind': x} for x in proof['hits'])
            agent_details = receipt['lifetime']['native']['details'].get('agent', {})
            checks = {
                'settled': receipt['phase'] == 'settled',
                'strict': receipt['policy']['evidence'] == 'strict',
                'observe_on': receipt['policy']['observe'] == 'on',
                'enforced': receipt['containment'] == 'enforced' and receipt['child_protection'] == 'enforced',
                'observer': receipt['observer']['backend'] == 'ptrace' and receipt['observer']['set'] == 'linux-closed-v1' and receipt['observer']['attached'],
                'coverage': all(v['status'] == 'active' and not v['gaps'] for v in receipt['coverage'].values()),
                'tree_empty': receipt['lifetime']['tree_empty'] is True,
                'cleanup': receipt['state_cleanup'] == 'complete',
                'vault_only': len(receipt['credentials']) == 1 and all(c['mode'] == 'vault' and c['never_staged'] and c.get('digest') is None and c['digest_unavailable_reason'] == 'never_staged' for c in receipt['credentials']),
                'source_hidden_and_placeholder': '"placeholder": true, "source_readable": false, "raw_anthropic_inherited": false' in (run / 'stderr.log').read_text(),
                'raw_values_absent_in_readable_samples': not proof['hits'],
                'sampled_environments_nonempty': proof['readable_process_environments'] > 0,
                'journal_present': (data / 'attempt-journals' / receipt['attempt_id'] / 'trace.ndjson').is_file(),
                'mitm_ca_declared': receipt['lifetime']['native']['details'].get('credential_injection') == 'mitm_ca',
                'tls_authority_verified': agent_details.get('tls_application_authority_verified') is True,
                'path_binding_declared': agent_details.get('vault_authority',{}).get('path_bound_credentials') == 1,
                'process_binding_declared': agent_details.get('vault_authority',{}).get('process_bound_credentials') == 1,
                'refresh_declared_for_codex': agent_details.get('vault_authority',{}).get('refresh_credentials') == (1 if row['agent']=='codex' else 0),
                'same_coverage_classes': sorted(receipt['coverage']) == sorted(before_receipt['coverage']),
                'same_network_allowlist': receipt['applied']['network']['allowed_hosts'] == before_receipt['applied']['network']['allowed_hosts'],
                'same_syscall_filter': receipt['applied']['syscalls'] == before_receipt['applied']['syscalls'],
                'same_protected_coverage': receipt['applied']['filesystem']['protected_coverage'] == before_receipt['applied']['filesystem']['protected_coverage'],
                'same_observer_plan': receipt['lifetime']['native']['details']['observer_plan'] == before_receipt['lifetime']['native']['details']['observer_plan'],
            }
            stderr = (run / 'stderr.log').read_text()
            transport = {'websocket_diagnostic_lines': sum('websocket' in x.lower() for x in stderr.splitlines()),
                         'https_fallback_lines': sum('falling back' in x.lower() for x in stderr.splitlines())}
            # Save the actual declaration, without inventing a field name or
            # pretending it captures every private application payload.
            receipt_checks.append({'host': host, 'agent': row['agent'], 'task': row['task'],
                                   'repetition': row['repetition'], 'artifact': str(run.relative_to(root)),
                                   'checks': checks, 'all_checked_pass': all(checks.values()),
                                   'transport_diagnostics': transport,
                                   'agent_declaration': agent_details,
                                   'observer_diagnostics': receipt['observer']['gaps']})
            compare.append({'host': host, 'agent': row['agent'], 'task': row['task'],
                            'repetition': row['repetition'], 'kind': 'workflow' if row in workflow else 'small',
                            'before_transport': 'vault_static_snapshot',
                            'after_transport': 'vault_live_bound_refresh', 'before_success': before['success'],
                            'after_success': row['success'], 'before_exit': before['exit'], 'after_exit': row['exit'],
                            'before_elapsed_ms_descriptive': before['elapsed_ms'],
                            'after_elapsed_ms_with_sampling_descriptive': row['elapsed_ms'],
                            'before_raw_sha256': sha(old_flow_path if row in workflow else old_small_path),
                            'before_raw_path': str((old_flow_path if row in workflow else old_small_path).relative_to(previous)),
                            'before_https_fallback_lines': sum('falling back' in x.lower() for x in before_stderr.splitlines()),
                            'after_https_fallback_lines': transport['https_fallback_lines'],
                            'after_artifact': str(run.relative_to(root))})
        checks = json.loads((data / 'mechanisms/checks.json').read_text())
        measured = [r for r in rows(data / 'mechanisms/timings.ndjson') if not r['warmup']]
        pairs = []
        for i in range(30):
            pair = {r['mode']: r for r in measured if r['pair'] == i}
            assert set(pair) == {'environment', 'vault'}
            if all(r['exit'] == 0 for r in pair.values()):
                pairs.append(pair['vault']['elapsed_ms'] - pair['environment']['elapsed_ms'])
        rng = random.Random(20261012)
        boots = [statistics.median(rng.choices(pairs, k=len(pairs))) for _ in range(10000)] if pairs else []
        offline = json.loads((data / 'mechanisms/summary.json').read_text())
        offline.update({'paired_median_extra_ms_ci95': [percentile(boots, .025), percentile(boots, .975)] if boots else None,
                        'bootstrap_samples': 10000, 'measured_receipts': len(measured)})
        mechanism_receipts = []
        for r in measured:
            d = json.loads((data / r['artifact'] / 'jail.json').read_text())
            mechanism_receipts.append({'strict': d['policy']['evidence'] == 'strict',
                                       'enforced': d['containment'] == 'enforced',
                                       'observer_attached': d['observer']['attached'],
                                       'active_coverage_no_gaps': all(c['status'] == 'active' and not c['gaps'] for c in d['coverage'].values()),
                                       'tree_empty': d['lifetime']['tree_empty'] is True,
                                       'cleanup_complete': d['state_cleanup'] == 'complete'})
        offline['all_measured_receipt_checks_pass'] = all(all(r.values()) for r in mechanism_receipts)
        summary['hosts'][host] = {'small_success': sum(r['success'] for r in after), 'small_calls': len(after),
                                 'workflow_success': sum(r['success'] for r in workflow), 'workflow_calls': len(workflow),
                                 'boundary_checks_pass': sum(c['pass'] for c in checks), 'boundary_checks': len(checks),
                                 'exposure': exposure, 'offline_startup': offline,
                                 'export_manifest_sha256': sha(data / 'export-manifest.json')}
        summary['hosts'][host]['codex_calls_with_https_fallback'] = sum(
            r['transport_diagnostics']['https_fallback_lines'] > 0 for r in receipt_checks
            if r['host'] == host and r['agent'] == 'codex')
        summary['hosts'][host]['lifecycle'] = json.loads((data / 'lifecycle/checks.json').read_text())
        summary['hosts'][host]['startup_binary_pairs'] = json.loads((data / 'startup-pairs/summary.json').read_text())
        pair_receipts = []
        for row in rows(data / 'startup-pairs/timings.ndjson'):
            if row['warmup']:
                continue
            receipt = json.loads((data / row['artifact'] / 'jail.json').read_text())
            pair_receipts.append(row['exit'] == 0 and receipt['phase'] == 'settled'
                and receipt['policy']['evidence'] == 'strict' and receipt['policy']['observe'] == 'on'
                and receipt['containment'] == 'enforced' and receipt['observer']['attached']
                and all(c['status'] == 'active' and not c['gaps'] for c in receipt['coverage'].values())
                and receipt['lifetime']['tree_empty'] is True and receipt['state_cleanup'] == 'complete')
        summary['hosts'][host]['startup_binary_pairs']['measured_receipts'] = len(pair_receipts)
        summary['hosts'][host]['startup_binary_pairs']['all_measured_receipt_checks_pass'] = all(pair_receipts)
        provider = data / 'provider-refresh-json/result.json'
        summary['hosts'][host]['real_provider_refresh'] = json.loads(provider.read_text()) if provider.exists() else {'verified_here': False, 'reason': 'No successful real-provider refresh record in this host export.'}
        pilot = data / 'provider-refresh/result.json'
        if pilot.exists():
            summary['hosts'][host]['initial_failed_provider_pilot'] = json.loads(pilot.read_text())
        summary['hosts'][host]['cohort_complete'] = len(after) == 18 and len(workflow) == 3
    summary['scored_calls'] = len(compare)
    summary['verified_scored_receipts'] = sum(r['all_checked_pass'] for r in receipt_checks)
    summary['verification_failures'] = [r for r in receipt_checks if not r['all_checked_pass']]
    label = '' if args.hosts == 'vps,pi' and not args.allow_partial else 'interim-' + args.hosts.replace(',', '-') + '-'
    save(root / ('analysis/' + label + 'summary.json'), summary)
    save(root / ('analysis/' + label + 'receipt-verification.json'), receipt_checks)
    save(root / ('analysis/' + label + 'binary-bindings.json'), bindings)
    save(root / ('analysis/' + label + 'before-after.json'), compare)
    with (root / ('analysis/' + label + 'before-after.csv')).open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(compare[0]), lineterminator='\n')
        w.writeheader()
        w.writerows(compare)
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
