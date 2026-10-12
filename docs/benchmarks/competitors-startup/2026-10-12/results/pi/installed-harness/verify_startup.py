#!/usr/bin/env python3
"""Verify exported evidence, selected coding receipts and paired safety results."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
selected = json.loads((root / 'analysis/final/selected-results.json').read_text())
before_root = root.parents[1] / 'competitors-after/2026-10-11/results'
before_selected = json.loads((before_root.parent / 'analysis/final/selected-results.json').read_text())
before_rows = {}
for item in before_selected['native_agents'] + [r for r in before_selected['workflows'] if r['kind'] == 'native']:
    if item['mode'] != 'ouro':
        continue
    source = before_root / item['source']
    for row in map(json.loads, source.read_text().splitlines()):
        if row['agent'] == item['agent'] and row['mode'] == 'ouro':
            before_rows[(item['host'], row['agent'], row['task'], row['repetition'])] = (source, row)
coding_observation = []
proof = {'schema': 'startup-evidence-verification/1', 'hosts': {}, 'selected_ouro_receipts': 0,
         'safety_statuses_equal': {}, 'unchanged_source_manifest': True}
for path, expected in json.loads((root / 'source-files.json').read_text()).items():
    assert hashlib.sha256((Path.cwd() / path).read_bytes()).hexdigest() == expected, path
for host in ['vps', 'pi', 'mac']:
    base = root / 'results' / host
    exports = [base] if host == 'mac' else [base, base / 'container-control-export']
    export_proofs = []
    for export in exports:
        manifest = json.loads((export / 'export-manifest.json').read_text())
        for row in manifest:
            assert hashlib.sha256((export / row['path']).read_bytes()).hexdigest() == row['sha256'], (host, export.name, row['path'])
        journals = json.loads((export / 'journal-export-coverage.json').read_text())
        assert not journals['missing'], journals['missing']
        assert set(journals['referenced']) == set(journals['exported'])
        for attempt in journals['exported']:
            path = export / 'attempt-journals' / attempt / 'trace.ndjson'
            assert path.stat().st_size > 0, path
            for line in path.read_text().splitlines():
                json.loads(line)
        cleanup = json.loads((export / 'service-cleanup.json').read_text())
        assert all(row.get('exited_or_zombie') for row in cleanup)
        export_proofs.append({'source': str(export.relative_to(root)), 'manifest_files': len(manifest),
            'exported_journals': len(journals['exported']), 'missing_journals': 0,
            'temporary_services_stopped': True})
    # The final Ouro selection can reference only the fresh native export.
    journals = json.loads((base / 'journal-export-coverage.json').read_text())
    proof['hosts'][host] = {'exports': export_proofs,
        'final_native_exported_journals': len(journals['exported']),
        'container_controls_reused': host != 'mac'}
    if host == 'mac':
        continue
    doctor_before = json.loads((base / 'doctor-before.json').read_text())
    doctor_after = json.loads((base / 'validation/doctor-after.json').read_text())
    statuses = lambda report: {r['name']: (r['status'], r['reason_code'], r['mechanism']) for r in report['capabilities']}
    assert statuses(doctor_before) == statuses(doctor_after), host
    assert doctor_after['build']['debug_assertions'] is False and doctor_after['build']['opt_level'] == '3'
    assert doctor_after['build']['rustc'].startswith('rustc 1.98.1 ')
    local_source = json.loads((root / 'source-files.json').read_text())
    assert json.loads((base / 'validation/source-files.json').read_text()) == local_source
    proof['hosts'][host]['doctor_statuses_equal'] = True
    proof['hosts'][host]['binary_before_sha256'] = doctor_before['binaries']['ouro-jail']['sha256']
    proof['hosts'][host]['binary_after_sha256'] = doctor_after['binaries']['ouro-jail']['sha256']
    summary = json.loads((base / 'perf-after/summary.json').read_text())
    old = {r['probe']: r['status'] for r in summary['safety'] if r['tool'] == 'ouro-before'}
    new = {r['probe']: r['status'] for r in summary['safety'] if r['tool'] == 'ouro-jail'}
    assert old and old == new, (host, old, new)
    syscall_before = next(r['records'] for r in summary['safety'] if r['tool'] == 'ouro-before' and r.get('probe') == 'syscall_surface')
    syscall_after = next(r['records'] for r in summary['safety'] if r['tool'] == 'ouro-jail' and r.get('probe') == 'syscall_surface')
    assert syscall_before == syscall_after, (host, syscall_before, syscall_after)
    proof['hosts'][host]['syscall_probe_results_equal'] = True
    proof['safety_statuses_equal'][host] = old
    denied = json.loads((base / 'file-denial/summary.json').read_text())
    assert {r['binary_variant'] for r in denied} == {'before', 'after'}
    assert len(denied) == 2
    for r in denied:
        assert r['exit'] == 0 and not r['timeout'] and r['original_unchanged']
        assert 'FILE-DENIAL-PASS' in r['stdout']
        assert r['receipt']['policy']['observe'] == 'on' and r['receipt']['policy']['evidence'] == 'strict'
        assert r['receipt']['lifetime']['tree_empty'] and r['receipt']['containment'] == 'enforced'
        assert r['receipt']['attempt_id'] in journals['exported']
    proof['hosts'][host]['file_denial_before_after_pass'] = True
    backing = json.loads((base / 'backing-after/backing.json').read_text())
    assert all(r['exit'] == 0 and r['host_nonce_matches'] and r['same_inode'] for r in backing)
    proof['hosts'][host]['scored_workspace_backing_shared'] = True
    write_journals = []
    for row in map(json.loads, (base / 'perf-after/launches.ndjson').read_text().splitlines()):
        if row['phase'] != 'measurement' or row['case'] != 'writes' or row['tool'] not in ['ouro-before', 'ouro-jail']:
            continue
        attempt = row['receipt']['attempt_id']
        path = base / 'attempt-journals' / attempt / 'trace.ndjson'
        events = list(map(json.loads, path.read_text().splitlines()))
        # This closed observation set records mutation-capable open results;
        # fs.create belongs to the fs.write coverage class. It does not claim
        # to trace every write(2), its data bytes, or storage durability.
        writes = [e for e in events if e['operation'] in ['fs.create', 'fs.write']]
        assert len(writes) == row['receipt']['coverage']['fs.write']['observed_count'] == 1000
        assert all(e['stage'] == 'result' and e['outcome']['ok'] and e['outcome']['completion'] == 'syscall_return' for e in writes)
        assert all(e['fields']['path_complete'] for e in writes)
        assert {e['fields']['path']['value'] for e in writes} == {f'outputs/f{i:04d}' for i in range(1000)}
        write_journals.append({'tool': row['tool'], 'round': row['round'], 'attempt_id': attempt,
            'journal_source': str(path.relative_to(root)), 'mutation_open_results': len(writes),
            'receipt_count_matches_journal': True})
    assert len(write_journals) == 60
    (root / f'analysis/final/{host}-write-journal-counts.json').write_text(json.dumps(write_journals, indent=2) + '\n')
    proof['hosts'][host]['write_journals_verified'] = len(write_journals)
    datasets = {}
    for r in selected['native_agents'] + [r for r in selected['workflows'] if r['kind'] == 'native']:
        if r['host'] == host and r['mode'] == 'ouro':
            datasets.setdefault(r['source'], set()).add(r['agent'])
    for source, agents in sorted(datasets.items()):
        path = root / 'results' / source
        for row in map(json.loads, path.read_text().splitlines()):
            if row['mode'] != 'ouro' or row['agent'] not in agents:
                continue
            if row['success']:
                assert row['exit'] == 0 and not row['timeout'], row
                checker = row['checker']
                assert checker['tests_unchanged'] and checker['tests_pass'] and checker['hidden_pass']
            receipt = json.loads((path.parent / row['artifact'] / 'jail.json').read_text())
            assert receipt['policy']['observe'] == 'on' and receipt['policy']['evidence'] == 'strict'
            assert receipt['containment'] == 'enforced' and receipt['exec_observed'] is True
            assert receipt['observer']['attached'] is True and receipt['observer']['backend'] == 'ptrace'
            assert receipt['observer']['set'] == 'linux-closed-v1'
            assert receipt['lifetime']['tree_empty'] is True
            if row['success']:
                assert receipt['outcome']['kind'] == 'exited'
            assert all(not c.get('gaps') for c in receipt['coverage'].values())
            before_path, before_row = before_rows[(host, row['agent'], row['task'], row['repetition'])]
            before_receipt = json.loads((before_path.parent / before_row['artifact'] / 'jail.json').read_text())
            gaps_before = before_receipt['observer']['gaps']
            gaps_after = receipt['observer']['gaps']
            gap_types = lambda gaps: {(g['source'], g['reason'], tuple(g['classes'])) for g in gaps}
            # Provider/model work may change audit-only diagnostic counts.
            # Neither run may lose a declared coverage class.
            assert all(g['source'] == 'audit' and g['reason'] == 'path_claim_unverified' and not g['classes'] for g in gaps_before)
            assert all(g['source'] == 'audit' and g['reason'] == 'path_claim_unverified' and not g['classes'] for g in gaps_after)
            assert {k: v['status'] for k, v in before_receipt['coverage'].items()} == {k: v['status'] for k, v in receipt['coverage'].items()}
            coding_observation.append({'host': host, 'agent': row['agent'], 'task': row['task'], 'repetition': row['repetition'],
                'before_source': str(before_path.relative_to(before_root)), 'after_source': source,
                'before_observer_diagnostics': gaps_before, 'after_observer_diagnostics': gaps_after,
                'declared_coverage_statuses_equal': True, 'declared_coverage_gaps_after': False})
            assert receipt['attempt_id'] in journals['exported']
            proof['selected_ouro_receipts'] += 1
(root / 'analysis/final/coding-observation-before-after.json').write_text(json.dumps(coding_observation, indent=2) + '\n')
proof['coding_receipts_with_existing_audit_diagnostics'] = sum(bool(r['after_observer_diagnostics']) for r in coding_observation)
(root / 'analysis/final/evidence-verification.json').write_text(json.dumps(proof, indent=2) + '\n')
print(json.dumps(proof))
