#!/usr/bin/env python3
"""Select complete corrected protocols; keep every pilot in the separate audit."""
import argparse
import csv
import hashlib
import json
import statistics
from pathlib import Path
from audit_results import audit

p = argparse.ArgumentParser()
p.add_argument('root', type=Path)
args = p.parse_args()
root = args.root
out = root.parent / 'analysis/final'
out.mkdir(parents=True, exist_ok=True)
selected = {'schema': 'selected-startup-benchmark/1', 'selection': [],
            'native_agents': [], 'container_agents': [], 'workflows': [], 'performance': []}

def rows(host, dataset):
    base = root / host
    if host != 'mac' and dataset.startswith('container-'):
        base = base / 'container-control-export'
    path = base / dataset / 'agent-runs.ndjson'
    batch = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return path, batch

def provenance(path, filters):
    selected['selection'].append({'source': str(path.relative_to(root)), 'filter': filters,
                                  'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})

for host in ['vps', 'pi', 'mac']:
    modes = ['direct', 'ouro', 'greywall', 'mxc'] if host != 'mac' else ['direct', 'greywall', 'mxc']
    for agent in ['claude', 'opencode', 'codex']:
        dataset = 'native-after'
        path, batch = rows(host, dataset)
        for mode in modes:
            chosen = [r for r in batch if r['agent'] == agent and r['mode'] == mode]
            assert len(chosen) == 6, (host, dataset, agent, mode, len(chosen))
            assert {(r['task'], r['repetition']) for r in chosen} == {
                (task, rep) for task in ['add-multiply', 'fix-offbyone', 'refactor-yaml-json'] for rep in [0, 1]}
            passed = [r for r in chosen if r['success']]
            selected['native_agents'].append({'host': host, 'agent': agent, 'mode': mode,
                'attempted': len(chosen), 'passed': len(passed),
                'median_success_ms': statistics.median(r['elapsed_ms'] for r in passed) if passed else None,
                'exit_counts': {str(code): sum(r['exit'] == code for r in chosen) for code in {r['exit'] for r in chosen}},
                'source': str(path.relative_to(root))})
            provenance(path, {'agent': agent, 'mode': mode})
        wf = 'workflow-after'
        path, batch = rows(host, wf)
        chosen = [r for r in batch if r['agent'] == agent]
        assert len(chosen) == len(modes), (host, wf, agent, len(chosen))
        for r in chosen:
            selected['workflows'].append(dict(host=host, kind='native', source=str(path.relative_to(root)),
                **{key: r.get(key) for key in ['agent', 'mode', 'success', 'exit', 'elapsed_ms', 'artifact', 'checker']}))
        provenance(path, {'agent': agent})

    for agent in ['claude', 'opencode', 'codex']:
        dataset = 'container-after-v2' if host == 'mac' else 'container-after-' + agent
        path, batch = rows(host, dataset)
        for mode in ['docker', 'openshell-ephemeral', 'openshell-warm']:
            mode_path, mode_batch = path, batch
            if host == 'pi' and mode == 'openshell-warm':
                avail = root / host / 'container-control-export/container-warm-availability/availability.json'
                startup = next(r for r in json.loads(avail.read_text()) if r['agent'] == agent)
            chosen = [r for r in mode_batch if r['agent'] == agent and r['mode'] == mode]
            if host == 'pi' and mode == 'openshell-warm' and not chosen:
                assert startup['ready'] is False
                selected['container_agents'].append({'host': host, 'agent': agent, 'mode': mode,
                    'attempted': 0, 'passed': 0, 'status': 'unavailable at startup', 'startup_attempted': 1,
                    'source': str(avail.relative_to(root))})
                continue
            assert len(chosen) == 6, (host, dataset, agent, mode, len(chosen))
            passed = [r for r in chosen if r['success']]
            selected['container_agents'].append({'host': host, 'agent': agent, 'mode': mode,
                'attempted': len(chosen), 'passed': len(passed),
                'median_success_ms': statistics.median(r['elapsed_ms'] for r in passed) if passed else None,
                'median_inner_ms': statistics.median(r['container_result']['work_ms'] for r in passed) if passed else None,
                'source': str(mode_path.relative_to(root))})
            provenance(mode_path, {'agent': agent, 'mode': mode})
        wf = 'container-workflow-after' if host == 'mac' else 'container-workflow-after-' + agent
        path, batch = rows(host, wf)
        chosen = [r for r in batch if r['agent'] == agent]
        expected = sum(1 for r in selected['container_agents'] if r['host'] == host and r['agent'] == agent and r['attempted'])
        assert len(chosen) == expected, (host, wf, agent, len(chosen), expected)
        for r in chosen:
            selected['workflows'].append(dict(host=host, kind='container', source=str(path.relative_to(root)),
                **{key: r.get(key) for key in ['agent', 'mode', 'success', 'exit', 'elapsed_ms', 'artifact']}))
        provenance(path, {'agent': agent})

    for dataset, filename, kind in [('perf-after', 'launches.ndjson', 'native'),
                                    ('container-perf-after', 'openshell-launches.ndjson', 'container')]:
        base = root / host / 'container-control-export' if host != 'mac' and kind == 'container' else root / host
        path = base / dataset / filename
        checked = audit(path)
        provenance(path, 'measurement; observation-off diagnostics excluded')
        for key, values in checked['table'].items():
            tool, case = key.split('/')
            if tool == 'ouro-obs-off':
                continue
            assert values['attempted'] == values['valid'] == 30, (host, dataset, key, values)
            selected['performance'].append(dict(host=host, kind=kind, tool=tool, case=case,
                source=str(path.relative_to(root)), **values))

(out / 'selected-results.json').write_text(json.dumps(selected, indent=2) + '\n')
for kind, keys in [('native_agents', ['host', 'agent', 'mode', 'attempted', 'passed', 'median_success_ms', 'source']),
                   ('container_agents', ['host', 'agent', 'mode', 'attempted', 'passed', 'status', 'median_success_ms', 'median_inner_ms', 'source']),
                   ('workflows', ['host', 'kind', 'agent', 'mode', 'success', 'exit', 'elapsed_ms', 'source', 'artifact'])]:
    with (out / (kind.replace('_', '-') + '.csv')).open('w', newline='') as f:
        writer = csv.DictWriter(f, keys, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(selected[kind])
with (out / 'performance.csv').open('w', newline='') as f:
    writer = csv.DictWriter(f, ['host', 'kind', 'tool', 'case', 'attempted', 'valid', 'median_ms', 'p95_ms', 'work_median_ms', 'source'])
    writer.writeheader()
    for r in selected['performance']:
        writer.writerow({key: r[key] for key in ['host', 'kind', 'tool', 'case', 'attempted', 'valid', 'source']} |
                        {'median_ms': r['elapsed_ms']['median'], 'p95_ms': r['elapsed_ms']['p95_nearest_rank'],
                         'work_median_ms': r['work_ms']['median'] if r['work_ms'] else None})
counts = {'native_invocations': sum(r['attempted'] for r in selected['native_agents']),
          'container_invocations': sum(r['attempted'] for r in selected['container_agents']),
          'workflow_invocations': len(selected['workflows']),
          'valid_performance_samples': sum(r['valid'] for r in selected['performance']),
          'performance_buckets': len(selected['performance'])}
(out / 'counts.json').write_text(json.dumps(counts, indent=2) + '\n')
print(json.dumps(counts))
