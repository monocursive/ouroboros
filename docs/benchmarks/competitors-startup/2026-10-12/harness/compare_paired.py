#!/usr/bin/env python3
"""Contemporaneous old/new Ouro comparison, with fixed-round paired intervals."""
import argparse
import csv
import hashlib
import json
import random
import statistics
from pathlib import Path
from audit_results import audit, stats

p = argparse.ArgumentParser()
p.add_argument('root', type=Path)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--hosts', default='vps,pi')
args = p.parse_args()
args.out.mkdir(parents=True, exist_ok=True)
result = []
evidence = {}
unavailable = []
scored_ouro_samples = 0
for host in args.hosts.split(','):
    source = args.root / host / 'perf-after/launches.ndjson'
    rows = [json.loads(line) for line in source.read_text().splitlines()]
    checked = audit(source)
    evidence[host] = checked
    for sample in rows:
        if sample['phase'] != 'measurement' or sample['tool'] not in ['ouro-before', 'ouro-jail']:
            continue
        receipt = sample['receipt']
        assert receipt['policy']['observe'] == 'on' and receipt['policy']['evidence'] == 'strict'
        assert receipt['containment'] == 'enforced' and receipt['exec_observed']
        assert receipt['observer']['attached'] and receipt['observer']['backend'] == 'ptrace'
        assert receipt['observer']['set'] == 'linux-closed-v1' and not receipt['observer']['gaps']
        assert receipt['lifetime']['tree_empty'] and not any(c.get('gaps') for c in receipt['coverage'].values())
        scored_ouro_samples += 1
    for case in ['noop', 'python', 'git', 'reads', 'writes', 'spawn', 'cpu']:
        for tool in ['ouro-before', 'ouro-jail']:
            verdict = checked['table'].get(tool + '/' + case)
            if verdict is None:
                failed = [r for r in rows if r['phase'] == 'case-preflight' and r['tool'] == tool and r['case'] == case and r['exit'] != 0]
                assert len(failed) == 1, (host, tool, case, 'missing cell without explicit failed preflight')
                unavailable.append({'host': host, 'case': case, 'tool': tool, 'phase': 'case-preflight', 'exit': failed[0]['exit'], 'sequence': failed[0]['sequence'], 'stderr': failed[0]['stderr'], 'source': str(source.relative_to(args.root)), 'scored_attempts': 0})
                continue
            assert verdict['attempted'] == verdict['valid'] == 30, (host, case, tool, verdict)
        if any(r['host'] == host and r['case'] == case for r in unavailable):
            continue
        old = {r['round']: r for r in rows if r['phase'] == 'measurement'
               and r['tool'] == 'ouro-before' and r['case'] == case}
        new = {r['round']: r for r in rows if r['phase'] == 'measurement'
               and r['tool'] == 'ouro-jail' and r['case'] == case}
        assert old.keys() == new.keys()
        pairs = [(old[i], new[i]) for i in sorted(old)]
        for a, b in pairs:
            for sample in [a, b]:
                receipt = sample['receipt']
                assert receipt['policy']['observe'] == 'on'
                assert receipt['policy']['evidence'] == 'strict'
                assert receipt['containment'] == 'enforced'
                assert receipt['exec_observed'] is True
                assert receipt['observer']['attached'] is True
                assert receipt['observer']['backend'] == 'ptrace'
                assert receipt['observer']['set'] == 'linux-closed-v1'
                assert not receipt['observer']['gaps']
                assert receipt['coverage']['exec']['observed_count'] >= 2
                if case == 'writes':
                    assert receipt['coverage']['fs.write']['observed_count'] == 1000
            assert {k: v['status'] for k, v in a['receipt']['coverage'].items()} == {
                k: v['status'] for k, v in b['receipt']['coverage'].items()}
        policy_equal = all(a['receipt']['policy']['digest'] == b['receipt']['policy']['digest']
                           for a, b in pairs)
        assert policy_equal, 'Policy differs between binary variants'
        diffs = [b['elapsed_ms'] - a['elapsed_ms'] for a, b in pairs]
        ratios = [b['elapsed_ms'] / a['elapsed_ms'] for a, b in pairs]
        rng = random.Random(20261011)
        bootstrap = sorted(statistics.median(rng.choices(diffs, k=len(diffs)))
                           for _ in range(10000))
        before = stats([a['elapsed_ms'] for a, _ in pairs])
        after = stats([b['elapsed_ms'] for _, b in pairs])
        result.append({'host': host, 'case': case, 'n_pairs': len(pairs),
                       'old_median_ms': before['median'], 'after_median_ms': after['median'],
                       'old_p95_ms': before['p95_nearest_rank'], 'after_p95_ms': after['p95_nearest_rank'],
                       'paired_median_delta_ms': statistics.median(diffs),
                       'paired_delta_ci95_low_ms': bootstrap[249],
                       'paired_delta_ci95_high_ms': bootstrap[9749],
                       'paired_median_reduction_percent': (1 - statistics.median(ratios)) * 100,
                       'policy_digests_equal': policy_equal,
                       'strict_observation_and_containment_verified': True,
                       'source': str(source.relative_to(args.root)),
                       'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest()})
(args.out / 'paired-startup.json').write_text(json.dumps(
    {'schema': 'ouro-paired-comparison/2', 'comparisons': result, 'validation': evidence,
     'unavailable_comparisons': unavailable, 'scored_ouro_samples_verified': scored_ouro_samples,
     'paired_samples': 2 * sum(r['n_pairs'] for r in result),
     'bootstrap': '10000 round-pair resamples; percentile 95% CI of median change; seed 20261011; descriptive, no multiple-test correction'},
    indent=2) + '\n')
with (args.out / 'paired-startup.csv').open('w', newline='') as f:
    w = csv.DictWriter(f, list(result[0]))
    w.writeheader()
    w.writerows(result)
