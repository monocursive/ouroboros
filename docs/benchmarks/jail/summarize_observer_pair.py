#!/usr/bin/env python3
"""Verify the paired workload inventory and summarize fixed-workload timing."""
import argparse
import json
import math
from pathlib import Path
import random
import statistics


def analyze(result):
    if result['status'] != 'completed':
        raise ValueError('benchmark did not complete')
    rows = result['rows']; count = result['samples']; warmups = result['warmups']
    expected = {(i, arm) for i in range(-warmups, count) for arm in ['before', 'after']}
    observed = [(r['iteration'], r['arm']) for r in rows]
    if len(observed) != len(set(observed)) or set(observed) != expected:
        raise ValueError('missing, duplicate, or unexpected paired observations')
    pairs = {}
    for row in rows:
        first, last = row['fixture_start'], row['fixture_end']
        start, end = first['args']['monotonic_ns'], last['args']['end_ns']
        if (not row['receipt_healthy'] or row['exit'] != 0 or not last['args']['ok']
                or first['op'] != 'perf-start' or last['op'] != 'fileops'
                or start != last['args']['start_ns'] or end <= start
                or row['wall_ns'] <= end - start
                or any(last['args'][key] != result['rounds'] for key in ['created', 'renamed', 'unlinked'])):
            raise ValueError('invalid workload or receipt verdict')
        if row['iteration'] >= 0:
            pairs.setdefault(row['iteration'], {})[row['arm']] = {'work_ns': end - start, 'wall_ns': row['wall_ns']}
    summary = {'pairs': count, 'measured_launches': 2 * count, 'warmup_launches': 2 * warmups,
               'exclusions': 0, 'max_load1': max(r['load1'] for r in rows),
               'bootstrap': {'seed': 20261008, 'resamples': 10000, 'unit': 'paired round', 'interval': 'percentile'}}
    rng = random.Random(20261008)
    for metric in ['work_ns', 'wall_ns']:
        summary[metric] = {}
        for arm in ['before', 'after']:
            times = sorted(p[arm][metric] / 1e6 for p in pairs.values())
            summary[metric][arm] = {'median_ms': statistics.median(times),
                                     'p95_ms': times[math.ceil(len(times) * .95) - 1]}
        ratios = [p['after'][metric] / p['before'][metric] for p in pairs.values()]
        estimates = sorted(statistics.median(rng.choices(ratios, k=count)) for _ in range(10000))
        summary[metric]['paired_ratio'] = {'median': statistics.median(ratios),
                                           'bootstrap_95pct': [estimates[250], estimates[9749]]}
    summary['work_improvement_demonstrated'] = summary['work_ns']['paired_ratio']['bootstrap_95pct'][1] < 1
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    summary = analyze(json.loads((args.directory / 'result.json').read_text()))
    (args.directory / 'analysis.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
