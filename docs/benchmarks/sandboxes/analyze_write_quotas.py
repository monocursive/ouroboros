#!/usr/bin/env python3
"""Summarize observe_limits.py output with paired bootstrap intervals."""
import argparse
import json
import math
from pathlib import Path
import random
import statistics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results', type=Path)
    args = parser.parse_args()
    rows = json.loads((args.results / 'runs.json').read_text())
    rng = random.Random(20261001)
    out = {}
    for mode in ['reads', 'writes']:
        out[mode] = {}
        measured = [r for r in rows if r['label'].startswith(mode + ':')
                    and int(r['label'].split(':')[1]) >= 0]
        for arm in ['direct', 'before', 'after']:
            selected = [r for r in measured if r['arm'] == arm]
            out[mode][arm] = {}
            for metric in ['payload_ns', 'elapsed_ns']:
                values = sorted(r[metric] / 1e6 for r in selected)
                out[mode][arm][metric] = {
                    'median_ms': statistics.median(values),
                    'p95_ms': values[math.ceil(len(values) * .95) - 1],
                }
        for metric in ['payload_ns', 'elapsed_ns']:
            pairs = {}
            for row in measured:
                if row['arm'] in ['before', 'after']:
                    pairs.setdefault(row['label'], {})[row['arm']] = row[metric]
            ratios = [p['after'] / p['before'] for p in pairs.values()]
            boots = sorted(statistics.median(rng.choices(ratios, k=len(ratios)))
                           for _ in range(10000))
            out[mode][metric + '_paired_ratio'] = {
                'median': statistics.median(ratios),
                'bootstrap_95pct': [boots[250], boots[9749]], 'pairs': len(ratios),
            }
    out['max_sampled_load1'] = max(r['loadavg'][0] for r in rows)
    out['bootstrap'] = {'seed': 20261001, 'resamples': 10000,
                        'unit': 'round', 'statistic': 'median paired after/before ratio',
                        'interval': 'percentile'}
    (args.results / 'analysis.json').write_text(json.dumps(out, indent=2) + '\n')
    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    main()
