#!/usr/bin/env python3
"""Independently check every retained spawn pilot attempt and matched pair."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import statistics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.root
    metadata = json.loads((root / 'metadata.json').read_text())
    rows = [json.loads(line) for line in (root / 'timings.ndjson').read_text().splitlines()]
    samples, warmups = metadata['samples'], metadata['warmup_rounds']
    assert len(rows) == 4 * (samples + warmups)
    assert metadata['candidate_pilot'] and metadata['excluded_from_final_competitor_scores']
    proof = []
    after_count = 0
    for row in rows:
        directory = root / row['artifact']
        receipt = json.loads((directory / 'jail.json').read_text())
        active = {'exec', 'fs.write', 'fs.deny', 'net', 'limits'}
        if row['profile'] == 'vault':
            active.add('proxy.net')
        assert row['valid'] and row['exit'] == 0
        assert all(row['payload'][k] == v for k, v in {'workload': 'noop', 'count': 1, 'checksum': 0}.items())
        assert receipt['phase'] == 'settled' and receipt['containment'] == 'enforced'
        assert receipt['exec_observed'] and receipt['policy']['evidence'] == 'strict'
        assert receipt['policy']['observe'] == 'on'
        assert receipt['observer']['attached'] and receipt['observer']['backend'] == 'ptrace'
        assert not receipt['observer']['gaps']
        assert receipt['lifetime']['tree_empty'] and receipt['lifetime']['integrity'] == 'verified'
        assert receipt['state_cleanup'] == 'complete'
        assert all(receipt['coverage'][k]['status'] == 'active' and not receipt['coverage'][k]['gaps'] for k in active)
        assert all(not coverage['gaps'] for coverage in receipt['coverage'].values())
        if row['profile'] == 'tool':
            assert receipt['coverage']['proxy.net']['status'] == 'unsupported'
        if row['arm'] == 'after':
            assert receipt['lifetime']['native']['details']['bootstrap_spawn']['mechanism'] == metadata['expected_after_spawn']
            after_count += 1
        proof.append({'artifact': row['artifact'], **{
            name + '_sha256': hashlib.sha256((directory / filename).read_bytes()).hexdigest()
            for name, filename in [('receipt', 'jail.json'), ('trace', 'trace.ndjson'), ('policy', 'policy.json')]
        }})
    profiles = {}
    for kind in ('tool', 'vault'):
        pairs = []
        for pair in range(samples):
            subset = [row for row in rows if row['pair'] == pair and row['profile'] == kind]
            assert len(subset) == 2 and {row['arm'] for row in subset} == {'before', 'after'}
            pairs.append({row['arm']: row['elapsed_ms'] for row in subset})
        differences = [pair['after'] - pair['before'] for pair in pairs]
        rng = random.Random(20261013)
        boots = sorted(statistics.median(rng.choices(differences, k=samples)) for _ in range(10000))
        profiles[kind] = {
            'before_median_ms': statistics.median(pair['before'] for pair in pairs),
            'after_median_ms': statistics.median(pair['after'] for pair in pairs),
            'paired_difference_median_ms': statistics.median(differences),
            'paired_difference_bootstrap_ci95_ms': [boots[250], boots[9750]],
            'measurable_improvement': boots[9750] < 0,
        }
    result = {
        'schema': 'direct-cgroup-candidate-pilot-analysis/1',
        'status': 'candidate pilot; safety validation and final workload rerun required',
        'production_adopted': False, 'excluded_from_final_competitor_scores': True,
        'source_input_digests': {name: version['build']['inputs'] for name, version in metadata['versions'].items()},
        'all_attempts_verified': len(rows), 'after_mechanism_attempts_verified': after_count,
        'profiles': profiles,
        'method': 'Uninstrumented original no-op and 1000 input files; shared workspace/launch/env/limits; shuffled arms; discarded warmups; only current matched pairs. Paired median with seeded 10000 bootstrap resamples.',
        'before_after_changed': 'bootstrap creation and stdio descriptor handling; fresh probes, durability, watcher, observer, readback and settlement preserved',
        'baseline_shift': 'Current medians differ from previous pilots; old cohorts are not mixed into this comparison.',
        'remaining': ['native regression suites and strict clippy', 'final-source rebuild and matched rerun',
                      'clean VM/reference/freeze/CI proof if adopted', 'original workloads and agent/competitor rerun'],
        'artifact_proof': proof,
    }
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ['all_attempts_verified', 'after_mechanism_attempts_verified', 'profiles']}))


if __name__ == '__main__':
    main()
