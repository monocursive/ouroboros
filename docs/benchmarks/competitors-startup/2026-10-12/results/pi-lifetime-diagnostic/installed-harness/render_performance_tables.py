#!/usr/bin/env python3
import json,sys
from pathlib import Path
root=Path(sys.argv[1]);sel=json.loads((root/'analysis/final/selected-results.json').read_text());paired=json.loads((root/'analysis/paired/paired-startup.json').read_text())
lines=['# Paired Ouro measurements','','Each cell has 30 round pairs; milliseconds. Median percentage reductions and differences are computed within rounds. Intervals are descriptive bootstrap intervals, not a multiple-testing-adjusted guarantee.','','| Host | Work | Before median / p95 | After median / p95 | Paired reduction | Median change | 95% interval |','|---|---|---:|---:|---:|---:|---:|']
for r in paired['comparisons']:lines.append(f"| {r['host']} | {r['case']} | {r['old_median_ms']:.1f} / {r['old_p95_ms']:.1f} | {r['after_median_ms']:.1f} / {r['after_p95_ms']:.1f} | {r['paired_median_reduction_percent']:.1f}% | {r['paired_median_delta_ms']:.1f} | [{r['paired_delta_ci95_low_ms']:.1f}, {r['paired_delta_ci95_high_ms']:.1f}] |")
(root/'analysis/paired/paired-tables.md').write_text('\n'.join(lines)+'\n')
lines=['# Native launch plus work','','Median / p95 milliseconds. Container lifecycle timings live separately in performance.csv. Scored old/new Ouro has strict observation enabled. All detailed inputs, counts/checksums and sources are retained.']
lookup={(r['host'],r['tool'],r['case']):r for r in sel['performance'] if r['kind']=='native'}
for host in ['vps','pi','mac']:
 lines+=['','## '+host,'','| Work | Direct | MXC | Ouro before | Ouro final | Greywall |','|---|---:|---:|---:|---:|---:|']
 for case in ['noop','python','git','reads','writes','spawn','cpu']:
  vals=[]
  for tool in ['direct','mxc','ouro-before','ouro-jail','greywall']:
   r=lookup.get((host,tool,case));vals.append(f"{r['elapsed_ms']['median']:.1f} / {r['elapsed_ms']['p95_nearest_rank']:.1f}" if r else 'unavailable')
  lines.append('| '+case+' | '+' | '.join(vals)+' |')
(root/'analysis/final/native-performance.md').write_text('\n'.join(lines)+'\n')
