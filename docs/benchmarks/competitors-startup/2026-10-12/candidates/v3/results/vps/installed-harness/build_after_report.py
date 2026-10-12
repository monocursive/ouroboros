#!/usr/bin/env python3
"""Derive before/after tables from fixed selections, keeping all failures."""
import csv
import json
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
before_root = root.parents[1] / 'competitors'
before = json.loads((before_root / 'results/2026-10-11/analysis/selected-results.json').read_text())
after = json.loads((root / 'analysis/final/selected-results.json').read_text())
counts = json.loads((root / 'analysis/final/counts.json').read_text())
proof = json.loads((root / 'analysis/final/evidence-verification.json').read_text())
out = root / 'analysis/comparison'
out.mkdir(parents=True, exist_ok=True)
def table(headers, rows):
    return '\n'.join(['| ' + ' | '.join(headers) + ' |', '|' + '|'.join(['---'] * len(headers)) + '|'] +
                     ['| ' + ' | '.join(map(str, row)) + ' |' for row in rows])
def write_csv(name, rows):
    with (out / name).open('w', newline='') as f:
        writer = csv.DictWriter(f, list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
def kind(row):
    return row.get('kind', row.get('class'))
comparisons = {}
for category in ['native_agents', 'container_agents', 'workflows', 'performance']:
    def key(row):
        if category == 'performance':
            return row['host'], kind(row), row['tool'], row['case']
        if category == 'workflows':
            return row['host'], kind(row), row['agent'], row['mode']
        return row['host'], row['agent'], row['mode']
    old = {key(row): row for row in before[category]}
    rows = []
    for row in after[category]:
        if row.get('tool') == 'ouro-before':
            continue
        previous = old[key(row)]
        value = {'host': row['host']}
        if category == 'performance':
            value |= {'kind': kind(row), 'tool': row['tool'], 'case': row['case'],
                      'historical_before_median_ms': previous['elapsed_ms']['median'],
                      'historical_before_p95_ms': previous['elapsed_ms']['p95_nearest_rank'],
                      'after_median_ms': row['elapsed_ms']['median'],
                      'after_p95_ms': row['elapsed_ms']['p95_nearest_rank'],
                      'before_valid': previous['valid'], 'after_valid': row['valid']}
        elif category == 'workflows':
            value |= {'kind': kind(row), 'agent': row['agent'], 'mode': row['mode'],
                      'before_success': previous['success'], 'after_success': row['success'],
                      'before_exit': previous['exit'], 'after_exit': row['exit'],
                      'before_ms': previous['elapsed_ms'], 'after_ms': row['elapsed_ms']}
        else:
            value |= {'agent': row['agent'], 'mode': row['mode'],
                      'before_attempted': previous['attempted'], 'before_passed': previous['passed'],
                      'after_attempted': row['attempted'], 'after_passed': row['passed'],
                      'before_median_success_ms': previous.get('median_success_ms'),
                      'after_median_success_ms': row.get('median_success_ms')}
        value |= {'before_source': previous['source'], 'after_source': row['source']}
        rows.append(value)
    comparisons[category] = rows
    write_csv(category.replace('_', '-') + '-before-after.csv', rows)
native = comparisons['native_agents']
containers = comparisons['container_agents']
small = []
for host in ['vps', 'pi', 'mac']:
    for agent in ['claude', 'opencode', 'codex']:
        cells = []
        for category, mode in [(native, 'direct'), (native, 'ouro'), (native, 'mxc'), (native, 'greywall'),
                               (containers, 'openshell-ephemeral'), (containers, 'openshell-warm')]:
            row = next((r for r in category if r['host'] == host and r['agent'] == agent and r['mode'] == mode), None)
            cells.append('unavailable' if row is None or not row['after_attempted'] else
                         f"{row['before_passed']}/{row['before_attempted']} -> {row['after_passed']}/{row['after_attempted']}")
        small.append([host + ' / ' + agent, *cells])
workflow = comparisons['workflows']
wf_table = table(['Host', 'Class', 'Client', 'Mode', 'Before pass / exit', 'After pass / exit'],
                 [[r['host'], r['kind'], r['agent'], r['mode'], f"{r['before_success']} / {r['before_exit']}",
                   f"{r['after_success']} / {r['after_exit']}"] for r in workflow])
(out / 'workflow-tables.md').write_text(wf_table + '\n')
perf_tables = []
for execution in ['native', 'container']:
    for host in ['vps', 'pi', 'mac']:
        rows = [r for r in comparisons['performance'] if r['host'] == host and r['kind'] == execution]
        perf_tables.append('## ' + host + ' / ' + execution + '\n\n' + table(
            ['Tool', 'Case', 'Historical before median / p95 (ms)', 'After median / p95 (ms)'],
            [[r['tool'], r['case'], f"{r['historical_before_median_ms']:.1f} / {r['historical_before_p95_ms']:.1f}",
              f"{r['after_median_ms']:.1f} / {r['after_p95_ms']:.1f}"] for r in rows]))
(out / 'performance-tables.md').write_text('\n\n'.join(perf_tables) + '\n')
paired = (root / 'analysis/paired/paired-tables.md').read_text().strip()
failures = [r for r in after['workflows'] if not r['success']]
(out / 'workflow-failures.json').write_text(json.dumps(failures, indent=2) + '\n')
noops = []
for host in ['vps', 'pi', 'mac']:
    cells = []
    for tool in ['direct', 'mxc', 'ouro-jail', 'greywall']:
        r = next((r for r in comparisons['performance'] if r['host'] == host and r['kind'] == 'native'
                  and r['tool'] == tool and r['case'] == 'noop'), None)
        cells.append('unavailable' if not r else f"{r['historical_before_median_ms']:.1f} -> {r['after_median_ms']:.1f}")
    noops.append([host, *cells])
report = f'''# Ouro file denial and startup: before/after benchmark

The regular-file denial bug is fixed on Linux x86_64 and ARM64. Startup work now
shares one fresh namespace probe sandbox per measurement call. The paired no-op
medians fell from 138.6 to 115.7ms on the VPS and 321.7 to 288.6ms on the Pi:
16.5% and 10.3% reductions in the ratio of medians. This keeps strict observation,
the original policies, containment, receipts, journals and empty-tree settlement.
Pi writes remain noisy with a worse after median; no improvement is claimed there.

The [original comparison](../../competitors/README.md), its selected results and
archive are unchanged. This rerun retains {counts['native_invocations']} native small-task invocations,
{counts['container_invocations']} container small-task invocations, {counts['workflow_invocations']} workflows and
{counts['valid_performance_samples']} valid scored timing samples across {counts['performance_buckets']} buckets.
The extra old-Ouro arm contributes 420 samples; it controls for host/time drift.
Setup pilots, excluded observation-off diagnostics and unavailable launches remain
in the [complete audit](analysis/all-datasets-audit.json). The unchanged Mac VM
preview contributes 12 additional diagnostic samples, separate from scored lanes.

## Implementation and file-denial proof

The old implementation mounted a directory tmpfs over every denied path. A
regular file inside a visible parent caused bubblewrap setup to fail, exit 125.
The patch classifies denial targets and overlays files with empty descriptor data,
mode 000 and a read-only bind, after every grant. Directory masks remain sealed
tmpfs mounts; ancestor denials subsume nested masks. No denied source contents
are read or altered. Missing descriptors and setup errors refuse execution.
The live regression checks read-only and writable parents, readable siblings,
direct and symlink reads, writes, truncation, chmod, unchanged original content,
the actual read-only mount receipt and an empty process tree.

Both hosts reproduce before exit 125 and after exit 0/FILE-DENIAL-PASS, with the
original canary unchanged. Raw probe evidence: [VPS](results/vps/file-denial/),
[Pi](results/pi/file-denial/). The VPS receipt records four denied write-open
events and no coverage gaps; this count does not imply coverage of every read or
chmod operation. The observer's declared closed set is unchanged.

User, PID and network namespace capability probes previously spawned separate
sandboxes to consume the same status report. They now share one fresh sandbox
inside a call while each validator retains its checks and timeout/error behavior.
There is no persistent capability cache. Boundary readbacks, observer attachment,
filter verification, mount pinning, cgroups, leases, journals and settlement remain.
[Source patch](source.patch) and [file hashes](source-files.json) bind this result
to the four uncommitted source files, based on c364e3cb3678eb9120901f71bf3881d85e3c4911.
The backend's descriptor mount mechanism is documented in
[bubblewrap's manual](https://github.com/containers/bubblewrap/blob/v0.11.0/bwrap.xml).

## Paired Ouro measurements

Each host/workload has 30 interleaved old/new pairs after three discarded warmups,
with the original operation counts, checksums, fixtures and seed. Policies match
by digest. All 840 old/new samples have strict observation on, enforced containment,
observed exec, attached ptrace/linux-closed-v1, unchanged coverage statuses, no
gaps and empty-tree settlement. Every writes sample observes all 1,000 writes.
The descriptive bootstrap interval resamples round-pair changes 10,000 times;
it is not a claim about every machine or a multiple-comparison-adjusted result.

{paired}

The median paired ratios give no-op reductions 10.9% VPS and 8.5% Pi; these differ
from the ratios of separate medians above. Pi writes: 672.0 -> 773.2ms median,
paired median change -3.2ms with interval [-38.0,305.8]. This is inconclusive.
Some Pi p95 values also worsen despite lower medians. No sample was rerun or
dropped to improve these results. [CSV](analysis/paired/paired-startup.csv),
[JSON and receipt validation](analysis/paired/paired-startup.json).

## Same competitor and coding lanes

Client versions, models, task prompts/checks, policy roles, deadlines and product
versions match the [original methods](../../competitors/METHODS.md). Models remain
Claude Sonnet 4.5 for Claude/OpenCode and gpt-6.1-sol with low reasoning for Codex.
The coding profiles use writable workspaces, private client state, read-only
installations and default-deny egress with required provider destinations.
No additional login was needed. Secrets stay on the hosts and are excluded or
redacted from public evidence. Competitor sources and host restrictions were
not changed. Exact host, executable and image provenance accompany each export.

Historical-before -> after native no-op median (ms), separate from the paired
source attribution above:

{table(['Host', 'Direct', 'MXC', 'Ouro observed', 'Greywall'], noops)}

Each small-task cell is three tasks twice, with fresh repositories/state and
independent checks. Agent elapsed times include provider/model latency, so they
measure compatibility rather than isolated sandbox startup. Native wrappers and
container lifecycles remain separate classes. Each Docker/OpenShell pair uses
the same image, clients, UID and recorder; new image tags retain the earlier
references. The recorder also captures CSV source files omitted by an earlier
artifact recorder, without changing prompts or checks.

{table(['Host / client', 'Direct', 'Ouro', 'MXC', 'Greywall', 'OpenShell fresh', 'OpenShell warm'], small)}

All Ouro small-task and workflow invocations on Linux pass their supplied and
hidden checks with strict observation and no declared coverage-class gaps. Fourteen
Claude receipts retain pre-existing audit-only path_claim_unverified diagnostics
(classes=[]); before receipts have the same diagnostic type. Counts vary with
the model's commands. These receipts are not described as wholly gap-free.
OpenCode/Codex have no observer diagnostics. The detailed comparison is in
[coding observation before/after](analysis/final/coding-observation-before-after.json).
Mac native Ouro remains unavailable;
the unchanged offline VM preview is not evidence for this Linux patch. Greywall
Mac syntax refusal and MXC Mac Codex CFPreferences failure remain visible. Pi
OpenShell startup availability is tested afresh and reported separately; a failed
startup never becomes a successful timing. Docker is its positive control.

Workflows preserve the 15-turn Claude limit and require exit 0 even if a patch
passes tests. All failures are in [workflow-failures.json](analysis/comparison/workflow-failures.json)
and the [full before/after workflow table](analysis/comparison/workflow-tables.md).
All seven workloads for every available product/class are in the
[performance tables](analysis/comparison/performance-tables.md),
[before/after CSVs](analysis/comparison/) and [selected raw-source index](analysis/final/selected-results.json).
The original [full feature matrix](../../competitors/feature-matrix.md) is retained;
its file-denial failure is superseded by this patch and the [feature follow-up](feature-matrix.md).

## Validation and limits

Rust 1.98.1 release builds and Linux Clippy pass on both architectures. Each Linux
unit suite passes 564 tests with 2 ignored. All 46 VPS review_linux tests pass;
the new live file regression passes on both hosts. Local portable units pass 267
with 1 ignored, and local Clippy passes. Actual before/after doctor capability
statuses match on both Linux hosts. The full VPS Linux test run retains these
environment/provenance failures: two pinned AppArmor/host status assertions;
the nested-user-namespace expectation for the pinned host; and two stale saved
preview-evidence checks. The earlier unscoped cgroup assertion also fails with
the old binary and passes in the repository-standard systemd user scope. No
assertion, freeze record or restriction was relaxed to hide a failure.

These are provisioned benchmark machines, as documented originally. The VPS's
AppArmor namespace override and byte-identical bubblewrap copy predate this
follow-up. The Pi still lacks memory-controller/Landlock availability and uses
the previously provisioned exact-kernel Unix diagnostics module. Native agent
passes are not a security certification, full pinned-host conformance or release
readiness. Fresh release freeze/provenance evidence has not been issued.

The Mac duplicate-provider import failed before any task. Linux pilot client
symlinks traversed an ungranted intermediate benchmark directory and produced
ENOENT. Direct-to-install links restore the original layout without changing
bytes or widening grants. All modes/tasks/repetitions for affected clients were
rerun in new directories; individual valid failures were not retried. Exact
selections and hashes are recorded, and every pilot remains. A missing Mac
extra-probe script and a missing VPS gateway link failed before execution; the
unchanged script/binary were linked or copied before continuing. Pi warm
availability pilot names exceeded the 19-character limit; corrected checks use
short names after the measured phase. The VPS Codex image hit ENOSPC before
any task: omitting a redundant chmod copy-up layer preserves verified input
permissions and bytes while avoiding duplication. Failed builder artifacts remain.

Export manifests verify {sum(v['manifest_files'] for v in proof['hosts'].values())} files and retain
{sum(v['exported_journals'] for v in proof['hosts'].values())} referenced Ouro journals, with none missing.
All 42 selected native Ouro coding/workflow receipts have been checked. Own
completed build caches were removed only after binary equality checks, with
cleanup manifests. The VPS completed source checkout was backed up locally and
all 7,893 files verified before reclaiming it during the remaining agent phase.
The VPS follow-up proxy store was compressed and hash-verified
before removing its plaintext copy; the credential-bearing archive stays private
on that host. Temporary gateways/proxies are stopped. Evidence is sanitized;
credentials, private homes/state, proxy databases and CA private keys are excluded.
The original private stores and logins remain on the hosts for reuse.

## Reuse

Use [METHODS.md](METHODS.md) and [harness](harness/) to rerun the same protocol.
[Exact tested executables](binaries/README.md) retain old and patched Ouro for
both Linux architectures, with hashes matched to the doctor reports.
[Host export archives](archives/) preserve raw results, source snapshots, logs,
patches, receipts, journal coverage and executable/image hashes. [Final bundle](benchmark-after-2026-10-11.tar.gz) and
[SHA256SUMS](SHA256SUMS) cover this whole follow-up. Pair it with the unchanged original
benchmark archive for historical before results. No commit or push was made.
'''
(root / 'README.md').write_text(report)
print(json.dumps({'comparison_tables': len(comparisons), 'workflow_failures': len(failures), 'report': str(root / 'README.md')}))
