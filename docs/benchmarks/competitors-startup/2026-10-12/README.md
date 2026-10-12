# Remaining startup overhead and Pi writes

The final patch reduces Linux startup while retaining fresh capability checks, strict observation and empty-tree settlement. The source baseline is ac1263a; it already contains the earlier file-denial fix. The original and first-after datasets remain unchanged.

## Matched startup comparison

No-op wall medians, milliseconds; 30 valid samples per arm on each host. Paired reductions use the median of within-round ratios, which differs from the ratio of column medians.

| Host | Before | After | Paired reduction | Paired change 95% interval | MXC | Greywall |
|---|---:|---:|---:|---:|---:|---:|
| VPS | 114.4 | 94.2 | 20.4% | [-29.7, -19.8] ms | 20.0 | 1609.2 |
| PI | 283.4 | 229.7 | 19.7% | [-65.0, -45.3] ms | 23.6 | 1792.7 |

On vps, the remaining median gap to MXC is 74.2 ms (4.7x its elapsed time), versus 94.3 ms before. Greywall takes 17.1x Ouro's elapsed time in this lane.
On pi, the remaining median gap to MXC is 206.1 ms (9.7x its elapsed time), versus 259.8 ms before. Greywall takes 7.8x Ouro's elapsed time in this lane.

[Matched workloads, medians, tails and intervals](analysis/paired/paired-startup.csv), [all native/container performance cells](analysis/final/performance.csv). Bootstrap intervals use 10,000 round-pair resamples and seed 20261011; they are descriptive, with no multiple-test correction.

All 810 scored Ouro samples retain enforced containment, strict observation, attached ptrace/linux-closed-v1, unchanged declared coverage, no gaps and empty-tree settlement. Each of the 120 write samples retains all 1,000 successful mutation-capable open results in its journal, matching the fs.write coverage class (fs.create for O_CREAT). This set observes mutation-capable opens; it does not claim every write(2), payload bytes or storage durability. Fresh doctor status/reason/mechanism rows and syscall results match.

There are 780 samples in 13 matched workload comparisons, with matching policy digests and declared coverage. Pi Ouro Git timing is unavailable after a preflight state_write_failed/persistence-budget refusal; it has no invented score or paired interval. All other medians and tails are retained; no universal latency improvement is claimed.

The final Pi detached-child receipt verifies an empty tree but its heartbeat canary is inconclusive (no heartbeat was emitted); the command exits 1 with evidence_lost/entry_abandoned in fs.write and fs.deny. Its baseline arm exits 0 without a gap. The baseline heartbeat is witnessed/stopped; this final canary is not counted as a matching pass. Observation outcome differs and is retained. Separate unscored lifetime diagnostics after the benchmark run 30 pairs: both binaries have 30/30 witnessed/stopped heartbeats, empty trees, successful exits and no gaps. This does not prove equal failure rates or replace the original failure. [Diagnostic evidence](analysis/pi-lifetime-diagnostic.json); no timeout, observation requirement or scored outcome is relaxed.

## What changed

- Ordinary unprotected DT_REG entries avoid redundant metadata queries only in stable local ext-family/tmpfs directories. Recently changed directories, unknown filesystems and failed filesystem/clock readbacks keep the original stat path. Protected names, directories, symlinks and unknown types still receive no-follow stat; bounds, directory stamps, inode pins and mount-handoff checks remain. Eligible stable-directory profiles remove roughly 2,000 metadata queries from the standard fixture; recent-directory profiles may retain them.
- Namespace, read-only-bind and baseline-filter checks share one fresh successful sandbox. Every independent validator must succeed; unsuccessful combinations fall back to the prior unfiltered/individual paths. There is no persistent capability cache. A failed combination costs an additional attempt before the original independent fallback checks.
- Boundary fields are read from one blocked-launcher /proc/status snapshot. Missing CapEff explicitly refuses. Observer shutdown wakes on events/channel closure, still draining and joining for the final account.
- The v5 hint shortcut was guarded against coalesced recent directory timestamps; all unguarded Ouro data is retained in [candidate v5](candidates/v5/README.md). Unchanged competitor calls are reused with their original hashes; every Ouro client task/workflow and the full timing matrix are rerun.
- The v4 read-only failure fallback was withdrawn to preserve independent namespace capability results when bind setup emits no output. A new regression covers this case; all v4 native results are excluded and retained in [candidate v4](candidates/v4/README.md). The unchanged container controls are reused with their original hashes.
- A candidate cached backend-version optimization was withdrawn to retain fresh receipt readback in long-lived processes. Its complete/partial measurements and interruption records remain in [candidate evidence](candidates/v3/README.md), excluded from final comparisons.

## Pi writes

The direct control spends about 805 ms closing just-truncated files, versus about 2 ms when overwriting without truncation or creating fresh files. Writes themselves take about 13 ms. The SD/ext4 close hotspot also appears without Ouro; it is not established as an Ouro-specific regression.

[Pi investigation](PI-WRITES.md) separates observed facts from the inferred ext4 allocation/writeback explanation. The diagnostic variants change semantics and are excluded. Original O_TRUNC work, storage, governor, mount options, durability requirements and observation policy stay unchanged.

| Host | Write before median | After median | Paired change 95% interval |
|---|---:|---:|---:|
| VPS | 294.9 ms | 270.4 ms | [-31.3, -17.1] ms |
| PI | 672.3 ms | 501.2 ms | [-593.5, 27.0] ms |

The first v5 Pi timing cohort recorded a baseline CPU preflight persistence-budget failure. An operator pause could then contaminate an in-flight timing; the whole cohort, including 123 measured rows, is retained as excluded. The complete timing protocol was restarted with unchanged settings. [Interruption and raw failure](results/pi/native-control-export/perf-after-operator-excluded/EXCLUDED.json) remain explicit; no failed model call is selectively retried.

## Coding and container rerun

Final selection combines newly rerun v6 Ouro data and interleaved timings, unchanged complete v5 native competitor/direct calls, v4 container controls, and the complete Mac controls. The frozen protocol retains 198 native small-task calls, 144 container small-task calls and 57 inventory workflows. There are 4590 valid timing samples in 153 cells. Failed attempts remain in the raw data. Models, client/product versions, prompts, task checks, limits and schedules are unchanged.

| Native product | Linux small tasks | Linux workflows | Mac small tasks | Mac workflows |
|---|---:|---:|---:|---:|
| ouro | 36/36 | 6/6 | unavailable | unavailable |
| mxc | 36/36 | 5/6 | 12/18 | 2/3 |
| greywall | 36/36 | 6/6 | 0/18 | 0/3 |
| direct | 36/36 | 6/6 | 18/18 | 3/3 |

[Native coding calls](analysis/final/native-agents.csv), [container coding calls](analysis/final/container-agents.csv), [all workflows](analysis/final/workflows.csv), [before/after coding observation](analysis/final/coding-observation-before-after.json). Model/provider elapsed times and individual coding failures are compatibility evidence, not clean sandbox CPU measurements.

One retained OpenShell/Codex Mac call failed because the selected model was at capacity; it was neither retried nor switched to another model. Mac container small tasks pass 53/54 and workflows 9/9. Greywall Mac Seatbelt and MXC Mac Codex CFPreferences failures remain visible.

Fresh/retained containers are separate lifecycle classes with matched Docker controls. OpenShell images are reused exactly on Mac/Pi; deleted VPS client images are reconstructed in owned new tags with unchanged client bytes and recipe, and removed only after their evidence is retained. Full IDs, build logs, policies and inputs are saved.

## Where Ouro leads and trails

- Ouro launches substantially faster than Greywall in the measured Linux wrapper lane. Strict receipts and journals expose policy, executable identity, containment, coverage/loss and process-tree settlement. Tested memory limits refuse on the Pi when enforcement is unavailable; normal containment/observer settings remain intact.
- MXC still has lower native startup cost. These interfaces do not deliver identical evidence surfaces, so the latency result is not a claim of equal audit behavior. Other optional competitor audit backends were not measured.
- OpenShell offers working retained containers and online Mac execution. Ouro has no native Mac agent lane in this comparison; its offline Mac VM preview is a separate diagnostic. OpenShell startup fails on the Pi, while native Ouro runs there. Fresh container creation and retained exec are not mixed into wrapper rankings.
- Linux agent compatibility is largely shared with the working competitors. Provider capacity and turn-limit outcomes do not establish that a jail improves model intelligence. Ouro vault/provider brokerage and competitor privileged audit options remain untested.
- Tested file-denial and network/resource behavior is retained. Greywall rule-precedence follow-ups include the alternative working minimal rules; visible-socket IPC policy differences are not described as sandbox escapes.

## Validation and reuse

Rust 1.98.1 release builds use opt-level 3. Clippy and 567 Linux unit tests per host pass. The VPS passes all 206 exercised observer/isolation integration tests and both new mechanism regressions. On the Pi, broader suites retain confirmed baseline host/architecture, slow-consumer and queue-pressure failures; no assertion, queue limit or host restriction was relaxed. These are not a fresh pinned reference-host job or release freeze.

[Evidence verification](analysis/final/evidence-verification.json), [protocol](METHODS.md), [final source patch](source.patch), [source hashes](source-files.json), [binary hashes](analysis/binaries.json), [full raw artifacts](results/), [archives](archives/), and SHA256SUMS bind the saved results. Credentials, private proxy stores, agent homes and CA private keys are excluded/redacted; exact-value and pattern audits precede packaging. Every referenced final Ouro journal is retained and verified.

The changes and artifacts are uncommitted in the working tree. No release or deployment is claimed.
