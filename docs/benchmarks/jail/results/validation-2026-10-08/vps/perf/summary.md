# `ouro-jail` performance (jail-v1 §5)

Collected 2026-10-08T07:32:57Z on `vps-450b3fe8` (Ubuntu 26.04.1 LTS, kernel 7.0.0-31-generic, 4 CPUs, 3814 MiB) as `ubuntu` (lingering: yes). Revision `f933105ebfcbdfee0133986e21cfe7423e7aeb75`. `ouro-jail` sha256 `73f3de8cdb17eb6b74996f6d7f4d8c43c893a423a6547cd3708abfd8b94b8395`; `ouro-fixture` sha256 `10d161af824e84513ea9455c581af2328af23f8e2fbd2d3c4eb3928ef65ae0bf`; bubblewrap 0.11.1.

Raw data: `launches.ndjson`, 630 records, sha256 `5e9097ac5bbf434fd1cb8a6fe6e0626629fa34f1864be9bae9d4ee6e2f53adde`; summarised 2026-10-08T07:36:27Z by xtask 0.1.0 at source revision `unknown`.

Parameters: 30 measured launch(es) per arm after 5 warm-up launch(es) per arm (90 warm-up records discarded); sessions ["plain","scope"]; profiles ["tool"]; workloads ["noop","spawn-tree","fileops"]; fileops 5000 rounds; spawn-tree 200 children; sampling every 5 ms; arm order seed 20261008.

Host quietness: threshold `--max-load 3`: a verdict needs every counted launch of both sides at or below it. Before the measured launches the 1-minute load average was 0.25 / 1.16 / 1.64 and `/proc/pressure/cpu` `some avg10` was 0.00 / 3.38 / 4.08 % (min / median / max); across them the host's CPU stall was 0.0 / 6.5 / 114.1 ms. The host has 4 CPUs. The 1-minute load includes the harness's own recent launches.

## Verdict roll-up

A budget holds for a profile only if every cell below passes. The overhead budget is read three ways, each its own verdict: **work phase** (the target's own entry to end; the integrator's current reading of §5), **post-start** (work + teardown: everything after entry, so startup + post-start cover the whole run), and **end-to-end wall** (startup included).

| Profile | Comparison | p95 added startup < 250 ms | Work phase < 20% | Post-start < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|
| tool | off vs direct | pass (6 of 6 cells pass, 0 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) |
| tool | on vs direct | pass (6 of 6 cells pass, 0 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) |

## `--observe off` against direct: the jail's own overhead (`tool`)

Under the decision of 2026-09-24 the §5 budgets apply to this comparison if observation misses them (next section); otherwise they apply to both. Each cell: median / p95 over the valid launches. `exec_unconfirmed` marks valid launches whose receipt outcome is `unknown` because, with observation off, the target ended before the supervisor confirmed its exec (the jail then exits 1); the target's own lines prove it ran, and the timing is the jail's real path.

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % | p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start (work + teardown) < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | tool | noop | tool/off / direct | 30 (0; flagged: exec_unconfirmed 30) | 30 (0) | 0.47 | 1.4 / 0.0 / 0.2 / 1.7 | 108.6 / 125.8 | 22.5 / 23.4 | 25.0 / 109.2 | 9159.5 / 9522.1 | 7902.0 / 8969.4 | pass (125.8 ms) | n/a | n/a | n/a |
| plain | tool | spawn-tree | tool/off / direct | 30 (0) | 30 (0) | 0.84 | 1.5 / 159.5 / 0.3 / 161.5 | 112.6 / 131.3 | 17.8 / 23.6 | 7.8 / 17.9 | 22.0 / 30.3 | 93.1 / 103.3 | pass (131.3 ms) | n/a | n/a | n/a |
| plain | tool | fileops | tool/off / direct | 30 (0) | 30 (0) | 1.31 | 1.5 / 182.7 / 0.3 / 184.6 | 113.7 / 123.6 | 20.2 / 24.1 | 25.0 / 36.0 | 34.9 / 46.6 | 99.9 / 109.5 | pass (123.6 ms) | fail (25.0%) | fail (34.9%) | fail (99.9%) |
| scope | tool | noop | tool/off / direct | 30 (0; flagged: exec_unconfirmed 30) | 30 (0) | 1.31 | 1.5 / 0.0 / 0.2 / 1.7 | 97.7 / 111.1 | 22.6 / 25.4 | 26.6 / 99.0 | 8368.3 / 9402.3 | 6877.4 / 7701.6 | pass (111.1 ms) | n/a | n/a | n/a |
| scope | tool | spawn-tree | tool/off / direct | 30 (0) | 30 (0) | 1.28 | 1.5 / 157.5 / 0.3 / 159.3 | 94.8 / 104.9 | 19.4 / 24.4 | 10.5 / 20.1 | 23.9 / 31.3 | 81.9 / 93.8 | pass (104.9 ms) | n/a | n/a | n/a |
| scope | tool | fileops | tool/off / direct | 30 (0) | 30 (0) | 1.64 | 1.6 / 184.9 / 0.4 / 186.9 | 100.6 / 114.9 | 19.9 / 24.3 | 25.8 / 44.5 | 37.9 / 54.6 | 92.1 / 115.2 | pass (114.9 ms) | fail (25.8%) | fail (37.9%) | fail (92.1%) |

## `--observe on` against direct: the budgets with observation (`tool`)

The §5 budgets as first written, observation included.

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % | p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start (work + teardown) < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | tool | noop | tool/on / direct | 30 (0) | 30 (0) | 0.47 | 1.4 / 0.0 / 0.2 / 1.7 | 115.8 / 129.8 | 5.2 / 16.1 | 41.6 / 119.0 | 2123.1 / 6552.2 | 7459.7 / 8250.8 | pass (129.8 ms) | n/a | n/a | n/a |
| plain | tool | spawn-tree | tool/on / direct | 30 (0) | 30 (0) | 0.84 | 1.5 / 159.5 / 0.3 / 161.5 | 120.0 / 135.4 | 5.9 / 15.4 | 52.7 / 76.0 | 56.5 / 79.5 | 129.9 / 153.5 | pass (135.4 ms) | n/a | n/a | n/a |
| plain | tool | fileops | tool/on / direct | 30 (0) | 30 (0) | 1.31 | 1.5 / 182.7 / 0.3 / 184.6 | 119.9 / 131.7 | 6.5 / 17.7 | 472.5 / 538.8 | 475.7 / 547.4 | 538.9 / 611.2 | pass (131.7 ms) | fail (472.5%) | fail (475.7%) | fail (538.9%) |
| scope | tool | noop | tool/on / direct | 30 (0) | 30 (0) | 1.31 | 1.5 / 0.0 / 0.2 / 1.7 | 101.8 / 114.1 | 4.9 / 15.7 | 37.6 / 80.0 | 1816.1 / 5809.5 | 6279.2 / 7277.8 | pass (114.1 ms) | n/a | n/a | n/a |
| scope | tool | spawn-tree | tool/on / direct | 30 (0) | 30 (0) | 1.28 | 1.5 / 157.5 / 0.3 / 159.3 | 102.1 / 112.6 | 5.6 / 15.2 | 55.6 / 71.3 | 60.5 / 75.3 | 123.7 / 143.1 | pass (112.6 ms) | n/a | n/a | n/a |
| scope | tool | fileops | tool/on / direct | 30 (0) | 30 (0) | 1.64 | 1.6 / 184.9 / 0.4 / 186.9 | 102.2 / 123.4 | 7.2 / 16.8 | 503.6 / 534.3 | 505.8 / 538.8 | 560.6 / 592.3 | pass (123.4 ms) | fail (503.6%) | fail (505.8%) | fail (560.6%) |

## Observation cost: `--observe on` against `--observe off` (reported, no budget)

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | tool | noop | tool/on / tool/off | 30 (0) | 30 (0) | 0.47 | 110.0 / 0.0 / 22.7 / 132.4 | 7.3 / 21.2 | -17.3 / -6.4 | 13.3 / 75.3 | -76.0 / -28.2 | -5.5 / 4.4 |
| plain | tool | spawn-tree | tool/on / tool/off | 30 (0) | 30 (0) | 0.84 | 114.1 / 171.9 / 18.1 / 311.8 | 7.4 / 22.8 | -11.9 / -2.3 | 41.7 / 63.3 | 28.3 / 47.1 | 19.0 / 31.3 |
| plain | tool | fileops | tool/on / tool/off | 30 (0) | 30 (0) | 1.31 | 115.2 / 228.3 / 20.5 / 369.0 | 6.2 / 18.0 | -13.7 / -2.5 | 358.1 / 411.1 | 326.7 / 379.8 | 219.7 / 255.9 |
| scope | tool | noop | tool/on / tool/off | 30 (0) | 30 (0) | 1.31 | 99.2 / 0.0 / 22.8 / 122.0 | 4.1 / 16.3 | -17.7 / -6.9 | 8.7 / 42.2 | -77.4 / -30.2 | -8.6 / 5.7 |
| scope | tool | spawn-tree | tool/on / tool/off | 30 (0) | 30 (0) | 1.28 | 96.2 / 174.1 / 19.7 / 289.7 | 7.4 / 17.8 | -13.8 / -4.2 | 40.8 / 55.0 | 29.5 / 41.5 | 23.0 / 33.7 |
| scope | tool | fileops | tool/on / tool/off | 30 (0) | 30 (0) | 1.64 | 102.2 / 232.6 / 20.3 / 359.0 | 1.6 / 22.8 | -12.7 / -3.1 | 379.9 / 404.3 | 339.3 / 363.2 | 244.0 / 260.5 |

## Informational profiles

### `agent`, off vs direct

(no data)

### `agent`, on vs direct

(no data)

### `none`, off vs direct

(no data)

### `none`, on vs direct

(no data)

## Per arm

| Session | Workload | Arm | Valid | Excluded (reasons) | Flagged | Startup ms | Work ms | Teardown ms | Post-start ms | Wall ms |
|---|---|---|---|---|---|---|---|---|---|---|
| plain | noop | direct | 30/30 | 0 (none) | none | 1.4 / 1.7 | 0.0 / 0.0 | 0.2 / 0.3 | 0.2 / 0.3 | 1.7 / 2.0 |
| plain | noop | tool/off | 30/30 | 0 (none) | exec_unconfirmed 30 | 110.0 / 127.2 | 0.0 / 0.1 | 22.7 / 23.6 | 22.8 / 23.7 | 132.4 / 150.0 |
| plain | noop | tool/on | 30/30 | 0 (none) | none | 117.2 / 131.2 | 0.1 / 0.1 | 5.4 / 16.3 | 5.5 / 16.4 | 125.1 / 138.2 |
| plain | spawn-tree | direct | 30/30 | 0 (none) | none | 1.5 / 2.0 | 159.5 / 171.2 | 0.3 / 0.4 | 159.8 / 171.6 | 161.5 / 173.4 |
| plain | spawn-tree | tool/off | 30/30 | 0 (none) | none | 114.1 / 132.9 | 171.9 / 188.1 | 18.1 / 23.9 | 194.9 / 208.2 | 311.8 / 328.2 |
| plain | spawn-tree | tool/on | 30/30 | 0 (none) | none | 121.6 / 136.9 | 243.5 / 280.6 | 6.2 / 15.7 | 250.1 / 286.8 | 371.2 / 409.3 |
| plain | fileops | direct | 30/30 | 0 (none) | none | 1.5 / 1.9 | 182.7 / 210.8 | 0.3 / 0.4 | 183.0 / 211.2 | 184.6 / 212.6 |
| plain | fileops | tool/off | 30/30 | 0 (none) | none | 115.2 / 125.1 | 228.3 / 248.4 | 20.5 / 24.5 | 246.9 / 268.2 | 369.0 / 386.9 |
| plain | fileops | tool/on | 30/30 | 0 (none) | none | 121.4 / 133.3 | 1045.7 / 1166.8 | 6.8 / 18.0 | 1053.6 / 1184.8 | 1179.7 / 1313.2 |
| scope | noop | direct | 30/30 | 0 (none) | none | 1.5 / 1.9 | 0.0 / 0.1 | 0.2 / 0.3 | 0.3 / 0.3 | 1.7 / 2.1 |
| scope | noop | tool/off | 30/30 | 0 (none) | exec_unconfirmed 30 | 99.2 / 112.6 | 0.0 / 0.1 | 22.8 / 25.6 | 22.9 / 25.6 | 122.0 / 136.4 |
| scope | noop | tool/on | 30/30 | 0 (none) | none | 103.3 / 115.5 | 0.1 / 0.1 | 5.1 / 15.9 | 5.2 / 16.0 | 111.5 / 129.0 |
| scope | spawn-tree | direct | 30/30 | 0 (none) | none | 1.5 / 1.8 | 157.5 / 174.4 | 0.3 / 0.4 | 157.8 / 174.8 | 159.3 / 176.2 |
| scope | spawn-tree | tool/off | 30/30 | 0 (none) | none | 96.2 / 106.3 | 174.1 / 189.2 | 19.7 / 24.7 | 195.6 / 207.2 | 289.7 / 308.7 |
| scope | spawn-tree | tool/on | 30/30 | 0 (none) | none | 103.6 / 114.1 | 245.2 / 269.9 | 5.9 / 15.5 | 253.3 / 276.7 | 356.3 / 387.3 |
| scope | fileops | direct | 30/30 | 0 (none) | none | 1.6 / 2.2 | 184.9 / 211.7 | 0.4 / 0.5 | 185.3 / 212.2 | 186.9 / 214.3 |
| scope | fileops | tool/off | 30/30 | 0 (none) | none | 102.2 / 116.5 | 232.6 / 267.2 | 20.3 / 24.7 | 255.6 / 286.5 | 359.0 / 402.2 |
| scope | fileops | tool/on | 30/30 | 0 (none) | none | 103.8 / 124.9 | 1116.4 / 1173.1 | 7.5 / 17.2 | 1122.8 / 1183.9 | 1234.7 / 1293.9 |

### Peak memory (KiB, median / p95 / max over valid launches)

| Session | Workload | Arm | Launched HWM (sampled) | Reaped tree (`wait4`) | Leaf `memory.peak` (sampled) | Target |
|---|---|---|---|---|---|---|
| plain | noop | direct | n/a | 3984 / 4048 / 4156 | n/a | 3984 / 4048 / 4048 |
| plain | noop | tool/off | 8482 / 8632 / 8656 | 8424 / 8536 / 8568 | 1766 / 1992 / 1992 | 3984 / 4048 / 4048 |
| plain | noop | tool/on | 8592 / 8720 / 8740 | 8438 / 8588 / 8684 | 1764 / 1984 / 1988 | 4064 / 4112 / 4112 |
| plain | spawn-tree | direct | 4088 / 4216 / 4220 | 4048 / 4176 / 4176 | n/a | 4046 / 4176 / 4176 |
| plain | spawn-tree | tool/off | 8504 / 8636 / 8672 | 8428 / 8524 / 8548 | 3898 / 4396 / 4772 | 4048 / 4176 / 4176 |
| plain | spawn-tree | tool/on | 8622 / 8776 / 8828 | 8440 / 8588 / 8616 | 3316 / 3680 / 4028 | 4084 / 4176 / 4176 |
| plain | fileops | direct | 4024 / 4136 / 4152 | 3982 / 4048 / 4048 | n/a | 3980 / 4048 / 4048 |
| plain | fileops | tool/off | 8538 / 8684 / 8700 | 8424 / 8556 / 8568 | 2200 / 2456 / 2476 | 3984 / 4048 / 4052 |
| plain | fileops | tool/on | 8622 / 8756 / 8768 | 8456 / 8588 / 8688 | 1936 / 1988 / 1996 | 4048 / 4108 / 4112 |
| scope | noop | direct | n/a | 3984 / 4048 / 4160 | n/a | 3984 / 4048 / 4048 |
| scope | noop | tool/off | 8504 / 8656 / 8696 | 8390 / 8596 / 8600 | 1710 / 1984 / 1992 | 3984 / 4048 / 4048 |
| scope | noop | tool/on | 8616 / 8732 / 8736 | 8452 / 8616 / 8620 | 1768 / 1992 / 1992 | 4048 / 4112 / 4120 |
| scope | spawn-tree | direct | 4090 / 4212 / 4216 | 4048 / 4176 / 4176 | n/a | 4048 / 4176 / 4176 |
| scope | spawn-tree | tool/off | 8544 / 8668 / 8684 | 8434 / 8584 / 8592 | 3954 / 4396 / 5192 | 4048 / 4176 / 4180 |
| scope | spawn-tree | tool/on | 8604 / 8784 / 8820 | 8418 / 8564 / 8648 | 3400 / 3976 / 4200 | 4062 / 4176 / 4176 |
| scope | fileops | direct | 4024 / 4152 / 4156 | 3984 / 4104 / 4108 | n/a | 3984 / 4048 / 4108 |
| scope | fileops | tool/off | 8544 / 8640 / 8652 | 8432 / 8536 / 8600 | 2208 / 2464 / 2496 | 3978 / 4048 / 4112 |
| scope | fileops | tool/on | 8628 / 8752 / 8796 | 8448 / 8584 / 8596 | 1956 / 2216 / 2220 | 4058 / 4128 / 4140 |

### Events and losses

Event counts: the receipt's `coverage.<class>.observed_count` over valid launches, median (min–max). Losses: over every measured launch of the arm, valid or not; a count that differs from the workload's exact one excludes the launch (`count_mismatch`).

| Session | Workload | Arm | Excluded | exec | fs.write | fs.deny | net | proxy.net | Trace frames | Observer gaps (lost) | Coverage gaps (lost) | Receipt errors | Incomplete traces | Trace notes (all kinds) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | noop | tool/off | 0 | n/a | n/a | n/a | n/a | n/a | 3 | 0 (0) | 0 (0) | 30 | 0 | lifecycle 30 |
| plain | noop | tool/on | 0 | 2 | 0 | 0 | 0 | n/a | 7 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | spawn-tree | tool/off | 0 | n/a | n/a | n/a | n/a | n/a | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | spawn-tree | tool/on | 0 | 402 | 0 | 0 | 0 | n/a | 407 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | fileops | tool/off | 0 | n/a | n/a | n/a | n/a | n/a | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | fileops | tool/on | 0 | 2 | 15000 | 0 | 0 | n/a | 15007 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | noop | tool/off | 0 | n/a | n/a | n/a | n/a | n/a | 3 | 0 (0) | 0 (0) | 30 | 0 | lifecycle 30 |
| scope | noop | tool/on | 0 | 2 | 0 | 0 | 0 | n/a | 7 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | spawn-tree | tool/off | 0 | n/a | n/a | n/a | n/a | n/a | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | spawn-tree | tool/on | 0 | 402 | 0 | 0 | 0 | n/a | 407 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | fileops | tool/off | 0 | n/a | n/a | n/a | n/a | n/a | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | fileops | tool/on | 0 | 2 | 15000 | 0 | 0 | n/a | 15007 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |

## backend-evaluation.md §4, `tool`

Startup: p95 added against direct. Overheads: median against direct, work phase / post-start / end-to-end wall, each with its verdict. Peak RSS: supervisor sampled HWM median / p95 (KiB). Events: median trace frames. Losses: observer + coverage gaps, receipt errors, incomplete traces and excluded launches, over all launches.

plain session:

| Workload | Observe | Valid (excl.) | Startup p95 added | Work phase | Post-start | End-to-end wall | Peak RSS | Event count | Losses (gaps / errors / incomplete / excluded) |
|---|---|---|---|---|---|---|---|---|---|
| noop | off | 30 (0) | pass (125.8 ms) | 25.0% | 9159.5% | 7902.0% | 8482 / 8632 | 3 | 0 / 30 / 0 / 0 |
| noop | on | 30 (0) | pass (129.8 ms) | 41.6% | 2123.1% | 7459.7% | 8592 / 8720 | 7 | 0 / 0 / 0 / 0 |
| spawn-tree | off | 30 (0) | pass (131.3 ms) | 7.8% | 22.0% | 93.1% | 8504 / 8636 | 5 | 0 / 0 / 0 / 0 |
| spawn-tree | on | 30 (0) | pass (135.4 ms) | 52.7% | 56.5% | 129.9% | 8622 / 8776 | 407 | 0 / 0 / 0 / 0 |
| fileops | off | 30 (0) | pass (123.6 ms) | fail (25.0%) | fail (34.9%) | fail (99.9%) | 8538 / 8684 | 5 | 0 / 0 / 0 / 0 |
| fileops | on | 30 (0) | pass (131.7 ms) | fail (472.5%) | fail (475.7%) | fail (538.9%) | 8622 / 8756 | 15007 | 0 / 0 / 0 / 0 |

scope session:

| Workload | Observe | Valid (excl.) | Startup p95 added | Work phase | Post-start | End-to-end wall | Peak RSS | Event count | Losses (gaps / errors / incomplete / excluded) |
|---|---|---|---|---|---|---|---|---|---|
| noop | off | 30 (0) | pass (111.1 ms) | 26.6% | 8368.3% | 6877.4% | 8504 / 8656 | 3 | 0 / 30 / 0 / 0 |
| noop | on | 30 (0) | pass (114.1 ms) | 37.6% | 1816.1% | 6279.2% | 8616 / 8732 | 7 | 0 / 0 / 0 / 0 |
| spawn-tree | off | 30 (0) | pass (104.9 ms) | 10.5% | 23.9% | 81.9% | 8544 / 8668 | 5 | 0 / 0 / 0 / 0 |
| spawn-tree | on | 30 (0) | pass (112.6 ms) | 55.6% | 60.5% | 123.7% | 8604 / 8784 | 407 | 0 / 0 / 0 / 0 |
| fileops | off | 30 (0) | pass (114.9 ms) | fail (25.8%) | fail (37.9%) | fail (92.1%) | 8544 / 8640 | 5 | 0 / 0 / 0 / 0 |
| fileops | on | 30 (0) | pass (123.4 ms) | fail (503.6%) | fail (505.8%) | fail (560.6%) | 8628 / 8752 | 15007 | 0 / 0 / 0 / 0 |

## Definitions

- **Launcher.** `ouro-fixture perf-launch`, outside the jail, forks the arm's command: the workload itself (direct) or `ouro-jail run --profile P --observe on|off --workspace WS -- workload`. It reads `CLOCK_MONOTONIC` just before `fork` and again after `wait4` returns. While the command runs it samples the launched process's `VmHWM` and, for a jailed arm only, looks up the execution leaf from the receipt and reads its `memory.peak`, every sampling interval: a small asymmetric cost (`--sample-ms 0` is the control run).
- **Startup.** From that first reading to the target's own first reading at entry to its workload mode (after its exec, dynamic loading and argument parsing, the same for every arm). The target reports its time namespace and the launcher its own; a launch where they differ or are unknown is excluded. For a jailed arm startup includes the supervisor's own start, the scope step (plain session), the capability probes, preparation, bubblewrap, observer attachment and the exec.
- **Work.** The target's end reading minus its entry reading: the workload phase alone, where the observer's per-call cost falls.
- **Teardown.** The launcher's reading after `wait4` minus the target's end reading: the target's exit and, for a jailed arm, settlement, tree verification, the receipts, the trace flush and the leaf's removal.
- **Post-start.** Work + teardown: everything after the target's entry. Startup + post-start = wall, so the startup budget and a post-start budget together leave no jail time uncounted.
- **Wall.** The launcher's two readings: spawn to the jail's exit.
- **Added (ms).** A launch's startup (or teardown) minus the baseline arm's median, same session and workload. Warm: after the discarded warm-up launch of every arm.
- **Overhead (%).** A launch's work, post-start or wall time over the baseline arm's median, minus one. The median of these is the ratio of medians minus one.
- **Median / p95.** The middle value (mean of the two middle values for an even count); p95 by nearest rank, the ⌈0.95·n⌉-th smallest value (the 29th of 30).
- **Peak RSS.** Launched HWM: the launched process's own `VmHWM` (the supervisor for a jailed arm), last sample (a lower bound). Reaped tree: `wait4`'s `ru_maxrss`, the largest resident set of the launched process and anything it reaped. Leaf: the execution leaf's `memory.peak` (cgroup memory including page cache), last sample. Target: the target's own `ru_maxrss` at its end.
- **Validity.** A launch counts only if the launcher ran and exec'd, the target printed both lines and completed its workload, one clock and ordered readings, direct execution exited 0; and for a jailed arm: exactly one attempt, a settled final receipt of the arm's profile and observation mode, the session's scope state (`entered` from a plain session, `already_delegated` in a scope), outcome `exited 0` (or, with observation off, the recorded exec-confirmation limit with jail exit 1, flagged), no receipt error, tree death verified, no degraded class, no coverage or observer gap, with observation on an attached observer and every closed-set class active, every event count exactly the workload's (execs: 2 × (1 + children) in the `exec` class, one `proc.exec` and one `proc.exit` each; fileops: one `fs.create`, `fs.rename`, `fs.unlink` per round, their sum in `fs.write`; nothing in `fs.deny`, `net`, `limits`, `proxy.net`; the trace's audit frames equal to the receipt's closed-set counts; no audit frame with observation off), and a trace that is complete and ends on the final receipt's note (§13.3). Everything else is excluded, counted by reason, never averaged, and its attempt, stdout and stderr are kept under `kept/`.
- **Verdicts.** Against direct execution only. `insufficient`: fewer than 30 valid launches on either side, any excluded launch on either side (no verdict over survivors), or a raw-data problem. `loaded`: the host was not shown quiet (a counted launch of either side above `--max-load` or with no load recorded, or `--allow-loaded`). A roll-up passes only if every cell passes.
- **Arm order.** A seeded permutation per round (seed in the parameters); each launch records its predecessor.
- **CPU share.** Not equalised: a direct target runs in the harness's own cgroup, a jailed one in its execution leaf, and their CPU weights differ only under contention, which the quiet-host condition rules out for a verdict. The direct target's cgroup is recorded per launch.
- **Sessions.** The plain and scope passes run one after the other, so a difference between them is confounded by time; each pass's load is in `passes.ndjson`.
