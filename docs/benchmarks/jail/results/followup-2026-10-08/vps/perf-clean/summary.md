# `ouro-jail` performance (jail-v1 §5)

Collected 2026-10-08T10:34:19Z on `vps-450b3fe8` (Ubuntu 26.04.1 LTS, kernel 7.0.0-31-generic, 4 CPUs, 3814 MiB) as `ubuntu` (lingering: yes). Revision `d972bb0dfbd52255d8577caac620e56a485f250a`. `ouro-jail` sha256 `fc2a54da0d08f47ea589a179484ae56995c20dcf9ce7dfa3228244d4529bd2a3`; `ouro-fixture` sha256 `243e6719e5f2e31e380988ddea6d697aec145ab3b1f5e50e769e92799b2b9be8`; bubblewrap 0.11.1.

Raw data: `launches.ndjson`, 630 records, sha256 `452a1d6a0331fc376ff0fca03d44b4ac97b82f0c77d7a8ded573227d73ee93d8`; summarised 2026-10-08T10:37:33Z by xtask 0.1.0 at source revision `unknown`.

Parameters: 30 measured launch(es) per arm after 5 warm-up launch(es) per arm (90 warm-up records discarded); sessions ["plain","scope"]; profiles ["tool"]; workloads ["noop","spawn-tree","fileops"]; fileops 5000 rounds; spawn-tree 200 children; sampling every 5 ms; arm order seed 20261008.

Host quietness: threshold `--max-load 3`: a verdict needs every counted launch of both sides at or below it. Before the measured launches the 1-minute load average was 1.46 / 1.83 / 2.14 and `/proc/pressure/cpu` `some avg10` was 3.11 / 3.69 / 3.97 % (min / median / max); across them the host's CPU stall was 0.0 / 6.6 / 70.6 ms. The host has 4 CPUs. The 1-minute load includes the harness's own recent launches.

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
| plain | tool | noop | tool/off / direct | 30 (0; flagged: exec_unconfirmed 30) | 30 (0) | 1.59 | 1.4 / 0.0 / 0.2 / 1.7 | 112.0 / 126.7 | 22.6 / 23.4 | 35.5 / 105.4 | 9243.0 / 9565.6 | 8116.7 / 8988.3 | pass (126.7 ms) | n/a | n/a | n/a |
| plain | tool | spawn-tree | tool/off / direct | 30 (0) | 30 (0) | 1.91 | 1.4 / 155.2 / 0.3 / 156.8 | 107.8 / 121.7 | 20.0 / 22.3 | 6.8 / 13.2 | 19.4 / 26.6 | 89.0 / 102.3 | pass (121.7 ms) | n/a | n/a | n/a |
| plain | tool | fileops | tool/off / direct | 30 (0) | 30 (0) | 1.88 | 1.4 / 175.3 / 0.3 / 177.2 | 105.1 / 113.0 | 18.7 / 23.7 | 25.3 / 32.6 | 34.1 / 45.9 | 94.8 / 108.4 | pass (113.0 ms) | fail (25.3%) | fail (34.1%) | fail (94.8%) |
| scope | tool | noop | tool/off / direct | 30 (0; flagged: exec_unconfirmed 30) | 30 (0) | 2.07 | 1.4 / 0.0 / 0.2 / 1.7 | 97.5 / 119.2 | 22.5 / 24.4 | 26.2 / 90.7 | 8590.1 / 9320.0 | 7088.7 / 8534.1 | pass (119.2 ms) | n/a | n/a | n/a |
| scope | tool | spawn-tree | tool/off / direct | 30 (0) | 30 (0) | 2.14 | 1.4 / 148.2 / 0.3 / 149.9 | 90.8 / 102.9 | 20.1 / 23.6 | 9.3 / 16.2 | 24.6 / 31.9 | 82.3 / 97.8 | pass (102.9 ms) | n/a | n/a | n/a |
| scope | tool | fileops | tool/off / direct | 30 (0) | 30 (0) | 1.96 | 1.4 / 172.4 / 0.3 / 174.3 | 94.3 / 106.7 | 21.5 / 25.1 | 28.1 / 46.9 | 42.1 / 60.0 | 92.5 / 117.3 | pass (106.7 ms) | fail (28.1%) | fail (42.1%) | fail (92.5%) |

## `--observe on` against direct: the budgets with observation (`tool`)

The §5 budgets as first written, observation included.

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % | p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start (work + teardown) < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | tool | noop | tool/on / direct | 30 (0) | 30 (0) | 1.59 | 1.4 / 0.0 / 0.2 / 1.7 | 114.5 / 128.6 | 5.5 / 16.3 | 57.6 / 495.5 | 2277.0 / 6656.6 | 7399.6 / 8389.7 | pass (128.6 ms) | n/a | n/a | n/a |
| plain | tool | spawn-tree | tool/on / direct | 30 (0) | 30 (0) | 1.91 | 1.4 / 155.2 / 0.3 / 156.8 | 113.8 / 121.5 | 5.8 / 15.8 | 55.6 / 67.0 | 60.7 / 74.2 | 132.7 / 147.3 | pass (121.5 ms) | n/a | n/a | n/a |
| plain | tool | fileops | tool/on / direct | 30 (0) | 30 (0) | 1.88 | 1.4 / 175.3 / 0.3 / 177.2 | 110.6 / 123.6 | 6.7 / 16.1 | 425.6 / 469.4 | 428.0 / 471.7 | 487.7 / 532.0 | pass (123.6 ms) | fail (425.6%) | fail (428.0%) | fail (487.7%) |
| scope | tool | noop | tool/on / direct | 30 (0) | 30 (0) | 2.07 | 1.4 / 0.0 / 0.2 / 1.7 | 98.5 / 119.0 | 5.6 / 16.1 | 47.4 / 921.3 | 2184.2 / 6138.1 | 6318.7 / 7493.9 | pass (119.0 ms) | n/a | n/a | n/a |
| scope | tool | spawn-tree | tool/on / direct | 30 (0) | 30 (0) | 2.14 | 1.4 / 148.2 / 0.3 / 149.9 | 95.9 / 104.9 | 5.6 / 15.1 | 55.0 / 64.9 | 58.9 / 69.1 | 123.7 / 136.3 | pass (104.9 ms) | n/a | n/a | n/a |
| scope | tool | fileops | tool/on / direct | 30 (0) | 30 (0) | 1.96 | 1.4 / 172.4 / 0.3 / 174.3 | 96.4 / 111.5 | 6.3 / 16.7 | 443.7 / 483.9 | 447.8 / 492.5 | 498.4 / 543.5 | pass (111.5 ms) | fail (443.7%) | fail (447.8%) | fail (498.4%) |

## Observation cost: `--observe on` against `--observe off` (reported, no budget)

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | tool | noop | tool/on / tool/off | 30 (0) | 30 (0) | 1.59 | 113.4 / 0.0 / 22.8 / 136.5 | 2.5 / 16.6 | -17.1 / -6.4 | 16.3 / 339.6 | -74.6 / -27.7 | -8.7 / 3.3 |
| plain | tool | spawn-tree | tool/on / tool/off | 30 (0) | 30 (0) | 1.91 | 109.2 / 165.7 / 20.3 / 296.3 | 6.0 / 13.6 | -14.2 / -4.2 | 45.7 / 56.4 | 34.6 / 45.9 | 23.1 / 30.9 |
| plain | tool | fileops | tool/on / tool/off | 30 (0) | 30 (0) | 1.88 | 106.5 / 219.6 / 19.0 / 345.2 | 5.5 / 18.5 | -12.0 / -2.6 | 319.6 / 354.6 | 293.6 / 326.2 | 201.7 / 224.4 |
| scope | tool | noop | tool/on / tool/off | 30 (0) | 30 (0) | 2.07 | 99.0 / 0.0 / 22.7 / 121.5 | 1.0 / 21.5 | -16.9 / -6.4 | 16.8 / 709.5 | -73.7 / -28.2 | -10.7 / 5.6 |
| scope | tool | spawn-tree | tool/on / tool/off | 30 (0) | 30 (0) | 2.14 | 92.2 / 162.0 / 20.3 / 273.2 | 5.0 / 14.0 | -14.4 / -5.0 | 41.8 / 50.8 | 27.5 / 35.7 | 22.7 / 29.6 |
| scope | tool | fileops | tool/on / tool/off | 30 (0) | 30 (0) | 1.96 | 95.8 / 220.8 / 21.9 / 335.5 | 2.0 / 17.2 | -15.2 / -4.9 | 324.5 / 355.9 | 285.5 / 317.0 | 210.9 / 234.4 |

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
| plain | noop | direct | 30/30 | 0 (none) | none | 1.4 / 1.9 | 0.0 / 0.1 | 0.2 / 0.3 | 0.2 / 0.4 | 1.7 / 2.2 |
| plain | noop | tool/off | 30/30 | 0 (none) | exec_unconfirmed 30 | 113.4 / 128.1 | 0.0 / 0.1 | 22.8 / 23.6 | 22.9 / 23.7 | 136.5 / 150.9 |
| plain | noop | tool/on | 30/30 | 0 (none) | none | 115.9 / 130.0 | 0.1 / 0.2 | 5.7 / 16.5 | 5.8 / 16.5 | 124.6 / 141.0 |
| plain | spawn-tree | direct | 30/30 | 0 (none) | none | 1.4 / 1.7 | 155.2 / 168.7 | 0.3 / 0.4 | 155.5 / 169.0 | 156.8 / 170.5 |
| plain | spawn-tree | tool/off | 30/30 | 0 (none) | none | 109.2 / 123.0 | 165.7 / 175.6 | 20.3 / 22.6 | 185.6 / 196.8 | 296.3 / 317.2 |
| plain | spawn-tree | tool/on | 30/30 | 0 (none) | none | 115.2 / 122.8 | 241.4 / 259.2 | 6.1 / 16.1 | 249.8 / 270.8 | 364.9 / 387.8 |
| plain | fileops | direct | 30/30 | 0 (none) | none | 1.4 / 1.8 | 175.3 / 187.4 | 0.3 / 0.4 | 175.6 / 187.7 | 177.2 / 189.1 |
| plain | fileops | tool/off | 30/30 | 0 (none) | none | 106.5 / 114.4 | 219.6 / 232.5 | 19.0 / 24.0 | 235.6 / 256.3 | 345.2 / 369.2 |
| plain | fileops | tool/on | 30/30 | 0 (none) | none | 111.9 / 125.0 | 921.3 / 998.1 | 7.0 / 16.4 | 927.3 / 1004.1 | 1041.4 / 1119.9 |
| scope | noop | direct | 30/30 | 0 (none) | none | 1.4 / 2.0 | 0.0 / 0.1 | 0.2 / 0.3 | 0.3 / 0.4 | 1.7 / 3.0 |
| scope | noop | tool/off | 30/30 | 0 (none) | exec_unconfirmed 30 | 99.0 / 120.6 | 0.0 / 0.1 | 22.7 / 24.6 | 22.8 / 24.7 | 121.5 / 146.0 |
| scope | noop | tool/on | 30/30 | 0 (none) | none | 100.0 / 120.4 | 0.1 / 0.4 | 5.8 / 16.3 | 6.0 / 16.4 | 108.5 / 128.4 |
| scope | spawn-tree | direct | 30/30 | 0 (none) | none | 1.4 / 1.6 | 148.2 / 158.2 | 0.3 / 0.3 | 148.5 / 158.5 | 149.9 / 160.1 |
| scope | spawn-tree | tool/off | 30/30 | 0 (none) | none | 92.2 / 104.3 | 162.0 / 172.3 | 20.3 / 23.9 | 185.0 / 195.8 | 273.2 / 296.4 |
| scope | spawn-tree | tool/on | 30/30 | 0 (none) | none | 97.2 / 106.2 | 229.7 / 244.4 | 5.9 / 15.3 | 235.9 / 251.1 | 335.3 / 354.1 |
| scope | fileops | direct | 30/30 | 0 (none) | none | 1.4 / 1.6 | 172.4 / 193.7 | 0.3 / 0.4 | 172.7 / 194.2 | 174.3 / 195.5 |
| scope | fileops | tool/off | 30/30 | 0 (none) | none | 95.8 / 108.1 | 220.8 / 253.3 | 21.9 / 25.4 | 245.4 / 276.3 | 335.5 / 378.9 |
| scope | fileops | tool/on | 30/30 | 0 (none) | none | 97.8 / 112.9 | 937.4 / 1006.8 | 6.7 / 17.0 | 946.2 / 1023.5 | 1043.2 / 1121.7 |

### Peak memory (KiB, median / p95 / max over valid launches)

| Session | Workload | Arm | Launched HWM (sampled) | Reaped tree (`wait4`) | Leaf `memory.peak` (sampled) | Target |
|---|---|---|---|---|---|---|
| plain | noop | direct | n/a | 3984 / 4112 / 4112 | n/a | 3984 / 4048 / 4112 |
| plain | noop | tool/off | 8440 / 8568 / 8580 | 8370 / 8532 / 8544 | 1764 / 2016 / 2016 | 3984 / 4048 / 4112 |
| plain | noop | tool/on | 8498 / 8596 / 8596 | 8308 / 8460 / 8468 | 1766 / 1984 / 2016 | 3984 / 4048 / 4048 |
| plain | spawn-tree | direct | 4090 / 4216 / 4220 | 4048 / 4176 / 4176 | n/a | 4048 / 4176 / 4176 |
| plain | spawn-tree | tool/off | 8414 / 8544 / 8548 | 8296 / 8432 / 8504 | 3910 / 4600 / 5044 | 4048 / 4156 / 4172 |
| plain | spawn-tree | tool/on | 8512 / 8632 / 8712 | 8256 / 8476 / 8528 | 3366 / 3916 / 4496 | 4048 / 4176 / 4176 |
| plain | fileops | direct | 4028 / 4156 / 4156 | 3984 / 4148 / 4176 | n/a | 3984 / 4048 / 4088 |
| plain | fileops | tool/off | 8414 / 8520 / 8524 | 8306 / 8412 / 8424 | 2204 / 2516 / 2524 | 3984 / 4048 / 4112 |
| plain | fileops | tool/on | 8524 / 8656 / 8732 | 8336 / 8472 / 8516 | 1956 / 2224 / 2224 | 3984 / 4048 / 4048 |
| scope | noop | direct | n/a | 3984 / 4048 / 4048 | n/a | 3984 / 4048 / 4048 |
| scope | noop | tool/off | 8396 / 8512 / 8564 | 8320 / 8480 / 8512 | 1848 / 1984 / 1984 | 3984 / 4048 / 4112 |
| scope | noop | tool/on | 8512 / 8632 / 8692 | 8312 / 8516 / 8528 | 1768 / 1988 / 2056 | 3984 / 4048 / 4048 |
| scope | spawn-tree | direct | 4090 / 4216 / 4220 | 4048 / 4176 / 4176 | n/a | 4048 / 4176 / 4176 |
| scope | spawn-tree | tool/off | 8440 / 8544 / 8560 | 8330 / 8516 / 8520 | 3980 / 4512 / 5044 | 4048 / 4176 / 4176 |
| scope | spawn-tree | tool/on | 8508 / 8640 / 8656 | 8304 / 8452 / 8480 | 3488 / 4004 / 4456 | 4048 / 4176 / 4176 |
| scope | fileops | direct | 4030 / 4152 / 4156 | 3990 / 4048 / 4112 | n/a | 3984 / 4048 / 4048 |
| scope | fileops | tool/off | 8432 / 8536 / 8540 | 8334 / 8496 / 8524 | 2212 / 2484 / 2484 | 3984 / 4048 / 4112 |
| scope | fileops | tool/on | 8492 / 8648 / 8716 | 8256 / 8444 / 8500 | 1844 / 1992 / 2052 | 3984 / 4048 / 4112 |

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
| noop | off | 30 (0) | pass (126.7 ms) | 35.5% | 9243.0% | 8116.7% | 8440 / 8568 | 3 | 0 / 30 / 0 / 0 |
| noop | on | 30 (0) | pass (128.6 ms) | 57.6% | 2277.0% | 7399.6% | 8498 / 8596 | 7 | 0 / 0 / 0 / 0 |
| spawn-tree | off | 30 (0) | pass (121.7 ms) | 6.8% | 19.4% | 89.0% | 8414 / 8544 | 5 | 0 / 0 / 0 / 0 |
| spawn-tree | on | 30 (0) | pass (121.5 ms) | 55.6% | 60.7% | 132.7% | 8512 / 8632 | 407 | 0 / 0 / 0 / 0 |
| fileops | off | 30 (0) | pass (113.0 ms) | fail (25.3%) | fail (34.1%) | fail (94.8%) | 8414 / 8520 | 5 | 0 / 0 / 0 / 0 |
| fileops | on | 30 (0) | pass (123.6 ms) | fail (425.6%) | fail (428.0%) | fail (487.7%) | 8524 / 8656 | 15007 | 0 / 0 / 0 / 0 |

scope session:

| Workload | Observe | Valid (excl.) | Startup p95 added | Work phase | Post-start | End-to-end wall | Peak RSS | Event count | Losses (gaps / errors / incomplete / excluded) |
|---|---|---|---|---|---|---|---|---|---|
| noop | off | 30 (0) | pass (119.2 ms) | 26.2% | 8590.1% | 7088.7% | 8396 / 8512 | 3 | 0 / 30 / 0 / 0 |
| noop | on | 30 (0) | pass (119.0 ms) | 47.4% | 2184.2% | 6318.7% | 8512 / 8632 | 7 | 0 / 0 / 0 / 0 |
| spawn-tree | off | 30 (0) | pass (102.9 ms) | 9.3% | 24.6% | 82.3% | 8440 / 8544 | 5 | 0 / 0 / 0 / 0 |
| spawn-tree | on | 30 (0) | pass (104.9 ms) | 55.0% | 58.9% | 123.7% | 8508 / 8640 | 407 | 0 / 0 / 0 / 0 |
| fileops | off | 30 (0) | pass (106.7 ms) | fail (28.1%) | fail (42.1%) | fail (92.5%) | 8432 / 8536 | 5 | 0 / 0 / 0 / 0 |
| fileops | on | 30 (0) | pass (111.5 ms) | fail (443.7%) | fail (447.8%) | fail (498.4%) | 8492 / 8648 | 15007 | 0 / 0 / 0 / 0 |

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
