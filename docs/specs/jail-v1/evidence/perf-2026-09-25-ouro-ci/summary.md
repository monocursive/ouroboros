# `ouro-jail` performance (jail-v1 §5)

Collected 2026-09-25T02:20:40Z on `vps-450b3fe8` (Ubuntu 26.04.1 LTS, kernel 7.0.0-31-generic, 4 CPUs, 3814 MiB) as `ouro-ci` (lingering: yes). Revision `4380241f3195bcc73a5186282400eda3b174ee41`. `ouro-jail` sha256 `90dbd434296f8b3679d56fea1c6413f30bf7d8cfe558abc1e6cb2961eef5e898`; `ouro-fixture` sha256 `0aebd551a9fa5404ed80b47d03960d5e1b80dd3356c07fef48b8419cc8d74e8e`; bubblewrap 0.11.1.

Raw data: `launches.ndjson`, 1302 records, sha256 `ee1ff987f541c367c7d41f8c8e10302ce7bdddd55116ef6f172e5e1075325e73`; summarised 2026-09-25T02:33:23Z by xtask 0.1.0 at source revision `1cd10600fae070e71a2ab1279c51af325e0400c5`.

Parameters: 30 measured launch(es) per arm after 1 warm-up launch(es) per arm (42 warm-up records discarded); sessions ["plain","scope"]; profiles ["tool","agent","none"]; workloads ["noop","spawn-tree","fileops"]; fileops 5000 rounds; spawn-tree 200 children; sampling every 5 ms; arm order seed 1790302840055834092.

Host quietness: threshold `--max-load 3`: a verdict needs every counted launch of both sides at or below it. Before the measured launches the 1-minute load average was 1.21 / 1.67 / 2.09 and `/proc/pressure/cpu` `some avg10` was 1.04 / 3.61 / 4.10 % (min / median / max); across them the host's CPU stall was 0.0 / 6.7 / 108.6 ms. The host has 4 CPUs. The 1-minute load includes the harness's own recent launches.

## Revalidated under the current rules

These records were taken under older validity rules; `perf summarize --revalidate` applied the rules of the summarising revision to them (the raw file is unchanged):

- plain noop agent/off warm-up: stored excluded (errors), flagged exec_unconfirmed, now valid, flagged exec_unconfirmed (1 record(s))
- plain noop agent/off: stored excluded (errors), flagged exec_unconfirmed, now valid, flagged exec_unconfirmed (30 record(s))
- plain noop tool/off warm-up: stored excluded (errors), flagged exec_unconfirmed, now valid, flagged exec_unconfirmed (1 record(s))
- plain noop tool/off: stored excluded (errors), flagged exec_unconfirmed, now valid, flagged exec_unconfirmed (30 record(s))
- scope noop agent/off warm-up: stored excluded (errors), flagged exec_unconfirmed, now valid, flagged exec_unconfirmed (1 record(s))
- scope noop agent/off: stored excluded (errors), flagged exec_unconfirmed, now valid, flagged exec_unconfirmed (30 record(s))
- scope noop tool/off warm-up: stored excluded (errors), flagged exec_unconfirmed, now valid, flagged exec_unconfirmed (1 record(s))
- scope noop tool/off: stored excluded (errors), flagged exec_unconfirmed, now valid, flagged exec_unconfirmed (30 record(s))

## Verdict roll-up

A budget holds for a profile only if every cell below passes. The overhead budget is read three ways, each its own verdict: **work phase** (the target's own entry to end; the integrator's current reading of §5), **post-start** (work + teardown: everything after entry, so startup + post-start cover the whole run), and **end-to-end wall** (startup included).

| Profile | Comparison | p95 added startup < 250 ms | Work phase < 20% | Post-start < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|
| tool | off vs direct | pass (6 of 6 cells pass, 0 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) |
| tool | on vs direct | pass (6 of 6 cells pass, 0 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) |
| agent | off vs direct | pass (6 of 6 cells pass, 0 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) |
| agent | on vs direct | pass (6 of 6 cells pass, 0 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) |
| none | off vs direct | pass (6 of 6 cells pass, 0 fail, 0 insufficient, 0 loaded) | pass (2 of 2 cells pass, 0 fail, 0 insufficient, 0 loaded) | pass (2 of 2 cells pass, 0 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) |
| none | on vs direct | pass (6 of 6 cells pass, 0 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) | fail (0 of 2 cells pass, 2 fail, 0 insufficient, 0 loaded) |

## `--observe off` against direct: the jail's own overhead (`tool`)

Under the decision of 2026-09-24 the §5 budgets apply to this comparison if observation misses them (next section); otherwise they apply to both. Each cell: median / p95 over the valid launches. `exec_unconfirmed` marks valid launches whose receipt outcome is `unknown` because, with observation off, the target ended before the supervisor confirmed its exec (the jail then exits 1); the target's own lines prove it ran, and the timing is the jail's real path.

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % | p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start (work + teardown) < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | tool | noop | tool/off / direct | 30 (0; flagged: exec_unconfirmed 30) | 30 (0) | 2.09 | 1.3 / 0.0 / 0.2 / 1.5 | 101.3 / 121.7 | 22.2 / 24.8 | 34.7 / 182.2 | 10357.2 / 11593.8 | 8019.9 / 9374.2 | pass (121.7 ms) | n/a | n/a | n/a |
| plain | tool | spawn-tree | tool/off / direct | 30 (0) | 30 (0) | 1.85 | 1.4 / 154.3 / 0.3 / 155.9 | 103.7 / 118.3 | 19.6 / 24.0 | -1.3 / 6.2 | 13.1 / 19.6 | 77.7 / 89.5 | pass (118.3 ms) | n/a | n/a | n/a |
| plain | tool | fileops | tool/off / direct | 30 (0) | 30 (0) | 2.09 | 1.4 / 163.3 / 0.3 / 165.2 | 103.7 / 119.2 | 17.5 / 23.9 | 30.8 / 42.3 | 43.4 / 56.4 | 103.7 / 121.2 | pass (119.2 ms) | fail (30.8%) | fail (43.4%) | fail (103.7%) |
| scope | tool | noop | tool/off / direct | 30 (0; flagged: exec_unconfirmed 30) | 30 (0) | 2.09 | 1.4 / 0.0 / 0.2 / 1.6 | 86.2 / 99.1 | 22.1 / 22.9 | 37.9 / 611.5 | 9662.8 / 10009.4 | 6775.5 / 7559.8 | pass (99.1 ms) | n/a | n/a | n/a |
| scope | tool | spawn-tree | tool/off / direct | 30 (0) | 30 (0) | 1.91 | 1.4 / 149.1 / 0.3 / 150.7 | 84.8 / 92.3 | 19.5 / 24.8 | -1.4 / 4.5 | 10.4 / 17.6 | 67.6 / 76.5 | pass (92.3 ms) | n/a | n/a | n/a |
| scope | tool | fileops | tool/off / direct | 30 (0) | 30 (0) | 1.69 | 1.4 / 163.2 / 0.4 / 164.9 | 86.3 / 98.5 | 19.2 / 23.8 | 28.4 / 35.2 | 38.7 / 49.7 | 92.6 / 99.7 | pass (98.5 ms) | fail (28.4%) | fail (38.7%) | fail (92.6%) |

## `--observe on` against direct: the budgets with observation (`tool`)

The §5 budgets as first written, observation included.

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % | p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start (work + teardown) < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | tool | noop | tool/on / direct | 30 (0) | 30 (0) | 2.09 | 1.3 / 0.0 / 0.2 / 1.5 | 106.4 / 119.6 | 5.7 / 15.2 | 50.5 / 1425.2 | 2657.8 / 7239.8 | 7407.0 / 8329.8 | pass (119.6 ms) | n/a | n/a | n/a |
| plain | tool | spawn-tree | tool/on / direct | 30 (0) | 30 (0) | 1.85 | 1.4 / 154.3 / 0.3 / 155.9 | 106.7 / 119.7 | 4.6 / 15.1 | 43.3 / 59.5 | 48.9 / 67.6 | 115.6 / 139.3 | pass (119.7 ms) | n/a | n/a | n/a |
| plain | tool | fileops | tool/on / direct | 30 (0) | 30 (0) | 2.09 | 1.4 / 163.3 / 0.3 / 165.2 | 107.7 / 123.7 | 5.3 / 15.2 | 401.0 / 433.1 | 403.5 / 437.5 | 463.7 / 498.1 | pass (123.7 ms) | fail (401.0%) | fail (403.5%) | fail (463.7%) |
| scope | tool | noop | tool/on / direct | 30 (0) | 30 (0) | 2.09 | 1.4 / 0.0 / 0.2 / 1.6 | 90.5 / 105.1 | 4.3 / 14.7 | 46.9 / 698.8 | 1917.9 / 6430.7 | 5964.2 / 6917.3 | pass (105.1 ms) | n/a | n/a | n/a |
| scope | tool | spawn-tree | tool/on / direct | 30 (0) | 30 (0) | 1.91 | 1.4 / 149.1 / 0.3 / 150.7 | 87.9 / 101.8 | 4.9 / 15.0 | 41.0 / 58.3 | 46.1 / 68.6 | 104.9 / 130.5 | pass (101.8 ms) | n/a | n/a | n/a |
| scope | tool | fileops | tool/on / direct | 30 (0) | 30 (0) | 1.69 | 1.4 / 163.2 / 0.4 / 164.9 | 91.3 / 106.0 | 4.9 / 15.2 | 398.7 / 423.3 | 401.9 / 425.4 | 454.4 / 476.0 | pass (106.0 ms) | fail (398.7%) | fail (401.9%) | fail (454.4%) |

## Observation cost: `--observe on` against `--observe off` (reported, no budget)

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | tool | noop | tool/on / tool/off | 30 (0) | 30 (0) | 2.09 | 102.6 / 0.0 / 22.3 / 125.2 | 5.1 / 18.4 | -16.5 / -6.9 | 11.7 / 1032.4 | -73.6 / -29.8 | -7.5 / 3.8 |
| plain | agent | noop | agent/on / agent/off | 30 (0) | 30 (0) | 2.09 | 122.2 / 0.0 / 23.9 / 145.4 | 3.9 / 24.2 | -17.0 / -13.8 | 23.3 / 1328.3 | -70.7 / -54.5 | -7.5 / 4.7 |
| plain | none | noop | none/on / none/off | 30 (0) | 30 (0) | 2.09 | 44.5 / 0.0 / 12.7 / 57.8 | 13.4 / 21.3 | -9.9 / -9.2 | -0.9 / 166.2 | -77.6 / -72.2 | 5.1 / 18.8 |
| plain | tool | spawn-tree | tool/on / tool/off | 30 (0) | 30 (0) | 1.85 | 105.1 / 152.3 / 19.9 / 277.0 | 3.0 / 16.0 | -15.0 / -4.5 | 45.2 / 61.6 | 31.7 / 48.2 | 21.3 / 34.6 |
| plain | agent | spawn-tree | agent/on / agent/off | 30 (0) | 30 (0) | 1.85 | 125.1 / 152.1 / 18.3 / 295.0 | 5.7 / 19.0 | -10.3 / -8.1 | 47.2 / 62.2 | 38.4 / 52.4 | 24.1 / 36.9 |
| plain | none | spawn-tree | none/on / none/off | 30 (0) | 30 (0) | 1.85 | 46.6 / 154.3 / 8.7 / 211.4 | 13.6 / 26.6 | -5.4 / -4.0 | 70.7 / 89.9 | 61.7 / 79.5 | 53.4 / 73.5 |
| plain | tool | fileops | tool/on / tool/off | 30 (0) | 30 (0) | 2.09 | 105.1 / 213.7 / 17.8 / 336.4 | 4.0 / 20.0 | -12.2 / -2.2 | 283.0 / 307.6 | 251.2 / 274.9 | 176.8 / 193.7 |
| plain | agent | fileops | agent/on / agent/off | 30 (0) | 30 (0) | 2.09 | 123.2 / 208.4 / 20.5 / 355.4 | 10.0 / 21.8 | -12.8 / -10.1 | 294.6 / 354.1 | 264.7 / 319.8 | 170.5 / 209.3 |
| plain | none | fileops | none/on / none/off | 30 (0) | 30 (0) | 2.09 | 45.3 / 164.4 / 7.9 / 219.1 | 12.3 / 21.0 | -4.4 / -3.3 | 363.7 / 395.3 | 338.8 / 367.8 | 276.4 / 301.3 |
| scope | tool | noop | tool/on / tool/off | 30 (0) | 30 (0) | 2.09 | 87.6 / 0.0 / 22.3 / 110.1 | 4.3 / 19.0 | -17.8 / -7.4 | 6.5 / 479.2 | -79.3 / -33.1 | -11.8 / 2.1 |
| scope | agent | noop | agent/on / agent/off | 30 (0) | 30 (0) | 2.09 | 107.9 / 0.0 / 23.6 / 129.9 | 2.8 / 16.5 | -17.2 / -13.2 | 15.9 / 338.1 | -72.7 / -55.7 | -9.0 / 2.4 |
| scope | none | noop | none/on / none/off | 30 (0) | 30 (0) | 2.09 | 36.9 / 0.0 / 12.6 / 49.5 | 7.4 / 18.3 | -9.7 / -8.7 | 2.1 / 1138.9 | -76.3 / -68.9 | -4.6 / 16.6 |
| scope | tool | spawn-tree | tool/on / tool/off | 30 (0) | 30 (0) | 1.91 | 86.2 / 146.9 / 19.7 / 252.4 | 3.1 / 17.0 | -14.6 / -4.4 | 43.0 / 60.6 | 32.3 / 52.7 | 22.3 / 37.6 |
| scope | agent | spawn-tree | agent/on / agent/off | 30 (0) | 30 (0) | 1.91 | 106.1 / 149.0 / 21.6 / 274.9 | 6.5 / 13.2 | -14.3 / -11.1 | 43.7 / 55.8 | 33.0 / 43.2 | 21.8 / 29.1 |
| scope | none | spawn-tree | none/on / none/off | 30 (0) | 30 (0) | 1.91 | 39.4 / 151.4 / 9.0 / 198.3 | 2.6 / 16.0 | -5.8 / -4.5 | 67.0 / 81.8 | 65.0 / 79.7 | 50.4 / 63.7 |
| scope | tool | fileops | tool/on / tool/off | 30 (0) | 30 (0) | 1.69 | 87.8 / 209.6 / 19.6 / 317.6 | 5.0 / 19.7 | -14.4 / -4.1 | 288.3 / 307.4 | 262.0 / 278.9 | 187.9 / 199.1 |
| scope | agent | fileops | agent/on / agent/off | 30 (0) | 30 (0) | 1.69 | 106.9 / 208.2 / 21.0 / 336.5 | 8.6 / 20.4 | -13.5 / -10.5 | 292.2 / 325.7 | 263.1 / 293.9 | 179.2 / 202.1 |
| scope | none | fileops | none/on / none/off | 30 (0) | 30 (0) | 1.69 | 39.7 / 161.8 / 7.6 / 209.5 | 2.9 / 9.3 | -4.1 / -3.1 | 372.8 / 444.0 | 341.3 / 407.5 | 287.4 / 344.0 |

## Informational profiles

### `agent`, off vs direct

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % | p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start (work + teardown) < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | agent | noop | agent/off / direct | 30 (0; flagged: exec_unconfirmed 30) | 30 (0) | 2.09 | 1.3 / 0.0 / 0.2 / 1.5 | 120.9 / 142.2 | 23.8 / 25.1 | 28.7 / 94.0 | 11106.5 / 11743.7 | 9334.1 / 10384.7 | pass (142.2 ms) | n/a | n/a | n/a |
| plain | agent | spawn-tree | agent/off / direct | 30 (0) | 30 (0) | 1.85 | 1.4 / 154.3 / 0.3 / 155.9 | 123.7 / 138.4 | 18.0 / 24.9 | -1.4 / 8.6 | 8.5 / 22.1 | 89.3 / 107.4 | pass (138.4 ms) | n/a | n/a | n/a |
| plain | agent | fileops | agent/off / direct | 30 (0) | 30 (0) | 2.09 | 1.4 / 163.3 / 0.3 / 165.2 | 121.8 / 139.9 | 20.2 / 26.6 | 27.6 / 48.6 | 39.0 / 64.2 | 115.2 / 142.1 | pass (139.9 ms) | fail (27.6%) | fail (39.0%) | fail (115.2%) |
| scope | agent | noop | agent/off / direct | 30 (0; flagged: exec_unconfirmed 30) | 30 (0) | 2.09 | 1.4 / 0.0 / 0.2 / 1.6 | 106.5 / 123.8 | 23.4 / 24.7 | 18.2 / 62.8 | 10230.7 / 10799.1 | 8017.4 / 8593.5 | pass (123.8 ms) | n/a | n/a | n/a |
| scope | agent | spawn-tree | agent/off / direct | 30 (0) | 30 (0) | 1.91 | 1.4 / 149.1 / 0.3 / 150.7 | 104.7 / 117.9 | 21.3 / 26.1 | -0.0 / 6.9 | 12.2 / 19.2 | 82.5 / 96.2 | pass (117.9 ms) | n/a | n/a | n/a |
| scope | agent | fileops | agent/off / direct | 30 (0) | 30 (0) | 1.69 | 1.4 / 163.2 / 0.4 / 164.9 | 105.5 / 119.1 | 20.6 / 25.2 | 27.6 / 36.2 | 38.9 / 50.8 | 104.0 / 119.9 | pass (119.1 ms) | fail (27.6%) | fail (38.9%) | fail (104.0%) |

### `agent`, on vs direct

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % | p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start (work + teardown) < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | agent | noop | agent/on / direct | 30 (0) | 30 (0) | 2.09 | 1.3 / 0.0 / 0.2 / 1.5 | 124.7 / 145.1 | 6.8 / 9.9 | 58.7 / 1738.2 | 3180.9 / 5001.4 | 8630.8 / 9776.7 | pass (145.1 ms) | n/a | n/a | n/a |
| plain | agent | spawn-tree | agent/on / direct | 30 (0) | 30 (0) | 1.85 | 1.4 / 154.3 / 0.3 / 155.9 | 129.4 / 142.6 | 7.7 / 9.9 | 45.1 / 59.9 | 50.2 / 65.4 | 134.8 / 159.2 | pass (142.6 ms) | n/a | n/a | n/a |
| plain | agent | fileops | agent/on / direct | 30 (0) | 30 (0) | 2.09 | 1.4 / 163.3 / 0.3 / 165.2 | 131.8 / 143.6 | 7.4 / 10.1 | 403.5 / 479.4 | 406.9 / 483.4 | 482.1 / 565.5 | pass (143.6 ms) | fail (403.5%) | fail (406.9%) | fail (482.1%) |
| scope | agent | noop | agent/on / direct | 30 (0) | 30 (0) | 2.09 | 1.4 / 0.0 / 0.2 / 1.6 | 109.3 / 123.0 | 6.2 / 10.2 | 36.9 / 417.6 | 2718.5 / 4473.9 | 7283.6 / 8211.5 | pass (123.0 ms) | n/a | n/a | n/a |
| scope | agent | spawn-tree | agent/on / direct | 30 (0) | 30 (0) | 1.91 | 1.4 / 149.1 / 0.3 / 150.7 | 111.2 / 117.9 | 7.0 / 10.2 | 43.6 / 55.7 | 49.2 / 60.5 | 122.2 / 135.6 | pass (117.9 ms) | n/a | n/a | n/a |
| scope | agent | fileops | agent/on / direct | 30 (0) | 30 (0) | 1.69 | 1.4 / 163.2 / 0.4 / 164.9 | 114.1 / 125.9 | 7.1 / 10.2 | 400.4 / 443.2 | 404.2 / 447.1 | 469.7 / 516.4 | pass (125.9 ms) | fail (400.4%) | fail (404.2%) | fail (469.7%) |

### `none`, off vs direct

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % | p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start (work + teardown) < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | none | noop | none/off / direct | 30 (0) | 30 (0) | 2.09 | 1.3 / 0.0 / 0.2 / 1.5 | 43.2 / 56.4 | 12.5 / 13.4 | 37.4 / 128.9 | 5857.6 / 6259.5 | 3652.2 / 4482.5 | pass (56.4 ms) | n/a | n/a | n/a |
| plain | none | spawn-tree | none/off / direct | 30 (0) | 30 (0) | 1.85 | 1.4 / 154.3 / 0.3 / 155.9 | 45.2 / 62.7 | 8.5 / 13.2 | -0.0 / 15.4 | 6.8 / 20.4 | 35.6 / 53.7 | pass (62.7 ms) | n/a | n/a | n/a |
| plain | none | fileops | none/off / direct | 30 (0) | 30 (0) | 2.09 | 1.4 / 163.3 / 0.3 / 165.2 | 43.8 / 64.1 | 7.5 / 13.2 | 0.6 / 14.8 | 6.7 / 19.1 | 32.6 / 53.4 | pass (64.1 ms) | pass (0.6%) | pass (6.7%) | fail (32.6%) |
| scope | none | noop | none/off / direct | 30 (0) | 30 (0) | 2.09 | 1.4 / 0.0 / 0.2 / 1.6 | 35.5 / 46.1 | 12.4 / 13.1 | 26.4 / 120.5 | 5437.7 / 5710.1 | 2990.9 / 3655.5 | pass (46.1 ms) | n/a | n/a | n/a |
| scope | none | spawn-tree | none/off / direct | 30 (0) | 30 (0) | 1.91 | 1.4 / 149.1 / 0.3 / 150.7 | 38.0 / 48.6 | 8.7 / 13.5 | 1.6 / 10.8 | 4.0 / 17.9 | 31.6 / 44.8 | pass (48.6 ms) | n/a | n/a | n/a |
| scope | none | fileops | none/off / direct | 30 (0) | 30 (0) | 1.69 | 1.4 / 163.2 / 0.4 / 164.9 | 38.3 / 47.3 | 7.2 / 13.0 | -0.8 / 6.3 | 6.5 / 12.7 | 27.0 / 35.9 | pass (47.3 ms) | pass (-0.8%) | pass (6.5%) | fail (27.0%) |

### `none`, on vs direct

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % | p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start (work + teardown) < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | none | noop | none/on / direct | 30 (0) | 30 (0) | 2.09 | 1.3 / 0.0 / 0.2 / 1.5 | 56.5 / 64.4 | 2.6 / 3.3 | 36.1 / 265.8 | 1231.9 / 1556.1 | 3842.5 / 4359.4 | pass (64.4 ms) | n/a | n/a | n/a |
| plain | none | spawn-tree | none/on / direct | 30 (0) | 30 (0) | 1.85 | 1.4 / 154.3 / 0.3 / 155.9 | 58.8 / 71.7 | 3.1 / 4.5 | 70.7 / 89.9 | 72.7 / 91.8 | 108.1 / 135.3 | pass (71.7 ms) | n/a | n/a | n/a |
| plain | none | fileops | none/on / direct | 30 (0) | 30 (0) | 2.09 | 1.4 / 163.3 / 0.3 / 165.2 | 56.1 / 64.9 | 3.1 / 4.3 | 366.6 / 398.4 | 368.4 / 399.3 | 399.2 / 432.2 | pass (64.9 ms) | fail (366.6%) | fail (368.4%) | fail (399.2%) |
| scope | none | noop | none/on / direct | 30 (0) | 30 (0) | 2.09 | 1.4 / 0.0 / 0.2 / 1.6 | 42.9 / 53.7 | 2.7 / 3.7 | 29.1 / 1465.7 | 1213.9 / 1620.9 | 2850.2 / 3503.9 | pass (53.7 ms) | n/a | n/a | n/a |
| scope | none | spawn-tree | none/on / direct | 30 (0) | 30 (0) | 1.91 | 1.4 / 149.1 / 0.3 / 150.7 | 40.6 / 53.9 | 2.9 / 4.2 | 69.6 / 84.7 | 71.6 / 87.0 | 98.0 / 115.5 | pass (53.9 ms) | n/a | n/a | n/a |
| scope | none | fileops | none/on / direct | 30 (0) | 30 (0) | 1.69 | 1.4 / 163.2 / 0.4 / 164.9 | 41.2 / 47.6 | 3.1 / 4.1 | 368.8 / 439.5 | 370.2 / 440.7 | 392.0 / 463.9 | pass (47.6 ms) | fail (368.8%) | fail (370.2%) | fail (392.0%) |

## Per arm

| Session | Workload | Arm | Valid | Excluded (reasons) | Flagged | Startup ms | Work ms | Teardown ms | Post-start ms | Wall ms |
|---|---|---|---|---|---|---|---|---|---|---|
| plain | noop | direct | 30/30 | 0 (none) | none | 1.3 / 1.6 | 0.0 / 0.1 | 0.2 / 0.2 | 0.2 / 0.3 | 1.5 / 1.8 |
| plain | noop | tool/off | 30/30 | 0 (none) | exec_unconfirmed 30 | 102.6 / 123.0 | 0.0 / 0.1 | 22.3 / 25.0 | 22.4 / 25.0 | 125.2 / 146.0 |
| plain | noop | tool/on | 30/30 | 0 (none) | none | 107.7 / 121.0 | 0.0 / 0.5 | 5.9 / 15.4 | 5.9 / 15.7 | 115.7 / 129.9 |
| plain | noop | agent/off | 30/30 | 0 (none) | exec_unconfirmed 30 | 122.2 / 143.5 | 0.0 / 0.1 | 23.9 / 25.3 | 24.0 / 25.3 | 145.4 / 161.6 |
| plain | noop | agent/on | 30/30 | 0 (none) | none | 126.1 / 146.4 | 0.0 / 0.6 | 7.0 / 10.1 | 7.0 / 10.9 | 134.6 / 152.2 |
| plain | noop | none/off | 30/30 | 0 (none) | none | 44.5 / 57.7 | 0.0 / 0.1 | 12.7 / 13.6 | 12.7 / 13.6 | 57.8 / 70.6 |
| plain | noop | none/on | 30/30 | 0 (none) | none | 57.8 / 65.7 | 0.0 / 0.1 | 2.8 / 3.5 | 2.9 / 3.5 | 60.8 / 68.7 |
| plain | spawn-tree | direct | 30/30 | 0 (none) | none | 1.4 / 2.0 | 154.3 / 163.7 | 0.3 / 0.3 | 154.6 / 164.0 | 155.9 / 165.7 |
| plain | spawn-tree | tool/off | 30/30 | 0 (none) | none | 105.1 / 119.7 | 152.3 / 164.0 | 19.9 / 24.2 | 174.9 / 184.8 | 277.0 / 295.4 |
| plain | spawn-tree | tool/on | 30/30 | 0 (none) | none | 108.0 / 121.1 | 221.2 / 246.2 | 4.9 / 15.4 | 230.3 / 259.1 | 336.0 / 373.0 |
| plain | spawn-tree | agent/off | 30/30 | 0 (none) | none | 125.1 / 139.8 | 152.1 / 167.6 | 18.3 / 25.2 | 167.8 / 188.8 | 295.0 / 323.2 |
| plain | spawn-tree | agent/on | 30/30 | 0 (none) | none | 130.7 / 144.0 | 223.9 / 246.7 | 7.9 / 10.2 | 232.2 / 255.7 | 366.0 / 403.9 |
| plain | spawn-tree | none/off | 30/30 | 0 (none) | none | 46.6 / 64.1 | 154.3 / 178.1 | 8.7 / 13.4 | 165.1 / 186.1 | 211.4 / 239.5 |
| plain | spawn-tree | none/on | 30/30 | 0 (none) | none | 60.2 / 73.1 | 263.4 / 293.1 | 3.3 / 4.8 | 267.0 / 296.5 | 324.3 / 366.7 |
| plain | fileops | direct | 30/30 | 0 (none) | none | 1.4 / 1.9 | 163.3 / 175.7 | 0.3 / 0.4 | 163.7 / 176.0 | 165.2 / 177.7 |
| plain | fileops | tool/off | 30/30 | 0 (none) | none | 105.1 / 120.6 | 213.7 / 232.4 | 17.8 / 24.2 | 234.7 / 256.0 | 336.4 / 365.3 |
| plain | fileops | tool/on | 30/30 | 0 (none) | none | 109.1 / 125.1 | 818.4 / 870.9 | 5.6 / 15.6 | 824.1 / 879.7 | 931.1 / 987.9 |
| plain | fileops | agent/off | 30/30 | 0 (none) | none | 123.2 / 141.3 | 208.4 / 242.7 | 20.5 / 26.9 | 227.5 / 268.8 | 355.4 / 399.9 |
| plain | fileops | agent/on | 30/30 | 0 (none) | none | 133.2 / 145.0 | 822.4 / 946.5 | 7.7 / 10.4 | 829.7 / 954.9 | 961.4 / 1099.2 |
| plain | fileops | none/off | 30/30 | 0 (none) | none | 45.3 / 65.5 | 164.4 / 187.6 | 7.9 / 13.5 | 174.7 / 195.0 | 219.1 / 253.5 |
| plain | fileops | none/on | 30/30 | 0 (none) | none | 57.6 / 66.3 | 762.2 / 814.1 | 3.4 / 4.6 | 766.7 / 817.2 | 824.6 / 879.1 |
| scope | noop | direct | 30/30 | 0 (none) | none | 1.4 / 2.2 | 0.0 / 0.1 | 0.2 / 0.3 | 0.2 / 0.3 | 1.6 / 2.5 |
| scope | noop | tool/off | 30/30 | 0 (none) | exec_unconfirmed 30 | 87.6 / 100.5 | 0.0 / 0.2 | 22.3 / 23.1 | 22.4 / 23.1 | 110.1 / 122.6 |
| scope | noop | tool/on | 30/30 | 0 (none) | none | 91.9 / 106.5 | 0.0 / 0.3 | 4.5 / 14.9 | 4.6 / 15.0 | 97.1 / 112.3 |
| scope | noop | agent/off | 30/30 | 0 (none) | exec_unconfirmed 30 | 107.9 / 125.2 | 0.0 / 0.1 | 23.6 / 24.9 | 23.7 / 25.0 | 129.9 / 139.2 |
| scope | noop | agent/on | 30/30 | 0 (none) | none | 110.7 / 124.4 | 0.0 / 0.2 | 6.4 / 10.4 | 6.5 / 10.5 | 118.2 / 133.0 |
| scope | noop | none/off | 30/30 | 0 (none) | none | 36.9 / 47.5 | 0.0 / 0.1 | 12.6 / 13.3 | 12.7 / 13.3 | 49.5 / 60.1 |
| scope | noop | none/on | 30/30 | 0 (none) | none | 44.2 / 55.1 | 0.0 / 0.5 | 2.9 / 3.9 | 3.0 / 3.9 | 47.2 / 57.7 |
| scope | spawn-tree | direct | 30/30 | 0 (none) | none | 1.4 / 1.6 | 149.1 / 165.2 | 0.3 / 0.4 | 149.4 / 165.5 | 150.7 / 167.1 |
| scope | spawn-tree | tool/off | 30/30 | 0 (none) | none | 86.2 / 93.7 | 146.9 / 155.7 | 19.7 / 25.1 | 164.9 / 175.6 | 252.4 / 265.9 |
| scope | spawn-tree | tool/on | 30/30 | 0 (none) | none | 89.4 / 103.2 | 210.1 / 236.0 | 5.1 / 15.3 | 218.3 / 251.8 | 308.7 / 347.2 |
| scope | spawn-tree | agent/off | 30/30 | 0 (none) | none | 106.1 / 119.3 | 149.0 / 159.4 | 21.6 / 26.4 | 167.5 / 178.0 | 274.9 / 295.6 |
| scope | spawn-tree | agent/on | 30/30 | 0 (none) | none | 112.6 / 119.3 | 214.1 / 232.1 | 7.3 / 10.4 | 222.8 / 239.8 | 334.8 / 354.9 |
| scope | spawn-tree | none/off | 30/30 | 0 (none) | none | 39.4 / 50.0 | 151.4 / 165.1 | 9.0 / 13.7 | 155.4 / 176.1 | 198.3 / 218.1 |
| scope | spawn-tree | none/on | 30/30 | 0 (none) | none | 42.0 / 55.3 | 252.8 / 275.3 | 3.1 / 4.5 | 256.3 / 279.3 | 298.3 / 324.7 |
| scope | fileops | direct | 30/30 | 0 (none) | none | 1.4 / 1.8 | 163.2 / 179.2 | 0.4 / 0.5 | 163.5 / 179.5 | 164.9 / 180.9 |
| scope | fileops | tool/off | 30/30 | 0 (none) | none | 87.8 / 100.0 | 209.6 / 220.6 | 19.6 / 24.2 | 226.7 / 244.8 | 317.6 / 329.4 |
| scope | fileops | tool/on | 30/30 | 0 (none) | none | 92.8 / 107.5 | 813.8 / 853.9 | 5.2 / 15.5 | 820.8 / 859.1 | 914.4 / 950.0 |
| scope | fileops | agent/off | 30/30 | 0 (none) | none | 106.9 / 120.5 | 208.2 / 222.3 | 21.0 / 25.6 | 227.1 / 246.7 | 336.5 / 362.7 |
| scope | fileops | agent/on | 30/30 | 0 (none) | none | 115.5 / 127.3 | 816.6 / 886.4 | 7.5 / 10.5 | 824.6 / 894.6 | 939.6 / 1016.6 |
| scope | fileops | none/off | 30/30 | 0 (none) | none | 39.7 / 48.8 | 161.8 / 173.5 | 7.6 / 13.3 | 174.2 / 184.3 | 209.5 / 224.2 |
| scope | fileops | none/on | 30/30 | 0 (none) | none | 42.6 / 49.1 | 765.1 / 880.3 | 3.5 / 4.5 | 768.9 / 884.2 | 811.5 / 930.1 |

### Peak memory (KiB, median / p95 / max over valid launches)

| Session | Workload | Arm | Launched HWM (sampled) | Reaped tree (`wait4`) | Leaf `memory.peak` (sampled) | Target |
|---|---|---|---|---|---|---|
| plain | noop | direct | n/a | 3970 / 4016 / 4016 | n/a | 3888 / 4016 / 4016 |
| plain | noop | tool/off | 7516 / 7608 / 7608 | 7498 / 7616 / 7644 | 1764 / 2040 / 2048 | 3888 / 4016 / 4016 |
| plain | noop | tool/on | 7600 / 7720 / 7732 | 7436 / 7692 / 7692 | 1762 / 2048 / 2068 | 3888 / 4016 / 4080 |
| plain | noop | agent/off | 7900 / 8024 / 8040 | 7666 / 7836 / 7844 | 2436 / 2708 / 2712 | 3926 / 4016 / 4020 |
| plain | noop | agent/on | 8006 / 8136 / 8152 | 7726 / 7856 / 7984 | 2436 / 2708 / 2724 | 3898 / 4052 / 4056 |
| plain | noop | none/off | 7346 / 7440 / 7464 | 7304 / 7364 / 7364 | 804 / 828 / 840 | 3888 / 3992 / 4016 |
| plain | noop | none/on | 7464 / 7652 / 7680 | 7330 / 7464 / 7472 | 664 / 828 / 1068 | 3888 / 4016 / 4076 |
| plain | spawn-tree | direct | 4046 / 4060 / 4184 | 4006 / 4080 / 4140 | n/a | 3950 / 4016 / 4140 |
| plain | spawn-tree | tool/off | 7538 / 7676 / 7676 | 7468 / 7664 / 7724 | 4034 / 4472 / 4612 | 3946 / 4144 / 4144 |
| plain | spawn-tree | tool/on | 7626 / 7736 / 7736 | 7476 / 7668 / 7672 | 3448 / 4000 / 4268 | 3944 / 4016 / 4144 |
| plain | spawn-tree | agent/off | 7936 / 8052 / 8056 | 7716 / 7828 / 7828 | 4358 / 4940 / 5824 | 3954 / 4080 / 4144 |
| plain | spawn-tree | agent/on | 8032 / 8132 / 8148 | 7718 / 7864 / 7944 | 3958 / 4400 / 4696 | 4016 / 4144 / 4144 |
| plain | spawn-tree | none/off | 7346 / 7440 / 7468 | 7310 / 7384 / 7404 | 3304 / 4108 / 4148 | 3986 / 4080 / 4144 |
| plain | spawn-tree | none/on | 7504 / 7612 / 7620 | 7326 / 7440 / 7516 | 2692 / 3300 / 3484 | 3972 / 4016 / 4144 |
| plain | fileops | direct | 3990 / 4056 / 4120 | 3952 / 4056 / 4080 | n/a | 3946 / 3976 / 3980 |
| plain | fileops | tool/off | 7558 / 7672 / 7672 | 7460 / 7592 / 7644 | 2252 / 2520 / 2532 | 3888 / 3952 / 3980 |
| plain | fileops | tool/on | 7612 / 7740 / 7740 | 7430 / 7668 / 7672 | 2016 / 2056 / 2304 | 3888 / 3952 / 3980 |
| plain | fileops | agent/off | 7912 / 8052 / 8076 | 7684 / 7828 / 7836 | 2872 / 3096 / 3104 | 3896 / 4020 / 4080 |
| plain | fileops | agent/on | 8020 / 8136 / 8140 | 7778 / 7892 / 7956 | 2476 / 2716 / 2724 | 3926 / 4052 / 4056 |
| plain | fileops | none/off | 7364 / 7468 / 7480 | 7310 / 7380 / 7388 | 1472 / 1552 / 1712 | 3908 / 3980 / 3980 |
| plain | fileops | none/on | 7496 / 7656 / 7656 | 7334 / 7480 / 7512 | 822 / 1084 / 1328 | 3888 / 3956 / 4076 |
| scope | noop | direct | n/a | 3928 / 4016 / 4080 | n/a | 3910 / 3996 / 4080 |
| scope | noop | tool/off | 7510 / 7608 / 7668 | 7452 / 7636 / 7644 | 1770 / 2040 / 2040 | 3888 / 3988 / 4076 |
| scope | noop | tool/on | 7584 / 7684 / 7720 | 7448 / 7588 / 7632 | 1780 / 2040 / 2044 | 3888 / 4016 / 4044 |
| scope | noop | agent/off | 7886 / 8028 / 8060 | 7696 / 7788 / 7856 | 2436 / 2732 / 2736 | 3888 / 3952 / 3980 |
| scope | noop | agent/on | 7998 / 8096 / 8136 | 7742 / 7848 / 7892 | 2436 / 2712 / 2736 | 3952 / 4056 / 4056 |
| scope | noop | none/off | 7336 / 7408 / 7416 | 7238 / 7344 / 7348 | 816 / 820 / 820 | 3888 / 4004 / 4004 |
| scope | noop | none/on | 7462 / 7532 / 7580 | 7260 / 7444 / 7456 | 768 / 816 / 816 | 3888 / 4016 / 4016 |
| scope | spawn-tree | direct | 4044 / 4124 / 4184 | 4004 / 4144 / 4144 | n/a | 3952 / 4080 / 4144 |
| scope | spawn-tree | tool/off | 7524 / 7668 / 7668 | 7468 / 7628 / 7668 | 4150 / 4604 / 4668 | 3958 / 4080 / 4144 |
| scope | spawn-tree | tool/on | 7596 / 7736 / 7736 | 7418 / 7604 / 7720 | 3552 / 4072 / 4124 | 3950 / 4080 / 4120 |
| scope | spawn-tree | agent/off | 7916 / 8048 / 8052 | 7686 / 7788 / 7828 | 4478 / 5564 / 5800 | 3966 / 4016 / 4016 |
| scope | spawn-tree | agent/on | 8020 / 8148 / 8148 | 7770 / 7952 / 7956 | 3804 / 4544 / 4552 | 3970 / 4144 / 4144 |
| scope | spawn-tree | none/off | 7328 / 7440 / 7460 | 7242 / 7324 / 7416 | 3418 / 4036 / 4348 | 3948 / 4080 / 4080 |
| scope | spawn-tree | none/on | 7484 / 7592 / 7600 | 7272 / 7396 / 7428 | 2698 / 3336 / 3452 | 3944 / 4144 / 4144 |
| scope | fileops | direct | 3934 / 4060 / 4064 | 3952 / 4016 / 4020 | n/a | 3888 / 4016 / 4020 |
| scope | fileops | tool/off | 7534 / 7660 / 7672 | 7476 / 7692 / 7720 | 2270 / 2540 / 2544 | 3834 / 4016 / 4016 |
| scope | fileops | tool/on | 7608 / 7708 / 7736 | 7400 / 7568 / 7608 | 2014 / 2044 / 2252 | 3824 / 3980 / 3984 |
| scope | fileops | agent/off | 7908 / 7992 / 8048 | 7686 / 7804 / 7836 | 2936 / 3188 / 3244 | 3926 / 4016 / 4016 |
| scope | fileops | agent/on | 8018 / 8140 / 8144 | 7784 / 7928 / 7964 | 2476 / 2720 / 2724 | 3954 / 4056 / 4056 |
| scope | fileops | none/off | 7344 / 7408 / 7412 | 7234 / 7364 / 7376 | 1472 / 1540 / 1548 | 3824 / 3980 / 4016 |
| scope | fileops | none/on | 7482 / 7528 / 7532 | 7288 / 7392 / 7456 | 816 / 1072 / 1328 | 3832 / 3976 / 4016 |

### Events and losses

Event counts: the receipt's `coverage.<class>.observed_count` over valid launches, median (min–max). Losses: over every measured launch of the arm, valid or not; a count that differs from the workload's exact one excludes the launch (`count_mismatch`).

| Session | Workload | Arm | Excluded | exec | fs.write | fs.deny | net | proxy.net | Trace frames | Observer gaps (lost) | Coverage gaps (lost) | Receipt errors | Incomplete traces | Trace notes (all kinds) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | noop | tool/off | 0 | n/a | n/a | n/a | n/a | n/a | 3 | 0 (0) | 0 (0) | 30 | 0 | lifecycle 30 |
| plain | noop | tool/on | 0 | 2 | 0 | 0 | 0 | n/a | 7 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | noop | agent/off | 0 | n/a | n/a | n/a | n/a | 0 | 3 | 0 (0) | 0 (0) | 30 | 0 | lifecycle 30 |
| plain | noop | agent/on | 0 | 2 | 0 | 0 | 0 | 0 | 7 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | noop | none/off | 0 | n/a | n/a | n/a | n/a | n/a | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | noop | none/on | 0 | 2 | 0 | 0 | 0 | n/a | 7 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | spawn-tree | tool/off | 0 | n/a | n/a | n/a | n/a | n/a | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | spawn-tree | tool/on | 0 | 402 | 0 | 0 | 0 | n/a | 407 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | spawn-tree | agent/off | 0 | n/a | n/a | n/a | n/a | 0 | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | spawn-tree | agent/on | 0 | 402 | 0 | 0 | 0 | 0 | 407 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | spawn-tree | none/off | 0 | n/a | n/a | n/a | n/a | n/a | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | spawn-tree | none/on | 0 | 402 | 0 | 0 | 0 | n/a | 407 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | fileops | tool/off | 0 | n/a | n/a | n/a | n/a | n/a | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | fileops | tool/on | 0 | 2 | 15000 | 0 | 0 | n/a | 15007 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | fileops | agent/off | 0 | n/a | n/a | n/a | n/a | 0 | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | fileops | agent/on | 0 | 2 | 15000 | 0 | 0 | 0 | 15007 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | fileops | none/off | 0 | n/a | n/a | n/a | n/a | n/a | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| plain | fileops | none/on | 0 | 2 | 15000 | 0 | 0 | n/a | 15007 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | noop | tool/off | 0 | n/a | n/a | n/a | n/a | n/a | 3 | 0 (0) | 0 (0) | 30 | 0 | lifecycle 30 |
| scope | noop | tool/on | 0 | 2 | 0 | 0 | 0 | n/a | 7 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | noop | agent/off | 0 | n/a | n/a | n/a | n/a | 0 | 3 | 0 (0) | 0 (0) | 30 | 0 | lifecycle 30 |
| scope | noop | agent/on | 0 | 2 | 0 | 0 | 0 | 0 | 7 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | noop | none/off | 0 | n/a | n/a | n/a | n/a | n/a | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | noop | none/on | 0 | 2 | 0 | 0 | 0 | n/a | 7 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | spawn-tree | tool/off | 0 | n/a | n/a | n/a | n/a | n/a | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | spawn-tree | tool/on | 0 | 402 | 0 | 0 | 0 | n/a | 407 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | spawn-tree | agent/off | 0 | n/a | n/a | n/a | n/a | 0 | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | spawn-tree | agent/on | 0 | 402 | 0 | 0 | 0 | 0 | 407 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | spawn-tree | none/off | 0 | n/a | n/a | n/a | n/a | n/a | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | spawn-tree | none/on | 0 | 402 | 0 | 0 | 0 | n/a | 407 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | fileops | tool/off | 0 | n/a | n/a | n/a | n/a | n/a | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | fileops | tool/on | 0 | 2 | 15000 | 0 | 0 | n/a | 15007 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | fileops | agent/off | 0 | n/a | n/a | n/a | n/a | 0 | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | fileops | agent/on | 0 | 2 | 15000 | 0 | 0 | 0 | 15007 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | fileops | none/off | 0 | n/a | n/a | n/a | n/a | n/a | 5 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |
| scope | fileops | none/on | 0 | 2 | 15000 | 0 | 0 | n/a | 15007 | 0 (0) | 0 (0) | 0 | 0 | lifecycle 60 |

## backend-evaluation.md §4, `tool`

Startup: p95 added against direct. Overheads: median against direct, work phase / post-start / end-to-end wall, each with its verdict. Peak RSS: supervisor sampled HWM median / p95 (KiB). Events: median trace frames. Losses: observer + coverage gaps, receipt errors, incomplete traces and excluded launches, over all launches.

plain session:

| Workload | Observe | Valid (excl.) | Startup p95 added | Work phase | Post-start | End-to-end wall | Peak RSS | Event count | Losses (gaps / errors / incomplete / excluded) |
|---|---|---|---|---|---|---|---|---|---|
| noop | off | 30 (0) | pass (121.7 ms) | 34.7% | 10357.2% | 8019.9% | 7516 / 7608 | 3 | 0 / 30 / 0 / 0 |
| noop | on | 30 (0) | pass (119.6 ms) | 50.5% | 2657.8% | 7407.0% | 7600 / 7720 | 7 | 0 / 0 / 0 / 0 |
| spawn-tree | off | 30 (0) | pass (118.3 ms) | -1.3% | 13.1% | 77.7% | 7538 / 7676 | 5 | 0 / 0 / 0 / 0 |
| spawn-tree | on | 30 (0) | pass (119.7 ms) | 43.3% | 48.9% | 115.6% | 7626 / 7736 | 407 | 0 / 0 / 0 / 0 |
| fileops | off | 30 (0) | pass (119.2 ms) | fail (30.8%) | fail (43.4%) | fail (103.7%) | 7558 / 7672 | 5 | 0 / 0 / 0 / 0 |
| fileops | on | 30 (0) | pass (123.7 ms) | fail (401.0%) | fail (403.5%) | fail (463.7%) | 7612 / 7740 | 15007 | 0 / 0 / 0 / 0 |

scope session:

| Workload | Observe | Valid (excl.) | Startup p95 added | Work phase | Post-start | End-to-end wall | Peak RSS | Event count | Losses (gaps / errors / incomplete / excluded) |
|---|---|---|---|---|---|---|---|---|---|
| noop | off | 30 (0) | pass (99.1 ms) | 37.9% | 9662.8% | 6775.5% | 7510 / 7608 | 3 | 0 / 30 / 0 / 0 |
| noop | on | 30 (0) | pass (105.1 ms) | 46.9% | 1917.9% | 5964.2% | 7584 / 7684 | 7 | 0 / 0 / 0 / 0 |
| spawn-tree | off | 30 (0) | pass (92.3 ms) | -1.4% | 10.4% | 67.6% | 7524 / 7668 | 5 | 0 / 0 / 0 / 0 |
| spawn-tree | on | 30 (0) | pass (101.8 ms) | 41.0% | 46.1% | 104.9% | 7596 / 7736 | 407 | 0 / 0 / 0 / 0 |
| fileops | off | 30 (0) | pass (98.5 ms) | fail (28.4%) | fail (38.7%) | fail (92.6%) | 7534 / 7660 | 5 | 0 / 0 / 0 / 0 |
| fileops | on | 30 (0) | pass (106.0 ms) | fail (398.7%) | fail (401.9%) | fail (454.4%) | 7608 / 7708 | 15007 | 0 / 0 / 0 / 0 |

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
