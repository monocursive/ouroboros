# `ouro-jail` performance (jail-v1 §5)

Collected 2026-09-25T07:19:41Z on `vps-450b3fe8` (Ubuntu 26.04.1 LTS, kernel 7.0.0-31-generic, 4 CPUs, 3814 MiB) as `ouro-ci` (lingering: yes). Revision `027de7d284b19a8cb7ecc4a1ba496d4408b46627`. `ouro-jail` sha256 `aa2d77aa7efa322fef0afd3e3ae47a3da9ec2776bc91941d2c85ba7773724677`; `ouro-fixture` sha256 `0aebd551a9fa5404ed80b47d03960d5e1b80dd3356c07fef48b8419cc8d74e8e`; bubblewrap 0.11.1.

Raw data: `launches.ndjson`, 1302 records, sha256 `5447d2925724269e950ea0e7b59f84e032ecce85af1e76762ae69488d99db1e1`; summarised 2026-09-25T07:27:24Z by xtask 0.1.0 at source revision `unknown`.

Parameters: 30 measured launch(es) per arm after 1 warm-up launch(es) per arm (42 warm-up records discarded); sessions ["plain","scope"]; profiles ["tool","agent","none"]; workloads ["noop","spawn-tree","fileops"]; fileops 5000 rounds; spawn-tree 200 children; sampling every 5 ms; arm order seed 1790320781015462105.

Host quietness: threshold `--max-load 3`: a verdict needs every counted launch of both sides at or below it. Before the measured launches the 1-minute load average was 1.41 / 1.67 / 2.03 and `/proc/pressure/cpu` `some avg10` was 2.72 / 3.81 / 4.45 % (min / median / max); across them the host's CPU stall was 0.0 / 7.6 / 106.3 ms. The host has 4 CPUs. The 1-minute load includes the harness's own recent launches.

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
| plain | tool | noop | tool/off / direct | 30 (0; flagged: exec_unconfirmed 30) | 30 (0) | 2.03 | 1.5 / 0.0 / 0.2 / 1.8 | 109.2 / 122.1 | 22.5 / 24.1 | 33.9 / 77.2 | 9543.4 / 10197.6 | 7486.0 / 8290.9 | pass (122.1 ms) | n/a | n/a | n/a |
| plain | tool | spawn-tree | tool/off / direct | 30 (0) | 30 (0) | 2.03 | 1.5 / 164.1 / 0.3 / 166.0 | 109.0 / 118.9 | 18.9 / 24.0 | -0.8 / 8.0 | 12.4 / 19.6 | 75.1 / 88.0 | pass (118.9 ms) | n/a | n/a | n/a |
| plain | tool | fileops | tool/off / direct | 30 (0) | 30 (0) | 1.72 | 1.6 / 179.5 / 0.4 / 181.4 | 111.0 / 128.1 | 19.4 / 24.2 | 29.6 / 51.9 | 39.5 / 65.2 | 99.9 / 129.3 | pass (128.1 ms) | fail (29.6%) | fail (39.5%) | fail (99.9%) |
| scope | tool | noop | tool/off / direct | 30 (0; flagged: exec_unconfirmed 30) | 30 (0) | 1.73 | 1.5 / 0.0 / 0.2 / 1.8 | 95.2 / 109.0 | 22.6 / 23.5 | 22.8 / 66.9 | 9122.0 / 9484.9 | 6639.8 / 7423.4 | pass (109.0 ms) | n/a | n/a | n/a |
| scope | tool | spawn-tree | tool/off / direct | 30 (0) | 30 (0) | 1.87 | 1.5 / 161.3 / 0.3 / 163.1 | 90.6 / 101.3 | 18.6 / 24.2 | -1.0 / 6.0 | 8.9 / 20.9 | 65.7 / 77.7 | pass (101.3 ms) | n/a | n/a | n/a |
| scope | tool | fileops | tool/off / direct | 30 (0) | 30 (0) | 1.80 | 1.6 / 174.3 / 0.4 / 176.4 | 91.5 / 109.1 | 18.6 / 23.2 | 28.9 / 43.6 | 40.3 / 52.3 | 90.7 / 107.8 | pass (109.1 ms) | fail (28.9%) | fail (40.3%) | fail (90.7%) |

## `--observe on` against direct: the budgets with observation (`tool`)

The §5 budgets as first written, observation included.

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % | p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start (work + teardown) < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | tool | noop | tool/on / direct | 30 (0) | 30 (0) | 2.03 | 1.5 / 0.0 / 0.2 / 1.8 | 113.8 / 139.0 | 5.4 / 15.6 | 66.0 / 361.6 | 2303.7 / 6628.7 | 6890.1 / 8452.9 | pass (139.0 ms) | n/a | n/a | n/a |
| plain | tool | spawn-tree | tool/on / direct | 30 (0) | 30 (0) | 2.03 | 1.5 / 164.1 / 0.3 / 166.0 | 115.1 / 128.1 | 5.4 / 16.0 | 49.0 / 66.2 | 52.9 / 73.7 | 121.1 / 150.2 | pass (128.1 ms) | n/a | n/a | n/a |
| plain | tool | fileops | tool/on / direct | 30 (0) | 30 (0) | 1.72 | 1.6 / 179.5 / 0.4 / 181.4 | 119.5 / 132.3 | 5.9 / 16.8 | 432.6 / 516.4 | 435.1 / 524.5 | 498.1 / 586.2 | pass (132.3 ms) | fail (432.6%) | fail (435.1%) | fail (498.1%) |
| scope | tool | noop | tool/on / direct | 30 (0) | 30 (0) | 1.73 | 1.5 / 0.0 / 0.2 / 1.8 | 99.7 / 123.9 | 5.1 / 16.3 | 43.3 / 347.6 | 2075.6 / 6582.7 | 5964.6 / 7715.2 | pass (123.9 ms) | n/a | n/a | n/a |
| scope | tool | spawn-tree | tool/on / direct | 30 (0) | 30 (0) | 1.87 | 1.5 / 161.3 / 0.3 / 163.1 | 96.7 / 109.2 | 5.4 / 15.7 | 48.9 / 64.8 | 52.4 / 73.5 | 109.6 / 134.8 | pass (109.2 ms) | n/a | n/a | n/a |
| scope | tool | fileops | tool/on / direct | 30 (0) | 30 (0) | 1.80 | 1.6 / 174.3 / 0.4 / 176.4 | 98.5 / 107.7 | 6.1 / 15.7 | 423.4 / 492.5 | 425.6 / 494.8 | 477.3 / 549.6 | pass (107.7 ms) | fail (423.4%) | fail (425.6%) | fail (477.3%) |

## Observation cost: `--observe on` against `--observe off` (reported, no budget)

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | tool | noop | tool/on / tool/off | 30 (0) | 30 (0) | 2.03 | 110.7 / 0.0 / 22.7 / 133.2 | 4.6 / 29.9 | -17.1 / -6.9 | 23.9 / 244.7 | -75.1 / -30.2 | -7.9 / 12.7 |
| plain | agent | noop | agent/on / agent/off | 30 (0) | 30 (0) | 2.03 | 129.9 / 0.0 / 24.4 / 151.5 | 8.9 / 22.8 | -17.5 / -14.9 | 31.6 / 184.8 | -71.5 / -60.9 | -3.9 / 5.4 |
| plain | none | noop | none/on / none/off | 30 (0) | 30 (0) | 2.03 | 54.6 / 0.0 / 13.0 / 67.5 | 7.0 / 20.1 | -9.9 / -8.9 | 6.2 / 105.5 | -75.5 / -68.1 | -4.2 / 15.7 |
| plain | tool | spawn-tree | tool/on / tool/off | 30 (0) | 30 (0) | 2.03 | 110.5 / 162.8 / 19.2 / 290.7 | 6.2 / 19.1 | -13.5 / -2.9 | 50.2 / 67.5 | 36.0 / 54.5 | 26.3 / 42.9 |
| plain | agent | spawn-tree | agent/on / agent/off | 30 (0) | 30 (0) | 2.03 | 133.2 / 162.8 / 21.7 / 317.9 | 7.7 / 22.6 | -13.0 / -10.7 | 48.5 / 71.9 | 34.9 / 54.6 | 24.2 / 35.7 |
| plain | none | spawn-tree | none/on / none/off | 30 (0) | 30 (0) | 2.03 | 52.7 / 164.6 / 8.6 / 225.8 | 5.9 / 19.2 | -5.0 / -3.3 | 75.0 / 84.1 | 66.5 / 75.1 | 56.9 / 62.8 |
| plain | tool | fileops | tool/on / tool/off | 30 (0) | 30 (0) | 1.72 | 112.5 / 232.6 / 19.8 / 362.6 | 8.6 / 21.3 | -13.5 / -2.6 | 310.9 / 375.6 | 283.5 / 347.6 | 199.2 / 243.3 |
| plain | agent | fileops | agent/on / agent/off | 30 (0) | 30 (0) | 1.72 | 137.0 / 232.9 / 21.0 / 389.9 | 8.3 / 34.5 | -12.0 / -10.0 | 320.6 / 353.2 | 286.5 / 316.7 | 188.5 / 215.9 |
| plain | none | fileops | none/on / none/off | 30 (0) | 30 (0) | 1.72 | 55.8 / 179.4 / 9.0 / 242.7 | 4.8 / 20.3 | -5.1 / -4.1 | 389.3 / 467.7 | 375.6 / 451.3 | 288.7 / 348.4 |
| scope | tool | noop | tool/on / tool/off | 30 (0) | 30 (0) | 1.73 | 96.7 / 0.0 / 22.8 / 119.5 | 4.5 / 28.7 | -17.5 / -6.3 | 16.7 / 264.5 | -76.4 / -27.5 | -10.0 / 16.0 |
| scope | agent | noop | agent/on / agent/off | 30 (0) | 30 (0) | 1.73 | 121.9 / 0.0 / 24.4 / 146.5 | 0.8 / 17.1 | -17.0 / -13.0 | 15.6 / 163.2 | -69.3 / -53.0 | -10.9 / 1.3 |
| scope | none | noop | none/on / none/off | 30 (0) | 30 (0) | 1.73 | 47.0 / 0.0 / 13.1 / 59.8 | -2.7 / 13.2 | -10.0 / -9.0 | -1.1 / 48.7 | -76.3 / -68.4 | -20.3 / 6.4 |
| scope | tool | spawn-tree | tool/on / tool/off | 30 (0) | 30 (0) | 1.87 | 92.1 / 159.6 / 18.8 / 270.2 | 6.1 / 18.6 | -13.2 / -2.9 | 50.4 / 66.5 | 39.9 / 59.3 | 26.5 / 41.7 |
| scope | agent | spawn-tree | agent/on / agent/off | 30 (0) | 30 (0) | 1.87 | 116.4 / 160.4 / 21.4 / 298.6 | 6.7 / 17.3 | -13.5 / -11.0 | 49.0 / 60.7 | 34.8 / 45.8 | 23.3 / 32.8 |
| scope | none | spawn-tree | none/on / none/off | 30 (0) | 30 (0) | 1.87 | 39.9 / 162.3 / 8.7 / 210.9 | 5.0 / 15.8 | -5.3 / -3.8 | 76.1 / 85.7 | 69.6 / 78.7 | 59.9 / 68.6 |
| scope | tool | fileops | tool/on / tool/off | 30 (0) | 30 (0) | 1.80 | 93.1 / 224.7 / 19.0 / 336.3 | 7.0 / 16.2 | -12.5 / -2.9 | 306.0 / 359.6 | 274.7 / 324.0 | 202.7 / 240.6 |
| scope | agent | fileops | agent/on / agent/off | 30 (0) | 30 (0) | 1.80 | 116.0 / 224.3 / 21.1 / 371.6 | 7.4 / 16.8 | -12.4 / -9.9 | 302.1 / 348.8 | 265.3 / 309.0 | 178.4 / 208.0 |
| scope | none | fileops | none/on / none/off | 30 (0) | 30 (0) | 1.80 | 44.4 / 173.9 / 9.1 / 224.7 | -1.6 / 5.1 | -5.3 / -4.5 | 390.6 / 434.1 | 363.6 / 404.5 | 301.6 / 333.4 |

## Informational profiles

### `agent`, off vs direct

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % | p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start (work + teardown) < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | agent | noop | agent/off / direct | 30 (0; flagged: exec_unconfirmed 30) | 30 (0) | 2.03 | 1.5 / 0.0 / 0.2 / 1.8 | 128.4 / 146.2 | 24.2 / 25.2 | 26.2 / 153.2 | 10245.7 / 10691.7 | 8530.4 / 9355.3 | pass (146.2 ms) | n/a | n/a | n/a |
| plain | agent | spawn-tree | agent/off / direct | 30 (0) | 30 (0) | 2.03 | 1.5 / 164.1 / 0.3 / 166.0 | 131.7 / 143.6 | 21.3 / 25.7 | -0.8 / 7.9 | 13.2 / 20.3 | 91.5 / 104.5 | pass (143.6 ms) | n/a | n/a | n/a |
| plain | agent | fileops | agent/off / direct | 30 (0) | 30 (0) | 1.72 | 1.6 / 179.5 / 0.4 / 181.4 | 135.4 / 164.0 | 20.7 / 27.4 | 29.8 / 46.2 | 42.0 / 60.2 | 115.0 / 147.1 | pass (164.0 ms) | fail (29.8%) | fail (42.0%) | fail (115.0%) |
| scope | agent | noop | agent/off / direct | 30 (0; flagged: exec_unconfirmed 30) | 30 (0) | 1.73 | 1.5 / 0.0 / 0.2 / 1.8 | 120.4 / 144.2 | 24.2 / 26.0 | 22.6 / 81.6 | 9785.0 / 10480.3 | 8158.8 / 9252.3 | pass (144.2 ms) | n/a | n/a | n/a |
| scope | agent | spawn-tree | agent/off / direct | 30 (0) | 30 (0) | 1.87 | 1.5 / 161.3 / 0.3 / 163.1 | 114.9 / 121.9 | 21.1 / 25.6 | -0.5 / 11.3 | 13.3 / 23.8 | 83.1 / 98.3 | pass (121.9 ms) | n/a | n/a | n/a |
| scope | agent | fileops | agent/off / direct | 30 (0) | 30 (0) | 1.80 | 1.6 / 174.3 / 0.4 / 176.4 | 114.4 / 128.5 | 20.8 / 26.3 | 28.7 / 44.9 | 42.5 / 59.6 | 110.7 / 130.5 | pass (128.5 ms) | fail (28.7%) | fail (42.5%) | fail (110.7%) |

### `agent`, on vs direct

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % | p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start (work + teardown) < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | agent | noop | agent/on / direct | 30 (0) | 30 (0) | 2.03 | 1.5 / 0.0 / 0.2 / 1.8 | 137.3 / 151.1 | 6.7 / 9.3 | 66.0 / 259.4 | 2844.6 / 3946.5 | 8195.6 / 8994.3 | pass (151.1 ms) | n/a | n/a | n/a |
| plain | agent | spawn-tree | agent/on / direct | 30 (0) | 30 (0) | 2.03 | 1.5 / 164.1 / 0.3 / 166.0 | 139.4 / 154.3 | 8.3 / 10.6 | 47.3 / 70.5 | 52.7 / 75.1 | 137.9 / 159.8 | pass (154.3 ms) | n/a | n/a | n/a |
| plain | agent | fileops | agent/on / direct | 30 (0) | 30 (0) | 1.72 | 1.6 / 179.5 / 0.4 / 181.4 | 143.7 / 169.9 | 8.6 / 10.7 | 445.8 / 488.1 | 448.7 / 491.5 | 520.3 / 579.2 | pass (169.9 ms) | fail (445.8%) | fail (448.7%) | fail (520.3%) |
| scope | agent | noop | agent/on / direct | 30 (0) | 30 (0) | 1.73 | 1.5 / 0.0 / 0.2 / 1.8 | 121.1 / 137.4 | 7.3 / 11.2 | 41.8 / 222.7 | 2931.6 / 4545.4 | 7259.9 / 8263.9 | pass (137.4 ms) | n/a | n/a | n/a |
| scope | agent | spawn-tree | agent/on / direct | 30 (0) | 30 (0) | 1.87 | 1.5 / 161.3 / 0.3 / 163.1 | 121.6 / 132.2 | 7.6 / 10.1 | 48.2 / 59.8 | 52.7 / 65.2 | 125.8 / 143.2 | pass (132.2 ms) | n/a | n/a | n/a |
| scope | agent | fileops | agent/on / direct | 30 (0) | 30 (0) | 1.80 | 1.6 / 174.3 / 0.4 / 176.4 | 121.8 / 131.2 | 8.4 / 10.8 | 417.3 / 477.4 | 420.6 / 482.9 | 486.6 / 548.9 | pass (131.2 ms) | fail (417.3%) | fail (420.6%) | fail (486.6%) |

### `none`, off vs direct

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % | p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start (work + teardown) < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | none | noop | none/off / direct | 30 (0) | 30 (0) | 2.03 | 1.5 / 0.0 / 0.2 / 1.8 | 53.0 / 68.3 | 12.8 / 14.2 | 35.4 / 73.9 | 5429.0 / 6028.2 | 3746.4 / 4705.2 | pass (68.3 ms) | n/a | n/a | n/a |
| plain | none | spawn-tree | none/off / direct | 30 (0) | 30 (0) | 1.95 | 1.5 / 164.1 / 0.3 / 166.0 | 51.2 / 64.5 | 8.3 / 13.5 | 0.3 / 17.4 | 6.8 / 19.7 | 36.0 / 50.7 | pass (64.5 ms) | n/a | n/a | n/a |
| plain | none | fileops | none/off / direct | 30 (0) | 30 (0) | 1.72 | 1.6 / 179.5 / 0.4 / 181.4 | 54.3 / 68.7 | 8.6 / 11.7 | -0.0 / 15.2 | 3.1 / 20.8 | 33.8 / 58.0 | pass (68.7 ms) | pass (-0.0%) | pass (3.1%) | fail (33.8%) |
| scope | none | noop | none/off / direct | 30 (0) | 30 (0) | 1.73 | 1.5 / 0.0 / 0.2 / 1.8 | 45.4 / 51.8 | 12.9 / 14.4 | 32.6 / 66.1 | 5189.6 / 5824.1 | 3269.4 / 3651.0 | pass (51.8 ms) | n/a | n/a | n/a |
| scope | none | spawn-tree | none/off / direct | 30 (0) | 30 (0) | 1.87 | 1.5 / 161.3 / 0.3 / 163.1 | 38.4 / 46.3 | 8.4 / 12.6 | 0.6 / 6.4 | 5.6 / 14.6 | 29.3 / 39.1 | pass (46.3 ms) | n/a | n/a | n/a |
| scope | none | fileops | none/off / direct | 30 (0) | 30 (0) | 1.80 | 1.6 / 174.3 / 0.4 / 176.4 | 42.8 / 50.2 | 8.8 / 11.7 | -0.2 / 11.2 | 5.8 / 17.2 | 27.4 / 42.1 | pass (50.2 ms) | pass (-0.2%) | pass (5.8%) | fail (27.4%) |

### `none`, on vs direct

| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall overhead % | p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start (work + teardown) < 20% | End-to-end wall < 20% |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| plain | none | noop | none/on / direct | 30 (0) | 30 (0) | 2.03 | 1.5 / 0.0 / 0.2 / 1.8 | 60.1 / 73.2 | 2.9 / 3.9 | 43.8 / 178.3 | 1252.4 / 1661.1 | 3585.3 / 4349.7 | pass (73.2 ms) | n/a | n/a | n/a |
| plain | none | spawn-tree | none/on / direct | 30 (0) | 30 (0) | 2.03 | 1.5 / 164.1 / 0.3 / 166.0 | 57.1 / 70.4 | 3.3 / 4.9 | 75.6 / 84.7 | 77.7 / 86.9 | 113.5 / 121.5 | pass (70.4 ms) | n/a | n/a | n/a |
| plain | none | fileops | none/on / direct | 30 (0) | 30 (0) | 1.72 | 1.6 / 179.5 / 0.4 / 181.4 | 59.1 / 74.6 | 3.5 / 4.5 | 389.1 / 467.5 | 390.4 / 468.5 | 420.1 / 499.9 | pass (74.6 ms) | fail (389.1%) | fail (390.4%) | fail (420.1%) |
| scope | none | noop | none/on / direct | 30 (0) | 30 (0) | 1.73 | 1.5 / 0.0 / 0.2 / 1.8 | 42.7 / 58.6 | 2.9 / 3.9 | 31.1 / 97.2 | 1151.9 / 1568.9 | 2584.1 / 3484.4 | pass (58.6 ms) | n/a | n/a | n/a |
| scope | none | spawn-tree | none/on / direct | 30 (0) | 30 (0) | 1.87 | 1.5 / 161.3 / 0.3 / 163.1 | 43.4 / 54.2 | 3.1 / 4.6 | 77.2 / 86.9 | 79.2 / 88.8 | 106.7 / 118.1 | pass (54.2 ms) | n/a | n/a | n/a |
| scope | none | fileops | none/on / direct | 30 (0) | 30 (0) | 1.80 | 1.6 / 174.3 / 0.4 / 176.4 | 41.3 / 47.9 | 3.4 / 4.2 | 389.6 / 433.0 | 390.6 / 433.9 | 411.6 / 452.1 | pass (47.9 ms) | fail (389.6%) | fail (390.6%) | fail (411.6%) |

## Per arm

| Session | Workload | Arm | Valid | Excluded (reasons) | Flagged | Startup ms | Work ms | Teardown ms | Post-start ms | Wall ms |
|---|---|---|---|---|---|---|---|---|---|---|
| plain | noop | direct | 30/30 | 0 (none) | none | 1.5 / 1.8 | 0.0 / 0.1 | 0.2 / 0.3 | 0.2 / 0.3 | 1.8 / 2.1 |
| plain | noop | tool/off | 30/30 | 0 (none) | exec_unconfirmed 30 | 110.7 / 123.7 | 0.0 / 0.1 | 22.7 / 24.3 | 22.8 / 24.3 | 133.2 / 147.3 |
| plain | noop | tool/on | 30/30 | 0 (none) | none | 115.3 / 140.6 | 0.1 / 0.2 | 5.6 / 15.8 | 5.7 / 15.9 | 122.7 / 150.1 |
| plain | noop | agent/off | 30/30 | 0 (none) | exec_unconfirmed 30 | 129.9 / 147.7 | 0.0 / 0.1 | 24.4 / 25.4 | 24.4 / 25.5 | 151.5 / 166.0 |
| plain | noop | agent/on | 30/30 | 0 (none) | none | 138.8 / 152.6 | 0.1 / 0.1 | 6.9 / 9.5 | 7.0 / 9.6 | 145.6 / 159.7 |
| plain | noop | none/off | 30/30 | 0 (none) | none | 54.6 / 69.9 | 0.0 / 0.1 | 13.0 / 14.4 | 13.1 / 14.5 | 67.5 / 84.4 |
| plain | noop | none/on | 30/30 | 0 (none) | none | 61.6 / 74.7 | 0.0 / 0.1 | 3.1 / 4.1 | 3.2 / 4.2 | 64.7 / 78.1 |
| plain | spawn-tree | direct | 30/30 | 0 (none) | none | 1.5 / 1.8 | 164.1 / 177.8 | 0.3 / 0.4 | 164.4 / 178.1 | 166.0 / 179.5 |
| plain | spawn-tree | tool/off | 30/30 | 0 (none) | none | 110.5 / 120.4 | 162.8 / 177.2 | 19.2 / 24.3 | 184.8 / 196.7 | 290.7 / 312.1 |
| plain | spawn-tree | tool/on | 30/30 | 0 (none) | none | 116.6 / 129.6 | 244.6 / 272.8 | 5.8 / 16.3 | 251.4 / 285.5 | 367.0 / 415.4 |
| plain | spawn-tree | agent/off | 30/30 | 0 (none) | none | 133.2 / 145.1 | 162.8 / 177.0 | 21.7 / 26.0 | 186.1 / 197.9 | 317.9 / 339.4 |
| plain | spawn-tree | agent/on | 30/30 | 0 (none) | none | 140.9 / 155.8 | 241.8 / 279.8 | 8.6 / 10.9 | 251.1 / 287.8 | 395.0 / 431.3 |
| plain | spawn-tree | none/off | 30/30 | 0 (none) | none | 52.7 / 66.0 | 164.6 / 192.7 | 8.6 / 13.8 | 175.5 / 196.9 | 225.8 / 250.1 |
| plain | spawn-tree | none/on | 30/30 | 0 (none) | none | 58.6 / 71.9 | 288.2 / 303.1 | 3.6 / 5.3 | 292.2 / 307.3 | 354.4 / 367.7 |
| plain | fileops | direct | 30/30 | 0 (none) | none | 1.6 / 1.9 | 179.5 / 206.5 | 0.4 / 0.5 | 179.9 / 206.8 | 181.4 / 208.6 |
| plain | fileops | tool/off | 30/30 | 0 (none) | none | 112.5 / 129.7 | 232.6 / 272.6 | 19.8 / 24.5 | 251.0 / 297.2 | 362.6 / 415.9 |
| plain | fileops | tool/on | 30/30 | 0 (none) | none | 121.1 / 133.9 | 955.9 / 1106.3 | 6.3 / 17.2 | 962.6 / 1123.5 | 1084.8 / 1244.7 |
| plain | fileops | agent/off | 30/30 | 0 (none) | none | 137.0 / 165.6 | 232.9 / 262.4 | 21.0 / 27.8 | 255.4 / 288.1 | 389.9 / 448.2 |
| plain | fileops | agent/on | 30/30 | 0 (none) | none | 145.3 / 171.5 | 979.6 / 1055.5 | 9.0 / 11.1 | 987.1 / 1064.2 | 1125.0 / 1232.0 |
| plain | fileops | none/off | 30/30 | 0 (none) | none | 55.8 / 70.3 | 179.4 / 206.8 | 9.0 / 12.0 | 185.5 / 217.4 | 242.7 / 286.6 |
| plain | fileops | none/on | 30/30 | 0 (none) | none | 60.7 / 76.2 | 877.8 / 1018.6 | 3.8 / 4.9 | 882.3 / 1022.8 | 943.4 / 1088.2 |
| scope | noop | direct | 30/30 | 0 (none) | none | 1.5 / 1.9 | 0.0 / 0.1 | 0.2 / 0.3 | 0.2 / 0.4 | 1.8 / 2.5 |
| scope | noop | tool/off | 30/30 | 0 (none) | exec_unconfirmed 30 | 96.7 / 110.6 | 0.0 / 0.1 | 22.8 / 23.7 | 22.8 / 23.7 | 119.5 / 133.4 |
| scope | noop | tool/on | 30/30 | 0 (none) | none | 101.2 / 125.4 | 0.1 / 0.2 | 5.3 / 16.5 | 5.4 / 16.6 | 107.5 / 138.6 |
| scope | noop | agent/off | 30/30 | 0 (none) | exec_unconfirmed 30 | 121.9 / 145.7 | 0.0 / 0.1 | 24.4 / 26.2 | 24.5 / 26.2 | 146.5 / 165.9 |
| scope | noop | agent/on | 30/30 | 0 (none) | none | 122.7 / 139.0 | 0.1 / 0.1 | 7.5 / 11.4 | 7.5 / 11.5 | 130.5 / 148.3 |
| scope | noop | none/off | 30/30 | 0 (none) | none | 47.0 / 53.4 | 0.0 / 0.1 | 13.1 / 14.6 | 13.1 / 14.7 | 59.8 / 66.5 |
| scope | noop | none/on | 30/30 | 0 (none) | none | 44.3 / 60.2 | 0.0 / 0.1 | 3.1 / 4.1 | 3.1 / 4.1 | 47.6 / 63.6 |
| scope | spawn-tree | direct | 30/30 | 0 (none) | none | 1.5 / 1.8 | 161.3 / 171.9 | 0.3 / 0.3 | 161.6 / 172.2 | 163.1 / 173.9 |
| scope | spawn-tree | tool/off | 30/30 | 0 (none) | none | 92.1 / 102.8 | 159.6 / 170.9 | 18.8 / 24.5 | 176.0 / 195.4 | 270.2 / 289.7 |
| scope | spawn-tree | tool/on | 30/30 | 0 (none) | none | 98.2 / 110.7 | 240.1 / 265.7 | 5.7 / 16.0 | 246.2 / 280.2 | 341.8 / 382.9 |
| scope | spawn-tree | agent/off | 30/30 | 0 (none) | none | 116.4 / 123.5 | 160.4 / 179.5 | 21.4 / 25.9 | 183.0 / 200.0 | 298.6 / 323.3 |
| scope | spawn-tree | agent/on | 30/30 | 0 (none) | none | 123.1 / 133.7 | 239.0 / 257.8 | 7.9 / 10.4 | 246.7 / 266.9 | 368.3 / 396.6 |
| scope | spawn-tree | none/off | 30/30 | 0 (none) | none | 39.9 / 47.8 | 162.3 / 171.6 | 8.7 / 12.8 | 170.7 / 185.1 | 210.9 / 226.9 |
| scope | spawn-tree | none/on | 30/30 | 0 (none) | none | 44.9 / 55.7 | 285.8 / 301.4 | 3.4 / 4.9 | 289.5 / 305.0 | 337.1 / 355.6 |
| scope | fileops | direct | 30/30 | 0 (none) | none | 1.6 / 2.2 | 174.3 / 190.1 | 0.4 / 0.4 | 174.7 / 190.5 | 176.4 / 192.7 |
| scope | fileops | tool/off | 30/30 | 0 (none) | none | 93.1 / 110.7 | 224.7 / 250.4 | 19.0 / 23.6 | 245.0 / 266.0 | 336.3 / 366.5 |
| scope | fileops | tool/on | 30/30 | 0 (none) | none | 100.1 / 109.3 | 912.4 / 1032.8 | 6.5 / 16.1 | 918.1 / 1039.0 | 1018.1 / 1145.5 |
| scope | fileops | agent/off | 30/30 | 0 (none) | none | 116.0 / 130.1 | 224.3 / 252.5 | 21.1 / 26.7 | 248.9 / 278.8 | 371.6 / 406.4 |
| scope | fileops | agent/on | 30/30 | 0 (none) | none | 123.3 / 132.8 | 901.7 / 1006.5 | 8.7 / 11.2 | 909.4 / 1018.2 | 1034.5 / 1144.4 |
| scope | fileops | none/off | 30/30 | 0 (none) | none | 44.4 / 51.8 | 173.9 / 193.9 | 9.1 / 12.1 | 184.9 / 204.7 | 224.7 / 250.6 |
| scope | fileops | none/on | 30/30 | 0 (none) | none | 42.9 / 49.5 | 853.4 / 929.1 | 3.8 / 4.6 | 857.0 / 932.6 | 902.2 / 973.6 |

### Peak memory (KiB, median / p95 / max over valid launches)

| Session | Workload | Arm | Launched HWM (sampled) | Reaped tree (`wait4`) | Leaf `memory.peak` (sampled) | Target |
|---|---|---|---|---|---|---|
| plain | noop | direct | n/a | 3970 / 4016 / 4072 | n/a | 3888 / 4000 / 4016 |
| plain | noop | tool/off | 7464 / 7576 / 7620 | 7388 / 7536 / 7544 | 1772 / 2048 / 2048 | 3886 / 4016 / 4016 |
| plain | noop | tool/on | 7546 / 7692 / 7692 | 7382 / 7528 / 7532 | 1776 / 2040 / 2048 | 3888 / 3940 / 3980 |
| plain | noop | agent/off | 7852 / 8000 / 8056 | 7642 / 7792 / 7912 | 2440 / 2472 / 2700 | 3952 / 4060 / 4060 |
| plain | noop | agent/on | 7982 / 8124 / 8156 | 7742 / 7932 / 7972 | 2436 / 2716 / 2724 | 3942 / 4060 / 4060 |
| plain | noop | none/off | 7266 / 7360 / 7368 | 7300 / 7352 / 7364 | 768 / 840 / 844 | 3930 / 4012 / 4016 |
| plain | noop | none/on | 7412 / 7628 / 7652 | 7306 / 7408 / 7436 | 768 / 820 / 828 | 3888 / 4016 / 4080 |
| plain | spawn-tree | direct | 4040 / 4124 / 4136 | 4008 / 4136 / 4144 | n/a | 3952 / 4080 / 4080 |
| plain | spawn-tree | tool/off | 7480 / 7612 / 7656 | 7420 / 7544 / 7608 | 3934 / 4360 / 4712 | 3948 / 4080 / 4140 |
| plain | spawn-tree | tool/on | 7546 / 7712 / 7712 | 7372 / 7512 / 7660 | 3326 / 3748 / 4012 | 3980 / 4076 / 4080 |
| plain | spawn-tree | agent/off | 7904 / 7984 / 8016 | 7662 / 7752 / 7800 | 4308 / 4968 / 5076 | 3982 / 4080 / 4080 |
| plain | spawn-tree | agent/on | 8004 / 8164 / 8172 | 7702 / 7912 / 7944 | 3722 / 4420 / 4656 | 4012 / 4080 / 4096 |
| plain | spawn-tree | none/off | 7260 / 7380 / 7384 | 7300 / 7364 / 7364 | 3174 / 3668 / 3840 | 3950 / 4080 / 4080 |
| plain | spawn-tree | none/on | 7416 / 7640 / 7644 | 7312 / 7408 / 7416 | 2578 / 2900 / 2912 | 3952 / 4080 / 4080 |
| plain | fileops | direct | 3928 / 4096 / 4096 | 3948 / 4056 / 4056 | n/a | 3854 / 4020 / 4056 |
| plain | fileops | tool/off | 7486 / 7652 / 7688 | 7416 / 7596 / 7720 | 2202 / 2296 / 2444 | 3912 / 4016 / 4016 |
| plain | fileops | tool/on | 7548 / 7704 / 7764 | 7384 / 7548 / 7592 | 1784 / 2268 / 2320 | 3896 / 4016 / 4016 |
| plain | fileops | agent/off | 7864 / 8052 / 8072 | 7634 / 7804 / 7864 | 2730 / 3108 / 3120 | 3950 / 4020 / 4020 |
| plain | fileops | agent/on | 7984 / 8112 / 8152 | 7704 / 7916 / 7936 | 2458 / 2704 / 2708 | 3958 / 4020 / 4060 |
| plain | fileops | none/off | 7272 / 7384 / 7388 | 7298 / 7356 / 7364 | 1402 / 1560 / 1584 | 3876 / 4016 / 4020 |
| plain | fileops | none/on | 7434 / 7580 / 7588 | 7310 / 7376 / 7452 | 816 / 1216 / 1312 | 3902 / 4020 / 4020 |
| scope | noop | direct | n/a | 3904 / 4016 / 4016 | n/a | 3888 / 3952 / 4016 |
| scope | noop | tool/off | 7536 / 7664 / 7676 | 7458 / 7684 / 7720 | 1780 / 2040 / 2048 | 3888 / 4016 / 4044 |
| scope | noop | tool/on | 7590 / 7732 / 7756 | 7384 / 7604 / 7660 | 1770 / 2040 / 2040 | 3884 / 4016 / 4016 |
| scope | noop | agent/off | 7886 / 7992 / 7996 | 7646 / 7744 / 7752 | 2440 / 2716 / 2724 | 3936 / 4056 / 4056 |
| scope | noop | agent/on | 7966 / 8100 / 8104 | 7748 / 7916 / 7940 | 2426 / 2476 / 2744 | 3930 / 4056 / 4060 |
| scope | noop | none/off | 7248 / 7376 / 7380 | 7178 / 7324 / 7324 | 768 / 816 / 828 | 3888 / 4016 / 4080 |
| scope | noop | none/on | 7396 / 7552 / 7560 | 7206 / 7444 / 7476 | 536 / 820 / 820 | 3888 / 4000 / 4016 |
| scope | spawn-tree | direct | 4056 / 4184 / 4188 | 4016 / 4144 / 4144 | n/a | 4004 / 4144 / 4144 |
| scope | spawn-tree | tool/off | 7482 / 7668 / 7696 | 7398 / 7596 / 7608 | 3936 / 4368 / 4448 | 4006 / 4144 / 4144 |
| scope | spawn-tree | tool/on | 7558 / 7712 / 7716 | 7388 / 7532 / 7616 | 3420 / 3728 / 3932 | 3952 / 4144 / 4144 |
| scope | spawn-tree | agent/off | 7880 / 8028 / 8080 | 7656 / 7792 / 7912 | 4314 / 5000 / 5052 | 4016 / 4016 / 4056 |
| scope | spawn-tree | agent/on | 7990 / 8164 / 8172 | 7716 / 7976 / 7976 | 3848 / 4356 / 4488 | 4002 / 4080 / 4104 |
| scope | spawn-tree | none/off | 7270 / 7376 / 7380 | 7112 / 7292 / 7296 | 3346 / 3640 / 3740 | 3952 / 4080 / 4144 |
| scope | spawn-tree | none/on | 7482 / 7568 / 7636 | 7256 / 7404 / 7432 | 2666 / 3004 / 3012 | 3940 / 4116 / 4144 |
| scope | fileops | direct | 4022 / 4084 / 4088 | 4012 / 4048 / 4080 | n/a | 3924 / 4040 / 4048 |
| scope | fileops | tool/off | 7470 / 7616 / 7636 | 7408 / 7608 / 7656 | 2208 / 2432 / 2464 | 3914 / 4016 / 4016 |
| scope | fileops | tool/on | 7572 / 7704 / 7756 | 7400 / 7592 / 7652 | 1800 / 2056 / 2284 | 3952 / 4016 / 4040 |
| scope | fileops | agent/off | 7904 / 8008 / 8024 | 7676 / 7816 / 7852 | 2894 / 2972 / 2972 | 3968 / 4060 / 4060 |
| scope | fileops | agent/on | 7990 / 8156 / 8164 | 7742 / 7944 / 7976 | 2488 / 2728 / 2740 | 3960 / 4056 / 4060 |
| scope | fileops | none/off | 7268 / 7376 / 7376 | 7172 / 7300 / 7348 | 1328 / 1536 / 1696 | 3930 / 4036 / 4040 |
| scope | fileops | none/on | 7458 / 7556 / 7556 | 7238 / 7428 / 7436 | 816 / 1072 / 1076 | 3948 / 4016 / 4016 |

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
| noop | off | 30 (0) | pass (122.1 ms) | 33.9% | 9543.4% | 7486.0% | 7464 / 7576 | 3 | 0 / 30 / 0 / 0 |
| noop | on | 30 (0) | pass (139.0 ms) | 66.0% | 2303.7% | 6890.1% | 7546 / 7692 | 7 | 0 / 0 / 0 / 0 |
| spawn-tree | off | 30 (0) | pass (118.9 ms) | -0.8% | 12.4% | 75.1% | 7480 / 7612 | 5 | 0 / 0 / 0 / 0 |
| spawn-tree | on | 30 (0) | pass (128.1 ms) | 49.0% | 52.9% | 121.1% | 7546 / 7712 | 407 | 0 / 0 / 0 / 0 |
| fileops | off | 30 (0) | pass (128.1 ms) | fail (29.6%) | fail (39.5%) | fail (99.9%) | 7486 / 7652 | 5 | 0 / 0 / 0 / 0 |
| fileops | on | 30 (0) | pass (132.3 ms) | fail (432.6%) | fail (435.1%) | fail (498.1%) | 7548 / 7704 | 15007 | 0 / 0 / 0 / 0 |

scope session:

| Workload | Observe | Valid (excl.) | Startup p95 added | Work phase | Post-start | End-to-end wall | Peak RSS | Event count | Losses (gaps / errors / incomplete / excluded) |
|---|---|---|---|---|---|---|---|---|---|
| noop | off | 30 (0) | pass (109.0 ms) | 22.8% | 9122.0% | 6639.8% | 7536 / 7664 | 3 | 0 / 30 / 0 / 0 |
| noop | on | 30 (0) | pass (123.9 ms) | 43.3% | 2075.6% | 5964.6% | 7590 / 7732 | 7 | 0 / 0 / 0 / 0 |
| spawn-tree | off | 30 (0) | pass (101.3 ms) | -1.0% | 8.9% | 65.7% | 7482 / 7668 | 5 | 0 / 0 / 0 / 0 |
| spawn-tree | on | 30 (0) | pass (109.2 ms) | 48.9% | 52.4% | 109.6% | 7558 / 7712 | 407 | 0 / 0 / 0 / 0 |
| fileops | off | 30 (0) | pass (109.1 ms) | fail (28.9%) | fail (40.3%) | fail (90.7%) | 7470 / 7616 | 5 | 0 / 0 / 0 / 0 |
| fileops | on | 30 (0) | pass (107.7 ms) | fail (423.4%) | fail (425.6%) | fail (477.3%) | 7572 / 7704 | 15007 | 0 / 0 / 0 / 0 |

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
