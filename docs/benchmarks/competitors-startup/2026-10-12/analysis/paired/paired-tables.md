# Paired Ouro measurements

Each cell has 30 round pairs; milliseconds. Median percentage reductions and differences are computed within rounds. Intervals are descriptive bootstrap intervals, not a multiple-testing-adjusted guarantee.

| Host | Work | Before median / p95 | After median / p95 | Paired reduction | Median change | 95% interval |
|---|---|---:|---:|---:|---:|---:|
| vps | noop | 114.4 / 133.8 | 94.2 / 102.2 | 20.4% | -24.0 | [-29.7, -19.8] |
| vps | python | 150.5 / 175.3 | 131.2 / 162.3 | 13.1% | -20.1 | [-25.2, -12.1] |
| vps | git | 158.5 / 186.2 | 134.8 / 158.9 | 16.5% | -25.6 | [-28.7, -17.2] |
| vps | reads | 121.4 / 139.6 | 96.6 / 112.0 | 18.3% | -22.9 | [-27.4, -16.6] |
| vps | writes | 294.9 / 313.7 | 270.4 / 295.7 | 8.7% | -25.5 | [-31.3, -17.1] |
| vps | spawn | 223.4 / 250.4 | 206.7 / 218.3 | 7.7% | -17.6 | [-29.8, -14.4] |
| vps | cpu | 137.3 / 160.6 | 118.9 / 135.6 | 15.1% | -21.9 | [-25.4, -16.4] |
| pi | noop | 283.4 / 354.4 | 229.7 / 282.8 | 19.7% | -57.2 | [-65.0, -45.3] |
| pi | python | 423.9 / 495.1 | 381.7 / 486.3 | 8.8% | -36.0 | [-48.8, -27.1] |
| pi | reads | 292.1 / 359.3 | 250.9 / 343.6 | 14.0% | -42.6 | [-68.6, -26.7] |
| pi | writes | 672.3 / 2422.1 | 501.2 / 2426.8 | 10.4% | -56.0 | [-593.5, 27.0] |
| pi | spawn | 486.7 / 637.4 | 432.5 / 577.5 | 13.0% | -63.5 | [-86.6, -37.4] |
| pi | cpu | 356.3 / 451.8 | 311.6 / 426.7 | 13.0% | -44.8 | [-53.3, -34.4] |
