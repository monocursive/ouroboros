# Rerun 2026-10-16 performance tables

Median / p95 wall time in milliseconds over successful measured samples (30 per bucket after three discarded warmups; container lane 30/1). Failed or unconfirmed launches are excluded and counted.

## vps native

| tool | case | n | ok | median | p95 | work median |
|---|---|---:|---:|---:|---:|---:|
| direct | noop | 30 | 30 | 1.01 | 2.21 | 0.0 |
| direct | python | 30 | 30 | 37.88 | 48.51 | 0.0 |
| direct | git | 30 | 30 | 41.44 | 50.91 | 3.87 |
| direct | reads | 30 | 30 | 5.74 | 7.07 | 4.69 |
| direct | writes | 30 | 30 | 63.6 | 84.45 | 62.19 |
| direct | spawn | 30 | 30 | 73.06 | 78.58 | 72.05 |
| direct | cpu | 30 | 30 | 25.55 | 27.11 | 24.34 |
| greywall | noop | 30 | 30 | 1585.94 | 1647.31 | 0.0 |
| greywall | python | 30 | 30 | 1626.48 | 1692.68 | 0.0 |
| greywall | git | 30 | 30 | 1634.56 | 1673.84 | 6.01 |
| greywall | reads | 30 | 30 | 1591.35 | 1665.25 | 6.93 |
| greywall | writes | 30 | 30 | 1656.33 | 1737.3 | 71.71 |
| greywall | spawn | 30 | 30 | 1658.87 | 1715.37 | 79.27 |
| greywall | cpu | 30 | 30 | 1612.85 | 1664.66 | 24.22 |
| mxc | noop | 30 | 30 | 19.51 | 20.8 | 0.0 |
| mxc | python | 30 | 30 | 68.38 | 70.04 | 0.0 |
| mxc | git | 30 | 30 | 67.85 | 69.94 | 5.6 |
| mxc | reads | 30 | 30 | 20.32 | 37.31 | 6.06 |
| mxc | writes | 30 | 30 | 118.16 | 119.55 | 68.65 |
| mxc | spawn | 30 | 30 | 118.09 | 120.33 | 76.44 |
| mxc | cpu | 30 | 30 | 67.8 | 69.89 | 24.28 |
| ukai | noop | 30 | 30 | 91.89 | 103.48 | 0.0 |
| ukai | python | 30 | 30 | 128.09 | 150.83 | 0.0 |
| ukai | git | 30 | 30 | 138.13 | 163.34 | 7.15 |
| ukai | reads | 30 | 30 | 98.61 | 111.4 | 6.66 |
| ukai | writes | 30 | 30 | 232.34 | 254.9 | 139.88 |
| ukai | spawn | 30 | 30 | 206.03 | 220.81 | 114.92 |
| ukai | cpu | 30 | 30 | 115.76 | 134.66 | 24.22 |
| ukai-obs-off | noop | 0 | 0 | None | None | None |
| ukai-obs-off | python | 30 | 30 | 131.47 | 151.73 | 0.0 |
| ukai-obs-off | git | 30 | 30 | 141.27 | 151.95 | 5.72 |
| ukai-obs-off | reads | 0 | 0 | None | None | None |
| ukai-obs-off | writes | 30 | 30 | 167.21 | 194.85 | 70.44 |
| ukai-obs-off | spawn | 30 | 30 | 173.47 | 195.01 | 78.73 |
| ukai-obs-off | cpu | 30 | 30 | 118.53 | 132.48 | 24.24 |

## pi native

| tool | case | n | ok | median | p95 | work median |
|---|---|---:|---:|---:|---:|---:|
| direct | noop | 30 | 30 | 1.84 | 2.52 | 0.0 |
| direct | python | 30 | 30 | 137.9 | 152.34 | 0.0 |
| direct | git | 30 | 30 | 146.22 | 165.38 | 8.23 |
| direct | reads | 30 | 30 | 12.61 | 17.91 | 10.71 |
| direct | writes | 30 | 30 | 878.97 | 3457.7 | 877.09 |
| direct | spawn | 30 | 30 | 136.11 | 163.48 | 134.23 |
| direct | cpu | 30 | 30 | 82.18 | 82.52 | 80.27 |
| greywall | noop | 30 | 30 | 1790.71 | 1859.3 | 0.0 |
| greywall | python | 30 | 30 | 1929.33 | 1974.7 | 0.0 |
| greywall | git | 30 | 30 | 1939.47 | 1978.57 | 8.43 |
| greywall | reads | 30 | 30 | 1801.52 | 1844.04 | 10.97 |
| greywall | writes | 30 | 30 | 2670.56 | 3418.44 | 859.39 |
| greywall | spawn | 30 | 30 | 1930.85 | 2014.77 | 135.9 |
| greywall | cpu | 30 | 30 | 1869.85 | 1910.6 | 80.16 |
| mxc | noop | 30 | 30 | 23.57 | 42.05 | 0.0 |
| mxc | python | 30 | 30 | 171.96 | 224.25 | 0.0 |
| mxc | git | 30 | 30 | 171.99 | 224.95 | 8.47 |
| mxc | reads | 30 | 30 | 39.66 | 39.96 | 10.69 |
| mxc | writes | 30 | 30 | 923.08 | 2975.86 | 866.8 |
| mxc | spawn | 30 | 30 | 172.02 | 225.41 | 134.56 |
| mxc | cpu | 30 | 30 | 121.84 | 123.73 | 80.27 |
| ukai | noop | 30 | 30 | 232.0 | 1747.7 | 0.0 |
| ukai | python | 30 | 30 | 370.99 | 448.9 | 0.0 |
| ukai | git | 30 | 30 | 382.15 | 567.81 | 9.73 |
| ukai | reads | 30 | 30 | 249.76 | 2050.47 | 11.43 |
| ukai | writes | 30 | 30 | 522.35 | 3271.04 | 236.08 |
| ukai | spawn | 30 | 30 | 433.08 | 993.4 | 198.05 |
| ukai | cpu | 30 | 30 | 310.09 | 412.86 | 80.19 |
| ukai-obs-off | noop | 0 | 0 | None | None | None |
| ukai-obs-off | python | 30 | 30 | 363.5 | 449.77 | 0.0 |
| ukai-obs-off | git | 30 | 30 | 375.19 | 472.45 | 8.37 |
| ukai-obs-off | reads | 30 | 30 | 246.84 | 1687.26 | 11.01 |
| ukai-obs-off | writes | 30 | 30 | 1108.01 | 3112.95 | 860.01 |
| ukai-obs-off | spawn | 30 | 30 | 368.78 | 490.5 | 139.97 |
| ukai-obs-off | cpu | 30 | 30 | 314.37 | 2044.36 | 80.27 |

## mac native

| tool | case | n | ok | median | p95 | work median |
|---|---|---:|---:|---:|---:|---:|
| direct | noop | 30 | 30 | 2.62 | 3.41 | 0.0 |
| direct | python | 30 | 30 | 34.0 | 36.41 | 0.0 |
| direct | git | 30 | 30 | 44.78 | 46.71 | 10.02 |
| direct | reads | 30 | 30 | 21.47 | 24.39 | 18.8 |
| direct | writes | 30 | 30 | 49.62 | 52.9 | 47.1 |
| direct | spawn | 30 | 30 | 147.75 | 151.33 | 144.98 |
| direct | cpu | 30 | 30 | 21.39 | 24.43 | 18.72 |
| mxc | noop | 30 | 30 | 16.74 | 24.08 | 0.0 |
| mxc | python | 30 | 30 | 1768.69 | 1814.22 | 0.0 |
| mxc | git | 30 | 30 | 3440.04 | 3497.25 | 1691.01 |
| mxc | reads | 30 | 30 | 58.28 | 61.09 | 19.19 |
| mxc | writes | 30 | 30 | 100.79 | 102.46 | 47.78 |
| mxc | spawn | 30 | 30 | 199.6 | 211.3 | 142.91 |
| mxc | cpu | 30 | 30 | 58.59 | 60.67 | 18.58 |

## vps container

| tool | case | ok | median |
|---|---|---:|---:|
| docker-fresh | noop | 30 | 255.45 |
| docker-fresh | python | 30 | 295.51 |
| docker-fresh | git | 30 | 337.48 |
| docker-fresh | reads | 30 | 269.09 |
| docker-fresh | writes | 30 | 368.23 |
| docker-fresh | spawn | 30 | 325.35 |
| docker-fresh | cpu | 30 | 280.07 |
| docker-warm | noop | 30 | 59.78 |
| docker-warm | python | 30 | 99.3 |
| docker-warm | git | 30 | 106.59 |
| docker-warm | reads | 30 | 68.37 |
| docker-warm | writes | 30 | 135.84 |
| docker-warm | spawn | 30 | 128.39 |
| docker-warm | cpu | 30 | 83.56 |
| openshell-fresh | noop | 30 | 869.22 |
| openshell-fresh | python | 30 | 889.46 |
| openshell-fresh | git | 30 | 926.24 |
| openshell-fresh | reads | 30 | 886.33 |
| openshell-fresh | writes | 30 | 958.02 |
| openshell-fresh | spawn | 30 | 894.57 |
| openshell-fresh | cpu | 30 | 881.16 |
| openshell-warm | noop | 30 | 67.02 |
| openshell-warm | python | 30 | 111.53 |
| openshell-warm | git | 30 | 117.7 |
| openshell-warm | reads | 30 | 96.75 |
| openshell-warm | writes | 30 | 178.19 |
| openshell-warm | spawn | 30 | 146.42 |
| openshell-warm | cpu | 30 | 90.09 |

## pi container

| tool | case | ok | median |
|---|---|---:|---:|
| docker-fresh | noop | 30 | 993.23 |
| docker-fresh | python | 30 | 1173.37 |
| docker-fresh | git | 30 | 1266.82 |
| docker-fresh | reads | 30 | 1049.83 |
| docker-fresh | writes | 30 | 1427.77 |
| docker-fresh | spawn | 30 | 1152.69 |
| docker-fresh | cpu | 30 | 1078.42 |
| docker-warm | noop | 30 | 151.07 |
| docker-warm | python | 30 | 285.41 |
| docker-warm | git | 30 | 319.32 |
| docker-warm | reads | 30 | 164.75 |
| docker-warm | writes | 30 | 1019.17 |
| docker-warm | spawn | 30 | 288.07 |
| docker-warm | cpu | 30 | 231.08 |

## mac container

| tool | case | ok | median |
|---|---|---:|---:|
| docker-fresh | noop | 30 | 222.61 |
| docker-fresh | python | 30 | 239.88 |
| docker-fresh | git | 30 | 241.94 |
| docker-fresh | reads | 30 | 219.61 |
| docker-fresh | writes | 30 | 249.32 |
| docker-fresh | spawn | 30 | 231.98 |
| docker-fresh | cpu | 30 | 233.1 |
| docker-warm | noop | 30 | 28.42 |
| docker-warm | python | 30 | 48.45 |
| docker-warm | git | 30 | 52.74 |
| docker-warm | reads | 30 | 34.15 |
| docker-warm | writes | 30 | 58.42 |
| docker-warm | spawn | 30 | 49.1 |
| docker-warm | cpu | 30 | 56.95 |
| openshell-fresh | noop | 30 | 597.82 |
| openshell-fresh | python | 30 | 581.39 |
| openshell-fresh | git | 30 | 576.6 |
| openshell-fresh | reads | 30 | 594.96 |
| openshell-fresh | writes | 30 | 619.86 |
| openshell-fresh | spawn | 30 | 591.08 |
| openshell-fresh | cpu | 30 | 575.64 |
| openshell-warm | noop | 30 | 54.26 |
| openshell-warm | python | 30 | 74.11 |
| openshell-warm | git | 30 | 82.35 |
| openshell-warm | reads | 30 | 78.1 |
| openshell-warm | writes | 30 | 96.95 |
| openshell-warm | spawn | 30 | 80.32 |
| openshell-warm | cpu | 30 | 77.66 |

