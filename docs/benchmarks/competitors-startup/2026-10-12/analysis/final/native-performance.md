# Native launch plus work

Median / p95 milliseconds. Container lifecycle timings live separately in performance.csv. Scored old/new Ouro has strict observation enabled. All detailed inputs, counts/checksums and sources are retained.

## vps

| Work | Direct | MXC | Ouro before | Ouro final | Greywall |
|---|---:|---:|---:|---:|---:|
| noop | 1.0 / 2.1 | 20.0 / 22.8 | 114.4 / 133.8 | 94.2 / 102.2 | 1609.2 / 1660.5 |
| python | 40.4 / 54.1 | 68.4 / 70.5 | 150.5 / 175.3 | 131.2 / 162.3 | 1638.2 / 1698.1 |
| git | 44.2 / 54.4 | 68.5 / 71.9 | 158.5 / 186.2 | 134.8 / 158.9 | 1640.5 / 1720.2 |
| reads | 5.9 / 7.9 | 21.0 / 38.1 | 121.4 / 139.6 | 96.6 / 112.0 | 1612.2 / 1692.7 |
| writes | 106.9 / 122.7 | 119.6 / 169.6 | 294.9 / 313.7 | 270.4 / 295.7 | 1701.7 / 1787.2 |
| spawn | 75.4 / 80.4 | 118.5 / 120.4 | 223.4 / 250.4 | 206.7 / 218.3 | 1677.0 / 1787.8 |
| cpu | 25.6 / 28.4 | 68.3 / 70.4 | 137.3 / 160.6 | 118.9 / 135.6 | 1620.0 / 1700.1 |

## pi

| Work | Direct | MXC | Ouro before | Ouro final | Greywall |
|---|---:|---:|---:|---:|---:|
| noop | 1.9 / 2.1 | 23.6 / 23.8 | 283.4 / 354.4 | 229.7 / 282.8 | 1792.7 / 1836.0 |
| python | 138.2 / 139.6 | 172.1 / 224.7 | 423.9 / 495.1 | 381.7 / 486.3 | 1933.2 / 1980.3 |
| git | 147.4 / 182.0 | 172.1 / 224.1 | 434.3 / 480.1 | unavailable | 1936.2 / 1980.6 |
| reads | 12.8 / 19.9 | 39.8 / 40.4 | 292.1 / 359.3 | 250.9 / 343.6 | 1805.2 / 1871.0 |
| writes | 867.5 / 1984.0 | 923.1 / 2024.6 | 672.3 / 2422.1 | 501.2 / 2426.8 | 2677.6 / 4586.9 |
| spawn | 136.2 / 182.7 | 172.0 / 224.4 | 486.7 / 637.4 | 432.5 / 577.5 | 1926.2 / 1973.3 |
| cpu | 82.2 / 82.5 | 121.9 / 122.4 | 356.3 / 451.8 | 311.6 / 426.7 | 1873.7 / 1954.5 |

## mac

| Work | Direct | MXC | Ouro before | Ouro final | Greywall |
|---|---:|---:|---:|---:|---:|
| noop | 2.8 / 3.6 | 17.0 / 23.9 | unavailable | unavailable | unavailable |
| python | 34.1 / 36.0 | 1765.5 / 1781.2 | unavailable | unavailable | unavailable |
| git | 44.3 / 46.5 | 3441.2 / 3504.1 | unavailable | unavailable | unavailable |
| reads | 22.2 / 26.2 | 58.1 / 60.5 | unavailable | unavailable | unavailable |
| writes | 50.2 / 56.7 | 100.5 / 102.6 | unavailable | unavailable | unavailable |
| spawn | 147.1 / 152.0 | 197.4 / 220.5 | unavailable | unavailable | unavailable |
| cpu | 21.3 / 23.1 | 58.9 / 61.3 | unavailable | unavailable | unavailable |
