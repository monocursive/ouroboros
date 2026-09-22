# J2: nondelegated SSH-session measurement

Measured 2026-09-22 as `ouro-ci@37.59.114.70`, using the J2 development binary.
`/proc/self/cgroup`: `0::/user.slice/user-1001.slice/session-818.scope`.
Each case used a separate private state/workspace, a Python target writing a
marker, a canonical receipt, and a 15-second driver deadline.

| Observe | PID request | Exit | Phase | Marker | Applied pids |
|---|---|---|---|---|---|
| on | preferred default 256 | 0 | settled | present | false; mechanism/scope/hit null |
| on | explicit 256 | 125 | refused | absent | no boundary created |
| off | preferred default 256 | 0 | settled | present | false; mechanism/scope/hit null |
| off | explicit 256 | 125 | refused | absent | no boundary created |

Both explicit cases reported `missing_capability` at `probing`, remediation
`host_setup`, requirement `limit:pids`, reason `cgroup_unavailable`. The driver
asserted exit status, marker existence, and the preferred-limit receipt fields.
The corresponding delegated cases run in `conformance_j2` through the full
conformance driver.
