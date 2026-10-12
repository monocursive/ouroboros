# Measured feature follow-up

The unchanged [original feature comparison](../../competitors/feature-matrix.md)
contains documented interfaces, backends, default policies and their scope. This
table records the exercised behavior in this rerun. It supersedes the original
Ouro regular-file-denial failure. Product versions and host provisioning are the
same; competitor sources were not patched.

| Exercised behavior | Ouro after | Greywall/Greyproxy | OpenShell | MXC |
|---|---|---|---|---|
| Denied regular file inside a visible parent | Fixed; RO and RW parent regression, mode 000 read-only mask, original contents unchanged | Original parent denyWrite/child denyRead precedence issue reproduced separately | RO workspace policy tested with writable Docker positive control | Denied paths enforced in tested native backends |
| Denied directory and symlink/hardlink canaries | VPS/Pi deny; same statuses as interleaved old binary | Linux parent denyWrite configuration still permits denied reads; minimal-rule diagnostic retained | Separate container path policy, not native host-file aliases | Native Linux/Mac deny these canaries |
| Host TCP and signal canaries | VPS/Pi deny; unchanged old/new | Linux deny | Default-policy host egress blocked where runtime reaches payload; Docker controls reachable | Native deny |
| Explicitly visible Unix socket | Ouro denies connection in tested tool policy | Linux connection allowed | Different container boundary; not this host-path probe | Linux connection allowed; Mac denied |
| Descendant after root exit | VPS/Pi heartbeat stops, receipts settle empty tree | Linux heartbeat stops; Mac syntax refusal | Retained sandbox lifecycle is explicit; delete is separate from exec return | Linux stops; Mac heartbeat persists after wrapper return under Seatbelt |
| Wall/PID ceilings | Original finite requests and actual cgroup readbacks retained | No product resource ceiling configured | Separate exec/lifecycle deadlines, bounded benchmark guard | Configured 1000ms process timeout |
| Explicit memory/CPU ceilings | VPS enforces; Pi missing memory controller causes refusal, never silently unbounded | No common ceiling interface in this test | VPS/Mac matched Docker controls; Pi availability reported separately | No common ceiling in these native backends |
| Explicit storage/inode ceiling | Unbounded shared workspace refuses request; unchanged | No ceiling configured | No common interface tested | No common interface tested |
| Observer and evidence | Strict on, attached ptrace/linux-closed-v1, declared coverage unchanged with no class gaps; all 1000 expected writes observed per measured write run. Claude coding retains baseline audit-only unverified-path diagnostics | Proxy decisions/transactions; privileged eBPF remains untested | Gateway/supervisor logs; different durability model | Executor diagnostics; platform-specific audits outside this scope |
| Clients | All Linux Ouro small tasks and workflows pass | All Linux small tasks pass; workflow outcomes retain model/turn-limit failures; Mac syntax refusal | VPS/Mac all three clients exercised; Pi startup failure retained | Linux all three; Mac Claude/OpenCode pass, Codex CFPreferences failure |
| Native Mac Ouro | Unsupported; unchanged offline VM preview remains a separate diagnostic | macOS 27 syntax issue unchanged | Linux ARM64 Docker through OrbStack | Seatbelt |

Connecting to an explicitly visible Unix socket is not an ungranted path escape.
Buffered file workloads do not use fsync. Lower startup medians do not prove a
faster disk, complete exploit resistance, release readiness or stronger coverage
than the observer declares. No default memory/CPU/storage/inode cap was added.

Raw native feature results are in each host's `perf-after/summary.json`,
`resource-after/resources.json`, `backing-after/backing.json` and
`grey-rules-after/rules.json`. Container limits, filesystem and egress probes
are in the corresponding `container-*-after` datasets. The paired analysis checks
the old/new native safety statuses and all declared receipt coverage. See
[README](README.md), [METHODS](METHODS.md) and [evidence verification](analysis/final/evidence-verification.json).
