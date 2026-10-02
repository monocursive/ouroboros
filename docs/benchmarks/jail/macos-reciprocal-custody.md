# Native macOS reciprocal custody — 2026-09-30

Two independent Endpoint Security custodians cleaned up the seven known fixture
processes after either custodian died or stopped responding. The original
single-custodian failure is addressed for these controlled cases. **The full
lifetime gate remains open:** killing both custodians left every known fixture
process running. With fail-closed `AUTH_EXEC` enabled, those survivors could
still execute a new command after both clients disappeared.

This is development evidence for a native mechanism, not a production backend
or a claim that an arbitrary process tree is empty. `ouro-jail run` remains
unsupported on macOS. Apple's [existing entitlement request](endpoint-security-request.md)
is reused; no new request, identifier registration or host provisioning was made.

## Implementation and boundaries

[macos_es_pair.c](macos_es_pair.c) runs a guardian and its ward. Each creates
its own macOS 27 `es_new_descendants_client`, subscribes before releasing its
direct child, and independently observes workload fork, exec and exit events.
Children start suspended. Release and cleanup use kernel audit tokens with PID
versions. A lost control pipe or a 750 ms heartbeat lapse triggers cleanup;
newly observed members are also killed during teardown. The parent observes its
ward; the ward observes the workload. Neither client's membership table is
populated from the other's logs.

The custody pipe descriptors are private to the custodians and closed on
workload exec. Reserved descriptors 198 and 199 are absent in all seven fixture
processes. This checks the custody channel, not every possible inherited
descriptor. A Seatbelt signal policy denies the workload's SIGTERM and SIGKILL
attempts against both custodians: all 800 attempts in the main series returned
`EPERM`.

The optional `--auth-exec` lane subscribes both clients to `AUTH_EXEC`, responds
without caching, configures and reads back `ES_DEADLINE_MISS_MODE_FAIL_CLOSED`,
and sets a 250 ms maximum deadline. Integrity loss or teardown changes the
client's exec response to deny. Apple's
[deadline-mode API](https://developer.apple.com/documentation/endpointsecurity/es_set_deadline_miss_mode(_:_:))
describes denial on deadline/queue loss; it does not document retaining
enforcement after both clients die. This distinction was tested.

[macos_es_pair.py](macos_es_pair.py) validates independent observations, injects
faults, snapshots birth identities before cleanup, and then performs separately
verified emergency cleanup. It returns **125 even after a completed series**,
because the production lifetime gate has not passed. A missing entitlement
returns 125 before spawning the ward, opening workload logs or executing a
requested `touch` marker. No successful production receipt is emitted.

The filesystem policy allows ordinary accesses; it isolates signal custody
only. These trials do **not** evaluate filesystem containment, proxying, Mach
services, all inherited descriptors, resources or shared observer coverage.

## Environment

The retained `ouro-jail-es-dev` Tart VM ran macOS 27.0 build 26A428 with SDK 27.0,
four virtual CPUs and 8 GiB RAM. The guest was already SIP-disabled, retained
authenticated root, and ran ad-hoc ES helpers as UID 501 without an approved
Apple profile or signing key. Host SIP remained enabled. Guest Ethernet was
disabled; `en0` had no IP address and no default route. No host files, clipboard,
USB devices, credentials or signing keys were shared. The VM was stopped afterward.

[Guest settings](results/macos-es-pair-2026-09-30/guest-settings.txt) and
[host SIP](results/macos-es-pair-2026-09-30/host-sip.txt) are retained. Repeat the
gates with normal SIP and an approved signature/profile before native support
is advertised. The [protected-host refusal](results/macos-es-pair-2026-09-30/host-refusal.json)
and a separate check rejecting `--development-vm` on the host both passed.
The [supplied Mac control](results/macos-es-pair-2026-09-30/remote-mac-refusal.json)
also refused before spawning on macOS 27.0.1 build 26A434 with SIP enabled.
Only the six research sources were transferred; its temporary build directory
was removed after the result was collected.

## Results

Two complete series contain ten repetitions of each of ten cases: **200 trials**.
The fixture includes a normal child, SIGTERM-resistant child, `setsid` child,
double-fork daemon, separate `posix_spawn` group/session children, and its root.
Each case starts after both clients have observed all seven kernel identities.
Integrity faults are synthetic; actual dropped events and unobserved forks
remain open tests.

| Case | Notify: known fixture empty | AUTH_EXEC: known fixture empty | AUTH observation p50 / p95 |
| --- | --- | --- | --- |
| Three-second wall expiry | 10/10 | 10/10 | 3071.95 / 3164.41 ms |
| Cancellation | 10/10 | 10/10 | 30.89 / 32.07 ms |
| Workload-root SIGKILL | 10/10 | 10/10 | 310.76 / 457.14 ms |
| Guardian SIGKILL | 10/10 | 10/10 | 126.67 / 139.66 ms |
| Ward SIGKILL | 10/10 | 10/10 | 121.35 / 137.06 ms |
| Guardian SIGSTOP | 10/10 | 10/10 | 815.69 / 893.19 ms |
| Ward SIGSTOP | 10/10 | 10/10 | 861.49 / 963.98 ms |
| Synthetic guardian integrity fault | 10/10 | 10/10 | 30.56 / 34.60 ms |
| Synthetic ward integrity fault | 10/10 | 10/10 | 36.82 / 135.45 ms |
| Both custodians SIGKILL | **0/10** | **0/10** | 706.70 / 767.54 ms; survivors |

Observation timings include independent snapshots and waiting for the surviving
custodian's drain. They begin after fixture readiness and the fault request,
not at launch. Wall timings are therefore not the exact applied workload wall
budget. Pause timings include the 750 ms heartbeat limit. These are VM mechanism
measurements on a working developer host, not a sandbox performance comparison.
With ten samples, p95 is the maximum observed value.

With AUTH enabled, the paused-guardian exec probe created **0/10 markers**
(observation p50/p95 350.44/391.05 ms); the paused-ward probe also created **0/10**
(346.94/436.26 ms). `posix_spawn` returned zero, but every child was reaped with
SIGKILL before completing `touch`. Completed work, not spawn's return code,
determines that outcome. After both clients died, the same probe created
**10/10 markers**, returned success and was reaped normally (83.68/129.20 ms).
All seven original fixture processes remained alive with advancing heartbeats
at snapshots more than half a second after the kill. Emergency cleanup follows
these snapshots and never counts as custody proof.

Synthetic faults retain `gap=true` and integrity refusal even when the known
fixture was cleaned up. ES synchronization and an observed member count are not
promoted to complete tree proof. No `tree_empty=true` receipt is issued.

The [original single-custodian regression](results/macos-es-pair-2026-09-30/original-regression.json)
retained its four outcomes, including survivors after custodian death. Its
[original refusal path](results/macos-es-pair-2026-09-30/original-refusal.json)
also passed. An independent final [cleanup audit](results/macos-es-pair-2026-09-30/cleanup-audit.json)
found no live survivors among 2,196 recorded fixture/custodian birth identities
from completed records and retained failure diagnostics.

## Reproduce and inspect

Copy only the six files named in `source_sha256` into the isolated VM described
in [the development runbook](macos-development.md). Choose fresh output paths:

```sh
python3 macos_es_pair.py --development-vm --out /tmp/pair-notify --samples 10
python3 macos_es_pair.py --development-vm --auth-exec --out /tmp/pair-auth --samples 10
```

On an approved, normally protected development Mac, omit `--development-vm` and
use `--identity` plus `--profile` as in the original runbook. Approval does not
resolve the simultaneous-loss counterexample.

Raw [notify results](results/macos-es-pair-2026-09-30/notify/results.json) and
[AUTH_EXEC results](results/macos-es-pair-2026-09-30/auth/results.json) include
both event streams, independent snapshots, custody identities, signal attacks
and cleanup outcomes. Each lane includes its exact tested sources.
[Post-run hashes](results/macos-es-pair-2026-09-30/after-hashes.json) matched the
helpers and sources; both signatures verified again after testing.
The [evidence validator](macos_es_pair_summary.py) checks those hashes, complete
trials, independent membership, executed work, integrity flags, cleanup and the
simultaneous-loss counterexample. Its 11 regression tests reject misleading
support claims or incomplete/tampered data. Validated summaries:
[notify](results/macos-es-pair-2026-09-30/notify/summary.json),
[AUTH_EXEC](results/macos-es-pair-2026-09-30/auth/summary.json).

Diagnostics are retained, including two corrected test-oracle failures:
[reading settlement before the peer's final drain](results/macos-es-pair-2026-09-30/diagnostics/read-before-drain/results.json)
and [treating spawn success as executed work](results/macos-es-pair-2026-09-30/diagnostics/spawn-oracle/failure.json).
Corrected complete series are separate; no failing diagnostic was silently
removed or counted as a successful production gate.

## Implementation decision

Reciprocal custody is useful evidence for one custodian's failure. It has not
been selected as the production lifetime mechanism. Enabling macOS execution
still requires custody covering simultaneous client loss and real event loss,
bounded concurrent-fork teardown, a complete final drain, actual PID reuse and
sleep/wake behavior. Containment, resources, observer mapping and real
Node/shell/Git/agent compatibility also remain open. Those gates must pass under
normal protection and an approved signature. The Rust macOS refusal backend
and frozen Linux backend remain unchanged.
