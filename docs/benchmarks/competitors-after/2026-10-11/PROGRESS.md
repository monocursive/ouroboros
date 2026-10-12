# Startup and file denial follow-up

User requested an Ouro file-denial fix, lower startup overhead with isolation
and observation preserved, and the same benchmark rerun with before/after data.

Original evidence is immutable at ../../competitors/. Original source HEAD:
c364e3cb3678eb9120901f71bf3881d85e3c4911. Work remains uncommitted.

Implemented: separate directory and file denial masks. File masks use empty
data descriptors, bubblewrap --perms 000 --ro-bind-data, and mount after grants.
Nested denials already covered by an ancestor mask are omitted. No source file
is opened for contents or changed. Namespace status probes share one fresh
sandbox in a measurement call; each user/PID/network result retains its checks.
No persistent capability cache, reduced observation, or skipped settlement.

VPS Linux release unit suite: 564 pass, 2 ignored. File denial regression passes
for RO and RW parents; checks direct and symlink reads, writes, truncation, chmod,
original contents, actual RO mount receipt and empty lifetime. Full Linux Jail
tests are compiling/running serially. Pi release build underway. Local portable
unit suite: 267 pass, 1 ignored; local Clippy passes, Linux lint still pending.

Initial full-test invocation from plain SSH stopped in conformance_j1: host
AppArmor status differs from the pinned reference manifest (previous benchmark
setup set restriction=0); s11 compared a CLI auto-scoped receipt with the
unscoped test process's unavailable cgroup. The original binary fails the same
s11 assertion. Repository-standard `systemd-run --user --scope` passes s11.
Full tests now run serially in that scope with only the host-manifest assertion
excluded; original failures are retained. Capture actual doctor reports for
both binaries; do not claim pinned-reference conformance or release readiness.

Full scoped VPS run completed and retained every result. Additional failures:
linux_mechanisms' pinned host status assertion also expects AppArmor restriction
on; unix_peer_linux expects nested namespaces unavailable while this provisioned
host allows them; two portable_release_evidence checks correctly reject saved
preview evidence as stale for changed source. No runtime assertion was relaxed.
Final source comments were synchronized after that run. Rebuild hit ENOSPC;
only this follow-up's 70 completed test executables were removed (502,882,616
bytes), with names/sizes/hashes saved in build-cache-cleanup.json. Final build,
Linux Clippy, units and file regression are being checked on both architectures.
Original unrelated caches/data are untouched by this cleanup.

Parent-only strace profiles preserve original Ouro runs at profiles/vps-before.
Never trace children owned by Ouro's tracer. Profiles are diagnostic, excluded
from performance claims. Final Linux performance rerun adds an interleaved old
Ouro binary arm (same policies and observation) to control for host/time drift.
All original seven workloads, 30 samples and 3 warmups remain. Original full
agent and container protocols will also rerun with their versions/models pinned.

Remote follow-up roots: ~/bench-ouro-after, distinct from ~/bench-ouro. Existing
logins remain authorized. Mac native pipeline PID 17678, started with isolated
result and fixture directories; original artifact trees untouched. Temporary
services will be stopped after all capture. Original auth/keys are used only on
the hosts and excluded/redacted by the evidence exporter.

Final VPS source: build/Clippy/564 units pass; all 46 review_linux tests pass.
Final Pi source: Clippy/564 units pass; file denial regression passes. Doctor
capability statuses are identical before and after on VPS and Pi. Native Linux
benchmark PIDs: VPS 2715866, Pi 275490. Mac native 54 small + 9 workflow complete;
its container+feature+unchanged offline VM diagnostic pipeline is now starting.
VPS installed hashes: after 3829f0f215f51d79cfbc95062670bff5fb9c6aeb7457996f1826a305988d800c;
before 369031ec48662e0a0e4f3ecf7e40912ef4292f7b15ecd0e1b545b49ea29c0d69.
Own completed VPS target cache (614313962 bytes) removed after installed binary
hash equality checks, following the earlier recorded test-executable cleanup.
No compiler or intrusive tests run during measured benchmark phases.

Mac container startup hit a duplicate imported-provider-profile error before any
agent or measurement ran; retained as results/container-after plus pipeline log.
Same existing profiles/Anthropic provider are reused; fresh Codex provider
benchmark-codex-after created from authorized still-valid cache, expiry updated
before refresh configuration. Selected Mac container dataset is now
container-after-v2 (with setup already prepared), pipeline-v2.log. No scored
failures retried. New image tag keeps the earlier image reference distinct;
runner includes CSV source snapshots, the earlier recorder limitation.

Fixed-work timings complete on VPS/Pi with no invalid sequences. Final paired
analysis at analysis/paired. Strict observation, attached ptrace, enforced
containment, identical policy digests, and 30 valid samples per arm/case verified.
No-op medians: VPS old 138.6ms -> after115.7ms; Pi old321.7ms -> after288.6ms.
Pi writes have broad SD variance: after median worse, paired change interval
includes zero; retain/report rather than rerun for a desired result.

Linux native setup error: new client symlinks chained through before/bin, which
was ungranted when that client’s real install is elsewhere (VPS Claude/OpenCode,
Pi OpenCode). All ENOENT rows are setup-invalid, not product results. VPS pilot
interrupted with only its runner/current owned child group signalled; pid record
at native-after/pilot-interruption.json. Client links normalized directly to the
original canonical installs; no file bytes or policy grants widened. VPS now
reruns all agents at native-after-v2/workflow-after-v2, PID2775273. Pi Claude and
Codex regular-file installs are valid in native-after/workflow-after; after that
pipeline finishes, normalize links and rerun all OpenCode modes separately at
native-opencode-v2/workflow-opencode-v2. Do not change links during measured work.

Mac container after-v2 running (54 tasks), all first 48 pass. Gateway after PID
recorded at results/gateway-start.json; pipeline PID35185. Later workflow, fixed
container work, limits/filesystem/egress probes and 12 unchanged preview VM
diagnostics follow sequentially. Original container setup-error pilot retained.

Continuation checkpoint: VPS native-after-v2 all72 and workflow-after-v2 all12
pass. Its Grey rule probe finished; private proxy store stopped, compressed,
verified and plaintext removed, preserving a0600 archive on host. Completed source
checkout offloaded to archives/vps-build-source.tar.gz; all7893 file hashes matched
before removal, inventory and removal evidence retained. Original before10192
manifest files and archive digest verified unchanged. Current secret audit finds
zero actual benchmark credentials in10822 items (including source archive).
VPS container start stopped before tasks on missing after/bin/openshell-gateway;
restored direct links to unchanged /usr/bin executables, layout hashes recorded.
Container resume PID2804018; first8/18 Claude small tasks passed. Pi after original
72+12 finished; OpenCode corrected24 in progress (19 passed), then4 workflows and
container pipeline follow. link_container_tools.py runs only when that native
phase has ended. Mac all runs/extra probes complete, exported/imported1433 files,
archive SHA1ab2c613d60ffd2de1de002de6ee15b1328efd9c7854f0704e1cf6466b3f5f7c;
services stopped. Mac native30/54 and workflows5/9; known Grey/MXC-Codex failures;
container54/54 and workflows9/9; VM12 diagnostics valid.
Final selectors/report/receipt/journal/credential verification scripts prepared,
not yet run across all hosts. Wait for Linux finish/export, import, then select,
verify, generate report/comparison tables, archive/checksums, final git audit.

Later checkpoint: Pi warm availability first attempts were setup-invalid because
bench-pi-after-${agent} names exceed OpenShell's19-char limit. Cold/default-name
Pi launches reproduce actual ControlSupervisorStartFailed errors (~8s), Docker
controls pass. Preserve name-invalid script and availability dataset. Followup
PID351447 waits for initial post pipeline338348; restarts same gateway, corrected
short-name3 startup checks at container-warm-availability-v2, adds warm tasks only
if actual ready, preserves phase1 snapshots/initial archive then reexports. Final
selector uses v2 availability and can include any available warm lane.
VPS Claude18+3 and OpenCode18+3 containers all pass. Codex build before tasks hit
ENOSPC on redundant chmod copy-up of large binaries. Invalid directory/log saved
as container-after-codex-build-invalid; old harness copyup variant preserved.
New builder asserts exact a+rX input permissions and omits redundant chmod; no
bytes or runtime modes change. Only failed build container84eaa7223eaf and own
untagged intermediates998149bf1ea8/3707554db23f removed; Docker cascading removal
of parent caused initial cleanup helper IndexError (no tasks ran); retry handles
already removed IDs and records all queries. VPS resumePID3142583 starts Codex
18+3, then perf/features/export. Before images remain tagged and retained.
Run spans October11-12 local time; directory retains start date, UTC rows exact.

FINAL: All three hosts complete. VPS exportc53e175ca3e982c58a525bfe6f33590c92a7371649291b747c3af8ee39afda58
3065 files/718 journals; corrected Pi exportf827fcd449d93026e0d57b0f34b72eb690f4dc84ecbe9a62c4a07697e426dbf0
2536 files/744 journals; Mac1433 files/no native Ouro journals. All1462 referenced
journals retained, all7034 manifest files verified, temporary services stopped.
Corrected Pi warm checks reproduce runtime ControlSupervisorStartFailed for all3
clients. Selected198 native +144 container small-task calls +57 workflows =399;
154 performance buckets, all30/30 valid =4620 samples. Audit covers40 datasets.
All42 selected native Ouro coding receipts strict/attached/settled, no declared
class gaps.14 Claude receipts retain baseline audit-only path_claim_unverified
diagnostics; same type before, counts model-dependent, not counted event loss.
The840 paired old/new performance samples have no observer gaps.
All4 exact tested Ouro binaries retained locally and hash-verified against doctor.
Report/comparison CSVs complete; final source still only4 product files modified,
no commit/push. Bundle/checksums and final credential audit finish delivery.
