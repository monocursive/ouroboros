# Credential lifecycle follow-up: methods

This follow-up compares the sealed 12 October vault evidence with a new Ouro
runtime. The tasks, hidden checkers, clients, models, flags, seeded schedules,
wall budgets and observation requirements are unchanged. The prior evidence
is preserved in `../2026-10-12`; its 1,706 manifest members were verified before
this run. Competitor results are retained from the earlier comparison, rather
than described as new competitor runs.

The final candidate adds supervisor OAuth refresh, live source leases, URL path
and executable binding, and a verified RFC6455 upgrade. The Linux syscall
filters, observer plan, coverage classes, protected coverage and network
allowlist are compared against each corresponding baseline receipt. Independent
100 ms exposure sampling remains enabled for client calls. Online elapsed times
therefore include provider variability and sampling; they are descriptive, not
causal sandbox performance measurements.

There are 18 small calls and three inventory workflows per Linux host. Claude
Code 2.1.295, OpenCode 1.19.0 and Codex 0.159.2 have the same executable hashes
as the baseline. The manually installed Pi Claude executable originally had
mode 0775. A byte-identical regular copy with mode 0755 is used in the new
private benchmark bin directory: executable binding refuses group/other writable
objects. `results/pi/installation.json` records this installation difference.
No executable safety rule was relaxed.

Two offline controls run before model calls: the byte-identical environment
versus vault harness from 12 October, and an additional randomized comparison
of the old and new Ouro executables with exactly the same static vault policy.
Each control has three warmup pairs and 30 measured pairs per host. The former
uses seed 20261012; the latter uses seed 20261013. Paired median differences,
10,000 bootstrap resamples, failed attempts and all receipts are retained.
Neither control includes a model call or exposure sampler.

Eight existing boundary checks per host are rerun unchanged. Fourteen additional
real-jail checks use synthetic credentials and an explicit plaintext loopback
fixture. They exercise native executable binding, a wrong executable claiming a
PID in HTTP, exact/segment path restriction, escaped path refusal, active source
rotation, streamed-response deletion, missing-source preexec refusal, idle
refresh, concurrent refresh ownership, invalid grants, pending-grant refusal and
deleting the source during issuer exchange. A separate unit fixture verifies
full-duplex WebSocket traffic and its revocation. Live revocation checks report
delete-to-attempt-settlement time; they do not claim a hard real-time limit.

The source lease and initiating process are checked at release and at 100 ms
intervals while a connection remains live. Executable identity comes from a
pidfd and kernel `/proc/PID/exe` captured by the seccomp mediator, then matched to
the sealed bridge connection. Child HTTP headers do not supply that authority.
Socket delegation by an allowed program is not per-byte attribution.

Refresh sources are private 0600 single-link token documents outside every
child grant. The child receives only an attempt placeholder and account routing
metadata. Refresh requests use the pinned issuer endpoint and public client ID;
OpenAI's encoding is JSON as in the pinned Codex source. A persisted pending
marker is written before submitting a rotating grant. An uncertain request is
never automatically replayed, and concurrent attempts fail closed. Successful
rotation must be persisted before release. Natural provider expiry is distinct
from the explicit forced-expiry metadata diagnostic.

Failed configuration/transport pilots and partial prefixes remain in the raw
export, with their own harness snapshots and binary provenance. They are not
substituted into the final scored cohort. The first real-provider refresh pilot
failed after submission; it is retained as a failure. The initial parallel Pi
unit run had a bridge timing failure; its isolated rerun and complete serial
suite are retained alongside it. The access-only Codex WebSocket diagnostic is
explicitly unscored and performs no refresh request.

Final binaries are bound to the measured build input digest and their exact
SHA-256 hashes. Benchmark builds have unknown revision/cleanliness claims and
are not presented as clean release builds. The exact 123 build inputs are saved
in `archives/candidate-build-inputs.tar.gz`. Scoped tests and benchmarks do not
substitute for the full provisioned reference-host conformance job or its
validated freeze record.

Exports exclude private credential sources, login caches, vendor state, build
caches and repositories. Sanitization includes current and historical auth
values. Every retained file has a hash manifest; all referenced attempt journals
must be exported. Exact credential and pattern audits precede final sealing.
