# Jail implementation and execution evidence — 2026-09-28–29

This is an uncommitted implementation against `dev` at
`2c8f28dcda4bc60b2e5ba51b2f8f9d7c93bf5bfa`. The binaries' build-input digests
identify the tested source. This report does not claim a published release,
a clean-revision conformance freeze, or a working native macOS jail.

The [2026-09-29 follow-up](followup-2026-09-29.md) records the complete regression
rerun, new live boundary cases and K17 phase measurements, including any failed
attempts and their corrections.

## Implemented

The existing jail now has hardened operator profile loading, `none` config
isolation, supervisor/backend writable-root guards, descriptor-based backend
execution, compat `clone3` refusal, resolver sanitization, protected scan
revalidation, pseudo-filesystem root checks, cross-device alias checks and
updated syscall denials. Exec confirmation carries candidate inode identities
captured in the stopped child's filesystem view, so renames after resume cannot
change the queued event's meaning. A continuously replenished mediation queue
is drained in bounded batches; the real flood fixture now reaches its wall
limit instead of starving supervision.

HTTP and SOCKS5 use one destination policy. Named tunnels inspect a bounded
first flight; plaintext HTTP relays one request. TLS SNI inspection does not
verify encrypted HTTP authority. Attempts with vaulted credentials terminate
TLS, check the decrypted Host, validate the upstream certificate and hostname,
and substitute an exact Authorization placeholder only for its authorized
origin. This TLS lane supports one HTTP/1.1 request per connection, without
chunked uploads or HTTP/2. Ordinary non-vault TLS remains opaque after SNI.

`learn` proposes exact existing objects from failed read snapshots and explicit
host:port destinations from allowlist denials. It reports denied writes without
granting them. Proposals bind to a receipt digest and retain evidence references;
The live read-only write fixture exposed an omitted `EROFS` case in learning;
the consumer now includes it in denied writes without changing the audit event
class or proposing a grant. TTY-confirmed adoption changes ordinary operator configuration. `tail --json`
replays the original journal bytes; `--follow` drains through supervisor exit.
Optional argv deny/forbid rules run at Linux exec stops and are accident filters,
not containment of program effects.

Fourteen embedded launch profiles and eight toolchain fragments resolve without
operator files. Operator overrides remain authoritative. Starter profiles are
experimental; doctor readiness is not proof that a vendor agent works.

## Reproduce

Use Rust 1.98.1. Run Linux tests serially inside a delegated systemd user scope,
with explicit paths to the binary and fixture that were built from the same
source. The named host was `ubuntu@37.59.114.70`: Ubuntu 26.04.1,
x86_64 Linux 7.0.0-31, bubblewrap 0.11.1. The local machine was an arm64 Mac
running Darwin 27.0.0, Apple M5 Pro (18 CPUs, 64 GiB RAM). The reference VM exposed four AMD EPYC-Milan CPUs and 3.7 GiB RAM. Full host/build metadata accompanies benchmark samples.

```sh
cargo +1.98.1 build -p ouro-jail -p ouro-fixture
OURO_JAIL_BIN="$PWD/target/debug/ouro-jail" \
OURO_FIXTURE_BIN="$PWD/target/debug/ouro-fixture" \
OURO_CONFORMANCE=1 cargo +1.98.1 test --workspace -- --test-threads=1
python3 docs/benchmarks/jail/acceptance.py --binary target/debug/ouro-jail --out acceptance.json
python3 docs/benchmarks/jail/bench.py --binary target/release/ouro-jail --out timings.json
```

Benchmarks use optimized builds, five warmup rounds and 30 measured rounds.
Cases alternate in a seeded random order; JSON retains the order, every raw
sample, exit counts, host load and build provenance. These are whole CLI
wall-clock timings, including process startup and teardown. They are not the
formal J5 phase-timing/performance gate and contain no same-run greywall arm.

The acceptance script uses disposable state and fixture-only secrets. Its
network success checks use `https://example.com/`; signature tests use an
ephemeral key without any publication authority. The vendored `a5_c3.c` and
`a5_sysprobe.c` are the fifth audit's original probes. Other original audit
scripts remain in the operator's working tree; this is not a claim to have
reproduced every audit finding.

## macOS decision gate

The [native probe](macos_lifecycle.py) compiled and ran a real Seatbelt-contained
fork/setsid fixture. Its detached child survived termination of the original
process group ([raw result](results/macos-seatbelt-lifecycle.json)). The probe
then killed that child. This disproves the proposed native process-group
cleanup mechanism; it does not prove a different native mechanism impossible.

The [follow-up native investigation](macos-native-mechanisms.md) tests launchd,
coalitions, Seatbelt syscall filtering, kqueue and audit-token signalling on
this Mac. The [raw results](results/macos-native-mechanisms.json) include real
detached processes, supervisor death, job removal, a Node compatibility check
and timings. macOS 27's descendant-scoped Endpoint Security client is the next
native candidate; its capability probe on the normally protected host returns
`ERR_NOT_ENTITLED`.

The [ES prototype and signing runner](macos_es.py) are prepared. Ad-hoc and
Developer ID-signed capability/refusal runs are saved in
[signing evidence](results/macos-es-entitlement.json). The operator submitted
the [entitlement request](endpoint-security-request.md) on 2026-09-29; request
ID `S9YJTLLH28` is confirmed and Apple approval is pending. The
[development VM experiment](macos-development.md) uses Apple's documented
SIP-disabled development route. The real ES client succeeds with an ad-hoc
signature, without a profile, as UID 501. In the corrected 40-case run, all
30 surviving-custodian trials cleaned up the known fixture processes; all ten
custodian-death trials left all five processes alive. The runner independently
removed those survivors afterward. This is a demonstrated lifetime failure,
not an entitlement blocker.

Contained execution continues to refuse on macOS. The original Mac benchmark
measures refusal latency, not sandbox launch performance. The new launchd
timings also cannot be presented as successful tree teardown. The lifecycle
contract remains unchanged while stronger native mechanisms are investigated.
A disposable macOS 27 Tart VM was created with guest Ethernet disabled and
without host directories, signing keys or clipboard sharing. The host's SIP
remained enabled. Its [raw results and timings](results/macos-es-development/rerun/summary.json)
are development mechanism measurements, not production jail benchmarks.

## Distribution

The [packager](../../../crates/ouro-jail/dist/package.py) signs SHA256SUMS with an
explicit key. The [installer](../../../crates/ouro-jail/dist/install.sh) accepts
an explicit artifact directory or HTTPS base URL and a trusted public key,
verifies signature and artifact checksum, and atomically replaces the binary
only with `--upgrade`. It runs without a TTY. The [test](../../../crates/ouro-jail/dist/test_install.py)
checks corrupt archives/signatures and preservation of an existing installation.

The operator deferred the release repository, tap and signing identity. No
production key, Homebrew publication, CI release, four-target artifact matrix,
or clean-VM time-to-first-agent result is claimed. A regenerated freeze manifest
records current contracts; its previous tested-revision claim was removed because
it no longer describes this dirty tree. `freeze --check` remains a release gate.

## Acceptance limits

The current work does not close all J6–J11 release gates. Native macOS execution,
clean-VM onboarding, the full audit adversarial
matrix and a clean-revision CI/conformance freeze still need evidence. C1's
non-terminating encrypted-Host residual and the protected-directory scan's
non-atomic external-writer window remain explicit in the specification.

## Acceptance coverage

The following maps evidence to the spec without promoting a partial check to a
passed release milestone. Portable proxy tests use real Unix/TCP sockets on both
hosts; Linux acceptance additionally exercises the actual namespace bridge.

| Rows | Evidence and remaining gap |
|---|---|
| K01–K02 | Shared HTTP/SOCKS first-flight tests: matching/mismatched TLS names, malformed/oversized input, timeout and no upstream connect; host-only grants mean 443. Non-terminating TLS retains the encrypted-Host residual. |
| K03–K04 | Real `none` config and binary-root refusals; live backend replacement/mode-change refusals and execution of the pinned image after pathname replacement. The complete audit race matrix is not claimed. |
| K05 | i386 and x32 live probes, plus filter/classifier tests; a host without x32 support alone cannot prove filter enforcement. |
| K06–K07 | Live pseudo-filesystem/profile/surface probes, private mount alias test, resolver cases and refusal of a nested `.git` created after scanning. Two consecutive mid-scan changes remain untested live. |
| K08–K10 | Exact-read proposal, receipt digest, denied-write and network-cause filtering, real TTY adoption and successful rerun. The file, directory and two-destination live fixtures pass, alongside a read-only write refusal. |
| K11 | OpenCode execution, learning, receipt-bound proposals and a launch using every proposed grant pass; evidence below. |
| K12–K16 | Real bridge HTTP vault and SOCKS/TLS requests; portable socket TLS injection, wrong Host/origin and bad-certificate refusals; receipt/cleanup checks. |
| K17 | Pass on the final Linux source: 540 valid measured launches, zero exclusions, 130.6 ms worst p95 added startup and 36.6%–40.1% file post-start overhead. Raw phase records and the summary-bound verdict are in the follow-up. |
| K18 | Absolute first-flight deadline and size cap; real idle/oversize refusal, existing trickle/backpressure/stop tests. |
| K19–K20 | Live and settled byte-identical tail; fractional timestamp boundary regression. |
| K21–K22 | Real root/descendant deny, forbid and unmatched rewrite; portable matcher, rule-cap and unsupported-platform checks. |
| K23–K26 | Blocked by the native macOS lifetime design. Development ES trials work while the custodian survives, but custodian death leaves the workload alive. |
| K27 | Local signed install/upgrade/corruption checks; clean-VM onboarding and publication deferred. |
| K28 | All 14 embedded profiles ready under Linux doctor, override/fragment validation tests, explicit experimental statuses. |
| K29 | Protected-host ES probe refuses before release without the entitlement. SIP-disabled VM event/lifecycle trials are recorded; approval and validation under normal security settings remain pending. |

## Validation results

- **Mac workspace:** the [2026-09-29 log](results/linux-followup/macos/test.log) reports
  1,022 passed, zero failed, seven ignored. This includes portable socket/TLS
  tests and Mac refusal checks, not a working contained macOS backend.
- **Linux workspace:** the [2026-09-29 log](results/linux-followup/test.log)
  reports **1,731 passed, zero failed, 16 ignored**, with real conformance
  enabled in a delegated user scope. This full run includes the corrected
  mount fixture, timestamp/learning fixes and new boundary regressions.
- **Earlier failures:** the [2026-09-28 run](results/linux-workspace-tests.log)
  had two failures from one mount fixture and its nested helper. The fixture
  now establishes private mounts through bubblewrap before exec. A new backend
  swap test then exposed an incorrect pre-exec refusal status; that fix and
  the retained failing output are documented in the
  [follow-up](followup-2026-09-29.md).
- **Build checks:** strict Clippy on both hosts, formatting, dependency
  advisories/bans/licenses/sources, document contracts and link checks pass.
  The initial failed runs are retained for diagnosis, not counted as green proof.

Totals are libtest-reported counts and include nested helper executions, not a
claim of that many distinct security properties. The debug workspace build
metadata is saved separately from the optimized benchmark build metadata.
The final regression builds have source-input digest
`sha256:b875989505499065d70e903736987a9f3c91d195d56cee3463d92c4ac8163611`:
optimized Linux and debug Mac, Rust 1.98.1, revision `2c8f28dc` with
`dirty: true`. The earlier 2026-09-28 invocation and agent measurements use
`sha256:fa366f0c82364e99146c6a65573709799830f1904b026ed20f4b060ca31db501`,
optimization level 3 on both hosts. Binary SHA-256 values are saved beside
each set of results.

## Final live acceptance

[The final acceptance record](results/linux-followup/acceptance.json) contains **46 passing
checks** against the final optimized Linux binary. Refusals check their expected
error codes, and successful/settled attempts retain their receipts. The i386
observation-off probes return the expected `EPERM`; their short-lived execs may
remain unconfirmed in the supervisor's receipt, separately from the fixture's
observed syscall result.

On the earlier optimized build, OpenCode **1.18.32**, with its embedded profile and credential-free
`opencode/big-pickle`, wrote `greeting.txt` containing exactly `hello\n` in both
runs. Execution took **8.89 s**; learning took **6.92 s**. Both exited zero,
recorded active coverage with no gaps, verified lifetime integrity and an empty
tree. Learning proposed **zero additional filesystem or network grants**;
unsupported pseudo-filesystem reads remain in its unresolved list. A third
contained launch using every proposal succeeded.

Evidence: [run summary](results/agent/result.json),
[execution receipt](results/agent/run-jail.json),
[learning receipt](results/agent/learn-jail.json),
[proposal](results/agent/learned.toml), and
[proposal-check receipt](results/agent/proposal-probe-jail.json).
The fixture uses an empty disposable repository and exposes no operator
credentials. Two successful agent runs do not establish reliability under all
workloads; the historical intermittent startup/evidence issues are not declared
closed by this small sample.

The [saved-result validator](verify_results.py) checks **47 live receipts and
9,697 live events**, schema and semantic rules, learning receipt SHA-256/evidence
references, sample counts and matching Mac/Linux source digests. Signed,
non-interactive installation and upgrade tests pass on
[Mac](results/install-test.txt) and [Linux](results/linux-install.log), including
corrupt-manifest/archive rejection and preservation of the installed binary.

## Final phase measurements — 2026-09-29

[K17 passes](results/linux-followup/k17.json) on the optimized Linux binary.
The [follow-up report](followup-2026-09-29.md#k17-results) includes all six
session/workload cells, the J5 trend, observation costs, raw records and exact
commands. There are 90 warmups and 540 measured launches, no exclusions or
integrity failures, and a maximum measured load of 1.63 against the declared
3.0 limit.

Worst p95 added startup is **130.6 ms**. File-workload median post-start overhead
is **36.6% plain / 40.1% delegated** with observation off. These results meet
both K17's 500 ms / 100% limits and J5's retained 250 ms / 50% ceilings.
With observation, post-start duration on the syscall-heavy file workload is
**4.0–4.1 times** its observation-off duration; observed whole-command medians are
**1.17 s / 1.14 s**. Its cost is reported separately from the jail's own budget.

The 60 unobserved no-op launches are explicitly flagged `exec_unconfirmed`,
as permitted for timing by J5; they are not successful-execution receipts.
Every measured observed launch has the expected event counts, no evidence loss
and verified tree death. The Mac independently reproduced the Linux summary
from its raw records, apart from the recomputation timestamp.

## Historical wall-clock measurements — 2026-09-28

Five warmup rounds and 30 measured rounds per case, randomized with a recorded
seed. Raw samples: [Linux](results/linux.json), [Mac](results/macos.json).
All observed Linux launch/workload samples exited zero, reported an empty tree,
and had no coverage gaps.

| Host / case | Median ms | p95 ms | Meaning |
|---|---:|---:|---|
| linux / direct true | 0.89 | 1.94 | 30 successful exits |
| linux / version | 1.97 | 2.39 | 30 successful exits |
| linux / tool / observation off | 107.07 | 123.84 | 30 exec_unconfirmed flags; invocation only |
| linux / tool / observation on | 96.82 | 109.66 | 30 successful exits |
| linux / agent / observation off | 127.11 | 138.82 | 30 exec_unconfirmed flags; invocation only |
| linux / agent / observation on | 115.39 | 136.18 | 30 successful exits |
| linux / direct 100 writes | 2.41 | 3.26 | 30 successful exits |
| linux / tool / observed 100 writes | 102.28 | 121.12 | 30 successful exits |
| macos / direct true | 2.64 | 3.07 | 30 successful exits |
| macos / version | 3.75 | 4.22 | 30 successful exits |
| macos / contained refusal | 26.66 | 28.53 | exit 125; no contained execution |

The observation-off rows are not successful-execution claims. A target that
exits before a sampled image check yields `exec_unconfirmed`; the benchmark
verifies that exact receipt error and marks the sample. Mac refusal likewise
is not comparable to a Linux sandbox launch. The initial benchmark's incorrect
expectation of exit zero for unobserved `true` is retained in the initial JSON;
those records are superseded by the explicitly flagged final measurements.
