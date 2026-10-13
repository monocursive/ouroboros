# Ouro credential lifecycle follow-up — 13 October 2026 (complete)

The fresh device login resolved the blocked credential input. **All 42 scored
calls pass with 42 verified strict receipts**, using the same Claude Code,
OpenCode and Codex clients, models, tasks, hidden checkers, schedules and budgets
as the sealed baseline. All 14 scored Codex calls complete with zero HTTPS
fallback diagnostics; the baseline's 14 calls had 405 WebSocket upgrades and
fallback. One real OpenAI OAuth refresh exchange succeeds and persists rotated
access and refresh tokens.

The [12 October baseline](../2026-10-12/README.md) and
[28-call interim bundle](../2026-10-13/README.md) remain unchanged. Failed pilots
remain in the exports. [Methods](METHODS.md), [reproduction](REPRODUCE.md),
[matched before/after CSV](analysis/before-after.csv),
[full analysis](analysis/summary.json).

| Final scored cohort | VPS | Pi |
| --- | ---: | ---: |
| Small tasks, all three clients | 18/18 | 18/18 |
| Larger inventory workflows | 3/3 | 3/3 |
| Strict enforced receipts, all checks pass | 21/21 | 21/21 |
| Codex calls, zero HTTPS fallback | 7/7 | 7/7 |
| Existing credential boundary checks | 8/8 | 8/8 |
| Added live lifecycle/binding checks | 14/14 | 14/14 |

Every scored receipt retains the baseline syscall filter, protected coverage,
network allowlist and observer plan. All six coverage classes are active without
gaps; the ptrace observer is attached, trees settle empty, and state cleanup
completes. Credential sources remain outside child grants and unreadable inside
the jail; secrets are vault-only, never staged, and have no recorded credential
digest. [Per-call receipt checks](analysis/receipt-verification.json).

The unchanged bounded sampler finds zero raw-token hits in 14,663 snapshots,
60,968 readable process-environment checks and 1,033,892 regular-file checks,
and in retained client stdout/stderr. It records 14,586 unreadable environment
checks separately. This does not prove absence from arbitrary memory, all files
or every instant. Private caches, source documents and actual tokens are excluded
from the exported evidence and remain outside Git.

## Before/after credential behavior

| Capability | Sealed before | Final evidence |
| --- | --- | --- |
| Live source rotation/deletion | Active attempt continued using a static snapshot | New source generation used; old leases close; deletion stops a streamed response |
| Revocation timing | No live source revocation | Delete to attempt settlement: 119.63 ms VPS, 189.34 ms Pi in the fixture |
| URL path binding | Same approved origin could receive the token on another path | Wrong/escaped paths refuse without secret release |
| Process binding | No credential executable restriction | Kernel connection initiator and pinned executable checked; a wrong executable claiming a PID in HTTP refuses |
| Automatic refresh | Not implemented | Idle refresh, persistence, concurrent ownership and failed-grant refusal pass synthetic real-jail fixtures; one real issuer exchange succeeds on VPS |
| Codex WebSockets | All 14 scored calls fell back after 405 upgrades | All 14 matched scored calls pass without fallback diagnostics |

Revocation uses 100 ms polling under responsive filesystem/scheduler conditions,
not a hard real-time guarantee. Process binding authorizes the connection
initiator; deliberate socket delegation is not per-byte attribution. The
RFC6455 upgrade verifies nonce/version and the upstream accept response with
normal TLS certificate/name validation. Existing compatibility limits for
chunked uploads, `Expect`, HTTP/2 and certificate pinning remain. Lifecycle
transitions and safe refusal reasons enter the trace without payload logging.

## Verified real-provider refresh

After a fresh Mac device login, the VPS diagnostic forces only source expiry
metadata and performs one JSON issuer exchange. It exits zero in 584.13 ms,
rotates both access and refresh tokens, persists the result and clears pending
state. The original JWT was still valid: **natural-expiry recovery and a long
expiry-duration soak were not exercised**.
[Successful diagnostic](results/vps/provider-refresh-json/result.json).

The rotated grant was privately compare-and-swap synchronized into the authorized
VPS, Pi and Mac login caches before the scored Codex phase. The Pi uses that
verified grant; it does not perform a second independent real refresh exchange.
Both hosts' synthetic lifecycle suites exercise refresh.
[Safe synchronization checks](validation/provider-grant-synchronization.json).

The first form-encoded provider pilot failed after submission and left pending
state. Its uncertain grant was not replayed, and the failure remains retained.
[Initial failed pilot](results/vps/provider-refresh/result.json). The corrected
JSON request and JWT-expiry fallback match the
[pinned Codex provider implementation](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/login/src/auth/manager.rs#L1523).
Access-only WebSocket diagnostics remain explicitly unscored.

## Startup controls

Thirty randomized old/new binary pairs use exactly the same static vault policy,
with three warmup pairs, no provider calls and no exposure sampler.

| Host | Before median | After median | Paired median increase | Bootstrap 95% interval |
| --- | ---: | ---: | ---: | ---: |
| VPS | 129.29 ms | 130.29 ms | +2.36 ms | −0.24 to +3.71 ms |
| Pi | 466.22 ms | 483.86 ms | +6.75 ms | −15.49 to +23.44 ms |

All 120 measured launches pass. Both intervals include zero: these trials do not
resolve an incremental startup cost, and establish no speedup. The unchanged
environment/vault control passes another 120 measured receipt checks; paired
vault increases are +2.13 ms on VPS (−0.51 to +5.87 ms) and +9.29 ms on Pi
(−6.20 to +26.17 ms). Online agent elapsed times include provider variation and
sampling, so they remain descriptive. These agent-profile controls cannot be
substituted numerically for the separate tool-profile MXC startup comparison.

## Retained competitor comparison

Ouro now demonstrates live revocation, refresh, path/process restriction and
Codex WebSocket compatibility together with strict receipts and complete attempt
journals. These added lifecycle fixtures were not run equivalently on competitors;
they establish Ouro capabilities, not an overall security ranking. Greywall's
substitution and OpenShell's provider handling remain the verified comparators
from the frozen runs. OpenShell already exposed provider lifecycle and
endpoint/binary policy controls; Ouro's real refresh evidence now closes its
previously unverified provider exchange gap for the tested issuer. MXC's tested
configuration used ordinary environment/auth-file credentials and still wins the
separate native startup comparison. Ouro's native Mac vault remains unbenchmarked.
No competitors were rerun during this credential follow-up.
[Retained competitor provenance](before/competitor-credential-provenance.json),
[separate startup comparison](../../competitors-startup/2026-10-12/README.md).

## Validation and reuse

Rust 1.98.1: 275 local unit tests pass, 579 Linux unit tests pass per architecture
(Pi final suite serial), ten selected VPS integration suites pass, portable proxy
52 tests pass, and contract validation passes. The full xtask suite now passes
206 tests. Clippy, formatting and the I02 vendor scan pass. Initial pilot, Pi
parallel bridge timing and validation failures remain beside successful reruns.
[Validation summary](validation/summary.json).

Conformance transfer now omits the four comparison corpora (about 1.8 GB) while
preserving the Jail release-test fixtures and all source/test inputs. The exact
dependency review includes generic HTTP refresh transport and RFC6455's mandated
SHA-1 challenge; the gate still rejects any unreviewed addition. One unit-only
HTTPS fixture URL uses a generic issuer to satisfy the execution-core vendor
scan. These validation repairs do not change shipped runtime behavior.
[Post-benchmark validation patch](validation/post-benchmark-validation.patch).

Fresh full reference-host conformance and `freeze --check` remain pending the
4 GiB disk-space prerequisite and approval to remove five separately named old
CI target directories. Scoped tests are not a substitute for this run. The stale
freeze tested record remains removed; full release readiness is not claimed.

The measured executables have unknown revision/cleanliness claims. Their exact
123 inputs and input digest bind them to the retained source archive, which
includes the original unit-fixture URL. The sole current-tree difference in those
inputs is that unit-only URL; benchmark hashes and receipts remain unchanged.
[Build inputs](validation/candidate-inputs.json),
[source archive](archives/candidate-build-inputs.tar.gz),
[input difference check](validation/post-benchmark-input-differences.json),
[sanitized VPS export](archives/vps-export.tar.gz),
[sanitized Pi export](archives/pi-export.tar.gz).

All 42 runs, receipts, journals, checker outcomes, harness/source snapshots,
failed pilots and offline startup pairs are reusable. `SHA256SUMS` covers every
retained file; the accompanying complete evidence archive verifies all members
against that manifest. Exact private-value and token-pattern audits precede
sealing and publication.
