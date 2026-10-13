# Ouro credential lifecycle follow-up — 13 October 2026 (interim)

The credential fixes are implemented and tested: supervisor OAuth refresh,
live source revocation, URL path and kernel executable binding, and verified
Codex WebSockets. **The full provider benchmark is incomplete pending a fresh
Codex login.** All 28 completed Claude Code/OpenCode calls pass with 28 verified
strict receipts. Fourteen scored Codex calls remain unlaunched; they are not
counted as successes or replaced by access-only calls.

The [sealed 12 October baseline](../2026-10-12/README.md) remains unchanged.
Its 1,706 manifest members were checked with zero mismatches. This follow-up
retains the same clients, tasks, models, flags, schedules, hidden checkers,
wall budgets and exposure sampler. The only client installation adjustment is
a byte-identical Pi Claude copy made 0755 instead of the original manual 0775
installation, because executable binding refuses group/other writable objects.
[Methods](METHODS.md), [reproduction](REPRODUCE.md),
[baseline integrity](analysis/prior-evidence-integrity.json).

| Scored final cohort | VPS | Pi |
| --- | ---: | ---: |
| Claude Code/OpenCode small tasks | 12/12 | 12/12 |
| Claude Code/OpenCode inventory workflows | 2/2 | 2/2 |
| Verified strict, enforced receipts | 14/14 | 14/14 |
| Scored Codex calls | 0/7; awaiting fresh login | 0/7; awaiting fresh login |
| Existing credential boundary checks | 8/8 | 8/8 |
| New live lifecycle/binding checks | 14/14 | 14/14 |

All completed scored receipts retain the baseline syscall filter, protected
coverage, network allowlist and observer plan. All six coverage classes are
active without gaps, the ptrace observer is attached, all trees settle empty,
and state cleanup completes. Sources are unreadable inside the jail, tokens
are vault-only and never staged, and no credential digest is recorded.
[Receipt verification](analysis/interim-vps-pi-receipt-verification.json),
[matched before/after CSV](analysis/interim-vps-pi-before-after.csv),
[complete interim analysis](analysis/interim-vps-pi-summary.json).

The unchanged exposure sampler found zero raw-token hits in 11,064 snapshots,
44,051 readable process-environment checks and 635,677 regular-file checks,
as well as raw client stdout/stderr. It counted 11,011 unreadable environment
checks separately. This is bounded sampling, not absence proof for arbitrary
memory, all files or every instant.

## Before/after credential behavior

| Capability | Sealed before | Candidate evidence |
| --- | --- | --- |
| Active source rotation/deletion | Active attempt continued using its snapshot | New token used in active attempt; old leases closed; deletion stops a streamed response |
| Revocation timing | No live source revocation | Delete to attempt settlement: 119.63 ms VPS, 189.34 ms Pi in the fixture |
| Path restriction | Token reached another path on the same approved origin | Wrong/escaped paths refused without secret release |
| Process restriction | No credential executable restriction | Kernel connection initiator checked; wrong executable claiming a PID in HTTP refused |
| Automatic refresh | Not implemented | Idle refresh, rotated-source persistence, concurrent grant ownership and failed-grant refusal pass synthetic real-jail fixtures and unit tests |
| Codex WebSockets | All 14 scored calls logged 405 upgrades and HTTPS fallback | One final-build access-only diagnostic passed using WebSockets with zero fallback/error messages; full scored Codex cohort pending |

Revocation uses 100 ms polling under responsive filesystem/scheduler conditions,
not a hard real-time guarantee. Executable binding authorizes the connection
initiator, not each byte after deliberate socket delegation. RFC6455 upgrade
requires a valid nonce/version and a verified upstream accept response. Ordinary
HTTP remains one request per connection; chunked uploads, `Expect`, HTTP/2 and
certificate pinning retain their compatibility limits. Lifecycle transitions
and safe refusal reasons enter the existing trace; payloads and secrets do not.

## Real-provider refresh is still unverified

The first real OpenAI refresh diagnostic used forced-expiry source metadata and
failed after submitting the grant. It exited 125 and left `refresh_pending:
true`; no successful token rotation was recorded. That failure is retained in
[the provider pilot](results/vps/provider-refresh/result.json). Whether the
issuer consumed the rotating grant is unknown, so it has not been replayed.

The request encoding was corrected to JSON and response expiry handling now
accepts issuer JWT expiry when `expires_in` is absent, matching the
[pinned Codex 0.159.2 provider implementation](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/login/src/auth/manager.rs#L1523).
A fresh Mac login is required to verify this corrected flow safely. Successful
real-provider refresh and natural-expiry recovery are not claimed by this
interim report. The two WebSocket diagnostics use the still-valid access token,
never send a refresh request, and remain outside the scored cohort.

## Startup controls

Thirty randomized old/new binary pairs use exactly the same static vault policy,
with three warmup pairs and no provider calls or exposure sampler.

| Host | Before median | After median | Paired median increase | Bootstrap 95% interval |
| --- | ---: | ---: | ---: | ---: |
| VPS | 129.29 ms | 130.29 ms | +2.36 ms | −0.24 to +3.71 ms |
| Pi | 466.22 ms | 483.86 ms | +6.75 ms | −15.49 to +23.44 ms |

All 120 measured launches in that control passed. Both intervals include zero;
no additional cost was detected in these trials, and no speedup is claimed.
The unchanged environment/vault control also passed all 120 measured receipt
checks: paired vault increase +2.13 ms on VPS (−0.51 to +5.87 ms) and +9.29 ms on
Pi (−6.20 to +26.17 ms). Online client times include provider variation and the
sampler and cannot establish causal sandbox performance. These agent-profile
controls are not numerically interchangeable with the earlier tool-profile
MXC startup comparison.

## Comparison with retained competitors

Ouro now demonstrates live source revocation, idle refresh and path/executable
restriction alongside strict receipts and complete attempt journals. These
fixtures were added for Ouro and were not run equivalently on competitors, so
they establish Ouro capabilities rather than an overall security win.
Greywall's substitution and OpenShell's provider handling remain the verified
credential comparators from the earlier frozen builds. OpenShell already
exposed provider lifecycle and endpoint/binary policy controls; corrected real
OpenAI refresh reliability in Ouro remains unverified. MXC's tested setup used
ordinary environment/auth-file credentials and still wins the separate native
startup comparison. Ouro's native Mac vault and cross-platform gap remain.
[Retained competitor provenance](before/competitor-credential-provenance.json).

## Validation and reuse

Rust 1.98.1: 275 local unit tests passed; 579 Linux unit tests passed on each
architecture (Pi final suite serial); VPS selected integration suites passed;
portable proxy 52 tests, freeze tooling nine tests, contract validation, clippy
and formatting passed. Initial fixture/profile/hash and Pi bridge timing
failures and their successful repairs/reruns are retained in validation logs.
[Validation summary](validation/summary.json).

Fresh full reference-host conformance is pending the disk-space prerequisite:
the VPS has about 470 MB free while the driver requires 4 GiB. Five specific
inactive CI build caches were proposed for removal; that approval is pending.
The freeze was regenerated and its stale tested record dropped. `freeze
--check` is not claimed passing until a fresh validated run is recorded.

The benchmark binaries have unknown revision/cleanliness claims and are bound
to the exact measured build-input digest and executable hashes instead.
[Inputs](validation/candidate-inputs.json),
[source archive](archives/candidate-build-inputs.tar.gz),
[sanitized VPS export](archives/vps-interim-export.tar.gz),
[sanitized Pi export](archives/pi-interim-export.tar.gz).
All completed runs, receipts, journal references, hidden-checker outcomes,
patches, failed pilots, source/harness snapshots and startup pairs are retained.
The interim archive and hash manifest explicitly record that only 28 of the
expected 42 scored calls are present. Private credentials remain outside Git.
