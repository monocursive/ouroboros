# Ouro vault credential benchmark — 12 October 2026

Ouro's vault is now exercised with Claude Code, OpenCode and Codex on the VPS
and Pi. **All 42 scored coding calls passed, all 42 receipts retained strict
observation and enforced containment, and all 16 live credential boundary
checks passed.** This closes the unmeasured-vault gap. It does not establish
provider lifecycle parity with OpenShell.

The pending startup fixes and all their evidence were committed first at
`cf98e6a1`. This follow-up uses those exact runtime binaries. Its changes are
credential benchmark tooling, operator examples and documentation; runtime
isolation, observation, host configuration and budgets are unchanged. The
three earlier evidence trees remain byte-preserved. See
[methods](METHODS.md), [protocol and exclusions](analysis/protocol.json), and
[prior evidence integrity](analysis/prior-evidence-integrity.json).

## Before and after credential transport

The saved baseline used a real Anthropic key in the child's environment and a
copied Codex auth file. The vault lane supplies an attempt-scoped placeholder
and releases the token only through its declared header at the exact approved
HTTPS origin. Codex receives an external-token adapter with no real ID or
refresh token. It uses the same non-secret identity template already exercised
for OpenShell; the initial incorrect auth-mode pilot remains excluded evidence.

| Host | Environment/staged baseline | Vault small tasks | Vault larger workflows | Verified scored receipts | Boundary checks |
| --- | --- | --- | --- | --- | --- |
| VPS | 18/18 small, 3/3 workflows | 18/18 | 3/3 | 21/21 | 8/8 |
| Pi | 18/18 small, 3/3 workflows | 18/18 | 3/3 | 21/21 | 8/8 |

Client builds, models, tasks, prompts, turn/wall limits, fresh state and hidden
checkers match the previous benchmark. The original seeded schedule is retained.
Every scored attempt is present, including client transport diagnostics.
[Before/after CSV](analysis/before-after.csv), [JSON](analysis/before-after.json),
[binary bindings](analysis/binary-bindings.json),
[receipt verification](analysis/receipt-verification.json).

The exposure checker found **zero raw-token hits** in 12,090 periodic
snapshots, 50,481 readable process-environment observations, 935,700 regular
file checks, and unredacted client stdout/stderr. There were 12,022 unreadable
process-environment observations; those are counted, not called clean. Sampling
does not establish absence in arbitrary memory, all files, or every instant.
Credential sources were unreadable from every scored contained command, and
all receipts recorded `vault`, `never_staged: true`, and no credential digest.
The declared coverage classes, syscall filters, observer budgets, protected
coverage and network allowlists matched their baseline receipts. All scored
trees settled empty and vendor-state cleanup completed.

## Offline startup cost

Thirty interleaved pairs per host compare environment and vault preparation in
the same `agent` no-op fixture, without provider calls or exposure sampling.
All 120 measured launches passed their receipt checks. Warmups and journals
are retained.

| Host | Environment median | Vault median | Paired median extra time | Bootstrap 95% interval |
| --- | ---: | ---: | ---: | ---: |
| VPS | 130.31 ms | 128.34 ms | −1.76 ms | −4.37 to +3.63 ms |
| Pi | 470.59 ms | 472.05 ms | −5.18 ms | −18.22 to +12.32 ms |

Both intervals include zero: **no additional vault startup cost was detected
in these trials**. This is not a speedup claim or a replacement for the earlier
tool-profile startup benchmark. Paired differences need not equal differences
between marginal medians. Online client times include provider variability and
the exposure watcher, so they do not measure causal sandbox overhead.
[Full analysis](analysis/summary.json).

## Where Ouro now compares better, and where it remains behind

Ouro now demonstrates placeholder-based credential use alongside its strict
receipts, complete exported attempt journals, source-file isolation and
empty-tree proof. Against its earlier environment/staged mode, it removes the
real key/auth token from ordinary child state while retaining the tested task
compatibility. Greywall and OpenShell already demonstrated placeholder/provider
workflows, so this establishes Ouro's corresponding capability rather than a
general security win over them. The same independent exposure sampler was not
run on competitors; their tests do not inherit this new result.

| Credential feature | Ouro, newly measured | Greywall/GreyProxy, retained evidence | OpenShell, retained evidence |
| --- | --- | --- | --- |
| Real coding clients with credential substitution | All three, 42/42 calls | API-key substitution exercised in working Linux lanes | Provider handles/bootstrap exercised on VPS/Mac; Pi startup unavailable |
| Independent raw-token sampling | No hits in the bounded checks above | Equivalent sampling not performed | Equivalent sampling not performed |
| Credential destination restriction | Exact scheme/host/port and named header; live negative checks passed | Proxy credential rules exercised; equivalent new negatives not rerun | Provider endpoint/binary policies configured and exercised; path binding documented |
| Rotation and revocation | Source replacement/deletion affects future attempts; active attempts retain their snapshot | Lifecycle reliability not settled by this dataset | Refresh/bootstrap handling exercised; earlier expired-token refresh failed 401 and recovery required a fresh provider/cache |
| Operator integration | Private raw-token file, reviewed launch profile, contained environment/auth adapter | Automatic proxy substitution already exercised | Provider profiles, handles and external-token bootstrap already exercised |

MXC's tested native configurations used ordinary environment/auth-file
credentials and did not expose an equivalent broker in this benchmark. Ouro's
vault adds a demonstrated brokerage option relative to that tested setup;
MXC remains substantially faster in the separate native startup benchmark.
The native Mac Ouro vault remains unavailable/unmeasured, so this does not
close Ouro's cross-platform gap.

Three material limitations remain:

1. **OAuth refresh and live revocation.** Ouro snapshots a raw token at
   preparation. The synchronized fixture proved that rotating, then deleting,
   the source does not change an active attempt's token. The next missing-source
   attempt refused before execution; a subsequent restored source used its new
   token. There is no expiry scheduler or gateway refresh worker. OpenShell
   offers that provider lifecycle, although its retained refresh failure also
   limits a reliability claim.
2. **Credential path/process scoping and setup effort.** Ouro binds origin and
   header, without URL-path or per-client-binary credential restrictions. The
   fixture received the token at another path on the same approved origin.
   Client variable mapping and Codex's non-refreshing external-token adapter
   require explicit operator setup. Setup duration was not timed, so no numerical
   usability ranking is claimed.
3. **Codex WebSocket transport.** All 14 scored Codex calls logged WebSocket
   HTTP 405 responses and fell back to HTTPS before succeeding; the previous
   staged-auth calls had no such fallback. The vault's HTTP parser removes
   hop-by-hop `Upgrade`/`Connection` headers and its TLS lane handles one
   HTTP/1.1 request per connection. WebSocket support is not established. The
   scored flags were left unchanged; retries were not hidden to improve timing.
   HTTP/2, chunked uploads, `Expect`, and certificate pinning retain their
   documented compatibility limits.

[VPS lifecycle proof](results/vps/lifecycle/summary.json),
[Pi lifecycle proof](results/pi/lifecycle/summary.json),
[hashed competitor sources](analysis/competitor-credential-provenance.json).
Primary references: [versioned OpenShell external-token adapter](https://raw.githubusercontent.com/NVIDIA/OpenShell/v0.1.3/examples/codex-app-server/start-codex-app-server),
[current OpenShell provider/refresh reference](https://docs.nvidia.com/openshell/dev/how-it-works/providers/profiles),
[Ouro vault implementation](../../../../crates/ouro-jail/src/vault.rs).
Current documentation is distinguished from the measured pinned builds.

## Reuse and validation

Saved evidence includes every scored call, excluded pilots, stdout/stderr,
prompts, changed files, independent checks, receipts, referenced journals,
startup pairs, lifecycle fixtures, sanitized host archives and exact installed
harnesses. The offline analysis verifies source hashes and compares the saved
baseline. [Reproduction](REPRODUCE.md).

The new [Claude vault starter](../../../../crates/ouro-jail/profiles/launch/claude-vault.toml)
and [OpenCode vault starter](../../../../crates/ouro-jail/profiles/launch/opencode-vault.toml)
each parsed and executed with a harmless fixture key on both hosts. These
starter checks are distinct from the real-provider task results. Pinned Rust
1.98.1 passed eight vault transport tests and the vault declaration regression
locally. This is benchmark/compatibility evidence, not a fresh release freeze
or reference-host conformance claim.
