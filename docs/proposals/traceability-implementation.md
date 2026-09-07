# Traceability implementation and validation

Branch: `codex/traceability-and-audit`, from `dev` at `4aeee8f`.
The [operating guide](../AUDIT.md) describes the implemented controls, configuration,
trust boundaries and deployment procedures. The [proposal](traceability-and-audit.md)
records the original design rationale. No commit, push or deployment is implied by this
work record.

## Implemented

- Optional standard/local/required profiles; service-owned policy and digest; private
  policy files, named token identities, roles, expiry/revocation, audit access events.
- Disabled recording bypasses the writer even inside execution context. Packaged fleet
  startup preserves audit policy settings; automatic service installation refuses policy
  it cannot persist, with an operator-managed service path documented.
- Canonical v2 hash-linked segmented records with durable file/directory sync, poisoned
  ambiguous writes, capacity refusal, blob ownership and optional AES-GCM encryption.
- Native model projection plus final HTTP transport capture, physical-attempt policy,
  incremental chunks, terminal failures/results and auxiliary summarization capture.
- Tool proposals/effective input/dispatch/raw response/model-visible response, shell
  output, authority and approval links, hook/escalation records and file snapshots.
- Required provider/tool admission, actor checks, protected paths, OS read/network
  fencing for shell commands, and destination-policy checks for remote native work.
- Encrypted new operational checkpoints/conversations/rewind/compaction state; an offline
  forward-encryption utility and read-only inventory for legacy managed content.
- Optional embedded SQLite metadata projection with SQL filtering, incremental refresh,
  canonical fallback and rebuild; bounded shared API and Rust CLI; web investigation,
  call outcomes, artifacts and evidence tar downloads.
- Portable hashed evidence bundles and offline Rust verification/restore; independently
  supplied manifest digests and Ed25519 public keys; cross-language signed fixtures.
- Separate append-only collector, signed event receipts and nonce-bound inventories,
  idempotent retries, recovery comparison and historical receipt key rotation.
- Background custody/OTLP delivery, backoff and metadata-only OTLP HTTP/JSON export.
- Canonical retention/holds/purge authorizations, restartable cleanup, retired stream IDs,
  blob/server-export cleanup, receipt-required destructive recovery and index cleanup.

## Evidence gathered on 2026-09-07

The focused tests use invented data and local fixtures; none call a paid model provider.
They cover final HTTP body equivalence and refusal before opening a connection; refusal
before model/tool effects; crash/sync/capacity/corruption/symlink handling; encryption and
key loss/rotation; SQLite catch-up/rebuild; signed custody/conflicts/whole-stream deletion;
roles/revocation; hold/purge recovery; export traversal/inventory and escaped browser
content. See `test/audit/` and `tui/src/audit_cli.rs`.

- **119 focused Elixir tests passed** across audit, gateway streaming/golden/protocol,
  web authentication/call authorization and native replay. The audit subset contains 31
  tests, including refusal before network dispatch, exact HTTP body digest/byte count,
  interrupted-process termination and disabled-mode independence from the writer.
- **31 audit tests passed on Linux arm64** (Ubuntu container, Elixir 1.20.2, OTP 29.0.5),
  including SQLite and a real bubblewrap read/network containment check as an unprivileged
  user. `scripts/audit-linux-test.sh` reproduces the disposable container setup; it does
  not establish operation on a customer's host/kernel.
- **53 native hook tests passed** with an isolated `TMPDIR` on macOS arm64. The earlier
  complete Elixir run reported 4118/4121 passed and 9 skipped: a WASM dry-build timeout and
  two component-hook handshake timeouts. The WASM test passed separately. Subsequent hook
  runs also had subprocess timeouts; a clean `dev` archive with its original lockfile
  reproduced four hook failures. The isolated-directory rerun passed all 53. These runs
  establish environment-sensitive failures, not a proven root cause; the complete Elixir
  suite is not represented as an uninterrupted green run.
- **Complete Rust suites passed:** 1,666 tests with default features and 1,674 with
  `embed`. Earlier EPMD timing failures passed isolated reruns and the successful
  full run. After the final fleet-policy addition, both library profiles passed again:
  860 default tests and 869 embedded tests.
- The independent Rust verifier passed the Elixir-generated signed four-event fixture,
  including a small exponential float, the external digest and all four trusted receipts,
  while pointed at an unavailable gateway. Nested noncanonical JSON, missing files,
  altered inventory and invalid signatures are rejected by focused tests.
- The production release assembled, started and wrote/query-verified synthetic evidence
  with SQLite both disabled and enabled. A separate release `eval` collector accepted
  real localhost HTTP appends, idempotent retries and fresh signed inventories, without
  starting the agent supervisor or configuring its data directory.
- Browser inspection of synthetic localhost data verified sign-in, audit navigation,
  actor filtering, the call-outcome table, unknown outcomes, escaped event fields and
  export preparation. The authenticated tar download is also exercised automatically.
- Elixir compilation with warnings as errors, formatting, the development launcher
  regression script and whitespace checks passed. Rust Clippy is checked with warnings
  as errors for default and embedded profiles. A changed-file credential-pattern scan
  found no matches; signing material in the repository fixture is explicitly public
  invented test material. No production credentials or model calls were used in fixtures.

Review remediation on 2026-09-07 fixed trusted actor propagation through gateway starts,
durable plane requests and native children; protected skill discovery/loading; collector
retry after a post-append receipt failure; operational attachment/screenshot/output
encryption and offline migration; and terminal evidence for questions and child tools.
The gateway execution regressions also exposed and fixed the native prompt builder's
missing required-audit sandbox case.

After these fixes, **377 focused Elixir tests passed** on macOS with isolated data and
temporary directories. This run includes the audit suite, real gateway-to-native scripted
turns under local and required audit, coding/interactive state and resume, native child
completion/background/timeout/interruption, image transport and screenshot decoding,
privacy migration/key rotation, gateway protocol/streaming, web authorization and replay.
Compilation with warnings as errors, formatting and whitespace checks passed. The model
transport test used a local HTTP server and invented credentials; the migration test ran
in a separate stopped-runtime process. These fixes have not been deployed or newly
validated on Linux or a live model provider.

Representative commands:

```sh
mix test test/audit test/ouroboros/gateway/streaming_test.exs test/ouroboros/gateway/golden_test.exs test/ouroboros/gateway/protocol_docs_test.exs test/ouroboros/web/auth_test.exs test/ouroboros/web/call_test.exs test/provider/native/replay_test.exs
sh scripts/audit-linux-test.sh
# Give each concurrent test VM its own temporary directory.
TMPDIR=/absolute/private/test-tmp mix test test/provider/native/hooks_test.exs test/provider/native/hooks_narrowing_golden_test.exs
mix compile --force --warnings-as-errors
mix format --check-formatted
MIX_ENV=prod mix release --overwrite
# From tui/:
cargo test
cargo test --features embed
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features embed -- -D warnings
```

### Synthetic storage measurement

`mix run --no-start scripts/audit-benchmark.exs 1000`, macOS arm64, Elixir 1.20.2,
OTP 29; one stream, 1,000 approximately 2 KiB invented text chunks. Other validation
processes were running on the same workstation. Includes real local file/directory sync;
excludes model calls, remote custody RTT and long-term retention/export scans.

| Capture | Median append | P95 append | Total append | Rebuild index | Search (20 results) | Disk including index |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Metadata | 0.691 ms | 1.759 ms | 822 ms | 343 ms | 0.163 ms | 1,806,095 B |
| Redacted | 0.540 ms | 0.912 ms | 605 ms | 87 ms | 0.163 ms | 3,934,095 B |
| Full + encryption | 1.427 ms | 4.025 ms | 1,983 ms | 72 ms | 0.162 ms | 4,890,095 B |

These are small synthetic measurements, not an SLA. Warm-cache/order effects explain why
metadata was slower than redacted in this run. Required custody adds a network round trip
per event. Scan-based queries, full-stream details, retention inventory and bundle assembly
still materialize retained history; the operating guide documents this scaling boundary.

### Dependency review

SQLite introduced Exqlite 0.39 and DBConnection. Req is now an explicit dependency.
Mint was upgraded from 1.9.3 to 1.10.0, which addresses the
[upstream HTTP parser advisory](https://github.com/elixir-mint/mint/security/advisories/GHSA-g83f-2j6r-q6m4).
The pre-existing Earmark 1.4.49 package is retired and has an
[HTML attribute advisory](https://github.com/advisories/GHSA-52mm-h59v-f3c7).
The audit renderer uses escaped HEEx text, not Markdown HTML; the existing transcript
renderer calls `Earmark.Parser.as_ast` and implements its own allowlisted, escaped HTML
renderer, bypassing the affected `Earmark.Transform` path. The dependency warning remains
visible; it is not claimed to be an upstream fix.

## Deliberate boundaries

This is one organization on trusted runtime hosts, with native execution as the enforceable
profile. Opaque vendor/internal calls, MCP/desktop/component capability coverage, SSO,
multi-tenant isolation, a central PostgreSQL service, automatic global erasure, hidden
provider reasoning, automatic fleet audit-service installation and production compliance
certification are not claimed. Unsupported
execution is refused under required mode. Capture metadata is explicitly distinct from the
encrypted operational working set. Managed migration does not sanitize old logs/journals,
custom storage, OS swap, backups, workspace files or provider copies.

Customer acceptance still requires protected service configuration, real identity/key
operations, TLS/custodian separation, OS controls, representative load, and independent
backup/restore and incident exercises. Local tests and release assembly do not establish
those deployment facts.
