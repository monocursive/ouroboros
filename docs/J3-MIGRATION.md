# Owned core runtime migration

Implementation source: post-J2 `dev` at
`4dc862776b754544459967e5d292e81497d569b6`, 2026-09-10. The proposed J3
specification named an earlier revision; the compatibility fixtures record the
actual source and exact dependency versions used for capture.

## Runtime and compatibility

`Ouroboros.Mesh.Supervisor` owns the local registry, handler task supervisor,
and dynamic agent supervisor. `Mesh.Server` owns each logical agent's state,
admits a bounded waiting queue, and commits one complete callback result at a
time. Inspection is explicitly projected as
`%{agent: %{id: logical_id, state: domain_state}}`. Internal scheduler data is
not an API. The gateway method set remains unchanged.

Allowed extensions implement `Mesh.Agent.init_state/1` and
`handle_message/3`. The context carries the logical ID and actual server PID.
An allowed module with only the removed framework contract receives
`unsupported_agent_contract`. This does not restore dynamic BEAM deployment.
The static WASM wrapper retains its signed component identity, configuration,
normalization, bounded limits, pool/store checks, precompiled provenance, and
whole-reply replacement. Caller-supplied instance handles are discarded.

Pool ownership follows the actual server PID even when instantiation completes
after the requesting task dies. A replacement using the same stable instance ID
clears a predecessor's pending reclamation, so delayed cleanup cannot destroy
the replacement. Both races have focused regressions that failed before the fix.

`Ouroboros.Action` supplies metadata and NimbleOptions validation. Validation,
permission checks, execution, and audit recording remain separate. The owned
schema converter rejects unsupported declarations; existing nested/open model
schema overrides stay explicit. The internal validation exception is now
`Ouroboros.Action.ValidationError`. Direct non-map validation returns an owned
error; native tool argument normalization and model-facing diagnostics retain
their frozen behavior. The actual optional description callback is
`description/1`, alongside `model_schema/0`.

`Signals.AgentMessage` is the owned executable struct; its JSON metadata and
typed message fields preserve the captured wire representation. The legacy
`jido_dispatch` field remains opaque data and is never executed. `Ouroboros.ID`
generates lowercase UUIDv7 values using cryptographic randomness; a backward
clock is reflected in the timestamp without promising identifier ordering.
Prefixes and J2's separate runtime identifier format are unchanged.

`Ouroboros.Storage` defines only checkpoint get, put, and delete. Its ETS
adapter has an explicit supervised owner: tables survive individual store
restarts and disappear with that owner. The file adapter's key hashes, paths,
encoding, publication order, and uncertain-commit behavior are unchanged.
Historical structs are normalized through a finite reviewed data vocabulary,
with safe term decoding and no executable modules under the retired namespace.
Unknown runtime-minted names retain the established refusal/quarantine policy.
Signed artifact contents and historical map keys retain their exact data tags:
normalizing either would invalidate a signature or collapse distinct keys.
This includes the historical pair-map encoding of artifacts with extra fields.
Cold loading resolves only fixed, owned struct modules; stored module names do
not trigger dynamic loading or arbitrary constructors. Only registry entries
and signing journals receive owned default-field widening. Other loaded struct
identities are reconstructed as inert tagged maps with their stored fields;
they no longer run constructors or gain newly introduced defaults on read.

The [storage inventory and corpus](../test/support/j3_fixture/README.md)
records all eight stores, namespaces, checkpoint keys, paths, and adapter
options. The [action/message corpus](../test/support/fixtures/action_message_baseline.md)
records validation, defaults, effective inputs, diagnostics, and serialized
metadata. Existing J1, pre-core-reduction, and pre-J2 fixtures are unchanged.

## Fleet transition

Fleet protocol revision **5** fences the changed mesh contract. Remote mesh
placement, messaging, inspection, and stop check the existing runtime
compatibility contract before dispatch, even when optional placement role
checking is disabled. Duplicate healthy-cluster starts still use the existing
global lock; this does not provide partition-safe consensus. Multiple visible
owners refuse mutations and messages with `ambiguous_replicas`.
Rollout admission and each actual remote dispatch apply the same mandatory
check, including rollback and paths that call the owner's local mesh facade.

Drain and stop all participating nodes before upgrading. There is one runtime,
with no selectable compatibility backend. Code rollback after writes requires
verified backward readability or restoration of the pre-migration backup while
the runtime is stopped. Reinstalling dependencies is insufficient.

## Dependencies

Removed: `jido`, `jido_action`, `jido_signal`, and their unreachable dependencies
`crontab`, `fuse`, `multigraph`, `poolboy`, `telemetry_metrics`, and
`time_zone_info`. All **44 surviving lock entries retain their exact versions**.
`jido_ai` and `jido_harness` were already removed by J1/J2.

Direct production dependencies are `nimble_options`, `req_llm`, `req`,
`exqlite`, `toml`, `mint`, `libcluster`, `phoenix`, `phoenix_live_view`,
`phoenix_html`, `bandit`, `earmark`, `zoi`, `jason`, `telemetry`, `jsv`, and
`erlexec`. `nimble_options` is now explicitly declared. `splode` remains a
transitive ReqLLM dependency. `dialyxir` and `lazy_html` remain development/test
dependencies.

`scripts/check_runtime_graph.exs` walks the application metadata, including
installed optional applications, and rejects retired packages or executable
BEAM modules on the code path. It runs without starting services or reading
runtime data. CI and `make boot-gate` include this check.

## Validation evidence

The following checks ran locally against this implementation. They provide
source/build and test evidence. No fleet deployment, live model-provider run,
or production data upgrade was performed.

| Gate | Result |
|---|---|
| Required-WASM `make test` stages | 3,759 ExUnit tests passed, 14 skipped; all 60 historical boots passed; Rust tests, formatting and both Clippy configurations passed after resuming the Rust phase with the helper path exported |
| `make dialyzer` | Passed, with 26 existing baseline skips and all obsolete Jido suppressions removed |
| `make protocol-docs` | Gateway goldens and generated protocol documentation unchanged |
| `npm run test:browser` | 6 desktop/mobile Chromium journeys passed |
| `scripts/wasm-linux-test.sh --trace` | 884 passed, 23 platform-specific skips; real helper and Linux bubblewrap exercised |
| J3 fresh-VM boot gate | 20 passed: 10 lazy and 10 preloaded boots |
| Clean production build | Warnings-as-errors compile and recursive runtime-graph check passed |
| Production-only historical decode | Fresh lazy and preloaded runs each passed all 16 checkpoints, 255 already-existing atoms, and 8 historical signatures |

The initial Rust phase correctly failed its required-helper check because the
invocation omitted `OUROBOROS_WASM_HELPER`. With that variable set to the built
helper's absolute path and `OUROBOROS_REQUIRE_WASM=1`, the entire Rust phase was
rerun successfully: `cargo test`, `cargo test --features embed`, `cargo fmt
--check`, and Clippy with `--all-targets -- -D warnings` for both feature sets.
All 49 real-helper WASM CLI tests passed in each configuration. The already
passing Elixir and boot phases were not repeated for this environment correction.

The first hosted boot-gate run exposed a platform-dependent audit byte assertion.
GNU tar materialized the macOS archive's AppleDouble metadata as ordinary files,
adding 3,749 bytes to the audit inventory; SQLite's disposable index and WAL also
vary with refresh timing. Extraction now excludes those metadata entries from
disposable copies. The gate checks the canonical journal's exact SHA256 manifest,
17 segments and 58,709 bytes, and separately requires a healthy index containing
all 73 records. The frozen archive and its checksum are unchanged.
Validation passed all 60 Linux boots, both clean production loading modes, and
fresh lazy/preloaded original-fixture boots on both Linux and macOS.

The production-only check rejects repository test code and retired executable
modules, starts no runtime services, and checks both the original fixture and a
temporary copy for writes or quarantine. All older fixture directories remain
byte-for-byte unchanged. The new J3 fixture was captured with the actual old
packages in an isolated archive of the baseline revision, before decoding it
with the owned runtime.

Focused checks also cover action/message parity, schema validation, UUIDv7,
queue limits, distributed mesh refusal and lifecycle behavior, storage failure
injection, cold loading, signed nested history, map-key cardinality, and the
full 83-test Pool suite. These checks are supplemented by the complete suites
above; repeated focused runs are not added together as distinct coverage.
