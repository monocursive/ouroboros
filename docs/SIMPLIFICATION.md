# Runtime simplification, September 2026

The audit led to shared mechanisms at existing boundaries. Batch tasks, interactive
sessions, native subagents, durable teams, and BEAM/WASM upgrades retain their distinct
lifetimes and APIs.

## Ownership and restart matrix

The root remains `rest_for_one`. Its durable directory owner, effect ledger, model
admission, permission authorities, stores, and workspace manager are upstream of their
consumers. Coding/interactive/team stores remain above the workspace manager because it
reads their checkpoints to reconstruct reservations before admitting work.

| Replaced owner | Must restart | Must survive |
|---|---|---|
| Durable directory owner or effect ledger | All execution consumers | No consumer may retain stale authority |
| Model admission | Jido and downstream execution consumers | Effect ledger |
| Workspace manager | Session coordinators and downstream surfaces | Durable stores |
| Coding registry | Coding task supervisor and recovery | Workspace reservations, interactive sessions, scheduler |
| Interactive registry | Interactive task supervisor and recovery | Coding sessions and workspace reservations |
| Automation store | Later automation owners | Session planes and permission authorities |
| CodeIntel supervisor after exhausting its restart budget | Its language-server pool | WASM, Desktop, MCP and session owners |
| WASM supervisor | Its pool, then boot recovery | Desktop, MCP, CodeIntel and web |
| Gateway or web | Its own connections | Durable owners and unrelated helpers |

`ApplicationRecoveryTest` injects authority and registry failures and exhausts the
CodeIntel restart budget. `McpTest` exhausts the MCP budget and checks surviving peers. The WASM
boot task remains transient and follows the WASM supervisor in its own `rest_for_one`
subtree. This is different from the temporary worktree reconciliation task.

The isolation checks exercise normal restart-budget escalation. An untrappable kill of
a supervisor bypasses its child shutdown; named-child cleanup races or repeated parent
failures can still exhaust the surface tier and restart its siblings.

The gateway binds and publishes synchronously, preserving startup failures at that
boundary. Its linked acceptor waits for the runtime application to finish starting
before handling requests. An immediate `runtime.shutdown` therefore cannot interrupt
application startup and bypass removal of the gateway and runtime-owner markers.

`config :ouroboros, automation_enabled: false` omits the orchestration/Control stores,
scheduler and optional Control server. The default is `true`, preserving existing
behavior. Permission rules and grants, native subagents, coding, interactive sessions,
and teams remain available. Status reports orchestration as disabled. Disabling this
setting does not delete saved plans or runs; re-enabling loads their checkpoints.

## Checkpoint publication

`Storage.Records` is shared by Coding, Interactive, Team, Orchestration, and Control.
Owners retain validation, version checks, and domain transitions. Updating an existing
record writes only that record, including its own retained history.

- Creation: sync the record, then publish its id in the versioned index.
- Deletion: publish the reduced index, then remove orphan files.
- Migration: retain the legacy aggregate until every record is written and the new
  index is published. Interactive retains its existing `:session` record-key format.
- Corruption: fail closed on an unreadable index; quarantine an unreadable individual
  record, keeping its bytes for inspection and loading the remaining records.
- Ambiguous commit: stop the store for reconciliation; never claim a definite refusal
  or undo a possibly published record.

This is a forward storage migration. Builds that only understand whole-map checkpoints
cannot read a migrated index. Preserve a data-directory backup before rolling back to
such a build. Per-record writes do not make the effect ledger append-only, and they do
not change `Storage.DurableFile`'s file/rename/directory-sync guarantees.

## Runtime event semantics

`EventPresentation` owns provider-alias interpretation outside the web namespace. Gateway
live events, backlogs, and replay results add `semantic` for supported common concepts:
text, thinking, calls/results, usage, approvals, and terminal outcomes. A record has
`version: 1`, a `kind`, and `data`. It is computed from the redacted, transport-bounded
payload; the original payload and envelope remain available. Historical checkpoints
need no rewriting. This field is display information, never execution authority.

The terminal consumes those typed fields directly. Old servers, unknown versions,
malformed semantic records, and concepts not yet in that contract use its explicitly
named legacy parser. Browser layout and terminal grouping stay local.

`test/support/semantic_corpus.json` contains shared expected semantic records. Both
language suites consume it. The terminal also verifies that it can display each record
without reading provider fields again and falls back for unknown versions. Existing
cell tests separately pin local rendering behavior.

## Other shared mechanisms

- `ProcessEnvironment` applies credential checks and explicit Port unsets. Exec, WASM,
  and Desktop retain separate allowlists. Desktop inherits only execution/locale paths;
  macOS bootstrap-session identity is an OS property, not arbitrary environment data.
- `Transport.JsonLines` owns bounded incremental framing; each pipe retains its limits,
  buffer, noise budget, and protocol-specific encoders. LSP framing remains separate.
- `Session.Recovery`, `Session.Routing`, and `Workspace.Admission` own the common sweep,
  routing budgets, and bounded retry for the same owner's stale lease.
- `Control.Permissions.Engine` maps missing/failed/malformed engines to asks. Native
  plan-mode refusal and transport-specific approval delivery remain separate. An engine
  failure does not supply a persistent-rule suggestion.
- `ToolAttempt` carries the validated call, classification, effect id, hook context and
  authority together through live admission and execution. Rewrites and Desktop target
  confirmation replace the call and subject together. Replay substitutes recorded
  results before constructing a live attempt.
- The repetition guard bounds consecutive equivalent calls, permitting intervening
  edits; the turn iteration budget still bounds alternating calls.
- `Gateway.Methods.Contract` declares metadata, parameter envelopes, requirements, and
  literal handler names together. Type conversion, target resolution, and domain bounds
  remain explicit in handlers; option types are shared with the contract. Documentation
  and dispatch use this table; the source-reading test interpreter has been removed.
- `Web.Live.AccountConnection` owns device-code start/cancel/read/poll transitions.
  Parent views own completion behavior. Raw API keys remain callback locals and never
  become preferences or socket state.
- The CLI's `RuntimeConnection` and `Ownership` distinguish attached runtimes from owned
  children. Explicit asynchronous error cleanup and exit handling act only on owned
  children; detach relinquishes ownership. Spawn locks and process-birth checks remain
  in the existing startup path. Fleet service installation and identity checks live in
  `fleet/service.rs`, behind the existing public facade.

The separate BEAM and WASM upgrade engines remain supported. Removing an extension
lane, merging batch and interactive persistence schemas, or replacing the effect ledger
with a new storage engine would require a separate compatibility and product decision.
