# Runtime simplification, September 2026

The audit led to shared mechanisms at existing boundaries. Interactive sessions, native
subagents, and the WebAssembly capability lane retain their distinct lifetimes and APIs.

> The coding, team, orchestration and control planes this document also covered were
> deleted in September 2026; see [the core reduction](proposals/core.md) §3 D3. The
> merge of the interactive and coding persistence schemas it once proposed is moot.

## Ownership and restart matrix

The root remains `rest_for_one`. Its durable directory owner, effect ledger, model
admission, permission authorities, stores, and workspace manager are upstream of their
consumers. The interactive store remains above the workspace manager because it reads
its checkpoints to reconstruct reservations before admitting work.

| Replaced owner | Must restart | Must survive |
|---|---|---|
| Durable directory owner or effect ledger | All execution consumers | No consumer may retain stale authority |
| Model admission | Jido and downstream execution consumers | Effect ledger |
| Workspace manager | Session coordinators and downstream surfaces | Durable stores |
| Interactive registry | Interactive task supervisor and recovery | Workspace reservations |
| WASM supervisor | Its pool, then boot recovery | MCP and web |
| Gateway or web | Its own connections | Durable owners and unrelated helpers |

`ApplicationRecoveryTest` injects authority and registry failures.
`McpTest` exhausts the MCP budget and checks surviving peers. The WASM
boot task remains transient and follows the WASM supervisor in its own `rest_for_one`
subtree. This is different from the temporary worktree reconciliation task.

The isolation checks exercise normal restart-budget escalation. An untrappable kill of
a supervisor bypasses its child shutdown; named-child cleanup races or repeated parent
failures can still exhaust the surface tier and restart its siblings.

The gateway binds and publishes synchronously, preserving startup failures at that
boundary. Its linked acceptor waits for the runtime application to finish starting
before handling requests. An immediate `runtime.shutdown` therefore cannot interrupt
application startup and bypass removal of the gateway and runtime-owner markers.

## Checkpoint publication

`Storage.Records` is the per-record store, and `Interactive.Store` is the only store built
on it: one `Storage.DurableFile` checkpoint per session plus a versioned index. Every other
durable store — grants, permissions, the effect ledger, policy promotion, the rollout
register, the signing journal, the epoch watermark, the cluster's session-owner record —
keeps one aggregate checkpoint. The owner retains validation, version checks, and domain
transitions. Updating an existing record writes only that record, including its own
retained history.

- Creation: sync the record, then publish its id in the versioned index.
- Deletion: publish the reduced index, then remove orphan files.
- Migration: retain the legacy aggregate until every record is written and the new
  index is published. Interactive retains its existing `:session` record-key format.
- Corruption: fail closed on an unreadable index; quarantine an unreadable individual
  record, keeping its bytes for inspection and loading the remaining records. The
  aggregate stores that can hold a name no build can spell — grants and the effect
  ledger — apply the same doctrine at file granularity; see "Durable checkpoints across
  builds" below.
- Ambiguous commit: stop the store for reconciliation; never claim a definite refusal
  or undo a possibly published record.

This is a forward storage migration. Builds that only understand whole-map checkpoints
cannot read a migrated index. Preserve a data-directory backup before rolling back to
such a build. Per-record writes do not make the effect ledger append-only, and they do
not change `Storage.DurableFile`'s file/rename/directory-sync guarantees.

## Runtime event semantics

`EventPresentation` owns the runtime's event projection. It used to own provider-alias
interpretation as well — the camelCase ACP spellings, the Codex and Claude key variants —
and lost it in September 2026 with the wrapped vendor providers themselves
([the core reduction](proposals/core.md) §3 D2): one provider writes one spelling. Gateway
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

- `ProcessEnvironment` applies credential checks and explicit Port unsets. Exec and WASM
  retain separate allowlists.
- `Transport.JsonLines` owns bounded incremental framing; each pipe retains its limits,
  buffer, noise budget, and protocol-specific encoders.
- `Session.Recovery`, `Session.Routing`, and `Workspace.Admission` own the common sweep,
  routing budgets, and bounded retry for the same owner's stale lease.
- `Control.Permissions.Engine` maps missing/failed/malformed engines to asks. The native
  plan-mode refusal remains separate. An engine failure does not supply a persistent-rule
  suggestion.
- `ToolAttempt` carries the validated call, classification, effect id, hook context and
  authority together through live admission and execution. A hook rewrite replaces the
  call and subject together. Replay substitutes recorded results before constructing a
  live attempt.
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
  in the existing startup path. Fleet service installation was deleted with the rest of
  the enrollment product (`proposals/core.md` §3).

## Durable checkpoints across builds

Every `Storage.DurableFile` checkpoint is decoded with
`:erlang.binary_to_term(binary, [:safe])`, which refuses to create an atom, so a build
that deletes the last module spelling an atom has changed the durable format whatever
else it did. Three mechanisms, one per kind of name, keep a data directory written by an
older build readable: `Ouroboros.Storage.RetiredAtoms` for a name no module of this build
spells any more; `DurableFile.get_checkpoint_or_quarantine/2` for a name no build can
spell — the node that wrote a record, or a capability module minted at runtime; and
`DurableFile.ensure_build_loaded/0` for a name this build spells in a module that has not
loaded yet. The cost of a miss depends on the store: a `Storage.Records` store drops one
record from its index and boots, and a whole-file store would lose the file, which is why
grants and the effect ledger quarantine the file and start empty rather than stop the
node. The contract, both blast radii, and what an operator sees afterwards are in
[ARCHITECTURE.md](ARCHITECTURE.md#durable-checkpoints), and `make boot-gate` is the
proof: a data directory written by `dev` at `3bc8887` booting on this tree, twenty times.

There is one extension lane, WebAssembly, and one persistence schema for sessions, the
interactive one. Adding a second lane, or replacing the effect ledger with a different
storage engine, would require a separate compatibility and product decision.
