# J3: Replace the remaining Jido core interfaces

Status: proposed implementation specification, 2026-09-10. No implementation is
included. Baseline: `dev` at `d6cc85309141111b6ae1ae3852b254a30092f426`.

Implement after [J1](remove-jido-ai.md) and [J2](replace-jido-harness.md). This slice
removes `jido`, `jido_action`, and `jido_signal` and their unreachable dependencies.
The resulting production application graph contains no Jido package.

## 1. Outcome

Ouroboros owns its mesh processes, message envelope, action/tool definitions, ID
generation, and checkpoint adapter contract. Preserve WASM deployment, execution,
evaluation, cleanup, rollback, and boot restoration. Preserve valid old checkpoint
readability without retaining executable Jido modules or enabling unsafe decoding.

Keep OTP distribution, supervision, and the existing durable file implementation.
Replace only the Jido behavior that has callers. Do not rebuild its general agent
framework, scheduler, signal bus, plugins, workflow engine, or thread journals.

## 2. Current dependencies and owners

| Interface | Current users | Replacement responsibility |
|---|---|---|
| `Ouroboros.Jido` / `Jido.AgentServer` | Mesh start/stop/state and directory reconciliation | Owned registry, dynamic supervisor, mesh server |
| `Jido.Agent` / state operations | Static `Wasm.Capability` and test agents | Explicit state initialization and serialized transitions |
| `Jido.Action` | Native tools, mesh receive action, WASM message action | Small owned definition/validation contract |
| `Jido.Action.Schema` | J1's owned tool schema adapter | Conversion for the schema subset actually used |
| `Jido.Signal` | `Signals.AgentMessage` | Owned typed message envelope |
| `Jido.Signal.ID` | Session/approval/correlation/artifact IDs | Owned ID utility preserving current identifier contracts |
| `Jido.Storage` / `.ETS` | Checkpoint adapters and store initialization | Owned checkpoint-only behavior and ephemeral adapter |

The source boundaries are [`Mesh`](../../lib/ouroboros/mesh.ex),
[`Mesh.Directory`](../../lib/ouroboros/mesh/directory.ex),
[`Wasm.Capability`](../../lib/ouroboros/wasm/capability.ex),
[`Tools`](../../lib/ouroboros/provider/native/tools.ex), and
[`Storage.DurableFile`](../../lib/ouroboros/storage/durable_file.ex).

## 3. Scope and exclusions

Migrate all production consumers, test agents, fixtures, config, boot helpers,
current documentation, and dependency-specific typing suppressions. Preserve the
existing gateway method set and supported data shapes.

Do not change the WASM guest ABI, artifact hashes, manifest/signature verification,
fuel/memory/deadline policy, shell sandbox, permission grammar, model behavior,
audit custody, or durable record storage format merely to remove a library.
Do not restore the removed dynamic BEAM-code deployment lane. Historical records
referring to its modules remain data; they do not become executable again.

## 4. Owned mesh runtime

Replace `Ouroboros.Jido` with `Ouroboros.Mesh.Supervisor`, an owned local Registry,
and a DynamicSupervisor. Use `Ouroboros.Mesh.Server` as the serialized owner of one
logical agent's state. Keep `Mesh` as the public start, locate, message, stop, and
inspection facade; keep `:pg` membership and `:erpc` owner-node routing.

An allowed agent module implements a narrow `Ouroboros.Mesh.Agent` behavior:

```elixir
@callback init_state(map()) :: {:ok, map()} | {:error, term()}
@callback handle_message(map(), map(), map()) ::
  {:ok, map()} | {:error, term()}
```

The arguments to `handle_message/3` are the validated message, current domain state,
and an owned context containing the logical ID and actual server PID. A successful
callback returns the complete next state. Failure leaves state unchanged unless the
domain handler deliberately represents that failure as a successful error-bearing
state transition, as the WASM handler currently does.

There are no implicit recursive merges, directives, or framework state operations.
If an action must run in a supervised task to retain current responsiveness, the
server still serializes commits and supplies its own PID explicitly in the context.
Preserve current queue, timeout, error-policy, and restart behavior used by callers;
do not replace bounded scheduling with an unbounded mailbox of pending work.

Keep the existing observable inspection subset:

```elixir
{:ok, %{agent: %{id: logical_id, state: domain_state}}}
```

This keeps the state access used by WASM holder lookup and rollout evaluation.
Inventory additional fields consumed by the gateway, tests, or diagnostics and
provide them as owned data where meaningful. Do not expose an emulation of Jido's
private scheduler/process internals. Normalize gateway output explicitly so changes
in internal struct names cannot silently change public fixtures.

Required mesh semantics:

- Duplicate healthy-cluster starts remain serialized using the existing mechanism;
  no claim of partition-safe consensus is added.
- Multiple visible owners still cause mutation/message routing to fail with
  `ambiguous_replicas`; read-only observation may remain deterministic.
- Placement requires a connected eligible node. Remote timeout, `noproc`, and
  disconnection remain returned failures rather than caller crashes.
- Directory restart reconciles existing registry members without duplicate `:pg`
  joins; process death removes/reconciles the correct membership.
- Agent allowlisting remains explicit. An old Jido-only extension is refused by a
  named unsupported-contract error before startup; no compatibility code executes it.

Preserve the bounded receive-message convention where it still has callers: newest
64 messages and the existing byte cap, last-message identity, and message count.
Do not instantiate an unused inbox/history subsystem in every WASM server.

## 5. WASM lifecycle contract

Move the current WASM handler into the owned callback contract while preserving its
domain behavior. Keep the component digest, configuration, limits, pool and store
selection, precompiled provenance, last message, last answer, and error semantics.

### Initialization and authority

Keep all current domain-specific checks and normalization of caller-supplied state.
Never trust a supplied live instance handle. Derive the instance identity from the
logical agent ID. Preserve the configured maxima and element-wise limit clamping,
trusted pool checks, store-root override policy, and precompiled digest validation.
Moving these checks earlier must not silently change documented normalization or
the signed evaluation's interpretation of initial state.

The pool receives the actual server PID directly from the owned context. It must
not depend on directory visibility to discover the owner, and must not mistake a
temporary action task for the server. The directory-not-yet-registered path therefore
cannot create an unowned instance.

### Execution and reclamation

- Every successful reply replaces `last_answer` wholesale. Keys from an earlier
  guest reply cannot survive in a later reply by deep merge.
- Preserve guest trap, fuel exhaustion, memory limit, deadline, missing instance,
  and pool failure handling. An ordinary call timeout does not by itself prove the
  instance is gone or authorize resending a potentially executed message.
- Pool monitoring remains the primary cleanup mechanism. A terminate callback can
  accelerate cleanup but cannot replace monitoring: crashes and forced kills skip it.
- Stop, crash, forced kill, supervisor restart, failed deployment, probe completion,
  and evaluation cleanup leave no owned instance or abandoned task behind.
- Rollback and reboot reconstruction still resolve the correct signed component,
  stable logical ID, digest, configuration, and bounded runtime limits.

Do not change the guest ABI or produce a new artifact hash to compensate for an
Elixir host-wrapper change.

## 6. Tool/action definitions and schema parity

Add a small `Ouroboros.Action` behavior and optional definition macro for the existing
metadata and callbacks: `name/0`, `description/0`, `schema/0`, `validate_params/1`,
and `run/2`. Keep the existing optional native description/model-schema callbacks.
Inventory any additional action exports or validation hooks with actual callers;
implement only those needed by the owned tools and mesh handlers.

Continue using a declared validation library such as the already-present
`NimbleOptions` for keyword schema validation. Own only the translation and error
normalization needed by this repository. Do not copy Jido's action executor,
retry engine, graph machinery, or support for unused schema dialects.

Replace J1's direct `Jido.Action.Schema` call inside its owned adapter with an owned
converter covering every type/option in the actual tool definitions. Keep schema
declarations as the source of truth and preserve deliberate `model_schema/0`
overrides for nested/open arguments. Unsupported future schema types fail visibly
at definition/spec construction; they must not silently degrade to a string or any.

Reuse J1's frozen schema and validation fixtures unchanged. Add a before/after
validation corpus for the action layer now being replaced: required/default values,
accepted types, bounds, key conversion precedence, malformed arguments, nested
data, and visible error text. Internal Jido exception types may become owned errors;
the existing normalized tool result and model-facing diagnostics must stay compatible.
MCP arguments remain dynamic and must not create atoms from remote schemas or keys.

`Tools.validate_call/3`, action validation, permission checks, and execution remain
separate steps. Removing the action framework must not bypass any of them or change
the effective arguments recorded in audit events.

## 7. Messages and identifiers

Keep `Ouroboros.Signals.AgentMessage` as an owned struct with its used constructor
and validation surface. Preserve `ouroboros.agent.message`, source/subject,
sender, body, correlation, causation, and any ID/time/content metadata consumed or
serialized today. Freeze its actual wire representation before replacing the macro.
There is no new general signal bus; delivery still uses `Mesh.send_message`.

Introduce `Ouroboros.ID` and replace all Jido signal-ID calls. Preserve lowercase
UUIDv7 syntax for call sites currently using it, using the existing cryptographic
randomness/time primitives or a separately justified focused dependency. Retain
prefixes such as `ouro-approval-`. Do not change J2's runtime ID format merely for
consistency, rewrite stored IDs, derive IDs from secrets, or promise a total global
order across nodes. Existing IDs remain opaque and valid on every read path.

Test version/variant bits, formatting, same-millisecond generation, and the behavior
under an injected backward clock. Event sequencing continues to use explicit cursors,
not assumptions about ordering of random UUID tails.

## 8. Checkpoint-only storage contract

Introduce `Ouroboros.Storage` with:

```elixir
@callback get_checkpoint(term(), keyword()) ::
  {:ok, term()} | :not_found | {:error, term()}
@callback put_checkpoint(term(), term(), keyword()) :: :ok | {:error, term()}
@callback delete_checkpoint(term(), keyword()) :: :ok | {:error, term()}
```

Retain the used `normalize_storage/1` forms, with explicit invalid-configuration
handling. Adapt `Storage.DurableFile` to this behavior without changing its data
encoding or publication protocol. Add `Ouroboros.Storage.ETS` for the existing
ephemeral development/test use. Give ETS tables explicit ownership by their store
lifecycle; a table must not accidentally belong to the first arbitrary caller.
Keep ephemeral versus synced durability labels accurate after module names change.

Migrate every store: effect ledger, grants, permissions, policy promotion, interactive
records, rollout registry, forge epochs, and signing journal. Inventory their config
keys, adapter options, table names, logical checkpoint keys, and on-disk paths before
changing anything. A module rename must not change a key hashed into a filename.

Remove unused thread-journal callbacks and their absence-only tests after confirming
there are no production callers. Do not add a thread store to satisfy the old behavior.

The file adapter must retain:

- The existing key hash/path, record namespace, content envelope, file mode, and
  safe Erlang-term encoding/decoding.
- Exclusive temporary creation, file sync, atomic rename, then directory sync.
- A failure before rename leaving the previous checkpoint intact.
- `commit_outcome_unknown` after a visible rename whose durable completion cannot
  be proved; no retry may turn that into an assumed absent effect.
- Existing delete durability, stale-temporary handling, integrity validation, and
  quarantine distinctions. SQLite remains an optional/rebuildable index.

## 9. Old checkpoint readability without Jido

Package removal shrinks the atom table available to `binary_to_term(..., [:safe])`.
The existing `ensure_build_loaded/0` can only preload packages still installed; it
does not make removed Jido atoms safe to decode. Address that explicitly.

Before removal, extend the synthetic boot corpus with every durable store above.
Include nested old action errors, signal/request structs, retired provider values,
module identities, capabilities, approvals, policy/signing state, and ledger
attempts. Keep the pre-core-reduction and pre-J2 corpora unchanged as additional gates.

Use the existing `Storage.RetiredAtoms` mechanism for a finite reviewed set of legacy
atom and struct-tag names. Decode known legacy shapes as data through explicit
normalizers; do not call `struct/2` on an absent Jido module. Add no executable modules
under the `Jido` namespace merely to make historical data load.

Never use unrestricted `binary_to_term`, `String.to_atom`, or dynamic module loading
on stored/untrusted values. Unknown runtime-minted module names keep the existing
documented quarantine/refusal behavior. Valid known baseline records must not be
quarantined just because their defining dependency disappeared.

Assert preservation of record counts, IDs, paths, timestamps, usage, grants,
permissions, signatures, effect outcomes, and historical event contents. Reading or
listing old data must not rewrite it, reserve a workspace, launch a removed provider,
or dispatch a model/tool/capability effect. Test both lazy-loading and all-modules-
preloaded boot in fresh VMs with no Jido BEAM files available.

## 10. Implementation slices

1. Capture action/message/storage fixtures and enumerate disappearing atoms while
   the old packages still exist. Record exact versions and baseline source revision.
2. Introduce owned IDs and message validation, then owned action definitions and
   schema conversion; prove parity with J1's corpus before removing the old calls.
3. Introduce the mesh server/supervisor and adapt WASM plus all state-inspection
   consumers. Prove local and distributed lifecycle behavior with the real helper.
4. Move adapters/stores to the owned storage contract; preserve paths and bytes,
   then complete legacy-data normalization and missing-atom coverage.
5. Remove all three packages, prune only unreachable dependencies, clean stale
   build artifacts, and run the full gates. Update architecture and fixture tooling.

Temporary compatibility facades may support individual slices, but the completed
change must have one runtime and no selectable Jido backend. Do not deploy a mixed
fleet while mesh contract versions differ; drain/stop and upgrade participating
nodes. Increment the existing [`Cluster` fleet protocol revision](../../lib/ouroboros/cluster.ex)
again for this mesh change and reuse its compatibility checks. All remote mesh
mutation/control paths must refuse mismatched peers before dispatch; do not add a
separate version-negotiation subsystem.
Code rollback after writes requires verified backward readability or restoring the
pre-migration backup on a stopped runtime; a dependency reinstall alone is insufficient.

## 11. Acceptance and validation

| Area | Required evidence |
|---|---|
| Tools | J1 schemas remain equivalent; action defaults/validation/effective inputs and audit payloads match the pre-J3 corpus |
| Mesh | Duplicate starts, ambiguous owners, remote timeouts/disconnects, directory restart, module refusal and process restart retain semantics |
| WASM state | Disjoint consecutive guest replies do not merge; malformed seeded state cannot bypass existing bounds or select an untrusted pool/store |
| WASM ownership | Forced kill and startup before directory registration both reclaim instances; evaluation/probe/deploy failure leaves no orphan |
| WASM lifecycle | Real-helper trap/timeout/resource limits, signed deploy, rollback, precompiled identity, and reboot restoration pass locally and across nodes |
| Storage | Adapter contract, stable key/path, write/delete failure injection, uncertainty, integrity, and quarantine behavior pass |
| Compatibility | All known old corpora boot without Jido; valid records are preserved; unknown data cannot create atoms or execute code |
| Public behavior | Gateway golden/protocol fixtures and client-visible mesh/WASM/session behavior remain compatible |

Run the focused mesh, tools/schema, storage, retired-atoms, WASM capability/pool,
rollout/evaluation/deploy/boot, and multi-node suites. Then run `make test`,
`make dialyzer`, golden/protocol drift checks, and the existing required-WASM CI
configuration so missing helpers fail rather than skip. Retain the Linux sandbox
proof and run browser journeys for the operator surfaces affected by the migration.

Final completion requires a clean production build with none of `jido`,
`jido_action`, `jido_signal`, `jido_ai`, or `jido_harness` in its application graph.
Remaining Jido text is limited to historical documentation, explicit legacy data
tags, and compatibility fixtures. The implementation report lists surviving
dependencies and any intentional API compatibility changes; no passing local test
is presented as proof of a deployed fleet or a live-provider outcome.
