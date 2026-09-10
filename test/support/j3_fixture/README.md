# Pre-J3 checkpoint corpus

Captured before dependency removal from revision
`4dc862776b754544459967e5d292e81497d569b6`, the actual post-J2 checkout used for
implementation. The proposal's older `d6cc853` revision is not the capture source.
`BASELINE.json` records Elixir 1.20.2 / OTP 29 and Jido 2.3.3, jido_action 2.3.2,
jido_signal 2.2.2. `SHA256.json` freezes all 16 checkpoint files; `atoms.txt` is
the atom inventory of their decoded terms. These files are immutable evidence.

`scripts/fixture/build_j3_fixture.exs` ran against pre-J3 test BEAMs, and the final
capture was verified and regenerated in an isolated archive of that exact source
revision with its original locked packages. It uses real Jido signal and action-error
constructors and the existing DurableFile writer. Eight synthetic pre-J2 sessions
and their failed ledger entry gain nested core signals, five concrete action
exceptions, and historical agent/instruction data tags. Existing approvals,
removed-provider values, usage, identifiers, timestamps, paths, and outcomes remain.
The other six stores are recaptured using the old adapter from the original
synthetic integration corpus. The intentionally unknown runtime-minted grant in
that earlier corpus is excluded from this known-baseline corpus. Its original
quarantine gate and all old fixture bytes remain unchanged.

The agent/instruction values use their actual old constructors without starting
an agent or executing an instruction. A synthetic signed WASM manifest and its
public key appear in the nested history, with real old signal/error structs in
its signed metadata. Both the raw manifest and its original Wire encoding are
captured; each fresh boot verifies its original Ed25519 signature and proves a
round-trip through the current Wire encoder preserves the same signed term.
The history also includes a retired agent struct as a map key beside an identical
plain-map key; both entries must survive normalization without a key collision.
Signing-journal decisions remain historical refusals. No
credentials, provider invocation, capability execution, or workspace admission
was involved in capture.

## Storage inventory and preserved identity

| Config key | ETS namespace | Logical checkpoint key | Production leaf |
| --- | --- | --- | --- |
| `interactive_storage` | `:ouroboros_interactive` | `{:ouroboros, :interactive_sessions, 1}` | `interactive` |
| `effect_ledger_storage` | `:ouroboros_effect_ledger` | `{:ouroboros, :agent_effect_ledger, 1}` | `effect-ledger` |
| `grants_storage` | `:ouroboros_grants` | `{:ouroboros, :agent_grants, 1}` | `grants` |
| `permissions_storage` | `:ouroboros_permissions` | `{:ouroboros, :control_permissions, 1}` | `permissions` |
| `policy_promotion_storage` | `:ouroboros_policy_promotion` | `{:ouroboros, :policy_promotion, 1}` | `policy-promotion` |
| `capability_storage` | `:ouroboros_capabilities` | `{:ouroboros, :capability_rollouts, 1}` | `capabilities` |
| `epoch_storage` | `:ouroboros_forge_epochs` | `{:ouroboros, :forge_epoch, 1}` | `forge-epochs` |
| `signing_journal_storage` | `:ouroboros_signing_journal` | `{:ouroboros, :signing_journal, 1}` | `signing-journal` |

The interactive index is version 2. Each record uses
`{index_key, :session, 2, session_id}`. `DurableFile` still accepts `path:` and
the existing test-only `durability_hook:`; it writes
`<data_dir>/<leaf>/checkpoints/<base64url(sha256(term_to_binary(key)))>.term`.
No key contains the renamed adapter module. The content envelope, term encoding,
0600 mode, exclusive temporary open, file sync, rename, directory sync, and
uncertain-commit result are unchanged.

The old ETS adapter created named `<namespace>_checkpoints`,
`<namespace>_threads`, and `<namespace>_thread_meta` tables. Production callers
only used checkpoints. The owned adapter retains each configured namespace in
an unnamed checkpoint table, with no thread tables or dynamic name atoms.
`Ouroboros.Storage.ETS` owns these tables under the application's supervision;
they survive individual store/caller restarts and disappear when that owner
stops. Tests needing another lifetime explicitly start an owner and pass `owner:`.
Durability remains `:ephemeral_checkpoint`; DurableFile remains
`:synced_checkpoint`.

## Gate

Run `BOOT_GATE_RUNS=1 sh scripts/fixture/j3_boot_gate.sh` for one fresh lazy VM
and one fresh preloaded VM, or omit the count for ten of each. The gate fails if
any Jido BEAM is on the code path or a retired application starts. Each run
boots a new copy under a node name different from the writer, then validates
all eight store domains, nested historical errors/messages, counts and IDs,
unchanged source checksums, no quarantine, no session/capability startup and no
workspace lease. `make boot-gate` also retains the two older corpora.
