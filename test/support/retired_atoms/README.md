# Checkpoints written before the core reduction

Two `Ouroboros.Storage.DurableFile` checkpoints holding atoms slice C5 deleted, read back
by `test/storage/retired_atoms_test.exs`. They are committed as bytes on purpose: a test
that built these terms in its own VM would intern `:computer_use` and the rest by running,
and would then pass on a build where `Ouroboros.Storage.RetiredAtoms` had been emptied.

| File | Store key | Holds |
|---|---|---|
| `permissions/checkpoints/omYQ2mvz3V8r8vpf1v7f2IaCRF8lg1aZfFm1nbOQw5c.term` | `Ouroboros.Control.Permissions.checkpoint_key/0` | `ComputerUse(app:com.apple.Calculator)`, `ComputerUse(observe)`, `ComputerUse(act)` and one live `Bash(ls *)`, all user scope |
| `effect-ledger/checkpoints/XnLGrSCV_IRERSfkSZWB7eyECHaDTDOgoorZOsi65Ug.term` | `Ouroboros.Agent.EffectLedger.checkpoint_key/0` | one settled `:tool_call` entry for `desktop_act`, subject `app` / `desktop_action` / `window_id` |

Two more hold atoms slice C2 (native is the only provider) deleted, an
`Ouroboros.Storage.Records` store and a single-file ledger checkpoint:

| File | Store | Holds |
|---|---|---|
| `interactive/checkpoints/*.term` (index + one record) | `Ouroboros.Interactive.Store` | one session record `fixture-retired-claude` with `provider: :claude`, `options.transport: :acp`, `provider_options` keys `cli_path` / `betas` / `no_ide`, and `error: :provider_transport_unavailable` |
| `effect-ledger-provider/checkpoints/XnLGrSCV_IRERSfkSZWB7eyECHaDTDOgoorZOsi65Ug.term` | `Ouroboros.Agent.EffectLedger.checkpoint_key/0` | one settled `:tool_call` entry whose `attempt.provider` is `:claude` |

The C2 bytes were written by `scratchpad/rev/mkfixture_c2.exs` in a separate VM: the record
is a valid `provider: :native` `Interactive.State.new/2` struct, then mutated to name the
removed provider, transport, `provider_options` keys and ACP failure atom — **each created
by `String.to_atom/1`** — and written through the real `Storage.Records` and `EffectLedger`
paths. `interactive/` is a Records store, so it has an index file (`{:ouroboros,
:interactive_sessions, 1}`, holding only `:version`/`:ids`) beside the one record; the
`is exercised` test preloads the build (as the store does) before its raw `[:safe]` read so
those structural keys are interned. Nine of the ten provider names, and every one of these
atoms, is also spelled by `jido_harness` on a real boot, so **the fixture cannot fail a real
node on them**; the bare-VM probe (removing `:claude` from `RetiredAtoms` and decoding in an
`elixir -pa` VM) is the proof that the list, not luck, is what interns them.

## Provenance

The terms are `765bd88`'s — the commit slice C5 was cut from, the last one whose code
could produce them. `765bd88`'s `Pattern.parse!/1` was run against the three
`ComputerUse(…)` strings and returned exactly the `kind`, `spec`, `raw` and `fragile?` the
permission fixture carries; the ledger subject is exactly what that commit's
`EffectLedger.sanitize_subject/1` emitted for a desktop tool call (`effect_ledger.ex:739-744`
there, the three `put_if` lines this slice removed). The bytes were then written by
`DurableFile.put_checkpoint/3` in this worktree, with the four deleted atoms created by
`String.to_atom/1`: `:erlang.term_to_binary/1` does not record which build interned a name,
and the `Rule`, `Pattern` and `EffectLedger.Entry` structs are byte-for-byte the same on
both commits.

Regenerating them is not routine — these are a record of what an older node wrote, not a
golden fixture that follows the code. If a store's checkpoint *format* changes so that
these can no longer be read at all, that is the migration the change owes an answer to,
and the answer belongs beside it rather than in a rewrite of these bytes.

## Checkpoints this build cannot decode

Captured bytes, not code. Each file is one `:erlang.term_to_binary/1` checkpoint written by
a VM that held a name this repo's source never contained, so `:erlang.binary_to_term(bytes,
[:safe])` refuses it on every build — including the one that reads it back in the suite. The
tests copy a file into a temporary store and assert the owning process boots anyway, with
the bytes quarantined beside it. They exist so those tests do not quietly depend on the test
VM never having interned the name.

| file | written by | holds | read back by |
|---|---|---|---|
| `grants_forge_capability_atom.checkpoint.term` | `Ouroboros.Control.Grants` v1 | one `:forge` grant whose `constraints.modules` is `Elixir.Ouroboros.Capability.ForgedGrantProbe`, a capability module atom the deleted BEAM forge lane minted at runtime | `test/storage/checkpoint_quarantine_test.exs` |
| `effect_ledger_forge_capability_atom.checkpoint.term` | `Ouroboros.Agent.EffectLedger` v3 | one settled `forge` entry carrying the same atom in `attempt.module`, `result.module` and `authority.constraints.modules` | `test/storage/checkpoint_quarantine_test.exs` |

Never write that name as a literal — not here, not in a test, not in `test/support`. A
literal interns it in the beam of whatever compiles it, and the fixture stops being the
hazard it is here to be. `String.to_atom/1` in a separate VM is how these were made:

```elixir
# mix run <script> test/support/retired_atoms
capability = String.to_atom("Elixir.Ouroboros.Capability.ForgedGrantProbe")

%{
  version: 1,
  grants: %{
    {"agent-1", :forge} => %Ouroboros.Control.Grants.Grant{
      principal: "agent-1",
      effect: :forge,
      constraints: %{modules: [capability]},
      granted_at: "2026-08-20T11:04:07.000000Z"
    }
  }
}
|> then(&File.write!("test/support/retired_atoms/grants_forge_capability_atom.checkpoint.term", :erlang.term_to_binary(&1)))
```

The ledger file is the same recipe over one `Ouroboros.Agent.EffectLedger.Entry` struct;
`test/storage/checkpoint_quarantine_test.exs` names every field it asserts on.
