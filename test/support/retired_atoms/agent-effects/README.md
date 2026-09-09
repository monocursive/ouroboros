# An effect-ledger checkpoint written before the core reduction

One `Ouroboros.Storage.DurableFile` checkpoint holding atoms slice C1 deleted, read back by
`test/storage/retired_atoms_test.exs`. It is committed as bytes on purpose: a test that
built this term in its own VM would intern `:effect_denied` and the rest by running, and
would then pass on a build where `Ouroboros.Storage.RetiredAtoms` had been emptied.

| File | Store key | Holds |
|---|---|---|
| `checkpoints/XnLGrSCV_IRERSfkSZWB7eyECHaDTDOgoorZOsi65Ug.term` | `Ouroboros.Agent.EffectLedger.checkpoint_key/0` | five entries the deleted `Ouroboros.Agent.Effects.Runner` wrote |

The five, newest first:

1. a `:denied` `:delegate` whose error classification is
   `{:effect_denied, :delegate, :unidentified_principal}` — the runner's own guard for an
   agent with no identity;
2. an `:ok` `:start_agent` naming `Ouroboros.Agent.Worker` in `attempt.module` and
   `result.module`, under an authority whose `constraints.modules` allow-list names
   `Ouroboros.Agent.Worker` and `Ouroboros.Agent.Coordinator`;
3. and 4. two `:ok` `:delegate` results carrying the team's separate `delivery` field, once
   `:delivered` and once `:delivering`;
5. a `:failed` `:delegate` whose classification is
   `{:effect_failed, :delegate, {:delegation_setup_failed, :coding_start,
   {:coding_task_owner_conflict, :text}}}` — three levels of atom, which is what
   `EffectLedger.classify/1` preserves and `Team.Server.durable_error/1` preserved below it.

## Provenance

The shapes are `765bd88`'s — the commit slice C1 was cut from, the last one whose code could
produce them. Each entry was written against that commit's own sources rather than invented:
`sanitize_error/1` stores `%{classification: classify(error), fingerprint: …}`
(`effect_ledger.ex:833` here, unchanged from there), `classify/1` returns an atom as itself
and walks a tuple element by element, and `@attempt_fields.start_agent` /
`@result_fields.start_agent` / `@result_fields.delegate` are the same lists on both commits.
The error terms are the runner's verbatim: `principal/2` at
`765bd88:agent/effects/runner.ex:130`, `settlement/3` at `:288`, and the team server's
`fail_durable_delegation/4` stage atoms at `:1746`, `:1783`, `:1873`, `:1877`.

The bytes were written by `DurableFile.put_checkpoint/3` in this worktree, with every
retired atom created by `String.to_atom/1`: `:erlang.term_to_binary/1` does not record which
build interned a name, and the `EffectLedger.Entry` struct is byte-for-byte the same on both
commits. `origin_node` and `result.node` are `:nonode@nohost` rather than a real node name,
because a node name cannot be pre-interned by any list — a separate, pre-existing hazard
that this fixture is deliberately not about.

Regenerating this is not routine — it is a record of what an older node wrote, not a golden
fixture that follows the code. If the ledger's checkpoint *format* changes so that this can
no longer be read at all, that is the migration the change owes an answer to, and the answer
belongs beside it rather than in a rewrite of these bytes.
