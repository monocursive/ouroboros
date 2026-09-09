# Checkpoints written before the core reduction

Two `Ouroboros.Storage.DurableFile` checkpoints holding atoms slice C5 deleted, read back
by `test/storage/retired_atoms_test.exs`. They are committed as bytes on purpose: a test
that built these terms in its own VM would intern `:computer_use` and the rest by running,
and would then pass on a build where `Ouroboros.Storage.RetiredAtoms` had been emptied.

| File | Store key | Holds |
|---|---|---|
| `permissions/checkpoints/omYQ2mvz3V8r8vpf1v7f2IaCRF8lg1aZfFm1nbOQw5c.term` | `Ouroboros.Control.Permissions.checkpoint_key/0` | `ComputerUse(app:com.apple.Calculator)`, `ComputerUse(observe)`, `ComputerUse(act)` and one live `Bash(ls *)`, all user scope |
| `effect-ledger/checkpoints/XnLGrSCV_IRERSfkSZWB7eyECHaDTDOgoorZOsi65Ug.term` | `Ouroboros.Agent.EffectLedger.checkpoint_key/0` | one settled `:tool_call` entry for `desktop_act`, subject `app` / `desktop_action` / `window_id` |

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
