# A grant checkpoint written before the core reduction

One `Ouroboros.Storage.DurableFile` checkpoint holding module atoms slice C1 deleted, read
back by `test/storage/retired_atoms_test.exs`. Committed as bytes for the same reason as the
ledger fixture beside it: a term this suite built would intern the names by running.

| File | Store key | Holds |
|---|---|---|
| `checkpoints/CP0IFH0ps1fsBRuJhefYyIIqfj7BW2_vAsCndT_MRbo.term` | `Ouroboros.Control.Grants.checkpoint_key/0` | two grants for `agent-alpha`: `:start_agent` narrowed to `[Ouroboros.Agent.Worker, Ouroboros.Agent.Coordinator]`, and `:delegate` narrowed to `["team-atlas"]` |

`Ouroboros.Control.Grants` is a deny-by-default authority whose checkpoint is one file, so a
name it cannot decode is not one lost grant — it is `{:grant_checkpoint_unreadable, …}` out
of `init/1` and a node that does not boot. The `:start_agent` allow-list is `modules:`
(`grants.ex:84`, `:97`), which holds module atoms directly, and `Ouroboros.Agent.Worker` was
`Mesh.start_agent/2`'s default `:agent` at `765bd88` — so it is the module an operator's
narrowed grant most plausibly names.

`:delegate` itself stays in `@constraints`/`@effects` and is not retired; slice C1's report
§6 says why. This fixture pins the direction that matters for a stale grant: the allow-list
still admits exactly the modules it names and nothing else, so an authority nobody has
migrated is not a wider authority.

## Provenance

The `Grant` struct and the `%{version: 1, grants: %{{principal, effect} => grant}}`
checkpoint shape are unchanged between `765bd88` and this branch. The bytes were written by
`DurableFile.put_checkpoint/3` in this worktree with the two module atoms created by
`Module.concat/1`, never spelled as literals.

Regenerating this is not routine, for the reason the ledger fixture's README gives.
