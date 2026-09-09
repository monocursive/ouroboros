defmodule Ouroboros.Storage.RetiredAtoms do
  @moduledoc """
  Atoms this build no longer spells, which a checkpoint an older build wrote still holds.

  `Ouroboros.Storage.DurableFile` reads with `:erlang.binary_to_term(binary, [:safe])`,
  which refuses to *create* an atom. A store is one file, so an atom the reading VM has
  never interned does not cost one record — it costs the whole store, and a node that
  cannot read its interactive sessions or its cluster journal does not boot. Deleting the
  last line of code that spelled an atom is therefore a durable-format change, whatever
  else it is.

  Listing an atom here is not a shim and keeps no code path alive: it interns the name and
  nothing more. The reader that used to understand the value must treat it as a value that
  matches nothing — an unknown event type presents as a named note, an unknown map key is
  carried and ignored — and never as a reason to crash.

  Journals that route through `Ouroboros.Upgrade.Wire` (the signing journal, the rollout
  registry, the node executor, the WASM store) need no entry here: that boundary writes
  every atom as a tagged binary and reads an unknown one back as its name.

  This list is consumed at compile time by `Ouroboros.Storage.DurableFile`, so the atoms
  are interned by the module that does the decoding, whatever loads first.
  """

  # Each atom, and the store that may still hold it.
  @retired [
    # `Ouroboros.Interactive.State`'s field for what a conversation delegated. Every
    # interactive checkpoint written before September 2026 has this key.
    :delegations,
    # The transcript event type `/delegate` appended to the parent conversation.
    :delegation,
    # The delegation record's team, inside that field.
    :team_id,
    # The node the delegated task ran on, inside that field.
    :task_node,
    # The digest of the delegated objective, inside that field.
    :objective_digest,
    # The digest of the delegated result, inside that field.
    :result_digest,
    # Two delegation statuses the parent copied from the team's own record. The others it
    # could hold — `:started`, `:pending`, `:active`, `:completed`, `:failed`,
    # `:cancelled`, `:lost` — are still spelled elsewhere in this build.
    :delivering,
    :delivered,
    # The second plane's key in `Ouroboros.Cluster`'s session-owner checkpoint. Still
    # spelled in `Ouroboros.Provider` today; listed because the checkpoint outlives the
    # line that spells it.
    :coding
  ]

  @doc "Every atom this build interns only so an older checkpoint can be read."
  @spec retired() :: [atom()]
  def retired, do: @retired
end
