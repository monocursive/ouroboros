defmodule Ouroboros.Storage.RetiredAtoms do
  @moduledoc """
  Every atom the core reduction removed that a store on disk may already hold.

  `Ouroboros.Storage.DurableFile` decodes each checkpoint with
  `:erlang.binary_to_term(binary, [:safe])`, and `[:safe]` refuses to *create* an atom, so
  a checkpoint naming an atom this build no longer has fails to decode as a **whole file**
  — not the one stale record, the file: every surviving permission rule beside it, the
  entire effect ledger — and because both stores are supervised children of
  `Ouroboros.Application`, an upgraded node does not boot and does not self-heal. Keeping
  the names below interned, without keeping a line of the code that meant them, is what
  makes such a file readable again. The consumers then have to treat the stale value as
  inert rather than as a crash: a retired pattern kind matches nothing
  (`Ouroboros.Control.Permissions.Matcher`), and a retired ledger subject key is a key
  nothing reads.

  Every later slice of the reduction appends here rather than starting its own list, and
  the comment on each entry says which slice removed it and which store held it. Nothing
  reads `all/0` at runtime: the list exists to be compiled into an atom table, which
  `Ouroboros.Storage.DurableFile` also does so that loading the adapter is enough.
  """

  @retired [
    # C5 (plan §4 A4, desktop automation). The `Pattern.kind` of any persisted
    # `ComputerUse(observe|act|app:…)` rule, in the permission checkpoint.
    :computer_use,
    # C5. `Pattern.spec.form` of a persisted `ComputerUse(observe)` rule, same checkpoint.
    :observe,
    # C5. `Pattern.spec.form` of a persisted `ComputerUse(act)` rule, same checkpoint.
    :act,
    # C5. A subject key of every `:tool_call` entry a desktop tool wrote, in the
    # effect-ledger checkpoint.
    :desktop_action,
    # C5. The second such subject key, same checkpoint.
    :window_id
  ]

  @doc """
  Every atom a surviving store may hold that no code in this build would create.

  The order is the order slices retired them.
  """
  @spec all() :: [atom()]
  def all, do: @retired
end
