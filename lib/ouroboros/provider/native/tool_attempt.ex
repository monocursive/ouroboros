defmodule Ouroboros.Provider.Native.ToolAttempt do
  @moduledoc """
  One validated tool attempt, carried through classification, authorization and execution.

  Hook rewrites and Desktop target confirmation replace the call and classification
  together before ledger admission. The effect id remains stable throughout the attempt.
  Replay never constructs this value: it substitutes recorded results before live lookup.
  """
  @enforce_keys [:call, :module, :classified, :effect_id]
  defstruct @enforce_keys ++ [authority: nil, hook_context: []]

  def new(call, module, classified, effect_id),
    do: %__MODULE__{call: call, module: module, classified: classified, effect_id: effect_id}

  def authorize(attempt, call, classified, hook_context, authority),
    do: %{
      attempt
      | call: call,
        classified: classified,
        hook_context: hook_context,
        authority: authority
    }
end
