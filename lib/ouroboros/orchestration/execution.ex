defmodule Ouroboros.Orchestration.Execution do
  @moduledoc """
  Serializable execution envelope passed to provider adapters.

  `token` survives scheduler and owner crashes. An adapter should use it as its
  provider-side idempotency/reconnect key.
  """

  @enforce_keys [:plan_id, :step_id, :attempt, :input, :metadata, :state]
  defstruct [
    :plan_id,
    :step_id,
    :token,
    :input,
    :attempt,
    :state,
    metadata: %{},
    recovered?: false
  ]

  @type t :: %__MODULE__{
          plan_id: String.t(),
          step_id: String.t(),
          token: String.t() | nil,
          input: term(),
          attempt: non_neg_integer(),
          state: atom(),
          metadata: map(),
          recovered?: boolean()
        }
end
