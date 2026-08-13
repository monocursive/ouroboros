defmodule Ouroboros.Orchestration.Execution do
  @moduledoc """
  Serializable execution envelope passed to provider adapters.

  `token` survives scheduler and owner crashes. An adapter should use it as its
  provider-side idempotency/reconnect key.

  `kind` is the step's declared kind. The scheduler resolves the executor from
  it, and it travels in the envelope so an adapter handling more than one kind,
  or a cancellation callback, never has to re-read the plan to learn what it is
  holding.
  """

  alias Ouroboros.Orchestration.Step

  @enforce_keys [:plan_id, :step_id, :attempt, :input, :metadata, :state]
  defstruct [
    :plan_id,
    :step_id,
    :token,
    :input,
    :attempt,
    :state,
    kind: :coding,
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
          kind: Step.kind(),
          metadata: map(),
          recovered?: boolean()
        }
end
