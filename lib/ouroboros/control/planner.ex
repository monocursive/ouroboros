defmodule Ouroboros.Control.Planner do
  @moduledoc """
  Provider-neutral planner boundary.

  Implementations receive a stable `request_id`. A provider-backed adapter
  should use it as its idempotency key because a process crash may cause the
  same logical request to be invoked again.

  The ID alone does not make an inference provider exactly-once. An adapter
  without provider-side deduplication can repeat work after the provider
  responds but before Ouroboros checkpoints the returned plan.
  """

  @type context :: %{
          required(:run_id) => String.t(),
          required(:revision) => non_neg_integer(),
          required(:request_id) => String.t(),
          required(:feedback) => term(),
          required(:previous_plan) => Ouroboros.Orchestration.Plan.t() | nil
        }

  @callback plan(String.t(), context(), keyword()) ::
              {:ok, [map() | keyword()] | %{required(:steps) => [map() | keyword()]}}
              | {:error, term()}
end
