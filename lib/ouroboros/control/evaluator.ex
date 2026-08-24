defmodule Ouroboros.Control.Evaluator do
  @moduledoc """
  Provider-neutral evaluator boundary for a terminal orchestration plan.

  The supplied plan contains every durable step result/error. Implementations
  receive a stable `evaluation_id` so recovery can safely retry an interrupted
  evaluation.

  A stable ID is a correlation/deduplication input, not an exactly-once promise:
  providers without idempotent requests may be called again after a crash in
  the response-before-checkpoint window.
  """

  alias Ouroboros.Orchestration.Plan

  @type context :: %{
          required(:run_id) => String.t(),
          required(:revision) => non_neg_integer(),
          required(:evaluation_id) => String.t(),
          required(:objective) => String.t(),
          required(:plan) => Plan.t()
        }

  @type decision ::
          :accept
          | {:accept, term()}
          | {:accept, term(), Ouroboros.Control.EvidenceContract.t()}
          | {:revise, term()}
          | {:fail, term()}

  @callback evaluate(context(), keyword()) :: {:ok, decision()} | {:error, term()}
end
