defmodule Ouroboros.Orchestration.Step do
  @moduledoc """
  A durable unit of work in an orchestration plan.

  Runtime owners and monitors intentionally do not live in this struct. An
  `execution_token` is the durable identity an executor uses to deduplicate a
  recovered attempt.
  """

  alias Ouroboros.Orchestration.Serializable

  @states [:pending, :ready, :running, :completed, :failed, :cancelled, :blocked]

  @enforce_keys [:id]
  defstruct [
    :id,
    :input,
    :result,
    :error,
    :execution_token,
    :started_at,
    :finished_at,
    dependencies: [],
    metadata: %{},
    state: :pending,
    attempt: 0,
    blocked_by: [],
    cancellation: nil
  ]

  @type state :: :pending | :ready | :running | :completed | :failed | :cancelled | :blocked

  @type cancellation :: %{
          required(:status) => :pending | :completed | :not_required,
          required(:reason) => term(),
          required(:requested_at) => integer(),
          optional(:finished_at) => integer(),
          optional(:outcome) => term()
        }

  @type t :: %__MODULE__{
          id: String.t(),
          input: term(),
          result: term(),
          error: term(),
          execution_token: String.t() | nil,
          started_at: integer() | nil,
          finished_at: integer() | nil,
          dependencies: [String.t()],
          metadata: map(),
          state: state(),
          attempt: non_neg_integer(),
          blocked_by: [String.t()],
          cancellation: cancellation() | nil
        }

  @spec states() :: [state()]
  def states, do: @states

  @doc false
  @spec valid?(t()) :: boolean()
  def valid?(%__MODULE__{} = step) do
    is_binary(step.id) and step.state in @states and is_list(step.dependencies) and
      Enum.all?(step.dependencies, &is_binary/1) and is_map(step.metadata) and
      is_integer(step.attempt) and step.attempt >= 0 and is_list(step.blocked_by) and
      token_valid?(step.execution_token) and Serializable.valid?(step)
  end

  def valid?(_other), do: false

  defp token_valid?(nil), do: true
  defp token_valid?(token), do: is_binary(token) and byte_size(token) > 0
end
