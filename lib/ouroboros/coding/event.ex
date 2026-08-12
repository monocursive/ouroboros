defmodule Ouroboros.Coding.Event do
  @moduledoc """
  A durable, provider-neutral observation from a coding task.

  Harness sequence numbers are retained separately from Ouroboros task sequence
  numbers so a task can replay provider output after its coordinator restarts without
  duplicating events.
  """

  @enforce_keys [:id, :task_id, :sequence, :type, :timestamp, :payload]
  defstruct @enforce_keys ++
              [provider: nil, provider_session_id: nil, harness_sequence: nil]

  @type t :: %__MODULE__{
          id: String.t(),
          task_id: String.t(),
          sequence: pos_integer(),
          type: atom(),
          timestamp: String.t(),
          payload: map(),
          provider: atom() | nil,
          provider_session_id: String.t() | nil,
          harness_sequence: non_neg_integer() | nil
        }

  @spec from_harness(String.t(), pos_integer(), Jido.Harness.Event.t()) :: t()
  def from_harness(task_id, sequence, %Jido.Harness.Event{} = event) do
    %__MODULE__{
      id: Jido.Signal.ID.generate!(),
      task_id: task_id,
      sequence: sequence,
      type: event.type,
      timestamp: event.timestamp,
      payload: Jido.Harness.Redaction.redact(event.payload),
      provider: event.provider,
      provider_session_id: event.provider_session_id,
      harness_sequence: event.sequence
    }
  end

  @spec internal(String.t(), pos_integer(), atom(), map()) :: t()
  def internal(task_id, sequence, type, payload \\ %{}) do
    %__MODULE__{
      id: Jido.Signal.ID.generate!(),
      task_id: task_id,
      sequence: sequence,
      type: type,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      payload: Jido.Harness.Redaction.redact(payload)
    }
  end

  @spec terminal?(t()) :: boolean()
  def terminal?(%__MODULE__{type: type}),
    do: type in [:run_completed, :run_failed, :run_cancelled, :task_lost]
end
