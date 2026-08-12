defmodule Ouroboros.Interactive.Event do
  @moduledoc "A redacted, durable projection of one Harness session event."

  @enforce_keys [:id, :session_id, :sequence, :type, :timestamp, :payload]
  defstruct @enforce_keys ++
              [
                :harness_session_id,
                :provider,
                :provider_session_id,
                :turn_id,
                :request_id
              ]

  @type t :: %__MODULE__{
          id: String.t(),
          session_id: String.t(),
          sequence: pos_integer(),
          type: atom(),
          timestamp: String.t(),
          payload: map(),
          harness_session_id: String.t() | nil,
          provider: atom() | nil,
          provider_session_id: String.t() | nil,
          turn_id: String.t() | nil,
          request_id: String.t() | nil
        }

  @doc false
  @spec from_harness(String.t(), Jido.Harness.Event.t()) :: t()
  def from_harness(session_id, %Jido.Harness.Event{} = event) do
    %__MODULE__{
      id: event_id(session_id, event.sequence),
      session_id: session_id,
      sequence: event.sequence,
      type: event.type,
      timestamp: event.timestamp,
      payload: Jido.Harness.Redaction.redact(event.payload || %{}),
      harness_session_id: event.session_id,
      provider: event.provider,
      provider_session_id: event.provider_session_id,
      turn_id: event.turn_id,
      request_id: event.request_id
    }
  end

  defp event_id(session_id, sequence) do
    :sha256
    |> :crypto.hash(:erlang.term_to_binary({:ouroboros_interactive_event, session_id, sequence}))
    |> Base.url_encode64(padding: false)
  end
end
