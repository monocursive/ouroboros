defmodule Ouroboros.HarnessEventProjection do
  @moduledoc """
  Projects normalized Harness events into the narrow form Ouroboros persists.

  Direct and remaining managed adapters already emit normalized event types. Baseline
  `Jido.Harness.Redaction` runs at their live boundaries and again in Harness storage;
  this projection never consults raw provider records.
  """

  alias Jido.Harness.Event

  @doc "Returns the provider-neutral fields Ouroboros may persist from a Harness event."
  @spec durable_fields(Event.t()) :: {Event.event_type(), map()}
  def durable_fields(%Event{} = event), do: {event.type, event.payload || %{}}
end
