defmodule Ouroboros.HarnessEventProjection do
  @moduledoc false

  alias Jido.Harness.Event

  @doc "Normalizes the narrow provider event Ouroboros needs before Harness journals it."
  @spec before_journal(Event.t(), [String.t()]) :: Event.t()
  def before_journal(%Event{} = event, extra_secrets \\ []) do
    case started_codex_command(event) do
      {:ok, payload} ->
        %{
          event
          | type: :tool_call,
            payload: Jido.Harness.Redaction.redact(payload, extra_secrets)
        }

      :error ->
        event
    end
  end

  @doc "Returns the provider-neutral fields Ouroboros may persist from a Harness event."
  @spec durable_fields(Event.t()) :: {Event.event_type(), map()}
  def durable_fields(%Event{} = event) do
    event = before_journal(event)
    {event.type, event.payload || %{}}
  end

  defp started_codex_command(%Event{
         provider: :codex,
         type: :provider_event,
         raw: %{
           "type" => "item.started",
           "item" => %{"type" => "command_execution"} = item
         }
       }),
       do: {:ok, command_tool_call(item)}

  defp started_codex_command(%Event{}), do: :error

  # Codex reports the same item id again when the command completes. Keeping that
  # identifier in the durable normalized payload lets replaying clients update the
  # running row instead of inventing a second command.
  defp command_tool_call(item) do
    %{
      "call_id" => item["id"] || "command",
      "name" => "exec_command",
      "input" => %{"cmd" => item["command"], "cwd" => item["cwd"]}
    }
  end
end
