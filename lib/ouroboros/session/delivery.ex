defmodule Ouroboros.Session.Delivery do
  @moduledoc false

  # The runtime publishes this small projection itself. Durable stores and recovery
  # must never call a runtime which may itself be waiting for a durable checkpoint.
  def state(runtime_id, generation, cursor)
      when is_binary(runtime_id) and is_binary(generation) do
    case Registry.lookup(Ouroboros.SessionRegistry, {:runtime, runtime_id}) do
      [] ->
        :settled

      [{_pid, %{generation: ^generation, terminal?: true, pending?: true, output_cursor: output}}]
      when is_integer(output) and output >= 0 ->
        if cursor == output, do: :pending, else: :uncheckpointed

      [{_pid, %{generation: value}}] when is_binary(value) and value != generation ->
        :settled

      [{_pid, %{generation: ^generation, terminal?: terminal?, pending?: pending?}}]
      when is_boolean(terminal?) and is_boolean(pending?) and (not terminal? or not pending?) ->
        :settled

      _legacy_or_unknown ->
        :unknown
    end
  rescue
    ArgumentError -> :unknown
  end

  def state(_runtime_id, _generation, _cursor), do: :settled

  def publish(runtime_id, generation, terminal?, pending?, output_cursor) do
    Registry.update_value(Ouroboros.SessionRegistry, {:runtime, runtime_id}, fn _ ->
      %{
        generation: generation,
        terminal?: terminal?,
        pending?: pending?,
        output_cursor: output_cursor
      }
    end)
  end
end
