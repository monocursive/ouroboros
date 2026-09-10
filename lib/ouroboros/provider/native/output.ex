defmodule Ouroboros.Provider.Native.Output do
  @moduledoc """
  Private retained transport state owned by Native.Session, with no worker process.

  Production bounds are 4,096 events and 32 MiB, with an 8 MiB individual event limit.
  A separate 256-event / 8 MiB reserve admits lifecycle and denial/cancel markers
  while the loop's single synchronous submission waits. These limits are node
  configuration (`:native_output_limits`), never a caller-controlled request option.
  The 8 MiB event bound exceeds the existing 3 MB detailed file-change fixture;
  the 32 MiB queue accommodates two existing 16 MiB detail retention windows.
  Output is released only by acknowledgement from the current attachment.
  """

  @default_count 4096
  @default_bytes 32 * 1024 * 1024
  @default_event_bytes 8 * 1024 * 1024
  @reserve_count 256
  @reserve_bytes 8 * 1024 * 1024
  @text_bytes 1024 * 1024

  def new(request) do
    limits = Application.get_env(:ouroboros, :native_output_limits, [])
    table = :ets.new(__MODULE__, [:ordered_set, :private])

    :ets.insert(
      table,
      {:meta,
       %{
         cursor: 0,
         acked: 0,
         count: 0,
         bytes: 0,
         max_count: Keyword.get(limits, :max_count, @default_count),
         max_bytes: Keyword.get(limits, :max_bytes, @default_bytes),
         event_bytes: Keyword.get(limits, :event_bytes, @default_event_bytes),
         reserve_count: @reserve_count,
         reserve_bytes: @reserve_bytes,
         attachment: nil,
         coordinator: nil,
         notified?: false,
         drained: 0,
         secrets: Ouroboros.Redaction.secrets_from_env(request.env)
       }}
    )

    table
  end

  def snapshot(table), do: :ets.lookup_element(table, :meta, 2)
  def high_water(table), do: snapshot(table).cursor
  def empty?(table), do: snapshot(table).count == 0

  def attach(table, coordinator, attachment, cursor) do
    meta = snapshot(table)

    put(table, %{
      meta
      | coordinator: coordinator,
        attachment: attachment,
        notified?: meta.coordinator == coordinator and meta.notified?,
        drained: max(meta.acked, min(cursor, meta.cursor))
    })

    notify(table)
  end

  def detach(table) do
    meta = snapshot(table)
    put(table, %{meta | coordinator: nil, attachment: nil, notified?: false})
  end

  def authorized?(table, attachment, caller) do
    meta = snapshot(table)
    meta.attachment == attachment and meta.coordinator == caller
  end

  def control_room?(table, count) do
    meta = snapshot(table)

    meta.count + count <= meta.max_count and meta.bytes < meta.max_bytes
  end

  def admission(table, event) do
    meta = snapshot(table)
    bytes = encoded_size(event)

    cond do
      bytes > min(meta.event_bytes, meta.max_bytes) -> {:error, :event_too_large}
      meta.count >= meta.max_count or meta.bytes + bytes > meta.max_bytes -> :full
      true -> :ok
    end
  end

  def control_admission(table, event) do
    case admission(table, event) do
      :ok -> :ok
      :full -> {:error, :output_backpressure}
      error -> error
    end
  end

  def append!(table, event) do
    meta = snapshot(table)

    event = %{
      event
      | sequence: meta.cursor + 1,
        payload: Ouroboros.Redaction.redact(event.payload, meta.secrets)
    }

    bytes = encoded_size(event)

    if bytes > meta.event_bytes or meta.count >= meta.max_count + meta.reserve_count or
         meta.bytes + bytes > meta.max_bytes + meta.reserve_bytes do
      # Fail closed with a runtime disappearance/gap; never silently evict unacked facts.
      exit({:retained_output_exhausted, %{count: meta.count, bytes: meta.bytes}})
    end

    :ets.insert(table, {{:event, event.sequence}, event, bytes})
    put(table, %{meta | cursor: event.sequence, count: meta.count + 1, bytes: meta.bytes + bytes})
    accumulate(table, event)
    notify(table)
    :ok
  end

  def drain(table, attachment, cursor, limit)
      when is_integer(cursor) and cursor >= 0 and
             is_integer(limit) and limit > 0 and limit <= 500 do
    meta = snapshot(table)

    cond do
      meta.attachment != attachment ->
        {:error, :stale_attachment}

      cursor < meta.acked ->
        {:error,
         {:retained_range_gap,
          %{
            requested: cursor,
            retained_from: meta.acked + 1,
            high_water: meta.cursor,
            generation: attachment.generation
          }}}

      cursor > meta.cursor ->
        {:error,
         {:retained_range_gap,
          %{
            requested: cursor,
            retained_from: meta.acked + 1,
            high_water: meta.cursor,
            generation: attachment.generation,
            reason: :cursor_ahead
          }}}

      true ->
        events =
          for seq <- indexes(cursor, min(meta.cursor, cursor + limit)),
              [{_, event, _}] = :ets.lookup(table, {:event, seq}),
              do: event

        drained =
          case List.last(events) do
            nil -> cursor
            event -> event.sequence
          end

        put(table, %{meta | drained: max(meta.drained, drained)})
        {:ok, events}
    end
  end

  def drain(_table, _attachment, _cursor, _limit), do: {:error, :invalid_cursor}

  def ack(table, attachment, cursor) do
    meta = snapshot(table)

    cond do
      meta.attachment != attachment ->
        {:error, :stale_attachment}

      not is_integer(cursor) or cursor < meta.acked or cursor > meta.drained ->
        {:error, :invalid_ack}

      true ->
        {count, bytes} =
          Enum.reduce(indexes(meta.acked, cursor), {0, 0}, fn seq, {count, bytes} ->
            case :ets.take(table, {:event, seq}) do
              [{_, _event, size}] -> {count + 1, bytes + size}
              [] -> {count, bytes}
            end
          end)

        :ets.match_object(table, {{:turn, :_}, :_})
        |> Enum.each(fn {key, result} ->
          if is_integer(result.terminal_cursor) and result.terminal_cursor <= cursor,
            do: :ets.delete(table, key)
        end)

        put(table, %{
          meta
          | acked: cursor,
            count: meta.count - count,
            bytes: meta.bytes - bytes,
            notified?: false
        })

        notify(table)
        :ok
    end
  end

  def register_turn(table, session_id, turn_id, request, conversation_id) do
    result = %{
      session_id: session_id,
      turn_id: turn_id,
      provider: :native,
      provider_session_id: conversation_id,
      status: :running,
      text: "",
      text_truncated?: false,
      usage: %{},
      metadata: request.metadata,
      error: nil,
      events: [],
      final?: false,
      terminal_cursor: nil
    }

    :ets.insert(table, {{:turn, turn_id}, result})
  end

  def turn_result(table, turn_id) do
    case :ets.lookup(table, {:turn, turn_id}) do
      [{_, %{terminal_cursor: nil}}] ->
        {:error, :timeout}

      [{_, result}] ->
        events =
          :ets.match_object(table, {{:event, :_}, :_, :_})
          |> Enum.map(fn {_, event, _} -> event end)
          |> Enum.filter(&(&1.turn_id == turn_id))

        {:ok, result |> Map.drop([:final?, :terminal_cursor]) |> Map.put(:events, events)}

      [] ->
        {:error, :not_found}
    end
  end

  defp accumulate(table, %{turn_id: turn_id} = event) when is_binary(turn_id) do
    case :ets.lookup(table, {:turn, turn_id}) do
      [{key, result}] ->
        result =
          case event.type do
            :output_text_delta ->
              if(result.final?,
                do: result,
                else: text(result, result.text <> (event.payload["text"] || ""))
              )

            :output_text_final ->
              result |> text(event.payload["text"] || "") |> Map.put(:final?, true)

            :usage ->
              %{result | usage: Map.merge(result.usage, event.payload)}

            type when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
              status =
                %{
                  turn_completed: :completed,
                  turn_failed: :failed,
                  turn_interrupted: :interrupted
                }[type]

              %{
                result
                | status: status,
                  terminal_cursor: event.sequence,
                  error: if(status == :failed, do: event.payload["error"], else: nil)
              }

            _ ->
              result
          end

        :ets.insert(table, {key, result})

      [] ->
        :ok
    end
  end

  defp accumulate(_table, _event), do: :ok

  defp text(result, text) when byte_size(text) <= @text_bytes, do: %{result | text: text}

  defp text(result, text) do
    text = binary_part(text, byte_size(text) - @text_bytes, @text_bytes)
    %{result | text: valid_tail(text), text_truncated?: true}
  end

  defp valid_tail(<<>>), do: ""

  defp valid_tail(text) do
    if String.valid?(text), do: text, else: valid_tail(binary_part(text, 1, byte_size(text) - 1))
  end

  defp notify(table) do
    meta = snapshot(table)

    if is_pid(meta.coordinator) and not meta.notified? and meta.cursor > meta.acked do
      send(
        meta.coordinator,
        {:session_output, meta.attachment.runtime_id, meta.attachment.generation, meta.cursor}
      )

      put(table, %{meta | notified?: true})
    end

    :ok
  end

  defp indexes(cursor, cursor), do: []
  defp indexes(cursor, last) when cursor < last, do: (cursor + 1)..last
  defp put(table, meta), do: :ets.insert(table, {:meta, meta})
  defp encoded_size(event), do: event |> :erlang.term_to_binary() |> byte_size()
end
