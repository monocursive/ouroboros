defmodule Ouroboros.Poll.Timer do
  @moduledoc false

  # One pending timer per message, not one per call.
  #
  # The interactive coordinator uses this only for explicit reconciliation and failed
  # checkpoint retries. Native output normally wakes the coordinator by notification;
  # there is no recurring active or idle output poll.
  #
  # The rule here is *earliest due wins*: a request for a wakeup no sooner than the one
  # already armed is dropped, and a request for an earlier one cancels its predecessor —
  # flushing the message if the cancel lost the race — so exactly one timer per key is ever
  # outstanding. Overlapping recovery requests cannot multiply the retry schedule.

  @type runtime :: map()
  @type key :: atom()

  @doc """
  Arms `message` to arrive in `delay` ms, unless a sooner one is already armed.

  `key` names the field on `runtime` holding this timer's `%{ref: reference, due: integer}`
  record — the caller's runtime map must already carry it (as `nil` when unarmed).
  """
  @spec schedule(runtime(), key(), term(), non_neg_integer()) :: runtime()
  def schedule(runtime, key, message, delay) when is_integer(delay) and delay >= 0 do
    due = System.monotonic_time(:millisecond) + delay

    case Map.fetch!(runtime, key) do
      %{due: pending_due} when pending_due <= due ->
        runtime

      pending ->
        cancel(pending, message)
        Map.put(runtime, key, %{ref: Process.send_after(self(), message, delay), due: due})
    end
  end

  @doc """
  Forgets the timer under `key`, for the handler of the message it just delivered.

  A delivered timer's record is stale — its `due` is in the past, so leaving it in place
  would make every later `schedule/4` believe a sooner wakeup was already armed.
  """
  @spec clear(runtime(), key()) :: runtime()
  def clear(runtime, key), do: Map.put(runtime, key, nil)

  @doc """
  Cancels a pending timer record, flushing its message if the cancel lost the race.
  """
  @spec cancel(nil | %{ref: reference()}, term()) :: :ok
  def cancel(nil, _message), do: :ok

  def cancel(%{ref: ref}, message) do
    if Process.cancel_timer(ref) == false do
      receive do
        ^message -> :ok
      after
        0 -> :ok
      end
    end

    :ok
  end
end
