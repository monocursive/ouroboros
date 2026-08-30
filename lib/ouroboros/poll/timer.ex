defmodule Ouroboros.Poll.Timer do
  @moduledoc false

  # One pending timer per message, not one per call.
  #
  # Both session coordinators drive themselves with `Process.send_after(self(), :poll, …)`,
  # and both have many paths that ask for a poll for the same reason at the same moment —
  # a dispatch that checkpoints and then wants an immediate drain, a steer answered while
  # the previous poll's timer is still outstanding. Armed naively, every extra timer became
  # another self-perpetuating chain: each delivery scheduled its own successor, so the
  # coordinator's real wakeup rate was `interval / number of chains` and climbed for the
  # lifetime of the session.
  #
  # The rule here is *earliest due wins*: a request for a wakeup no sooner than the one
  # already armed is dropped, and a request for an earlier one cancels its predecessor —
  # flushing the message if the cancel lost the race — so exactly one timer per key is ever
  # outstanding. That invariant is what makes an adaptive interval mean anything: a decayed
  # backoff that a second chain keeps re-arming at the fast interval is not a backoff.

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
