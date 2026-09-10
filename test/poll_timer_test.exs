defmodule Ouroboros.PollTimerTest do
  use ExUnit.Case, async: true
  alias Ouroboros.Poll.Timer

  describe "Timer" do
    test "arming once delivers exactly one message" do
      runtime = Timer.schedule(%{poll_timer: nil}, :poll_timer, :poll, 0)

      assert %{ref: ref} = runtime.poll_timer
      assert is_reference(ref)
      assert_receive :poll, 1_000
      refute_receive :poll, 50
    end

    test "a request no sooner than the one already armed is dropped, not stacked" do
      armed = Timer.schedule(%{poll_timer: nil}, :poll_timer, :poll, 5_000)
      %{ref: original} = armed.poll_timer

      later = Timer.schedule(armed, :poll_timer, :poll, 10_000)
      same = Timer.schedule(armed, :poll_timer, :poll, 5_000)

      assert later.poll_timer.ref == original
      assert same.poll_timer.ref == original
      assert is_integer(Process.read_timer(original))
    end

    test "an earlier request replaces the pending timer instead of adding a second" do
      armed = Timer.schedule(%{poll_timer: nil}, :poll_timer, :poll, 5_000)
      %{ref: original} = armed.poll_timer

      sooner = Timer.schedule(armed, :poll_timer, :poll, 0)

      refute sooner.poll_timer.ref == original
      assert Process.read_timer(original) == false
      assert_receive :poll, 1_000
      refute_receive :poll, 50
    end

    # The multiplication this discipline exists to stop: before it, every one of these
    # calls armed its own timer, and every delivery scheduled its own successor, so a busy
    # conversation ended up with as many self-perpetuating poll chains as it had verbs.
    test "many overlapping requests still yield exactly one outstanding timer" do
      runtime =
        Enum.reduce(1..25, %{poll_timer: nil}, fn _call, acc ->
          Timer.schedule(acc, :poll_timer, :poll, 0)
        end)

      assert %{ref: ref} = runtime.poll_timer
      assert is_reference(ref)
      assert_receive :poll, 1_000
      refute_receive :poll, 100
    end

    test "clear/2 forgets a delivered timer so the next schedule is not mistaken for later" do
      runtime =
        %{poll_timer: nil}
        |> Timer.schedule(:poll_timer, :poll, 5_000)
        |> Timer.clear(:poll_timer)

      assert runtime.poll_timer == nil
      assert %{ref: ref} = Timer.schedule(runtime, :poll_timer, :poll, 0).poll_timer
      assert is_reference(ref)
    end

    test "cancel/2 flushes the message when the timer already fired" do
      ref = Process.send_after(self(), :poll, 0)
      until(fn -> Process.read_timer(ref) == false end)

      assert Timer.cancel(%{ref: ref}, :poll) == :ok
      refute_received :poll
    end

    test "cancel/2 on an unarmed slot is a no-op" do
      assert Timer.cancel(nil, :poll) == :ok
    end
  end

  # Waits for a condition rather than for a duration: the ceiling is generous and the
  # assertion is never about how long anything took.
  defp until(fun, attempts \\ 500)
  defp until(_fun, 0), do: flunk("condition did not become true")

  defp until(fun, attempts) do
    unless fun.() do
      Process.sleep(2)
      until(fun, attempts - 1)
    end
  end
end
