defmodule Ouroboros.PollCadenceTest do
  @moduledoc """
  The wakeup policy, as arithmetic.

  `Ouroboros.Poll.Cadence` holds no timer and reads no clock, which is the point: the
  question "how long until this coordinator looks again" is answerable — and so assertable
  — without a single `Process.sleep/1`. The integration half, that a live coordinator
  actually decays and actually resets, lives in `interactive_poll_cadence_test.exs`.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Poll.{Cadence, Timer}

  describe "Cadence" do
    test "starts at the fast interval" do
      cadence = Cadence.new(25, 1_000)

      assert Cadence.interval(cadence) == 25
      assert Cadence.fast?(cadence)
      refute Cadence.capped?(cadence)
    end

    test "idle polls double the interval up to the cap, and stay there" do
      cadence = Cadence.new(25, 1_000)

      intervals =
        Enum.scan(1..8, cadence, fn _step, acc -> Cadence.idle(acc) end)
        |> Enum.map(&Cadence.interval/1)

      assert intervals == [50, 100, 200, 400, 800, 1_000, 1_000, 1_000]
    end

    test "the cap is reached in six empty polls from 25ms" do
      cadence = Enum.reduce(1..6, Cadence.new(25, 1_000), fn _step, acc -> Cadence.idle(acc) end)

      assert Cadence.interval(cadence) == 1_000
      assert Cadence.capped?(cadence)
      refute Cadence.fast?(cadence)
    end

    test "a busy poll resets to fast from anywhere in the decay" do
      capped = Enum.reduce(1..20, Cadence.new(25, 1_000), fn _step, acc -> Cadence.idle(acc) end)

      assert Cadence.interval(capped) == 1_000
      assert capped |> Cadence.busy() |> Cadence.interval() == 25
      assert capped |> Cadence.busy() |> Cadence.fast?()
    end

    test "busy is idempotent — repeated resets never poll faster than the fast interval" do
      cadence = Cadence.new(25, 1_000)

      assert cadence |> Cadence.busy() |> Cadence.busy() |> Cadence.busy() |> Cadence.interval() ==
               25
    end

    test "advance/2 spells the predicate: true decays, false resets" do
      cadence = Cadence.new(25, 1_000)

      assert cadence |> Cadence.advance(true) |> Cadence.interval() == 50

      assert cadence |> Cadence.advance(true) |> Cadence.advance(false) |> Cadence.interval() ==
               25
    end

    test "an interval never exceeds the cap or drops below the fast interval" do
      cadence = Cadence.new(25, 1_000)

      Enum.reduce(1..50, cadence, fn step, acc ->
        acc = if rem(step, 7) == 0, do: Cadence.busy(acc), else: Cadence.idle(acc)
        interval = Cadence.interval(acc)

        assert interval >= 25
        assert interval <= 1_000
        acc
      end)
    end

    test "a cap below the fast interval is clamped rather than inverting the policy" do
      cadence = Cadence.new(25, 10)

      assert Cadence.interval(cadence) == 25
      assert cadence |> Cadence.idle() |> Cadence.interval() == 25
    end
  end

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
