defmodule Ouroboros.Cluster.DialBackoffTest do
  use ExUnit.Case, async: true

  # The policy behind `Ouroboros.Cluster.RosterEpmd`'s dial pacing, exercised as what it
  # is: a pure function of a clock, a membership list and a sweep outcome. Every "time
  # passes" below is an integer, so none of this waits for anything and none of it can
  # flake on a loaded machine.
  alias Ouroboros.Cluster.DialBackoff

  @dead :"ouro-dead@127.0.0.1"
  @live :"ouro-live@127.0.0.1"

  # A one second sweep is the cadence a fleet-spawned daemon actually runs
  # (`OUROBOROS_CLUSTER_RECONNECT_MS` is set to 1000 in `tui/src/fleet.rs`), and the one
  # that produced the incident this policy exists to end.
  @sweep_ms 1_000

  describe "the schedule" do
    test "the first three failures are dialed at the plain sweep cadence" do
      # A mesh that is merely forming looks exactly like a mesh that is failing. The grace
      # is what keeps the two indistinguishable in cost: peers booting in any order find
      # each other inside it, so formation timing is untouched by the policy.
      assert DialBackoff.window_for(1, @sweep_ms) == 0
      assert DialBackoff.window_for(2, @sweep_ms) == 0
      assert DialBackoff.window_for(3, @sweep_ms) == 0
      assert DialBackoff.grace_attempts() == 3

      {sweeps, _backoff} = run_sweeps(DialBackoff.new(), [@dead], 4, failing: [@dead])

      assert Enum.map(sweeps, & &1.dial) == [[@dead], [@dead], [@dead], [@dead]]
      assert Enum.map(sweeps, & &1.waiting) == [[], [], [], []]

      # Only the fourth failure arms anything, and it is the first thing worth logging.
      assert Enum.map(sweeps, & &1.widened) == [[], [], [], [{@dead, 4, 2 * @sweep_ms}]]
    end

    test "past the grace the wait doubles each failure and stops at a two minute cap" do
      windows = for attempts <- 1..14, do: DialBackoff.window_for(attempts, @sweep_ms)

      assert windows == [
               0,
               0,
               0,
               2_000,
               4_000,
               8_000,
               16_000,
               32_000,
               64_000,
               120_000,
               120_000,
               120_000,
               120_000,
               120_000
             ]

      assert DialBackoff.cap_ms() == 120_000
      assert Enum.max(windows) == DialBackoff.cap_ms()

      # The schedule is denominated in sweeps, not in milliseconds, so it means the same
      # thing at the 5s default as at the 1s fleet cadence — and still lands under the cap.
      assert DialBackoff.window_for(4, 5_000) == 10_000
      assert DialBackoff.window_for(8, 5_000) == 120_000
      assert DialBackoff.window_for(4, 200) == 400

      # An unreachable host does not build a bignum for as long as it stays down.
      assert DialBackoff.window_for(1_000_000, @sweep_ms) == 120_000
    end

    test "a host inside its window is left out of the sweep entirely" do
      # Exclusion is the whole mechanism: libcluster logs its warning per dial it
      # attempts, so a dial that never happens is also a warning that never happens.
      {_sweeps, backoff} = run_sweeps(DialBackoff.new(), [@dead], 4, failing: [@dead])

      # The fourth failure armed 2s at t=3000, so the window closes at t=5000.
      assert {[], [@dead], _backoff} = DialBackoff.select(backoff, [@dead], [], 4_999)
      assert {[@dead], [], _backoff} = DialBackoff.select(backoff, [@dead], [], 5_000)

      # A healthy host sharing the roster is never held back by its neighbour's window.
      assert {[@live], [@dead], _backoff} =
               DialBackoff.select(backoff, [@dead, @live], [], 4_999)
    end

    test "the dial rate decays, and the log with it" do
      # 130 sweeps is the point a 1s cadence reaches the ceiling: windows of 2, 4, 8, 16,
      # 32 and 64 seconds have to elapse first.
      {sweeps, backoff} = run_sweeps(DialBackoff.new(), [@dead], 130, failing: [@dead])

      # Ten dials where the fixed cadence made 130 — this is the CPU the incident burned.
      assert Enum.count(sweeps, &(&1.dial != [])) == 10

      reports = Enum.flat_map(sweeps, & &1.widened)

      # And seven log lines, each naming a wait the line before it did not.
      assert Enum.map(reports, fn {_host, _attempts, window} -> window end) ==
               [2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 120_000]

      assert Enum.all?(reports, fn {host, _attempts, _window} -> host == @dead end)

      # From here it is silent: 200 further sweeps of a host that will never answer cost
      # one handshake and not a single line, because the cap is not a state change.
      {later, _backoff} =
        run_sweeps(backoff, [@dead], 200, failing: [@dead], start: 130 * @sweep_ms)

      assert Enum.count(later, &(&1.dial != [])) == 1
      assert Enum.flat_map(later, & &1.widened) == []
    end

    test "jitter only ever pulls the next dial earlier, and never past the cap" do
      # `rand` is injected precisely so this is an assertion rather than a hope. Ten
      # consecutive failures put the host at the ceiling, which is where the promise
      # "connected within the cap" has to hold.
      none = fail_times(DialBackoff.new(), 10, 0, fn -> 0.0 end)
      full = fail_times(DialBackoff.new(), 10, 0, fn -> 1.0 end)

      # No jitter waits the whole window — exactly the cap, never more.
      assert {[], [@dead], _} = DialBackoff.select(none, [@dead], [], DialBackoff.cap_ms() - 1)
      assert {[@dead], [], _} = DialBackoff.select(none, [@dead], [], DialBackoff.cap_ms())

      # Full jitter gives back a quarter of it, and gives it back early rather than late.
      early = div(DialBackoff.cap_ms() * 3, 4)
      assert {[], [@dead], _} = DialBackoff.select(full, [@dead], [], early - 1)
      assert {[@dead], [], _} = DialBackoff.select(full, [@dead], [], early)

      # The same shape one rung down, where the window is still growing.
      none = fail_times(DialBackoff.new(), 4, 0, fn -> 0.0 end)
      full = fail_times(DialBackoff.new(), 4, 0, fn -> 1.0 end)

      assert {[], [@dead], _} = DialBackoff.select(none, [@dead], [], 1_999)
      assert {[@dead], [], _} = DialBackoff.select(none, [@dead], [], 2_000)
      assert {[], [@dead], _} = DialBackoff.select(full, [@dead], [], 1_499)
      assert {[@dead], [], _} = DialBackoff.select(full, [@dead], [], 1_500)
    end
  end

  describe "what resets it" do
    test "a host that answers is forgiven, grace and all" do
      {_sweeps, backoff} = run_sweeps(DialBackoff.new(), [@dead], 6, failing: [@dead])

      # It comes back: the sweep that finds it answering clears its whole history.
      {dial, [], backoff} = DialBackoff.select(backoff, [@dead], [], 500_000)
      assert dial == [@dead]
      {backoff, widened} = DialBackoff.record(backoff, dial, [], 500_000, @sweep_ms, &pinned/0)
      assert widened == []

      # And if it dies again it starts from the beginning rather than from where it left
      # off — three sweeps of grace again, not the four seconds it had climbed to.
      {sweeps, _backoff} =
        run_sweeps(backoff, [@dead], 4, failing: [@dead], start: 500_000 + @sweep_ms)

      assert Enum.map(sweeps, & &1.dial) == [[@dead], [@dead], [@dead], [@dead]]
      assert Enum.map(sweeps, & &1.widened) == [[], [], [], [{@dead, 4, 2 * @sweep_ms}]]
    end

    test "a host that leaves membership and returns is dialed on the sweep it returns" do
      # This is the bug `RosterEpmd` was written to kill, in a new costume: an operator who
      # re-adds a member must not wait out a window earned by whatever held that name
      # before. `ouro fleet add` after a cancel, and a fresh invite, are the same shape.
      {_sweeps, backoff} = run_sweeps(DialBackoff.new(), [@dead], 8, failing: [@dead])

      # Mid-window, and it would still be waiting if it had stayed in the roster.
      assert {[], [@dead], _backoff} = DialBackoff.select(backoff, [@dead], [], 8_000)

      # The member is cancelled: one sweep of a roster without it forgets it.
      assert {[], [], backoff} = DialBackoff.select(backoff, [], [], 8_000)

      # It is invited back, and is dialed at once — same clock reading, no wait at all.
      assert {[@dead], [], backoff} = DialBackoff.select(backoff, [@dead], [], 8_000)

      # With a full grace ahead of it, not a resumed climb.
      {backoff, widened} =
        DialBackoff.record(backoff, [@dead], [@dead], 8_000, @sweep_ms, &pinned/0)

      assert widened == []
      assert {[@dead], [], _backoff} = DialBackoff.select(backoff, [@dead], [], 8_000)
    end

    test "a member that dialed inward is forgiven while its window is still open" do
      # The NATed-owner shape: this node gave up dialing, and the member connected to it
      # instead. It has answered, whichever side opened the socket.
      {_sweeps, backoff} = run_sweeps(DialBackoff.new(), [@dead], 8, failing: [@dead])

      assert {[], [@dead], _backoff} = DialBackoff.select(backoff, [@dead], [], 8_000)
      assert {[@dead], [], backoff} = DialBackoff.select(backoff, [@dead], [@dead], 8_000)

      # If that link later drops, the host starts from grace rather than mid-climb.
      {sweeps, _backoff} = run_sweeps(backoff, [@dead], 4, failing: [@dead], start: 9_000)
      assert Enum.map(sweeps, & &1.widened) == [[], [], [], [{@dead, 4, 2 * @sweep_ms}]]
    end

    test "one host's failures never pace another's" do
      failing = [@dead]

      {sweeps, _backoff} =
        run_sweeps(DialBackoff.new(), [@dead, @live], 10, failing: failing)

      # The reachable host is dialed on every single sweep; the unreachable one decays.
      assert Enum.all?(sweeps, &(@live in &1.dial))
      assert Enum.count(sweeps, &(@dead in &1.dial)) == 6
      assert Enum.all?(sweeps, fn sweep -> Enum.all?(sweep.widened, &(elem(&1, 0) == @dead)) end)
    end
  end

  describe "inputs it refuses to trust" do
    test "a failure reported for a host this sweep never dialed is ignored" do
      # `record/6` folds the dialer's own report back in; a host that was not in the dial
      # list cannot have failed it, and must not acquire a window from someone else's.
      {backoff, widened} =
        DialBackoff.record(DialBackoff.new(), [], [@dead], 0, @sweep_ms, &pinned/0)

      assert widened == []
      assert {[@dead], [], _backoff} = DialBackoff.select(backoff, [@dead], [], 0)
    end

    test "a duplicated roster entry is dialed once" do
      assert {[@dead], [], _backoff} =
               DialBackoff.select(DialBackoff.new(), [@dead, @dead, @dead], [], 0)
    end
  end

  # One sweep of the loop `RosterEpmd` runs, with the clock and the dial outcome supplied
  # rather than observed.
  defp run_sweeps(backoff, hosts, count, opts) do
    failing = Keyword.get(opts, :failing, [])
    rand = Keyword.get(opts, :rand, &pinned/0)
    start = Keyword.get(opts, :start, 0)
    connected = Keyword.get(opts, :connected, [])

    Enum.map_reduce(0..(count - 1), backoff, fn tick, backoff ->
      now = start + tick * @sweep_ms
      {dial, waiting, backoff} = DialBackoff.select(backoff, hosts, connected, now)
      failed = Enum.filter(dial, &(&1 in failing))
      {backoff, widened} = DialBackoff.record(backoff, dial, failed, now, @sweep_ms, rand)

      {%{dial: dial, waiting: waiting, widened: widened}, backoff}
    end)
  end

  # `count` consecutive failures with the clock held still, for the tests that care about
  # where a host lands rather than about how long it took to get there.
  defp fail_times(backoff, count, now, rand) do
    Enum.reduce(1..count, backoff, fn _attempt, backoff ->
      {backoff, _widened} = DialBackoff.record(backoff, [@dead], [@dead], now, @sweep_ms, rand)
      backoff
    end)
  end

  # No jitter: the schedule is what is under test here, and the jitter has its own.
  defp pinned, do: 0.0
end
