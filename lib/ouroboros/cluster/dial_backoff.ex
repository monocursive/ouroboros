defmodule Ouroboros.Cluster.DialBackoff do
  @moduledoc """
  Per-host dial pacing for `Ouroboros.Cluster.RosterEpmd`: how long a roster member that
  will not answer is left alone, and every event that puts it back in the dial list.

  The dialer re-resolves membership every sweep and hands the whole list to
  `Cluster.Strategy.connect_nodes/4`, which dials each host it is not already connected
  to. For a member that is *durably* unreachable — a stale EPMD registration naming a
  machine that is gone is the case that produced this module — that is one full
  distribution handshake attempt per sweep, forever, at whatever
  `OUROBOROS_CLUSTER_RECONNECT_MS` says. A fleet-spawned daemon sets that to one second
  (`tui/src/fleet.rs`), and an owner left in that state burned roughly half a core for
  37 hours inside the TLS dial path while writing a byte-identical libcluster warning
  every second.

  This module is the policy, and only the policy: it never dials, never reads a clock and
  never logs. It answers "which of these hosts may this sweep dial" and "given what that
  sweep found, when has each failure earned another attempt". `RosterEpmd` owns the
  clock, the socket and the log line, which is what makes the schedule below testable
  without a single sleep.

  ## The schedule

  The first three consecutive failures cost nothing — they are dialed at the plain sweep
  cadence. That grace is what keeps a healthy mesh exactly as fast as it was: peers that
  boot in any order find each other within the first sweeps, and a cluster still forming
  is indistinguishable, from here, from one that is failing. Only past the grace does the
  wait appear, doubling on every further failure from one sweep interval up to a two
  minute ceiling.

  Growth is anchored to the sweep interval rather than to a fixed number of milliseconds
  so that the policy means the same thing under every configured cadence: it always
  spends its grace on the first three sweeps, whatever those cost in wall-clock time, and
  it never asks a dialer to wait less than the interval it was configured with. Against
  the one-second fleet cadence that produced the incident, a permanently dead host drops
  from ~133,000 handshake attempts over 37 hours to roughly 1,100.

  ## What resets it

  Three things, and all three are the same operation — forgetting the host:

    * it answered (it connected, or it was already connected when the sweep ran);
    * it is no longer in membership, so a member removed and re-added, or a fresh
      invite, is dialed on the sweep it appears rather than inheriting a wait earned by
      whatever held that name before;
    * it is connected right now, however that link was made. A NATed member that dialed
      *inward* while this node was backing off has answered; it must not keep serving out
      a window it earned while it was down.

  The second is deliberate and load-bearing. `RosterEpmd` exists because a dialer that
  freezes its host list makes an operator wait forever for a mesh that will never form;
  a backoff that outlives membership would be that same bug wearing a different hat.
  """

  import Bitwise

  # Consecutive failures dialed at the plain sweep cadence before any wait is imposed.
  # Formation races — the peer is still booting — resolve inside this window, so a mesh
  # that is merely coming up never pays for the policy.
  @grace_attempts 3

  # The longest a host can be ignored. Two minutes is short enough that an operator who
  # fixes a peer sees the mesh close without touching the dialer, and long enough that a
  # permanently dead one costs ~30 handshakes an hour instead of 3,600.
  @cap_ms 120_000

  # Jitter only ever pulls a retry *earlier*, so the cap stays a real ceiling and two
  # nodes that started together stop dialing a third in lockstep.
  @jitter 0.25

  # A guard on the shift, not on the schedule: `@cap_ms` has bound the wait long before
  # this many consecutive failures, and an unbounded exponent would build a bignum per
  # sweep for as long as the host stays down.
  @max_shift 16

  defstruct hosts: %{}

  @typedoc "What one host has earned: how many failures in a row, and until when."
  @type host_state :: %{attempts: pos_integer(), until: integer(), window: non_neg_integer()}

  @opaque t :: %__MODULE__{hosts: %{node() => host_state()}}

  @doc "A policy that has seen nothing and is therefore holding nobody back."
  @spec new() :: t()
  def new, do: %__MODULE__{}

  @doc "Consecutive failures dialed at the plain sweep cadence before any wait appears."
  @spec grace_attempts() :: pos_integer()
  def grace_attempts, do: @grace_attempts

  @doc "The ceiling on a single wait, in milliseconds."
  @spec cap_ms() :: pos_integer()
  def cap_ms, do: @cap_ms

  @doc """
  Splits the current membership into the hosts this sweep dials and the hosts still
  waiting out a window, dropping the history of every host the resets above forgive.

  `now` is a monotonic millisecond reading; `connected` is what this node is linked to
  right now. The returned policy has already been pruned, so the caller must keep it even
  when it dials nothing.
  """
  @spec select(t(), [node()], [node()], integer()) :: {[node()], [node()], t()}
  def select(%__MODULE__{hosts: tracked}, hosts, connected, now)
      when is_list(hosts) and is_list(connected) and is_integer(now) do
    hosts = Enum.uniq(hosts)

    tracked =
      tracked
      |> Map.take(hosts)
      |> Map.drop(connected)

    {waiting, dial} =
      Enum.split_with(hosts, fn host ->
        case tracked do
          %{^host => %{until: until}} -> now < until
          _no_history -> false
        end
      end)

    {dial, waiting, %__MODULE__{hosts: tracked}}
  end

  @doc """
  Folds one sweep's outcome back into the policy.

  `attempted` is what `select/4` handed the dialer and `failed` is the subset that did not
  answer; anything else in `attempted` is healthy — it either connected or was already
  connected, and `Cluster.Strategy.connect_nodes/4` reports neither — so its history is
  dropped. `sweep_ms` is the configured reconnect interval, which is the unit the wait
  grows in. `rand` returns a float in `(0.0, 1.0)` and exists so a test can pin the
  jitter; production passes nothing.

  Returns the new policy and the hosts whose wait *changed*, as
  `{host, attempts, window_ms}`. That list is the only thing worth logging: it fires once
  each time the wait widens and falls silent once the cap is reached, so an unreachable
  host produces a handful of lines that each say something new rather than one identical
  line per sweep.
  """
  @spec record(t(), [node()], [node()], integer(), pos_integer(), (-> float())) ::
          {t(), [{node(), pos_integer(), pos_integer()}]}
  def record(state, attempted, failed, now, sweep_ms, rand \\ &:rand.uniform/0)

  def record(%__MODULE__{hosts: tracked}, attempted, failed, now, sweep_ms, rand)
      when is_list(attempted) and is_list(failed) and is_integer(now) and is_integer(sweep_ms) and
             sweep_ms > 0 and is_function(rand, 0) do
    reported = MapSet.new(failed)

    # Split rather than trust: only a host this sweep actually dialed can have failed it.
    {failed, answered} = Enum.split_with(attempted, &MapSet.member?(reported, &1))

    {tracked, widened} =
      Enum.reduce(failed, {Map.drop(tracked, answered), []}, fn host, {tracked, widened} ->
        previous = Map.get(tracked, host)
        attempts = if previous, do: previous.attempts + 1, else: 1
        window = window_for(attempts, sweep_ms)

        entry = %{attempts: attempts, until: now + jittered(window, rand), window: window}

        widened =
          if window > 0 and (is_nil(previous) or previous.window != window),
            do: [{host, attempts, window} | widened],
            else: widened

        {Map.put(tracked, host, entry), widened}
      end)

    {%__MODULE__{hosts: tracked}, Enum.reverse(widened)}
  end

  @doc """
  The wait `attempts` consecutive failures have earned at this sweep interval, before
  jitter. Exposed because it is the whole schedule, and a test that has to reconstruct it
  is not testing it.
  """
  @spec window_for(pos_integer(), pos_integer()) :: non_neg_integer()
  def window_for(attempts, _sweep_ms) when attempts <= @grace_attempts, do: 0

  def window_for(attempts, sweep_ms) when is_integer(sweep_ms) and sweep_ms > 0 do
    min(sweep_ms <<< min(attempts - @grace_attempts, @max_shift), @cap_ms)
  end

  defp jittered(0, _rand), do: 0
  defp jittered(window, rand), do: window - trunc(window * @jitter * rand.())
end
