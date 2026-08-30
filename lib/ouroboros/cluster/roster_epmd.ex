defmodule Ouroboros.Cluster.RosterEpmd do
  @moduledoc """
  libcluster's Epmd strategy with one difference: the host list is re-resolved on
  every connection sweep instead of frozen into the topology when formation starts.

  `Cluster.Strategy.Epmd` reads `config[:hosts]` once, so a fleet whose roster grew
  while this runtime was up — `ouro fleet add` on a live owner — was never dialed:
  the new member appeared in the saved profile immediately, while the dialer kept the
  list it was born with until the next restart. When the new member cannot dial inward
  (a NATed owner is the common case), the mesh then never forms and the operator waits
  forever. The inverse held too: a canceled member was dialed until restart.

  Each sweep asks `Ouroboros.Cluster.membership_hosts/0` for the current list, which
  reads the saved fleet profile and falls back to the `OUROBOROS_CLUSTER_HOSTS` boot
  seed when no profile is active. Membership changes therefore reach the dialer within
  one reconnect interval, in both directions. Nothing here disconnects a removed
  member: leaving the fleet and retiring its state are explicit operator flows, and
  this process only ever adds connections.

  The first sweep runs after `init/1` returns rather than inside it, so an offline
  peer can no longer hold this node's boot for a distribution timeout per host.

  A host that keeps refusing the handshake is dialed on a widening schedule instead of
  every sweep — see `Ouroboros.Cluster.DialBackoff` for the policy and for the three
  things that reset it. The sweep itself keeps its cadence: membership is still
  re-resolved every interval, so a roster change still reaches this dialer within one of
  them, and a host that is merely in backoff is left out of that sweep's dial list rather
  than delaying it. Leaving it out is also what silences the repetition: libcluster logs
  its warning per attempted dial, so an attempt that does not happen says nothing.
  """

  use GenServer
  use Cluster.Strategy

  alias Cluster.Strategy.State
  alias Ouroboros.Cluster.DialBackoff

  # Matches `Ouroboros.Cluster`'s reconnect default; `build_topologies(:epmd)` always
  # sets `config[:timeout]`, so this only guards a hand-built topology.
  @default_sweep_interval 5_000

  @impl true
  def start_link([%State{config: config} = state]) do
    # An empty seed refuses to start exactly like libcluster's Epmd strategy did;
    # `build_topologies(:epmd)` already rejects that configuration with a named error.
    case Keyword.get(config, :hosts, []) do
      [] -> :ignore
      # The topology supervisor already identifies this child by topology. A global
      # module registration would make a second independent Cluster.Supervisor fail with
      # `already_started`, even though libcluster explicitly supports named supervisors.
      seeds when is_list(seeds) -> GenServer.start_link(__MODULE__, state)
    end
  end

  @impl true
  def init(%State{} = state) do
    # `meta` is this strategy's own scratch space and libcluster hands it over untouched.
    # Both halves belong to the sweep loop: the timer it must not fork, and the dial
    # history it must not lose.
    {:ok, %State{state | meta: %{timer: nil, backoff: DialBackoff.new()}}, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, %State{} = state), do: {:noreply, sweep(state)}

  @impl true
  def handle_info(:connect, %State{} = state), do: {:noreply, sweep(state)}

  def handle_info(_message, %State{} = state), do: {:noreply, state}

  defp sweep(%State{config: config, meta: %{timer: timer, backoff: backoff}} = state) do
    # One timer chain, ever: a stray `:connect` (a manual nudge, a late message)
    # must advance the sweep, not fork a second schedule that doubles the dial rate.
    if is_reference(timer), do: Process.cancel_timer(timer)

    sweep_ms = Keyword.get(config, :timeout, @default_sweep_interval)

    # Membership is read whole, every sweep, exactly as before: the backoff decides what
    # is *dialed*, never what this node considers a member. `expected_nodes/0` and every
    # operator surface built on it keep answering the roster.
    {dial, _waiting, backoff} =
      DialBackoff.select(
        backoff,
        Ouroboros.Cluster.membership_hosts(),
        connected_nodes(state),
        System.monotonic_time(:millisecond)
      )

    failed =
      case Cluster.Strategy.connect_nodes(state.topology, state.connect, state.list_nodes, dial) do
        :ok -> []
        {:error, bad_nodes} -> Enum.map(bad_nodes, fn {host, _reason} -> host end)
      end

    # Read the clock again rather than reusing the one above: `connect_nodes/4` blocks for
    # a handshake timeout per unreachable host, and a window that started before those
    # seconds elapsed is a window that much shorter than the policy promised.
    {backoff, widened} =
      DialBackoff.record(backoff, dial, failed, System.monotonic_time(:millisecond), sweep_ms)

    Enum.each(widened, &log_backoff(state.topology, &1))

    # An explicit timer instead of a GenServer timeout: any stray message would reset
    # a `{:noreply, state, timeout}` clock, and a paused sweep is this bug again.
    timer = Process.send_after(self(), :connect, sweep_ms)

    %State{state | meta: %{timer: timer, backoff: backoff}}
  end

  # `connect_nodes/4` asks this same question internally, but only to decide what to skip
  # dialing. The policy needs the answer too, to forgive a member that came up and dialed
  # us rather than the other way round.
  defp connected_nodes(%State{list_nodes: {module, function, args}}) do
    apply(module, function, args)
  end

  # One line each time the wait widens, and silence once it reaches the cap. It replaces a
  # sentence repeated once per sweep with a handful that each report a state change, and
  # it shares libcluster's prefix so it reads inline with the "unable to connect" warnings
  # it is explaining.
  defp log_backoff(topology, {host, attempts, window_ms}) do
    resume = DateTime.utc_now() |> DateTime.add(window_ms, :millisecond) |> DateTime.to_iso8601()

    Cluster.Logger.warn(
      topology,
      "backing off #{inspect(host)} for #{format_wait(window_ms)} after #{attempts} " <>
        "consecutive failed dials; not dialed again before #{resume}"
    )
  end

  defp format_wait(ms) when ms < 1_000, do: "#{ms}ms"
  defp format_wait(ms), do: "#{Float.round(ms / 1_000, 1)}s"
end
