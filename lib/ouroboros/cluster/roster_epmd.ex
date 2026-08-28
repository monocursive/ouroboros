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
  """

  use GenServer
  use Cluster.Strategy

  alias Cluster.Strategy.State

  # Matches `Ouroboros.Cluster`'s reconnect default; `build_topologies(:epmd)` always
  # sets `config[:timeout]`, so this only guards a hand-built topology.
  @default_sweep_interval 5_000

  @impl true
  def start_link([%State{config: config} = state]) do
    # An empty seed refuses to start exactly like libcluster's Epmd strategy did;
    # `build_topologies(:epmd)` already rejects that configuration with a named error.
    case Keyword.get(config, :hosts, []) do
      [] -> :ignore
      seeds when is_list(seeds) -> GenServer.start_link(__MODULE__, state, name: __MODULE__)
    end
  end

  @impl true
  def init(%State{} = state) do
    {:ok, state, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, %State{} = state), do: {:noreply, sweep(state)}

  @impl true
  def handle_info(:connect, %State{} = state), do: {:noreply, sweep(state)}

  def handle_info(_message, %State{} = state), do: {:noreply, state}

  defp sweep(%State{config: config, meta: timer} = state) do
    # One timer chain, ever: a stray `:connect` (a manual nudge, a late message)
    # must advance the sweep, not fork a second schedule that doubles the dial rate.
    if is_reference(timer), do: Process.cancel_timer(timer)

    Cluster.Strategy.connect_nodes(
      state.topology,
      state.connect,
      state.list_nodes,
      Ouroboros.Cluster.membership_hosts()
    )

    # An explicit timer instead of a GenServer timeout: any stray message would reset
    # a `{:noreply, state, timeout}` clock, and a paused sweep is this bug again.
    timer =
      Process.send_after(self(), :connect, Keyword.get(config, :timeout, @default_sweep_interval))

    %State{state | meta: timer}
  end
end
