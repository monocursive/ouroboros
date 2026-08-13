defmodule Ouroboros.Cluster.Monitor do
  @moduledoc false

  use GenServer

  require Logger

  # Topology churn is the one cluster event an operator cannot reconstruct after the
  # fact: `Node.list/0` shows what is connected now, never what left. This process turns
  # every visible nodeup/nodedown into a log line, and asks the arriving node what role
  # it claims so a mis-rolled or foreign node is visible at the moment it joins rather
  # than at the moment it is refused work.
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(_opts) do
    # Valid whether or not distribution has started: a node that becomes alive later
    # still delivers to this subscription.
    :ok = :net_kernel.monitor_nodes(true, [:nodedown_reason, node_type: :visible])
    {:ok, %{}}
  end

  @impl true
  def handle_info({:nodeup, joined, _info}, state) do
    Logger.info("cluster nodeup #{inspect(joined)} role=#{inspect(observed_role(joined))}")
    {:noreply, state}
  end

  def handle_info({:nodedown, left, info}, state) do
    reason =
      case info do
        list when is_list(list) -> Keyword.get(list, :nodedown_reason, :unknown)
        _other -> :unknown
      end

    Logger.warning("cluster nodedown #{inspect(left)} reason=#{inspect(reason)}")
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  # A node that just appeared is exactly the node most likely to be mid-boot,
  # unreachable again, or not running this runtime at all. Every one of those is an
  # observation to log, never a reason to crash the monitor.
  defp observed_role(target) do
    case Ouroboros.Cluster.role(target) do
      {:ok, role} -> role
      {:error, reason} -> {:unknown, reason}
    end
  end
end

defmodule Ouroboros.Cluster do
  @moduledoc """
  Node role and cluster formation: who this node is, and how it finds the others.

  The runtime's distribution *semantics* (mesh membership over `:pg`, `:erpc` routing,
  multi-node upgrade coordination) never depended on how nodes met. This module owns the
  other half — formation and identity — and is deliberately the only place that knows
  either.

  ## Roles

  Every node boots as exactly one of `:core`, `:builder`, or `:signer`, from
  `config :ouroboros, :node_role` (default `:core`). The role shapes the supervision
  tree (`Ouroboros.Application`): a `:core` node runs the full runtime, while `:builder`
  and `:signer` run this supervisor and nothing else. That is not a sandbox — see
  "Limits" below — it is a least-privilege posture: a builder host has no team store, no
  scheduler, no control plane, and no coding sessions to lose, so compromising it yields
  a compiler, not a fleet.

  An unrecognized `:node_role` refuses the boot rather than defaulting to the most
  privileged role.

  ## Formation

  Formation is off by default. `OUROBOROS_CLUSTER_STRATEGY` selects one of:

    * `none` (default) — no discovery. Nodes connect because something else connected
      them, exactly as before this module existed.
    * `epmd` — a static list of node names in `OUROBOROS_CLUSTER_HOSTS`
      (comma-separated), retried on an interval so boot order does not matter.
    * `gossip` — libcluster's multicast gossip, optionally keyed by
      `OUROBOROS_CLUSTER_GOSSIP_SECRET`.
    * `dns` — poll the A records of `OUROBOROS_CLUSTER_DNS_QUERY` and connect
      `basename@ip`.

  A strategy that is named but misconfigured refuses the boot; it does not quietly fall
  back to an unformed cluster.

  ## Limits

  Role is a *placement* concept, not a security boundary. Any node that completes the
  distribution handshake — cookie, and TLS if configured — has full `:erpc` authority
  over every other connected node, so a hostile connected node ignores every check here
  by calling whatever it likes directly. Role checks stop misconfiguration and
  accidents: work sent to a node that cannot run it, or a build sent to a node that is
  not a builder. The boundaries that hold against a hostile *artifact* are the verifier's
  namespace policy and signature verification, not this module.
  """

  use Supervisor

  @roles [:core, :builder, :signer]
  @strategies [:none, :epmd, :gossip, :dns]
  @role_key {__MODULE__, :node_role}
  @formation_name __MODULE__.Formation
  @probe_timeout 5_000
  @default_reconnect_ms 5_000

  @type role :: :core | :builder | :signer
  @type strategy :: :none | :epmd | :gossip | :dns
  @type posture :: %{node: node(), role: role(), running: boolean()}

  @doc false
  def start_link(opts), do: Supervisor.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(_opts) do
    Supervisor.init(formation_children() ++ [__MODULE__.Monitor], strategy: :one_for_one)
  end

  @doc """
  Resolves, validates, and records this node's role. Called once, at application boot.

  Raises on an unrecognized role: booting the most privileged tree because a deployment
  variable was mistyped is the failure this refuses to have.
  """
  @spec boot_role!() :: role()
  def boot_role! do
    case Application.get_env(:ouroboros, :node_role, :core) do
      role when role in @roles ->
        :persistent_term.put(@role_key, role)
        role

      other ->
        raise ArgumentError,
              "config :ouroboros, :node_role must be one of #{inspect(@roles)}, got: " <>
                inspect(other)
    end
  end

  @doc "Returns every role this runtime understands."
  @spec roles() :: [role()]
  def roles, do: @roles

  @doc """
  Returns this node's role.

  Reads what `boot_role!/0` recorded. On a node where this runtime never started, it
  falls back to configuration and finally to `:core`; that fallback never widens
  authority, because every check that consumes a role also requires the target to be
  running this runtime.
  """
  @spec role() :: role()
  def role do
    case :persistent_term.get(@role_key, nil) do
      role when role in @roles ->
        role

      _absent ->
        case Application.get_env(:ouroboros, :node_role, :core) do
          role when role in @roles -> role
          _other -> :core
        end
    end
  end

  @doc """
  Returns the role a connected node claims.

  Bounded, and never raises: an unreachable node, a node without this code, and a node
  that answers something unexpected are all error tuples.
  """
  @spec role(node()) :: {:ok, role()} | {:error, term()}
  def role(target) when is_atom(target) do
    cond do
      target == node() -> {:ok, role()}
      target not in Node.list() -> {:error, :node_not_connected}
      true -> with {:ok, %{role: role}} <- probe(target), do: {:ok, role}
    end
  end

  @doc """
  Lists the connected nodes running this runtime in `role`.

  Includes this node when its own role matches. "Connected" means already in
  `Node.list/0`: this reports the cluster as formed, it does not form it.
  """
  @spec nodes_by_role(role()) :: [node()]
  def nodes_by_role(role) when role in @roles do
    postures()
    |> Enum.filter(fn {_node, posture} -> match?(%{role: ^role, running: true}, posture) end)
    |> Enum.map(fn {target, _posture} -> target end)
    |> Enum.sort()
  end

  @doc """
  Describes this node's role, the roles it can see, how it forms, and how distribution
  is protected.

  The security section reports posture, never secrets: whether a cookie is set, not
  which one.
  """
  @spec status() :: map()
  def status do
    observed = postures()

    %{
      node: node(),
      role: role(),
      distributed: Node.alive?(),
      connected_nodes: Enum.sort(Node.list()),
      roles: group_roles(observed),
      formation: formation_status(),
      security: dist_security()
    }
  end

  @doc """
  Describes this node to a caller on another node.

  Remote-reachable by construction, and deliberately trivial: it exposes the role and
  whether the runtime's root supervisor is alive, which is what every role check needs
  and nothing else. A node with this code on its path but no running runtime answers
  honestly with `running: false`.
  """
  @spec local_posture() :: posture()
  def local_posture do
    %{node: node(), role: role(), running: is_pid(Process.whereis(Ouroboros.Supervisor))}
  end

  @doc """
  Asserts that `target` is connected, running this runtime, and in `expected` role.

  `:any` accepts any role and still requires connectivity and a running runtime. The
  error is a bare reason — `:node_not_connected`, `:runtime_not_running`,
  `{:role, actual, expected}`, or a probe failure — so each caller can name its own
  refusal around it.
  """
  @spec ensure_role(node(), role() | :any) :: :ok | {:error, term()}
  def ensure_role(target, expected)
      when is_atom(target) and (expected in @roles or expected == :any) do
    cond do
      target == node() ->
        check_role(local_posture(), expected)

      target not in Node.list() ->
        {:error, :node_not_connected}

      true ->
        with {:ok, posture} <- probe(target), do: check_role(posture, expected)
    end
  end

  @doc """
  Asserts that agents and workers may be placed on `target`.

  Placement requires a connected `:core` node running this runtime, because that is the
  only role whose tree contains the teams, stores, and schedulers a placed worker will
  reach for. `config :ouroboros, :placement_role_check` (default `true`) disables the
  check for setups that place onto nodes this runtime cannot introspect.
  """
  @spec ensure_placeable(node()) :: :ok | {:error, term()}
  def ensure_placeable(target) when is_atom(target) do
    if Application.get_env(:ouroboros, :placement_role_check, true) do
      ensure_role(target, :core)
    else
      :ok
    end
  end

  @doc """
  Returns the configured formation strategy.

  An unrecognized value is an error rather than a silent `:none`, so a typo cannot
  disable clustering on a node that was deployed to cluster.
  """
  @spec strategy() :: {:ok, strategy()} | {:error, term()}
  def strategy do
    case env("OUROBOROS_CLUSTER_STRATEGY") do
      nil ->
        {:ok, :none}

      value ->
        case Enum.find(@strategies, &(Atom.to_string(&1) == value)) do
          nil -> {:error, {:unknown_cluster_strategy, value}}
          strategy -> {:ok, strategy}
        end
    end
  end

  @doc """
  Builds the libcluster topologies this node's environment describes.

  `{:ok, []}` means no formation. Every other strategy either produces a complete
  topology or an error naming the variable it needs.
  """
  @spec topologies() :: {:ok, keyword()} | {:error, term()}
  def topologies do
    with {:ok, strategy} <- strategy(), do: build_topologies(strategy)
  end

  @doc "Reports how distribution on this node is protected, without revealing secrets."
  @spec dist_security() :: map()
  def dist_security do
    proto = proto_dist()

    %{
      distributed: Node.alive?(),
      proto_dist: proto,
      tls: proto in [:inet_tls, :inet6_tls],
      cookie: if(:erlang.get_cookie() == :nocookie, do: :unset, else: :set)
    }
  end

  # `-proto_dist` is an emulator flag, so it is readable from `:init` whether it came
  # from vm.args, ELIXIR_ERL_OPTIONS, or the command line. Absent means the default
  # cleartext TCP distribution.
  defp proto_dist do
    case :init.get_argument(:proto_dist) do
      {:ok, [[value] | _rest]} -> List.to_atom(value)
      _absent -> :inet_tcp
    end
  end

  defp formation_children do
    case topologies() do
      {:ok, []} ->
        []

      {:ok, topologies} ->
        [{Cluster.Supervisor, [topologies, [name: @formation_name]]}]

      {:error, reason} ->
        raise ArgumentError,
              "cluster formation is configured but unusable: #{inspect(reason)}"
    end
  end

  defp build_topologies(:none), do: {:ok, []}

  defp build_topologies(:epmd) do
    case node_list("OUROBOROS_CLUSTER_HOSTS") do
      [] ->
        {:error, {:missing_cluster_configuration, "OUROBOROS_CLUSTER_HOSTS"}}

      hosts ->
        # `timeout` is libcluster's retry interval, not a deadline. Leaving it
        # `:infinity` would attempt connection once, at boot, and a cluster whose
        # members boot in any order would never form.
        {:ok,
         [
           ouroboros: [
             strategy: Cluster.Strategy.Epmd,
             config: [hosts: hosts, timeout: reconnect_interval()]
           ]
         ]}
    end
  end

  defp build_topologies(:gossip) do
    with {:ok, port} <- optional_port("OUROBOROS_CLUSTER_GOSSIP_PORT") do
      config =
        []
        |> put_present(:secret, env("OUROBOROS_CLUSTER_GOSSIP_SECRET"))
        |> put_present(:port, port)

      {:ok, [ouroboros: [strategy: Cluster.Strategy.Gossip, config: config]]}
    end
  end

  defp build_topologies(:dns) do
    with {:ok, query} <- required_env("OUROBOROS_CLUSTER_DNS_QUERY"),
         {:ok, basename} <- dns_basename() do
      {:ok,
       [
         ouroboros: [
           strategy: Cluster.Strategy.DNSPoll,
           config: [
             query: query,
             node_basename: basename,
             polling_interval: reconnect_interval()
           ]
         ]
       ]}
    end
  end

  # DNS polling builds `basename@ip`, so the basename must match what the peers
  # actually registered. Deriving it from this node's own name is right whenever the
  # fleet is homogeneous, which is the case this strategy is for.
  defp dns_basename do
    case env("OUROBOROS_CLUSTER_DNS_BASENAME") do
      nil ->
        case node() |> Atom.to_string() |> String.split("@", parts: 2) do
          [name, _host] when name != "" -> {:ok, name}
          _other -> {:error, {:missing_cluster_configuration, "OUROBOROS_CLUSTER_DNS_BASENAME"}}
        end

      basename ->
        {:ok, basename}
    end
  end

  defp put_present(config, _key, nil), do: config
  defp put_present(config, key, value), do: Keyword.put(config, key, value)

  defp optional_port(name) do
    case env(name) do
      nil ->
        {:ok, nil}

      value ->
        case Integer.parse(value) do
          {port, ""} when port > 0 and port < 65_536 -> {:ok, port}
          _other -> {:error, {:invalid_cluster_configuration, name}}
        end
    end
  end

  defp reconnect_interval do
    case env("OUROBOROS_CLUSTER_RECONNECT_MS") do
      nil ->
        @default_reconnect_ms

      value ->
        case Integer.parse(value) do
          {interval, ""} when interval > 0 -> interval
          _other -> @default_reconnect_ms
        end
    end
  end

  defp required_env(name) do
    case env(name) do
      nil -> {:error, {:missing_cluster_configuration, name}}
      value -> {:ok, value}
    end
  end

  defp node_list(name) do
    (env(name) || "")
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.map(&String.to_atom/1)
  end

  defp env(name) do
    case System.get_env(name) do
      nil -> nil
      value -> if String.trim(value) == "", do: nil, else: String.trim(value)
    end
  end

  defp formation_status do
    strategy =
      case strategy() do
        {:ok, strategy} -> strategy
        {:error, reason} -> {:invalid, reason}
      end

    topologies =
      case topologies() do
        {:ok, topologies} -> Keyword.keys(topologies)
        {:error, _reason} -> []
      end

    %{
      strategy: strategy,
      topologies: topologies,
      supervised: is_pid(Process.whereis(@formation_name))
    }
  end

  defp group_roles(observed) do
    initial = Map.new(@roles, &{&1, []})

    observed
    |> Enum.reduce(Map.put(initial, :unreachable, []), fn
      {target, %{role: role, running: true}}, acc -> Map.update!(acc, role, &[target | &1])
      {target, _other}, acc -> Map.update!(acc, :unreachable, &[target | &1])
    end)
    |> Map.new(fn {role, nodes} -> {role, Enum.sort(nodes)} end)
  end

  defp postures do
    targets = [node() | Node.list()]

    targets
    |> :erpc.multicall(__MODULE__, :local_posture, [], @probe_timeout)
    |> Enum.zip(targets)
    |> Map.new(fn
      {{:ok, %{role: role, running: running} = posture}, target}
      when role in @roles and is_boolean(running) ->
        {target, posture}

      {other, target} ->
        {target, {:error, other}}
    end)
  end

  defp probe(target) do
    case :erpc.call(target, __MODULE__, :local_posture, [], @probe_timeout) do
      %{role: role, running: running} = posture when role in @roles and is_boolean(running) ->
        {:ok, posture}

      other ->
        {:error, {:invalid_posture, inspect(other)}}
    end
  catch
    # A node without this runtime's code answers `:undef` as an `:erpc` exception, an
    # unreachable one raises `:erpc` errors, and a node mid-shutdown exits. None of
    # those may escape into a caller that is only asking a question.
    kind, reason -> {:error, {:probe_failed, {kind, inspect(reason)}}}
  end

  defp check_role(%{running: false}, _expected), do: {:error, :runtime_not_running}
  defp check_role(%{running: true}, :any), do: :ok
  defp check_role(%{role: role, running: true}, role), do: :ok
  defp check_role(%{role: role}, expected), do: {:error, {:role, role, expected}}
end
