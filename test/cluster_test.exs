defmodule Ouroboros.ClusterTest do
  use ExUnit.Case, async: false

  # libcluster's strategies are aliased first, on purpose: `Ouroboros.Cluster` takes the
  # `Cluster` alias below, after which `Cluster.Strategy.Epmd` would name a module that
  # does not exist.
  alias Cluster.Strategy.DNSPoll
  alias Cluster.Strategy.Epmd
  alias Cluster.Strategy.Gossip

  alias Ouroboros.Cluster
  alias Ouroboros.Mesh
  alias Ouroboros.Team
  alias Ouroboros.Team.Server
  alias Ouroboros.Upgrade.Forge.BuildPeer

  @capability Ouroboros.Capability.RemotelyBuilt
  @formation_cookie :ouroboros_formation_test

  describe "node role" do
    test "defaults to :core and says so in both status surfaces" do
      assert Cluster.roles() == [:core, :builder, :signer]
      assert Cluster.role() == :core
      assert Cluster.role(node()) == {:ok, :core}
      assert Cluster.local_posture() == %{node: node(), role: :core, running: true}

      status = Cluster.status()
      assert status.node == node()
      assert status.role == :core
      assert status.distributed == Node.alive?()
      assert node() in status.roles.core
      assert status.roles.builder == []
      assert status.roles.signer == []

      # Formation is off unless an operator names a strategy, and the security section
      # reports posture rather than the cookie itself.
      assert status.formation.strategy == :none
      assert status.formation.topologies == []
      assert status.formation.supervised == false
      assert status.security.tls == false
      assert status.security.proto_dist == :inet_tcp
      assert status.security.cookie in [:set, :unset]
      refute Map.has_key?(status.security, :value)

      runtime = Ouroboros.status()
      assert runtime.role == :core
      assert runtime.cluster.role == :core
      assert runtime.availability.cluster == :available
    end

    test "an unrecognized configured role refuses to resolve rather than defaulting up" do
      previous = Application.get_env(:ouroboros, :node_role)
      Application.put_env(:ouroboros, :node_role, :root)
      on_exit(fn -> Application.put_env(:ouroboros, :node_role, previous) end)

      assert_raise ArgumentError, ~r/node_role/, fn -> Cluster.boot_role!() end
    end
  end

  describe "roles across real nodes" do
    @tag timeout: 180_000
    test "reads a peer's role and groups connected nodes by it" do
      core = start_app_peer!()
      builder = start_app_peer!(node_role: :builder)

      assert Cluster.role(core) == {:ok, :core}
      assert Cluster.role(builder) == {:ok, :builder}

      # `nodes_by_role/1` reports the formed cluster, so this node counts itself.
      core_nodes = Cluster.nodes_by_role(:core)
      assert node() in core_nodes
      assert core in core_nodes
      refute builder in core_nodes

      assert builder in Cluster.nodes_by_role(:builder)
      assert Cluster.nodes_by_role(:signer) == []

      status = Cluster.status()
      assert core in status.roles.core
      assert builder in status.roles.builder
    end

    @tag timeout: 180_000
    test "a node that is not connected or not running the runtime is never a role" do
      assert Cluster.role(:"ouroboros-absent@127.0.0.1") == {:error, :node_not_connected}

      assert Cluster.ensure_role(:"ouroboros-absent@127.0.0.1", :core) ==
               {:error, :node_not_connected}

      bare = start_bare_peer!()

      # The peer has this code on its path, so it can answer at all — and answers
      # honestly that the runtime is not running.
      assert Cluster.role(bare) == {:ok, :core}
      assert Cluster.ensure_role(bare, :core) == {:error, :runtime_not_running}
      assert Cluster.ensure_role(bare, :any) == {:error, :runtime_not_running}
      refute bare in Cluster.nodes_by_role(:core)
    end
  end

  describe "formation" do
    @tag timeout: 300_000
    test "two nodes with the epmd strategy form a cluster with no manual Node.connect" do
      ensure_distributed!()

      [first_name, second_name] =
        for suffix <- ["a", "b"] do
          :"ouroboros_form_#{suffix}_#{System.unique_integer([:positive])}@#{hostname()}"
        end

      hosts = "#{first_name},#{second_name}"

      # These peers have no distribution when they boot and no knowledge of this VM:
      # their control channel is a pipe. Nothing in this test connects them — the only
      # thing that can is the strategy the application starts.
      first = start_unformed_peer!(first_name)
      second = start_unformed_peer!(second_name)

      for peer <- [first, second] do
        configure_formation!(peer, hosts)
      end

      for peer <- [first, second] do
        assert {:ok, _applications} =
                 :peer.call(peer, Application, :ensure_all_started, [:ouroboros], 60_000)
      end

      assert_eventually(fn -> second_name in :peer.call(first, Node, :list, []) end, 300)
      assert_eventually(fn -> first_name in :peer.call(second, Node, :list, []) end, 300)

      # Formation is what each side observes, not merely what it attempted.
      assert :peer.call(first, Cluster, :nodes_by_role, [:core]) ==
               Enum.sort([first_name, second_name])

      first_status = :peer.call(first, Cluster, :status, [])
      assert first_status.formation.strategy == :epmd
      assert first_status.formation.topologies == [:ouroboros]
      assert first_status.formation.supervised == true

      # And they formed with each other rather than through this VM, which never
      # connected to either of them.
      refute first_name in Node.list()
      refute second_name in Node.list()
    end

    test "a strategy that is named but unusable refuses to build a topology" do
      with_env(%{"OUROBOROS_CLUSTER_STRATEGY" => "none"}, fn ->
        assert Cluster.strategy() == {:ok, :none}
        assert Cluster.topologies() == {:ok, []}
      end)

      with_env(%{"OUROBOROS_CLUSTER_STRATEGY" => "kubernetes"}, fn ->
        assert Cluster.strategy() == {:error, {:unknown_cluster_strategy, "kubernetes"}}
        assert Cluster.topologies() == {:error, {:unknown_cluster_strategy, "kubernetes"}}
      end)

      with_env(%{"OUROBOROS_CLUSTER_STRATEGY" => "epmd", "OUROBOROS_CLUSTER_HOSTS" => nil}, fn ->
        assert Cluster.topologies() ==
                 {:error, {:missing_cluster_configuration, "OUROBOROS_CLUSTER_HOSTS"}}
      end)

      with_env(
        %{"OUROBOROS_CLUSTER_STRATEGY" => "dns", "OUROBOROS_CLUSTER_DNS_QUERY" => nil},
        fn ->
          assert Cluster.topologies() ==
                   {:error, {:missing_cluster_configuration, "OUROBOROS_CLUSTER_DNS_QUERY"}}
        end
      )
    end

    test "each strategy builds the topology its variables describe" do
      with_env(
        %{
          "OUROBOROS_CLUSTER_STRATEGY" => "epmd",
          "OUROBOROS_CLUSTER_HOSTS" => "a@host , b@host",
          "OUROBOROS_CLUSTER_RECONNECT_MS" => "750"
        },
        fn ->
          assert {:ok, [ouroboros: topology]} = Cluster.topologies()
          assert topology[:strategy] == Epmd
          assert topology[:config][:hosts] == [:a@host, :b@host]
          # Not `:infinity`: a cluster whose members boot in any order must retry.
          assert topology[:config][:timeout] == 750
        end
      )

      with_env(
        %{
          "OUROBOROS_CLUSTER_STRATEGY" => "dns",
          "OUROBOROS_CLUSTER_DNS_QUERY" => "ouroboros.internal",
          "OUROBOROS_CLUSTER_DNS_BASENAME" => "core"
        },
        fn ->
          assert {:ok, [ouroboros: topology]} = Cluster.topologies()
          assert topology[:strategy] == DNSPoll
          assert topology[:config][:query] == "ouroboros.internal"
          assert topology[:config][:node_basename] == "core"
        end
      )

      with_env(
        %{
          "OUROBOROS_CLUSTER_STRATEGY" => "gossip",
          "OUROBOROS_CLUSTER_GOSSIP_SECRET" => "shared",
          "OUROBOROS_CLUSTER_GOSSIP_PORT" => "45999"
        },
        fn ->
          assert {:ok, [ouroboros: topology]} = Cluster.topologies()
          assert topology[:strategy] == Gossip
          assert topology[:config][:secret] == "shared"
          assert topology[:config][:port] == 45_999
        end
      )

      with_env(
        %{"OUROBOROS_CLUSTER_STRATEGY" => "gossip", "OUROBOROS_CLUSTER_GOSSIP_PORT" => "no"},
        fn ->
          assert Cluster.topologies() ==
                   {:error, {:invalid_cluster_configuration, "OUROBOROS_CLUSTER_GOSSIP_PORT"}}
        end
      )
    end
  end

  describe "placement" do
    @tag timeout: 180_000
    test "agents are placed on a :core peer and refused everywhere else" do
      core = start_app_peer!()
      builder = start_app_peer!(node_role: :builder)
      bare = start_bare_peer!()

      accepted = unique_id("placed")
      assert {:ok, pid} = Mesh.start_agent_on(core, accepted, role: "remote reviewer")
      assert node(pid) == core
      on_exit(fn -> Mesh.stop_agent(accepted) end)

      refused = unique_id("refused")

      assert Mesh.start_agent_on(builder, refused) ==
               {:error, {:placement_refused, builder, {:role, :builder, :core}}}

      assert Mesh.start_agent_on(bare, refused) ==
               {:error, {:placement_refused, bare, :runtime_not_running}}

      assert Mesh.whereis(refused) == nil
    end

    @tag timeout: 180_000
    test "a team refuses a worker on a node that cannot run one" do
      builder = start_app_peer!(node_role: :builder)

      team_id = unique_id("cluster-team")

      team =
        start_supervised!(
          {Server, id: team_id, supervisor_id: {__MODULE__, team_id}, cleanup_agents: true}
        )

      assert Team.add_worker(team, unique_id("builder-worker"), node: builder) ==
               {:error, {:invalid_worker_node, builder, {:role, :builder, :core}}}

      assert Team.add_worker(team, unique_id("absent-worker"),
               node: :"ouroboros-absent@127.0.0.1"
             ) ==
               {:error,
                {:invalid_worker_node, :"ouroboros-absent@127.0.0.1", :node_not_connected}}

      # The refusals are placement decisions, not team damage: a local worker still works.
      local_id = unique_id("local-worker")
      assert {:ok, %{id: ^local_id, node: local_node}} = Team.add_worker(team, local_id)
      assert local_node == node()
    end
  end

  describe "remote builds" do
    @tag timeout: 300_000
    test "a builder node compiles the capability and this node never loads it" do
      builder = start_app_peer!(node_role: :builder)

      previous = Application.get_env(:ouroboros, :forge_builder_node)
      Application.put_env(:ouroboros, :forge_builder_node, builder)

      on_exit(fn ->
        Application.put_env(:ouroboros, :forge_builder_node, previous)
        unload(@capability)
      end)

      assert {:ok, build} =
               BuildPeer.build(@capability, capability_source(), capability_test_source())

      assert build.module == @capability
      assert is_binary(build.binary)
      assert build.test_report.failures == 0
      assert build.test_report.total == 1

      # The compile happened inside a peer of the builder: not distributed, and not this
      # VM. Mirrors forge_build_peer_test — the module name is still unknown here.
      assert build.peer_runtime.distributed == false
      assert build.peer_runtime.node == :nonode@nohost
      assert :code.which(@capability) == :non_existing
      assert :code.get_object_code(@capability) == :error
      refute Code.ensure_loaded?(@capability)

      # Nor did the builder itself load it: it too only held the binary.
      assert :erpc.call(builder, :code, :which, [@capability]) == :non_existing

      # The artifact's runtime triple is the builder's, which is exactly why a builder
      # must be a role of the same release: the verifier compares it to every target.
      assert build.peer_runtime.otp_release == to_string(:erlang.system_info(:otp_release))

      assert build.peer_runtime.system_architecture ==
               to_string(:erlang.system_info(:system_architecture))
    end

    @tag timeout: 180_000
    test "a builder that is mis-rolled or unreachable is a typed refusal, not a build" do
      core = start_app_peer!()

      previous = Application.get_env(:ouroboros, :forge_builder_node)
      on_exit(fn -> Application.put_env(:ouroboros, :forge_builder_node, previous) end)

      Application.put_env(:ouroboros, :forge_builder_node, core)

      assert BuildPeer.build(@capability, capability_source(), nil) ==
               {:error, {:forge_builder_refused, core, {:role, :core, :builder}}}

      absent = :"ouroboros-absent@127.0.0.1"
      Application.put_env(:ouroboros, :forge_builder_node, absent)

      assert BuildPeer.build(@capability, capability_source(), nil) ==
               {:error, {:forge_builder_refused, absent, :node_not_connected}}

      Application.put_env(:ouroboros, :forge_builder_node, "not-a-node")

      assert BuildPeer.build(@capability, capability_source(), nil) ==
               {:error, {:invalid_forge_builder_node, "not-a-node"}}

      # The escape hatch relaxes the role and nothing else: the target must still be a
      # connected node running this runtime.
      allow_previous = Application.get_env(:ouroboros, :forge_builder_allow_any_role)
      Application.put_env(:ouroboros, :forge_builder_allow_any_role, true)

      on_exit(fn ->
        Application.put_env(:ouroboros, :forge_builder_allow_any_role, allow_previous)
      end)

      Application.put_env(:ouroboros, :forge_builder_node, absent)

      assert BuildPeer.build(@capability, capability_source(), nil) ==
               {:error, {:forge_builder_refused, absent, :node_not_connected}}
    end

    test "an unset builder leaves the local build path untouched" do
      assert Application.get_env(:ouroboros, :forge_builder_node) == nil

      assert {:ok, observed} =
               BuildPeer.with_peer(fn peer ->
                 {:ok, BuildPeer.call(peer, :erlang, :node, [])}
               end)

      assert observed == :nonode@nohost
    end
  end

  describe "least-privileged trees" do
    @tag timeout: 180_000
    test "a :builder node starts cluster formation and nothing else" do
      builder = start_app_peer!(node_role: :builder)

      assert :erpc.call(builder, Cluster, :role, []) == :builder
      assert is_pid(:erpc.call(builder, Process, :whereis, [Ouroboros.Supervisor]))
      assert is_pid(:erpc.call(builder, Process, :whereis, [Ouroboros.Cluster]))

      # None of the planes a core node owns exist here. A compromised builder has a
      # compiler on it, not a fleet's teams, sessions, journals, or control plane.
      for name <- [
            Ouroboros.Jido,
            Ouroboros.Mesh.Directory,
            Ouroboros.Coding.Store,
            Ouroboros.Interactive.Store,
            Ouroboros.Team.Store,
            Ouroboros.Team.Supervisor,
            Ouroboros.Orchestration.Store,
            Ouroboros.Orchestration.Scheduler,
            Ouroboros.Control.Store,
            Ouroboros.Control.Grants,
            Ouroboros.Release.Runtime,
            Ouroboros.Upgrade.NodeExecutor,
            Ouroboros.Upgrade.Rollout.Registry
          ] do
        assert :erpc.call(builder, Process, :whereis, [name]) == nil,
               "#{inspect(name)} must not run on a :builder node"
      end

      # The application really is running; the tree is small on purpose.
      applications = :erpc.call(builder, Application, :started_applications, [])
      assert Enum.any?(applications, &(elem(&1, 0) == :ouroboros))

      status = :erpc.call(builder, Ouroboros, :status, [])
      assert status.role == :builder
      assert status.availability.cluster == :available
      assert status.availability.teams == :unavailable
      assert status.availability.coding == :unavailable
      assert status.availability.mesh == :unavailable
    end
  end

  describe "release templates" do
    test "vm.args renders cleartext distribution by default and TLS when built for it" do
      cleartext =
        render_template("rel/vm.args.eex", %{
          "OUROBOROS_DIST_TLS" => nil,
          "OUROBOROS_DIST_TLS_OPTFILE" => nil,
          "OUROBOROS_DIST_PORT_MIN" => nil,
          "OUROBOROS_DIST_PORT_MAX" => nil
        })

      refute cleartext =~ "-proto_dist"
      refute cleartext =~ "inet_dist_listen_min"
      assert cleartext =~ "cleartext"

      tls =
        render_template("rel/vm.args.eex", %{
          "OUROBOROS_DIST_TLS" => "1",
          "OUROBOROS_DIST_TLS_OPTFILE" => "/etc/ouroboros/dist_tls.conf",
          "OUROBOROS_DIST_PORT_MIN" => "9100",
          "OUROBOROS_DIST_PORT_MAX" => "9105"
        })

      assert tls =~ "-proto_dist inet_tls"
      assert tls =~ "-ssl_dist_optfile /etc/ouroboros/dist_tls.conf"
      assert tls =~ "-kernel inet_dist_listen_min 9100 inet_dist_listen_max 9105"

      # The remote-command VMs must speak the same protocol to reach the node at all,
      # and must not pin the port the running node already holds.
      remote =
        render_template("rel/remote.vm.args.eex", %{
          "OUROBOROS_DIST_TLS" => "1",
          "OUROBOROS_DIST_TLS_OPTFILE" => "/etc/ouroboros/dist_tls.conf",
          "OUROBOROS_DIST_PORT_MIN" => "9100",
          "OUROBOROS_DIST_PORT_MAX" => "9105"
        })

      assert remote =~ "-proto_dist inet_tls"
      refute remote =~ "inet_dist_listen_min"
    end

    test "a half-configured distribution refuses to render an artifact" do
      assert_raise RuntimeError, ~r/OUROBOROS_DIST_TLS_OPTFILE/, fn ->
        render_template("rel/vm.args.eex", %{
          "OUROBOROS_DIST_TLS" => "1",
          "OUROBOROS_DIST_TLS_OPTFILE" => nil
        })
      end

      assert_raise RuntimeError, ~r/must be set together/, fn ->
        render_template("rel/vm.args.eex", %{
          "OUROBOROS_DIST_PORT_MIN" => "9100",
          "OUROBOROS_DIST_PORT_MAX" => nil
        })
      end

      assert_raise RuntimeError, ~r/must not exceed/, fn ->
        render_template("rel/vm.args.eex", %{
          "OUROBOROS_DIST_PORT_MIN" => "9200",
          "OUROBOROS_DIST_PORT_MAX" => "9100"
        })
      end

      assert_raise RuntimeError, ~r/TCP port/, fn ->
        render_template("rel/vm.args.eex", %{
          "OUROBOROS_DIST_PORT_MIN" => "0",
          "OUROBOROS_DIST_PORT_MAX" => "9100"
        })
      end
    end

    test "env.sh refuses a blank node name or cookie and exports the ones it is given" do
      script = Path.join(tmp_dir!(), "env.sh")

      # The real cli script sources env.sh and then reads what it exported, so the probe
      # below stands in for that reader.
      probe = """

      echo "NODE=$RELEASE_NODE"
      echo "COOKIE=$RELEASE_COOKIE"
      echo "DIST=$RELEASE_DISTRIBUTION"
      """

      File.write!(script, render_template("rel/env.sh.eex", %{}) <> probe)

      assert {output, 1} = run_script(script, %{"RELEASE_COMMAND" => "start"})
      assert output =~ "OUROBOROS_NODE must be set"

      assert {output, 1} =
               run_script(script, %{"RELEASE_COMMAND" => "start", "OUROBOROS_NODE" => "core-1"})

      assert output =~ "must be a long name"

      assert {output, 1} =
               run_script(script, %{
                 "RELEASE_COMMAND" => "start",
                 "OUROBOROS_NODE" => "core-1@10.0.0.11",
                 "OUROBOROS_COOKIE" => ""
               })

      assert output =~ "OUROBOROS_COOKIE must be set"

      assert {output, 0} =
               run_script(script, %{
                 "RELEASE_COMMAND" => "start",
                 "OUROBOROS_NODE" => "core-1@10.0.0.11",
                 "OUROBOROS_COOKIE" => "shared-secret"
               })

      assert output =~ "NODE=core-1@10.0.0.11"
      assert output =~ "COOKIE=shared-secret"
      assert output =~ "DIST=name"

      # `version` neither starts nor reaches a node, so it needs no identity.
      assert {_output, 0} = run_script(script, %{"RELEASE_COMMAND" => "version"})
    end
  end

  describe "production preflight" do
    setup do
      previous = System.get_env()

      data_dir =
        Path.join(
          System.tmp_dir!(),
          "ouroboros-cluster-config-#{System.unique_integer([:positive])}"
        )

      managed = [
        "OUROBOROS_DATA_DIR",
        "OUROBOROS_NODE_ROLE",
        "OUROBOROS_CLUSTER_STRATEGY",
        "OUROBOROS_CLUSTER_HOSTS",
        "OUROBOROS_ALLOW_INSECURE_DIST",
        "OUROBOROS_FORGE_BUILDER_NODE",
        "OUROBOROS_UPGRADE_TRUSTED_SIGNERS"
      ]

      Enum.each(managed, &System.delete_env/1)
      System.put_env("OUROBOROS_DATA_DIR", data_dir)

      on_exit(fn ->
        File.rm_rf(data_dir)

        Enum.each(managed, fn name ->
          case Map.fetch(previous, name) do
            {:ok, value} -> System.put_env(name, value)
            :error -> System.delete_env(name)
          end
        end)
      end)

      :ok
    end

    test "clustering without TLS distribution refuses the boot unless it is overridden" do
      # Not clustering: nothing to refuse, whatever the transport is.
      assert prod_config()[:ouroboros][:node_role] == :core

      System.put_env("OUROBOROS_CLUSTER_STRATEGY", "epmd")

      # This test VM runs cleartext distribution, which is precisely the posture the
      # preflight exists to catch.
      assert_raise RuntimeError, ~r/not running TLS distribution/, fn -> prod_config() end

      System.put_env("OUROBOROS_ALLOW_INSECURE_DIST", "1")
      assert prod_config()[:ouroboros][:node_role] == :core
    end

    test "role and builder are read from the environment and refused when unrecognized" do
      System.put_env("OUROBOROS_NODE_ROLE", "builder")
      System.put_env("OUROBOROS_FORGE_BUILDER_NODE", "builder-1@10.0.0.20")

      config = prod_config()[:ouroboros]
      assert config[:node_role] == :builder
      assert config[:forge_builder_node] == :"builder-1@10.0.0.20"

      System.put_env("OUROBOROS_NODE_ROLE", "root")
      assert_raise RuntimeError, ~r/OUROBOROS_NODE_ROLE/, fn -> prod_config() end

      System.put_env("OUROBOROS_NODE_ROLE", "core")
      System.put_env("OUROBOROS_CLUSTER_STRATEGY", "kubernetes")
      assert_raise RuntimeError, ~r/OUROBOROS_CLUSTER_STRATEGY/, fn -> prod_config() end
    end
  end

  defp prod_config, do: Config.Reader.read!("config/runtime.exs", env: :prod, target: :host)

  defp render_template(path, env) do
    with_env(env, fn ->
      EEx.eval_file(path, assigns: [release: %{name: :ouroboros}])
    end)
  end

  defp run_script(path, env) do
    merged =
      Map.merge(
        %{"OUROBOROS_NODE" => nil, "OUROBOROS_COOKIE" => nil, "RELEASE_COMMAND" => "start"},
        env
      )

    System.cmd("sh", [path], env: Map.to_list(merged), stderr_to_stdout: true)
  end

  defp with_env(env, fun) do
    previous = Map.new(env, fn {name, _value} -> {name, System.get_env(name)} end)

    try do
      Enum.each(env, fn
        {name, nil} -> System.delete_env(name)
        {name, value} -> System.put_env(name, value)
      end)

      fun.()
    after
      Enum.each(previous, fn
        {name, nil} -> System.delete_env(name)
        {name, value} -> System.put_env(name, value)
      end)
    end
  end

  defp start_app_peer!(env \\ []) do
    peer_node = start_bare_peer!()

    put_peer_env!(peer_node, :coding_storage, {Jido.Storage.ETS, table: peer_table(peer_node)})

    Enum.each(env, fn {key, value} -> put_peer_env!(peer_node, key, value) end)

    {:ok, _applications} = :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])
    peer_node
  end

  defp start_bare_peer! do
    ensure_distributed!()

    name = String.to_atom("ouroboros_cluster_peer_#{System.unique_integer([:positive])}")
    {:ok, peer, peer_node} = :peer.start(%{name: name, args: code_path_args(), wait_boot: 30_000})
    on_exit(fn -> stop_peer(peer) end)
    peer_node
  end

  # A peer with no distribution and no idea this VM exists: its control channel is a
  # pipe. Distribution is started inside it afterwards so that the only thing which can
  # connect it to anything is cluster formation itself.
  defp start_unformed_peer!(name) do
    {:ok, peer, :nonode@nohost} =
      :peer.start(%{connection: :standard_io, args: code_path_args(), wait_boot: 30_000})

    on_exit(fn -> stop_peer(peer) end)

    {:ok, _started} = :peer.call(peer, :application, :ensure_all_started, [:elixir], 30_000)

    [short_name, _host] = name |> Atom.to_string() |> String.split("@", parts: 2)

    {:ok, _kernel} =
      :peer.call(peer, :net_kernel, :start, [[String.to_atom(short_name), :shortnames]], 30_000)

    true = :peer.call(peer, :erlang, :set_cookie, [@formation_cookie])
    ^name = :peer.call(peer, :erlang, :node, [])
    peer
  end

  defp configure_formation!(peer, hosts) do
    :ok =
      :peer.call(peer, System, :put_env, [
        %{
          "OUROBOROS_CLUSTER_STRATEGY" => "epmd",
          "OUROBOROS_CLUSTER_HOSTS" => hosts,
          "OUROBOROS_CLUSTER_RECONNECT_MS" => "200"
        }
      ])

    :ok =
      :peer.call(peer, Application, :put_env, [
        :ouroboros,
        :coding_storage,
        {Jido.Storage.ETS, table: :ouroboros_formation_coding}
      ])
  end

  defp put_peer_env!(peer_node, key, value) do
    :ok = :erpc.call(peer_node, Application, :put_env, [:ouroboros, key, value])
  end

  defp peer_table(peer_node) do
    peer_node |> Atom.to_string() |> String.replace(~r/[^a-zA-Z0-9]/, "_") |> String.to_atom()
  end

  defp code_path_args, do: Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

  defp stop_peer(peer) do
    :peer.stop(peer)
  catch
    _kind, _reason -> :ok
  end

  defp hostname do
    {:ok, host} = :inet.gethostname()
    List.to_string(host)
  end

  defp ensure_distributed! do
    unless Node.alive?() do
      name = String.to_atom("ouroboros_cluster_root_#{System.unique_integer([:positive])}")
      {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end

    :ok
  end

  defp tmp_dir! do
    dir = Path.join(System.tmp_dir!(), "ouroboros-rel-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end

  defp unload(module) do
    :code.delete(module)
    :code.soft_purge(module)
    :ok
  end

  defp capability_source do
    """
    defmodule #{inspect(@capability)} do
      @vsn 1

      def double(n) when is_integer(n), do: n * 2
    end
    """
  end

  defp capability_test_source do
    """
    defmodule Ouroboros.Capability.RemotelyBuiltTest do
      use ExUnit.Case, async: false

      test "doubles" do
        assert #{inspect(@capability)}.double(21) == 42
      end
    end
    """
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive])}"

  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(50)
      assert_eventually(fun, attempts - 1)
    end
  end
end
