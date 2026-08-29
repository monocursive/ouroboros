defmodule Ouroboros.ClusterTest do
  use ExUnit.Case, async: false

  # libcluster's strategies are aliased first, on purpose: `Ouroboros.Cluster` takes the
  # `Cluster` alias below, after which `Cluster.Strategy.DNSPoll` would name a module
  # that does not exist. The epmd strategy is Ouroboros' own `Cluster.RosterEpmd`.
  alias Cluster.Strategy.DNSPoll
  alias Cluster.Strategy.Gossip

  alias Ouroboros.Cluster
  alias Ouroboros.Gateway.Methods
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

    test "fleet compatibility has an explicit manual protocol revision" do
      runtime = Cluster.local_fleet_posture().runtime

      assert runtime.fleet_protocol_revision == 1

      assert Cluster.runtime_compatible?(
               runtime,
               %{runtime | system_architecture: "different-test-architecture"}
             )

      refute Cluster.runtime_compatible?(
               runtime,
               %{runtime | fleet_protocol_revision: runtime.fleet_protocol_revision + 1}
             )

      refute Cluster.runtime_compatible?(runtime, Map.delete(runtime, :fleet_protocol_revision))
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

    @tag timeout: 180_000
    test "fleet directory retains an offline peer with last-known runtime facts" do
      peer = start_app_peer!()

      assert_eventually(
        fn ->
          Enum.any?(Cluster.fleet_status().machines, fn machine ->
            machine.node == peer and machine.state == :connected and machine.role == :core and
              machine.runtime_running? == true
          end)
        end,
        300
      )

      before = Enum.find(Cluster.fleet_status().machines, &(&1.node == peer))
      assert before.compatibility == :compatible
      assert before.last_up_at
      assert before.runtime.fleet_protocol_revision == 1
      assert before.runtime.otp_release == to_string(:erlang.system_info(:otp_release))

      assert %{status: :warning, guidance: roster_guidance} =
               Enum.find(
                 Cluster.fleet_doctor().checks,
                 &(&1.id == {:machine_connectivity, peer})
               )

      assert roster_guidance =~ "latest signed roster"
      assert roster_guidance =~ "rotate the fleet"

      # CPU architecture is inventory, not a compatibility fence: Erlang distribution
      # and the agent protocol are cross-architecture. Simulate the common arm64 Mac +
      # x86_64 Linux fleet and ensure doctor does not turn it into a false outage.
      :sys.replace_state(Ouroboros.Cluster.Monitor, fn state ->
        put_in(
          state,
          [:machines, peer, :runtime, :system_architecture],
          "different-test-architecture"
        )
      end)

      with_env(
        %{
          "OUROBOROS_CLUSTER_STRATEGY" => "epmd",
          "OUROBOROS_CLUSTER_HOSTS" => Atom.to_string(peer)
        },
        fn ->
          mixed_arch = Enum.find(Cluster.fleet_status().machines, &(&1.node == peer))
          assert mixed_arch.runtime.system_architecture == "different-test-architecture"
          assert mixed_arch.compatibility == :compatible

          assert %{status: :ok} =
                   Enum.find(Cluster.fleet_doctor().checks, fn check ->
                     check.id == {:machine_compatibility, peer}
                   end)

          protocol_revision = mixed_arch.runtime.fleet_protocol_revision

          :sys.replace_state(Ouroboros.Cluster.Monitor, fn state ->
            put_in(
              state,
              [:machines, peer, :runtime, :fleet_protocol_revision],
              protocol_revision + 1
            )
          end)

          protocol_skew = Enum.find(Cluster.fleet_status().machines, &(&1.node == peer))
          assert protocol_skew.compatibility == :incompatible

          assert %{status: :error, guidance: guidance} =
                   Enum.find(Cluster.fleet_doctor().checks, fn check ->
                     check.id == {:machine_compatibility, peer}
                   end)

          assert guidance =~ "same Ouroboros build"

          :sys.replace_state(Ouroboros.Cluster.Monitor, fn state ->
            put_in(
              state,
              [:machines, peer, :runtime, :fleet_protocol_revision],
              protocol_revision
            )
          end)
        end
      )

      joined_fleet = Cluster.fleet_status()
      assert joined_fleet.summary.expected == length(joined_fleet.machines)
      assert joined_fleet.summary.expected >= joined_fleet.summary.connected

      # Stop the peer through BEAM rather than by touching an OS pid. The monitor has no
      # process left to query afterward, so retaining these facts proves this is a
      # last-known directory rather than a decorated Node.list/0.
      true = :rpc.cast(peer, System, :stop, [])

      assert_eventually(
        fn ->
          case Enum.find(Cluster.fleet_status().machines, &(&1.node == peer)) do
            %{state: :offline, last_down_at: value, down_reason: reason}
            when is_binary(value) and is_binary(reason) ->
              true

            _other ->
              false
          end
        end,
        300
      )

      offline = Enum.find(Cluster.fleet_status().machines, &(&1.node == peer))
      assert offline.role == :core

      assert Map.drop(offline.runtime, [:system_architecture]) ==
               Map.drop(before.runtime, [:system_architecture])

      assert offline.runtime.system_architecture == "different-test-architecture"
      assert offline.last_seen_at >= before.last_seen_at
      assert Cluster.status().fleet.summary.offline >= 0
      assert Cluster.resolve_machine(Atom.to_string(peer)) == {:error, :unknown_machine}
      assert Cluster.resolve_known_machine(Atom.to_string(peer)) == {:ok, peer}

      doctor = Cluster.fleet_doctor()
      refute inspect(doctor) =~ Atom.to_string(:erlang.get_cookie())

      assert %{status: :warning, node: ^peer} =
               Enum.find(doctor.checks, &(&1.id == {:machine_connectivity, peer}))
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

    # W8. `fleet.status` answered a directory and no label, so every surface that wanted to
    # say which fleet it was looking at fell back to this machine's node name — one member
    # standing in for the whole. The name has always been in the profile; the decoder simply
    # dropped it. What must not change while retaining it: the validation above it.
    test "the fleet's name survives the roster decode, and never gates it" do
      fleet_id = "aaaa1111bbbb2222cccc4444"
      data_dir = tmp_dir!()
      fleet_dir = Path.join(data_dir, "fleet")
      File.mkdir_p!(fleet_dir)

      owner = test_fleet_member("owner", "127.0.0.1")
      owner_node = :"ouro-owner@127.0.0.1"

      previous_data_dir = Application.get_env(:ouroboros, :data_dir)
      Cluster.reset_membership_cache()

      on_exit(fn ->
        Cluster.reset_membership_cache()

        if previous_data_dir,
          do: Application.put_env(:ouroboros, :data_dir, previous_data_dir),
          else: Application.delete_env(:ouroboros, :data_dir)
      end)

      with_env(
        %{
          "OUROBOROS_CLUSTER_STRATEGY" => "epmd",
          "OUROBOROS_CLUSTER_HOSTS" => Atom.to_string(owner_node),
          "OUROBOROS_FLEET_ID" => fleet_id
        },
        fn ->
          Application.put_env(:ouroboros, :data_dir, data_dir)

          write_test_fleet_profile!(fleet_dir, fleet_id, local: owner, members: [owner])

          assert Cluster.fleet_name() == "Cluster test fleet"
          assert Cluster.fleet_status().fleet_name == "Cluster test fleet"

          # A rename is picked up without a restart, for the reason membership is: the
          # profile is the authority and it is re-read, not cached at boot.
          rewrite_fleet_profile_name!(fleet_dir, "Ironworks")
          assert Cluster.fleet_name() == "Ironworks"

          # Every way the name can be unusable is the same answer — an unnamed fleet —
          # and none of them costs this node its roster.
          for unusable <- [nil, "", "   ", 42, "bell\aname", String.duplicate("n", 121)] do
            rewrite_fleet_profile_name!(fleet_dir, unusable)

            assert Cluster.fleet_name() == nil,
                   "#{inspect(unusable)} was accepted as a fleet name"

            # The validation the roster's *safety* rests on is untouched: this profile is
            # still decoded, and still names its member.
            assert owner_node in Cluster.membership_hosts(),
                   "#{inspect(unusable)} as a name cost this node its roster"
          end

          # A profile that is genuinely invalid still refuses, name or no name.
          File.write!(Path.join(fleet_dir, "profile.json"), "{ not json")
          assert Cluster.fleet_name() == nil

          # And with no profile at all there is no fleet to name.
          File.rm!(Path.join(fleet_dir, "profile.json"))
          assert Cluster.fleet_name() == nil
          assert Cluster.fleet_status().fleet_name == nil
        end
      )
    end

    test "expected membership follows the saved fleet profile while the runtime is up" do
      fleet_id = "aaaa1111bbbb2222cccc3333"
      data_dir = tmp_dir!()
      fleet_dir = Path.join(data_dir, "fleet")
      File.mkdir_p!(fleet_dir)

      owner = test_fleet_member("owner", "127.0.0.1")
      late = test_fleet_member("late", "127.0.0.1")
      owner_node = :"ouro-owner@127.0.0.1"
      late_node = :"ouro-late@127.0.0.1"

      previous_data_dir = Application.get_env(:ouroboros, :data_dir)
      Cluster.reset_membership_cache()

      on_exit(fn ->
        Cluster.reset_membership_cache()

        if previous_data_dir,
          do: Application.put_env(:ouroboros, :data_dir, previous_data_dir),
          else: Application.delete_env(:ouroboros, :data_dir)
      end)

      with_env(
        %{
          "OUROBOROS_CLUSTER_STRATEGY" => "epmd",
          "OUROBOROS_CLUSTER_HOSTS" => Atom.to_string(owner_node),
          "OUROBOROS_FLEET_ID" => fleet_id
        },
        fn ->
          Application.put_env(:ouroboros, :data_dir, data_dir)

          write_test_fleet_profile!(fleet_dir, fleet_id, local: owner, members: [owner])
          assert owner_node in Cluster.expected_nodes()
          refute late_node in Cluster.expected_nodes()

          # The roster grows while the runtime is up: no restart, no environment
          # change — only the saved profile moves, exactly what `ouro fleet add` does.
          write_test_fleet_profile!(fleet_dir, fleet_id,
            local: owner,
            members: [owner, late],
            roster_revision: 2
          )

          assert late_node in Cluster.membership_hosts()
          assert late_node in Cluster.expected_nodes()

          # An unreadable profile must keep the membership last read, never shrink to
          # the boot seed: dropping the just-added member is the wait-forever bug again.
          File.write!(Path.join(fleet_dir, "profile.json"), "{ not json")
          assert late_node in Cluster.membership_hosts()

          # The inverse: a canceled member leaves the dial list without a restart.
          write_test_fleet_profile!(fleet_dir, fleet_id,
            local: owner,
            members: [owner],
            tombstones: [late],
            roster_revision: 3
          )

          refute late_node in Cluster.membership_hosts()
          refute late_node in Cluster.expected_nodes()

          # With no active profile the boot seed is the whole answer, as before.
          File.rm!(Path.join(fleet_dir, "profile.json"))
          assert Cluster.membership_hosts() == [owner_node]
        end
      )
    end

    @tag timeout: 300_000
    test "a member invited while the owner runtime is live is dialed without a restart" do
      ensure_distributed!()
      host = hostname()
      unique = System.unique_integer([:positive])
      owner_machine = "own#{unique}"
      late_machine = "late#{unique}"
      owner_name = :"ouro-#{owner_machine}@#{host}"
      late_name = :"ouro-#{late_machine}@#{host}"
      fleet_id = "feed5eed0123456789abcdef"

      data_dir = tmp_dir!()
      # The owner peer boots the full runtime on this directory, and the runtime
      # refuses a data directory that is not private.
      File.chmod!(data_dir, 0o700)
      fleet_dir = Path.join(data_dir, "fleet")
      File.mkdir_p!(fleet_dir)

      owner_member = test_fleet_member(owner_machine, host)
      late_member = test_fleet_member(late_machine, host)
      write_test_fleet_profile!(fleet_dir, fleet_id, local: owner_member, members: [owner_member])

      owner = start_unformed_peer!(owner_name)
      late = start_unformed_peer!(late_name)

      # Only the owner forms. The late member never dials anyone — this is the NATed
      # owner + reachable member shape, where the mesh forms only if the owner's own
      # dialer learns the roster change while running.
      configure_formation!(owner, Atom.to_string(owner_name))
      :ok = :peer.call(owner, System, :put_env, [%{"OUROBOROS_FLEET_ID" => fleet_id}])

      :ok =
        :peer.call(late, Application, :put_env, [
          :ouroboros,
          :coding_storage,
          {Jido.Storage.ETS, table: :ouroboros_late_invite_coding}
        ])

      for peer <- [owner, late] do
        assert {:ok, _applications} =
                 :peer.call(peer, Application, :ensure_all_started, [:ouroboros], 60_000)
      end

      # Set after boot: a durable data directory at boot demands the trusted `ouro`
      # process-identity helper this test VM cannot provide. The monitor and the
      # dialer read the profile live either way.
      :ok = :peer.call(owner, Application, :put_env, [:ouroboros, :data_dir, data_dir])

      # Several sweeps pass; a one-machine roster must not invent the other machine.
      Process.sleep(600)
      refute late_name in :peer.call(owner, Node, :list, [])

      # `ouro fleet add` while the owner runtime is up: only the saved profile changes.
      write_test_fleet_profile!(fleet_dir, fleet_id,
        local: owner_member,
        members: [owner_member, late_member],
        roster_revision: 2
      )

      assert_eventually(fn -> late_name in :peer.call(owner, Node, :list, []) end, 300)
      assert late_name in :peer.call(owner, Cluster, :expected_nodes, [])

      # The inverse: cancellation stops the dialing without a restart. Wait until the
      # owner has seen the shrunk roster, break the link, and prove it stays down.
      write_test_fleet_profile!(fleet_dir, fleet_id,
        local: owner_member,
        members: [owner_member],
        tombstones: [late_member],
        roster_revision: 3
      )

      assert_eventually(
        fn -> late_name not in :peer.call(owner, Cluster, :expected_nodes, []) end,
        300
      )

      true = :peer.call(owner, Node, :disconnect, [late_name])
      Process.sleep(1_000)
      refute late_name in :peer.call(owner, Node, :list, [])
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
          assert topology[:strategy] == Cluster.RosterEpmd
          # The seed list: every sweep re-resolves through `membership_hosts/0`.
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

    test "static topology exposes an expected offline machine with recovery guidance" do
      absent = :"expected-core@127.0.0.1"

      with_env(
        %{
          "OUROBOROS_CLUSTER_STRATEGY" => "epmd",
          "OUROBOROS_CLUSTER_HOSTS" => Atom.to_string(absent),
          "OUROBOROS_CLUSTER_RECONNECT_MS" => "250"
        },
        fn ->
          fleet = Cluster.fleet_status()
          machine = Enum.find(fleet.machines, &(&1.node == absent))

          assert machine.expected? == true
          assert machine.state == :offline
          assert fleet.formation.reconnect_ms == 250
          assert fleet.summary.offline >= 1

          doctor = Cluster.fleet_doctor()

          assert Enum.any?(doctor.checks, fn check ->
                   check.id == {:machine_connectivity, absent} and check.status == :error and
                     check.message =~ "will keep retrying" and check.guidance =~ "EPMD"
                 end)
        end
      )
    end

    test "doctor never calls an explicitly overridden cleartext fleet healthy" do
      ensure_distributed!()
      absent = :"cleartext-core@127.0.0.1"

      with_env(
        %{
          "OUROBOROS_CLUSTER_STRATEGY" => "epmd",
          "OUROBOROS_CLUSTER_HOSTS" => Atom.to_string(absent)
        },
        fn ->
          doctor = Cluster.fleet_doctor()

          refute doctor.healthy?

          assert %{status: :error, message: message, guidance: guidance} =
                   Enum.find(doctor.checks, &(&1.id == :distribution_encryption))

          assert message =~ "cleartext"
          assert guidance =~ "generated fleet TLS profile"
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

    @tag timeout: 180_000
    test "an incompatible core is refused by placement and both gateway start planes" do
      core = start_app_peer!()
      incompatible_version = "999.0.0-placement-test"
      replace_peer_version!(core, incompatible_version)

      # The directory and live placement probe deliberately use the same contract. Force
      # an immediate refresh because this test changes an application spec without taking
      # the distributed node down, which produces no natural nodeup event.
      send(Ouroboros.Cluster.Monitor, {:refresh_connected, [core]})

      assert_eventually(
        fn ->
          case Enum.find(Cluster.fleet_status().machines, &(&1.node == core)) do
            %{
              compatibility: :incompatible,
              runtime: %{ouroboros_version: ^incompatible_version}
            } ->
              true

            _other ->
              false
          end
        end,
        300
      )

      expected =
        Cluster.local_fleet_posture().runtime
        |> Map.take([:fleet_protocol_revision, :ouroboros_version, :otp_release])

      assert {:error,
              {:runtime_incompatible, %{ouroboros_version: ^incompatible_version} = actual,
               ^expected}} =
               Cluster.ensure_placeable(core)

      assert actual.otp_release == expected.otp_release
      assert actual.fleet_protocol_revision == expected.fleet_protocol_revision

      assert %{status: :error, node: ^core} =
               Enum.find(
                 Cluster.fleet_doctor().checks,
                 &(&1.id == {:machine_compatibility, core})
               )

      interactive_id = unique_id("incompatible-interactive")
      coding_id = unique_id("incompatible-coding")

      starts = [
        {"interactive.start",
         %{
           "id" => interactive_id,
           "node" => Atom.to_string(core)
         }},
        {"coding.start",
         %{
           "id" => coding_id,
           "objective" => "must not start on a mismatched runtime",
           "machine" => Atom.to_string(core)
         }}
      ]

      # Workspace validation precedes placement: this peer is deliberately incompatible,
      # yet missing and relative destination paths are parameter refusals rather than a
      # version refusal or an accidental expansion from the packaged release's cwd.
      for {method, params} <- starts do
        assert {:error, -32_602, missing} = Methods.invoke(method, params)
        assert missing =~ "params.workspace is required"
        assert missing =~ "nonempty absolute path"
        assert missing =~ "on that machine"

        assert {:error, -32_602, relative} =
                 Methods.invoke(method, Map.put(params, "workspace", "."))

        assert relative =~ "params.workspace must be an absolute path"
        assert relative =~ "packaged release"

        assert {:error, -32_602, empty} =
                 Methods.invoke(method, Map.put(params, "workspace", ""))

        assert empty =~ "params.workspace must be a nonempty string"
      end

      for {method, params} <-
            Enum.map(starts, fn {method, params} ->
              {method, Map.put(params, "workspace", File.cwd!())}
            end) do
        assert {:error, -32_004, message, %{"outcome" => "not_dispatched"}} =
                 Methods.invoke(method, params)

        assert message =~ "Ouroboros version, OTP release, or fleet protocol revision differs"
        assert message =~ "install the same Ouroboros build"
      end

      assert :not_found ==
               :erpc.call(core, Ouroboros.Interactive.Store, :get, [interactive_id])

      assert :not_found == :erpc.call(core, Ouroboros.Coding.Store, :get, [coding_id])
    end

    @tag timeout: 180_000
    test "connected core query failures are incomplete without freezing an idle offline seed" do
      reset_session_owner_evidence!()
      on_exit(fn -> reset_session_owner_evidence!() end)

      core = start_app_peer!()

      previous_strategy = System.get_env("OUROBOROS_CLUSTER_STRATEGY")
      previous_hosts = System.get_env("OUROBOROS_CLUSTER_HOSTS")
      System.put_env("OUROBOROS_CLUSTER_STRATEGY", "epmd")
      System.put_env("OUROBOROS_CLUSTER_HOSTS", Atom.to_string(core))

      on_exit(fn ->
        if previous_strategy,
          do: System.put_env("OUROBOROS_CLUSTER_STRATEGY", previous_strategy),
          else: System.delete_env("OUROBOROS_CLUSTER_STRATEGY")

        if previous_hosts,
          do: System.put_env("OUROBOROS_CLUSTER_HOSTS", previous_hosts),
          else: System.delete_env("OUROBOROS_CLUSTER_HOSTS")
      end)

      assert_eventually(
        fn ->
          match?(
            %{expected?: true, state: :connected, role: :core},
            Enum.find(Cluster.fleet_status().machines, &(&1.node == core))
          )
        end,
        300
      )

      assert {:ok, interactive} = Methods.invoke("interactive.list", %{})
      assert is_list(interactive)
      assert {:ok, coding} = Methods.invoke("coding.list", %{})
      assert is_list(coding)

      # Keep distribution alive but remove the owner-local stores. This is the exact
      # posture in which silently mapping the remote error to [] used to erase its rows
      # while fleet.status continued to call the node connected.
      assert :ok = :erpc.call(core, Application, :stop, [:ouroboros])
      assert core in Node.list()

      for method <- ["interactive.list", "coding.list"] do
        assert {:error, -32_004, message,
                %{"reason" => "owner_query_incomplete", "node" => owner}} =
                 Methods.invoke(method, %{})

        assert owner == Atom.to_string(core)
        assert message =~ "session list is incomplete"
        assert message =~ "keeping the previous fleet view"
      end

      # Both complete lists above proved this core empty, so its later outage must not
      # freeze an otherwise useful refresh merely because it is a saved invitation seed.
      # Positive start/list evidence, not stale topology alone, is the retention fence.
      true = :rpc.cast(core, System, :stop, [])

      assert_eventually(fn -> core not in Node.list() end, 300)

      assert_eventually(
        fn ->
          match?(
            %{state: :offline, role: :core, runtime_running?: true},
            Enum.find(Cluster.fleet_status().machines, &(&1.node == core))
          )
        end,
        300
      )

      for method <- ["interactive.list", "coding.list"] do
        assert {:ok, sessions} = Methods.invoke(method, %{})
        assert is_list(sessions)
      end
    end

    test "a complete empty reply clears only that connected owner's positive evidence" do
      assert :ok =
               Cluster.record_session_snapshot(:interactive, [
                 {node(), [%{id: "observed-session"}]}
               ])

      assert {:ok, observed} = Cluster.session_owners(:interactive)
      assert MapSet.member?(observed, Atom.to_string(node()))

      assert :ok = Cluster.record_session_snapshot(:interactive, [{node(), []}])
      assert {:ok, cleared} = Cluster.session_owners(:interactive)
      refute MapSet.member?(cleared, Atom.to_string(node()))
    end

    test "local session-owner evidence follows a late distribution identity" do
      # The full suite starts the application without distribution and individual
      # distributed tests start net_kernel later. Simulate that transition directly so
      # this regression does not itself depend on which test seed starts distribution.
      ensure_distributed!()
      _ = Cluster.fleet_status()
      current = node()
      former = :nonode@nohost

      on_exit(fn ->
        reset_session_owner_evidence!()
        _ = Cluster.fleet_status()
      end)

      :sys.replace_state(Ouroboros.Cluster.Monitor, fn state ->
        local = Map.fetch!(state.machines, current)

        machines =
          state.machines
          |> Map.delete(current)
          |> Map.put(former, %{local | node: former, state: :local})

        owners =
          state.session_owners
          |> Map.put(:interactive, MapSet.new([Atom.to_string(former)]))

        %{state | machines: machines, session_owners: owners}
      end)

      _ = Cluster.fleet_status()

      assert {:ok, owners} = Cluster.session_owners(:interactive)
      assert MapSet.member?(owners, Atom.to_string(current))
      refute MapSet.member?(owners, Atom.to_string(former))

      assert Enum.any?(Cluster.fleet_status().machines, &(&1.node == current))
      refute Enum.any?(Cluster.fleet_status().machines, &(&1.node == former))

      assert :ok = Cluster.record_session_snapshot(:interactive, [{current, []}])
    end

    test "session-owner evidence accepts fleets beyond the former 256-machine ceiling" do
      reset_session_owner_evidence!()
      on_exit(fn -> reset_session_owner_evidence!() end)

      owners =
        Enum.map(1..257, fn index ->
          String.to_atom("evidence-owner-#{index}@127.0.0.1")
        end)

      observations = Enum.map(owners, &{&1, [%{id: "session-on-#{&1}"}]})

      assert :ok = Cluster.record_session_snapshot(:interactive, observations)
      assert {:ok, recorded} = Cluster.session_owners(:interactive)
      assert MapSet.size(recorded) == 257
      assert Enum.all?(owners, &MapSet.member?(recorded, Atom.to_string(&1)))

      assert :ok =
               Cluster.record_session_snapshot(
                 :interactive,
                 Enum.map(owners, &{&1, []})
               )
    end

    test "a new fleet ignores durable owner evidence from a previous fleet identity" do
      data_dir = tmp_dir!()
      fleet_dir = Path.join(data_dir, "fleet")
      File.mkdir_p!(fleet_dir)

      previous_data_dir = Application.get_env(:ouroboros, :data_dir)
      previous_fleet_id = System.get_env("OUROBOROS_FLEET_ID")
      current_fleet_id = "111122223333444455556666"

      Application.put_env(:ouroboros, :data_dir, data_dir)
      System.put_env("OUROBOROS_FLEET_ID", current_fleet_id)

      write_test_fleet_profile!(fleet_dir, current_fleet_id)

      on_exit(fn ->
        if previous_data_dir,
          do: Application.put_env(:ouroboros, :data_dir, previous_data_dir),
          else: Application.delete_env(:ouroboros, :data_dir)

        if previous_fleet_id,
          do: System.put_env("OUROBOROS_FLEET_ID", previous_fleet_id),
          else: System.delete_env("OUROBOROS_FLEET_ID")
      end)

      assert :ok =
               Ouroboros.Storage.DurableFile.put_checkpoint(
                 {:ouroboros, :cluster_session_owners, 1},
                 %{
                   version: 1,
                   fleet_id: "aaaabbbbccccddddeeeeffff",
                   interactive: ["former-core@127.0.0.1"],
                   coding: []
                 },
                 path: Path.join(fleet_dir, "cluster-directory")
               )

      previous_monitor = Process.whereis(Ouroboros.Cluster.Monitor)
      Process.exit(previous_monitor, :kill)

      assert_eventually(
        fn ->
          case Process.whereis(Ouroboros.Cluster.Monitor) do
            monitor when is_pid(monitor) -> monitor != previous_monitor
            _absent -> false
          end
        end,
        300
      )

      assert {:ok, owners} = Cluster.session_owners(:interactive)
      refute MapSet.member?(owners, "former-core@127.0.0.1")
    end

    test "a malformed fleet tombstone makes owner evidence unavailable instead of clearing it" do
      fleet_id = "2468ace02468ace02468ace0"
      data_dir = tmp_dir!()
      fleet_dir = Path.join(data_dir, "fleet")
      File.mkdir_p!(fleet_dir)
      owner = :"ouro-lost@127.0.0.2"
      removed = test_fleet_member("lost", "127.0.0.2")
      previous_data_dir = Application.get_env(:ouroboros, :data_dir)

      with_env(%{"OUROBOROS_FLEET_ID" => fleet_id}, fn ->
        Application.put_env(:ouroboros, :data_dir, data_dir)

        on_exit(fn ->
          if previous_data_dir,
            do: Application.put_env(:ouroboros, :data_dir, previous_data_dir),
            else: Application.delete_env(:ouroboros, :data_dir)
        end)

        write_test_fleet_profile!(fleet_dir, fleet_id)
        reset_session_owner_evidence!()

        assert :ok =
                 Cluster.record_session_snapshot(:interactive, [
                   {owner, [%{id: "retained-owner"}]}
                 ])

        malformed = Map.put(removed, "node", "ouro-someone-else@127.0.0.2")

        write_test_fleet_profile!(fleet_dir, fleet_id,
          tombstones: [malformed],
          roster_revision: 2
        )

        restart_cluster_monitor!()

        assert {:error, {:fleet_profile_unreadable, :invalid_fleet_profile_roster}} =
                 Cluster.session_owners(:interactive)

        assert {:error, -32_004, _message,
                %{
                  "reason" => "owner_query_incomplete",
                  "node" => "unknown",
                  "evidence" => "unavailable"
                }} = Methods.invoke("interactive.list", %{})

        # Repairing the profile recovers the unchanged durable evidence; malformed input
        # never became an implicit state-loss acknowledgement.
        write_test_fleet_profile!(fleet_dir, fleet_id, roster_revision: 2)
        restart_cluster_monitor!()

        assert {:ok, recovered} = Cluster.session_owners(:interactive)
        assert MapSet.member?(recovered, Atom.to_string(owner))
        assert :ok = Cluster.record_session_snapshot(:interactive, [{owner, []}])
      end)
    end

    test "an unreadable owner checkpoint refuses a recording start instead of overwriting it" do
      fleet_id = "1357bdf01357bdf01357bdf0"
      data_dir = tmp_dir!()
      fleet_dir = Path.join(data_dir, "fleet")
      File.mkdir_p!(fleet_dir)
      previous_data_dir = Application.get_env(:ouroboros, :data_dir)

      with_env(%{"OUROBOROS_FLEET_ID" => fleet_id}, fn ->
        Application.put_env(:ouroboros, :data_dir, data_dir)

        on_exit(fn ->
          reset_session_owner_evidence!()

          if previous_data_dir,
            do: Application.put_env(:ouroboros, :data_dir, previous_data_dir),
            else: Application.delete_env(:ouroboros, :data_dir)
        end)

        write_test_fleet_profile!(fleet_dir, fleet_id)
        checkpoint_dir = Path.join(fleet_dir, "cluster-directory")

        # A checkpoint this build cannot decode, rather than an absent one: absent evidence
        # is legitimately empty, undecodable evidence is unknown.
        assert :ok =
                 Ouroboros.Storage.DurableFile.put_checkpoint(
                   {:ouroboros, :cluster_session_owners, 1},
                   %{
                     version: 1,
                     fleet_id: fleet_id,
                     interactive: "not-an-owner-list",
                     coding: []
                   },
                   path: checkpoint_dir
                 )

        assert [checkpoint] =
                 Path.wildcard(Path.join([checkpoint_dir, "checkpoints", "*.term"]))

        undecodable = File.read!(checkpoint)
        restart_cluster_monitor!()

        assert {:error, {:invalid_session_owners, :interactive}} =
                 Cluster.session_owners(:interactive)

        # Every remote start reaches this call through `Placement.fence_possible_owner/2`.
        # It must fail closed the way retirement already does rather than persist a map
        # derived from the empty in-memory baseline.
        assert {:error,
                {:session_owner_evidence_unavailable, {:invalid_session_owners, :interactive}}} =
                 Cluster.record_session_snapshot(:interactive, [
                   {:"ouro-lost@127.0.0.2", [%{possible_start: true}]}
                 ])

        # An observation that changes nothing takes the same refusal: the skip-write branch
        # was the one that used to call unreadable evidence reliable without writing at all.
        assert {:error, {:session_owner_evidence_unavailable, _reason}} =
                 Cluster.record_session_snapshot(:interactive, [])

        assert File.read!(checkpoint) == undecodable

        # The journal names both planes, so a recorded interactive observation must never
        # be able to answer for coding either.
        assert {:error, {:invalid_session_owners, :interactive}} =
                 Cluster.session_owners(:coding)
      end)
    end

    @tag timeout: 180_000
    test "a roster tombstone preserves evidence until an explicit offline state-loss acknowledgement" do
      fleet_id = "9876543210abcdef98765432"
      data_dir = tmp_dir!()
      fleet_dir = Path.join(data_dir, "fleet")
      File.mkdir_p!(fleet_dir)

      machine = "retire#{System.unique_integer([:positive])}"
      ensure_distributed!()

      {:ok, peer, target} =
        :peer.start(%{
          name: String.to_atom("ouro-#{machine}"),
          args: code_path_args(),
          wait_boot: 30_000
        })

      on_exit(fn -> stop_peer(peer) end)
      [_name, host] = target |> Atom.to_string() |> String.split("@", parts: 2)
      removed_member = test_fleet_member(machine, host)

      previous_data_dir = Application.get_env(:ouroboros, :data_dir)

      with_env(%{"OUROBOROS_FLEET_ID" => fleet_id}, fn ->
        Application.put_env(:ouroboros, :data_dir, data_dir)

        on_exit(fn ->
          if previous_data_dir,
            do: Application.put_env(:ouroboros, :data_dir, previous_data_dir),
            else: Application.delete_env(:ouroboros, :data_dir)
        end)

        write_test_fleet_profile!(fleet_dir, fleet_id)
        reset_session_owner_evidence!()

        assert {:error, -32_007, missing_message} =
                 Methods.invoke("fleet.forget_session_owner", %{
                   "machine" => machine,
                   "accept_state_loss" => true
                 })

        assert missing_message =~ "no roster tombstone"

        write_test_fleet_profile!(fleet_dir, fleet_id,
          tombstones: [removed_member],
          roster_revision: 2
        )

        assert :ok =
                 Cluster.record_session_snapshot(:interactive, [
                   {target, [%{id: "offline-interactive"}]}
                 ])

        assert :ok =
                 Cluster.record_session_snapshot(:coding, [
                   {target, [%{id: "offline-coding"}]}
                 ])

        assert {:error, -32_602, confirmation_message} =
                 Methods.invoke("fleet.forget_session_owner", %{"machine" => machine})

        assert confirmation_message =~ "accept_state_loss must be true"

        assert {:error, -32_004, connected_message,
                %{
                  "reason" => "session_owner_connected",
                  "machine" => ^machine,
                  "node" => connected_node
                }} =
                 Methods.invoke("fleet.forget_session_owner", %{
                   "machine" => machine,
                   "accept_state_loss" => true
                 })

        assert connected_node == Atom.to_string(target)
        assert connected_message =~ "inspect or copy its sessions"

        stop_peer(peer)
        assert_eventually(fn -> target not in Node.list() end, 300)
        restart_cluster_monitor!()

        # Cancellation and signed roster import are not session-state retirement. The
        # tombstone alone survives a Monitor/BEAM recovery and keeps both planes honest.
        for plane <- [:interactive, :coding] do
          assert {:ok, owners} = Cluster.session_owners(plane)
          assert MapSet.member?(owners, Atom.to_string(target))
        end

        for method <- ["interactive.list", "coding.list"] do
          assert {:error, -32_004, _message,
                  %{"reason" => "owner_query_incomplete", "node" => owner}} =
                   Methods.invoke(method, %{})

          assert owner == Atom.to_string(target)
        end

        assert {:ok,
                %{
                  machine: ^machine,
                  node: forgotten_node,
                  roster_revision: 2,
                  removed: true
                }} =
                 Methods.invoke("fleet.forget_session_owner", %{
                   "machine" => machine,
                   "accept_state_loss" => true
                 })

        assert forgotten_node == Atom.to_string(target)

        for plane <- [:interactive, :coding] do
          assert {:ok, owners} = Cluster.session_owners(plane)
          refute MapSet.member?(owners, Atom.to_string(target))
        end

        # Repeating an already-confirmed retirement is safe for automation and still
        # forces a synced checkpoint before success.
        assert {:ok, %{removed: false, roster_revision: 2}} =
                 Methods.invoke("fleet.forget_session_owner", %{
                   "machine" => machine,
                   "accept_state_loss" => true
                 })

        restart_cluster_monitor!()

        assert {:ok, interactive} = Methods.invoke("interactive.list", %{})
        assert is_list(interactive)
        assert {:ok, coding} = Methods.invoke("coding.list", %{})
        assert is_list(coding)
      end)
    end

    @tag timeout: 180_000
    test "session lists query cores without treating connected builders or signers as missing stores" do
      with_env(
        %{
          "OUROBOROS_CLUSTER_STRATEGY" => "none",
          "OUROBOROS_CLUSTER_HOSTS" => nil
        },
        fn ->
          core = start_app_peer!()
          builder = start_app_peer!(node_role: :builder)
          signer = start_signer_peer!()
          on_exit(fn -> clear_session_owner_evidence(:interactive, core) end)

          assert_eventually(
            fn ->
              machines = Cluster.fleet_status().machines

              match?(%{role: :core}, Enum.find(machines, &(&1.node == core))) and
                match?(%{role: :builder}, Enum.find(machines, &(&1.node == builder))) and
                match?(%{role: :signer}, Enum.find(machines, &(&1.node == signer)))
            end,
            300
          )

          assert :erpc.call(builder, Process, :whereis, [Ouroboros.Interactive.Store]) == nil
          assert :erpc.call(signer, Process, :whereis, [Ouroboros.Interactive.Store]) == nil

          id = unique_id("mixed-role-core-session")
          create_remote_interactive_session!(core, id)

          assert {:ok, sessions} = Methods.invoke("interactive.list", %{})
          assert Enum.any?(sessions, &(&1.id == id and &1.node == core))
        end
      )
    end

    @tag timeout: 180_000
    test "a successful remote start records its owner before the first fleet list" do
      with_env(
        %{
          "OUROBOROS_CLUSTER_STRATEGY" => "none",
          "OUROBOROS_CLUSTER_HOSTS" => nil
        },
        fn ->
          core = start_app_peer!()
          on_exit(fn -> clear_session_owner_evidence(:interactive, core) end)

          previous_providers = Application.get_env(:jido_harness, :providers)
          previous_config = Application.get_env(:jido_harness, :provider_config)

          providers =
            previous_providers
            |> then(&Map.new(&1 || %{}))
            |> Map.put(:ouroboros_test, Ouroboros.Test.HarnessAdapter)

          config =
            previous_config
            |> then(&Map.new(&1 || %{}))
            |> Map.put(:ouroboros_test, %{test_pid: self()})

          Application.put_env(:jido_harness, :providers, providers)
          Application.put_env(:jido_harness, :provider_config, config)

          # No turn is sent, so this creates a durable ready session without leaving a
          # provider stream running — exactly the start-before-first-list boundary.
          :ok = :erpc.call(core, Application, :put_env, [:jido_harness, :providers, providers])

          :ok =
            :erpc.call(core, Application, :put_env, [
              :jido_harness,
              :provider_config,
              Map.put(config, :ouroboros_test, %{})
            ])

          on_exit(fn ->
            if previous_providers,
              do: Application.put_env(:jido_harness, :providers, previous_providers),
              else: Application.delete_env(:jido_harness, :providers)

            if previous_config,
              do: Application.put_env(:jido_harness, :provider_config, previous_config),
              else: Application.delete_env(:jido_harness, :provider_config)
          end)

          assert_eventually(
            fn ->
              match?(
                %{state: :connected, role: :core, compatibility: :compatible},
                Enum.find(Cluster.fleet_status().machines, &(&1.node == core))
              )
            end,
            300
          )

          id = unique_id("remote-created-before-list")

          assert {:ok, %Ouroboros.Interactive.Ref{id: ^id, node: ^core}} =
                   Methods.invoke("interactive.start", %{
                     "id" => id,
                     "provider" => "ouroboros_test",
                     "workspace" => File.cwd!(),
                     "node" => Atom.to_string(core)
                   })

          assert {:ok, owners} = Cluster.session_owners(:interactive)
          assert MapSet.member?(owners, Atom.to_string(core))

          true = :rpc.cast(core, System, :stop, [])
          assert_eventually(fn -> core not in Node.list() end, 300)

          assert {:error, -32_004, _message,
                  %{"reason" => "owner_query_incomplete", "node" => owner}} =
                   Methods.invoke("interactive.list", %{})

          assert owner == Atom.to_string(core)
        end
      )
    end

    @tag timeout: 180_000
    test "a pre-dispatch owner fence survives a lost remote reply and monitor restart" do
      fleet_id = "abcdefabcdefabcdefabcdef"

      with_env(
        %{
          "OUROBOROS_CLUSTER_STRATEGY" => "none",
          "OUROBOROS_CLUSTER_HOSTS" => nil,
          "OUROBOROS_FLEET_ID" => fleet_id
        },
        fn ->
          data_dir = tmp_dir!()
          fleet_dir = Path.join(data_dir, "fleet")
          File.mkdir_p!(fleet_dir)

          write_test_fleet_profile!(fleet_dir, fleet_id)

          previous_data_dir = Application.get_env(:ouroboros, :data_dir)
          Application.put_env(:ouroboros, :data_dir, data_dir)

          on_exit(fn ->
            if previous_data_dir,
              do: Application.put_env(:ouroboros, :data_dir, previous_data_dir),
              else: Application.delete_env(:ouroboros, :data_dir)
          end)

          core = start_app_peer!()
          on_exit(fn -> clear_session_owner_evidence(:interactive, core) end)

          assert_eventually(
            fn ->
              match?(
                %{state: :connected, role: :core, compatibility: :compatible},
                Enum.find(Cluster.fleet_status().machines, &(&1.node == core))
              )
            end,
            300
          )

          # Hold the remote store before its create reply. The gateway request is now
          # outcome-unknown if distribution is lost, so the possible-owner fence must
          # already be durable before this call can reach the remote node.
          assert :ok =
                   :erpc.call(core, :sys, :suspend, [Ouroboros.Interactive.Store])

          id = unique_id("lost-remote-start-reply")

          start =
            Task.async(fn ->
              Methods.invoke("interactive.start", %{
                "id" => id,
                "provider" => "native",
                "workspace" => File.cwd!(),
                "node" => Atom.to_string(core)
              })
            end)

          assert_eventually(
            fn ->
              case Cluster.session_owners(:interactive) do
                {:ok, owners} -> MapSet.member?(owners, Atom.to_string(core))
                _unavailable -> false
              end
            end,
            300
          )

          true = :rpc.cast(core, System, :stop, [])
          assert_eventually(fn -> core not in Node.list() end, 300)
          lost_reply = Task.await(start, 10_000)
          assert is_tuple(lost_reply) and elem(lost_reply, 0) == :error

          previous_monitor = Process.whereis(Ouroboros.Cluster.Monitor)
          Process.exit(previous_monitor, :kill)

          assert_eventually(
            fn ->
              case Process.whereis(Ouroboros.Cluster.Monitor) do
                monitor when is_pid(monitor) -> monitor != previous_monitor
                _absent -> false
              end
            end,
            300
          )

          assert {:ok, recovered} = Cluster.session_owners(:interactive)
          assert MapSet.member?(recovered, Atom.to_string(core))

          assert {:error, -32_004, _message,
                  %{"reason" => "owner_query_incomplete", "node" => owner}} =
                   Methods.invoke("interactive.list", %{})

          assert owner == Atom.to_string(core)
        end
      )
    end

    @tag timeout: 180_000
    test "a listed non-expected session owner cannot disappear behind a local-only list" do
      fleet_id = "00112233445566778899aabb"

      with_env(
        %{
          "OUROBOROS_CLUSTER_STRATEGY" => "none",
          "OUROBOROS_CLUSTER_HOSTS" => nil,
          "OUROBOROS_FLEET_ID" => fleet_id
        },
        fn ->
          data_dir = tmp_dir!()
          fleet_dir = Path.join(data_dir, "fleet")
          File.mkdir_p!(fleet_dir)

          write_test_fleet_profile!(fleet_dir, fleet_id)

          previous_data_dir = Application.get_env(:ouroboros, :data_dir)
          Application.put_env(:ouroboros, :data_dir, data_dir)

          on_exit(fn ->
            if previous_data_dir,
              do: Application.put_env(:ouroboros, :data_dir, previous_data_dir),
              else: Application.delete_env(:ouroboros, :data_dir)
          end)

          core = start_app_peer!()
          on_exit(fn -> clear_session_owner_evidence(:interactive, core) end)

          assert_eventually(
            fn ->
              match?(
                %{expected?: false, state: :connected, role: :core},
                Enum.find(Cluster.fleet_status().machines, &(&1.node == core))
              )
            end,
            300
          )

          id = unique_id("learned-owner-session")
          create_remote_interactive_session!(core, id)

          assert {:ok, sessions} = Methods.invoke("interactive.list", %{})
          assert Enum.any?(sessions, &(&1.id == id and &1.node == core))
          assert {:ok, interactive_owners} = Cluster.session_owners(:interactive)
          assert MapSet.member?(interactive_owners, Atom.to_string(core))
          assert {:ok, coding_owners} = Cluster.session_owners(:coding)
          refute MapSet.member?(coding_owners, Atom.to_string(core))

          # The monitor is deliberately at the tail of the supervision tree and can
          # restart independently. Its positive owner evidence must come back from the
          # synced checkpoint before another successful list can erase remote rows.
          previous_monitor = Process.whereis(Ouroboros.Cluster.Monitor)
          Process.exit(previous_monitor, :kill)

          assert_eventually(
            fn ->
              case Process.whereis(Ouroboros.Cluster.Monitor) do
                monitor when is_pid(monitor) -> monitor != previous_monitor
                _absent -> false
              end
            end,
            300
          )

          assert {:ok, recovered_owners} = Cluster.session_owners(:interactive)
          assert MapSet.member?(recovered_owners, Atom.to_string(core))

          true = :rpc.cast(core, System, :stop, [])
          assert_eventually(fn -> core not in Node.list() end, 300)

          assert_eventually(
            fn ->
              match?(
                %{expected?: false, state: :offline},
                Enum.find(Cluster.fleet_status().machines, &(&1.node == core))
              )
            end,
            300
          )

          assert {:error, -32_004, _message,
                  %{"reason" => "owner_query_incomplete", "node" => owner}} =
                   Methods.invoke("interactive.list", %{})

          assert owner == Atom.to_string(core)
        end
      )
    end

    @tag timeout: 180_000
    test "positive session evidence survives version skew and protects the next list" do
      with_env(
        %{
          "OUROBOROS_CLUSTER_STRATEGY" => "none",
          "OUROBOROS_CLUSTER_HOSTS" => nil
        },
        fn ->
          core = start_app_peer!()
          on_exit(fn -> clear_session_owner_evidence(:interactive, core) end)

          assert_eventually(
            fn ->
              match?(
                %{expected?: false, state: :connected, compatibility: :compatible},
                Enum.find(Cluster.fleet_status().machines, &(&1.node == core))
              )
            end,
            300
          )

          id = unique_id("skewed-owner-session")
          create_remote_interactive_session!(core, id)

          assert {:ok, sessions} = Methods.invoke("interactive.list", %{})
          assert Enum.any?(sessions, &(&1.id == id and &1.node == core))
          assert {:ok, owners} = Cluster.session_owners(:interactive)
          assert MapSet.member?(owners, Atom.to_string(core))

          revision =
            Cluster.fleet_status().machines
            |> Enum.find(&(&1.node == core))
            |> get_in([:runtime, :fleet_protocol_revision])

          :sys.replace_state(Ouroboros.Cluster.Monitor, fn state ->
            put_in(
              state,
              [:machines, core, :runtime, :fleet_protocol_revision],
              revision + 1
            )
          end)

          assert Enum.find(Cluster.fleet_status().machines, &(&1.node == core)).compatibility ==
                   :incompatible

          true = :rpc.cast(core, System, :stop, [])
          assert_eventually(fn -> core not in Node.list() end, 300)

          assert_eventually(
            fn ->
              match?(
                %{expected?: false, state: :offline, compatibility: :incompatible},
                Enum.find(Cluster.fleet_status().machines, &(&1.node == core))
              )
            end,
            300
          )

          assert {:error, -32_004, _message,
                  %{"reason" => "owner_query_incomplete", "node" => owner}} =
                   Methods.invoke("interactive.list", %{})

          assert owner == Atom.to_string(core)
        end
      )
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
            Ouroboros.Agent.EffectLedger,
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

      # Asking for distribution without naming the node is the mistake this refuses; the
      # bare environment is a different posture entirely and is covered below.
      assert {output, 1} = run_script(script, %{"OUROBOROS_DIST" => "name"})
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

      assert output =~ "OUROBOROS_COOKIE_FILE"
      assert output =~ "legacy OUROBOROS_COOKIE"

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

    test "env.sh starts a told-nothing release without distribution at all" do
      script = Path.join(tmp_dir!(), "env.sh")

      probe = """

      echo "NODE=$RELEASE_NODE"
      echo "COOKIE=$RELEASE_COOKIE"
      echo "DIST=$RELEASE_DISTRIBUTION"
      """

      File.write!(script, render_template("rel/env.sh.eex", %{}) <> probe)

      # No name, no strategy, no OUROBOROS_DIST: the single-machine daemon. It has no node
      # name or distribution listener. The release launcher still gets a fresh disposable
      # boot cookie so it never falls back to the artifact's shared releases/COOKIE.
      assert {output, 0} = run_script(script, %{})
      assert output =~ "DIST=none"
      assert output =~ "NODE=\n"
      assert output =~ ~r/COOKIE=ouro_boot_[a-f0-9]{64}\n/

      # A cluster strategy is a request for distribution, so it takes the strict path and
      # is refused for the name it was not given rather than defaulted into a node that
      # can never join anything.
      assert {output, 1} = run_script(script, %{"OUROBOROS_CLUSTER_STRATEGY" => "epmd"})
      assert output =~ "OUROBOROS_NODE must be set"

      # The refusal is a signpost: the posture that needs no variables is named in it.
      assert output =~ "single-machine"
      assert output =~ "ouro"

      # An explicit OUROBOROS_DIST=none with a strategy is still the contradiction it was;
      # the new default changes nothing an operator typed.
      assert {output, 1} =
               run_script(script, %{
                 "OUROBOROS_DIST" => "none",
                 "OUROBOROS_CLUSTER_STRATEGY" => "epmd"
               })

      assert output =~ "OUROBOROS_DIST=none disables distribution"

      # And an explicit OUROBOROS_DIST=none on its own is exactly what the default now is.
      assert {output, 0} = run_script(script, %{"OUROBOROS_DIST" => "none"})
      assert output =~ "DIST=none"

      # Naming the node is enough to take the strict path with OUROBOROS_DIST unset.
      assert {output, 1} = run_script(script, %{"OUROBOROS_NODE" => "core-1@10.0.0.11"})
      assert output =~ "OUROBOROS_COOKIE_FILE"
      assert output =~ "legacy OUROBOROS_COOKIE"
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
        "OUROBOROS_COOKIE_FILE",
        "OUROBOROS_FORGE_BUILDER_NODE",
        "OUROBOROS_UPGRADE_TRUSTED_SIGNERS"
      ]

      Enum.each(managed, &System.delete_env/1)
      System.put_env("OUROBOROS_DATA_DIR", data_dir)
      Ouroboros.DataDir.ensure_private!(data_dir)

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

    test "a fleet cookie file is private and replaces the release's decoy before boot" do
      ensure_distributed!()
      previous_cookie = :erlang.get_cookie()
      on_exit(fn -> Node.set_cookie(previous_cookie) end)

      cookie_file = Path.join(System.fetch_env!("OUROBOROS_DATA_DIR"), "fleet-cookie")
      cookie = String.duplicate("a", 64)
      File.mkdir_p!(Path.dirname(cookie_file))
      File.write!(cookie_file, cookie, [:binary, :sync])
      File.chmod!(cookie_file, 0o600)
      System.put_env("OUROBOROS_COOKIE_FILE", cookie_file)

      assert prod_config()[:ouroboros][:node_role] == :core
      assert :erlang.get_cookie() == String.to_existing_atom(cookie)

      File.chmod!(cookie_file, 0o644)

      assert_raise RuntimeError, ~r/OUROBOROS_COOKIE_FILE must have mode 0600/, fn ->
        prod_config()
      end
    end
  end

  defp prod_config, do: Config.Reader.read!("config/runtime.exs", env: :prod, target: :host)

  defp render_template(path, env) do
    with_env(env, fn ->
      EEx.eval_file(path, assigns: [release: %{name: :ouroboros}])
    end)
  end

  defp run_script(path, env) do
    # Every variable the script reads is cleared first, so a host that exports one of them
    # cannot make a test pass or fail for a reason the test never named.
    merged =
      Map.merge(
        %{
          "OUROBOROS_NODE" => nil,
          "OUROBOROS_COOKIE" => nil,
          "OUROBOROS_COOKIE_FILE" => nil,
          "OUROBOROS_DIST" => nil,
          "OUROBOROS_CLUSTER_STRATEGY" => nil,
          "RELEASE_COMMAND" => "start"
        },
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

  defp write_test_fleet_profile!(fleet_dir, fleet_id, opts \\ []) do
    local = Keyword.get(opts, :local, test_fleet_member("owner", "127.0.0.1"))
    members = Keyword.get(opts, :members, [local])
    tombstones = Keyword.get(opts, :tombstones, [])

    profile = %{
      "schema" => 1,
      "fleet_id" => fleet_id,
      "name" => "Cluster test fleet",
      "machine" => local["machine"],
      "host" => local["host"],
      "node" => local["node"],
      "role" => "core",
      "members" => members,
      "roster_revision" => Keyword.get(opts, :roster_revision, 1),
      "tombstones" => tombstones,
      "gateway_port" => 41_789,
      "epmd_port" => 44_369,
      "dist_port_min" => 45_100,
      "dist_port_max" => 45_199
    }

    path = Path.join(fleet_dir, "profile.json")
    File.write!(path, Jason.encode!(profile), [:binary, :sync])
    File.chmod!(path, 0o600)
    path
  end

  defp test_fleet_member(machine, host) do
    %{"machine" => machine, "host" => host, "node" => "ouro-#{machine}@#{host}"}
  end

  # Change only the name on a profile that is otherwise exactly as it was, so a test of the
  # name cannot pass by having accidentally rewritten the roster underneath it.
  defp rewrite_fleet_profile_name!(fleet_dir, name) do
    path = Path.join(fleet_dir, "profile.json")

    profile =
      path
      |> File.read!()
      |> Jason.decode!()
      |> then(fn profile ->
        if is_nil(name), do: Map.delete(profile, "name"), else: Map.put(profile, "name", name)
      end)

    File.write!(path, Jason.encode!(profile), [:binary, :sync])
    File.chmod!(path, 0o600)
    path
  end

  defp restart_cluster_monitor! do
    previous_monitor = Process.whereis(Ouroboros.Cluster.Monitor)
    Process.exit(previous_monitor, :kill)

    assert_eventually(
      fn ->
        case Process.whereis(Ouroboros.Cluster.Monitor) do
          monitor when is_pid(monitor) -> monitor != previous_monitor
          _absent -> false
        end
      end,
      300
    )
  end

  defp reset_session_owner_evidence! do
    :sys.replace_state(Ouroboros.Cluster.Monitor, fn state ->
      state
      |> Map.put(:session_owners, %{interactive: MapSet.new(), coding: MapSet.new()})
      |> Map.put(:session_owner_evidence, :reliable)
    end)
  end

  defp start_app_peer!(env \\ []) do
    peer_node = start_bare_peer!()

    put_peer_env!(peer_node, :coding_storage, {Jido.Storage.ETS, table: peer_table(peer_node)})

    Enum.each(env, fn {key, value} -> put_peer_env!(peer_node, key, value) end)

    {:ok, _applications} = :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])
    peer_node
  end

  defp create_remote_interactive_session!(peer_node, id) do
    # These tests exercise owner evidence rather than provider inference; Native is
    # available on every Ouroboros peer and its approval channel accepts the default.
    assert {:ok, session} =
             :erpc.call(peer_node, Ouroboros.Interactive.State, :new, [
               id,
               [provider: :native, workspace: File.cwd!(), approval_mode: :default]
             ])

    assert :ok =
             :erpc.call(peer_node, Ouroboros.Interactive.Store, :create, [session])
  end

  defp start_signer_peer! do
    peer_node = start_bare_peer!()
    key_dir = tmp_dir!()
    key_path = Path.join(key_dir, "signer.seed")
    File.write!(key_path, :crypto.strong_rand_bytes(32), [:binary, :sync])
    File.chmod!(key_path, 0o600)

    put_peer_env!(peer_node, :node_role, :signer)
    put_peer_env!(peer_node, :signer_id, "cluster-test-signer")

    put_peer_env!(
      peer_node,
      :signing_journal_storage,
      {Jido.Storage.ETS, table: peer_table(peer_node)}
    )

    :ok =
      :erpc.call(peer_node, System, :put_env, [
        %{"OUROBOROS_SIGNER_KEY_PATH" => key_path}
      ])

    {:ok, _applications} =
      :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])

    peer_node
  end

  defp clear_session_owner_evidence(plane, target) do
    case Process.whereis(Ouroboros.Cluster.Monitor) do
      monitor when is_pid(monitor) ->
        :sys.replace_state(monitor, fn state ->
          owners =
            state
            |> Map.get(:session_owners, %{})
            |> Map.update(plane, MapSet.new(), &MapSet.delete(&1, Atom.to_string(target)))

          Map.put(state, :session_owners, owners)
        end)

      _absent ->
        :ok
    end
  catch
    :exit, _reason -> :ok
  end

  defp replace_peer_version!(peer_node, version) do
    spec = :erpc.call(peer_node, Application, :spec, [:ouroboros])
    :ok = :erpc.call(peer_node, Application, :stop, [:ouroboros])
    :ok = :erpc.call(peer_node, Application, :unload, [:ouroboros])

    changed = Keyword.put(spec, :vsn, String.to_charlist(version))

    :ok =
      :erpc.call(peer_node, :application, :load, [{:application, :ouroboros, changed}])

    # Unloading an application drops runtime overrides that are not part of its .app
    # spec. Restore the peer-local test store before the least-privilege tree boots.
    put_peer_env!(
      peer_node,
      :coding_storage,
      {Jido.Storage.ETS, table: peer_table(peer_node)}
    )

    {:ok, _applications} =
      :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])

    assert :erpc.call(peer_node, Application, :spec, [:ouroboros, :vsn]) ==
             String.to_charlist(version)
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
