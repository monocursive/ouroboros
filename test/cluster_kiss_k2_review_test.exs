defmodule Ouroboros.ClusterKissK2ReviewTest do
  @moduledoc """
  Adversarial review of slice K2 (`docs/proposals/fleet-kiss.md` §2, §3, §4, §12).

  Every test here began as a *finding*: it pinned behaviour the slice had and the contract
  or the module's own documentation said it did not, written to fail the day the behaviour
  was fixed so that the fix had to come here and invert the assertion deliberately. That
  day is this one. Each assertion below now states the fixed behaviour, with the defect it
  replaced named in the comment above it, because a test that only says what is true today
  cannot stop the same mistake being made again.

  Two observations were never defects and are unchanged: a profile whose members carry no
  `dist_port` decodes clean here, and the label derived from a member's node name is its
  host. One finding is only half fixed here — a machine already out of the profile still
  cannot have its evidence retired — because the half that matters is in `ouro fleet
  forget`, which claims retirement with no runtime to ask.
  """
  # `OUROBOROS_DIST_PORT(S)`, `:inet_db` and the `kernel` application environment are all
  # process-global, so this module owns them for its duration.
  use ExUnit.Case, async: false

  alias Ouroboros.Cluster
  alias Ouroboros.Cluster.Epmd

  @variables ["OUROBOROS_DIST_PORT", "OUROBOROS_DIST_PORTS", "OUROBOROS_FLEET_ID"]

  setup do
    previous = Map.new(@variables, &{&1, System.get_env(&1)})
    Enum.each(@variables, &System.delete_env/1)

    on_exit(fn -> restore_environment(previous) end)

    {:ok, cluster_environment: previous}
  end

  defp restore_environment(previous) do
    Enum.each(previous, fn
      {name, nil} -> System.delete_env(name)
      {name, value} -> System.put_env(name, value)
    end)
  end

  describe "FINDING 1 (fixed): the dial path answers a member's port from the host's own text" do
    setup do
      # `kernel epmd_module` is the application-environment half of `-epmd_module`;
      # `net_kernel:epmd_module/0` reads it, and `inet_tcp_dist` reads that. This test VM
      # carries no `-epmd_module` argument, so setting it here is the only spelling.
      previous_module = Application.get_env(:kernel, :epmd_module)
      Application.put_env(:kernel, :epmd_module, Epmd)

      # `inet_tcp_dist:call_epmd_function/3` gates on `erlang:function_exported/3`, which
      # is false for a module that is merely *on the path*, and silently applies
      # `erl_epmd` instead. On a live node that cannot happen: `erl_distribution` starts
      # the epmd module as its first child, and calling `start_link/0` loads it before
      # anything reaches `address_please/3`. These tests call `fam_setup/4` directly,
      # without ever starting distribution, so they have to do that loading themselves —
      # otherwise OTP answers from `erl_epmd`, every port comes from the fallback, and the
      # test passes or fails on whichever earlier test happened to touch the module first.
      {:module, Epmd} = Code.ensure_loaded(Epmd)

      # One static host entry, so `pi.internal` resolves without a network and without a
      # DNS server: the point of the test is which key is looked up, not who answers.
      previous_lookup = :inet_db.res_option(:lookup)
      :ok = :inet_db.set_lookup([:file, :native])
      :ok = :inet_db.add_host({127, 0, 0, 1}, [~c"pi.internal"])

      on_exit(fn ->
        :inet_db.del_host({127, 0, 0, 1})
        :inet_db.set_lookup(previous_lookup)

        if is_nil(previous_module),
          do: Application.delete_env(:kernel, :epmd_module),
          else: Application.put_env(:kernel, :epmd_module, previous_module)
      end)

      :ok
    end

    test "an IP-literal member is answered from the map" do
      # The control, and the case that worked all along. `fleet::runtime_env` writes one
      # `node=port` entry per member; a Tailscale fleet advertises IPv4 addresses, so the
      # host's text and the resolved address are the same string and the key matches
      # whichever end of the dial path looks it up.
      System.put_env("OUROBOROS_DIST_PORT", "13700")
      System.put_env("OUROBOROS_DIST_PORTS", "ouro-a@127.0.0.1=13700,ouro-pi@127.0.0.2=13701")

      assert {13_701, _version} = dialled(:"ouro-pi@127.0.0.2")
    end

    test "a DNS-named member is dialled on its own port" do
      # §2 allows a member's `host` to be "advertised IPv4 **or private DNS name**", and
      # `valid_profile_host?/1` accepts one. `fleet::runtime_env` then writes
      # `ouro-pi@pi.internal=13701`.
      System.put_env("OUROBOROS_DIST_PORT", "13700")
      System.put_env("OUROBOROS_DIST_PORTS", "ouro-a@127.0.0.1=13700,ouro-pi@pi.internal=13701")

      # Read as a hand call, the map answers. It always did.
      assert Epmd.port_please(~c"ouro-pi", ~c"pi.internal") == {:port, 13_701, 5}

      # THE FINDING: driven the way `net_kernel` drives it, it did not.
      # `inet_tcp_dist:fam_setup/4` calls `address_please/3` first and hands
      # `port_please/2` the *address*, so the key built for the lookup was
      # `ouro-pi@127.0.0.1` — in no map anyone writes — `Map.get(ports, "127.0.0.1")`
      # missed too, and the answer was the `OUROBOROS_DIST_PORT` fallback: this node's own
      # listener. Invisible while one fleet shares one port, wrong the moment it does not.
      # The lookup now happens in `address_please/3`, which still holds the host as the
      # profile spelled it, and its four-tuple skips `port_please/2` on this path.
      assert {13_701, _version} = dialled(:"ouro-pi@pi.internal")
    end

    test "a bare host=port entry still answers, as the fallback it is documented to be" do
      # The hand-written spelling §3 described. It is no longer what the launcher writes —
      # one `name@host=port` per member is — but a map that uses it is still read, and for
      # a DNS-named member it now reaches the dial path like any other.
      System.put_env("OUROBOROS_DIST_PORT", "13700")
      System.put_env("OUROBOROS_DIST_PORTS", "127.0.0.1=13700,pi.internal=13701")

      assert Epmd.port_please(~c"ouro-pi", ~c"pi.internal") == {:port, 13_701, 5}
      assert {13_701, _version} = dialled(:"ouro-pi@pi.internal")
    end

    test "a node-name entry wins over a bare host entry, wherever the two sit" do
      # Two nodes on one host is the case a host-keyed map cannot answer, so the node's own
      # name is consulted first. Order in the string must not decide it: the map is built
      # before anything is looked up, and these are two different keys.
      System.put_env("OUROBOROS_DIST_PORT", "13700")

      for map <- [
            "pi.internal=13799,ouro-pi@pi.internal=13701",
            "ouro-pi@pi.internal=13701,pi.internal=13799"
          ] do
        System.put_env("OUROBOROS_DIST_PORTS", map)

        assert {13_701, _version} = dialled(:"ouro-pi@pi.internal")

        # And a node on that host the map does not name reads the host's entry.
        assert {13_799, _version} = dialled(:"ouro-other@pi.internal")
      end
    end

    test "a trailing dot is the DNS root and not part of the key" do
      # A node name may carry a fully qualified host while the map is written from the
      # profile's `host`, which may not — and `valid_profile_host?/1` admits either — so
      # the two fold to one key, and the fold is applied to both sides of the map.
      for {map, dialled} <- [
            {"ouro-pi@pi.internal=13701", ~c"pi.internal."},
            {"ouro-pi@pi.internal.=13701", ~c"pi.internal"},
            {"pi.internal.=13701", ~c"pi.internal"}
          ] do
        System.put_env("OUROBOROS_DIST_PORTS", map)

        assert Epmd.port_please(~c"ouro-pi", dialled) == {:port, 13_701, 5},
               "#{inspect(dialled)} did not fold onto #{inspect(map)}"
      end

      # Only the *key* folds: resolution stays exactly what `:inet` does with the name it
      # was given, because a trailing dot tells a resolver not to append its search
      # domains and dropping it there could answer with a different host. So the dial path
      # needs the qualified spelling to resolve before it can reach the map at all.
      System.put_env("OUROBOROS_DIST_PORTS", "ouro-pi@pi.internal=13701")
      assert catch_exit(dialled(:"ouro-pi@pi.internal.")) == :shutdown

      :ok = :inet_db.add_host({127, 0, 0, 1}, [~c"pi.internal.", ~c"pi.internal"])
      assert {13_701, _version} = dialled(:"ouro-pi@pi.internal.")
    end

    test "with no fallback port the DNS-named member is still dialled from the map" do
      # THE FINDING, at its sharpest: with `OUROBOROS_DIST_PORT` unset there was nothing
      # to fall back to, so the miss was `:noport` and `fam_setup` turned it into a
      # shutdown — a member the map named by its own node name could not be dialled at
      # all. `port_please/2` still answers `:noport` for the address, because an address
      # is not what the map is keyed by; the dial path no longer asks it.
      System.put_env("OUROBOROS_DIST_PORTS", "ouro-pi@pi.internal=13701")

      assert Epmd.port_please(~c"ouro-pi", {127, 0, 0, 1}) == :noport
      assert {13_701, _version} = dialled(:"ouro-pi@pi.internal")
    end

    # `inet_tcp_dist:fam_setup/4` is the function `inet_tls_dist:do_setup/7` calls, so
    # this is the TLS dialer's own resolution step with the TLS handshake left off. It
    # answers `{#net_address{address = {IP, Port}}, ConnectOptions, Version}`.
    defp dialled(node) do
      parse = fn address -> :inet.parse_strict_address(address, :inet) end

      {{:net_address, {_ip, port}, _host, _protocol, _family}, _options, version} =
        :inet_tcp_dist.fam_setup(:inet, node, :longnames, parse)

      {port, version}
    end
  end

  describe "FINDING 2 (fixed): profile schemas that are not 2 and are not schema 1" do
    setup do
      data_dir =
        Path.join(
          System.tmp_dir!(),
          "ouro-k2-review-#{System.unique_integer([:positive])}"
        )

      fleet_dir = Path.join(data_dir, "fleet")
      File.mkdir_p!(fleet_dir)
      previous = Application.get_env(:ouroboros, :data_dir)
      Application.put_env(:ouroboros, :data_dir, data_dir)

      on_exit(fn ->
        if is_nil(previous),
          do: Application.delete_env(:ouroboros, :data_dir),
          else: Application.put_env(:ouroboros, :data_dir, previous)

        File.rm_rf(data_dir)
      end)

      {:ok, fleet_dir: fleet_dir, fleet_id: String.duplicate("a", 24)}
    end

    test "a profile with no schema key gets the sentence", context do
      # §2 and §12 give one sentence for a profile this build cannot read, and
      # `profile_problem/0` is what `fleet.status` and `fleet.doctor` render it from.
      # THE FINDING: a file with no `schema` key — a hand-edited profile, or a truncated
      # write — read as a malformed roster instead, and every operator surface stayed
      # silent about it. A missing schema is now an unspoken schema, which is the same
      # condition with the same repair.
      write_profile!(context, Map.delete(profile(context.fleet_id), "schema"))

      assert Cluster.Monitor.fleet_profile_storage() == {:error, :unsupported_profile_schema}
      assert %{reason: :unsupported_profile_schema} = Cluster.profile_problem()

      # A schema that is not an integer at all is the same answer, not a roster error.
      for invalid <- ["2", 2.0, nil, [2], %{"v" => 2}] do
        write_profile!(context, Map.put(profile(context.fleet_id), "schema", invalid))
        assert Cluster.Monitor.fleet_profile_storage() == {:error, :unsupported_profile_schema}
      end
    end

    test "a schema-1 profile from a different fleet gets the sentence too", context do
      # THE FINDING: the identity-mismatch clause was matched before the schema clause, so
      # the one condition §12 promises a sentence for lost to a condition it does not
      # mention — and a machine moved between fleets while carrying an old profile is
      # exactly the machine that needs the sentence. The schema is now decided first.
      old =
        context.fleet_id
        |> profile()
        |> Map.merge(%{"schema" => 1, "fleet_id" => "b" <> String.duplicate("a", 23)})

      write_profile!(context, old)

      assert Cluster.Monitor.fleet_profile_storage() == {:error, :unsupported_profile_schema}
      assert %{reason: :unsupported_profile_schema} = Cluster.profile_problem()

      # A *schema-2* profile from another fleet is still the mismatch it was: this build
      # can read it, and what is wrong with it is whose it is.
      write_profile!(
        context,
        Map.put(profile(context.fleet_id), "fleet_id", "b" <> String.duplicate("a", 23))
      )

      assert Cluster.Monitor.fleet_profile_storage() ==
               {:error, {:fleet_profile_unreadable, :fleet_profile_identity_mismatch}}

      assert Cluster.profile_problem() == nil
    end

    test "a schema newer than 2 gets a sentence that fits it", context do
      write_profile!(context, Map.put(profile(context.fleet_id), "schema", 3))

      assert Cluster.Monitor.fleet_profile_storage() == {:error, :unsupported_profile_schema}

      assert %{reason: :unsupported_profile_schema, message: message} = Cluster.profile_problem()

      # THE FINDING: §2 words this for the case that happens today — a profile from an
      # older Ouroboros — and the sentence said so literally. The same file, the same
      # repair and the same sentence have to serve a machine left behind by an upgrade,
      # holding a schema this build has not learned yet, so it names the disagreement
      # rather than its direction. §2's second half is kept exactly, because the repair
      # genuinely is the same.
      refute message =~ "older"
      assert message =~ "a different version of Ouroboros than the one running here"
      assert message =~ "run `ouro fleet leave` here and set the fleet up again."
    end

    test "a member with no dist_port is accepted, and nothing here ever reads one", context do
      # Not a defect on its own — `fleet::runtime_env` is what turns `dist_port` into
      # `OUROBOROS_DIST_PORTS` — but it means a profile whose members lost their ports
      # decodes clean here and the runtime only finds out at dial time.
      member = %{"machine" => "pi", "host" => "127.0.0.2", "node" => "ouro-pi@127.0.0.2"}
      local = %{"machine" => "owner", "host" => "127.0.0.1", "node" => "ouro-owner@127.0.0.1"}

      write_profile!(
        context,
        context.fleet_id |> profile() |> Map.put("members", [local, member])
      )

      assert {:ok, _fleet_id, decoded, _opts} = Cluster.Monitor.fleet_profile_storage()
      assert decoded.members == %{"owner" => "ouro-owner@127.0.0.1", "pi" => "ouro-pi@127.0.0.2"}
    end

    defp profile(fleet_id) do
      %{
        "schema" => 2,
        "fleet_id" => fleet_id,
        "name" => "K2 review fleet",
        "machine" => "owner",
        "host" => "127.0.0.1",
        "node" => "ouro-owner@127.0.0.1",
        "role" => "core",
        "dist_port" => 13_700,
        "gateway_port" => 41_789,
        "members" => [
          %{
            "machine" => "owner",
            "host" => "127.0.0.1",
            "node" => "ouro-owner@127.0.0.1",
            "dist_port" => 13_700
          }
        ],
        "tags" => []
      }
    end

    defp write_profile!(context, profile) do
      System.put_env("OUROBOROS_FLEET_ID", context.fleet_id)
      path = Path.join(context.fleet_dir, "profile.json")
      File.write!(path, Jason.encode!(profile), [:binary, :sync])
      File.chmod!(path, 0o600)
      path
    end
  end

  describe "FINDING 3 (half fixed): `forget_session_owner` resolves a machine by three sources" do
    setup %{cluster_environment: cluster_environment} do
      data_dir =
        Path.join(
          System.tmp_dir!(),
          "ouro-k2-forget-#{System.unique_integer([:positive])}"
        )

      fleet_dir = Path.join(data_dir, "fleet")
      File.mkdir_p!(fleet_dir)
      previous = Application.get_env(:ouroboros, :data_dir)
      Application.put_env(:ouroboros, :data_dir, data_dir)
      fleet_id = String.duplicate("c", 24)
      System.put_env("OUROBOROS_FLEET_ID", fleet_id)

      on_exit(fn ->
        if is_nil(previous),
          do: Application.delete_env(:ouroboros, :data_dir),
          else: Application.put_env(:ouroboros, :data_dir, previous)

        # The monitor outlives this test and otherwise retains the fake offline owner,
        # making later session lists fail closed. Restore both storage and fleet identity
        # before reloading the original evidence; the outer environment cleanup runs later.
        restore_environment(cluster_environment)
        restart_monitor!()
        File.rm_rf(data_dir)
      end)

      {:ok, fleet_dir: fleet_dir, fleet_id: fleet_id}
    end

    test "the label derived from a member's node name is its host, never its machine name" do
      # `resolve_session_owner/3`'s third source filters the evidence by
      # `default_machine_label(owner) == machine`. `default_machine_label/1` answers the
      # *host* half of `name@host`, while `machine` is the operator's `--machine` word,
      # and `tui/src/fleet.rs` writes `node` as `ouro-<machine>@<host>`. The two are equal
      # only when a machine is named after its own host, so for every profile `ouro fleet`
      # actually writes, that source resolves nothing.
      assert Cluster.default_machine_label(:"ouro-vps@100.64.0.2") == "100.64.0.2"
      assert Cluster.default_machine_label(:"ouro-vps@vps.example") == "vps.example"
      refute Cluster.default_machine_label(:"ouro-vps@100.64.0.2") == "vps"
    end

    test "a member the profile names is retired whichever case the operator typed", context do
      owner = "ouro-vps@127.0.0.2"
      write_fleet!(context, [local_member(), member("vps", "127.0.0.2")])
      restart_monitor!()
      remember!(owner)

      # THE FINDING: `tui/src/fleet.rs`'s `same_name/2` is `eq_ignore_ascii_case`, and its
      # own unit test asserts `forget_machine(&dir, "VPS")` removes the member `vps`.
      # `main.rs` asks *this* first, with the string the operator typed, so a
      # case-sensitive match here meant `ouro fleet forget VPS` never reached the roster
      # edit — and the sentence the gateway printed was "is not a member of this fleet",
      # about a machine that is one. The two halves now agree.
      #
      # The answer names the member as the *profile* spells it, not as it was typed, so an
      # operator who wrote `VPS` is told which member that was.
      assert {:ok, %{machine: "vps", node: ^owner, removed: true}} =
               Cluster.forget_session_owner("VPS")

      # And the canonical spelling resolves to the same member, which is now already
      # retired: one machine, not two.
      assert {:ok, %{machine: "vps", node: ^owner, removed: false}} =
               Cluster.forget_session_owner("vps")

      assert {:ok, owners} = Cluster.session_owners(:interactive)
      refute MapSet.member?(owners, owner)
    end

    test "a connected owner is refused and nothing durable is written", context do
      # FINDING 4, and the half of it a test can hold. Connectivity was read once, and
      # then a profile read, a validation and a checkpoint write happened before the
      # evidence was actually destroyed — so a partitioned owner that came back inside
      # that window had its sessions made unlistable by a decision taken before it
      # returned. The check is now made again immediately before the write, because the
      # write is irreversible and the last word belongs to the last look.
      #
      # The window itself is microseconds wide and not reproducible from here. What is
      # pinned is the outcome it protects: while the node is connected, the refusal is
      # this one, and the checkpoint on disk is exactly as it was.
      # This node, as a member of its own fleet: the one node a test can be certain is
      # connected without starting a peer, and without depending on whether some earlier
      # module in the run happened to make this VM distributed.
      owner = Atom.to_string(node())
      [_name, host] = String.split(owner, "@", parts: 2)
      self_member = %{"machine" => "k2self", "host" => host, "node" => owner}

      write_self_fleet!(context, self_member)
      restart_monitor!()
      remember!(owner)

      assert Cluster.forget_session_owner("k2self") ==
               {:error, {:session_owner_connected, "k2self", owner}}

      assert {:ok, owners} = Cluster.session_owners(:interactive)
      assert MapSet.member?(owners, owner)

      # And nothing reached the durable directory: a refusal that had already written
      # would be a retirement with an error message on top of it.
      assert Path.wildcard(
               Path.join([context.fleet_dir, "cluster-directory", "checkpoints", "*.term"])
             ) == []
    end

    test "a member already out of the profile still cannot have its evidence retired",
         context do
      # NOT FIXED HERE, and deliberately. This is the state after `ouro fleet forget NAME`
      # was run with the runtime stopped: `main.rs` only calls the gateway when a live
      # publication exists, but it edits the roster and prints "its saved session-owner
      # evidence has been retired" either way. Starting the runtime and asking again
      # cannot repair it — the profile no longer names the machine, a freshly started
      # monitor's directory is seeded from that same profile, and the evidence's own label
      # is the host. The owner is stranded.
      #
      # The repair belongs on the CLI side, which must not claim a retirement it could not
      # ask for. Widening the resolution here instead would mean guessing which node an
      # unknown name meant, and the thing being destroyed is irreversible.
      owner = "ouro-vps@127.0.0.2"
      write_fleet!(context, [local_member()])
      restart_monitor!()
      remember!(owner)

      assert Cluster.forget_session_owner("vps") ==
               {:error, {:unknown_session_owner_machine, "vps"}}

      # And it is still there, on a node no member names.
      assert {:ok, owners} = Cluster.session_owners(:interactive)
      assert MapSet.member?(owners, owner)
    end

    defp local_member, do: member(local_machine_name(), "127.0.0.1")

    defp local_machine_name, do: "k2rev"

    defp member(machine, host),
      do: %{
        "machine" => machine,
        "host" => host,
        "node" => "ouro-#{machine}@#{host}",
        "dist_port" => 13_700
      }

    # A fleet whose only member is this VM, so the owner under test is a node that is
    # connected by definition.
    defp write_self_fleet!(context, local) do
      profile = %{
        "schema" => 2,
        "fleet_id" => context.fleet_id,
        "name" => "K2 review fleet",
        "machine" => local["machine"],
        "host" => local["host"],
        "node" => local["node"],
        "role" => "core",
        "dist_port" => 13_700,
        "gateway_port" => 41_789,
        "members" => [local],
        "tags" => []
      }

      path = Path.join(context.fleet_dir, "profile.json")
      File.write!(path, Jason.encode!(profile), [:binary, :sync])
      File.chmod!(path, 0o600)
      :ok
    end

    defp write_fleet!(context, members) do
      local = local_member()

      profile = %{
        "schema" => 2,
        "fleet_id" => context.fleet_id,
        "name" => "K2 review fleet",
        "machine" => local["machine"],
        "host" => local["host"],
        "node" => local["node"],
        "role" => "core",
        "dist_port" => 13_700,
        "gateway_port" => 41_789,
        "members" => members,
        "tags" => []
      }

      path = Path.join(context.fleet_dir, "profile.json")
      File.write!(path, Jason.encode!(profile), [:binary, :sync])
      File.chmod!(path, 0o600)
      :ok
    end

    # The evidence, put where a fresh monitor would have read it from its checkpoint:
    # `record_session_snapshot/2` is the production writer, and it only records owners
    # this node observed, which is not the fleet shape under test.
    defp remember!(owner) do
      :sys.replace_state(Cluster.Monitor, fn state ->
        state
        |> Map.put(:session_owners, %{interactive: MapSet.new([owner])})
        |> Map.put(:session_owner_evidence, :reliable)
      end)
    end

    defp restart_monitor! do
      :ok = Supervisor.terminate_child(Cluster, Cluster.Monitor)
      {:ok, _monitor} = Supervisor.restart_child(Cluster, Cluster.Monitor)
      :ok
    end
  end
end
