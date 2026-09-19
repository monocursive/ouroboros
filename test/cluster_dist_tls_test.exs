defmodule Ouroboros.ClusterDistTlsTest do
  @moduledoc """
  What the generated `ssl_dist.conf` actually refuses.

  `ouro fleet create` writes one mutual-TLS policy and `fleet::validate_materials` pins it
  byte-for-byte, so nothing can weaken an installed file. Nothing pinned the *meaning* of
  the string itself: the one assertion that ever proved "a certificate this fleet's CA did
  not sign is refused" lived in the revocation callback's own test and went with the
  module. A drift test that compares the generator's output to itself would not notice
  `verify_peer` disappearing from one half.

  So this consults two generated policies from two independent fleets — the committed
  fixtures under `test/support/fleet_tls/`, produced by `ouro fleet create` and described
  by the README beside them — and drives `:ssl` with them directly, the way
  `inet_tls_dist` will. It touches no data directory.

  The last describe block goes one step further and runs the real thing: two OS nodes
  that form a mesh over `-proto_dist inet_tls` with `-start_epmd false` and
  `Ouroboros.Cluster.Epmd` as their `-epmd_module`, so the policy above and the port
  answers in that module are proved together, against no port mapper at all.
  """
  use ExUnit.Case, async: true

  alias Ouroboros.Cluster.Epmd

  @fixtures Path.expand("support/fleet_tls", __DIR__)
  @timeout 5_000

  # The fleet's production port spaces. A test that binds inside one of them can collide
  # with a real runtime on this machine, or with the fleet suites, so an ephemeral port
  # that lands in one is drawn again.
  @reserved [13_700..13_729, 14_000..14_999, 47_000..47_999]

  setup_all do
    {:ok, _} = Application.ensure_all_started(:ssl)
    :ok
  end

  describe "the generated mutual-TLS policy" do
    test "is what create writes, and it asks for a verified peer on both halves" do
      %{server: server, client: client} = policy("fleet_a")

      for {half, options} <- [server: server, client: client] do
        assert Keyword.get(options, :verify) == :verify_peer, "#{half} does not verify its peer"
        assert Keyword.get(options, :secure_renegotiate) == true
        assert Keyword.get(options, :reuse_sessions) == false
        assert Keyword.get(options, :session_tickets) == :disabled
        assert Keyword.has_key?(options, :cacertfile)
        assert Keyword.has_key?(options, :certfile)
        assert Keyword.has_key?(options, :keyfile)
      end

      assert Keyword.get(server, :fail_if_no_peer_cert) == true
      refute Keyword.has_key?(client, :fail_if_no_peer_cert)
    end

    test "accepts a peer its own fleet CA signed" do
      a = policy("fleet_a")
      assert {client, server} = handshake(a.server, a.client)
      assert {:ok, _socket} = client
      assert {:ok, _socket} = server
    end

    test "the server refuses a certificate its fleet CA did not sign" do
      a = policy("fleet_a")
      b = policy("fleet_b")
      foreign = Keyword.put(b.client, :verify, :verify_none)

      # As generated, the server also advertises which CA it trusts, so a foreign client
      # never even offers its certificate. That is a refusal, but it is not the one under
      # test, so drop the hint and make the client present the certificate: what is being
      # proved is that trusting it is refused, not that offering it is discouraged.
      offered =
        handshake(Keyword.put(a.server, :certificate_authorities, false), foreign)

      assert {client, server} = offered
      assert {:error, {:tls_alert, {:unknown_ca, _}}} = server
      # Under TLS 1.3 the client finishes before the server's verdict travels, so the
      # refusal reaches it on its first read rather than at connect. Either way there is
      # no usable session.
      case client do
        {:ok, socket} -> assert {:error, _} = :ssl.recv(socket, 0, @timeout)
        {:error, _} -> :ok
      end

      # And with the policy exactly as `ouro fleet create` writes it, the same peer is
      # still refused — one step earlier.
      assert {_client, refused} = handshake(a.server, foreign)
      assert {:error, {:tls_alert, {alert, _}}} = refused
      assert alert in [:unknown_ca, :certificate_required]
    end

    test "the client refuses a certificate its fleet CA did not sign" do
      a = policy("fleet_a")
      b = policy("fleet_b")

      foreign =
        b.server
        |> Keyword.put(:verify, :verify_none)
        |> Keyword.delete(:fail_if_no_peer_cert)

      assert {client, _server} = handshake(foreign, a.client)
      assert {:error, {:tls_alert, {:unknown_ca, _}}} = client
    end

    test "the server refuses a peer that offers no certificate at all" do
      a = policy("fleet_a")

      anonymous =
        a.client
        |> Keyword.put(:verify, :verify_none)
        |> Keyword.delete(:certfile)
        |> Keyword.delete(:keyfile)

      assert {_client, server} = handshake(a.server, anonymous)
      assert {:error, {:tls_alert, {alert, _}}} = server
      assert alert in [:certificate_required, :handshake_failure]
    end
  end

  describe "two nodes, no port mapper" do
    @tag timeout: 120_000
    test "form a TLS mesh in both directions through Ouroboros.Cluster.Epmd" do
      optfile = optfile!("fleet_a")
      cookie = :"ouroboros_dist_tls_#{System.unique_integer([:positive])}"

      # Distinct listeners, drawn from the ephemeral range and screened against the
      # fleet's production port spaces. Nothing here is a fixed number.
      [port_a, port_b] = ephemeral_loopback_ports!(2)

      suffix = System.unique_integer([:positive])
      name_a = "ouro-k2a-#{suffix}"
      name_b = "ouro-k2b-#{suffix}"

      # Both leaves are `fleet_a`'s, whose subject alternative name is 127.0.0.1 — the
      # host both nodes advertise — so each side verifies the other against the one CA
      # this fleet has, which is the whole of §1's "one fleet is one shared bundle".
      node_a = :"#{name_a}@127.0.0.1"
      node_b = :"#{name_b}@127.0.0.1"

      # One map, given to both, naming every member including self. It is keyed by whole
      # node name here because both nodes are on one host; a fleet with one member per
      # host writes `host=port` and reads the same way.
      ports = "#{node_a}=#{port_a},#{node_b}=#{port_b}"

      a = start_epmdless_peer!(optfile)
      b = start_epmdless_peer!(optfile)

      distribute!(a, node_a, port_a, ports, cookie)
      distribute!(b, node_b, port_b, ports, cookie)

      # Neither node can have learned the other from a registry, because neither consults
      # one: `erl_epmd` is not their port mapper and they were told not to start a daemon.
      for peer <- [a, b] do
        assert :peer.call(peer, :net_kernel, :epmd_module, []) == Epmd
        refute :peer.call(peer, :net_kernel, :epmd_module, []) == :erl_epmd
        assert :peer.call(peer, :init, :get_argument, [:proto_dist]) == {:ok, [[~c"inet_tls"]]}
        assert :peer.call(peer, :init, :get_argument, [:start_epmd]) == {:ok, [[~c"false"]]}
      end

      # And nothing answers for either of them on 4369. This machine may well be running
      # a port mapper — other suites in this build start named peers, which start one —
      # so the assertion is that neither of these two names is in it, asked both from
      # here and from inside each node.
      for answer <- [
            :erl_epmd.names(~c"127.0.0.1"),
            :peer.call(a, :erl_epmd, :names, [~c"127.0.0.1"]),
            :peer.call(b, :erl_epmd, :names, [~c"127.0.0.1"])
          ] do
        registrations = epmd_registrations(answer)
        refute name_a in registrations
        refute name_b in registrations
      end

      # A dials B. The only thing that can tell it B's port is `port_please/3` reading
      # the map above.
      assert :peer.call(a, Node, :connect, [node_b], @timeout * 4) == true
      assert_eventually(fn -> [node_b] == :peer.call(a, Node, :list, []) end)
      assert_eventually(fn -> [node_a] == :peer.call(b, Node, :list, []) end)
      assert dialled_address(a, node_b) == {{127, 0, 0, 1}, port_b}

      # The reverse direction is a separate proof, not the same connection read twice:
      # drop it and let B be the one that dials.
      assert :peer.call(a, :erlang, :disconnect_node, [node_b]) == true
      assert_eventually(fn -> [] == :peer.call(a, Node, :list, []) end)
      assert_eventually(fn -> [] == :peer.call(b, Node, :list, []) end)

      assert :peer.call(b, Node, :connect, [node_a], @timeout * 4) == true
      assert_eventually(fn -> [node_a] == :peer.call(b, Node, :list, []) end)
      assert_eventually(fn -> [node_b] == :peer.call(a, Node, :list, []) end)
      assert dialled_address(b, node_a) == {{127, 0, 0, 1}, port_a}

      # The mesh is a real one: each side can run code on the other.
      assert :peer.call(a, :erpc, :call, [node_b, :erlang, :node, []], @timeout * 2) == node_b
      assert :peer.call(b, :erpc, :call, [node_a, :erlang, :node, []], @timeout * 2) == node_a

      # And it is the encrypted transport, as each side records the other: `:tls` is what
      # `inet_tls_dist` writes into the address it hands `net_kernel`, and cleartext
      # `inet_tcp_dist` writes `:tcp` there instead.
      for {peer, other} <- [{a, node_b}, {b, node_a}] do
        assert {:net_address, _address, ~c"127.0.0.1", :tls, :inet} =
                 peer |> :peer.call(:net_kernel, :node_info, [other, :address]) |> unwrap_info()

        assert :peer.call(peer, :erlang, :system_info, [:dist_ctrl]) != []
      end
    end

    test "a node given no ports at all cannot dial, and says so rather than guessing" do
      # The same module, the same absence of a registry: with neither variable set there
      # is no answer to invent, which is what keeps a misconfigured member from silently
      # dialing something else's listener.
      assert Epmd.port_please(~c"ouro-k2a", {127, 0, 0, 1}) == :noport
    end
  end

  # A peer with no distribution, no port mapper, and no idea this VM exists: its control
  # channel is a pipe. Distribution is started inside it afterwards, by `distribute!/5`,
  # once its environment names the ports this fleet uses.
  defp start_epmdless_peer!(optfile) do
    args =
      code_path_args() ++
        [
          ~c"-start_epmd",
          ~c"false",
          ~c"-epmd_module",
          ~c"Elixir.Ouroboros.Cluster.Epmd",
          ~c"-proto_dist",
          ~c"inet_tls",
          ~c"-ssl_dist_optfile",
          String.to_charlist(optfile),
          ~c"-kernel",
          ~c"inet_dist_use_interface",
          ~c"{127,0,0,1}"
        ]

    {:ok, peer, :nonode@nohost} =
      :peer.start(%{connection: :standard_io, args: args, wait_boot: 60_000})

    on_exit(fn -> stop_peer(peer) end)

    {:ok, _elixir} = :peer.call(peer, :application, :ensure_all_started, [:elixir], 60_000)
    {:ok, _ssl} = :peer.call(peer, :application, :ensure_all_started, [:ssl], 60_000)
    peer
  end

  # The launcher's half of §3, as two environment variables, and then distribution. The
  # order matters: `listen_port_please/2` is asked for this node's port while
  # `net_kernel` starts, so the environment has to be in place first.
  defp distribute!(peer, name, port, ports, cookie) do
    :ok =
      :peer.call(peer, System, :put_env, [
        %{
          "OUROBOROS_DIST_PORT" => Integer.to_string(port),
          "OUROBOROS_DIST_PORTS" => ports
        }
      ])

    {:ok, _kernel} = :peer.call(peer, :net_kernel, :start, [[name, :longnames]], 60_000)
    ^name = :peer.call(peer, :erlang, :node, [])
    true = :peer.call(peer, :erlang, :set_cookie, [cookie])

    # The listener is on the port this node was told to take, which is `listen_port_please`
    # answering rather than the kernel picking an ephemeral one.
    assert {:ok, _socket} =
             :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 5_000)

    :ok
  end

  # `net_kernel:node_info/2` answers with a `#net_address{}`, whose first field is
  # `{IP, Port}` — the address this node actually dialed, which is the one fact that
  # distinguishes "the map was read" from "something else found the peer".
  defp dialled_address(peer, other) do
    peer
    |> :peer.call(:net_kernel, :node_info, [other, :address])
    |> unwrap_info()
    |> elem(1)
  end

  defp unwrap_info({:ok, value}), do: value
  defp unwrap_info(value), do: value

  defp ephemeral_loopback_ports!(count) do
    Enum.reduce(1..count, [], fn _index, taken ->
      [ephemeral_loopback_port!(taken, 50) | taken]
    end)
  end

  defp ephemeral_loopback_port!(_taken, 0),
    do: flunk("no ephemeral loopback port outside the fleet's production ranges")

  defp ephemeral_loopback_port!(taken, attempts) do
    {:ok, socket} = :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false])
    {:ok, {_address, port}} = :inet.sockname(socket)
    :ok = :gen_tcp.close(socket)

    if port in taken or Enum.any?(@reserved, &(port in &1)) do
      ephemeral_loopback_port!(taken, attempts - 1)
    else
      port
    end
  end

  # `ssl_dist.conf` as the BEAM will read it, written where a peer can open it.
  defp optfile!(fleet) do
    contents =
      @fixtures
      |> Path.join("ssl_dist.conf.template")
      |> File.read!()
      |> String.replace("@FLEET_DIR@", Path.join(@fixtures, fleet))

    path =
      Path.join(
        System.tmp_dir!(),
        "ouro-dist-#{fleet}-#{System.unique_integer([:positive])}.conf"
      )

    File.write!(path, contents)
    on_exit(fn -> File.rm(path) end)
    path
  end

  # Every node name a real EPMD daemon on this host hands out, from an `:erl_epmd.names/1`
  # answer asked here or inside a peer. No daemon at all is the empty list: this is a
  # question about what is registered, and "nothing is" is the same answer either way.
  defp epmd_registrations({:ok, names}),
    do: Enum.map(names, fn {name, _port} -> List.to_string(name) end)

  defp epmd_registrations(_no_daemon), do: []

  defp code_path_args, do: Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

  # A peer whose VM is already gone is not a failure of the test that used it.
  defp stop_peer(peer) do
    :peer.stop(peer)
  catch
    _kind, _reason -> :ok
  end

  defp assert_eventually(fun, attempts \\ 200)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(50)
      assert_eventually(fun, attempts - 1)
    end
  end

  # The policy as the BEAM will read it: the committed template with a fixture directory
  # substituted, consulted by `:file.consult/1` exactly as `-ssl_dist_optfile` is.
  defp policy(fleet) do
    directory = Path.join(@fixtures, fleet)

    contents =
      @fixtures
      |> Path.join("ssl_dist.conf.template")
      |> File.read!()
      |> String.replace("@FLEET_DIR@", directory)

    path =
      Path.join(
        System.tmp_dir!(),
        "ouro-ssl-dist-#{fleet}-#{System.unique_integer([:positive])}.conf"
      )

    File.write!(path, contents)

    try do
      {:ok, [terms]} = :file.consult(String.to_charlist(path))
      %{server: Keyword.fetch!(terms, :server), client: Keyword.fetch!(terms, :client)}
    after
      File.rm(path)
    end
  end

  defp handshake(server_options, client_options) do
    {:ok, listen} =
      :ssl.listen(
        0,
        [:binary, {:ip, {127, 0, 0, 1}}, {:active, false}, {:reuseaddr, true}] ++ server_options
      )

    {:ok, {_address, port}} = :ssl.sockname(listen)
    parent = self()

    accepting =
      spawn(fn ->
        result =
          with {:ok, socket} <- :ssl.transport_accept(listen, @timeout) do
            :ssl.handshake(socket, @timeout)
          end

        send(parent, {:accepted, self(), result})
      end)

    client =
      :ssl.connect(~c"127.0.0.1", port, [:binary, {:active, false}] ++ client_options, @timeout)

    server =
      receive do
        {:accepted, ^accepting, result} -> result
      after
        @timeout * 2 -> flunk("the accepting side never answered")
      end

    :ssl.close(listen)
    {client, server}
  end
end
