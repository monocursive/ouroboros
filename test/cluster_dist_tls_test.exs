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
  `inet_tls_dist` will. It touches no data directory and starts no node.
  """
  use ExUnit.Case, async: true

  @fixtures Path.expand("support/fleet_tls", __DIR__)
  @timeout 5_000

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
