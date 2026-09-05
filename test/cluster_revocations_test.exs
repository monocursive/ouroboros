defmodule Ouroboros.ClusterRevocationsTest do
  use ExUnit.Case, async: false
  alias Ouroboros.Cluster.Revocations

  @fixture Path.expand("support/fleet_revocation", __DIR__)

  setup do
    data = Path.join(System.tmp_dir!(), "ouro-revocations-#{System.unique_integer([:positive])}")
    root = Path.join(data, "fleet")
    File.mkdir_p!(root)
    File.chmod!(data, 0o700)
    File.chmod!(root, 0o700)
    fleet = File.read!(Path.join(@fixture, "fleet-id.txt")) |> String.trim()
    ca = File.read!(Path.join(@fixture, "ca-cert.pem"))
    encoded = File.read!(Path.join(@fixture, "revocation.json"))

    private_write(
      Path.join(root, "profile.json"),
      JSON.encode!(%{fleet_id: fleet, node: "ouro-core@127.0.0.1"})
    )

    private_write(Path.join(root, "ca-cert.pem"), ca)
    start_supervised!({Revocations, data_dir: data, enabled: true})

    on_exit(fn ->
      :persistent_term.erase({Revocations, :policy})
      :persistent_term.erase({Revocations, :connections})
      File.rm_rf!(data)
    end)

    %{data: data, root: root, fleet: fleet, ca: ca, encoded: encoded}
  end

  test "accepts Rust-issued attestations, refuses tampering and cross-fleet replay", ctx do
    assert {:ok, "ouro-revoked@127.0.0.1"} = Revocations.validate(ctx.encoded, ctx.fleet, ctx.ca)
    artifact = JSON.decode!(ctx.encoded)

    bad =
      JSON.encode!(
        Map.update!(artifact, "payload", &String.replace(&1, "ouro-revoked", "ouro-core"))
      )

    assert {:error, _} = Revocations.validate(bad, ctx.fleet, ctx.ca)
    assert {:error, _} = Revocations.validate(ctx.encoded, "other-fleet", ctx.ca)
    assert {:error, _} = Revocations.validate(String.duplicate("x", 16_385), ctx.fleet, ctx.ca)
  end

  test "invalid input does not crash the authority or drop authenticated peers", ctx do
    peer = sleeper()

    assert :ok =
             GenServer.call(Revocations, {:connection, ctx.root, "ouro-other@127.0.0.1", peer})

    authority = Process.whereis(Revocations)
    assert {:error, _} = Revocations.install("{}")
    assert Process.whereis(Revocations) == authority
    assert Process.alive?(peer)
  end

  test "a follower with no current issuance roster cannot claim fleet-wide completion", ctx do
    assert {:ok, result} = Revocations.distribute(ctx.encoded)
    refute result.complete
    assert result.pending == ["ouro-core@127.0.0.1"]
    assert result.reason == :issuer_unavailable
    assert {:ok, [_]} = Revocations.snapshot()
  end

  test "revocation kills the certificate holder before a BEAM name is registered", ctx do
    revoked = sleeper()
    survivor = sleeper()

    assert :ok =
             GenServer.call(
               Revocations,
               {:connection, ctx.root, "ouro-revoked@127.0.0.1", revoked}
             )

    assert :ok =
             GenServer.call(
               Revocations,
               {:connection, ctx.root, "ouro-survivor@127.0.0.1", survivor}
             )

    monitor = Process.monitor(revoked)
    assert {:ok, "ouro-revoked@127.0.0.1"} = Revocations.install(ctx.encoded)
    assert_receive {:DOWN, ^monitor, :process, ^revoked, :killed}
    assert Process.alive?(survivor)

    assert {:error, :revoked} =
             GenServer.call(
               Revocations,
               {:connection, ctx.root, "ouro-revoked@127.0.0.1", self()}
             )

    assert {:ok, _} = Revocations.install(ctx.encoded)
    assert {:ok, [stored]} = Revocations.snapshot()
    assert stored == ctx.encoded
    [name] = File.ls!(ctx.root) |> Enum.filter(&String.starts_with?(&1, "revoke-"))
    assert Bitwise.band(File.stat!(Path.join(ctx.root, name)).mode, 0o777) == 0o600
    # Policy refresh must not turn missing files into permission to reconnect.
    File.rm!(Path.join(ctx.root, name))
    send(Process.whereis(Revocations), :refresh)
    assert {:ok, [_]} = Revocations.snapshot()
  end

  test "TLS validation fails closed when policy is absent, wrong, or revoked", ctx do
    [{:Certificate, der, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(@fixture, "node-cert.pem")))

    cert = :public_key.pkix_decode_cert(der, :otp)
    assert {:fail, _} = Revocations.verify(cert, :valid_peer, ~c"wrong-fleet")
    # Register a disposable TLS-process stand-in; the caller is killed on revocation.
    parent = self()

    ssl =
      spawn(fn ->
        send(
          parent,
          {:verified, Revocations.verify(cert, :valid_peer, String.to_charlist(ctx.root))}
        )

        receive do
          :stop -> :ok
        end
      end)

    assert_receive {:verified, {:valid, _}}
    monitor = Process.monitor(ssl)
    assert {:ok, _} = Revocations.install(ctx.encoded)
    assert_receive {:DOWN, ^monitor, :process, ^ssl, :killed}
    assert {:fail, _} = Revocations.verify(cert, :valid_peer, String.to_charlist(ctx.root))
    assert {:fail, :unknown_ca} = Revocations.verify(cert, {:bad_cert, :unknown_ca}, [])
    stop_supervised!(Revocations)
    assert {:fail, _} = Revocations.verify(cert, :valid_peer, String.to_charlist(ctx.root))
  end

  test "restarting the policy closes old sockets and reloads permanent records", ctx do
    survivor = sleeper()
    monitor = Process.monitor(survivor)

    assert :ok =
             GenServer.call(
               Revocations,
               {:connection, ctx.root, "ouro-survivor@127.0.0.1", survivor}
             )

    assert {:ok, _} = Revocations.install(ctx.encoded)
    stop_supervised!(Revocations)
    start_supervised!({Revocations, data_dir: ctx.data, enabled: true})
    assert_receive {:DOWN, ^monitor, :process, ^survivor, :killed}
    assert {:ok, [_]} = Revocations.snapshot()

    assert {:error, :revoked} =
             GenServer.call(
               Revocations,
               {:connection, ctx.root, "ouro-revoked@127.0.0.1", self()}
             )
  end

  defp private_write(path, bytes) do
    File.write!(path, bytes)
    File.chmod!(path, 0o600)
  end

  defp sleeper do
    pid =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> Process.exit(pid, :kill) end)
    pid
  end
end
