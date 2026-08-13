defmodule Ouroboros.Upgrade.DistOffForgeTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Test.DistOffForge
  alias Ouroboros.Upgrade.Forge.Signer

  # The loop under test boots a build peer, compiles a capability, and runs its tests
  # before anything is deployed, all inside a peer this test boots first.
  @moduletag timeout: 300_000

  @module Ouroboros.Capability.DistOffEcho
  @signer "dist-off-forge-signer"

  test "forges, signs, deploys, and runs a capability on a node with no distribution" do
    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)
    peer = start_dist_off_peer!(public_key, private_key)

    # The posture `rel/env.sh.eex` produces for `OUROBOROS_DIST=none` (docs/TUI.md §2.10),
    # asserted before anything is forged rather than assumed: no distribution was ever
    # started, so this VM has no name, no epmd registration, and no cookie to leak. It is
    # a peer rather than this test's own VM because other files in this suite start
    # `:net_kernel` and never stop it, which would make the property depend on seed order.
    assert :peer.call(peer, :erlang, :is_alive, []) == false
    assert :peer.call(peer, :erlang, :node, []) == :nonode@nohost

    assert {:ok, summary} =
             :peer.call(
               peer,
               DistOffForge,
               :run,
               [
                 %{
                   module: @module,
                   signer_id: @signer,
                   epoch_table: unique_atom("dist_off_forge_epochs")
                 }
               ],
               240_000
             )

    # The single most likely failure point of the dist-off posture: `Upgrade.Epoch`
    # allocates under `:global.trans`, and `:global` here has no distribution beneath it.
    assert summary.allocated_epoch > 0
    assert summary.artifact.epoch > summary.allocated_epoch

    # Forged and signed on a node that could not have asked a remote signer for anything.
    assert summary.artifact.signer == @signer
    assert summary.artifact.signature_bytes == 64
    assert summary.artifact.dispositions == [:introduce]

    # The candidate's own test really ran, in a build peer that was itself non-distributed
    # while running inside a node that had no distribution to lend it.
    assert summary.artifact.test_total == 1
    assert summary.artifact.test_failures == 0
    refute summary.artifact.build_peer_distributed

    # Deployed and promoted by the local path, which never reaches for `:erpc`.
    assert summary.rollout.state == :live
    assert summary.rollout.nodes == [:nonode@nohost]
    assert summary.registry.state == :live
    assert summary.registry.module == @module
    assert summary.loaded == ~c"ouroboros://capability/#{inspect(@module)}"

    # And running: a module that did not exist when this VM booted, answering a message.
    assert summary.exchange.local?
    assert summary.exchange.body == "ping"
    assert summary.exchange.messages_received == 1

    # Nothing along the way quietly started distribution to make any of it work.
    refute summary.alive?
    assert summary.node == :nonode@nohost
    assert summary.connected == []
    assert :peer.call(peer, :erlang, :is_alive, []) == false
  end

  # `connection: :standard_io` makes the control channel a pipe and `-start_epmd false`
  # denies the peer a port mapper, which is what `RELEASE_DISTRIBUTION=none` amounts to at
  # runtime: the node can be driven without ever being reachable.
  defp start_dist_off_peer!(public_key, private_key) do
    arguments = [~c"-start_epmd", ~c"false"] ++ Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    assert {:ok, peer, :nonode@nohost} =
             :peer.start(%{connection: :standard_io, args: arguments, wait_boot: 30_000})

    on_exit(fn -> stop_peer(peer) end)

    # A bare `erl` boot has Elixir on its code path without having started it.
    assert {:ok, _started} =
             :peer.call(peer, :application, :ensure_all_started, [:elixir], 60_000)

    # The peer trusts exactly one signer and nothing unsigned, so the artifact it deploys
    # to itself is admitted by its signature rather than by a permissive test policy.
    put_env!(peer, :upgrade_trust_policy,
      allow_unsigned: false,
      trusted_signers: %{@signer => public_key}
    )

    put_env!(peer, :coding_storage, {Jido.Storage.ETS, table: unique_atom("dist_off_coding")})
    put_env!(peer, :forge_signer, {Signer.Local, private_key: private_key})
    put_env!(peer, :forge_signer_id, @signer)

    assert {:ok, _applications} =
             :peer.call(peer, Application, :ensure_all_started, [:ouroboros], 120_000)

    peer
  end

  defp put_env!(peer, key, value) do
    assert :ok = :peer.call(peer, Application, :put_env, [:ouroboros, key, value])
  end

  defp unique_atom(prefix), do: String.to_atom("#{prefix}_#{System.unique_integer([:positive])}")

  defp stop_peer(peer) do
    :peer.stop(peer)
    :ok
  catch
    _kind, _reason -> :ok
  end
end
