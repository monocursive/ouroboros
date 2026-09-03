defmodule Ouroboros.Wasm.EpochNodesTest do
  # Not async: it starts peer VMs, and `Ouroboros.Upgrade.Epoch` serializes allocation with
  # a cluster-wide `:global.trans/4`.
  use ExUnit.Case, async: false

  # Two peer VMs per test at worst, each a cold BEAM boot.
  @moduletag timeout: 180_000
  @moduletag :capture_log

  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm.Deploy
  alias Ouroboros.Wasm.Upload

  @signer "wasm-epoch-nodes-key"
  @bytes "\0asm\x0d\x00\x01\x00 a component this test never runs"

  @eval %{
    probes: [%{input: %{"n" => 1}, expect: :any_reply}],
    budget_ms: 1_000,
    required: :all
  }

  # The two processes `Ouroboros.Upgrade.Epoch.next/2` needs on every node it is handed:
  # the executor it reads `last_epoch` from, and the register it reads the lane-W watermark
  # from. A node running neither answers neither, which is the whole defect.
  @plane [Ouroboros.Upgrade.Rollout.Registry, Ouroboros.Upgrade.NodeExecutor]

  setup do
    ensure_distributed!()

    tmp =
      Path.join(System.tmp_dir!(), "ouro-wasm-epoch-nodes-#{System.unique_integer([:positive])}")

    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf(tmp) end)

    key_path = Path.join(tmp, "signer.key")
    File.write!(key_path, :crypto.strong_rand_bytes(32))
    File.chmod!(key_path, 0o600)

    service =
      start_supervised!(
        {Service,
         [
           name: nil,
           key_path: key_path,
           signer_id: @signer,
           storage:
             {Jido.Storage.ETS,
              table: String.to_atom("epoch_nodes_journal_#{System.unique_integer([:positive])}")}
         ]},
        id: {Service, System.unique_integer([:positive])}
      )

    %{service: service, uploads: Path.join(tmp, "uploads"), tmp: tmp}
  end

  describe "which nodes an epoch is allocated over" do
    # The defect W11 proved live. `Epoch.next/2` asks every node it is handed for
    # `NodeExecutor.status/0` and for its lane-W register, so handing it every *connected*
    # node made signing impossible on the one topology D15 prescribes: the key on a
    # `:signer`-role node, whose supervision tree is the signing service and cluster
    # formation and nothing else. `wasm.sign` refused with
    # `{:epoch_not_allocated, {:epoch_status_unavailable, …}}` and there was no way past it.
    #
    # Restore `epoch_nodes/1` to `{:ok, candidates}` — no classification — and this is red.
    test "a connected node that runs no rollout plane is excluded rather than asked",
         context do
      signer_peer = start_bare_peer!()

      # A signer's shape: it runs the signing service and nothing this allocation needs.
      plant!(signer_peer, [Ouroboros.Upgrade.Signing.Service])

      assert {:ok, receipt} = sign(context, epoch_nodes: [node(), signer_peer])
      assert is_integer(receipt.epoch) and receipt.epoch > 0
    end

    # Half a plane is not a node that admits nothing: a register with no executor may hold
    # a watermark above the number about to be minted, and the executor that would report it
    # is not there. Excluding it would mint a stale epoch; asking it would fail anyway. It is
    # the unreachable answer. Make `classify_plane/1` return `:absent` for a partial plane
    # and this is red.
    test "a candidate with a register but no executor fails the allocation closed", context do
      half_peer = start_bare_peer!()
      plant!(half_peer, [Ouroboros.Upgrade.Rollout.Registry])

      assert {:error, {:epoch_not_allocated, {:candidates_unreachable, faults}}} =
               sign(context, epoch_nodes: [node(), half_peer])

      assert %{^half_peer => {:partial_plane, [Ouroboros.Upgrade.NodeExecutor]}} = faults
    end

    # The floor comes from the nodes that hold a register, not from the one doing the
    # signing. A signer node driving its own signature is the case that has to work.
    test "a plane-holding candidate's watermark is still the floor", context do
      registry = start_registry!()
      storage = ets_storage()

      {:ok, _entry} =
        Registry.deploying(
          %{
            artifact_id: "seed-#{System.unique_integer([:positive])}",
            module: "wasm/seeded",
            epoch: 5_000,
            nodes: [node()],
            component_sha256: String.duplicate("a", 64)
          },
          registry
        )

      signer_peer = start_bare_peer!()
      plant!(signer_peer, [Ouroboros.Upgrade.Signing.Service])

      assert {:ok, receipt} =
               sign(context,
                 epoch_nodes: [node(), signer_peer],
                 epoch_opts: [storage: storage, wasm_epoch_registry: registry]
               )

      # Above what the one node that could refuse it has admitted. Drop the local node from
      # the held set and this is 1.
      assert receipt.epoch > 5_000
    end

    # A fresh fleet, or a lone signer with the key and nothing else. Nothing can call 1
    # stale, because nothing has admitted anything.
    test "with no register among the candidates the first epoch is 1", context do
      bare_peer = start_bare_peer!()

      assert {:ok, receipt} = sign(context, epoch_nodes: [bare_peer])
      assert receipt.epoch == 1
    end
  end

  describe "a candidate that cannot be asked" do
    # The half that must NOT be silently excluded. A node this end cannot reach may be
    # running a register whose watermark is above anything the allocation can see, and an
    # epoch minted below it is one that node refuses at stage time. "No plane" and "no
    # answer" look alike from here, so only the first one narrows the set.
    #
    # Change `rollout_plane/2`'s `catch` to answer `:absent` and this is red: the peer is
    # dropped and the signature succeeds over a floor nobody checked.
    test "a plane-running peer that does not answer in time fails the allocation closed",
         context do
      peer = start_bare_peer!()
      plant!(peer, @plane)

      # It genuinely holds the plane: the probe would classify it `:holds` given time.
      assert is_pid(:erpc.call(peer, :erlang, :whereis, [Registry], 5_000))

      assert {:error, {:epoch_not_allocated, {:candidates_unreachable, unreachable}}} =
               sign(context, epoch_nodes: [node(), peer], epoch_probe_timeout: 0)

      assert Map.has_key?(unreachable, peer)
    end

    test "a candidate that has gone away fails the allocation closed", context do
      {peer, peer_node} = start_bare_peer!(:with_handle)
      plant!(peer_node, @plane)

      :peer.stop(peer)
      await_disconnected!(peer_node)

      assert {:error, {:epoch_not_allocated, {:candidates_unreachable, unreachable}}} =
               sign(context, epoch_nodes: [node(), peer_node])

      assert Map.has_key?(unreachable, peer_node)
    end
  end

  ## Helpers

  defp sign(context, opts) do
    {:ok, %{upload: upload}} = Upload.append(nil, 0, @bytes, true, root: context.uploads)

    Deploy.sign(
      %{
        upload: upload,
        name: "greeter",
        author: "test-agent",
        imports: [],
        eval: @eval
      },
      [signing_service: context.service, upload_root: context.uploads] ++ opts
    )
  end

  # A peer VM with no `:ouroboros` application at all — the cheapest faithful stand-in for
  # every node that is connected and holds no rollout plane: a `:signer`, a `:builder`, a
  # bare client. Names are planted on it with `plant!/2` to give it whatever shape a case
  # needs, because what the probe reads is `:erlang.whereis/1` and nothing of ours.
  defp start_bare_peer!(handle \\ :node_only) do
    name = String.to_atom("ouro_epoch_peer_#{:os.getpid()}_#{System.unique_integer([:positive])}")
    args = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    {:ok, peer, peer_node} = :peer.start(%{name: name, args: args, wait_boot: 60_000})
    on_exit(fn -> stop_peer(peer) end)

    if handle == :with_handle, do: {peer, peer_node}, else: peer_node
  end

  defp plant!(peer_node, names) do
    Enum.each(names, fn name ->
      pid = :erpc.call(peer_node, :erlang, :spawn, [:timer, :sleep, [:infinity]])
      true = :erpc.call(peer_node, :erlang, :register, [name, pid])
    end)
  end

  defp stop_peer(peer) do
    :peer.stop(peer)
  catch
    :exit, _reason -> :ok
  end

  # 400 x 25ms: a peer's disconnection reaches `Node.list/0` asynchronously, and the ceiling
  # exists to catch a peer that will never leave rather than to race the notice.
  defp await_disconnected!(target, attempts \\ 400)

  defp await_disconnected!(target, 0),
    do: flunk("#{target} is still connected: #{inspect(Node.list())}")

  defp await_disconnected!(target, attempts) do
    if target in Node.list() do
      Process.sleep(25)
      await_disconnected!(target, attempts - 1)
    else
      :ok
    end
  end

  defp start_registry! do
    name = String.to_atom("epoch_nodes_registry_#{System.unique_integer([:positive])}")

    {:ok, pid} = Registry.start_link(name: name, storage: ets_storage())

    on_exit(fn ->
      try do
        GenServer.stop(pid)
      catch
        :exit, _reason -> :ok
      end
    end)

    name
  end

  defp ets_storage do
    {Jido.Storage.ETS,
     table: String.to_atom("epoch_nodes_store_#{System.unique_integer([:positive])}")}
  end

  defp ensure_distributed! do
    unless Node.alive?() do
      name = String.to_atom("ouroboros_wasm_epoch_root_#{System.unique_integer([:positive])}")
      {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end
  end
end
