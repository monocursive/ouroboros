defmodule Ouroboros.Test.DistOffForge do
  @moduledoc false

  # The forge loop, written to run inside the node that runs it rather than beside it.
  #
  # `test/upgrade/dist_off_forge_test.exs` drives this through a `:peer` that never joined
  # a mesh, which is the only way to hold a node at `:nonode@nohost` while the rest of the
  # suite is free to start distribution. Such a peer can only call code that is on its own
  # code path, and a function defined in a `.exs` file is not on it — so the loop lives in
  # a compiled support module and hands back a plain serializable summary the test asserts
  # against.

  alias Ouroboros.Mesh
  alias Ouroboros.Upgrade.{Epoch, Forge}
  alias Ouroboros.Upgrade.Forge.Source
  alias Ouroboros.Upgrade.Rollout
  alias Ouroboros.Upgrade.Rollout.Registry

  @author "dist-off-test-agent"

  @doc """
  Allocates an epoch, forges and signs `module`, deploys it here, and messages it.

  Returns `{:ok, summary}` with only atoms, binaries, numbers, and maps in it, or
  `{:error, stage, reason}` naming the stage that refused.
  """
  @spec run(map()) :: {:ok, map()} | {:error, atom(), term()}
  def run(%{module: module, signer_id: signer_id, epoch_table: table}) do
    storage = {Jido.Storage.ETS, table: table}

    with {:ok, source} <- source(module),
         {:ok, allocated} <- allocate(storage),
         {:ok, signed} <- forge(source, signer_id, storage),
         {:ok, outcome} <- deploy(signed, module),
         {:ok, exchange} <- exercise(module) do
      {:ok,
       %{
         alive?: :erlang.is_alive(),
         node: node(),
         connected: Node.list(:connected),
         allocated_epoch: allocated,
         artifact: %{
           id: signed.id,
           epoch: signed.epoch,
           signer: signed.signature.signer,
           signature_bytes: byte_size(signed.signature.value),
           dispositions: Enum.map(signed.modules, & &1.disposition),
           test_total: signed.metadata.forge.test_report.total,
           test_failures: signed.metadata.forge.test_report.failures,
           build_peer_distributed: signed.metadata.forge.peer_runtime.distributed
         },
         rollout: %{state: outcome.state, epoch: outcome.epoch, nodes: outcome.nodes},
         registry: registry_state(signed.id),
         loaded: :code.which(module),
         exchange: exchange
       }}
    end
  end

  defp source(module) do
    case Source.new(
           module: module,
           source: capability_source(module),
           test_source: capability_test_source(module),
           author: @author
         ) do
      {:ok, source} -> {:ok, source}
      {:error, reason} -> {:error, :source, reason}
    end
  end

  # The allocation the dist-off posture is most likely to break: `Epoch.next/2` takes
  # `:global.trans` on a VM where `:global` has no distribution under it.
  defp allocate(storage) do
    case Epoch.next([node()], storage: storage) do
      {:ok, epoch} -> {:ok, epoch}
      {:error, reason} -> {:error, :epoch, reason}
    end
  end

  defp forge(source, signer_id, storage) do
    case Forge.forge(source, nodes: [node()], signer_id: signer_id, storage: storage) do
      {:ok, signed} -> {:ok, signed}
      {:error, reason} -> {:error, :forge, reason}
    end
  end

  defp deploy(signed, module) do
    case Rollout.deploy(signed, module, [node()]) do
      {:ok, outcome} -> {:ok, outcome}
      {:error, reason} -> {:error, :deploy, sanitize(reason)}
    end
  end

  # The rollout's own probe already started, messaged, and stopped this capability. Doing
  # it again through the mesh is the part an operator would call running it: a module that
  # did not exist when this VM booted, answering a message on a node with no distribution.
  defp exercise(module) do
    id = "dist-off-capability-#{System.unique_integer([:positive])}"

    with {:ok, pid} <- start_agent(id, module),
         {:ok, agent} <- Mesh.send_message("dist-off-test", id, "ping") do
      Mesh.stop_agent(id)

      {:ok,
       %{
         local?: node(pid) == node(),
         body: agent.state.last_message.body,
         messages_received: agent.state.messages_received
       }}
    else
      {:error, reason} -> {:error, :exercise, sanitize(reason)}
    end
  end

  defp start_agent(id, module) do
    case Mesh.start_agent(id, agent: module) do
      {:ok, pid} -> {:ok, pid}
      {:error, reason} -> {:error, reason}
    end
  end

  defp registry_state(artifact_id) do
    case Registry.get(artifact_id) do
      {:ok, entry} -> %{state: entry.state, module: entry.module, nodes: entry.nodes}
      other -> other
    end
  end

  # Everything here crosses a `:peer` control channel and lands in an ExUnit failure
  # message, so a reason carrying pids, refs, or structs becomes text before it travels.
  defp sanitize(reason) do
    if serializable?(reason), do: reason, else: inspect(reason)
  end

  defp serializable?(term) when is_atom(term) or is_binary(term) or is_number(term), do: true
  defp serializable?(term) when is_list(term), do: Enum.all?(term, &serializable?/1)

  defp serializable?(term) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.all?(&serializable?/1)

  defp serializable?(term) when is_map(term) do
    not is_struct(term) and
      Enum.all?(term, fn {key, value} -> serializable?(key) and serializable?(value) end)
  end

  defp serializable?(_term), do: false

  defp capability_source(module) do
    """
    defmodule #{inspect(module)} do
      @vsn 1

      use Jido.Agent,
        name: "ouroboros_capability_dist_off_echo",
        description: "A capability forged on a node with no distribution",
        schema: [
          role: [type: :string, default: "capability"],
          inbox: [type: :list, default: []],
          last_message: [type: :any, default: nil],
          messages_received: [type: :non_neg_integer, default: 0]
        ],
        signal_routes: [
          {"ouroboros.agent.message", Ouroboros.Agent.Worker.ReceiveMessage}
        ]
    end
    """
  end

  defp capability_test_source(module) do
    """
    defmodule #{inspect(module)}Test do
      use ExUnit.Case, async: false

      test "compiles and declares its identity" do
        assert #{inspect(module)}.new().name == "ouroboros_capability_dist_off_echo"
      end
    end
    """
  end
end
