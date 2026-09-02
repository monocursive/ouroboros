defmodule Ouroboros.Wasm.EpochTest do
  # Not async: two cases move `:signing_max_artifact_bytes`'s neighbour, the signing policy's
  # view of this node's watermark, by writing to a register.
  use ExUnit.Case, async: false

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.Policy
  alias Ouroboros.Wasm.Artifact

  @moduletag :capture_log

  # The exact number the register calls the last plausible epoch. Restated here on purpose:
  # a test that read it from the module under test would move with it.
  @ceiling 100_000_000_000_000

  @bytes "\0asm\x01\x00\x00\x00 a component this test never runs"

  setup do
    name = String.to_atom("wasm_epoch_reg_#{System.unique_integer([:positive])}")

    {:ok, pid} =
      Registry.start_link(
        name: name,
        storage:
          {Jido.Storage.ETS,
           table: String.to_atom("wasm_epoch_rollouts_#{System.unique_integer([:positive])}")}
      )

    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    %{registry: name}
  end

  describe "the wedge, from the socket end" do
    # The reviewer's case, with the assertion the other way up. `epoch` was an optional
    # parameter validated only for positivity, so the number below reached a manifest.
    test "no epoch a client names reaches a manifest, because there is no such parameter" do
      for epoch <- [1, 7, @ceiling, @ceiling + 1] do
        assert {:error, code, message} =
                 Methods.invoke("wasm.sign", %{
                   "upload" => String.duplicate("0", 32),
                   "name" => "greeter",
                   "author" => "operator",
                   "imports" => [],
                   "epoch" => epoch
                 })

        assert code == Methods.code(:invalid_params)
        assert message =~ "epoch", "epoch #{epoch} was accepted as a parameter"
      end
    end
  end

  describe "the wedge, from the register end" do
    # The register admits an epoch only *above* its watermark, and refuses one at or above
    # its plausibility ceiling. When the ceiling itself was admissible those two rules met:
    # an entry recorded at the ceiling left no number that was both fresh and plausible, on
    # every lane-W capability on the node, and the watermark is carried in the checkpoint so
    # pruning could not lower it back. Change the comparison in `fetch_epoch/1` from `>=` to
    # `>` and this test's first assertion goes green and its second goes red.
    test "the ceiling itself is not admissible, so it cannot become a watermark",
         %{registry: registry} do
      assert {:error, {:implausible_epoch, @ceiling, @ceiling}} =
               Registry.deploying(
                 %{
                   artifact_id: "poison",
                   module: "wasm/greeter",
                   epoch: @ceiling,
                   nodes: [node()],
                   component_sha256: String.duplicate("a", 64)
                 },
                 registry
               )

      assert Registry.wasm_epoch(registry) == 0
    end

    test "one below the ceiling still leaves the node deployable", %{registry: registry} do
      near = @ceiling - 2

      assert {:ok, _entry} =
               Registry.deploying(
                 %{
                   artifact_id: "near",
                   module: "wasm/greeter",
                   epoch: near,
                   nodes: [node()],
                   component_sha256: String.duplicate("a", 64)
                 },
                 registry
               )

      # There is exactly one number left, and it is admissible. The point is not that this
      # is a comfortable place to be — it is that the last usable number is usable, rather
      # than the register having eaten the whole range at the boundary.
      assert {:ok, _entry} =
               Registry.deploying(
                 %{
                   artifact_id: "next",
                   module: "wasm/other",
                   epoch: near + 1,
                   nodes: [node()],
                   component_sha256: String.duplicate("b", 64)
                 },
                 registry
               )
    end
  end

  describe "the wedge, from the signer end" do
    # The second guard, in front of the register's. A signature is what makes a huge epoch
    # deployable at all — a manifest nobody signed never reaches a register — so the signer
    # refuses a number far above anything this node has seen even when the number arrived
    # from somewhere other than a gateway parameter.
    test "a manifest whose epoch is far above this node's watermark is not signed" do
      assert {:refused, {:epoch_too_far_ahead, @ceiling, bound}} =
               Policy.Default.evaluate(artifact!(@ceiling), context())

      assert bound < @ceiling
    end

    test "an epoch this node could plausibly have allocated is signed" do
      assert {:ok, findings} = Policy.Default.evaluate(artifact!(7), context())
      assert findings.epoch == 7

      # The floor rises with what the node knows, so the guard is not a ceiling on how many
      # deployments a cluster may do.
      assert {:ok, _findings} = Policy.Default.evaluate(artifact!(1_000_000), context())
    end
  end

  defp artifact!(epoch) do
    {:ok, artifact} =
      Artifact.build(@bytes,
        name: "greeter",
        epoch: epoch,
        imports: ["log"],
        author: "test-agent",
        eval: %{probes: [%{input: %{"n" => 1}, expect: :any_reply}], budget_ms: 1_000}
      )

    artifact
  end

  defp context do
    %{
      signer_id: "wasm-epoch-test-key",
      requester: node(),
      require_wasm_eval: true,
      component_bytes: @bytes,
      max_artifact_bytes: 16 * 1024 * 1024,
      node: node()
    }
  end
end
