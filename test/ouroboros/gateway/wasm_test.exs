defmodule Ouroboros.Gateway.WasmTest do
  # Not async: `wasm.status` reads this node's own pool, store and rollout register, and
  # the assertion that it starts nothing is about that singleton.
  use ExUnit.Case, async: false

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Wasm.Pool

  @moduletag :capture_log

  describe "the table" do
    test "both verbs are `:read`, because neither changes anything and neither starts one" do
      assert "wasm.status" in Methods.names()
      assert "wasm.list" in Methods.names()

      assert {:ok, %{scope: :read}} = Methods.fetch("wasm.status")
      assert {:ok, %{scope: :read}} = Methods.fetch("wasm.list")
    end

    # W12 reversed the "there will never be a wasm.deploy" decision, and D15 says why: a
    # deployment's authority is the signature the target verifies against its own trust
    # policy, so the socket is a courier. The four verbs that would make it an authority
    # are still absent, and that is what this test now pins.
    test "there is still no verb that makes a socket decide what this node runs" do
      for forbidden <- ~w(wasm.load wasm.drop wasm.instantiate wasm.call wasm.probe) do
        refute forbidden in Methods.names(),
               "#{forbidden} would make a socket an authority over what this node runs"
      end
    end

    test "the four operator verbs are `:operate`, which is the scope that already starts work" do
      for verb <- ~w(wasm.upload wasm.sign wasm.deploy wasm.rollback) do
        assert verb in Methods.names()
        assert {:ok, %{scope: :operate}} = Methods.fetch(verb)
      end

      # A deploy's ceiling can fire while the rollout is still running on a peer, and
      # `:erpc` does not stop a peer. The table says so rather than letting a client read
      # `-32005` as "it did not happen".
      assert {:ok, %{outcome: :unknown}} = Methods.fetch("wasm.deploy")
    end
  end

  describe "wasm.status" do
    test "describes this node's helper, store, register and boot" do
      assert {:ok, status} = Methods.invoke("wasm.status", %{})

      assert status.node == node()
      assert is_boolean(status.helper.present)
      assert status.helper.phase in [:absent, :idle, :handshaking, :ready, :broken]
      assert status.helper.world == Ouroboros.Wasm.world()
      assert status.helper.hook_component_budget == Pool.hook_component_budget()
      assert is_integer(status.helper.hook_components)
      assert is_map(status.store)
      assert is_map(status.rollouts)
      assert is_boolean(status.boot.enabled)
    end

    test "answering starts no helper: the node's pool is exactly as idle afterwards" do
      # A pool that has already spawned a child for another test is not evidence either way,
      # so the claim is the honest one: this verb does not *advance* the phase.
      before = phase()
      assert {:ok, _status} = Methods.invoke("wasm.status", %{})
      assert phase() == before
    end

    test "the envelope is closed: an unknown key is refused by name" do
      assert {:error, code, message} =
               Methods.invoke("wasm.status", %{"helper" => "please start it"})

      assert code == Methods.code(:invalid_params)
      assert message =~ "helper"
    end

    test "`node` names the machine whose helper answers" do
      assert {:ok, status} = Methods.invoke("wasm.status", %{"node" => Atom.to_string(node())})
      assert status.node == node()
    end

    test "a machine this node is not connected to is refused rather than answered locally" do
      assert {:error, code, message} =
               Methods.invoke("wasm.status", %{"node" => "ouroboros@nowhere-in-this-fleet"})

      assert code == Methods.code(:invalid_params)
      assert message =~ "connected machine"
    end
  end

  describe "wasm.list" do
    test "answers two bounded, sorted lists with the totals beside them" do
      assert {:ok, list} = Methods.invoke("wasm.list", %{})

      assert list.node == node()
      assert is_list(list.rollouts)
      assert is_list(list.components)
      assert list.rollouts == Enum.sort_by(list.rollouts, & &1.artifact_id)
      assert list.components == Enum.sort_by(list.components, & &1.sha256)
    end

    test "the envelope is closed here too" do
      assert {:error, code, message} = Methods.invoke("wasm.list", %{"state" => "live"})

      assert code == Methods.code(:invalid_params)
      assert message =~ "state"
    end
  end

  defp phase do
    case Process.whereis(Pool) do
      nil -> :absent
      pid -> Pool.status(pid).phase
    end
  end
end
