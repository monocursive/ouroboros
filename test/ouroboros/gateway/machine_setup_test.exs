defmodule Ouroboros.Gateway.MachineSetupTest do
  use ExUnit.Case, async: false
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Gateway.Methods.Contract

  test "machine setup is explicit and refuses missing or ambiguous destinations before running locally" do
    for method <-
          ~w(account.read runtime.providers runtime.models workspace.browse account.login.start credentials.xai.set) do
      assert Contract.machine_scoped?(method)

      params =
        if method == "credentials.xai.set", do: %{"api_key" => "fixture-not-a-key"}, else: %{}

      assert {:error, -32004, message} =
               Methods.invoke(method, Map.put(params, "machine", "not-an-enrolled-computer"))

      assert message =~ "offline or unknown"

      for target <- [nil, "", 42, "tag:shared"] do
        assert {:error, -32602, _} = Methods.invoke(method, %{"machine" => target})
      end
    end

    refute Contract.machine_scoped?("runtime.status")
    refute Contract.machine_scoped?("interactive.send_message")
    assert {:ok, %{scope: :operate}} = Methods.fetch("credentials.xai.set")
  end

  @tag timeout: 90_000
  test "folders and account setup run on the selected OS process, with no local fallback after it stops" do
    unless Node.alive?() do
      assert {:ok, _} =
               :net_kernel.start([
                 :"setup_root_#{System.unique_integer([:positive])}",
                 :shortnames
               ])
    end

    args = [~c"+S", ~c"2:2"] ++ Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    assert {:ok, peer, peer_node} =
             :peer.start(%{
               name: :"setup_peer_#{System.unique_integer([:positive])}",
               args: args,
               wait_boot: 30_000
             })

    on_exit(fn -> if Process.alive?(peer), do: :peer.stop(peer) end)
    dir = Path.join(System.tmp_dir!(), "ouro-machine-setup-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(dir, "remote-project"))
    {:ok, dir} = Ouroboros.Workspace.Path.canonicalize(dir)
    on_exit(fn -> File.rm_rf!(dir) end)

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :ouroboros,
        :coding_storage,
        {Jido.Storage.ETS, table: :machine_setup_storage}
      ])

    :ok =
      :erpc.call(peer_node, Application, :put_env, [:ouroboros, :workspace_allowed_roots, [dir]])

    assert {:ok, _} = :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])

    :erpc.call(peer_node, Code, :compile_string, [
      """
        defmodule MachineSetupAccountFixture do
          def read, do: {:ok, %{computer: node()}}
          def login(flow), do: {:ok, %{computer: node(), flow: flow}}
        end
      """
    ])

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :ouroboros,
        :account_adapter,
        MachineSetupAccountFixture
      ])

    machine = to_string(peer_node)

    assert {:ok, listing} =
             Methods.invoke("workspace.browse", %{"machine" => machine, "path" => dir})

    assert listing["path"] == dir
    assert Enum.any?(listing["entries"], &(&1["name"] == "remote-project"))

    assert {:ok, %{computer: ^peer_node}} =
             Methods.invoke("account.read", %{"machine" => machine})

    assert {:ok, %{computer: ^peer_node, flow: :device_code}} =
             Methods.invoke("account.login.start", %{"machine" => machine, "flow" => "browser"})

    :peer.stop(peer)
    assert {:error, -32004, _} = Methods.invoke("workspace.browse", %{"machine" => machine})
  end
end
