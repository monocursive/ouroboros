defmodule Ouroboros.MeshTest.ForgedAgent do
  @moduledoc false

  use Jido.Agent,
    name: "ouroboros_mesh_test_forged",
    description: "Stands in for an agent module forged outside the reserved namespaces",
    schema: [
      role: [type: :string, default: "worker"],
      seed: [type: :any, default: nil]
    ]
end

defmodule Ouroboros.MeshTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Mesh
  alias Ouroboros.Mesh.Directory
  alias Ouroboros.MeshTest.ForgedAgent

  describe "exception discipline" do
    test "an unreachable node fails placement with an error tuple instead of raising" do
      id = unique_id("unreachable")
      target = unreachable_node()

      # A node that is not connected is refused before any remote call is attempted.
      assert {:error, {:placement_refused, ^target, :node_not_connected}} =
               Mesh.start_agent_on(target, id)

      assert Mesh.whereis(id) == nil
    end

    test "an unreachable node still converts a transport fault instead of raising" do
      id = unique_id("unreachable-unchecked")
      target = unreachable_node()

      # With the placement check off, the call reaches `:erpc` and fails there. That
      # path must stay an error tuple: `:erpc` reports transport faults as `:error` but
      # a remote exit as `:exit`, and catching only one used to crash the caller.
      previous = Application.get_env(:ouroboros, :placement_role_check, true)
      Application.put_env(:ouroboros, :placement_role_check, false)
      on_exit(fn -> Application.put_env(:ouroboros, :placement_role_check, previous) end)

      assert {:error, {:remote_start_failed, ^target, {kind, _reason}}} =
               Mesh.start_agent_on(target, id)

      assert kind in [:error, :exit, :throw]
      assert Mesh.whereis(id) == nil
    end

    test "a target that never answers times out into an error tuple" do
      id = unique_id("silent")
      pid = spawn(fn -> Process.sleep(:infinity) end)
      on_exit(fn -> Process.exit(pid, :kill) end)
      assert :ok = Directory.register(id, pid)

      assert {:error, {:agent_call_failed, :exit, {:timeout, _call}}} =
               Mesh.send_message("root", id, %{text: "hello"}, timeout: 50)

      assert {:error, {:agent_call_failed, :exit, {:timeout, _call}}} =
               Mesh.assign_task("root", id, "stall", timeout: 50)

      assert {:error, {:agent_call_failed, :exit, {:timeout, _call}}} =
               Mesh.complete_task(id, "task-1", :done, timeout: 50)
    end

    test "a target that dies mid-call fails the call instead of the caller" do
      id = unique_id("dying")
      pid = spawn(fn -> receive do: (_message -> exit(:boom)) end)
      on_exit(fn -> Process.exit(pid, :kill) end)
      assert :ok = Directory.register(id, pid)

      assert {:error, {:agent_call_failed, :exit, {:boom, _call}}} = Mesh.state(id)
    end
  end

  describe "agent module allow-list" do
    test "refuses a module outside the reserved namespaces" do
      id = unique_id("denied")

      assert {:error, {:agent_module_not_allowed, Kernel}} = Mesh.start_agent(id, agent: Kernel)

      assert {:error, {:agent_module_not_allowed, ForgedAgent}} =
               Mesh.start_agent(id, agent: ForgedAgent)

      assert Mesh.whereis(id) == nil
    end

    test "accepts a module named by application config" do
      id = unique_id("configured")
      allow_agent_modules([ForgedAgent])

      assert {:ok, pid} = Mesh.start_agent(id, agent: ForgedAgent, role: "forged")
      on_exit(fn -> Mesh.stop_agent(id) end)

      assert Mesh.whereis(id) == pid
      assert {:ok, server_state} = Mesh.state(id)
      assert server_state.agent.state.role == "forged"
    end

    test "accepts the reserved Ouroboros.Agent namespace by default" do
      id = unique_id("reserved")

      assert {:ok, _pid} = Mesh.start_agent(id, agent: Ouroboros.Agent.Worker)
      on_exit(fn -> Mesh.stop_agent(id) end)
    end
  end

  describe "initial_state seeding" do
    test "merges an explicit map over the extracted trio" do
      id = unique_id("seeded")

      assert {:ok, _pid} =
               Mesh.start_agent(id,
                 role: "extracted",
                 objective: "extracted objective",
                 initial_state: %{role: "explicit", status: :working}
               )

      on_exit(fn -> Mesh.stop_agent(id) end)

      assert {:ok, server_state} = Mesh.state(id)
      assert server_state.agent.state.role == "explicit"
      assert server_state.agent.state.objective == "extracted objective"
      assert server_state.agent.state.status == :working
    end

    test "refuses a non-map initial state" do
      id = unique_id("bad-seed")

      assert {:error, {:invalid_initial_state, :not_a_map}} =
               Mesh.start_agent(id, initial_state: :not_a_map)

      assert Mesh.whereis(id) == nil
    end
  end

  describe "directory restart" do
    test "reconciling after a crash does not double-join a live agent" do
      id = unique_id("reconciled")
      assert {:ok, pid} = Mesh.start_agent(id, role: "reviewer")
      on_exit(fn -> Mesh.stop_agent(id) end)

      assert Mesh.members(id) == [pid]

      directory = Process.whereis(Directory)
      Process.exit(directory, :kill)

      assert_eventually(fn ->
        case Process.whereis(Directory) do
          nil -> false
          restarted -> restarted != directory and reconciled?(id, pid)
        end
      end)

      # :pg memberships outlive the directory, so a reconciling restart must not
      # report one healthy process as a split-brain pair.
      assert Mesh.members(id) == [pid]
      assert %{replicas: 1, pid: ^pid} = Enum.find(Mesh.list_agents(), &(&1.id == id))

      # The mesh directory is a rest_for_one boundary; let its downstream peers
      # finish restarting before this test hands the runtime to the next one.
      assert_eventually(fn -> is_pid(Process.whereis(Ouroboros.Orchestration.Scheduler)) end)
    end
  end

  # Borrow the local node's host so the name stays legal under whichever naming mode
  # an earlier test left :net_kernel in.
  defp unreachable_node do
    host =
      case String.split(to_string(node()), "@") do
        [_name, host] -> host
        _other -> "localhost"
      end

    :"ouroboros-nowhere@#{host}"
  end

  defp reconciled?(id, pid) do
    match?({^pid, _ref}, Map.get(:sys.get_state(Directory).by_id, id))
  catch
    _kind, _reason -> false
  end

  defp allow_agent_modules(modules) do
    previous = Application.get_env(:ouroboros, :mesh_allowed_agent_modules)
    Application.put_env(:ouroboros, :mesh_allowed_agent_modules, modules)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ouroboros, :mesh_allowed_agent_modules)
        value -> Application.put_env(:ouroboros, :mesh_allowed_agent_modules, value)
      end
    end)
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive])}"

  defp assert_eventually(fun, attempts \\ 200)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(10)
      assert_eventually(fun, attempts - 1)
    end
  end
end
