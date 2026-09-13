defmodule Ouroboros.Runtime.SafeStatusOwnerLifecycleTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Interactive.{Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Session
  alias Ouroboros.Session.RuntimeInfo, as: SessionInfo

  @moduletag :capture_log
  @secret "SECRET_OWNER_LIFECYCLE_CANARY_8d05d7"

  setup do
    previous_config = Ouroboros.Test.NativeConfig.snapshot()
    journal_dir = unique_path("journal")
    workspace = unique_path("workspace-#{@secret}")
    File.mkdir_p!(workspace)

    Ouroboros.Test.NativeConfig.configure(%{
      native: %{test_pid: self(), retention: %{journal_dir: journal_dir}}
    })

    id = unique_id("safe-status-owner")

    on_exit(fn ->
      retire(id)
      Ouroboros.Test.NativeConfig.configure(previous_config)
      File.rm_rf(journal_dir)
      File.rm_rf(workspace)
    end)

    {:ok, id: id, workspace: workspace}
  end

  test "a status reader captured for dead owner A cannot follow the logical session to owner B",
       %{id: id, workspace: workspace} do
    assert {:ok, session} =
             InteractiveSession.start(
               id: id,
               provider: :native,
               workspace: workspace,
               approval_mode: :auto_approve
             )

    owner_a = Task.whereis(id)
    assert is_pid(owner_a)
    owner_node = node(owner_a)
    stale_reader = fn -> InteractiveSession.safe_status_from_owner(owner_a, owner_node) end

    assert {:ok, status_a} = stale_reader.()
    assert_safe_public_status(status_a, id)

    monitor = Process.monitor(owner_a)
    Process.exit(owner_a, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^owner_a, :killed}, 1_000

    owner_b =
      eventually(fn ->
        case Task.whereis(id) do
          pid when is_pid(pid) and pid != owner_a -> pid
          _ -> false
        end
      end)

    assert is_pid(owner_b)
    assert owner_b != owner_a
    assert node(owner_b) == owner_node

    # This is the retained closure's production operation. An implementation that looked
    # the logical id up again would return B's successful status and fail this assertion.
    assert {:error, {:session_call_failed, _reason}} = stale_reader.()

    assert {:ok, status_b} =
             InteractiveSession.safe_status_from_owner(owner_b, node(owner_b))

    assert_safe_public_status(status_b, id)
    assert {:ok, public_status_b} = Methods.invoke("interactive.safe_status", %{"id" => id})
    assert_safe_public_status(public_status_b, id)
    assert public_status_b["identity"] == status_b["identity"]
    assert public_status_b["posture"] == status_b["posture"]

    encoded = JSON.encode!(public_status_b)
    refute encoded =~ @secret
    refute encoded =~ workspace
    assert byte_size(encoded) <= 16_384

    assert :ok = InteractiveSession.close(session)
    eventually(fn -> match?({:ok, %{status: :closed}}, InteractiveSession.info(session)) end)
  end

  defp assert_safe_public_status(status, id) do
    assert status["scope"] == "session"
    assert status["owner"] == id
    assert status["identity"]["logical_id"] == id
    assert status["provenance"] == "interactive_owner"
    assert status["freshness"] == "fresh"
    assert status["identity"]["pid"] == nil
    assert status["identity"]["port"] == nil
    assert status["identity"]["birth"] == nil
    assert status["listener"]["publication"] == "unavailable"
  end

  defp eventually(fun, attempts \\ 300)
  defp eventually(_fun, 0), do: flunk("condition did not become true")

  defp eventually(fun, attempts) do
    case fun.() do
      value when value in [false, nil] ->
        Process.sleep(10)
        eventually(fun, attempts - 1)

      value ->
        value
    end
  end

  defp retire(id) do
    case Task.whereis(id) do
      pid when is_pid(pid) ->
        _ = DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)

      _ ->
        :ok
    end

    case Store.get(id) do
      {:ok, state} ->
        _ = Store.put(%{state | status: :cancelled})
        _ = Store.delete(id)

      _ ->
        :ok
    end

    Session.list()
    |> Enum.filter(&(&1.session_id == id and not SessionInfo.terminal?(&1)))
    |> Enum.each(&Session.kill(&1.session_id))
  end

  defp unique_path(prefix) do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-#{prefix}-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"
end
