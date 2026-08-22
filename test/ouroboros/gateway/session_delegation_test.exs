defmodule Ouroboros.Gateway.SessionDelegationTest do
  @moduledoc """
  G1's runtime half: `interactive.delegate` and `interactive.delegations`.

  The claim under test is deliberately narrow, because it is what the docs promise: a
  delegation is a *coding task with a parent*, not a sub-conversation. So the assertions
  are about the link — the child's durable `parent`, the parent's transcript entries and
  `children` ids, the one team per workspace root, and the id that makes a re-delegation
  the same delegation rather than a second one.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{Session, SessionInfo}
  alias Ouroboros.Coding.Store, as: CodingStore
  alias Ouroboros.Coding.Task, as: CodingTask
  alias Ouroboros.Coding.TaskState
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Interactive.{Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Team
  alias Ouroboros.Test.HarnessAdapter

  @provider :ouroboros_test

  setup do
    cleanup_sessions()

    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)
    journal_dir = unique_journal_dir()

    root = Path.join(System.tmp_dir!(), "delegation-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(workspace)

    Application.put_env(
      :jido_harness,
      :providers,
      Map.put(map_or_empty(previous_providers), @provider, HarnessAdapter)
    )

    Application.put_env(
      :jido_harness,
      :provider_config,
      Map.put(map_or_empty(previous_provider_config), @provider, %{
        test_pid: self(),
        retention: %{journal_dir: journal_dir}
      })
    )

    on_exit(fn ->
      cleanup_sessions()
      close_teams(workspace)
      restore(:providers, previous_providers)
      restore(:provider_config, previous_provider_config)
      File.rm_rf(journal_dir)
      File.rm_rf(root)
    end)

    {:ok, id: unique_id("delegating"), workspace: workspace}
  end

  describe "the method table" do
    test "delegate is operate with an unknown outcome, delegations is read" do
      table = Methods.table()

      assert table["interactive.delegate"].scope == :operate
      assert table["interactive.delegate"].outcome == :unknown
      assert "interactive.delegate" in Methods.names()
      refute Methods.permits?(:read, table["interactive.delegate"])

      assert table["interactive.delegations"].scope == :read
      assert "interactive.delegations" in Methods.names()
      assert Methods.permits?(:read, table["interactive.delegations"])
    end
  end

  describe "the parameter contract" do
    test "an unsupported field is refused rather than ignored" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.delegate", %{
                 "id" => "s",
                 "objective" => "do the thing",
                 "coding_node" => "somewhere"
               })

      assert message =~ "coding_node"
    end

    test "a blank objective is a parameter error" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.delegate", %{"id" => "s", "objective" => ""})

      assert message =~ "nonempty string"
    end

    test "an unknown provider names the ones this node serves" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.delegate", %{
                 "id" => "s",
                 "objective" => "do the thing",
                 "provider" => "not-a-provider"
               })

      assert message =~ "must name a provider this node serves"
    end

    test "a session id that names nothing is not found, on both verbs" do
      assert {:error, -32_007, _message} =
               Methods.invoke("interactive.delegate", %{"id" => "nope", "objective" => "x"})

      assert {:error, -32_007, _message} =
               Methods.invoke("interactive.delegations", %{"id" => "nope"})
    end
  end

  describe "delegating" do
    test "a delegation is a coding task carrying this conversation as its parent",
         %{id: id, workspace: workspace} do
      start_session(id, workspace)

      assert {:ok, result} =
               Methods.invoke("interactive.delegate", %{
                 "id" => id,
                 "objective" => "review the repository"
               })

      assert result.plane == :coding
      assert is_binary(result.delegation_id)
      assert is_binary(result.task_id)
      assert result.task_node == node()

      # The durable half of the relationship, on the child.
      assert {:ok, %TaskState{} = task} = CodingStore.get(result.task_id)
      assert task.parent == %{plane: :interactive, id: id}
      assert task.objective == "review the repository"

      # The child works where the conversation does. Compared through the resolver rather
      # than by string: workspace admission may have replaced the path with its lease
      # root, which is the same directory spelled differently.
      assert Ouroboros.Workspace.Path.canonicalize(task.workspace) ==
               Ouroboros.Workspace.Path.canonicalize(workspace)

      # And `coding.info` carries it, so a client nesting rows does not need the store.
      assert {:ok, info} = Methods.invoke("coding.info", %{"id" => result.task_id})
      assert info.parent == %{plane: :interactive, id: id}

      cleanup_delegation(result)
      retire_session(id)
    end

    test "the parent's transcript gains a started delegation event",
         %{id: id, workspace: workspace} do
      start_session(id, workspace)

      assert {:ok, result} =
               Methods.invoke("interactive.delegate", %{"id" => id, "objective" => "explore"})

      assert {:ok, events} =
               Methods.invoke("interactive.replay", %{"id" => id, "cursor" => 0, "limit" => 100})

      event = Enum.find(events, &(&1.type == :delegation))
      assert event, "no delegation event on the parent's log"
      assert event.payload["delegation_id"] == result.delegation_id
      assert event.payload["task_id"] == result.task_id
      assert event.payload["status"] == "started"
      assert is_binary(event.payload["objective_digest"])

      # A digest, never the objective's text: that is the child's own record.
      refute event.payload["objective"]

      cleanup_delegation(result)
      retire_session(id)
    end

    test "the workspace's default team is created once and shows up in teams.list",
         %{id: id, workspace: workspace} do
      other = unique_id("also-delegating")
      start_session(id, workspace)
      start_session(other, workspace)

      assert {:ok, first} =
               Methods.invoke("interactive.delegate", %{"id" => id, "objective" => "one"})

      assert {:ok, second} =
               Methods.invoke("interactive.delegate", %{"id" => other, "objective" => "two"})

      # One team per canonical workspace root per node, so a second conversation in the
      # same repository joins rather than starting a parallel one.
      expected = Team.workspace_team_id(workspace)
      assert first.team_id == expected
      assert second.team_id == expected
      assert String.starts_with?(expected, "#{node()}:workspace-team:")

      assert {:ok, teams} = Methods.invoke("teams.list", %{})
      assert Enum.count(teams, &(&1.id == expected)) == 1

      cleanup_delegation(first)
      cleanup_delegation(second)
      retire_session(other)
      retire_session(id)
    end

    test "re-delegating under the same id answers with the same delegation",
         %{id: id, workspace: workspace} do
      start_session(id, workspace)
      delegation_id = unique_id("caller-owned")

      params = %{
        "id" => id,
        "objective" => "run it once",
        "delegation_id" => delegation_id
      }

      assert {:ok, first} = Methods.invoke("interactive.delegate", params)
      assert {:ok, second} = Methods.invoke("interactive.delegate", params)

      assert second.delegation_id == first.delegation_id
      assert second.task_id == first.task_id
      assert second.status == :existing

      # And exactly one child, one transcript entry, one row.
      assert {:ok, session} = Methods.invoke("interactive.info", %{"id" => id})
      assert map_size(session.delegations) == 1

      assert {:ok, events} =
               Methods.invoke("interactive.replay", %{"id" => id, "cursor" => 0, "limit" => 100})

      assert Enum.count(events, &(&1.type == :delegation)) == 1

      cleanup_delegation(first)
      retire_session(id)
    end

    test "a terminal session cannot delegate", %{id: id, workspace: workspace} do
      start_session(id, workspace)
      assert {:ok, _closed} = Methods.invoke("interactive.close", %{"id" => id})

      wait_until(fn ->
        match?({:ok, %{status: status}} when status in [:closed, :cancelled], Store.get(id))
      end)

      assert {:error, -32_006, _message, data} =
               Methods.invoke("interactive.delegate", %{"id" => id, "objective" => "too late"})

      assert ["session_not_delegable", _details] = data

      retire_session(id)
    end
  end

  describe "list rows and delegations" do
    test "interactive rows carry children ids and coding rows carry parent",
         %{id: id, workspace: workspace} do
      start_session(id, workspace)

      assert {:ok, result} =
               Methods.invoke("interactive.delegate", %{"id" => id, "objective" => "nest me"})

      assert {:ok, rows} = Methods.invoke("interactive.list", %{})
      row = Enum.find(rows, &(&1.id == id))
      assert row.children == [result.task_id]

      # Ids only: a row is bounded, and the record is one `interactive.info` away.
      assert row.delegations == %{}

      assert {:ok, coding_rows} = Methods.invoke("coding.list", %{})
      child = Enum.find(coding_rows, &(&1.id == result.task_id))
      assert child.parent == %{plane: :interactive, id: id}

      cleanup_delegation(result)
      retire_session(id)
    end

    test "interactive.delegations reads the team's own record",
         %{id: id, workspace: workspace} do
      start_session(id, workspace)

      assert {:ok, result} =
               Methods.invoke("interactive.delegate", %{"id" => id, "objective" => "status me"})

      assert {:ok, [delegation]} = Methods.invoke("interactive.delegations", %{"id" => id})

      assert delegation.delegation_id == result.delegation_id
      assert delegation.task_id == result.task_id
      assert delegation.plane == :coding
      assert delegation.team_id == Team.workspace_team_id(workspace)
      assert is_binary(delegation.objective_digest)

      # The team is up, so the status is the team's rather than the conversation's copy.
      assert delegation.source == :team

      cleanup_delegation(result)
      retire_session(id)
    end

    test "a session that delegated nothing answers with an empty list", %{id: id, workspace: ws} do
      start_session(id, ws)
      assert {:ok, []} = Methods.invoke("interactive.delegations", %{"id" => id})
      retire_session(id)
    end
  end

  describe "the terminal note" do
    test "the parent sees the terminal status and a bounded result digest",
         %{id: id, workspace: workspace} do
      start_session(id, workspace)

      assert {:ok, result} =
               Methods.invoke("interactive.delegate", %{"id" => id, "objective" => "finish me"})

      # Drive the child to a terminal status through its own durable record, which is
      # exactly what `Team.Server` verifies before it notifies anyone.
      finish_coding_task(result.task_id)

      terminal =
        wait_until(fn ->
          {:ok, events} =
            Methods.invoke("interactive.replay", %{"id" => id, "cursor" => 0, "limit" => 100})

          Enum.find(
            events,
            &(&1.type == :delegation and &1.payload["status"] not in [nil, "started"])
          )
        end)

      assert terminal.payload["delegation_id"] == result.delegation_id
      assert terminal.payload["status"] == "completed"
      assert is_binary(terminal.payload["result_digest"])
      # A digest, not the result: that is the child task's own record.
      refute terminal.payload["result"]

      assert {:ok, session} = Methods.invoke("interactive.info", %{"id" => id})
      assert session.delegations[result.delegation_id].status == :completed

      cleanup_delegation(result)
      retire_session(id)
    end
  end

  # Stops the coding coordinator and writes a completed checkpoint, which is the durable
  # source of truth `Team.Server.verified_coding_task/1` reads. Every field it compares
  # has to survive untouched or it reports an owner conflict instead of a completion.
  defp finish_coding_task(task_id) do
    case CodingTask.whereis(task_id) do
      pid when is_pid(pid) ->
        DynamicSupervisor.terminate_child(Ouroboros.Coding.TaskSupervisor, pid)

      _absent ->
        :ok
    end

    {:ok, task} = CodingStore.get(task_id)

    :ok =
      CodingStore.put(%{
        task
        | status: :completed,
          result: %{"summary" => "delegated work finished"},
          updated_at: DateTime.utc_now() |> DateTime.to_iso8601()
      })
  end

  defp cleanup_delegation(%{task_id: task_id}) do
    case CodingTask.whereis(task_id) do
      pid when is_pid(pid) ->
        DynamicSupervisor.terminate_child(Ouroboros.Coding.TaskSupervisor, pid)

      _absent ->
        :ok
    end

    case CodingStore.get(task_id) do
      {:ok, task} ->
        _ = CodingStore.put(%{task | status: :cancelled})
        _ = CodingStore.delete(task_id)

      _absent ->
        :ok
    end

    :ok
  end

  defp close_teams(workspace) do
    case Team.whereis(Team.workspace_team_id(workspace)) do
      pid when is_pid(pid) -> DynamicSupervisor.terminate_child(Ouroboros.Team.Supervisor, pid)
      _absent -> :ok
    end
  rescue
    _error -> :ok
  catch
    :exit, _reason -> :ok
  end

  defp wait_until(fun, attempts \\ 600)
  defp wait_until(_fun, 0), do: flunk("condition did not become true")

  defp wait_until(fun, attempts) do
    case fun.() do
      value when value in [false, nil] ->
        Process.sleep(25)
        wait_until(fun, attempts - 1)

      value ->
        value
    end
  end

  defp start_session(id, workspace, opts \\ []) do
    opts = Keyword.merge([id: id, provider: @provider, workspace: workspace], opts)
    assert {:ok, ref} = InteractiveSession.start(opts)
    ref
  end

  defp retire_session(id) do
    case Task.whereis(id) do
      pid when is_pid(pid) ->
        DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)

      _absent ->
        :ok
    end

    case Store.get(id) do
      {:ok, session} ->
        _ = Store.put(%{session | status: :cancelled})
        _ = Store.delete(id)

      _absent ->
        :ok
    end

    :ok
  end

  defp cleanup_sessions do
    Session.list()
    |> Enum.each(fn info ->
      unless SessionInfo.terminal?(info), do: Session.kill(info.session_id)
      _ = Session.prune(info.session_id)
    end)
  rescue
    _error -> :ok
  catch
    :exit, _reason -> :ok
  end

  defp unique_journal_dir do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-delegation-journal-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp map_or_empty(nil), do: %{}
  defp map_or_empty(value), do: Map.new(value)

  defp restore(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore(key, value), do: Application.put_env(:jido_harness, key, value)
end
