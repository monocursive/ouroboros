defmodule Ouroboros.CodingSessionTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.{Run, RunInfo, RunRequest}
  alias Ouroboros.Coding.{Event, Task, TaskRef, TaskState}
  alias Ouroboros.CodingSession
  alias Ouroboros.Test.HarnessAdapter

  @provider :ouroboros_test

  setup do
    cleanup_test_runs()

    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)
    journal_dir = unique_journal_dir()
    id = unique_id("coding")

    providers =
      previous_providers
      |> empty_map_if_nil()
      |> Map.put(@provider, HarnessAdapter)

    provider_config =
      previous_provider_config
      |> empty_map_if_nil()
      |> Map.put(@provider, %{
        test_pid: self(),
        retention: %{journal_dir: journal_dir}
      })

    Application.put_env(:jido_harness, :providers, providers)
    Application.put_env(:jido_harness, :provider_config, provider_config)

    on_exit(fn ->
      terminate_coordinator(id)
      cleanup_test_runs()
      restore_env(:providers, previous_providers)
      restore_env(:provider_config, previous_provider_config)
      File.rm_rf(journal_dir)
    end)

    {:ok, id: id}
  end

  test "persists progress, atomically subscribes, replays by cursor, and awaits success", %{
    id: id
  } do
    {task_ref, _run_id, adapter} = start_controlled_session(id, "inspect the workspace")

    assert {:ok, backlog} = CodingSession.subscribe(task_ref, cursor: 0)
    assert_ordered(backlog)

    assert :ok = HarnessAdapter.emit(adapter, :output_text_delta, %{"text" => "working"})

    assert_receive {:ouroboros_coding_event, ^id,
                    %Event{type: :output_text_delta, payload: %{"text" => "working"}} = progress},
                   1_000

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "done"})

    assert :ok =
             HarnessAdapter.emit(adapter, :usage, %{
               "input_tokens" => 3,
               "output_tokens" => 1
             })

    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok, %TaskState{} = completed} = CodingSession.await(task_ref, 2_000)
    assert completed.status == :completed
    assert completed.result.status == :completed
    assert completed.result.text == "done"
    assert completed.result.usage == %{"input_tokens" => 3, "output_tokens" => 1}
    assert completed.provider_session_id == "ouroboros-test-session"

    assert {:ok, events} = CodingSession.replay(task_ref, cursor: 0, limit: 100)
    assert_ordered(events)

    assert Enum.map(events, & &1.type) == [
             :run_started,
             :output_text_delta,
             :output_text_final,
             :usage,
             :run_completed
           ]

    assert Enum.count(events, &Event.terminal?/1) == 1
    assert Enum.map(events, & &1.harness_sequence) == Enum.to_list(1..5)

    assert {:ok, after_progress} =
             CodingSession.replay(task_ref, cursor: progress.sequence, limit: 100)

    assert Enum.all?(after_progress, &(&1.sequence > progress.sequence))
    assert Enum.map(after_progress, & &1.type) == [:output_text_final, :usage, :run_completed]
    assert :ok = CodingSession.unsubscribe(task_ref)
  end

  test "reattaches after coordinator death without starting a duplicate Harness run", %{id: id} do
    {task_ref, run_id, adapter} = start_controlled_session(id, "survive coordinator restart")
    coordinator = Task.whereis(id)
    monitor = Process.monitor(coordinator)

    Process.exit(coordinator, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^coordinator, :killed}, 1_000

    replacement =
      assert_eventually(fn ->
        case Task.whereis(id) do
          pid when is_pid(pid) and pid != coordinator -> pid
          _ -> false
        end
      end)

    assert is_pid(replacement)

    assert {:ok, %TaskState{harness_run_id: ^run_id, status: :running}} =
             CodingSession.info(task_ref)

    refute_receive {:ouroboros_test_adapter_started, _duplicate_run,
                    %RunRequest{metadata: %{ouroboros_task_id: ^id}}, _duplicate_adapter},
                   100

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "reattached"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok, %TaskState{status: :completed} = completed} =
             CodingSession.await(task_ref, 2_000)

    assert completed.result.run_id == run_id
    assert completed.result.text == "reattached"

    refute_receive {:ouroboros_test_adapter_started, _duplicate_run,
                    %RunRequest{metadata: %{ouroboros_task_id: ^id}}, _duplicate_adapter},
                   100
  end

  test "await timeout leaves the detached run alive and does not cancel it", %{id: id} do
    {task_ref, run_id, adapter} =
      start_controlled_session(id, "keep running after waiter timeout")

    assert {:error, :timeout} = CodingSession.await(task_ref, 25)
    assert Process.alive?(adapter)

    assert {:ok, %TaskState{status: :running, harness_run_id: ^run_id}} =
             CodingSession.info(task_ref)

    refute_receive {:ouroboros_test_adapter_cancelled, ^run_id}, 100

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "still alive"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok, %TaskState{status: :completed} = completed} =
             CodingSession.await(task_ref, 2_000)

    assert completed.result.text == "still alive"
  end

  test "cancellation reaches one durable cancelled terminal event", %{id: id} do
    {task_ref, run_id, _adapter} = start_controlled_session(id, "cancel deterministically")

    assert :ok = CodingSession.cancel(task_ref)
    assert_receive {:ouroboros_test_adapter_cancelled, ^run_id}, 1_000

    assert {:ok, %TaskState{status: :cancelled} = cancelled} =
             CodingSession.await(task_ref, 2_000)

    assert cancelled.result.status == :cancelled

    assert {:ok, events} = CodingSession.replay(task_ref, cursor: 0, limit: 100)
    assert Enum.count(events, &(&1.type == :run_cancelled)) == 1
    assert Enum.count(events, &Event.terminal?/1) == 1
    assert List.last(events).type == :run_cancelled
  end

  defp start_controlled_session(id, objective) do
    assert {:ok, %TaskRef{id: ^id} = task_ref} =
             CodingSession.start(objective,
               id: id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^id}} = request, adapter},
                   1_000

    assert request.prompt != objective
    assert Ouroboros.Test.Prompt.wrapped?(request.prompt, objective)
    assert request.approval_mode == :prompt
    assert request.sandbox_mode == :workspace_write

    assert_eventually(fn ->
      match?(
        {:ok, %TaskState{status: :running, harness_run_id: ^run_id}},
        CodingSession.info(task_ref)
      )
    end)

    {task_ref, run_id, adapter}
  end

  defp assert_ordered(events) do
    sequences = Enum.map(events, & &1.sequence)
    assert sequences == Enum.sort(sequences)
    assert sequences == Enum.uniq(sequences)
  end

  defp assert_eventually(fun, attempts \\ 200)

  defp assert_eventually(fun, attempts) when attempts > 0 do
    case fun.() do
      false ->
        Process.sleep(10)
        assert_eventually(fun, attempts - 1)

      nil ->
        Process.sleep(10)
        assert_eventually(fun, attempts - 1)

      result ->
        result
    end
  end

  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp cleanup_test_runs do
    @provider
    |> then(&Run.list(providers: [&1]))
    |> Enum.each(fn info ->
      unless RunInfo.terminal?(info) do
        _ = Run.cancel(info.run_id)
        _ = Run.await(info.run_id, 1_000)
      end

      _ = Run.prune(info.run_id)
    end)
  end

  defp terminate_coordinator(id) do
    case Task.whereis(id) do
      pid when is_pid(pid) ->
        DynamicSupervisor.terminate_child(Ouroboros.Coding.TaskSupervisor, pid)

      nil ->
        :ok
    end
  end

  defp unique_journal_dir do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-coding-test-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix),
    do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp empty_map_if_nil(nil), do: %{}
  defp empty_map_if_nil(value), do: Map.new(value)

  defp restore_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_env(key, value), do: Application.put_env(:jido_harness, key, value)
end
