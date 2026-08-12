defmodule Ouroboros.CodingSessionEdgeTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.{Run, RunInfo, RunRequest}
  alias Ouroboros.Coding.{Event, Store, Task, TaskRef, TaskState}
  alias Ouroboros.CodingSession
  alias Ouroboros.Test.HarnessAdapter

  @provider :ouroboros_test

  defmodule StorageFixture do
    @moduledoc false

    def get_checkpoint(_key, opts), do: Keyword.fetch!(opts, :response)
  end

  setup do
    cleanup_test_runs()

    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)
    journal_dir = unique_journal_dir()
    id = unique_id("coding-edge")

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

  test "zero-timeout await distinguishes pending and terminal state, then coordinators retire", %{
    id: id
  } do
    {task_ref, adapter} = start_controlled_session(id, "exercise zero-timeout await")
    coordinator = Task.whereis(id)
    coordinator_monitor = Process.monitor(coordinator)

    assert {:error, :timeout} = CodingSession.await(task_ref, 0)
    assert Process.alive?(coordinator)

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "done"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok, %TaskState{status: :completed}} = CodingSession.await(task_ref, 2_000)

    assert_receive {:DOWN, ^coordinator_monitor, :process, ^coordinator, :normal}, 1_000
    assert_eventually(fn -> Task.whereis(id) == nil end)

    assert {:ok, %TaskState{status: :completed}} = CodingSession.await(task_ref, 0)
  end

  test "subscribe returns every retained event when the backlog exceeds ten thousand", %{id: id} do
    event_count = 10_001
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601()

    events =
      Enum.map(1..event_count, fn sequence ->
        %Event{
          id: "#{id}-#{sequence}",
          task_id: id,
          sequence: sequence,
          type: :output_text_delta,
          timestamp: timestamp,
          payload: %{"text" => Integer.to_string(sequence)}
        }
      end)

    assert {:ok, task} =
             TaskState.new(id, "retain a large event backlog",
               provider: @provider,
               workspace: File.cwd!(),
               event_limit: event_count
             )

    terminal_task = %{
      task
      | status: :completed,
        events: events,
        next_sequence: event_count + 1,
        result: %{status: :completed}
    }

    assert :ok = Store.create(terminal_task)

    assert {:ok, backlog} = CodingSession.subscribe(TaskRef.new(id), cursor: 0)
    assert length(backlog) == event_count
    assert hd(backlog).sequence == 1
    assert List.last(backlog).sequence == event_count
  end

  test "store initialization fails closed on unreadable and invalid checkpoints" do
    assert {:stop, {:coding_task_checkpoint_unreadable, :disk_corrupt}} =
             Store.init(storage: {StorageFixture, response: {:error, :disk_corrupt}})

    assert {:stop, :invalid_coding_task_checkpoint} =
             Store.init(storage: {StorageFixture, response: {:ok, %{"bad" => :checkpoint}}})
  end

  test "task state rejects unknown, inline environment, MCP, and unsafe provider options" do
    base = [provider: @provider, workspace: File.cwd!()]

    assert {:error, {:unknown_option, :surprise}} =
             TaskState.new(unique_id("unknown"), "objective", base ++ [surprise: true])

    assert {:error, :inline_environment_not_persisted} =
             TaskState.new(unique_id("env"), "objective", base ++ [env: %{}])

    assert {:error, :inline_environment_not_persisted} =
             TaskState.new(unique_id("env-mode"), "objective", base ++ [env_mode: nil])

    assert {:error, :inline_mcp_config_not_persisted} =
             TaskState.new(unique_id("mcp"), "objective", base ++ [mcp_config: %{}])

    assert {:error, {:unsafe_provider_options, @provider}} =
             TaskState.new(
               unique_id("provider-options"),
               "objective",
               base ++ [provider_options: %{arbitrary_argv: ["--dangerous"]}]
             )
  end

  test "public task state summarizes but never exposes private request material" do
    assert {:ok, task} =
             TaskState.new(unique_id("public"), "objective",
               provider: :codex,
               workspace: File.cwd!(),
               system_prompt: "PRIVATE SYSTEM PROMPT",
               attachments: ["/private/attachment.png"],
               add_dirs: ["/private/source"],
               provider_options: %{web_search_enabled: true}
             )

    public = TaskState.public(task)

    assert public.options.has_system_prompt
    assert public.options.has_provider_options
    assert public.options.attachment_count == 1
    assert public.options.additional_directory_count == 1

    refute Map.has_key?(public.options, :system_prompt)
    refute Map.has_key?(public.options, :provider_options)
    refute Map.has_key?(public.options, :attachments)
    refute Map.has_key?(public.options, :add_dirs)

    rendered = inspect(public)
    refute rendered =~ "PRIVATE SYSTEM PROMPT"
    refute rendered =~ "/private/attachment.png"
    refute rendered =~ "/private/source"
    refute rendered =~ "web_search_enabled"
  end

  defp start_controlled_session(id, objective) do
    assert {:ok, %TaskRef{id: ^id} = task_ref} =
             CodingSession.start(objective,
               id: id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, _run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^id}}, adapter},
                   1_000

    {task_ref, adapter}
  end

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
      "ouroboros-coding-edge-test-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp assert_eventually(fun, attempts \\ 100)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(10)
      assert_eventually(fun, attempts - 1)
    end
  end

  defp unique_id(prefix),
    do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp empty_map_if_nil(nil), do: %{}
  defp empty_map_if_nil(value), do: Map.new(value)

  defp restore_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_env(key, value), do: Application.put_env(:jido_harness, key, value)
end
