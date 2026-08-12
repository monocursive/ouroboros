defmodule Ouroboros.CodingWorkspaceTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.{Run, RunInfo, RunRequest}
  alias Ouroboros.Coding.{Task, TaskRef, TaskState}
  alias Ouroboros.CodingSession
  alias Ouroboros.Test.HarnessAdapter
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Manager, as: WorkspaceManager

  @provider :ouroboros_test

  setup do
    cleanup_test_runs()

    base =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-coding-workspace-#{System.unique_integer([:positive, :monotonic])}"
      )

    allowed = Path.join(base, "allowed")
    nested = Path.join(allowed, "nested")
    outside = Path.join(base, "outside")
    File.mkdir_p!(nested)
    File.mkdir_p!(outside)

    start_supervised!(
      {Workspace,
       allowed_roots: [allowed],
       name: WorkspaceManager,
       id: {:coding_workspace_manager, System.unique_integer([:positive, :monotonic])}}
    )

    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)
    journal_dir = unique_journal_dir()

    providers = Map.put(empty_map_if_nil(previous_providers), @provider, HarnessAdapter)

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
      cleanup_test_runs()
      restore_env(:providers, previous_providers)
      restore_env(:provider_config, previous_provider_config)
      File.rm_rf(journal_dir)
      File.rm_rf(base)
    end)

    {:ok, allowed: allowed, nested: nested, outside: outside}
  end

  test "outside and symlink-escaped workspaces fail before Harness starts", context do
    %{allowed: allowed, outside: outside} = context
    outside_id = unique_id("outside")
    escape_id = unique_id("escape")
    escape = Path.join(allowed, "escape")
    File.ln_s!(outside, escape)

    assert {:error,
            {:workspace_admission_failed,
             {:workspace_outside_allowed_roots, _canonical_outside, _roots}}} =
             CodingSession.start("must not run",
               id: outside_id,
               provider: @provider,
               workspace: outside
             )

    assert {:error, {:workspace_admission_failed, _symlink_rejection}} =
             CodingSession.start("must not follow escape",
               id: escape_id,
               provider: @provider,
               workspace: escape
             )

    refute_receive {:ouroboros_test_adapter_started, _run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^outside_id}}, _adapter},
                   100

    refute_receive {:ouroboros_test_adapter_started, _run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^escape_id}}, _adapter},
                   100

    assert {:ok, %TaskState{status: :failed, harness_run_id: nil}} =
             CodingSession.info(TaskRef.new(outside_id))

    assert {:ok, %TaskState{status: :failed, harness_run_id: nil}} =
             CodingSession.info(TaskRef.new(escape_id))
  end

  test "workspace mode defaults from sandbox policy and rejects unknown modes", %{nested: nested} do
    assert {:ok, %TaskState{workspace_mode: :shared_read}} =
             TaskState.new(unique_id("read-default"), "read", workspace: nested)

    assert {:ok, %TaskState{workspace_mode: :exclusive}} =
             TaskState.new(unique_id("write-default"), "write",
               workspace: nested,
               sandbox_mode: :workspace_write
             )

    assert {:error, {:invalid_workspace_mode, :write}} =
             TaskState.new(unique_id("invalid-mode"), "invalid",
               workspace: nested,
               workspace_mode: :write
             )
  end

  test "exclusive overlap is rejected and cancellation releases the lease", %{nested: nested} do
    first_id = unique_id("writer")
    second_id = unique_id("conflict")

    {first_ref, run_id, _adapter} =
      start_controlled(first_id, nested, workspace_mode: :exclusive)

    assert {:error, {:workspace_admission_failed, {:workspace_conflict, conflicts}}} =
             CodingSession.start("conflicting writer",
               id: second_id,
               provider: @provider,
               workspace: nested,
               workspace_mode: :exclusive
             )

    assert Enum.any?(conflicts, &(&1.task_id == first_id and &1.mode == :exclusive))

    refute_receive {:ouroboros_test_adapter_started, _duplicate_run,
                    %RunRequest{metadata: %{ouroboros_task_id: ^second_id}}, _adapter},
                   100

    assert :ok = CodingSession.cancel(first_ref)
    assert_receive {:ouroboros_test_adapter_cancelled, ^run_id}, 1_000
    assert {:ok, %TaskState{status: :cancelled}} = CodingSession.await(first_ref, 2_000)
    assert_eventually(fn -> Workspace.list() == [] end)
  end

  test "canonical lease metadata is public and completion releases it", %{nested: nested} do
    id = unique_id("complete")
    {task_ref, _run_id, adapter} = start_controlled(id, nested)

    assert {:ok,
            %TaskState{
              workspace: canonical,
              workspace_mode: :shared_read,
              workspace_lease_id: lease_id
            }} = CodingSession.info(task_ref)

    assert is_binary(lease_id)

    assert [%{id: ^lease_id, root: ^canonical, task_id: ^id, mode: :shared_read}] =
             Workspace.list()

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "done"})
    assert :ok = HarnessAdapter.finish(adapter)
    assert {:ok, %TaskState{status: :completed}} = CodingSession.await(task_ref, 2_000)
    assert_eventually(fn -> Workspace.list() == [] end)
  end

  test "coordinator crash reacquires before reattach and starts no duplicate run", %{
    nested: nested
  } do
    id = unique_id("reattach")
    {task_ref, run_id, adapter} = start_controlled(id, nested, workspace_mode: :exclusive)
    coordinator = Task.whereis(id)
    {:ok, before_crash} = CodingSession.info(task_ref)

    Process.exit(coordinator, :kill)

    replacement =
      assert_eventually(fn ->
        case Task.whereis(id) do
          pid when is_pid(pid) and pid != coordinator -> pid
          _other -> false
        end
      end)

    assert is_pid(replacement)

    assert {:ok,
            %TaskState{
              status: :running,
              harness_run_id: ^run_id,
              workspace_lease_id: replacement_lease_id
            }} = CodingSession.info(task_ref)

    assert replacement_lease_id != before_crash.workspace_lease_id

    refute_receive {:ouroboros_test_adapter_started, _duplicate_run,
                    %RunRequest{metadata: %{ouroboros_task_id: ^id}}, _duplicate_adapter},
                   100

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "reattached"})
    assert :ok = HarnessAdapter.finish(adapter)
    assert {:ok, %TaskState{status: :completed}} = CodingSession.await(task_ref, 2_000)
    assert_eventually(fn -> Workspace.list() == [] end)
  end

  defp start_controlled(id, workspace, extra_opts \\ []) do
    opts =
      [id: id, provider: @provider, workspace: workspace]
      |> Keyword.merge(extra_opts)

    assert {:ok, %TaskRef{id: ^id} = task_ref} = CodingSession.start("controlled task", opts)

    assert_receive {:ouroboros_test_adapter_started, run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^id}}, adapter},
                   1_000

    assert_eventually(fn ->
      match?(
        {:ok, %TaskState{status: :running, harness_run_id: ^run_id}},
        CodingSession.info(task_ref)
      )
    end)

    {task_ref, run_id, adapter}
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

  defp assert_eventually(fun, attempts \\ 200)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    case fun.() do
      result when result in [false, nil] ->
        Process.sleep(10)
        assert_eventually(fun, attempts - 1)

      result ->
        result
    end
  end

  defp unique_journal_dir do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-coding-workspace-journal-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix),
    do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp empty_map_if_nil(nil), do: %{}
  defp empty_map_if_nil(value), do: Map.new(value)

  defp restore_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_env(key, value), do: Application.put_env(:jido_harness, key, value)
end
