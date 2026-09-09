defmodule Ouroboros.InteractiveWorkspaceAdmissionTest do
  @moduledoc """
  A session never skips the workspace lease.

  `Ouroboros.Interactive.Task.admit_leased_workspace/1` asks two questions in order: is the
  manager running, and are roots configured. Only the second answering "no" makes an
  unleased session legal. Roots configured with no manager is a crashed authority
  boundary, and the session fails rather than running unleased — the property the deleted
  `test/coding_workspace_test.exs:246` asserted for the plane that is gone.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{Session, SessionInfo}
  alias Ouroboros.Interactive.State
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.HarnessAdapter
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Manager, as: WorkspaceManager

  @provider :ouroboros_test

  setup do
    cleanup_sessions()

    workspace =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-admission-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.mkdir_p!(workspace)

    previous = %{
      roots: Application.get_env(:ouroboros, :workspace_allowed_roots),
      providers: Application.get_env(:jido_harness, :providers),
      provider_config: Application.get_env(:jido_harness, :provider_config)
    }

    journal_dir = Path.join(workspace, "journal")

    Application.put_env(
      :jido_harness,
      :providers,
      Map.put(map_or_empty(previous.providers), @provider, HarnessAdapter)
    )

    Application.put_env(
      :jido_harness,
      :provider_config,
      Map.put(map_or_empty(previous.provider_config), @provider, %{
        test_pid: self(),
        retention: %{journal_dir: journal_dir}
      })
    )

    on_exit(fn ->
      cleanup_sessions()
      restore(:ouroboros, :workspace_allowed_roots, previous.roots)
      restore(:jido_harness, :providers, previous.providers)
      restore(:jido_harness, :provider_config, previous.provider_config)
      File.rm_rf(workspace)
    end)

    {:ok, workspace: workspace}
  end

  test "roots configured with no manager fails the session closed", %{workspace: workspace} do
    Application.put_env(:ouroboros, :workspace_allowed_roots, [workspace])
    refute is_pid(Process.whereis(WorkspaceManager))

    id = unique_id("no-manager")

    assert {:error, {:workspace_admission_failed, :workspace_manager_unavailable}} =
             InteractiveSession.start(id: id, provider: @provider, workspace: workspace)

    # The refusal is durable, not only a reply: a session nobody can account for would be
    # the same silence as one that ran unleased.
    assert {:ok, %State{status: :failed, workspace_lease_id: nil} = session} =
             InteractiveSession.info(Ouroboros.Interactive.Ref.new(id))

    assert session.error == {:workspace_admission_failed, :workspace_manager_unavailable}
  end

  test "the same start takes a lease once the manager is up", %{workspace: workspace} do
    Application.put_env(:ouroboros, :workspace_allowed_roots, [workspace])

    start_supervised!(
      {Workspace,
       allowed_roots: [workspace],
       name: WorkspaceManager,
       recover_reservations: false,
       id: {:admission_manager, System.unique_integer([:positive, :monotonic])}}
    )

    id = unique_id("with-manager")

    assert {:ok, ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: workspace)

    assert {:ok, %State{} = session} = InteractiveSession.info(ref)
    assert is_binary(session.workspace_lease_id)
    assert [%{root: leased}] = Workspace.list()
    assert leased == session.workspace

    assert :ok = InteractiveSession.close(ref)
  end

  test "no roots and no manager is the only unleased start there is", %{workspace: workspace} do
    Application.delete_env(:ouroboros, :workspace_allowed_roots)
    refute is_pid(Process.whereis(WorkspaceManager))

    id = unique_id("unconfigured")

    assert {:ok, ref} =
             InteractiveSession.start(id: id, provider: @provider, workspace: workspace)

    assert {:ok, %State{workspace_lease_id: nil}} = InteractiveSession.info(ref)
    assert :ok = InteractiveSession.close(ref)
  end

  # ---------------------------------------------------------------- helpers

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

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp map_or_empty(nil), do: %{}
  defp map_or_empty(value), do: Map.new(value)

  defp restore(app, key, nil), do: Application.delete_env(app, key)
  defp restore(app, key, value), do: Application.put_env(app, key, value)
end
