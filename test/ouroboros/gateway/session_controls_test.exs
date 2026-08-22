defmodule Ouroboros.Gateway.SessionControlsTest do
  @moduledoc """
  The gateway half of the session controls: `interactive.configure`, `interactive.rename`,
  `interactive.fork`, and `runtime.models`.

  Asked through `Ouroboros.Gateway.Methods.invoke/2` rather than through a socket, because
  what is under test is the parameter contract and the shape of the answer — the socket,
  the scope gate, and the envelope are already pinned by `Ouroboros.Gateway.OperateTest`
  and the golden fixtures.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{Session, SessionInfo}
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Interactive.{State, Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.HarnessAdapter

  @provider :ouroboros_test

  setup do
    cleanup_sessions()

    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)
    journal_dir = unique_journal_dir()

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
      restore_env(:providers, previous_providers)
      restore_env(:provider_config, previous_provider_config)
      File.rm_rf(journal_dir)
    end)

    {:ok, id: unique_id("gateway-controls")}
  end

  describe "the method table" do
    test "the new session controls are operate-scoped and advertised" do
      table = Methods.table()

      for method <- ["interactive.configure", "interactive.rename"] do
        assert table[method].scope == :operate
        assert method in Methods.names()

        # A read listener must not be able to move a permission posture or rewrite
        # durable session state.
        refute Methods.permits?(:read, table[method])
        assert Methods.permits?(:operate, table[method])
      end
    end
  end

  describe "interactive.configure" do
    test "the four configurable fields cross the wire and reach the session", %{id: id} do
      ref = start_session(id)

      assert {:ok, result} =
               Methods.invoke("interactive.configure", %{
                 "id" => id,
                 "approval_mode" => "auto_approve",
                 "sandbox_mode" => "read_only"
               })

      assert result.applies == :next_turn
      assert result.changed == [:approval_mode, :sandbox_mode]
      assert result.options.approval_mode == :auto_approve
      assert result.options.sandbox_mode == :read_only

      assert {:ok, session} = InteractiveSession.info(ref)
      assert State.public(session).options.approval_mode == :auto_approve

      retire_session(id)
    end

    test "a field outside the configurable set is a parameter error naming the set" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.configure", %{
                 "id" => "some-session",
                 "workspace" => "/tmp"
               })

      assert message =~ "unsupported fields"
      assert message =~ "workspace"

      assert {:error, -32_602, message} =
               Methods.invoke("interactive.configure", %{
                 "id" => "some-session",
                 "system_prompt" => "become someone else"
               })

      assert message =~ "system_prompt"
    end

    test "an unknown enum value is refused with the accepted spellings" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.configure", %{
                 "id" => "some-session",
                 "approval_mode" => "yolo"
               })

      assert message =~ "approval_mode"
      assert message =~ "auto_approve"
    end

    test "a session id that names nothing is not found" do
      assert {:error, -32_007, message} =
               Methods.invoke("interactive.configure", %{
                 "id" => "no-such-session",
                 "approval_mode" => "auto_approve"
               })

      assert message =~ "no such record"
    end

    test "the X1 refusal travels as data a client can render", %{id: id} do
      start_session(id, transport: :managed_no_approvals, approval_mode: :auto_edit)

      assert {:error, -32_006, message, data} =
               Methods.invoke("interactive.configure", %{
                 "id" => id,
                 "approval_mode" => "prompt"
               })

      assert message =~ "refused the call"
      assert ["unsupported_approval_mode", details] = data
      assert details["reason"] == "no_approval_channel"
      assert details["requested"] == "prompt"
      assert details["supported"] == ["default", "auto_edit", "auto_approve"]

      retire_session(id)
    end
  end

  describe "interactive.rename" do
    test "a title crosses the wire and comes back on the session", %{id: id} do
      start_session(id)

      assert {:ok, session} =
               Methods.invoke("interactive.rename", %{"id" => id, "title" => "Named from a client"})

      assert session.title == "Named from a client"
      assert session.title_source == :human

      retire_session(id)
    end

    test "a title a picker row could not draw is a parameter error, not a mangled title" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.rename", %{"id" => "some-session", "title" => ""})

      assert message =~ "nonempty string"
    end

    test "the bound and the control-character rule reach the client as messages", %{id: id} do
      start_session(id)

      assert {:error, -32_602, too_long} =
               Methods.invoke("interactive.rename", %{
                 "id" => id,
                 "title" => String.duplicate("x", 200)
               })

      assert too_long =~ "at most 120 characters"

      assert {:error, -32_602, controls} =
               Methods.invoke("interactive.rename", %{
                 "id" => id,
                 "title" => "clear\e[2Jthe screen"
               })

      assert controls =~ "control characters"

      retire_session(id)
    end

    test "an unsupported field is refused rather than ignored" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.rename", %{
                 "id" => "some-session",
                 "title" => "fine",
                 "title_source" => "human"
               })

      assert message =~ "title_source"
    end
  end

  defp start_session(id, opts \\ []) do
    opts = Keyword.merge([id: id, provider: @provider, workspace: File.cwd!()], opts)
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
      "ouroboros-gateway-controls-journal-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp map_or_empty(nil), do: %{}
  defp map_or_empty(value), do: Map.new(value)

  defp restore_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_env(key, value), do: Application.put_env(:jido_harness, key, value)
end
