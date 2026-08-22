defmodule Ouroboros.Gateway.WorkspaceExecTest do
  @moduledoc """
  B7's runtime half: `workspace.exec`, the one verb in this gateway that runs a command.

  Everything under test here is a boundary rather than a feature. Who may run a command
  (a session already at `auto_approve`, or a permission rule that says so, and nobody
  else); what is written down before it runs; what the transcript and the next turn's
  runtime envelope are told afterwards; and what happens to output too large to carry.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{Session, SessionInfo}
  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Control.Permissions
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Interactive.{Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Runtime.Exposure
  alias Ouroboros.Test.HarnessAdapter

  @provider :ouroboros_test

  setup do
    cleanup_sessions()

    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)
    previous_data_dir = Application.get_env(:ouroboros, :data_dir)
    journal_dir = unique_journal_dir()

    root = Path.join(System.tmp_dir!(), "workspace-exec-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(workspace)
    File.write!(Path.join(workspace, "marker.txt"), "hello from the workspace\n")
    data_dir = Path.join(root, "data")
    File.mkdir_p!(data_dir)
    Application.put_env(:ouroboros, :data_dir, data_dir)

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
      restore(:jido_harness, :providers, previous_providers)
      restore(:jido_harness, :provider_config, previous_provider_config)
      restore(:ouroboros, :data_dir, previous_data_dir)
      File.rm_rf(journal_dir)
      File.rm_rf(root)
    end)

    {:ok, id: unique_id("exec"), workspace: workspace, data_dir: data_dir}
  end

  describe "the method table" do
    test "workspace.exec is operate-scoped, advertised, and admits an unknown outcome" do
      entry = Methods.table()["workspace.exec"]

      assert entry.scope == :operate
      assert entry.outcome == :unknown
      assert "workspace.exec" in Methods.names()
      refute Methods.permits?(:read, entry)
      assert Methods.permits?(:operate, entry)
    end

    test "its ceiling is the runner's own, so a killed task never orphans an entry" do
      assert Methods.table()["workspace.exec"].timeout == 10 * 60 * 1_000
    end
  end

  describe "the parameter contract" do
    test "an unsupported field is refused rather than ignored" do
      assert {:error, -32_602, message} =
               Methods.invoke("workspace.exec", %{
                 "id" => "s",
                 "command" => "true",
                 "cwd" => "/tmp"
               })

      assert message =~ "cwd"
    end

    test "a blank command is a parameter error" do
      assert {:error, -32_602, message} =
               Methods.invoke("workspace.exec", %{"id" => "s", "command" => ""})

      assert message =~ "nonempty string"
    end

    test "a session id that names nothing is not found" do
      assert {:error, -32_007, _message} =
               Methods.invoke("workspace.exec", %{"id" => "nope", "command" => "true"})
    end
  end

  describe "permitted by mode" do
    test "an auto_approve session runs the command and reports status and elapsed",
         %{id: id, workspace: workspace} do
      start_session(id, workspace, approval_mode: :auto_approve)

      assert {:ok, result} =
               Methods.invoke("workspace.exec", %{"id" => id, "command" => "cat marker.txt"})

      assert result.exit_status == 0
      assert result.output =~ "hello from the workspace"
      assert result.timed_out == false
      assert is_integer(result.duration_ms)
      assert result.cwd == workspace
      assert is_binary(result.effect_id)
      assert String.starts_with?(result.effect_id, "shell-")

      # The command ran in the session's admitted workspace, not the runtime's cwd.
      assert {:ok, pwd} = Methods.invoke("workspace.exec", %{"id" => id, "command" => "pwd"})
      assert String.trim(pwd.output) == resolved(workspace)

      retire_session(id)
    end

    test "a non-zero exit is a result, not a fault", %{id: id, workspace: workspace} do
      start_session(id, workspace, approval_mode: :auto_approve)

      assert {:ok, result} =
               Methods.invoke("workspace.exec", %{"id" => id, "command" => "exit 3"})

      assert result.exit_status == 3

      retire_session(id)
    end
  end

  describe "refused, with the rule that would allow it" do
    test "a session that is not auto_approve is refused and told what would work",
         %{id: id, workspace: workspace} do
      start_session(id, workspace, approval_mode: :auto_edit)

      assert {:error, -32_006, message, data} =
               Methods.invoke("workspace.exec", %{"id" => id, "command" => "git status --short"})

      assert message =~ "refused the call"
      assert ["shell_refused", details] = data
      assert details["reason"] == "no_rule"
      assert details["approval_mode"] == "auto_edit"
      assert details["session_id"] == id

      # The whole point of the refusal: it names the rule, in the engine's own language,
      # that `permissions.add` would take verbatim.
      assert details["suggested_rule"] == "Bash(git status *)"
      assert details["message"] =~ "permissions.add"

      retire_session(id)
    end

    test "a refused command writes nothing to the ledger", %{id: id, workspace: workspace} do
      start_session(id, workspace, approval_mode: :prompt)

      before = shell_entries(id)

      assert {:error, -32_006, _message, ["shell_refused", _details]} =
               Methods.invoke("workspace.exec", %{"id" => id, "command" => "echo nope"})

      assert shell_entries(id) == before

      retire_session(id)
    end

    test "a deny rule refuses even where an allow rule also matches",
         %{id: id, workspace: workspace} do
      start_session(id, workspace, approval_mode: :prompt)

      {:ok, allow} = add_rule(workspace, "Bash(echo *)", :allow)
      {:ok, deny} = add_rule(workspace, "Bash(echo denied)", :deny)

      assert {:error, -32_006, _message, ["shell_refused", details]} =
               Methods.invoke("workspace.exec", %{"id" => id, "command" => "echo denied"})

      assert details["reason"] == "rule_denied"
      assert details["denied_by"]["pattern"] == "Bash(echo denied)"
      assert details["message"] =~ "deny beats every allow"

      remove_rule(deny)
      remove_rule(allow)
      retire_session(id)
    end
  end

  describe "permitted by rule" do
    test "a workspace allow rule lets a prompt-mode session run exactly that command",
         %{id: id, workspace: workspace} do
      start_session(id, workspace, approval_mode: :prompt)
      {:ok, rule} = add_rule(workspace, "Bash(echo *)", :allow)

      assert {:ok, result} =
               Methods.invoke("workspace.exec", %{"id" => id, "command" => "echo allowed"})

      assert result.exit_status == 0
      assert result.output =~ "allowed"

      # And only that command: the rule is an allowlist, not a mode change.
      assert {:error, -32_006, _message, ["shell_refused", details]} =
               Methods.invoke("workspace.exec", %{"id" => id, "command" => "cat marker.txt"})

      assert details["suggested_rule"] == "Bash(cat *)"

      remove_rule(rule)
      retire_session(id)
    end
  end

  describe "the ledger" do
    test "the entry exists before the command runs and is settled after",
         %{id: id, workspace: workspace} do
      start_session(id, workspace, approval_mode: :auto_approve)

      # A command that blocks until this test lets it finish, so the started entry can be
      # observed while the command is still running.
      gate = Path.join(workspace, "gate")

      task =
        Elixir.Task.async(fn ->
          Methods.invoke("workspace.exec", %{
            "id" => id,
            "command" => "while [ ! -f gate ]; do sleep 0.02; done; echo released"
          })
        end)

      started =
        wait_until(fn ->
          case shell_entries(id) do
            [%{status: :started} = entry] -> entry
            _other -> false
          end
        end)

      # Content-minimised: the digest and the directory, never the command text.
      assert started.attempt.command_digest ==
               Ouroboros.Workspace.Exec.digest(
                 "while [ ! -f gate ]; do sleep 0.02; done; echo released"
               )

      assert started.attempt.cwd == workspace
      assert started.attempt.session_id == id
      assert started.attempt.node == node()
      refute Map.has_key?(started.attempt, :command)
      assert started.authority.reason == "auto_approve"

      File.write!(gate, "go")
      assert {:ok, result} = Elixir.Task.await(task, 30_000)
      assert result.exit_status == 0

      settled = wait_until(fn -> Enum.find(shell_entries(id), &(&1.status == :ok)) end)
      assert settled.id == started.id
      assert settled.result.exit_status == 0
      assert settled.result.spilled == false
      assert settled.result.timed_out == false
      assert is_binary(settled.settled_at)

      retire_session(id)
    end

    test "a failing command settles as failed rather than being lost",
         %{id: id, workspace: workspace} do
      start_session(id, workspace, approval_mode: :auto_approve)

      assert {:ok, _result} =
               Methods.invoke("workspace.exec", %{"id" => id, "command" => "exit 9"})

      settled = wait_until(fn -> Enum.find(shell_entries(id), &(&1.status == :failed)) end)
      assert settled.result.exit_status == 9

      retire_session(id)
    end
  end

  describe "bounded output" do
    test "output past 30 KiB is elided inline and spilled to a private file",
         %{id: id, workspace: workspace, data_dir: data_dir} do
      start_session(id, workspace, approval_mode: :auto_approve)

      # 40_000 lines of 'x' — comfortably past the inline bound, cheaply produced.
      command = "awk 'BEGIN { for (i = 0; i < 40000; i++) print \"xxxxxxxxxx\" }'"

      assert {:ok, result} = Methods.invoke("workspace.exec", %{"id" => id, "command" => command})

      assert result.output_bytes > 30 * 1024
      assert byte_size(result.output) < result.output_bytes
      assert result.output =~ "bytes elided"

      assert is_binary(result.spilled)
      assert String.starts_with?(result.spilled, data_dir)
      assert File.exists?(result.spilled)
      assert byte_size(File.read!(result.spilled)) == result.output_bytes

      # 0600: the spill is the whole output of a command run in someone's workspace.
      assert {:ok, %File.Stat{mode: mode}} = File.stat(result.spilled)
      assert Bitwise.band(mode, 0o777) == 0o600

      retire_session(id)
    end
  end

  describe "the transcript and the next turn" do
    test "the command appears as a runtime-native provider_event carrying no command text",
         %{id: id, workspace: workspace} do
      start_session(id, workspace, approval_mode: :auto_approve)

      assert {:ok, result} =
               Methods.invoke("workspace.exec", %{"id" => id, "command" => "echo transcript-me"})

      assert {:ok, events} =
               Methods.invoke("interactive.replay", %{"id" => id, "cursor" => 0, "limit" => 100})

      event =
        Enum.find(
          events,
          &(&1.type == :provider_event and &1.payload["kind"] == "operator_shell")
        )

      assert event, "the operator command is not on the session's log"
      assert event.payload["command_digest"] == result.command_digest
      assert event.payload["exit_status"] == 0
      assert event.payload["output_excerpt"] =~ "transcript-me"
      assert event.payload["effect_id"] == result.effect_id
      refute event.payload["command"]

      retire_session(id)
    end

    test "the runtime envelope carries the last three commands, and only three",
         %{id: id, workspace: workspace} do
      start_session(id, workspace, approval_mode: :auto_approve)

      for n <- 1..4 do
        assert {:ok, _result} =
                 Methods.invoke("workspace.exec", %{
                   "id" => id,
                   "command" => "echo command-number-#{n}"
                 })
      end

      {:ok, session} = Store.get(id)
      capture = session.runtime_snapshot

      assert Exposure.valid_capture?(capture)
      assert capture.envelope =~ "operator_commands:"

      # The newest three, oldest dropped.
      refute capture.envelope =~ "command-number-1"
      assert capture.envelope =~ "command-number-2"
      assert capture.envelope =~ "command-number-3"
      assert capture.envelope =~ "command-number-4"
      assert capture.envelope =~ "exit=0"

      retire_session(id)
    end

    test "a session with runtime_exposure disabled keeps no envelope at all",
         %{id: id, workspace: workspace} do
      start_session(id, workspace, approval_mode: :auto_approve, runtime_exposure: false)

      assert {:ok, _result} =
               Methods.invoke("workspace.exec", %{"id" => id, "command" => "echo quiet"})

      {:ok, session} = Store.get(id)
      assert session.runtime_snapshot == nil

      retire_session(id)
    end
  end

  describe "Exposure's own bounds" do
    test "an excerpt is redacted, stripped of control characters, and byte-bounded" do
      long = String.duplicate("y", 4_000)

      capture =
        Exposure.capture(
          operator_shell: [
            %{command_digest: "abc", exit_status: 0, excerpt: "before\e[2Jafter"},
            %{command_digest: "def", exit_status: 1, excerpt: long}
          ]
        )

      assert Exposure.valid_capture?(capture)
      # ESC is a control character and goes; the bytes after it were never control
      # characters and are left as the literal text they are.
      refute capture.envelope =~ "\e"
      assert capture.envelope =~ "before [2Jafter"
      # 512 bytes, not four thousand.
      refute capture.envelope =~ String.duplicate("y", 1_000)
      assert capture.envelope =~ String.duplicate("y", 500)
    end

    test "more than three commands are trimmed to the newest three by Exposure itself" do
      commands =
        for n <- 1..6, do: %{command_digest: "d#{n}", exit_status: 0, excerpt: "excerpt-#{n}"}

      capture = Exposure.capture(operator_shell: commands)

      refute capture.envelope =~ "excerpt-3"
      assert capture.envelope =~ "excerpt-4"
      assert capture.envelope =~ "excerpt-6"
    end

    test "no commands means no heading, rather than an empty one" do
      refute Exposure.capture([]).envelope =~ "operator_commands"
      refute Exposure.capture(operator_shell: []).envelope =~ "operator_commands"
    end
  end

  defp shell_entries(session_id) do
    case EffectLedger.list(effect: :operator_shell, limit: 100) do
      {:ok, entries} -> Enum.filter(entries, &(&1.attempt.session_id == session_id))
      _unavailable -> []
    end
  end

  # `pwd` prints the directory with every symlink resolved, which the string a session
  # was started with need not be — `/var` is a link to `/private/var` on macOS.
  defp resolved(path) do
    case Ouroboros.Workspace.Path.canonicalize(path) do
      {:ok, canonical} -> canonical
      {:error, _reason} -> path
    end
  end

  defp add_rule(workspace, pattern, decision) do
    Permissions.add(%{
      scope: :workspace,
      decision: decision,
      pattern: pattern,
      workspace: workspace
    })
  end

  defp remove_rule({:ok, rule}), do: remove_rule(rule)
  defp remove_rule(%{id: id}), do: Permissions.remove(:workspace, id)

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

  defp start_session(id, workspace, opts) do
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
      "ouroboros-workspace-exec-journal-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp map_or_empty(nil), do: %{}
  defp map_or_empty(value), do: Map.new(value)

  defp restore(app, key, nil), do: Application.delete_env(app, key)
  defp restore(app, key, value), do: Application.put_env(app, key, value)
end
