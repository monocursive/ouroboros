defmodule Ouroboros.Provider.Native.SandboxEscalationTest do
  @moduledoc """
  What happens after the OS sandbox stops a command, driven through the real loop.

  Nothing here stubs the sandbox or the shell: a scripted model asks for a `bash` command
  that genuinely cannot run under this node's sandbox, and the loop is left to do what it
  does — put the denial to the operator once, and re-run the identical command in a fenced
  escalation profile if they say yes. The permission engine is the one thing swapped out,
  and only in the tests that are about the engine:
  `config :ouroboros, :permissions_engine` is the seam
  `Ouroboros.Provider.Native.Permissions` already reads.

  A node with no OS sandbox has no denial to escalate — `workspace_write` there refuses
  `bash` rather than wrapping it — so these skip with the reason printed rather than
  passing green having checked nothing.

  Not `async`: the permission engine and the native data directory are node configuration.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.ApprovalResponse
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Test.NativeModelScript

  @backend Sandbox.detect().backend

  @needs_sandbox (case @backend do
                    :none ->
                      [
                        skip:
                          "no OS sandbox on this node, so `workspace_write` refuses `bash` " <>
                            "and there is no denial to escalate"
                      ]

                    _present ->
                      []
                  end)

  # What a denied write looks like from inside each backend. Seatbelt refuses the syscall
  # (`EPERM`, which every program spells `Operation not permitted`); bubblewrap mounts the
  # protected root read-only, so the same write fails `EROFS` (`Read-only file system`).
  # `Sandbox.denial_line?/1` recognises both; these assertions have to expect the one this
  # node's backend produces, or they pass only on the platform they were written on.
  @denial (case @backend do
             :bwrap -> "Read-only file system"
             _other -> "Operation not permitted"
           end)

  # An engine whose whole job is to answer the escalation question a specific way, so the
  # "a rule pre-answered it" paths are exercised without inventing rule syntax here.
  defmodule ScriptedEngine do
    @moduledoc false

    def evaluate(%{context: %{sandbox_escalation: true}}),
      do: Application.get_env(:ouroboros, :test_escalation_answer, {:ask, :no_rule})

    def evaluate(_request), do: {:ask, :no_rule}

    def record(_decision_id, _attrs), do: :ok
  end

  setup do
    root = Path.join(System.tmp_dir!(), "native-escalate-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "workspace/lib"))
    File.mkdir_p!(Path.join(root, "workspace/.git"))
    File.mkdir_p!(Path.join(root, "session"))
    File.write!(Path.join(root, "workspace/lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")
    escalation_target = Path.join(root, "workspace/.git/escalated.txt")

    on_exit(fn -> File.rm_rf(root) end)

    {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [], :workspace_write)

    %{
      root: root,
      scope: scope,
      session_dir: Path.join(root, "session"),
      workspace: scope.root,
      # `.git` is inside the workspace but deliberately read-only in the ordinary profile.
      # The approved profile lifts this segment fence and nothing broader.
      outside: escalation_target
    }
  end

  defp with_engine(engine, answer) do
    previous_engine = Application.get_env(:ouroboros, :permissions_engine)
    previous_answer = Application.get_env(:ouroboros, :test_escalation_answer)
    Application.put_env(:ouroboros, :permissions_engine, engine)
    Application.put_env(:ouroboros, :test_escalation_answer, answer)

    on_exit(fn ->
      restore(:permissions_engine, previous_engine)
      restore(:test_escalation_answer, previous_answer)
    end)
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  defp start_loop(context, script, overrides \\ []) do
    {model_spec, agent} = NativeModelScript.start(script)
    test = self()

    loop =
      struct!(
        %Loop{
          emit: fn event -> send(test, {:event, event}) end,
          model_module: NativeModelScript,
          model_spec: model_spec,
          system: "system",
          scope: context.scope,
          session_dir: context.session_dir,
          session_id: "sess-escalate",
          provider_session_id: "native-escalate",
          turn_id: "turn-1",
          approval_mode: :auto_approve,
          # `:infinity` so an answered escalation never races a deadline on a loaded
          # machine; the unanswered path is tested with an explicit short deadline.
          approval_timeout_ms: :infinity
        },
        overrides
      )

    {loop, agent}
  end

  defp run(loop, prompt \\ "do the thing") do
    parent = self()
    spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, prompt)}) end)
  end

  defp collect(acc \\ []) do
    receive do
      {:event, %{type: type} = event}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        Enum.reverse([event | acc])

      {:event, event} ->
        collect([event | acc])
    after
      20_000 ->
        flunk("no terminal turn event within 20s; collected: #{inspect(Enum.reverse(acc))}")
    end
  end

  defp find(events, type), do: Enum.find(events, &(&1.type == type))
  defp all(events, type), do: Enum.filter(events, &(&1.type == type))

  defp escalation_event(events),
    do:
      events
      |> all(:provider_event)
      |> Enum.find(&(&1.payload["kind"] == "sandbox_escalation"))

  defp escape_script(_context, id \\ "c1") do
    [
      [
        {:tool_call,
         %{
           id: id,
           name: "bash",
           input: %{
             "command" => "dir=$(printf '\\056git'); echo escaped > \"$PWD/$dir/escalated.txt\""
           }
         }}
      ],
      [{:text, "done"}, {:finish, :stop}]
    ]
  end

  describe "a filesystem denial an operator can lift" do
    @describetag @needs_sandbox

    test "raises an approval carrying the command, the cwd, and the constraint", context do
      {loop, _agent} = start_loop(context, escape_script(context))
      pid = run(loop)

      assert_receive {:event, %{type: :approval_requested} = ask}, 10_000

      assert ask.payload["kind"] == "sandbox_escalation"
      assert ask.payload["tool_call"]["name"] == "bash"

      assert ask.payload["tool_call"]["command"] ==
               "dir=$(printf '\\056git'); echo escaped > \"$PWD/$dir/escalated.txt\""

      assert ask.payload["tool_call"]["cwd"] == context.workspace
      assert ask.payload["reason"] =~ @denial
      assert ask.payload["reason"] =~ "allows writes only under"
      assert ask.payload["reason"] =~ context.workspace

      # This is the card where "don't ask again" matters most, and it used to carry
      # `%{"command_prefix" => "dir=$(printf"}` — a shape no client could draw, from a
      # token that was never a rule. It now carries what `permissions.add` would take.
      rule = ask.payload["suggested_rule"]

      assert is_binary(rule)
      assert {:ok, _pattern} = Ouroboros.Control.Permissions.Pattern.parse(rule)

      assert is_binary(ask.request_id)

      send(
        pid,
        {:native_approval, ask.request_id, %ApprovalResponse{decision: :approve, scope: :once}}
      )

      collect()
    end

    test "approving re-runs the same command in the fenced profile, in the same turn", context do
      {loop, _agent} = start_loop(context, escape_script(context))
      pid = run(loop)

      assert_receive {:event, %{type: :approval_requested} = ask}, 10_000

      send(
        pid,
        {:native_approval, ask.request_id, %ApprovalResponse{decision: :approve, scope: :once}}
      )

      events = collect()

      assert File.read!(context.outside) == "escaped\n"

      [result] = all(events, :tool_result)
      refute result.payload["is_error"]

      # The model is shown the re-run, and told plainly that a first attempt happened —
      # a command that partly succeeded before the denial has now run twice.
      assert result.payload["output"] =~ "The OS sandbox stopped the first attempt"
      assert result.payload["output"] =~ "has now happened twice"
      assert result.payload["output"] =~ "Runtime data, config, `.ouroboros`"

      # And the transcript keeps the half the tool result no longer carries.
      event = escalation_event(events)
      assert event.payload["decision"] == "approved"
      assert event.payload["granted_by"] == "human"
      assert event.payload["call_id"] == "c1"
      assert event.payload["constraint"] == "filesystem"
      assert event.payload["evidence"] =~ @denial
      assert event.payload["stopped_by"] == Sandbox.label(Sandbox.detect())
      assert event.payload["sandboxed_output"] =~ @denial
      assert event.request_id == ask.request_id
    end

    test "denying leaves the sandboxed failure standing and re-runs nothing", context do
      {loop, _agent} = start_loop(context, escape_script(context))
      pid = run(loop)

      assert_receive {:event, %{type: :approval_requested} = ask}, 10_000

      send(
        pid,
        {:native_approval, ask.request_id,
         %ApprovalResponse{decision: :deny, scope: :once, reason: "not that one"}}
      )

      events = collect()

      refute File.exists?(context.outside)

      [result] = all(events, :tool_result)
      assert result.payload["is_error"]
      assert result.payload["output"] =~ @denial
      assert result.payload["output"] =~ "declined: not that one"
      assert result.payload["output"] =~ "Do not ask for it again"

      assert escalation_event(events).payload["decision"] == "declined"
      assert escalation_event(events).payload["granted_by"] == "human"
    end

    test "an unanswered escalation is a declined one at the deadline", context do
      {loop, _agent} = start_loop(context, escape_script(context), approval_timeout_ms: 300)
      run(loop)

      assert_receive {:event, %{type: :approval_requested}}, 10_000

      events = collect()

      refute File.exists?(context.outside)

      [result] = all(events, :tool_result)
      assert result.payload["is_error"]
      assert result.payload["output"] =~ "Nobody answered"
      assert result.payload["output"] =~ "300 ms"
      assert escalation_event(events).payload["granted_by"] == "timeout"
    end

    test "an interrupt while the escalation is outstanding declines it and stops the turn",
         context do
      {loop, _agent} = start_loop(context, escape_script(context))
      pid = run(loop)

      assert_receive {:event, %{type: :approval_requested}}, 10_000

      send(pid, :native_interrupt)

      events = collect()

      refute File.exists?(context.outside)
      assert find(events, :turn_interrupted)

      [result] = all(events, :tool_result)
      assert result.payload["is_error"]
      assert result.payload["output"] =~ "interrupted while the fenced escalation request"
      assert escalation_event(events).payload["granted_by"] == "interrupted"
    end

    test "a session-scope approval is not asked a second time in the same session", context do
      script = [
        [
          {:tool_call,
           %{
             id: "c1",
             name: "bash",
             input: %{
               "command" => "dir=$(printf '\\056git'); echo escaped > \"$PWD/$dir/escalated.txt\""
             }
           }}
        ],
        [
          {:tool_call,
           %{
             id: "c2",
             name: "bash",
             input: %{
               "command" => "dir=$(printf '\\056git'); echo escaped > \"$PWD/$dir/escalated.txt\""
             }
           }}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, script)
      pid = run(loop)

      assert_receive {:event, %{type: :approval_requested} = ask}, 10_000

      send(
        pid,
        {:native_approval, ask.request_id, %ApprovalResponse{decision: :approve, scope: :session}}
      )

      events = collect()

      # The first ask was taken out of the mailbox by `assert_receive` above, so anything
      # left here would be a *second* one — and the point of `scope: :session` is that
      # there is not one.
      assert all(events, :approval_requested) == []
      assert [first, second] = all(events, :provider_event) |> Enum.filter(&sandbox_kind?/1)
      assert first.payload["granted_by"] == "human"
      assert second.payload["granted_by"] == "session_grant"

      for result <- all(events, :tool_result) do
        refute result.payload["is_error"]
        assert result.payload["output"] =~ "The OS sandbox stopped the first attempt"
      end
    end
  end

  describe "what the permission engine may pre-answer" do
    @describetag @needs_sandbox

    test "an engine allow uses the fenced profile without putting anything to a human", context do
      with_engine(ScriptedEngine, {:allow, "escalation-rule"})

      {loop, _agent} = start_loop(context, escape_script(context))
      run(loop)

      events = collect()

      assert all(events, :approval_requested) == []
      assert File.read!(context.outside) == "escaped\n"

      event = escalation_event(events)
      assert event.payload["decision"] == "approved"
      assert event.payload["granted_by"] == "rule"
    end

    test "an obfuscated protected-root target remains denied after an engine allow", context do
      with_engine(ScriptedEngine, {:allow, "escalation-rule"})

      data_dir = Path.join(context.root, "data-obfuscated")
      File.mkdir_p!(data_dir)
      previous = Application.get_env(:ouroboros, :native_data_dir)
      Application.put_env(:ouroboros, :native_data_dir, data_dir)
      on_exit(fn -> restore(:native_data_dir, previous) end)

      target = Path.join(data_dir, "ledger.db")
      link = Path.join(context.workspace, "runtime-link")
      File.ln_s!(data_dir, link)

      # Neither the command nor the shell's EPERM text names the protected root. The
      # kernel profile, not textual inspection, must be the boundary on the approved run.
      script = [
        [
          {:tool_call,
           %{
             id: "c1",
             name: "bash",
             input: %{
               "command" =>
                 "sh -c 'echo escaped > runtime-link/ledger.db' 2>&1 || " <>
                   "echo 'Operation not permitted' >&2; exit 1"
             }
           }}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, script)
      run(loop)
      events = collect()

      refute File.exists?(target)
      assert all(events, :approval_requested) == []
      assert escalation_event(events).payload["decision"] == "approved"
      assert escalation_event(events).payload["granted_by"] == "rule"

      [result] = all(events, :tool_result)
      assert result.payload["is_error"]
      assert result.payload["output"] =~ "fenced workspace profile"
      assert result.payload["output"] =~ @denial
    end

    test "an engine deny refuses the escalation without putting anything to a human",
         context do
      with_engine(ScriptedEngine, {:deny, "no-escapes"})

      {loop, _agent} = start_loop(context, escape_script(context))
      run(loop)

      events = collect()

      assert all(events, :approval_requested) == []
      refute File.exists?(context.outside)

      [result] = all(events, :tool_result)
      assert result.payload["is_error"]
      assert result.payload["output"] =~ "refuses the fenced escalation re-run"
      assert result.payload["output"] =~ "no-escapes"
      assert escalation_event(events).payload["granted_by"] == "rule"
    end
  end

  describe "denials that are never offered" do
    @describetag @needs_sandbox

    test "a write under the node's own data directory keeps the do-it-yourself answer",
         context do
      # The escalation is withheld here by `Sandbox.escalatable?/3`, not by the engine, so
      # the engine is scripted to *ask* — if it were the thing refusing, this test would
      # pass for the wrong reason.
      with_engine(ScriptedEngine, {:ask, :no_rule})

      data_dir = Path.join(context.root, "data")
      File.mkdir_p!(data_dir)
      previous = Application.get_env(:ouroboros, :native_data_dir)
      Application.put_env(:ouroboros, :native_data_dir, data_dir)
      on_exit(fn -> restore(:native_data_dir, previous) end)

      target = Path.join(data_dir, "ledger.db")

      script = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "echo x > #{target}"}}}],
        [{:text, "done"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, script)
      run(loop)

      events = collect()

      assert all(events, :approval_requested) == []
      assert escalation_event(events) == nil
      refute File.exists?(target)

      [result] = all(events, :tool_result)
      assert result.payload["is_error"]
      assert result.payload["output"] =~ @denial
      # The pre-escalation advice, unchanged: ask a human, do not expect a way out.
      assert result.payload["output"] =~ "ask_user"
      refute result.payload["output"] =~ "re-runs the command once inside a fenced profile"
    end

    test "plan mode never reaches an escalation: the write is refused before bash runs",
         context do
      {loop, _agent} = start_loop(context, escape_script(context), approval_mode: :plan)
      run(loop)

      events = collect()

      assert all(events, :approval_requested) == []
      assert escalation_event(events) == nil
      refute File.exists?(context.outside)

      [result] = all(events, :tool_result)
      assert result.payload["is_error"]
      assert result.payload["output"] =~ "plan mode"
    end
  end

  describe "an unrestricted session, end to end" do
    test "commits in a git repository, which a workspace_write session cannot", context do
      repo = Path.join(context.root, "repo")
      File.mkdir_p!(repo)
      File.write!(Path.join(repo, "README.md"), "one\n")

      git = fn args -> System.cmd("git", args, cd: repo, stderr_to_stdout: true) end
      git.(["init", "-q"])
      git.(["-c", "user.email=a@b", "-c", "user.name=a", "add", "-A"])
      git.(["-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "base"])

      {:ok, scope} = Paths.scope(repo, [], :unrestricted)

      command =
        "echo two >> README.md && git add -A && " <>
          "git -c user.email=a@b -c user.name=a commit -qm second"

      script = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => command}}}],
        [{:text, "committed"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(%{context | scope: scope}, script)
      run(loop)

      events = collect()

      [result] = all(events, :tool_result)
      refute result.payload["is_error"]

      {log, 0} = git.(["log", "--oneline"])
      assert log |> String.trim() |> String.split("\n") |> length() == 2

      # And the call said what it ran under, so a client footer reads `none` from a fact.
      assert find(events, :tool_call).payload["sandbox"] == "none"
      # No escalation was needed: there was no sandbox to be stopped by.
      assert escalation_event(events) == nil
    end

    @tag :sandbox_exec
    @tag @needs_sandbox
    test "the same commit under workspace_write is stopped, then escalated and committed",
         context do
      repo = Path.join(context.root, "repo2")
      File.mkdir_p!(repo)
      File.write!(Path.join(repo, "README.md"), "one\n")

      git = fn args -> System.cmd("git", args, cd: repo, stderr_to_stdout: true) end
      git.(["init", "-q"])
      git.(["-c", "user.email=a@b", "-c", "user.name=a", "add", "-A"])
      git.(["-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "base"])

      {:ok, scope} = Paths.scope(repo, [], :workspace_write)

      command =
        "git add -A && git -c user.email=a@b -c user.name=a commit -qm second --allow-empty"

      script = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => command}}}],
        [{:text, "committed"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(%{context | scope: scope}, script)
      pid = run(loop)

      assert_receive {:event, %{type: :approval_requested} = ask}, 10_000
      assert ask.payload["kind"] == "sandbox_escalation"

      send(
        pid,
        {:native_approval, ask.request_id, %ApprovalResponse{decision: :approve, scope: :once}}
      )

      events = collect()

      [result] = all(events, :tool_result)
      refute result.payload["is_error"]

      {log, 0} = git.(["log", "--oneline"])
      assert log |> String.trim() |> String.split("\n") |> length() == 2
    end
  end

  # The loop tests above drive the loop process directly. This one goes through the real
  # session transport, because that is where the approval *lifecycle* lives: the session
  # tracks the request id off the `approval_requested` event, `respond_approval/3` refuses
  # an id it is not holding, and `Jido.Harness.Session.Lifecycle` auto-denies an approval
  # raised for a turn that is no longer active. An escalation is raised mid-turn, before
  # any terminal event, so it must route like an ordinary tool approval does.
  describe "through the session transport" do
    @describetag @needs_sandbox

    setup context do
      data_dir = Path.join(context.root, "data")
      File.mkdir_p!(data_dir)

      previous_dir = Application.get_env(:ouroboros, :native_data_dir)
      previous_model = Application.get_env(:ouroboros, :native_model_module)
      Application.put_env(:ouroboros, :native_data_dir, data_dir)
      Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

      on_exit(fn ->
        restore(:native_data_dir, previous_dir)
        restore(:native_model_module, previous_model)
      end)

      :ok
    end

    test "the operator's answer reaches the loop through respond_approval/3", context do
      {model_spec, _agent} = NativeModelScript.start(escape_script(context))

      request =
        Jido.Harness.SessionRequest.new!(%{
          provider: :native,
          cwd: context.workspace,
          model: model_spec,
          approval_mode: :auto_approve,
          approval_timeout_ms: :infinity
        })

      {:ok, handle} =
        Ouroboros.Provider.Native.Session.open(request, %{
          session_id: "sess-escalate-transport",
          provider: :native,
          owner: self(),
          adapter: Ouroboros.Provider.Native,
          config: %{},
          process_manager: Jido.Harness.ProcessDriver.Erlexec,
          telemetry_context: %{}
        })

      on_exit(fn ->
        if Process.alive?(handle), do: Ouroboros.Provider.Native.Session.close(handle)
      end)

      assert_receive {:session_adapter_event, %{type: :provider_event}}, 10_000

      Ouroboros.Provider.Native.Session.send(
        handle,
        Jido.Harness.TurnRequest.new!("escape"),
        "turn-1"
      )

      ask = await_session_event(:approval_requested)
      assert ask.payload["kind"] == "sandbox_escalation"

      # An id the session is not holding is refused, which is what makes the id it *is*
      # holding meaningful: the escalation was tracked off its own `approval_requested`
      # event like any other approval, not admitted because something answered.
      assert {:error, :unknown_request} =
               Ouroboros.Provider.Native.Session.respond_approval(
                 handle,
                 "napp_not_a_real_request",
                 %ApprovalResponse{decision: :approve, scope: :once}
               )

      assert :ok =
               Ouroboros.Provider.Native.Session.respond_approval(
                 handle,
                 ask.request_id,
                 %ApprovalResponse{
                   decision: :approve,
                   scope: :once
                 }
               )

      assert %{type: :turn_completed} = await_session_event(:turn_completed)
      assert File.read!(context.outside) == "escaped\n"
    end
  end

  defp await_session_event(type) do
    receive do
      {:session_adapter_event, %{type: ^type} = event} -> event
      {:session_adapter_event, _other} -> await_session_event(type)
    after
      20_000 -> flunk("no #{type} within 20s")
    end
  end

  defp sandbox_kind?(%{payload: %{"kind" => "sandbox_escalation"}}), do: true
  defp sandbox_kind?(_event), do: false
end
