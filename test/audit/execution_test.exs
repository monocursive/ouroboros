defmodule Ouroboros.Audit.ExecutionTest do
  use ExUnit.Case, async: false
  @moduletag :capture_log
  alias Ouroboros.Audit.{Bundle, Config, Store}
  alias Ouroboros.Provider.Native.{Journal, Loop, Paths}
  alias Ouroboros.Test.NativeModelScript

  setup do
    {:ok, temporary} = Ouroboros.Workspace.Path.canonicalize(System.tmp_dir!())
    root = Path.join(temporary, "ouro-audit-execution-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "workspace"))
    File.mkdir_p!(Path.join(root, "session"))
    {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [], :workspace_write)
    previous = Application.get_env(:ouroboros, :audit)
    :ok = Supervisor.terminate_child(Ouroboros.Supervisor, Store)
    config = Config.new!(mode: :required, capture: :full, root: Path.join(root, "evidence"))
    Application.put_env(:ouroboros, :audit, config)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ouroboros, :audit, previous),
        else: Application.delete_env(:ouroboros, :audit)

      Supervisor.restart_child(Ouroboros.Supervisor, Store)
      File.rm_rf!(root)
    end)

    %{root: root, config: config, scope: scope, session_dir: Path.join(root, "session")}
  end

  defp loop(context, script) do
    {model, agent} = NativeModelScript.start(script)
    test = self()

    {%Loop{
       emit: fn event -> send(test, {:event, event}) end,
       model_module: NativeModelScript,
       model_spec: model,
       system: "audit test",
       scope: context.scope,
       session_dir: context.session_dir,
       session_id: "audit-test-session",
       provider_session_id: "audit-test-provider",
       turn_id: "turn-1",
       approval_mode: :auto_approve,
       journal: Journal.open(context.session_dir)
     }, agent}
  end

  test "disabled recording has no dependency on an audit writer, even inside a hook context" do
    Application.put_env(:ouroboros, :audit, Config.new!([]))
    refute Process.whereis(Store)

    assert {:ok, nil} =
             Ouroboros.Audit.with_execution(
               %{stream: Journal.digest("disabled-hook"), fields: %{"call_id" => "disabled"}},
               fn -> Ouroboros.Audit.execution("process_dispatch", %{"command" => "true"}) end
             )
  end

  test "a native change is correlated, exportable and independently verifiable", context do
    start_supervised!({Store, config: context.config})

    {loop, model} =
      loop(context, [
        [
          {:tool_call,
           %{id: "write-1", name: "write", input: %{"path" => "answer.txt", "content" => "42"}}}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ])

    assert {:ok, _} = Loop.run_turn(loop, "write the answer")
    assert File.read!(Path.join(context.scope.root, "answer.txt")) == "42"
    assert length(NativeModelScript.requests(model)) == 2
    assert {:ok, %{records: records}} = Journal.verify(Journal.path(context.session_dir))
    assert Enum.count(records, &(&1["kind"] == "model_call")) == 2
    assert Enum.any?(records, &(&1["kind"] == "model_chunk"))

    assert Enum.any?(
             records,
             &(&1["kind"] == "tool_dispatch" and &1["arguments"]["content"] == "42")
           )

    assert Enum.any?(records, &(&1["kind"] == "tool_response"))
    assert {:ok, snapshot} = Store.snapshot()
    assert {:ok, exported} = Bundle.write(snapshot, Path.join(context.root, "export"))

    assert {:ok, %{integrity: "matches_supplied_trust_anchor"}} =
             Bundle.verify(exported.path, exported.manifest_sha256)

    [segment] =
      Store.segments(Store.stream_path(exported.path, Store.stream_id(context.session_dir)))

    File.write!(segment, "")

    assert {:error, :audit_bundle_verification_failed} =
             Bundle.verify(exported.path, exported.manifest_sha256)
  end

  test "skill discovery and loading cannot read protected files through symlinks", context do
    start_supervised!({Store, config: context.config})
    alias Ouroboros.Provider.Native.{Skills, Tools}
    skills = Path.join(context.scope.root, ".agents/skills")
    File.mkdir_p!(Path.join(skills, "leaf"))
    protected = Path.join(context.config.root, "SKILL.md")

    File.write!(
      protected,
      "---\nname: secret\ndescription: confidential policy\n---\nprivate policy"
    )

    File.ln_s!(protected, Path.join(skills, "leaf/SKILL.md"))
    File.ln_s!(context.config.root, Path.join(skills, "directory"))
    File.mkdir_p!(Path.join(skills, "safe"))
    File.write!(Path.join(skills, "safe/SKILL.md"), "Safe skill body")
    assert Enum.any?(Skills.discover(context.scope.root), &(&1.name == "safe"))

    refute Enum.any?(
             Skills.discover(context.scope.root),
             &(&1.name in ["secret", "leaf", "directory"])
           )

    assert {:ok, %{body: "Safe skill body"}} = Skills.load("safe", context.scope.root)

    result =
      Tools.execute(
        Tools.Skill,
        %{"name" => "secret"},
        %{scope: context.scope, session_dir: context.session_dir, reads: %{}},
        1000
      )

    assert result.is_error
    refute result.output =~ "confidential policy"
    # Reloading a previously valid path must revalidate it.
    File.rm!(Path.join(skills, "safe/SKILL.md"))
    File.ln_s!(protected, Path.join(skills, "safe/SKILL.md"))
    assert {:error, _} = Skills.load("safe", context.scope.root)
  end

  for {name, input, outcome} <- [
        {"ask_user", %{"question" => "Choose?"}, "timed_out"},
        {"ask_user", %{"question" => ""}, "failed"},
        {"agent", %{"prompt" => "work"}, "failed"}
      ] do
    test "#{name} #{outcome} records a correlated terminal response #{inspect(input)}", context do
      start_supervised!({Store, config: context.config})

      {loop, _} =
        loop(context, [
          [
            {:tool_call,
             %{id: "special", name: unquote(name), input: unquote(Macro.escape(input))}}
          ],
          [{:text, "done"}, {:finish, :stop}]
        ])

      assert {:ok, _} = Loop.run_turn(%{loop | approval_timeout_ms: 1}, "go")
      assert {:ok, %{records: records}} = Store.read(Journal.path(context.session_dir))

      assert [%{outcome: unquote(outcome), terminal_event_id: terminal}] =
               Enum.filter(Ouroboros.Audit.Query.calls(records), &(&1.name == unquote(name)))

      assert terminal
      response = Enum.find(records, &(&1["event_id"] == terminal))
      assert response["call_id"] == "special"
      assert response["result"]
      result = Enum.find(records, &(&1["kind"] == "tool_result"))
      assert result["ledger_ref"] == response["ledger_effect_id"]
    end
  end

  for response <- [:answer, :interrupt] do
    test "ask_user #{response} records its outcome before continuing", context do
      start_supervised!({Store, config: context.config})

      {loop, _} =
        loop(context, [
          [{:tool_call, %{id: "question", name: "ask_user", input: %{"question" => "Choose?"}}}],
          [{:text, "done"}, {:finish, :stop}]
        ])

      emit = fn event ->
        if event.type == :approval_requested do
          if unquote(response) == :interrupt do
            send(self(), :native_interrupt)
          else
            send(
              self(),
              {:native_approval, event.request_id,
               %Jido.Harness.ApprovalResponse{decision: :approve, scope: :once, reason: "answer"}}
            )
          end
        end
      end

      assert {:ok, _} = Loop.run_turn(%{loop | emit: emit}, "go")
      assert {:ok, %{records: records}} = Store.read(Journal.path(context.session_dir))
      [call] = Enum.filter(Ouroboros.Audit.Query.calls(records), &(&1.name == "ask_user"))

      assert call.outcome ==
               if(unquote(response) == :interrupt, do: "interrupted", else: "completed")
    end
  end

  test "required recording failure prevents the first model request", context do
    start_supervised!(
      {Store,
       config: context.config,
       durability_hook: fn point ->
         if point == :before_write, do: {:error, :enospc}, else: :ok
       end}
    )

    {loop, model} = loop(context, [[{:text, "should not run"}]])
    assert {:ok, %{interrupted?: true}} = Loop.run_turn(loop, "hello")
    assert NativeModelScript.requests(model) == []
    assert_receive {:event, %{type: :turn_failed, payload: %{"reason" => "audit_unavailable"}}}
  end

  test "a hook cannot bypass required containment by requesting unrestricted execution",
       context do
    start_supervised!({Store, config: context.config})
    marker = Path.join(context.scope.root, "hook-must-not-run")

    hook = %{
      kind: :command,
      command: "printf unsafe > '#{marker}'",
      event: :session_start,
      matcher: nil,
      cwd: context.scope.root,
      timeout_ms: 1000,
      sandbox_mode: :unrestricted,
      trusted: true,
      scope: :node
    }

    config = %Ouroboros.Provider.Native.Hooks{hooks: [hook], workspace: context.scope.root}

    assert_raise Ouroboros.Audit.Unavailable, fn ->
      Ouroboros.Provider.Native.Hooks.session_start(config, %{
        "session_id" => "hook-test",
        "cwd" => context.scope.root
      })
    end

    refute File.exists?(marker)
    {:ok, rows} = Ouroboros.Audit.Query.events(context.config.root)
    assert Enum.any?(rows, &(&1["kind"] == "hook_refused"))
  end

  test "recording failure during shell output kills the child before later work", context do
    {:ok, counter} = Agent.start_link(fn -> 0 end)

    hook = fn
      :before_write ->
        if Agent.get_and_update(counter, &{&1 + 1, &1 + 1}) == 2, do: {:error, :enospc}, else: :ok

      _ ->
        :ok
    end

    start_supervised!({Store, config: context.config, durability_hook: hook})
    marker = Path.join(context.scope.root, "must-not-run")

    assert_raise Ouroboros.Audit.Unavailable, fn ->
      Ouroboros.Provider.Native.Exec.run(
        "/bin/sh",
        ["-c", "printf started; sleep 1; printf escaped > '#{marker}'"],
        cd: context.scope.root,
        timeout_ms: 3000
      )
    end

    Process.sleep(1100)
    refute File.exists?(marker)
  end

  test "recording failure immediately before tool dispatch prevents the write", context do
    {:ok, counter} = Agent.start_link(fn -> 0 end)

    hook = fn
      :before_write ->
        if Agent.get_and_update(counter, &{&1 + 1, &1 + 1}) == 7, do: {:error, :enospc}, else: :ok

      _ ->
        :ok
    end

    start_supervised!({Store, config: context.config, durability_hook: hook})

    {loop, model} =
      loop(context, [
        [
          {:tool_call,
           %{
             id: "write-1",
             name: "write",
             input: %{"path" => "forbidden.txt", "content" => "must not be written"}
           }}
        ],
        [{:text, "must not continue"}]
      ])

    assert {:ok, %{interrupted?: true}} = Loop.run_turn(loop, "write")
    refute File.exists?(Path.join(context.scope.root, "forbidden.txt"))
    assert length(NativeModelScript.requests(model)) == 1
  end
end
