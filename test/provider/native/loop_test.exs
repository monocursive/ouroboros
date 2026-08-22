defmodule Ouroboros.Provider.Native.LoopTest do
  use ExUnit.Case, async: true

  alias Jido.Harness.ApprovalResponse
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-loop-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "workspace/lib"))
    File.mkdir_p!(Path.join(root, "session"))
    File.write!(Path.join(root, "workspace/lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")
    on_exit(fn -> File.rm_rf(root) end)

    {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [], :workspace_write)

    %{root: root, scope: scope, session_dir: Path.join(root, "session"), workspace: scope.root}
  end

  # The loop is a process: it emits to a function and takes control on its mailbox, so a
  # test drives it exactly the way the session does.
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
          session_id: "sess-1",
          provider_session_id: "native-x-y",
          turn_id: "turn-1",
          approval_mode: :auto_approve,
          approval_timeout_ms: 2_000
        },
        overrides
      )

    {loop, agent}
  end

  defp run(loop, prompt \\ "do the thing") do
    parent = self()
    pid = spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, prompt)}) end)
    pid
  end

  defp collect(acc \\ []) do
    receive do
      {:event, %{type: type} = event} when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        Enum.reverse([event | acc])

      {:event, event} ->
        collect([event | acc])
    after
      15_000 -> flunk("no terminal turn event within 15s; collected: #{inspect(Enum.reverse(acc))}")
    end
  end

  defp types(events), do: Enum.map(events, & &1.type)

  defp find(events, type), do: Enum.find(events, &(&1.type == type))
  defp all(events, type), do: Enum.filter(events, &(&1.type == type))

  describe "a scripted turn that reads, edits, runs bash, and finishes" do
    test "emits the full sequence in order", context do
      script = [
        [
          {:thinking, "let me look"},
          {:text, "reading the file"},
          {:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}
        ],
        [
          {:tool_call,
           %{
             id: "c2",
             name: "edit",
             input: %{
               "path" => "lib/a.ex",
               "old_string" => "def x, do: 1",
               "new_string" => "def x, do: 2"
             }
           }}
        ],
        [{:tool_call, %{id: "c3", name: "bash", input: %{"command" => "echo checked"}}}],
        [
          {:text, "done: changed x and ran the check"},
          {:usage, %{input_tokens: 120, output_tokens: 40}},
          {:finish, :stop}
        ]
      ]

      {loop, agent} = start_loop(context, script)
      run(loop)
      events = collect()

      assert types(events) == [
               :turn_started,
               :thinking_delta,
               :output_text_delta,
               :output_text_final,
               :tool_call,
               :tool_result,
               :tool_call,
               :tool_result,
               :file_change,
               :tool_call,
               :tool_result,
               :output_text_delta,
               :output_text_final,
               :usage,
               :turn_completed
             ]

      assert Enum.find_index(types(events), &(&1 == :file_change)) >
               Enum.find_index(types(events), &(&1 == :tool_result))

      assert NativeModelScript.call_count(agent) == 4

      [read_call, edit_call, bash_call] = all(events, :tool_call)
      assert read_call.payload["name"] == "read"
      assert read_call.payload["call_id"] == "c1"
      assert edit_call.payload["name"] == "edit"
      assert bash_call.payload["input"]["command"] == "echo checked"

      [read_result, edit_result, bash_result] = all(events, :tool_result)
      refute read_result.payload["is_error"]
      assert read_result.payload["output"] =~ "def x, do: 1"
      refute edit_result.payload["is_error"]
      assert bash_result.payload["output"] =~ "checked"

      change = find(events, :file_change)
      assert [%{"kind" => "modify", "diff" => diff, "relative_path" => "lib/a.ex"}] = change.payload["changes"]
      assert diff =~ "-  def x, do: 1"
      assert diff =~ "+  def x, do: 2"

      assert File.read!(Path.join(context.workspace, "lib/a.ex")) =~ "def x, do: 2"

      usage = find(events, :usage)
      assert usage.payload["input_tokens"] == 120
      assert usage.payload["output_tokens"] == 40
      assert usage.payload["total_tokens"] == 160

      completed = find(events, :turn_completed)
      assert completed.payload["status"] == "completed"
      assert completed.payload["iterations"] == 4
      assert completed.payload["input_tokens"] == 120
    end

    test "carries the system prompt and the tool schemas into every model call", context do
      {loop, agent} = start_loop(context, [[{:text, "ok"}, {:finish, :stop}]])
      run(loop)
      collect()

      [request] = NativeModelScript.requests(agent)
      assert request.system == "system"
      assert Enum.map(request.tools, & &1.name) == ["read", "write", "edit", "bash", "plan"]
      assert [%{role: :user, content: "do the thing"}] = request.messages
    end

    test "a `plan` call becomes a plan_updated event", context do
      script = [
        [
          {:tool_call,
           %{
             id: "p1",
             name: "plan",
             input: %{"steps" => [%{"step" => "read", "status" => "completed"}]}
           }}
        ],
        [{:text, "planned"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, script)
      run(loop)
      events = collect()

      plan = find(events, :plan_updated)
      assert plan.payload["plan"] == [%{"step" => "read", "status" => "completed"}]
    end
  end

  describe "bounds" do
    test "stops on the third identical call and names the doom loop", context do
      repeat = {:tool_call, %{id: "c", name: "read", input: %{"path" => "lib/a.ex"}}}
      script = List.duplicate([repeat], 6)

      {loop, _agent} = start_loop(context, script)
      run(loop)
      events = collect()

      failed = find(events, :turn_failed)
      assert failed.payload["reason"] == "doom_loop"
      assert failed.payload["error"] =~ "doom loop"
      assert failed.payload["error"] =~ "read"
      # Two ran, the third was refused before executing.
      assert length(all(events, :tool_result)) == 2
    end

    test "fails the turn by name at max_iterations", context do
      script =
        List.duplicate(
          [{:tool_call, %{id: "c", name: "bash", input: %{"command" => "echo #{:rand.uniform()}"}}}],
          10
        )

      {loop, _agent} =
        start_loop(context, script, max_iterations: 2)

      run(loop)
      events = collect()

      failed = find(events, :turn_failed)
      assert failed.payload["reason"] == "max_iterations"
      assert failed.payload["error"] =~ "max_iterations (2)"
    end

    test "a model error fails the turn rather than crashing it", context do
      defmodule FailingModel do
        @behaviour Ouroboros.Provider.Native.Model
        @impl true
        def stream(_request, _opts), do: {:error, :no_credentials}
      end

      {loop, _agent} = start_loop(context, [])
      run(%{loop | model_module: FailingModel})
      events = collect()

      failed = find(events, :turn_failed)
      assert failed.payload["reason"] == "model_error"
      assert failed.payload["error"] =~ "no_credentials"
    end

    test "an unknown tool answers in-band with the tools that do exist", context do
      script = [
        [{:tool_call, %{id: "c1", name: "grep", input: %{"pattern" => "x"}}}],
        [{:text, "ok"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, script)
      run(loop)
      events = collect()

      [result] = all(events, :tool_result)
      assert result.payload["is_error"]
      assert result.payload["output"] =~ "not a tool in this session"
      assert result.payload["output"] =~ "read, write, edit, bash, plan"
    end
  end

  describe "approvals" do
    @write_script [
      [
        {:tool_call,
         %{id: "c1", name: "write", input: %{"path" => "lib/new.ex", "content" => "hello\n"}}}
      ],
      [{:text, "wrote it"}, {:finish, :stop}]
    ]

    test "asks before a write under :prompt and runs it when approved", context do
      {loop, _agent} = start_loop(context, @write_script, approval_mode: :prompt)
      pid = run(loop)

      assert_receive {:event, %{type: :approval_requested} = ask}, 5_000
      assert ask.payload["kind"] == "file_change"
      assert ask.payload["tool_call"]["name"] == "write"
      assert ask.payload["tool_call"]["cwd"] == context.workspace
      assert ask.payload["suggested_rule"] == %{"tool" => "write", "paths" => ask.payload["paths"]}
      assert ask.payload["reason"] =~ "no permission rule engine"
      assert is_binary(ask.request_id)

      send(pid, {:native_approval, ask.request_id, %ApprovalResponse{decision: :approve, scope: :once}})

      events = collect()
      assert File.read!(Path.join(context.workspace, "lib/new.ex")) == "hello\n"
      assert find(events, :turn_completed)
    end

    test "a denial becomes an error tool result and the file is not written", context do
      {loop, _agent} = start_loop(context, @write_script, approval_mode: :prompt)
      pid = run(loop)

      assert_receive {:event, %{type: :approval_requested} = ask}, 5_000

      send(
        pid,
        {:native_approval, ask.request_id,
         %ApprovalResponse{decision: :deny, scope: :once, reason: "not now"}}
      )

      events = collect()
      [result] = all(events, :tool_result)
      assert result.payload["is_error"]
      assert result.payload["output"] =~ "operator denied"
      assert result.payload["output"] =~ "not now"
      refute File.exists?(Path.join(context.workspace, "lib/new.ex"))
    end

    test "an unanswered approval is denied at the timeout", context do
      {loop, _agent} =
        start_loop(context, @write_script, approval_mode: :prompt, approval_timeout_ms: 200)

      run(loop)

      assert_receive {:event, %{type: :approval_requested}}, 5_000

      events = collect()
      [result] = all(events, :tool_result)
      assert result.payload["is_error"]
      assert result.payload["output"] =~ "nobody answered"
      assert result.payload["output"] =~ "200 ms"
      refute File.exists?(Path.join(context.workspace, "lib/new.ex"))
    end

    test "a session-scope approval is not asked again in the same turn", context do
      script = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "echo one"}}}],
        [{:tool_call, %{id: "c2", name: "bash", input: %{"command" => "echo one"}}}],
        [{:text, "twice"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, script, approval_mode: :prompt)
      pid = run(loop)

      assert_receive {:event, %{type: :approval_requested} = ask}, 5_000

      send(
        pid,
        {:native_approval, ask.request_id, %ApprovalResponse{decision: :approve, scope: :session}}
      )

      events = collect()

      # `assert_receive` already took the one ask out of the mailbox, so an empty list
      # here is the claim under test: the second identical call was never asked about.
      assert all(events, :approval_requested) == []
      assert length(all(events, :tool_result)) == 2
      assert Enum.all?(all(events, :tool_result), &(&1.payload["is_error"] == false))
    end

    test ":auto_approve skips the ask entirely", context do
      {loop, _agent} = start_loop(context, @write_script, approval_mode: :auto_approve)
      run(loop)
      events = collect()

      assert all(events, :approval_requested) == []
      assert File.exists?(Path.join(context.workspace, "lib/new.ex"))
    end

    test ":auto_edit approves a write inside the workspace without asking", context do
      {loop, _agent} = start_loop(context, @write_script, approval_mode: :auto_edit)
      run(loop)
      events = collect()

      assert all(events, :approval_requested) == []
      assert find(events, :turn_completed)
    end

    test ":auto_edit still asks for a command", context do
      script = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "rm -rf /"}}}],
        [{:text, "no"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, script, approval_mode: :auto_edit)
      pid = run(loop)

      assert_receive {:event, %{type: :approval_requested} = ask}, 5_000
      assert ask.payload["kind"] == "command"
      assert ask.payload["tool_call"]["command"] == "rm -rf /"
      assert ask.payload["suggested_rule"]["command_prefix"] == "rm"

      send(pid, {:native_approval, ask.request_id, %ApprovalResponse{decision: :deny, scope: :once}})
      collect()
    end

    test ":auto_edit does not auto-approve a write into a declared add_dir", %{root: root} = context do
      File.mkdir_p!(Path.join(root, "extra"))
      {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [Path.join(root, "extra")], :workspace_write)

      script = [
        [
          {:tool_call,
           %{
             id: "c1",
             name: "write",
             input: %{"path" => Path.join(root, "extra/x.txt"), "content" => "x"}
           }}
        ],
        [{:text, "no"}, {:finish, :stop}]
      ]

      {loop, _agent} =
        start_loop(%{context | scope: scope}, script, approval_mode: :auto_edit, scope: scope)

      pid = run(loop)

      assert_receive {:event, %{type: :approval_requested} = ask}, 5_000
      send(pid, {:native_approval, ask.request_id, %ApprovalResponse{decision: :deny, scope: :once}})
      collect()
    end

    test "a read is never gated behind a human when no engine exists", context do
      script = [
        [{:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}],
        [{:text, "read it"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, script, approval_mode: :prompt)
      run(loop)
      events = collect()

      assert all(events, :approval_requested) == []
      assert find(events, :turn_completed)
    end
  end

  describe "steer and interrupt" do
    test "a steered message is delivered at the next tool boundary", context do
      script = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "echo one"}}}],
        [{:text, "acknowledged"}, {:finish, :stop}]
      ]

      {loop, agent} = start_loop(context, script)
      pid = run(loop)

      # Steer while the first tool call is in flight; it must not interrupt it.
      assert_receive {:event, %{type: :tool_call}}, 5_000
      send(pid, {:native_steer, "actually, stop after this and explain"})

      events = collect()
      assert find(events, :turn_completed)

      [_first, second] = NativeModelScript.requests(agent)

      assert List.last(second.messages) == %{
               role: :user,
               content: "actually, stop after this and explain"
             }

      # The steer lands after the tool result it interrupted, not before it.
      assert Enum.at(second.messages, -2).role == :tool
    end

    test "an interrupt stops after the current tool and emits turn_interrupted", context do
      script = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "echo one"}}}],
        [{:tool_call, %{id: "c2", name: "bash", input: %{"command" => "echo two"}}}],
        [{:text, "never"}, {:finish, :stop}]
      ]

      {loop, agent} = start_loop(context, script)
      pid = run(loop)

      assert_receive {:event, %{type: :tool_call}}, 5_000
      send(pid, :native_interrupt)

      events = collect()

      assert List.last(types(events)) == :turn_interrupted
      assert find(events, :turn_interrupted).payload["reason"] == "interrupted"
      # The tool that was already running finished; the second was never dispatched.
      assert length(all(events, :tool_result)) == 1
      assert NativeModelScript.call_count(agent) == 1
    end

    test "an interrupt while an approval is pending stops the turn", context do
      {loop, _agent} = start_loop(context, @write_script, approval_mode: :prompt)
      pid = run(loop)

      assert_receive {:event, %{type: :approval_requested}}, 5_000
      send(pid, :native_interrupt)

      events = collect()
      assert List.last(types(events)) == :turn_interrupted
      refute File.exists?(Path.join(context.workspace, "lib/new.ex"))
    end
  end

  describe "payload discipline" do
    test "no environment secret reaches an event payload", context do
      System.put_env("OUROBOROS_NATIVE_TEST_API_KEY", "sk-super-secret-value")
      on_exit(fn -> System.delete_env("OUROBOROS_NATIVE_TEST_API_KEY") end)

      script = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "echo done"}}}],
        [{:text, "finished"}, {:usage, %{input_tokens: 1, output_tokens: 1}}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, script)
      run(loop)
      events = collect()

      serialized = inspect(Enum.map(events, & &1.payload))
      refute serialized =~ "sk-super-secret-value"
      refute serialized =~ "OUROBOROS_NATIVE_TEST_API_KEY"
    end

    test "every payload is string-keyed with JSON-encodable values", context do
      script = [
        [{:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}],
        [{:text, "ok"}, {:usage, %{input_tokens: 3, output_tokens: 2}}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, script)
      run(loop)
      events = collect()

      for event <- events do
        assert Enum.all?(Map.keys(event.payload), &is_binary/1)
        assert is_binary(JSON.encode!(event.payload))
      end
    end
  end
end
