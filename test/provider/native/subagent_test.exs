defmodule Ouroboros.Provider.Native.SubagentTest do
  @moduledoc """
  G3 — the native `agent` tool, and the child session behind it.

  The claims here are the ones a subagent is worth nothing without: the child spends its
  own context and hands back a summary, it can never do anything its parent could not, it
  cannot nest forever, it cannot outnumber its parent, its approvals reach the same person
  the parent's do, its spend is the parent's spend, and every one of those is bounded by a
  number this suite reads back rather than trusts.

  Parent and child each get their own scripted model — one script agent per session, which
  is why the child's spec travels as `provider_options["subagent_model"]`.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.ApprovalResponse
  alias Jido.Harness.SessionRequest
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Provider.Native.Session
  alias Ouroboros.Provider.Native.Subagent
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.Agent, as: AgentTool
  alias Ouroboros.Provider.Native.Tools.AgentResult
  alias Ouroboros.Test.NativeModelScript
  alias Ouroboros.Workspace.Worktree

  setup do
    root = Path.join(System.tmp_dir!(), "native-subagent-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")

    data_dir = Path.join(root, "data")
    File.mkdir_p!(data_dir)

    # Keyed by the real application keys, because `restore/2` puts them back by the key it
    # is given: a friendlier name here would leave `:workspace_allowed_roots` pointing at a
    # directory this test is about to delete, and the next module to restart the
    # application would fail to start at all.
    previous =
      Map.new(
        [:native_data_dir, :native_model_module, :data_dir, :workspace_allowed_roots],
        &{&1, Application.get_env(:ouroboros, &1)}
      )

    Application.put_env(:ouroboros, :native_data_dir, data_dir)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      Enum.each(previous, fn {key, value} -> restore(key, value) end)
      File.rm_rf(root)
    end)

    %{root: root, workspace: workspace, data_dir: data_dir}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  # ---------------------------------------------------------------- harness

  defp open(context, parent_script, child_script, overrides \\ %{}) do
    {parent_spec, parent_agent} = NativeModelScript.start(parent_script)
    {child_spec, child_agent} = NativeModelScript.start(child_script)

    options =
      overrides
      |> Map.get(:provider_options, %{})
      |> Map.put("subagent_model", child_spec)

    session_id = "sub-sess-#{System.unique_integer([:positive])}"

    request =
      SessionRequest.new!(
        Map.merge(
          %{
            provider: :native,
            cwd: Map.get(overrides, :cwd, context.workspace),
            model: parent_spec,
            approval_mode: Map.get(overrides, :approval_mode, :auto_approve),
            approval_timeout_ms: 5_000,
            provider_options: options
          },
          Map.drop(overrides, [:provider_options, :approval_mode, :cwd])
        )
      )

    session_context = %{
      session_id: session_id,
      provider: :native,
      owner: self(),
      adapter: Ouroboros.Provider.Native,
      config: %{},
      process_manager: Jido.Harness.ProcessDriver.Erlexec,
      telemetry_context: %{}
    }

    {:ok, handle} = Session.open(request, session_context)
    on_exit(fn -> if Process.alive?(handle), do: Session.close(handle) end)

    %{
      handle: handle,
      session_id: session_id,
      parent_agent: parent_agent,
      child_agent: child_agent,
      child_spec: child_spec
    }
  end

  defp send_turn(handle, text \\ "go", turn_id \\ "turn-1"),
    do: :ok = Session.send(handle, TurnRequest.new!(text), turn_id)

  defp collect_until(type, acc \\ [], timeout \\ 30_000) do
    receive do
      {:session_adapter_event, %{type: ^type} = event} -> Enum.reverse([event | acc])
      {:session_adapter_event, event} -> collect_until(type, [event | acc], timeout)
    after
      timeout -> flunk("no #{type}; saw #{inspect(Enum.map(acc, & &1.type))}")
    end
  end

  defp await_subagent(phase, timeout \\ 30_000) do
    receive do
      {:session_adapter_event,
       %{type: :provider_event, payload: %{"kind" => "subagent", "phase" => ^phase}} = event} ->
        event

      {:session_adapter_event, _other} ->
        await_subagent(phase, timeout)
    after
      timeout -> flunk("no subagent #{phase} event within #{timeout}ms")
    end
  end

  defp subagent_events(events, phase) do
    Enum.filter(events, fn event ->
      event.type == :provider_event and event.payload["kind"] == "subagent" and
        event.payload["phase"] == phase
    end)
  end

  defp tool_result(events, name),
    do: Enum.find(events, &(&1.type == :tool_result and &1.payload["name"] == name))

  defp agent_call(input, id \\ "c1"), do: {:tool_call, %{id: id, name: "agent", input: input}}

  defp finish(text \\ "done"),
    do: [{:text, text}, {:usage, %{input_tokens: 10, output_tokens: 3}}, {:finish, :stop}]

  # ---------------------------------------------------------------- the round trip

  describe "a parent spawns a child" do
    test "the child reads a file in its own session and the parent gets only the summary",
         context do
      %{handle: handle, session_id: session_id} =
        open(
          context,
          [
            [agent_call(%{"prompt" => "summarise lib/a.ex", "description" => "read a.ex"})],
            finish("summarised")
          ],
          [
            [{:tool_call, %{id: "r1", name: "read", input: %{"path" => "lib/a.ex"}}}],
            [
              {:text, "A defines x/0 and returns 1."},
              {:usage, %{input_tokens: 40, output_tokens: 9}},
              {:finish, :stop}
            ]
          ]
        )

      send_turn(handle)
      events = collect_until(:turn_completed)

      [spawned] = subagent_events(events, "spawned")
      assert spawned.payload["task_id"] =~ ~r/\Asub-/
      assert spawned.payload["description"] == "read a.ex"
      assert spawned.payload["background"] == false
      assert spawned.payload["depth"] == 1
      assert spawned.payload["worktree"] == false
      assert spawned.payload["max_turns"] == 12
      assert String.starts_with?(spawned.payload["provider_session_id"], "native-")

      assert [_at_least_one | _] = subagent_events(events, "progress")

      [settled] = subagent_events(events, "settled")
      assert settled.payload["status"] == "completed"
      assert settled.payload["tool_calls"] == 1
      assert settled.payload["input_tokens"] == 40
      assert settled.payload["output_tokens"] == 9

      result = tool_result(events, "agent")
      assert result.payload["is_error"] == false
      assert result.payload["output"] =~ "A defines x/0 and returns 1."
      assert result.payload["output"] =~ "1 tool call(s)"
      assert result.payload["output"] =~ settled.payload["provider_session_id"]

      # The child's own transcript stays where a client can open it later: under the
      # child's session directory, named by the id the spawn event carried. The parent's
      # conversation never contained the file.
      child_dir = Path.join(context.data_dir, settled.payload["provider_session_id"])
      transcript = File.read!(Path.join(child_dir, "conversation.json"))
      assert transcript =~ "def x, do: 1"

      parent_dir = Path.join(context.data_dir, spawned.provider_session_id)
      refute File.read!(Path.join(parent_dir, "conversation.json")) =~ "def x, do: 1"

      assert session_id != settled.payload["provider_session_id"]
    end

    test "the child's usage folds into the parent's own usage and turn totals", context do
      %{handle: handle} =
        open(
          context,
          [[agent_call(%{"prompt" => "look", "description" => "look"})], finish()],
          [
            [
              {:text, "found it"},
              {:usage, %{input_tokens: 71, output_tokens: 13}},
              {:finish, :stop}
            ]
          ]
        )

      send_turn(handle)
      events = collect_until(:turn_completed)

      folded =
        Enum.find(events, &(&1.type == :usage and Map.has_key?(&1.payload, "subagent_task_id")))

      assert folded.payload["input_tokens"] == 71
      assert folded.payload["output_tokens"] == 13

      # The child's request size is a fact about the child's window, so the fold carries
      # no meter — the parent's own `usage` events are the only thing that moves it.
      refute Map.has_key?(folded.payload, "context_window")
      refute Map.has_key?(folded.payload, "context_used")

      completed = List.last(events)
      assert completed.type == :turn_completed
      assert completed.payload["input_tokens"] == 10 + 71
      assert completed.payload["output_tokens"] == 3 + 13

      # …and the parent's context meter did not adopt the child's request size.
      assert {:ok, info} = Session.info(handle)
      assert info.context_used == 10
    end

    test "a child's summary and the events about it are bounded", context do
      %{handle: handle} =
        open(
          context,
          [[agent_call(%{"prompt" => "say a lot", "description" => "verbose"})], finish()],
          [[{:text, String.duplicate("x", 200_000)}, {:finish, :stop}]]
        )

      send_turn(handle)
      events = collect_until(:turn_completed)

      [settled] = subagent_events(events, "settled")
      assert settled.payload["summary_bytes"] <= 12 * 1024 + 8

      result = tool_result(events, "agent")
      assert byte_size(result.payload["output"]) <= 16 * 1024 + 8
    end
  end

  # ---------------------------------------------------------------- the bounds

  describe "what a child may be" do
    test "its tools are the intersection of the allowlist and the parent's own", context do
      %{handle: handle} =
        open(
          context,
          [
            [
              agent_call(%{
                "prompt" => "find things",
                "description" => "search",
                "tools" => ["read", "bash", "write"]
              })
            ],
            finish()
          ],
          [[{:text, "nothing found"}, {:finish, :stop}]],
          %{allowed_tools: ["read", "grep", "agent"]}
        )

      send_turn(handle)
      events = collect_until(:turn_completed)

      [spawned] = subagent_events(events, "spawned")
      assert spawned.payload["tools"] == ["read"]
    end

    test "a child asking for nothing but tools its parent lacks is refused with the list",
         context do
      %{handle: handle} =
        open(
          context,
          [
            [agent_call(%{"prompt" => "run it", "tools" => ["bash", "write"]})],
            finish()
          ],
          [[{:text, "unused"}, {:finish, :stop}]],
          %{allowed_tools: ["read", "agent"]}
        )

      send_turn(handle)
      events = collect_until(:turn_completed)

      result = tool_result(events, "agent")
      assert result.payload["is_error"] == true
      assert result.payload["output"] =~ "only be given tools you already have"
      assert result.payload["output"] =~ "read"
      assert subagent_events(events, "spawned") == []
    end

    test "a grandchild is shown no agent tool and is refused if it invents one", context do
      hidden = Tools.depth_hidden(subagent_depth: AgentTool.max_depth())
      assert hidden == ["agent", "agent_result"]

      names =
        Tools.specs(nil, nil, subagent_depth: AgentTool.max_depth()) |> Enum.map(& &1.name)

      refute "agent" in names
      refute "agent_result" in names
      assert "read" in names

      %{handle: handle} =
        open(
          context,
          [[agent_call(%{"prompt" => "spawn deeper"})], finish()],
          [[{:text, "unused"}, {:finish, :stop}]],
          %{provider_options: %{"subagent_depth" => AgentTool.max_depth()}}
        )

      send_turn(handle)
      events = collect_until(:turn_completed)

      result = tool_result(events, "agent")
      assert result.payload["is_error"] == true
      assert result.payload["output"] =~ "subagent depth cap is 2"
      assert result.payload["output"] =~ "A grandchild may not spawn children"
    end

    test "the fifth concurrent child is refused rather than queued", context do
      %{handle: handle} =
        open(
          context,
          [[agent_call(%{"prompt" => "one more"})], finish()],
          [[{:text, "unused"}, {:finish, :stop}]]
        )

      # Four live children, tracked exactly as a real spawn tracks them. They answer one
      # message and exit, so the session's own teardown does not wait on them.
      for index <- 1..AgentTool.max_concurrent() do
        pid = spawn(fn -> receive do: (_any -> :ok) end)
        assert :ok = GenServer.call(handle, {:subagent_track, "fake-#{index}", pid, %{}})
      end

      send_turn(handle)
      events = collect_until(:turn_completed)

      result = tool_result(events, "agent")
      assert result.payload["is_error"] == true
      assert result.payload["output"] =~ "already running and the limit is 4"
      assert result.payload["output"] =~ "agent_result"
      assert subagent_events(events, "spawned") == []
    end

    test "a child inherits its parent's posture and can never widen it" do
      parent = %{
        depth: 0,
        provider_session_id: "native-parent",
        session_id: "sess-1",
        session_pid: self(),
        request:
          SessionRequest.new!(%{
            provider: :native,
            cwd: File.cwd!(),
            approval_timeout_ms: 1_000,
            disallowed_tools: ["bash"]
          }),
        context: %{owner: self(), session_id: "sess-1", provider: :native},
        scope: %{root: File.cwd!(), roots: [File.cwd!()], sandbox_mode: :read_only},
        model_spec: "scripted:parent",
        approval_mode: :plan,
        tool_names: ["read", "grep", "agent"],
        options: %{},
        subscriber: self(),
        background_subscriber: self(),
        running: 0,
        tracked: 0
      }

      assert {:ok, spec} = AgentTool.plan(%{"prompt" => "explore"}, parent)

      # A planning parent hands its child the plan posture, not a way out of it.
      assert spec.request.sandbox_mode == :read_only
      assert spec.request.approval_mode == :prompt
      assert spec.request.provider_options["plan"] == true
      assert spec.request.disallowed_tools == ["bash"]
      assert spec.request.provider_options["subagent_depth"] == 1
      assert spec.request.provider_options["subagent_parent"] == "native-parent"
      assert spec.depth == 1

      # And there is no parameter on the tool that could have widened any of it.
      assert Keyword.keys(AgentTool.schema()) == [
               :prompt,
               :description,
               :tools,
               :worktree,
               :background,
               :max_turns
             ]

      prompting = %{
        parent
        | approval_mode: :prompt,
          scope: %{parent.scope | sandbox_mode: :workspace_write}
      }

      assert {:ok, prompting_spec} = AgentTool.plan(%{"prompt" => "explore"}, prompting)
      assert prompting_spec.request.approval_mode == :prompt
      assert prompting_spec.request.sandbox_mode == :workspace_write
      refute Map.has_key?(prompting_spec.request.provider_options, "plan")
    end

    test "max_turns is capped and reaches the child as its own iteration bound" do
      parent = %{
        depth: 0,
        provider_session_id: "native-parent",
        session_id: "sess-2",
        session_pid: self(),
        request: SessionRequest.new!(%{provider: :native, cwd: File.cwd!()}),
        context: %{owner: self(), session_id: "sess-2", provider: :native},
        scope: %{root: File.cwd!(), roots: [File.cwd!()], sandbox_mode: :workspace_write},
        model_spec: "scripted:parent",
        approval_mode: :auto_approve,
        tool_names: ["read"],
        options: %{},
        subscriber: self(),
        background_subscriber: self(),
        running: 0,
        tracked: 0
      }

      assert {:ok, spec} = AgentTool.plan(%{"prompt" => "x", "max_turns" => 9_000}, parent)
      assert spec.request.provider_options["max_iterations"] == 30

      assert {:ok, default} = AgentTool.plan(%{"prompt" => "x"}, parent)
      assert default.request.provider_options["max_iterations"] == 12
      assert default.deadline_ms == 300_000

      bounded = %{parent | options: %{"subagent_deadline_ms" => 9_000_000}}
      assert {:ok, clamped} = AgentTool.plan(%{"prompt" => "x"}, bounded)
      assert clamped.deadline_ms == 900_000
    end
  end

  # ---------------------------------------------------------------- deadlines

  describe "the deadline" do
    test "fires, stops the child, and reports timed_out with what it had", context do
      %{handle: handle} =
        open(
          context,
          [[agent_call(%{"prompt" => "take too long", "description" => "slow"})], finish()],
          [
            [{:tool_call, %{id: "b1", name: "bash", input: %{"command" => "sleep 20"}}}],
            [{:text, "late"}, {:finish, :stop}]
          ],
          %{provider_options: %{"subagent_deadline_ms" => 1_500}}
        )

      send_turn(handle)
      events = collect_until(:turn_completed, [], 60_000)

      [settled] = subagent_events(events, "settled")
      assert settled.payload["status"] == "timed_out"

      result = tool_result(events, "agent")
      assert result.payload["is_error"] == true
      assert result.payload["output"] =~ "timed_out"
      assert result.payload["output"] =~ "deadline expired"
    end
  end

  # ---------------------------------------------------------------- background

  describe "a background child" do
    test "returns a task_id, settles on the session's own stream, and is collectable",
         context do
      %{handle: handle} =
        open(
          context,
          [
            [
              agent_call(%{
                "prompt" => "read it",
                "description" => "bg read",
                "background" => true,
                "tools" => ["read"]
              })
            ],
            finish()
          ],
          [
            [{:tool_call, %{id: "r1", name: "read", input: %{"path" => "lib/a.ex"}}}],
            [
              {:text, "it defines x/0"},
              {:usage, %{input_tokens: 5, output_tokens: 2}},
              {:finish, :stop}
            ]
          ]
        )

      send_turn(handle)
      events = collect_until(:turn_completed)

      [spawned] = subagent_events(events, "spawned")
      task_id = spawned.payload["task_id"]
      assert spawned.payload["background"] == true

      result = tool_result(events, "agent")
      assert result.payload["output"] =~ task_id
      assert result.payload["output"] =~ "agent_result"

      # It settles on the *session's* stream, with no turn id: the turn that spawned it
      # has ended, and the work is still this session's.
      settled = await_subagent("settled")
      assert settled.payload["task_id"] == task_id
      assert settled.payload["status"] == "completed"
      assert settled.turn_id == nil

      handles = collector(handle)
      collected = AgentResult.run(%{task_id: task_id, wait_ms: 5_000}, %{subagents: handles})

      assert {:ok, %{output: output, is_error: false}} = collected
      assert output =~ "it defines x/0"
      assert output =~ "completed"

      # Collected means released: a second collection says so rather than answering twice.
      assert {:ok, %{is_error: true, output: again}} =
               AgentResult.run(%{task_id: task_id, wait_ms: 0}, %{subagents: handles})

      assert again =~ "No subagent"
    end

    test "is refused when its tools could ask a person nobody can reach", context do
      %{handle: handle} =
        open(
          context,
          [
            [
              agent_call(%{
                "prompt" => "write something",
                "background" => true,
                "tools" => ["read", "write"]
              })
            ],
            finish()
          ],
          [[{:text, "unused"}, {:finish, :stop}]],
          %{approval_mode: :prompt}
        )

      send_turn(handle)

      # `agent` is an effect, so under `:prompt` the spawn itself is put to a person. The
      # refusal under test is the one *after* that: a person said yes, and the child still
      # cannot be run in the background with tools that could ask them again.
      approve(handle, await_approval().request_id)
      events = collect_until(:turn_completed)

      result = tool_result(events, "agent")
      assert result.payload["is_error"] == true
      assert result.payload["output"] =~ "has nobody to reach"
      assert result.payload["output"] =~ "write"
      assert result.payload["output"] =~ "background: false"
      assert subagent_events(events, "spawned") == []
    end

    test "is stopped when the parent session closes, not when the turn ends", context do
      %{handle: handle} =
        open(
          context,
          [
            [
              agent_call(%{
                "prompt" => "keep going",
                "description" => "long",
                "background" => true
              })
            ],
            finish()
          ],
          [
            [{:tool_call, %{id: "b1", name: "bash", input: %{"command" => "sleep 20"}}}],
            [{:text, "late"}, {:finish, :stop}]
          ]
        )

      send_turn(handle)
      events = collect_until(:turn_completed)
      [spawned] = subagent_events(events, "spawned")
      task_id = spawned.payload["task_id"]

      # The turn is over and the child is still running: that is the whole promise.
      assert {:ok, child} = GenServer.call(handle, {:subagent_lookup, task_id})
      assert Process.alive?(child)

      :ok = Session.close(handle)
      wait_until(fn -> not Process.alive?(child) end)
    end
  end

  # ---------------------------------------------------------------- approvals

  describe "approvals" do
    test "an approval the child raises is put to the parent's own channel", context do
      %{handle: handle} =
        open(
          context,
          [
            [agent_call(%{"prompt" => "write lib/b.ex", "description" => "write b"})],
            finish()
          ],
          [
            [
              {:tool_call,
               %{
                 id: "w1",
                 name: "write",
                 input: %{"path" => "lib/b.ex", "content" => "defmodule B do\nend\n"}
               }}
            ],
            [{:text, "wrote it"}, {:finish, :stop}]
          ],
          %{approval_mode: :prompt}
        )

      send_turn(handle)

      # The `agent` call itself is an effect and asks first.
      spawn_request = await_approval()
      refute Map.has_key?(spawn_request.payload, "subagent")
      approve(handle, spawn_request.request_id)

      # Then the child's own write asks — on this session's channel, with a request id
      # this session minted, carrying which child is asking.
      child_request = await_approval()
      assert child_request.payload["kind"] == "file_change"
      assert child_request.payload["subagent"]["description"] == "write b"
      assert child_request.request_id != spawn_request.request_id
      approve(handle, child_request.request_id)

      events = collect_until(:turn_completed)

      [settled] = subagent_events(events, "settled")
      assert settled.payload["status"] == "completed"
      assert settled.payload["files_changed"] == 1

      assert File.read!(Path.join(context.workspace, "lib/b.ex")) =~ "defmodule B"
    end

    test "interrupting the parent stops the child and says it was stopped", context do
      %{handle: handle} =
        open(
          context,
          [[agent_call(%{"prompt" => "long job", "description" => "long"})], finish()],
          [
            [{:tool_call, %{id: "b1", name: "bash", input: %{"command" => "sleep 20"}}}],
            [{:text, "late"}, {:finish, :stop}]
          ]
        )

      send_turn(handle)
      spawned = await_subagent("spawned")
      assert :ok = Session.interrupt(handle, :active)

      events = collect_until(:turn_interrupted, [], 60_000)
      [settled] = subagent_events(events, "settled")

      assert settled.payload["task_id"] == spawned.payload["task_id"]
      assert settled.payload["status"] == "stopped"
    end
  end

  # ---------------------------------------------------------------- worktrees

  describe "a worktree child" do
    setup context do
      git(context.workspace, ["init", "--initial-branch=main"])
      git(context.workspace, ["add", "."])

      git(context.workspace, [
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "user.name=Ouroboros Test",
        "commit",
        "-m",
        "base"
      ])

      # This block runs the *no data directory* posture, and that is a finding rather than
      # a convenience. `Ouroboros.Workspace.Worktree.root/1` puts worktrees under
      # `<data_dir>/worktrees`, and `Ouroboros.Control.Permissions.Rules` protects
      # `<data_dir>/**` from every write with a rule no rule can overrule — so on a node
      # *with* a data directory, no session can write inside a worktree at all, D7's own
      # included. The last test in this block pins that so it stays visible.
      #
      # The root is created before the admission check runs, because
      # `Worktree.admissible?/1` canonicalizes a root that exists and compares the literal
      # string for one that does not, and on a host whose temp directory is a symlink those
      # are two different answers.
      Application.delete_env(:ouroboros, :data_dir)
      worktree_root = Worktree.root([])
      File.mkdir_p!(worktree_root)
      Application.put_env(:ouroboros, :workspace_allowed_roots, [worktree_root])

      %{worktree_root: worktree_root}
    end

    test "edits inside the worktree and leaves the parent's tree untouched", context do
      %{handle: handle} =
        open(
          context,
          [
            [
              agent_call(%{
                "prompt" => "add lib/b.ex",
                "description" => "isolated write",
                "worktree" => true
              })
            ],
            finish()
          ],
          [
            [
              {:tool_call,
               %{
                 id: "w1",
                 name: "write",
                 input: %{"path" => "lib/b.ex", "content" => "defmodule B do\nend\n"}
               }}
            ],
            [{:text, "wrote it in the worktree"}, {:finish, :stop}]
          ]
        )

      send_turn(handle)
      events = collect_until(:turn_completed, [], 60_000)

      [spawned] = subagent_events(events, "spawned")
      assert spawned.payload["worktree"] == true
      assert String.contains?(spawned.payload["workspace"], "worktrees")
      refute spawned.payload["workspace"] == context.workspace

      [settled] = subagent_events(events, "settled")
      assert settled.payload["status"] == "completed"
      assert settled.payload["files_changed"] == 1

      # The worktree holds uncommitted work, so it is kept and its path is reported rather
      # than deleted along with the child.
      assert settled.payload["worktree"]["retired"] == "kept"
      worktree_path = settled.payload["worktree"]["path"]
      on_exit(fn -> File.rm_rf(worktree_path) end)

      assert File.read!(Path.join(worktree_path, "lib/b.ex")) =~ "defmodule B"
      refute File.exists?(Path.join(context.workspace, "lib/b.ex"))

      result = tool_result(events, "agent")
      assert result.payload["output"] =~ "Worktree kept"
    end

    # A limit of where D7 puts worktrees, not of G3, pinned here so it is visible rather
    # than folklore. `Ouroboros.Control.Permissions.Rules` protects `<data_dir>/**` from
    # every write and says outright that no rule turns it off; `Workspace.Worktree.root/1`
    # puts worktrees under `<data_dir>/worktrees`. So on a node with a data directory —
    # every release — a session running in a worktree can write nothing at all. Delete this
    # test when the worktree root moves out of the data directory, or when the protected
    # list exempts it.
    test "with a data directory configured the node's protected-path rule denies the child's writes",
         context do
      File.mkdir_p!(Path.join(context.data_dir, "worktrees"))
      Application.put_env(:ouroboros, :data_dir, context.data_dir)
      Application.put_env(:ouroboros, :workspace_allowed_roots, [context.data_dir])

      %{handle: handle} =
        open(
          context,
          [[agent_call(%{"prompt" => "add lib/b.ex", "worktree" => true})], finish()],
          [
            [
              {:tool_call,
               %{id: "w1", name: "write", input: %{"path" => "lib/b.ex", "content" => "x"}}}
            ],
            [{:text, "tried"}, {:finish, :stop}]
          ]
        )

      send_turn(handle)
      events = collect_until(:turn_completed, [], 60_000)

      [settled] = subagent_events(events, "settled")
      on_exit(fn -> File.rm_rf(settled.payload["worktree"]["path"]) end)

      assert settled.payload["files_changed"] == 0

      transcript =
        File.read!(
          Path.join([
            context.data_dir,
            settled.payload["provider_session_id"],
            "conversation.json"
          ])
        )

      assert transcript =~ "protected-path"
    end

    test "a worktree this node cannot lease is refused rather than silently shared",
         context do
      Application.put_env(:ouroboros, :workspace_allowed_roots, [])

      %{handle: handle} =
        open(
          context,
          [[agent_call(%{"prompt" => "isolate me", "worktree" => true})], finish()],
          [[{:text, "unused"}, {:finish, :stop}]]
        )

      send_turn(handle)
      events = collect_until(:turn_completed)

      result = tool_result(events, "agent")
      assert result.payload["is_error"] == true
      assert result.payload["output"] =~ "workspace_allowed_roots"
      assert result.payload["output"] =~ "OUROBOROS_WORKSPACE_ROOTS"
      assert subagent_events(events, "spawned") == []
    end
  end

  # ---------------------------------------------------------------- the ledger

  describe "the ledger" do
    test "the agent call is an entry and the child's calls name the parent it ran under",
         context do
      %{handle: handle, session_id: session_id} =
        open(
          context,
          [[agent_call(%{"prompt" => "read it", "description" => "reader"})], finish()],
          [
            [{:tool_call, %{id: "r1", name: "read", input: %{"path" => "lib/a.ex"}}}],
            [{:text, "read"}, {:finish, :stop}]
          ]
        )

      send_turn(handle)
      events = collect_until(:turn_completed)
      [spawned] = subagent_events(events, "spawned")

      {:ok, entries} =
        EffectLedger.list(principal: "session:" <> session_id, effect: :tool_call)

      by_tool = Map.new(entries, &{&1.attempt.tool, &1})

      assert %{} = parent_entry = by_tool["agent"]
      assert parent_entry.attempt.session_id == session_id
      assert parent_entry.attempt.provider == :native
      assert parent_entry.cause.signal_type == "native.tool_call"
      refute Map.has_key?(parent_entry.authority.constraints, :subagent_parent)

      assert %{} = child_entry = by_tool["read"]
      assert child_entry.attempt.session_id == session_id
      assert child_entry.cause.signal_type == "native.subagent.tool_call"
      assert child_entry.authority.constraints.subagent_parent == spawned.provider_session_id
      assert is_binary(child_entry.authority.constraints.subagent_task_id)

      # The child's own turn is its own: a reader can tell the two apart without guessing.
      assert child_entry.attempt.turn_id != parent_entry.attempt.turn_id
      assert String.starts_with?(child_entry.attempt.turn_id, "sub_turn_")
    end
  end

  # ---------------------------------------------------------------- helpers

  defp collector(handle) do
    %{
      lookup: fn task_id ->
        case GenServer.call(handle, {:subagent_lookup, task_id}) do
          {:ok, pid} -> {:ok, pid}
          :error -> :error
        end
      end,
      release: fn task_id -> GenServer.call(handle, {:subagent_release, task_id}) end
    }
  end

  defp await_approval(timeout \\ 30_000) do
    receive do
      {:session_adapter_event, %{type: :approval_requested} = event} -> event
      {:session_adapter_event, _other} -> await_approval(timeout)
    after
      timeout -> flunk("no approval_requested within #{timeout}ms")
    end
  end

  defp approve(handle, request_id) do
    :ok =
      Session.respond_approval(
        handle,
        request_id,
        ApprovalResponse.new!(%{decision: :approve, scope: :once})
      )
  end

  defp git(cwd, argv) do
    {output, status} = System.cmd("git", argv, cd: cwd, stderr_to_stdout: true)
    assert status == 0, "git #{Enum.join(argv, " ")} failed: #{output}"
    :ok
  end

  defp wait_until(fun, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 15_000

    cond do
      fun.() -> :ok
      System.monotonic_time(:millisecond) > deadline -> flunk("condition never held")
      true -> Process.sleep(25) && wait_until(fun, deadline)
    end
  end

  # `Subagent.render/1` is what a tool result carries, so its shape is asserted directly
  # rather than only through a session that happened to produce one.
  describe "the summary" do
    test "names the status, the digest, and where the transcript is" do
      rendered =
        Subagent.render(%{
          task_id: "sub-abc",
          description: "explore",
          provider_session_id: "native-x-y",
          session_dir: "/tmp/x",
          status: :stopped,
          error: "the parent stopped this child",
          turns: 3,
          tool_calls: 7,
          files_changed: ["lib/a.ex"],
          files_changed_count: 1,
          approvals_denied: 2,
          usage: %{input: 100, output: 20, cost: nil},
          text: "what I found",
          worktree: nil,
          background: true,
          depth: 1,
          tools: ["read"]
        })

      assert rendered =~ "Subagent sub-abc (explore) stopped."
      assert rendered =~ "the parent stopped this child"
      assert rendered =~ "3 model turn(s), 7 tool call(s), 1 file(s) changed"
      assert rendered =~ "100 in / 20 out tokens"
      assert rendered =~ "Files: lib/a.ex"
      assert rendered =~ "2 approval(s) this child raised were denied"
      assert rendered =~ "Transcript: native-x-y"

      # An unpriced child says nothing about cost rather than saying it was free.
      refute rendered =~ "$"
    end
  end
end
