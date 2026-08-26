defmodule Ouroboros.Provider.Native.RewindTest do
  @moduledoc """
  `/rewind` end to end: a live session edits files across several turns, then goes back.

  This is the test that matters for D10's claim, because the claim is about a *session* —
  files and conversation together, and an honest account of what is beyond reach before
  the operator commits.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.SessionRequest
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.{Paths, Session}
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-rewind-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")

    data_dir = Path.join(root, "data")
    File.mkdir_p!(data_dir)

    previous_dir = Application.get_env(:ouroboros, :native_data_dir)
    previous_model = Application.get_env(:ouroboros, :native_model_module)
    Application.put_env(:ouroboros, :native_data_dir, data_dir)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      restore(:native_data_dir, previous_dir)
      restore(:native_model_module, previous_model)
      File.rm_rf(root)
    end)

    # macOS puts the temp root behind a `/private` symlink, and the session resolves
    # `cwd` through it. A test comparing paths has to compare the canonical ones.
    {:ok, canonical} = Ouroboros.Workspace.Path.canonicalize(workspace)

    %{root: root, workspace: workspace, canonical: canonical}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  defp open(context, script, overrides \\ %{}) do
    {model_spec, agent} = NativeModelScript.start(script)

    request =
      SessionRequest.new!(
        Map.merge(
          %{
            provider: :native,
            cwd: context.workspace,
            model: model_spec,
            approval_mode: :auto_approve,
            approval_timeout_ms: 2_000
          },
          overrides
        )
      )

    {:ok, handle} = Session.open(request, session_context())
    on_exit(fn -> if Process.alive?(handle), do: Session.close(handle) end)
    %{handle: handle, agent: agent}
  end

  defp session_context do
    %{
      session_id: "sess-#{System.unique_integer([:positive])}",
      provider: :native,
      owner: self(),
      adapter: Ouroboros.Provider.Native,
      config: %{},
      process_manager: Jido.Harness.ProcessDriver.Erlexec,
      telemetry_context: %{}
    }
  end

  defp turn(handle, turn_id, prompt \\ "go") do
    :ok = Session.send(handle, TurnRequest.new!(prompt), turn_id)
    await_terminal()
  end

  defp await_terminal(acc \\ []) do
    receive do
      {:session_adapter_event, %{type: type} = event}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        Enum.reverse([event | acc])

      {:session_adapter_event, event} ->
        await_terminal([event | acc])
    after
      20_000 -> flunk("no terminal turn event within 20s")
    end
  end

  defp drain do
    receive do
      {:session_adapter_event, _event} -> drain()
    after
      50 -> :ok
    end
  end

  defp write_call(id, path, content),
    do: {:tool_call, %{id: id, name: "write", input: %{"path" => path, "content" => content}}}

  defp done, do: [{:text, "done"}, {:finish, :stop}]

  # Three turns: create a file, change it, change it again.
  defp three_turn_script do
    [
      [write_call("c1", "lib/b.ex", "first\n")],
      [{:text, "made b"}, {:finish, :stop}],
      [write_call("c2", "lib/b.ex", "second\n")],
      [{:text, "changed b"}, {:finish, :stop}],
      [write_call("c3", "lib/b.ex", "third\n")],
      [{:text, "changed b again"}, {:finish, :stop}]
    ]
  end

  # One write per turn, so every turn is exactly four messages: the prompt, the assistant
  # message that called `write`, its result, and the assistant message that ends the turn.
  # That is what makes the trim arithmetic in the resume tests below checkable by hand.
  defp writing_turns(count) do
    Enum.flat_map(1..count, fn index ->
      [[write_call("c#{index}", "lib/b.ex", "body #{index}\n")], done()]
    end)
  end

  describe "rewind_points/1" do
    test "one row per turn, in order, with what each touched", context do
      %{handle: handle} = open(context, three_turn_script())

      turn(handle, "t1")
      turn(handle, "t2")
      turn(handle, "t3")
      drain()

      assert {:ok, points} = Session.rewind_points(handle)
      assert Enum.map(points, & &1["turn_id"]) == ["t1", "t2", "t3"]
      assert Enum.all?(points, &(&1["files"] == 1))
      assert Enum.all?(points, &(&1["commands"] == 0))
    end

    test "each turn also announces its own summary as it finishes", context do
      %{handle: handle} = open(context, three_turn_script())

      events = turn(handle, "t1")

      summary =
        Enum.find(events, &(&1.type == :provider_event and &1.payload["kind"] == "checkpoint"))

      assert summary
      assert summary.payload["turn"]["turn_id"] == "t1"
      assert summary.payload["turn"]["files"] == 1
    end
  end

  describe "rewind/3" do
    test ":files restores byte-exact and leaves the conversation alone", context do
      %{handle: handle} = open(context, three_turn_script())
      file = Path.join(context.canonical, "lib/b.ex")

      turn(handle, "t1")
      turn(handle, "t2")
      turn(handle, "t3")
      drain()

      assert File.read!(file) == "third\n"
      assert {:ok, outcome} = Session.rewind(handle, "t1", :files)

      assert File.read!(file) == "first\n"
      assert outcome.restored == [%{path: file, action: "restored"}]
      assert outcome.unrestorable == []
      assert outcome.turns == ["t2", "t3"]
      # The transcript is untouched by a files-only rewind.
      assert outcome.messages > 0
    end

    test ":both also truncates the conversation to that turn", context do
      %{handle: handle, agent: agent} = open(context, three_turn_script())

      turn(handle, "t1")
      turn(handle, "t2")
      turn(handle, "t3")
      drain()

      before_rewind = NativeModelScript.requests(agent) |> List.last() |> Map.fetch!(:messages)

      assert {:ok, outcome} = Session.rewind(handle, "t1", :both)
      assert outcome.messages < length(before_rewind)

      # The next turn's model call starts from the truncated conversation.
      :ok = Session.send(handle, TurnRequest.new!("continue"), "t4")
      await_terminal()

      after_rewind = NativeModelScript.requests(agent) |> List.last() |> Map.fetch!(:messages)
      assert length(after_rewind) == outcome.messages + 1
      refute Enum.any?(after_rewind, &(&1[:content] == "changed b again"))
    end

    test ":conversation truncates and leaves every file where it is", context do
      %{handle: handle} = open(context, three_turn_script())
      file = Path.join(context.canonical, "lib/b.ex")

      turn(handle, "t1")
      turn(handle, "t2")
      drain()

      assert {:ok, outcome} = Session.rewind(handle, "t1", :conversation)

      assert File.read!(file) == "second\n"
      assert outcome.restored == []
      assert outcome.turns == []
    end

    test "rewinding to the start deletes a file the session created", context do
      %{handle: handle} = open(context, three_turn_script())
      file = Path.join(context.canonical, "lib/b.ex")

      turn(handle, "t1")
      drain()
      assert File.exists?(file)

      assert {:ok, outcome} = Session.rewind(handle, 0, :files)

      refute File.exists?(file)
      assert outcome.restored == [%{path: file, action: "deleted"}]
    end

    test "a bash-made change is listed as unrestorable, by turn, and named", context do
      script = [
        [
          {:tool_call,
           %{
             id: "c1",
             name: "bash",
             input: %{"command" => "echo 'made by a shell' > lib/shell_made.txt"}
           }}
        ],
        [{:text, "ran it"}, {:finish, :stop}],
        [write_call("c2", "lib/b.ex", "tracked\n")],
        [{:text, "wrote it"}, {:finish, :stop}]
      ]

      %{handle: handle} = open(context, script)
      shell_made = Path.join(context.canonical, "lib/shell_made.txt")

      turn(handle, "t1")
      turn(handle, "t2")
      drain()

      assert File.exists?(shell_made)
      assert {:ok, outcome} = Session.rewind(handle, 0, :files)

      # The tracked write is undone...
      refute File.exists?(Path.join(context.canonical, "lib/b.ex"))

      # ...and the shell's file is still there, reported rather than silently missed.
      assert File.exists?(shell_made)
      assert [warning] = outcome.unrestorable
      assert warning.turn_id == "t1"
      assert warning.reason =~ "shell command"
      assert warning.reason =~ "cannot be restored"
    end

    test "both halves are announced in the transcript", context do
      %{handle: handle} = open(context, three_turn_script())

      turn(handle, "t1")
      turn(handle, "t2")
      drain()

      {:ok, _outcome} = Session.rewind(handle, "t1", :both)

      change = await_event(:file_change)
      assert [entry] = change.payload["changes"]
      assert entry["reason"] == "rewind"
      assert entry["relative_path"] == "lib/b.ex"

      status = await_event(:provider_event)
      assert status.payload["kind"] == "status"
      assert status.payload["event"] == "rewind"
      assert status.payload["to_turn"] == "t1"
      assert status.payload["what"] == "both"
      assert status.payload["restored"] == 1
    end

    test "an unknown turn id is refused and changes nothing", context do
      %{handle: handle} = open(context, three_turn_script())
      file = Path.join(context.canonical, "lib/b.ex")

      turn(handle, "t1")
      drain()

      assert {:error, {:unknown_turn, "not-a-turn"}} =
               Session.rewind(handle, "not-a-turn", :files)

      assert File.read!(file) == "first\n"
    end

    # The manifest used to be append-only, so the turns a rewind undid stayed in it. A
    # second rewind then restored file contents this session's timeline never had, and
    # offered the operator a turn boundary the transcript no longer contained.
    test "the undone turns leave the manifest and cannot be rewound to again", context do
      %{handle: handle} =
        open(context, three_turn_script() ++ [[write_call("c4", "lib/b.ex", "fourth\n")], done()])

      turn(handle, "t1")
      turn(handle, "t2")
      turn(handle, "t3")
      drain()

      assert {:ok, _outcome} = Session.rewind(handle, "t1", :both)
      drain()

      turn(handle, "t4")
      drain()

      assert {:ok, points} = Session.rewind_points(handle)
      assert Enum.map(points, & &1["turn_id"]) == ["t1", "t4"]

      assert {:error, {:unknown_turn, "t2"}} = Session.rewind(handle, "t2", :both)
      assert File.read!(Path.join(context.canonical, "lib/b.ex")) == "fourth\n"
    end

    test "is refused while a turn is running", context do
      script = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "sleep 0.6"}}}],
        [{:text, "done"}, {:finish, :stop}]
      ]

      %{handle: handle} = open(context, script)
      :ok = Session.send(handle, TurnRequest.new!("go"), "t1")

      # Wait for the tool to start, so the loop is demonstrably mid-turn.
      await_event(:tool_call)

      assert {:error, :busy} = Session.rewind(handle, 0, :files)
      await_terminal()
    end
  end

  # `event_limit: 8` keeps eight messages, so a session of four-message turns has dropped
  # the head of its own conversation by the third one. The turn manifest counts from the
  # start of the session either way, and a rewind that compared those counts against the
  # tail it holds after a resume either did nothing or kept a window out of the middle of
  # the conversation and called it a turn.
  describe "rewind after a resume that trimmed the transcript" do
    test "cuts at a real turn boundary", context do
      %{handle: handle} =
        open(context, writing_turns(3), %{provider_options: %{event_limit: 8}})

      ready = await_event(:provider_event)

      turn(handle, "t1", "one")
      turn(handle, "t2", "two")
      turn(handle, "t3", "three")
      drain()

      :ok = Session.close(handle)
      drain()

      {model_spec, agent} = NativeModelScript.start([done()])

      request =
        SessionRequest.new!(%{
          provider: :native,
          cwd: context.workspace,
          model: model_spec,
          approval_mode: :auto_approve,
          approval_timeout_ms: 2_000,
          provider_session_id: ready.provider_session_id,
          provider_options: %{event_limit: 8}
        })

      {:ok, resumed} = Session.open(request, session_context())
      on_exit(fn -> if Process.alive?(resumed), do: Session.close(resumed) end)
      drain()

      # Twelve messages were written, eight survive: the transcript now starts at the
      # second turn, and the second turn ended at absolute message eight.
      assert {:ok, outcome} = Session.rewind(resumed, "t2", :both)
      refute Map.has_key?(outcome, :checkpoint_error)
      assert outcome.messages == 4

      # The head of what survived is the start of a turn, not the middle of one.
      :ok = Session.send(resumed, TurnRequest.new!("continue"), "t4")
      await_terminal()

      [call] = NativeModelScript.requests(agent)
      assert Enum.map(call.messages, & &1.role) == [:user, :assistant, :tool, :assistant, :user]
      assert hd(call.messages).content == "two"
    end

    test "says so rather than silently succeeding when the boundary was trimmed away",
         context do
      %{handle: handle} =
        open(context, writing_turns(4), %{provider_options: %{event_limit: 8}})

      ready = await_event(:provider_event)

      turn(handle, "t1", "one")
      turn(handle, "t2", "two")
      turn(handle, "t3", "three")
      turn(handle, "t4", "four")
      drain()

      :ok = Session.close(handle)
      drain()

      {model_spec, _agent} = NativeModelScript.start([done()])

      request =
        SessionRequest.new!(%{
          provider: :native,
          cwd: context.workspace,
          model: model_spec,
          approval_mode: :auto_approve,
          approval_timeout_ms: 2_000,
          provider_session_id: ready.provider_session_id,
          provider_options: %{event_limit: 8}
        })

      {:ok, resumed} = Session.open(request, session_context())
      on_exit(fn -> if Process.alive?(resumed), do: Session.close(resumed) end)
      drain()

      file = Path.join(context.canonical, "lib/b.ex")
      assert File.read!(file) == "body 4\n"

      # Sixteen messages were written and eight survive, so the first turn's boundary is
      # older than anything this session still holds. The files half is honoured and the
      # conversation half is refused *by name* — not reported as a success that quietly
      # left the transcript alone.
      assert {:error, {:rewind_checkpoint_failed, reason, outcome}} =
               Session.rewind(resumed, "t1", :both)

      assert reason == {:turn_boundary_dropped, "t1"}
      assert outcome.checkpoint_error == reason
      assert outcome.messages == 8
      assert File.read!(file) == "body 1\n"

      status = await_status_event()
      assert status.payload["event"] == "rewind"
      assert status.payload["conversation_error"] =~ "turn_boundary_dropped"
    end

    test "an old checkpoint without offset still refuses a boundary inside the trimmed tail",
         context do
      %{handle: handle} =
        open(context, writing_turns(4), %{provider_options: %{event_limit: 8}})

      ready = await_event(:provider_event)

      turn(handle, "t1", "one")
      turn(handle, "t2", "two")
      turn(handle, "t3", "three")
      turn(handle, "t4", "four")
      drain()

      :ok = Session.close(handle)
      drain()

      {:ok, dir, _durable?} = Paths.session_dir(ready.provider_session_id)
      path = Path.join(dir, "conversation.json")
      payload = path |> File.read!() |> JSON.decode!()
      assert payload["offset"] > 0
      File.write!(path, JSON.encode!(Map.drop(payload, ["offset", "rewind_floor"])))

      {model_spec, _agent} = NativeModelScript.start([done()])

      request =
        SessionRequest.new!(%{
          provider: :native,
          cwd: context.workspace,
          model: model_spec,
          approval_mode: :auto_approve,
          approval_timeout_ms: 2_000,
          provider_session_id: ready.provider_session_id,
          provider_options: %{event_limit: 8}
        })

      {:ok, resumed} = Session.open(request, session_context())
      on_exit(fn -> if Process.alive?(resumed), do: Session.close(resumed) end)
      drain()

      # Sixteen messages, eight survive. Without the inferred offset a rewind to t1 would
      # take the first four of the tail and call it a turn boundary. With it, the
      # boundary is named as dropped.
      assert {:error, {:rewind_checkpoint_failed, reason, _outcome}} =
               Session.rewind(resumed, "t1", :both)

      assert reason == {:turn_boundary_dropped, "t1"}
    end
  end

  test "a rewind after a compaction cuts at the summary, not mid-history", context do
    script = [
      [write_call("c1", "lib/b.ex", "first\n")],
      [
        {:text, String.duplicate("a long stretch of assistant prose. ", 4_000)},
        {:finish, :stop}
      ],
      [write_call("c2", "lib/b.ex", "second\n")],
      [{:text, "changed b"}, {:finish, :stop}],
      [{:text, "## Goal\n\nkeep going"}],
      [{:text, "carrying on"}, {:finish, :stop}]
    ]

    %{handle: handle, agent: agent} =
      open(context, script, %{provider_options: %{keep_recent_tokens: 200}})

    file = Path.join(context.canonical, "lib/b.ex")

    turn(handle, "t1")
    turn(handle, "t2")
    drain()

    assert {:ok, report} = Session.compact(handle, nil)
    assert report.archived_messages > 0
    drain()

    # Compaction puts a summary where the head of the conversation used to be, so the
    # manifest's counts stop indexing this list directly. The first turn's messages are
    # exactly what that summary now stands for, and one message is the honest answer.
    assert {:ok, outcome} = Session.rewind(handle, "t1", :both)
    refute Map.has_key?(outcome, :checkpoint_error)
    assert outcome.messages == 1
    assert File.read!(file) == "first\n"

    :ok = Session.send(handle, TurnRequest.new!("continue"), "t3")
    await_terminal()

    [request] = Enum.take(NativeModelScript.requests(agent), -1)
    assert length(request.messages) == 2
    assert hd(request.messages).content =~ "compacted"
    refute Enum.any?(request.messages, &(&1[:content] == "changed b"))
  end

  defp await_status_event do
    event = await_event(:provider_event)
    if event.payload["kind"] == "status", do: event, else: await_status_event()
  end

  defp await_event(type) do
    receive do
      {:session_adapter_event, %{type: ^type} = event} -> event
      {:session_adapter_event, _other} -> await_event(type)
    after
      15_000 -> flunk("no #{type} within 15s")
    end
  end
end
