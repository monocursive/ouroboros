defmodule Ouroboros.Provider.Native.InteractivePlaneTest do
  @moduledoc """
  `Ouroboros.InteractiveSession` against `provider: :native`, with nothing special asked
  for — no transport named, no option a vendor provider would not also take.

  This is the D1 acceptance claim in its plainest form: a caller who picks this provider
  the way they pick `codex` gets a durable session, the normalized event stream, and a
  `provider_session_id` this runtime can resume from. Everything below the plane is
  covered by the transport and loop tests; what is under test here is that the plane
  needs no special case.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Interactive.{Ref, State, Store}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Provider.Native.{Journal, Paths}
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-plane-#{System.unique_integer([:positive])}")
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

    %{root: root, workspace: workspace}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  defp await_replay(session, predicate, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 15_000
    {:ok, events} = InteractiveSession.replay(session, cursor: 0, limit: 200)

    cond do
      predicate.(events) ->
        events

      System.monotonic_time(:millisecond) > deadline ->
        flunk("condition never held; saw #{inspect(Enum.map(events, & &1.type))}")

      true ->
        Process.sleep(25)
        await_replay(session, predicate, deadline)
    end
  end

  defp await_turns(session, count) do
    await_replay(session, fn events ->
      Enum.count(events, &(&1.type == :turn_completed)) >= count
    end)
  end

  test "a session started the ordinary way runs a turn and keeps a resumable id", context do
    {model_spec, _agent} =
      NativeModelScript.start([
        [
          {:text, "reading"},
          {:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}
        ],
        [{:text, "all good"}, {:usage, %{input_tokens: 7, output_tokens: 2}}, {:finish, :stop}]
      ])

    assert {:ok, session} =
             InteractiveSession.start(
               id: "native-plane-#{System.unique_integer([:positive])}",
               provider: :native,
               workspace: context.workspace,
               model: model_spec,
               approval_mode: :auto_approve
             )

    on_exit(fn -> InteractiveSession.close(session) end)

    assert {:ok, _turn} =
             InteractiveSession.send_message(session, "look at lib/a.ex", id: "turn-1")

    events =
      await_replay(session, fn events -> Enum.any?(events, &(&1.type == :turn_completed)) end)

    types = Enum.map(events, & &1.type)

    assert :session_started in types
    assert :session_ready in types
    assert :tool_call in types
    assert :tool_result in types
    assert :usage in types

    assert {:ok, info} = InteractiveSession.info(session)
    assert info.provider == :native
    assert String.starts_with?(info.provider_session_id, "native-")

    result = Enum.find(events, &(&1.type == :tool_result))
    assert result.payload["output"] =~ "def x, do: 1"
  end

  test "the plane's default approval_mode is not refused, unlike a managed transport",
       context do
    {model_spec, _agent} = NativeModelScript.start([[{:text, "hi"}, {:finish, :stop}]])

    # X1 refuses `:prompt` on a transport with no approvals channel. This transport has
    # one, so the plane default survives all the way to a started session.
    assert {:ok, session} =
             InteractiveSession.start(
               id: "native-prompt-#{System.unique_integer([:positive])}",
               provider: :native,
               workspace: context.workspace,
               model: model_spec
             )

    on_exit(fn -> InteractiveSession.close(session) end)

    assert {:ok, info} = InteractiveSession.info(session)
    assert info.provider == :native
  end

  # G3's acceptance claim at the level a client actually sees it: a subagent needs no
  # plane change at all. The parent is an ordinary interactive session, the child never
  # becomes a second one, and everything a client would draw a child row from is in the
  # parent's own replayed event stream.
  test "a subagent's whole round trip is in the parent session's replayed events",
       context do
    {child_spec, _child} =
      NativeModelScript.start([
        [{:tool_call, %{id: "r1", name: "read", input: %{"path" => "lib/a.ex"}}}],
        [
          {:text, "A defines x/0 and returns 1."},
          {:usage, %{input_tokens: 61, output_tokens: 12}},
          {:finish, :stop}
        ]
      ])

    {parent_spec, _parent} =
      NativeModelScript.start([
        [
          {:tool_call,
           %{
             id: "c1",
             name: "agent",
             input: %{
               "prompt" => "summarise lib/a.ex",
               "description" => "read a.ex",
               "tools" => ["read"]
             }
           }}
        ],
        [
          {:text, "The child says A defines x/0."},
          {:usage, %{input_tokens: 20, output_tokens: 6}},
          {:finish, :stop}
        ]
      ])

    assert {:ok, session} =
             InteractiveSession.start(
               id: "native-subagent-#{System.unique_integer([:positive])}",
               provider: :native,
               workspace: context.workspace,
               model: parent_spec,
               approval_mode: :auto_approve,
               provider_options: %{"subagent_model" => child_spec}
             )

    on_exit(fn -> InteractiveSession.close(session) end)

    assert {:ok, _turn} =
             InteractiveSession.send_message(session, "summarise lib/a.ex", id: "turn-1")

    events =
      await_replay(session, fn events -> Enum.any?(events, &(&1.type == :turn_completed)) end)

    subagent =
      Enum.filter(events, fn event ->
        event.type == :provider_event and event.payload["kind"] == "subagent"
      end)

    assert Enum.map(subagent, & &1.payload["phase"]) |> Enum.uniq() |> Enum.sort() ==
             ["progress", "settled", "spawned"]

    spawned = Enum.find(subagent, &(&1.payload["phase"] == "spawned"))
    settled = Enum.find(subagent, &(&1.payload["phase"] == "settled"))

    assert spawned.payload["tools"] == ["read"]
    assert spawned.payload["depth"] == 1
    assert settled.payload["status"] == "completed"
    assert settled.payload["tool_calls"] == 1
    assert settled.payload["input_tokens"] == 61

    # The plane produced no second session for the child, and no second rail row: the
    # child is named only by a provider session id inside the parent's events.
    assert {:ok, info} = InteractiveSession.info(session)
    assert info.provider_session_id == spawned.provider_session_id
    refute info.provider_session_id == settled.payload["provider_session_id"]

    result =
      Enum.find(events, &(&1.type == :tool_result and &1.payload["name"] == "agent"))

    assert result.payload["output"] =~ "A defines x/0 and returns 1."

    # The child's spend is on the parent's stream as `usage`, so a footer that sums them
    # is right, and it carries no context meter, so a footer that reads one is untouched.
    folded =
      Enum.find(events, &(&1.type == :usage and Map.has_key?(&1.payload, "subagent_task_id")))

    assert folded.payload["input_tokens"] == 61
    refute Map.has_key?(folded.payload, "context_window")

    # The child's own turn id, so the plane accounts it as its own contribution and adds it
    # rather than reading it as the parent re-reporting a running total. See
    # `Loop.fold_subagent_usage/3`.
    assert String.starts_with?(folded.turn_id, "sub_turn_")

    completed = Enum.find(events, &(&1.type == :turn_completed))
    assert completed.payload["input_tokens"] == 20 + 61

    # …and the plane's own accounting, which is what `/cost` reads, has both in it.
    assert {:ok, info} = InteractiveSession.info(session)
    assert info.usage.total_tokens == 73 + 26

    if System.get_env("OUROBOROS_SHOW_SUBAGENT_EVENTS") == "1" do
      for event <- events do
        IO.puts("#{event.type} #{inspect(event.payload, limit: :infinity)}")
      end
    end
  end

  # R3, end to end at the level a client uses: `interactive.fork` with the two new
  # parameters, over a provider that has a conversation to cut and real models to
  # substitute. The pieces below the plane are covered by
  # `Ouroboros.Provider.Native.ForkAtTurnTest`; what is under test here is that the plane
  # threads both of them from the caller's map to the child's start request without a
  # special case, and that the child's *journal* is what names the substituted model —
  # which is what makes a fork-for-eval self-describing after the fact.
  test "a fork carries a branch point and a substituted model to the child", context do
    {parent_spec, _parent_agent} =
      NativeModelScript.start([
        [
          {:tool_call,
           %{
             id: "w1",
             name: "write",
             input: %{"path" => "lib/b.ex", "content" => "first\n"}
           }}
        ],
        [{:text, "wrote first"}, {:finish, :stop}],
        [
          {:tool_call,
           %{
             id: "w2",
             name: "write",
             input: %{"path" => "lib/b.ex", "content" => "second\n"}
           }}
        ],
        [{:text, "wrote second"}, {:finish, :stop}]
      ])

    parent_id = "native-fork-parent-#{System.unique_integer([:positive])}"

    assert {:ok, parent} =
             InteractiveSession.start(
               id: parent_id,
               provider: :native,
               workspace: context.workspace,
               model: parent_spec,
               approval_mode: :auto_approve
             )

    on_exit(fn -> InteractiveSession.close(parent) end)

    assert {:ok, _turn} = InteractiveSession.send_message(parent, "write first", id: "turn-1")
    await_turns(parent, 1)

    assert {:ok, _turn} = InteractiveSession.send_message(parent, "write second", id: "turn-2")
    await_turns(parent, 2)

    assert {:ok, before_fork} = InteractiveSession.info(parent)
    parent_provider_id = before_fork.provider_session_id

    # The branch point is asked for the way a client asks: `rewind_points` hands back the
    # turns this session can be cut at, and `to_turn` takes exactly one of them. The ids
    # are the runtime's own, not the caller-minted turn ids, which is precisely why a
    # client has to ask rather than guess.
    assert {:ok, points} = InteractiveSession.rewind_points(parent)
    assert length(points) == 2
    first_turn = points |> List.first() |> Map.fetch!("turn_id")

    {child_spec, child_agent} =
      NativeModelScript.start([[{:text, "branched"}, {:finish, :stop}]])

    child_id = "native-fork-child-#{System.unique_integer([:positive])}"

    assert {:ok, child} =
             InteractiveSession.fork(parent, child_id, %{
               to_turn: first_turn,
               model: child_spec
             })

    on_exit(fn -> InteractiveSession.close(Ref.new(child.id)) end)
    assert child.id == child_id

    child_ref = Ref.new(child.id)
    assert {:ok, child_info} = InteractiveSession.info(child_ref)
    assert State.forked_from(child_info) == parent_id
    assert child_info.provider == :native
    refute child_info.provider_session_id == parent_provider_id

    # The substituted model is the child's start intent, not the parent's.
    assert {:ok, durable} = Store.get(child.id)
    assert State.request(durable).model == child_spec
    refute State.request(durable).model == parent_spec

    assert {:ok, _turn} = InteractiveSession.send_message(child_ref, "carry on", id: "child-1")

    await_turns(child_ref, 1)

    # Branched at turn one: the child's context holds the first turn and not the second.
    # `=~` rather than equality because a prompt reaches the model inside the runtime
    # exposure envelope, and what matters here is which turns are present.
    [call] = NativeModelScript.requests(child_agent)
    contents = Enum.map(call.messages, &to_string(&1.content || ""))
    assert Enum.any?(contents, &(&1 =~ "write first"))
    assert Enum.any?(contents, &(&1 =~ "Wrote lib/b.ex"))
    refute Enum.any?(contents, &(&1 =~ "write second"))
    refute Enum.any?(contents, &(&1 =~ "wrote second"))
    assert List.last(call.messages).content =~ "carry on"

    # Four inherited messages — the whole of turn one — plus the child's own prompt.
    assert length(call.messages) == 5

    # And the child's own journal names the model it ran on. This is the record that makes
    # an eval fork readable months later without the operator having to remember what they
    # substituted.
    assert {:ok, child_after} = InteractiveSession.info(child_ref)
    {:ok, dir, _durable?} = Paths.session_dir(child_after.provider_session_id)
    {:ok, window} = Journal.window(Journal.path(dir), limit: 500)

    opened = Enum.find(window.records, &(&1["kind"] == "session_opened"))
    assert opened["forked_from_provider_session_id"] == parent_provider_id
    assert opened["forked_at_turn"] == first_turn

    started = Enum.find(window.records, &(&1["kind"] == "turn_started"))
    assert started["model_spec"] == child_spec

    # The parent is untouched: still two turns, still its own conversation.
    assert {:ok, after_fork} = InteractiveSession.info(parent)
    assert after_fork.provider_session_id == parent_provider_id
    assert State.forked_from(after_fork) == nil
  end
end
