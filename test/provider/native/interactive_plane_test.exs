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

  alias Ouroboros.InteractiveSession
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

    completed = Enum.find(events, &(&1.type == :turn_completed))
    assert completed.payload["input_tokens"] == 20 + 61

    if System.get_env("OUROBOROS_SHOW_SUBAGENT_EVENTS") == "1" do
      for event <- events do
        IO.puts("#{event.type} #{inspect(event.payload, limit: :infinity)}")
      end
    end
  end
end
