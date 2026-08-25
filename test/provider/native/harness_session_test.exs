defmodule Ouroboros.Provider.Native.HarnessSessionTest do
  @moduledoc """
  The native transport driven the way the runtime actually drives it: through
  `Jido.Harness.Session`, not by calling the adapter's callbacks directly.

  The unit tests in `session_test.exs` prove the transport answers each callback. This
  one proves the division of labour is right — that the worker's own `turn_started`,
  `input_accepted`, `approval_resolved`, and turn bookkeeping compose with the events
  this provider emits, rather than duplicating or dropping them.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.Session
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-harness-#{System.unique_integer([:positive])}")
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

  defp start_session(context, script, overrides \\ %{}) do
    {model_spec, agent} = NativeModelScript.start(script)

    {:ok, session_id} =
      Session.start(
        :native,
        Map.merge(
          %{
            cwd: context.workspace,
            model: model_spec,
            approval_mode: :auto_approve,
            # `:infinity` so an answered approval never races a deadline on a loaded
            # machine; the unanswered path is tested with an explicit short deadline.
            approval_timeout_ms: :infinity
          },
          overrides
        )
      )

    on_exit(fn -> Session.close(session_id) end)
    %{session_id: session_id, agent: agent}
  end

  # The worker journals; a test reads the journal rather than a mailbox.
  defp await_replay(session_id, predicate, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 15_000
    {:ok, events} = Session.replay(session_id, cursor: 0, limit: 500)

    cond do
      predicate.(events) ->
        events

      System.monotonic_time(:millisecond) > deadline ->
        flunk("condition never held; saw #{inspect(Enum.map(events, & &1.type))}")

      true ->
        Process.sleep(20)
        await_replay(session_id, predicate, deadline)
    end
  end

  defp saw?(events, type), do: Enum.any?(events, &(&1.type == type))

  test "a turn through the worker carries both the worker's markers and the loop's events",
       context do
    script = [
      [
        {:text, "reading"},
        {:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}
      ],
      [{:text, "done"}, {:usage, %{input_tokens: 11, output_tokens: 4}}, {:finish, :stop}]
    ]

    %{session_id: session_id} = start_session(context, script)

    assert {:ok, turn_id} = Session.send_message(session_id, "look at lib/a.ex")
    events = await_replay(session_id, &saw?(&1, :turn_completed))
    types = Enum.map(events, & &1.type)

    # The worker's own bookkeeping.
    assert :session_started in types
    assert :session_ready in types
    assert :input_accepted in types
    assert :turn_started in types

    # Exactly one `turn_started`: the worker appends it, and the loop's is dropped
    # rather than duplicated.
    assert Enum.count(types, &(&1 == :turn_started)) == 1

    # The loop's events.
    assert :tool_call in types
    assert :tool_result in types
    assert :usage in types

    assert Enum.all?(
             Enum.filter(events, &(&1.type in [:tool_call, :tool_result, :turn_completed])),
             &(&1.turn_id == turn_id)
           )

    assert {:ok, result} = Session.await(session_id, turn_id, 15_000)
    assert result.status == :completed
    assert result.text =~ "done"
  end

  test "an approval reaches the worker's pending set and resolves through it", context do
    script = [
      [
        {:tool_call,
         %{id: "c1", name: "write", input: %{"path" => "lib/new.ex", "content" => "hi\n"}}}
      ],
      [{:text, "wrote it"}, {:finish, :stop}]
    ]

    %{session_id: session_id} = start_session(context, script, %{approval_mode: :prompt})

    {:ok, _turn_id} = Session.send_message(session_id, "write it")

    events = await_replay(session_id, &saw?(&1, :approval_requested))
    ask = Enum.find(events, &(&1.type == :approval_requested))

    assert {:ok, info} = Session.info(session_id)
    assert info.state == :awaiting_approval

    assert :ok = Session.respond_approval(session_id, ask.request_id, %{decision: :approve})

    events = await_replay(session_id, &saw?(&1, :turn_completed))
    assert saw?(events, :approval_resolved)
    assert File.read!(Path.join(context.workspace, "lib/new.ex")) == "hi\n"
  end

  test "an unanswered approval is denied by the worker's timeout", context do
    script = [
      [
        {:tool_call,
         %{id: "c1", name: "write", input: %{"path" => "lib/never.ex", "content" => "no\n"}}}
      ],
      [{:text, "refused"}, {:finish, :stop}]
    ]

    %{session_id: session_id} =
      start_session(context, script, %{approval_mode: :prompt, approval_timeout_ms: 300})

    {:ok, _turn_id} = Session.send_message(session_id, "write it")

    events = await_replay(session_id, &saw?(&1, :turn_completed))
    resolved = Enum.find(events, &(&1.type == :approval_resolved))

    assert resolved.payload["decision"] == "deny"
    refute File.exists?(Path.join(context.workspace, "lib/never.ex"))
  end

  test "steer is accepted because the transport declares it, and reaches the model", context do
    # The command sleeps so the tool is demonstrably still running when the steer is
    # sent. `await_replay` polls every 20 ms and the journal adds its own latency, so a
    # tool that finished in microseconds turned "delivered at the next tool boundary"
    # into a race against the poll — the property under test is *where* the steer lands,
    # not how fast the runtime is.
    script = [
      [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "sleep 0.4; echo one"}}}],
      [{:text, "acknowledged"}, {:finish, :stop}]
    ]

    %{session_id: session_id, agent: agent} = start_session(context, script)

    {:ok, _turn_id} = Session.send_message(session_id, "go")
    await_replay(session_id, &saw?(&1, :tool_call))

    assert {:ok, request_id} = Session.steer(session_id, "also check the tests")
    assert is_binary(request_id)

    events = await_replay(session_id, &saw?(&1, :turn_completed))

    assert Enum.any?(events, fn event ->
             event.type == :input_accepted and event.payload["kind"] == "steer"
           end)

    [_first, second] = NativeModelScript.requests(agent)
    assert List.last(second.messages) == %{role: :user, content: "also check the tests"}
  end

  test "a follow-up is queued by the worker and runs after the turn", context do
    script = [
      [{:text, "first"}, {:finish, :stop}],
      [{:text, "second"}, {:finish, :stop}]
    ]

    %{session_id: session_id, agent: agent} = start_session(context, script)

    {:ok, _turn_id} = Session.send_message(session_id, "one")
    assert {:ok, queued} = Session.follow_up(session_id, "two")

    await_replay(session_id, fn events ->
      Enum.count(events, &(&1.type == :turn_completed)) == 2
    end)

    assert {:ok, result} = Session.await(session_id, queued, 15_000)
    assert result.status == :completed
    assert NativeModelScript.call_count(agent) == 2
  end

  test "interrupt is reported by the worker as soon as the transport accepts it", context do
    # The first command sleeps so the turn is demonstrably still running when the
    # interrupt arrives. `await_replay` polls every 20 ms and the journal adds its own
    # latency; a tool that finished in microseconds made "the turn stops after the
    # current tool" a race against the poll rather than a property.
    script = [
      [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "sleep 0.4; echo one"}}}],
      [{:tool_call, %{id: "c2", name: "bash", input: %{"command" => "echo two"}}}],
      [{:text, "never"}, {:finish, :stop}]
    ]

    %{session_id: session_id, agent: agent} = start_session(context, script)

    {:ok, turn_id} = Session.send_message(session_id, "go")
    await_replay(session_id, &saw?(&1, :tool_call))

    assert :ok = Session.interrupt(session_id, turn_id)

    events = await_replay(session_id, &saw?(&1, :turn_interrupted))
    assert {:ok, result} = Session.await(session_id, turn_id, 15_000)
    assert result.status == :interrupted

    # The worker finishes the turn on its own `interrupt` returning `:ok`, so every
    # event the loop emits afterwards — including the result of the tool that was
    # already running — is dropped as stale. The loop still stops cleanly, and no
    # further model call is made. This is harness behaviour, and the reason the
    # transcript can show fewer tool results than the workspace shows effects.
    assert Enum.count(events, &(&1.type == :turn_interrupted)) == 1
    Process.sleep(200)
    assert NativeModelScript.call_count(agent) == 1
  end

  test "the session closes cleanly through the worker", context do
    %{session_id: session_id} =
      start_session(context, [[{:text, "hi"}, {:finish, :stop}]])

    {:ok, _turn_id} = Session.send_message(session_id, "hi")
    await_replay(session_id, &saw?(&1, :turn_completed))

    assert :ok = Session.close(session_id)
    assert {:ok, info} = Session.info(session_id)
    assert info.state == :closed
  end
end
