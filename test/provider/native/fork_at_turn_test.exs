defmodule Ouroboros.Provider.Native.ForkAtTurnTest do
  @moduledoc """
  R3: forking a native session at a turn rather than at its tail.

  The two halves this composes both shipped already — `Checkpoint.message_count_at/2`
  resolves a turn to a message count, and `seed_fork` copies a parent's conversation into
  a child — and what is under test here is the composition and, more than that, its
  refusals. A branch point the parent no longer holds and a turn id belonging to some
  other session are both requests for a conversation that does not exist, and the failure
  worth guarding against is not an error: it is a fork that quietly branched at the tail
  instead and left a child claiming a history it never had.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.SessionRequest
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.{Checkpoint, Journal, Paths, Session}
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-fork-turn-#{System.unique_integer([:positive])}")
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

    %{root: root, workspace: workspace, data_dir: data_dir}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

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
    %{handle: handle, agent: agent, model_spec: model_spec}
  end

  # A fork that never opens, because the boundary it asked for is not one this parent can
  # honour. The refusal is `init/1`'s, so it arrives as a failed open rather than as a
  # session that started and then disagreed with itself.
  defp open_fork(context, source_id, script, provider_options) do
    {model_spec, _agent} = NativeModelScript.start(script)

    request =
      SessionRequest.new!(%{
        provider: :native,
        cwd: context.workspace,
        model: model_spec,
        approval_mode: :auto_approve,
        approval_timeout_ms: 2_000,
        provider_session_id: source_id,
        provider_options: Map.put(provider_options, :fork_session, true)
      })

    Session.open(request, session_context())
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

  defp await_event(type, acc \\ []) do
    receive do
      {:session_adapter_event, %{type: ^type} = event} ->
        event

      {:session_adapter_event, event} ->
        await_event(type, [event | acc])
    after
      20_000 -> flunk("no #{type} within 20s; saw #{inspect(Enum.map(acc, & &1.type))}")
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

  # One write per turn, so every turn is exactly four messages — the prompt, the assistant
  # message that called `write`, its result, and the assistant message that ends the turn.
  # The manifest only records a turn that touched a file or ran a command, so a script of
  # bare text turns would leave `to_turn` nothing to resolve against.
  defp writing_turns(count) do
    Enum.flat_map(1..count, fn index ->
      [[write_call("c#{index}", "lib/b.ex", "body #{index}\n")], done()]
    end)
  end

  defp messages_of(session_id) do
    {:ok, path, _durable?} = Checkpoint.locate(session_id)
    {:ok, messages} = Checkpoint.read(path)
    messages
  end

  defp records_of(session_id) do
    {:ok, dir, _durable?} = Paths.session_dir(session_id)
    {:ok, window} = Journal.window(Journal.path(dir), limit: 500)
    window.records
  end

  defp record(session_id, kind),
    do: Enum.find(records_of(session_id), &(&1["kind"] == kind))

  describe "fork at a turn" do
    test "the child is the parent's conversation truncated to that turn", context do
      %{handle: parent} = open(context, writing_turns(3))
      parent_ready = await_event(:provider_event)

      turn(parent, "t1", "one")
      turn(parent, "t2", "two")
      turn(parent, "t3", "three")
      drain()

      :ok = Session.close(parent)
      drain()

      parent_id = parent_ready.provider_session_id
      assert length(messages_of(parent_id)) == 12

      assert {:ok, child} = open_fork(context, parent_id, [done()], %{fork_to_turn: "t1"})
      child_ready = await_event(:provider_event)
      child_id = child_ready.provider_session_id
      refute child_id == parent_id

      # Four messages: the first turn and nothing after it. Not a window out of the middle
      # of the conversation, and not the whole thing.
      assert length(messages_of(child_id)) == 4

      # And that is what the model is actually handed on the child's first turn, which is
      # the only thing that makes the truncation mean anything.
      :ok = Session.send(child, TurnRequest.new!("continue"), "c1")
      await_terminal()

      assert :ok = Session.close(child)

      # The parent is untouched: same conversation, same length, on disk.
      assert length(messages_of(parent_id)) == 12
    end

    test "the child's first model call sees only the turns it branched at", context do
      %{handle: parent} = open(context, writing_turns(3))
      parent_ready = await_event(:provider_event)

      turn(parent, "t1", "one")
      turn(parent, "t2", "two")
      turn(parent, "t3", "three")
      drain()

      :ok = Session.close(parent)
      drain()

      {model_spec, agent} = NativeModelScript.start([done()])

      request =
        SessionRequest.new!(%{
          provider: :native,
          cwd: context.workspace,
          model: model_spec,
          approval_mode: :auto_approve,
          approval_timeout_ms: 2_000,
          provider_session_id: parent_ready.provider_session_id,
          provider_options: %{fork_session: true, fork_to_turn: "t2"}
        })

      assert {:ok, child} = Session.open(request, session_context())
      on_exit(fn -> if Process.alive?(child), do: Session.close(child) end)
      drain()

      :ok = Session.send(child, TurnRequest.new!("continue"), "c1")
      await_terminal()

      [call] = NativeModelScript.requests(agent)
      contents = Enum.map(call.messages, &to_string(&1.content || ""))

      # Turns one and two are in the child's context; turn three is not.
      assert Enum.any?(contents, &(&1 == "one"))
      assert Enum.any?(contents, &(&1 == "two"))
      refute Enum.any?(contents, &(&1 == "three"))
      assert List.last(call.messages).content == "continue"
    end

    test "the child's journal names the parent it branched from and the turn it cut at",
         context do
      %{handle: parent} = open(context, writing_turns(2))
      parent_ready = await_event(:provider_event)

      turn(parent, "t1", "one")
      turn(parent, "t2", "two")
      drain()

      :ok = Session.close(parent)
      drain()

      parent_id = parent_ready.provider_session_id

      assert {:ok, child} = open_fork(context, parent_id, [done()], %{fork_to_turn: "t1"})
      child_ready = await_event(:provider_event)
      child_id = child_ready.provider_session_id

      opened = record(child_id, "session_opened")

      # R1's field, on the truncated path as well as the tail one.
      assert opened["forked_from_provider_session_id"] == parent_id
      assert opened["resumed"] == false

      # And the truncation itself, because a child whose record was indistinguishable from
      # a tail fork's would claim a history it does not have.
      assert opened["forked_at_turn"] == "t1"
      assert opened["forked_message_count"] == 4

      assert :ok = Session.close(child)
    end

    test "a tail fork records no branch point, exactly as before this parameter existed",
         context do
      %{handle: parent} = open(context, writing_turns(2))
      parent_ready = await_event(:provider_event)

      turn(parent, "t1", "one")
      turn(parent, "t2", "two")
      drain()

      :ok = Session.close(parent)
      drain()

      parent_id = parent_ready.provider_session_id

      assert {:ok, child} = open_fork(context, parent_id, [done()], %{})
      child_ready = await_event(:provider_event)
      child_id = child_ready.provider_session_id

      assert length(messages_of(child_id)) == 8

      opened = record(child_id, "session_opened")
      assert opened["forked_from_provider_session_id"] == parent_id
      refute Map.has_key?(opened, "forked_at_turn")
      refute Map.has_key?(opened, "forked_message_count")

      assert :ok = Session.close(child)
    end

    test "turn 0 is the empty conversation, which is a branch point like any other",
         context do
      %{handle: parent} = open(context, writing_turns(2))
      parent_ready = await_event(:provider_event)

      turn(parent, "t1", "one")
      turn(parent, "t2", "two")
      drain()

      :ok = Session.close(parent)
      drain()

      parent_id = parent_ready.provider_session_id

      assert {:ok, child} = open_fork(context, parent_id, [done()], %{fork_to_turn: 0})
      child_ready = await_event(:provider_event)

      assert messages_of(child_ready.provider_session_id) == []
      assert :ok = Session.close(child)
    end
  end

  describe "refusals" do
    # `event_limit: 8` keeps eight messages, so a session of four-message turns has dropped
    # the head of its own conversation by the third. No slice of what survives is the
    # conversation as it stood at the first turn, and a fork that branched at the tail
    # anyway would hand back a child claiming a boundary it does not have.
    test "a boundary the parent no longer holds is refused by name", context do
      %{handle: parent} =
        open(context, writing_turns(4), %{provider_options: %{event_limit: 8}})

      parent_ready = await_event(:provider_event)

      turn(parent, "t1", "one")
      turn(parent, "t2", "two")
      turn(parent, "t3", "three")
      turn(parent, "t4", "four")
      drain()

      :ok = Session.close(parent)
      drain()

      parent_id = parent_ready.provider_session_id
      assert length(messages_of(parent_id)) == 8

      assert {:error, {:turn_boundary_dropped, "t1"}} =
               open_fork(context, parent_id, [done()], %{
                 fork_to_turn: "t1",
                 event_limit: 8
               })

      # Refused, not degraded: the parent is where it was and no child exists.
      assert length(messages_of(parent_id)) == 8
    end

    # `message_count_at/2` already refuses a turn id from another session — this pins that
    # refusal at the fork surface, where borrowing an id would truncate the wrong
    # conversation rather than merely fail a rewind.
    test "a turn id belonging to another session is refused", context do
      %{handle: first} = open(context, writing_turns(2))
      first_ready = await_event(:provider_event)
      turn(first, "alpha-1", "one")
      turn(first, "alpha-2", "two")
      drain()
      :ok = Session.close(first)
      drain()

      %{handle: second} = open(context, writing_turns(2))
      second_ready = await_event(:provider_event)
      turn(second, "beta-1", "one")
      turn(second, "beta-2", "two")
      drain()
      :ok = Session.close(second)
      drain()

      refute first_ready.provider_session_id == second_ready.provider_session_id

      # `alpha-1` is a real turn — in the *other* session. Forking the second session at it
      # must not resolve against the first one's manifest.
      assert {:error, {:unknown_turn, "alpha-1"}} =
               open_fork(context, second_ready.provider_session_id, [done()], %{
                 fork_to_turn: "alpha-1"
               })

      assert length(messages_of(second_ready.provider_session_id)) == 8
    end

    test "a turn id that never existed anywhere is refused the same way", context do
      %{handle: parent} = open(context, writing_turns(1))
      parent_ready = await_event(:provider_event)
      turn(parent, "t1", "one")
      drain()
      :ok = Session.close(parent)
      drain()

      assert {:error, {:unknown_turn, "not-a-turn"}} =
               open_fork(context, parent_ready.provider_session_id, [done()], %{
                 fork_to_turn: "not-a-turn"
               })
    end
  end

  describe "model substitution" do
    test "the child's first turn_started journal record names the model it was started on",
         context do
      %{handle: parent} = open(context, writing_turns(1))
      parent_ready = await_event(:provider_event)
      turn(parent, "t1", "one")
      drain()
      :ok = Session.close(parent)
      drain()

      parent_id = parent_ready.provider_session_id
      parent_started = record(parent_id, "turn_started")

      # A *different* script, and so a different model spec, is what the child runs on.
      {child_model, _agent} = NativeModelScript.start([done()])

      request =
        SessionRequest.new!(%{
          provider: :native,
          cwd: context.workspace,
          model: child_model,
          approval_mode: :auto_approve,
          approval_timeout_ms: 2_000,
          provider_session_id: parent_id,
          provider_options: %{fork_session: true, fork_to_turn: "t1"}
        })

      assert {:ok, child} = Session.open(request, session_context())
      on_exit(fn -> if Process.alive?(child), do: Session.close(child) end)
      child_ready = await_event(:provider_event)

      :ok = Session.send(child, TurnRequest.new!("continue"), "c1")
      await_terminal()

      child_started = record(child_ready.provider_session_id, "turn_started")

      assert child_started["model_spec"]
      refute child_started["model_spec"] == parent_started["model_spec"]
    end
  end
end
