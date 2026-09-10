defmodule Ouroboros.Provider.Native.RuntimeContractTest do
  use ExUnit.Case, async: false
  alias Ouroboros.Session
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-contract-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)

    previous =
      for key <- [:native_data_dir, :native_model_module, :native_output_limits],
          into: %{},
          do: {key, Application.get_env(:ouroboros, key)}

    Application.put_env(:ouroboros, :native_data_dir, Path.join(root, "data"))
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      Enum.each(previous, fn {key, value} ->
        if is_nil(value),
          do: Application.delete_env(:ouroboros, key),
          else: Application.put_env(:ouroboros, key, value)
      end)

      File.rm_rf!(root)
    end)

    %{root: root}
  end

  defp open(root, script, options \\ %{}) do
    {model, agent} = NativeModelScript.start(script)
    id = "logical-#{System.unique_integer([:positive])}"
    {:ok, _} = Registry.register(Ouroboros.Interactive.Registry, id, nil)

    request =
      Map.merge(
        %{provider: :native, cwd: root, model: model, approval_mode: :auto_approve},
        options
      )

    {:ok, runtime} = Session.open(id, request)
    {:ok, attachment, info} = Session.attach(runtime, self(), 0)

    on_exit(fn ->
      if Process.alive?(info.pid),
        do: DynamicSupervisor.terminate_child(Ouroboros.SessionTransportSupervisor, info.pid)
    end)

    %{
      logical: id,
      runtime: runtime,
      request: request,
      attachment: attachment,
      pid: info.pid,
      agent: agent
    }
  end

  defp drain_until(context, type, cursor \\ 0, events \\ []) do
    {:ok, batch, _} = Session.drain(context.attachment, cursor, 500)
    events = events ++ batch

    cursor =
      case List.last(batch) do
        nil -> cursor
        event -> event.sequence
      end

    if Enum.any?(events, &(&1.type == type)) do
      {events, cursor}
    else
      :ok = Session.ack(context.attachment, cursor)

      receive do
        {:session_output, runtime, _, _} when runtime == context.runtime ->
          drain_until(context, type, cursor, events)
      after
        5_000 -> flunk("missing #{type}: #{inspect(Enum.map(events, & &1.type))}")
      end
    end
  end

  test "one runtime deduplicates start and turn, with one origin for lifecycle facts", %{
    root: root
  } do
    context =
      open(root, [
        [{:text, "hello"}, {:usage, %{input_tokens: 2, output_tokens: 1}}, {:finish, :stop}]
      ])

    assert {:ok, context.runtime} == Session.open(context.logical, context.request)

    assert {:error, :conflicting_start} =
             Session.open(context.logical, Map.put(context.request, :system_prompt, "different"))

    assert {:ok, "turn-owned"} = Session.submit(context.runtime, "turn-owned", :message, "hello")
    assert {:ok, "turn-owned"} = Session.submit(context.runtime, "turn-owned", :message, "hello")

    assert {:error, :conflicting_turn} =
             Session.submit(context.runtime, "turn-owned", :message, "other")

    {events, cursor} = drain_until(context, :turn_completed)

    for type <- [
          :session_started,
          :session_ready,
          :input_accepted,
          :turn_started,
          :turn_completed
        ] do
      assert Enum.count(events, &(&1.type == type)) == 1
    end

    assert {:ok, result} = Session.turn_result(context.runtime, "turn-owned")
    assert result.status == :completed
    assert result.text == "hello"
    assert NativeModelScript.call_count(context.agent) == 1
    assert Enum.map(events, & &1.sequence) == Enum.to_list(1..cursor)
    assert :ok = Session.ack(context.attachment, cursor)
    assert :ok = Session.close(context.runtime)
    {_events, cursor} = drain_until(context, :session_closed, cursor)
    assert Process.alive?(context.pid)
    assert :ok = Session.ack(context.attachment, cursor)
    refute Process.alive?(context.pid)
  end

  test "reattachment invalidates old acknowledgements and reports retained gaps", %{root: root} do
    context = open(root, [])
    {:ok, events, _} = Session.drain(context.attachment, 0, 500)
    cursor = List.last(events).sequence
    {:ok, replacement, info} = Session.attach(context.runtime, self(), 0)
    assert info.runtime_id != info.logical_id
    assert info.native_conversation_id != info.runtime_id
    assert {:error, :stale_attachment} = Session.ack(context.attachment, cursor)
    assert {:ok, ^events, _} = Session.drain(replacement, 0, 500)
    assert :ok = Session.ack(replacement, cursor)

    assert {:error, {:retained_range_gap, %{retained_from: retained_from}}} =
             Session.drain(replacement, 0, 500)

    assert retained_from == cursor + 1
  end

  test "attachments bind acknowledgement to the coordinator caller and coalesce repeated attaches",
       %{root: root} do
    context = open(root, [])
    {:ok, events, _} = Session.drain(context.attachment, 0, 500)
    cursor = List.last(events).sequence
    parent = self()

    thief =
      spawn(fn ->
        send(parent, {:foreign_ack, Session.ack(context.attachment, cursor)})
        send(parent, {:foreign_drain, Session.drain(context.attachment, 0, 500)})
      end)

    assert is_pid(thief)
    assert_receive {:foreign_ack, {:error, :stale_attachment}}
    assert_receive {:foreign_drain, {:error, :stale_attachment}}

    for _ <- 1..100 do
      assert {:ok, _attachment, _info} = Session.attach(context.runtime, self(), 0)
    end

    {:messages, messages} = Process.info(self(), :messages)

    assert Enum.count(messages, fn
             {:session_output, runtime, _, _} -> runtime == context.runtime
             _ -> false
           end) == 1

    {:ok, attachment, _} = Session.attach(context.runtime, self(), cursor + 100)

    assert {:error, {:retained_range_gap, %{reason: :cursor_ahead}}} =
             Session.drain(attachment, cursor + 100, 500)

    assert {:error, :invalid_ack} = Session.ack(attachment, cursor + 100)
  end

  test "production event bound preserves existing multi-megabyte detail payloads", %{root: root} do
    text = String.duplicate("x", 3_000_000)
    context = open(root, [[{:text, text}, {:finish, :stop}]])
    assert {:ok, "large-output"} = Session.submit(context.runtime, "large-output", :message, "go")
    {events, _cursor} = drain_until(context, :turn_completed)
    final = Enum.find(events, &(&1.type == :output_text_final))
    assert final.payload["text"] == text
    assert {:ok, result} = Session.turn_result(context.runtime, "large-output")
    assert result.text_truncated?
    assert byte_size(result.text) == 1024 * 1024
  end

  test "full output retains one blocked producer while interrupt stays responsive", %{root: root} do
    Application.put_env(:ouroboros, :native_output_limits,
      max_count: 8,
      max_bytes: 4096,
      event_bytes: 2048
    )

    context = open(root, [[{:text, String.duplicate("chunk", 100)}, {:finish, :stop}]])
    assert {:ok, "blocked-turn"} = Session.submit(context.runtime, "blocked-turn", :message, "go")
    await_blocked(context.pid)
    assert {:message_queue_len, count} = Process.info(context.pid, :message_queue_len)
    assert count < 5
    assert :ok = Session.interrupt(context.runtime, "blocked-turn")
    assert {:ok, result} = Session.turn_result(context.runtime, "blocked-turn")
    assert result.status == :interrupted
    {events, _cursor} = drain_until(context, :turn_interrupted)
    assert Enum.count(events, &(&1.type == :turn_interrupted)) == 1
    assert length(events) < 16
  end

  test "oversized producer fails the turn before an effect can follow", %{root: root} do
    Application.put_env(:ouroboros, :native_output_limits,
      max_count: 16,
      max_bytes: 4096,
      event_bytes: 2048
    )

    context =
      open(root, [
        [
          {:text, String.duplicate("x", 3000)},
          {:tool_call,
           %{
             id: "must-not-run",
             name: "write",
             input: %{"path" => "must-not-exist.txt", "content" => "no"}
           }},
          {:finish, :stop}
        ]
      ])

    assert {:ok, "oversized"} = Session.submit(context.runtime, "oversized", :message, "go")
    {events, _cursor} = drain_until(context, :turn_failed)

    assert Enum.any?(
             events,
             &(&1.type == :turn_failed and &1.payload["reason"] == "event_too_large")
           )

    assert Process.alive?(context.pid)
    refute File.exists?(Path.join(root, "must-not-exist.txt"))
  end

  test "approval expiry denies once and stale answers cannot release another waiter", %{
    root: root
  } do
    script = [
      [
        {:tool_call,
         %{id: "write-1", name: "write", input: %{"path" => "denied.txt", "content" => "no"}}}
      ],
      [{:text, "denied"}, {:finish, :stop}]
    ]

    context = open(root, script, %{approval_mode: :prompt, approval_timeout_ms: 30})

    assert {:ok, "approval-turn"} =
             Session.submit(context.runtime, "approval-turn", :message, "write")

    {events, _cursor} = drain_until(context, :turn_completed)
    approval = Enum.find(events, &(&1.type == :approval_requested))
    assert approval
    resolutions = Enum.filter(events, &(&1.type == :approval_resolved))
    assert length(resolutions) == 1
    assert hd(resolutions).payload["decision"] == "deny"

    assert {:error, :unknown_request} =
             Session.respond_approval(context.runtime, approval.request_id, %{decision: :approve})

    refute File.exists?(Path.join(root, "denied.txt"))
  end

  test "coordinator death preserves runtime generation, queued input and unacknowledged output",
       %{root: root} do
    Application.put_env(:ouroboros, :native_output_limits,
      max_count: 12,
      max_bytes: 4096,
      event_bytes: 2048
    )

    context =
      open(root, [[{:text, "first"}, {:finish, :stop}], [{:text, "second"}, {:finish, :stop}]])

    # Admit the follow-up before the first stream can fill the deliberately tiny
    # retained buffer. Suspending this private model agent gates only model output;
    # the runtime still owns and acknowledges both turn admissions normally.
    :ok = :sys.suspend(context.agent)

    try do
      assert {:ok, "first"} = Session.submit(context.runtime, "first", :message, "one")
      assert {:ok, "second"} = Session.submit(context.runtime, "second", :follow_up, "two")
    after
      :ok = :sys.resume(context.agent)
    end

    await_blocked(context.pid)
    Registry.unregister(Ouroboros.Interactive.Registry, context.logical)
    parent = self()

    coordinator =
      spawn(fn ->
        {:ok, _} = Registry.register(Ouroboros.Interactive.Registry, context.logical, nil)
        {:ok, _attachment, info} = Session.attach(context.runtime, self(), 0)
        send(parent, {:attached_generation, info.generation})

        receive do
          :stop -> :ok
        end
      end)

    assert_receive {:attached_generation, generation}
    monitor = Process.monitor(coordinator)
    Process.exit(coordinator, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^coordinator, :killed}
    assert Process.alive?(context.pid)
    {:ok, _} = Registry.register(Ouroboros.Interactive.Registry, context.logical, nil)
    {:ok, attachment, info} = Session.attach(context.runtime, self(), 0)
    assert info.generation == generation
    assert info.active_turn_id == "first"
    assert info.queued_turn_ids == ["second"]
    assert {:ok, "first"} = Session.submit(context.runtime, "first", :message, "one")
    context = %{context | attachment: attachment}
    {first_events, cursor} = drain_until(context, :turn_completed)
    assert Enum.count(first_events, &(&1.type == :turn_started and &1.turn_id == "first")) == 1
    :ok = Session.ack(attachment, cursor)
    {second_events, _cursor} = drain_until(context, :turn_completed, cursor)

    assert Enum.count(second_events, &(&1.type == :turn_completed and &1.turn_id == "second")) ==
             1

    assert NativeModelScript.call_count(context.agent) == 2
  end

  test "unexpected runtime death stops its supervised execution task", %{root: root} do
    Application.put_env(:ouroboros, :native_output_limits,
      max_count: 8,
      max_bytes: 4096,
      event_bytes: 2048
    )

    context = open(root, [[{:text, "blocked"}, {:finish, :stop}]])
    assert {:ok, "active"} = Session.submit(context.runtime, "active", :message, "go")
    await_blocked(context.pid)
    loop = :sys.get_state(context.pid).loop.pid
    monitor = Process.monitor(loop)
    Process.exit(context.pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^loop, :killed}
    assert {:error, :not_found} = Session.info(context.runtime)
  end

  test "failed configuration leaves durable plan posture and applied settings untouched", %{
    root: root
  } do
    context = open(root, [])
    {:ok, before} = Session.plan_state(context.runtime)

    assert {:error, {:unsupported_configuration, :zz_bad, true}} =
             Session.configure(context.runtime, %{plan: true, zz_bad: true})

    assert {:ok, ^before} = Session.plan_state(context.runtime)
    assert :ok = Session.configure(context.runtime, %{plan: true})
    assert {:ok, %{plan: true, sandbox_mode: :read_only}} = Session.plan_state(context.runtime)

    assert {:error, {:unsupported_configuration, :zz_bad, true}} =
             Session.configure(context.runtime, %{plan: false, zz_bad: true})

    assert {:ok, %{plan: true, sandbox_mode: :read_only}} = Session.plan_state(context.runtime)
  end

  defp await_blocked(pid, attempts \\ 100)
  defp await_blocked(_pid, 0), do: flunk("producer never blocked")

  defp await_blocked(pid, attempts) do
    if :sys.get_state(pid).pending_producer do
      :ok
    else
      Process.sleep(10)
      await_blocked(pid, attempts - 1)
    end
  end
end
