defmodule Ouroboros.Session.DeliveryTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Interactive.{State, Store}
  alias Ouroboros.Session
  alias Ouroboros.Session.Delivery
  alias Ouroboros.Test.NativeModelScript

  @moduletag :tmp_dir
  @moduletag :capture_log

  setup %{tmp_dir: root} do
    id = "delivery-#{System.unique_integer([:positive, :monotonic])}"
    previous = Application.get_env(:ouroboros, :native_model_module)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)
    {model, model_agent} = NativeModelScript.start([])
    {:ok, _} = Registry.register(Ouroboros.Interactive.Registry, id, nil)
    {:ok, runtime_id} = Session.open(id, %{cwd: root, model: model})
    {:ok, attachment, info} = Session.attach(runtime_id, self(), 0)

    store =
      start_supervised!(
        {Store, name: nil, storage: {Ouroboros.Storage.ETS, table: :delivery_projection_test}}
      )

    {:ok, record} = State.new(id, workspace: root)

    record = %{
      record
      | status: :failed,
        runtime_id: runtime_id,
        runtime_generation: info.generation
    }

    on_exit(fn ->
      if Process.alive?(info.pid),
        do: DynamicSupervisor.terminate_child(Ouroboros.SessionTransportSupervisor, info.pid)

      if previous,
        do: Application.put_env(:ouroboros, :native_model_module, previous),
        else: Application.delete_env(:ouroboros, :native_model_module)
    end)

    %{
      runtime_id: runtime_id,
      attachment: attachment,
      info: info,
      record: record,
      store: store,
      model: model_agent
    }
  end

  test "locally terminal records do not pin a still-active runtime", ctx do
    assert Delivery.state(ctx.runtime_id, ctx.info.generation, 0) == :settled
    assert :ok = Store.create(ctx.record, ctx.store)
    assert :ok = Store.delete(ctx.record.id, ctx.store)
    assert Process.alive?(ctx.info.pid)
    assert NativeModelScript.call_count(ctx.model) == 0
  end

  test "terminal delivery pins only its generation until acknowledgement", ctx do
    assert :ok = Session.close(ctx.runtime_id)
    assert {:ok, events, _} = Session.drain(ctx.attachment, 0, 500)
    cursor = List.last(events).sequence
    assert Delivery.state(ctx.runtime_id, ctx.info.generation, 0) == :uncheckpointed
    assert Delivery.state(ctx.runtime_id, ctx.info.generation, cursor + 1) == :uncheckpointed
    assert Delivery.state(ctx.runtime_id, "different-generation", cursor) == :settled
    stale = %{ctx.record | runtime_generation: "different-generation"}
    assert :ok = Store.create(stale, ctx.store)
    assert {:ok, [id]} = Store.prune_terminal(0, ctx.store)
    assert id == stale.id
    assert :ok = Store.create(ctx.record, ctx.store)
    assert {:error, :session_delivery_uncheckpointed} = Store.delete(ctx.record.id, ctx.store)
    assert {:ok, []} = Store.prune_terminal(0, ctx.store)

    checkpoint = %{
      ctx.record
      | runtime_cursor: cursor,
        cursor: cursor,
        events: Enum.map(events, &Ouroboros.Interactive.Event.from_execution(ctx.record.id, &1))
    }

    assert :ok = Store.put(checkpoint, ctx.store)
    assert Delivery.state(ctx.runtime_id, ctx.info.generation, cursor) == :pending
    assert {:error, :session_delivery_pending} = Store.delete(ctx.record.id, ctx.store)

    # Neither the store nor its retention decision needs a reply from the runtime.
    :ok = :sys.suspend(ctx.info.pid)

    try do
      assert {:ok, []} = Store.prune_terminal(0, ctx.store)
      assert Delivery.state(ctx.runtime_id, ctx.info.generation, cursor) == :pending
    after
      :sys.resume(ctx.info.pid)
    end

    monitor = Process.monitor(ctx.info.pid)
    assert :ok = Session.ack(ctx.attachment, cursor)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 1_000
    assert Delivery.state(ctx.runtime_id, ctx.info.generation, cursor) == :settled
    assert :ok = Store.delete(ctx.record.id, ctx.store)
    assert NativeModelScript.call_count(ctx.model) == 0
  end

  test "late terminal-owner events advance the delivery projection", ctx do
    assert :ok = Session.close(ctx.runtime_id)
    assert {:ok, before} = Session.info(ctx.runtime_id)
    send(ctx.info.pid, {:subagent, "late-fixture", {:progress, %{"phase" => "completed"}}})
    assert {:ok, after_event} = Session.info(ctx.runtime_id)
    assert after_event.output_cursor == before.output_cursor + 1

    assert Delivery.state(ctx.runtime_id, ctx.info.generation, before.output_cursor) ==
             :uncheckpointed

    assert Delivery.state(ctx.runtime_id, ctx.info.generation, after_event.output_cursor) ==
             :pending
  end

  test "a malformed matching projection is unknown, not settled", ctx do
    id = ctx.runtime_id <> "-malformed"

    assert {:ok, _} =
             Registry.register(Ouroboros.SessionRegistry, {:runtime, id}, %{
               generation: ctx.info.generation
             })

    assert Delivery.state(id, ctx.info.generation, 0) == :unknown

    assert {_, _} =
             Registry.update_value(Ouroboros.SessionRegistry, {:runtime, id}, fn _ ->
               %{generation: ctx.info.generation, terminal?: true, pending?: true}
             end)

    assert Delivery.state(id, ctx.info.generation, 0) == :unknown
  end
end
