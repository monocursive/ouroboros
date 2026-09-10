defmodule Ouroboros.InteractiveTurnCorrelationTest do
  use ExUnit.Case, async: false
  @moduletag :capture_log

  alias Ouroboros.Interactive.{Event, State, Store, Task}
  alias Ouroboros.Session
  alias Ouroboros.Session.TurnRequest
  alias Ouroboros.Test.{ControlledModel, NativeConfig}

  test "delayed acceptance settles its stable ambiguous turn without taking a newer intent" do
    root = Path.join(System.tmp_dir!(), "turn-correlation-#{System.unique_integer([:positive])}")
    id = "turn-correlation-#{System.unique_integer([:positive])}"
    File.mkdir_p!(root)
    previous_dir = Application.get_env(:ouroboros, :native_data_dir)
    previous_config = NativeConfig.snapshot()
    Application.put_env(:ouroboros, :native_data_dir, Path.join(root, "native"))
    NativeConfig.configure(%{native: %{test_pid: self()}})

    on_exit(fn ->
      if pid = Task.whereis(id),
        do: DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)

      for info <- Session.list(),
          info.logical_id == id,
          do: DynamicSupervisor.terminate_child(Ouroboros.SessionTransportSupervisor, info.pid)

      Store.delete(id)
      NativeConfig.configure(previous_config)

      if is_nil(previous_dir),
        do: Application.delete_env(:ouroboros, :native_data_dir),
        else: Application.put_env(:ouroboros, :native_data_dir, previous_dir)

      File.rm_rf!(root)
    end)

    {:ok, _} = Registry.register(Ouroboros.Interactive.Registry, id, nil)
    {:ok, runtime_id} = Session.open(id, %{cwd: root})
    {:ok, attachment, info} = Session.attach(runtime_id, self(), 0)
    {:ok, initial, _} = Session.drain(attachment, 0, 500)
    cursor = List.last(initial).sequence
    :ok = Session.ack(attachment, cursor)

    {:ok, request} = TurnRequest.new("the original accepted input")
    assert {:ok, "original"} = Session.submit(runtime_id, "original", :message, request)
    assert_receive {:ouroboros_test_model_started, "original", _, producer}, 3_000

    original =
      State.new_turn("original", :message, request)
      |> Map.put(:status, :ambiguous)
      |> Map.put(:error, :timeout)

    newer = State.new_turn("newer", :follow_up, TurnRequest.new!("the unrelated newer input"))
    {:ok, base} = State.new(id, workspace: root, runtime_exposure: false)

    session = %{
      base
      | status: :running,
        runtime_id: runtime_id,
        runtime_generation: info.generation,
        runtime_cursor: cursor,
        cursor: cursor,
        provider_session_id: info.provider_session_id,
        events: Enum.map(initial, &Event.from_execution(id, &1)),
        turns: %{"original" => original, "newer" => newer}
    }

    :ok = Store.create(session)
    Registry.unregister(Ouroboros.Interactive.Registry, id)

    {:ok, _coordinator} =
      DynamicSupervisor.start_child(Ouroboros.Interactive.TaskSupervisor, {Task, id})

    running =
      eventually(fn ->
        {:ok, state} = Store.get(id)
        if state.turns["original"].status == :running, do: state
      end)

    assert running.turns["original"].runtime_turn_id == "original"
    assert running.turns["original"].error == nil
    assert running.turns["newer"].runtime_turn_id == nil
    refute Map.has_key?(running.turns, "recovered:original")

    accepted =
      Enum.find(running.events, &(&1.type == :input_accepted and &1.turn_id == "original"))

    assert accepted.payload["text"] == "the original accepted input"

    ControlledModel.emit(producer, :output_text_delta, %{"text" => "settled original"})
    ControlledModel.finish(producer)

    completed =
      eventually(fn ->
        {:ok, state} = Store.get(id)
        if state.turns["original"].status == :completed, do: state
      end)

    assert completed.turns["original"].result.text == "settled original"
    assert completed.turns["newer"].runtime_turn_id == nil
    refute Map.has_key?(completed.turns, "recovered:original")
    refute_receive {:ouroboros_test_model_started, _, _, _}, 100
  end

  defp eventually(fun, attempts \\ 300)
  defp eventually(_fun, 0), do: flunk("condition did not become true")

  defp eventually(fun, attempts) do
    case fun.() do
      value when value in [nil, false] ->
        Process.sleep(10)
        eventually(fun, attempts - 1)

      value ->
        value
    end
  end
end
