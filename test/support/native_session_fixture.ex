defmodule Ouroboros.Test.NativeSessionFixture do
  @moduledoc """
  A test consumer of the owned runtime contract. It registers a coordinator identity,
  drains each notified batch into a test transcript, then acknowledges that transcript.
  The handle is the real execution PID so lifecycle and restart assertions remain real.
  No provider adapter or production worker is simulated by this helper.
  """
  use GenServer
  alias Ouroboros.Session
  alias Ouroboros.Session.{Request, TurnRequest}

  def open(%Request{} = request, context) do
    case GenServer.start(__MODULE__, {request, context, Map.get(context, :owner, self())}) do
      {:ok, consumer} -> GenServer.call(consumer, :handle)
      {:error, reason} -> {:error, reason}
    end
  end

  def open_child(%Request{} = request, context),
    do: open(request, Map.put(context, :child_runtime, true))

  def start(:native, attrs) do
    with {:ok, request} <- Request.new(attrs) do
      open(request, %{
        session_id: "native-fixture-#{System.unique_integer([:positive])}",
        owner: self()
      })
    end
  end

  def send(handle, request, turn_id) do
    case Session.submit(handle, turn_id, :message, request) do
      {:ok, ^turn_id} -> :ok
      other -> other
    end
  end

  def send_message(handle, request), do: submit(handle, :message, request)
  def follow_up(handle, request), do: submit(handle, :follow_up, request)

  defp submit(handle, mode, request) do
    Session.submit(handle, "test-turn-#{System.unique_integer([:positive])}", mode, request)
  end

  def steer(handle, %TurnRequest{} = request, request_id) do
    case Session.steer(handle, request_id, request) do
      {:ok, ^request_id} -> :ok
      other -> other
    end
  end

  def steer(handle, request),
    do: Session.steer(handle, "test-steer-#{System.unique_integer([:positive])}", request)

  def respond_approval(handle, request_id, response),
    do: Session.respond_approval(handle, request_id, response)

  def configure(handle, changes), do: Session.configure(handle, changes)
  def interrupt(handle, turn_id \\ :active), do: Session.interrupt(handle, turn_id)
  def compact(handle, focus \\ nil), do: Session.compact(handle, focus)
  def plan_mode(handle, enabled), do: Session.plan_mode(handle, enabled)
  def plan_state(handle), do: Session.plan_state(handle)

  def handoff(handle, prompt \\ nil, opts \\ []) do
    with {:ok, result} <- Session.handoff(handle, prompt, opts) do
      if result.pid do
        with {:ok, consumer} <-
               GenServer.start(__MODULE__, {:attach_existing, result.pid, self()}),
             {:ok, pid} <- GenServer.call(consumer, :handle) do
          {:ok, %{result | pid: pid}}
        end
      else
        {:ok, result}
      end
    end
  end

  def rewind(handle, to_turn, what \\ :both), do: Session.rewind(handle, to_turn, what)
  def rewind_points(handle), do: Session.rewind_points(handle)
  def bridge_tool(handle, call, emit), do: Session.bridge_tool(handle, call, emit)

  def info(handle) do
    case receiver(handle) do
      nil -> {:error, :not_found}
      consumer -> GenServer.call(consumer, :info)
    end
  end

  def close(handle) do
    result = Session.close(handle)
    sync(handle)
    result
  end

  def replay(handle, opts \\ []) do
    case receiver(handle) do
      nil ->
        {:error, :not_found}

      consumer ->
        GenServer.call(
          consumer,
          {:replay, Keyword.get(opts, :cursor, 0), Keyword.get(opts, :limit, 500)}
        )
    end
  end

  def await(handle, turn_id, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    await_result(handle, turn_id, deadline)
  end

  defp await_result(handle, turn_id, deadline) do
    result =
      case receiver(handle) do
        nil -> {:error, :not_found}
        consumer -> GenServer.call(consumer, {:result, turn_id})
      end

    case result do
      {:ok, result} ->
        {:ok, result}

      other ->
        if System.monotonic_time(:millisecond) >= deadline do
          other
        else
          Process.sleep(10)
          await_result(handle, turn_id, deadline)
        end
    end
  end

  defp receiver(handle) do
    case Registry.lookup(Ouroboros.Provider.Native.Registry, {:test_consumer, handle}) do
      [{pid, _}] -> pid
      _ -> nil
    end
  end

  defp sync(handle) do
    if consumer = receiver(handle), do: GenServer.call(consumer, :sync)
  catch
    :exit, _ -> :ok
  end

  @impl true
  def init({%Request{} = request, context, owner}) do
    logical_id = context.session_id

    with {:ok, _} <- Registry.register(Ouroboros.Interactive.Registry, logical_id, nil),
         {:ok, runtime_id} <- open_runtime(logical_id, request, context),
         {:ok, info} <- Session.info(runtime_id),
         {:ok, attachment, _} <- Session.attach(runtime_id, self(), 0),
         {:ok, _} <-
           Registry.register(Ouroboros.Provider.Native.Registry, {:test_consumer, info.pid}, nil) do
      {:ok,
       %{
         runtime_id: runtime_id,
         handle: info.pid,
         attachment: attachment,
         owner: owner,
         owner_monitor: Process.monitor(owner),
         cursor: 0,
         events: [],
         results: %{},
         info: info
       }, {:continue, :drain}}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  def init({:attach_existing, runtime, owner}) do
    with {:ok, info} <- Session.info(runtime),
         {:ok, _} <- Registry.register(Ouroboros.Interactive.Registry, info.logical_id, nil),
         {:ok, attachment, _} <- Session.attach(runtime, self(), 0),
         {:ok, _} <-
           Registry.register(Ouroboros.Provider.Native.Registry, {:test_consumer, info.pid}, nil) do
      {:ok,
       %{
         runtime_id: info.runtime_id,
         handle: info.pid,
         attachment: attachment,
         owner: owner,
         owner_monitor: Process.monitor(owner),
         cursor: 0,
         events: [],
         results: %{},
         info: info
       }, {:continue, :drain}}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  defp open_runtime(logical_id, request, %{child_runtime: true} = context),
    do: Session.open_child(logical_id, request, Map.delete(context, :child_runtime))

  defp open_runtime(logical_id, request, _context), do: Session.open(logical_id, request)

  @impl true
  def handle_continue(:drain, state), do: {:noreply, drain(state)}

  @impl true
  def handle_call(:handle, _from, state), do: {:reply, {:ok, state.handle}, state}
  def handle_call(:sync, _from, state), do: {:reply, :ok, drain(state)}

  def handle_call(:info, _from, state) do
    state = drain(state)

    reply =
      case Session.context_info(state.runtime_id) do
        {:ok, context} -> {:ok, Map.merge(context, state.info)}
        {:error, :not_found} -> {:ok, state.info}
        other -> other
      end

    {:reply, reply, state}
  end

  def handle_call({:result, turn_id}, _from, state) do
    state = drain(state)
    {:reply, Map.get(state.results, turn_id, {:error, :pending}), state}
  end

  def handle_call({:replay, cursor, limit}, _from, state) do
    state = drain(state)

    {:reply, {:ok, state.events |> Enum.filter(&(&1.sequence > cursor)) |> Enum.take(limit)},
     state}
  end

  @impl true
  def handle_info({:session_output, _runtime, _generation, _cursor}, state),
    do: {:noreply, drain(state)}

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, %{owner_monitor: monitor} = state) do
    Session.close(state.runtime_id)
    {:stop, :normal, drain(state)}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp drain(state) do
    case Session.drain(state.attachment, state.cursor, 500) do
      {:ok, [], info} ->
        %{state | info: info}

      {:ok, events, info} ->
        cursor = List.last(events).sequence
        # The test transcript is the receiver's saved state; send only from that copy.
        results =
          Enum.reduce(events, state.results, fn event, results ->
            if event.type in [:turn_completed, :turn_failed, :turn_interrupted] do
              Map.put(
                results,
                event.turn_id,
                Session.turn_result(state.runtime_id, event.turn_id)
              )
            else
              results
            end
          end)

        updated = %{
          state
          | events: state.events ++ events,
            cursor: cursor,
            results: results,
            info: info
        }

        :ok = Session.ack(state.attachment, cursor)
        Enum.each(events, &Kernel.send(state.owner, {:native_test_event, &1}))
        drain(updated)

      {:error, :not_found} ->
        state

      other ->
        raise "native test consumer drain failed: #{inspect(other)}"
    end
  end
end
