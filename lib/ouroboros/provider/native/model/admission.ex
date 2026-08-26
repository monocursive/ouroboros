defmodule Ouroboros.Provider.Native.Model.Admission do
  @moduledoc """
  Node-wide admission control for Native model streams.

  A Native session can fan out into four children and those children can fan out again.
  Per-session child limits therefore do not bound the number of long-lived HTTP streams on
  one runtime. Finch's HTTP/1 pool is the transport, not the scheduler: when its capacity is
  exceeded it queues against one selected pool worker and eventually raises an opaque checkout
  timeout.

  This server owns the limit before Finch. Callers beyond it wait in a bounded, monitored queue;
  dead sessions are removed, queue waits have their own deadline, and a checked-out lease is
  released if its owner dies. `with_stream/2` holds the lease for the complete lazy enumeration,
  including early halt and exceptions.
  """

  use GenServer

  defmodule Lease do
    @moduledoc false
    @enforce_keys [:server, :ref]
    defstruct [:server, :ref]

    @type t :: %__MODULE__{server: GenServer.server(), ref: reference()}
  end

  defmodule LeaseStream do
    @moduledoc false
    @enforce_keys [:enumerable, :lease]
    defstruct [:enumerable, :lease]

    @type t :: %__MODULE__{enumerable: Enumerable.t(), lease: Lease.t()}
  end

  @type checkout_error ::
          {:model_capacity_exhausted, %{limit: pos_integer(), queue_limit: pos_integer()}}
          | {:model_capacity_timeout, %{limit: pos_integer(), waited_ms: pos_integer()}}
          | {:model_admission_unavailable, term()}

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, Keyword.put(opts, :server, name), name: name)
  end

  @doc "Waits for one model-stream lease within the server's bounded queue."
  @spec checkout(GenServer.server()) :: {:ok, Lease.t()} | {:error, checkout_error()}
  def checkout(server \\ __MODULE__) do
    GenServer.call(server, {:checkout, self()}, :infinity)
  catch
    :exit, reason -> {:error, {:model_admission_unavailable, reason}}
  end

  @doc "Releases a lease. Releasing an already released lease is harmless."
  @spec release(Lease.t()) :: :ok
  def release(%Lease{server: server, ref: ref}) do
    GenServer.call(server, {:release, ref}, :infinity)
  catch
    :exit, _reason -> :ok
  end

  @doc """
  Runs a stream constructor under admission and returns a lease-holding enumerable.

  The constructor must return the same `{:ok, enumerable} | {:error, reason}` shape as a model
  client. A pre-stream error, unexpected return, or exception releases immediately; a successful
  lazy stream holds the lease until enumeration finishes, halts, raises, or its owner process exits.
  """
  @spec with_stream((-> {:ok, Enumerable.t()} | {:error, term()}), GenServer.server()) ::
          {:ok, Enumerable.t()} | {:error, term()}
  def with_stream(fun, server \\ __MODULE__) when is_function(fun, 0) do
    with {:ok, lease} <- checkout(server) do
      try do
        case fun.() do
          {:ok, enumerable} ->
            {:ok, %LeaseStream{enumerable: enumerable, lease: lease}}

          {:error, _reason} = error ->
            :ok = release(lease)
            error

          other ->
            :ok = release(lease)
            {:error, {:invalid_stream, other}}
        end
      rescue
        error ->
          :ok = release(lease)
          reraise error, __STACKTRACE__
      catch
        kind, reason ->
          :ok = release(lease)
          :erlang.raise(kind, reason, __STACKTRACE__)
      end
    end
  end

  @doc false
  @spec status(GenServer.server()) :: map()
  def status(server \\ __MODULE__), do: GenServer.call(server, :status)

  @impl true
  def init(opts) do
    with {:ok, limit} <- positive_integer(Keyword.get(opts, :limit, 8), :limit),
         {:ok, queue_limit} <- positive_integer(Keyword.get(opts, :queue_limit, 32), :queue_limit),
         {:ok, queue_timeout_ms} <-
           positive_integer(Keyword.get(opts, :queue_timeout_ms, 120_000), :queue_timeout_ms) do
      {:ok,
       %{
         server: Keyword.fetch!(opts, :server),
         limit: limit,
         queue_limit: queue_limit,
         queue_timeout_ms: queue_timeout_ms,
         active: %{},
         active_monitors: %{},
         queue: :queue.new(),
         waiters: %{},
         waiter_monitors: %{}
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:checkout, owner}, from, state) do
    cond do
      map_size(state.active) < state.limit ->
        {lease, state} = activate(state, owner)
        {:reply, {:ok, lease}, state}

      map_size(state.waiters) >= state.queue_limit ->
        error =
          {:model_capacity_exhausted, %{limit: state.limit, queue_limit: state.queue_limit}}

        {:reply, {:error, error}, state}

      true ->
        ref = make_ref()
        monitor = Process.monitor(owner)
        timer = Process.send_after(self(), {:checkout_timeout, ref}, state.queue_timeout_ms)

        waiter = %{from: from, owner: owner, monitor: monitor, timer: timer}

        {:noreply,
         %{
           state
           | queue: :queue.in(ref, state.queue),
             waiters: Map.put(state.waiters, ref, waiter),
             waiter_monitors: Map.put(state.waiter_monitors, monitor, ref)
         }}
    end
  end

  def handle_call({:release, ref}, _from, state) do
    {:reply, :ok, release_active(state, ref)}
  end

  def handle_call(:status, _from, state) do
    {:reply,
     %{
       limit: state.limit,
       active: map_size(state.active),
       queued: map_size(state.waiters),
       queue_limit: state.queue_limit,
       queue_timeout_ms: state.queue_timeout_ms
     }, state}
  end

  @impl true
  def handle_info({:checkout_timeout, ref}, state) do
    case Map.get(state.waiters, ref) do
      nil ->
        {:noreply, state}

      %{from: from} ->
        GenServer.reply(
          from,
          {:error,
           {:model_capacity_timeout, %{limit: state.limit, waited_ms: state.queue_timeout_ms}}}
        )

        {:noreply, remove_waiter(state, ref, true)}
    end
  end

  def handle_info({:DOWN, monitor, :process, _owner, _reason}, state) do
    cond do
      ref = state.active_monitors[monitor] ->
        {:noreply, release_active(state, ref, false)}

      ref = state.waiter_monitors[monitor] ->
        {:noreply, remove_waiter(state, ref, false)}

      true ->
        {:noreply, state}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp activate(state, owner) do
    ref = make_ref()
    monitor = Process.monitor(owner)
    lease = %Lease{server: state.server, ref: ref}

    state = %{
      state
      | active: Map.put(state.active, ref, %{owner: owner, monitor: monitor}),
        active_monitors: Map.put(state.active_monitors, monitor, ref)
    }

    {lease, state}
  end

  defp activate_waiter(state, ref, waiter) do
    _ = Process.cancel_timer(waiter.timer, async: false, info: false)
    lease = %Lease{server: state.server, ref: ref}

    GenServer.reply(waiter.from, {:ok, lease})

    %{
      state
      | active: Map.put(state.active, ref, %{owner: waiter.owner, monitor: waiter.monitor}),
        active_monitors: Map.put(state.active_monitors, waiter.monitor, ref),
        waiter_monitors: Map.delete(state.waiter_monitors, waiter.monitor)
    }
  end

  defp release_active(state, ref, demonitor? \\ true) do
    case Map.pop(state.active, ref) do
      {nil, _active} ->
        state

      {%{monitor: monitor}, active} ->
        if demonitor?, do: Process.demonitor(monitor, [:flush])

        state
        |> Map.put(:active, active)
        |> Map.put(:active_monitors, Map.delete(state.active_monitors, monitor))
        |> grant_next()
    end
  end

  defp remove_waiter(state, ref, demonitor?) do
    case Map.pop(state.waiters, ref) do
      {nil, _waiters} ->
        state

      {%{monitor: monitor, timer: timer}, waiters} ->
        _ = Process.cancel_timer(timer, async: false, info: false)
        if demonitor?, do: Process.demonitor(monitor, [:flush])

        # Drop the ref from the Erlang queue here. Leaving it for `grant_next/1` to skip
        # would grow without bound under timeout churn while the limit is full.
        %{
          state
          | waiters: waiters,
            waiter_monitors: Map.delete(state.waiter_monitors, monitor),
            queue: :queue.delete(ref, state.queue)
        }
    end
  end

  defp grant_next(state) do
    case :queue.out(state.queue) do
      {:empty, queue} ->
        %{state | queue: queue}

      {{:value, ref}, queue} ->
        state = %{state | queue: queue}

        case Map.pop(state.waiters, ref) do
          {nil, _waiters} ->
            grant_next(state)

          {waiter, waiters} ->
            state
            |> Map.put(:waiters, waiters)
            |> activate_waiter(ref, waiter)
        end
    end
  end

  defp positive_integer(value, _name) when is_integer(value) and value > 0, do: {:ok, value}
  defp positive_integer(value, name), do: {:error, {:invalid_option, name, value}}
end

defimpl Enumerable, for: Ouroboros.Provider.Native.Model.Admission.LeaseStream do
  alias Ouroboros.Provider.Native.Model.Admission

  def reduce(%{enumerable: enumerable, lease: lease}, acc, fun) do
    reduce_with_release(fn -> Enumerable.reduce(enumerable, acc, fun) end, lease)
  end

  def count(_stream), do: {:error, __MODULE__}
  def member?(_stream, _value), do: {:error, __MODULE__}
  def slice(_stream), do: {:error, __MODULE__}

  defp reduce_with_release(fun, lease) do
    result =
      try do
        fun.()
      rescue
        error ->
          :ok = Admission.release(lease)
          reraise error, __STACKTRACE__
      catch
        kind, reason ->
          :ok = Admission.release(lease)
          :erlang.raise(kind, reason, __STACKTRACE__)
      end

    case result do
      {:suspended, acc, continuation} ->
        {:suspended, acc,
         fn next -> reduce_with_release(fn -> continuation.(next) end, lease) end}

      {status, _acc} = terminal when status in [:done, :halted] ->
        :ok = Admission.release(lease)
        terminal
    end
  end
end
