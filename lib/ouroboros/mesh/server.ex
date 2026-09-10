defmodule Ouroboros.Mesh.Server do
  @moduledoc """
  Serialized state ownership with one supervised handler and a bounded waiting queue.

  A caller timeout does not cancel a possibly executed message. State inspection and
  queue admission remain responsive while a handler runs. Handler tasks are linked to
  their owner so forced owner death cannot abandon work.
  """
  use GenServer
  require Logger

  alias Ouroboros.Signals.AgentMessage

  def start_link(opts) do
    id = Keyword.fetch!(opts, :id)
    GenServer.start_link(__MODULE__, opts, name: {:via, Registry, {Ouroboros.Mesh.Registry, id}})
  end

  def call(pid, signal, timeout), do: GenServer.call(pid, {:signal, signal}, timeout)
  def state(pid), do: GenServer.call(pid, :get_state)

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    module = Keyword.fetch!(opts, :agent)
    max_queue = Keyword.get(opts, :max_queue_size, 10_000)
    policy = Keyword.get(opts, :error_policy, :log_only)

    with :ok <- validate_options(max_queue, policy),
         {:ok, domain} <-
           invoke(fn -> module.init_state(Keyword.fetch!(opts, :initial_state)) end) do
      send(self(), :register)

      {:ok,
       %{
         id: Keyword.fetch!(opts, :id),
         module: module,
         domain: domain,
         queue: :queue.new(),
         queue_size: 0,
         max_queue_size: max_queue,
         active: nil,
         error_policy: policy,
         error_count: 0
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:get_state, _from, state), do: {:reply, {:ok, inspect_state(state)}, state}

  def handle_call({:signal, signal}, from, state) do
    with {:ok, validated} <- validate_message(signal) do
      cond do
        state.active == nil ->
          {:noreply, dispatch(state, validated.data, from)}

        state.queue_size < state.max_queue_size ->
          {:noreply,
           %{
             state
             | queue: :queue.in({validated.data, from}, state.queue),
               queue_size: state.queue_size + 1
           }}

        true ->
          {:reply, {:error, :queue_overflow}, state}
      end
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_info({ref, result}, %{active: %{ref: ref, from: from}} = state) do
    Process.demonitor(ref, [:flush])
    finish(result, from, %{state | active: nil})
  end

  def handle_info(
        {:DOWN, ref, :process, _pid, reason},
        %{active: %{ref: ref, from: from}} = state
      ),
      do: finish({:error, {:handler_exit, reason}}, from, %{state | active: nil})

  def handle_info(:register, state) do
    if Process.whereis(Ouroboros.Mesh.Directory) do
      try do
        Ouroboros.Mesh.Directory.register_async(state.id, self())
      catch
        :exit, _ -> Process.send_after(self(), :register, 25)
      end
    else
      Process.send_after(self(), :register, 25)
    end

    {:noreply, state}
  end

  def handle_info({:EXIT, _pid, _reason}, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{active: %{pid: pid}}), do: Process.exit(pid, :kill)
  def terminate(_reason, _state), do: :ok

  defp dispatch(state, data, from) do
    context = %{id: state.id, server_pid: self()}
    module = state.module
    domain = state.domain

    task =
      Task.Supervisor.async(Ouroboros.Mesh.Tasks, fn ->
        invoke(fn -> module.handle_message(data, domain, context) end)
      end)

    %{state | active: %{pid: task.pid, ref: task.ref, from: from}}
  end

  defp finish({:ok, domain}, from, state) do
    state = %{state | domain: domain}
    GenServer.reply(from, {:ok, %{id: state.id, state: domain}})
    {:noreply, next(state)}
  end

  defp finish({:error, reason}, from, state) do
    GenServer.reply(from, {:error, reason})
    state = %{state | error_count: state.error_count + 1}

    Logger.error(fn ->
      "mesh agent #{state.id} handler failed: #{inspect(reason, limit: 10, printable_limit: 200)}"
    end)

    case state.error_policy do
      :stop_on_error ->
        {:stop, {:agent_error, reason}, state}

      {:max_errors, max} when state.error_count >= max ->
        {:stop, {:max_errors_exceeded, state.error_count}, state}

      _ ->
        {:noreply, next(state)}
    end
  end

  defp next(state) do
    case :queue.out(state.queue) do
      {{:value, {data, from}}, queue} ->
        dispatch(%{state | queue: queue, queue_size: state.queue_size - 1}, data, from)

      {:empty, _} ->
        state
    end
  end

  defp inspect_state(state), do: %{agent: %{id: state.id, state: state.domain}}

  # The local constructor retains its validation diagnostics. A remote process can also
  # construct a malformed envelope directly; no validation-library exception may kill
  # the state owner or discard its already committed work.
  defp validate_message(signal) do
    AgentMessage.validate(signal)
  rescue
    error -> {:error, {:invalid_message, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:invalid_message, kind, reason}}
  end

  defp invoke(fun) do
    case fun.() do
      {:ok, state} when is_map(state) and not is_struct(state) -> {:ok, state}
      {:error, reason} -> {:error, reason}
      other -> {:error, {:invalid_agent_result, other}}
    end
  rescue
    error -> {:error, Exception.message(error)}
  catch
    kind, reason -> {:error, {:handler_failure, kind, reason}}
  end

  defp validate_options(max, policy) when is_integer(max) and max >= 0 do
    case policy do
      value when value in [:log_only, :stop_on_error] -> :ok
      {:max_errors, count} when is_integer(count) and count > 0 -> :ok
      other -> {:error, {:unsupported_error_policy, other}}
    end
  end

  defp validate_options(max, _policy), do: {:error, {:invalid_max_queue_size, max}}
end
