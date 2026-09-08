defmodule Ouroboros.Audit.Worker do
  @moduledoc "Bounded retry scheduling for optional custody and derived telemetry."
  use GenServer
  alias Ouroboros.Audit.{Archive, Config}
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  def status, do: GenServer.call(__MODULE__, :status)
  @impl true
  def init(_) do
    config = Config.current()

    if Config.enabled?(config) and (config.archive != nil or config.otlp_endpoint != nil),
      do: send(self(), :flush)

    {:ok, %{config: config, error: nil, last_success: nil, retries: 0, task: nil}}
  end

  @impl true
  def handle_call(:status, _, state),
    do: {:reply, Map.take(state, [:error, :last_success, :retries]), state}

  @impl true
  def handle_info(:flush, %{task: nil} = state) do
    owner = self()
    config = state.config
    {pid, ref} = spawn_monitor(fn -> send(owner, {:flushed, flush(config)}) end)
    {:noreply, %{state | task: {pid, ref}}}
  end

  def handle_info({:flushed, result}, state) do
    {_, ref} = state.task
    Process.demonitor(ref, [:flush])

    next =
      case result do
        :ok ->
          %{
            state
            | task: nil,
              error: nil,
              retries: 0,
              last_success: DateTime.to_iso8601(DateTime.utc_now())
          }

        _ ->
          %{state | task: nil, error: :audit_export_retry_pending, retries: state.retries + 1}
      end

    Process.send_after(
      self(),
      :flush,
      min(5_000 * trunc(:math.pow(2, min(next.retries, 6))), 300_000)
    )

    {:noreply, next}
  end

  def handle_info({:DOWN, ref, :process, _, _}, %{task: {_, ref}} = state) do
    Process.send_after(self(), :flush, 30_000)

    {:noreply,
     %{state | task: nil, error: :audit_export_retry_pending, retries: state.retries + 1}}
  end

  def handle_info(_, state), do: {:noreply, state}
  @impl true
  def terminate(_, %{task: {pid, _}}), do: Process.exit(pid, :shutdown)
  def terminate(_, _), do: :ok

  defp flush(config) do
    result =
      if config.archive do
        with {:ok, pending} <- Archive.pending(config) do
          Enum.reduce_while(Enum.take(pending, 200), :ok, fn record, :ok ->
            case Archive.deliver(record, config) do
              :ok -> {:cont, :ok}
              error -> {:halt, error}
            end
          end)
        end
      else
        :ok
      end

    with :ok <- result, do: Ouroboros.Audit.OTLP.flush(config)
  end
end
