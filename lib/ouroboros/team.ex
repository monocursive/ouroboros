defmodule Ouroboros.Team do
  @moduledoc """
  Public API for supervised coding-agent teams.

  A team owns an inspectable Jido coordinator, local or remote Mesh workers, and
  provider-neutral `Ouroboros.CodingSession` delegations. Its serializable aggregate
  checkpoint is the source of truth: a restarted team rebuilds runtime projections,
  re-subscribes to active task cursors, and retries terminal delivery idempotently.
  A re-subscription that is refused falls back to polling the durable coding
  checkpoint rather than compensating a run that is still healthy.

  `add_worker/3` and `delegate/4` admit work that can reach another node, so both
  are bounded by `:team_call_timeout` (default 60s) and return `{:error, :timeout}`
  instead of blocking this caller behind a wedged peer. A timed-out request may
  still have been accepted durably; `state/1` reports the outcome.
  """

  alias Ouroboros.Team.Server

  @type server :: GenServer.server()
  @supervisor Ouroboros.Team.Supervisor
  @default_call_timeout 60_000

  @doc "Starts a team beneath the application-owned dynamic supervisor."
  @spec start(keyword()) :: DynamicSupervisor.on_start_child()
  def start(opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      case Process.whereis(@supervisor) do
        pid when is_pid(pid) -> DynamicSupervisor.start_child(@supervisor, {Server, opts})
        nil -> {:error, {:team_supervisor_unavailable, @supervisor}}
      end
    else
      {:error, :invalid_team_options}
    end
  end

  def start(_opts), do: {:error, :invalid_team_options}

  @doc "Returns the live local owner of a logical team ID."
  @spec whereis(String.t()) :: pid() | nil
  def whereis(id) when is_binary(id) do
    case Registry.lookup(Ouroboros.Team.Registry, id) do
      [{pid, _value}] -> pid
      [] -> nil
    end
  rescue
    ArgumentError -> nil
  catch
    :exit, _reason -> nil
  end

  @doc "Starts a team or returns its already-running local owner."
  @spec start_or_get(keyword()) :: DynamicSupervisor.on_start_child()
  def start_or_get(opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      case Keyword.fetch(opts, :id) do
        {:ok, id} when is_binary(id) ->
          case whereis(id) do
            pid when is_pid(pid) -> {:ok, pid}
            nil -> normalize_start_or_get(start(opts))
          end

        _other ->
          {:error, :invalid_team_id}
      end
    else
      {:error, :invalid_team_options}
    end
  end

  def start_or_get(_opts), do: {:error, :invalid_team_options}

  @doc "Starts a team server, normally beneath a supervisor."
  defdelegate start_link(opts), to: Server

  @doc "Adds a worker on this node or the connected node selected by `:node`."
  @spec add_worker(server(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def add_worker(team, worker_id, opts \\ []) do
    control_call(team, {:add_worker, worker_id, opts})
  end

  @doc "Assigns an objective and starts a detached, provider-neutral coding run."
  @spec delegate(server(), String.t(), String.t(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def delegate(team, worker_id, objective, opts \\ []) do
    control_call(team, {:delegate, worker_id, objective, opts})
  end

  @doc "Durably requests cancellation; final worker delivery remains asynchronous."
  @spec cancel(server(), String.t()) :: :ok | {:error, term()}
  def cancel(team, delegation_id) do
    GenServer.call(team, {:cancel, delegation_id}, :infinity)
  end

  @doc "Durably begins closure; final cancellation delivery and shutdown are asynchronous."
  @spec close(server()) :: :ok | {:error, term()}
  def close(team), do: GenServer.call(team, :close, :infinity)

  @doc "Returns explicit team runtime state, including delivery progress."
  @spec state(server()) :: map()
  def state(team), do: GenServer.call(team, :state)

  @doc "Returns the full inspectable Jido coordinator process state."
  @spec coordinator_state(server()) :: {:ok, Jido.AgentServer.State.t()} | {:error, term()}
  def coordinator_state(team), do: GenServer.call(team, :coordinator_state)

  @doc "Waits for worker and coordinator delivery of a persisted terminal result."
  @spec await(server(), String.t(), timeout()) :: {:ok, map()} | {:error, term()}
  def await(team, delegation_id, timeout \\ :infinity) do
    request_ref = make_ref()

    try do
      GenServer.call(team, {:await, delegation_id, request_ref}, timeout)
    catch
      :exit, {:timeout, _call} ->
        GenServer.cast(team, {:cancel_await, delegation_id, request_ref})
        {:error, :timeout}

      :exit, reason ->
        {:error, {:team_unavailable, reason}}
    end
  end

  defp normalize_start_or_get({:error, {:already_started, pid}}) when is_pid(pid), do: {:ok, pid}
  defp normalize_start_or_get(result), do: result

  # Membership and delegation admit work that can reach a remote node. An
  # unbounded call would let one wedged peer freeze this control plane, so the
  # caller is released with an explicit timeout while the durable request stands.
  defp control_call(team, message) do
    GenServer.call(team, message, call_timeout())
  catch
    :exit, {:timeout, _call} -> {:error, :timeout}
  end

  defp call_timeout do
    case Application.get_env(:ouroboros, :team_call_timeout, @default_call_timeout) do
      :infinity -> :infinity
      timeout when is_integer(timeout) and timeout > 0 -> timeout
      _other -> @default_call_timeout
    end
  end
end
