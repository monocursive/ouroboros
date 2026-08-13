defmodule Ouroboros.Gateway.Methods do
  @moduledoc """
  The exact set of runtime calls this build exposes, and the bound on each of them.

  ## Dispatch never grows an atom

  `table/0` is a literal map from a method *string* to its scope and ceiling, and
  `invoke/2` is one literal clause per method. A client cannot name a function this
  module does not already contain, and no client byte reaches `String.to_atom/1`. The one
  parameter that is module-shaped — `upgrade.history`'s — is resolved through
  `String.to_existing_atom/1` inside a rescue, so an unknown name is `-32602` rather than
  a new atom in a table that is never garbage collected.

  ## Every upstream call is bounded, because the planes are not

  The runtime is deliberately not uniformly bounded: `InteractiveSession.start/1` waits
  `:infinity` for provider readiness, `Team.cancel/2` and `close/1` call at `:infinity`,
  and `Team.state/1` is an uncaught 5s `GenServer.call`. So the ceiling lives here, in
  `table/0`, and `Ouroboros.Gateway.Conn` runs each handler in a supervised task under
  it. A handler that outlives its entry is killed and answered `-32005`.

  Every upstream call is additionally made in the `safe_call` posture — `try/rescue/catch
  :exit`. Several planes *exit* rather than return an error when they are down:
  `Upgrade.NodeExecutor.status/0` is a bare `GenServer.call`, and so is
  `Team.state/1`. A `:noproc` becomes `-32004`, a `:timeout` becomes `-32005`, and
  anything else becomes `-32006` carrying the Wire-encoded reason. None of them become a
  dead connection.

  Two upstream shapes are answered specially because a generic mapping would lie about
  them:

    * `Control.Grants.list/1` swallows `:exit` into `[]`, so a missing authority would
      read as "this principal holds no grants". The handler checks the process first and
      answers `-32004` instead of a false empty.
    * `Orchestration.Scheduler.get/2` returns a bare `:not_found`, not an error tuple, and
      its *server* is the first argument with a default — so the call is written out in
      full rather than left to look like `get(id)`.

  ## Scope

  Each entry carries the scope it requires. Slice 1 serves the `:read` set; the
  `:operate` verbs land in the same table with `scope: :operate` and are refused with
  `-32003` by the connection before a handler ever runs.
  """

  alias Ouroboros.CodingSession
  alias Ouroboros.Control
  alias Ouroboros.Control.Grants
  alias Ouroboros.Gateway.Wire
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Mesh
  alias Ouroboros.Orchestration.Scheduler
  alias Ouroboros.Team
  alias Ouroboros.Upgrade.NodeExecutor
  alias Ouroboros.Upgrade.Rollout.Registry, as: Rollouts
  alias Ouroboros.Upgrade.Signing.Service, as: SigningService

  @default_timeout 15_000

  # One provider probe shells out to check an installed executable, so the fan-out is
  # bounded well inside the method ceiling: a provider that never answers costs the
  # client a null status for that provider, not a timed-out method.
  @provider_probe_timeout 5_000

  # Kept below the method ceiling on purpose. An `:erpc` that outlives the gateway task
  # would be reported as `-32005 upstream_timeout` with no detail; letting `:erpc` decide
  # first produces the honest answer, which is that the signing node did not respond.
  @signing_erpc_timeout 10_000

  @replay_limit 500
  @default_replay_limit 100

  # `hello`'s entry does not describe a task ceiling — the handshake is answered by the
  # connection itself and never runs in a task. It describes the deadline by which the
  # handshake must have completed, and `Ouroboros.Gateway.Conn` reads it from here so
  # that the number a client is told about and the number enforced cannot drift apart.
  @hello_deadline 10_000

  @codes %{
    parse_error: -32700,
    invalid_request: -32600,
    method_not_found: -32601,
    invalid_params: -32602,
    unauthenticated: -32001,
    protocol_mismatch: -32002,
    scope_denied: -32003,
    unavailable: -32004,
    upstream_timeout: -32005,
    upstream_error: -32006,
    not_found: -32007
  }

  @table %{
    # `hello` is in the table because the handshake is a method a client calls and has to
    # find in `methods`. It is answered by the connection itself, which owns the socket
    # lifecycle a failed handshake has to close, so its timeout is the handshake deadline.
    "hello" => %{scope: :read, timeout: @hello_deadline},
    "runtime.status" => %{scope: :read, timeout: @default_timeout},
    "runtime.providers" => %{scope: :read, timeout: @default_timeout},
    "agents.list" => %{scope: :read, timeout: @default_timeout},
    "agents.state" => %{scope: :read, timeout: @default_timeout},
    "interactive.list" => %{scope: :read, timeout: @default_timeout},
    "interactive.info" => %{scope: :read, timeout: @default_timeout},
    "interactive.replay" => %{scope: :read, timeout: @default_timeout},
    "coding.list" => %{scope: :read, timeout: @default_timeout},
    "coding.info" => %{scope: :read, timeout: @default_timeout},
    "coding.replay" => %{scope: :read, timeout: @default_timeout},
    "teams.list" => %{scope: :read, timeout: @default_timeout},
    "teams.state" => %{scope: :read, timeout: @default_timeout},
    "plans.list" => %{scope: :read, timeout: @default_timeout},
    "plans.get" => %{scope: :read, timeout: @default_timeout},
    "control.list" => %{scope: :read, timeout: @default_timeout},
    "control.get" => %{scope: :read, timeout: @default_timeout},
    "upgrade.status" => %{scope: :read, timeout: @default_timeout},
    "upgrade.rollouts" => %{scope: :read, timeout: @default_timeout},
    "upgrade.history" => %{scope: :read, timeout: @default_timeout},
    "signing.decisions" => %{scope: :read, timeout: @default_timeout},
    "grants.list" => %{scope: :read, timeout: @default_timeout}
  }

  @type entry :: %{scope: :read | :operate, timeout: pos_integer()}

  @typedoc """
  What a handler answers. `{:ok, term}` is Wire-encoded into `result`; the error shapes
  become a JSON-RPC error object, with `data` Wire-encoded when present.
  """
  @type result ::
          {:ok, term()}
          | {:error, integer(), String.t()}
          | {:error, integer(), String.t(), term()}

  @doc "The method table: name to the scope it requires and the ceiling it runs under."
  @spec table() :: %{String.t() => entry()}
  def table, do: @table

  @doc "Every method name this build serves, as reported in the `hello` result."
  @spec names() :: [String.t()]
  def names, do: @table |> Map.keys() |> Enum.sort()

  @doc "Looks up one method without ever converting the name to an atom."
  @spec fetch(String.t()) :: {:ok, entry()} | :error
  def fetch(name) when is_binary(name), do: Map.fetch(@table, name)

  @doc """
  Whether a listener running at `listener_scope` may run this method.

  Scope is a property of the listener, fixed at boot, not of the connection: a client
  cannot ask for more than the process it connected to was started with. Slice 1's table
  is entirely `:read`, so this refuses nothing yet — it is the gate the `:operate` verbs
  arrive behind, and it lives beside the table that declares them rather than inside the
  connection that happens to consult it.
  """
  @spec permits?(:read | :operate, entry()) :: boolean()
  def permits?(:operate, _entry), do: true
  def permits?(:read, %{scope: scope}), do: scope == :read

  @doc "The numeric code for one named protocol error."
  @spec code(atom()) :: integer()
  def code(name), do: Map.fetch!(@codes, name)

  @doc """
  Runs one method's handler. Called inside a supervised task, never in the connection.
  """
  @spec invoke(String.t(), map()) :: result()
  def invoke(method, params)

  def invoke("runtime.status", _params), do: safe(fn -> {:ok, Ouroboros.status()} end)

  def invoke("runtime.providers", _params), do: safe(fn -> {:ok, providers()} end)

  def invoke("agents.list", _params), do: safe(fn -> reply(Mesh.list_agents()) end)

  def invoke("agents.state", params) do
    with_id(params, fn id -> safe(fn -> reply(Mesh.state(id)) end) end)
  end

  def invoke("interactive.list", _params), do: safe(fn -> reply(InteractiveSession.list()) end)

  def invoke("interactive.info", params) do
    with_id(params, fn id -> safe(fn -> reply(InteractiveSession.info(id)) end) end)
  end

  def invoke("interactive.replay", params) do
    with_replay(params, fn id, opts -> InteractiveSession.replay(id, opts) end)
  end

  def invoke("coding.list", _params), do: safe(fn -> reply(CodingSession.list()) end)

  def invoke("coding.info", params) do
    with_id(params, fn id -> safe(fn -> reply(CodingSession.info(id)) end) end)
  end

  def invoke("coding.replay", params) do
    with_replay(params, fn id, opts -> CodingSession.replay(id, opts) end)
  end

  def invoke("teams.list", _params), do: safe(fn -> {:ok, teams()} end)

  def invoke("teams.state", params) do
    with_id(params, fn id ->
      case Team.whereis(id) do
        pid when is_pid(pid) -> safe(fn -> reply(Team.state(pid)) end)
        nil -> not_found("no team #{inspect(id)} is running on this node")
      end
    end)
  end

  def invoke("plans.list", _params), do: safe(fn -> reply(Scheduler.list(Scheduler)) end)

  def invoke("plans.get", params) do
    with_id(params, fn id -> safe(fn -> reply(Scheduler.get(Scheduler, id)) end) end)
  end

  def invoke("control.list", _params), do: safe(fn -> reply(Control.list()) end)

  def invoke("control.get", params) do
    with_id(params, fn id -> safe(fn -> reply(Control.get(id)) end) end)
  end

  def invoke("upgrade.status", _params), do: safe(fn -> {:ok, NodeExecutor.status()} end)

  def invoke("upgrade.rollouts", _params), do: safe(fn -> reply(Rollouts.list()) end)

  def invoke("upgrade.history", params) do
    with {:ok, name} <- fetch_string(params, "module"),
         {:ok, module} <- resolve_module(name) do
      safe(fn -> reply(Rollouts.history(module)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("signing.decisions", _params) do
    case Application.get_env(:ouroboros, :signing_node) do
      signing_node when is_atom(signing_node) and not is_nil(signing_node) ->
        signing_decisions(signing_node)

      _absent ->
        unavailable(
          "no signing node is configured on this node; OUROBOROS_SIGNING_NODE names " <>
            "the :signer node that holds the key and its decision journal"
        )
    end
  end

  def invoke("grants.list", params) do
    with {:ok, principal} <- fetch_string(params, "principal") do
      # `Grants.list/1` catches `:exit` and answers `[]`, which would render as "this
      # principal holds nothing" on a node where the authority is simply not running.
      if is_pid(Process.whereis(Grants)) do
        safe(fn -> reply(Grants.list(principal)) end)
      else
        unavailable("the effect grant authority is not running on this node")
      end
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  # Reached only if `table/0` and the clauses above ever drift apart. Answering rather
  # than raising keeps that drift a client-visible error instead of a killed task.
  def invoke(method, _params) when is_binary(method) do
    {:error, code(:method_not_found), "this build does not serve #{method}"}
  end

  defp providers do
    specs = Ouroboros.providers()

    specs
    |> Task.async_stream(&probe_provider/1,
      timeout: @provider_probe_timeout,
      on_timeout: :kill_task,
      max_concurrency: max(length(specs), 1),
      ordered: true
    )
    |> Enum.zip(specs)
    |> Enum.map(fn
      {{:ok, probed}, _spec} ->
        probed

      {{:exit, _reason}, spec} ->
        %{provider: spec.provider, spec: spec, status: nil, error: :probe_timeout}
    end)
  end

  defp probe_provider(spec) do
    case Ouroboros.provider_status(spec.provider) do
      {:ok, status} -> %{provider: spec.provider, spec: spec, status: status, error: nil}
      {:error, reason} -> %{provider: spec.provider, spec: spec, status: nil, error: reason}
    end
  end

  # Projected exactly as `Ouroboros.status/0` projects it, so a client reading both sees
  # one shape for a team rather than two.
  defp teams do
    Team.Store.list()
    |> Enum.map(fn team ->
      %{
        id: team.id,
        status: team.status,
        worker_count: map_size(team.workers),
        delegation_count: map_size(team.delegations),
        updated_at: team.updated_at
      }
    end)
  end

  defp signing_decisions(signing_node) do
    if Node.alive?() do
      erpc_decisions(signing_node)
    else
      unavailable(
        "this node is not distributed, so it cannot reach signing node " <>
          "#{signing_node}; a daemon started with OUROBOROS_DIST=none has no :erpc"
      )
    end
  end

  defp erpc_decisions(signing_node) do
    reply(:erpc.call(signing_node, SigningService, :decisions, [], erpc_timeout()))
  rescue
    error in ErlangError -> erpc_failure(signing_node, error.original)
    error -> upstream_error(error)
  catch
    :exit, reason -> exit_result(reason)
    kind, reason -> upstream_error({kind, reason})
  end

  defp erpc_failure(signing_node, {:erpc, :noconnection}) do
    unavailable("signing node #{signing_node} is not connected to this node")
  end

  defp erpc_failure(signing_node, {:erpc, :timeout}) do
    {:error, code(:upstream_timeout), "signing node #{signing_node} did not answer in time"}
  end

  defp erpc_failure(_signing_node, other), do: upstream_error(other)

  defp erpc_timeout do
    min(
      Application.get_env(:ouroboros, :signing_call_timeout, @signing_erpc_timeout),
      @signing_erpc_timeout
    )
  end

  defp with_id(params, fun) do
    case fetch_string(params, "id") do
      {:ok, id} -> fun.(id)
      {:invalid, message} -> invalid_params(message)
    end
  end

  defp with_replay(params, replay) do
    with {:ok, id} <- fetch_string(params, "id"),
         {:ok, cursor} <- fetch_cursor(params),
         {:ok, limit} <- fetch_limit(params) do
      safe(fn -> reply(replay.(id, cursor: cursor, limit: limit)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  defp fetch_string(params, key) do
    case Map.get(params, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _other -> {:invalid, "params.#{key} must be a nonempty string"}
    end
  end

  defp fetch_cursor(params) do
    case Map.get(params, "cursor", 0) do
      cursor when is_integer(cursor) and cursor >= 0 -> {:ok, cursor}
      _other -> {:invalid, "params.cursor must be a non-negative integer"}
    end
  end

  defp fetch_limit(params) do
    case Map.get(params, "limit", @default_replay_limit) do
      limit when is_integer(limit) and limit > 0 and limit <= @replay_limit ->
        {:ok, limit}

      _other ->
        {:invalid, "params.limit must be an integer between 1 and #{@replay_limit}"}
    end
  end

  # A client echoes back the module name this gateway printed, and `Wire` prints module
  # atoms without their `Elixir.` prefix. Both spellings resolve, and neither creates an
  # atom: an unknown module is a parameter error, not a new entry in the atom table.
  defp resolve_module("Elixir." <> _rest = name), do: existing_atom(name, name)
  defp resolve_module(name), do: existing_atom("Elixir." <> name, name)

  defp existing_atom(preferred, original) do
    {:ok, String.to_existing_atom(preferred)}
  rescue
    ArgumentError ->
      try do
        {:ok, String.to_existing_atom(original)}
      rescue
        ArgumentError ->
          {:invalid,
           "params.module must name a module this node has loaded, got: #{inspect(original)}"}
      end
  end

  defp safe(fun) do
    fun.()
  rescue
    error -> upstream_error(error)
  catch
    :exit, reason -> exit_result(reason)
    kind, reason -> upstream_error({kind, reason})
  end

  defp reply({:ok, value}), do: {:ok, value}

  defp reply(:not_found), do: not_found("no such record on this node")
  defp reply({:error, :not_found}), do: not_found("no such record on this node")

  defp reply({:error, {:agent_not_found, id}}),
    do: not_found("no agent #{inspect(id)} is visible from this node")

  defp reply({:error, {:team_not_found, id}}),
    do: not_found("no team #{inspect(id)} is visible from this node")

  defp reply({:error, :control_disabled_or_unavailable}),
    do: unavailable("the control plane is disabled or not running on this node")

  defp reply({:error, {:signing_service_unavailable, _detail} = reason}),
    do: {:error, code(:unavailable), "the signing service did not answer", Wire.to_json(reason)}

  defp reply({:error, reason}),
    do: {:error, code(:upstream_error), "the runtime refused the call", Wire.to_json(reason)}

  defp reply(value), do: {:ok, value}

  defp exit_result(reason) do
    case exit_class(reason) do
      :gone ->
        {:error, code(:unavailable), "that plane is not running on this node",
         Wire.to_json(reason)}

      :timeout ->
        {:error, code(:upstream_timeout), "the runtime did not answer in time",
         Wire.to_json(reason)}

      :other ->
        {:error, code(:upstream_error), "the runtime failed the call", Wire.to_json(reason)}
    end
  end

  defp exit_class(:noproc), do: :gone
  defp exit_class({:noproc, _detail}), do: :gone
  defp exit_class(:normal), do: :gone
  defp exit_class({:normal, _detail}), do: :gone
  defp exit_class(:shutdown), do: :gone
  defp exit_class({:shutdown, _detail}), do: :gone
  defp exit_class(:timeout), do: :timeout
  defp exit_class({:timeout, _detail}), do: :timeout
  defp exit_class(_reason), do: :other

  defp upstream_error(reason) do
    {:error, code(:upstream_error), "the runtime failed the call", Wire.to_json(reason)}
  end

  defp unavailable(message), do: {:error, code(:unavailable), message}
  defp not_found(message), do: {:error, code(:not_found), message}
  defp invalid_params(message), do: {:error, code(:invalid_params), message}
end
