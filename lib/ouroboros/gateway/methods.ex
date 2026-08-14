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

  Each entry carries the scope it requires. The `:read` set answers on any listener; the
  `:operate` verbs carry `scope: :operate` and are refused with `-32003` by the connection
  before a handler ever runs. `runtime.shutdown` needs one more thing than its scope —
  `OUROBOROS_GATEWAY_ALLOW_SHUTDOWN=1` — and that check lives in the connection, which is
  the only thing holding the listener's configuration.

  ## Client input never becomes an atom

  The mutating verbs take options, and every option a plane accepts is an atom key with,
  frequently, an atom value. None of them are built from client bytes. Option *keys* are
  literal atoms in this module, chosen by matching the client's string against an
  allowlist. Option *values* that are enums come from a literal map of the exact terms the
  upstream schema declares (`Jido.Harness.RunRequest`'s approval and sandbox modes,
  `ApprovalResponse`'s decisions). A provider name is matched against the providers this
  node actually serves, and a node name against `[node() | Node.list()]` — by string
  comparison against atoms that already exist, never by conversion. An option this module
  does not list is `-32602` naming it rather than silently dropped, the same posture the
  planes take toward their own callers.

  ## Subscriptions are not invoked here

  `interactive.subscribe` and its three siblings are in `table/0` — a client has to find
  them in `hello` — but they are answered by `Ouroboros.Gateway.Conn` itself rather than by
  `invoke/2`, because the plane registers `self()` as the subscriber and a dispatch task is
  the wrong `self()`. `subscribe/3`, `unsubscribe/2`, `session/2`, and `coordinator/2` are
  the pieces that connection calls; they are here so that the knowledge of which plane
  function answers which shape stays in one module.

  A pruned cursor is the one upstream shape whose *detail* a client acts on, so it is not
  flattened into a message: `{:error, {:cursor_pruned, floor}}` becomes `-32006` with
  `data` `%{"reason" => "cursor_pruned", "floor" => floor}`, and a client resumes from the
  floor. It is the only error in this build whose `data` carries a `"reason"` discriminator,
  and the golden fixtures pin the shape.
  """

  alias Ouroboros.Coding.Task, as: CodingTask
  alias Ouroboros.Coding.TaskState
  alias Ouroboros.CodingSession
  alias Ouroboros.Control
  alias Ouroboros.Control.Grants
  alias Ouroboros.Gateway.Wire
  alias Ouroboros.Interactive.State, as: InteractiveState
  alias Ouroboros.Interactive.Task, as: InteractiveTask
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Mesh
  alias Ouroboros.Orchestration.Scheduler
  alias Ouroboros.Provider.CodexAppServer
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

  # `InteractiveSession.start/1` waits `:infinity` for provider readiness by design — a
  # provider that has to be installed, authenticated, or woken up legitimately takes
  # minutes on a first run. The gateway still refuses to hold a request open forever, so
  # this is the one ceiling measured in provider time rather than in control-plane time.
  @start_timeout 120_000

  # `Team.add_worker/3` and `delegate/4` bound themselves at 60s; `cancel/2` and `close/1`
  # call at `:infinity`. Both land here as 60s, and for the two `:infinity` verbs the
  # timeout answer says what it can honestly say: the gateway stopped waiting, the runtime
  # did not stop working, and `teams.state` is where the outcome shows up.
  @team_timeout 60_000

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
    "account.read" => %{scope: :read, timeout: @default_timeout},
    "agents.list" => %{scope: :read, timeout: @default_timeout},
    "agents.state" => %{scope: :read, timeout: @default_timeout},
    "interactive.list" => %{scope: :read, timeout: @default_timeout},
    "interactive.info" => %{scope: :read, timeout: @default_timeout},
    "interactive.replay" => %{scope: :read, timeout: @default_timeout},
    "interactive.subscribe" => %{scope: :read, timeout: @default_timeout},
    "interactive.unsubscribe" => %{scope: :read, timeout: @default_timeout},
    "coding.list" => %{scope: :read, timeout: @default_timeout},
    "coding.info" => %{scope: :read, timeout: @default_timeout},
    "coding.replay" => %{scope: :read, timeout: @default_timeout},
    "coding.subscribe" => %{scope: :read, timeout: @default_timeout},
    "coding.unsubscribe" => %{scope: :read, timeout: @default_timeout},
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
    "grants.list" => %{scope: :read, timeout: @default_timeout},
    "interactive.start" => %{scope: :operate, timeout: @start_timeout},
    "account.login.start" => %{scope: :operate, timeout: @default_timeout},
    "account.login.cancel" => %{scope: :operate, timeout: @default_timeout},
    "account.logout" => %{scope: :operate, timeout: @default_timeout},
    "interactive.send_message" => %{scope: :operate, timeout: @default_timeout},
    "interactive.follow_up" => %{scope: :operate, timeout: @default_timeout},
    "interactive.steer" => %{scope: :operate, timeout: @default_timeout},
    "interactive.respond_approval" => %{scope: :operate, timeout: @default_timeout},
    "interactive.interrupt" => %{scope: :operate, timeout: @default_timeout},
    "interactive.close" => %{scope: :operate, timeout: @default_timeout},
    "interactive.kill" => %{scope: :operate, timeout: @default_timeout},
    "coding.start" => %{scope: :operate, timeout: @start_timeout},
    "coding.cancel" => %{scope: :operate, timeout: @default_timeout},
    "teams.add_worker" => %{scope: :operate, timeout: @team_timeout},
    "teams.delegate" => %{scope: :operate, timeout: @team_timeout},
    # The two verbs whose upstream call is `:infinity`. A gateway timeout here does not
    # cancel anything, so the answer carries `outcome: unknown` rather than implying the
    # request was refused; `teams.state` is how a client learns which it was.
    "teams.cancel" => %{scope: :operate, timeout: @team_timeout, outcome: :unknown},
    "teams.close" => %{scope: :operate, timeout: @team_timeout, outcome: :unknown},
    "control.submit" => %{scope: :operate, timeout: @default_timeout},
    "control.cancel" => %{scope: :operate, timeout: @default_timeout},
    "agents.stop" => %{scope: :operate, timeout: @default_timeout},
    # Answered by the connection: it holds the listener configuration this verb needs a
    # second permission from, and it owns the socket the acknowledgement has to reach
    # before the node stops.
    "runtime.shutdown" => %{scope: :operate, timeout: @default_timeout}
  }

  # The exact terms the upstream schemas declare, spelled out here so that a client string
  # is matched against them rather than converted into one. `Jido.Harness.RunRequest`
  # names the first three; `Jido.Harness.ApprovalResponse` names the last two.
  @approval_modes %{
    "default" => :default,
    "prompt" => :prompt,
    "auto_edit" => :auto_edit,
    "auto_approve" => :auto_approve
  }

  @sandbox_modes %{
    "default" => :default,
    "read_only" => :read_only,
    "workspace_write" => :workspace_write,
    "unrestricted" => :unrestricted
  }

  @reasoning_efforts %{"low" => :low, "medium" => :medium, "high" => :high}

  @approval_decisions %{"approve" => :approve, "deny" => :deny}
  @approval_scopes %{"once" => :once, "session" => :session}

  # What a client may set when it starts a session or a coding run. Everything here is
  # durable, provider-neutral execution intent. Deliberately absent: `env`, `mcp_config`,
  # and `provider_options` — the durable checkpoint refuses inline environment and MCP
  # configuration outright ([coding/task_state.ex]), and provider knobs are node
  # configuration rather than something a terminal hands over per run.
  @start_options %{
    "id" => :string,
    "provider" => :provider,
    "workspace" => :string,
    "model" => :string,
    "system_prompt" => :string,
    "max_turns" => :positive_integer,
    "event_limit" => :event_limit,
    "approval_mode" => {:enum, @approval_modes},
    "sandbox_mode" => {:enum, @sandbox_modes},
    "reasoning_effort" => {:enum, @reasoning_efforts}
  }

  # `Ouroboros.Team.Server` accepts exactly these two for a worker.
  @worker_options %{"role" => :string, "node" => :node}

  @delegation_options %{
    "id" => :string,
    "coding_node" => :node,
    "workspace" => :string,
    "provider" => :provider
  }

  @control_options %{"id" => :string, "max_revisions" => :non_negative_integer}

  @type entry :: %{
          :scope => :read | :operate,
          :timeout => pos_integer(),
          optional(:outcome) => :unknown
        }

  @typedoc "Which plane a session id belongs to. The two have separate id spaces."
  @type plane :: :interactive | :coding

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
  cannot ask for more than the process it connected to was started with. This lives beside
  the table that declares the scopes rather than inside the connection that consults it,
  so that adding a verb and deciding what it costs are the same edit.
  """
  @spec permits?(:read | :operate, entry()) :: boolean()
  def permits?(:operate, _entry), do: true
  def permits?(:read, %{scope: scope}), do: scope == :read

  @doc "The numeric code for one named protocol error."
  @spec code(atom()) :: integer()
  def code(name), do: Map.fetch!(@codes, name)

  @doc """
  Validates the parameters of a subscribe call.

  Separate from `invoke/2` because the connection makes this call itself; the validation
  still belongs beside every other parameter rule rather than in the socket handler.
  """
  @spec subscription_params(map()) ::
          {:ok, String.t(), non_neg_integer()} | {:invalid, String.t()}
  def subscription_params(params) do
    with {:ok, id} <- fetch_string(params, "id"),
         {:ok, cursor} <- fetch_cursor(params) do
      {:ok, id, cursor}
    end
  end

  @doc "Validates the one parameter an unsubscribe call carries."
  @spec session_param(map()) :: {:ok, String.t()} | {:invalid, String.t()}
  def session_param(params), do: fetch_string(params, "id")

  @doc """
  Subscribes the **calling process** to a session and returns the backlog after `cursor`.

  Must be called from the process that wants the events: both planes register `self()` and
  monitor it. `Ouroboros.Gateway.Conn` therefore calls this inline instead of dispatching
  it to a task, and accepts that the call is bounded by the plane's own control-plane
  timeout rather than by a gateway ceiling it could enforce on a task it owns.
  """
  @spec subscribe(plane(), String.t(), non_neg_integer()) :: result()
  def subscribe(:interactive, id, cursor) do
    safe(fn -> reply(InteractiveSession.subscribe(id, cursor: cursor)) end)
  end

  def subscribe(:coding, id, cursor) do
    safe(fn -> reply(CodingSession.subscribe(id, cursor: cursor)) end)
  end

  @doc "Stops event delivery to the calling process. Same `self()` rule as `subscribe/3`."
  @spec unsubscribe(plane(), String.t()) :: result()
  def unsubscribe(:interactive, id), do: safe(fn -> reply(InteractiveSession.unsubscribe(id)) end)
  def unsubscribe(:coding, id), do: safe(fn -> reply(CodingSession.unsubscribe(id)) end)

  @doc """
  The session's durable status and whether it is terminal.

  Asked immediately after a successful subscribe, because a terminal session answers a
  backlog and silently declines the registration
  ([interactive/task.ex:100](../lib/ouroboros/interactive/task.ex)). Without this check a
  client would sit forever waiting for live events from a session that had already ended.
  """
  @spec session(plane(), String.t()) :: {:ok, atom(), boolean()} | :error
  def session(:interactive, id) do
    case safe(fn -> InteractiveSession.info(id) end) do
      {:ok, %InteractiveState{} = state} -> {:ok, state.status, InteractiveState.terminal?(state)}
      _other -> :error
    end
  end

  def session(:coding, id) do
    case safe(fn -> CodingSession.info(id) end) do
      {:ok, %TaskState{} = task} -> {:ok, task.status, TaskState.terminal?(task)}
      _other -> :error
    end
  end

  @doc """
  The coordinator process a subscription is registered with, or `nil`.

  A subscription is only as alive as that process: when it retires after a terminal
  session, or crashes and is restarted by its supervisor, the registration is gone and no
  further events arrive. The connection monitors what this returns so it can say so
  instead of leaving a client waiting on a stream that ended.
  """
  @spec coordinator(plane(), String.t()) :: pid() | nil
  def coordinator(:interactive, id), do: InteractiveTask.whereis(id)
  def coordinator(:coding, id), do: CodingTask.whereis(id)

  @doc """
  Runs one method's handler. Called inside a supervised task, never in the connection.
  """
  @spec invoke(String.t(), map()) :: result()
  def invoke(method, params)

  def invoke("runtime.status", _params), do: safe(fn -> {:ok, Ouroboros.status()} end)

  def invoke("runtime.providers", _params), do: safe(fn -> {:ok, providers()} end)

  def invoke("account.read", params) do
    with :ok <- only_keys(params, []) do
      safe(fn -> reply(account_adapter().read()) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("account.login.start", params) do
    with :ok <- only_keys(params, ["flow"]),
         {:ok, flow} <- account_flow(Map.get(params, "flow", "browser")) do
      safe(fn -> reply(account_adapter().login(flow)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("account.login.cancel", params) do
    with :ok <- only_keys(params, ["login_id"]),
         {:ok, login_id} <- fetch_string(params, "login_id") do
      safe(fn -> reply(account_adapter().cancel(login_id)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("account.logout", params) do
    with :ok <- only_keys(params, []) do
      safe(fn -> reply(account_adapter().logout()) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

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

  def invoke("interactive.start", params) do
    safe(fn ->
      case options(params, @start_options) do
        {:ok, opts} -> reply(InteractiveSession.start(opts))
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  def invoke("interactive.send_message", params) do
    with_turn(params, &InteractiveSession.send_message/3)
  end

  def invoke("interactive.follow_up", params) do
    with_turn(params, &InteractiveSession.follow_up/3)
  end

  def invoke("interactive.steer", params) do
    safe(fn ->
      with {:ok, id} <- fetch_string(params, "id"),
           {:ok, input} <- fetch_string(params, "input") do
        reply(InteractiveSession.steer(id, input))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  def invoke("interactive.respond_approval", params) do
    safe(fn ->
      with {:ok, id} <- fetch_string(params, "id"),
           {:ok, request_id} <- fetch_string(params, "request_id"),
           {:ok, response} <- approval_response(params) do
        reply(InteractiveSession.respond_approval(id, request_id, response))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  def invoke("interactive.interrupt", params) do
    safe(fn ->
      with {:ok, id} <- fetch_string(params, "id"),
           {:ok, turn_id} <- fetch_optional_string(params, "turn_id") do
        # `:active` is what the plane calls "whichever turn is running now", and it is
        # the only thing a terminal's Ctrl-C can mean.
        reply(InteractiveSession.interrupt(id, turn_id || :active))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  def invoke("interactive.close", params) do
    with_id(params, fn id -> safe(fn -> reply(InteractiveSession.close(id)) end) end)
  end

  def invoke("interactive.kill", params) do
    with_id(params, fn id -> safe(fn -> reply(InteractiveSession.kill(id)) end) end)
  end

  def invoke("coding.start", params) do
    safe(fn ->
      with {:ok, objective} <- fetch_string(params, "objective"),
           {:ok, opts} <- options(params, @start_options, ["objective"]) do
        reply(CodingSession.start(objective, opts))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  def invoke("coding.cancel", params) do
    with_id(params, fn id -> safe(fn -> reply(CodingSession.cancel(id)) end) end)
  end

  def invoke("teams.add_worker", params) do
    safe(fn ->
      with {:ok, worker_id} <- fetch_string(params, "worker_id"),
           {:ok, opts} <- options(params, @worker_options, ["team_id", "worker_id"]),
           {:ok, team} <- team(params) do
        reply(Team.add_worker(team, worker_id, opts))
      else
        {:invalid, message} -> invalid_params(message)
        {:missing, message} -> not_found(message)
      end
    end)
  end

  def invoke("teams.delegate", params) do
    safe(fn ->
      with {:ok, worker_id} <- fetch_string(params, "worker_id"),
           {:ok, objective} <- fetch_string(params, "objective"),
           {:ok, opts} <-
             options(params, @delegation_options, ["team_id", "worker_id", "objective"]),
           {:ok, team} <- team(params) do
        reply(Team.delegate(team, worker_id, objective, opts))
      else
        {:invalid, message} -> invalid_params(message)
        {:missing, message} -> not_found(message)
      end
    end)
  end

  def invoke("teams.cancel", params) do
    safe(fn ->
      with {:ok, delegation_id} <- fetch_string(params, "delegation_id"),
           {:ok, team} <- team(params) do
        reply(Team.cancel(team, delegation_id))
      else
        {:invalid, message} -> invalid_params(message)
        {:missing, message} -> not_found(message)
      end
    end)
  end

  def invoke("teams.close", params) do
    safe(fn ->
      case team(params) do
        {:ok, team} -> reply(Team.close(team))
        {:invalid, message} -> invalid_params(message)
        {:missing, message} -> not_found(message)
      end
    end)
  end

  def invoke("control.submit", params) do
    safe(fn ->
      with {:ok, objective} <- fetch_string(params, "objective"),
           {:ok, opts} <- options(params, @control_options, ["objective"]) do
        reply(Control.submit(objective, opts))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  def invoke("control.cancel", params) do
    with_id(params, fn id -> safe(fn -> reply(Control.cancel(id)) end) end)
  end

  def invoke("agents.stop", params) do
    with_id(params, fn id -> safe(fn -> reply(Mesh.stop_agent(id)) end) end)
  end

  # Reached only if `table/0` and the clauses above ever drift apart. Answering rather
  # than raising keeps that drift a client-visible error instead of a killed task.
  # `runtime.shutdown` and the four subscription verbs reach the connection instead of
  # this function and never arrive here.
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

  # A turn id supplied by the caller is what makes dispatch idempotent: resending the same
  # `{id, input, turn_id}` after a lost response returns the same turn instead of starting
  # a second one. Passed straight through, because the plane is what owns that guarantee.
  defp with_turn(params, dispatch) do
    safe(fn ->
      with {:ok, id} <- fetch_string(params, "id"),
           {:ok, input} <- fetch_string(params, "input"),
           {:ok, turn_id} <- fetch_optional_string(params, "turn_id") do
        reply(dispatch.(id, input, if(turn_id, do: [id: turn_id], else: [])))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  defp team(params) do
    case fetch_string(params, "team_id") do
      {:ok, team_id} ->
        case Team.whereis(team_id) do
          pid when is_pid(pid) -> {:ok, pid}
          nil -> {:missing, "no team #{inspect(team_id)} is running on this node"}
        end

      {:invalid, message} ->
        {:invalid, message}
    end
  end

  # Every atom an option key can become, in one literal table. A client string that is not
  # a key here never reaches `Keyword`, and nothing in this module converts one.
  @option_keys %{
    "id" => :id,
    "provider" => :provider,
    "workspace" => :workspace,
    "model" => :model,
    "system_prompt" => :system_prompt,
    "max_turns" => :max_turns,
    "event_limit" => :event_limit,
    "approval_mode" => :approval_mode,
    "sandbox_mode" => :sandbox_mode,
    "reasoning_effort" => :reasoning_effort,
    "role" => :role,
    "node" => :node,
    "coding_node" => :coding_node,
    "max_revisions" => :max_revisions
  }

  # An option outside the allowlist is refused rather than dropped. Silently ignoring
  # `sandbox_mode` because it was spelled `sandboxMode` would run the session under a
  # policy the operator did not ask for, which is the failure this refusal exists to
  # prevent. `positional` names the keys that are arguments rather than options.
  defp options(params, allowed, positional \\ []) do
    params
    |> Map.drop(positional)
    |> Enum.reduce_while({:ok, []}, fn {key, value}, {:ok, opts} ->
      case Map.fetch(allowed, key) do
        {:ok, kind} ->
          case option_value(key, kind, value) do
            {:ok, term} -> {:cont, {:ok, [{Map.fetch!(@option_keys, key), term} | opts]}}
            {:invalid, message} -> {:halt, {:invalid, message}}
          end

        :error ->
          {:halt,
           {:invalid,
            "params.#{key} is not an option this gateway passes through; it accepts " <>
              (allowed |> Map.keys() |> Enum.sort() |> Enum.join(", "))}}
      end
    end)
    |> case do
      {:ok, opts} -> {:ok, Enum.reverse(opts)}
      {:invalid, message} -> {:invalid, message}
    end
  end

  defp option_value(key, :string, value) do
    if is_binary(value) and String.trim(value) != "",
      do: {:ok, value},
      else: {:invalid, "params.#{key} must be a nonempty string"}
  end

  defp option_value(key, :positive_integer, value) do
    if is_integer(value) and value > 0,
      do: {:ok, value},
      else: {:invalid, "params.#{key} must be a positive integer"}
  end

  defp option_value(key, :non_negative_integer, value) do
    if is_integer(value) and value >= 0,
      do: {:ok, value},
      else: {:invalid, "params.#{key} must be a non-negative integer"}
  end

  # The plane's own ceiling. A session that retains more than this is refused upstream,
  # and answering that here names the parameter instead of the checkpoint.
  defp option_value(key, :event_limit, value) do
    if is_integer(value) and value > 0 and value <= 100_000,
      do: {:ok, value},
      else: {:invalid, "params.#{key} must be an integer between 1 and 100000"}
  end

  defp option_value(key, {:enum, allowed}, value) do
    with true <- is_binary(value),
         {:ok, term} <- Map.fetch(allowed, value) do
      {:ok, term}
    else
      _refused ->
        {:invalid,
         "params.#{key} must be one of " <>
           (allowed |> Map.keys() |> Enum.sort() |> Enum.join(", "))}
    end
  end

  # Matched against the providers this build actually serves, by string, so an unknown
  # name is a parameter error rather than a new atom or a session that fails at start.
  defp option_value(key, :provider, value) do
    names = Enum.map(Ouroboros.providers(), & &1.provider)

    case Enum.find(names, &(is_binary(value) and Atom.to_string(&1) == value)) do
      nil ->
        {:invalid,
         "params.#{key} must name a provider this node serves: " <>
           (names |> Enum.map(&Atom.to_string/1) |> Enum.sort() |> Enum.join(", "))}

      provider ->
        {:ok, provider}
    end
  end

  # Node names are compared as strings against atoms that already exist. A node this one
  # is not connected to could not be placed on anyway, so refusing here is the same answer
  # the placement check would give, arrived at without minting an atom.
  defp option_value(key, :node, value) do
    case Enum.find([node() | Node.list()], &(is_binary(value) and Atom.to_string(&1) == value)) do
      nil ->
        {:invalid,
         "params.#{key} must name this node or one connected to it: " <>
           ([node() | Node.list()]
            |> Enum.map(&Atom.to_string/1)
            |> Enum.sort()
            |> Enum.join(", "))}

      name ->
        {:ok, name}
    end
  end

  # The upstream schema accepts a bare decision or a map. Both are reconstructed here from
  # literal terms: the plane never sees a value this module did not already contain.
  # `provider_options` is deliberately not accepted — an approval is a yes or a no, and a
  # place to smuggle provider flags through is not what a confirmation dialog should be.
  defp approval_response(params) do
    case Map.get(params, "response") do
      decision when is_binary(decision) ->
        case Map.fetch(@approval_decisions, decision) do
          {:ok, value} -> {:ok, %{decision: value, scope: :once}}
          :error -> {:invalid, approval_message()}
        end

      response when is_map(response) ->
        structured_approval(response)

      _other ->
        {:invalid, approval_message()}
    end
  end

  defp structured_approval(response) do
    unknown = Map.keys(response) -- ["decision", "scope", "reason"]

    with [] <- unknown,
         {:ok, decision} <- Map.fetch(@approval_decisions, Map.get(response, "decision")),
         {:ok, scope} <- Map.fetch(@approval_scopes, Map.get(response, "scope", "once")),
         {:ok, reason} <- fetch_optional_string(response, "reason") do
      approval = %{decision: decision, scope: scope}
      {:ok, if(reason, do: Map.put(approval, :reason, reason), else: approval)}
    else
      _refused -> {:invalid, approval_message()}
    end
  end

  defp approval_message do
    ~s(params.response must be "approve", "deny", or an object ) <>
      ~s({"decision": "approve"|"deny", "scope": "once"|"session", "reason": "..."})
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

  defp only_keys(params, allowed) when is_map(params) do
    case Map.keys(params) -- allowed do
      [] ->
        :ok

      unknown ->
        {:invalid, "params contains unsupported fields: #{Enum.sort(unknown) |> Enum.join(", ")}"}
    end
  end

  defp account_flow("browser"), do: {:ok, :browser}
  defp account_flow("device_code"), do: {:ok, :device_code}

  defp account_flow(_other),
    do: {:invalid, "params.flow must be browser or device_code"}

  defp account_adapter do
    Application.get_env(:ouroboros, :codex_account_adapter, CodexAppServer)
  end

  # An absent optional string is `nil` rather than an error; a present one is held to the
  # same rule as a required one, so `""` is a mistake and not a silent default.
  defp fetch_optional_string(params, key) do
    case Map.get(params, key) do
      nil -> {:ok, nil}
      value when is_binary(value) and value != "" -> {:ok, value}
      _other -> {:invalid, "params.#{key} must be a nonempty string when present"}
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

  # A pruned cursor is the one upstream detail a client acts on rather than displays: it
  # restarts from the floor and marks the transcript as truncated below it. So the floor
  # travels as data under a named reason instead of inside a sentence.
  defp reply({:error, {:cursor_pruned, floor}}) do
    {:error, code(:upstream_error),
     "the session no longer retains events at or below that cursor; replay from #{floor}",
     %{"reason" => "cursor_pruned", "floor" => floor}}
  end

  # Several planes bound themselves and answer `:timeout` rather than exiting. The request
  # may still have been accepted durably — `Ouroboros.Team` says so explicitly — so the
  # answer is the same "the gateway stopped waiting, the runtime did not" that a ceiling
  # breach gets, and it carries the same admission of not knowing.
  defp reply({:error, :timeout}) do
    {:error, code(:upstream_timeout), "the runtime did not answer in time",
     %{"outcome" => "unknown"}}
  end

  defp reply({:error, {:timeout, operation}}),
    do: {:error, code(:upstream_timeout), "Codex app-server timed out during #{operation}"}

  defp reply({:error, {:unavailable, message}}) when is_binary(message), do: unavailable(message)

  defp reply({:error, {:upstream, message}}) when is_binary(message),
    do: upstream_error({:codex_app_server, message})

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
