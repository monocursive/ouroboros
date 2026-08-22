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
  alias Ouroboros.Coding.TaskRef
  alias Ouroboros.Coding.TaskState
  alias Ouroboros.CodingSession
  alias Ouroboros.Cluster
  alias Ouroboros.Control
  alias Ouroboros.Control.Grants
  alias Ouroboros.Gateway.Config, as: GatewayConfig
  alias Ouroboros.Gateway.Wire
  alias Ouroboros.Interactive.State, as: InteractiveState
  alias Ouroboros.Interactive.Ref, as: InteractiveRef
  alias Ouroboros.Interactive.Task, as: InteractiveTask
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Mesh
  alias Ouroboros.Orchestration.Scheduler
  alias Ouroboros.Provider.CodexAppServer
  alias Ouroboros.Runtime.Capabilities
  alias Ouroboros.Team
  alias Ouroboros.Upgrade.NodeExecutor
  alias Ouroboros.Upgrade.Rollout.Registry, as: Rollouts
  alias Ouroboros.Upgrade.Signing.Service, as: SigningService

  @default_timeout 15_000

  # One provider probe shells out to check an installed executable, so the fan-out is
  # bounded well inside the method ceiling: a provider that never answers costs the
  # client a null status for that provider, not a timed-out method.
  @provider_probe_timeout 5_000
  @fleet_query_timeout 5_000

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

  # Preview and admit run the forge build peer (60s default) and, for admit, a rollout.
  # Keep the gateway ceiling above that so a named forge refusal wins over -32005.
  @forge_timeout 120_000

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
    "fleet.status" => %{scope: :read, timeout: @default_timeout},
    "fleet.doctor" => %{scope: :read, timeout: @default_timeout},
    "account.read" => %{scope: :read, timeout: @default_timeout},
    "agents.list" => %{scope: :read, timeout: @default_timeout},
    "agents.state" => %{scope: :read, timeout: @default_timeout},
    "interactive.list" => %{scope: :read, timeout: @default_timeout},
    "interactive.info" => %{scope: :read, timeout: @default_timeout},
    "interactive.replay" => %{scope: :read, timeout: @default_timeout},
    # One event, whole. It is `replay` with a window of one — same plane call, same
    # routing, same ceiling — so the only thing that makes it a separate method is the
    # larger per-leaf byte cap it encodes the answer under.
    "interactive.event_detail" => %{scope: :read, timeout: @default_timeout},
    "interactive.subscribe" => %{scope: :read, timeout: @default_timeout},
    "interactive.unsubscribe" => %{scope: :read, timeout: @default_timeout},
    "coding.list" => %{scope: :read, timeout: @default_timeout},
    "coding.info" => %{scope: :read, timeout: @default_timeout},
    "coding.replay" => %{scope: :read, timeout: @default_timeout},
    "coding.event_detail" => %{scope: :read, timeout: @default_timeout},
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
    # This is intentionally not coupled to invitation cancellation. It is the explicit
    # state-loss boundary that lets an operator retire durable session-owner evidence
    # only after a signed roster tombstone is present and the machine is offline.
    "fleet.forget_session_owner" => %{scope: :operate, timeout: @default_timeout},
    # Session ids are caller-owned and both planes reconcile the same immutable intent.
    # A ceiling can fire after durable creation, so never imply that minting a second id
    # is safe merely because the gateway stopped waiting.
    "interactive.start" => %{scope: :operate, timeout: @start_timeout, outcome: :unknown},
    "account.login.start" => %{scope: :operate, timeout: @default_timeout},
    "account.login.cancel" => %{scope: :operate, timeout: @default_timeout},
    "account.logout" => %{scope: :operate, timeout: @default_timeout},
    # Both calls checkpoint intent before dispatch. A gateway ceiling can therefore fire
    # after the provider accepted the turn, so the client must reconcile the session
    # rather than present the timeout as a refusal or blindly mint another turn id.
    "interactive.send_message" => %{
      scope: :operate,
      timeout: @default_timeout,
      outcome: :unknown
    },
    "interactive.follow_up" => %{
      scope: :operate,
      timeout: @default_timeout,
      outcome: :unknown
    },
    "interactive.steer" => %{scope: :operate, timeout: @default_timeout},
    "interactive.respond_approval" => %{scope: :operate, timeout: @default_timeout},
    "interactive.interrupt" => %{scope: :operate, timeout: @default_timeout},
    "interactive.close" => %{scope: :operate, timeout: @default_timeout},
    "interactive.kill" => %{scope: :operate, timeout: @default_timeout},
    "interactive.delete" => %{scope: :operate, timeout: @default_timeout},
    "coding.start" => %{scope: :operate, timeout: @start_timeout, outcome: :unknown},
    "coding.cancel" => %{scope: :operate, timeout: @default_timeout},
    "coding.delete" => %{scope: :operate, timeout: @default_timeout},
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
    "capabilities.list" => %{scope: :operate, timeout: @default_timeout},
    "capabilities.preview" => %{scope: :operate, timeout: @forge_timeout},
    "capabilities.admit" => %{scope: :operate, timeout: @forge_timeout},
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
    "reasoning_effort" => {:enum, @reasoning_efforts},
    "runtime_exposure" => :boolean,
    "machine" => :node,
    "node" => :node
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
  @spec subscription_params(plane(), map()) ::
          {:ok, InteractiveRef.t() | TaskRef.t(), non_neg_integer()} | {:invalid, String.t()}
  def subscription_params(plane, params) do
    with :ok <- only_keys(params, ["id", "cursor", "node"]),
         {:ok, session} <- session_target(plane, params),
         {:ok, cursor} <- fetch_cursor(params) do
      {:ok, session, cursor}
    end
  end

  @doc "Validates the one parameter an unsubscribe call carries."
  @spec session_param(plane(), map()) ::
          {:ok, InteractiveRef.t() | TaskRef.t()} | {:invalid, String.t()}
  def session_param(plane, params) do
    with :ok <- only_keys(params, ["id", "node"]), do: session_target(plane, params)
  end

  @doc """
  Subscribes the **calling process** to a session and returns the backlog after `cursor`.

  Must be called from the process that wants the events: both planes register `self()` and
  monitor it. `Ouroboros.Gateway.Conn` therefore calls this inline instead of dispatching
  it to a task, and accepts that the call is bounded by the plane's own control-plane
  timeout rather than by a gateway ceiling it could enforce on a task it owns.
  """
  @spec subscribe(plane(), InteractiveRef.t() | TaskRef.t(), non_neg_integer()) :: result()
  def subscribe(:interactive, session, cursor) do
    safe(fn -> reply(InteractiveSession.subscribe(session, cursor: cursor)) end)
  end

  def subscribe(:coding, session, cursor) do
    safe(fn -> reply(CodingSession.subscribe(session, cursor: cursor)) end)
  end

  @doc "Stops event delivery to the calling process. Same `self()` rule as `subscribe/3`."
  @spec unsubscribe(plane(), InteractiveRef.t() | TaskRef.t()) :: result()
  def unsubscribe(:interactive, session),
    do: safe(fn -> reply(InteractiveSession.unsubscribe(session)) end)

  def unsubscribe(:coding, session), do: safe(fn -> reply(CodingSession.unsubscribe(session)) end)

  @doc """
  The session's durable status and whether it is terminal.

  Asked immediately after a successful subscribe, because a terminal session answers a
  backlog and silently declines the registration
  ([interactive/task.ex:100](../lib/ouroboros/interactive/task.ex)). Without this check a
  client would sit forever waiting for live events from a session that had already ended.
  """
  @spec session(plane(), InteractiveRef.t() | TaskRef.t()) :: {:ok, atom(), boolean()} | :error
  def session(:interactive, session) do
    case safe(fn -> InteractiveSession.info(session) end) do
      {:ok, %InteractiveState{} = state} -> {:ok, state.status, InteractiveState.terminal?(state)}
      _other -> :error
    end
  end

  def session(:coding, session) do
    case safe(fn -> CodingSession.info(session) end) do
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
  @spec coordinator(plane(), InteractiveRef.t() | TaskRef.t()) :: pid() | nil
  def coordinator(:interactive, %InteractiveRef{id: id, node: owner}),
    do: coordinator_on(owner, InteractiveTask, id)

  def coordinator(:coding, %TaskRef{id: id, node: owner}),
    do: coordinator_on(owner, CodingTask, id)

  @doc """
  Runs one method's handler. Called inside a supervised task, never in the connection.
  """
  @spec invoke(String.t(), map()) :: result()
  def invoke(method, params)

  def invoke("runtime.status", _params), do: safe(fn -> {:ok, Ouroboros.status()} end)

  def invoke("runtime.providers", _params), do: safe(fn -> {:ok, providers()} end)

  def invoke("fleet.status", _params), do: safe(fn -> {:ok, Cluster.fleet_status()} end)

  def invoke("fleet.doctor", _params), do: safe(fn -> {:ok, Cluster.fleet_doctor()} end)

  def invoke("fleet.forget_session_owner", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["machine", "accept_state_loss"]),
           {:ok, machine} <- fetch_string(params, "machine"),
           true <- Map.get(params, "accept_state_loss") == true do
        machine
        |> Cluster.forget_session_owner()
        |> forget_session_owner_reply()
      else
        false ->
          invalid_params(
            "params.accept_state_loss must be true; forgetting an owner can hide its offline interactive and coding sessions"
          )

        {:invalid, message} ->
          invalid_params(message)
      end
    end)
  end

  def invoke("account.read", params) do
    with :ok <- only_keys(params, []) do
      safe(fn -> account_reply(account_adapter().read()) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("account.login.start", params) do
    with :ok <- only_keys(params, ["flow"]),
         {:ok, flow} <- account_flow(Map.get(params, "flow", "browser")) do
      safe(fn -> account_reply(account_adapter().login(flow)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("account.login.cancel", params) do
    with :ok <- only_keys(params, ["login_id"]),
         {:ok, login_id} <- fetch_string(params, "login_id") do
      safe(fn -> account_reply(account_adapter().cancel(login_id)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("account.logout", params) do
    with :ok <- only_keys(params, []) do
      safe(fn -> account_reply(account_adapter().logout()) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("agents.list", _params), do: safe(fn -> reply(Mesh.list_agents()) end)

  def invoke("agents.state", params) do
    with_id(params, fn id -> safe(fn -> reply(Mesh.state(id)) end) end)
  end

  def invoke("interactive.list", _params),
    do: safe(fn -> fleet_sessions(InteractiveSession) end)

  def invoke("interactive.info", params) do
    with_session(params, :interactive, ["id", "node"], fn session ->
      safe(fn -> reply(InteractiveSession.info(session)) end)
    end)
  end

  def invoke("interactive.replay", params) do
    with_replay(params, :interactive, fn session, opts ->
      InteractiveSession.replay(session, opts)
    end)
  end

  def invoke("interactive.event_detail", params) do
    with_event_detail(params, :interactive, fn session, opts ->
      InteractiveSession.replay(session, opts)
    end)
  end

  def invoke("coding.list", _params), do: safe(fn -> fleet_sessions(CodingSession) end)

  def invoke("coding.info", params) do
    with_session(params, :coding, ["id", "node"], fn session ->
      safe(fn -> reply(CodingSession.info(session)) end)
    end)
  end

  def invoke("coding.replay", params) do
    with_replay(params, :coding, fn session, opts -> CodingSession.replay(session, opts) end)
  end

  def invoke("coding.event_detail", params) do
    with_event_detail(params, :coding, fn session, opts ->
      CodingSession.replay(session, opts)
    end)
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
        {:ok, opts} ->
          {owner, opts} = Keyword.pop(opts, :node, node())
          start_interactive_on(owner, opts)

        {:invalid, message} ->
          invalid_params(message)
      end
    end)
  end

  def invoke("interactive.send_message", params) do
    with_turn(params, :interactive, &InteractiveSession.send_message/3)
  end

  def invoke("interactive.follow_up", params) do
    with_turn(params, :interactive, &InteractiveSession.follow_up/3)
  end

  def invoke("interactive.steer", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["id", "input", "node"]),
           {:ok, session} <- session_target(:interactive, params),
           {:ok, input} <- fetch_turn_input(params) do
        # The interactive plane has no caller-keyed steer idempotency: Harness mints the
        # request id inside its worker, so a lost acknowledgement cannot be replayed and
        # re-sending injects the same text twice. What the plane *does* make durable is
        # the text itself — the coordinator remembers the prompt and enriches the
        # projected `input_accepted(kind=steer)` event, so replay quotes it.
        reply(InteractiveSession.steer(session, input))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  def invoke("interactive.respond_approval", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["id", "request_id", "response", "node"]),
           {:ok, session} <- session_target(:interactive, params),
           {:ok, request_id} <- fetch_string(params, "request_id"),
           {:ok, response} <- approval_response(params) do
        reply(InteractiveSession.respond_approval(session, request_id, response))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  def invoke("interactive.interrupt", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["id", "turn_id", "node"]),
           {:ok, session} <- session_target(:interactive, params),
           {:ok, turn_id} <- fetch_optional_string(params, "turn_id") do
        # `:active` is what the plane calls "whichever turn is running now", and it is
        # the only thing a terminal's Ctrl-C can mean.
        reply(InteractiveSession.interrupt(session, turn_id || :active))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  def invoke("interactive.close", params) do
    with_session(params, :interactive, ["id", "node"], fn session ->
      safe(fn -> reply(InteractiveSession.close(session)) end)
    end)
  end

  def invoke("interactive.kill", params) do
    with_session(params, :interactive, ["id", "node"], fn session ->
      safe(fn -> reply(InteractiveSession.kill(session)) end)
    end)
  end

  def invoke("interactive.delete", params) do
    with_session(params, :interactive, ["id", "node"], fn session ->
      safe(fn -> reply(InteractiveSession.delete(session)) end)
    end)
  end

  def invoke("coding.start", params) do
    safe(fn ->
      with {:ok, objective} <- fetch_string(params, "objective"),
           {:ok, opts} <- options(params, @start_options, ["objective"]) do
        {owner, opts} = Keyword.pop(opts, :node, node())
        start_coding_on(owner, objective, opts)
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  def invoke("coding.cancel", params) do
    with_session(params, :coding, ["id", "node"], fn session ->
      safe(fn -> reply(CodingSession.cancel(session)) end)
    end)
  end

  def invoke("coding.delete", params) do
    with_session(params, :coding, ["id", "node"], fn session ->
      safe(fn -> reply(CodingSession.delete(session)) end)
    end)
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

  def invoke("capabilities.list", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["workspace"]),
           {:ok, workspace} <- fetch_string(params, "workspace") do
        reply(Capabilities.list(workspace))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  def invoke("capabilities.preview", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["workspace", "path"]),
           {:ok, workspace} <- fetch_string(params, "workspace"),
           {:ok, path} <- fetch_string(params, "path") do
        reply(Capabilities.preview(workspace, path))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  def invoke("capabilities.admit", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["workspace", "path", "session_id"]),
           {:ok, workspace} <- fetch_string(params, "workspace"),
           {:ok, path} <- fetch_string(params, "path"),
           {:ok, session_id} <- fetch_optional_string(params, "session_id") do
        opts = if session_id, do: [author: "session:" <> session_id], else: []
        reply(Capabilities.admit(workspace, path, opts))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  # Reached only if `table/0` and the clauses above ever drift apart. Answering rather
  # than raising keeps that drift a client-visible error instead of a killed task.
  # `runtime.shutdown` and the four subscription verbs reach the connection instead of
  # this function and never arrive here.
  def invoke(method, _params) when is_binary(method) do
    {:error, code(:method_not_found), "this build does not serve #{method}"}
  end

  defp start_interactive_on(owner, opts) do
    case destination_workspace(owner, opts) do
      :ok ->
        case Cluster.ensure_placeable(owner) do
          :ok ->
            case fence_possible_owner(:interactive, owner) do
              :ok ->
                owner
                |> InteractiveSession.start_for_gateway_on(opts)
                |> remember_started_owner(:interactive, owner)
                |> start_reply()

              {:error, _reason} ->
                unavailable_not_dispatched(
                  "machine #{owner} start was not dispatched because durable fleet owner evidence could not be checkpointed; repair the Ouroboros data directory and retry"
                )
            end

          {:error, reason} ->
            unavailable_not_dispatched(
              "machine #{owner} cannot run this interactive session: #{placement_reason(reason)}"
            )
        end

      {:error, reason} ->
        invalid_params(destination_workspace_message(owner, reason))
    end
  end

  defp start_coding_on(owner, objective, opts) do
    case destination_workspace(owner, opts) do
      :ok ->
        case Cluster.ensure_placeable(owner) do
          :ok ->
            case fence_possible_owner(:coding, owner) do
              :ok ->
                owner
                |> CodingSession.start_for_gateway_on(objective, opts)
                |> remember_started_owner(:coding, owner)
                |> start_reply()

              {:error, _reason} ->
                unavailable_not_dispatched(
                  "machine #{owner} start was not dispatched because durable fleet owner evidence could not be checkpointed; repair the Ouroboros data directory and retry"
                )
            end

          {:error, reason} ->
            unavailable_not_dispatched(
              "machine #{owner} cannot run this coding task: #{placement_reason(reason)}"
            )
        end

      {:error, reason} ->
        invalid_params(destination_workspace_message(owner, reason))
    end
  end

  # A relative path belongs to the process that expands it. On a selected remote owner
  # that process is a packaged release whose cwd is an implementation detail, not the
  # developer's project. Require the client to name the destination path explicitly;
  # the remote plane remains responsible for checking that the directory exists.
  defp destination_workspace(owner, _opts) when owner == node(), do: :ok

  defp destination_workspace(owner, opts) do
    case Keyword.fetch(opts, :workspace) do
      {:ok, workspace} when is_binary(workspace) ->
        if Path.type(workspace) == :absolute,
          do: :ok,
          else: {:error, {:remote_workspace_not_absolute, owner}}

      :error ->
        {:error, {:remote_workspace_missing, owner}}

      {:ok, _invalid} ->
        {:error, {:remote_workspace_missing, owner}}
    end
  end

  defp destination_workspace_message(owner, {:remote_workspace_missing, owner}) do
    "params.workspace is required when params.machine or params.node selects remote " <>
      "machine #{owner}; provide a nonempty absolute path that exists on that machine"
  end

  defp destination_workspace_message(owner, {:remote_workspace_not_absolute, owner}) do
    "params.workspace must be an absolute path on remote machine #{owner}; relative paths " <>
      "would resolve inside the packaged release rather than the destination project"
  end

  defp placement_reason(:node_not_connected), do: "it is not connected"
  defp placement_reason(:runtime_not_running), do: "its Ouroboros runtime is not running"

  defp placement_reason({:runtime_incompatible, _actual, _expected}),
    do:
      "its Ouroboros version, OTP release, or fleet protocol revision differs from this gateway; " <>
        "install the same Ouroboros build before placing sessions there"

  defp placement_reason({:role, actual, :core}),
    do: "its role is #{actual}; agent sessions require a machine that runs agents"

  defp placement_reason(reason), do: inspect(reason, limit: 10, printable_limit: 200)

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

  # Session checkpoints are owner-local, so a client attached to one gateway has to ask
  # every connected compatible core. A successful array is authoritative in existing
  # clients; it must therefore include every queryable core and fail when an owner proven
  # by an earlier complete list or successful start is no longer queryable. That positive
  # observation matters for transitive peers which were never invitation seeds and for
  # peers whose last-known runtime later became incompatible. Returning [] for either
  # kind of disconnected owner made its sessions disappear even though this gateway had
  # already proved that it owned checkpoints.
  # Fail the read instead: the TUI retains its last-known rows and retries, which is both
  # backward-compatible and honest. A seed with no positive evidence does not freeze an
  # otherwise useful list during an ordinary outage. Sessions created exclusively through
  # another gateway remain owner-local until journals themselves are replicated.
  defp fleet_sessions(module) when module in [InteractiveSession, CodingSession] do
    query_fleet_sessions(module, session_plane(module))
  end

  defp query_fleet_sessions(module, plane) do
    fleet = Cluster.fleet_status()
    targets = fleet_session_targets(fleet)

    case unavailable_session_owner(plane, targets) do
      {:unavailable, target} ->
        incomplete_session_list(target)

      {:error, reason} ->
        incomplete_session_evidence(reason)

      :none ->
        results =
          targets
          |> Task.async_stream(
            &fleet_session_query(&1, module),
            max_concurrency: max(length(targets), 1),
            ordered: true,
            timeout: @fleet_query_timeout,
            on_timeout: :kill_task
          )

        targets
        |> Enum.zip(results)
        |> Enum.reduce_while({:ok, []}, fn
          {target, {:ok, {:ok, sessions}}}, {:ok, observations} ->
            {:cont, {:ok, [{target, sessions} | observations]}}

          {target, _unavailable_or_foreign}, _observations ->
            {:halt, incomplete_session_list(target)}
        end)
        |> case do
          {:ok, observations} ->
            # This synchronous update happens before the successful list escapes. Every
            # queried target participates, so an empty connected owner clears its old
            # evidence while an unavailable required owner can never be cleared by accident.
            case Cluster.record_session_snapshot(plane, observations) do
              :ok ->
                sessions = Enum.flat_map(observations, &elem(&1, 1))

                {:ok,
                 Enum.sort_by(sessions, fn session ->
                   {session |> Map.get(:node, node()) |> Atom.to_string(),
                    Map.get(session, :id, "")}
                 end)}

              {:error, reason} ->
                incomplete_session_evidence(reason)
            end

          error ->
            error
        end
    end
  end

  defp session_plane(InteractiveSession), do: :interactive
  defp session_plane(CodingSession), do: :coding

  # Builders and signers deliberately run no session stores. Asking every distributed
  # node made a healthy mixed-role fleet look incomplete, so only connected, compatible
  # cores participate. Positive evidence still wins: a previously listed owner that is
  # now offline, incompatible, or no longer a core is required and fails closed below.
  defp fleet_session_targets(fleet) do
    fleet.machines
    |> Enum.filter(fn machine ->
      machine.state in [:local, :connected] and machine.role == :core and
        machine.runtime_running? == true and machine.compatibility in [:local, :compatible]
    end)
    |> Enum.map(& &1.node)
    |> Enum.uniq()
  end

  defp unavailable_session_owner(plane, targets) do
    queried = targets |> Enum.map(&Atom.to_string/1) |> MapSet.new()

    case Cluster.session_owners(plane) do
      {:ok, owners} ->
        unavailable =
          owners
          |> Enum.sort()
          |> Enum.find(&(not MapSet.member?(queried, &1)))

        if is_binary(unavailable), do: {:unavailable, unavailable}, else: :none

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp incomplete_session_evidence(_reason) do
    {:error, code(:unavailable),
     "session list is incomplete because durable fleet owner evidence is unavailable; keeping the previous fleet view is safer than hiding its sessions",
     %{
       "reason" => "owner_query_incomplete",
       "node" => "unknown",
       "evidence" => "unavailable"
     }}
  end

  defp incomplete_session_list(target) do
    owner = if(is_atom(target), do: Atom.to_string(target), else: target)

    {:error, code(:unavailable),
     "session list is incomplete because owner #{owner} did not answer; keeping the previous fleet view is safer than hiding its sessions",
     %{"reason" => "owner_query_incomplete", "node" => owner}}
  end

  # `Task.async_stream/3` bounds slow owners. Convert exceptions/exits inside each task
  # into ordinary data as well, so a dead remote Store cannot link-exit the gateway
  # caller while we are trying to report the partial read honestly.
  defp fleet_session_query(target, module) do
    sessions =
      if target == node() do
        apply(module, :list, [])
      else
        :erpc.call(target, module, :list, [], @fleet_query_timeout)
      end

    if is_list(sessions), do: {:ok, sessions}, else: {:error, :invalid_reply}
  rescue
    error -> {:error, {:exception, error}}
  catch
    kind, reason -> {:error, {kind, reason}}
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
  # a second one. `input` keeps accepting the original string shape and additionally accepts
  # the small provider-neutral TurnRequest subset a terminal can honestly construct. Richer
  # provider knobs remain runtime configuration rather than an escape hatch through JSON.
  defp with_turn(params, plane, dispatch) do
    safe(fn ->
      with :ok <- only_keys(params, ["id", "input", "turn_id", "node"]),
           {:ok, session} <- session_target(plane, params),
           {:ok, input} <- fetch_turn_input(params),
           {:ok, turn_id} <- fetch_optional_string(params, "turn_id") do
        reply(dispatch.(session, input, if(turn_id, do: [id: turn_id], else: [])))
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
    "runtime_exposure" => :runtime_exposure,
    "role" => :role,
    "machine" => :node,
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
      {:ok, opts} ->
        opts = Enum.reverse(opts)

        if Keyword.keys(opts) == Enum.uniq(Keyword.keys(opts)) do
          {:ok, opts}
        else
          {:invalid, "params.machine and params.node are aliases; provide only one"}
        end

      {:invalid, message} ->
        {:invalid, message}
    end
  end

  defp option_value(_key, :boolean, value) when is_boolean(value), do: {:ok, value}

  defp option_value(key, :boolean, _value),
    do: {:invalid, "params.#{key} must be a boolean"}

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
    case Cluster.resolve_machine(value) do
      {:error, _reason} ->
        {:invalid,
         "params.#{key} must name a connected machine or BEAM node: " <>
           (Cluster.fleet_status().machines
            |> Enum.filter(&(&1.state in [:local, :connected]))
            |> Enum.flat_map(&[&1.machine, Atom.to_string(&1.node)])
            |> Enum.uniq()
            |> Enum.sort()
            |> Enum.join(", "))}

      {:ok, target} ->
        {:ok, target}
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

  defp with_replay(params, plane, replay) do
    with :ok <- only_keys(params, ["id", "cursor", "limit", "node"]),
         {:ok, session} <- session_target(plane, params),
         {:ok, cursor} <- fetch_cursor(params),
         {:ok, limit} <- fetch_limit(params) do
      safe(fn -> reply(replay.(session, cursor: cursor, limit: limit)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  # `replay` with a window of one. Both planes take an *exclusive* cursor
  # ([interactive/task.ex:1419](../interactive/task.ex)), so the event at `sequence` is the
  # one after `sequence - 1`, and the two refusals a client has to tell apart come out of
  # that call unchanged: below the retained floor the plane answers `{:cursor_pruned,
  # floor}` and the existing `reply/1` clause names the floor, while above the high-water
  # mark it answers an empty window and this answers `-32007`.
  #
  # The `^sequence` match is not decoration. A window of one starting below a gap returns
  # the *next* event that exists, and answering with an event the client did not ask for
  # would be a worse lie than not finding it.
  defp with_event_detail(params, plane, replay) do
    with :ok <- only_keys(params, ["id", "sequence", "node"]),
         {:ok, session} <- session_target(plane, params),
         {:ok, sequence} <- fetch_sequence(params) do
      safe(fn ->
        case replay.(session, cursor: sequence - 1, limit: 1) do
          {:ok, [%{sequence: ^sequence} = event]} -> {:ok, detail(event)}
          {:ok, _window} -> not_found("that session retains no event at sequence #{sequence}")
          other -> reply(other)
        end
      end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  # Encoded here rather than by the `Conn`, because this is the one answer that gets the
  # larger per-leaf cap: the whole point of the method is to hand back the leaf a
  # streamed event could only excerpt. What it returns is already a JSON tree, so the
  # connection's own `Wire.to_json/1` walks plain strings and maps and leaves it alone.
  defp detail(event) do
    limits = GatewayConfig.event_limits()

    Wire.to_json(event,
      event_leaf_bytes: limits.detail_leaf_bytes,
      event_payload_bytes: limits.detail_leaf_bytes
    )
  end

  defp fetch_sequence(params) do
    case Map.get(params, "sequence") do
      sequence when is_integer(sequence) and sequence > 0 -> {:ok, sequence}
      _other -> {:invalid, "params.sequence must be a positive integer"}
    end
  end

  defp with_session(params, plane, allowed, fun) do
    with :ok <- only_keys(params, allowed),
         {:ok, session} <- session_target(plane, params) do
      fun.(session)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  defp session_target(plane, params) do
    with {:ok, id} <- fetch_string(params, "id"),
         {:ok, owner} <- optional_owner(params) do
      owner = owner || node()

      case plane do
        :interactive -> {:ok, InteractiveRef.new(id, owner)}
        :coding -> {:ok, TaskRef.new(id, owner)}
      end
    end
  end

  defp optional_owner(params) do
    case Map.fetch(params, "node") do
      :error ->
        {:ok, nil}

      {:ok, value} when is_binary(value) ->
        case Cluster.resolve_known_machine(value) do
          {:ok, owner} ->
            {:ok, owner}

          {:error, _reason} ->
            {:invalid,
             "params.node must name a known BEAM node: " <>
               (Cluster.fleet_status().machines
                |> Enum.flat_map(&[&1.machine, Atom.to_string(&1.node)])
                |> Enum.uniq()
                |> Enum.sort()
                |> Enum.join(", "))}
        end

      {:ok, _value} ->
        {:invalid, "params.node must name a known BEAM node"}
    end
  end

  defp coordinator_on(owner, module, id) when owner == node(), do: module.whereis(id)

  defp coordinator_on(owner, module, id) do
    if owner in Node.list() do
      :erpc.call(owner, module, :whereis, [id], @default_timeout)
    else
      nil
    end
  catch
    _kind, _reason -> nil
  end

  defp fetch_string(params, key) do
    case Map.get(params, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _other -> {:invalid, "params.#{key} must be a nonempty string"}
    end
  end

  defp fetch_turn_input(params) do
    case Map.get(params, "input") do
      input when is_binary(input) and input != "" ->
        {:ok, input}

      input when is_map(input) ->
        structured_turn_input(input)

      _other ->
        {:invalid,
         "params.input must be a nonempty string or an object containing prompt and optional attachments/reasoning_effort"}
    end
  end

  defp structured_turn_input(input) do
    with :ok <- only_keys(input, ["prompt", "attachments", "reasoning_effort"]),
         {:ok, prompt} <- fetch_string(input, "prompt"),
         {:ok, attachments} <- fetch_optional_string_list(input, "attachments", 32),
         {:ok, reasoning_effort} <-
           fetch_optional_enum(input, "reasoning_effort", @reasoning_efforts) do
      turn = %{prompt: prompt}
      turn = if attachments == [], do: turn, else: Map.put(turn, :attachments, attachments)

      {:ok,
       if(reasoning_effort,
         do: Map.put(turn, :reasoning_effort, reasoning_effort),
         else: turn
       )}
    end
  end

  defp fetch_optional_string_list(params, key, limit) do
    case Map.get(params, key, []) do
      values when is_list(values) and length(values) <= limit ->
        if Enum.all?(values, &(is_binary(&1) and String.trim(&1) != "")),
          do: {:ok, values},
          else: {:invalid, "params.input.#{key} must contain only nonempty strings"}

      _other ->
        {:invalid, "params.input.#{key} must be a list of at most #{limit} nonempty strings"}
    end
  end

  defp fetch_optional_enum(params, key, allowed) do
    case Map.get(params, key) do
      nil ->
        {:ok, nil}

      value when is_binary(value) ->
        case Map.fetch(allowed, value) do
          {:ok, term} ->
            {:ok, term}

          :error ->
            {:invalid,
             "params.input.#{key} must be one of " <>
               (allowed |> Map.keys() |> Enum.sort() |> Enum.join(", "))}
        end

      _other ->
        {:invalid,
         "params.input.#{key} must be one of " <>
           (allowed |> Map.keys() |> Enum.sort() |> Enum.join(", "))}
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

  defp reply({:error, {:session_not_terminal, status}}) do
    {:error, code(:upstream_error),
     "the session is still #{status}; close or kill it before removing the durable record",
     %{"reason" => "session_not_terminal", "status" => to_string(status)}}
  end

  defp reply({:error, {:task_not_terminal, status}}) do
    {:error, code(:upstream_error),
     "the coding task is still #{status}; cancel it before removing the durable record",
     %{"reason" => "task_not_terminal", "status" => to_string(status)}}
  end

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

  defp reply({:error, {:unavailable, message}}) when is_binary(message), do: unavailable(message)

  defp reply({:error, {:owner_unavailable, owner}}) when is_atom(owner) do
    {:error, code(:unavailable), "session owner #{owner} is offline; Ouroboros is reconnecting",
     %{"reason" => "owner_unavailable", "node" => owner, "outcome" => "unknown"}}
  end

  defp reply({:error, {:owner_unavailable, owner, detail}}) when is_atom(owner) do
    {:error, code(:unavailable),
     "session owner #{owner} did not answer; Ouroboros is reconnecting",
     %{
       "reason" => "owner_unavailable",
       "node" => owner,
       "detail" => Wire.to_json(detail),
       "outcome" => "unknown"
     }}
  end

  defp reply({:error, reason}), do: turn_error_reply(reason)
  defp reply(value), do: {:ok, value}

  # Start has a durable boundary the generic `reply/1` cannot infer. Once the exact
  # caller-owned request is checkpointed, readiness failure is still a successful
  # creation outcome: clients must open that stable failed session, not mint another or
  # remain trapped reconciling it. Conflicts are the inverse — this request definitely
  # created nothing, because the id already belongs to different immutable intent.
  # Owner-evidence failure cannot rewrite a created session into `not_dispatched`; the
  # monitor marks its evidence unreliable so subsequent lists fail closed instead.
  defp fence_possible_owner(_plane, owner) when owner == node(), do: :ok

  defp fence_possible_owner(plane, owner) do
    Cluster.record_session_snapshot(plane, [{owner, [%{possible_start: true}]}])
  end

  defp remember_started_owner({:ok, %{node: owner}} = result, plane, owner) do
    _ = Cluster.record_session_snapshot(plane, [{owner, [%{created: true}]}])
    result
  end

  defp remember_started_owner({:created, %{node: owner}, _reason} = result, plane, owner) do
    _ = Cluster.record_session_snapshot(plane, [{owner, [%{created: true}]}])
    result
  end

  defp remember_started_owner(result, _plane, _owner), do: result

  defp start_reply({:created, %{id: id, node: owner}, reason}) do
    {:ok,
     %{
       "id" => id,
       "node" => owner,
       "outcome" => "created",
       "ready" => false,
       "error" => Wire.to_json(reason)
     }}
  end

  defp start_reply({:error, {:session_id_conflict, id} = reason}) do
    {:error, code(:upstream_error),
     "session id #{inspect(id)} already belongs to different immutable start options",
     %{
       "reason" => "session_id_conflict",
       "id" => id,
       "outcome" => "not_dispatched",
       "error" => Wire.to_json(reason)
     }}
  end

  defp start_reply({:error, {:task_id_conflict, id} = reason}) do
    {:error, code(:upstream_error),
     "coding task id #{inspect(id)} already belongs to a different immutable request",
     %{
       "reason" => "task_id_conflict",
       "id" => id,
       "outcome" => "not_dispatched",
       "error" => Wire.to_json(reason)
     }}
  end

  defp start_reply(result), do: reply(result)

  @doc false
  # These are not refusals. Harness may already have returned a turn id, its call may
  # have exited before a trustworthy acknowledgement, or a synchronous refusal may have
  # failed to replace the durable `:dispatching` intent that recovery can still send.
  # In every case the caller-owned id is the reconciliation boundary and retrying under
  # a new id could duplicate live work.
  def turn_error_reply(
        {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn_id} = reason
      )
      when is_binary(turn_id) do
    unknown_turn_dispatch(turn_id, reason)
  end

  def turn_error_reply(
        {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn_id,
         {:harness_refused, _refusal}} = reason
      )
      when is_binary(turn_id) do
    unknown_turn_dispatch(turn_id, reason)
  end

  def turn_error_reply(
        {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn_id,
         {:request_exposure_failed, _failure}} = reason
      )
      when is_binary(turn_id) do
    unknown_turn_dispatch(turn_id, reason)
  end

  def turn_error_reply({:turn_dispatch_ambiguous, turn_id} = reason)
      when is_binary(turn_id) do
    unknown_turn_dispatch(turn_id, reason)
  end

  def turn_error_reply({:turn_dispatch_ambiguous, turn_id, :checkpoint_failed} = reason)
      when is_binary(turn_id) do
    unknown_turn_dispatch(turn_id, reason)
  end

  # Harness accepts `follow_up` while a session is running and queues it, but refuses a
  # second immediate `send_message` as `:busy`. Name that distinction so an interactive
  # client can preserve the draft and switch to the queueing verb instead of showing an
  # opaque upstream failure. Harness answered synchronously, so this input did not cross
  # the dispatch boundary and a retry under a fresh logical id is safe.
  def turn_error_reply({:turn_dispatch_failed, :busy} = reason) do
    {:error, code(:upstream_error),
     "the session is already running a turn; queue this input with interactive.follow_up",
     %{
       "reason" => "busy",
       "outcome" => "not_dispatched",
       "retry_with" => "interactive.follow_up",
       "error" => Wire.to_json(reason)
     }}
  end

  def turn_error_reply(reason),
    do: {:error, code(:upstream_error), "the runtime refused the call", Wire.to_json(reason)}

  defp unknown_turn_dispatch(turn_id, reason) do
    {:error, code(:upstream_timeout),
     "the runtime could not confirm the turn dispatch; the turn may already be running",
     %{
       "outcome" => "unknown",
       "turn_id" => turn_id,
       "error" => Wire.to_json(reason)
     }}
  end

  # The account boundary is the one upstream that names Codex in its errors, and those
  # sentences are only true of it. `{:error, {:timeout, _}}` and `{:error, {:upstream, _}}`
  # are shapes any plane could answer with for its own reasons; mapping them in the shared
  # `reply/1` would tell an operator that Codex timed out during something Codex was never
  # asked to do. So the attribution lives here, with the four methods that actually call it.
  defp account_reply({:error, {:timeout, operation}}),
    do: {:error, code(:upstream_timeout), "Codex app-server timed out during #{operation}"}

  defp account_reply({:error, {:upstream, message}}) when is_binary(message),
    do: upstream_error({:codex_app_server, message})

  # `{:unavailable, message}` already reads as a sentence about whatever was unavailable,
  # and `reply/1` maps it without attributing it to anyone.
  defp account_reply(result), do: reply(result)

  defp forget_session_owner_reply({:ok, result}), do: {:ok, result}

  defp forget_session_owner_reply({:error, {:invalid_session_owner_machine, machine}}) do
    invalid_params(
      "params.machine must be the exact fleet machine name, got: #{inspect(machine)}"
    )
  end

  defp forget_session_owner_reply({:error, {:session_owner_not_tombstoned, machine}}) do
    not_found(
      "fleet profile has no signed roster tombstone for machine #{inspect(machine)}; cancel it and import the updated roster before accepting state loss"
    )
  end

  defp forget_session_owner_reply({:error, {:session_owner_connected, machine, owner}}) do
    {:error, code(:unavailable),
     "machine #{machine} is connected as #{owner}; inspect or copy its sessions instead of forgetting live state",
     %{
       "reason" => "session_owner_connected",
       "machine" => machine,
       "node" => owner
     }}
  end

  defp forget_session_owner_reply({:error, :fleet_profile_unavailable}) do
    unavailable(
      "no active fleet profile is available; this command only retires a member already tombstoned by a signed fleet roster"
    )
  end

  defp forget_session_owner_reply({:error, {:fleet_profile_unavailable, reason}}) do
    {:error, code(:unavailable),
     "the local fleet profile could not be validated; repair or re-import it before forgetting session state",
     %{"reason" => "fleet_profile_unavailable", "error" => Wire.to_json(reason)}}
  end

  defp forget_session_owner_reply({:error, {:session_owner_evidence_unavailable, reason}}) do
    {:error, code(:unavailable),
     "durable session-owner evidence is unavailable; repair it before accepting state loss",
     %{"reason" => "session_owner_evidence_unavailable", "error" => Wire.to_json(reason)}}
  end

  defp forget_session_owner_reply({:error, {:session_owner_forget_checkpoint_failed, reason}}) do
    {:error, code(:upstream_error),
     "session-owner evidence could not be checkpointed, so no state was forgotten",
     %{
       "reason" => "session_owner_forget_checkpoint_failed",
       "error" => Wire.to_json(reason)
     }}
  end

  defp forget_session_owner_reply({:error, reason}), do: upstream_error(reason)

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

  defp unavailable_not_dispatched(message),
    do: {:error, code(:unavailable), message, %{"outcome" => "not_dispatched"}}

  defp not_found(message), do: {:error, code(:not_found), message}
  defp invalid_params(message), do: {:error, code(:invalid_params), message}
end
