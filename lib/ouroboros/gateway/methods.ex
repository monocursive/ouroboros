defmodule Ouroboros.Gateway.Methods do
  @moduledoc """
  The exact set of runtime calls this build exposes, and the bound on each of them.

  ## Dispatch never grows an atom

  `Methods.Contract` maps each method *string* to its scope, ceiling, parameters and
  literal handler atom. `invoke/2` validates that contract before dispatching. A client cannot name a function this
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

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.CodeIntel
  alias Ouroboros.Coding.Task, as: CodingTask
  alias Ouroboros.Coding.TaskRef
  alias Ouroboros.Coding.TaskState
  alias Ouroboros.CodingSession
  alias Ouroboros.Cluster
  alias Ouroboros.Control
  alias Ouroboros.Control.Grants
  alias Ouroboros.Control.Permissions
  alias Ouroboros.Gateway.Methods.Browse
  alias Ouroboros.Gateway.Methods.Contract
  alias Ouroboros.Gateway.Methods.Encode
  alias Ouroboros.Gateway.Methods.Placement
  alias Ouroboros.Gateway.Methods.Present
  alias Ouroboros.Gateway.Methods.Safe
  alias Ouroboros.Gateway.Wire
  alias Ouroboros.Interactive.State, as: InteractiveState
  alias Ouroboros.Interactive.Ref, as: InteractiveRef
  alias Ouroboros.Interactive.Task, as: InteractiveTask
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Mesh
  alias Ouroboros.Orchestration.Scheduler
  alias Ouroboros.Provider.AnthropicKey
  alias Ouroboros.Provider.GrokAuth
  alias Ouroboros.Provider.OpenAIAuth
  alias Ouroboros.Provider.XAIKey
  alias Ouroboros.Provider.Native.Desktop
  alias Ouroboros.Provider.Native.Mcp
  alias Ouroboros.Provider.Native.Replay
  alias Ouroboros.Runtime.Capabilities
  alias Ouroboros.Team
  alias Ouroboros.Upgrade.NodeExecutor
  alias Ouroboros.Upgrade.Rollout.Registry, as: Rollouts
  alias Ouroboros.Upgrade.Signing.Service, as: SigningService
  alias Ouroboros.Wasm.Surface, as: WasmSurface
  alias Ouroboros.Wasm.Artifact, as: WasmArtifact
  alias Ouroboros.Wasm.Capability, as: WasmCapability
  alias Ouroboros.Wasm.Deploy, as: WasmDeploy
  alias Ouroboros.Wasm.Upload, as: WasmUpload
  alias Ouroboros.Wasm.Download, as: WasmDownload

  import Ouroboros.Gateway.Methods.Safe,
    only: [
      safe: 1,
      reply: 1,
      invalid_params: 1,
      not_found: 1,
      unavailable: 1,
      upstream_error: 1,
      account_reply: 1,
      grok_account_reply: 1,
      forget_session_owner_reply: 1,
      fork_reply: 1,
      exit_result: 1
    ]

  @default_timeout Contract.default_timeout()

  # Permissions, MCP, and ledger get share this bound on owner-routed `:erpc`.
  @fleet_query_timeout 5_000

  # W13. `agents.message` waits on an agent, and for a lane-W capability that agent is
  # waiting on a component under its own deadline. The caller's `timeout_ms` is capped at
  # `@max_agent_message_timeout_ms` and this ceiling sits above it, so the gateway is never
  # the thing that gives up first: a client that asked for thirty seconds and got a
  # gateway timeout at fifteen would have no way to tell a slow capability from a wedged
  # one.

  @default_agent_message_timeout_ms Contract.default_agent_message_timeout_ms()
  @max_agent_message_timeout_ms Contract.max_agent_message_timeout_ms()

  # What may cross into an agent, and what may come back. Both are the same number because
  # both are a message body — one written by a gateway client, one written by whatever the
  # agent is. The reply is additionally *marked* when it is cut, because a JSON document
  # that was silently truncated is a JSON document a client will try to parse.
  @max_agent_message_bytes Contract.max_agent_message_bytes()

  # A mesh agent id. Long enough for the `"wasm/" <> name` a rollout mints and for the
  # opaque ids the forge does, short enough that a refused lookup costs nothing.
  @max_agent_id_bytes Contract.max_agent_id_bytes()

  # The id prefix a lane-W capability runs under. `Ouroboros.Wasm.Rollout` mints it; it is
  # restated here rather than imported because this module must not depend on the wasm plane
  # to answer a verb about the mesh, and it is one short literal.
  @wasm_agent_prefix "wasm/"

  # E2/E3. Code intelligence is the one read whose upstream is a foreign OS process, and
  # its own defaults are generous on purpose: `initialize_timeout_ms` is 45s because
  # ElixirLS and jdtls compile the world on first launch. A gateway method cannot wait
  # that long, so these three numbers replace the pool's defaults on every gateway call
  # and are chosen to sum below the 15s ceiling — a cold server is answered "not ready
  # yet", which is an honest answer a caller can retry, rather than a killed task.
  @code_intel_wait_ready_ms 5_000
  @code_intel_request_timeout_ms 8_000
  @code_intel_max_wait_ms Contract.code_intel_max_wait_ms()
  @code_intel_erpc_timeout 14_000

  # Kept below the method ceiling on purpose. An `:erpc` that outlives the gateway task
  # would be reported as `-32005 upstream_timeout` with no detail; letting `:erpc` decide
  # first produces the honest answer, which is that the signing node did not respond.
  @signing_erpc_timeout 10_000

  # W12. Lane W's four operator verbs, each bounded by the work it actually does rather
  # than by one number covering all of them.
  #
  # `wasm.upload` writes at most half a mebibyte to a local file: it is a `@default_timeout`
  # verb wearing its own name so the number is not silently inherited.
  #
  # `wasm.sign` may inspect the component with this node's helper (a compile-free read, but
  # a helper that has to be spawned first) and then wait on a signing service that bounds
  # itself at `:signing_call_timeout` — fifteen seconds by default — on another host.
  #
  # `wasm.deploy` runs a whole rollout: stage (60s per node), probe, evaluate (30s), and a
  # durable start (15s), gate after gate. Its ceiling is above the sum on purpose, the way
  # `@forge_timeout` is: a rollout that settles `:quarantined` is a named answer an operator
  # can act on, and a gateway ceiling firing first would replace it with `-32005` and no
  # detail about which node did not report.
  # W19. `wasm.download` reads at most half a mebibyte out of a node-local file: it is
  # `wasm.upload`'s own ceiling, in the other direction, for the same work.
  @wasm_download_timeout Contract.wasm_download_timeout()

  @wasm_upload_timeout Contract.wasm_upload_timeout()
  @wasm_sign_timeout Contract.wasm_sign_timeout()
  @wasm_deploy_timeout Contract.wasm_deploy_timeout()
  @wasm_rollback_timeout Contract.wasm_rollback_timeout()

  # Below each ceiling above, so the plane's own typed refusal wins the race against a
  # transport deadline that says nothing about why.
  @wasm_erpc_slack 5_000

  @replay_limit Contract.replay_limit()
  @default_replay_limit Contract.default_replay_limit()

  # `InteractiveSession.start/1` waits `:infinity` for provider readiness by design — a
  # provider that has to be installed, authenticated, or woken up legitimately takes
  # minutes on a first run. The gateway still refuses to hold a request open forever, so
  # this is the one ceiling measured in provider time rather than in control-plane time.

  # `interactive.request_approval` waits for a person. Fifteen minutes is the stated
  # ceiling: long enough that stepping away from the terminal is not a denial, short
  # enough that a forgotten prompt does not hold a gateway task open for a shift.

  # G1. One `interactive.delegate` may make two team calls, each bounded at 60s by
  # `Team.control_call/2`, plus the parent's own checkpoint. Below the sum on purpose: a
  # delegation that has taken this long has a team that is not answering, and the caller
  # learns which from `teams.state` rather than by waiting out both bounds.

  # B7. One operator command, and the same number `Ouroboros.Workspace.Exec` stops it at.
  # A ceiling below the runner's would kill the gateway task while the command kept
  # running, and the entry it started would be settled by nobody.

  # D9. A compaction that has to summarise makes one model call on the session's own
  # model with no tools. That is provider latency, not control-plane latency, so it gets
  # a ceiling of its own — well above the default and well below a start's.

  # Preview and admit run the forge build peer (60s default) and, for admit, a rollout.
  # Keep the gateway ceiling above that so a named forge refusal wins over -32005.

  # R2. Verified replay re-derives a whole session: one `Loop.run_turn/2` per recorded turn,
  # each rebuilding the cached prefix from the workspace (instruction files, the tool
  # schemas) and re-digesting the conversation. There is no provider latency in any of it —
  # the model is a recording — so the cost is local CPU and local reads, and it scales with
  # how long the session was. Two minutes is chosen the way `@compaction_timeout` is: well
  # above what any session an operator would ask about takes, and well below a ceiling that
  # would let one call hold a gateway task for a shift. A session too long to verify inside
  # it is a real answer — that session needs an offline verifier, not a longer socket.

  # `Team.add_worker/3` and `delegate/4` bound themselves at 60s; `cancel/2` and `close/1`
  # call at `:infinity`. Both land here as 60s, and for the two `:infinity` verbs the
  # timeout answer says what it can honestly say: the gateway stopped waiting, the runtime
  # did not stop working, and `teams.state` is where the outcome shows up.

  # `hello`'s entry does not describe a task ceiling — the handshake is answered by the
  # connection itself and never runs in a task. It describes the deadline by which the
  # handshake must have completed, and `Ouroboros.Gateway.Conn` reads it from here so
  # that the number a client is told about and the number enforced cannot drift apart.

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

  # The exact terms the upstream schemas declare, spelled out here so that a client string
  # is matched against them rather than converted into one. `Jido.Harness.RunRequest`
  # names the first three; `Jido.Harness.ApprovalResponse` names the last two.

  @reasoning_efforts Contract.reasoning_efforts()

  # W12. The whole of a probe, named here so the refusal can list them rather than say only
  # which key was wrong.
  @probe_keys ["input", "expect"]

  @approval_decisions Contract.approval_decisions()
  @approval_scopes Contract.approval_scopes()
  # The one shape of `provider_options` an answer may carry: a plan-exit question's
  # explicit choice and the follow-up prompt that runs once the session is out of plan
  # mode (B2). Anything else under that key is still refused — an approval is a yes or a
  # no, and this is the narrowest door a plan-aware client needs.
  @plan_exit_choices Contract.plan_exit_choices()
  @max_follow_up_bytes 32 * 1024

  # The permission engine's own vocabulary, spelled out for the same reason as the rest:
  # a client string is matched against these terms, never converted into one.
  @permission_scopes Contract.permission_scopes()

  # What `permissions.add` may write. `:node` is operator configuration, read from
  # `config :ouroboros, :permissions` and never authored over the wire. `:session` is a
  # session's own "don't ask again" — it is written by answering an approval, and giving
  # an operator a verb to mint one for a session they are not in would be a different
  # thing wearing the same name.
  @permission_rule_scopes Contract.permission_rule_scopes()

  # Removal reaches one scope further, because cleaning up after a session that remembered
  # something is a real operator need.
  @permission_removable_scopes Contract.permission_removable_scopes()

  @permission_decisions Contract.permission_decisions()

  # What a client may set when it starts a session or a coding run. Everything here is
  # durable, provider-neutral execution intent. Deliberately absent: `env`, `mcp_config`,
  # and `provider_options` — the durable checkpoint refuses inline environment and MCP
  # configuration outright ([coding/task_state.ex]), and provider knobs are node
  # configuration rather than something a terminal hands over per run.
  @start_options Contract.start_options()

  # What `interactive.configure` may name on an *open* session. A strict subset of
  # `@start_options`: everything else there is immutable start intent, and a session that
  # could have its workspace or its event limit moved underneath it would no longer be
  # the session its id promised. Whether any one of these four is actually changeable is
  # the transport's answer, asked per session rather than encoded here.
  #
  # C4. `mode` is the sixth, and it is not a member of any vocabulary this gateway knows:
  # it carries the *agent's own* mode id, which an ACP agent published in `session/new`
  # and which `Ouroboros.Provider.Session.Dialect.ACP` validates against that list before
  # sending `session/set_mode`. A `:string` here rather than an enum is the honest type —
  # the allowed values belong to the agent, not to this table — and every transport whose
  # dialect declares no modes refuses it by name.
  @configuration_options Contract.configuration_options()

  # `Ouroboros.Team.Server` accepts exactly these two for a worker.
  @worker_options Contract.worker_options()

  @delegation_options Contract.delegation_options()

  # What `interactive.delegate` may name. A strict subset of `@delegation_options`:
  # `coding_node` is absent because the child runs where the conversation does, and the
  # delegation's own `id` is a positional argument rather than an option.
  @interactive_delegation_options Contract.interactive_delegation_options()

  @control_options Contract.control_options()

  # ---------------------------------------------------------------------------------
  # H3. The parameter contract, as data.
  #
  # `@table` says what a method costs and what scope it needs; this says what it *takes*.
  # It exists so that `docs/PROTOCOL.md` is generated from this module rather than written
  # beside it — a reference kept in step by hand is a reference that is wrong within a
  # release.
  #
  # Two things keep it from becoming prose:
  #
  #   * Where the validator already holds its rules as data — the `options/3` allowlists
  #     above — the entries are *derived* from that data rather than restated, so a kind
  #     or an enum member cannot drift from what `option_value/3` matches on.
  #   * Everything else is checked by `Ouroboros.Gateway.ProtocolDocsTest`, which parses
  #     this file and asserts that each method's key set here is exactly the allowlist its
  #     `invoke/2` clause enforces — through `only_keys/2`, `options/3`, or a shared
  #     `with_*` helper — and that a key `fetch_string/2` demands is marked required while
  #     one `fetch_optional_*` accepts is marked optional.
  #
  # `:closed` means an unknown key is `-32602` naming it. `:open` means the clause reads
  # what it needs and ignores the rest — stated rather than smoothed over, because the
  # difference is exactly what a client discovers by sending a typo.
  #
  # A descriptor is `{name, requirement, type, note}`. `requirement` is `:required`,
  # `:optional`, or `{:optional, default}` where the *gateway* supplies the default.
  # `type` is the term the validator matches on; the two `{:enum_mfa, …}`/`{:limits, …}`
  # forms name a function this build answers from, so a doc built here cannot state a
  # narrower vocabulary than the runtime accepts. `note` is `nil` or one sentence.
  # ---------------------------------------------------------------------------------

  # The routing pair every plane verb carries: which session, and which machine owns it.

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
  def table, do: Contract.table()

  @doc """
  The state fields a signed eval spec's `state_matches` check may name.

  Read from `Ouroboros.Wasm.Capability`'s own schema rather than restated, so the closed
  set cannot drift from the agent it describes. Public because the test that pins the set
  must assert against the agent and not against a copy in this module.
  """
  @spec wasm_state_fields() :: [atom()]
  def wasm_state_fields, do: WasmCapability.new().state |> Map.keys()

  @doc "Every method name this build serves, as reported in the `hello` result."
  @spec names() :: [String.t()]
  def names, do: table() |> Map.keys() |> Enum.sort()

  @doc "Looks up one method without ever converting the name to an atom."
  @spec fetch(String.t()) :: {:ok, entry()} | :error
  def fetch(name) when is_binary(name), do: Map.fetch(table(), name)

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

  @doc "Every named protocol error and its numeric code."
  @spec codes() :: %{atom() => integer()}
  def codes, do: @codes

  @doc """
  The parameter contract of every method, normalised.

  Each entry is `%{envelope: :closed | :open, params: [descriptor], note: String.t() | nil}`
  where a descriptor is `%{name:, requirement:, type:, note:}`. `:closed` means an unknown
  key is refused with `-32602` naming it; `:open` means the handler reads what it needs and
  ignores the rest.

  Public because `mix ouroboros.protocol.docs` generates `docs/PROTOCOL.md` from it, and
  `Ouroboros.Gateway.ProtocolDocsTest` proves it still agrees with the validators in this
  file. A reference written beside the code rather than out of it is a reference that goes
  wrong quietly; this is the seam that makes the drift loud.
  """
  @spec params() :: %{String.t() => map()}
  defdelegate params(), to: Contract
  defdelegate params(method), to: Contract

  @doc """
  Validates the parameters of a subscribe call.

  Separate from `invoke/2` because the connection makes this call itself; the validation
  still belongs beside every other parameter rule rather than in the socket handler.
  """
  @spec subscription_params(plane(), map()) ::
          {:ok, InteractiveRef.t() | TaskRef.t(), non_neg_integer()} | {:invalid, String.t()}
  def subscription_params(plane, params) do
    with :ok <- Contract.validate("#{plane}.subscribe", params),
         {:ok, session} <- session_target(plane, params),
         {:ok, cursor} <- fetch_cursor(params) do
      {:ok, session, cursor}
    end
  end

  @doc "Validates the one parameter an unsubscribe call carries."
  @spec session_param(plane(), map()) ::
          {:ok, InteractiveRef.t() | TaskRef.t()} | {:invalid, String.t()}
  def session_param(plane, params) do
    with :ok <- Contract.validate("#{plane}.unsubscribe", params),
         do: session_target(plane, params)
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
  def invoke(method, params) do
    case Contract.handler(method) do
      {:ok, handler} when handler != :connection ->
        case Contract.validate(method, params) do
          :ok -> apply(__MODULE__, handler, [params])
          {:invalid, message} -> invalid_params(message)
        end

      _ ->
        {:error, code(:method_not_found), "unknown method #{inspect(method)}"}
    end
  end

  @doc false
  def handle_runtime_status(_params) do
    safe(fn -> {:ok, Ouroboros.status()} end)
  end

  @doc false
  def handle_runtime_providers(_params) do
    safe(fn -> {:ok, Present.providers()} end)
  end

  @doc false
  def handle_runtime_models(_params) do
    safe(fn -> {:ok, Ouroboros.Models.list()} end)
  end

  @doc false
  def handle_fleet_status(_params) do
    safe(fn -> {:ok, Cluster.fleet_status()} end)
  end

  @doc false
  def handle_fleet_doctor(_params) do
    safe(fn -> {:ok, Cluster.fleet_doctor()} end)
  end

  @doc false
  def handle_fleet_revoke(params) do
    with {:ok, artifact} <- fetch_string(params, "artifact"),
         true <- byte_size(artifact) <= 16384 do
      safe(fn -> Cluster.Revocations.distribute(artifact) end)
    else
      {:invalid, message} -> invalid_params(message)
      _ -> invalid_params("artifact must be a signed revocation of at most 16 KiB")
    end
  end

  @doc false
  def handle_fleet_forget_session_owner(params) do
    safe(fn ->
      with {:ok, machine} <- fetch_string(params, "machine"),
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

  @doc false
  def handle_account_read(_params) do
    safe(fn -> account_reply(account_adapter().read()) end)
  end

  @doc false
  def handle_account_login_start(params) do
    with {:ok, flow} <- account_flow(Map.get(params, "flow", "browser")) do
      safe(fn -> account_reply(account_adapter().login(flow)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_account_login_complete(params) do
    with {:ok, login_id} <- fetch_string(params, "login_id"),
         {:ok, code} <- fetch_string(params, "code"),
         {:ok, state} <- fetch_string(params, "state") do
      safe(fn -> account_reply(account_adapter().complete(login_id, code, state)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_account_login_cancel(params) do
    with {:ok, login_id} <- fetch_string(params, "login_id") do
      safe(fn -> account_reply(account_adapter().cancel(login_id)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_account_logout(_params) do
    safe(fn -> account_reply(account_adapter().logout()) end)
  end

  @doc false
  def handle_grok_account_read(_params) do
    safe(fn -> grok_account_reply(grok_account_adapter().read()) end)
  end

  @doc false
  def handle_grok_account_login_start(_params) do
    safe(fn -> grok_account_reply(grok_account_adapter().login()) end)
  end

  @doc false
  def handle_grok_account_login_cancel(params) do
    with {:ok, login_id} <- fetch_string(params, "login_id") do
      safe(fn -> grok_account_reply(grok_account_adapter().cancel(login_id)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_credentials_anthropic_set(params) do
    with {:ok, api_key} <- fetch_optional_api_key(params, "api_key"),
         {:ok, workspace_id} <- fetch_optional_workspace_id(params, "workspace_id"),
         :ok <- require_anthropic_update(api_key, workspace_id) do
      safe(fn -> reply(anthropic_key_adapter().configure(api_key, workspace_id)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_credentials_xai_set(params) do
    with {:ok, api_key} <- fetch_api_key(params, "api_key") do
      safe(fn -> reply(xai_key_adapter().put(api_key)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_agents_list(_params) do
    safe(fn -> reply(Mesh.list_agents()) end)
  end

  # W13/F4. `agents.state` is `:read` and hands back an agent's whole state. For a lane-W
  # capability that state holds `last_answer` and `last_message` — a component's own prose,
  # unbounded, through the one verb a read-only listener may call. So for a `wasm/` agent
  # the two fields are bounded exactly as `agents.message`'s reply is and the answer carries
  # `untrusted: true` beside them, which is the same label its sibling verb carries and for
  # the same reason. Every other agent is answered unchanged: this is a statement about who
  # wrote the content, not a general cap on introspection.
  @doc false
  def handle_agents_state(params) do
    with_id(params, fn id -> safe(fn -> reply(bounded_agent_state(id, Mesh.state(id))) end) end)
  end

  @doc false
  def handle_interactive_list(_params) do
    safe(fn -> Present.fleet_sessions(InteractiveSession) end)
  end

  @doc false
  def handle_interactive_info(params) do
    with_session(params, :interactive, fn session ->
      safe(fn -> reply(InteractiveSession.info(session)) end)
    end)
  end

  @doc false
  def handle_interactive_replay(params) do
    with_replay(params, :interactive, fn session, opts ->
      InteractiveSession.replay(session, opts)
    end)
  end

  @doc false
  def handle_interactive_event_detail(params) do
    with_event_detail(params, :interactive, fn session, opts ->
      InteractiveSession.replay(session, opts)
    end)
  end

  @doc false
  def handle_interactive_journal(params) do
    with {:ok, session} <- session_target(:interactive, params),
         {:ok, since} <- fetch_since_seq(params),
         {:ok, limit} <- fetch_limit(params) do
      safe(fn ->
        reply(InteractiveSession.journal(session, since_seq: since, limit: limit))
      end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  # R2. The verdict is shaped here rather than in the engine, because the engine's own
  # vocabulary is tuples — `{:replay_diverged, …}` and `{:replay_boundary, reason, seq}` —
  # and a wire that flattened both into a string would make a client guess which it had.
  @doc false
  def handle_interactive_replay_verify(params) do
    with_session(params, :interactive, fn session ->
      safe(fn ->
        case InteractiveSession.replay_verify(session) do
          {:ok, verdict} -> {:ok, replay_verdict(verdict)}
          other -> reply(other)
        end
      end)
    end)
  end

  @doc false
  def handle_coding_list(_params) do
    safe(fn -> Present.fleet_sessions(CodingSession) end)
  end

  @doc false
  def handle_coding_info(params) do
    with_session(params, :coding, fn session ->
      safe(fn -> reply(CodingSession.info(session)) end)
    end)
  end

  @doc false
  def handle_coding_replay(params) do
    with_replay(params, :coding, fn session, opts -> CodingSession.replay(session, opts) end)
  end

  @doc false
  def handle_coding_event_detail(params) do
    with_event_detail(params, :coding, fn session, opts ->
      CodingSession.replay(session, opts)
    end)
  end

  @doc false
  def handle_teams_list(_params) do
    safe(fn -> {:ok, Present.teams()} end)
  end

  @doc false
  def handle_teams_state(params) do
    with_id(params, fn id ->
      case Team.whereis(id) do
        pid when is_pid(pid) -> safe(fn -> reply(Team.state(pid)) end)
        nil -> not_found("no team #{inspect(id)} is running on this node")
      end
    end)
  end

  @doc false
  def handle_plans_list(_params) do
    safe(fn -> reply(Scheduler.list(Scheduler)) end)
  end

  @doc false
  def handle_plans_get(params) do
    with_id(params, fn id -> safe(fn -> reply(Scheduler.get(Scheduler, id)) end) end)
  end

  @doc false
  def handle_control_list(_params) do
    safe(fn -> reply(Control.list()) end)
  end

  @doc false
  def handle_control_get(params) do
    with_id(params, fn id -> safe(fn -> reply(Control.get(id)) end) end)
  end

  @doc false
  def handle_upgrade_status(_params) do
    safe(fn -> {:ok, NodeExecutor.status()} end)
  end

  @doc false
  def handle_upgrade_rollouts(_params) do
    safe(fn -> reply(Rollouts.list()) end)
  end

  @doc false
  def handle_upgrade_history(params) do
    with {:ok, name} <- fetch_string(params, "module"),
         {:ok, module} <- resolve_module(name) do
      safe(fn -> reply(Rollouts.history(module)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_signing_decisions(_params) do
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

  @doc false
  def handle_grants_list(params) do
    with {:ok, principal} <- fetch_string(params, "principal") do
      if is_pid(Process.whereis(Grants)) do
        safe(fn -> reply(Grants.list(principal)) end)
      else
        unavailable("the effect grant authority is not running on this node")
      end
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_permissions_list(params) do
    with {:ok, scope} <- permission_scope(params, "scope", @permission_scopes, :optional),
         {:ok, workspace} <- fetch_optional_string(params, "workspace"),
         {:ok, target} <- permissions_node(params) do
      permissions_call(target, :list, [[scope: scope, workspace: workspace]])
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  # A rule written here decides tool calls with no human present, which is exactly why it
  # is an `operate` verb and why the pattern is validated by the engine rather than here:
  # `Ouroboros.Control.Permissions.Pattern` is the only definition of the language, and a
  # second, laxer one at the edge would be a way past the first.
  @doc false
  def handle_permissions_add(params) do
    with {:ok, scope} <- permission_scope(params, "scope", @permission_rule_scopes, :required),
         {:ok, decision} <- permission_scope(params, "decision", @permission_decisions, :required),
         {:ok, pattern} <- fetch_string(params, "pattern"),
         {:ok, workspace} <- fetch_optional_string(params, "workspace"),
         {:ok, target} <- permissions_node(params) do
      rule = %{scope: scope, decision: decision, pattern: pattern, workspace: workspace}
      permissions_call(target, :add, [rule])
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_permissions_remove(params) do
    with {:ok, scope} <-
           permission_scope(params, "scope", @permission_removable_scopes, :required),
         {:ok, id} <- fetch_string(params, "id"),
         {:ok, target} <- permissions_node(params) do
      permissions_call(target, :remove, [scope, id])
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  # ---------------------------------------------------------------------------
  # D4 — MCP servers on the wire
  # ---------------------------------------------------------------------------

  # `workspace` is optional and narrows nothing on the running servers: it adds the ones
  # this node has *configured* for that workspace but has not started, together with the
  # entries it refused and why, which is the only way an operator can tell "my mcp.json
  # was ignored" from "my mcp.json was read and rejected".
  @doc false
  def handle_mcp_list(params) do
    with {:ok, workspace} <- fetch_optional_string(params, "workspace"),
         {:ok, target} <- permissions_node(params) do
      mcp_call(target, workspaces: List.wrap(workspace))
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_computer_use_status(params) do
    with {:ok, target} <- permissions_node(params) do
      safe(fn ->
        if target == node() do
          {:ok, Desktop.status()}
        else
          {:ok, :erpc.call(target, Desktop, :status, [], @fleet_query_timeout)}
        end
      end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_computer_use_probe(params) do
    with {:ok, target} <- permissions_node(params) do
      safe(fn ->
        if target == node() do
          {:ok, Desktop.probe()}
        else
          {:ok, :erpc.call(target, Desktop, :probe, [], @fleet_query_timeout)}
        end
      end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_computer_use_artifact(params) do
    with {:ok, sha} <- fetch_string(params, "sha256"),
         {:ok, session_id} <- fetch_optional_string(params, "session_id"),
         {:ok, target} <- permissions_node(params) do
      safe(fn ->
        if target == node() do
          reply(Desktop.artifact(sha, session_id))
        else
          reply(:erpc.call(target, Desktop, :artifact, [sha, session_id], @fleet_query_timeout))
        end
      end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  # ---------------------------------------------------------------------------
  # W5 — lane W on the wire
  #
  # Both start nothing: `Surface` reads a pool process that already exists rather than
  # asking for one, so `ouro wasm doctor` against a node that has never built the helper is
  # a report and not a spawn. The remote branch is the `computer_use.status` one — a
  # bounded `:erpc` to the machine whose helper is being described, so an unreachable node
  # reads as unreachable instead of as a gateway ceiling with no detail.
  # ---------------------------------------------------------------------------

  @doc false
  def handle_wasm_status(params) do
    wasm_call(params, :status)
  end

  @doc false
  def handle_wasm_list(params) do
    wasm_call(params, :list)
  end

  # ---------------------------------------------------------------------------
  # W12 — signing and deploy on the wire
  #
  # Three verbs and the transport underneath them. What makes them safe is not this
  # module: it is that the bytes carry a signature the **target** checks against its own
  # `upgrade_trust_policy` before the store, the helper or the rollout register sees them
  # (docs/WASM.md D15). This end validates shapes, bounds what it decodes, converts no
  # client byte into an atom it did not already hold, and routes.
  #
  # `wasm.upload` is the only one that takes bytes, because a component is bounded at
  # sixteen mebibytes and a frame at one (D16). It writes to a node-local file under the
  # data directory, and every bound on it — the chunk, the total, how many may be in
  # flight, how long an abandoned one lives — is in `Ouroboros.Wasm.Upload`.
  # ---------------------------------------------------------------------------

  @doc false
  def handle_wasm_upload(params) do
    with {:ok, upload} <- wasm_optional_upload(params),
         {:ok, offset} <- option_value("offset", :non_negative_integer, Map.get(params, "offset")),
         {:ok, chunk} <- wasm_chunk(params),
         {:ok, final?} <- wasm_flag(params, "final"),
         {:ok, target} <- permissions_node(params) do
      wasm_node_call(
        target,
        WasmUpload,
        :append,
        [upload, offset, chunk, final?, []],
        @wasm_upload_timeout - @wasm_erpc_slack
      )
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_wasm_sign(params) do
    with {:ok, upload} <- wasm_upload(params),
         {:ok, name} <- wasm_name(params),
         {:ok, author} <- fetch_string(params, "author"),
         {:ok, imports} <- wasm_imports(params),
         {:ok, kind} <- wasm_kind(params),
         {:ok, precompile} <- wasm_precompile(params),
         {:ok, language} <- fetch_optional_string(params, "language"),
         {:ok, source_sha256} <- wasm_optional_sha256(params),
         {:ok, start_config} <- wasm_start_config(params),
         {:ok, eval} <- wasm_eval(params, kind),
         {:ok, target} <- permissions_node(params) do
      attrs =
        %{
          upload: upload,
          name: name,
          author: author,
          imports: imports,
          kind: kind,
          precompile: precompile
        }
        |> wasm_put(:language, language)
        |> wasm_put(:source_sha256, source_sha256)
        |> wasm_put(:start_config, start_config)
        |> wasm_put(:eval, eval)

      wasm_node_call(
        target,
        WasmDeploy,
        :sign,
        [attrs, []],
        @wasm_sign_timeout - @wasm_erpc_slack
      )
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_wasm_deploy(params) do
    with {:ok, upload} <- wasm_upload(params),
         {:ok, target} <- permissions_node(params),
         {:ok, nodes} <- wasm_targets(params, target) do
      wasm_node_call(
        target,
        WasmDeploy,
        :deploy,
        [upload, nodes, []],
        @wasm_deploy_timeout - @wasm_erpc_slack
      )
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_wasm_rollback(params) do
    with {:ok, name} <- wasm_name(params),
         {:ok, target} <- permissions_node(params) do
      wasm_node_call(
        target,
        WasmDeploy,
        :rollback,
        [name, []],
        @wasm_rollback_timeout - @wasm_erpc_slack
      )
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  # ---------------------------------------------------------------------------
  # W19 — the artifact comes back in the frames the upload used
  #
  # `wasm.upload` cuts a component into frames on the way in; this cuts an artifact into the
  # same frames on the way out, because since W8 the bundle carries a second section the
  # client has never seen and one reply is not a file transfer (D28). What makes it safe is
  # not this module either: a node hands out only what its own `sign/2` compiled and signed,
  # from a slot that verb minted, bound by a digest the signed manifest already carries. There
  # is deliberately no verb that *puts* — a download area a client could fill would be a node
  # storing other people's bytes on request.
  # ---------------------------------------------------------------------------

  @doc false
  def handle_wasm_download(params) do
    with {:ok, download} <- wasm_download(params),
         {:ok, offset} <- option_value("offset", :non_negative_integer, Map.get(params, "offset")),
         {:ok, target} <- permissions_node(params) do
      wasm_node_call(
        target,
        WasmDownload,
        :read,
        [download, offset, []],
        @wasm_download_timeout - @wasm_erpc_slack
      )
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  # ---------------------------------------------------------------------------
  # E2/E3 — code intelligence on the wire
  # ---------------------------------------------------------------------------

  @doc false
  def handle_runtime_lsp_status(_params) do
    safe(fn -> {:ok, CodeIntel.status()} end)
  end

  @doc false
  def handle_code_intel_request(params) do
    with {:ok, workspace} <- code_intel_workspace(params),
         {:ok, operation} <- code_intel_operation(params),
         {:ok, path} <- fetch_string(params, "path"),
         {:ok, line} <- code_intel_position(params, "line"),
         {:ok, character} <- code_intel_position(params, "character"),
         {:ok, query} <- fetch_optional_string(params, "query"),
         {:ok, target} <- permissions_node(params) do
      location = %{path: path, line: line, character: character, query: query}

      code_intel_call(target, :request, [
        operation,
        location,
        code_intel_opts(workspace, query: query)
      ])
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_code_intel_diagnostics(params) do
    with {:ok, workspace} <- code_intel_workspace(params),
         {:ok, path} <- fetch_string(params, "path"),
         {:ok, wait_ms} <- code_intel_wait_ms(params),
         {:ok, target} <- permissions_node(params) do
      code_intel_call(target, :diagnostics, [path, code_intel_opts(workspace, wait_ms: wait_ms)])
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  # `:operate`, and answered with the pre-touch baseline. An external tool that has just
  # written a file needs both halves of the new-only rule — what the server said about the
  # old text, and the version the new text was assigned — and reading the baseline in the
  # same gateway call is the only ordering in which nothing can arrive between them.
  @doc false
  def handle_code_intel_touch(params) do
    with {:ok, workspace} <- code_intel_workspace(params),
         {:ok, path} <- fetch_string(params, "path"),
         {:ok, action} <- code_intel_action(params),
         {:ok, target} <- permissions_node(params) do
      code_intel_call(target, :touch_with_baseline, [path, action, code_intel_opts(workspace)])
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  # ---------------------------------------------------------------------------
  # I1/I3 — the effect ledger on the wire, and across the fleet
  # ---------------------------------------------------------------------------

  @doc false
  def handle_ledger_list(params) do
    with {:ok, filters} <- ledger_filters(params),
         {:ok, fleet?} <- ledger_fleet(params),
         {:ok, target} <- permissions_node(params) do
      if fleet? do
        Present.ledger_fleet_list(filters)
      else
        Present.ledger_local_list(target, filters)
      end
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_ledger_get(params) do
    with {:ok, id} <- fetch_string(params, "id"),
         {:ok, target} <- permissions_node(params) do
      ledger_call(target, :get, [id])
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_ledger_export(params) do
    with {:ok, since} <- ledger_since(params),
         {:ok, target} <- permissions_node(params) do
      Present.ledger_export(target, since)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  @doc false
  def handle_interactive_start(params) do
    safe(fn ->
      case options(params, @start_options) do
        {:ok, opts} ->
          {owner, opts} = Keyword.pop(opts, :node, node())
          Placement.start_interactive(owner, opts)

        {:invalid, message} ->
          invalid_params(message)
      end
    end)
  end

  @doc false
  def handle_interactive_send_message(params) do
    with_turn(params, :interactive, &InteractiveSession.send_message/3)
  end

  @doc false
  def handle_interactive_retry_turn(params) do
    with_session(params, :interactive, fn session ->
      with {:ok, source} <- fetch_string(params, "source_turn_id") do
        safe(fn -> reply(InteractiveSession.retry_turn(session, source)) end)
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  @doc false
  def handle_interactive_follow_up(params) do
    with_turn(params, :interactive, &InteractiveSession.follow_up/3)
  end

  @doc false
  def handle_interactive_steer(params) do
    safe(fn ->
      with {:ok, session} <- session_target(:interactive, params),
           {:ok, input} <- fetch_turn_input(params) do
        reply(InteractiveSession.steer(session, input))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  # C2. The bridge's own verb. `ouro mcp-serve` calls it once per tool Claude Code would
  # otherwise have prompted about, and the answer it gets is the decision to relay back as
  # the permission-prompt tool's `allow`/`deny` object. Owner-routed like every other
  # session verb; the coordinator, not this module, decides.
  @doc false
  def handle_interactive_request_approval(params) do
    safe(fn ->
      with {:ok, session} <- session_target(:interactive, params),
           {:ok, request} <- approval_request(params) do
        case InteractiveSession.request_approval(session, request) do
          {:ok, answer} -> {:ok, Encode.approval_answer(answer)}
          other -> reply(other)
        end
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  # B1. What a session may still be changed to is the transport's answer, not this
  # table's: everything here does is turn four JSON fields into the four atoms the
  # runtime validates against the provider's own declarations, and hand back what came
  # out — including `applies`, which a client has to be able to render as "from the next
  # turn" rather than assume.
  @doc false
  def handle_interactive_configure(params) do
    safe(fn ->
      with {:ok, session} <- session_target(:interactive, params),
           {:ok, changes} <- options(params, @configuration_options, ["id", "node"]) do
        reply(InteractiveSession.configure(session, Map.new(changes)))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  # B6. The bound and the sanitising live in `Interactive.State`, not here: the same rule
  # has to hold for a title a person typed and for one the runtime derived from a prompt,
  # and a check that lived at the gateway would only cover the first.
  @doc false
  def handle_interactive_rename(params) do
    safe(fn ->
      with {:ok, session} <- session_target(:interactive, params),
           {:ok, title} <- fetch_string(params, "title") do
        reply(InteractiveSession.rename(session, title))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  # B6. The child's id is caller-owned for the same reason a start's is: a ceiling can
  # fire after the child exists, and a client that had to mint a second id to find out
  # would create a second session instead.
  #
  # R3. `to_turn` and `model` are the two things a fork may change about the child. Both
  # are validated here and decided deeper: whether this provider can branch anywhere but
  # its tail is `Ouroboros.Provider.session_fork_options/3`'s answer, and whether the
  # parent still holds the named boundary is the native session's.
  @doc false
  def handle_interactive_fork(params) do
    safe(fn ->
      with {:ok, session} <- session_target(:interactive, params),
           {:ok, fork_id} <- fetch_optional_string(params, "fork_id"),
           {:ok, to_turn} <- fetch_optional_rewind_target(params, "to_turn"),
           {:ok, model} <- fetch_optional_option_string(params, "model") do
        fork_reply(InteractiveSession.fork(session, fork_id, %{to_turn: to_turn, model: model}))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  # D9. Compaction is the one verb here whose refusal is a capability answer rather than a
  # parameter one: `unsupported_on_transport` names the transport that cannot do it, so a
  # client greys the key out instead of offering an action that will always fail.
  # D6. `to_turn` names the turn to return to; `what` is `files`, `conversation`, or
  # `both` (the default). The answer says which files were restored and which could not
  # be, because a bash command's effects are nobody's checkpoint.
  @doc false
  def handle_interactive_rewind(params) do
    safe(fn ->
      with {:ok, session} <- session_target(:interactive, params),
           {:ok, to_turn} <- fetch_rewind_target(params, "to_turn"),
           {:ok, what} <-
             fetch_optional_enum(params, "what", %{
               "files" => :files,
               "conversation" => :conversation,
               "both" => :both
             }) do
        reply(InteractiveSession.rewind(session, to_turn, what || :both))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  @doc false
  def handle_interactive_rewind_points(params) do
    safe(fn ->
      with {:ok, session} <- session_target(:interactive, params) do
        reply(InteractiveSession.rewind_points(session))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  @doc false
  def handle_interactive_compact(params) do
    safe(fn ->
      with {:ok, session} <- session_target(:interactive, params),
           {:ok, focus} <- fetch_optional_string(params, "focus") do
        reply(InteractiveSession.compact(session, focus))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  # A handoff starts a session, so it answers in `interactive.start`'s shape and carries
  # the same admission a ceiling forces: the caller-owned `handoff_id` is what makes a
  # timed-out handoff reconcilable rather than a second child.
  @doc false
  def handle_interactive_handoff(params) do
    safe(fn ->
      with {:ok, session} <- session_target(:interactive, params),
           {:ok, prompt} <- fetch_optional_string(params, "prompt"),
           {:ok, handoff_id} <- fetch_optional_string(params, "handoff_id") do
        fork_reply(InteractiveSession.handoff(session, prompt, handoff_id))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  # Read scope, and it answers for every transport. `source` is the field that keeps it
  # honest: `"native"` means the session counted these figures itself, `"usage"` means
  # they are what the provider reported and nothing more was known.
  @doc false
  def handle_interactive_context(params) do
    with_session(params, :interactive, fn session ->
      safe(fn -> reply(InteractiveSession.context(session)) end)
    end)
  end

  # B7. The one verb here that runs a command. Everything that decides whether it may —
  # the session's approval mode, the permission engine, the ledger entry that has to
  # exist first — is the coordinator's, so this is only the parameter contract and the
  # routing. A refusal comes back as `["shell_refused", {reason, suggested_rule, …}]`.
  @doc false
  def handle_workspace_exec(params) do
    safe(fn ->
      with {:ok, session} <- session_target(:interactive, params),
           {:ok, command} <- fetch_string(params, "command") do
        reply(InteractiveSession.exec(session, command))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  # D11. The one method that reads the filesystem for its own sake. Everything that decides
  # what it may read is `Ouroboros.Gateway.Methods.Browse` — the roots, the canonical
  # containment check, and the rule that a refusal outside them says only that — so this is
  # the parameter contract and the mapping from its typed refusals onto the wire.
  @doc false
  def handle_workspace_browse(params) do
    safe(fn ->
      with {:ok, path} <- fetch_optional_string(params, "path") do
        case Browse.browse(path) do
          {:ok, listing} -> {:ok, listing}
          {:error, refusal} -> browse_refusal(refusal)
        end
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  # G1. Three optional fields and no more: a delegation inherits this conversation's
  # workspace and provider unless told otherwise, and everything else about the child —
  # its team, its worker, its parent link, its coding node — is the runtime's to decide.
  # `delegation_id` is caller-owned for the reason `fork_id` is: this verb's ceiling
  # answers `outcome: unknown`, and a client that had to mint a second id to find out
  # would delegate the same objective twice.
  @doc false
  def handle_interactive_delegate(params) do
    safe(fn ->
      with {:ok, session} <- session_target(:interactive, params),
           {:ok, objective} <- fetch_string(params, "objective"),
           {:ok, delegation_id} <- fetch_optional_string(params, "delegation_id"),
           {:ok, opts} <-
             options(params, @interactive_delegation_options, [
               "id",
               "objective",
               "delegation_id",
               "node"
             ]) do
        opts =
          if delegation_id do
            Keyword.put(opts, :id, delegation_id)
          else
            opts
          end

        reply(InteractiveSession.delegate(session, objective, opts))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  # Read scope: `source` on each row says whether the status came from the team that owns
  # the delegation or from the conversation's own copy of it, so a client can tell a live
  # answer from a remembered one.
  @doc false
  def handle_interactive_delegations(params) do
    with_session(params, :interactive, fn session ->
      safe(fn -> reply(InteractiveSession.delegations(session)) end)
    end)
  end

  @doc false
  def handle_interactive_respond_approval(params) do
    safe(fn ->
      with {:ok, session} <- session_target(:interactive, params),
           {:ok, request_id} <- fetch_string(params, "request_id"),
           {:ok, response} <- approval_response(params) do
        reply(InteractiveSession.respond_approval(session, request_id, response))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  @doc false
  def handle_interactive_interrupt(params) do
    safe(fn ->
      with {:ok, session} <- session_target(:interactive, params),
           {:ok, turn_id} <- fetch_optional_string(params, "turn_id") do
        reply(InteractiveSession.interrupt(session, turn_id || :active))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  @doc false
  def handle_interactive_close(params) do
    with_session(params, :interactive, fn session ->
      safe(fn -> reply(InteractiveSession.close(session)) end)
    end)
  end

  @doc false
  def handle_interactive_kill(params) do
    with_session(params, :interactive, fn session ->
      safe(fn -> reply(InteractiveSession.kill(session)) end)
    end)
  end

  @doc false
  def handle_interactive_delete(params) do
    with_session(params, :interactive, fn session ->
      safe(fn -> reply(InteractiveSession.delete(session)) end)
    end)
  end

  @doc false
  def handle_coding_start(params) do
    safe(fn ->
      with {:ok, objective} <- fetch_string(params, "objective"),
           {:ok, opts} <- options(params, @start_options, ["objective"]) do
        {owner, opts} = Keyword.pop(opts, :node, node())
        Placement.start_coding(owner, objective, opts)
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  @doc false
  def handle_coding_respond_approval(params) do
    safe(fn ->
      with {:ok, task} <- session_target(:coding, params),
           {:ok, request_id} <- fetch_string(params, "request_id"),
           {:ok, response} <- approval_response(params) do
        reply(CodingSession.respond_approval(task, request_id, response))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  @doc false
  def handle_coding_cancel(params) do
    with_session(params, :coding, fn session ->
      safe(fn -> reply(CodingSession.cancel(session)) end)
    end)
  end

  @doc false
  def handle_coding_delete(params) do
    with_session(params, :coding, fn session ->
      safe(fn -> reply(CodingSession.delete(session)) end)
    end)
  end

  @doc false
  def handle_teams_add_worker(params) do
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

  @doc false
  def handle_teams_delegate(params) do
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

  @doc false
  def handle_teams_cancel(params) do
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

  @doc false
  def handle_teams_close(params) do
    safe(fn ->
      case team(params) do
        {:ok, team} -> reply(Team.close(team))
        {:invalid, message} -> invalid_params(message)
        {:missing, message} -> not_found(message)
      end
    end)
  end

  @doc false
  def handle_control_submit(params) do
    safe(fn ->
      with {:ok, objective} <- fetch_string(params, "objective"),
           {:ok, opts} <- options(params, @control_options, ["objective"]) do
        reply(Control.submit(objective, opts))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  @doc false
  def handle_control_cancel(params) do
    with_id(params, fn id -> safe(fn -> reply(Control.cancel(id)) end) end)
  end

  @doc false
  def handle_agents_stop(params) do
    with_id(params, fn id -> safe(fn -> reply(Mesh.stop_agent(id)) end) end)
  end

  # ---------------------------------------------------------------------------
  # W13 — one message into one mesh agent
  #
  # The scriptable half of §7.7: `ouro` and anything else holding an `:operate` listener
  # can now reach a deployed capability the way the native `capability` tool does, without
  # a model and without an IEx shell. Every bound is settled here, before the mesh is
  # touched, because the parameters arrive over a socket: an id longer than any this
  # runtime mints, a body larger than a message, and a timeout past this verb's own
  # ceiling are all refused rather than clamped — a client that asked for something this
  # node will not do should be told so, not quietly given something else.
  #
  # The reply is the agent's `last_answer` and is untrusted by construction. It is
  # returned whole when it encodes small and as a marked truncated string when it does
  # not, and `untrusted: true` rides beside it so a client rendering it has no excuse.
  # ---------------------------------------------------------------------------

  @doc false
  def handle_agents_message(params) do
    safe(fn ->
      with {:ok, to} <- agent_id(params, "to"),
           {:ok, from} <- agent_from(params),
           {:ok, body} <- agent_message_body(params),
           {:ok, timeout} <- agent_message_timeout(params) do
        reply(send_agent_message(from, to, body, timeout))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  @doc false
  def handle_capabilities_list(params) do
    safe(fn ->
      with {:ok, workspace} <- fetch_string(params, "workspace") do
        reply(Capabilities.list(workspace))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  @doc false
  def handle_capabilities_preview(params) do
    safe(fn ->
      with {:ok, workspace} <- fetch_string(params, "workspace"),
           {:ok, path} <- fetch_string(params, "path") do
        reply(Capabilities.preview(workspace, path))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  @doc false
  def handle_capabilities_admit(params) do
    safe(fn ->
      with {:ok, workspace} <- fetch_string(params, "workspace"),
           {:ok, path} <- fetch_string(params, "path"),
           {:ok, session_id} <- fetch_optional_string(params, "session_id") do
        opts =
          if session_id do
            [author: "session:" <> session_id]
          else
            []
          end

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

  # D11. Six refusals, each named in `data.reason` so a client branches on the reason
  # rather than on the sentence. The one that carries the rule rather than the mistake is
  # `outside_roots`: it says the path is outside the directories this node browses and
  # stops there — not whether it exists, not what it resolved to, not which root it was
  # nearest. `roots` travels with it because a client that has to explain the refusal
  # needs the surface it was held to, and those paths are the same ones a successful
  # listing already hands back.
  defp browse_refusal({:no_browse_roots, _detail}) do
    {:error, code(:unavailable),
     "this node browses no directories: $HOME is unset and :workspace_allowed_roots " <>
       "(OUROBOROS_WORKSPACE_ROOTS) names none that resolve to one",
     %{"reason" => "no_browse_roots"}}
  end

  defp browse_refusal({:relative_path, _detail}) do
    {:error, code(:invalid_params),
     "params.path must be an absolute path; this method resolves nothing against the " <>
       "daemon's working directory", %{"reason" => "relative_path"}}
  end

  defp browse_refusal({:outside_roots, %{roots: roots}}) do
    {:error, code(:invalid_params), "params.path is outside every directory this node browses",
     %{"reason" => "outside_roots", "roots" => roots}}
  end

  defp browse_refusal({:no_such_directory, _detail}) do
    {:error, code(:not_found), "no directory at that path on this node",
     %{"reason" => "no_such_directory"}}
  end

  defp browse_refusal({:not_a_directory, _detail}) do
    {:error, code(:invalid_params), "params.path does not name a directory",
     %{"reason" => "not_a_directory"}}
  end

  defp browse_refusal({:unreadable, %{detail: detail}}) do
    {:error, code(:upstream_error), "that directory could not be resolved or read",
     %{"reason" => "unreadable", "detail" => detail}}
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
    "worktree" => :worktree,
    "plan" => :plan,
    "mode" => :mode,
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

  # `actor` is how a caller answering with nobody at the keyboard says so — `ouro run
  # --approve-all` is the one that exists — and it is what the ledger's `approval` entry
  # records. Unstated means a person; it is never inferred from the scope or the socket.
  @approval_actors %{"human" => :human, "headless" => :headless, "automation" => :automation}

  defp structured_approval(response) do
    unknown = Map.keys(response) -- ["decision", "scope", "reason", "actor", "provider_options"]

    with [] <- unknown,
         {:ok, decision} <- Map.fetch(@approval_decisions, Map.get(response, "decision")),
         {:ok, scope} <- Map.fetch(@approval_scopes, Map.get(response, "scope", "once")),
         {:ok, reason} <- fetch_optional_string(response, "reason"),
         {:ok, actor} <- Map.fetch(@approval_actors, Map.get(response, "actor", "human")),
         {:ok, provider_options} <- plan_exit_options(Map.get(response, "provider_options")) do
      approval = %{decision: decision, scope: scope}

      approval =
        if reason, do: Map.put(approval, :reason, reason), else: approval

      approval =
        if provider_options,
          do: Map.put(approval, :provider_options, provider_options),
          else: approval

      {:ok, if(actor == :human, do: approval, else: Map.put(approval, :actor, actor))}
    else
      _refused -> {:invalid, approval_message()}
    end
  end

  defp plan_exit_options(nil), do: {:ok, nil}

  defp plan_exit_options(options) when is_map(options) do
    with [] <- Map.keys(options) -- ["choice", "follow_up"],
         true <- Map.get(options, "choice", "auto_edit") in @plan_exit_choices,
         {:ok, follow_up} <- fetch_optional_string(options, "follow_up"),
         true <- is_nil(follow_up) or byte_size(follow_up) <= @max_follow_up_bytes do
      {:ok,
       options
       |> Map.take(["choice", "follow_up"])
       |> Enum.reject(fn {_key, value} -> is_nil(value) end)
       |> Map.new()}
    else
      _refused -> :refused
    end
  end

  defp plan_exit_options(_other), do: :refused

  # What a permission-prompt tool actually carries. `tool_name` is the only required
  # field: Claude Code's call names the tool, hands over its arguments object, and
  # correlates with a `tool_use_id`. `cwd` is the bridge's own addition — the directory
  # the tool would run in, which is the fact a person needs and the payload the Codex
  # dialect already carries. Nothing else is accepted, because an approval request is a
  # question, not a place to hand the runtime extra instructions.
  defp approval_request(params) do
    case Map.get(params, "request") do
      request when is_map(request) ->
        with [] <- Map.keys(request) -- ["tool_name", "input", "tool_use_id", "cwd"],
             {:ok, tool_name} <- fetch_request_string(request, "tool_name"),
             {:ok, tool_use_id} <- fetch_optional_request_string(request, "tool_use_id"),
             {:ok, cwd} <- fetch_optional_request_string(request, "cwd"),
             {:ok, input} <- fetch_optional_object(request, "input") do
          {:ok,
           %{
             tool_name: tool_name,
             input: input,
             tool_use_id: tool_use_id,
             cwd: cwd
           }}
        else
          {:invalid, message} -> {:invalid, message}
          _refused -> {:invalid, approval_request_message()}
        end

      _absent ->
        {:invalid, approval_request_message()}
    end
  end

  defp fetch_request_string(request, key) do
    case Map.get(request, key) do
      value when is_binary(value) ->
        if String.trim(value) == "",
          do: {:invalid, "params.request.#{key} must be a nonempty string"},
          else: {:ok, value}

      _absent_or_wrong ->
        {:invalid, "params.request.#{key} must be a nonempty string"}
    end
  end

  defp fetch_optional_request_string(request, key) do
    case Map.get(request, key) do
      nil -> {:ok, nil}
      _present -> fetch_request_string(request, key)
    end
  end

  defp fetch_optional_object(params, key) do
    case Map.get(params, key) do
      nil -> {:ok, nil}
      value when is_map(value) -> {:ok, value}
      _other -> {:invalid, "params.request.#{key} must be an object"}
    end
  end

  defp approval_request_message do
    ~s(params.request must be an object {"tool_name": "...", "input": {...}, ) <>
      ~s("tool_use_id": "...", "cwd": "..."} with a non-empty tool_name)
  end

  defp approval_message do
    ~s(params.response must be "approve", "deny", or an object ) <>
      ~s({"decision": "approve"|"deny", "scope": "once"|"session", "reason": "..."})
  end

  defp permission_scope(params, key, allowed, requirement) do
    case {Map.get(params, key), requirement} do
      {nil, :optional} -> {:ok, nil}
      {value, _requirement} when is_binary(value) -> fetch_permission_term(key, allowed, value)
      {_value, _requirement} -> {:invalid, permission_message(key, allowed)}
    end
  end

  defp fetch_permission_term(key, allowed, value) do
    case Map.fetch(allowed, value) do
      {:ok, term} -> {:ok, term}
      :error -> {:invalid, permission_message(key, allowed)}
    end
  end

  defp permission_message(key, allowed) do
    "params.#{key} must be one of " <>
      (allowed |> Map.keys() |> Enum.sort() |> Enum.join(", "))
  end

  defp permissions_node(params) do
    case Map.get(params, "node") do
      nil -> {:ok, node()}
      value -> option_value("node", :node, value)
    end
  end

  # Node-local authority, queried where it lives. A remote answer is bounded by `:erpc`
  # rather than by this module's ceiling, so an unreachable machine is reported as an
  # unreachable machine instead of as a gateway timeout with no detail.
  defp permissions_call(target, function, arguments) do
    safe(fn ->
      if target == node() do
        reply(apply(Permissions, function, arguments))
      else
        reply(:erpc.call(target, Permissions, function, arguments, @fleet_query_timeout))
      end
    end)
  end

  # W5. Same posture as `permissions_call/3` and `mcp_call/2`: a helper, a component store
  # and a rollout register are node-local, so the machine that owns them is the machine
  # that describes them. `Ouroboros.Wasm.Surface` raises nothing and blocks on nothing
  # without a deadline — a pool it does not find is `:absent`, a store it cannot read is
  # `nil` — so what crosses `:erpc` is always an ordinary map. A peer too old to hold the
  # module answers `-32006` naming it, which is the honest reading of "that node cannot
  # describe a lane it does not have".
  defp wasm_call(params, function) do
    with :ok <- only_keys(params, ["node"]),
         {:ok, target} <- permissions_node(params) do
      safe(fn ->
        if target == node() do
          {:ok, apply(WasmSurface, function, [[]])}
        else
          {:ok, :erpc.call(target, WasmSurface, function, [[]], @fleet_query_timeout)}
        end
      end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  # W13 ------------------------------------------------------------------------------
  defp bounded_agent_state(@wasm_agent_prefix <> _name, {:ok, %{agent: %{state: state}} = server})
       when is_map(state) do
    {answer, answer_truncated?} = bounded_answer(Map.get(state, :last_answer))
    {message, message_truncated?} = bounded_answer(Map.get(state, :last_message))

    bounded =
      state
      |> Map.replace(:last_answer, answer)
      |> Map.replace(:last_message, message)

    {:ok,
     server
     |> Map.put(:agent, Map.put(server.agent, :state, bounded))
     |> Map.put(:untrusted, true)
     |> Map.put(:truncated, answer_truncated? or message_truncated?)}
  end

  defp bounded_agent_state(_id, result), do: result

  defp agent_id(params, key) do
    case Map.get(params, key) do
      value when is_binary(value) and value != "" ->
        if byte_size(value) <= @max_agent_id_bytes,
          do: {:ok, value},
          else: {:invalid, "params.#{key} must be at most #{@max_agent_id_bytes} bytes"}

      _other ->
        {:invalid, "params.#{key} must be a nonempty string"}
    end
  end

  # A `from` is a label on the message, and an absent one is not an error: the caller is a
  # gateway client, and saying so is more honest than making every script invent an
  # identity the mesh does not check anyway.
  defp agent_from(params) do
    case Map.get(params, "from") do
      nil -> {:ok, "gateway"}
      _present -> agent_id(params, "from")
    end
  end

  # Bounded by what it costs on the wire into the agent, not by what the decoded term costs
  # here: the number in the contract is the number a client can measure. Measured by
  # encoding, and an unencodable body is refused rather than carried to an agent that would
  # have to refuse it later with less to say about why.
  defp agent_message_body(params) do
    case Map.fetch(params, "body") do
      :error ->
        {:invalid, "params.body is required and may be any JSON value"}

      {:ok, body} ->
        case encoded_bytes(body) do
          {:ok, size} when size <= @max_agent_message_bytes ->
            {:ok, body}

          {:ok, size} ->
            {:invalid,
             "params.body encodes to #{size} bytes; the bound is #{@max_agent_message_bytes}"}

          :error ->
            {:invalid, "params.body must be a JSON value"}
        end
    end
  end

  defp encoded_bytes(term) do
    {:ok, byte_size(JSON.encode!(term))}
  rescue
    _error -> :error
  end

  defp agent_message_timeout(params) do
    case Map.get(params, "timeout_ms") do
      nil ->
        {:ok, @default_agent_message_timeout_ms}

      value when is_integer(value) and value >= 1 and value <= @max_agent_message_timeout_ms ->
        {:ok, value}

      _other ->
        {:invalid,
         "params.timeout_ms must be an integer between 1 and #{@max_agent_message_timeout_ms}"}
    end
  end

  defp send_agent_message(from, to, body, timeout) do
    case Mesh.send_message(from, to, body, timeout: timeout) do
      {:ok, agent} -> {:ok, agent_message_result(from, to, agent)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp agent_message_result(from, to, agent) do
    {answer, truncated?} = bounded_answer(agent_answer(agent, to))

    %{
      to: to,
      from: from,
      # Stated in the result and not only in the reference. Every path a component's words
      # take to a reader carries this label (docs/WASM.md D17), and a client that drew this
      # into a transcript beside the operator's own text without it would be the one place
      # the rule was not enforced.
      untrusted: true,
      truncated: truncated?,
      reply: answer
    }
  end

  # `Jido.AgentServer.call/3` answers with the agent as it stands after the signal, which
  # is where `Ouroboros.Mesh`'s whole message convention puts a reply. A shape this build
  # does not recognise falls back to the directory rather than to a guess.
  defp agent_answer(%{state: %{last_answer: answer}}, _to), do: answer

  defp agent_answer(_agent, to) do
    case Mesh.state(to) do
      {:ok, %{agent: %{state: %{last_answer: answer}}}} -> answer
      _unreadable -> nil
    end
  end

  # Whole when it fits, and a marked string when it does not — never a silently cut JSON
  # document, which is a document a client will try to parse and fail on with no idea why.
  defp bounded_answer(answer) do
    case encoded_bytes(answer) do
      {:ok, size} when size <= @max_agent_message_bytes ->
        {answer, false}

      {:ok, _size} ->
        {truncate(JSON.encode!(answer)), true}

      :error ->
        {truncate(inspect(answer, limit: 200, printable_limit: @max_agent_message_bytes)), true}
    end
  end

  defp truncate(text) when byte_size(text) <= @max_agent_message_bytes, do: text

  # In band, and by design. A client holding a JSON document that was silently cut has a
  # document it will try to parse and fail on with no idea why; the marker is the only thing
  # in the value itself that says what happened, and it is the same sentence the native
  # `capability` tool appends for the same reason. Room is made for it *inside* the bound,
  # so a truncated reply is never larger than an untruncated one may be.
  defp truncate(text) do
    marker = "… truncated at #{@max_agent_message_bytes} bytes."
    keep = @max_agent_message_bytes - byte_size(marker)

    text |> binary_part(0, max(keep, 0)) |> valid_prefix() |> Kernel.<>(marker)
  end

  # The cut is by bytes and walked back to a whole character: half a codepoint is a string
  # the JSON encoder on the way out would refuse.
  defp valid_prefix(binary) do
    cond do
      String.valid?(binary) -> binary
      byte_size(binary) == 0 -> binary
      true -> binary |> binary_part(0, byte_size(binary) - 1) |> valid_prefix()
    end
  end

  # W12. The same routing as `wasm_call/2`, with a per-verb deadline: these do real work
  # on the machine they name — a file write, a signing round trip, a whole rollout — so one
  # `@fleet_query_timeout` covering all of them would kill the longest of them at five
  # seconds. The `:erpc` deadline sits below the method's ceiling so the plane's own typed
  # refusal wins the race against a transport timeout with nothing in it.
  defp wasm_node_call(target, module, function, args, timeout) do
    safe(fn ->
      if target == node() do
        wasm_reply(apply(module, function, args))
      else
        wasm_reply(:erpc.call(target, module, function, args, timeout))
      end
    end)
  end

  # The refusals worth naming. Everything below them is a client's own mistake about a
  # transfer or a file it supplied, so it is `-32602` rather than an upstream failure; a
  # node that cannot sign at all is `-32004`, because "this node has no signer" and "this
  # signer said no" need different operator responses.
  defp wasm_reply({:ok, value}), do: {:ok, value}

  defp wasm_reply({:error, :no_signing_service}) do
    unavailable(
      "this node has no signing service: OUROBOROS_SIGNING_NODE must name the :signer " <>
        "node that holds the key, or this node must run one itself. A component is signed " <>
        "where the key is, never here"
    )
  end

  defp wasm_reply({:error, {:signing_service_unavailable, _detail} = reason}),
    do: {:error, code(:unavailable), "the signing service did not answer", Wire.to_json(reason)}

  defp wasm_reply({:error, {:signer_unreachable, target, _detail} = reason}) do
    {:error, code(:unavailable), "signing node #{target} did not answer", Wire.to_json(reason)}
  end

  defp wasm_reply({:error, {:signing_refused, _reason} = reason}) do
    {:error, code(:upstream_error), "the signing policy refused this manifest",
     Wire.to_json(reason)}
  end

  defp wasm_reply({:error, {:imports_not_derivable, _detail} = reason}) do
    invalid_params(
      "params.imports must be given: this node could not read the component's own import " <>
        "list (#{inspect(reason, limit: 5, printable_limit: 120)}), and a manifest that " <>
        "declares the wrong imports is quarantined at stage time rather than warned about"
    )
  end

  # The held offset travels in `data` as well as in the sentence, because resuming is what a
  # client does with it and parsing a number out of an error message is not a protocol.
  defp wasm_reply({:error, {:offset_mismatch, held, _sent}}) do
    {:error, code(:invalid_params),
     "params.offset must be #{held}, which is what this upload holds",
     %{"reason" => "offset_mismatch", "offset" => held}}
  end

  defp wasm_reply({:error, {:unknown_upload, id}}),
    do: not_found("no upload #{id} on this node; it may have expired or been consumed")

  defp wasm_reply({:error, {:upload_incomplete, id}}),
    do: invalid_params("upload #{id} has not been committed; send its last frame with final")

  defp wasm_reply({:error, {:upload_closed, id}}),
    do: invalid_params("upload #{id} is already committed and takes no further frames")

  defp wasm_reply({:error, {:too_many_uploads, _held, max}}) do
    unavailable(
      "this node already holds #{max} uploads; they expire ten minutes after their last frame"
    )
  end

  defp wasm_reply({:error, :no_data_dir}) do
    unavailable("this node has no data directory, so it can stage nothing and store nothing")
  end

  defp wasm_reply({:error, {:no_live_rollout, name}}),
    do: not_found("no live lane-W rollout named #{inspect(name)} on this node")

  # W19. The three ways a `wasm.download` is a client's own mistake about a transfer. "There
  # is no such slot" and "you asked from the wrong place" send an operator to different
  # places: the first is a signature to make again, the second is a client that lost its
  # place in a file it is halfway through.
  defp wasm_reply({:error, {:unknown_download, id}}) do
    not_found(
      "no download #{id} on this node; a slot ends when its final chunk is read, and " <>
        "otherwise when its clocks run out — sign again to mint another"
    )
  end

  defp wasm_reply({:error, {:offset_not_a_chunk_boundary, _offset, chunk}}) do
    invalid_params(
      "params.offset must be a multiple of #{chunk}, which is this node's chunk: a download " <>
        "is walked with the offsets its own answers hand back, never seeked into"
    )
  end

  defp wasm_reply({:error, {:offset_past_size, _offset, size}}),
    do: invalid_params("params.offset must be below #{size}, which is this download's size")

  defp wasm_reply({:error, {:invalid_download_id, _id}}),
    do: invalid_params("params.download must be a download id this node minted")

  defp wasm_reply(other), do: reply(other)

  ## W12 parameters

  defp wasm_upload(params) do
    with {:ok, value} <- fetch_string(params, "upload"), do: wasm_upload_id(value)
  end

  defp wasm_optional_upload(params) do
    case Map.get(params, "upload") do
      nil -> {:ok, nil}
      value when is_binary(value) -> wasm_upload_id(value)
      _other -> {:invalid, "params.upload must be the id a previous frame returned"}
    end
  end

  # W19. The same shape and the same reasoning as an upload id, and validated here for the
  # same reason: it becomes a filename on the far side.
  defp wasm_download(params) do
    with {:ok, value} <- fetch_string(params, "download") do
      if Regex.match?(~r/\A[0-9a-f]{32}\z/, value),
        do: {:ok, value},
        else: {:invalid, "params.download must be a download id this node minted"}
    end
  end

  # Bounded and validated here as well as on the node that minted it: an id that made a
  # round trip through a client is a value that arrived from a client, and it becomes a
  # filename there.
  defp wasm_upload_id(value) do
    if Regex.match?(~r/\A[0-9a-f]{32}\z/, value),
      do: {:ok, value},
      else: {:invalid, "params.upload must be an upload id this node minted"}
  end

  # The manifest's own charset, checked at the edge so a name that could hold a path
  # separator or a bidirectional control never reaches the register's module field.
  defp wasm_name(params) do
    with {:ok, value} <- fetch_string(params, "name") do
      if WasmArtifact.name?(value) do
        {:ok, value}
      else
        {:invalid,
         "params.name must be lower case, start with a letter or digit, then letters, " <>
           "digits, `.`, `_` or `-`, and be at most 64 bytes: it is the rollout register's " <>
           "module and the durable id a start block claims cluster-wide"}
      end
    end
  end

  # Bounded before it is decoded, not after: base64 is four characters to three bytes, so
  # the encoded length already states what a decode would allocate.
  defp wasm_chunk(params) do
    max = WasmUpload.max_chunk_bytes()

    case Map.get(params, "data") do
      value when is_binary(value) and value != "" ->
        if byte_size(value) > div(max + 2, 3) * 4 + 4 do
          {:invalid, "params.data must be base64 of at most #{max} bytes"}
        else
          wasm_decode64(value, max)
        end

      _other ->
        {:invalid, "params.data must be a nonempty base64 string"}
    end
  end

  defp wasm_decode64(value, max) do
    case Base.decode64(value) do
      {:ok, ""} -> {:invalid, "params.data must decode to at least one byte"}
      {:ok, chunk} when byte_size(chunk) <= max -> {:ok, chunk}
      {:ok, _oversize} -> {:invalid, "params.data must be base64 of at most #{max} bytes"}
      :error -> {:invalid, "params.data must be base64"}
    end
  end

  defp wasm_flag(params, key) do
    case Map.get(params, key, false) do
      value when is_boolean(value) -> {:ok, value}
      _other -> {:invalid, "params.#{key} must be a boolean"}
    end
  end

  defp wasm_optional_positive(params, key) do
    case Map.get(params, key) do
      nil -> {:ok, nil}
      value -> option_value(key, :positive_integer, value)
    end
  end

  defp wasm_optional_sha256(params) do
    case Map.get(params, "source_sha256") do
      nil ->
        {:ok, nil}

      value when is_binary(value) ->
        if WasmArtifact.sha256?(value),
          do: {:ok, value},
          else: {:invalid, "params.source_sha256 must be 64 lower-case hex characters"}

      _other ->
        {:invalid, "params.source_sha256 must be 64 lower-case hex characters"}
    end
  end

  # Required, and `[]` is a legitimate answer meaning "this component imports nothing" —
  # which is why it must be *said* rather than inferred from an absent key. The node does
  # not read the component to find out (D15): it is unsigned input from a socket, and the
  # helper is not a parser this end gets to point at it.
  defp wasm_imports(params) do
    case Map.get(params, "imports") do
      nil ->
        {:invalid,
         "params.imports is required: this node does not parse unsigned bytes to find out " <>
           "what a component imports. Compute it with `ouro wasm inspect`, or send [] for a " <>
           "component that imports nothing"}

      values when is_list(values) and length(values) <= 8 ->
        if Enum.all?(values, &(is_binary(&1) and &1 != "" and byte_size(&1) <= 64)),
          do: {:ok, values},
          else:
            {:invalid, "params.imports must contain only nonempty strings of at most 64 bytes"}

      _other ->
        {:invalid, "params.imports must be a list of at most 8 nonempty strings"}
    end
  end

  # The signer bounds this at 16 KiB and refuses anything larger; refusing it here too
  # means a config nobody could sign is not first uploaded, hashed, and journalled.
  defp wasm_start_config(params) do
    case Map.get(params, "start_config") do
      nil ->
        {:ok, nil}

      value when is_binary(value) and byte_size(value) <= 16_384 ->
        {:ok, value}

      _other ->
        {:invalid, "params.start_config must be a string of at most 16384 bytes"}
    end
  end

  # A signed eval spec is the only place in this table where a client's bytes decide an
  # atom, and they do not: every atom below is a literal in this module, and the one field
  # that names something outside it — a capability's own state key — goes through
  # `String.to_existing_atom/1` in a rescue, exactly as `upgrade.history`'s module does.
  #
  # `initial_state` is deliberately not accepted. `Ouroboros.Wasm.Rollout.start_state/2`
  # names the six keys that decide what is being evaluated and a signed spec merges *under*
  # them, so the only keys an `initial_state` here could still choose are ones no lane-W
  # capability reads. A parameter that can only do nothing is a parameter that will one day
  # do something.
  # W15. A closed set of two, and an absent one means `capability` — which is what every
  # `wasm.sign` written before there were two kinds meant.
  # W8. Absent means true, which is what an operator asking a node with a helper to sign
  # something means. A present value that is not a boolean is refused rather than coerced: a
  # client that wrote `"false"` and got a precompile has been told the opposite of what happened.
  defp wasm_precompile(params) do
    case Map.get(params, "precompile") do
      nil -> {:ok, true}
      value when is_boolean(value) -> {:ok, value}
      other -> {:invalid, "params.precompile must be a boolean, got #{inspect(other)}"}
    end
  end

  defp wasm_kind(params) do
    case Map.get(params, "kind") do
      nil ->
        {:ok, :capability}

      "capability" ->
        {:ok, :capability}

      "policy" ->
        {:ok, :policy}

      other ->
        {:invalid, "params.kind must be \"capability\" or \"policy\", got #{inspect(other)}"}
    end
  end

  defp wasm_eval(params, kind) do
    case {Map.get(params, "eval"), kind} do
      {nil, _kind} -> {:ok, nil}
      {spec, :policy} when is_map(spec) -> wasm_policy_eval_spec(spec)
      {spec, _capability} when is_map(spec) -> wasm_eval_spec(spec)
      _other -> {:invalid, "params.eval must be an object"}
    end
  end

  # A policy component's signed spec: the requests it must decide, and how it must decide them.
  # Validated here for shape and again by `Ouroboros.Wasm.PolicyEngine.validate_eval/1` at the
  # signer, which is the one that decides — this is the gateway refusing a frame it can name a
  # fault in rather than forwarding it.
  defp wasm_policy_eval_spec(spec) do
    with :ok <- only_keys(spec, ["cases", "budget_ms"]),
         {:ok, cases} <- wasm_policy_cases(Map.get(spec, "cases")),
         {:ok, budget} <- wasm_optional_positive(spec, "budget_ms") do
      {:ok, %{cases: cases} |> wasm_put(:budget_ms, budget)}
    end
  end

  defp wasm_policy_cases(cases) when is_list(cases) and cases != [] and length(cases) <= 20 do
    cases
    |> Enum.reduce_while({:ok, []}, fn one, {:ok, acc} ->
      case wasm_policy_case(one) do
        {:ok, valid} -> {:cont, {:ok, [valid | acc]}}
        {:invalid, message} -> {:halt, {:invalid, message}}
      end
    end)
    |> case do
      {:ok, valid} -> {:ok, Enum.reverse(valid)}
      invalid -> invalid
    end
  end

  defp wasm_policy_cases(_other),
    do: {:invalid, "params.eval.cases must be a list of 1 to 20 objects"}

  defp wasm_policy_case(one) when is_map(one) do
    with :ok <- only_keys(one, ["request", "expect"]),
         request when is_map(request) <-
           Map.get(one, "request") ||
             {:invalid, "params.eval.cases[].request is required and must be an object"},
         {:ok, decision} <- wasm_policy_decision(Map.get(one, "expect")) do
      {:ok, %{request: request, expect: %{decision: decision}}}
    else
      {:invalid, message} -> {:invalid, message}
      _not_an_object -> {:invalid, "params.eval.cases[].request must be an object"}
    end
  end

  defp wasm_policy_case(_other), do: {:invalid, "params.eval.cases[] must be an object"}

  defp wasm_policy_decision(%{"decision" => decision} = expect)
       when decision in ["allow", "deny", "ask"] do
    with :ok <- only_keys(expect, ["decision"]) do
      {:ok, String.to_existing_atom(decision)}
    end
  end

  defp wasm_policy_decision(_other),
    do:
      {:invalid,
       "params.eval.cases[].expect must be {\"decision\": \"allow\" | \"deny\" | \"ask\"}"}

  defp wasm_eval_spec(spec) do
    with :ok <- only_keys(spec, ["probes", "budget_ms", "max_latency_ms", "required"]),
         {:ok, probes} <- wasm_probes(Map.get(spec, "probes")),
         {:ok, budget} <- wasm_optional_positive(spec, "budget_ms"),
         {:ok, latency} <- wasm_optional_positive(spec, "max_latency_ms"),
         {:ok, required} <- wasm_required(Map.get(spec, "required")) do
      {:ok,
       %{probes: probes}
       |> wasm_put(:budget_ms, budget)
       |> wasm_put(:max_latency_ms, latency)
       |> wasm_put(:required, required)}
    end
  end

  defp wasm_probes(probes) when is_list(probes) and probes != [] and length(probes) <= 20 do
    probes
    |> Enum.reduce_while({:ok, []}, fn probe, {:ok, acc} ->
      case wasm_probe(probe) do
        {:ok, valid} -> {:cont, {:ok, [valid | acc]}}
        {:invalid, message} -> {:halt, {:invalid, message}}
      end
    end)
    |> case do
      {:ok, valid} -> {:ok, Enum.reverse(valid)}
      invalid -> invalid
    end
  end

  defp wasm_probes(_other),
    do: {:invalid, "params.eval.probes must be a list of 1 to 20 objects"}

  # `only_keys/2`'s sentence is right for a method's own envelope, where a client has the
  # parameter reference in front of it, and wrong two levels down inside a spec: "params
  # contains unsupported fields: message" is a true statement that tells somebody writing
  # their first eval spec nothing about what to write instead. The author of W11's guide hit
  # exactly that, spelling the body `message` because that is what `agents.message` calls it.
  # So this one says what a probe takes.
  defp wasm_probe(probe) when is_map(probe) do
    with :ok <- wasm_probe_keys(probe),
         true <-
           Map.has_key?(probe, "input") or {:invalid, "params.eval.probes[].input is required"},
         {:ok, expect} <- wasm_expect(Map.get(probe, "expect")) do
      {:ok, %{input: Map.get(probe, "input"), expect: expect}}
    else
      {:invalid, message} -> {:invalid, message}
    end
  end

  defp wasm_probe(_other), do: {:invalid, "params.eval.probes[] must be an object"}

  defp wasm_probe_keys(probe) do
    case Map.keys(probe) -- @probe_keys do
      [] ->
        :ok

      unknown ->
        {:invalid,
         "params.eval.probes[] takes " <>
           Enum.join(@probe_keys, " and ") <>
           " and nothing else, got: " <>
           (unknown |> Enum.sort() |> Enum.join(", ")) <>
           ". `input` is the message body handed to the capability, whatever the capability " <>
           "itself calls it"}
    end
  end

  defp wasm_expect(nil), do: {:ok, :any_reply}

  defp wasm_expect(%{"kind" => "any_reply"} = expect) do
    with :ok <- only_keys(expect, ["kind"]), do: {:ok, :any_reply}
  end

  defp wasm_expect(%{"kind" => "contains", "substring" => substring} = expect)
       when is_binary(substring) and substring != "" do
    with :ok <- only_keys(expect, ["kind", "substring"]) do
      if String.valid?(substring) and byte_size(substring) <= 1_024,
        do: {:ok, {:contains, substring}},
        else:
          {:invalid, "params.eval.probes[].expect.substring must be text of at most 1024 bytes"}
    end
  end

  defp wasm_expect(%{"kind" => "equals"} = expect) do
    with :ok <- only_keys(expect, ["kind", "value"]) do
      if Map.has_key?(expect, "value"),
        do: {:ok, {:equals, Map.get(expect, "value")}},
        else: {:invalid, "params.eval.probes[].expect.value is required for an equals check"}
    end
  end

  defp wasm_expect(%{"kind" => "state_matches", "key" => key} = expect) when is_binary(key) do
    with :ok <- only_keys(expect, ["kind", "key", "value"]),
         {:ok, field} <- wasm_state_key(key) do
      if Map.has_key?(expect, "value"),
        do: {:ok, {:state_matches, field, Map.get(expect, "value")}},
        else:
          {:invalid, "params.eval.probes[].expect.value is required for a state_matches check"}
    end
  end

  defp wasm_expect(_other) do
    {:invalid,
     "params.eval.probes[].expect must name a kind: any_reply, contains, equals or state_matches"}
  end

  # A field of the wrapper agent's own state, and nothing else.
  #
  # `String.to_existing_atom/1` was the first answer and it is the wrong bound: it admits
  # every atom the VM happens to hold — thousands of module names, every option key of
  # every dependency — as a state field to match on. What an eval spec may name is what
  # `Ouroboros.Wasm.Capability` declares, so the list is read from the agent itself rather
  # than restated here, and the comparison is a string against `Atom.to_string/1` so no
  # conversion happens at all: a name outside the list never becomes an atom, existing or
  # otherwise.
  defp wasm_state_key(key) when byte_size(key) <= 128 do
    case Enum.find(wasm_state_fields(), &(Atom.to_string(&1) == key)) do
      nil ->
        {:invalid,
         "params.eval.probes[].expect.key must name a field of the wasm capability's state (" <>
           Enum.join(wasm_state_names(), ", ") <> "), got: " <> inspect(key)}

      field ->
        {:ok, field}
    end
  end

  defp wasm_state_key(_key),
    do: {:invalid, "params.eval.probes[].expect.key must be at most 128 bytes"}

  defp wasm_state_names, do: wasm_state_fields() |> Enum.map(&Atom.to_string/1) |> Enum.sort()

  defp wasm_required(nil), do: {:ok, nil}
  defp wasm_required("all"), do: {:ok, :all}

  defp wasm_required(%{"at_least" => n}) when is_integer(n) and n >= 1,
    do: {:ok, {:at_least, n}}

  defp wasm_required(_other),
    do: {:invalid, ~s(params.eval.required must be "all" or {"at_least": n})}

  # The targets a rollout drives. Defaulted to the driving node, because a deployment to
  # nowhere is not a shorter deployment, and bounded and deduplicated here so the rollout's
  # own `{:duplicate_nodes, _}` is a refusal a client cannot reach by accident.
  defp wasm_targets(params, driver) do
    case Map.get(params, "nodes") do
      nil ->
        {:ok, [driver]}

      values when is_list(values) and values != [] and length(values) <= 32 ->
        values
        |> Enum.reduce_while({:ok, []}, fn value, {:ok, acc} ->
          case option_value("nodes", :node, value) do
            {:ok, target} -> {:cont, {:ok, [target | acc]}}
            {:invalid, message} -> {:halt, {:invalid, message}}
          end
        end)
        |> case do
          {:ok, targets} -> {:ok, targets |> Enum.reverse() |> Enum.uniq()}
          invalid -> invalid
        end

      _other ->
        {:invalid, "params.nodes must be a list of 1 to 32 connected machines"}
    end
  end

  defp wasm_put(map, _key, nil), do: map
  defp wasm_put(map, key, value), do: Map.put(map, key, value)

  # Same posture as `permissions_call/3` and `code_intel_call/3`, and for the same
  # reason: an MCP server runs on the machine whose session asked for it, so a session
  # on another host is described by that host's pool or not at all.
  # `Ouroboros.Provider.Native.Mcp.status/1` raises nothing and blocks on nothing without
  # a deadline, so what crosses `:erpc` is always an ordinary map.
  defp mcp_call(target, opts) do
    safe(fn ->
      if target == node() do
        {:ok, Mcp.status(opts)}
      else
        {:ok, :erpc.call(target, Mcp, :status, [opts], @fleet_query_timeout)}
      end
    end)
  end

  # ---------------------------------------------------------------------------
  # Code intelligence (E2/E3)
  # ---------------------------------------------------------------------------

  # Same posture as `permissions_call/3` and for the same reason: the pool runs where the
  # files are, so a session on another machine is answered by that machine's pool or not
  # at all. `Ouroboros.CodeIntel` raises nothing and blocks on nothing without a deadline,
  # so what crosses `:erpc` is always an ordinary tuple.
  defp code_intel_call(target, function, arguments) do
    safe(fn ->
      if target == node() do
        Encode.code_intel_reply(apply(CodeIntel, function, arguments))
      else
        Encode.code_intel_reply(
          :erpc.call(target, CodeIntel, function, arguments, @code_intel_erpc_timeout)
        )
      end
    end)
  end

  # The pool's own defaults are longer than a gateway method may wait, so every gateway
  # call states its bounds rather than inheriting them.
  defp code_intel_opts(workspace, extra \\ []) do
    [
      workspace_root: workspace,
      wait_ready_ms: @code_intel_wait_ready_ms,
      request_timeout_ms: @code_intel_request_timeout_ms
    ] ++ Enum.reject(extra, fn {_key, value} -> is_nil(value) end)
  end

  # Carried as the caller typed it and canonicalised on the *target* node, because a path
  # is only meaningful where the files are. It narrows the marker walk and can never widen
  # it: `CodeIntel.Registry` holds an explicit workspace to the same admitted-roots check
  # as an implicit one, so naming `/` here is refused rather than obeyed.
  defp code_intel_workspace(params), do: fetch_string(params, "workspace")

  defp code_intel_operation(params) do
    case Map.get(params, "operation") do
      value when is_binary(value) ->
        case Enum.find(CodeIntel.operations(), &(Atom.to_string(&1) == value)) do
          nil -> {:invalid, code_intel_operation_message()}
          operation -> {:ok, operation}
        end

      _other ->
        {:invalid, code_intel_operation_message()}
    end
  end

  defp code_intel_operation_message do
    "params.operation must be one of " <>
      (CodeIntel.operations() |> Enum.map(&Atom.to_string/1) |> Enum.sort() |> Enum.join(", "))
  end

  defp code_intel_action(params) do
    case Map.get(params, "action") do
      "open" -> {:ok, :open}
      "ensure_open" -> {:ok, :ensure_open}
      "changed" -> {:ok, :changed}
      "closed" -> {:ok, :closed}
      _other -> {:invalid, "params.action must be one of changed, closed, ensure_open, open"}
    end
  end

  defp code_intel_position(params, key) do
    case Map.get(params, key, 0) do
      value when is_integer(value) and value >= 0 -> {:ok, value}
      _other -> {:invalid, "params.#{key} must be a non-negative integer"}
    end
  end

  defp code_intel_wait_ms(params) do
    case Map.get(params, "wait_ms") do
      nil ->
        {:ok, nil}

      value when is_integer(value) and value >= 0 and value <= @code_intel_max_wait_ms ->
        {:ok, value}

      _other ->
        {:invalid, "params.wait_ms must be an integer between 0 and #{@code_intel_max_wait_ms}"}
    end
  end

  # ---------------------------------------------------------------------------
  # The effect ledger (I1/I3)
  # ---------------------------------------------------------------------------

  defp ledger_call(target, function, arguments) do
    safe(fn ->
      if target == node() do
        reply(apply(EffectLedger, function, arguments))
      else
        reply(:erpc.call(target, EffectLedger, function, arguments, @fleet_query_timeout))
      end
    end)
  end

  defp ledger_filters(params) do
    with {:ok, principal} <- fetch_optional_string(params, "principal"),
         {:ok, effect} <- ledger_effect(params),
         {:ok, status} <- ledger_status(params),
         {:ok, since} <- ledger_since_sequence(params),
         {:ok, order} <- ledger_order(params),
         {:ok, limit} <- ledger_limit(params) do
      {:ok,
       [
         principal: principal,
         effect: effect,
         status: status,
         since_sequence: since,
         order: order,
         limit: limit
       ]
       |> Enum.reject(fn {key, value} ->
         is_nil(value) and key in [:principal, :effect, :status]
       end)}
    end
  end

  defp ledger_effect(params), do: ledger_atom(params, "effect", EffectLedger.effects())
  defp ledger_status(params), do: ledger_atom(params, "status", EffectLedger.statuses())

  # Matched by string against terms that already exist, never converted. Same rule the
  # provider and node parameters follow.
  defp ledger_atom(params, key, allowed) do
    case Map.get(params, key) do
      nil ->
        {:ok, nil}

      value when is_binary(value) ->
        case Enum.find(allowed, &(Atom.to_string(&1) == value)) do
          nil -> {:invalid, ledger_atom_message(key, allowed)}
          term -> {:ok, term}
        end

      _other ->
        {:invalid, ledger_atom_message(key, allowed)}
    end
  end

  defp ledger_atom_message(key, allowed) do
    "params.#{key} must be one of " <>
      (allowed |> Enum.map(&Atom.to_string/1) |> Enum.sort() |> Enum.join(", "))
  end

  defp ledger_since_sequence(params) do
    case Map.get(params, "since_sequence", 0) do
      value when is_integer(value) and value >= 0 -> {:ok, value}
      _other -> {:invalid, "params.since_sequence must be a non-negative integer"}
    end
  end

  defp ledger_since(params) do
    case Map.get(params, "since", 0) do
      value when is_integer(value) and value >= 0 -> {:ok, value}
      _other -> {:invalid, "params.since must be a non-negative integer"}
    end
  end

  defp ledger_order(params) do
    case Map.get(params, "order", "desc") do
      "desc" -> {:ok, :desc}
      "asc" -> {:ok, :asc}
      _other -> {:invalid, "params.order must be asc or desc"}
    end
  end

  defp ledger_limit(params) do
    limits = EffectLedger.query_limits()

    case Map.get(params, "limit", limits.default) do
      value when is_integer(value) and value >= 1 and value <= limits.max ->
        {:ok, value}

      _other ->
        {:invalid, "params.limit must be an integer between 1 and #{limits.max}"}
    end
  end

  defp ledger_fleet(params) do
    case Map.get(params, "fleet", false) do
      value when is_boolean(value) -> {:ok, value}
      _other -> {:invalid, "params.fleet must be a boolean"}
    end
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
          {:ok, [%{sequence: ^sequence} = event]} -> {:ok, Encode.detail(event)}
          {:ok, _window} -> not_found("that session retains no event at sequence #{sequence}")
          other -> reply(other)
        end
      end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  defp fetch_sequence(params) do
    case Map.get(params, "sequence") do
      sequence when is_integer(sequence) and sequence > 0 -> {:ok, sequence}
      _other -> {:invalid, "params.sequence must be a positive integer"}
    end
  end

  defp with_session(params, plane, fun) do
    with {:ok, session} <- session_target(plane, params) do
      fun.(session)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  # A closed answer, and `verified` is not derivable from `divergence` being absent on the
  # client side alone — a bounded record is *not* verified and still names no divergence in
  # the diverged sense, so the boolean is stated rather than implied.
  defp replay_verdict(verdict) do
    %{
      "verified" => verdict.verified == true,
      "turns" => verdict.turns,
      "records" => verdict.records,
      "head" => verdict.head,
      "divergence" => Replay.describe(verdict.divergence)
    }
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

  # A rewind target is a turn id or a non-negative turn ordinal, exactly what the native
  # session's `rewind_points` hands back.
  defp fetch_rewind_target(params, key) do
    case Map.get(params, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      value when is_integer(value) and value >= 0 -> {:ok, value}
      _other -> {:invalid, "params.#{key} must be a turn id or a non-negative turn number"}
    end
  end

  # The same target where naming none is a legitimate answer: `interactive.fork` without a
  # `to_turn` branches at the tail, which is what it has always done.
  defp fetch_optional_rewind_target(params, key) do
    if Map.has_key?(params, key), do: fetch_rewind_target(params, key), else: {:ok, nil}
  end

  # `interactive.start` validates `model` through `option_value/3`'s `:string`, which
  # refuses a whitespace-only spec rather than passing it to a resolver. A fork's `model`
  # is the same option reaching the same place, so it is held to the same rule instead of
  # `fetch_optional_string/2`'s slightly looser one.
  defp fetch_optional_option_string(params, key) do
    if Map.has_key?(params, key),
      do: option_value(key, :string, Map.get(params, key)),
      else: {:ok, nil}
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
    Application.get_env(:ouroboros, :account_adapter, OpenAIAuth)
  end

  defp grok_account_adapter do
    Application.get_env(:ouroboros, :grok_account_adapter, GrokAuth)
  end

  defp anthropic_key_adapter do
    Application.get_env(:ouroboros, :anthropic_key_adapter, AnthropicKey)
  end

  defp xai_key_adapter do
    Application.get_env(:ouroboros, :xai_key_adapter, XAIKey)
  end

  defp fetch_api_key(params, key) do
    case Map.get(params, key) do
      value when is_binary(value) ->
        value = String.trim(value)

        cond do
          value == "" ->
            {:invalid, "params.#{key} must be a nonempty string"}

          byte_size(value) > 8 * 1024 ->
            {:invalid, "params.#{key} must be at most 8192 bytes"}

          String.contains?(value, ["\n", "\r", "\0", "\t", " "]) ->
            {:invalid, "params.#{key} must not contain whitespace or control characters"}

          true ->
            {:ok, value}
        end

      _other ->
        {:invalid, "params.#{key} must be a nonempty string"}
    end
  end

  defp fetch_optional_api_key(params, key) do
    case Map.fetch(params, key) do
      :error -> {:ok, nil}
      {:ok, _value} -> fetch_api_key(params, key)
    end
  end

  defp fetch_optional_workspace_id(params, key) do
    case Map.fetch(params, key) do
      :error ->
        {:ok, :keep}

      {:ok, value} when value in [nil, ""] ->
        {:ok, :clear}

      {:ok, value} when is_binary(value) ->
        workspace_id = String.trim(value)

        cond do
          workspace_id == "" ->
            {:ok, :clear}

          byte_size(workspace_id) > 256 ->
            {:invalid, "params.#{key} must be at most 256 bytes"}

          not Regex.match?(~r/\Awrkspc_[A-Za-z0-9]+\z/, workspace_id) ->
            {:invalid, "params.#{key} must be a wrkspc_-prefixed Anthropic workspace id"}

          true ->
            {:ok, workspace_id}
        end

      {:ok, _value} ->
        {:invalid, "params.#{key} must be a string, empty to clear, or omitted"}
    end
  end

  defp require_anthropic_update(nil, :keep),
    do: {:invalid, "params must include api_key or workspace_id"}

  defp require_anthropic_update(_api_key, _workspace_id), do: :ok

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

  # R1's cursor. Named apart from `cursor` because it counts journal records rather than
  # events, and the two sequences are different numbers over the same session.
  defp fetch_since_seq(params) do
    case Map.get(params, "since_seq", 0) do
      value when is_integer(value) and value >= 0 -> {:ok, value}
      _other -> {:invalid, "params.since_seq must be a non-negative integer"}
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

  @doc false
  defdelegate turn_error_reply(reason), to: Safe

  @doc """
  The hash chain over an ordered run of ledger entries, as `ledger.export` answers it.

  Each line is the exact text whose bytes its hash covers:
  `hash(n) = sha256(hash(n-1) || line(n))`, with `hash(-1)` the published seed and every
  hash the lowercase hex of 32 bytes. A client verifies an export by hashing the strings
  it was handed, in order — no agreement about how to re-encode an entry is needed, which
  is the only reason the claim is checkable at all.

  Public because the golden fixture is derived through it: a change to the chain has to
  show up as a fixture diff a reviewer signs off on, not as a silent change to what a
  client is verifying.
  """
  @spec chain([EffectLedger.Entry.t()]) :: map()
  defdelegate chain(entries), to: Encode
end
