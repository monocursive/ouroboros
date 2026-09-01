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
  alias Ouroboros.Gateway.Methods.Encode
  alias Ouroboros.Gateway.Methods.Placement
  alias Ouroboros.Gateway.Methods.Present
  alias Ouroboros.Gateway.Methods.Safe
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

  @default_timeout 15_000

  # Permissions, MCP, and ledger get share this bound on owner-routed `:erpc`.
  @fleet_query_timeout 5_000

  # E2/E3. Code intelligence is the one read whose upstream is a foreign OS process, and
  # its own defaults are generous on purpose: `initialize_timeout_ms` is 45s because
  # ElixirLS and jdtls compile the world on first launch. A gateway method cannot wait
  # that long, so these three numbers replace the pool's defaults on every gateway call
  # and are chosen to sum below the 15s ceiling — a cold server is answered "not ready
  # yet", which is an honest answer a caller can retry, rather than a killed task.
  @code_intel_wait_ready_ms 5_000
  @code_intel_request_timeout_ms 8_000
  @code_intel_max_wait_ms 10_000
  @code_intel_erpc_timeout 14_000

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

  # `interactive.request_approval` waits for a person. Fifteen minutes is the stated
  # ceiling: long enough that stepping away from the terminal is not a denial, short
  # enough that a forgotten prompt does not hold a gateway task open for a shift.
  @approval_prompt_timeout 15 * 60 * 1_000

  # G1. One `interactive.delegate` may make two team calls, each bounded at 60s by
  # `Team.control_call/2`, plus the parent's own checkpoint. Below the sum on purpose: a
  # delegation that has taken this long has a team that is not answering, and the caller
  # learns which from `teams.state` rather than by waiting out both bounds.
  @delegate_timeout 90_000

  # B7. One operator command, and the same number `Ouroboros.Workspace.Exec` stops it at.
  # A ceiling below the runner's would kill the gateway task while the command kept
  # running, and the entry it started would be settled by nobody.
  @shell_timeout 10 * 60 * 1_000

  # D9. A compaction that has to summarise makes one model call on the session's own
  # model with no tools. That is provider latency, not control-plane latency, so it gets
  # a ceiling of its own — well above the default and well below a start's.
  @compaction_timeout 120_000

  # Preview and admit run the forge build peer (60s default) and, for admit, a rollout.
  # Keep the gateway ceiling above that so a named forge refusal wins over -32005.
  @forge_timeout 120_000

  # R2. Verified replay re-derives a whole session: one `Loop.run_turn/2` per recorded turn,
  # each rebuilding the cached prefix from the workspace (instruction files, the tool
  # schemas) and re-digesting the conversation. There is no provider latency in any of it —
  # the model is a recording — so the cost is local CPU and local reads, and it scales with
  # how long the session was. Two minutes is chosen the way `@compaction_timeout` is: well
  # above what any session an operator would ask about takes, and well below a ceiling that
  # would let one call hold a gateway task for a shift. A session too long to verify inside
  # it is a real answer — that session needs an offline verifier, not a longer socket.
  @replay_verify_timeout 120_000

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
    # A3/F3. What `llm_db` knows about the models each configured provider draws from —
    # the window and the price a client needs to turn a session's `usage` into a context
    # percentage and a cost. Read scope: it consults a packaged snapshot and the node's
    # own provider configuration, and starts nothing.
    "runtime.models" => %{scope: :read, timeout: @default_timeout},
    "fleet.status" => %{scope: :read, timeout: @default_timeout},
    "fleet.doctor" => %{scope: :read, timeout: @default_timeout},
    "account.read" => %{scope: :read, timeout: @default_timeout},
    "grok.account.read" => %{scope: :read, timeout: @default_timeout},
    "agents.list" => %{scope: :read, timeout: @default_timeout},
    "agents.state" => %{scope: :read, timeout: @default_timeout},
    "interactive.list" => %{scope: :read, timeout: @default_timeout},
    "interactive.info" => %{scope: :read, timeout: @default_timeout},
    "interactive.replay" => %{scope: :read, timeout: @default_timeout},
    # One event, whole. It is `replay` with a window of one — same plane call, same
    # routing, same ceiling — so the only thing that makes it a separate method is the
    # larger per-leaf byte cap it encodes the answer under.
    "interactive.event_detail" => %{scope: :read, timeout: @default_timeout},
    # R1. The native session's turn journal — the replay substrate, and a different record
    # from the event stream `replay` above serves: events are what a client renders, this
    # is what the session *was*. Read scope by the same dividing line as everything else in
    # this block: it reads one file and starts nothing.
    "interactive.journal" => %{scope: :read, timeout: @default_timeout},
    # D9. What a session can honestly say about its own context window. Read scope: it
    # asks a live transport a question and starts nothing.
    "interactive.context" => %{scope: :read, timeout: @default_timeout},
    # G1. What this conversation delegated, with the status the team currently holds.
    "interactive.delegations" => %{scope: :read, timeout: @default_timeout},
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
    # The permission engine is node-local like every other authority here, so these three
    # route to the machine whose rules they describe. Reading is `read`; writing a rule
    # widens or narrows what a session may do without a human present, so it is `operate`.
    "permissions.list" => %{scope: :read, timeout: @default_timeout},
    # ---------------------------------------------------------------------------------
    # E2/E3/I3. Code intelligence and the effect ledger, on the wire.
    #
    # Every one of these is `:read` except `code_intel.touch`, and the split is the same
    # one the rest of this table makes: reading what a language server or the ledger
    # already knows changes nothing, while telling a language server that a file moved
    # spends this node's memory on a document a caller chose. Reads route to the node that
    # owns the workspace or the entries, because both authorities are node-local — a pool
    # runs where the files are (D7) and a ledger where the effect ran (I3) — and a remote
    # answer is a bounded `:erpc` so an unreachable machine reads as unreachable rather
    # than as a gateway ceiling with no detail.
    # ---------------------------------------------------------------------------------
    "runtime.lsp.status" => %{scope: :read, timeout: @default_timeout},
    "code_intel.request" => %{scope: :read, timeout: @default_timeout},
    "code_intel.diagnostics" => %{scope: :read, timeout: @default_timeout},
    "ledger.list" => %{scope: :read, timeout: @default_timeout},
    "ledger.get" => %{scope: :read, timeout: @default_timeout},
    "ledger.export" => %{scope: :read, timeout: @default_timeout},
    # ---------------------------------------------------------------------------------
    # D4. MCP servers on the wire.
    #
    # `:read` for the same reason `runtime.lsp.status` is: this projects what a node's
    # pool already holds and starts nothing. Node-routed, because an MCP server runs
    # where its session runs — the pool is keyed by workspace and lives on the machine
    # that owns it — so a fleet answer is one call per machine, not a merged view this
    # node could invent. There is no `mcp.add`: a server definition is code that runs on
    # somebody's machine, and it is declared in node configuration or in a file an
    # operator wrote, never authored over a socket.
    # ---------------------------------------------------------------------------------
    "mcp.list" => %{scope: :read, timeout: @default_timeout},
    "computer_use.status" => %{scope: :read, timeout: @default_timeout},
    "computer_use.artifact" => %{scope: :read, timeout: @default_timeout},
    # Starts the helper so `ouro desktop doctor` can report TCC. Status stays start-nothing.
    "computer_use.probe" => %{scope: :operate, timeout: @default_timeout},
    "code_intel.touch" => %{scope: :operate, timeout: @default_timeout},
    # This is intentionally not coupled to invitation cancellation. It is the explicit
    # state-loss boundary that lets an operator retire durable session-owner evidence
    # only after a roster tombstone is present and the machine is offline. The tombstone
    # lives in the local fleet profile, which the client rebuilds only from a roster whose
    # signature it verified at import; this node trusts that profile and does not verify.
    "fleet.forget_session_owner" => %{scope: :operate, timeout: @default_timeout},
    # Session ids are caller-owned and both planes reconcile the same immutable intent.
    # A ceiling can fire after durable creation, so never imply that minting a second id
    # is safe merely because the gateway stopped waiting.
    "permissions.add" => %{scope: :operate, timeout: @default_timeout},
    "permissions.remove" => %{scope: :operate, timeout: @default_timeout},
    "interactive.start" => %{scope: :operate, timeout: @start_timeout, outcome: :unknown},
    "account.login.start" => %{scope: :operate, timeout: @default_timeout},
    "account.login.complete" => %{scope: :operate, timeout: @default_timeout},
    "account.login.cancel" => %{scope: :operate, timeout: @default_timeout},
    "account.logout" => %{scope: :operate, timeout: @default_timeout},
    "grok.account.login.start" => %{scope: :operate, timeout: @default_timeout},
    "grok.account.login.cancel" => %{scope: :operate, timeout: @default_timeout},
    # A credential value crosses this boundary once and is never returned. Operate scope
    # is the same authority that may start paid work; read links cannot re-key the node.
    "credentials.anthropic.set" => %{scope: :operate, timeout: @default_timeout},
    "credentials.xai.set" => %{scope: :operate, timeout: @default_timeout},
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
    # B1/B6. Session controls that change an open session rather than starting a new one.
    # `configure` is bounded by what the transport declares it can still change and
    # answers with when the change takes hold. `:operate` because it writes durable
    # session state and moves a permission posture.
    "interactive.configure" => %{scope: :operate, timeout: @default_timeout},
    # A title is durable session state a person chose, so it is `:operate` for the same
    # reason `configure` is, and bounded at the boundary because it lands on every list row.
    "interactive.rename" => %{scope: :operate, timeout: @default_timeout},
    # A fork starts a session, so it inherits `interactive.start`'s ceiling and the same
    # admission: a gateway timeout here cannot prove the child was not created, and the
    # caller-owned `id` is what makes reconciling it possible rather than guesswork.
    "interactive.fork" => %{scope: :operate, timeout: @start_timeout, outcome: :unknown},
    # D9. The three context verbs. `compact` and `handoff` move a session's conversation
    # and are therefore `:operate`; `context` reads what the session already knows and
    # starts nothing, so it sits with the other reads. `handoff` starts a session, so it
    # inherits `interactive.start`'s ceiling and its outcome admission.
    "interactive.compact" => %{scope: :operate, timeout: @compaction_timeout},
    # D6. Rewind restores files byte-exact from the native session's own checkpoints and
    # truncates its conversation; it is the native transport's verb and refused elsewhere.
    "interactive.rewind" => %{scope: :operate, timeout: @compaction_timeout},
    "interactive.rewind_points" => %{scope: :read, timeout: @default_timeout},
    # R2. Verified replay. `:operate` rather than `:read` by the dividing line this table
    # already draws at `computer_use.status`/`probe`: it starts a process — a real turn loop
    # per recorded turn — even though it spends no tokens, executes no tool and writes
    # nothing. Its own ceiling, because a long session re-derives many turns.
    "interactive.replay_verify" => %{scope: :operate, timeout: @replay_verify_timeout},
    # B7. The operator's own shell, in the session's admitted workspace, on its owner
    # node. `:operate` and nothing less: it runs a command. The ceiling is the runner's
    # own — ten minutes — because the gateway killing the task would leave a ledger entry
    # nobody settles, and `Exec` already stops the command at the same number.
    "workspace.exec" => %{scope: :operate, timeout: @shell_timeout, outcome: :unknown},
    # D11. One directory listing, so a client that has to choose a workspace before it can
    # start a session does not need a second channel to the disk. `:operate` even though it
    # writes nothing and starts nothing: this exists to start sessions, and a listener held
    # at `read` scope is one that was not trusted to. The ceiling is the default because the
    # work is one `readdir` and one `lstat` per name on a local filesystem.
    "workspace.browse" => %{scope: :operate, timeout: @default_timeout},
    # G1. A delegation is a coding task with a parent, started through the workspace's
    # default team. `:operate` because it starts work, and the ceiling is the team's own
    # (`teams.add_worker` and `teams.delegate` each bound themselves at 60s, and this verb
    # may make both calls). A ceiling that fires cannot prove the child was not created,
    # which is why the delegation's id is caller-owned.
    "interactive.delegate" => %{scope: :operate, timeout: @delegate_timeout, outcome: :unknown},
    "interactive.handoff" => %{scope: :operate, timeout: @start_timeout, outcome: :unknown},
    "interactive.steer" => %{scope: :operate, timeout: @default_timeout},
    # C2. The one method whose latency is a person's: it asks the session's owner for a
    # decision and holds the request open until a human answers, the permission engine
    # answers for them, or the coordinator's own deadline passes. Fifteen minutes is the
    # documented ceiling and the outermost of three — the coordinator denies at thirteen
    # and the plane's transport stops waiting at fourteen — so a client that reaches this
    # number has learned that its own runtime stopped answering, not that the tool ran.
    "interactive.request_approval" => %{scope: :operate, timeout: @approval_prompt_timeout},
    "interactive.respond_approval" => %{scope: :operate, timeout: @default_timeout},
    "interactive.interrupt" => %{scope: :operate, timeout: @default_timeout},
    "interactive.close" => %{scope: :operate, timeout: @default_timeout},
    "interactive.kill" => %{scope: :operate, timeout: @default_timeout},
    "interactive.delete" => %{scope: :operate, timeout: @default_timeout},
    "coding.start" => %{scope: :operate, timeout: @start_timeout, outcome: :unknown},
    "coding.respond_approval" => %{scope: :operate, timeout: @default_timeout},
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

  @reasoning_efforts %{
    "none" => :none,
    "low" => :low,
    "medium" => :medium,
    "high" => :high,
    "xhigh" => :xhigh,
    "max" => :max
  }

  @approval_decisions %{"approve" => :approve, "deny" => :deny}
  @approval_scopes %{"once" => :once, "session" => :session}
  # The one shape of `provider_options` an answer may carry: a plan-exit question's
  # explicit choice and the follow-up prompt that runs once the session is out of plan
  # mode (B2). Anything else under that key is still refused — an approval is a yes or a
  # no, and this is the narrowest door a plan-aware client needs.
  @plan_exit_choices ["auto_edit", "prompt", "keep_planning"]
  @max_follow_up_bytes 32 * 1024
  @approval_response_param {"response", :required,
                            {:either,
                             [
                               {:enum_of, @approval_decisions},
                               {:object,
                                [
                                  {"decision", :required, {:enum_of, @approval_decisions}, nil},
                                  {"scope", {:optional, "once"}, {:enum_of, @approval_scopes},
                                   "`session` additionally writes a session-scoped rule from the pattern the request suggested"},
                                  {"reason", :optional, :string, nil},
                                  {"actor", {:optional, "human"},
                                   {:enum, ["human", "headless", "automation"]},
                                   "who answered; the durable approval record preserves it"},
                                  {"provider_options", :optional,
                                   {:object,
                                    [
                                      {"choice", :optional, {:enum, @plan_exit_choices},
                                       "a plan-exit question's explicit answer"},
                                      {"follow_up", :optional, :string,
                                       "the bounded prompt to run after leaving plan mode"}
                                    ]}, "accepted only for a plan-exit answer"}
                                ]}
                             ]}, "an approval is a yes or a no"}

  # The permission engine's own vocabulary, spelled out for the same reason as the rest:
  # a client string is matched against these terms, never converted into one.
  @permission_scopes %{
    "node" => :node,
    "user" => :user,
    "workspace" => :workspace,
    "session" => :session
  }

  # What `permissions.add` may write. `:node` is operator configuration, read from
  # `config :ouroboros, :permissions` and never authored over the wire. `:session` is a
  # session's own "don't ask again" — it is written by answering an approval, and giving
  # an operator a verb to mint one for a session they are not in would be a different
  # thing wearing the same name.
  @permission_rule_scopes %{"user" => :user, "workspace" => :workspace}

  # Removal reaches one scope further, because cleaning up after a session that remembered
  # something is a real operator need.
  @permission_removable_scopes Map.put(@permission_rule_scopes, "session", :session)

  @permission_decisions %{"allow" => :allow, "deny" => :deny, "ask" => :ask}

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
    # D7. Both planes already carry `worktree_requested` durably and provision before the
    # lease; this is the option that lets `ouro new --worktree` reach it. Deliberately not
    # in `@configuration_options`: a session cannot be moved into a worktree after its
    # workspace has been admitted and leased.
    "worktree" => :boolean,
    # B2. Start planning: a read-only posture with a plan-exit question at the end of the
    # turn. Which transports can be told is `Ouroboros.Provider.plan_mode/2`'s answer.
    "plan" => :boolean,
    "machine" => :node,
    "node" => :node
  }

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
  @configuration_options %{
    "approval_mode" => {:enum, @approval_modes},
    "sandbox_mode" => {:enum, @sandbox_modes},
    "model" => :string,
    "reasoning_effort" => {:enum, @reasoning_efforts},
    "plan" => :boolean,
    "mode" => :string
  }

  # `Ouroboros.Team.Server` accepts exactly these two for a worker.
  @worker_options %{"role" => :string, "node" => :node}

  @delegation_options %{
    "id" => :string,
    "coding_node" => :node,
    "workspace" => :string,
    "provider" => :provider
  }

  # What `interactive.delegate` may name. A strict subset of `@delegation_options`:
  # `coding_node` is absent because the child runs where the conversation does, and the
  # delegation's own `id` is a positional argument rather than an option.
  @interactive_delegation_options %{"workspace" => :string, "provider" => :provider}

  @control_options %{"id" => :string, "max_revisions" => :non_negative_integer}

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

  @start_option_notes %{
    "id" =>
      "caller-owned; a matching retry adopts the same immutable intent and a conflicting reuse is refused",
    "machine" => "an alias of `node` — provide one or the other, never both",
    "workspace" =>
      "required, and absolute, when `machine`/`node` selects a machine other than this one",
    "worktree" => "provisions a `git worktree` under the data directory before the lease is taken"
  }

  @start_params for {name, kind} <- Enum.sort(@start_options),
                    do: {name, :optional, kind, Map.get(@start_option_notes, name)}

  @configuration_option_notes %{
    "mode" =>
      "the *agent's* own mode id, validated against the `availableModes` it published; refused by name on a transport whose dialect declares none",
    "plan" => "not a Harness configuration key — it takes its own per-transport path (B2)"
  }

  @configuration_params for {name, kind} <- Enum.sort(@configuration_options),
                            do:
                              {name, :optional, kind, Map.get(@configuration_option_notes, name)}

  @worker_params for {name, kind} <- Enum.sort(@worker_options),
                     do:
                       {name, :optional, kind,
                        if(name == "node", do: "the machine the worker runs on", else: nil)}

  @delegation_params for {name, kind} <- Enum.sort(@delegation_options),
                         do:
                           {name, :optional, kind,
                            if(name == "id", do: "caller-owned delegation id", else: nil)}

  @interactive_delegation_params for {name, kind} <-
                                       Enum.sort(@interactive_delegation_options),
                                     do:
                                       {name, :optional, kind,
                                        "defaults to the conversation's own"}

  @control_params for {name, kind} <- Enum.sort(@control_options),
                      do: {name, :optional, kind, nil}

  # The routing pair every plane verb carries: which session, and which machine owns it.
  @session_id {"id", :required, :string, "the interactive session id"}
  @session_node {"node", :optional, :node,
                 "the machine that owns the session; this one by default"}
  @task_id {"id", :required, :string, "the coding task id"}
  @task_node {"node", :optional, :node, "the machine that owns the task; this one by default"}
  @authority_node {"node", :optional, :node,
                   "the machine whose authority answers; this one by default"}

  @cursor_param {"cursor", {:optional, 0}, :non_negative_integer,
                 "exclusive — the window starts at the next sequence"}
  @limit_param {"limit", {:optional, @default_replay_limit}, {:integer, 1, @replay_limit}, nil}
  @sequence_param {"sequence", :required, :positive_integer,
                   "the exact sequence; a gap answers `-32007` rather than the next event that exists"}
  @ledger_limit_param {"limit", :optional, {:limits, {EffectLedger, :query_limits, []}},
                       "the ledger's own bound, not this table's"}

  @turn_input_param {"input", :required,
                     {:either,
                      [
                        :string,
                        {:object,
                         [
                           {"prompt", :required, :string, nil},
                           {"attachments", :optional, {:list, :string, 32},
                            "each must be an existing regular file the leased workspace contains"},
                           {"reasoning_effort", :optional, {:enum_of, @reasoning_efforts}, nil}
                         ]}
                      ]}, nil}
  @turn_id_param {"turn_id", :optional, :string,
                  "caller-supplied; resending the same `{id, input, turn_id}` returns the same turn rather than starting a second"}

  @params %{
    "hello" =>
      {:open,
       [
         {"token", :required, :string,
          "compared against the listener's token by SHA-256 digest, so neither length nor content leaks"},
         {"protocol", :required, {:const, 1},
          "anything else is `-32002` carrying `{\"server_protocol\": 1}`, and the socket closes"},
         {"client", :optional, :string,
          "a display name for the audit line, cut to 120 characters"}
       ]},
    "runtime.status" => {:open, []},
    "runtime.providers" => {:open, []},
    "runtime.models" => {:open, []},
    "runtime.lsp.status" => {:open, []},
    "runtime.shutdown" =>
      {:open, [],
       "answered by the connection, which requires `OUROBOROS_GATEWAY_ALLOW_SHUTDOWN=1` on top of operate scope"},
    "fleet.status" => {:open, []},
    "fleet.doctor" => {:open, []},
    "fleet.forget_session_owner" =>
      {:closed,
       [
         {"machine", :required, :string,
          "must appear in the validated local profile's roster tombstones, and must be offline"},
         {"accept_state_loss", :required, {:const, true},
          "anything else is refused: this retires durable session-owner evidence"}
       ]},
    "account.read" => {:closed, []},
    "account.login.start" =>
      {:closed, [{"flow", {:optional, "browser"}, {:enum, ["browser", "device_code"]}, nil}]},
    "account.login.complete" =>
      {:closed,
       [
         {"login_id", :required, :string, "the loginId returned by account.login.start"},
         {"code", :required, :string, "the OAuth authorization code"},
         {"state", :required, :string, "the OAuth state returned to the callback"}
       ]},
    "account.login.cancel" =>
      {:closed,
       [{"login_id", :required, :string, "correlates with the `loginId` the start reply carried"}]},
    "account.logout" => {:closed, []},
    "grok.account.read" => {:closed, []},
    "grok.account.login.start" =>
      {:closed, [],
       "starts `grok login --device-auth`; the first-party CLI owns and refreshes every subscription token"},
    "grok.account.login.cancel" =>
      {:closed,
       [{"login_id", :required, :string, "the loginId returned by grok.account.login.start"}]},
    "credentials.anthropic.set" =>
      {:closed,
       [
         {"api_key", {:optional, nil}, :string,
          "replaces the privately stored key; may be omitted when updating an existing stored credential"},
         {"workspace_id", {:optional, nil}, :string,
          "`wrkspc_`-prefixed workspace for an identity-linked key; may be omitted for a single-workspace key"}
       ],
       "updates the node-owned Anthropic credential without returning it; `ANTHROPIC_API_KEY` and `ANTHROPIC_WORKSPACE_ID` still take precedence"},
    "credentials.xai.set" =>
      {:closed, [{"api_key", :required, :string, "replaces the privately stored xAI API key"}],
       "updates the node-owned xAI API key without returning it; `XAI_API_KEY` still takes precedence"},
    "agents.list" => {:open, []},
    "agents.state" => {:open, [{"id", :required, :string, "the agent id"}]},
    "agents.stop" => {:open, [{"id", :required, :string, "the agent id"}]},
    "interactive.list" => {:open, []},
    "interactive.info" => {:closed, [@session_id, @session_node]},
    "interactive.replay" => {:closed, [@session_id, @cursor_param, @limit_param, @session_node]},
    "interactive.event_detail" => {:closed, [@session_id, @sequence_param, @session_node]},
    "interactive.journal" =>
      {:closed,
       [
         @session_id,
         {"since_seq", {:optional, 0}, :non_negative_integer,
          "exclusive — the window starts at the next journal sequence"},
         @limit_param,
         @session_node
       ], "native sessions only; every other transport answers `-32006`"},
    "interactive.replay_verify" =>
      {:closed, [@session_id, @session_node],
       "native sessions only; every other transport answers `-32006`. Re-runs the recorded " <>
         "turns through the real turn loop and answers `{verified, turns, records, head, " <>
         "divergence}`. `divergence` is `null`, a `diverged` object naming the record and " <>
         "the field that stopped agreeing, or a `boundary` object naming why verification " <>
         "stops there — `turns` counts what verified either way"},
    "interactive.context" => {:closed, [@session_id, @session_node]},
    "interactive.delegations" => {:closed, [@session_id, @session_node]},
    "interactive.subscribe" =>
      {:closed, [@session_id, @cursor_param, @session_node],
       "answered by the connection itself, because the plane registers the calling process"},
    "interactive.unsubscribe" => {:closed, [@session_id, @session_node]},
    "coding.list" => {:open, []},
    "coding.info" => {:closed, [@task_id, @task_node]},
    "coding.replay" => {:closed, [@task_id, @cursor_param, @limit_param, @task_node]},
    "coding.event_detail" => {:closed, [@task_id, @sequence_param, @task_node]},
    "coding.subscribe" =>
      {:closed, [@task_id, @cursor_param, @task_node],
       "answered by the connection itself, because the plane registers the calling process"},
    "coding.unsubscribe" => {:closed, [@task_id, @task_node]},
    "teams.list" => {:open, []},
    "teams.state" => {:open, [{"id", :required, :string, "the team id"}]},
    "plans.list" => {:open, []},
    "plans.get" => {:open, [{"id", :required, :string, "the plan id"}]},
    "control.list" => {:open, []},
    "control.get" => {:open, [{"id", :required, :string, "the control run id"}]},
    "upgrade.status" => {:open, []},
    "upgrade.rollouts" => {:open, []},
    "upgrade.history" =>
      {:open,
       [
         {"module", :required, :string,
          "a module this node has loaded, with or without the `Elixir.` prefix; an unknown name is `-32602`, never a new atom"}
       ]},
    "signing.decisions" => {:open, []},
    "grants.list" =>
      {:open,
       [{"principal", :required, :string, "per-principal by design; there is no list-all"}]},
    "permissions.list" =>
      {:closed,
       [
         {"scope", :optional, {:enum_of, @permission_scopes}, nil},
         {"workspace", :optional, :string, nil},
         @authority_node
       ]},
    "permissions.add" =>
      {:closed,
       [
         {"scope", :required, {:enum_of, @permission_rule_scopes},
          "`node` rules come from `config :ouroboros, :permissions` and are never written over the wire"},
         {"pattern", :required, :string,
          "validated by `Control.Permissions.Pattern` and by nothing else"},
         {"decision", :required, {:enum_of, @permission_decisions}, nil},
         {"workspace", :optional, :string, "required for a `workspace` rule"},
         @authority_node
       ]},
    "permissions.remove" =>
      {:closed,
       [
         {"scope", :required, {:enum_of, @permission_removable_scopes}, nil},
         {"id", :required, :string, "an unknown id is `-32007`"},
         @authority_node
       ]},
    "code_intel.request" =>
      {:closed,
       [
         {"workspace", :required, :string,
          "narrows the marker walk and can never widen it; `/` is refused rather than obeyed"},
         {"operation", :required, {:enum_mfa, {CodeIntel, :operations, []}}, nil},
         {"path", :required, :string, nil},
         {"line", {:optional, 0}, :non_negative_integer, "0-based, as the protocol reports it"},
         {"character", {:optional, 0}, :non_negative_integer, "0-based"},
         {"query", :optional, :string, "for the two symbol searches"},
         @authority_node
       ]},
    "mcp.list" =>
      {:closed,
       [
         {"workspace", :optional, :string,
          "narrow the answer to the servers claimed by sessions in this workspace; every workspace by default"},
         @authority_node
       ]},
    "computer_use.status" =>
      {:closed,
       [
         @authority_node
       ]},
    "computer_use.probe" =>
      {:closed,
       [
         @authority_node
       ]},
    "computer_use.artifact" =>
      {:closed,
       [
         {"sha256", :required, :string,
          "the content hash of a staged screenshot from a tool_result artifact; served as base64 from this node only"},
         {"session_id", :optional, :string,
          "native provider session id whose desktop/ dir to search; omitted, only the live helper pool's session dirs are searched"},
         @authority_node
       ]},
    "code_intel.diagnostics" =>
      {:closed,
       [
         {"workspace", :required, :string, nil},
         {"path", :required, :string, nil},
         {"wait_ms", :optional, {:integer, 0, @code_intel_max_wait_ms},
          "how long to wait for the cache to describe the file's current content"},
         @authority_node
       ]},
    "code_intel.touch" =>
      {:closed,
       [
         {"workspace", :required, :string, nil},
         {"path", :required, :string, nil},
         {"action", :required, {:enum, ["changed", "closed", "ensure_open", "open"]},
          "`ensure_open` is the one to reach for when asking about a file; `open` re-reads it and assigns a new version"},
         @authority_node
       ]},
    "ledger.list" =>
      {:closed,
       [
         {"principal", :optional, :string, nil},
         {"effect", :optional, {:enum_mfa, {EffectLedger, :effects, []}}, nil},
         {"status", :optional, {:enum_mfa, {EffectLedger, :statuses, []}}, nil},
         {"since_sequence", {:optional, 0}, :non_negative_integer, nil},
         {"order", {:optional, "desc"}, {:enum, ["asc", "desc"]}, nil},
         @ledger_limit_param,
         @authority_node,
         {"fleet", {:optional, false}, :boolean,
          "fans out to every connected core node over the same bounded `:erpc` the `fleet.*` verbs use"}
       ]},
    "ledger.get" =>
      {:closed, [{"id", :required, :string, "an unknown id is `-32007`"}, @authority_node]},
    "ledger.export" =>
      {:closed,
       [
         {"since", {:optional, 0}, :non_negative_integer, "the first sequence to export"},
         @authority_node
       ]},
    "interactive.start" => {:closed, @start_params},
    "interactive.send_message" =>
      {:closed, [@session_id, @turn_input_param, @turn_id_param, @session_node]},
    "interactive.follow_up" =>
      {:closed, [@session_id, @turn_input_param, @turn_id_param, @session_node]},
    "interactive.steer" =>
      {:closed, [@session_id, @turn_input_param, @session_node],
       "no `turn_id`: the harness mints a steer's request id inside its own worker, so this verb has no caller-keyed idempotency"},
    "interactive.request_approval" =>
      {:closed,
       [
         @session_id,
         {"request", :required,
          {:object,
           [
             {"tool_name", :required, :string, nil},
             {"input", :optional, :object, "the tool's own arguments"},
             {"tool_use_id", :optional, :string, nil},
             {"cwd", :optional, :string, "the directory the tool would run in"}
           ]}, "a closed object; nothing else is accepted"},
         @session_node
       ]},
    "interactive.respond_approval" =>
      {:closed,
       [
         @session_id,
         {"request_id", :required, :string, "the id the `approval_requested` event carried"},
         @approval_response_param,
         @session_node
       ]},
    "interactive.configure" =>
      {:closed, [@session_id, @session_node | @configuration_params],
       "a strict subset of `interactive.start`'s options; whether any one of them is changeable is the transport's answer, asked per session"},
    "interactive.rename" =>
      {:closed,
       [
         @session_id,
         {"title", :required, :string,
          "trimmed, at most 120 graphemes, and refused rather than stripped if it holds a control character"},
         @session_node
       ]},
    "interactive.fork" =>
      {:closed,
       [
         @session_id,
         {"fork_id", :optional, :string, "caller-owned id for the child"},
         {"to_turn", :optional, :turn_target,
          "branch at the end of this turn rather than at the tail; native sessions only, and refused rather than silently widened when the parent no longer holds that boundary"},
         {"model", :optional, :string,
          "the child's model, replacing the parent's rather than inheriting it"},
         @session_node
       ]},
    "interactive.rewind" =>
      {:closed,
       [
         @session_id,
         {"to_turn", :required, :turn_target, nil},
         {"what", {:optional, "both"}, {:enum, ["both", "conversation", "files"]}, nil},
         @session_node
       ]},
    "interactive.rewind_points" => {:closed, [@session_id, @session_node]},
    "interactive.compact" =>
      {:closed,
       [
         @session_id,
         {"focus", :optional, :string, "what the fold should keep"},
         @session_node
       ]},
    "interactive.handoff" =>
      {:closed,
       [
         @session_id,
         {"prompt", :optional, :string,
          "a prompt forging the `<ouroboros-runtime>` delimiters is refused, not escaped"},
         {"handoff_id", :optional, :string, "caller-owned id for the child"},
         @session_node
       ]},
    "workspace.exec" =>
      {:closed,
       [
         @session_id,
         {"command", :required, :string,
          "run through `/bin/sh -c` in the session's admitted workspace, on its owner node"},
         @session_node
       ]},
    "workspace.browse" =>
      {:closed,
       [
         {"path", :optional, :string,
          "an absolute path inside one of `roots`; the first root by default, and a relative path is refused rather than resolved against the daemon's working directory"}
       ],
       "directories only, dotfiles excluded, name-sorted, and bounded at " <>
         "#{Browse.limit()} entries with `truncated` saying whether the list was cut"},
    "interactive.delegate" =>
      {:closed,
       [
         @session_id,
         {"objective", :required, :string, nil},
         {"delegation_id", :optional, :string,
          "caller-owned; a repeat under the same id answers with the same delegation rather than a second one"},
         @session_node | @interactive_delegation_params
       ]},
    "interactive.interrupt" =>
      {:closed,
       [
         @session_id,
         {"turn_id", :optional, :string, "the running turn by default"},
         @session_node
       ]},
    "interactive.close" => {:closed, [@session_id, @session_node]},
    "interactive.kill" => {:closed, [@session_id, @session_node]},
    "interactive.delete" => {:closed, [@session_id, @session_node], "terminal sessions only"},
    "coding.start" => {:closed, [{"objective", :required, :string, nil} | @start_params]},
    "coding.respond_approval" =>
      {:closed,
       [
         @task_id,
         {"request_id", :required, :string, "the id the approval_requested event carried"},
         @approval_response_param,
         @task_node
       ]},
    "coding.cancel" => {:closed, [@task_id, @task_node]},
    "coding.delete" => {:closed, [@task_id, @task_node], "terminal tasks only"},
    "teams.add_worker" =>
      {:closed,
       [
         {"team_id", :required, :string, "must name a team running on this node"},
         {"worker_id", :required, :string, nil} | @worker_params
       ]},
    "teams.delegate" =>
      {:closed,
       [
         {"team_id", :required, :string, "must name a team running on this node"},
         {"worker_id", :required, :string, nil},
         {"objective", :required, :string, nil} | @delegation_params
       ]},
    "teams.cancel" =>
      {:open,
       [
         {"team_id", :required, :string, "must name a team running on this node"},
         {"delegation_id", :required, :string, nil}
       ]},
    "teams.close" =>
      {:open, [{"team_id", :required, :string, "must name a team running on this node"}]},
    "control.submit" => {:closed, [{"objective", :required, :string, nil} | @control_params]},
    "control.cancel" => {:open, [{"id", :required, :string, "the control run id"}]},
    "capabilities.list" => {:closed, [{"workspace", :required, :string, nil}]},
    "capabilities.preview" =>
      {:closed, [{"workspace", :required, :string, nil}, {"path", :required, :string, nil}]},
    "capabilities.admit" =>
      {:closed,
       [
         {"workspace", :required, :string, nil},
         {"path", :required, :string, nil},
         {"session_id", :optional, :string,
          "recorded as `session:<id>` in the admission's authorship"}
       ]}
  }

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
  def params do
    Map.new(@params, fn {method, entry} -> {method, normalize_params(entry)} end)
  end

  @doc "One method's parameter contract, or `:error` if this build does not serve it."
  @spec params(String.t()) :: {:ok, map()} | :error
  def params(method) when is_binary(method) do
    case Map.fetch(@params, method) do
      {:ok, entry} -> {:ok, normalize_params(entry)}
      :error -> :error
    end
  end

  defp normalize_params({envelope, descriptors}),
    do: normalize_params({envelope, descriptors, nil})

  defp normalize_params({envelope, descriptors, note}) do
    %{envelope: envelope, note: note, params: Enum.map(descriptors, &normalize_descriptor/1)}
  end

  defp normalize_descriptor({name, requirement, type, note}) do
    %{name: name, requirement: requirement, type: type, note: note}
  end

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

  def invoke("runtime.providers", _params), do: safe(fn -> {:ok, Present.providers()} end)

  def invoke("runtime.models", _params), do: safe(fn -> {:ok, Ouroboros.Models.list()} end)

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

  def invoke("account.login.complete", params) do
    with :ok <- only_keys(params, ["login_id", "code", "state"]),
         {:ok, login_id} <- fetch_string(params, "login_id"),
         {:ok, code} <- fetch_string(params, "code"),
         {:ok, state} <- fetch_string(params, "state") do
      safe(fn -> account_reply(account_adapter().complete(login_id, code, state)) end)
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

  def invoke("grok.account.read", params) do
    with :ok <- only_keys(params, []) do
      safe(fn -> grok_account_reply(grok_account_adapter().read()) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("grok.account.login.start", params) do
    with :ok <- only_keys(params, []) do
      safe(fn -> grok_account_reply(grok_account_adapter().login()) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("grok.account.login.cancel", params) do
    with :ok <- only_keys(params, ["login_id"]),
         {:ok, login_id} <- fetch_string(params, "login_id") do
      safe(fn -> grok_account_reply(grok_account_adapter().cancel(login_id)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("credentials.anthropic.set", params) do
    with :ok <- only_keys(params, ["api_key", "workspace_id"]),
         {:ok, api_key} <- fetch_optional_api_key(params, "api_key"),
         {:ok, workspace_id} <- fetch_optional_workspace_id(params, "workspace_id"),
         :ok <- require_anthropic_update(api_key, workspace_id) do
      safe(fn -> reply(anthropic_key_adapter().configure(api_key, workspace_id)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("credentials.xai.set", params) do
    with :ok <- only_keys(params, ["api_key"]),
         {:ok, api_key} <- fetch_api_key(params, "api_key") do
      safe(fn -> reply(xai_key_adapter().put(api_key)) end)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("agents.list", _params), do: safe(fn -> reply(Mesh.list_agents()) end)

  def invoke("agents.state", params) do
    with_id(params, fn id -> safe(fn -> reply(Mesh.state(id)) end) end)
  end

  def invoke("interactive.list", _params),
    do: safe(fn -> Present.fleet_sessions(InteractiveSession) end)

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

  def invoke("interactive.journal", params) do
    with :ok <- only_keys(params, ["id", "since_seq", "limit", "node"]),
         {:ok, session} <- session_target(:interactive, params),
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
  def invoke("interactive.replay_verify", params) do
    with_session(params, :interactive, ["id", "node"], fn session ->
      safe(fn ->
        case InteractiveSession.replay_verify(session) do
          {:ok, verdict} -> {:ok, replay_verdict(verdict)}
          other -> reply(other)
        end
      end)
    end)
  end

  def invoke("coding.list", _params), do: safe(fn -> Present.fleet_sessions(CodingSession) end)

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

  def invoke("teams.list", _params), do: safe(fn -> {:ok, Present.teams()} end)

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

  def invoke("permissions.list", params) do
    with :ok <- only_keys(params, ["scope", "workspace", "node"]),
         {:ok, scope} <- permission_scope(params, "scope", @permission_scopes, :optional),
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
  def invoke("permissions.add", params) do
    with :ok <- only_keys(params, ["scope", "pattern", "decision", "workspace", "node"]),
         {:ok, scope} <- permission_scope(params, "scope", @permission_rule_scopes, :required),
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

  def invoke("permissions.remove", params) do
    with :ok <- only_keys(params, ["scope", "id", "node"]),
         {:ok, scope} <-
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
  def invoke("mcp.list", params) do
    with :ok <- only_keys(params, ["workspace", "node"]),
         {:ok, workspace} <- fetch_optional_string(params, "workspace"),
         {:ok, target} <- permissions_node(params) do
      mcp_call(target, workspaces: List.wrap(workspace))
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("computer_use.status", params) do
    with :ok <- only_keys(params, ["node"]),
         {:ok, target} <- permissions_node(params) do
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

  def invoke("computer_use.probe", params) do
    with :ok <- only_keys(params, ["node"]),
         {:ok, target} <- permissions_node(params) do
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

  def invoke("computer_use.artifact", params) do
    with :ok <- only_keys(params, ["sha256", "session_id", "node"]),
         {:ok, sha} <- fetch_string(params, "sha256"),
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
  # E2/E3 — code intelligence on the wire
  # ---------------------------------------------------------------------------

  def invoke("runtime.lsp.status", _params), do: safe(fn -> {:ok, CodeIntel.status()} end)

  def invoke("code_intel.request", params) do
    with :ok <-
           only_keys(params, [
             "workspace",
             "operation",
             "path",
             "line",
             "character",
             "query",
             "node"
           ]),
         {:ok, workspace} <- code_intel_workspace(params),
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

  def invoke("code_intel.diagnostics", params) do
    with :ok <- only_keys(params, ["workspace", "path", "wait_ms", "node"]),
         {:ok, workspace} <- code_intel_workspace(params),
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
  def invoke("code_intel.touch", params) do
    with :ok <- only_keys(params, ["workspace", "path", "action", "node"]),
         {:ok, workspace} <- code_intel_workspace(params),
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

  def invoke("ledger.list", params) do
    with :ok <-
           only_keys(params, [
             "principal",
             "effect",
             "status",
             "since_sequence",
             "order",
             "limit",
             "node",
             "fleet"
           ]),
         {:ok, filters} <- ledger_filters(params),
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

  def invoke("ledger.get", params) do
    with :ok <- only_keys(params, ["id", "node"]),
         {:ok, id} <- fetch_string(params, "id"),
         {:ok, target} <- permissions_node(params) do
      ledger_call(target, :get, [id])
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("ledger.export", params) do
    with :ok <- only_keys(params, ["since", "node"]),
         {:ok, since} <- ledger_since(params),
         {:ok, target} <- permissions_node(params) do
      Present.ledger_export(target, since)
    else
      {:invalid, message} -> invalid_params(message)
    end
  end

  def invoke("interactive.start", params) do
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

  # C2. The bridge's own verb. `ouro mcp-serve` calls it once per tool Claude Code would
  # otherwise have prompted about, and the answer it gets is the decision to relay back as
  # the permission-prompt tool's `allow`/`deny` object. Owner-routed like every other
  # session verb; the coordinator, not this module, decides.
  def invoke("interactive.request_approval", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["id", "request", "node"]),
           {:ok, session} <- session_target(:interactive, params),
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
  def invoke("interactive.configure", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["id", "node" | Map.keys(@configuration_options)]),
           {:ok, session} <- session_target(:interactive, params),
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
  def invoke("interactive.rename", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["id", "title", "node"]),
           {:ok, session} <- session_target(:interactive, params),
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
  def invoke("interactive.fork", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["id", "fork_id", "to_turn", "model", "node"]),
           {:ok, session} <- session_target(:interactive, params),
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
  def invoke("interactive.rewind", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["id", "to_turn", "what", "node"]),
           {:ok, session} <- session_target(:interactive, params),
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

  def invoke("interactive.rewind_points", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["id", "node"]),
           {:ok, session} <- session_target(:interactive, params) do
        reply(InteractiveSession.rewind_points(session))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  def invoke("interactive.compact", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["id", "focus", "node"]),
           {:ok, session} <- session_target(:interactive, params),
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
  def invoke("interactive.handoff", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["id", "prompt", "handoff_id", "node"]),
           {:ok, session} <- session_target(:interactive, params),
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
  def invoke("interactive.context", params) do
    with_session(params, :interactive, ["id", "node"], fn session ->
      safe(fn -> reply(InteractiveSession.context(session)) end)
    end)
  end

  # B7. The one verb here that runs a command. Everything that decides whether it may —
  # the session's approval mode, the permission engine, the ledger entry that has to
  # exist first — is the coordinator's, so this is only the parameter contract and the
  # routing. A refusal comes back as `["shell_refused", {reason, suggested_rule, …}]`.
  def invoke("workspace.exec", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["id", "command", "node"]),
           {:ok, session} <- session_target(:interactive, params),
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
  def invoke("workspace.browse", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["path"]),
           {:ok, path} <- fetch_optional_string(params, "path") do
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
  def invoke("interactive.delegate", params) do
    safe(fn ->
      with :ok <-
             only_keys(params, [
               "id",
               "objective",
               "delegation_id",
               "provider",
               "workspace",
               "node"
             ]),
           {:ok, session} <- session_target(:interactive, params),
           {:ok, objective} <- fetch_string(params, "objective"),
           {:ok, delegation_id} <- fetch_optional_string(params, "delegation_id"),
           {:ok, opts} <-
             options(params, @interactive_delegation_options, [
               "id",
               "objective",
               "delegation_id",
               "node"
             ]) do
        opts = if delegation_id, do: Keyword.put(opts, :id, delegation_id), else: opts
        reply(InteractiveSession.delegate(session, objective, opts))
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  # Read scope: `source` on each row says whether the status came from the team that owns
  # the delegation or from the conversation's own copy of it, so a client can tell a live
  # answer from a remembered one.
  def invoke("interactive.delegations", params) do
    with_session(params, :interactive, ["id", "node"], fn session ->
      safe(fn -> reply(InteractiveSession.delegations(session)) end)
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
        Placement.start_coding(owner, objective, opts)
      else
        {:invalid, message} -> invalid_params(message)
      end
    end)
  end

  def invoke("coding.respond_approval", params) do
    safe(fn ->
      with :ok <- only_keys(params, ["id", "request_id", "response", "node"]),
           {:ok, task} <- session_target(:coding, params),
           {:ok, request_id} <- fetch_string(params, "request_id"),
           {:ok, response} <- approval_response(params) do
        reply(CodingSession.respond_approval(task, request_id, response))
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

  defp with_session(params, plane, allowed, fun) do
    with :ok <- only_keys(params, allowed),
         {:ok, session} <- session_target(plane, params) do
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
