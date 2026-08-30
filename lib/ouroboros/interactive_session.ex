defmodule Ouroboros.InteractiveSession do
  @moduledoc """
  Durable, distribution-aware interactive coding sessions.

  The upstream Harness owns provider transports and active processes. Ouroboros
  owns durable session/turn intent, redacted replay, workspace admission, crash
  reattachment, and node-aware routing.
  """

  alias Jido.Harness.ApprovalResponse
  alias Ouroboros.Interactive.{Ref, State, Store, Task}
  alias Ouroboros.Provider.Native.Replay
  alias Ouroboros.Team
  alias Ouroboros.Workspace.Exec

  @type session :: Ref.t() | String.t()

  @turn_options [:attachments, :reasoning_effort, :output_schema, :metadata, :provider_options]

  # Control-plane operations (info/replay/subscribe/steer/respond_approval/interrupt/
  # close/kill) are bounded so one wedged coordinator cannot freeze every caller.
  # `await/3` is the deliberate exception: it threads the caller's own timeout, and the
  # transport is given that timeout plus a margin so the local waiter, not the
  # transport, decides when to stop waiting.
  @default_call_timeout 30_000
  @remote_margin_ms 5_000

  # A human approval is the one control-plane call whose latency is a person's. The three
  # ceilings are layered so that the innermost one answers: the coordinator denies at 13
  # minutes, this transport stops waiting at 14, and the gateway kills the task at 15.
  @approval_request_timeout 14 * 60 * 1_000

  # R2. Verified replay re-derives a whole session — one turn loop per recorded turn — and
  # the gateway stops waiting at two minutes. This sits just below that on purpose, the way
  # the signing `:erpc` bound does: letting the remote call decide first produces the honest
  # answer, which is that the owner node did not finish, rather than a bare gateway ceiling
  # with nothing in it.
  @replay_verify_timeout 110_000

  @doc "Starts or adopts a caller-independent interactive coding session."
  @spec start(keyword()) :: {:ok, Ref.t()} | {:error, term()}
  def start(opts \\ [])

  def start(opts) when is_list(opts) do
    case start_for_gateway(opts) do
      {:created, %Ref{}, reason} -> {:error, reason}
      result -> result
    end
  end

  def start(_opts), do: {:error, :invalid_options}

  @doc false
  @spec start_for_gateway(keyword()) ::
          {:ok, Ref.t()} | {:created, Ref.t(), term()} | {:error, term()}
  def start_for_gateway(opts) when is_list(opts) do
    if valid_options?(opts) do
      id = Keyword.get_lazy(opts, :id, &Jido.Signal.ID.generate!/0)

      with {:ok, session} <- State.new(id, opts),
           {:ok, persisted} <- create_or_match(session) do
        ref = Ref.new(id)

        case persisted.status do
          status when status in [:failed, :lost] ->
            {:created, ref, {:session_start_failed, persisted.error}}

          status when status in [:closed, :cancelled] ->
            {:ok, ref}

          _active ->
            case ensure_coordinator(id) do
              {:ok, pid} ->
                # Readiness waits for provider start-up, whose latency is legitimately
                # unbounded, so it keeps the long wait rather than the control-plane
                # bound. The request already exists durably at this point. Preserve that
                # fact when provider/workspace readiness fails so the gateway can open
                # the failed session instead of making a same-id client reconcile
                # forever. A coordinator whose readiness never settles — a store that
                # keeps refusing checkpoints, for instance — answers this call itself
                # at the readiness deadline with `{:session_start_unresolved, id}`,
                # so a caller here cannot wait forever on a session that can no
                # longer report anything.
                case safe_call(pid, :ready, :infinity) do
                  {:ok, _state} -> {:ok, ref}
                  {:error, reason} -> {:created, ref, reason}
                end

              {:error, reason} ->
                {:created, ref, reason}
            end
        end
      else
        {:error, reason} -> {:error, reason}
      end
    else
      {:error, :invalid_options}
    end
  end

  def start_for_gateway(_opts), do: {:error, :invalid_options}

  @doc "Starts an interactive session on a selected connected node."
  @spec start_on(node(), keyword()) :: {:ok, Ref.t()} | {:error, term()}
  def start_on(owner, opts \\ [])

  def start_on(owner, opts) when is_atom(owner) and not is_nil(owner) do
    case route(owner, __MODULE__, :start, [opts]) do
      {:ok, %Ref{} = ref} -> {:ok, %{ref | node: owner}}
      other -> other
    end
  end

  def start_on(_owner, _opts), do: {:error, :invalid_owner}

  @doc false
  @spec start_for_gateway_on(node(), keyword()) ::
          {:ok, Ref.t()} | {:created, Ref.t(), term()} | {:error, term()}
  def start_for_gateway_on(owner, opts \\ [])

  def start_for_gateway_on(owner, opts) when is_atom(owner) and not is_nil(owner) do
    case route(owner, __MODULE__, :start_for_gateway, [opts]) do
      {:ok, %Ref{} = ref} -> {:ok, %{ref | node: owner}}
      {:created, %Ref{} = ref, reason} -> {:created, %{ref | node: owner}, reason}
      other -> other
    end
  end

  def start_for_gateway_on(_owner, _opts), do: {:error, :invalid_owner}

  @doc "Returns a durable public session snapshot."
  def info(session), do: call(session, :info)

  @doc """
  Lists local durable interactive sessions as bounded rows.

  Rows, not whole sessions: this list is fanned out over `:erpc` to every fleet node and
  then across the socket on every refresh, so it carries what a picker draws — id, status,
  workspace, machine, title, cursor, usage, capabilities — and never a session's retained
  event window. `info/1` is one call away for anything else.
  """
  def list do
    Store.list()
    |> Enum.filter(&(&1.node == node()))
    |> Enum.map(&State.summary/1)
  end

  @doc """
  The workspaces of the sessions this node holds, for the code-intelligence admission.

  `Ouroboros.CodeIntel.Registry` admits a file under one of these beside the configured
  `:workspace_allowed_roots`: a session's workspace is already where this node runs an
  agent with a shell. Deleting the session withdraws the admission.
  """
  @spec workspaces() :: [Path.t()]
  def workspaces do
    Store.list()
    |> Enum.filter(&(&1.node == node()))
    |> Enum.map(& &1.workspace)
    |> Enum.filter(&is_binary/1)
    |> Enum.uniq()
  end

  @doc "Atomically subscribes the caller and returns events after an exclusive cursor."
  def subscribe(session, opts \\ []) do
    with :ok <- validate_options(opts, [:cursor]) do
      call(session, {:subscribe, self(), Keyword.get(opts, :cursor, 0)})
    end
  end

  @doc "Stops live event delivery to the caller."
  def unsubscribe(session), do: call(session, {:unsubscribe, self()})

  @doc "Replays retained redacted events after an exclusive cursor."
  def replay(session, opts \\ []) do
    with :ok <- validate_options(opts, [:cursor, :limit]) do
      call(session, {:replay, Keyword.get(opts, :cursor, 0), Keyword.get(opts, :limit, 100)})
    end
  end

  @doc "Starts an immediate turn. A caller-supplied id makes dispatch idempotent."
  def send_message(session, input, opts \\ []) do
    send_turn(session, :message, input, opts)
  end

  @doc "Queues a follow-up turn with durable, idempotent intent."
  def follow_up(session, input, opts \\ []) do
    send_turn(session, :follow_up, input, opts)
  end

  @doc "Waits for one logical turn; waiter timeout never interrupts provider work."
  def await(session, turn_id, timeout \\ :infinity) do
    with {:ok, id, owner} <- session_identity(session),
         :ok <- validate_turn_id(turn_id),
         :ok <- validate_timeout(timeout) do
      request_ref = make_ref()

      if owner == node() do
        local_await(id, turn_id, request_ref, timeout)
      else
        route(
          owner,
          __MODULE__,
          :local_await,
          [id, turn_id, request_ref, timeout],
          transport_timeout(timeout)
        )
      end
    end
  end

  @doc false
  def local_await(id, turn_id, request_ref, timeout) do
    with :ok <- validate_id(id),
         :ok <- validate_turn_id(turn_id),
         true <- is_reference(request_ref) || {:error, :invalid_request_reference},
         :ok <- validate_timeout(timeout),
         {:ok, pid} <- ensure_coordinator(id) do
      try do
        GenServer.call(pid, {:await_turn, request_ref, turn_id}, timeout)
      catch
        :exit, {:timeout, _call} ->
          GenServer.cast(pid, {:cancel_await, request_ref})
          {:error, :timeout}

        :exit, reason ->
          {:error, {:session_call_failed, reason}}
      end
    end
  end

  @doc "Steers an active native provider turn when its transport supports steering."
  def steer(session, input, opts \\ []) do
    with :ok <- validate_options(opts, @turn_options) do
      call(session, {:steer, input, opts})
    end
  end

  @doc """
  Changes approval mode, sandbox mode, model, or reasoning effort on an open session.

  Answers `{:ok, %{options:, applies:, changed:}}` where `applies` is `:now` only for a
  transport that carries the change to a live provider process, and `:next_turn` for
  every transport that rebuilds its request per turn. The turn already running is never
  retroactively re-governed, so a caller that reports `:next_turn` as immediate is
  reporting something this runtime did not do.
  """
  @spec configure(session(), map() | keyword()) :: {:ok, map()} | {:error, term()}
  def configure(session, changes) when is_list(changes) do
    if Keyword.keyword?(changes),
      do: configure(session, Map.new(changes)),
      else: {:error, {:invalid_configuration, %{reason: :not_a_map, changes: changes}}}
  end

  def configure(session, changes) when is_map(changes), do: call(session, {:configure, changes})

  def configure(_session, changes),
    do: {:error, {:invalid_configuration, %{reason: :not_a_map, changes: changes}}}

  @doc """
  Branches a session into a new one that carries its provider session and history.

  The new session is started on the parent's own node with the parent's provider,
  workspace, and effective options; only its start request differs, by carrying the
  parent's `provider_session_id` and whatever the transport spells "branch this". The
  parent is not sent a turn, not interrupted, and not closed.

  Refused where the transport declares no way to branch, and where the provider has not
  yet named a session to branch from.

  Three steps, in this order for one reason: the parent's coordinator plans the fork and
  counts it, but never starts it. Starting a session waits on provider readiness with no
  bound, and a coordinator held behind that wait would answer nothing — not `info/1`, not
  `interrupt/2`, not its own turns — until a child it does not own had finished starting.
  """
  @spec fork(session(), String.t() | nil) :: {:ok, map()} | {:error, term()}
  def fork(session, id \\ nil) do
    with {:ok, _parent_id, owner} <- session_identity(session),
         {:ok, opts} <- call(session, {:fork_plan, id}),
         {:ok, child} <- start_child(owner, opts, :fork_start_failed) do
      # The child exists and carries `forked_from`, which is the durable half of the
      # relationship. The parent's count is a hint that follows it, and a parent that
      # cannot record one does not undo a fork that already happened.
      _ = call(session, :count_fork)
      {:ok, child}
    end
  end

  # Shared by `fork/2` and `handoff/3`: both answer in `start/1`'s shape because both
  # *are* starts, and a client that can already open a created-but-not-ready session
  # should not need a third branch to open this one.
  defp start_child(owner, opts, failure_tag) do
    result =
      if owner == node(),
        do: start_for_gateway(opts),
        else: start_for_gateway_on(owner, opts)

    case result do
      # `start_for_gateway/1` rather than `start/1`: a child whose provider refused to
      # open is still a durable session with an id the caller can inspect, and reporting
      # it as a refusal would leave that session unreachable.
      {:ok, %Ref{id: id, node: child_node}} ->
        {:ok, %{id: id, node: child_node, ready: true, error: nil}}

      {:created, %Ref{id: id, node: child_node}, reason} ->
        {:ok, %{id: id, node: child_node, ready: false, error: reason}}

      {:error, reason} ->
        {:error, {failure_tag, reason}}
    end
  end

  @doc """
  Delegates an objective from this conversation to a coding task (G1).

  A delegation is a *coding task with a parent*, not a sub-conversation: it runs on the
  coding plane with its own id, its own transcript, and its own durable record, and what
  makes it this session's is `parent: %{plane: :interactive, id}` on that record. The
  parent's transcript gains a `delegation` event when it starts and another when it ends.

  The team is the workspace's default one — one per canonical workspace root per node,
  created lazily, durable through the same checkpoint every other team uses, and visible
  in `teams.list`. One worker per conversation, which is what makes a second `/delegate`
  from the same session queue behind the first rather than fan out.

  `id` is caller-owned like a start's: re-delegating under an id this session already
  recorded answers with that delegation instead of starting a second one.

  Options: `:id`, `:workspace` (default: this session's), `:provider` (default: this
  session's).
  """
  @spec delegate(session(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def delegate(session, objective, opts \\ []) do
    with :ok <- validate_options(opts, [:id, :workspace, :provider]),
         {:ok, _id, _owner} <- session_identity(session),
         {:ok, plan} <- call(session, {:delegate_plan, objective, opts}) do
      if Map.get(plan, :existing) do
        {:ok, delegation_reply(plan.id, plan.team_id, plan.task_id, plan.coding_node, :existing)}
      else
        start_delegation(session, objective, plan)
      end
    end
  end

  @doc """
  Lists this conversation's delegations with the status the *team* currently holds.

  The session's own record is a hint that follows the team's — a terminal note the parent
  was not up to receive is simply missing from it — so this reads the team, and falls back
  to what the session recorded only when the team is not reachable, saying which it did in
  `source`.
  """
  @spec delegations(session()) :: {:ok, [map()]} | {:error, term()}
  def delegations(session) do
    with {:ok, recorded} <- call(session, :delegations) do
      {:ok,
       recorded
       |> Map.values()
       |> Enum.sort_by(& &1.created_at)
       |> Enum.map(&current_delegation/1)}
    end
  end

  @doc """
  Tells a conversation that one of its delegations reached a terminal status.

  Called by `Ouroboros.Team.Server` from the seam where it verifies the coding task's
  durable checkpoint, and fire-and-forget on purpose: the team's obligation is delivering
  the result to its own worker, and a parent that is closed, unreachable, or simply not
  running must never hold that up. A note nobody received leaves the parent's copy stale;
  `delegations/1` reads the team's own record, which is why that is survivable.
  """
  @spec note_delegation(session(), String.t(), atom(), String.t() | nil) :: :ok
  def note_delegation(session, delegation_id, status, result_digest)
      when is_binary(delegation_id) and is_atom(status) do
    with {:ok, id, owner} <- session_identity(session) do
      message = {:delegation_settled, delegation_id, status, result_digest}

      if owner == node() do
        cast_local(id, message)
      else
        :erpc.cast(owner, __MODULE__, :cast_local, [id, message])
      end
    end

    :ok
  catch
    _kind, _reason -> :ok
  end

  def note_delegation(_session, _delegation_id, _status, _result_digest), do: :ok

  @doc false
  def cast_local(id, message) do
    case Task.whereis(id) do
      pid when is_pid(pid) -> GenServer.cast(pid, message)
      # Deliberately not started here. A conversation nobody has open does not need to be
      # woken to file a note it can rebuild from the team's own record next time it is.
      nil -> :ok
    end

    :ok
  catch
    _kind, _reason -> :ok
  end

  # The team work happens here rather than inside the coordinator: `add_worker/3` and
  # `delegate/4` are bounded at sixty seconds each, and a conversation that answered
  # nothing for two minutes because it asked a team a question would be a worse bargain
  # than the delegation is worth.
  defp start_delegation(session, objective, plan) do
    with {:ok, team, team_id} <- Team.workspace_team(plan.workspace),
         {:ok, _worker} <- ensure_worker(team, plan),
         {:ok, delegation} <-
           Team.delegate(team, plan.worker_id, objective,
             id: plan.id,
             coding_node: plan.coding_node,
             workspace: plan.workspace,
             provider: plan.provider,
             parent: plan.parent
           ) do
      record = %{
        id: delegation.id,
        team_id: team_id,
        task_id: delegation.task_ref.id,
        task_node: delegation.task_ref.node,
        objective_digest: plan.objective_digest
      }

      case call(session, {:delegation_started, record}) do
        {:ok, _recorded} ->
          {:ok,
           delegation_reply(
             delegation.id,
             team_id,
             delegation.task_ref.id,
             delegation.task_ref.node,
             delegation.status
           )}

        # The child exists and carries the parent, which is the durable half of the
        # relationship. A parent that could not record it is missing a rail row, not a
        # delegation — and `_owner` names the node it is on so a caller can still find it.
        {:error, reason} ->
          {:error, {:delegation_unrecorded, %{delegation_id: delegation.id, reason: reason}}}
      end
    else
      {:error, reason} -> {:error, {:delegation_failed, reason}}
    end
  end

  # A worker this session already has is not an error. `Team.Server` answers
  # `{:worker_already_added, id}` for a second add of the same id, which for one worker
  # per conversation is the ordinary case rather than the exception.
  defp ensure_worker(team, plan) do
    case Team.add_worker(team, plan.worker_id, node: plan.coding_node) do
      {:ok, worker} -> {:ok, worker}
      {:error, {:worker_already_added, _id}} -> {:ok, %{id: plan.worker_id}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp delegation_reply(id, team_id, task_id, task_node, status) do
    %{
      delegation_id: id,
      team_id: team_id,
      task_id: task_id,
      task_node: task_node,
      plane: :coding,
      status: status
    }
  end

  defp current_delegation(record) do
    base = %{
      delegation_id: record.id,
      team_id: record.team_id,
      task_id: record.task_id,
      task_node: record.task_node,
      plane: :coding,
      objective_digest: record.objective_digest,
      status: record.status,
      result_digest: Map.get(record, :result_digest),
      created_at: record.created_at,
      updated_at: record.updated_at,
      source: :session
    }

    case team_delegation(record) do
      {:ok, delegation} ->
        %{
          base
          | status: delegation.status,
            updated_at: delegation.updated_at || record.updated_at,
            source: :team
        }

      :unavailable ->
        base
    end
  end

  defp team_delegation(record) do
    with pid when is_pid(pid) <- Team.whereis(record.team_id),
         %{delegations: delegations} <- Team.state(pid),
         {:ok, delegation} <- Map.fetch(delegations, record.id) do
      {:ok, delegation}
    else
      _unavailable -> :unavailable
    end
  rescue
    _error -> :unavailable
  catch
    :exit, _reason -> :unavailable
  end

  @doc """
  Runs one command in this session's admitted workspace, on its owner node (B7).

  The operator's own act, not a tool: no model asks for it, no provider is told about it,
  and it is permitted only where the session is already at `approval_mode: :auto_approve`
  or `Ouroboros.Control.Permissions` answers `{:allow, _}` for `tool: "bash"` with that
  command under this session's principal. Anything else — including a rule store that
  could not be read — is `{:shell_refused, %{reason, suggested_rule, …}}` naming the rule
  that would have worked.

  Recorded in `Ouroboros.Agent.EffectLedger` as an `:operator_shell` effect *before* it
  runs and settled after, carrying the command's digest and working directory and never
  its text. The transcript gains a runtime-native `provider_event` so the conversation
  shows what happened, and the next turn's `<ouroboros-runtime>` envelope carries the
  last three commands' excerpts.

  The command runs in the *caller's* process on the owner node rather than inside the
  session coordinator, because a coordinator held for ten minutes would answer nothing
  else in that time.
  """
  @spec exec(session(), String.t()) :: {:ok, map()} | {:error, term()}
  def exec(session, command) do
    with {:ok, id, owner} <- session_identity(session) do
      if owner == node() do
        local_exec(id, command)
      else
        route(
          owner,
          __MODULE__,
          :local_exec,
          [id, command],
          transport_timeout(Exec.timeout_ms())
        )
      end
    end
  end

  @doc false
  def local_exec(id, command) do
    with :ok <- validate_id(id),
         {:ok, pid} <- ensure_coordinator(id),
         {:ok, plan} <- safe_call(pid, {:exec_plan, command}, call_timeout()) do
      outcome = run_planned_command(command, plan)

      # The settlement is told to the coordinator whatever happened, including a command
      # this runtime could not start: an entry left `:started` would become `:ambiguous`
      # on the next boot, which is the honest answer for a crash and a misleading one
      # here.
      _ = safe_call(pid, {:exec_settled, plan.effect_id, outcome}, call_timeout())

      case outcome do
        %{error: reason} -> {:error, {:shell_failed, reason}}
        result -> {:ok, Map.put(result, :effect_id, plan.effect_id)}
      end
    end
  end

  defp run_planned_command(command, plan) do
    case Exec.run(command, plan.cwd,
           timeout_ms: plan.timeout_ms,
           spill_dir: plan.spill_dir
         ) do
      {:ok, result} -> result
      {:error, reason} -> %{error: reason}
    end
  end

  @doc """
  Compacts an open native session's conversation now, optionally focused.

  Refused with `{:unsupported_on_transport, %{transport:, verb: :compact}}` on every other
  transport: only a native session hands this runtime the conversation to fold, and a
  vendor's own compaction is surfaced as an event when it reports one rather than imitated.
  """
  @spec compact(session(), String.t() | nil) :: {:ok, map()} | {:error, term()}
  def compact(session, focus \\ nil)

  def compact(session, nil), do: call(session, {:compact, nil})

  def compact(session, focus) when is_binary(focus) do
    if String.trim(focus) == "",
      do: {:error, {:invalid_compaction_focus, %{reason: :blank}}},
      else: call(session, {:compact, focus})
  end

  def compact(_session, focus), do: {:error, {:invalid_compaction_focus, %{value: focus}}}

  @doc """
  Returns what this session can honestly say about its own context.

  A native session answers with its cached prefix's fingerprint, the window, what the last
  request used, its compactions, its retained archive ids, and which instruction files were
  loaded and dropped. Every other transport answers with the subset the runtime folded from
  its `usage` events, and `source` says which of the two you are reading — never a shape
  padded with nulls that look like measurements.
  """
  @spec context(session()) :: {:ok, map()} | {:error, term()}
  def context(session), do: call(session, :context)

  @doc "D6. Rewind a native session to `to_turn`; `what` is `:files`, `:conversation`, or `:both`."
  def rewind(session, to_turn, what \\ :both)

  def rewind(session, to_turn, what)
      when ((is_binary(to_turn) and to_turn != "") or (is_integer(to_turn) and to_turn >= 0)) and
             what in [:files, :conversation, :both],
      do: call(session, {:rewind, to_turn, what})

  def rewind(_session, to_turn, what),
    do: {:error, {:invalid_rewind, %{to_turn: to_turn, what: what}}}

  @doc "D6. The turns a native session can be rewound to, newest first."
  def rewind_points(session), do: call(session, :rewind_points)

  @doc """
  R1. A window of a native session's turn journal — the replay substrate.

  `opts` takes `:since_seq` (exclusive) and `:limit`. The answer carries the chain head,
  how far it verified, and what the budget truncated, because a record a caller cannot
  bound is a record they cannot rely on.
  """
  def journal(session, opts \\ []), do: call(session, {:journal, opts})

  @doc """
  R2. Re-runs this session's recorded turns through the real loop and answers the verdict.

  `%{verified:, turns:, records:, head:, divergence:}` — `turns` is how many verified, which
  is why a bounded record answers with a number rather than with a failure. Divergence is
  named, never continued past: either the loop re-derives what was recorded or it says at
  which record and in which field it stopped agreeing.

  Reads the journal file, so it needs no live native transport — a session whose runtime
  died a week ago replays wherever its session directory is. It does need the session's
  workspace, because the system prompt and the tool list are re-derived from it rather than
  read out of a record that holds only their digests.

  Two steps, and the split is the point. The coordinator is asked only *where the record is
  and what shape the session was* — a cheap question — and the verification itself runs in
  the caller's own process on the owner node, because re-running a turn loop per recorded
  turn inside the coordinator's `handle_call` would freeze the session for as long as it
  took. The caller's ceiling, not the session's availability, is what bounds it.
  """
  def replay_verify(session) do
    with {:ok, _id, owner} <- session_identity(session),
         {:ok, plan} <- call(session, :replay_plan) do
      route(owner, __MODULE__, :verify_plan, [plan], @replay_verify_timeout)
    end
  end

  @doc false
  @spec verify_plan({String.t(), keyword()}) :: {:ok, map()} | {:error, term()}
  def verify_plan({session_dir, opts}) do
    case Replay.verify(session_dir, opts) do
      # The events are the engine's own working evidence and can run to tens of thousands of
      # deltas for a single turn. The verdict is what a caller asked for; the stream is not.
      {:ok, verdict} -> {:ok, Map.delete(verdict, :events)}
      {:error, reason} -> {:error, {:replay_refused, reason}}
    end
  end

  @doc """
  Hands this session's work to a fresh one seeded with a curated packet.

  Amp's answer to compacting a compacted conversation: rather than folding again, the
  child's first message is the five-heading summary, the files this session touched with
  their current hashes, the open plan, and whatever the operator typed. The parent is not
  interrupted and not closed — a handoff is not a close, and ending the parent is the
  operator's decision.

  Three steps in the same order and for the same reason as `fork/2`: this session's
  coordinator writes the packet and names the child but never starts it, because starting
  a session waits on provider readiness with no bound.

  **Honest limit:** workspace admission is unchanged, so handing off from a live session
  that holds an exclusive lease is refused by the lease (`workspace_conflict`), exactly as
  a fork is. Starting the parent with `worktree: true` is the composable fix.
  """
  @spec handoff(session(), String.t() | nil, String.t() | nil) :: {:ok, map()} | {:error, term()}
  def handoff(session, prompt \\ nil, id \\ nil) do
    with {:ok, _parent_id, owner} <- session_identity(session),
         {:ok, opts} <- call(session, {:handoff_plan, prompt, id}) do
      start_child(owner, opts, :handoff_start_failed)
    end
  end

  @doc """
  Names a session, overriding any title the runtime derived from the first prompt.

  Allowed on a terminal session as well as a live one: a finished conversation is exactly
  what someone is trying to find again in a picker.
  """
  @spec rename(session(), String.t()) :: {:ok, State.t()} | {:error, term()}
  def rename(session, title), do: call(session, {:rename, title})

  @doc "Validates and responds to a provider approval request."
  def respond_approval(session, request_id, response) do
    if is_binary(request_id) and String.trim(request_id) != "" do
      with {:ok, response} <- normalize_approval_response(response) do
        call(session, {:respond_approval, request_id, response})
      end
    else
      {:error, :invalid_request_id}
    end
  end

  @doc """
  Asks this session's owner for a human decision on a tool call the provider cannot ask
  about itself.

  The one caller today is `ouro mcp-serve`, the stdio MCP server Claude Code is given as
  its `--permission-prompt-tool`. The coordinator mints the request id, records the
  question durably, consults the permission engine, and blocks until
  `respond_approval/3` names that id or its own deadline passes.

  Waits under a ceiling of its own — one minute above the coordinator's, one minute below
  the gateway's — so the answer a caller receives is the runtime's denial rather than a
  transport that stopped listening. A caller that gives up first tells the coordinator so,
  exactly as `await/3` does, and the row is closed as a denial rather than left open.
  """
  @spec request_approval(session(), map()) :: {:ok, map()} | {:error, term()}
  def request_approval(session, request) when is_map(request) do
    with {:ok, id, owner} <- session_identity(session) do
      request_ref = make_ref()

      if owner == node() do
        local_request_approval(id, request_ref, request, @approval_request_timeout)
      else
        route(
          owner,
          __MODULE__,
          :local_request_approval,
          [id, request_ref, request, @approval_request_timeout],
          transport_timeout(@approval_request_timeout)
        )
      end
    end
  end

  def request_approval(_session, _request), do: {:error, :invalid_approval_request}

  @doc false
  def local_request_approval(id, request_ref, request, timeout) do
    with :ok <- validate_id(id),
         true <- is_reference(request_ref) || {:error, :invalid_request_reference},
         true <- is_map(request) || {:error, :invalid_approval_request},
         :ok <- validate_timeout(timeout),
         {:ok, pid} <- ensure_coordinator(id) do
      try do
        GenServer.call(pid, {:request_approval, request_ref, request}, timeout)
      catch
        :exit, {:timeout, _call} ->
          GenServer.cast(pid, {:cancel_approval, request_ref})
          {:error, :timeout}

        :exit, reason ->
          {:error, {:session_call_failed, reason}}
      end
    end
  end

  @doc "Interrupts an active turn without closing the provider session."
  def interrupt(session, turn_id \\ :active)

  def interrupt(session, :active), do: call(session, {:interrupt, :active})

  def interrupt(session, turn_id) when is_binary(turn_id) do
    with :ok <- validate_turn_id(turn_id), do: call(session, {:interrupt, turn_id})
  end

  def interrupt(_session, _turn_id), do: {:error, :invalid_turn_id}

  @doc "Closes the provider session gracefully."
  def close(session), do: call(session, :close)

  @doc "Forcibly cancels the provider session."
  def kill(session), do: call(session, :kill)

  @doc """
  Deletes a terminal session's durable record.

  Live sessions must be closed or killed first. The coordinator is stopped before the
  checkpoint is removed so a retiring process cannot write the session back.
  """
  @spec delete(session()) :: :ok | :not_found | {:error, term()}
  def delete(session) do
    with {:ok, id, owner} <- session_identity(session) do
      if owner == node() do
        local_delete(id)
      else
        route(owner, __MODULE__, :local_delete, [id], call_timeout())
      end
    end
  end

  @doc false
  def local_delete(id) do
    with :ok <- validate_id(id) do
      case Store.get(id) do
        :not_found ->
          :not_found

        {:error, reason} ->
          {:error, {:storage_error, reason}}

        {:ok, %State{node: owner}} when owner != node() ->
          {:error, {:wrong_owner, owner}}

        {:ok, %State{} = session} ->
          if State.terminal?(session) do
            stop_local_coordinator(id)
            Store.delete(id)
          else
            {:error, {:session_not_terminal, session.status}}
          end
      end
    end
  end

  @doc false
  def local_call(id, message) do
    with :ok <- validate_id(id),
         {:ok, pid} <- ensure_coordinator(id),
         do: safe_call(pid, message, call_timeout())
  end

  defp create_or_match(session) do
    case Store.create(session) do
      :ok ->
        {:ok, session}

      {:error, :already_exists} ->
        case Store.get(session.id) do
          {:ok, existing} ->
            if same_request?(existing, session),
              do: {:ok, existing},
              else: {:error, {:session_id_conflict, session.id}}

          other ->
            {:error, {:existing_session_unavailable, other}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp same_request?(left, right) do
    immutable = [
      :id,
      :node,
      :provider,
      :workspace_mode,
      :event_limit,
      :options,
      :forked_from,
      :handed_off_from
    ]

    Map.take(left, immutable) == Map.take(right, immutable) and
      canonical_workspace(left.workspace) == canonical_workspace(right.workspace)
  end

  defp call(session, message) do
    with {:ok, id, owner} <- session_identity(session) do
      if owner == node(),
        do: local_call(id, message),
        else: route(owner, __MODULE__, :local_call, [id, message], call_timeout())
    end
  end

  defp stop_local_coordinator(id) do
    case Task.whereis(id) do
      pid when is_pid(pid) ->
        _ = DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)
        :ok

      _absent ->
        :ok
    end
  end

  defp ensure_coordinator(id) do
    case Task.whereis(id) do
      pid when is_pid(pid) ->
        {:ok, pid}

      nil ->
        case Store.get(id) do
          {:ok, %State{node: owner}} when owner == node() ->
            case DynamicSupervisor.start_child(Ouroboros.Interactive.TaskSupervisor, {Task, id}) do
              {:ok, pid} -> {:ok, pid}
              {:error, {:already_started, pid}} -> {:ok, pid}
              {:error, reason} -> {:error, reason}
            end

          {:ok, %State{node: owner}} ->
            {:error, {:wrong_owner, owner}}

          :not_found ->
            {:error, :not_found}

          {:error, reason} ->
            {:error, {:storage_error, reason}}
        end
    end
  end

  defp safe_call(pid, message, timeout) do
    try do
      GenServer.call(pid, message, timeout)
    catch
      :exit, {:timeout, _call} -> {:error, :timeout}
      :exit, reason -> {:error, {:session_call_failed, reason}}
    end
  end

  # Starting a session remotely keeps an unbounded transport: it has no
  # caller-supplied timeout to thread, and provider start-up latency is legitimately
  # unbounded.
  defp route(owner, module, function, arguments, timeout \\ :infinity) do
    cond do
      owner == node() -> apply(module, function, arguments)
      owner not in Node.list() -> {:error, {:owner_unavailable, owner}}
      true -> :erpc.call(owner, module, function, arguments, timeout)
    end
  catch
    :error, {:erpc, reason} when reason in [:noconnection, :timeout] ->
      {:error, {:owner_unavailable, owner, reason}}

    kind, reason ->
      {:error, {:remote_call_failed, owner, kind, reason}}
  end

  defp call_timeout do
    case Application.get_env(:ouroboros, :session_call_timeout, @default_call_timeout) do
      :infinity -> :infinity
      timeout when is_integer(timeout) and timeout > 0 -> timeout
      _invalid -> @default_call_timeout
    end
  end

  # `await/3` validates the timeout before routing, so only these two shapes reach here.
  defp transport_timeout(:infinity), do: :infinity
  defp transport_timeout(timeout) when is_integer(timeout), do: timeout + @remote_margin_ms

  defp validate_timeout(:infinity), do: :ok
  defp validate_timeout(timeout) when is_integer(timeout) and timeout >= 0, do: :ok
  defp validate_timeout(timeout), do: {:error, {:invalid_timeout, timeout}}

  defp send_turn(session, mode, input, opts) do
    with :ok <- validate_options(opts, [:id | @turn_options]),
         id = Keyword.get_lazy(opts, :id, &Jido.Signal.ID.generate!/0),
         :ok <- validate_turn_id(id) do
      call(session, {:send_turn, mode, id, input, Keyword.delete(opts, :id)})
    end
  end

  defp validate_options(opts, allowed) when is_list(opts) do
    cond do
      not Keyword.keyword?(opts) ->
        {:error, :invalid_options}

      Keyword.keys(opts) != Enum.uniq(Keyword.keys(opts)) ->
        {:error, :duplicate_options}

      unknown = Enum.find(Keyword.keys(opts), &(&1 not in allowed)) ->
        {:error, {:unknown_option, unknown}}

      true ->
        :ok
    end
  end

  defp validate_options(_opts, _allowed), do: {:error, :invalid_options}

  defp valid_options?(opts) when is_list(opts) do
    Keyword.keyword?(opts) and Keyword.keys(opts) == Enum.uniq(Keyword.keys(opts))
  end

  defp session_identity(%Ref{id: id, node: owner}) do
    with :ok <- validate_id(id),
         true <- (is_atom(owner) and not is_nil(owner)) || {:error, :invalid_owner},
         do: {:ok, id, owner}
  end

  defp session_identity(id) when is_binary(id) do
    with :ok <- validate_id(id), do: {:ok, id, node()}
  end

  defp session_identity(_session), do: {:error, :invalid_session}

  defp validate_id(id) when is_binary(id) do
    if String.trim(id) == "", do: {:error, :invalid_session_id}, else: :ok
  end

  defp validate_id(_id), do: {:error, :invalid_session_id}

  defp validate_turn_id(id) when is_binary(id) do
    if String.trim(id) == "", do: {:error, :invalid_turn_id}, else: :ok
  end

  defp validate_turn_id(_id), do: {:error, :invalid_turn_id}

  defp normalize_approval_response(response) do
    base =
      if is_map(response),
        do: Map.take(response, [:decision, :scope, :reason, :provider_options]),
        else: response

    with :ok <- validate_approval_extensions(response),
         {:ok, validated} <- ApprovalResponse.new(base) do
      extensions =
        if is_map(response), do: Map.take(response, [:actor, :rule_id]), else: %{}

      {:ok, validated |> Map.from_struct() |> Map.merge(extensions)}
    else
      {:error, reason} -> {:error, {:invalid_approval_response, reason}}
    end
  end

  defp validate_approval_extensions(response) when is_map(response) do
    allowed = [:decision, :scope, :reason, :provider_options, :actor, :rule_id]

    cond do
      unknown = Enum.find(Map.keys(response), &(&1 not in allowed)) ->
        {:error, {:unknown_field, unknown}}

      Map.get(response, :actor, :human) not in [
        :human,
        :headless,
        :automation,
        "human",
        "headless",
        "automation"
      ] ->
        {:error, {:invalid_actor, Map.get(response, :actor)}}

      not is_nil(Map.get(response, :rule_id)) and
          (not is_binary(Map.get(response, :rule_id)) or Map.get(response, :rule_id) == "") ->
        {:error, {:invalid_rule_id, Map.get(response, :rule_id)}}

      true ->
        :ok
    end
  end

  defp validate_approval_extensions(response) when response in [:approve, :deny], do: :ok
  defp validate_approval_extensions(response), do: {:error, {:invalid_response, response}}

  defp canonical_workspace(workspace) do
    case Ouroboros.Workspace.Path.canonicalize(workspace) do
      {:ok, canonical} -> canonical
      {:error, _reason} -> workspace
    end
  end
end
