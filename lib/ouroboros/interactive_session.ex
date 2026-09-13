defmodule Ouroboros.InteractiveSession do
  @moduledoc """
  Durable, distribution-aware interactive coding sessions.

  The upstream Harness owns provider transports and active processes. Ouroboros
  owns durable session/turn intent, redacted replay, workspace admission, crash
  reattachment, and node-aware routing.
  """

  alias Ouroboros.Session.ApprovalResponse
  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Interactive.{Event, Ref, State, Store, Task}
  alias Ouroboros.Provider.Native.{Checkpoint, Paths, Replay}
  alias Ouroboros.Workspace.Exec

  @type session :: Ref.t() | String.t()

  @turn_options [:attachments, :reasoning_effort, :output_schema, :metadata, :provider_options]
  @max_compaction_id_bytes 128

  # Control-plane operations (info/replay/subscribe/steer/respond_approval/interrupt/
  # close/kill) are bounded so one wedged coordinator cannot freeze every caller.
  # `await/3` is the deliberate exception: it threads the caller's own timeout, and the
  # transport is given that timeout plus a margin so the local waiter, not the
  # transport, decides when to stop waiting.

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
      {supplied_admission, opts} = Keyword.pop(opts, :maintenance_admission)
      {operation_id, opts} = Keyword.pop(opts, :maintenance_operation_id)
      id = Keyword.get_lazy(opts, :id, &Ouroboros.ID.generate!/0)
      operation_id = operation_id || maintenance_operation("session-start", [id])

      with {:ok, session} <- State.new(id, opts) do
        with_admission(operation_id, id, supplied_admission, fn lease ->
          with {:ok, persisted} <- create_or_match(session) do
            ref = Ref.new(id)

            case persisted.status do
              status when status in [:failed, :lost] ->
                {:created, ref, {:session_start_failed, persisted.error}}

              status when status in [:closed, :cancelled] ->
                {:created, ref, {:session_terminal, status}}

              _active ->
                case ensure_coordinator(id, lease) do
                  {:ok, pid} ->
                    # The admission lease spans Store creation, coordinator creation,
                    # Task/workspace admission and durable readiness. It is intentionally
                    # released only after this result is known.
                    case safe_call(pid, :ready, :infinity) do
                      {:ok, _state} -> {:ok, ref}
                      {:error, reason} -> {:created, ref, reason}
                    end

                  {:error, reason} ->
                    {:created, ref, reason}
                end
            end
          end
        end)
      else
        {:error, reason} -> {:error, reason}
      end
    else
      {:error, :invalid_options}
    end
  end

  def start_for_gateway(_opts), do: {:error, :invalid_options}

  @doc "Previews one known durable native checkpoint without creating a session."
  def preview_native(provider_session_id) do
    with :ok <- Paths.validate_session_id(provider_session_id),
         {:ok, dir} <- Paths.existing_session_dir(provider_session_id),
         path = Path.join(dir, "conversation.json"),
         {:ok, snapshot} <- Checkpoint.snapshot(path) do
      owner =
        Store.list()
        |> Enum.find_value(fn state ->
          imported_source =
            get_in(state, [Access.key(:imported_from), Access.key(:source_provider_session_id)])

          if state.provider_session_id == provider_session_id or
               imported_source == provider_session_id,
             do: state.id
        end)

      {:ok,
       %{
         provider_session_id: provider_session_id,
         digest: snapshot.digest,
         retained_messages: length(snapshot.messages),
         offset: snapshot.offset,
         rewind_floor: snapshot.rewind_floor,
         owned_by: owner
       }}
    else
      {:error, {:path_unavailable, _path, :enoent}} -> {:error, :native_checkpoint_not_found}
      {:error, :no_checkpoint} -> {:error, :native_checkpoint_not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Imports a digest-bound checkpoint as context under fresh logical/native identities."
  def import_native(provider_session_id, expected_digest, opts \\ []) do
    id = Keyword.get_lazy(opts, :id, &Ouroboros.ID.generate!/0)

    with {:ok, preview} <- preview_native(provider_session_id),
         :ok <- matching_digest(preview, expected_digest),
         :ok <- require_tail_ack(preview, opts) do
      with_admission(maintenance_operation("native-import", [id]), id, fn lease ->
        do_import_native(id, provider_session_id, expected_digest, preview, opts, lease)
      end)
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp do_import_native(id, provider_session_id, expected_digest, preview, opts, admission) do
    with provenance = import_provenance(preview, id, opts),
         {:ok, existing} <- existing_import(id, provenance),
         target_native = (existing && existing.provider_session_id) || Paths.new_session_id(),
         {:ok, session} <- import_session(id, target_native, preview, provenance, opts),
         {:ok, ledger, ledger_status} <- open_import_effect(session, preview),
         {:ok, persisted, creation} <-
           complete_import(
             ledger,
             session,
             existing,
             provider_session_id,
             target_native,
             expected_digest
           ),
         {:ok, admission} <- admit_or_replay_import(ledger, ledger_status, persisted, admission) do
      {:ok,
       %{
         id: persisted.id,
         provider_session_id: persisted.provider_session_id,
         source_provider_session_id: provider_session_id,
         idempotent: creation == :existing or ledger_status == :existing,
         ready: admission.ready,
         error: admission.error
       }}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp admit_or_replay_import(%{status: :ok, result: result}, :existing, _session, _admission) do
    {:ok, %{ready: Map.get(result, :ready), error: Map.get(result, :admission_error)}}
  end

  defp admit_or_replay_import(ledger, _status, session, admission),
    do: admit_import(ledger, session, admission)

  defp existing_import(id, provenance) do
    case Store.get(id) do
      :not_found ->
        {:ok, nil}

      {:ok, existing} ->
        if get_in(existing, [Access.key(:imported_from), Access.key(:fingerprint)]) ==
             provenance.fingerprint,
           do: {:ok, existing},
           else: {:error, {:session_id_conflict, id}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp import_session(id, target, preview, provenance, opts) do
    with {:ok, session} <-
           State.new(
             id,
             opts
             |> Keyword.drop([:id, :acknowledge_partial_tail])
             |> Keyword.put(:provider_session_id, target)
             |> Keyword.put(:imported_from, provenance)
           ) do
      {:ok, import_marker(%{session | provider_session_id: target}, preview, target)}
    end
  end

  defp seed_unless_existing(%State{}, _source, _target, _digest), do: :ok

  defp seed_unless_existing(nil, source, target, digest) do
    case Checkpoint.import(source, target, digest) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp create_import_or_cleanup(_session, %State{} = existing),
    do: {:ok, existing, :existing}

  defp create_import_or_cleanup(session, nil) do
    case Store.create_import(session) do
      :ok ->
        {:ok, session, :created}

      {:ok, existing, status} ->
        if existing.provider_session_id != session.provider_session_id do
          with :ok <- cleanup_seed(session), do: {:ok, existing, status}
        else
          {:ok, existing, status}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp complete_import(ledger, session, existing, source, target, digest) do
    result =
      with :ok <- seed_unless_existing(existing, source, target, digest),
           {:ok, persisted, creation} <- create_import_or_cleanup(session, existing) do
        {:ok, persisted, creation}
      end

    case result do
      {:ok, _, _} = success ->
        success

      {:error, reason} ->
        cleanup = if is_nil(existing), do: cleanup_seed(session), else: :ok

        reported_reason =
          if cleanup == :ok, do: reason, else: {:import_cleanup_failed, reason, cleanup}

        case settle_import_failure(ledger, reported_reason) do
          :ok -> {:error, reported_reason}
          {:error, settlement} -> {:error, {:import_failed_unsettled, reason, settlement}}
        end
    end
  end

  defp admit_import(ledger, session, admission) do
    readiness =
      with {:ok, pid} <- ensure_coordinator(session.id, admission),
           {:ok, _} <- safe_call(pid, :ready, :infinity) do
        :ok
      end

    case readiness do
      :ok ->
        with :ok <- settle_import_effect(ledger, session, true, nil),
             do: {:ok, %{ready: true, error: nil}}

      {:error, reason} ->
        # Import commits when the fresh target and logical record are durable. Coordinator
        # admission is a separate outcome, exactly as ordinary gateway start treats a
        # created-but-not-ready session. The returned target remains inspectable and can be
        # imported again after deleting the terminal logical record and repairing admission.
        with :ok <- settle_import_effect(ledger, session, false, reason),
             do: {:ok, %{ready: false, error: reason}}
    end
  end

  defp cleanup_seed(session) do
    cleanup = Application.get_env(:ouroboros, :native_import_cleanup)

    with :ok <- if(is_function(cleanup, 1), do: cleanup.(session), else: :ok),
         {:ok, path, _} <- Checkpoint.locate(session.provider_session_id) do
      directory = Path.dirname(path)
      errors = [remove_if_present(path)]

      errors =
        directory
        |> Path.join("conversation.json.tmp-*")
        |> Path.wildcard()
        |> Enum.reduce(errors, fn temporary, acc -> [remove_if_present(temporary) | acc] end)

      errors = [remove_dir_if_empty(directory) | errors] |> Enum.reject(&(&1 == :ok))
      if errors == [], do: :ok, else: {:error, errors}
    end
  end

  defp remove_if_present(path) do
    case File.rm(path) do
      :ok -> :ok
      {:error, :enoent} -> :ok
      {:error, reason} -> {:remove_failed, path, reason}
    end
  end

  defp remove_dir_if_empty(path) do
    case File.rmdir(path) do
      :ok -> :ok
      {:error, :enoent} -> :ok
      {:error, reason} -> {:rmdir_failed, path, reason}
    end
  end

  defp open_import_effect(session, preview) do
    attrs = %{
      id: "native-import:" <> session.imported_from.fingerprint,
      effect: :native_import,
      principal: "operator",
      claimed_from: nil,
      attempt: %{
        session_id: session.id,
        source_provider_session_id: preview.provider_session_id,
        source_digest: preview.digest,
        import_fingerprint: session.imported_from.fingerprint,
        node: node()
      },
      authority: %{decision: :operator, source: :gateway},
      cause: %{kind: :operator_action}
    }

    case EffectLedger.record_started(
           attrs,
           import_ledger()
         ) do
      {:ok, %{status: :failed} = entry, :existing} ->
        {:error, {:import_previously_failed, entry.id}}

      {:ok, entry, status} ->
        {:ok, entry, status}

      {:error, reason} ->
        {:error, {:import_unrecordable, reason}}
    end
  end

  defp settle_import_effect(entry, session, ready, admission_error) do
    outcome = %{
      status: :ok,
      result: %{
        session_id: session.id,
        provider_session_id: session.provider_session_id,
        source_provider_session_id: session.imported_from.source_provider_session_id,
        ready: ready,
        admission_error: if(admission_error, do: inspect(admission_error), else: nil)
      }
    }

    case EffectLedger.settle(
           entry.id,
           outcome,
           import_ledger()
         ) do
      {:ok, _, _} -> :ok
      {:error, {:effect_already_settled, _, :ok}} -> :ok
      {:error, reason} -> {:error, {:import_settlement_failed, reason}}
    end
  end

  defp settle_import_failure(entry, reason) do
    outcome = %{status: :failed, error: %{reason: inspect(reason)}}

    case EffectLedger.settle(entry.id, outcome, import_ledger()) do
      {:ok, _, _} -> :ok
      {:error, {:effect_already_settled, _, :failed}} -> :ok
      {:error, settlement} -> {:error, settlement}
    end
  end

  defp import_ledger,
    do: Application.get_env(:ouroboros, :native_import_ledger, EffectLedger)

  defp matching_digest(%{digest: digest}, digest), do: :ok
  defp matching_digest(_preview, _expected), do: {:error, :checkpoint_digest_changed}

  defp require_tail_ack(%{offset: 0}, _opts), do: :ok

  defp require_tail_ack(_preview, opts) do
    if Keyword.get(opts, :acknowledge_partial_tail) == true,
      do: :ok,
      else: {:error, :partial_tail_acknowledgement_required}
  end

  defp import_provenance(preview, id, opts) do
    semantic =
      %{
        id: id,
        source_provider_session_id: preview.provider_session_id,
        source_digest: preview.digest,
        offset: preview.offset,
        rewind_floor: preview.rewind_floor,
        options: Keyword.drop(opts, [:acknowledge_partial_tail])
      }
      |> :erlang.term_to_binary([:deterministic])

    %{
      source_provider_session_id: preview.provider_session_id,
      source_digest: preview.digest,
      retained_messages: preview.retained_messages,
      omitted_prefix: preview.offset,
      rewind_floor: preview.rewind_floor,
      fingerprint: Base.encode16(:crypto.hash(:sha256, semantic), case: :lower)
    }
  end

  defp import_marker(session, preview, target_native) do
    payload = %{
      "source_provider_session_id" => preview.provider_session_id,
      "source_digest" => preview.digest,
      "new_provider_session_id" => target_native,
      "retained_messages" => preview.retained_messages,
      "omitted_prefix" => preview.offset,
      "not_restored" => [
        "public events",
        "approvals and grants",
        "effects",
        "cursor and outcome",
        "ancestry and timestamps"
      ]
    }

    event = Event.from_runtime(session.id, 1, :native_checkpoint_imported, payload)
    %{session | events: [event], cursor: 1, sequence_offset: 1}
  end

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

  @doc "Retries the latest failed turn from its private checkpoint, once per source turn."
  def retry_turn(session, source_id) do
    with :ok <- validate_turn_id(source_id), do: call(session, {:retry_turn, source_id})
  end

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

  `overrides` is the small closed envelope a caller may change about the child, and it is
  a map rather than two more positional arguments because both members are optional and a
  third would read as `fork(session, id, nil, nil, "gpt-5")`:

    * `:to_turn` — a turn id or ordinal to branch *at*, exactly what `rewind_points/1`
      hands back. The child's conversation is the parent's truncated to the end of that
      turn. Native sessions only; a vendor thread branches where the vendor branches it.
    * `:model` — the child's model, replacing the parent's rather than inheriting it.

  Neither touches the parent, and a fork that names neither is the fork this function
  performed before they existed.

  Three steps, in this order for one reason: the parent's coordinator plans the fork and
  counts it, but never starts it. Starting a session waits on provider readiness with no
  bound, and a coordinator held behind that wait would answer nothing — not `info/1`, not
  `interrupt/2`, not its own turns — until a child it does not own had finished starting.
  """
  @spec fork(session(), String.t() | nil, map()) :: {:ok, map()} | {:error, term()}
  def fork(session, id \\ nil, overrides \\ %{}) do
    with {:ok, child_id} <- child_operation_id(id),
         {:ok, parent_id, owner} <- session_identity(session) do
      operation_id = maintenance_operation("fork", [parent_id, child_id])

      with_admission(operation_id, child_id, fn lease ->
        with {:ok, opts} <- call(session, {:fork_plan, child_id, overrides}),
             {:ok, child} <-
               start_child(
                 owner,
                 admission_options(opts, lease, operation_id),
                 :fork_start_failed
               ) do
          # The child exists and carries `forked_from`, which is the durable half of the
          # relationship. The parent's count is a hint that follows it.
          _ = call(session, :count_fork)
          {:ok, child}
        end
      end)
    end
  end

  # Shared by `fork/2` and `handoff/3`: both answer in `start/1`'s shape because both
  # *are* starts, and a client that can already open a created-but-not-ready session
  # should not need a third branch to open this one.
  defp child_start(opts) do
    start = Application.get_env(:ouroboros, :interactive_child_start, &start_for_gateway/1)
    start.(opts)
  end

  defp start_child(owner, opts, failure_tag) do
    result =
      if owner == node(),
        do: child_start(opts),
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

  @doc "Starts or reconciles a caller-owned compaction operation."
  def compact_start(session, id, focus \\ nil)

  def compact_start(session, id, nil)
      when is_binary(id) and id != "" and byte_size(id) <= @max_compaction_id_bytes,
      do: call(session, {:compact_start, id, nil})

  def compact_start(session, id, focus)
      when is_binary(id) and id != "" and byte_size(id) <= @max_compaction_id_bytes and
             is_binary(focus) do
    if String.trim(focus) == "",
      do: {:error, {:invalid_compaction_focus, %{reason: :blank}}},
      else: call(session, {:compact_start, id, focus})
  end

  def compact_start(_session, id, _focus),
    do: {:error, {:invalid_compaction_id, %{value: id, max_bytes: @max_compaction_id_bytes}}}

  @doc "Reads a caller-owned compaction operation without blocking behind its inference."
  def compact_status(session, id)
      when is_binary(id) and id != "" and byte_size(id) <= @max_compaction_id_bytes,
      do: call(session, {:compact_status, id})

  def compact_status(_session, id),
    do: {:error, {:invalid_compaction_id, %{value: id, max_bytes: @max_compaction_id_bytes}}}

  @doc "Cancels a running compaction operation owned by this session."
  def compact_cancel(session, id)
      when is_binary(id) and id != "" and byte_size(id) <= @max_compaction_id_bytes,
      do: call(session, {:compact_cancel, id})

  def compact_cancel(_session, id),
    do: {:error, {:invalid_compaction_id, %{value: id, max_bytes: @max_compaction_id_bytes}}}

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

  @doc "Returns a bounded privacy-safe status produced by the session's owning coordinator."
  @spec safe_status(session()) :: {:ok, map()} | {:error, term()}
  def safe_status(session), do: call(session, :safe_status)

  @doc false
  @spec safe_status_from_owner(pid(), node()) :: {:ok, map()} | {:error, term()}
  def safe_status_from_owner(owner, expected_node)
      when is_pid(owner) and is_atom(expected_node) do
    if node(owner) == expected_node and expected_node == node() do
      safe_call(owner, :safe_status, call_timeout())
    else
      {:error, :stale_session_owner}
    end
  end

  def safe_status_from_owner(_owner, _expected_node), do: {:error, :stale_session_owner}

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
    with {:ok, child_id} <- child_operation_id(id),
         {:ok, parent_id, owner} <- session_identity(session) do
      operation_id = maintenance_operation("handoff", [parent_id, child_id])

      with_admission(operation_id, child_id, fn lease ->
        with {:ok, opts} <- call(session, {:handoff_plan, prompt, child_id}),
             {:ok, child} <-
               start_child(
                 owner,
                 admission_options(opts, lease, operation_id),
                 :handoff_start_failed
               ) do
          {:ok, child}
        end
      end)
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
  Asks this session's owner for a human decision on a tool call that did not arrive
  through this session's own transport.

  The caller is `relay_approval/2` below: a native subagent's question, carried to the
  parent session that owns the modal. The coordinator mints the request id, records the
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

  @doc "Relay a target-decided approval without re-evaluating it against the parent's rules."
  def relay_approval(session, payload) when is_map(payload) do
    tool = Map.get(payload, "tool_call", %{})

    request = %{
      relay_payload: payload,
      tool_name: Map.get(tool, "name"),
      input: Map.get(tool, "input"),
      cwd: Map.get(tool, "cwd")
    }

    case request_approval(session, request) do
      {:ok, %{response: response}} ->
        Ouroboros.Session.ApprovalResponse.new!(response)

      {:ok, answer} ->
        Ouroboros.Session.ApprovalResponse.new!(%{
          decision: if(answer.decision in [:allow, "allow"], do: :approve, else: :deny),
          scope: :once,
          reason: Map.get(answer, :reason)
        })

      {:error, reason} ->
        Ouroboros.Session.ApprovalResponse.new!(%{
          decision: :deny,
          scope: :once,
          reason: "approval channel unavailable: #{inspect(reason)}"
        })
    end
  end

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
         {:ok, pid} <- ensure_coordinator(id) do
      case safe_call(pid, message, call_timeout()) do
        # The registry entry `Task.whereis/1` reads outlives its process for a moment
        # (registry DOWN handling is asynchronous), and a coordinator may retire between
        # the lookup and the call. `:noproc` proves the coordinator never received this
        # message, so re-ensuring is safe for every message: the second attempt reaches
        # a coordinator rebuilt from the durable record, or reports the session's
        # absence honestly. One retry only — `:timeout` stays an error, because a timed
        # out call may have been received, and retrying it could apply a change twice.
        {:error, {:session_call_failed, {:noproc, _call}}} ->
          with {:ok, pid} <- ensure_coordinator(id),
               do: safe_call(pid, message, call_timeout())

        reply ->
          reply
      end
    end
  end

  defp with_admission(operation_id, session_id, fun),
    do: with_admission(operation_id, session_id, nil, fun)

  defp with_admission(operation_id, session_id, supplied, fun) do
    server = maintenance_fence_server()

    case Process.whereis(server) do
      nil ->
        # Library/test trees without a configured target authority retain their in-memory
        # posture. A core runtime supervises Fence before reaching this entry point.
        if supplied, do: {:error, :maintenance_fence_unavailable}, else: fun.(nil)

      _pid ->
        acquisition =
          if supplied do
            case Ouroboros.Maintenance.Fence.validate_admission(supplied, session_id, server) do
              :ok -> {:ok, supplied, false}
              {:error, reason} -> {:error, reason}
            end
          else
            case Ouroboros.Maintenance.Fence.acquire_admission(
                   operation_id,
                   session_id,
                   :current,
                   server
                 ) do
              {:ok, lease} -> {:ok, lease, true}
              {:error, reason} -> {:error, reason}
            end
          end

        with {:ok, lease, owned?} <- acquisition do
          try do
            fun.(lease)
          after
            if owned?, do: Ouroboros.Maintenance.Fence.release(lease, server)
          end
        end
    end
  end

  defp maintenance_fence_server,
    do: Application.get_env(:ouroboros, :maintenance_fence_server, Ouroboros.Maintenance.Fence)

  defp child_operation_id(nil), do: {:ok, Ouroboros.ID.generate!()}

  defp child_operation_id(id) when is_binary(id) do
    cond do
      String.trim(id) == "" -> {:error, :invalid_fork_id}
      byte_size(id) > 128 -> {:error, {:invalid_fork_id, %{max_bytes: 128}}}
      true -> {:ok, id}
    end
  end

  defp child_operation_id(_id), do: {:error, :invalid_fork_id}

  defp maintenance_operation(kind, parts) do
    digest =
      :crypto.hash(:sha256, :erlang.term_to_binary({kind, parts})) |> Base.encode16(case: :lower)

    kind <> ":" <> digest
  end

  defp admission_options(opts, nil, _operation_id), do: opts

  defp admission_options(opts, lease, operation_id) do
    opts
    |> Keyword.put(:maintenance_admission, lease)
    |> Keyword.put(:maintenance_operation_id, operation_id)
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
      :handed_off_from,
      :imported_from
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

  defp ensure_coordinator(id, admission \\ nil) do
    if is_nil(admission) and Process.whereis(maintenance_fence_server()) do
      with_admission(maintenance_operation("coordinator-recovery", [id]), id, fn lease ->
        ensure_coordinator(id, lease)
      end)
    else
      ensure_coordinator_admitted(id, admission)
    end
  end

  defp ensure_coordinator_admitted(id, admission) do
    case Task.whereis(id) do
      pid when is_pid(pid) ->
        {:ok, pid}

      nil ->
        case Store.get(id) do
          {:ok, %State{node: owner}} when owner == node() ->
            child = if admission, do: {Task, {id, admission}}, else: {Task, id}

            case DynamicSupervisor.start_child(Ouroboros.Interactive.TaskSupervisor, child) do
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
  defp route(owner, module, function, arguments, timeout \\ :infinity),
    do: Ouroboros.Session.Routing.route(owner, module, function, arguments, timeout)

  defp call_timeout, do: Ouroboros.Session.Routing.call_timeout()
  defp transport_timeout(timeout), do: Ouroboros.Session.Routing.transport_timeout(timeout)

  defp validate_timeout(:infinity), do: :ok
  defp validate_timeout(timeout) when is_integer(timeout) and timeout >= 0, do: :ok
  defp validate_timeout(timeout), do: {:error, {:invalid_timeout, timeout}}

  defp send_turn(session, mode, input, opts) do
    with :ok <- validate_options(opts, [:id | @turn_options]),
         id = Keyword.get_lazy(opts, :id, &Ouroboros.ID.generate!/0),
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
