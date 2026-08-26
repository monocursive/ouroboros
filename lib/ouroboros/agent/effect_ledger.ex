defmodule Ouroboros.Agent.EffectLedger do
  @moduledoc """
  Durable, content-minimized history for grant-gated agent effects.

  `Ouroboros.Agent.Effects.Runner` records an admitted attempt here before it starts
  the supervised work. The same record is settled after the work finishes. Refusals
  are recorded as terminal entries before they are returned. This ordering makes the
  ledger an authority boundary rather than best-effort telemetry: if the initial
  checkpoint cannot be acknowledged, the effect does not run.

  Entries contain identities, the concrete grant target, a snapshot of the authority
  decision, signal IDs, and a bounded outcome projection. Message bodies, objectives,
  capability source, provider output, and forged BEAM binaries are never accepted into
  the checkpoint. Free-form error text is represented by a structural classification
  and a content-free fingerprint.

  The store is node-local. Production config uses
  `Ouroboros.Storage.DurableFile`; development and tests use ETS. A checkpoint found
  with unfinished attempts is rewritten at boot with those attempts marked
  `:ambiguous`: the old runtime acknowledged their start, but did not durably record an
  outcome. A later settlement may still replace `:ambiguous`, which keeps isolated
  process restarts honest without inventing a failure.

  Retention bounds terminal history while retaining every `:started` entry. Queries are
  independently bounded so a caller cannot copy the entire ledger out of its owner by
  accident.

  ## Retention is fair across kinds, not first-come

  I1 put two high-volume kinds in here — a `:tool_call` for every tool the native agent
  runs, and an `:approval` for every human answer — beside kinds a node produces a handful
  of times in its life. A single global "keep the newest N" would let one long turn's four
  hundred tool calls evict the only `:forge` this machine ever ran, which is the opposite
  of what a durable record is for.

  So eviction is max-min fair by effect kind: every kind present keeps its newest
  `retention_limit / kinds present` terminal entries before any kind keeps a second batch,
  and whatever slots are left over go to the newest entries overall. The total is still
  exactly `retention_limit`, so nothing about the checkpoint's size or the export's bounds
  changes; what changes is *which* entries a flood is allowed to push out. A `:started`
  entry is never evicted, as before.

  The limit itself stays at 1,000 (`config :ouroboros, :effect_ledger_limit`) rather than
  being raised for the new kinds. A larger number is a larger object to serialize and fsync
  on every single write, and every tool call already costs two of those; an operator who
  wants a longer native history raises the number knowingly rather than paying for it by
  default.
  """

  use GenServer

  require Logger

  alias Ouroboros.Control.Grants

  @store_key {:ouroboros, :agent_effect_ledger, 1}
  @checkpoint_version 1
  @default_retention_limit 1_000
  @default_query_limit 100
  @max_query_limit 500
  @terminal_statuses [:ok, :failed, :denied, :ambiguous]
  @statuses [:started | @terminal_statuses]
  @attempt_fields %{
    start_agent: [:module],
    stop_agent: [:agent],
    send_message: [:agent],
    delegate: [:team],
    forge: [:module],
    deploy: [:nodes],
    # A permission decision names the tool and the shape of the call, never the call.
    # `fingerprint` is a digest of the command line, paths, and domains; the text of any
    # of them is exactly the content this ledger exists to keep out.
    permission: [:tool, :mode, :provider, :fingerprint],
    # B7. A command an operator ran in a session's workspace, recorded before it runs.
    # `command_digest` is a digest of the command line and `cwd` is the directory it ran
    # in; the command text is exactly the content this ledger exists to keep out, and a
    # `cd` a reader cannot see is worth less than a command they could replay.
    operator_shell: [:session_id, :command_digest, :cwd, :node, :rule_id],
    # I1. One tool call the native agent was admitted to make, checkpointed before the
    # tool runs. `subject` is what the call is *about* — the paths it names, a digest of
    # the command line, the hosts it would reach, the MCP server and tool behind an
    # `mcp__*` name — and never what any of them contain. `sanitize_subject/1` below is
    # what makes that true here rather than at the call site's discretion.
    tool_call: [
      :session_id,
      :turn_id,
      :call_id,
      :tool,
      :provider,
      :subject,
      :node,
      :permission_entry_id
    ],
    # I1. One *human* answer to an approval question, on any provider. The engine's own
    # verdicts are `:permission` entries and stay there; this kind is for the answers a
    # person gave, which are the only ones nobody can reconstruct from the rules
    # afterwards. `permission_entry_id` links the two when both exist.
    approval: [
      :session_id,
      :request_id,
      :tool,
      :provider,
      :subject,
      :node,
      :permission_entry_id
    ]
  }
  @result_fields %{
    start_agent: [:agent_id, :module, :node],
    stop_agent: [:agent_id],
    send_message: [:to, :from, :messages_received],
    delegate: [:team, :worker_id, :delegation_id, :status, :delivery],
    forge: [:artifact_id, :module, :epoch, :signer, :source_sha256, :nodes],
    deploy: [:artifact_id, :module, :epoch, :nodes, :state],
    permission: [:decision, :scope, :actor, :rule_id],
    operator_shell: [:exit_status, :duration_ms, :output_bytes, :spilled, :timed_out],
    tool_call: [:status, :duration_ms, :output_bytes],
    approval: [:decision, :scope, :actor, :rule_id, :origin]
  }

  # The whole vocabulary a `tool_call` outcome may use. `:refused` is a call the runtime
  # never started; `:timed_out` is one the tool runner killed at `tool_timeout_ms`.
  @tool_call_statuses [:completed, :failed, :refused, :timed_out]

  # How much of a subject the ledger will hold. Paths and hostnames are identities, not
  # contents, but an unbounded list of them is still an unbounded write.
  @subject_paths 16
  @subject_hosts 8
  @subject_value_chars 512
  @subject_name_chars 128

  # Effect kinds this ledger records that are not grant-gated agent effects. A permission
  # decision is not something an agent asks for; it is what `Ouroboros.Control.Permissions`
  # answered on a session's behalf, and it belongs in the same durable history for the
  # same reason — an approval nobody can account for later did not happen (I1).
  # `:operator_shell` is here for the same reason and one more: it is the only effect in
  # this ledger a *person* asked for directly rather than an agent, and the whole claim
  # `workspace.exec` makes — that a command run through the runtime is accountable
  # afterwards — is this entry existing before the command did.
  #
  # `:tool_call` and `:approval` (I1) extend that claim from the one command an operator
  # typed to every tool the native agent runs and every approval a person answered on any
  # provider. Same discipline in both directions: the entry exists before the tool does,
  # and a ledger that cannot record refuses the call.
  @ledger_only_effects [:permission, :operator_shell, :tool_call, :approval]

  defmodule Entry do
    @moduledoc "One durable, content-minimized agent-effect attempt and its outcome."

    @enforce_keys [
      :sequence,
      :started_sequence,
      :id,
      :effect,
      :principal,
      :attempt,
      :authority,
      :cause,
      :status,
      :started_at,
      :origin_node
    ]
    defstruct @enforce_keys ++
                [claimed_from: nil, result: nil, error: nil, settled_at: nil]

    @type status :: :started | :ok | :failed | :denied | :ambiguous

    @type t :: %__MODULE__{
            sequence: pos_integer(),
            started_sequence: pos_integer(),
            id: String.t(),
            effect: atom(),
            principal: String.t(),
            claimed_from: String.t() | map() | nil,
            attempt: map(),
            authority: map(),
            cause: map(),
            status: status(),
            result: map() | nil,
            error: map() | nil,
            started_at: String.t(),
            settled_at: String.t() | nil,
            origin_node: node()
          }
  end

  @type server :: GenServer.server()
  @type write_result :: {:ok, Entry.t(), :created | :existing} | {:error, term()}

  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "Durably records an admitted attempt before its effect is allowed to run."
  @spec record_started(map(), server()) :: write_result()
  def record_started(attrs, server \\ __MODULE__)

  def record_started(attrs, server) when is_map(attrs) do
    safe_call(server, {:record, :started, attrs})
  end

  def record_started(_attrs, _server), do: {:error, :invalid_effect_entry}

  @doc "Durably records a refused attempt as one terminal entry."
  @spec record_denied(map(), server()) :: write_result()
  def record_denied(attrs, server \\ __MODULE__)

  def record_denied(attrs, server) when is_map(attrs) do
    safe_call(server, {:record, :denied, attrs})
  end

  def record_denied(_attrs, _server), do: {:error, :invalid_effect_entry}

  @doc """
  Durably records one attempt that begins and ends in the same instant.

  A permission decision has no window between admission and outcome to be ambiguous in,
  so it is written once, terminal, rather than as a `:started` entry a settlement would
  later have to find. Idempotent on `:id`, like the other two.
  """
  @spec record_settled(map(), server()) :: write_result()
  def record_settled(attrs, server \\ __MODULE__)

  def record_settled(attrs, server) when is_map(attrs) do
    safe_call(server, {:record, :ok, attrs})
  end

  def record_settled(_attrs, _server), do: {:error, :invalid_effect_entry}

  @doc "Durably settles a previously started (or restart-ambiguous) attempt."
  @spec settle(String.t(), map(), server()) ::
          {:ok, Entry.t(), :updated | :existing} | {:error, term()}
  def settle(effect_id, outcome, server \\ __MODULE__)

  def settle(effect_id, outcome, server) when is_binary(effect_id) and is_map(outcome) do
    safe_call(server, {:settle, effect_id, outcome})
  end

  def settle(_effect_id, _outcome, _server), do: {:error, :invalid_effect_settlement}

  @doc """
  Monitors the supervised runner responsible for a started effect.

  A runner that exits before durably settling its entry turns that entry ambiguous. The
  runner is attached before it receives permission to execute, so no admitted effect is
  left with an unobserved owner.
  """
  @spec watch_runner(String.t(), pid(), server()) :: :ok | {:error, term()}
  def watch_runner(effect_id, runner, server \\ __MODULE__)

  def watch_runner(effect_id, runner, server) when is_binary(effect_id) and is_pid(runner) do
    safe_call(server, {:watch_runner, effect_id, runner})
  end

  def watch_runner(_effect_id, _runner, _server), do: {:error, :invalid_effect_runner}

  @doc "Returns one retained effect by its stable effect ID."
  @spec get(String.t(), server()) :: {:ok, Entry.t()} | :not_found | {:error, term()}
  def get(effect_id, server \\ __MODULE__)

  def get(effect_id, server) when is_binary(effect_id) do
    safe_call(server, {:get, effect_id})
  end

  def get(_effect_id, _server), do: {:error, :invalid_effect_id}

  @doc """
  Returns retained effects, newest first by default.

  Filters are `:principal`, `:effect`, `:status`, `:since_sequence`, `:order`
  (`:asc` or `:desc`), and `:limit` (1..#{@max_query_limit}).
  """
  @spec list(keyword() | map(), server()) :: {:ok, [Entry.t()]} | {:error, term()}
  def list(filters \\ [], server \\ __MODULE__) do
    safe_call(server, {:list, filters})
  end

  @doc "Returns bounded ledger sizing and durability information."
  @spec status(server()) :: map() | {:error, term()}
  def status(server \\ __MODULE__), do: safe_call(server, :status)

  @doc """
  The bounds `list/2` holds every query to.

  Read by the gateway so that `ledger.list` and `ledger.export` are bounded by the
  ledger's own numbers rather than by a second set that could drift from them.
  """
  @spec query_limits() :: %{default: pos_integer(), max: pos_integer()}
  def query_limits, do: %{default: @default_query_limit, max: @max_query_limit}

  @doc "The statuses `list/2` accepts as a filter."
  @spec statuses() :: [Entry.status()]
  def statuses, do: @statuses

  @doc """
  The vocabulary a `:tool_call` result's `status` is recorded with.

  Distinct from `statuses/0`, which is the *entry* lifecycle every kind shares. This one
  says what happened to the tool: it ran (`:completed`), it ran and reported an error
  (`:failed`), the runtime never started it (`:refused`), or the tool runner killed it at
  its timeout (`:timed_out`).
  """
  @spec tool_call_statuses() :: [atom()]
  def tool_call_statuses, do: @tool_call_statuses

  @type durability :: :ephemeral_checkpoint | :durable_checkpoint | :synced_checkpoint

  @spec durability(server()) :: durability() | {:error, term()}
  def durability(server \\ __MODULE__), do: safe_call(server, :durability)

  @doc """
  Every effect kind this ledger records: the grant-gated agent effects plus the kinds the
  runtime originates on a session's behalf.
  """
  @spec effects() :: [atom()]
  def effects, do: Grants.effects() ++ @ledger_only_effects

  @doc false
  def checkpoint_key, do: @store_key

  @impl true
  def init(opts) do
    with {:ok, storage} <- storage_config(opts),
         {:ok, adapter, adapter_opts} <- normalize_storage(storage),
         {:ok, retention_limit} <- retention_limit(opts),
         {:ok, checkpoint} <- load(adapter, adapter_opts),
         {:ok, checkpoint} <- reconcile_unfinished(checkpoint, adapter, adapter_opts) do
      {:ok,
       %{
         adapter: adapter,
         opts: adapter_opts,
         entries: checkpoint.entries,
         next_sequence: checkpoint.next_sequence,
         retention_limit: retention_limit,
         durability: durability_level(adapter),
         runners: %{},
         runner_monitors: %{}
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:record, status, attrs}, _from, state)
      when status in [:started, :denied, :ok] do
    with {:ok, normalized} <- normalize_attrs(attrs),
         {:ok, reply, state} <- record(status, normalized, state) do
      {:reply, reply, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:settle, effect_id, outcome}, _from, state) do
    case settle_entry(effect_id, outcome, state) do
      {:ok, reply, state} -> {:reply, reply, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:watch_runner, effect_id, runner}, _from, state) do
    reply =
      case {Enum.find(state.entries, &(&1.id == effect_id)), Map.get(state.runners, effect_id)} do
        {nil, _runner} ->
          {:error, {:unknown_effect, effect_id}}

        {%Entry{status: status}, _runner} when status != :started ->
          :ok

        {%Entry{status: :started}, %{pid: ^runner}} ->
          :ok

        {%Entry{status: :started}, %{pid: other}} ->
          {:error, {:effect_runner_already_attached, effect_id, other}}

        {%Entry{status: :started}, nil} ->
          monitor = Process.monitor(runner)
          runners = Map.put(state.runners, effect_id, %{pid: runner, monitor: monitor})
          monitors = Map.put(state.runner_monitors, monitor, effect_id)
          {:ok, %{state | runners: runners, runner_monitors: monitors}}
      end

    case reply do
      {:ok, state} -> {:reply, :ok, state}
      other -> {:reply, other, state}
    end
  end

  def handle_call({:get, effect_id}, _from, state) do
    reply =
      case Enum.find(state.entries, &(&1.id == effect_id)) do
        nil -> :not_found
        entry -> {:ok, entry}
      end

    {:reply, reply, state}
  end

  def handle_call({:list, filters}, _from, state) do
    reply =
      with {:ok, query} <- normalize_query(filters) do
        entries =
          state.entries
          |> Enum.filter(&matches?(&1, query))
          |> order(query.order)
          |> Enum.take(query.limit)

        {:ok, entries}
      end

    {:reply, reply, state}
  end

  def handle_call(:status, _from, state) do
    status_counts = Enum.frequencies_by(state.entries, & &1.status)

    {:reply,
     %{
       durability: state.durability,
       retained: length(state.entries),
       in_flight: Map.get(status_counts, :started, 0),
       ambiguous: Map.get(status_counts, :ambiguous, 0),
       retention_limit: state.retention_limit,
       next_sequence: state.next_sequence
     }, state}
  end

  def handle_call(:durability, _from, state), do: {:reply, state.durability, state}

  @impl true
  def handle_info({:DOWN, monitor, :process, _runner, reason}, state) do
    case Map.pop(state.runner_monitors, monitor) do
      {nil, _monitors} ->
        {:noreply, state}

      {effect_id, monitors} ->
        state = %{
          state
          | runners: Map.delete(state.runners, effect_id),
            runner_monitors: monitors
        }

        case Enum.find(state.entries, &(&1.id == effect_id)) do
          %Entry{status: :started} = entry ->
            ambiguous = %Entry{
              entry
              | sequence: state.next_sequence,
                status: :ambiguous,
                error: sanitize_error({:effect_runner_exited_before_settlement, reason}),
                settled_at: now()
            }

            entries = replace(state.entries, ambiguous) |> trim(state.retention_limit)
            updated = %{state | entries: entries, next_sequence: state.next_sequence + 1}

            # Same discipline as `record/3` and `settle_entry/3`: a transition nobody
            # durably recorded did not happen. Keeping it in memory only would have this
            # process answer `:ambiguous` for an entry that is still `:started` on disk,
            # and hand out sequence numbers no checkpoint ever claimed.
            case checkpoint_state(updated) do
              :ok ->
                {:noreply, updated}

              {:error, reason} ->
                Logger.warning(
                  "effect ledger could not checkpoint the ambiguity of #{effect_id}: " <>
                    "#{inspect(reason, limit: 4)}; the entry stays :started until it is " <>
                    "settled or the next boot reconciles it"
                )

                {:noreply, state}
            end

          _terminal_or_missing ->
            {:noreply, state}
        end
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp record(status, attrs, state) do
    case Enum.find(state.entries, &(&1.id == attrs.id)) do
      nil ->
        entry = new_entry(status, attrs, state.next_sequence)
        entries = trim([entry | state.entries], state.retention_limit)
        updated = %{state | entries: entries, next_sequence: state.next_sequence + 1}

        persist(updated, {:ok, entry, :created}, :effect_ledger_checkpoint_failed)

      %Entry{} = existing ->
        if same_attempt?(existing, attrs, status) do
          {:ok, {:ok, existing, :existing}, state}
        else
          {:error, {:effect_id_conflict, attrs.id}}
        end
    end
  end

  defp settle_entry(effect_id, outcome, state) do
    with {:ok, status} <- settlement_status(outcome),
         %Entry{} = entry <- Enum.find(state.entries, &(&1.id == effect_id)) || :not_found do
      settled = apply_settlement(entry, status, outcome, state.next_sequence)

      cond do
        entry.status in [:started, :ambiguous] ->
          entries = replace(state.entries, settled) |> trim(state.retention_limit)
          updated = %{state | entries: entries, next_sequence: state.next_sequence + 1}

          case persist(updated, {:ok, settled, :updated}, :effect_ledger_checkpoint_failed) do
            {:ok, reply, persisted} -> {:ok, reply, forget_runner(persisted, effect_id)}
            {:error, reason} -> {:error, reason}
          end

        same_settlement?(entry, settled) ->
          {:ok, {:ok, entry, :existing}, state}

        true ->
          {:error, {:effect_already_settled, effect_id, entry.status}}
      end
    else
      :not_found -> {:error, {:unknown_effect, effect_id}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp new_entry(status, attrs, sequence) do
    timestamp = now()
    terminal? = status in @terminal_statuses

    %Entry{
      sequence: sequence,
      started_sequence: sequence,
      id: attrs.id,
      effect: attrs.effect,
      principal: attrs.principal,
      claimed_from: attrs.claimed_from,
      attempt: attrs.attempt,
      authority: attrs.authority,
      cause: attrs.cause,
      status: status,
      result: if(terminal?, do: sanitize_result(attrs.effect, attrs.result), else: nil),
      error: if(terminal?, do: sanitize_error(attrs.error), else: nil),
      started_at: timestamp,
      settled_at: if(terminal?, do: timestamp, else: nil),
      origin_node: node()
    }
  end

  defp apply_settlement(%Entry{} = entry, status, outcome, sequence) do
    %Entry{
      entry
      | sequence: sequence,
        status: status,
        result: sanitize_result(entry.effect, Map.get(outcome, :result)),
        error: sanitize_error(Map.get(outcome, :error)),
        settled_at: now()
    }
  end

  defp normalize_attrs(attrs) do
    with id when is_binary(id) and id != "" <- Map.get(attrs, :id),
         effect when is_atom(effect) <- Map.get(attrs, :effect),
         true <- effect in effects(),
         principal when is_binary(principal) and principal != "" <- Map.get(attrs, :principal),
         attempt when is_map(attempt) <- Map.get(attrs, :attempt),
         authority when is_map(authority) <- Map.get(attrs, :authority),
         cause when is_map(cause) <- Map.get(attrs, :cause) do
      {:ok,
       %{
         id: id,
         effect: effect,
         principal: principal,
         claimed_from: sanitize_identity(Map.get(attrs, :claimed_from)),
         attempt: sanitize_attempt(effect, attempt),
         authority: sanitize_authority(authority),
         cause: sanitize_cause(cause),
         result: Map.get(attrs, :result),
         error: Map.get(attrs, :error)
       }}
    else
      _invalid -> {:error, :invalid_effect_entry}
    end
  end

  defp settlement_status(%{status: status}) when status in [:ok, :failed], do: {:ok, status}
  defp settlement_status(_outcome), do: {:error, :invalid_effect_settlement}

  defp same_attempt?(entry, attrs, status) do
    compatible_status? =
      case status do
        :started -> entry.status in [:started, :ok, :failed, :ambiguous]
        :denied -> entry.status == :denied
        :ok -> entry.status == :ok
      end

    compatible_status? and entry.effect == attrs.effect and entry.principal == attrs.principal and
      entry.claimed_from == attrs.claimed_from and entry.attempt == attrs.attempt and
      entry.cause == attrs.cause
  end

  defp same_settlement?(entry, settled) do
    entry.status == settled.status and entry.result == settled.result and
      entry.error == settled.error
  end

  defp sanitize_attempt(effect, attempt) do
    attempt = Map.take(attempt, Map.fetch!(@attempt_fields, effect))

    case Map.fetch(attempt, :subject) do
      {:ok, subject} -> Map.put(attempt, :subject, sanitize_subject(subject))
      :error -> attempt
    end
  end

  # What a tool call or an approval was *about*, reduced to identities. A caller hands this
  # in already minimized — the loop knows which of a tool's arguments are paths and which
  # are contents — and this is the second gate that makes the claim structural: a key this
  # ledger does not name is dropped, a digest that is not a digest is dropped rather than
  # stored as the text somebody passed by mistake, and every list and string is bounded.
  defp sanitize_subject(subject) when is_map(subject) and not is_struct(subject) do
    %{}
    |> put_if(:paths, subject_list(Map.get(subject, :paths), @subject_paths))
    |> put_if(:command_sha256, subject_digest(Map.get(subject, :command_sha256)))
    |> put_if(:hosts, subject_list(Map.get(subject, :hosts), @subject_hosts))
    |> put_if(:mcp_server, subject_name(Map.get(subject, :mcp_server)))
    |> put_if(:mcp_tool, subject_name(Map.get(subject, :mcp_tool)))
    |> put_if(:app, subject_name(Map.get(subject, :app)))
    |> put_if(:desktop_action, subject_name(Map.get(subject, :desktop_action)))
  end

  defp sanitize_subject(_subject), do: %{}

  defp subject_list(values, limit) when is_list(values) do
    case values
         |> Enum.filter(&is_binary/1)
         |> Enum.take(limit)
         |> Enum.map(&String.slice(&1, 0, @subject_value_chars)) do
      [] -> nil
      bounded -> bounded
    end
  end

  defp subject_list(_values, _limit), do: nil

  defp subject_digest(<<digest::binary-size(64)>>) do
    if String.match?(digest, ~r/\A[0-9a-f]{64}\z/), do: digest, else: nil
  end

  defp subject_digest(_value), do: nil

  defp subject_name(value) when is_binary(value) and value != "",
    do: String.slice(value, 0, @subject_name_chars)

  defp subject_name(_value), do: nil

  defp sanitize_authority(authority) do
    %{}
    |> put_if(:decision, Map.get(authority, :decision))
    |> put_if(:reason, Map.get(authority, :reason))
    |> put_if(:constraints, sanitize_constraints(Map.get(authority, :constraints)))
    |> put_if(:granted_at, sanitize_identity(Map.get(authority, :granted_at)))
  end

  defp sanitize_constraints(constraints) when is_map(constraints), do: constraints
  defp sanitize_constraints(_constraints), do: nil

  defp sanitize_cause(cause) do
    %{}
    |> put_if(:signal_id, sanitize_identity(Map.get(cause, :signal_id)))
    |> put_if(:signal_type, sanitize_identity(Map.get(cause, :signal_type)))
  end

  defp sanitize_identity(nil), do: nil
  defp sanitize_identity(value) when is_atom(value), do: value

  defp sanitize_identity(value) when is_binary(value) and byte_size(value) <= 256,
    do: value

  defp sanitize_identity(value) when is_binary(value), do: fingerprint(value)
  defp sanitize_identity(value), do: fingerprint(value)

  defp sanitize_result(_effect, nil), do: nil

  defp sanitize_result(effect, result) when is_map(result) and not is_struct(result) do
    summary = Map.take(result, Map.fetch!(@result_fields, effect))

    refine_result(effect, summary, result)
  end

  defp sanitize_result(_effect, result), do: %{value_fingerprint: fingerprint(result)}

  defp refine_result(:delegate, summary, %{result: value}),
    do: Map.put(summary, :result_fingerprint, fingerprint(value))

  # A `:tool_call` status is a closed vocabulary, so a client can branch on it. A value
  # outside it is dropped rather than coerced: "the runtime recorded no status" is a fact,
  # and "failed" invented for it would be a claim.
  defp refine_result(:tool_call, %{status: status} = summary, _result)
       when status not in @tool_call_statuses,
       do: Map.delete(summary, :status)

  defp refine_result(_effect, summary, _result), do: summary

  defp sanitize_error(nil), do: nil

  defp sanitize_error(error) do
    %{classification: classify(error), fingerprint: fingerprint(error)}
  end

  defp classify(value) when is_atom(value) or is_number(value), do: value
  defp classify(value) when is_binary(value), do: :text

  defp classify(value) when is_tuple(value) do
    value |> Tuple.to_list() |> Enum.map(&classify/1) |> List.to_tuple()
  end

  defp classify(value) when is_list(value), do: :list
  defp classify(value) when is_map(value), do: :map
  defp classify(_value), do: :term

  defp fingerprint(value) do
    binary = :erlang.term_to_binary(value)

    %{
      sha256: :crypto.hash(:sha256, binary) |> Base.encode16(case: :lower),
      bytes: byte_size(binary)
    }
  rescue
    _error -> %{sha256: nil, bytes: nil}
  end

  defp put_if(map, _key, nil), do: map
  defp put_if(map, key, value), do: Map.put(map, key, value)

  defp replace(entries, replacement) do
    Enum.map(entries, fn
      %{id: id} when id == replacement.id -> replacement
      entry -> entry
    end)
  end

  defp trim(entries, retention_limit) do
    entries = Enum.sort_by(entries, & &1.sequence, :desc)
    {unfinished, terminal} = Enum.split_with(entries, &(&1.status == :started))

    (unfinished ++ retain_terminal(terminal, retention_limit))
    |> Enum.sort_by(& &1.sequence, :desc)
  end

  # Max-min fair across effect kinds. Every kind present keeps its newest `quota` entries
  # first, then the slots nobody claimed go to the newest entries overall. The total is
  # still `retention_limit`; what this buys is that one turn's four hundred `:tool_call`
  # entries cannot evict the only `:forge` this node ever ran. `terminal` arrives sorted
  # newest-first and `Enum.group_by/2` preserves that order within each group, so "newest
  # `quota`" is `Enum.take/2`.
  defp retain_terminal(terminal, retention_limit) when length(terminal) <= retention_limit,
    do: terminal

  defp retain_terminal(terminal, retention_limit) do
    by_kind = Enum.group_by(terminal, & &1.effect)
    quota = div(retention_limit, map_size(by_kind))

    kept = Enum.flat_map(by_kind, fn {_kind, entries} -> Enum.take(entries, quota) end)

    case retention_limit - length(kept) do
      spare when spare > 0 ->
        kept ++
          (by_kind
           |> Enum.flat_map(fn {_kind, entries} -> Enum.drop(entries, quota) end)
           |> Enum.sort_by(& &1.sequence, :desc)
           |> Enum.take(spare))

      _full ->
        kept
    end
  end

  defp normalize_query(filters) when is_list(filters) do
    if Keyword.keyword?(filters),
      do: normalize_query(Map.new(filters)),
      else: {:error, :invalid_query}
  end

  defp normalize_query(filters) when is_map(filters) do
    allowed = [:principal, :effect, :status, :since_sequence, :order, :limit]

    with [] <- Map.keys(filters) -- allowed,
         principal when is_nil(principal) or is_binary(principal) <- Map.get(filters, :principal),
         effect when is_nil(effect) or is_atom(effect) <- Map.get(filters, :effect),
         true <- is_nil(effect) or effect in effects(),
         status when is_nil(status) or status in @statuses <- Map.get(filters, :status),
         since when is_integer(since) and since >= 0 <- Map.get(filters, :since_sequence, 0),
         order when order in [:asc, :desc] <- Map.get(filters, :order, :desc),
         limit when is_integer(limit) and limit >= 1 and limit <= @max_query_limit <-
           Map.get(filters, :limit, @default_query_limit) do
      {:ok,
       %{
         principal: principal,
         effect: effect,
         status: status,
         since_sequence: since,
         order: order,
         limit: limit
       }}
    else
      _invalid -> {:error, :invalid_query}
    end
  end

  defp normalize_query(_filters), do: {:error, :invalid_query}

  defp matches?(entry, query) do
    (is_nil(query.principal) or entry.principal == query.principal) and
      (is_nil(query.effect) or entry.effect == query.effect) and
      (is_nil(query.status) or entry.status == query.status) and
      entry.sequence > query.since_sequence
  end

  defp order(entries, :desc), do: entries
  defp order(entries, :asc), do: Enum.reverse(entries)

  defp reconcile_unfinished(checkpoint, adapter, adapter_opts) do
    timestamp = now()

    {entries, next_sequence} =
      checkpoint.entries
      |> Enum.reverse()
      |> Enum.map_reduce(checkpoint.next_sequence, fn
        %Entry{status: :started} = entry, sequence ->
          reconciled = %Entry{
            entry
            | sequence: sequence,
              status: :ambiguous,
              error: sanitize_error(:runtime_restarted_before_settlement),
              settled_at: timestamp
          }

          {reconciled, sequence + 1}

        entry, sequence ->
          {entry, sequence}
      end)

    entries = entries |> Enum.reverse() |> Enum.sort_by(& &1.sequence, :desc)

    if entries == checkpoint.entries do
      {:ok, checkpoint}
    else
      reconciled = %{checkpoint | entries: entries, next_sequence: next_sequence}

      case checkpoint(adapter, adapter_opts, reconciled) do
        :ok -> {:ok, reconciled}
        {:error, reason} -> {:error, {:effect_ledger_reconciliation_failed, reason}}
      end
    end
  end

  defp persist(state, reply, error_tag) do
    case checkpoint_state(state) do
      :ok -> {:ok, reply, state}
      {:error, reason} -> {:error, {error_tag, reason}}
    end
  end

  defp checkpoint_state(state) do
    checkpoint = %{entries: state.entries, next_sequence: state.next_sequence}
    checkpoint(state.adapter, state.opts, checkpoint)
  end

  defp forget_runner(state, effect_id) do
    case Map.pop(state.runners, effect_id) do
      {nil, _runners} ->
        state

      {%{monitor: monitor}, runners} ->
        Process.demonitor(monitor, [:flush])
        %{state | runners: runners, runner_monitors: Map.delete(state.runner_monitors, monitor)}
    end
  end

  defp checkpoint(adapter, opts, checkpoint) do
    result =
      adapter_call(adapter, :put_checkpoint, [
        @store_key,
        Map.put(checkpoint, :version, @checkpoint_version),
        opts
      ])

    case result do
      {:error, {:commit_outcome_unknown, _reason} = ambiguity} -> exit(ambiguity)
      other -> other
    end
  end

  defp load(adapter, adapter_opts) do
    case adapter_call(adapter, :get_checkpoint, [@store_key, adapter_opts]) do
      :not_found ->
        {:ok, %{entries: [], next_sequence: 1}}

      {:ok,
       %{version: @checkpoint_version, entries: entries, next_sequence: next_sequence} =
           checkpoint}
      when is_list(entries) and is_integer(next_sequence) and next_sequence >= 1 ->
        if valid_checkpoint?(entries, next_sequence),
          do: {:ok, Map.take(checkpoint, [:entries, :next_sequence])},
          else: {:error, :invalid_effect_ledger_checkpoint}

      {:ok, %{version: version}} ->
        {:error, {:unsupported_effect_ledger_checkpoint, version}}

      {:ok, _invalid} ->
        {:error, :invalid_effect_ledger_checkpoint}

      {:error, reason} ->
        {:error, {:effect_ledger_checkpoint_unreadable, reason}}

      other ->
        {:error, {:invalid_effect_ledger_storage_response, other}}
    end
  end

  defp valid_checkpoint?(entries, next_sequence) do
    sequences = Enum.map(entries, & &1.sequence)
    started_sequences = Enum.map(entries, & &1.started_sequence)

    Enum.all?(entries, &valid_entry?/1) and
      length(sequences) == MapSet.size(MapSet.new(sequences)) and
      length(started_sequences) == MapSet.size(MapSet.new(started_sequences)) and
      length(entries) == MapSet.size(MapSet.new(entries, & &1.id)) and
      Enum.all?(sequences, &(&1 < next_sequence)) and
      Enum.all?(started_sequences, &(&1 < next_sequence)) and
      sequences == Enum.sort(sequences, :desc)
  rescue
    _error -> false
  end

  defp valid_entry?(%Entry{} = entry) do
    entry.sequence >= 1 and entry.started_sequence >= 1 and
      entry.started_sequence <= entry.sequence and is_binary(entry.id) and entry.id != "" and
      entry.effect in effects() and is_binary(entry.principal) and
      is_map(entry.attempt) and is_map(entry.authority) and is_map(entry.cause) and
      entry.status in @statuses and is_binary(entry.started_at) and
      valid_status_shape?(entry) and is_atom(entry.origin_node)
  end

  defp valid_entry?(_entry), do: false

  defp valid_status_shape?(%Entry{status: :started, settled_at: nil, result: nil, error: nil}),
    do: true

  defp valid_status_shape?(%Entry{status: status, settled_at: settled_at})
       when status in @terminal_statuses and is_binary(settled_at),
       do: true

  defp valid_status_shape?(_entry), do: false

  defp storage_config(opts) do
    case Keyword.fetch(opts, :storage) do
      {:ok, storage} ->
        {:ok, storage}

      :error ->
        {:ok,
         Application.get_env(
           :ouroboros,
           :effect_ledger_storage,
           {Jido.Storage.ETS, table: :ouroboros_effect_ledger}
         )}
    end
  end

  defp normalize_storage(storage) do
    {adapter, adapter_opts} = Jido.Storage.normalize_storage(storage)
    {:ok, adapter, adapter_opts}
  rescue
    error -> {:error, {:invalid_effect_ledger_storage, Exception.message(error)}}
  end

  defp retention_limit(opts) do
    limit =
      Keyword.get_lazy(opts, :retention_limit, fn ->
        Application.get_env(:ouroboros, :effect_ledger_limit, @default_retention_limit)
      end)

    if is_integer(limit) and limit >= 1,
      do: {:ok, limit},
      else: {:error, {:invalid_effect_ledger_limit, limit}}
  end

  defp durability_level(Jido.Storage.ETS), do: :ephemeral_checkpoint
  defp durability_level(Ouroboros.Storage.DurableFile), do: :synced_checkpoint
  defp durability_level(_adapter), do: :durable_checkpoint

  defp adapter_call(adapter, function, arguments) do
    apply(adapter, function, arguments)
  rescue
    error -> {:error, {:adapter_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:adapter_failure, kind, inspect(reason)}}
  end

  defp safe_call(server, message) do
    GenServer.call(server, message)
  catch
    :exit, reason -> {:error, {:effect_ledger_unavailable, reason}}
  end

  defp now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
