defmodule Ouroboros.Upgrade.NodeExecutor do
  @moduledoc """
  Node-local transactional BEAM loader with explicit process migration and rollback.

  `prepare/2` verifies the complete artifact before asking the OTP code server to
  prepare an atomic module batch. `commit/2` suspends declared stateful processes,
  makes the batch visible, runs `code_change/3`, resumes the processes, and returns a
  rollback receipt. Accepted transitions and their rollback receipts are stored as
  one atomic Jido.Storage checkpoint before success is returned. Restart reconciles
  the checkpoint against loaded BEAM identities; corruption, ambiguous write-ahead
  operations, and mismatches leave the executor inspectable but quarantined.

  The storage adapter is selected from the `:storage` start option or the
  `:ouroboros, :upgrade_storage` application environment. The node-local ETS fallback
  is useful for development but is not reboot durable. Prepared-code handles are
  deliberately memory-only; only a SHA-256 token digest and redacted reservation are
  journaled, and the reservation becomes `:lost_on_restart`.

  A commit failure that leaves this node mutated keeps the write-ahead artifact and its
  migration targets in the terminal journal record, so preimages remain restorable even
  though the transition failed. A quarantined executor refuses every mutating call,
  including rollback and promote; `reconcile_quarantine/1` is the only exit and only
  succeeds when the journal again matches loaded code.

  An artifact may also introduce modules that have never been loaded here. The inverse
  of loading a new module is unloading it, so rolling back a committed `:introduce`
  deletes and soft-purges it, and the identity this node then expects for that module is
  `:non_existing` — absence is a checked expectation, not an absence of expectation, so
  reconciliation still fails closed if the name reappears. Unloading is never brutal: a
  process still running introduced code produces `{:introduced_code_in_use, module}` and
  quarantine, exactly as retired code in use does on the replacement path.

  `status/1` never exposes prepare tokens or rollback receipt identifiers. A caller
  that retained a receipt ID can recover the capability through `receipt/2`. It does
  report reservation metadata, and `abort_prepared_reservation/2` releases a reservation
  whose token was lost with its prepare reply.

  This is the fast patch lane. Durable reboot-persistent upgrades still require OTP
  release artifacts (`.appup`/`.relup` and `:release_handler`).
  """

  use GenServer

  alias Ouroboros.Upgrade.{Artifact, Beam, ModuleName, Verifier, Wire}

  @journal_version 2
  @public_operation_limit 50
  @operation_history_limit 100
  @pending_outcomes [:committing, :rolling_back, :promoting]
  @operation_outcomes %{
    prepare: [:prepared],
    commit: [
      :committing,
      :committed,
      :failed,
      :rolled_back_after_journal_failure,
      :ambiguous_after_journal_failure
    ],
    abort: [:aborted],
    rollback: [:rolling_back, :rolled_back, :failed],
    promote: [:promoting, :promoted, :failed],
    restart: [:lost_on_restart, :pending_targets_resumed, :pending_target_resume_failed],
    quarantine: [:reconciliation_required, :cleared]
  }

  defmodule Migration do
    @moduledoc false
    @enforce_keys [:module, :pid]
    defstruct @enforce_keys ++ [extra: nil]
  end

  defmodule Receipt do
    @moduledoc "A node-local capability proving which artifact was committed."
    @enforce_keys [:id, :artifact, :migrations, :committed_at, :node]
    defstruct @enforce_keys
  end

  defmodule Journal do
    @moduledoc false
    # `expected_modules` holds exactly one entry per module name: committing, promoting,
    # and rolling back all replace the entry for the modules they name rather than
    # appending to it, so the map is bounded by the number of distinct modules this node
    # has ever patched and not by how often it patched them. Entries are not capped or
    # aged out on purpose — an expectation is what restart reconciliation fails closed
    # against, and dropping one would silently widen what this node will accept.
    @enforce_keys [
      :version,
      :last_epoch,
      :next_sequence,
      :receipts,
      :reservations,
      :token_outcomes,
      :operations,
      :expected_modules,
      :mode
    ]
    defstruct @enforce_keys ++ [quarantine_reason: nil]
  end

  @type token :: String.t()

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @spec prepare(Artifact.t(), keyword()) :: {:ok, token()} | {:error, term()}
  def prepare(artifact, opts \\ [])

  def prepare(artifact, opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      {server, opts} = client_options(opts)
      GenServer.call(server, {:prepare, artifact, opts}, Keyword.get(opts, :timeout, 15_000))
    else
      {:error, :invalid_options}
    end
  end

  def prepare(_artifact, _opts), do: {:error, :invalid_options}

  @spec receipt(String.t(), keyword()) :: {:ok, Receipt.t()} | :not_found | {:error, term()}
  def receipt(receipt_id, opts \\ [])

  def receipt(receipt_id, opts) when is_binary(receipt_id) and is_list(opts) do
    if receipt_id != "" and Keyword.keyword?(opts) do
      {server, opts} = client_options(opts)
      GenServer.call(server, {:receipt, receipt_id}, Keyword.get(opts, :timeout, 5_000))
    else
      {:error, :invalid_options}
    end
  end

  def receipt(_receipt_id, _opts), do: {:error, :invalid_receipt_id}

  @spec commit(token(), keyword()) :: {:ok, Receipt.t()} | {:error, term(), atom()}
  def commit(token, opts \\ [])

  def commit(token, opts) when is_binary(token) and is_list(opts) do
    if Keyword.keyword?(opts) do
      {server, opts} = client_options(opts)
      GenServer.call(server, {:commit, token, opts}, Keyword.get(opts, :timeout, 30_000))
    else
      {:error, :invalid_options, :unchanged}
    end
  end

  def commit(_token, _opts), do: {:error, :invalid_commit, :unchanged}

  @spec abort(token(), keyword()) :: :ok | {:error, term()}
  def abort(token, opts \\ [])

  def abort(token, opts) when is_binary(token) and is_list(opts) do
    if Keyword.keyword?(opts) do
      {server, opts} = client_options(opts)
      GenServer.call(server, {:abort, token}, Keyword.get(opts, :timeout, 5_000))
    else
      {:error, :invalid_options}
    end
  end

  def abort(_token, _opts), do: {:error, :invalid_request}

  @doc """
  Releases the single prepared reservation for `artifact_id` without its bearer token.

  A prepare whose reply is lost in transport leaves the reservation held and its token
  unknown, which would otherwise wedge the node until the process is killed. This is a
  node-local operator and coordinator path: it is journaled like `abort/2`, it cannot
  affect already committed code, and it never needs the token.
  """
  @spec abort_prepared_reservation(String.t(), keyword()) :: :ok | {:error, term()}
  def abort_prepared_reservation(artifact_id, opts \\ [])

  def abort_prepared_reservation(artifact_id, opts)
      when is_binary(artifact_id) and is_list(opts) do
    if artifact_id != "" and Keyword.keyword?(opts) do
      {server, opts} = client_options(opts)

      GenServer.call(
        server,
        {:abort_prepared_reservation, artifact_id},
        Keyword.get(opts, :timeout, 5_000)
      )
    else
      {:error, :invalid_options}
    end
  end

  def abort_prepared_reservation(_artifact_id, _opts), do: {:error, :invalid_artifact_id}

  @doc """
  Leaves quarantine only if the journal now matches this node's loaded code.

  This replays the startup reconciliation checks against current state and journals the
  transition. Anything that still disagrees is returned as diagnostics and the executor
  stays quarantined; there is no way to declare a mismatch resolved.

  An executor whose checkpoint could not be read at all has nothing to reconcile
  against, and answers `{:error, {:journal_unloaded, reason}}`. The in-memory journal is
  a placeholder, not history: clearing quarantine from it would report success while
  overwriting the evidence on disk with an empty record. The only exit is an operator
  who preserves or removes the checkpoint and restarts this node.
  """
  @spec reconcile_quarantine(keyword()) :: :ok | {:error, term()}
  def reconcile_quarantine(opts \\ [])

  def reconcile_quarantine(opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      {server, opts} = client_options(opts)
      GenServer.call(server, :reconcile_quarantine, Keyword.get(opts, :timeout, 15_000))
    else
      {:error, :invalid_options}
    end
  end

  def reconcile_quarantine(_opts), do: {:error, :invalid_options}

  @spec rollback(Receipt.t(), keyword()) :: :ok | {:error, term(), atom()}
  def rollback(receipt, opts \\ [])

  def rollback(%Receipt{} = receipt, opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      {server, opts} = client_options(opts)
      GenServer.call(server, {:rollback, receipt, opts}, Keyword.get(opts, :timeout, 30_000))
    else
      {:error, :invalid_options, :unchanged}
    end
  end

  def rollback(_receipt, _opts), do: {:error, :invalid_receipt, :unchanged}

  @doc "Makes an accepted patch permanent in memory by giving up fast rollback."
  @spec promote(Receipt.t(), keyword()) :: :ok | {:error, term()}
  def promote(receipt, opts \\ [])

  def promote(%Receipt{} = receipt, opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      {server, opts} = client_options(opts)
      GenServer.call(server, {:promote, receipt}, Keyword.get(opts, :timeout, 30_000))
    else
      {:error, :invalid_options}
    end
  end

  def promote(_receipt, _opts), do: {:error, :invalid_receipt}

  @spec status(keyword()) :: map()
  def status(opts \\ [])

  def status(opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      {server, opts} = client_options(opts)
      GenServer.call(server, :status, Keyword.get(opts, :timeout, 5_000))
    else
      %{mode: :quarantined, error: :invalid_options}
    end
  end

  def status(_opts), do: %{mode: :quarantined, error: :invalid_options}

  @impl true
  def init(opts) do
    policy =
      Keyword.get_lazy(opts, :trust_policy, fn ->
        Application.get_env(:ouroboros, :upgrade_trust_policy, [])
      end)

    {:ok, initialize_state(opts, policy)}
  end

  @impl true
  def handle_call({:prepare, %Artifact{} = artifact, opts}, _from, state) do
    with :ok <- ensure_ready(state),
         :ok <- ensure_no_prepared(state.prepared),
         :ok <- newer_epoch(artifact.epoch, state.journal.last_epoch),
         :ok <-
           Verifier.verify_with_expected(
             artifact,
             state.trust_policy,
             state.journal.expected_modules
           ),
         {:ok, migrations} <- normalize_migrations(artifact, Keyword.get(opts, :migrations, [])),
         # Preparation is disposition-blind on purpose: the code server does not require
         # a module to be loaded to prepare one, so a batch that mixes replacements with
         # first-time introductions still becomes visible in a single `finish_loading/1`.
         triples <- Enum.map(artifact.modules, &{&1.module, &1.filename, &1.binary}),
         {:ok, prepared_code} <- :code.prepare_loading(triples) do
      token = Jido.Signal.ID.generate!()
      token_digest = token_digest(token)
      prepared_at = now()

      prepared = %{
        artifact: artifact,
        code: prepared_code,
        migrations: migrations,
        token_digest: token_digest,
        prepared_at: prepared_at
      }

      reservation = %{
        artifact_id: artifact.id,
        epoch: artifact.epoch,
        prepared_at: prepared_at,
        modules: module_names(artifact)
      }

      journal =
        state.journal
        |> put_reservation(token_digest, reservation)
        |> put_token_outcome(token_digest, artifact, :prepared)
        |> append_operation(:prepare, artifact,
          outcome: :prepared,
          token_digest: token_digest,
          module_count: length(artifact.modules),
          migration_count: length(migrations)
        )

      case persist_journal(state, journal) do
        {:ok, state} ->
          {:reply, {:ok, token}, put_in(state.prepared[token], prepared)}

        {:error, reason, state} ->
          {:reply, {:error, {:journal_persist_failed, public_storage_reason(reason)}}, state}
      end
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
      other -> {:reply, {:error, {:prepare_failed, other}}, state}
    end
  end

  def handle_call({:receipt, receipt_id}, _from, state) do
    reply =
      case Map.fetch(state.journal.receipts, receipt_id) do
        {:ok, receipt} -> {:ok, receipt}
        :error -> :not_found
      end

    {:reply, reply, state}
  end

  def handle_call({:abort, token}, _from, state) do
    case Map.fetch(state.prepared, token) do
      {:ok, prepared} ->
        release_reservation(state, token, prepared)

      :error ->
        if completed_token_operation?(state.journal, token, [:aborted, :lost_on_restart]) do
          {:reply, :ok, state}
        else
          {:reply, {:error, :unknown_token}, state}
        end
    end
  end

  def handle_call({:abort_prepared_reservation, artifact_id}, _from, state)
      when is_binary(artifact_id) do
    case Enum.find(state.prepared, fn {_token, entry} -> entry.artifact.id == artifact_id end) do
      {token, prepared} ->
        release_reservation(state, token, prepared)

      nil ->
        if released_reservation?(state.journal, artifact_id) do
          {:reply, :ok, state}
        else
          {:reply, {:error, {:unknown_reservation, artifact_id}}, state}
        end
    end
  end

  def handle_call({:commit, token, opts}, _from, state) do
    with :ok <- ensure_ready(state) do
      case Map.fetch(state.prepared, token) do
        :error ->
          case committed_receipt_for_token(state.journal, token) do
            {:ok, receipt} ->
              {:reply, {:ok, receipt}, state}

            {:finalized, outcome} ->
              {:reply, {:error, {:commit_already_finalized, outcome}, :unchanged}, state}

            :not_found ->
              {:reply, {:error, :unknown_token, :unchanged}, state}
          end

        {:ok, prepared} ->
          commit_new(prepared, token, opts, state)
      end
    else
      {:error, reason} -> {:reply, {:error, reason, :quarantined}, state}
    end
  end

  def handle_call({:rollback, %Receipt{} = receipt, opts}, _from, state) do
    with :ok <- ensure_ready(state) do
      case Map.fetch(state.journal.receipts, receipt.id) do
        {:ok, ^receipt} ->
          timeout = Keyword.get(opts, :process_timeout, 5_000)

          intent =
            append_operation(state.journal, :rollback, receipt.artifact,
              outcome: :rolling_back,
              receipt_id: receipt.id,
              migration_count: length(receipt.migrations),
              modules: preimage_module_identities(receipt.artifact)
            )

          case persist_journal(state, intent) do
            {:ok, state} ->
              finish_rollback(receipt, timeout, state)

            {:error, reason, state} ->
              {:reply,
               {:error, {:journal_persist_failed, public_storage_reason(reason)}, :unchanged},
               state}
          end

        _ ->
          if completed_receipt_operation?(state.journal, :rollback, receipt.id, :rolled_back) do
            {:reply, :ok, state}
          else
            {:reply, {:error, :unknown_receipt, :unchanged}, state}
          end
      end
    else
      {:error, reason} -> {:reply, {:error, reason, :quarantined}, state}
    end
  end

  def handle_call({:promote, %Receipt{} = receipt}, _from, state) do
    with :ok <- ensure_ready(state) do
      case Map.fetch(state.journal.receipts, receipt.id) do
        {:ok, ^receipt} ->
          intent =
            append_operation(state.journal, :promote, receipt.artifact,
              outcome: :promoting,
              receipt_id: receipt.id,
              modules: target_module_identities(receipt.artifact)
            )

          case persist_journal(state, intent) do
            {:ok, state} ->
              finish_promote(receipt, state)

            {:error, reason, state} ->
              {:reply, {:error, {:journal_persist_failed, public_storage_reason(reason)}}, state}
          end

        _ ->
          if completed_receipt_operation?(state.journal, :promote, receipt.id, :promoted) do
            {:reply, :ok, state}
          else
            {:reply, {:error, :unknown_receipt}, state}
          end
      end
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:reconcile_quarantine, _from, state) do
    cond do
      # The placeholder journal an unreadable checkpoint comes up on satisfies every
      # reconciliation check vacuously. Answering `:ok` here would tell an operator the
      # node is reconciled and replace the preserved evidence with an empty record.
      not state.journal_loaded? ->
        {:reply, {:error, {:journal_unloaded, state.journal.quarantine_reason}}, state}

      state.journal.mode == :ready ->
        {:reply, {:error, :not_quarantined}, state}

      true ->
        case reconcile_current_state(state.journal) do
          :ok ->
            clear_quarantine(state)

          {:error, reason} ->
            {:reply, {:error, {:reconciliation_failed, public_quarantine_reason(reason)}}, state}
        end
    end
  end

  def handle_call(:status, _from, state) do
    {:reply,
     %{
       node: node(),
       mode: state.journal.mode,
       quarantine_reason: public_quarantine_reason(state.journal.quarantine_reason),
       last_epoch: state.journal.last_epoch,
       prepared:
         Enum.map(state.prepared, fn {_token, prepared} ->
           %{
             artifact_id: prepared.artifact.id,
             epoch: prepared.artifact.epoch,
             prepared_at: prepared.prepared_at,
             modules: module_names(prepared.artifact)
           }
         end),
       rollback_receipts: public_receipts(state.journal.receipts),
       operations: public_operations(state.journal.operations)
     }, state}
  end

  def handle_call({operation, _value}, _from, state)
      when operation in [:abort, :promote, :abort_prepared_reservation] do
    {:reply, {:error, :invalid_request}, state}
  end

  def handle_call({operation, _value, _opts}, _from, state)
      when operation in [:prepare, :commit, :rollback] do
    reply =
      if operation in [:commit, :rollback],
        do: {:error, :invalid_request, :unchanged},
        else: {:error, :invalid_request}

    {:reply, reply, state}
  end

  defp initialize_state(opts, policy) do
    case storage_from(opts) do
      {:ok, storage} ->
        load_state(storage, policy)

      {:error, reason} ->
        journal = quarantine_journal(empty_journal(), {:storage_configuration, reason})
        unloaded_state(nil, policy, journal)
    end
  end

  defp storage_from(opts) do
    configured =
      Keyword.get_lazy(opts, :storage, fn ->
        Application.get_env(
          :ouroboros,
          :upgrade_storage,
          {Jido.Storage.ETS, table: :ouroboros_upgrade}
        )
      end)

    try do
      {adapter, adapter_opts} = Jido.Storage.normalize_storage(configured)

      if Keyword.keyword?(adapter_opts) do
        {:ok, %{adapter: adapter, opts: adapter_opts}}
      else
        {:error, :invalid_adapter_options}
      end
    rescue
      _error -> {:error, :invalid_storage_configuration}
    catch
      _kind, _reason -> {:error, :invalid_storage_configuration}
    end
  end

  defp load_state(storage, policy) do
    case storage_get(storage) do
      :not_found ->
        base_state(storage, policy, empty_journal())

      {:ok, %Journal{} = journal} ->
        case validate_journal(journal) do
          :ok -> reconcile_loaded_journal(storage, policy, journal)
          {:error, reason} -> corrupt_state(storage, policy, reason)
        end

      {:ok, _invalid} ->
        corrupt_state(storage, policy, :invalid_checkpoint)

      {:error, reason} ->
        journal =
          empty_journal()
          |> quarantine_journal({:journal_read_failed, public_storage_reason(reason)})

        unloaded_state(storage, policy, journal)

      other ->
        journal =
          empty_journal()
          |> quarantine_journal({:invalid_storage_response, storage_response_kind(other)})

        unloaded_state(storage, policy, journal)
    end
  end

  defp corrupt_state(storage, policy, reason) do
    journal =
      empty_journal()
      |> quarantine_journal({:corrupt_checkpoint, public_corruption_reason(reason)})

    # Do not overwrite corrupt evidence automatically. An operator must preserve or
    # replace it deliberately; the live executor remains available for inspection only.
    unloaded_state(storage, policy, journal)
  end

  defp reconcile_loaded_journal(storage, policy, journal) do
    {journal, lost_reservations?} = lose_prepared_reservations(journal)
    {journal, target_reconciliation} = resume_pending_commit_targets(journal)

    reconciliation =
      with :ok <- target_reconciliation,
           :ok <- reconcile_current_state(journal) do
        :ok
      end

    journal =
      case reconciliation do
        :ok -> journal
        {:error, reason} -> quarantine_journal(journal, {:startup_reconciliation, reason})
      end

    state = base_state(storage, policy, journal)

    if lost_reservations? or reconciliation != :ok do
      case persist_journal(state, journal) do
        {:ok, state} ->
          state

        {:error, reason, state} ->
          journal =
            state.journal
            |> quarantine_journal({:startup_journal_write_failed, public_storage_reason(reason)})

          %{state | journal: journal}
      end
    else
      state
    end
  end

  defp release_reservation(state, token, prepared) do
    journal =
      state.journal
      |> delete_reservation(prepared.token_digest)
      |> put_token_outcome(prepared.token_digest, prepared.artifact, :aborted)
      |> append_operation(:abort, prepared.artifact,
        outcome: :aborted,
        token_digest: prepared.token_digest
      )

    case persist_journal(state, journal) do
      {:ok, state} ->
        {:reply, :ok, %{state | prepared: Map.delete(state.prepared, token)}}

      {:error, reason, state} ->
        {:reply, {:error, {:journal_persist_failed, public_storage_reason(reason)}}, state}
    end
  end

  # An ambiguous prepare can be retried by a coordinator that never learned the outcome
  # of the first attempt, so a reservation already released for this artifact answers
  # the same way a token abort does.
  defp released_reservation?(journal, artifact_id) do
    Enum.any?(journal.token_outcomes, fn {_digest, outcome} ->
      outcome.artifact_id == artifact_id and outcome.outcome in [:aborted, :lost_on_restart]
    end)
  end

  defp base_state(storage, policy, journal) do
    %{
      storage: storage,
      trust_policy: policy,
      journal: journal,
      prepared: %{},
      journal_loaded?: true
    }
  end

  # A checkpoint that exists but could not be read is not history this executor holds.
  # The journal it comes up on is a placeholder, and every write refuses rather than
  # becoming the first writer over evidence nobody has read yet.
  defp unloaded_state(storage, policy, journal) do
    %{base_state(storage, policy, journal) | journal_loaded?: false}
  end

  defp empty_journal do
    %Journal{
      version: @journal_version,
      last_epoch: 0,
      next_sequence: 1,
      receipts: %{},
      reservations: %{},
      token_outcomes: %{},
      operations: [],
      expected_modules: %{},
      mode: :ready,
      quarantine_reason: nil
    }
  end

  defp commit_new(prepared, token, opts, state) do
    case revalidate_commit(prepared.artifact, state) do
      :ok ->
        timeout = Keyword.get(opts, :process_timeout, 5_000)

        intent =
          state.journal
          |> delete_reservation(prepared.token_digest)
          |> advance_epoch(prepared.artifact.epoch)
          |> put_token_outcome(prepared.token_digest, prepared.artifact, :committing)
          |> append_operation(:commit, prepared.artifact,
            outcome: :committing,
            token_digest: prepared.token_digest,
            module_count: length(prepared.artifact.modules),
            migration_count: length(prepared.migrations),
            modules: target_module_identities(prepared.artifact),
            artifact: prepared.artifact,
            migrations: prepared.migrations
          )

        case persist_journal(state, intent) do
          {:ok, state} ->
            finish_commit(prepared, token, timeout, state)

          {:error, storage_reason, state} ->
            {:reply,
             {:error, {:journal_persist_failed, public_storage_reason(storage_reason)},
              :unchanged}, state}
        end

      {:error, reason} ->
        {:reply, {:error, {:commit_revalidation_failed, reason}, :unchanged}, state}
    end
  end

  defp finish_commit(prepared, token, timeout, state) do
    case commit_prepared(prepared, timeout) do
      {:ok, receipt} ->
        persist_committed(prepared, token, receipt, timeout, state)

      {:error, reason, recovery, rollback_material} ->
        journal =
          state.journal
          |> clear_pending_operation(:commit, :token_digest, prepared.token_digest)
          |> put_token_outcome(prepared.token_digest, prepared.artifact, :failed)
          |> append_failed_commit(prepared, reason, rollback_material)

        journal =
          if recovery == :quarantined,
            do: quarantine_journal(journal, failed_commit_quarantine(rollback_material)),
            else: journal

        state = %{state | prepared: Map.delete(state.prepared, token)}

        case persist_journal(state, journal) do
          {:ok, state} ->
            {:reply, {:error, reason, recovery}, state}

          {:error, storage_reason, state} ->
            {state, _persisted?} =
              quarantine_after_mutation(
                state,
                journal,
                {:failed_commit_journal_failed, public_storage_reason(storage_reason)}
              )

            {:reply,
             {:error,
              {:journal_persist_failed, public_storage_reason(storage_reason),
               :reconciliation_required}, :quarantined}, state}
        end
    end
  end

  # The write-ahead `:committing` record is the only place preimage bytes are durable.
  # Clearing it is correct once the node is provably back on its preimages, and wrong
  # when the failure left code mutated: the same record is then the only journaled way
  # back. Carry the artifact and its migration targets into the terminal record in that
  # case so an operator or a later restart can still restore them.
  #
  # For an introduced module the retained material is only the module identity: there
  # are no preimage bytes to keep because the way back is `:code.delete/1` plus a soft
  # purge, which needs nothing but the name. The record is retained all the same, so a
  # mixed artifact keeps one shape and the recorded `modules` list still states, per
  # module, what this node should be holding — a hash for a replacement, absence for an
  # introduction.
  defp append_failed_commit(journal, prepared, reason, :not_required) do
    append_operation(journal, :commit, prepared.artifact,
      outcome: :failed,
      token_digest: prepared.token_digest,
      reason: public_operation_reason(reason)
    )
  end

  defp append_failed_commit(journal, prepared, reason, :required) do
    append_operation(journal, :commit, prepared.artifact,
      outcome: :failed,
      token_digest: prepared.token_digest,
      reason: public_operation_reason(reason),
      module_count: length(prepared.artifact.modules),
      migration_count: length(prepared.migrations),
      modules: preimage_module_identities(prepared.artifact),
      artifact: prepared.artifact,
      migrations: prepared.migrations
    )
  end

  defp failed_commit_quarantine(:required),
    do: {:commit_recovery_failed, :rollback_material_retained}

  defp failed_commit_quarantine(:not_required),
    do: {:commit_recovery_failed, :reconciliation_required}

  defp persist_committed(prepared, token, receipt, timeout, state) do
    journal =
      state.journal
      |> clear_pending_operation(:commit, :token_digest, prepared.token_digest)
      |> put_receipt(receipt)
      |> put_token_outcome(prepared.token_digest, prepared.artifact, :committed, receipt.id)
      |> expect_committed(receipt, :committed)
      |> append_operation(:commit, prepared.artifact,
        outcome: :committed,
        token_digest: prepared.token_digest,
        receipt_id: receipt.id,
        migration_count: length(receipt.migrations)
      )

    state = %{state | prepared: Map.delete(state.prepared, token)}

    case persist_journal(state, journal) do
      {:ok, state} ->
        {:reply, {:ok, receipt}, state}

      {:error, storage_reason, failed_state} ->
        compensate_unjournaled_commit(
          failed_state,
          prepared,
          receipt,
          timeout,
          storage_reason
        )
    end
  end

  defp compensate_unjournaled_commit(state, prepared, receipt, timeout, storage_reason) do
    case rollback_receipt(receipt, timeout) do
      :ok ->
        journal =
          state.journal
          |> clear_pending_operation(:commit, :token_digest, prepared.token_digest)
          |> put_token_outcome(
            prepared.token_digest,
            prepared.artifact,
            :rolled_back_after_journal_failure
          )
          |> expect_preimages(receipt)
          |> append_operation(:commit, prepared.artifact,
            outcome: :rolled_back_after_journal_failure,
            token_digest: prepared.token_digest,
            reason: public_storage_reason(storage_reason)
          )

        {state, _persisted?} =
          quarantine_after_mutation(
            state,
            journal,
            {:commit_journal_failed_compensated, public_storage_reason(storage_reason)}
          )

        {:reply,
         {:error,
          {:journal_persist_failed, public_storage_reason(storage_reason), :commit_compensated},
          :rolled_back}, state}

      {:error, rollback_reason, _recovery} ->
        journal =
          state.journal
          |> clear_pending_operation(:commit, :token_digest, prepared.token_digest)
          |> put_receipt(receipt)
          |> put_token_outcome(prepared.token_digest, prepared.artifact, :ambiguous, receipt.id)
          |> expect_committed(receipt, :ambiguous)
          |> append_operation(:commit, prepared.artifact,
            outcome: :ambiguous_after_journal_failure,
            token_digest: prepared.token_digest,
            receipt_id: receipt.id,
            reason: :reconciliation_required
          )

        {state, _persisted?} =
          quarantine_after_mutation(
            state,
            journal,
            {:commit_journal_and_compensation_failed, public_storage_reason(storage_reason),
             public_operation_reason(rollback_reason)}
          )

        {:reply,
         {:error,
          {:journal_persist_failed, public_storage_reason(storage_reason), :compensation_failed},
          :quarantined}, state}
    end
  end

  defp finish_rollback(receipt, timeout, state) do
    case rollback_receipt(receipt, timeout) do
      :ok ->
        journal =
          state.journal
          |> clear_pending_operation(:rollback, :receipt_id, receipt.id)
          |> finalize_tokens_for_receipt(receipt.id, :rolled_back)
          |> delete_receipt(receipt.id)
          |> expect_preimages(receipt)
          |> append_operation(:rollback, receipt.artifact,
            outcome: :rolled_back,
            receipt_id: receipt.id
          )

        case persist_journal(state, journal) do
          {:ok, state} ->
            {:reply, :ok, state}

          {:error, reason, failed_state} ->
            {quarantined, _persisted?} =
              quarantine_after_mutation(
                failed_state,
                journal,
                {:rollback_journal_failed, public_storage_reason(reason)}
              )

            {:reply,
             {:error,
              {:journal_persist_failed, public_storage_reason(reason), :reconciliation_required},
              :quarantined}, quarantined}
        end

      {:error, reason, recovery} ->
        journal =
          state.journal
          |> clear_pending_operation(:rollback, :receipt_id, receipt.id)
          |> append_operation(:rollback, receipt.artifact,
            outcome: :failed,
            receipt_id: receipt.id,
            reason: public_operation_reason(reason)
          )

        journal =
          if recovery == :quarantined,
            do: quarantine_journal(journal, {:rollback_failed, :reconciliation_required}),
            else: journal

        case persist_journal(state, journal) do
          {:ok, state} ->
            {:reply, {:error, reason, recovery}, state}

          {:error, storage_reason, failed_state} ->
            {quarantined, _persisted?} =
              quarantine_after_mutation(
                failed_state,
                journal,
                {:rollback_failure_journal_failed, public_storage_reason(storage_reason)}
              )

            {:reply,
             {:error,
              {:journal_persist_failed, public_storage_reason(storage_reason),
               :reconciliation_required}, :quarantined}, quarantined}
        end
    end
  end

  defp finish_promote(receipt, state) do
    case purge_old_versions(receipt.artifact) do
      :ok ->
        journal =
          state.journal
          |> clear_pending_operation(:promote, :receipt_id, receipt.id)
          |> finalize_tokens_for_receipt(receipt.id, :promoted)
          |> delete_receipt(receipt.id)
          |> expect_committed(receipt, :promoted)
          |> append_operation(:promote, receipt.artifact,
            outcome: :promoted,
            receipt_id: receipt.id
          )

        case persist_journal(state, journal) do
          {:ok, state} ->
            {:reply, :ok, state}

          {:error, reason, failed_state} ->
            {quarantined, _persisted?} =
              quarantine_after_mutation(
                failed_state,
                journal,
                {:promote_journal_failed, public_storage_reason(reason)}
              )

            {:reply,
             {:error,
              {:journal_persist_failed, public_storage_reason(reason), :reconciliation_required}},
             quarantined}
        end

      {:error, reason} ->
        journal =
          state.journal
          |> clear_pending_operation(:promote, :receipt_id, receipt.id)
          |> quarantine_journal({:promote_failed, :reconciliation_required})
          |> append_operation(:promote, receipt.artifact,
            outcome: :failed,
            receipt_id: receipt.id,
            reason: public_operation_reason(reason)
          )

        {state, _persisted?} =
          quarantine_after_mutation(
            state,
            journal,
            {:promote_failed, public_operation_reason(reason)}
          )

        {:reply, {:error, {:promote_failed, reason, :reconciliation_required}}, state}
    end
  end

  defp persist_journal(%{storage: nil} = state, _journal) do
    {:error, :storage_unavailable, state}
  end

  defp persist_journal(%{journal_loaded?: false} = state, _journal) do
    {:error, :journal_unloaded, state}
  end

  defp persist_journal(state, journal) do
    case storage_put(state.storage, journal) do
      :ok -> {:ok, %{state | journal: journal}}
      {:error, {:commit_outcome_unknown, _reason} = ambiguity} -> exit(ambiguity)
      {:error, reason} -> {:error, reason, state}
      other -> {:error, {:invalid_storage_response, storage_response_kind(other)}, state}
    end
  end

  defp quarantine_after_mutation(state, base_journal, reason) do
    journal =
      base_journal
      |> quarantine_journal(reason)
      |> append_system_operation(:quarantine, :reconciliation_required,
        reason: public_quarantine_reason(reason)
      )

    case persist_journal(state, journal) do
      {:ok, state} -> {state, true}
      {:error, _reason, state} -> {%{state | journal: journal}, false}
    end
  end

  defp ensure_ready(%{journal: %Journal{mode: :ready}}), do: :ok

  defp ensure_ready(%{journal: %Journal{} = journal}) do
    {:error, {:executor_quarantined, public_quarantine_reason(journal.quarantine_reason)}}
  end

  defp client_options(opts) do
    {server, opts} = Keyword.pop(opts, :server, __MODULE__)
    {server, opts}
  end

  defp storage_get(storage) do
    safe_storage_call(fn ->
      case storage.adapter.get_checkpoint(journal_key(), storage.opts) do
        {:ok, wire} ->
          case Wire.load(wire) do
            %Journal{} = journal -> {:ok, journal_from_wire(journal)}
            other -> {:ok, other}
          end

        other ->
          other
      end
    end)
  end

  defp storage_put(storage, journal) do
    safe_storage_call(fn ->
      storage.adapter.put_checkpoint(
        journal_key(),
        Wire.dump(journal_to_wire(journal)),
        storage.opts
      )
    end)
  end

  # ## Module names across the checkpoint boundary
  #
  # A capability module's name is an atom only in the VM that loaded its code. This
  # journal is read by the VM that comes back after that one stopped, and
  # `binary_to_term/2` in `[:safe]` mode refuses a term naming an atom the reader has
  # never interned — so a journal that stored the atom would be read as corruption, come
  # up on the empty placeholder, and lose the receipts and expectations that are the only
  # way back. Names are written as binaries instead; see `Ouroboros.Upgrade.ModuleName`.
  #
  # Names that arrive next to BEAM bytes are resolved from those bytes: reading the
  # stored code interns the module it defines, so nothing enters the atom table that this
  # journal's own bytes do not already name, and `valid_beam_data?/1` still checks the
  # journaled name against them. Receipts are converted first for that reason — an
  # operation naming a receipt's modules carries the names without the bytes.
  #
  # A name that still does not resolve stays a binary, and reconciliation reads it for
  # what it is: a module this node is not holding. That fails closed with the journal
  # intact, which is the point.
  defp journal_to_wire(%Journal{} = journal) do
    map_journal_modules(journal, &ModuleName.to_wire/1, &beam_to_wire/1)
  end

  defp journal_from_wire(%Journal{} = journal) do
    map_journal_modules(journal, &ModuleName.from_wire/1, &beam_from_wire/1)
  end

  defp map_journal_modules(journal, name, beam) do
    receipts =
      Map.new(journal.receipts, fn {id, receipt} -> {id, map_receipt(receipt, name, beam)} end)

    operations = Enum.map(journal.operations, &map_operation(&1, name, beam))

    reservations =
      Map.new(journal.reservations, fn {digest, reservation} ->
        {digest, map_reservation(reservation, name)}
      end)

    expected_modules =
      Map.new(journal.expected_modules, fn {module, identity} -> {name.(module), identity} end)

    %{
      journal
      | receipts: receipts,
        operations: operations,
        reservations: reservations,
        expected_modules: expected_modules,
        quarantine_reason: map_reason(journal.quarantine_reason, name)
    }
  end

  defp beam_to_wire(%Beam{} = beam), do: %{beam | module: ModuleName.to_wire(beam.module)}
  defp beam_to_wire(beam), do: beam

  defp beam_from_wire(%Beam{module: module, binary: binary} = beam)
       when is_binary(module) and is_binary(binary) do
    _interned = Beam.inspect_binary(binary)
    %{beam | module: ModuleName.from_wire(module)}
  end

  defp beam_from_wire(%Beam{module: module} = beam) when is_binary(module),
    do: %{beam | module: ModuleName.from_wire(module)}

  defp beam_from_wire(beam), do: beam

  defp map_receipt(%Receipt{} = receipt, name, beam) do
    artifact = map_artifact(receipt.artifact, beam)
    %{receipt | artifact: artifact, migrations: map_migrations(receipt.migrations, name)}
  end

  defp map_receipt(receipt, _name, _beam), do: receipt

  defp map_artifact(%Artifact{modules: modules} = artifact, beam) when is_list(modules),
    do: %{artifact | modules: Enum.map(modules, beam)}

  defp map_artifact(artifact, _beam), do: artifact

  defp map_migrations(migrations, name) when is_list(migrations) do
    Enum.map(migrations, fn
      %Migration{} = migration -> %{migration | module: name.(migration.module)}
      other -> other
    end)
  end

  defp map_migrations(migrations, _name), do: migrations

  defp map_reservation(%{modules: modules} = reservation, name) when is_list(modules),
    do: %{reservation | modules: Enum.map(modules, name)}

  defp map_reservation(reservation, _name), do: reservation

  defp map_operation(operation, name, beam) when is_map(operation) do
    operation
    |> map_operation_key(:artifact, &map_artifact(&1, beam))
    |> map_operation_key(:migrations, &map_migrations(&1, name))
    |> map_operation_key(:modules, &map_module_identities(&1, name))
    |> map_operation_key(:reason, &map_reason(&1, name))
  end

  defp map_operation(operation, _name, _beam), do: operation

  defp map_operation_key(operation, key, fun) do
    case Map.fetch(operation, key) do
      {:ok, value} -> Map.put(operation, key, fun.(value))
      :error -> operation
    end
  end

  defp map_module_identities(modules, name) when is_list(modules) do
    Enum.map(modules, fn
      %{module: module} = identity -> %{identity | module: name.(module)}
      module -> name.(module)
    end)
  end

  defp map_module_identities(modules, _name), do: modules

  defp map_reason(reason, name) when is_tuple(reason) do
    reason |> Tuple.to_list() |> Enum.map(&map_reason(&1, name)) |> List.to_tuple()
  end

  defp map_reason(reason, name), do: name.(reason)

  # The journal version is deliberately *not* part of the key. Versioning the key would
  # hide an unreadable journal behind a `:not_found` and let this executor come up ready
  # with an empty history while the node's code was already patched. One stable key means
  # a journal this build cannot interpret is read, rejected by `validate_journal/1`, and
  # quarantined with its evidence left untouched.
  defp journal_key, do: {:ouroboros, :upgrade_node_executor, node()}

  defp safe_storage_call(fun) do
    fun.()
  rescue
    _error -> {:error, :adapter_exception}
  catch
    :exit, _reason -> {:error, :adapter_exit}
    _kind, _reason -> {:error, :adapter_failure}
  end

  defp validate_journal(%Journal{} = journal) do
    cond do
      journal.version != @journal_version ->
        {:error, :unsupported_version}

      not is_integer(journal.last_epoch) or journal.last_epoch < 0 ->
        {:error, :invalid_last_epoch}

      not is_integer(journal.next_sequence) or journal.next_sequence < 1 ->
        {:error, :invalid_next_sequence}

      journal.mode not in [:ready, :quarantined] ->
        {:error, :invalid_mode}

      journal.mode == :ready and not is_nil(journal.quarantine_reason) ->
        {:error, :invalid_ready_reason}

      not valid_receipts?(journal.receipts, journal.last_epoch) ->
        {:error, :invalid_receipts}

      not valid_reservations?(journal.reservations) ->
        {:error, :invalid_reservations}

      not valid_token_outcomes?(journal.token_outcomes) ->
        {:error, :invalid_token_outcomes}

      not valid_operations?(journal.operations, journal.next_sequence) ->
        {:error, :invalid_operations}

      not valid_expected_modules?(journal.expected_modules) ->
        {:error, :invalid_expected_modules}

      not valid_journal_relationships?(journal) ->
        {:error, :invalid_journal_relationships}

      true ->
        :ok
    end
  rescue
    _error -> {:error, :invalid_checkpoint}
  catch
    _kind, _reason -> {:error, :invalid_checkpoint}
  end

  defp valid_receipts?(receipts, last_epoch) when is_map(receipts) do
    Enum.all?(receipts, fn
      {id,
       %Receipt{
         id: id,
         artifact: %Artifact{} = artifact,
         migrations: migrations,
         committed_at: committed_at,
         node: receipt_node
       }}
      when is_binary(id) and is_list(migrations) and is_binary(committed_at) ->
        artifact.epoch <= last_epoch and receipt_node == node() and valid_artifact_data?(artifact) and
          Enum.all?(migrations, &valid_persisted_migration?/1)

      _other ->
        false
    end)
  end

  defp valid_receipts?(_receipts, _last_epoch), do: false

  defp valid_artifact_data?(%Artifact{} = artifact) do
    is_binary(artifact.id) and artifact.id != "" and is_integer(artifact.epoch) and
      artifact.epoch > 0 and is_list(artifact.modules) and artifact.modules != [] and
      Enum.all?(artifact.modules, &valid_beam_data?/1) and is_binary(artifact.otp_release) and
      is_binary(artifact.elixir_version) and is_binary(artifact.system_architecture) and
      is_binary(artifact.created_at) and is_map(artifact.metadata) and
      valid_signature_envelope?(artifact.signature)
  end

  defp valid_beam_data?(%Beam{disposition: :replace} = beam) do
    with true <- valid_new_beam_data?(beam),
         true <- is_list(beam.old_filename),
         true <- is_binary(beam.old_binary),
         true <- valid_sha256?(beam.old_sha256),
         true <- is_binary(beam.old_md5),
         true <- is_boolean(beam.stateful),
         true <- Beam.portable_term?(beam.migration_extra),
         true <- beam.stateful or is_nil(beam.migration_extra),
         {:ok, old_info} <- Beam.inspect_binary(beam.old_binary) do
      old_info.module == beam.module and old_info.md5 == beam.old_md5 and
        old_info.vsn == beam.old_vsn and Beam.sha256(beam.old_binary) == beam.old_sha256 and
        not old_info.on_load? and not old_info.nif? and not old_info.protocol?
    else
      _other -> false
    end
  rescue
    _error -> false
  end

  defp valid_beam_data?(%Beam{disposition: :introduce} = beam) do
    valid_new_beam_data?(beam) and is_nil(beam.old_filename) and is_nil(beam.old_binary) and
      is_nil(beam.old_sha256) and is_nil(beam.old_md5) and is_nil(beam.old_vsn) and
      beam.stateful == false and is_nil(beam.migration_extra)
  rescue
    _error -> false
  end

  defp valid_beam_data?(_beam), do: false

  defp valid_new_beam_data?(%Beam{} = beam) do
    with true <- is_atom(beam.module),
         true <- is_list(beam.filename),
         true <- is_binary(beam.binary),
         true <- valid_sha256?(beam.sha256),
         true <- is_binary(beam.md5),
         {:ok, new_info} <- Beam.inspect_binary(beam.binary) do
      new_info.module == beam.module and new_info.md5 == beam.md5 and
        new_info.vsn == beam.vsn and Beam.sha256(beam.binary) == beam.sha256 and
        not new_info.on_load? and not new_info.nif? and not new_info.protocol?
    else
      _other -> false
    end
  end

  defp valid_signature_envelope?(nil), do: true

  defp valid_signature_envelope?(%{signer: signer, value: value}) do
    is_binary(signer) and signer != "" and is_binary(value) and byte_size(value) == 64
  end

  defp valid_signature_envelope?(_signature), do: false

  defp valid_sha256?(value), do: is_binary(value) and byte_size(value) == 64

  defp valid_persisted_migration?(%Migration{module: module, pid: pid, extra: extra}) do
    is_atom(module) and is_pid(pid) and node(pid) == node() and portable_migration_extra?(extra)
  end

  defp valid_persisted_migration?(_migration), do: false

  defp valid_reservations?(reservations) when is_map(reservations) do
    Enum.all?(reservations, fn
      {digest, %{artifact_id: id, epoch: epoch, prepared_at: prepared_at, modules: modules}}
      when is_binary(digest) and byte_size(digest) == 64 and is_binary(id) and
             is_integer(epoch) and epoch > 0 and is_binary(prepared_at) and is_list(modules) ->
        Enum.all?(modules, &module_name?/1)

      _other ->
        false
    end)
  end

  defp valid_reservations?(_reservations), do: false

  defp valid_token_outcomes?(outcomes) when is_map(outcomes) do
    Enum.all?(outcomes, fn
      {digest, %{artifact_id: id, epoch: epoch, outcome: outcome} = entry}
      when is_binary(digest) and byte_size(digest) == 64 and is_binary(id) and
             is_integer(epoch) and epoch > 0 and
             outcome in [
               :prepared,
               :aborted,
               :lost_on_restart,
               :committing,
               :committed,
               :failed,
               :rolled_back_after_journal_failure,
               :rolled_back,
               :promoted,
               :ambiguous
             ] ->
        optional_binary?(Map.get(entry, :receipt_id)) and
          Map.keys(entry) -- [:artifact_id, :epoch, :outcome, :receipt_id] == []

      _other ->
        false
    end)
  end

  defp valid_token_outcomes?(_outcomes), do: false

  defp valid_operations?(operations, next_sequence) when is_list(operations) do
    sequences = Enum.map(operations, &Map.get(&1, :sequence))

    Enum.all?(operations, &valid_operation?/1) and sequences == Enum.uniq(sequences) and
      sequences == Enum.sort(sequences) and Enum.all?(sequences, &(&1 < next_sequence))
  end

  defp valid_operations?(_operations, _next_sequence), do: false

  defp valid_operation?(operation) when is_map(operation) do
    allowed =
      MapSet.new([
        :sequence,
        :operation,
        :outcome,
        :artifact_id,
        :epoch,
        :occurred_at,
        :token_digest,
        :receipt_id,
        :module_count,
        :migration_count,
        :modules,
        :artifact,
        :migrations,
        :reason
      ])

    keys_valid? = operation |> Map.keys() |> Enum.all?(&MapSet.member?(allowed, &1))

    keys_valid? and is_integer(operation[:sequence]) and operation[:sequence] > 0 and
      valid_operation_outcome?(operation[:operation], operation[:outcome]) and
      is_binary(operation[:occurred_at]) and
      optional_binary?(operation[:artifact_id]) and optional_positive_integer?(operation[:epoch]) and
      optional_digest?(operation[:token_digest]) and optional_binary?(operation[:receipt_id]) and
      optional_non_negative_integer?(operation[:module_count]) and
      optional_non_negative_integer?(operation[:migration_count]) and
      optional_operation_modules?(operation[:modules]) and
      optional_operation_artifact?(operation[:artifact]) and
      optional_operation_migrations?(operation[:migrations]) and safe_reason?(operation[:reason])
  end

  defp valid_operation?(_operation), do: false

  defp valid_operation_outcome?(operation, outcome) do
    outcome in Map.get(@operation_outcomes, operation, [])
  end

  defp valid_expected_modules?(expected) when is_map(expected) do
    Enum.all?(expected, fn
      {module,
       %{
         sha256: sha256,
         md5: md5,
         artifact_id: artifact_id,
         epoch: epoch,
         disposition: disposition
       }}
      when is_binary(sha256) and byte_size(sha256) == 64 and is_binary(md5) and
             is_binary(artifact_id) and is_integer(epoch) and epoch > 0 and
             disposition in [:committed, :promoted, :rolled_back, :ambiguous] ->
        module_name?(module)

      # The absent identity, and the only transition that can produce it: an
      # introduction that was rolled back. A committed or promoted module is present by
      # definition, so pairing absence with those dispositions is corruption.
      {module,
       %{
         sha256: :non_existing,
         md5: :non_existing,
         artifact_id: artifact_id,
         epoch: epoch,
         disposition: :rolled_back
       }}
      when is_binary(artifact_id) and is_integer(epoch) and epoch > 0 ->
        module_name?(module)

      _other ->
        false
    end)
  end

  defp valid_expected_modules?(_expected), do: false

  # A journaled module name is an atom when this VM knows it and the binary the
  # checkpoint stored when it does not. Both are names; neither is corruption.
  defp module_name?(module), do: (is_atom(module) and not is_nil(module)) or is_binary(module)

  defp valid_journal_relationships?(journal) do
    map_size(journal.reservations) <= 1 and
      valid_reservation_relationships?(journal) and
      valid_token_relationships?(journal) and
      valid_pending_relationships?(journal) and
      valid_retained_material_relationships?(journal) and
      valid_receipt_expectations?(journal)
  end

  # A terminal commit record carries rollback material only when the failure left this
  # node mutated. When it does, the retained artifact and migration targets are the
  # only remaining way back and must describe the same transition the record names.
  defp valid_retained_material_relationships?(journal) do
    journal.operations
    |> Enum.filter(&(&1.operation == :commit and &1.outcome == :failed))
    |> Enum.all?(fn operation ->
      is_nil(operation[:artifact]) or valid_retained_commit_context?(operation)
    end)
  end

  defp valid_retained_commit_context?(%{
         artifact_id: artifact_id,
         epoch: epoch,
         module_count: module_count,
         migration_count: migration_count,
         modules: modules,
         artifact: %Artifact{} = artifact,
         migrations: migrations
       })
       when is_list(modules) and is_list(migrations) do
    artifact.id == artifact_id and artifact.epoch == epoch and
      module_count == length(artifact.modules) and migration_count == length(migrations) and
      modules == preimage_module_identities(artifact) and
      valid_pending_migration_relationships?(artifact, migrations)
  end

  defp valid_retained_commit_context?(_operation), do: false

  defp valid_reservation_relationships?(journal) do
    Enum.all?(journal.reservations, fn {digest, reservation} ->
      case Map.get(journal.token_outcomes, digest) do
        %{
          artifact_id: artifact_id,
          epoch: epoch,
          outcome: :prepared,
          receipt_id: nil
        } ->
          artifact_id == reservation.artifact_id and epoch == reservation.epoch and
            epoch > journal.last_epoch

        _other ->
          false
      end
    end)
  end

  defp valid_token_relationships?(journal) do
    Enum.all?(journal.token_outcomes, fn {digest, token_outcome} ->
      valid_token_relationship?(journal, digest, token_outcome)
    end)
  end

  defp valid_token_relationship?(journal, digest, %{outcome: :prepared} = outcome) do
    case Map.get(journal.reservations, digest) do
      %{artifact_id: artifact_id, epoch: epoch} ->
        artifact_id == outcome.artifact_id and epoch == outcome.epoch and
          is_nil(outcome.receipt_id)

      _other ->
        false
    end
  end

  defp valid_token_relationship?(journal, digest, %{outcome: :committing} = outcome) do
    outcome.epoch <= journal.last_epoch and is_nil(outcome.receipt_id) and
      not Map.has_key?(journal.reservations, digest) and
      Enum.any?(journal.operations, fn operation ->
        operation.operation == :commit and operation.outcome == :committing and
          operation[:token_digest] == digest and operation.artifact_id == outcome.artifact_id and
          operation.epoch == outcome.epoch
      end)
  end

  defp valid_token_relationship?(journal, digest, %{outcome: outcome} = token_outcome)
       when outcome in [:committed, :ambiguous] do
    token_outcome.epoch <= journal.last_epoch and not Map.has_key?(journal.reservations, digest) and
      receipt_matches_token?(journal, token_outcome)
  end

  defp valid_token_relationship?(journal, digest, %{outcome: outcome} = token_outcome)
       when outcome in [:rolled_back, :promoted] do
    token_outcome.epoch <= journal.last_epoch and is_binary(token_outcome.receipt_id) and
      not Map.has_key?(journal.receipts, token_outcome.receipt_id) and
      not Map.has_key?(journal.reservations, digest)
  end

  defp valid_token_relationship?(journal, digest, %{outcome: outcome} = token_outcome)
       when outcome in [
              :aborted,
              :lost_on_restart,
              :failed,
              :rolled_back_after_journal_failure
            ] do
    # Abort and lost-on-restart are historical terminal outcomes. Their epoch
    # is newer than `last_epoch` when they are recorded, but a later unrelated
    # commit legitimately advances the monotonic epoch past them. Requiring
    # them to remain newer forever makes a valid journal corrupt on its next
    # executor restart. Failed mutations, on the other hand, advance the epoch
    # before they are finalized and must not point into the future.
    epoch_valid? =
      if outcome in [:aborted, :lost_on_restart],
        do: true,
        else: token_outcome.epoch <= journal.last_epoch

    epoch_valid? and is_nil(token_outcome.receipt_id) and
      not Map.has_key?(journal.reservations, digest)
  end

  defp valid_token_relationship?(_journal, _digest, _outcome), do: false

  defp receipt_matches_token?(journal, token_outcome) do
    case Map.get(journal.receipts, token_outcome.receipt_id) do
      %Receipt{artifact: artifact} ->
        artifact.id == token_outcome.artifact_id and artifact.epoch == token_outcome.epoch

      _other ->
        false
    end
  end

  defp valid_pending_relationships?(journal) do
    pending =
      Enum.filter(journal.operations, &(&1.outcome in @pending_outcomes))

    length(pending) <= 1 and
      Enum.all?(pending, fn
        %{operation: :commit, token_digest: digest} = operation ->
          match?(%{outcome: :committing}, Map.get(journal.token_outcomes, digest)) and
            valid_pending_commit_context?(operation)

        %{operation: operation, receipt_id: receipt_id}
        when operation in [:rollback, :promote] ->
          Map.has_key?(journal.receipts, receipt_id)

        _other ->
          false
      end)
  end

  defp valid_receipt_expectations?(journal) do
    Enum.all?(journal.receipts, fn {_receipt_id, receipt} ->
      Enum.all?(receipt.artifact.modules, fn beam ->
        case Map.get(journal.expected_modules, beam.module) do
          %{
            sha256: sha256,
            md5: md5,
            artifact_id: artifact_id,
            epoch: epoch,
            disposition: disposition
          }
          when disposition in [:committed, :ambiguous] ->
            sha256 == beam.sha256 and md5 == beam.md5 and artifact_id == receipt.artifact.id and
              epoch == receipt.artifact.epoch

          _other ->
            false
        end
      end)
    end)
  end

  defp optional_binary?(nil), do: true
  defp optional_binary?(value), do: is_binary(value)
  defp optional_positive_integer?(nil), do: true
  defp optional_positive_integer?(value), do: is_integer(value) and value > 0
  defp optional_non_negative_integer?(nil), do: true
  defp optional_non_negative_integer?(value), do: is_integer(value) and value >= 0
  defp optional_digest?(nil), do: true
  defp optional_digest?(value), do: is_binary(value) and byte_size(value) == 64
  defp optional_operation_modules?(nil), do: true

  defp optional_operation_modules?(modules) when is_list(modules) do
    Enum.all?(modules, fn
      %{module: module, md5: md5} ->
        module_name?(module) and (is_binary(md5) or md5 == :non_existing)

      module ->
        module_name?(module)
    end)
  end

  defp optional_operation_modules?(_modules), do: false

  defp optional_operation_artifact?(nil), do: true
  defp optional_operation_artifact?(%Artifact{} = artifact), do: valid_artifact_data?(artifact)
  defp optional_operation_artifact?(_artifact), do: false

  defp optional_operation_migrations?(nil), do: true

  defp optional_operation_migrations?(migrations) when is_list(migrations),
    do: Enum.all?(migrations, &valid_persisted_migration?/1)

  defp optional_operation_migrations?(_migrations), do: false

  defp valid_pending_commit_context?(%{
         artifact_id: artifact_id,
         epoch: epoch,
         module_count: module_count,
         migration_count: migration_count,
         modules: modules,
         artifact: %Artifact{} = artifact,
         migrations: migrations
       })
       when is_list(modules) and is_list(migrations) do
    artifact.id == artifact_id and artifact.epoch == epoch and
      module_count == length(artifact.modules) and migration_count == length(migrations) and
      modules == target_module_identities(artifact) and
      valid_pending_migration_relationships?(artifact, migrations)
  end

  defp valid_pending_commit_context?(_operation), do: false

  defp valid_pending_migration_relationships?(artifact, migrations) do
    beams = Map.new(artifact.modules, &{&1.module, &1})
    required = artifact.modules |> Enum.filter(& &1.stateful) |> MapSet.new(& &1.module)
    actual = MapSet.new(migrations, & &1.module)
    pids = Enum.map(migrations, & &1.pid)

    required == actual and pids == Enum.uniq(pids) and
      Enum.all?(migrations, fn migration ->
        case Map.get(beams, migration.module) do
          %Beam{stateful: true, migration_extra: expected} ->
            Beam.migration_extra_allowed?(expected, migration.extra)

          _other ->
            false
        end
      end)
  end

  defp safe_reason?(nil), do: true
  defp safe_reason?(reason) when is_atom(reason), do: true
  # A reason naming a module this VM never interned carries the name as a binary.
  defp safe_reason?(reason) when is_binary(reason), do: true
  defp safe_reason?({left, right}), do: safe_reason?(left) and safe_reason?(right)

  defp safe_reason?({first, second, third}),
    do: safe_reason?(first) and safe_reason?(second) and safe_reason?(third)

  defp safe_reason?(_reason), do: false

  defp reconcile_expected_modules(expected_modules) do
    Enum.reduce_while(expected_modules, :ok, fn {module, expected}, :ok ->
      case reconcile_expected_module(module, expected) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  # A name this VM never interned cannot name loaded code, so an expectation of absence
  # is satisfied by the name itself and any positive expectation is not. This is the
  # ordinary shape of a restart: the capability code is gone, and the journal that
  # describes it says so instead of reading as corruption.
  defp reconcile_expected_module(module, %{sha256: :non_existing, md5: :non_existing})
       when is_binary(module),
       do: :ok

  defp reconcile_expected_module(module, _expected) when is_binary(module),
    do: {:error, {:module_unavailable, module}}

  # Absence is checked against the code server directly. `loaded_module_identity/1` would
  # ask `Code.ensure_loaded/1`, which is allowed to *load* the module it is asked about.
  defp reconcile_expected_module(module, %{sha256: :non_existing, md5: :non_existing}) do
    if module_absent?(module),
      do: :ok,
      else: {:error, {:module_unexpectedly_present, module}}
  end

  defp reconcile_expected_module(module, expected) do
    case loaded_module_identity(module) do
      {:ok, %{md5: md5, sha256: sha256}} ->
        if md5 == expected.md5 and (is_nil(sha256) or sha256 == expected.sha256) do
          :ok
        else
          {:error, {:module_hash_mismatch, module}}
        end

      {:error, _reason} ->
        {:error, {:module_unavailable, module}}
    end
  end

  # The checks a restart runs against loaded code, without the mutating target resume.
  # `reconcile_quarantine/1` replays exactly these so a quarantine is only ever cleared
  # on the same evidence that would have let a restart come up ready.
  defp reconcile_current_state(journal) do
    with :ok <- reconcile_pending_operations(journal.operations),
         :ok <- reconcile_expected_modules(journal.expected_modules),
         :ok <- reconcile_receipts(journal.receipts) do
      :ok
    end
  end

  defp clear_quarantine(state) do
    journal =
      state.journal
      |> append_system_operation(:quarantine, :cleared,
        reason: public_quarantine_reason(state.journal.quarantine_reason)
      )

    journal = %{journal | mode: :ready, quarantine_reason: nil}

    case persist_journal(state, journal) do
      {:ok, state} ->
        {:reply, :ok, state}

      {:error, reason, state} ->
        {:reply, {:error, {:journal_persist_failed, public_storage_reason(reason)}}, state}
    end
  end

  defp reconcile_pending_operations(operations) do
    case Enum.find(operations, &(&1.outcome in @pending_outcomes)) do
      nil ->
        :ok

      operation ->
        case pending_operation_matches_loaded_code(operation) do
          :ok -> {:error, {:incomplete_operation, operation.operation}}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp pending_operation_matches_loaded_code(%{modules: expected_modules})
       when is_list(expected_modules) and expected_modules != [] do
    Enum.reduce_while(expected_modules, :ok, fn
      %{module: module, md5: :non_existing}, :ok when is_binary(module) ->
        {:cont, :ok}

      %{module: module, md5: expected_md5}, :ok
      when is_binary(module) and is_binary(expected_md5) ->
        {:halt, {:error, {:module_unavailable, module}}}

      %{module: module, md5: :non_existing}, :ok when is_atom(module) ->
        if module_absent?(module),
          do: {:cont, :ok},
          else: {:halt, {:error, {:module_unexpectedly_present, module}}}

      %{module: module, md5: expected_md5}, :ok
      when is_atom(module) and is_binary(expected_md5) ->
        case loaded_module_identity(module) do
          {:ok, %{md5: ^expected_md5}} -> {:cont, :ok}
          {:ok, _identity} -> {:halt, {:error, {:module_hash_mismatch, module}}}
          {:error, _reason} -> {:halt, {:error, {:module_unavailable, module}}}
        end

      _invalid, :ok ->
        {:halt, {:error, :invalid_pending_operation_modules}}
    end)
  end

  defp pending_operation_matches_loaded_code(_operation), do: :ok

  defp resume_pending_commit_targets(journal) do
    case Enum.find(
           journal.operations,
           &(&1.operation == :commit and &1.outcome == :committing)
         ) do
      nil ->
        {journal, :ok}

      %{migrations: migrations, token_digest: token_digest} ->
        result = resume_pending_migration_targets(migrations)

        {outcome, reason} =
          case result do
            :ok -> {:pending_targets_resumed, :live_targets_resumed}
            {:error, _reason} -> {:pending_target_resume_failed, :target_resume_failed}
          end

        journal =
          append_system_operation(journal, :restart, outcome,
            token_digest: token_digest,
            migration_count: length(migrations),
            reason: reason
          )

        {journal, result}
    end
  end

  defp resume_pending_migration_targets(migrations) do
    Enum.reduce(migrations, :ok, fn migration, result ->
      case resume_pending_migration_target(migration) do
        :ok -> result
        {:error, reason} when result == :ok -> {:error, reason}
        {:error, _reason} -> result
      end
    end)
  end

  defp resume_pending_migration_target(%Migration{module: module, pid: pid}) do
    cond do
      not Process.alive?(pid) ->
        :ok

      true ->
        case process_callback_module(pid) do
          {:ok, ^module} ->
            case safe_sys_call(fn -> :sys.resume(pid, 5_000) end) do
              :ok -> :ok
              {:error, _reason} -> {:error, {:pending_target_resume_failed, module}}
            end

          {:ok, _other_module} ->
            {:error, {:pending_target_module_mismatch, module}}

          {:error, _reason} ->
            {:error, {:pending_target_unverifiable, module}}
        end
    end
  end

  defp loaded_module_identity(module) do
    with {:module, ^module} <- Code.ensure_loaded(module),
         md5 when is_binary(md5) <- module.module_info(:md5) do
      # `module_info(:md5)` is the identity of the code the VM is executing.
      # `code:get_object_code/1` may instead read the code-path file after a
      # memory-only hot load, so use its stronger SHA-256 only when its own BEAM
      # identity agrees with the executing module.
      sha256 =
        case :code.get_object_code(module) do
          {^module, binary, _filename} ->
            case Beam.inspect_binary(binary) do
              {:ok, %{md5: ^md5}} -> Beam.sha256(binary)
              _other -> nil
            end

          :error ->
            nil
        end

      {:ok, %{sha256: sha256, md5: md5}}
    else
      _other -> {:error, :unavailable}
    end
  rescue
    _error -> {:error, :unavailable}
  end

  defp reconcile_receipts(receipts) do
    Enum.reduce_while(receipts, :ok, fn {_id, receipt}, :ok ->
      case Enum.find_value(receipt.migrations, &migration_reconciliation_error/1) do
        nil -> {:cont, :ok}
        reason -> {:halt, {:error, reason}}
      end
    end)
  end

  defp migration_reconciliation_error(%Migration{module: module, pid: pid}) do
    cond do
      not Process.alive?(pid) ->
        {:rollback_process_unavailable, module}

      true ->
        case process_callback_module(pid) do
          {:ok, ^module} -> nil
          {:ok, actual} -> {:rollback_process_module_mismatch, module, actual}
          {:error, reason} -> {:rollback_process_unverifiable, module, reason}
        end
    end
  end

  defp lose_prepared_reservations(%Journal{reservations: reservations} = journal)
       when map_size(reservations) == 0 do
    {journal, false}
  end

  defp lose_prepared_reservations(%Journal{} = journal) do
    journal =
      Enum.reduce(journal.reservations, journal, fn {digest, reservation}, acc ->
        acc
        |> put_token_outcome_from_reservation(digest, reservation, :lost_on_restart)
        |> append_operation_from_reservation(reservation,
          operation: :restart,
          outcome: :lost_on_restart,
          token_digest: digest
        )
      end)

    {%{journal | reservations: %{}}, true}
  end

  defp put_reservation(journal, digest, reservation) do
    %{journal | reservations: Map.put(journal.reservations, digest, reservation)}
  end

  defp delete_reservation(journal, digest) do
    %{journal | reservations: Map.delete(journal.reservations, digest)}
  end

  defp put_token_outcome(journal, digest, artifact, outcome, receipt_id \\ nil) do
    entry = %{
      artifact_id: artifact.id,
      epoch: artifact.epoch,
      outcome: outcome,
      receipt_id: receipt_id
    }

    %{journal | token_outcomes: Map.put(journal.token_outcomes, digest, entry)}
  end

  defp put_token_outcome_from_reservation(journal, digest, reservation, outcome) do
    entry = %{
      artifact_id: reservation.artifact_id,
      epoch: reservation.epoch,
      outcome: outcome,
      receipt_id: nil
    }

    %{journal | token_outcomes: Map.put(journal.token_outcomes, digest, entry)}
  end

  defp finalize_tokens_for_receipt(journal, receipt_id, outcome) do
    outcomes =
      Map.new(journal.token_outcomes, fn {digest, entry} ->
        if entry.receipt_id == receipt_id do
          {digest, %{entry | outcome: outcome}}
        else
          {digest, entry}
        end
      end)

    %{journal | token_outcomes: outcomes}
  end

  defp put_receipt(journal, %Receipt{} = receipt) do
    %{journal | receipts: Map.put(journal.receipts, receipt.id, receipt)}
  end

  defp delete_receipt(journal, receipt_id) do
    %{journal | receipts: Map.delete(journal.receipts, receipt_id)}
  end

  defp advance_epoch(journal, epoch) do
    %{journal | last_epoch: max(journal.last_epoch, epoch)}
  end

  defp expect_committed(journal, receipt, disposition) do
    expected =
      Enum.reduce(receipt.artifact.modules, journal.expected_modules, fn beam, acc ->
        put_expectation(acc, beam.module, %{
          sha256: beam.sha256,
          md5: beam.md5,
          artifact_id: receipt.artifact.id,
          epoch: receipt.artifact.epoch,
          disposition: disposition
        })
      end)

    %{journal | expected_modules: expected}
  end

  defp expect_preimages(journal, receipt) do
    expected =
      Enum.reduce(receipt.artifact.modules, journal.expected_modules, fn beam, acc ->
        put_expectation(acc, beam.module, preimage_expectation(beam, receipt.artifact))
      end)

    %{journal | expected_modules: expected}
  end

  # One module, one expectation. A name that was journaled as a binary because this VM
  # could not intern it is retired here rather than left beside the atom it resolves to
  # once the module is loaded again: two entries for one module would eventually disagree
  # about whether it is supposed to be present.
  defp put_expectation(expected, module, identity) do
    expected
    |> Map.delete(ModuleName.to_wire(module))
    |> Map.put(module, identity)
  end

  defp preimage_expectation(%Beam{disposition: :replace} = beam, artifact) do
    %{
      sha256: beam.old_sha256,
      md5: beam.old_md5,
      artifact_id: artifact.id,
      epoch: artifact.epoch,
      disposition: :rolled_back
    }
  end

  # Undoing an introduction leaves no bytes to expect, and "no entry" would mean "no
  # opinion". `:non_existing` is the identity of an absent module: a positive expectation
  # this node re-checks on every restart, so a name that reappears fails closed.
  defp preimage_expectation(%Beam{disposition: :introduce}, artifact) do
    %{
      sha256: :non_existing,
      md5: :non_existing,
      artifact_id: artifact.id,
      epoch: artifact.epoch,
      disposition: :rolled_back
    }
  end

  defp append_operation(journal, operation, %Artifact{} = artifact, attributes) do
    operation_metadata = %{
      sequence: journal.next_sequence,
      operation: operation,
      outcome: Keyword.fetch!(attributes, :outcome),
      artifact_id: artifact.id,
      epoch: artifact.epoch,
      occurred_at: now()
    }

    operation_metadata =
      attributes
      |> Keyword.delete(:outcome)
      |> Enum.into(operation_metadata)

    append_operation_metadata(journal, operation_metadata)
  end

  defp append_operation_from_reservation(journal, reservation, attributes) do
    operation_metadata = %{
      sequence: journal.next_sequence,
      operation: Keyword.fetch!(attributes, :operation),
      outcome: Keyword.fetch!(attributes, :outcome),
      artifact_id: reservation.artifact_id,
      epoch: reservation.epoch,
      occurred_at: now(),
      modules: reservation.modules
    }

    operation_metadata =
      attributes
      |> Keyword.drop([:operation, :outcome])
      |> Enum.into(operation_metadata)

    append_operation_metadata(journal, operation_metadata)
  end

  defp append_system_operation(journal, operation, outcome, attributes) do
    operation_metadata =
      attributes
      |> Enum.into(%{
        sequence: journal.next_sequence,
        operation: operation,
        outcome: outcome,
        artifact_id: nil,
        epoch: nil,
        occurred_at: now()
      })

    append_operation_metadata(journal, operation_metadata)
  end

  defp append_operation_metadata(journal, operation_metadata) do
    operations = trim_operations(journal.operations ++ [operation_metadata])
    %{journal | operations: operations, next_sequence: journal.next_sequence + 1}
  end

  # History is bounded, but never at the cost of evidence. A pending write-ahead record
  # is what restart reconciliation reads, and a record carrying an artifact is the only
  # remaining copy of a preimage; both survive trimming regardless of age. Sequences stay
  # unique and ascending, and `next_sequence` keeps advancing, so a trimmed journal still
  # validates on restart.
  defp trim_operations(operations) do
    excess = length(operations) - @operation_history_limit

    if excess > 0 do
      {trimmed, retained} = Enum.split(operations, excess)
      Enum.filter(trimmed, &retained_operation?/1) ++ retained
    else
      operations
    end
  end

  defp retained_operation?(operation) do
    operation.outcome in @pending_outcomes or Map.has_key?(operation, :artifact)
  end

  defp clear_pending_operation(journal, operation, identity_key, identity) do
    operations =
      Enum.reject(journal.operations, fn entry ->
        entry.operation == operation and entry.outcome in @pending_outcomes and
          entry[identity_key] == identity
      end)

    %{journal | operations: operations}
  end

  defp quarantine_journal(journal, reason) do
    %{journal | mode: :quarantined, quarantine_reason: public_quarantine_reason(reason)}
  end

  defp committed_receipt_for_token(journal, token) do
    digest = token_digest(token)

    case Map.get(journal.token_outcomes, digest) do
      %{outcome: :committed, receipt_id: receipt_id} ->
        case Map.fetch(journal.receipts, receipt_id) do
          {:ok, receipt} -> {:ok, receipt}
          :error -> {:finalized, :receipt_unavailable}
        end

      %{outcome: outcome}
      when outcome in [
             :rolled_back_after_journal_failure,
             :rolled_back,
             :promoted,
             :ambiguous,
             :failed
           ] ->
        {:finalized, outcome}

      _other ->
        :not_found
    end
  end

  defp completed_token_operation?(journal, token, outcomes) do
    digest = token_digest(token)

    case Map.get(journal.token_outcomes, digest) do
      %{outcome: outcome} -> outcome in outcomes
      _other -> false
    end
  end

  defp completed_receipt_operation?(journal, operation, receipt_id, outcome) do
    Enum.any?(journal.operations, fn entry ->
      entry.operation == operation and entry.outcome == outcome and
        entry[:receipt_id] == receipt_id
    end)
  end

  defp public_receipts(receipts) do
    receipts
    |> Map.values()
    |> Enum.map(fn receipt ->
      %{
        artifact_id: receipt.artifact.id,
        epoch: receipt.artifact.epoch,
        modules: module_names(receipt.artifact),
        migration_count: length(receipt.migrations),
        committed_at: receipt.committed_at
      }
    end)
    |> Enum.sort_by(&{&1.epoch, &1.artifact_id})
  end

  defp public_operations(operations) do
    operations
    |> Enum.take(-@public_operation_limit)
    |> Enum.reverse()
    |> Enum.map(fn operation ->
      operation
      |> Map.take([
        :sequence,
        :operation,
        :outcome,
        :artifact_id,
        :epoch,
        :occurred_at,
        :module_count,
        :migration_count,
        :modules,
        :reason
      ])
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()
    end)
  end

  defp token_digest(token), do: :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)
  defp module_names(artifact), do: Enum.map(artifact.modules, & &1.module)

  defp target_module_identities(artifact) do
    Enum.map(artifact.modules, &%{module: &1.module, md5: &1.md5})
  end

  # The pre-image identity of an introduced module is its absence.
  defp preimage_module_identities(artifact) do
    Enum.map(artifact.modules, fn
      %Beam{disposition: :introduce} = beam -> %{module: beam.module, md5: :non_existing}
      beam -> %{module: beam.module, md5: beam.old_md5}
    end)
  end

  defp module_absent?(module) do
    :code.which(module) == :non_existing and :code.get_object_code(module) == :error
  end

  defp now, do: DateTime.utc_now() |> DateTime.to_iso8601()

  defp public_storage_reason(reason)
       when reason in [
              :table_not_found,
              :adapter_exception,
              :adapter_exit,
              :adapter_failure,
              :journal_unloaded
            ],
       do: reason

  defp public_storage_reason(_reason), do: :storage_unavailable

  defp public_corruption_reason(reason)
       when is_atom(reason),
       do: reason

  defp public_corruption_reason(_reason), do: :invalid_checkpoint

  defp public_operation_reason(reason) do
    case reason do
      {tag, _detail} when is_atom(tag) -> tag
      {tag, _detail, _more} when is_atom(tag) -> tag
      reason when is_atom(reason) -> reason
      _other -> :operation_failed
    end
  end

  defp public_quarantine_reason(nil), do: nil
  defp public_quarantine_reason(reason) when is_atom(reason), do: reason

  # A module this VM never interned is named by the binary the journal stored. The name
  # is the fact an operator needs, and it is bounded by the journal that produced it.
  defp public_quarantine_reason(name) when is_binary(name), do: name

  defp public_quarantine_reason({tag, module}) when is_atom(tag) and is_atom(module),
    do: {tag, module}

  defp public_quarantine_reason({tag, reason}) when is_atom(tag),
    do: {tag, public_quarantine_reason(reason)}

  defp public_quarantine_reason({tag, first, second}) when is_atom(tag),
    do: {tag, public_quarantine_reason(first), public_quarantine_reason(second)}

  defp public_quarantine_reason(_reason), do: :reconciliation_required

  defp storage_response_kind(response) when is_atom(response), do: response
  defp storage_response_kind({tag, _value}) when is_atom(tag), do: tag
  defp storage_response_kind(_response), do: :unexpected

  # Failures return `{:error, reason, recovery, rollback_material}`. The last element
  # says whether this node's code was already mutated when the failure was final: a
  # failure before `finish_loading/1` leaves nothing to restore, while a failure at or
  # after it leaves the journal as the only place preimages still exist.
  defp commit_prepared(prepared, timeout) do
    pids = migration_pids(prepared.migrations)

    case suspend_all(pids, timeout) do
      {:error, reason, suspended} ->
        case resume_all(suspended) do
          :ok ->
            {:error, {:suspend_failed, reason}, :unchanged, :not_required}

          {:error, resume_errors} ->
            {:error,
             {:suspend_failed, reason, {:resume_failed, public_resume_errors(resume_errors)}},
             :quarantined, :not_required}
        end

      {:ok, suspended} ->
        case finish_loading(prepared.code) do
          :ok ->
            case migrate_up(prepared.migrations, prepared.artifact, timeout) do
              {:ok, migrated} ->
                case resume_all(suspended) do
                  :ok ->
                    {:ok,
                     %Receipt{
                       id: Jido.Signal.ID.generate!(),
                       artifact: prepared.artifact,
                       migrations: migrated,
                       committed_at: DateTime.utc_now() |> DateTime.to_iso8601(),
                       node: node()
                     }}

                  {:error, resume_errors} ->
                    recover_failed_resume(prepared, migrated, resume_errors, timeout)
                end

              {:error, reason, migrated} ->
                recover_failed_commit(prepared, migrated, suspended, reason, timeout)
            end

          {:error, {:finish_loading, reason}} ->
            case resume_all(suspended) do
              :ok ->
                {:error, {:finish_loading_failed, reason}, :unchanged, :not_required}

              {:error, resume_errors} ->
                {:error,
                 {:finish_loading_failed, reason,
                  {:resume_failed, public_resume_errors(resume_errors)}}, :quarantined,
                 :not_required}
            end
        end
    end
  end

  defp finish_loading(prepared_code) do
    case :code.finish_loading(prepared_code) do
      :ok -> :ok
      {:error, reason} -> {:error, {:finish_loading, reason}}
      other -> {:error, {:finish_loading, other}}
    end
  end

  defp migrate_up(migrations, artifact, timeout) do
    migrations
    |> Enum.reduce_while({:ok, []}, fn migration, {:ok, migrated} ->
      beam = Enum.find(artifact.modules, &(&1.module == migration.module))

      case safe_change_code(
             migration.pid,
             migration.module,
             beam.old_vsn,
             migration.extra,
             timeout
           ) do
        :ok -> {:cont, {:ok, [migration | migrated]}}
        {:error, reason} -> {:halt, {:error, reason, Enum.reverse(migrated)}}
      end
    end)
    |> case do
      {:ok, migrated} -> {:ok, Enum.reverse(migrated)}
      error -> error
    end
  end

  defp recover_failed_commit(prepared, migrated, suspended, reason, timeout) do
    case compensate_mutated_commit(prepared, migrated, suspended, timeout) do
      :ok ->
        {:error, {:migration_failed, reason}, :rolled_back, :not_required}

      {:error, recovery_errors} ->
        {:error, {:migration_failed, reason, recovery_errors}, :quarantined, :required}
    end
  end

  # A failed resume happens after the batch is visible and every migration ran. The
  # preimages and the migrated targets are still in scope here, so attempt the same
  # compensation a failed migration gets instead of quarantining a mutated node that
  # could have been restored.
  defp recover_failed_resume(prepared, migrated, resume_errors, timeout) do
    errors = public_resume_errors(resume_errors)
    suspended = resuspend_targets(migrated, timeout)

    case compensate_mutated_commit(prepared, migrated, suspended, timeout) do
      :ok ->
        {:error, {:resume_failed, errors}, :rolled_back, :not_required}

      {:error, recovery_errors} ->
        {:error, {:resume_failed, errors, recovery_errors}, :quarantined, :required}
    end
  end

  # `resume_all/1` resumes every target it can before reporting, so the ones that came
  # back are no longer suspended and would refuse `:sys.change_code/5`. Re-suspend them
  # the way rolling back a committed receipt does. This is best effort by design: a
  # target that cannot be suspended cannot be downgraded either, and the failed
  # downgrade is what makes that visible instead of a silent partial compensation.
  defp resuspend_targets(migrations, timeout) do
    migrations
    |> Enum.reduce([], fn migration, suspended ->
      case safe_sys_call(fn -> :sys.suspend(migration.pid, timeout) end) do
        :ok -> [migration.pid | suspended]
        {:error, _reason} -> suspended
      end
    end)
    |> Enum.uniq()
  end

  defp compensate_mutated_commit(prepared, migrated, suspended, timeout) do
    downgrade_result = downgrade_migrations(migrated, prepared.artifact, timeout)
    restore_result = restore_preimages(prepared.artifact)
    resume_result = resume_all(suspended)

    case {downgrade_result, restore_result, resume_result} do
      {:ok, :ok, :ok} -> :ok
      recovery_errors -> {:error, recovery_errors}
    end
  end

  defp rollback_receipt(receipt, timeout) do
    pids = migration_pids(receipt.migrations)

    case suspend_all(pids, timeout) do
      {:ok, suspended} ->
        migration_result = downgrade_migrations(receipt.migrations, receipt.artifact, timeout)
        restore_result = restore_preimages(receipt.artifact)
        resume_result = resume_all(suspended)

        case {migration_result, restore_result, resume_result} do
          {:ok, :ok, :ok} ->
            :ok

          recovery_errors ->
            {:error, {:rollback_failed, recovery_errors}, :quarantined}
        end

      {:error, reason, suspended} ->
        case resume_all(suspended) do
          :ok ->
            {:error, {:suspend_failed, reason}, :unchanged}

          {:error, resume_errors} ->
            {:error,
             {:suspend_failed, reason, {:resume_failed, public_resume_errors(resume_errors)}},
             :quarantined}
        end
    end
  end

  defp downgrade_migrations(migrations, artifact, timeout) do
    migrations
    |> Enum.reverse()
    |> Enum.reduce_while(:ok, fn migration, :ok ->
      beam = Enum.find(artifact.modules, &(&1.module == migration.module))

      case safe_change_code(
             migration.pid,
             migration.module,
             {:down, beam.vsn},
             migration.extra,
             timeout
           ) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, {migration.module, migration.pid, reason}}}
      end
    end)
  end

  defp restore_preimages(artifact) do
    with :ok <- Enum.reduce_while(artifact.modules, :ok, &restore_module/2) do
      purge_old_versions(artifact)
    end
  end

  defp restore_module(%Beam{disposition: :replace} = beam, :ok) do
    if :code.soft_purge(beam.module) do
      case :code.load_binary(beam.module, beam.old_filename, beam.old_binary) do
        {:module, module} when module == beam.module -> {:cont, :ok}
        other -> {:halt, {:error, {:reload_failed, beam.module, other}}}
      end
    else
      {:halt, {:error, {:old_code_in_use, beam.module}}}
    end
  end

  # There is no earlier version to put back, so the inverse of loading an introduced
  # module is unloading it: retire the current version, then drop it. A process still
  # executing that code stops the purge and is reported instead of being killed, which
  # leaves the module retired but not yet reclaimed. That state is inspectable, it is
  # what quarantine exists for, and it resolves the moment the process leaves the code.
  defp restore_module(%Beam{disposition: :introduce} = beam, :ok) do
    cond do
      # Gone already, with nothing retired behind the name. The replacement path reloads
      # its preimage without first asking whether someone had already put it back; the
      # goal here is absence, and absence is what this is. An unload that happened
      # outside this executor is caught where it belongs, in startup reconciliation
      # against the identity the journal expects.
      module_absent?(beam.module) and not :erlang.check_old_code(beam.module) ->
        {:cont, :ok}

      # `:code.delete/1` refuses while a retired version of the name still exists, which
      # for an introduced module means something else has been loaded over it. Undoing
      # the introduction under a live replacement is not this operation's to do.
      not :code.delete(beam.module) ->
        {:halt, {:error, {:introduced_unload_failed, beam.module}}}

      not :code.soft_purge(beam.module) ->
        {:halt, {:error, {:introduced_code_in_use, beam.module}}}

      true ->
        {:cont, :ok}
    end
  end

  # `:code.soft_purge/1` answers true when a module has no retired version at all, which
  # is exactly the state a just-introduced module is in. Nothing to purge is success:
  # promoting an artifact only means giving up the ability to go back, and an
  # introduction has no earlier version to give up.
  defp purge_old_versions(artifact) do
    Enum.reduce_while(artifact.modules, :ok, fn beam, :ok ->
      if :code.soft_purge(beam.module) do
        {:cont, :ok}
      else
        {:halt, {:error, {:retired_code_in_use, beam.module}}}
      end
    end)
  end

  defp suspend_all(pids, timeout) do
    Enum.reduce_while(pids, {:ok, []}, fn pid, {:ok, suspended} ->
      case safe_sys_call(fn -> :sys.suspend(pid, timeout) end) do
        :ok -> {:cont, {:ok, [pid | suspended]}}
        # A timed-out system request may still be processed later. Include the
        # attempted PID so the queued resume follows that late suspend request.
        {:error, reason} -> {:halt, {:error, {pid, reason}, [pid | suspended]}}
      end
    end)
  end

  defp resume_all(pids) do
    errors =
      Enum.reduce(pids, [], fn pid, errors ->
        case safe_sys_call(fn -> :sys.resume(pid, 5_000) end) do
          :ok -> errors
          {:error, reason} -> [{pid, reason} | errors]
        end
      end)

    if errors == [], do: :ok, else: {:error, Enum.reverse(errors)}
  end

  defp public_resume_errors(errors) do
    Enum.map(errors, fn {_pid, reason} -> public_operation_reason(reason) end)
  end

  defp safe_change_code(pid, module, old_vsn, extra, timeout) do
    safe_sys_call(fn -> :sys.change_code(pid, module, old_vsn, extra, timeout) end)
  end

  defp safe_sys_call(fun) do
    case fun.() do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
      other -> {:error, other}
    end
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp normalize_migrations(artifact, migrations) when is_list(migrations) do
    module_names = MapSet.new(artifact.modules, & &1.module)

    with {:ok, normalized} <- normalize_migration_entries(migrations, module_names),
         :ok <- ensure_unique_migration_pids(normalized),
         :ok <- ensure_stateful_modules_migrated(artifact, normalized),
         :ok <- ensure_signed_migration_extras(artifact, normalized) do
      {:ok, normalized}
    end
  end

  defp normalize_migrations(_artifact, migrations),
    do: {:error, {:invalid_migrations, migrations}}

  defp normalize_migration_entries(migrations, module_names) do
    migrations
    |> Enum.reduce_while({:ok, []}, fn
      {module, pid}, {:ok, acc} ->
        normalize_migration(module_names, %Migration{module: module, pid: pid}, acc)

      {module, pid, extra}, {:ok, acc} ->
        normalize_migration(
          module_names,
          %Migration{module: module, pid: pid, extra: extra},
          acc
        )

      %Migration{} = migration, {:ok, acc} ->
        normalize_migration(module_names, migration, acc)

      invalid, _acc ->
        {:halt, {:error, {:invalid_migration, invalid}}}
    end)
    |> case do
      {:ok, normalized} -> {:ok, Enum.reverse(normalized)}
      error -> error
    end
  end

  defp ensure_unique_migration_pids(migrations) do
    pids = Enum.map(migrations, & &1.pid)

    if pids == Enum.uniq(pids),
      do: :ok,
      else: {:error, {:duplicate_migration_pid, duplicate(pids)}}
  end

  defp ensure_stateful_modules_migrated(artifact, migrations) do
    required = artifact.modules |> Enum.filter(& &1.stateful) |> MapSet.new(& &1.module)
    actual = MapSet.new(migrations, & &1.module)
    missing = required |> MapSet.difference(actual) |> MapSet.to_list() |> Enum.sort()
    unexpected = actual |> MapSet.difference(required) |> MapSet.to_list() |> Enum.sort()

    cond do
      missing != [] -> {:error, {:missing_stateful_migrations, missing}}
      unexpected != [] -> {:error, {:migration_for_stateless_module, unexpected}}
      true -> :ok
    end
  end

  defp ensure_signed_migration_extras(artifact, migrations) do
    expected = Map.new(artifact.modules, &{&1.module, &1.migration_extra})

    case Enum.find(migrations, fn migration ->
           not Beam.migration_extra_allowed?(
             Map.fetch!(expected, migration.module),
             migration.extra
           )
         end) do
      nil -> :ok
      migration -> {:error, {:migration_extra_mismatch, migration.module}}
    end
  end

  defp normalize_migration(module_names, %Migration{module: module, pid: pid} = migration, acc) do
    cond do
      not MapSet.member?(module_names, module) ->
        {:halt, {:error, {:migration_module_not_in_artifact, module}}}

      not is_pid(pid) or node(pid) != node() or not Process.alive?(pid) ->
        {:halt, {:error, {:invalid_migration_pid, pid}}}

      pid == self() ->
        {:halt, {:error, {:protected_migration_pid, module}}}

      not portable_migration_extra?(migration.extra) ->
        {:halt, {:error, {:invalid_migration_extra, module}}}

      true ->
        case process_callback_module(pid) do
          {:ok, ^module} ->
            {:cont, {:ok, [migration | acc]}}

          {:ok, actual} ->
            {:halt, {:error, {:migration_target_module_mismatch, module, actual}}}

          {:error, reason} ->
            {:halt, {:error, {:migration_target_unverifiable, module, reason}}}
        end
    end
  end

  defp process_callback_module(pid) do
    case Process.info(pid, :dictionary) do
      {:dictionary, dictionary} ->
        case Keyword.get(dictionary, :"$initial_call") do
          {module, :init, arity} when is_atom(module) and is_integer(arity) -> {:ok, module}
          _other -> {:error, :initial_call_unavailable}
        end

      nil ->
        {:error, :process_unavailable}

      _other ->
        {:error, :process_dictionary_unavailable}
    end
  rescue
    _error -> {:error, :process_inspection_failed}
  end

  defp portable_migration_extra?(term), do: Beam.portable_term?(term)

  defp migration_pids(migrations), do: migrations |> Enum.map(& &1.pid) |> Enum.uniq()

  defp duplicate(values) do
    Enum.find(values, fn candidate -> Enum.count(values, &(&1 == candidate)) > 1 end)
  end

  defp ensure_no_prepared(prepared) when map_size(prepared) == 0, do: :ok

  defp ensure_no_prepared(prepared) do
    operations =
      Enum.map(prepared, fn {_token, entry} ->
        %{
          artifact_id: entry.artifact.id,
          epoch: entry.artifact.epoch,
          prepared_at: entry.prepared_at
        }
      end)

    {:error, {:upgrade_in_progress, operations}}
  end

  defp revalidate_commit(artifact, state) do
    with :ok <- newer_epoch(artifact.epoch, state.journal.last_epoch),
         :ok <-
           Verifier.verify_with_expected(
             artifact,
             state.trust_policy,
             state.journal.expected_modules
           ) do
      :ok
    end
  end

  defp newer_epoch(epoch, last_epoch) when epoch > last_epoch, do: :ok
  defp newer_epoch(epoch, last_epoch), do: {:error, {:stale_epoch, epoch, last_epoch}}
end
