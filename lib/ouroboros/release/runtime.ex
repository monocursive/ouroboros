defmodule Ouroboros.Release.Runtime do
  @moduledoc """
  Durable, capability-gated control plane for OTP release installation.

  Offline artifact inspection lives in `Ouroboros.Release.Artifact`. This
  process journals every state-changing adapter call with write-ahead intent,
  but keeps authorization evidence and capabilities only in memory. A restart
  reconciles an interrupted unpack/install/permanence operation with
  `which_releases/0`; an interrupted `check_install_release/2` is inherently
  unobservable and therefore quarantines the lane.

  The default authorizer denies every mutating action. Merely starting this
  process never installs or unpacks a release.
  """

  use GenServer

  alias Ouroboros.Release.{Artifact, Authorizer, HandlerAdapter, Journal, PackageStager}

  @actions [:unpack, :check_install, :install, :make_permanent]
  @checkpoint_key {:ouroboros, :release_runtime, 1}

  defmodule Capability do
    @moduledoc "An ephemeral authorization capability. It is never persisted."
    @enforce_keys [:id]
    defstruct @enforce_keys

    @type t :: %__MODULE__{id: binary()}
  end

  @type server :: GenServer.server()

  def start_link(opts \\ []) when is_list(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Inspects and durably records an archive without touching `:release_handler`."
  @spec inspect_package(server(), Path.t(), keyword()) :: {:ok, Artifact.t()} | {:error, term()}
  def inspect_package(server \\ __MODULE__, path, opts \\ []) do
    GenServer.call(server, {:inspect_package, path, opts}, 30_000)
  end

  @doc "Requests an ephemeral capability from the independently configured authorizer."
  @spec authorize(server(), Artifact.t(), [Authorizer.action()], term()) ::
          {:ok, Capability.t()} | {:error, term()}
  def authorize(server \\ __MODULE__, artifact, actions, approval) do
    GenServer.call(server, {:authorize, artifact, actions, approval})
  end

  @doc "Calls `release_handler:unpack_release/1`; this mutates release files and RELEASES state."
  @spec unpack(server(), Artifact.t(), Capability.t()) :: {:ok, map()} | {:error, term()}
  def unpack(server \\ __MODULE__, artifact, capability) do
    GenServer.call(server, {:mutate, :unpack, artifact, capability}, 30_000)
  end

  @doc "Calls `check_install_release/2`; relup instructions before point-of-no-return may run."
  @spec check_install(server(), Artifact.t(), Capability.t()) ::
          {:ok, map()} | {:error, term()}
  def check_install(server \\ __MODULE__, artifact, capability) do
    GenServer.call(server, {:mutate, :check_install, artifact, capability}, 30_000)
  end

  @doc "Calls `install_release/2`; this is the point where the running node is upgraded."
  @spec install(server(), Artifact.t(), Capability.t()) :: {:ok, map()} | {:error, term()}
  def install(server \\ __MODULE__, artifact, capability) do
    GenServer.call(server, {:mutate, :install, artifact, capability}, 120_000)
  end

  @doc "Calls `make_permanent/1`; this changes the release selected after reboot."
  @spec make_permanent(server(), Artifact.t(), Capability.t()) ::
          {:ok, map()} | {:error, term()}
  def make_permanent(server \\ __MODULE__, artifact, capability) do
    GenServer.call(server, {:mutate, :make_permanent, artifact, capability}, 30_000)
  end

  @spec status(server()) :: map()
  def status(server \\ __MODULE__), do: GenServer.call(server, :status)

  @impl true
  def init(opts) do
    with :ok <- validate_start_options(opts),
         {:ok, storage} <- normalize_storage(Keyword.get(opts, :storage, default_storage())),
         {:ok, journal} <- load_journal(storage),
         {:ok, snapshot} <- handler_snapshot(Keyword.get(opts, :adapter, HandlerAdapter.OTP)),
         {:ok, journal} <- reconcile(journal, snapshot),
         :ok <- persist_if_changed(storage, journal) do
      {:ok,
       %{
         adapter: Keyword.get(opts, :adapter, HandlerAdapter.OTP),
         authorizer: Keyword.get(opts, :authorizer, Authorizer.Deny),
         storage: storage,
         journal: journal,
         capabilities: %{},
         handler_snapshot: snapshot,
         capability_ttl_ms: Keyword.get(opts, :capability_ttl_ms, 5 * 60_000)
       }}
    else
      {:error, reason} ->
        {:ok,
         %{
           adapter: Keyword.get(opts, :adapter, HandlerAdapter.OTP),
           authorizer: Authorizer.Deny,
           storage: nil,
           journal: Journal.quarantine(Journal.new(), reason),
           capabilities: %{},
           handler_snapshot: [],
           capability_ttl_ms: 0
         }}
    end
  end

  @impl true
  def handle_call({:inspect_package, path, opts}, _from, state) do
    with :ok <- ensure_ready(state),
         {:ok, artifact} <- Artifact.inspect_package(path, opts),
         {:ok, journal} <-
           Journal.put_artifact(state.journal, Artifact.summary(artifact), :validated),
         {:ok, state} <- persist(state, journal) do
      {:reply, {:ok, artifact}, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:authorize, %Artifact{} = artifact, actions, approval}, _from, state) do
    with :ok <- ensure_ready(state),
         :ok <- validate_actions(actions),
         :ok <- ensure_recorded(state.journal, artifact),
         :ok <- Artifact.revalidate(artifact),
         :ok <- call_authorizer(state.authorizer, Artifact.summary(artifact), actions, approval) do
      capability = %Capability{id: random_id()}
      digest = capability_digest(capability)

      entry = %{
        artifact_sha256: artifact.sha256,
        actions: MapSet.new(actions),
        expires_at: System.monotonic_time(:millisecond) + state.capability_ttl_ms
      }

      {:reply, {:ok, capability}, put_in(state.capabilities[digest], entry)}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:authorize, _artifact, _actions, _approval}, _from, state),
    do: {:reply, {:error, :invalid_release_artifact}, state}

  def handle_call(
        {:mutate, action, %Artifact{} = artifact, %Capability{} = capability},
        _from,
        state
      )
      when action in @actions do
    with :ok <- ensure_ready(state),
         :ok <- validate_capability(capability),
         :ok <- authorize_action(state, artifact, action, capability),
         :ok <- ensure_recorded(state.journal, artifact),
         {:ok, state} <- refresh_handler_snapshot(state),
         :ok <- validate_transition(state.journal, artifact, action) do
      case begin_operation(state, artifact, action) do
        {:idempotent, result} ->
          {:reply, {:ok, result}, state}

        {:continue, journal} ->
          case persist(state, journal) do
            {:ok, state} -> finish_mutation(state, action, artifact)
            {:error, reason} -> {:reply, {:error, reason}, state}
          end
      end
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:mutate, _action, _artifact, _capability}, _from, state),
    do: {:reply, {:error, :invalid_release_operation}, state}

  def handle_call(:status, _from, state) do
    public = Journal.public(state.journal)

    {:reply,
     Map.merge(public, %{
       handler_releases: state.handler_snapshot,
       ephemeral_capability_count: map_size(state.capabilities)
     }), state}
  end

  defp finish_mutation(state, action, artifact) do
    with {:ok, staged_package} <- prepare_adapter_action(state.adapter, artifact, action),
         {:ok, raw_result} <- call_adapter(state.adapter, action, artifact, staged_package),
         {:ok, stage, public_result} <- successful_result(action, artifact, raw_result) do
      journal =
        state.journal
        |> Journal.update_latest_pending(artifact.sha256, action, :succeeded, public_result)
        |> Journal.advance(artifact.sha256, stage)

      case persist(state, journal) do
        {:ok, state} ->
          refresh_after_mutation(state, public_result)

        {:error, reason} ->
          quarantine_after_ambiguous(state, {:success_journal_failed, action, reason})
      end
    else
      {:error, reason} -> fail_mutation(state, action, artifact, reason)
    end
  end

  defp prepare_adapter_action(_adapter, _artifact, action) when action != :unpack,
    do: {:ok, nil}

  defp prepare_adapter_action(adapter, artifact, :unpack) do
    with {:ok, binary} <- Artifact.read_verified(artifact),
         {:ok, staged} <- PackageStager.stage(adapter, artifact.sha256, binary) do
      {:ok, staged.basename}
    end
  end

  defp fail_mutation(state, action, artifact, reason) do
    journal =
      Journal.update_latest_pending(
        state.journal,
        artifact.sha256,
        action,
        :failed,
        reason
      )

    case persist(state, journal) do
      {:ok, state} ->
        {:reply, {:error, reason}, state}

      {:error, persist_reason} ->
        quarantine_after_ambiguous(state, {:failure_journal_failed, action, persist_reason})
    end
  end

  defp refresh_after_mutation(state, public_result) do
    case handler_snapshot(state.adapter) do
      {:ok, snapshot} ->
        {:reply, {:ok, public_result}, %{state | handler_snapshot: snapshot}}

      {:error, reason} ->
        quarantine_after_ambiguous(state, {:post_mutation_snapshot_failed, reason})
    end
  end

  defp quarantine_after_ambiguous(state, reason) do
    journal = Journal.quarantine(state.journal, reason)

    state =
      case persist(state, journal) do
        {:ok, state} -> state
        {:error, _persist_reason} -> %{state | journal: journal}
      end

    {:reply, {:error, {:release_operation_ambiguous, reason}}, state}
  end

  defp begin_operation(state, artifact, action) do
    journal = state.journal
    stage = Map.fetch!(journal.artifacts, artifact.sha256).stage

    if completed?(stage, action) and effect_current?(state, artifact, action) do
      {:idempotent, %{action: action, version: artifact.version, idempotent: true}}
    else
      {:continue,
       Journal.append(journal, action, Artifact.summary(artifact), :pending, :write_ahead)}
    end
  end

  defp effect_current?(state, artifact, :unpack) do
    release_status(state.handler_snapshot, artifact.release_name, artifact.version) in [
      :unpacked,
      :current,
      :permanent,
      :old
    ]
  end

  defp effect_current?(_state, _artifact, :check_install), do: true

  defp effect_current?(state, artifact, :install) do
    release_status(state.handler_snapshot, artifact.release_name, artifact.version) in [
      :current,
      :permanent
    ]
  end

  defp effect_current?(state, artifact, :make_permanent) do
    release_status(state.handler_snapshot, artifact.release_name, artifact.version) == :permanent
  end

  defp refresh_handler_snapshot(state) do
    case handler_snapshot(state.adapter) do
      {:ok, snapshot} -> {:ok, %{state | handler_snapshot: snapshot}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp call_adapter(adapter, action, artifact, staged_package) do
    result =
      try do
        case action do
          :unpack ->
            adapter.unpack_release(String.to_charlist(staged_package))

          :check_install ->
            adapter.check_install_release(String.to_charlist(artifact.version), [])

          :install ->
            adapter.install_release(String.to_charlist(artifact.version), [])

          :make_permanent ->
            adapter.make_permanent(String.to_charlist(artifact.version))
        end
      rescue
        error -> {:error, {:adapter_exception, error}}
      catch
        kind, reason -> {:error, {:adapter_exit, kind, reason}}
      end

    case result do
      {:error, reason} -> {:error, reason}
      other -> {:ok, other}
    end
  end

  defp successful_result(:unpack, artifact, {:ok, version}) do
    with {:ok, version} <- normalize_handler_text(version),
         true <- version == artifact.version || {:error, {:unpacked_version_mismatch, version}} do
      {:ok, :unpacked, %{action: :unpack, version: version, idempotent: false}}
    end
  end

  defp successful_result(:check_install, artifact, {:ok, from_version, description}) do
    with {:ok, from_version} <- normalize_handler_text(from_version) do
      {:ok, :checked,
       %{
         action: :check_install,
         version: artifact.version,
         from_version: from_version,
         description: safe_description(description),
         idempotent: false
       }}
    end
  end

  defp successful_result(:install, artifact, {kind, from_version, description})
       when kind in [:ok, :continue_after_restart] do
    with {:ok, from_version} <- normalize_handler_text(from_version) do
      {:ok, :installed,
       %{
         action: :install,
         version: artifact.version,
         from_version: from_version,
         continuation: kind,
         description: safe_description(description),
         idempotent: false
       }}
    end
  end

  defp successful_result(:make_permanent, artifact, :ok) do
    {:ok, :permanent, %{action: :make_permanent, version: artifact.version, idempotent: false}}
  end

  defp successful_result(action, _artifact, result),
    do: {:error, {:unexpected_release_handler_result, action, result}}

  defp validate_transition(journal, artifact, action) do
    stage = Map.fetch!(journal.artifacts, artifact.sha256).stage

    valid? =
      case action do
        :unpack -> stage == :validated
        :check_install -> stage in [:unpacked, :checked]
        :install -> stage in [:checked, :installed]
        :make_permanent -> stage in [:installed, :permanent]
      end

    if valid? or completed?(stage, action),
      do: :ok,
      else: {:error, {:invalid_release_transition, stage, action}}
  end

  defp completed?(stage, :unpack), do: stage in [:unpacked, :checked, :installed, :permanent]
  defp completed?(stage, :check_install), do: stage in [:checked, :installed, :permanent]
  defp completed?(stage, :install), do: stage in [:installed, :permanent]
  defp completed?(:permanent, :make_permanent), do: true
  defp completed?(_stage, _action), do: false

  defp authorize_action(state, artifact, action, capability) do
    digest = capability_digest(capability)

    case Map.fetch(state.capabilities, digest) do
      {:ok, entry} ->
        cond do
          entry.expires_at < System.monotonic_time(:millisecond) ->
            {:error, :release_capability_expired}

          entry.artifact_sha256 != artifact.sha256 ->
            {:error, :release_capability_artifact_mismatch}

          not MapSet.member?(entry.actions, action) ->
            {:error, {:release_action_not_authorized, action}}

          true ->
            :ok
        end

      :error ->
        {:error, :invalid_release_capability}
    end
  end

  defp validate_capability(%Capability{id: id}) when is_binary(id) and byte_size(id) == 32,
    do: :ok

  defp validate_capability(%Capability{}), do: {:error, :invalid_release_capability}

  defp validate_actions(actions) when is_list(actions) and actions != [] do
    cond do
      actions != Enum.uniq(actions) -> {:error, :duplicate_release_actions}
      Enum.all?(actions, &(&1 in @actions)) -> :ok
      true -> {:error, :invalid_release_actions}
    end
  end

  defp validate_actions(_actions), do: {:error, :invalid_release_actions}

  defp call_authorizer(authorizer, artifact, actions, approval) when is_atom(authorizer) do
    try do
      case authorizer.authorize(artifact, actions, approval) do
        :ok -> :ok
        {:error, reason} -> {:error, {:authorization_denied, reason}}
        other -> {:error, {:invalid_authorizer_result, other}}
      end
    rescue
      error -> {:error, {:authorizer_failed, error}}
    catch
      kind, reason -> {:error, {:authorizer_failed, kind, reason}}
    end
  end

  defp ensure_recorded(journal, artifact) do
    case Map.fetch(journal.artifacts, artifact.sha256) do
      {:ok, entry} ->
        expected = %{
          artifact_id: artifact.id,
          sha256: artifact.sha256,
          package_name: artifact.package_name,
          release_name: artifact.release_name,
          version: artifact.version,
          erts_version: artifact.erts_version,
          inspection_policy: artifact.inspection_policy
        }

        if Map.take(entry, Map.keys(expected)) == expected,
          do: :ok,
          else: {:error, :release_artifact_identity_mismatch}

      _other ->
        {:error, :release_artifact_not_recorded}
    end
  end

  defp ensure_ready(%{journal: %{mode: :ready}}), do: :ok

  defp ensure_ready(%{journal: journal}),
    do: {:error, {:release_lane_quarantined, journal.quarantine_reason}}

  defp normalize_storage({adapter, opts}) when is_atom(adapter) and is_list(opts) do
    if Keyword.keyword?(opts),
      do: {:ok, {adapter, opts}},
      else: {:error, :invalid_release_storage}
  end

  defp normalize_storage(adapter) when is_atom(adapter), do: {:ok, {adapter, []}}
  defp normalize_storage(_storage), do: {:error, :invalid_release_storage}

  defp load_journal({adapter, opts}) do
    case adapter.get_checkpoint(@checkpoint_key, opts) do
      {:ok, journal} ->
        if Journal.valid?(journal), do: {:ok, journal}, else: {:error, :corrupt_release_journal}

      :not_found ->
        {:ok, Journal.new()}

      {:error, reason} ->
        {:error, {:release_journal_load_failed, reason}}
    end
  rescue
    error -> {:error, {:release_journal_load_failed, error}}
  end

  defp persist(state, journal) do
    case persist_journal(state.storage, journal) do
      :ok -> {:ok, %{state | journal: journal}}
      {:error, reason} -> {:error, {:release_journal_persist_failed, reason}}
    end
  end

  defp persist_if_changed(storage, journal), do: persist_journal(storage, journal)

  defp persist_journal({adapter, opts}, journal) do
    case adapter.put_checkpoint(@checkpoint_key, journal, opts) do
      {:error, {:commit_outcome_unknown, _reason} = ambiguity} -> exit(ambiguity)
      other -> other
    end
  rescue
    error -> {:error, error}
  end

  defp persist_journal(nil, _journal), do: {:error, :release_storage_unavailable}

  defp reconcile(journal, snapshot) do
    case Journal.latest_pending(journal) do
      nil -> reconcile_completed(journal, snapshot)
      operation -> reconcile_pending(journal, operation, snapshot)
    end
  end

  defp reconcile_pending(journal, %{action: :check_install} = operation, _snapshot) do
    {:ok, Journal.quarantine(journal, {:ambiguous_check_after_restart, operation.sequence})}
  end

  defp reconcile_pending(journal, operation, snapshot) do
    status = release_status(snapshot, operation.release_name, operation.version)

    case pending_effect(operation.action, status) do
      {:completed, stage} ->
        journal =
          journal
          |> Journal.update_latest_pending(
            operation.sha256,
            operation.action,
            :succeeded,
            {:reconciled_after_restart, status}
          )
          |> Journal.advance(operation.sha256, stage)

        reconcile_completed(journal, snapshot)

      :no_effect ->
        journal =
          Journal.update_latest_pending(
            journal,
            operation.sha256,
            operation.action,
            :interrupted_no_effect,
            :reconciled_after_restart
          )

        reconcile_completed(journal, snapshot)

      :ambiguous ->
        {:ok,
         Journal.quarantine(
           journal,
           {:ambiguous_release_operation, operation.action, operation.version, status}
         )}
    end
  end

  defp reconcile_completed(journal, snapshot) do
    mismatch =
      Enum.find_value(journal.artifacts, fn {_digest, artifact} ->
        status = release_status(snapshot, artifact.release_name, artifact.version)

        if stage_matches_handler?(artifact.stage, status),
          do: nil,
          else: {:release_state_mismatch, artifact.version, artifact.stage, status}
      end)

    if mismatch, do: {:ok, Journal.quarantine(journal, mismatch)}, else: {:ok, journal}
  end

  defp pending_effect(:unpack, nil), do: :no_effect

  defp pending_effect(:unpack, status) when status in [:unpacked, :current, :permanent, :old],
    do: {:completed, :unpacked}

  defp pending_effect(:install, status) when status in [:current, :permanent],
    do: {:completed, :installed}

  defp pending_effect(:install, :unpacked), do: :no_effect
  defp pending_effect(:make_permanent, :permanent), do: {:completed, :permanent}
  defp pending_effect(:make_permanent, :current), do: :no_effect
  defp pending_effect(_action, _status), do: :ambiguous

  defp stage_matches_handler?(:validated, _status), do: true

  defp stage_matches_handler?(stage, status) when stage in [:unpacked, :checked],
    do: status in [:unpacked, :current, :permanent, :old]

  defp stage_matches_handler?(:installed, status), do: status in [:current, :permanent, :old]
  defp stage_matches_handler?(:permanent, status), do: status in [:permanent, :old]
  defp stage_matches_handler?(_stage, _status), do: false

  defp handler_snapshot(adapter) do
    result =
      try do
        adapter.which_releases()
      rescue
        error -> {:error, {:adapter_exception, error}}
      catch
        kind, reason -> {:error, {:adapter_exit, kind, reason}}
      end

    case result do
      releases when is_list(releases) -> normalize_releases(releases)
      {:error, reason} -> {:error, {:release_handler_unavailable, reason}}
      other -> {:error, {:invalid_release_handler_snapshot, other}}
    end
  end

  defp normalize_releases(releases) do
    Enum.reduce_while(releases, {:ok, []}, fn
      {name, version, libraries, status}, {:ok, acc}
      when is_list(libraries) and status in [:unpacked, :current, :permanent, :old] ->
        with {:ok, name} <- normalize_handler_text(name),
             {:ok, version} <- normalize_handler_text(version),
             {:ok, libraries} <- normalize_handler_texts(libraries) do
          {:cont,
           {:ok, [%{name: name, version: version, libraries: libraries, status: status} | acc]}}
        else
          {:error, _reason} = error -> {:halt, error}
        end

      invalid, _acc ->
        {:halt, {:error, {:invalid_release_handler_entry, invalid}}}
    end)
    |> case do
      {:ok, entries} -> {:ok, Enum.sort_by(entries, &{&1.version, &1.name})}
      {:error, _reason} = error -> error
    end
  end

  defp normalize_handler_texts(values) do
    Enum.reduce_while(values, {:ok, []}, fn value, {:ok, acc} ->
      case normalize_handler_text(value) do
        {:ok, value} -> {:cont, {:ok, [value | acc]}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, values} -> {:ok, Enum.reverse(values)}
      {:error, _reason} = error -> error
    end
  end

  defp normalize_handler_text(value) when is_binary(value), do: {:ok, value}

  defp normalize_handler_text(value) when is_list(value) do
    {:ok, List.to_string(value)}
  rescue
    _error -> {:error, :invalid_release_handler_text}
  end

  defp normalize_handler_text(_value), do: {:error, :invalid_release_handler_text}

  defp release_status(snapshot, name, version) do
    case Enum.find(snapshot, &(&1.name == name and &1.version == version)) do
      nil -> nil
      release -> release.status
    end
  end

  defp validate_start_options(opts) do
    cond do
      not Keyword.keyword?(opts) ->
        {:error, :invalid_release_runtime_options}

      not is_atom(Keyword.get(opts, :adapter, HandlerAdapter.OTP)) ->
        {:error, :invalid_release_handler_adapter}

      not is_atom(Keyword.get(opts, :authorizer, Authorizer.Deny)) ->
        {:error, :invalid_release_authorizer}

      not is_integer(Keyword.get(opts, :capability_ttl_ms, 5 * 60_000)) ->
        {:error, :invalid_capability_ttl}

      Keyword.get(opts, :capability_ttl_ms, 5 * 60_000) <= 0 ->
        {:error, :invalid_capability_ttl}

      true ->
        :ok
    end
  end

  defp default_storage do
    Application.get_env(
      :ouroboros,
      :release_storage,
      {Jido.Storage.ETS, table: :ouroboros_releases}
    )
  end

  defp capability_digest(%Capability{id: id}), do: :crypto.hash(:sha256, id)
  defp random_id, do: :crypto.strong_rand_bytes(32)

  defp safe_description(description) do
    if is_binary(description) or is_list(description) or is_atom(description) or
         is_number(description),
       do: description,
       else: :redacted_description
  end
end
