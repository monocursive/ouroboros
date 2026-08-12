defmodule Ouroboros.Team.Snapshot.Worker do
  @moduledoc false

  @enforce_keys [:id, :node, :role, :hierarchy]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          id: String.t(),
          node: node(),
          role: String.t(),
          hierarchy: :jido_child | :mesh_remote
        }
end

defmodule Ouroboros.Team.Snapshot.Delegation do
  @moduledoc false

  @enforce_keys [
    :id,
    :worker_id,
    :objective,
    :task_ref,
    :coding_options,
    :request_fingerprint,
    :status,
    :created_at
  ]
  defstruct @enforce_keys ++
              [
                cursor: 0,
                event_count: 0,
                last_event: nil,
                result: nil,
                error: nil,
                delivery: :pending,
                delivery_error: nil,
                cancellation_requested_at: nil,
                updated_at: nil
              ]

  @type t :: %__MODULE__{
          id: String.t(),
          worker_id: String.t(),
          objective: String.t(),
          task_ref: Ouroboros.Coding.TaskRef.t(),
          coding_options: map(),
          request_fingerprint: String.t(),
          status: :starting | Ouroboros.Coding.TaskState.status(),
          cursor: non_neg_integer(),
          event_count: non_neg_integer(),
          last_event: Ouroboros.Coding.Event.t() | nil,
          result: map() | nil,
          error: term(),
          delivery: :pending | :delivering | :delivered,
          delivery_error: term(),
          cancellation_requested_at: String.t() | nil,
          created_at: String.t(),
          updated_at: String.t() | nil
        }
end

defmodule Ouroboros.Team.Snapshot do
  @moduledoc """
  Serializable source of truth for a coding-agent team.

  Runtime PIDs, monitors, waiter references, and release capabilities are kept out
  of this aggregate. One checkpoint therefore contains everything needed to
  reconstruct logical membership and reconcile detached coding tasks.
  """

  alias Ouroboros.Coding.TaskRef
  alias Ouroboros.Team.Snapshot.{Delegation, Worker}

  @version 3
  @enforce_keys [:id, :coordinator_id, :status, :created_at, :updated_at]
  defstruct @enforce_keys ++
              [
                version: @version,
                cleanup_agents?: true,
                workers: %{},
                delegations: %{}
              ]

  @type t :: %__MODULE__{
          version: pos_integer(),
          id: String.t(),
          coordinator_id: String.t(),
          status: :active | :closing | :closed,
          cleanup_agents?: boolean(),
          workers: %{optional(String.t()) => Worker.t()},
          delegations: %{optional(String.t()) => Delegation.t()},
          created_at: String.t(),
          updated_at: String.t()
        }

  @doc false
  @spec new(String.t(), String.t(), boolean()) :: t()
  def new(id, coordinator_id, cleanup_agents?) do
    now = timestamp()

    %__MODULE__{
      id: id,
      coordinator_id: coordinator_id,
      status: :active,
      cleanup_agents?: cleanup_agents?,
      created_at: now,
      updated_at: now
    }
  end

  @doc false
  @spec valid?(term()) :: boolean()
  def valid?(%__MODULE__{} = snapshot) do
    snapshot.version == @version and
      nonempty_binary?(snapshot.id) and
      nonempty_binary?(snapshot.coordinator_id) and
      snapshot.status in [:active, :closing, :closed] and
      is_boolean(snapshot.cleanup_agents?) and
      nonempty_binary?(snapshot.created_at) and
      nonempty_binary?(snapshot.updated_at) and
      valid_workers?(snapshot.workers) and
      valid_delegations?(snapshot.id, snapshot.delegations) and
      portable_term?(snapshot)
  end

  def valid?(_other), do: false

  @doc false
  def timestamp, do: DateTime.utc_now() |> DateTime.to_iso8601()

  @doc false
  @spec coding_task_id(String.t(), String.t()) :: String.t()
  def coding_task_id(team_id, delegation_id)
      when is_binary(team_id) and is_binary(delegation_id) do
    digest =
      {team_id, delegation_id}
      |> :erlang.term_to_binary([:deterministic])
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode16(case: :lower)

    "ouroboros-team-" <> digest
  end

  defp valid_workers?(workers) when is_map(workers) do
    Enum.all?(workers, fn
      {id, %Worker{id: id, node: owner, role: role, hierarchy: hierarchy}}
      when is_binary(id) and is_atom(owner) and is_binary(role) and
             hierarchy in [:jido_child, :mesh_remote] ->
        nonempty_binary?(id) and nonempty_binary?(role)

      _other ->
        false
    end)
  end

  defp valid_workers?(_workers), do: false

  defp valid_delegations?(team_id, delegations) when is_map(delegations) do
    Enum.all?(delegations, fn
      {id,
       %Delegation{
         id: id,
         worker_id: worker_id,
         objective: objective,
         task_ref: %TaskRef{id: coding_task_id, node: owner},
         coding_options: coding_options,
         request_fingerprint: fingerprint,
         status: status,
         cursor: cursor,
         event_count: event_count,
         delivery: delivery,
         created_at: created_at
       }}
      when is_binary(id) and is_binary(worker_id) and is_binary(objective) and
             is_atom(owner) and is_map(coding_options) and is_binary(fingerprint) and
             is_atom(status) and
             is_integer(cursor) and cursor >= 0 and is_integer(event_count) and event_count >= 0 and
             delivery in [:pending, :delivering, :delivered] and is_binary(created_at) ->
        nonempty_binary?(id) and nonempty_binary?(worker_id) and
          nonempty_binary?(objective) and byte_size(fingerprint) == 64 and
          coding_task_id == coding_task_id(team_id, id) and
          status in [:starting, :running, :completed, :failed, :cancelled, :lost] and
          valid_coding_options?(coding_options)

      _other ->
        false
    end)
  end

  defp valid_delegations?(_team_id, _delegations), do: false

  defp valid_coding_options?(%{
         workspace: workspace,
         workspace_mode: mode,
         provider: provider,
         event_limit: event_limit,
         origin_digest: origin_digest,
         options: options
       }) do
    is_binary(workspace) and mode in [:shared_read, :exclusive] and is_atom(provider) and
      is_integer(event_limit) and event_limit > 0 and valid_origin_digest?(origin_digest) and
      is_map(options)
  end

  defp valid_coding_options?(_options), do: false

  defp valid_origin_digest?(digest) when is_binary(digest) do
    case Base.decode16(digest, case: :lower) do
      {:ok, decoded} when byte_size(decoded) == 32 -> true
      _other -> false
    end
  end

  defp valid_origin_digest?(_digest), do: false

  # Erlang external terms can encode these values, but they are runtime authority,
  # not durable domain data. Reject them recursively at the checkpoint boundary.
  defp portable_term?(term) when is_pid(term) or is_port(term) or is_reference(term), do: false
  defp portable_term?(term) when is_function(term), do: false

  defp portable_term?(%_{} = struct) do
    struct |> Map.from_struct() |> portable_term?()
  end

  defp portable_term?(term) when is_map(term) do
    Enum.all?(term, fn {key, value} -> portable_term?(key) and portable_term?(value) end)
  end

  defp portable_term?(term) when is_list(term), do: Enum.all?(term, &portable_term?/1)

  defp portable_term?(term) when is_tuple(term) do
    term |> Tuple.to_list() |> Enum.all?(&portable_term?/1)
  end

  defp portable_term?(_term), do: true

  defp nonempty_binary?(value), do: is_binary(value) and String.trim(value) != ""
end
