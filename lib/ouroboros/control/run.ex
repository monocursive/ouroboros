defmodule Ouroboros.Control.Run do
  @moduledoc """
  Durable state for one autonomous objective.

  Planner and evaluator modules, processes, and provider options deliberately do
  not live in this aggregate. A run can therefore be checkpointed and recovered
  without serializing runtime ownership or credentials.
  """

  alias Ouroboros.Control.EvidenceContract
  alias Ouroboros.Orchestration.{Plan, Serializable}

  @statuses [
    :planning,
    :submitting,
    :running,
    :evaluating,
    :cancelling,
    :completed,
    :failed,
    :cancelled
  ]

  @enforce_keys [
    :id,
    :objective,
    :objective_fingerprint,
    :max_revisions,
    :status,
    :created_at,
    :updated_at
  ]
  defstruct @enforce_keys ++
              [
                revision: 0,
                version: 1,
                planner_request_id: nil,
                evaluation_id: nil,
                current_plan_id: nil,
                previous_plan_id: nil,
                pending_plan: nil,
                feedback: nil,
                decision: nil,
                result: nil,
                evidence_contract: nil,
                failure: nil,
                cancellation: nil,
                history: []
              ]

  @type status ::
          :planning
          | :submitting
          | :running
          | :evaluating
          | :cancelling
          | :completed
          | :failed
          | :cancelled

  @type cancellation :: %{
          required(:status) => :pending | :completed,
          required(:reason) => term(),
          required(:requested_at) => integer(),
          required(:plan_id) => String.t() | nil,
          optional(:finished_at) => integer(),
          optional(:outcome) => term()
        }

  @type t :: %__MODULE__{
          id: String.t(),
          objective: String.t(),
          objective_fingerprint: String.t(),
          max_revisions: non_neg_integer(),
          revision: non_neg_integer(),
          version: pos_integer(),
          status: status(),
          planner_request_id: String.t() | nil,
          evaluation_id: String.t() | nil,
          current_plan_id: String.t() | nil,
          previous_plan_id: String.t() | nil,
          pending_plan: Plan.t() | nil,
          feedback: term(),
          decision: term(),
          result: term(),
          evidence_contract: EvidenceContract.t() | nil,
          failure: term(),
          cancellation: cancellation() | nil,
          history: [map()],
          created_at: integer(),
          updated_at: integer()
        }

  @spec new(String.t(), String.t(), non_neg_integer()) :: {:ok, t()} | {:error, term()}
  def new(id, objective, max_revisions) do
    with true <- Plan.valid_id?(id) or {:error, {:invalid_id, id}},
         :ok <- validate_objective(objective),
         true <-
           (is_integer(max_revisions) and max_revisions >= 0) or
             {:error, :invalid_max_revisions} do
      now = System.system_time(:millisecond)

      {:ok,
       %__MODULE__{
         id: id,
         objective: objective,
         objective_fingerprint: fingerprint(objective),
         max_revisions: max_revisions,
         status: :planning,
         planner_request_id: request_id(id, :plan, 0),
         created_at: now,
         updated_at: now
       }}
    else
      {:error, _reason} = error -> error
    end
  end

  @spec validate(t()) :: :ok | {:error, term()}
  def validate(%__MODULE__{} = run) do
    with true <- Plan.valid_id?(run.id) or {:error, {:invalid_id, run.id}},
         :ok <- validate_objective(run.objective),
         true <-
           run.objective_fingerprint == fingerprint(run.objective) or
             {:error, :objective_fingerprint_mismatch},
         true <- run.status in @statuses or {:error, :invalid_status},
         true <-
           (is_integer(run.max_revisions) and run.max_revisions >= 0) or
             {:error, :invalid_max_revisions},
         true <-
           (is_integer(run.revision) and run.revision >= 0 and
              run.revision <= run.max_revisions) or {:error, :invalid_revision},
         true <-
           (is_integer(run.version) and run.version > 0) or {:error, :invalid_version},
         true <-
           (is_integer(run.created_at) and is_integer(run.updated_at)) or
             {:error, :invalid_timestamps},
         :ok <- validate_request_ids(run),
         :ok <- validate_plan_ids(run),
         :ok <- validate_history(run.history, run.revision),
         :ok <- validate_evidence_contract(run.evidence_contract),
         :ok <- validate_status_shape(run),
         true <- Serializable.valid?(run) or {:error, :unserializable_run} do
      :ok
    else
      {:error, _reason} = error -> error
    end
  end

  def validate(_other), do: {:error, :invalid_run}

  @spec transition(t(), map()) :: t()
  def transition(%__MODULE__{} = run, changes) when is_map(changes) do
    struct!(run, Map.merge(changes, %{version: run.version + 1, updated_at: now()}))
  end

  @spec fingerprint(term()) :: String.t()
  def fingerprint(term) do
    :sha256
    |> :crypto.hash(:erlang.term_to_binary(term, [:deterministic]))
    |> Base.encode16(case: :lower)
  end

  @spec request_id(String.t(), :plan | :evaluate, non_neg_integer()) :: String.t()
  def request_id(run_id, kind, revision) do
    digest = fingerprint({run_id, kind, revision})
    "control-#{kind}-#{digest}"
  end

  @spec plan_id(String.t(), non_neg_integer()) :: String.t()
  def plan_id(run_id, revision) do
    "control-plan-#{fingerprint({run_id, revision})}"
  end

  @doc false
  @spec plan_fingerprint(Plan.t()) :: String.t()
  def plan_fingerprint(%Plan{} = plan) do
    specs =
      Enum.map(plan.step_order, fn id ->
        step = Map.fetch!(plan.steps, id)

        %{
          id: step.id,
          dependencies: step.dependencies,
          input: step.input,
          metadata: step.metadata
        }
      end)

    fingerprint(specs)
  end

  defp validate_objective(objective) when is_binary(objective) do
    if String.trim(objective) == "", do: {:error, :empty_objective}, else: :ok
  end

  defp validate_objective(_objective), do: {:error, :invalid_objective}

  defp validate_request_ids(run) do
    expected_planner = request_id(run.id, :plan, run.revision)
    expected_evaluation = request_id(run.id, :evaluate, run.revision)

    cond do
      run.planner_request_id != expected_planner -> {:error, :planner_request_id_mismatch}
      run.evaluation_id not in [nil, expected_evaluation] -> {:error, :evaluation_id_mismatch}
      true -> :ok
    end
  end

  defp validate_plan_ids(run) do
    expected_current = plan_id(run.id, run.revision)

    expected_previous =
      if run.revision == 0,
        do: nil,
        else: plan_id(run.id, run.revision - 1)

    cond do
      run.current_plan_id not in [nil, expected_current] -> {:error, :current_plan_id_mismatch}
      run.previous_plan_id != expected_previous -> {:error, :previous_plan_id_mismatch}
      true -> :ok
    end
  end

  defp validate_history(history, revision) when is_list(history) do
    if Enum.all?(history, fn
         %{revision: entry_revision, decision: decision}
         when is_integer(entry_revision) and entry_revision >= 0 and entry_revision <= revision and
                decision in [:accept, :revise, :fail] ->
           true

         _other ->
           false
       end),
       do: :ok,
       else: {:error, :invalid_history}
  end

  defp validate_history(_history, _revision), do: {:error, :invalid_history}

  defp validate_evidence_contract(nil), do: :ok

  defp validate_evidence_contract(contract) do
    case EvidenceContract.normalize(contract) do
      {:ok, ^contract} -> :ok
      {:ok, _normalized} -> {:error, :noncanonical_evidence_contract}
      {:error, reason} -> {:error, {:invalid_evidence_contract, reason}}
    end
  end

  defp validate_status_shape(%__MODULE__{status: :planning} = run) do
    require_shape(run, current?: false, pending?: false, evaluation?: false)
  end

  defp validate_status_shape(%__MODULE__{status: :submitting} = run) do
    require_shape(run, current?: true, pending?: true, evaluation?: false)
  end

  defp validate_status_shape(%__MODULE__{status: :running} = run) do
    require_shape(run, current?: true, pending?: false, evaluation?: false)
  end

  defp validate_status_shape(%__MODULE__{status: :evaluating} = run) do
    require_shape(run, current?: true, pending?: false, evaluation?: true)
  end

  defp validate_status_shape(%__MODULE__{status: :cancelling} = run) do
    with :ok <- require_cancellation_shape(run, :pending),
         true <- run.decision == :cancelled or {:error, :invalid_cancellation_decision},
         true <- is_nil(run.failure) or {:error, :cancelling_run_has_failure} do
      :ok
    else
      {:error, _reason} = error -> error
    end
  end

  defp validate_status_shape(%__MODULE__{status: :completed, decision: :accept} = run) do
    with :ok <- require_shape(run, current?: true, pending?: false, evaluation?: true),
         true <- is_nil(run.failure) or {:error, :completed_run_has_failure} do
      :ok
    else
      {:error, _reason} = error -> error
    end
  end

  defp validate_status_shape(%__MODULE__{status: :failed, decision: :fail} = run) do
    with :ok <- validate_no_pending(run),
         :ok <- validate_no_cancellation(run),
         true <- not is_nil(run.failure) or {:error, :failed_run_missing_failure} do
      :ok
    else
      {:error, _reason} = error -> error
    end
  end

  defp validate_status_shape(%__MODULE__{status: :cancelled} = run) do
    with :ok <- require_cancellation_shape(run, :completed),
         true <- run.decision == :cancelled or {:error, :invalid_cancellation_decision},
         true <- is_nil(run.failure) or {:error, :cancelled_run_has_failure} do
      :ok
    else
      {:error, _reason} = error -> error
    end
  end

  defp validate_status_shape(%__MODULE__{status: status}),
    do: {:error, {:invalid_status_shape, status}}

  defp require_shape(run, shape) do
    with :ok <-
           validate_presence(
             run.current_plan_id,
             Keyword.fetch!(shape, :current?),
             :current_plan_id
           ),
         :ok <-
           validate_presence(
             run.evaluation_id,
             Keyword.fetch!(shape, :evaluation?),
             :evaluation_id
           ),
         :ok <- validate_pending(run, Keyword.fetch!(shape, :pending?)),
         :ok <- validate_no_cancellation(run) do
      :ok
    end
  end

  defp validate_presence(value, true, _field) when is_binary(value), do: :ok
  defp validate_presence(nil, false, _field), do: :ok
  defp validate_presence(_value, _required?, field), do: {:error, {:invalid_presence, field}}

  defp validate_pending(%__MODULE__{pending_plan: nil}, false), do: :ok

  defp validate_pending(%__MODULE__{pending_plan: %Plan{} = plan} = run, true) do
    with :ok <- Plan.validate(plan),
         true <- plan.id == run.current_plan_id or {:error, :pending_plan_id_mismatch},
         true <-
           plan.metadata[:control_run_id] == run.id or {:error, :pending_plan_run_mismatch},
         true <-
           plan.metadata[:control_revision] == run.revision or
             {:error, :pending_plan_revision_mismatch},
         true <-
           plan.metadata[:control_plan_fingerprint] == plan_fingerprint(plan) or
             {:error, :pending_plan_fingerprint_mismatch} do
      :ok
    else
      {:error, _reason} = error -> error
    end
  end

  defp validate_pending(_run, _required?), do: {:error, :invalid_pending_plan}

  defp validate_no_pending(%__MODULE__{pending_plan: nil}), do: :ok
  defp validate_no_pending(%__MODULE__{}), do: {:error, :failed_run_has_pending_plan}

  defp validate_no_cancellation(%__MODULE__{cancellation: nil}), do: :ok
  defp validate_no_cancellation(%__MODULE__{}), do: {:error, :unexpected_cancellation}

  defp require_cancellation_shape(run, status) do
    with :ok <- validate_no_pending(run),
         :ok <- validate_presence(run.evaluation_id, false, :evaluation_id),
         :ok <- validate_cancellation(run.cancellation, run.current_plan_id, status) do
      :ok
    end
  end

  defp validate_cancellation(cancellation, plan_id, :pending) when is_map(cancellation) do
    with true <-
           MapSet.new(Map.keys(cancellation)) ==
             MapSet.new([:status, :reason, :requested_at, :plan_id]) or
             {:error, :invalid_cancellation_fields},
         true <- cancellation[:status] == :pending or {:error, :invalid_cancellation_status},
         true <- cancellation[:plan_id] == plan_id or {:error, :cancellation_plan_mismatch},
         true <-
           is_integer(cancellation[:requested_at]) or {:error, :invalid_cancellation_timestamp},
         true <-
           Serializable.valid?(cancellation[:reason]) or
             {:error, :unserializable_cancellation_reason} do
      :ok
    else
      {:error, _reason} = error -> error
    end
  end

  defp validate_cancellation(cancellation, plan_id, :completed) when is_map(cancellation) do
    with true <-
           MapSet.new(Map.keys(cancellation)) ==
             MapSet.new([
               :status,
               :reason,
               :requested_at,
               :plan_id,
               :finished_at,
               :outcome
             ]) or {:error, :invalid_cancellation_fields},
         true <- cancellation[:status] == :completed or {:error, :invalid_cancellation_status},
         true <- cancellation[:plan_id] == plan_id or {:error, :cancellation_plan_mismatch},
         true <-
           (is_integer(cancellation[:requested_at]) and is_integer(cancellation[:finished_at])) or
             {:error, :invalid_cancellation_timestamp},
         true <-
           cancellation[:finished_at] >= cancellation[:requested_at] or
             {:error, :invalid_cancellation_timestamp},
         true <-
           (Serializable.valid?(cancellation[:reason]) and
              Serializable.valid?(cancellation[:outcome])) or
             {:error, :unserializable_cancellation} do
      :ok
    else
      {:error, _reason} = error -> error
    end
  end

  defp validate_cancellation(_cancellation, _plan_id, _status),
    do: {:error, :invalid_cancellation}

  defp now, do: System.system_time(:millisecond)
end
