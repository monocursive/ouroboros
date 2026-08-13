defmodule Ouroboros.Orchestration.Plan do
  @moduledoc """
  A serializable, provider-neutral dependency graph.

  Plan and step IDs are caller supplied and deliberately constrained to a
  stable, transport-safe character set. `step_order` preserves deterministic
  scheduling while `steps` provides direct lookup.

  A plan is heterogeneous: each step declares a `:kind` (`:coding` by default,
  `:forge` for a compile-and-deploy of one capability module) and its input is
  validated against that kind's schema here, before anything is persisted or
  dispatched. `Ouroboros.Orchestration.Step` owns the per-kind rules so the
  control plane can apply exactly the same ones to a model-produced plan.
  """

  alias Ouroboros.Orchestration.{Serializable, Step}

  @id_regex ~r/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
  @statuses [:pending, :ready, :running, :completed, :failed, :cancelled, :blocked]

  @enforce_keys [:id, :steps, :step_order]
  defstruct [
    :id,
    :created_at,
    :updated_at,
    metadata: %{},
    steps: %{},
    step_order: [],
    status: :pending,
    version: 1,
    failure: nil,
    cancellation: nil
  ]

  @type status :: :pending | :ready | :running | :completed | :failed | :cancelled | :blocked

  @type t :: %__MODULE__{
          id: String.t(),
          created_at: integer(),
          updated_at: integer(),
          metadata: map(),
          steps: %{String.t() => Step.t()},
          step_order: [String.t()],
          status: status(),
          version: pos_integer(),
          failure: term(),
          cancellation: term()
        }

  @spec new(String.t(), [map() | keyword()], keyword()) :: {:ok, t()} | {:error, term()}
  def new(id, step_specs, opts \\ [])

  def new(id, step_specs, opts) when is_list(step_specs) and is_list(opts) do
    with :ok <- validate_keyword(opts),
         :ok <- validate_id(id),
         :ok <- validate_nonempty(step_specs),
         {:ok, metadata} <- validate_metadata(Keyword.get(opts, :metadata, %{})),
         {:ok, steps, order} <- build_steps(step_specs),
         :ok <- validate_dependencies(steps),
         :ok <- validate_acyclic(steps) do
      now = System.system_time(:millisecond)
      steps = initialize_states(steps)

      {:ok,
       %__MODULE__{
         id: id,
         metadata: metadata,
         steps: steps,
         step_order: order,
         status: :ready,
         created_at: now,
         updated_at: now
       }}
    end
  end

  def new(_id, _step_specs, _opts), do: {:error, :invalid_plan_arguments}

  @spec validate(t()) :: :ok | {:error, term()}
  def validate(%__MODULE__{} = plan) do
    with :ok <- validate_id(plan.id),
         true <- plan.status in @statuses or {:error, :invalid_plan_status},
         true <-
           (is_map(plan.metadata) and Serializable.valid?(plan.metadata)) or
             {:error, :invalid_plan_metadata},
         true <-
           (is_map(plan.steps) and is_list(plan.step_order)) or
             {:error, :invalid_plan_steps},
         true <- map_size(plan.steps) > 0 or {:error, :empty_plan},
         true <-
           plan.step_order == Enum.uniq(plan.step_order) or
             {:error, :duplicate_step_order},
         true <-
           MapSet.new(plan.step_order) == MapSet.new(Map.keys(plan.steps)) or
             {:error, :step_order_mismatch},
         :ok <- validate_persisted_steps(plan.steps),
         :ok <- validate_dependencies(plan.steps),
         :ok <- validate_acyclic(plan.steps),
         true <- Serializable.valid?(plan) or {:error, :unserializable_plan} do
      :ok
    else
      {:error, _reason} = error -> error
      false -> {:error, :invalid_plan}
    end
  end

  def validate(_other), do: {:error, :invalid_plan}

  @spec valid_id?(term()) :: boolean()
  def valid_id?(id), do: is_binary(id) and Regex.match?(@id_regex, id)

  @doc """
  Restores a plan decoded from a durable snapshot.

  Only step shape has changed so far: a snapshot written before `:kind` existed
  loads as `:coding`. A kind this build does not know is refused, so an older
  node never reinterprets a newer plan as something it can run.
  """
  @spec upgrade(t()) :: {:ok, t()} | {:error, term()}
  def upgrade(%__MODULE__{} = plan) do
    with true <- is_map(plan.steps) or {:error, :invalid_plan_steps},
         {:ok, steps} <- upgrade_steps(plan.steps) do
      {:ok, %{plan | steps: steps}}
    else
      false -> {:error, :invalid_plan}
      {:error, _reason} = error -> error
    end
  end

  def upgrade(_other), do: {:error, :invalid_plan}

  defp upgrade_steps(steps) do
    Enum.reduce_while(steps, {:ok, %{}}, fn {id, step}, {:ok, acc} ->
      case Step.upgrade(step) do
        {:ok, upgraded} -> {:cont, {:ok, Map.put(acc, id, upgraded)}}
        {:error, reason} -> {:halt, {:error, {:invalid_step, id, reason}}}
      end
    end)
  end

  defp build_steps(specs) do
    Enum.reduce_while(specs, {:ok, %{}, []}, fn spec, {:ok, steps, order} ->
      with {:ok, spec} <- normalize_spec(spec),
           id <- Map.get(spec, :id),
           :ok <- validate_id(id),
           :ok <- ensure_unique_step_id(steps, id),
           {:ok, kind} <- validate_kind(Map.get(spec, :kind), id),
           {:ok, dependencies} <- validate_dependency_list(Map.get(spec, :dependencies, [])),
           {:ok, metadata} <- validate_metadata(Map.get(spec, :metadata, %{})),
           input <- Map.get(spec, :input),
           true <- Serializable.valid?(input) or {:error, {:unserializable_input, id}},
           :ok <- validate_step_input(kind, input, id) do
        step = %Step{
          id: id,
          kind: kind,
          dependencies: dependencies,
          input: input,
          metadata: metadata
        }

        {:cont, {:ok, Map.put(steps, id, step), order ++ [id]}}
      else
        {:error, _reason} = error -> {:halt, error}
      end
    end)
  end

  defp validate_kind(kind, id) do
    case Step.normalize_kind(kind) do
      {:ok, kind} -> {:ok, kind}
      {:error, reason} -> {:error, {:invalid_step_kind, id, reason}}
    end
  end

  defp validate_step_input(kind, input, id) do
    case Step.validate_input(kind, input) do
      :ok -> :ok
      {:error, reason} -> {:error, {:invalid_step_input, id, reason}}
    end
  end

  defp normalize_spec(spec) when is_map(spec), do: {:ok, spec}

  defp normalize_spec(spec) when is_list(spec) do
    if Keyword.keyword?(spec), do: {:ok, Map.new(spec)}, else: {:error, :invalid_step_spec}
  end

  defp normalize_spec(_spec), do: {:error, :invalid_step_spec}

  defp validate_persisted_steps(steps) do
    Enum.reduce_while(steps, :ok, fn
      {id, %Step{id: id} = step}, :ok ->
        if valid_id?(id) and Step.valid?(step),
          do: {:cont, :ok},
          else: {:halt, {:error, {:invalid_step, id}}}

      {id, _step}, :ok ->
        {:halt, {:error, {:invalid_step, id}}}
    end)
  end

  defp validate_id(id) do
    if valid_id?(id), do: :ok, else: {:error, {:invalid_id, id}}
  end

  defp validate_nonempty([]), do: {:error, :empty_plan}
  defp validate_nonempty([_ | _]), do: :ok

  defp validate_keyword(opts) do
    if Keyword.keyword?(opts), do: :ok, else: {:error, :invalid_options}
  end

  defp validate_metadata(metadata) when is_map(metadata) do
    if Serializable.valid?(metadata),
      do: {:ok, metadata},
      else: {:error, :unserializable_metadata}
  end

  defp validate_metadata(_metadata), do: {:error, :invalid_metadata}

  defp validate_dependency_list(dependencies) when is_list(dependencies) do
    cond do
      not Enum.all?(dependencies, &valid_id?/1) -> {:error, :invalid_dependencies}
      dependencies != Enum.uniq(dependencies) -> {:error, :duplicate_dependencies}
      true -> {:ok, dependencies}
    end
  end

  defp validate_dependency_list(_dependencies), do: {:error, :invalid_dependencies}

  defp ensure_unique_step_id(steps, id) do
    if Map.has_key?(steps, id), do: {:error, {:duplicate_step_id, id}}, else: :ok
  end

  defp validate_dependencies(steps) do
    ids = MapSet.new(Map.keys(steps))

    Enum.reduce_while(steps, :ok, fn {id, step}, :ok ->
      cond do
        id in step.dependencies ->
          {:halt, {:error, {:self_dependency, id}}}

        missing = Enum.find(step.dependencies, &(not MapSet.member?(ids, &1))) ->
          {:halt, {:error, {:unknown_dependency, id, missing}}}

        true ->
          {:cont, :ok}
      end
    end)
  end

  defp validate_acyclic(steps) do
    indegrees = Map.new(steps, fn {id, step} -> {id, length(step.dependencies)} end)

    dependents =
      Enum.reduce(steps, %{}, fn {id, step}, acc ->
        Enum.reduce(step.dependencies, acc, fn dependency, nested ->
          Map.update(nested, dependency, [id], &[id | &1])
        end)
      end)

    queue = for {id, 0} <- indegrees, do: id
    visited = visit_acyclic(queue, indegrees, dependents, 0)

    if visited == map_size(steps), do: :ok, else: {:error, :cyclic_dependencies}
  end

  defp visit_acyclic([], _indegrees, _dependents, visited), do: visited

  defp visit_acyclic([id | rest], indegrees, dependents, visited) do
    {indegrees, newly_ready} =
      Enum.reduce(Map.get(dependents, id, []), {indegrees, []}, fn dependent, {degrees, ready} ->
        next = Map.fetch!(degrees, dependent) - 1
        degrees = Map.put(degrees, dependent, next)
        {degrees, if(next == 0, do: [dependent | ready], else: ready)}
      end)

    visit_acyclic(rest ++ Enum.reverse(newly_ready), indegrees, dependents, visited + 1)
  end

  defp initialize_states(steps) do
    Map.new(steps, fn {id, step} ->
      state = if step.dependencies == [], do: :ready, else: :pending
      {id, %{step | state: state}}
    end)
  end
end
