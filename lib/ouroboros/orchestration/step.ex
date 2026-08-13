defmodule Ouroboros.Orchestration.Step do
  @moduledoc """
  A durable unit of work in an orchestration plan.

  Runtime owners and monitors intentionally do not live in this struct. An
  `execution_token` is the durable identity an executor uses to deduplicate a
  recovered attempt.

  ## Kinds

  A step declares what plane executes it. `:coding` is the historical default and
  keeps its free-form input. `:forge` names one compile-and-deploy of a single
  capability module and carries a closed input schema: exactly `module` and
  `source_path`, both strings.

  The forge input is deliberately the smallest thing a planner can say. The
  module name must sit inside the `Ouroboros.Capability.` namespace, mirroring
  `Ouroboros.Upgrade.Forge.Source`, and the source path must be relative with no
  traversal, because it is resolved under a workspace root that trusted runtime
  configuration owns. Everything else a forge needs — which workspace, which
  nodes, which signer — never appears here.

  Snapshots written before `:kind` existed have no such field. `upgrade/1` reads
  those as `:coding` and refuses any value that is not a kind this build knows,
  so a newer plan cannot be silently downgraded by an older node.
  """

  alias Ouroboros.Orchestration.Serializable

  @states [:pending, :ready, :running, :completed, :failed, :cancelled, :blocked]
  @kinds [:coding, :forge]

  # Mirrors `Ouroboros.Upgrade.Forge.Source`'s namespace policy. A forge step that
  # names anything else is rejected before it reaches a plan, not after a build.
  @capability_module ~r/^Ouroboros\.Capability\.[A-Z][A-Za-z0-9_]*(\.[A-Z][A-Za-z0-9_]*)*$/
  @max_source_path_bytes 1_024

  @enforce_keys [:id]
  defstruct [
    :id,
    :input,
    :result,
    :error,
    :execution_token,
    :started_at,
    :finished_at,
    kind: :coding,
    dependencies: [],
    metadata: %{},
    state: :pending,
    attempt: 0,
    blocked_by: [],
    cancellation: nil
  ]

  @type state :: :pending | :ready | :running | :completed | :failed | :cancelled | :blocked
  @type kind :: :coding | :forge
  @type forge_request :: %{module: String.t(), source_path: String.t()}

  @type cancellation :: %{
          required(:status) => :pending | :completed | :not_required,
          required(:reason) => term(),
          required(:requested_at) => integer(),
          optional(:finished_at) => integer(),
          optional(:outcome) => term()
        }

  @type t :: %__MODULE__{
          id: String.t(),
          kind: kind(),
          input: term(),
          result: term(),
          error: term(),
          execution_token: String.t() | nil,
          started_at: integer() | nil,
          finished_at: integer() | nil,
          dependencies: [String.t()],
          metadata: map(),
          state: state(),
          attempt: non_neg_integer(),
          blocked_by: [String.t()],
          cancellation: cancellation() | nil
        }

  @spec states() :: [state()]
  def states, do: @states

  @spec kinds() :: [kind()]
  def kinds, do: @kinds

  @doc """
  Normalizes a caller-supplied kind, accepting the atom or its exact string form.

  No atom is created here: only kinds this build already declares are accepted.
  """
  @spec normalize_kind(term()) :: {:ok, kind()} | {:error, term()}
  def normalize_kind(nil), do: {:ok, :coding}
  def normalize_kind(kind) when kind in @kinds, do: {:ok, kind}

  def normalize_kind(kind) when is_binary(kind) do
    case Enum.find(@kinds, &(Atom.to_string(&1) == kind)) do
      nil -> {:error, {:unknown_step_kind, kind}}
      known -> {:ok, known}
    end
  end

  def normalize_kind(kind), do: {:error, {:unknown_step_kind, kind}}

  @doc """
  Restores a step decoded from a durable snapshot.

  A snapshot written before `:kind` existed carries no such key and is read as
  `:coding`, which is what those steps have always been. A kind this build does
  not know is refused rather than coerced.
  """
  @spec upgrade(term()) :: {:ok, t()} | {:error, term()}
  def upgrade(%__MODULE__{} = step) do
    case Map.get(step, :kind, :coding) do
      kind when kind in @kinds -> {:ok, Map.put(step, :kind, kind)}
      other -> {:error, {:unknown_step_kind, other}}
    end
  end

  def upgrade(other), do: {:error, {:invalid_step, other}}

  @doc """
  Checks a step input against the schema its kind declares.

  `:coding` inputs stay free-form; the executing plane owns their meaning.
  """
  @spec validate_input(kind(), term()) :: :ok | {:error, term()}
  def validate_input(:coding, _input), do: :ok

  def validate_input(:forge, input) do
    case forge_request(input) do
      {:ok, _request} -> :ok
      {:error, _reason} = error -> error
    end
  end

  def validate_input(kind, _input), do: {:error, {:unknown_step_kind, kind}}

  @doc """
  Reads a `:forge` step input as the pair a forge executor may act on.

  Atom-keyed and string-keyed inputs are both accepted, because a plan may be
  built in Elixir or normalized from a model's JSON. Any other shape, an extra
  key, a module outside the capability namespace, or a path that is absolute or
  contains a traversal segment is refused.
  """
  @spec forge_request(term()) :: {:ok, forge_request()} | {:error, term()}
  def forge_request(input) do
    with {:ok, module, source_path} <- forge_fields(input),
         :ok <- validate_capability_module(module),
         :ok <- validate_source_path(source_path) do
      {:ok, %{module: module, source_path: source_path}}
    end
  end

  @doc false
  @spec valid?(t()) :: boolean()
  def valid?(%__MODULE__{} = step) do
    kind = Map.get(step, :kind)

    is_binary(step.id) and kind in @kinds and validate_input(kind, step.input) == :ok and
      step.state in @states and is_list(step.dependencies) and
      Enum.all?(step.dependencies, &is_binary/1) and is_map(step.metadata) and
      is_integer(step.attempt) and step.attempt >= 0 and is_list(step.blocked_by) and
      token_valid?(step.execution_token) and Serializable.valid?(step)
  end

  def valid?(_other), do: false

  defp forge_fields(input) when is_map(input) and not is_struct(input) do
    keys = input |> Map.keys() |> MapSet.new()

    cond do
      keys == MapSet.new([:module, :source_path]) ->
        {:ok, Map.fetch!(input, :module), Map.fetch!(input, :source_path)}

      keys == MapSet.new(["module", "source_path"]) ->
        {:ok, Map.fetch!(input, "module"), Map.fetch!(input, "source_path")}

      true ->
        {:error, {:invalid_forge_input, Enum.sort(keys)}}
    end
  end

  defp forge_fields(_input), do: {:error, :invalid_forge_input}

  defp validate_capability_module(module) when is_binary(module) do
    if Regex.match?(@capability_module, module),
      do: :ok,
      else: {:error, {:invalid_capability_module, module}}
  end

  defp validate_capability_module(module), do: {:error, {:invalid_capability_module, module}}

  # Relative, no traversal, no empty or dot segments, and no embedded null. The
  # workspace root this joins onto is trusted configuration; the path is not.
  defp validate_source_path(path) when is_binary(path) do
    cond do
      path == "" or byte_size(path) > @max_source_path_bytes ->
        {:error, {:invalid_source_path, path}}

      Path.type(path) != :relative ->
        {:error, {:invalid_source_path, path}}

      String.contains?(path, <<0>>) ->
        {:error, {:invalid_source_path, path}}

      Enum.any?(String.split(path, "/"), &(&1 in ["", ".", ".."])) ->
        {:error, {:invalid_source_path, path}}

      true ->
        :ok
    end
  end

  defp validate_source_path(path), do: {:error, {:invalid_source_path, path}}

  defp token_valid?(nil), do: true
  defp token_valid?(token), do: is_binary(token) and byte_size(token) > 0
end
