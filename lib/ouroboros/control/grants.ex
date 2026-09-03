defmodule Ouroboros.Control.Grants do
  @moduledoc """
  The durable, deny-by-default authority for agent effects.

  A grant is one triple — principal, effect, constraints — where the principal is a
  logical mesh agent ID, the effect is something `Ouroboros.Agent.Effects` can do to the
  world, and the constraints are the single allow-list that effect is checked against:

      :start_agent   modules: :any | [module]
      :stop_agent    agents:  :any | [agent_id]
      :send_message  agents:  :any | [agent_id]
      :delegate      teams:   :any | [team_id]
      :forge         modules: :any | [module | "wasm/<name>"]
      :deploy        nodes:   :any | [node]

  A `:forge` allow-list holds atoms — BEAM capability modules — and `"wasm/<name>"` strings,
  because lane W's capabilities have no module name at all: identity there is the component's
  digest, and the name a rollout, a `start` block and this allow-list all agree on is
  `"wasm/" <> Ouroboros.Wasm.Artifact.name?/1`. The two spellings can never match each other,
  so a grant narrowed to `[Ouroboros.Capability.Echo]` admits no wasm forge and a grant
  narrowed to `["wasm/counter"]` admits no BEAM one. `modules: :any` is what it has always
  been — forge whatever you like — and it now reaches both lanes, which is the widening this
  spelling makes explicit rather than hides.

  `granted?/3` is asked about a *concrete attempt*, not about an effect in the abstract,
  so a grant to start `Ouroboros.Capability.Echo` refuses a request to start anything
  else. Absence is refusal: a principal with no entry is denied, an effect with no entry
  is denied, an attempt missing the field its constraint reads is denied, and an
  authority that cannot answer — stopped, wedged, or unwritable — is denied. There is no
  path through this module that fails open.

  Writes are checkpointed before they are acknowledged, in the order every other store
  here uses. A grant whose checkpoint fails is not applied in memory and not reported as
  granted, so a storage fault narrows authority rather than widening it.

  A *revocation* whose checkpoint fails behaves the same way and is worth stating plainly,
  because the direction is the uncomfortable one: the grant stays. An authority that
  forgot a grant it could not durably forget would hand that grant straight back at the
  next restart, so an unacknowledged revocation has not happened. `revoke/2` returning an
  error means the principal still holds the effect, and the operator's next move is to
  retry it or stop the agent — not to assume it is gone.

  ## What this actually gates, and what it does not

  Grants gate the *action layer*: the typed signals an agent handles through
  `Ouroboros.Agent.Effects`. That is the layer well-behaved agent flows travel through,
  and constraining it is worth doing. It is not a sandbox, and describing it as one would
  be a lie:

    * Any BEAM the loader accepts runs with full ambient VM authority. Loaded code can
      call `Ouroboros.Mesh.start_agent/2`, `Ouroboros.Upgrade.Forge.forge/2`, or
      `grant/3` on this module directly, without passing through an effect action at all.
    * No effect exists for granting, so an agent cannot widen its own authority *through
      this surface*. That is a property of the surface, not of the VM.
    * The boundaries that hold against code that does not cooperate are elsewhere: the
      verifier's namespace policy, artifact signing (whose production default refuses),
      and the isolated build peer.

  This module lives under `Ouroboros.Control.` deliberately. That prefix is in
  `Ouroboros.Upgrade.Verifier`'s protected set, so the fast patch lane refuses to load an
  artifact that would replace or introduce the authority gating it — a capability an
  agent forged cannot patch the thing that decided it could forge. What keeps signing
  approval outside the blast radius is the same reasoning applied one level up, and it
  belongs outside this application entirely.

  Storage comes from `config :ouroboros, :grants_storage`: ETS in development and test,
  a synced `Ouroboros.Storage.DurableFile` in production. ETS means the authority dies
  with the VM and every principal starts denied, which is the safe direction to fail.
  """

  use GenServer

  @store_key {:ouroboros, :agent_grants, 1}
  @checkpoint_version 1

  # Every effect is constrained by exactly one allow-list, named for what it admits.
  @constraints %{
    start_agent: :modules,
    stop_agent: :agents,
    send_message: :agents,
    delegate: :teams,
    forge: :modules,
    deploy: :nodes
  }

  # ...and that allow-list is checked against exactly one field of the attempt.
  @attempt_keys %{modules: :module, agents: :agent, teams: :team, nodes: :nodes}

  @effects Map.keys(@constraints)

  defmodule Grant do
    @moduledoc "One principal's authority over one effect, and its allow-list."

    @enforce_keys [:principal, :effect, :constraints, :granted_at]
    defstruct @enforce_keys

    @type allowed :: :any | [term()]
    @type t :: %__MODULE__{
            principal: String.t(),
            effect: atom(),
            constraints: %{atom() => allowed()},
            granted_at: String.t()
          }
  end

  @type server :: GenServer.server()
  @type attempt :: %{optional(atom()) => term()}
  @type decision :: %{
          granted?: boolean(),
          grant: Grant.t() | nil,
          reason: :granted | :not_granted | :outside_constraints | :authority_unavailable
        }

  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "Returns the effects a grant can name."
  @spec effects() :: [atom()]
  def effects, do: @effects

  @doc """
  Grants `principal` one effect, bounded by `constraints`.

  Constraints are a keyword list or map carrying exactly the key this effect is checked
  against, whose value is `:any` or a list of permitted values. Re-granting replaces the
  previous constraints for that pair rather than merging them, so narrowing a grant is
  one call and never leaves a wider remnant behind.
  """
  @spec grant(String.t(), atom(), keyword() | map(), server()) ::
          {:ok, Grant.t()} | {:error, term()}
  def grant(principal, effect, constraints, server \\ __MODULE__) do
    GenServer.call(server, {:grant, principal, effect, constraints})
  catch
    :exit, reason -> {:error, {:grants_unavailable, reason}}
  end

  @doc "Removes one principal's authority over one effect."
  @spec revoke(String.t(), atom(), server()) :: :ok | {:error, term()}
  def revoke(principal, effect, server \\ __MODULE__) do
    GenServer.call(server, {:revoke, principal, effect})
  catch
    :exit, reason -> {:error, {:grants_unavailable, reason}}
  end

  @doc """
  Answers whether `principal` may perform this concrete `attempt` of `effect`.

  Every failure is a refusal. A missing grant, an attempt outside the allow-list, an
  attempt that does not name what the allow-list reads, a malformed call, and an
  unreachable authority all return `false`.
  """
  @spec granted?(String.t(), atom(), attempt(), server()) :: boolean()
  def granted?(principal, effect, attempt, server \\ __MODULE__)

  def granted?(principal, effect, attempt, server)
      when is_binary(principal) and is_atom(effect) and is_map(attempt) do
    GenServer.call(server, {:granted?, principal, effect, attempt})
  catch
    # An authority that cannot answer has not authorized anything.
    _kind, _reason -> false
  end

  def granted?(_principal, _effect, _attempt, _server), do: false

  @doc """
  Returns the authority decision and the exact grant snapshot used to make it.

  This is the inspectable counterpart to `granted?/4`. It remains fail-closed, but a
  caller that must durably explain an action can distinguish a missing grant from an
  attempt outside an existing grant's constraints. An unavailable authority returns a
  content-free `:authority_unavailable` reason rather than persisting an exit term.
  """
  @spec decision(String.t(), atom(), attempt(), server()) :: decision()
  def decision(principal, effect, attempt, server \\ __MODULE__)

  def decision(principal, effect, attempt, server)
      when is_binary(principal) and principal != "" and is_atom(effect) and is_map(attempt) do
    GenServer.call(server, {:decision, principal, effect, attempt})
  catch
    _kind, _reason -> denied_decision(:authority_unavailable)
  end

  def decision(_principal, _effect, _attempt, _server),
    do: denied_decision(:not_granted)

  @doc "Returns every grant held by one principal, ordered by effect."
  @spec list(String.t(), server()) :: [Grant.t()]
  def list(principal, server \\ __MODULE__) when is_binary(principal) do
    GenServer.call(server, {:list, principal})
  catch
    :exit, _reason -> []
  end

  @type durability :: :ephemeral_checkpoint | :durable_checkpoint | :synced_checkpoint

  @spec durability(server()) :: durability()
  def durability(server \\ __MODULE__), do: GenServer.call(server, :durability)

  @doc false
  def checkpoint_key, do: @store_key

  @impl true
  def init(opts) do
    with {:ok, storage} <- storage_config(opts),
         {:ok, adapter, adapter_opts} <- normalize_storage(storage),
         {:ok, grants} <- load(adapter, adapter_opts) do
      {:ok,
       %{
         adapter: adapter,
         opts: adapter_opts,
         grants: grants,
         durability: durability_level(adapter)
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:grant, principal, effect, constraints}, _from, state) do
    with {:ok, principal} <- validate_principal(principal),
         {:ok, effect} <- validate_effect(effect),
         {:ok, normalized} <- validate_constraints(effect, constraints) do
      grant = %Grant{
        principal: principal,
        effect: effect,
        constraints: normalized,
        granted_at: now()
      }

      persist(Map.put(state.grants, {principal, effect}, grant), grant, state)
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:revoke, principal, effect}, _from, state) do
    with {:ok, principal} <- validate_principal(principal),
         {:ok, effect} <- validate_effect(effect) do
      key = {principal, effect}

      if Map.has_key?(state.grants, key) do
        persist(Map.delete(state.grants, key), :ok, state)
      else
        {:reply, :ok, state}
      end
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:granted?, principal, effect, attempt}, _from, state) do
    permitted? =
      case Map.fetch(state.grants, {principal, effect}) do
        {:ok, grant} -> permits?(grant, attempt)
        :error -> false
      end

    {:reply, permitted?, state}
  end

  def handle_call({:decision, principal, effect, attempt}, _from, state) do
    decision =
      case Map.fetch(state.grants, {principal, effect}) do
        {:ok, grant} ->
          if permits?(grant, attempt) do
            %{granted?: true, grant: grant, reason: :granted}
          else
            %{granted?: false, grant: grant, reason: :outside_constraints}
          end

        :error ->
          denied_decision(:not_granted)
      end

    {:reply, decision, state}
  end

  def handle_call({:list, principal}, _from, state) do
    grants =
      state.grants
      |> Enum.filter(fn {{holder, _effect}, _grant} -> holder == principal end)
      |> Enum.map(fn {_key, grant} -> grant end)
      |> Enum.sort_by(& &1.effect)

    {:reply, grants, state}
  end

  def handle_call(:durability, _from, state), do: {:reply, state.durability, state}

  # A definite pre-commit failure leaves memory alone. Post-rename ambiguity stops this
  # authority below, so it cannot continue beside a different visible checkpoint.
  defp persist(grants, reply, state) do
    case adapter_call(state.adapter, :put_checkpoint, [
           @store_key,
           checkpoint(grants),
           state.opts
         ]) do
      :ok ->
        {:reply, ok(reply), %{state | grants: grants}}

      {:error, {:commit_outcome_unknown, _reason} = ambiguity} ->
        {:stop, ambiguity, {:error, {:grant_commit_outcome_unknown, ambiguity}}, state}

      {:error, reason} ->
        {:reply, {:error, {:grant_checkpoint_failed, reason}}, state}

      other ->
        {:reply, {:error, {:invalid_grant_storage_response, other}}, state}
    end
  end

  defp ok(:ok), do: :ok
  defp ok(%Grant{} = grant), do: {:ok, grant}

  defp permits?(%Grant{effect: :deploy, constraints: %{nodes: allowed}}, attempt) do
    # Deploying names a set, and the whole set has to be admitted. An empty target list
    # is not "trivially permitted", it is a malformed attempt.
    case Map.fetch(attempt, :nodes) do
      {:ok, [_ | _] = nodes} -> allowed == :any or Enum.all?(nodes, &(&1 in allowed))
      _other -> false
    end
  end

  defp permits?(%Grant{effect: effect, constraints: constraints}, attempt) do
    key = Map.fetch!(@constraints, effect)

    case {Map.fetch(constraints, key), Map.fetch(attempt, Map.fetch!(@attempt_keys, key))} do
      {{:ok, :any}, {:ok, _value}} -> true
      {{:ok, allowed}, {:ok, value}} when is_list(allowed) -> value in allowed
      _other -> false
    end
  end

  defp denied_decision(reason), do: %{granted?: false, grant: nil, reason: reason}

  defp validate_principal(principal) when is_binary(principal) and principal != "",
    do: {:ok, principal}

  defp validate_principal(other), do: {:error, {:invalid_principal, other}}

  defp validate_effect(effect) when effect in @effects, do: {:ok, effect}
  defp validate_effect(other), do: {:error, {:unknown_effect, other}}

  # An operator has to say what an effect may reach. Silence is not `:any`.
  defp validate_constraints(effect, constraints) do
    key = Map.fetch!(@constraints, effect)

    with {:ok, given} <- constraint_map(constraints),
         :ok <- ensure_only(given, key),
         {:ok, allowed} <- fetch_allowed(given, key, effect),
         :ok <- validate_values(key, allowed) do
      {:ok, %{key => allowed}}
    end
  end

  defp constraint_map(constraints) when is_map(constraints), do: {:ok, constraints}

  defp constraint_map(constraints) when is_list(constraints) do
    if Keyword.keyword?(constraints),
      do: {:ok, Map.new(constraints)},
      else: {:error, {:invalid_constraints, constraints}}
  end

  defp constraint_map(other), do: {:error, {:invalid_constraints, other}}

  defp ensure_only(given, key) do
    case given |> Map.keys() |> List.delete(key) do
      [] -> :ok
      extra -> {:error, {:unknown_constraints, extra}}
    end
  end

  defp fetch_allowed(given, key, effect) do
    case Map.fetch(given, key) do
      {:ok, :any} -> {:ok, :any}
      {:ok, values} when is_list(values) -> {:ok, values}
      {:ok, other} -> {:error, {:invalid_constraint, key, other}}
      :error -> {:error, {:missing_constraint, effect, key}}
    end
  end

  defp validate_values(_key, :any), do: :ok

  defp validate_values(:nodes, values) do
    if Enum.all?(values, &(is_atom(&1) and not is_nil(&1))),
      do: :ok,
      else: {:error, {:invalid_constraint, :nodes, values}}
  end

  defp validate_values(:modules, values) do
    if Enum.all?(values, &module_or_capability?/1),
      do: :ok,
      else: {:error, {:invalid_constraint, :modules, values}}
  end

  defp validate_values(key, values) when key in [:agents, :teams] do
    if Enum.all?(values, &(is_binary(&1) and &1 != "")),
      do: :ok,
      else: {:error, {:invalid_constraint, key, values}}
  end

  # A lane-W name is admitted in exactly the spelling everything else uses it in. Accepting
  # any binary here would let an operator write a grant that silently matches nothing, which
  # is a grant that reads as narrow and is not.
  defp module_or_capability?(value) when is_atom(value) and not is_nil(value), do: true

  defp module_or_capability?("wasm/" <> name), do: Ouroboros.Wasm.Artifact.name?(name)

  defp module_or_capability?(_value), do: false

  defp checkpoint(grants), do: %{version: @checkpoint_version, grants: grants}

  defp load(adapter, adapter_opts) do
    case adapter_call(adapter, :get_checkpoint, [@store_key, adapter_opts]) do
      :not_found ->
        {:ok, %{}}

      {:ok, %{version: @checkpoint_version, grants: grants}} when is_map(grants) ->
        if valid_grants?(grants), do: {:ok, grants}, else: {:error, :invalid_grant_checkpoint}

      # A checkpoint this build cannot interpret is preserved, not overwritten, and not
      # silently read as an empty authority.
      {:ok, %{version: version}} ->
        {:error, {:unsupported_grant_checkpoint, version}}

      {:ok, _invalid} ->
        {:error, :invalid_grant_checkpoint}

      {:error, reason} ->
        {:error, {:grant_checkpoint_unreadable, reason}}

      other ->
        {:error, {:invalid_grant_storage_response, other}}
    end
  end

  defp valid_grants?(grants) do
    Enum.all?(grants, fn
      {{principal, effect}, %Grant{principal: principal, effect: effect} = grant} ->
        is_binary(principal) and effect in @effects and is_map(grant.constraints)

      _other ->
        false
    end)
  end

  defp adapter_call(adapter, function, arguments) do
    apply(adapter, function, arguments)
  rescue
    error -> {:error, {:adapter_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:adapter_failure, kind, inspect(reason)}}
  end

  defp storage_config(opts) do
    case Keyword.fetch(opts, :storage) do
      {:ok, storage} ->
        {:ok, storage}

      :error ->
        case Application.get_env(:ouroboros, :grants_storage) do
          nil -> {:ok, {Jido.Storage.ETS, table: :ouroboros_grants}}
          storage -> {:ok, storage}
        end
    end
  end

  defp normalize_storage(storage) do
    {adapter, adapter_opts} = Jido.Storage.normalize_storage(storage)
    {:ok, adapter, adapter_opts}
  rescue
    error -> {:error, {:invalid_grants_storage, Exception.message(error)}}
  end

  defp durability_level(Jido.Storage.ETS), do: :ephemeral_checkpoint
  defp durability_level(Ouroboros.Storage.DurableFile), do: :synced_checkpoint
  defp durability_level(_adapter), do: :durable_checkpoint

  defp now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
