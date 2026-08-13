defmodule Ouroboros.Upgrade.Rollout do
  @moduledoc """
  Deploys a forged capability to explicit nodes behind a health gate, and records what
  happened.

  The sequence is fixed:

  1. checkpoint `:deploying` in `Ouroboros.Upgrade.Rollout.Registry` — durably, before
     anything is mutated. If that write fails the rollout does not start.
  2. `Coordinator.deploy/3` with `health_check: {Probe, :ready?, [module]}`, so every
     node that committed the code must also start it, message it, and stop it again.
  3. on success, `Coordinator.promote/2` and a `:live` record.
  4. on failure, read the deployment's own recovery evidence and record `:rolled_back`
     only if every node proved it compensated.

  ## Ambiguity is never rolled back

  This is the invariant the whole module exists to preserve. `Coordinator` distinguishes
  a node that answered "I rolled back" from a node that did not answer at all, and only
  the first is recovery `:rolled_back`. A node whose commit reply was lost may be running
  the new code right now. Recording that as `:rolled_back` would turn an unknown cluster
  into a clean-looking one, which is the single most expensive lie this system could
  tell, so anything short of proof is recorded as `:quarantined`.

  ## Promotion

  Promotion soft-purges retired code and discards rollback material. For an introduced
  module there is nothing retired to purge, so it succeeds trivially and simply retires
  the ability to unload by receipt; the capability stays live and can still be removed by
  a later deployment. A promotion that leaves any node quarantined downgrades the record
  to `:quarantined` even though the code is live, because the node's state is unknown.
  """

  alias Ouroboros.Upgrade.{Artifact, Coordinator}
  alias Ouroboros.Upgrade.Rollout.{Probe, Registry}

  @proven_recoveries [:rolled_back, :aborted, :unchanged, :not_needed]

  @type outcome :: %{
          artifact_id: String.t(),
          module: module(),
          epoch: pos_integer(),
          nodes: [node()],
          state: Registry.Entry.state(),
          deployment: Coordinator.DeploymentReceipt.t()
        }

  @doc """
  Deploys `artifact`, which must introduce `module`, to `nodes`.

  Options are passed through to `Coordinator.deploy/3`, minus `:health_check`, which this
  module owns. `:registry` names the registry process, `:source_sha256` and
  `:test_report` are recorded as provenance, and `:promote?` (default `true`) can keep
  rollback material rather than promoting.
  """
  @spec deploy(Artifact.t(), module(), [node()], keyword()) ::
          {:ok, outcome()} | {:error, term()}
  def deploy(artifact, module, nodes, opts \\ [])

  def deploy(%Artifact{} = artifact, module, nodes, opts)
      when is_atom(module) and is_list(nodes) and is_list(opts) do
    registry = Keyword.get(opts, :registry, Registry)

    with :ok <- ensure_introduces(artifact, module),
         {:ok, _entry} <- checkpoint(artifact, module, nodes, opts, registry) do
      artifact
      |> Coordinator.deploy(nodes, deploy_options(module, opts))
      |> settle(artifact, module, nodes, opts, registry)
    end
  end

  def deploy(artifact, module, nodes, _opts),
    do: {:error, {:invalid_rollout_request, inspect({artifact, module, nodes})}}

  @doc "Returns the registry entries this rollout plane believes are live."
  @spec live(keyword()) :: [Registry.Entry.t()]
  def live(opts \\ []), do: Registry.live(Keyword.get(opts, :registry, Registry))

  @doc """
  Classifies a failed deployment as `:rolled_back` or `:quarantined`, with its evidence.

  This is public because the invariant it encodes is the one worth testing directly: a
  live cluster only produces an ambiguous receipt under fault injection, and the rule
  that ambiguity is never reported as a rollback must hold for receipts nobody can
  conveniently manufacture on a healthy cluster.
  """
  @spec settled_state(Coordinator.DeploymentReceipt.t()) :: {Registry.Entry.state(), map()}
  def settled_state(%Coordinator.DeploymentReceipt{} = deployment), do: failure_result(deployment)

  # The health check and the registry record are both about one module, so an artifact
  # that introduces something else would be gated on the wrong thing.
  defp ensure_introduces(artifact, module) do
    case Enum.find(artifact.modules, &(&1.module == module)) do
      %{disposition: :introduce} -> :ok
      %{disposition: other} -> {:error, {:not_an_introduction, module, other}}
      nil -> {:error, {:module_not_in_artifact, module}}
    end
  end

  # Checkpoint before effect: nothing below this line runs unless the intent is durable.
  defp checkpoint(artifact, module, nodes, opts, registry) do
    attrs = %{
      artifact_id: artifact.id,
      module: module,
      epoch: artifact.epoch,
      nodes: nodes,
      source_sha256: Keyword.get_lazy(opts, :source_sha256, fn -> forge_digest(artifact) end),
      test_report: Keyword.get_lazy(opts, :test_report, fn -> forge_tests(artifact) end)
    }

    case Registry.deploying(attrs, registry) do
      {:ok, entry} -> {:ok, entry}
      {:error, reason} -> {:error, {:rollout_not_recorded, reason}}
    end
  end

  defp deploy_options(module, opts) do
    opts
    |> Keyword.drop([:registry, :source_sha256, :test_report, :promote?, :health_check])
    |> Keyword.put(:health_check, {Probe, :ready?, [module]})
  end

  defp settle({:ok, deployment}, artifact, module, nodes, opts, registry) do
    {state, detail} = promotion_result(deployment, opts)
    record(state, detail, artifact, module, nodes, deployment, registry)
  end

  defp settle({:error, deployment}, artifact, module, nodes, _opts, registry) do
    {state, detail} = failure_result(deployment)
    record(state, detail, artifact, module, nodes, deployment, registry)
  end

  defp promotion_result(deployment, opts) do
    if Keyword.get(opts, :promote?, true) do
      case Coordinator.promote(deployment) do
        {:ok, promoted} ->
          {:live, %{outcome: promoted.outcome, recovery: promoted.recovery}}

        {:error, promoted} ->
          promotion_failure(promoted)
      end
    else
      {:live, %{outcome: deployment.outcome, recovery: deployment.recovery, promoted: false}}
    end
  end

  # A failed promotion does not un-commit anything: the code is live and healthy on every
  # node either way. What it can leave behind is a node nobody can describe, and that
  # outranks the fact that the deployment itself succeeded.
  defp promotion_failure(%{recovery: :quarantined} = promoted) do
    {:quarantined,
     %{stage: :promote, outcome: promoted.outcome, nodes: node_recoveries(promoted)}}
  end

  defp promotion_failure(promoted) do
    {:live, %{stage: :promote, outcome: promoted.outcome, recovery: promoted.recovery}}
  end

  # Only proof of compensation on every node earns `:rolled_back`.
  defp failure_result(deployment) do
    recoveries = node_recoveries(deployment)

    proven? =
      deployment.recovery == :complete and
        Enum.all?(recoveries, fn {_node, recovery} -> recovery in @proven_recoveries end)

    detail = %{outcome: deployment.outcome, recovery: deployment.recovery, nodes: recoveries}

    if proven?, do: {:rolled_back, detail}, else: {:quarantined, detail}
  end

  defp node_recoveries(deployment) do
    Map.new(deployment.node_receipts, fn {target, receipt} -> {target, receipt.recovery} end)
  end

  defp record(state, detail, artifact, module, nodes, deployment, registry) do
    outcome = %{
      artifact_id: artifact.id,
      module: module,
      epoch: artifact.epoch,
      nodes: nodes,
      state: state,
      deployment: deployment
    }

    case Registry.mark(artifact.id, state, [detail: detail], registry) do
      {:ok, _entry} -> reply(state, outcome)
      {:error, reason} -> {:error, {:rollout_record_failed, state, reason, deployment}}
    end
  end

  defp reply(:live, outcome), do: {:ok, outcome}
  defp reply(state, outcome), do: {:error, {state, outcome}}

  defp forge_digest(artifact) do
    get_in(artifact.metadata, [:forge, :source_sha256])
  end

  defp forge_tests(artifact) do
    get_in(artifact.metadata, [:forge, :test_report]) || %{}
  end
end
