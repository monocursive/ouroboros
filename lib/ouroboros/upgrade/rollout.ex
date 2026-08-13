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

  ## The evaluation gate

  A health probe says the capability is alive. That is enough to *modify* a running
  system and not enough to *improve* one. When the artifact's signed metadata carries an
  `Ouroboros.Upgrade.Rollout.Evaluation` spec — or `:eval` supplies one — step 3 grows a
  stage between commit and promote:

      commit + health probe -> evaluate on every target -> promote | rollback | quarantine

  The code is committed and still rollback-able while evaluation runs, which is the
  whole point of doing it here rather than after promotion: the material needed to undo
  it has not been discarded yet. Then

    * every node satisfies its spec (and, under `compare: true`, does not regress
      against the version it replaces) -> `Coordinator.promote/2`, `:live`, and the
      report is recorded;
    * any node answers with a spec it did not satisfy -> `Coordinator.rollback/2`, and
      the same proof rule as any other failure decides `:rolled_back` or `:quarantined`;
    * any node's answer is *ambiguous* — a transport fault, a deadline, a shape this
      build does not recognize -> compensation is still attempted, and the record is
      `:quarantined` regardless of how cleanly it succeeded. An evaluation nobody
      received is not evidence of anything, and the same discipline that refuses to
      report an unknown node as rolled back refuses to report an unevaluated one as
      cleanly withdrawn.

  With no spec anywhere, none of this runs and the behaviour is exactly what it was.

  ## Champion and challenger

  `compare: true` deploys a capability *upgrade*: a `:replace` beam for a module that is
  already live. Before anything is committed the same spec is run against the current
  version on every target, and that baseline is what the challenger is held to — pass
  count no lower, total time within `:regression_budget` (default
  `config :ouroboros, :capability_eval_regression_budget`) of the champion's. A
  replacement is only accepted through this path, because promoting a new version of a
  live capability without comparing it to the one it displaces throws away the only
  baseline that will ever exist.

  Be clear about what that measures: the declared probe set, twice, on a shared VM. It
  is not production behaviour, not a cost model, and at these timescales `total_ms` is
  noisy enough that a tight regression budget will reject honest challengers.
  """

  alias Ouroboros.Upgrade.{Artifact, Coordinator}
  alias Ouroboros.Upgrade.Rollout.{Evaluation, Probe, Registry}

  @proven_recoveries [:rolled_back, :aborted, :unchanged, :not_needed]

  # Options this module owns. Everything else is the coordinator's.
  @rollout_options [
    :registry,
    :source_sha256,
    :test_report,
    :promote?,
    :health_check,
    :eval,
    :eval_nodes,
    :eval_timeout,
    :compare,
    :regression_budget
  ]

  @default_eval_timeout 30_000
  @default_regression_budget 1.2
  @max_eval_concurrency 8

  @type eval_report :: map()

  @type outcome :: %{
          artifact_id: String.t(),
          module: module(),
          epoch: pos_integer(),
          nodes: [node()],
          state: Registry.Entry.state(),
          eval_report: eval_report() | nil,
          deployment: Coordinator.DeploymentReceipt.t()
        }

  @doc """
  Deploys `artifact`, which must introduce `module`, to `nodes`.

  An artifact that *replaces* `module` is refused unless `compare: true`, which is the
  champion/challenger path described in the moduledoc.

  Options are passed through to `Coordinator.deploy/3`, minus `:health_check`, which this
  module owns. `:registry` names the registry process, `:source_sha256` and
  `:test_report` are recorded as provenance, and `:promote?` (default `true`) can keep
  rollback material rather than promoting.

  Evaluation options:

    * `:eval` - an evaluation spec overriding whatever the artifact's signed metadata
      carries. An override is convenient and is *not* tamper-evident: it is the
      caller's word, not the signer's.
    * `:eval_nodes` - the nodes evaluation runs on, defaulting to the deployment
      targets. Naming anything else narrows the gate and exists for fault injection.
    * `:eval_timeout` - per-node deadline for one evaluation, defaulting to
      `config :ouroboros, :capability_eval_timeout`.
    * `:compare` - run the spec against the live version first and hold the new one to
      that baseline. Requires a spec, and is the only way a `:replace` artifact is
      accepted.
    * `:regression_budget` - multiple of the champion's total time the challenger may
      take, defaulting to `config :ouroboros, :capability_eval_regression_budget`.
  """
  @spec deploy(Artifact.t(), module(), [node()], keyword()) ::
          {:ok, outcome()} | {:error, term()}
  def deploy(artifact, module, nodes, opts \\ [])

  def deploy(%Artifact{} = artifact, module, nodes, opts)
      when is_atom(module) and is_list(nodes) and is_list(opts) do
    registry = Keyword.get(opts, :registry, Registry)

    with :ok <- ensure_deployable(artifact, module, opts),
         {:ok, plan} <- evaluation_plan(artifact, module, nodes, opts),
         {:ok, _entry} <- checkpoint(artifact, module, nodes, opts, registry) do
      artifact
      |> Coordinator.deploy(nodes, deploy_options(module, opts))
      |> settle(artifact, module, nodes, opts, registry, plan)
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
  # that introduces something else would be gated on the wrong thing. A `:replace` is a
  # different animal: it displaces something already running, and the only honest way to
  # accept one is against a measured baseline, so it is admitted through `compare: true`
  # and nowhere else.
  defp ensure_deployable(artifact, module, opts) do
    case Enum.find(artifact.modules, &(&1.module == module)) do
      %{disposition: :introduce} -> :ok
      %{disposition: :replace} -> ensure_comparison(module, opts)
      %{disposition: other} -> {:error, {:not_an_introduction, module, other}}
      nil -> {:error, {:module_not_in_artifact, module}}
    end
  end

  defp ensure_comparison(module, opts) do
    if compare?(opts), do: :ok, else: {:error, {:not_an_introduction, module, :replace}}
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

  defp coordinator_options(opts), do: Keyword.drop(opts, @rollout_options)

  defp deploy_options(module, opts) do
    opts
    |> coordinator_options()
    |> Keyword.put(:health_check, {Probe, :ready?, [module]})
  end

  ## Evaluation planning

  # The champion baseline runs *before* the `:deploying` checkpoint on purpose. It
  # mutates nothing durable — it starts and stops a throwaway agent, exactly as the
  # health probe does — and a baseline that cannot be taken means no rollout was
  # attempted at all. Checkpointing first would leave a `:deploying` entry describing a
  # deployment that never happened, and the transition table has no honest exit for one.
  defp evaluation_plan(artifact, module, nodes, opts) do
    with {:ok, spec} <- eval_spec(artifact, opts) do
      cond do
        is_nil(spec) and compare?(opts) -> {:error, :comparison_requires_eval_spec}
        is_nil(spec) -> {:ok, nil}
        true -> build_plan(spec, module, nodes, opts)
      end
    end
  end

  defp build_plan(spec, module, nodes, opts) do
    with {:ok, targets} <- eval_nodes(nodes, opts) do
      plan = %{
        spec: spec,
        nodes: targets,
        timeout: eval_timeout(opts),
        regression_budget: regression_budget(opts),
        compare?: compare?(opts),
        champion: nil
      }

      if plan.compare?, do: with_champion(plan, module), else: {:ok, plan}
    end
  end

  defp with_champion(plan, module) do
    results = evaluate(module, plan)

    if Enum.all?(results, fn {_target, result} -> match?({:ok, _report}, result) end) do
      {:ok, %{plan | champion: Map.new(results, fn {target, {:ok, r}} -> {target, r} end)}}
    else
      {:error, {:champion_baseline_failed, Map.new(results, &{elem(&1, 0), summary(&1)})}}
    end
  end

  defp summary({_target, {:ok, report}}), do: Evaluation.summarize(report)
  defp summary({_target, {:error, reason}}), do: %{outcome: :failed, reason: bound(reason)}
  defp summary({_target, {:ambiguous, reason}}), do: %{outcome: :ambiguous, reason: bound(reason)}

  # An override is the caller's word; metadata is the signer's. Both are validated, so a
  # spec that reaches a node is one this build could have run.
  defp eval_spec(artifact, opts) do
    case Keyword.fetch(opts, :eval) do
      {:ok, nil} -> {:ok, nil}
      {:ok, spec} -> Evaluation.validate(spec)
      :error -> metadata_spec(artifact)
    end
  end

  defp metadata_spec(%Artifact{metadata: %{forge: %{eval: spec}}}) when not is_nil(spec),
    do: Evaluation.validate(spec)

  defp metadata_spec(_artifact), do: {:ok, nil}

  defp eval_nodes(nodes, opts) do
    case Keyword.get(opts, :eval_nodes, nodes) do
      [_ | _] = targets ->
        if Enum.all?(targets, &is_atom/1),
          do: {:ok, Enum.uniq(targets)},
          else: {:error, {:invalid_eval_nodes, inspect(targets)}}

      other ->
        {:error, {:invalid_eval_nodes, inspect(other)}}
    end
  end

  defp compare?(opts), do: Keyword.get(opts, :compare, false) == true

  defp eval_timeout(opts) do
    opts
    |> Keyword.get_lazy(:eval_timeout, fn ->
      Application.get_env(:ouroboros, :capability_eval_timeout, @default_eval_timeout)
    end)
    |> case do
      value when is_integer(value) and value > 0 -> value
      _invalid -> @default_eval_timeout
    end
  end

  defp regression_budget(opts) do
    opts
    |> Keyword.get_lazy(:regression_budget, fn ->
      Application.get_env(
        :ouroboros,
        :capability_eval_regression_budget,
        @default_regression_budget
      )
    end)
    |> case do
      value when is_number(value) and value >= 1 -> value
      _invalid -> @default_regression_budget
    end
  end

  ## Settlement

  defp settle({:ok, deployment}, artifact, module, nodes, opts, registry, nil) do
    {state, detail} = promotion_result(deployment, opts)
    record(state, detail, artifact, module, nodes, deployment, registry, nil)
  end

  defp settle({:ok, deployment}, artifact, module, nodes, opts, registry, plan) do
    results = evaluate(module, plan)
    report = eval_report(results, plan)

    case verdict(results, plan) do
      :pass ->
        {state, detail} = promotion_result(deployment, opts)

        record(
          state,
          Map.put(detail, :eval, report),
          artifact,
          module,
          nodes,
          deployment,
          registry,
          report
        )

      verdict ->
        compensated = compensate(deployment, opts)
        {proven, detail} = failure_result(compensated)
        state = if verdict == :ambiguous, do: :quarantined, else: proven

        record(
          state,
          Map.merge(detail, %{stage: :evaluate, eval: report}),
          artifact,
          module,
          nodes,
          compensated,
          registry,
          report
        )
    end
  end

  defp settle({:error, deployment}, artifact, module, nodes, _opts, registry, _plan) do
    {state, detail} = failure_result(deployment)
    record(state, detail, artifact, module, nodes, deployment, registry, nil)
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

  # An unpromoted deployment still holds every node's rollback material, so a capability
  # that failed evaluation can actually be withdrawn rather than merely disapproved of.
  defp compensate(deployment, opts) do
    case Coordinator.rollback(deployment, coordinator_options(opts)) do
      {:ok, rolled_back} -> rolled_back
      {:error, rolled_back} -> rolled_back
    end
  end

  ## Running the gate

  defp evaluate(module, plan) do
    targets = plan.nodes

    stream =
      Task.async_stream(targets, fn target -> evaluate_node(target, module, plan) end,
        ordered: true,
        max_concurrency: max(1, min(length(targets), @max_eval_concurrency)),
        timeout: plan.timeout + 1_000,
        on_timeout: :kill_task
      )

    targets
    |> Enum.zip(Enum.to_list(stream))
    |> Map.new(fn
      {target, {:ok, result}} ->
        {target, result}

      {target, {:exit, reason}} ->
        {target, {:ambiguous, {:task_exit, inspect(reason, limit: 10)}}}
    end)
  end

  # `Evaluation.run/3` ships with the application, so every target already has it and
  # nothing needs to be sent but a spec. A reply this build cannot read is treated the
  # way the coordinator treats an unreadable receipt: as ambiguity, not as a failure.
  defp evaluate_node(target, module, plan) do
    result =
      if target == node() do
        Evaluation.run(module, plan.spec, [])
      else
        :erpc.call(target, Evaluation, :run, [module, plan.spec, []], plan.timeout)
      end

    case result do
      {:ok, report} when is_map(report) -> {:ok, report}
      {:error, reason} -> {:error, reason}
      other -> {:ambiguous, {:unexpected_result, inspect(other, limit: 10)}}
    end
  rescue
    error -> {:ambiguous, {:exception, error.__struct__, Exception.message(error)}}
  catch
    kind, reason -> {:ambiguous, {kind, inspect(reason, limit: 10)}}
  end

  defp verdict(results, plan) do
    cond do
      Enum.any?(results, fn {_target, r} -> match?({:ambiguous, _reason}, r) end) -> :ambiguous
      Enum.all?(results, fn {target, r} -> node_passed?(target, r, plan) end) -> :pass
      true -> :fail
    end
  end

  defp node_passed?(target, {:ok, report}, plan) do
    Evaluation.passed?(report) and not regressed?(target, report, plan)
  end

  defp node_passed?(_target, _result, _plan), do: false

  defp regressed?(_target, _report, %{compare?: false}), do: false

  defp regressed?(target, report, plan) do
    case Map.get(plan.champion || %{}, target) do
      champion when is_map(champion) ->
        Map.get(report, :passed, 0) < Map.get(champion, :passed, 0) or
          Map.get(report, :total_ms, 0) > latency_ceiling(champion, plan)

      _absent ->
        true
    end
  end

  # A champion that finished in under a millisecond would otherwise set a ceiling no
  # challenger can meet. This is a floor on the arithmetic, not a claim about precision:
  # see the moduledoc on what timing this small is worth.
  defp latency_ceiling(champion, plan) do
    max(Map.get(champion, :total_ms, 0), 1) * plan.regression_budget
  end

  defp eval_report(results, plan) do
    %{
      spec: %{
        probes: length(plan.spec.probes),
        required: plan.spec.required,
        budget_ms: plan.spec.budget_ms,
        max_latency_ms: plan.spec.max_latency_ms
      },
      compare: plan.compare?,
      regression_budget: if(plan.compare?, do: plan.regression_budget),
      nodes:
        Map.new(results, fn {target, result} -> {target, node_report(target, result, plan)} end),
      champion: champion_report(plan)
    }
  end

  defp node_report(target, {:ok, report} = result, plan) do
    report
    |> Evaluation.summarize()
    |> Map.put(:outcome, if(node_passed?(target, result, plan), do: :passed, else: :failed))
    |> Map.put(:regressed, plan.compare? and regressed?(target, report, plan))
  end

  defp node_report(target, result, _plan), do: summary({target, result})

  defp champion_report(%{compare?: false}), do: nil

  defp champion_report(plan) do
    Map.new(plan.champion || %{}, fn {target, report} ->
      {target, Evaluation.summarize(report)}
    end)
  end

  defp bound(reason), do: inspect(reason, limit: 10, printable_limit: 200)

  ## Recording

  defp record(state, detail, artifact, module, nodes, deployment, registry, report) do
    outcome = %{
      artifact_id: artifact.id,
      module: module,
      epoch: artifact.epoch,
      nodes: nodes,
      state: state,
      eval_report: report,
      deployment: deployment
    }

    case Registry.mark(artifact.id, state, [detail: detail, eval_report: report], registry) do
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
