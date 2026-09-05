defmodule Ouroboros.Orchestration.ForgeExecutor do
  @moduledoc """
  Executes `:forge` orchestration steps: one capability module, forged and deployed.

  The step says what to build. Trusted runtime configuration says everything
  else. From the step input come exactly two strings — a module inside the
  `Ouroboros.Capability.` namespace and a workspace-relative source path. From
  this executor's options come the workspace root, the target nodes, the signer
  identity, the epoch storage, and the rollout registry. Nothing a planner can
  write chooses where code is read from, where it is deployed, or who signs it.

  One step is one pass through the pipeline that already exists: read the source
  under a shared-read workspace lease, build `Ouroboros.Upgrade.Forge.Source`,
  `Forge.forge/2` (parse hygiene, isolated build peer, BEAM introduction check,
  epoch allocation, signature) and `Ouroboros.Upgrade.Rollout.deploy/4` (durable
  `:deploying` checkpoint, coordinated deploy behind a health probe, promotion).
  This module adds no new authority: a forge whose signer is `Signer.Deny`, or
  whose signature no target node trusts, fails here exactly as it would anywhere
  else.

  ## Idempotency, and its limits

  The scheduler may re-offer a step with the same execution token after an owner
  or scheduler crash. Forging is not naturally repeatable — a build burns time
  and an epoch, and a second deploy of the same module is not a no-op — so the
  anchor is the durable rollout registry rather than anything held in memory.
  Before building, this executor reads every registry entry for the module and
  decides:

    * `:deploying` — a rollout of this module was checkpointed and its outcome is
      unknown. This is ambiguity, not permission. The attempt fails with a
      retryable `{:forge_deploy_in_flight, module, artifact_id}` and deploys
      nothing. An operator (or the interrupted rollout itself) settles that entry
      first.
    * `:live` with the same source digest on the same target nodes — the work
      this step describes is already done. The step completes idempotently, with
      `reattached?: true`, without forging again.
    * `:live` with a different digest on any target node — the module is already
      running other code there. An introduction cannot succeed against a name
      that exists, so this fails immediately with
      `{:capability_live, ...}` rather than spending a build to be told so.
    * `:quarantined` on any target node — the cluster's state for this module is
      unknown by construction, and the registry has no automatic exit from that.
      Fails closed with `{:capability_quarantined, ...}`; clearing it is
      `NodeExecutor.reconcile_quarantine/1` and an operator's judgement.
    * anything else (no entry, `:rolled_back`, a live entry on unrelated nodes) —
      proceed.

  What this does not give you: atomicity. The read is not held across the build,
  so two schedulers, or a manual claim racing a dispatch, can both pass admission
  and both deploy. The defences that do not depend on this check are underneath
  it — epochs are monotonic per target node, and a node refuses to introduce a
  module it already has — so the loser of that race fails explicitly instead of
  quietly double-loading. A `:deploying` entry left by a crash blocks the module
  until it is settled; that is the intended cost of never guessing.

  A completed step's result is a compact, serializable summary — artifact id,
  epoch, registry state, digest, nodes — never a deployment receipt struct.
  """

  @behaviour Ouroboros.Orchestration.Executor

  alias Ouroboros.Orchestration.{Execution, Scheduler, Serializable, Step}
  alias Ouroboros.Upgrade.Beam
  alias Ouroboros.Upgrade.Forge
  alias Ouroboros.Upgrade.Forge.{Signer, Source}
  alias Ouroboros.Upgrade.Rollout
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Path, as: WorkspacePath

  @options [
    :workspace,
    :workspace_server,
    :nodes,
    :signer_id,
    :author,
    :build_timeout,
    :epoch_storage,
    :registry
  ]

  @impl true
  def start(%Execution{} = execution, scheduler, opts) do
    with :ok <- ensure_forge_step(execution),
         {:ok, config} <- config(opts),
         {:ok, request} <- forge_request(execution),
         {:ok, module} <- capability_module(request.module) do
      {:ok, spawn(fn -> run(execution, scheduler, config, request, module) end)}
    end
  end

  # The scheduler kills this step's owner on cancel (the process `start/3` spawned).
  # Returning `:ok` means the request was accepted — not that a deploy already past
  # the registry `:deploying` checkpoint has rolled back. That leftover is the same
  # ambiguity a crashed owner leaves, and `admit/3` refuses to forge over it.
  @impl true
  def cancel(%Execution{kind: :forge}, _reason, _opts), do: :ok
  def cancel(%Execution{kind: kind}, _reason, _opts), do: {:error, {:unsupported_step_kind, kind}}

  # An owner that dies is re-offered the same step, so an exception here would
  # become a dispatch loop rather than a failure anyone can read. Every outcome
  # is turned into a durable report instead.
  defp run(execution, scheduler, config, request, module) do
    outcome =
      try do
        forge_and_deploy(execution, config, request, module)
      rescue
        error -> {:error, {:forge_executor_exception, Exception.message(error)}}
      catch
        kind, reason -> {:error, {:forge_executor_failure, kind, Serializable.safe(reason)}}
      end

    report(execution, scheduler, outcome)
  end

  defp report(execution, scheduler, outcome) do
    case outcome do
      {:ok, result} ->
        Scheduler.complete(
          scheduler,
          execution.plan_id,
          execution.step_id,
          execution.token,
          result
        )

      {:error, reason} ->
        Scheduler.fail(scheduler, execution.plan_id, execution.step_id, execution.token, reason)
    end
  end

  defp forge_and_deploy(execution, config, request, module) do
    with {:ok, source_code} <- read_source(execution, config, request),
         sha256 = Beam.sha256(source_code),
         {:ok, disposition} <- admit(config, module, sha256) do
      case disposition do
        {:completed, entry} -> {:ok, reattached_result(request, entry, sha256)}
        :proceed -> forge(execution, config, request, module, source_code, sha256)
      end
    end
  end

  defp forge(execution, config, request, module, source_code, sha256) do
    with :ok <- ensure_signer_available(),
         {:ok, source} <- build_source(execution, config, module, source_code),
         {:ok, artifact} <- forge_artifact(source, config),
         {:ok, outcome} <- deploy(artifact, module, config) do
      {:ok, forged_result(request, outcome, sha256)}
    end
  end

  # The source is read inside the lease and nothing else happens there: a build
  # peer boot and a cluster deployment must not hold a workspace lease.
  defp read_source(execution, config, request) do
    case workspace_server(config) do
      nil ->
        read_file(config.workspace, request.source_path)

      server ->
        case acquire_lease(config.workspace, lease_id(execution), server) do
          {:ok, lease, capability} ->
            try do
              read_file(lease.root, request.source_path)
            after
              release_lease(lease, capability, server)
            end

          {:error, reason} ->
            {:error, {:workspace_admission_failed, Serializable.safe(reason)}}
        end
    end
  end

  defp acquire_lease(workspace, task_id, server) do
    Workspace.acquire(workspace, task_id, mode: :shared_read, server: server)
  catch
    :exit, reason -> {:error, {:workspace_manager_unavailable, Serializable.safe(reason)}}
  end

  defp release_lease(lease, capability, server) do
    Workspace.release(lease, server: server, capability: capability)
  catch
    :exit, _reason -> :ok
  end

  defp lease_id(execution), do: "orchestration-forge-" <> execution.token

  # The relative path has already been refused if it is absolute or contains a
  # traversal segment. This resolves the directory it names through symbolic
  # links anyway and re-checks containment, because a link inside the workspace
  # is a path the planner did not have to write.
  defp read_file(workspace, source_path) do
    with {:ok, root} <- canonical_root(workspace),
         candidate = Path.join(root, source_path),
         {:ok, directory} <- canonical_directory(Path.dirname(candidate)),
         :ok <- ensure_within(directory, root, source_path),
         file = Path.join(directory, Path.basename(candidate)),
         :ok <- ensure_regular_file(file, source_path) do
      case File.read(file) do
        {:ok, contents} -> ensure_nonempty(contents, source_path)
        {:error, reason} -> {:error, {:source_unreadable, source_path, reason}}
      end
    end
  end

  defp canonical_root(workspace) do
    case WorkspacePath.canonicalize(workspace) do
      {:ok, root} -> {:ok, root}
      {:error, reason} -> {:error, {:invalid_forge_workspace, Serializable.safe(reason)}}
    end
  end

  defp canonical_directory(directory) do
    case WorkspacePath.canonicalize(directory) do
      {:ok, canonical} -> {:ok, canonical}
      {:error, reason} -> {:error, {:source_unreadable, directory, Serializable.safe(reason)}}
    end
  end

  defp ensure_within(directory, root, source_path) do
    if WorkspacePath.within?(directory, root),
      do: :ok,
      else: {:error, {:source_outside_workspace, source_path}}
  end

  defp ensure_regular_file(file, source_path) do
    case File.lstat(file) do
      {:ok, %File.Stat{type: :regular}} -> :ok
      {:ok, %File.Stat{type: type}} -> {:error, {:invalid_source_file, source_path, type}}
      {:error, reason} -> {:error, {:source_unreadable, source_path, reason}}
    end
  end

  defp ensure_nonempty("", source_path), do: {:error, {:empty_source, source_path}}
  defp ensure_nonempty(contents, _source_path), do: {:ok, contents}

  defp admit(config, module, sha256) do
    case history(config, module) do
      {:ok, entries} ->
        classify(entries, config.nodes, sha256, module)

      {:error, reason} ->
        {:error, {:rollout_registry_unavailable, Serializable.safe(reason)}}
    end
  end

  defp classify(entries, nodes, sha256, module) do
    cond do
      entry = Enum.find(entries, &(&1.state == :deploying)) ->
        {:error, {:forge_deploy_in_flight, inspect(module), entry.artifact_id}}

      entry = Enum.find(entries, &deployed?(&1, nodes, sha256)) ->
        {:ok, {:completed, entry}}

      entry = Enum.find(entries, &conflicting?(&1, nodes, :quarantined)) ->
        {:error, {:capability_quarantined, inspect(module), entry.artifact_id}}

      entry = Enum.find(entries, &conflicting?(&1, nodes, :live)) ->
        {:error,
         {:capability_live, inspect(module),
          %{artifact_id: entry.artifact_id, source_sha256: entry.source_sha256}}}

      true ->
        {:ok, :proceed}
    end
  end

  defp deployed?(entry, nodes, sha256) do
    entry.state == :live and entry.source_sha256 == sha256 and
      Enum.sort(entry.nodes) == Enum.sort(nodes)
  end

  defp conflicting?(entry, nodes, state) do
    entry.state == state and Enum.any?(entry.nodes, &(&1 in nodes))
  end

  defp history(config, module) do
    {:ok, Registry.history(module, config.registry)}
  catch
    :exit, reason -> {:error, {:registry_unavailable, reason}}
  end

  # Signing is the last stage of a forge and the only one that cannot be retried
  # into success. Asking first turns "this cluster has no signer" into an
  # immediate, named refusal instead of a build peer's worth of wasted work.
  defp ensure_signer_available do
    case Signer.configured() do
      {Signer.Deny, _opts} -> {:error, {:forge_signing_unavailable, Signer.Deny}}
      {_module, _opts} -> :ok
    end
  end

  defp build_source(execution, config, module, source_code) do
    attrs = [
      module: module,
      source: source_code,
      author: config.author || default_author(execution)
    ]

    case Source.new(attrs) do
      {:ok, source} -> {:ok, source}
      {:error, reason} -> {:error, {:source_rejected, Serializable.safe(reason)}}
    end
  end

  defp default_author(execution) do
    "orchestration:" <> execution.plan_id <> ":" <> execution.step_id
  end

  defp forge_artifact(source, config) do
    opts =
      [nodes: config.nodes]
      |> put_option(:signer_id, config.signer_id)
      |> put_option(:timeout, config.build_timeout)
      |> put_option(:storage, config.epoch_storage)

    case Forge.forge(source, opts) do
      {:ok, artifact} -> {:ok, artifact}
      {:error, reason} -> {:error, {:forge_failed, Serializable.safe(reason)}}
    end
  end

  defp deploy(artifact, module, config) do
    case Rollout.deploy(artifact, module, config.nodes, registry: config.registry) do
      {:ok, outcome} ->
        {:ok, outcome}

      {:error, {state, outcome}} when state in [:rolled_back, :quarantined] ->
        {:error, {:rollout_failed, state, deployment_summary(outcome)}}

      {:error, reason} ->
        {:error, {:rollout_failed, Serializable.safe(reason)}}
    end
  end

  # Receipts carry node-level structs that have no business in a durable plan.
  # What a reader needs from a failed rollout is which artifact, which epoch, and
  # what each node was left in.
  defp deployment_summary(%{deployment: deployment} = outcome) do
    %{
      artifact_id: outcome.artifact_id,
      module: inspect(outcome.module),
      epoch: outcome.epoch,
      nodes: outcome.nodes,
      outcome: deployment.outcome,
      recovery: deployment.recovery,
      node_recovery:
        Map.new(deployment.node_receipts, fn {target, receipt} -> {target, receipt.recovery} end)
    }
  end

  defp deployment_summary(outcome), do: Serializable.safe(outcome)

  defp forged_result(request, outcome, sha256) do
    %{
      kind: :forge,
      module: request.module,
      source_path: request.source_path,
      source_sha256: sha256,
      artifact_id: outcome.artifact_id,
      epoch: outcome.epoch,
      nodes: outcome.nodes,
      registry_state: outcome.state,
      reattached?: false
    }
  end

  defp reattached_result(request, entry, sha256) do
    %{
      kind: :forge,
      module: request.module,
      source_path: request.source_path,
      source_sha256: sha256,
      artifact_id: entry.artifact_id,
      epoch: entry.epoch,
      nodes: entry.nodes,
      registry_state: entry.state,
      reattached?: true
    }
  end

  defp ensure_forge_step(%Execution{kind: :forge}), do: :ok
  defp ensure_forge_step(%Execution{kind: kind}), do: {:error, {:unsupported_step_kind, kind}}

  defp forge_request(execution) do
    case Step.forge_request(execution.input) do
      {:ok, request} -> {:ok, request}
      {:error, reason} -> {:error, {:invalid_forge_step, execution.step_id, reason}}
    end
  end

  # The name is created only after it has matched the capability namespace, and
  # only from its own segments, so nothing here can name a module outside it.
  defp capability_module(module) do
    {:ok, Module.concat(String.split(module, "."))}
  rescue
    error -> {:error, {:invalid_capability_module, module, Exception.message(error)}}
  end

  defp config(opts) do
    with :ok <- validate_options(opts),
         {:ok, workspace} <- workspace(opts),
         {:ok, nodes} <- nodes(opts),
         {:ok, signer_id} <- optional_binary(opts, :signer_id),
         {:ok, author} <- optional_binary(opts, :author),
         {:ok, build_timeout} <- optional_timeout(opts, :build_timeout) do
      {:ok,
       %{
         workspace: workspace,
         workspace_server: Keyword.get(opts, :workspace_server, Workspace.Manager),
         nodes: nodes,
         signer_id: signer_id,
         author: author,
         build_timeout: build_timeout,
         epoch_storage: Keyword.get(opts, :epoch_storage),
         registry: Keyword.get(opts, :registry, Registry)
       }}
    end
  end

  defp validate_options(opts) do
    cond do
      not is_list(opts) or not Keyword.keyword?(opts) ->
        {:error, :invalid_forge_executor_options}

      unknown = Enum.find(Keyword.keys(opts), &(&1 not in @options)) ->
        {:error, {:unknown_forge_executor_option, unknown}}

      true ->
        :ok
    end
  end

  # The workspace is never taken from a step. It comes from this executor's own
  # options, falling back to the coding plane's configured workspace so a
  # deployment that already declared one does not have to declare it twice.
  defp workspace(opts) do
    workspace =
      Keyword.get_lazy(opts, :workspace, fn ->
        :ouroboros
        |> Application.get_env(:orchestration_coding_options, [])
        |> configured_workspace()
      end)

    if is_binary(workspace) and String.trim(workspace) != "",
      do: {:ok, workspace},
      else: {:error, :forge_workspace_required}
  end

  defp configured_workspace(coding_options) when is_list(coding_options) do
    if Keyword.keyword?(coding_options), do: Keyword.get(coding_options, :workspace)
  end

  defp configured_workspace(_coding_options), do: nil

  defp nodes(opts) do
    case Keyword.get(opts, :nodes, [node()]) do
      [_ | _] = nodes ->
        if Enum.all?(nodes, &is_atom/1),
          do: {:ok, nodes},
          else: {:error, {:invalid_forge_nodes, nodes}}

      other ->
        {:error, {:invalid_forge_nodes, other}}
    end
  end

  defp optional_binary(opts, key) do
    case Keyword.get(opts, key) do
      nil -> {:ok, nil}
      value when is_binary(value) and value != "" -> {:ok, value}
      other -> {:error, {:invalid_forge_executor_option, key, other}}
    end
  end

  defp optional_timeout(opts, key) do
    case Keyword.get(opts, key) do
      nil -> {:ok, nil}
      value when is_integer(value) and value > 0 -> {:ok, value}
      other -> {:error, {:invalid_forge_executor_option, key, other}}
    end
  end

  defp workspace_server(%{workspace_server: nil}), do: nil

  defp workspace_server(%{workspace_server: server}) when is_pid(server) do
    if Process.alive?(server), do: server
  end

  defp workspace_server(%{workspace_server: name}) when is_atom(name) do
    if is_pid(Process.whereis(name)), do: name
  end

  defp workspace_server(_config), do: nil

  defp put_option(opts, _key, nil), do: opts
  defp put_option(opts, key, value), do: Keyword.put(opts, key, value)
end
