defmodule Ouroboros.Wasm.Rollout do
  @moduledoc """
  Deploys one signed component to explicit nodes behind the same gates lane B uses, with
  the code-loading half deleted.

  `Ouroboros.Upgrade.Rollout` is the sentence this module is a variation on, and every
  discipline in it survives verbatim (docs/WASM.md §7.6, D7):

  1. validate the targets and verify the signature and the digest against the bytes in
     hand — all of it before anything is written;
  2. **checkpoint `:deploying` in `Ouroboros.Upgrade.Rollout.Registry` before any effect**,
     carrying the component sha. The register refuses a stale epoch in the same serialized
     call that writes the entry, so the epoch gate and the record are one decision. If that
     write is refused for any reason, the rollout does not start;
  3. stage on every node: publish the bytes and the manifest into that node's
     `Ouroboros.Wasm.Store`, `load` the component into that node's helper, and cross-check
     the helper's own reading against the signed manifest;
  4. probe every node with `Ouroboros.Upgrade.Rollout.Probe`, unchanged;
  5. evaluate every node with `Ouroboros.Upgrade.Rollout.Evaluation` against the **signed**
     spec, unchanged;
  6. settle: `:live`, `:rolled_back`, or `:quarantined`, by the same rules.

  What is gone is `Coordinator` and `NodeExecutor` — the prepare/commit/promote machinery
  that exists because loading BEAM code is a mutation with a pre-image. Nothing here loads
  code, so there is no pre-image, nothing to purge, and no `{:introduced_code_in_use, _}`
  to answer. "Rollback to absence" is literally that: stop the wrapper agent if one is
  running, and mark the entry.

  ## The settle table

  Every node contributes three outcomes — stage, probe, eval — and the worst one wins, in
  the order `Ouroboros.Upgrade.Rollout` uses:

  | any node's outcome            | rollout state                                |
  |-------------------------------|----------------------------------------------|
  | ambiguous anywhere            | `:quarantined`, however cleanly it compensated |
  | otherwise, any clean failure  | `:rolled_back` if every node proved it, else `:quarantined` |
  | every node passes             | `:live`                                      |

  Ambiguity is anything nobody answered for: an `:erpc` transport fault, a deadline, a
  reply this build cannot read — and one more that is specific to this lane, a
  **cross-check mismatch**. A node whose helper reads a different sha, world, size, or
  import set than the manifest claims is a node holding something nobody described. It
  never "just links less": that is `Ouroboros.Wasm.Verifier`'s sentence, and here it is
  quarantine.

  A deadline is ambiguity in the strong sense on a peer: `:erpc.call/5` stops waiting, it
  does not stop the peer, so a stage or an evaluation that missed its deadline may still be
  running there and may finish after this module has already settled the rollout. That is
  the honest reading of `:quarantined` — "somebody may be running this and nobody said so".

  ## The epoch, where it is minted, and what a retry means

  An epoch is inside the signed manifest, so this module cannot mint one — allocating a
  number here would invalidate the signature it was allocated for. Whoever builds a
  manifest allocates it first with `Ouroboros.Upgrade.Epoch.next/2`, exactly as
  `Ouroboros.Upgrade.Forge` does before `Artifact.build/2`. `Ouroboros.Wasm.Artifact.build/2`
  has no default for it, deliberately: a VM-local counter would eventually mint a number
  far above anything `Epoch.next/2` allocates, and one such entry in the register would
  refuse every properly minted epoch after it, forever.

  The other half is enforced by `Ouroboros.Upgrade.Rollout.Registry` itself, atomically,
  inside the same call that writes the `:deploying` entry — see its moduledoc. Lane B's
  monotonicity is enforced per node by `Ouroboros.Upgrade.NodeExecutor.prepare/2`; lane W
  has no node executor, so this register is the only durable record of what this plane has
  already deployed.

  **A retry is always a new manifest.** The register refuses a duplicate artifact id
  (`{:already_recorded, _}`) and refuses an epoch it has already seen in any state
  (`{:stale_epoch, n, n}`), so re-presenting a manifest that reached `:rolled_back` — or
  one still stuck at `:deploying` — is refused twice over. Retrying means minting a higher
  epoch, building a new manifest with a new id, and signing it again. That is parity with
  lane B, whose register refuses `{:already_recorded, _}` for the same reason and whose
  retry is likewise a re-forge, and it is what keeps "this exact artifact was deployed
  once" a fact rather than a hope.

  ## Starting, and reboot survival

  A rollout that reaches `:live` and whose manifest carries a `start` block starts the
  durable wrapper agent, which is the `Ouroboros.Runtime.Capabilities.maybe_start/2` rule
  applied to a lane that can honour it across reboots. Two facts shape how:

    * a mesh id is unique across the cluster (`Ouroboros.Mesh.start_agent/2` refuses an id
      already claimed anywhere), so `start.id` names **one** process, not one per node.
      Every target holds the bytes and could host it; this places it on the first target
      that accepts. `{:already_started, _}` counts as accepted **only** when the process
      holding the id is running this artifact's component — the same ownership question
      `withdraw/2` asks before it stops anything. A wrapper holding the id for some other
      component is a claim on the name, not a start of this capability.
    * the start is attempted only after the entry is `:live`, and a start that fails does
      not un-live it. The component is admitted on every node either way; what failed is
      one process, which an operator can start again. The report says which.

  `Ouroboros.Wasm.Boot` restarts those wrappers at boot from a node's **own** registry and
  a node's **own** store — both node-local durable state, which is the only kind a boot
  can rely on. **Boot restart therefore requires the driver to be one of the targets.** A
  driver that left itself out holds the record of a deployment whose bytes and manifest it
  does not have, and no node in the cluster holds both halves: the targets have the store
  and no entry, the driver has the entry and no store. Such a deployment runs until
  something restarts it and then stops existing. That is a durability limit, not an
  invalid topology — deploying to nodes you do not drive from is a legitimate thing to
  want — so it is reported rather than refused: the outcome carries
  `warnings: [{:driver_not_a_target, node()}]` and one `Logger.warning` says the same.

  A start id is claimed once cluster-wide, so a rollout can find its `start.id` already
  held by a wrapper running a **different** component. That is not a start, and reporting
  it as one would put a component nobody described behind an id somebody trusts, so it is
  `{:start_id_claimed_by, other_sha}` and the entry is marked `:quarantined`.

  ## Not here

  `compare:` — champion/challenger — is deferred. `Ouroboros.Upgrade.Rollout` accepts a
  `:replace` artifact only against a measured baseline, and the same argument applies to
  replacing a live component. It needs a rule for what "the version this displaces" means
  when identity is a digest rather than a module name, and inventing half of one here
  would be worse than not having it. Until then a new component is a new rollout, and the
  register's own supersede rule retires the entry it displaces.
  """

  require Logger

  alias Ouroboros.Cluster
  alias Ouroboros.Mesh
  alias Ouroboros.Upgrade.Beam
  alias Ouroboros.Upgrade.Rollout.{Evaluation, Probe, Registry}
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.{Artifact, Capability, Pool, Store, Verifier}

  @module_prefix "wasm/"
  @proven_recoveries [:rolled_back, :not_needed, :unchanged]

  # Staging publishes bytes and compiles a component. The helper's own `load` bound is
  # `Ouroboros.Wasm.config(:request_timeout_ms)`; this is the transport around it, plus
  # room for the file write.
  @default_stage_timeout_ms 60_000
  @default_eval_timeout_ms 30_000
  @default_start_timeout_ms 15_000

  @type node_evidence :: %{
          stage: :ok | {:mismatch, term()} | {:error, term()} | {:ambiguous, term()},
          probe: :ok | :skipped | {:error, term()} | {:ambiguous, term()},
          eval: map() | :absent | :skipped | {:error, term()} | {:ambiguous, term()},
          recovery: :not_needed | :rolled_back | :unchanged | :quarantined | nil
        }

  @type warning :: {:driver_not_a_target, node()}

  @type outcome :: %{
          artifact_id: String.t(),
          module: String.t(),
          component_sha256: String.t(),
          epoch: pos_integer(),
          name: String.t(),
          nodes: [node()],
          state: Registry.Entry.state(),
          stage: :stage | :probe | :evaluate | :settle | :start,
          eval_report: map() | nil,
          started: map() | nil,
          warnings: [warning()],
          deployment: %{optional(node()) => node_evidence()}
        }

  @doc """
  Deploys `artifact` — whose bytes are `bytes` — to `nodes`.

  Options:

    * `:registry` — the registry process holding the checkpoint. Defaults to
      `Ouroboros.Upgrade.Rollout.Registry`.
    * `:trust_policy` — this node's trust policy for the pre-flight verification,
      defaulting to `config :ouroboros, :upgrade_trust_policy`. Each **target** reads its
      own rather than being told one; a loading node that took the caller's word for which
      signers it trusts would not be verifying anything.
    * `:pool` — the helper pool name on every target. Defaults to `Ouroboros.Wasm.Pool`.
    * `:store_root` — an explicit component-store directory on every target, for tests
      that must not touch a real data directory. Defaults to `nil`, which means each
      node's own `:data_dir`.
    * `:limits` — the instance bounds the capability is probed, evaluated, and started
      under. Defaults to `Ouroboros.Wasm.capability_limits/0` **read here**, so one
      deployment means one set of bounds everywhere rather than whatever each node happens
      to be configured with.
    * `:start?` — whether a `:live` rollout starts the durable wrapper its manifest
      declares. Defaults to `true`.
    * `:stage_timeout`, `:probe_timeout`, `:eval_timeout`, `:start_timeout` — per-node
      transport deadlines. Every one of them is bounded; a deadline that fires is
      ambiguity, not failure.
  """
  @spec deploy(Artifact.t(), binary(), [node()], keyword()) ::
          {:ok, outcome()} | {:error, term()}
  def deploy(artifact, bytes, nodes, opts \\ [])

  def deploy(%Artifact{} = artifact, bytes, nodes, opts)
      when is_binary(bytes) and is_list(nodes) and is_list(opts) do
    registry = Keyword.get(opts, :registry, Registry)

    with {:ok, nodes} <- validate_nodes(nodes),
         :ok <- Verifier.verify(artifact, bytes, trust_policy(opts)),
         {:ok, spec} <- eval_spec(artifact),
         {:ok, _entry} <- checkpoint(artifact, nodes, registry) do
      run(artifact, bytes, nodes, opts, registry, spec, warnings(artifact, nodes))
    end
  end

  def deploy(artifact, bytes, nodes, _opts),
    do: {:error, {:invalid_rollout_request, inspect({artifact, byte_size_of(bytes), nodes})}}

  @doc "The registry entries this plane believes are live lane-W rollouts."
  @spec live(keyword()) :: [Registry.Entry.t()]
  def live(opts \\ []) do
    opts
    |> Keyword.get(:registry, Registry)
    |> Registry.live()
    |> Enum.filter(&lane_w?/1)
  end

  @doc """
  The `initial_state` a lane-W capability is stood up with, naming all six deciding keys.

  `Ouroboros.Upgrade.Rollout.Evaluation` merges a signed spec's `initial_state` *under*
  the start spec's, so a key the start spec omits is a key the signed spec may choose.
  For `Ouroboros.Wasm.Capability` the six that decide what is being evaluated are
  `:component`, `:config`, `:name`, `:limits`, `:pool` and `:store_root` — leaving
  `:limits` out lets a spec pick the bounds it is judged under, and leaving `:pool` or
  `:store_root` out lets it pick which helper and which bytes. This is the one place that
  list is built, so probe, evaluation, deploy-time start and boot-time restart cannot
  drift apart.
  """
  @spec start_state(Artifact.t(), keyword()) :: map()
  def start_state(%Artifact{} = artifact, opts \\ []) do
    %{
      component: artifact.component_sha256,
      config: start_config(artifact),
      name: artifact.name,
      limits: Keyword.get_lazy(opts, :limits, &Wasm.capability_limits/0),
      pool: Keyword.get(opts, :pool, Pool),
      store_root: Keyword.get(opts, :store_root)
    }
  end

  @doc """
  The `start` block a manifest declares, or `nil`.

  Read through a validator rather than by pattern match, because it arrives from a
  manifest: an id that is not a binary under the lane's prefix, or a config that is not a
  binary, is `nil` here — the signer refuses both, and a reader that would rather trust
  the signer than check is a reader one bad manifest away from `Mesh.start_agent/2` with
  whatever the manifest said.

  The id is **derived, not read**: it is `"wasm/" <> artifact.name` or it is nothing. A
  manifest naming any other id is a manifest claiming a durable id for a component it does
  not describe, which is what a signature must not be able to authorize (docs/WASM.md
  §7.5). `Ouroboros.Wasm.Boot` reaches the same rule through this function, so the deploy
  path and the reboot path cannot disagree about which process a component owns.
  """
  @spec start_block(Artifact.t()) :: %{id: String.t(), config: String.t()} | nil
  def start_block(%Artifact{metadata: metadata, name: name}) when is_map(metadata) do
    if Artifact.name?(name) do
      expected = @module_prefix <> name

      case Map.get(metadata, :start) do
        %{id: ^expected, config: config} when is_binary(config) -> %{id: expected, config: config}
        _absent_or_invalid -> nil
      end
    end
  end

  def start_block(_artifact), do: nil

  @doc false
  @spec stage(Artifact.t(), binary(), keyword()) ::
          {:ok, map()} | {:mismatch, term()} | {:error, term()}
  def stage(%Artifact{} = artifact, bytes, opts) when is_binary(bytes) and is_list(opts) do
    store_opts = store_opts(opts)
    pool = Keyword.get(opts, :pool, Pool)

    # This node's own trust policy, never the caller's. A loading node that was told which
    # signers to trust would be verifying the sender rather than the artifact.
    with :ok <- verified(artifact, bytes),
         {:ok, put} <- published(artifact, bytes, store_opts),
         {:ok, manifest} <- published_manifest(artifact, store_opts),
         {:ok, report} <- loaded(artifact, put.path, pool),
         :ok <- cross_checked(artifact, report) do
      {:ok,
       %{
         published: put.published,
         manifest_published: manifest.published,
         cached: Map.get(report, "cached", false),
         size: put.size
       }}
    end
  rescue
    error -> {:error, {:stage_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:stage_failure, kind, inspect(reason, limit: 10)}}
  end

  def stage(artifact, _bytes, _opts), do: {:error, {:invalid_artifact, inspect(artifact)}}

  @doc false
  @spec withdraw(String.t(), String.t()) :: :not_needed | :rolled_back | :unchanged | :quarantined
  def withdraw(id, component_sha256) when is_binary(id) and is_binary(component_sha256) do
    case Mesh.whereis(id) do
      nil ->
        :not_needed

      _pid ->
        if holder_component(id) == component_sha256, do: stop(id), else: :unchanged
    end
  rescue
    _error -> :quarantined
  catch
    _kind, _reason -> :quarantined
  end

  @doc false
  @spec claim(String.t(), keyword(), String.t()) ::
          {:ok, node()}
          | {:already_started, node()}
          | {:claimed, String.t() | :unknown}
          | {:error, term()}
  def claim(id, opts, component_sha256)
      when is_binary(id) and is_list(opts) and is_binary(component_sha256) do
    case Mesh.start_agent(id, opts) do
      {:ok, pid} ->
        {:ok, node(pid)}

      # The id is taken. Whether that is *this* capability already running — the idempotent
      # case a boot restart and a redeploy both rely on — or somebody else holding the name
      # is the same question `withdraw/2` asks before it stops anything, so it is asked the
      # same way.
      {:error, {:already_started, pid}} ->
        case holder_component(id) do
          ^component_sha256 -> {:already_started, node(pid)}
          other -> {:claimed, other}
        end

      {:error, reason} ->
        {:error, reason}

      other ->
        {:error, {:unexpected_result, inspect(other, limit: 10)}}
    end
  rescue
    error -> {:error, {:start_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:start_failure, kind, inspect(reason, limit: 10)}}
  end

  @doc """
  The component sha the wrapper holding `id` is running, or `:unknown`.

  The one question that distinguishes "this capability is already running" from "something
  else has taken this name". `Ouroboros.Wasm.Boot` asks it for the same reason a deploy
  does: an id is a claim, and a claim is not evidence of what is behind it.
  """
  @spec holder_component(String.t()) :: String.t() | :unknown
  def holder_component(id) when is_binary(id) do
    case Mesh.state(id) do
      {:ok, %{agent: %{state: %{component: sha}}}} when is_binary(sha) and sha != "" -> sha
      _other -> :unknown
    end
  rescue
    _error -> :unknown
  catch
    _kind, _reason -> :unknown
  end

  ## Pre-flight

  defp validate_nodes(nodes) do
    cond do
      nodes == [] ->
        {:error, :empty_node_list}

      not Enum.all?(nodes, &is_atom/1) ->
        {:error, {:invalid_nodes, nodes}}

      Enum.uniq(nodes) != nodes ->
        {:error, {:duplicate_nodes, nodes}}

      true ->
        ensure_placeable(nodes)
    end
  end

  # Connectivity first, so a node that is simply not there is named that way rather than
  # as a probe failure; then the `:core` role, through the same gate that admits any other
  # placement onto a node.
  defp ensure_placeable(nodes) do
    case Enum.reject(nodes, &connected?/1) do
      [] -> check_roles(nodes)
      disconnected -> {:error, {:disconnected_nodes, disconnected}}
    end
  end

  defp check_roles(nodes) do
    Enum.reduce_while(nodes, {:ok, nodes}, fn target, acc ->
      case Cluster.ensure_placeable(target) do
        :ok -> {:cont, acc}
        {:error, reason} -> {:halt, {:error, {:node_not_deployable, target, reason}}}
      end
    end)
  end

  defp connected?(target), do: target == node() or target in Node.list(:connected)

  # The signed spec, validated here so a manifest carrying one this build cannot run is
  # refused before a checkpoint exists rather than after every node has staged it.
  defp eval_spec(%Artifact{metadata: metadata}) when is_map(metadata) do
    case Map.get(metadata, :eval) do
      nil -> {:ok, nil}
      spec -> Evaluation.validate(spec)
    end
  end

  defp eval_spec(_artifact), do: {:ok, nil}

  # Checkpoint before effect: nothing below this line runs unless the intent is durable.
  #
  # The epoch gate is inside this call rather than in front of it. Reading the register's
  # watermark here and checkpointing after would be a read-then-write across two messages,
  # and two concurrent deploys at epochs 70 and 60 would both pass their reads and both
  # record. `Ouroboros.Upgrade.Rollout.Registry` decides it in the same serialized message
  # that writes the entry, the way `NodeExecutor.prepare/2` does for lane B; the refusal is
  # lifted out of the recording error here so callers see the reason and not the wrapper.
  defp checkpoint(artifact, nodes, registry) do
    attrs = %{
      artifact_id: artifact.id,
      module: @module_prefix <> artifact.name,
      epoch: artifact.epoch,
      nodes: nodes,
      component_sha256: artifact.component_sha256,
      source_sha256: Map.get(artifact.metadata, :source_sha256),
      test_report: Map.get(artifact.metadata, :test_report) || %{}
    }

    case Registry.deploying(attrs, registry) do
      {:ok, entry} -> {:ok, entry}
      {:error, {:stale_epoch, _epoch, _highest} = reason} -> {:error, reason}
      {:error, reason} -> {:error, {:rollout_not_recorded, reason}}
    end
  end

  ## The three gates

  defp run(artifact, bytes, nodes, opts, registry, spec, warnings) do
    evidence =
      Map.new(nodes, &{&1, %{stage: nil, probe: :skipped, eval: :skipped, recovery: nil}})

    evidence = gate(evidence, nodes, :stage, &stage_node(&1, artifact, bytes, opts))

    evidence =
      if all_passed?(evidence, :stage),
        do: gate(evidence, nodes, :probe, &probe_node(&1, artifact, opts)),
        else: evidence

    evidence =
      if all_passed?(evidence, :probe) and not is_nil(spec),
        do: gate(evidence, nodes, :eval, &eval_node(&1, artifact, spec, opts)),
        else: eval_absent(evidence, spec)

    settle(evidence, artifact, nodes, opts, registry, spec, warnings)
  end

  # Reported, not refused. Deploying to nodes you do not drive from is a legitimate thing
  # to want; what it costs is reboot survival, because no node then holds both halves of
  # what a restart reads. See the moduledoc.
  defp warnings(artifact, nodes) do
    if not is_nil(start_block(artifact)) and node() not in nodes do
      Logger.warning(
        "wasm rollout #{artifact.id} starts #{inspect(start_block(artifact).id)} but " <>
          "#{inspect(node())} is not one of #{inspect(nodes)}: this node holds the registry " <>
          "entry and none of the targets does, so no node can restart the wrapper at boot"
      )

      [{:driver_not_a_target, node()}]
    else
      []
    end
  end

  defp gate(evidence, nodes, key, fun) do
    nodes
    |> Task.async_stream(fn target -> {target, fun.(target)} end,
      ordered: true,
      max_concurrency: max(1, length(nodes)),
      timeout: :infinity
    )
    |> Enum.reduce(evidence, fn
      {:ok, {target, result}}, acc -> put_in(acc[target][key], result)
      {:exit, reason}, acc -> mark_all_ambiguous(acc, key, reason)
    end)
  end

  # An `Task.async_stream` exit loses which target it belonged to, so nothing is recorded
  # as having passed on the strength of it. Over-reporting ambiguity is the safe direction.
  defp mark_all_ambiguous(evidence, key, reason) do
    Map.new(evidence, fn {target, node_evidence} ->
      {target,
       Map.put(node_evidence, key, {:ambiguous, {:task_exit, inspect(reason, limit: 10)}})}
    end)
  end

  defp stage_node(target, artifact, bytes, opts) do
    remote_opts = [
      pool: Keyword.get(opts, :pool, Pool),
      store_root: Keyword.get(opts, :store_root)
    ]

    case remote(target, __MODULE__, :stage, [artifact, bytes, remote_opts], stage_timeout(opts)) do
      {:returned, {:ok, _evidence}} -> :ok
      {:returned, {:mismatch, reason}} -> {:mismatch, reason}
      {:returned, {:error, reason}} -> {:error, reason}
      {:returned, other} -> {:ambiguous, {:unexpected_result, inspect(other, limit: 10)}}
      {:ambiguous, reason} -> {:ambiguous, reason}
    end
  end

  defp probe_node(target, artifact, opts) do
    spec = {Capability, start_state(artifact, opts)}

    case remote(target, Probe, :ready?, [spec], probe_timeout(opts)) do
      {:returned, :ok} -> :ok
      {:returned, {:error, reason}} -> {:error, reason}
      {:returned, other} -> {:ambiguous, {:unexpected_result, inspect(other, limit: 10)}}
      {:ambiguous, reason} -> {:ambiguous, reason}
    end
  end

  defp eval_node(target, artifact, spec, opts) do
    start = {Capability, start_state(artifact, opts)}

    case remote(target, Evaluation, :run, [start, spec, []], eval_timeout(opts)) do
      {:returned, {:ok, report}} when is_map(report) -> Evaluation.summarize(report)
      {:returned, {:error, reason}} -> {:error, reason}
      {:returned, other} -> {:ambiguous, {:unexpected_result, inspect(other, limit: 10)}}
      {:ambiguous, reason} -> {:ambiguous, reason}
    end
  end

  defp eval_absent(evidence, nil),
    do:
      Map.new(evidence, fn {target, node_evidence} ->
        {target, %{node_evidence | eval: :absent}}
      end)

  defp eval_absent(evidence, _spec), do: evidence

  ## Settlement

  # The `:live` mark comes first and the durable start comes after it, in that order for
  # the reason `Ouroboros.Runtime.Capabilities.maybe_start/2` exists: the register is the
  # authority for "this rollout is live", and a wrapper is only ever started for a rollout
  # that already is. Like `maybe_start/2`, the register does not record *where* the wrapper
  # landed — that is in the returned outcome, because it is a fact about one process rather
  # than about the deployment.
  defp settle(evidence, artifact, nodes, opts, registry, spec, warnings) do
    case verdict(evidence) do
      :pass ->
        with {:ok, outcome} <- record(:live, evidence, artifact, nodes, registry, spec, warnings) do
          started(outcome, artifact, nodes, opts, registry)
        end

      verdict ->
        compensated = compensate(evidence, artifact, nodes, opts)
        state = if verdict == :ambiguous, do: :quarantined, else: proven_state(compensated)
        record(state, compensated, artifact, nodes, registry, spec, warnings)
    end
  end

  # The id is claimed cluster-wide by something running a different component. Trying the
  # next target would get the same answer, and calling it a start would put a component
  # nobody described behind an id somebody trusts.
  defp started(outcome, artifact, nodes, opts, registry) do
    case start_capability(artifact, nodes, opts) do
      {:claimed, id, other_sha} ->
        quarantine_claim(outcome, artifact, registry, id, other_sha)

      started ->
        {:ok, %{outcome | started: started}}
    end
  end

  defp quarantine_claim(outcome, artifact, registry, id, other_sha) do
    detail = %{stage: :start, start_id_claimed_by: bound(other_sha), start_id: id}

    quarantined = %{
      outcome
      | state: :quarantined,
        stage: :start,
        started: %{id: id, node: nil, claimed_by: other_sha}
    }

    case Registry.mark(artifact.id, :quarantined, [detail: detail], registry) do
      {:ok, _entry} -> {:error, {:quarantined, quarantined}}
      {:error, reason} -> {:error, {:rollout_record_failed, :quarantined, reason, quarantined}}
    end
  end

  # Exactly the order `Ouroboros.Upgrade.Rollout` settles in: ambiguity outranks failure,
  # failure outranks success, and "nobody answered" is never success.
  defp verdict(evidence) do
    outcomes = Enum.flat_map(evidence, fn {_target, e} -> [e.stage, e.probe, e.eval] end)

    cond do
      Enum.any?(outcomes, &ambiguous?/1) -> :ambiguous
      Enum.any?(outcomes, &failed?/1) -> :fail
      true -> :pass
    end
  end

  defp ambiguous?({:ambiguous, _reason}), do: true
  # A helper reading something other than the signed manifest is a node holding what
  # nobody described. It never "just links less".
  defp ambiguous?({:mismatch, _reason}), do: true
  defp ambiguous?(_outcome), do: false

  defp failed?({:error, _reason}), do: true
  defp failed?(%{satisfied?: satisfied?}), do: satisfied? != true
  defp failed?(_outcome), do: false

  defp all_passed?(evidence, key) do
    Enum.all?(evidence, fn {_target, e} -> Map.get(e, key) == :ok end)
  end

  # Nothing durable was started before the verdict, so withdrawing is proving absence: on
  # every target, either no wrapper holds this start id, or the one that does is this
  # component's and is stopped. A wrapper holding some *other* component's sha is left
  # alone and reported `:unchanged` — it belongs to a rollout this one did not displace.
  defp compensate(evidence, artifact, nodes, opts) do
    case start_block(artifact) do
      nil ->
        Map.new(evidence, fn {target, e} -> {target, %{e | recovery: :not_needed}} end)

      start ->
        nodes
        |> Enum.reduce(evidence, fn target, acc ->
          put_in(acc[target][:recovery], withdraw_node(target, start.id, artifact, opts))
        end)
    end
  end

  defp withdraw_node(target, id, artifact, opts) do
    args = [id, artifact.component_sha256]

    case remote(target, __MODULE__, :withdraw, args, start_timeout(opts)) do
      {:returned, recovery} when recovery in [:not_needed, :rolled_back, :unchanged] -> recovery
      _unproven -> :quarantined
    end
  end

  # Only proof on every node earns `:rolled_back`, which is the invariant the whole
  # module exists to preserve.
  defp proven_state(evidence) do
    if Enum.all?(evidence, fn {_target, e} -> e.recovery in @proven_recoveries end),
      do: :rolled_back,
      else: :quarantined
  end

  ## Starting the durable wrapper

  defp start_capability(artifact, nodes, opts) do
    with true <- Keyword.get(opts, :start?, true) != false,
         %{id: id} = start <- start_block(artifact) do
      place(nodes, id, start, artifact, opts, %{})
    else
      _no_start -> nil
    end
  end

  # One id, one process, cluster-wide. The first target that accepts hosts it; a target
  # answering `{:already_started, _}` has accepted **only** if the process holding the id is
  # running this artifact's component. Anything else is a claim on the name by somebody
  # else's capability, and no other target can answer differently, so it halts here.
  defp place([], id, _start, _artifact, _opts, errors),
    do: %{id: id, node: nil, errors: errors}

  defp place([target | rest], id, start, artifact, opts, errors) do
    state = start_state(artifact, opts) |> Map.put(:config, start.config)
    args = [id, [agent: Capability, initial_state: state], artifact.component_sha256]

    case remote(target, __MODULE__, :claim, args, start_timeout(opts)) do
      {:returned, {:ok, host}} ->
        %{id: id, node: host, errors: errors}

      {:returned, {:already_started, host}} ->
        %{id: id, node: host, errors: errors, already_started: true}

      {:returned, {:claimed, other_sha}} ->
        {:claimed, id, other_sha}

      {:returned, {:error, reason}} ->
        place(rest, id, start, artifact, opts, Map.put(errors, target, bound(reason)))

      {:returned, other} ->
        place(rest, id, start, artifact, opts, Map.put(errors, target, bound(other)))

      {:ambiguous, reason} ->
        place(rest, id, start, artifact, opts, Map.put(errors, target, bound(reason)))
    end
  end

  ## Recording

  defp record(state, evidence, artifact, nodes, registry, spec, warnings) do
    report = eval_report(evidence, spec)

    outcome = %{
      artifact_id: artifact.id,
      module: @module_prefix <> artifact.name,
      component_sha256: artifact.component_sha256,
      epoch: artifact.epoch,
      name: artifact.name,
      nodes: nodes,
      state: state,
      stage: stage_reached(evidence, spec),
      eval_report: report,
      started: nil,
      warnings: warnings,
      deployment: evidence
    }

    detail = %{
      stage: outcome.stage,
      nodes: Map.new(evidence, fn {target, e} -> {target, bound(e)} end)
    }

    case Registry.mark(artifact.id, state, [detail: detail, eval_report: report], registry) do
      {:ok, _entry} -> reply(state, outcome)
      {:error, reason} -> {:error, {:rollout_record_failed, state, reason, outcome}}
    end
  end

  defp reply(:live, outcome), do: {:ok, outcome}
  defp reply(state, outcome), do: {:error, {state, outcome}}

  defp stage_reached(evidence, spec) do
    cond do
      not all_passed?(evidence, :stage) -> :stage
      not all_passed?(evidence, :probe) -> :probe
      is_nil(spec) -> :settle
      true -> :evaluate
    end
  end

  defp eval_report(_evidence, nil), do: nil

  defp eval_report(evidence, spec) do
    %{
      spec: %{
        probes: length(spec.probes),
        required: spec.required,
        budget_ms: spec.budget_ms,
        max_latency_ms: spec.max_latency_ms
      },
      compare: false,
      nodes: Map.new(evidence, fn {target, e} -> {target, bound(e.eval)} end)
    }
  end

  ## Node-local work

  defp verified(artifact, bytes) do
    case Verifier.verify(
           artifact,
           bytes,
           Application.get_env(:ouroboros, :upgrade_trust_policy, [])
         ) do
      :ok -> :ok
      {:error, reason} -> {:error, {:component_rejected, reason}}
    end
  end

  # Content-addressed and idempotent: a node already holding this sha writes nothing and
  # reports `published: false`.
  defp published(artifact, bytes, store_opts) do
    case Store.put(bytes, artifact.component_sha256, store_opts) do
      {:ok, put} -> {:ok, put}
      {:error, reason} -> {:error, {:component_not_stored, reason}}
    end
  end

  defp published_manifest(artifact, store_opts) do
    case Store.put_manifest(artifact, store_opts) do
      {:ok, manifest} -> {:ok, manifest}
      {:error, reason} -> {:error, {:manifest_not_stored, reason}}
    end
  end

  defp loaded(artifact, path, pool) do
    case Pool.load(artifact.component_sha256, path, pool) do
      {:ok, report} when is_map(report) -> {:ok, report}
      {:error, reason} -> {:error, {:component_not_loaded, bound(reason)}}
      other -> {:error, {:component_not_loaded, bound(other)}}
    end
  end

  defp cross_checked(artifact, report) do
    case Verifier.cross_check(artifact, report) do
      :ok -> :ok
      {:error, reason} -> {:mismatch, reason}
    end
  end

  defp stop(id) do
    case Mesh.stop_agent(id) do
      :ok -> :rolled_back
      _unproven -> :quarantined
    end
  end

  ## Plumbing

  # Runs one gate on `target` under a deadline, converting anything unanswered into
  # ambiguity. The house rule, stated once: a transport fault is ambiguity, never failure
  # (`Ouroboros.Mesh`, `Ouroboros.Provider.Native.Subagent`).
  #
  # The local branch is bounded too, and that is the point of it being a branch rather than
  # a bare `apply/3`. A gate on this node does the same work a gate on a peer does —
  # filesystem writes in `stage/3`, `:global.trans/2` inside `Mesh.start_agent/2` — and an
  # unbounded local call would mean a rollout that hangs forever on the one node whose
  # deadline nobody set, while every peer's is enforced. So it runs in a task and is killed
  # at the deadline.
  #
  # The two branches are *not* symmetric, and saying otherwise was wrong. `:erpc.call/5`
  # with a timeout does not kill the process it spawned on the peer: it stops waiting and
  # demonitors, and the peer's process runs to completion. So a timed-out **local** gate is
  # killed mid-flight, while a timed-out **peer** gate keeps going and may publish bytes,
  # start a wrapper, or finish an evaluation after this coordinator has already settled the
  # rollout. Both outcomes are `{:ambiguous, _}` here and ambiguity quarantines, which is
  # exactly the state that says "a node may be running something nobody has accounted for".
  #
  # What each branch leaves behind is bounded rather than hoped for. The peer's own `after`
  # blocks run, because it was never killed; the local branch's do not, so
  # `Ouroboros.Upgrade.Rollout.Probe` and `Ouroboros.Upgrade.Rollout.Evaluation` each keep
  # their throwaway agent's cleanup in a process the kill does not reach.
  #
  # Public because it is this module's transport primitive: it carries no authority of its
  # own, and it is the unit whose contract is worth testing directly.
  @doc false
  @spec bounded_call(node(), module(), atom(), [term()], timeout()) ::
          {:returned, term()} | {:ambiguous, term()}
  def bounded_call(target, module, function, args, timeout) do
    if target == node() do
      local_call(module, function, args, timeout)
    else
      {:returned, :erpc.call(target, module, function, args, timeout)}
    end
  catch
    kind, reason -> {:ambiguous, {kind, inspect(reason, limit: 10)}}
  end

  # The inner `try` means the task never exits abnormally, so `Task.async`'s link cannot
  # take this process down with it — every outcome comes back as a value.
  defp local_call(module, function, args, timeout) do
    task =
      Task.async(fn ->
        try do
          {:returned, apply(module, function, args)}
        catch
          kind, reason -> {:ambiguous, {kind, inspect(reason, limit: 10)}}
        end
      end)

    case Task.yield(task, timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      {:exit, reason} -> {:ambiguous, {:exit, inspect(reason, limit: 10)}}
      nil -> {:ambiguous, :timeout}
    end
  end

  defp remote(target, module, function, args, timeout),
    do: bounded_call(target, module, function, args, timeout)

  defp trust_policy(opts) do
    Keyword.get_lazy(opts, :trust_policy, fn ->
      Application.get_env(:ouroboros, :upgrade_trust_policy, [])
    end)
  end

  defp store_opts(opts) do
    case Keyword.get(opts, :store_root) do
      root when is_binary(root) and root != "" -> [root: root]
      _unset -> []
    end
  end

  defp start_config(%Artifact{} = artifact) do
    case start_block(artifact) do
      %{config: config} -> config
      nil -> "{}"
    end
  end

  defp lane_w?(entry), do: is_binary(Map.get(entry, :component_sha256))

  defp stage_timeout(opts), do: positive(opts, :stage_timeout, @default_stage_timeout_ms)
  defp probe_timeout(opts), do: positive(opts, :probe_timeout, Probe.budget_ms())
  defp start_timeout(opts), do: positive(opts, :start_timeout, @default_start_timeout_ms)

  defp eval_timeout(opts) do
    positive(opts, :eval_timeout, fn ->
      Application.get_env(:ouroboros, :capability_eval_timeout, @default_eval_timeout_ms)
    end)
  end

  defp positive(opts, key, default) do
    case Keyword.get(opts, key) do
      value when is_integer(value) and value > 0 -> value
      _absent -> resolve(default)
    end
  end

  defp resolve(default) when is_function(default, 0) do
    case default.() do
      value when is_integer(value) and value > 0 -> value
      _invalid -> @default_eval_timeout_ms
    end
  end

  defp resolve(default), do: default

  defp byte_size_of(bytes) when is_binary(bytes), do: byte_size(bytes)
  defp byte_size_of(other), do: other

  # Everything recorded here lands in a durable registry entry and crosses `:erpc` on the
  # way. Small terms keep their shape because a named tuple is worth matching on; anything
  # unportable or oversized becomes bounded text.
  defp bound(term) do
    if Beam.portable_term?(term) and :erlang.external_size(term) <= 2_048,
      do: term,
      else: inspect(term, limit: 10, printable_limit: 200)
  end
end
