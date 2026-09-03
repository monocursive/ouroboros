defmodule Ouroboros.Wasm.Boot do
  @moduledoc """
  Restarts the lane-W capabilities this node was running before it stopped.

  Lane B cannot do this and says so: forged bytes die with the receipt at promote
  (docs/WASM.md §3.4), so a restarted release boots without any capability it was running.
  Lane W keeps its bytes on purpose (§7.4, D6), which turns "restart what was live" from a
  wish into a lookup — and this is the lookup.

  ## Two node-local facts, and nothing else

  A node restarts a wrapper when **its own** rollout registry marks the entry `:live` and
  **its own** component store holds the signed manifest for it. Both halves are durable
  node-local state; neither is a question asked of the cluster. That matters at boot, when
  the cluster may not exist yet: a restart that had to ask a peer what it should be running
  would be a restart that does nothing on the first node up, and something different on
  the second.

  The consequence is worth stating rather than hiding. A node that *drove* a rollout it
  was not itself a target of has the registry entry and not the manifest, and this reports
  `:manifest_missing` for it instead of guessing. Deploy to the nodes that should run the
  capability, and include the one you drive from.

  ## What is re-checked, and what is not

  The manifest's signature is verified again, against this node's trust policy, before
  anything starts. The component bytes are *not* read here — that would make boot cost
  scale with the size of every capability, and it would prove nothing extra: the agent is
  lazy, and the first message loads the component through the helper, which recomputes the
  digest from the file and refuses `sha_mismatch` before compiling. A wrapper started from
  a manifest this accepts cannot reach bytes that are not the signed ones.

  A manifest that no longer verifies, names a different component than the entry, or
  declares no `start` block is skipped with a named reason. Nothing here repairs a record;
  a `:live` entry whose manifest is unusable is an operator's question.

  What is **not** re-checked is `Ouroboros.Wasm.Verifier.cross_check/2` — the helper's own
  reading of the staged file against the manifest — because that needs the helper to
  compile the component, which is the boot cost this deliberately does not pay. Say plainly
  what that leaves open: a helper that has since started reading a component's world or
  imports differently (a rebuilt `ouro-wasm`, a different wasmtime) would start at boot what
  a deploy would have quarantined. The bytes are still the signed bytes — the helper
  recomputes the digest at `load` and refuses `sha_mismatch`, and the linker refuses an
  undeclared import at instantiation, which is the boundary that actually contains it
  (docs/WASM.md D5). What is lost is the *manifest disagreement* signal, and recovering it
  is a redeploy.

  ## Idempotent, by construction

  A mesh id is claimed once cluster-wide, so an id already running **this component** is a
  success and not a conflict: `{:already_started, _}` is counted as started. That is what
  makes this safe to run again after a supervisor restart takes the `rest_for_one` chain
  down and back up.

  An id held by a *different* component is a different fact and is reported as `failed`
  with `{:start_id_claimed_by, other_sha}`. Two `:live` entries can name one start id, and
  whichever boots first takes the name; counting the loser as started would report a
  capability as running under its own sha while something else answered for it.
  """

  require Logger

  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Wasm.{Artifact, Capability, Rollout, Store, Verifier}

  @type report :: %{
          started: [map()],
          skipped: [map()],
          failed: [map()]
        }

  @doc """
  Starts the durable wrapper for every `:live` lane-W entry whose manifest declares one.

  Options mirror `Ouroboros.Wasm.Rollout.deploy/4`'s: `:registry`, `:store_root`, `:pool`,
  `:limits`, and `:trust_policy`. Never raises — a boot task that raised would take the
  supervision chain with it, and a capability that failed to restart is a fact to report,
  not a reason to refuse the boot.
  """
  @spec restart_live(keyword()) :: report()
  def restart_live(opts \\ []) when is_list(opts) do
    registry = Keyword.get(opts, :registry, Registry)

    registry
    |> live_entries()
    |> Enum.reduce(%{started: [], skipped: [], failed: []}, &restart_entry(&1, &2, opts))
    |> reverse()
  rescue
    error -> empty(%{reason: Exception.message(error)})
  catch
    kind, reason -> empty(%{reason: inspect({kind, reason}, limit: 10)})
  end

  @doc "Runs `restart_live/1` and logs what it did. The shape the supervision tree starts."
  @spec run() :: :ok
  def run do
    report = restart_live()

    if report.started != [] or report.failed != [] or report.skipped != [] do
      Logger.info(
        "wasm boot restart: started #{length(report.started)}, " <>
          "failed #{length(report.failed)}, skipped #{length(report.skipped)}" <>
          detail(report)
      )
    end

    :ok
  end

  defp live_entries(registry) do
    registry
    |> Registry.live()
    |> Enum.filter(&is_binary(Map.get(&1, :component_sha256)))
  catch
    # No register is not an empty register, but at boot there is nothing to do about it
    # either: the caller is a one-shot task, and `run/0` logs the empty report.
    :exit, _reason -> []
  end

  defp restart_entry(entry, report, opts) do
    with {:ok, manifest} <- manifest(entry, opts),
         :ok <- verified(manifest, opts),
         :ok <- matches_entry(manifest, entry),
         %{id: _id} = start <- Rollout.start_block(manifest) do
      place(entry, manifest, start, report, opts)
    else
      nil -> skip(report, entry, :no_start_block)
      {:error, reason} -> skip(report, entry, reason)
    end
  end

  defp manifest(entry, opts) do
    case Store.fetch_manifest(entry.artifact_id, store_opts(opts)) do
      {:ok, %Artifact{} = manifest} -> {:ok, manifest}
      {:error, {:unknown_manifest, _id}} -> {:error, :manifest_missing}
      {:error, :no_data_dir} -> {:error, :no_data_dir}
      {:error, reason} -> {:error, {:manifest_unusable, reason}}
    end
  end

  defp verified(manifest, opts) do
    case Verifier.verify_manifest(manifest, trust_policy(opts)) do
      :ok -> :ok
      {:error, reason} -> {:error, {:manifest_rejected, reason}}
    end
  end

  # The register says which component this rollout was about. A manifest describing a
  # different one is not this entry's manifest, whatever the artifact id says.
  defp matches_entry(%Artifact{component_sha256: sha}, %{component_sha256: sha}), do: :ok

  defp matches_entry(%Artifact{component_sha256: manifest}, entry),
    do: {:error, {:component_mismatch, entry.component_sha256, manifest}}

  defp place(entry, manifest, start, report, opts) do
    state = manifest |> Rollout.start_state(opts) |> Map.put(:config, start.config)
    sha = manifest.component_sha256

    case Rollout.claim(start.id, [agent: Capability, initial_state: state], sha) do
      {:ok, host} ->
        record(report, :started, %{
          artifact_id: entry.artifact_id,
          id: start.id,
          node: host,
          component_sha256: sha
        })

      # An id already claimed *by this component* is an id doing its job. See the moduledoc.
      {:already_started, host} ->
        record(report, :started, %{
          artifact_id: entry.artifact_id,
          id: start.id,
          node: host,
          component_sha256: sha,
          already_started: true
        })

      # And an id claimed by a different component is not this capability running. Two
      # `:live` entries can name one start id, and whichever boots first takes the name;
      # reporting the loser as started would put a component nobody asked for behind an id
      # somebody trusts, and would hide it behind the winner's own sha.
      {:claimed, other} ->
        record(report, :failed, %{
          artifact_id: entry.artifact_id,
          id: start.id,
          component_sha256: sha,
          reason: {:start_id_claimed_by, other}
        })

      {:error, reason} ->
        record(report, :failed, %{
          artifact_id: entry.artifact_id,
          id: start.id,
          component_sha256: sha,
          reason: inspect(reason, limit: 10)
        })
    end
  end

  defp skip(report, entry, reason) do
    record(report, :skipped, %{
      artifact_id: Map.get(entry, :artifact_id),
      component_sha256: Map.get(entry, :component_sha256),
      reason: reason
    })
  end

  defp record(report, key, item), do: Map.update!(report, key, &[item | &1])

  defp reverse(report) do
    Map.new(report, fn {key, items} -> {key, Enum.reverse(items)} end)
  end

  # `:artifact_id` is filled in even here, because `run/0` renders every skipped entry the
  # same way. A rescue clause that produced a map the logger then raised a `KeyError` on
  # would defeat the whole point of the rescue.
  defp empty(reason),
    do: %{started: [], skipped: [Map.put_new(reason, :artifact_id, nil)], failed: []}

  defp store_opts(opts) do
    case Keyword.get(opts, :store_root) do
      root when is_binary(root) and root != "" -> [root: root]
      _unset -> []
    end
  end

  defp trust_policy(opts) do
    Keyword.get_lazy(opts, :trust_policy, fn ->
      Application.get_env(:ouroboros, :upgrade_trust_policy, [])
    end)
  end

  defp detail(%{started: [], failed: [], skipped: skipped}),
    do:
      "; skipped: " <> Enum.map_join(skipped, ", ", &"#{&1.artifact_id} (#{inspect(&1.reason)})")

  defp detail(%{started: started, failed: failed}) do
    ids = Enum.map_join(started, ", ", & &1.id)
    reasons = Enum.map_join(failed, ", ", &"#{&1.id} (#{&1.reason})")

    case {ids, reasons} do
      {"", ""} -> ""
      {ids, ""} -> "; running: " <> ids
      {"", reasons} -> "; unstarted: " <> reasons
      {ids, reasons} -> "; running: " <> ids <> "; unstarted: " <> reasons
    end
  end

  @doc """
  Whether this node has the durable state a restart reads.

  No data directory means no component store, which means no manifests and nothing to
  restart — a library start or a test run, where the supervision tree skips this task
  entirely rather than starting one that can only report an empty list.
  """
  @spec enabled?() :: boolean()
  def enabled? do
    case Application.get_env(:ouroboros, :data_dir) do
      dir when is_binary(dir) and dir != "" -> true
      _unset -> false
    end
  end
end
