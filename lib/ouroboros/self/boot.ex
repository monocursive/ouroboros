defmodule Ouroboros.Self.Boot do
  @moduledoc """
  Deploys what a previous installation forged, and applies what it earned (docs/SELF.md §S4).

  `Ouroboros.Wasm.Boot` restarts the lane-W capabilities **this node** was running before it
  stopped, out of its own register and its own store. This is the other half: the
  capabilities a *different* installation forged, carried in the repository under
  `priv/self/` by `Ouroboros.Self.Export`, deployed here on a first boot. Between them a
  fresh clone of this runtime starts with the policy the previous one learned, running,
  rather than with a file somebody has to remember to deploy by hand.

  ## It grants nothing

  A bundle in `priv/self/` is a file in a repository, and this treats it as exactly that.
  It goes through `Ouroboros.Wasm.Rollout.deploy/4` — the ordinary rollout — which verifies
  the manifest against **this node's own** trust policy before its checkpoint and again on
  every target before it stages a byte. So a fresh install runs a shipped policy only
  because its operator put the exporting key in `OUROBOROS_UPGRADE_TRUSTED_SIGNERS`, which
  is what `priv/self/signers.txt` exists to tell them. Until they do, every bundle here is
  skipped by name with the reason in the log, and the node boots with the rules it shipped
  with.

  A bundle that does not verify, does not decode, names a capability already live, or fails
  its own signed evaluation is skipped. Nothing here raises: a boot task that raised would
  take the supervision chain with it, and a capability that did not ship is a fact to
  report rather than a reason to refuse the boot.

  **And only a policy ships.** This directory is a directory in a repository, so what it
  holds is whatever `Ouroboros.Self.Export` wrote plus whatever anybody committed beside it.
  A manifest whose `kind` is anything but `:policy` is skipped by name with
  `{:not_a_policy, kind}`: a capability bundle left here would otherwise start on every
  fresh install under the posture, because of where its file was rather than because anyone
  promoted it.

  ## After `Ouroboros.Wasm.Boot`, not beside it

  Every decision below is a question about the rollout register — whether a name is already
  `:live`, whether the sha `promotions.json` names is live *now* — and `Ouroboros.Wasm.Boot`
  is what restarts this node's own capabilities into that register. So the two are one task
  in that order (`run_after_wasm/0`) and not two tasks racing, which is what they were:
  `Task.start_link` returns as soon as the process exists.

  ## Promotions are applied over an empty record and nowhere else

  `promotions.json` is a widening — it says which tools a policy component may resolve an
  `allow` for — so it is applied only when this node's `Ouroboros.Control.PolicyPromotion`
  record is **empty**, and only for a component sha that is `:live` here *now*, under the
  name the file names. A node that has promoted anything of its own keeps its own record;
  the shipped one is reported as skipped rather than merged, because merging two records
  would be inventing an answer to "which human promoted this".

  Each promotion goes through `PolicyPromotion.promote/6` like any other, so it lands in the
  effect ledger with an actor: `"shipped:<sha256 of promotions.json>"`. That string is the
  honest answer to "who promoted this tool on this machine" — not a person, and traceable
  to the exact bytes that carried it.

  ## Idempotent

  A second boot deploys nothing (every name is already `:live`) and promotes nothing (the
  record is no longer empty). A `priv/self` that does not exist is `:ok` with an empty
  report, which is every ordinary checkout of this repository.
  """

  require Logger

  alias Ouroboros.Control.PolicyPromotion
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Wasm.{Artifact, Bundle, Rollout}

  @promotions "promotions.json"

  # A record of counts and names. Sixteen tools with their evidence is a few kilobytes;
  # this is three orders of magnitude above every legitimate value and small enough that a
  # hostile file is a refusal rather than a parse.
  @max_promotions_bytes 256 * 1024

  @type report :: %{
          root: Path.t() | nil,
          deployed: [map()],
          skipped: [map()],
          promoted: [String.t()],
          promotions: atom() | tuple()
        }

  @doc """
  Whether this node ships `priv/self/` at boot.

  `config :ouroboros, :self_ship` — which only `OUROBOROS_POSTURE=self` sets — and a durable
  data directory, because the store a deploy writes into and the register it records in are
  both under one. Read as exactly `true`, the way every switch that widens what this node
  runs is read.
  """
  @spec enabled?() :: boolean()
  def enabled? do
    Application.get_env(:ouroboros, :self_ship, false) == true and
      is_binary(Application.get_env(:ouroboros, :data_dir)) and
      Application.get_env(:ouroboros, :data_dir) != ""
  end

  @doc "Where the shipped bundles are: `priv/self` inside this application."
  @spec default_root() :: Path.t()
  def default_root, do: Application.app_dir(:ouroboros, "priv/self")

  @doc """
  `Ouroboros.Wasm.Boot.run/0` and then `run/0`, in that order, in one task (S4, LOW-6).

  What `Ouroboros.Application.boot_restart_children/0` starts when both halves are on, and
  the reason it is one child rather than two: `Task.start_link` returns as soon as the
  process exists, so two task children of the same supervisor run concurrently — and every
  decision this module makes is a question about the rollout register `Ouroboros.Wasm.Boot`
  is busy restarting into. Concurrently, "is this name already live?" has two answers
  depending on which task got there first.

  Named rather than a closure so the child spec says the order out loud, and split from
  `run_after_wasm/2` so a test can prove it without booting either half.
  """
  @spec run_after_wasm() :: :ok
  def run_after_wasm, do: run_after_wasm(&Ouroboros.Wasm.Boot.run/0, &run/0)

  @doc false
  @spec run_after_wasm((-> any()), (-> any())) :: :ok
  def run_after_wasm(wasm, self) when is_function(wasm, 0) and is_function(self, 0) do
    _ = wasm.()
    _ = self.()
    :ok
  end

  @doc "Runs `ship/1` and logs what it did. The shape the supervision tree starts."
  @spec run() :: :ok
  def run do
    report = ship()

    if report.deployed != [] or report.skipped != [] or report.promoted != [] do
      Logger.info(
        "self ship: deployed #{length(report.deployed)}, skipped #{length(report.skipped)}, " <>
          "promoted #{length(report.promoted)}" <> detail(report)
      )
    end

    :ok
  end

  @doc """
  Deploys every bundle under `opts[:root]` whose name is not live, then applies
  `#{@promotions}`.

  Options are the node-local seams the rollout already takes — `:registry`, `:store_root`,
  `:pool`, `:trust_policy` — plus `:root` (the export directory) and `:promotion` (the
  `Ouroboros.Control.PolicyPromotion` server). Never raises.
  """
  @spec ship(keyword()) :: report()
  def ship(opts \\ []) when is_list(opts) do
    root = Keyword.get(opts, :root) || default_root()

    if File.dir?(root) do
      root
      |> bundles()
      |> Enum.reduce(empty(root), &deploy(&1, &2, opts))
      |> reverse()
      |> promote(root, opts)
    else
      empty(root)
    end
  rescue
    error -> failed(Keyword.get(opts, :root), Exception.message(error))
  catch
    kind, reason -> failed(Keyword.get(opts, :root), inspect({kind, reason}, limit: 10))
  end

  ## ── the bundles ───────────────────────────────────────────────────────────────────────

  defp bundles(root) do
    root
    |> Path.join("*.ouro-wasm")
    |> Path.wildcard()
    |> Enum.sort()
  end

  defp deploy(path, report, opts) do
    with {:ok, bundle} <- read_bundle(path),
         {:ok, %{artifact: artifact, bytes: bytes, precompiled: precompiled}} <-
           Bundle.decode(bundle),
         :ok <- a_policy(artifact),
         :ok <- not_live(artifact, opts) do
      rollout(path, artifact, bytes, precompiled, report, opts)
    else
      {:error, reason} -> skip(report, path, reason)
    end
  end

  # S4 fix wave. `priv/self` is a directory in a repository and this globs it, so what lands
  # here is whatever the export wrote plus whatever anybody committed beside it. Only one
  # kind of thing belongs: the promoted **policy**. A capability bundle dropped in here would
  # otherwise be deployed and started on every fresh install of this runtime under the
  # posture — a component nobody promoted, running because of where its file was.
  #
  # Asked before `not_live/2` and before the rollout, so a bundle of the wrong kind is
  # refused whatever else is true of it. It is a *claim* at this point — `Bundle.decode/1`
  # parses and does not verify — and that is the safe direction for a claim: this only ever
  # narrows what deploys, and the rollout still verifies the manifest against this node's own
  # trust policy before it stages a byte. A capability bundle that lied about its kind to get
  # past this line would be skipped by the same line for saying `:policy`.
  defp a_policy(%Artifact{kind: :policy}), do: :ok
  defp a_policy(%Artifact{kind: kind}), do: {:error, {:not_a_policy, kind}}

  # Bounded before it is read, and bounded by the same number a bundle could legally weigh.
  # A file larger than any bundle this build admits is not a bundle, and reading it into
  # memory to discover that is the mistake the ceiling exists to prevent.
  defp read_bundle(path) do
    case File.stat(path) do
      {:ok, %File.Stat{type: :regular, size: size}} when size > 0 ->
        if size > Bundle.max_bytes() do
          {:error, {:bundle_too_large, size}}
        else
          case File.read(path) do
            {:ok, bytes} -> {:ok, bytes}
            {:error, reason} -> {:error, {:bundle_unreadable, reason}}
          end
        end

      {:ok, %File.Stat{type: type}} ->
        {:error, {:not_a_regular_file, type}}

      {:error, reason} ->
        {:error, {:bundle_unreadable, reason}}
    end
  end

  # The register's own answer, asked before anything is verified: a bundle claiming a name
  # this node already runs is skipped whether or not it would have verified, which is the
  # safe direction for a claim that has not been checked yet.
  defp not_live(%Artifact{name: name}, opts) do
    module = "wasm/" <> name

    Keyword.get(opts, :registry, Registry)
    |> Registry.live()
    |> Enum.any?(&(Map.get(&1, :module) == module))
    |> case do
      true -> {:error, :already_live}
      false -> :ok
    end
  catch
    # No register is not an empty register. At boot the honest move is to ship nothing
    # rather than to deploy over a register this node cannot read.
    :exit, reason -> {:error, {:rollout_registry_unavailable, reason}}
  end

  defp rollout(path, artifact, bytes, precompiled, report, opts) do
    deploy_opts =
      opts
      |> Keyword.take([:registry, :pool, :store_root, :trust_policy, :limits])
      |> Keyword.put(:precompiled, precompiled)

    case Rollout.deploy(artifact, bytes, [node()], deploy_opts) do
      {:ok, %{state: :live}} ->
        record(report, :deployed, %{
          bundle: Path.basename(path),
          name: artifact.name,
          kind: artifact.kind,
          component_sha256: artifact.component_sha256
        })

      {:ok, %{state: state}} ->
        skip(report, path, {:not_live, state})

      {:error, reason} ->
        skip(report, path, reason)
    end
  end

  ## ── the record ────────────────────────────────────────────────────────────────────────

  defp promote(report, root, opts) do
    path = Path.join(root, @promotions)

    case read_record(path) do
      {:error, :enoent} -> %{report | promotions: :absent}
      {:error, reason} -> %{report | promotions: {:skipped, reason}}
      {:ok, bytes, record} -> apply_record(report, record, actor(bytes), opts)
    end
  end

  defp read_record(path) do
    with {:ok, %File.Stat{type: :regular, size: size}} <- File.stat(path),
         :ok <- bounded(size),
         {:ok, bytes} <- File.read(path),
         {:ok, record} when is_map(record) <- JSON.decode(bytes) do
      {:ok, bytes, record}
    else
      {:ok, %File.Stat{type: type}} -> {:error, {:not_a_regular_file, type}}
      {:ok, _not_an_object} -> {:error, :invalid_promotions_record}
      {:error, :enoent} -> {:error, :enoent}
      {:error, reason} -> {:error, {:promotions_unusable, reason}}
    end
  end

  defp bounded(size) when size > 0 and size <= @max_promotions_bytes, do: :ok
  defp bounded(size), do: {:error, {:promotions_size, size}}

  # The bytes that carried the promotion, named by their digest. Not a person: this is the
  # honest answer to "who promoted this tool on this machine", and it points at the exact
  # file a reviewer can read.
  defp actor(bytes), do: "shipped:" <> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  defp apply_record(report, record, actor, opts) do
    server = Keyword.get(opts, :promotion, PolicyPromotion)

    with {:ok, name, sha, tools} <- fields(record),
         :ok <- record_empty(server),
         :ok <- live_here(name, sha, opts) do
      Enum.reduce(tools, %{report | promotions: :applied}, fn {tool, evidence}, acc ->
        case PolicyPromotion.promote(name, sha, tool, evidence, actor, server) do
          {:ok, _record} -> %{acc | promoted: acc.promoted ++ [tool]}
          {:error, reason} -> %{acc | promotions: {:partial, tool, reason}}
        end
      end)
    else
      {:error, reason} -> %{report | promotions: {:skipped, reason}}
    end
  end

  defp fields(record) do
    with name when is_binary(name) and name != "" <- Map.get(record, "policy_name"),
         sha when is_binary(sha) <- Map.get(record, "component_sha256"),
         tools when is_map(tools) <- Map.get(record, "tools", %{}) do
      {:ok, name, sha, Enum.sort_by(evidence(tools), &elem(&1, 0))}
    else
      _malformed -> {:error, :invalid_promotions_record}
    end
  end

  # `PolicyPromotion.promote/6` validates every one of these itself and refuses anything it
  # does not recognise. What this does is translate the file's strings into the atom-keyed
  # map that function's contract names, and drop a tool whose evidence is not a map before
  # the call rather than after it.
  defp evidence(tools) do
    tools
    |> Enum.filter(fn {tool, evidence} -> is_binary(tool) and is_map(evidence) end)
    |> Enum.map(fn {tool, evidence} ->
      {tool,
       %{
         report_sha256: Map.get(evidence, "report_sha256"),
         decisions: Map.get(evidence, "decisions"),
         contradictions: Map.get(evidence, "contradictions"),
         replayed_at: Map.get(evidence, "replayed_at")
       }}
    end)
  end

  defp record_empty(server) do
    case PolicyPromotion.status(server) do
      %{policy_name: nil, component_sha256: nil} -> :ok
      %{policy_name: name} when is_binary(name) -> {:error, {:record_bound_to, name}}
      %{error: reason} -> {:error, {:policy_promotion_unavailable, reason}}
      _other -> {:error, :policy_promotion_unreadable}
    end
  end

  # The file names bytes; this asks whether those bytes are what this node is running under
  # that name, right now. A record applied over a policy that did not deploy would be a
  # widening for a component nobody is consulting.
  defp live_here(name, sha, opts) do
    module = "wasm/" <> name

    Keyword.get(opts, :registry, Registry)
    |> Registry.live()
    |> Enum.any?(&(Map.get(&1, :module) == module and Map.get(&1, :component_sha256) == sha))
    |> case do
      true -> :ok
      false -> {:error, {:policy_not_live, name, sha}}
    end
  catch
    :exit, reason -> {:error, {:rollout_registry_unavailable, reason}}
  end

  ## ── the report ────────────────────────────────────────────────────────────────────────

  defp empty(root),
    do: %{root: root, deployed: [], skipped: [], promoted: [], promotions: :absent}

  defp failed(root, reason),
    do: %{
      root: root,
      deployed: [],
      skipped: [%{bundle: nil, name: nil, reason: reason}],
      promoted: [],
      promotions: {:skipped, reason}
    }

  defp skip(report, path, reason) do
    record(report, :skipped, %{bundle: Path.basename(path), name: nil, reason: reason})
  end

  defp record(report, key, item), do: Map.update!(report, key, &[item | &1])

  defp reverse(report),
    do: %{report | deployed: Enum.reverse(report.deployed), skipped: Enum.reverse(report.skipped)}

  defp detail(report) do
    shipped =
      case report.deployed do
        [] -> ""
        entries -> "; running: " <> Enum.map_join(entries, ", ", & &1.name)
      end

    skipped =
      case report.skipped do
        [] -> ""
        entries -> "; skipped: " <> Enum.map_join(entries, ", ", &skipped_detail/1)
      end

    shipped <> skipped <> promotions_detail(report.promotions)
  end

  defp skipped_detail(%{bundle: bundle, reason: reason}),
    do: "#{bundle} (#{inspect(reason, limit: 5)})"

  defp promotions_detail(:applied), do: ""
  defp promotions_detail(:absent), do: ""
  defp promotions_detail(other), do: "; promotions: " <> inspect(other, limit: 5)
end
