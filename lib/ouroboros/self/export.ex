defmodule Ouroboros.Self.Export do
  @moduledoc """
  Writes what this installation learned into `priv/self/`, so the next one can carry it
  (docs/SELF.md §S4, S-D42).

  A promotion is durable node-local state: `Ouroboros.Control.PolicyPromotion` holds one
  policy name, the component sha256 it is bound to, and the tools that component earned the
  right to resolve, each with the replay numbers that earned it. None of that is in the
  repository, so a fresh clone of this runtime starts with the rules it shipped with and
  nothing a previous installation was taught. This is the file half of that gap; the boot
  half is `Ouroboros.Self.Boot`.

  Three files, and each is one thing:

    * `<name>.ouro-wasm` — the bundle, assembled out of **this node's own store**: the
      signed manifest, the precompiled artifact when the manifest declares one, and the
      component bytes. Byte for byte what `Ouroboros.Wasm.Bundle.encode/3` writes, which is
      byte for byte what `ouro wasm sign` produced, and what `ouro wasm deploy` takes.
    * `promotions.json` — the record: the policy name, the sha, and the tools **currently
      allowable** with their evidence. Not the tools that were ever promoted: a tool a human
      contradicted on this machine is a tool this machine narrowed, and shipping its
      promotion would re-widen it somewhere else (S-D43).
    * `signers.txt` — `signer_id:base64_public_key`, the exact line
      `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` takes and `ouro wasm keygen` prints. It is not a
      grant of trust. It is the sentence the receiving operator needs in order to decide
      whether to grant it, and until they paste it their node refuses the bundle.

  ## What it refuses

  An empty record: there is nothing to export, and a `priv/self` full of a policy nobody
  promoted would be a shipped widening nobody performed. A policy the register does not
  currently have `:live` under that name at that sha — the export ships what is running,
  not what is remembered. A manifest whose declared precompiled artifact this node no longer
  holds, because `Bundle.encode/3` refuses a bundle that declares a section it does not
  carry and a half-written export is worse than a refusal. And a signer whose public key is
  not in this node's trust policy, because then `signers.txt` could not be written and the
  bundle would arrive somewhere with no way to accept it.

  ## Nothing here is a secret

  A public key, a component that was already distributed as a signed bundle, and counts of
  decisions. The corpus those counts came from — `Ouroboros.Control.PolicyEvidence`, which
  holds the actual requests humans answered — is node-local and is not exported by this or
  by anything else.
  """

  require Logger

  alias Ouroboros.Control.PolicyPromotion
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Wasm.{Artifact, Bundle, Store}

  @default_out "priv/self"
  @promotions "promotions.json"
  @signers "signers.txt"
  @record_version 1

  @type report :: %{
          out: Path.t(),
          bundle: Path.t(),
          promotions: Path.t(),
          signers: Path.t(),
          policy_name: String.t(),
          component_sha256: String.t(),
          signer_id: String.t(),
          tools: [String.t()],
          bundle_bytes: pos_integer()
        }

  @doc "Where an export goes when nobody names a directory: `#{@default_out}`."
  @spec default_out() :: Path.t()
  def default_out, do: @default_out

  @doc "The three names an export writes, for a caller that has to clean or check them."
  @spec filenames(String.t()) :: [String.t()]
  def filenames(policy_name), do: [policy_name <> ".ouro-wasm", @promotions, @signers]

  @doc """
  Exports the promoted policy into `opts[:out]` (default `#{@default_out}`).

  Options beyond `:out` are the ordinary node-local seams: `:promotion` (the
  `Ouroboros.Control.PolicyPromotion` server), `:registry`, `:store_root` and
  `:trust_policy`. Answers `{:ok, report}` naming every file it wrote, or `{:error, reason}`
  having written nothing.
  """
  @spec run(keyword()) :: {:ok, report()} | {:error, term()}
  def run(opts \\ []) when is_list(opts) do
    out = Keyword.get(opts, :out, @default_out)

    with {:ok, name, sha, tools} <- promoted(opts),
         {:ok, entry} <- live_entry(name, sha, opts),
         {:ok, manifest} <- manifest(entry, sha, opts),
         {:ok, bytes} <- component(sha, opts),
         {:ok, precompiled} <- precompiled(manifest, opts),
         {:ok, bundle} <- Bundle.encode(manifest, bytes, precompiled),
         {:ok, signer_id, public} <- signer(manifest, opts),
         :ok <- prepare(out) do
      write(out, name, sha, tools, manifest, bundle, signer_id, public)
    end
  end

  ## ── what is promoted, and what is running ─────────────────────────────────────────────

  defp promoted(opts) do
    status = PolicyPromotion.status(Keyword.get(opts, :promotion, PolicyPromotion))

    case status do
      %{policy_name: name, component_sha256: sha}
      when is_binary(name) and name != "" and is_binary(sha) ->
        {:ok, name, sha, evidence(status)}

      %{error: reason} ->
        {:error, {:policy_promotion_unavailable, reason}}

      _empty ->
        {:error, :no_promoted_policy}
    end
  end

  # The tools currently allowable and their evidence, keyed by tool. `allowable_tools` is
  # already "promoted and not demoted since", so a demotion drops a tool out of the export
  # without this module knowing what a demotion is.
  defp evidence(%{allowable_tools: allowable, tools: tools}) do
    Map.new(allowable, fn tool ->
      entry = Map.get(tools, tool, %{})
      {tool, Map.get(entry, :evidence, %{})}
    end)
  end

  defp live_entry(name, sha, opts) do
    module = "wasm/" <> name

    Keyword.get(opts, :registry, Registry)
    |> Registry.live()
    |> Enum.find(&(&1.module == module and Map.get(&1, :component_sha256) == sha))
    |> case do
      nil -> {:error, {:policy_not_live, name, sha}}
      entry -> {:ok, entry}
    end
  catch
    :exit, reason -> {:error, {:rollout_registry_unavailable, reason}}
  end

  defp manifest(entry, sha, opts) do
    case Store.fetch_manifest(entry.artifact_id, store_opts(opts)) do
      {:ok, %Artifact{component_sha256: ^sha} = manifest} ->
        {:ok, manifest}

      {:ok, %Artifact{component_sha256: other}} ->
        {:error, {:manifest_describes_other_component, sha, other}}

      {:error, reason} ->
        {:error, {:manifest_unusable, reason}}
    end
  end

  defp component(sha, opts) do
    case Store.fetch(sha, store_opts(opts)) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, reason} -> {:error, {:component_unreadable, reason}}
    end
  end

  # Present exactly when the manifest declares it, because that is the rule
  # `Bundle.encode/3` enforces: a bundle carrying a section its manifest does not declare,
  # or declaring one it does not carry, is two statements about one file that disagree.
  defp precompiled(%Artifact{precompiled: nil}, _opts), do: {:ok, nil}

  defp precompiled(%Artifact{precompiled: %{sha256: sha}}, opts) do
    with {:ok, path} <- Store.precompiled_path(sha, store_opts(opts)),
         {:ok, bytes} <- File.read(path) do
      {:ok, bytes}
    else
      {:error, reason} -> {:error, {:precompiled_unavailable, sha, reason}}
    end
  end

  defp precompiled(%Artifact{precompiled: other}, _opts),
    do: {:error, {:invalid_precompiled_block, inspect(other, limit: 5)}}

  # The key this node verified the manifest against, read out of this node's own trust
  # policy rather than out of the bundle. A bundle carries a signer id and a signature and
  # never a key; the receiving operator's `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` is the only
  # place a key is ever believed, and this file is a suggestion for that line.
  defp signer(%Artifact{signature: %{signer: id}}, opts) when is_binary(id) and id != "" do
    case trusted_signers(opts) do
      %{^id => public} when is_binary(public) and byte_size(public) == 32 ->
        {:ok, id, public}

      _absent ->
        {:error, {:signer_not_trusted_here, id}}
    end
  end

  defp signer(%Artifact{}, _opts), do: {:error, :unsigned_manifest}

  # `Ouroboros.Wasm.Boot`'s, verbatim: a named store root is honoured only where this build
  # allows one, which is this repository's test environment and nowhere else.
  defp store_opts(opts) do
    case Keyword.get(opts, :store_root) do
      root when is_binary(root) and root != "" ->
        if Ouroboros.Wasm.allow_store_root_override?(), do: [root: root], else: []

      _unset ->
        []
    end
  end

  defp trusted_signers(opts) do
    policy =
      Keyword.get_lazy(opts, :trust_policy, fn ->
        Application.get_env(:ouroboros, :upgrade_trust_policy, [])
      end)

    case Keyword.get(List.wrap(policy), :trusted_signers) do
      signers when is_map(signers) -> signers
      _absent -> %{}
    end
  end

  ## ── writing ───────────────────────────────────────────────────────────────────────────

  defp prepare(out) do
    case File.mkdir_p(out) do
      :ok -> :ok
      {:error, reason} -> {:error, {:export_directory_unusable, out, reason}}
    end
  end

  defp write(out, name, sha, tools, manifest, bundle, signer_id, public) do
    bundle_path = Path.join(out, name <> ".ouro-wasm")
    promotions_path = Path.join(out, @promotions)
    signers_path = Path.join(out, @signers)

    record =
      document(name, sha, tools, manifest, signer_id, Path.basename(bundle_path))

    with :ok <- put(bundle_path, bundle),
         :ok <- put(promotions_path, record),
         :ok <- put(signers_path, "#{signer_id}:#{Base.encode64(public)}\n") do
      Logger.info(
        "self export: #{name} at #{String.slice(sha, 0, 12)} signed by #{signer_id}, " <>
          "#{length(Map.keys(tools))} promoted tool(s) into #{out}"
      )

      {:ok,
       %{
         out: out,
         bundle: bundle_path,
         promotions: promotions_path,
         signers: signers_path,
         policy_name: name,
         component_sha256: sha,
         signer_id: signer_id,
         tools: tools |> Map.keys() |> Enum.sort(),
         bundle_bytes: byte_size(bundle)
       }}
    end
  end

  defp put(path, contents) do
    case File.write(path, contents) do
      :ok -> :ok
      {:error, reason} -> {:error, {:export_unwritable, path, reason}}
    end
  end

  @doc """
  The bytes `promotions.json` holds, for a caller that wants the record without a directory.

  Public so `Ouroboros.Self.Boot`'s tests can build one by hand and so the drift between
  what is written and what is read is one function rather than two literals.
  """
  @spec document(String.t(), String.t(), map(), Artifact.t(), String.t(), String.t()) :: binary()
  def document(name, sha, tools, %Artifact{} = manifest, signer_id, bundle) do
    json([
      {"version", @record_version},
      {"policy_name", name},
      {"component_sha256", sha},
      {"artifact_id", manifest.id},
      {"bundle", bundle},
      {"signer_id", signer_id},
      {"exported_at", DateTime.utc_now() |> DateTime.to_iso8601()},
      {"exported_by", Atom.to_string(node())},
      {"tools",
       tools
       |> Enum.sort_by(&elem(&1, 0))
       |> Enum.map(fn {tool, evidence} -> {tool, tool_document(evidence)} end)}
    ])
  end

  defp tool_document(evidence) when is_map(evidence) do
    [
      {"decisions", Map.get(evidence, :decisions, 0)},
      {"contradictions", Map.get(evidence, :contradictions, 0)},
      {"report_sha256", Map.get(evidence, :report_sha256, "")},
      {"replayed_at", Map.get(evidence, :replayed_at, "")}
    ]
  end

  defp tool_document(_other), do: []

  ## ── a deterministic pretty JSON, because a human reads this diff ──────────────────────

  # `JSON.encode!/1` on a map answers in whatever order the map iterates and on one line.
  # This file is committed by the outer loop's pull request and read by a person, so it is
  # written as an ordered list of pairs, two-space indented, and an export that changed
  # nothing but the timestamp produces a one-line diff.
  defp json(pairs), do: IO.iodata_to_binary([object(pairs, ""), ?\n])

  defp object([], _indent), do: "{}"

  defp object(pairs, indent) do
    inner = indent <> "  "

    [
      "{\n",
      pairs
      |> Enum.map(fn {key, term} ->
        [inner, JSON.encode!(to_string(key)), ": ", value(term, inner)]
      end)
      |> Enum.intersperse(",\n"),
      "\n",
      indent,
      "}"
    ]
  end

  defp value(pairs, indent) when is_list(pairs), do: object(pairs, indent)
  defp value(other, _indent), do: JSON.encode!(other)
end
