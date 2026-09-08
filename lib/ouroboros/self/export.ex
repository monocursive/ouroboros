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

  ## The directory it leaves behind

  Written into a staging directory beside the destination and moved in one `File.rename/2`
  per file, so a boot that reads `priv/self` while an export is running reads three whole
  files or the three that were there before — never a `promotions.json` naming a bundle that
  is half on disk.

  And it leaves **one** bundle. A policy renamed between two exports used to leave both, and
  `Ouroboros.Self.Boot` globs `*.ouro-wasm`, so the next installation deployed a policy
  nobody promoted beside the one somebody did. Every `*.ouro-wasm` this export did not write
  is removed and named in the report's `removed`. `README.md` is untouched: it is the
  repository's file, not an export's.

  `:out` may be confined with `:confine_to` — see `confine/2`. `mix ouroboros.self.export`
  always passes the repository root, so `--out` cannot write a signed bundle and a trust
  suggestion outside the checkout.

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
          bundle_bytes: pos_integer(),
          removed: [String.t()]
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
    with {:ok, out} <-
           confine(Keyword.get(opts, :out, @default_out), Keyword.get(opts, :confine_to)),
         {:ok, name, sha, tools} <- promoted(opts),
         {:ok, entry} <- live_entry(name, sha, opts),
         {:ok, manifest} <- manifest(entry, sha, opts),
         # Before the bundle is assembled, not after: this is the cheapest refusal of the
         # four and the only one about *trust*. A manifest nobody signed, or one signed by
         # an id this node's trust policy does not carry, has no `signers.txt` line to
         # write — and a bundle that arrives somewhere with no way to accept it is worse
         # than a refusal here. It also means the unsigned case is reachable at all:
         # `Bundle.encode/3` refuses a manifest with no signature first (`:signature_required`).
         {:ok, signer_id, public} <- signer(manifest, opts),
         {:ok, bytes} <- component(sha, opts),
         {:ok, precompiled} <- precompiled(manifest, opts),
         {:ok, bundle} <- Bundle.encode(manifest, bytes, precompiled) do
      write(out, name, sha, tools, manifest, bundle, signer_id, public)
    end
  end

  @doc """
  Resolves an `--out` and refuses one that leaves `root` (S4 fix wave, LOW-4).

  `nil` for `root` means the caller is inside this application and named a directory on
  purpose — a test's own temporary tree, say — and is not confined. Every operator-facing
  caller passes one: `mix ouroboros.self.export` passes the repository it is running in,
  because `--out ../../../somewhere` writing a signed bundle and a trust suggestion outside
  the checkout is a switch doing something its name does not say.

  Both sides are resolved before they are compared, and the *existing* prefix of the target
  is canonicalized through the filesystem, so a symlinked `priv/self` — or a `/tmp` that is
  really `/private/tmp` — is judged by where it actually lands rather than by how it was
  spelled. A path with no existing ancestor inside the root cannot pass.
  """
  @spec confine(Path.t(), Path.t() | nil) :: {:ok, Path.t()} | {:error, term()}
  def confine(out, nil) when is_binary(out), do: {:ok, out}

  def confine(out, root) when is_binary(out) and is_binary(root) do
    resolved = resolve(out)
    inside = resolve(root)

    if resolved == inside or String.starts_with?(resolved, inside <> "/") do
      {:ok, out}
    else
      {:error, {:out_escapes_root, resolved, inside}}
    end
  end

  def confine(out, root), do: {:error, {:invalid_export_path, out, root}}

  # `Path.expand/1` settles `..` and a relative spelling; `real/2` settles the symlinks,
  # which is the half that matters here — a `priv/self` that is a link to somewhere else *is*
  # somewhere else, and a prefix check on the spelling would call it inside.
  #
  # Written here rather than through `Ouroboros.Workspace.Path.canonicalize/1` because that
  # one insists the path be an existing directory (an export may be the thing that creates
  # it) and refuses a path that crosses two links as a cycle, which `/tmp` on a Mac plus a
  # symlinked `priv/self` is. Component by component, bounded, and a name with nothing behind
  # it is kept as written.
  defp resolve(path), do: real(Path.expand(path), 0)

  @max_link_depth 32

  defp real(path, depth) when depth > @max_link_depth, do: path
  defp real("/", _depth), do: "/"

  defp real(path, depth) do
    parent = real(Path.dirname(path), depth)
    joined = Path.join(parent, Path.basename(path))

    case File.read_link(joined) do
      {:ok, target} ->
        absolute =
          if Path.type(target) == :absolute, do: target, else: Path.join(parent, target)

        real(Path.expand(absolute), depth + 1)

      {:error, _not_a_link} ->
        joined
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

  # S4 fix wave (MEDIUM-3). Written into a fresh directory beside the destination and moved
  # in, rather than written over the destination in place.
  #
  # Two reasons, and the second is the finding. A partly written export is a `priv/self` a
  # boot would read: three files whose `promotions.json` names a bundle that is half on disk.
  # A `File.rename/2` within one filesystem is atomic, so each of the three either is the new
  # file or is still the old one, and the staging directory is a sibling of the destination so
  # the rename never crosses a device. And the *previous* export's bundle is only replaced
  # when it had the same name: a policy renamed between two exports left both files here, and
  # `Ouroboros.Self.Boot` globs `*.ouro-wasm` — so the next install deployed a policy nobody
  # promoted, alongside the one somebody did. Anything ending `.ouro-wasm` that this export
  # did not write is removed, and the report says which.
  #
  # The directory is not replaced wholesale, deliberately: `priv/self/README.md` is committed
  # beside these three files and is not an export's to delete.
  defp stage(out) do
    staging =
      out <>
        ".tmp-#{System.unique_integer([:positive, :monotonic])}-" <>
        Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

    with :ok <- mkdir(out),
         :ok <- mkdir(staging) do
      {:ok, staging}
    end
  end

  defp mkdir(path) do
    case File.mkdir_p(path) do
      :ok -> :ok
      {:error, reason} -> {:error, {:export_directory_unusable, path, reason}}
    end
  end

  defp write(out, name, sha, tools, manifest, bundle, signer_id, public) do
    basename = name <> ".ouro-wasm"

    record = document(name, sha, tools, manifest, signer_id, basename)
    signers = "#{signer_id}:#{Base.encode64(public)}\n"

    with {:ok, staging} <- stage(out) do
      try do
        with :ok <- put(staging, basename, bundle),
             :ok <- put(staging, @promotions, record),
             :ok <- put(staging, @signers, signers),
             :ok <- publish(staging, out, [basename, @promotions, @signers]) do
          removed = sweep(out, basename)
          settled(out, basename, name, sha, tools, signer_id, bundle, removed)
        end
      after
        File.rm_rf(staging)
      end
    end
  end

  defp settled(out, basename, name, sha, tools, signer_id, bundle, removed) do
    Logger.info(
      "self export: #{name} at #{String.slice(sha, 0, 12)} signed by #{signer_id}, " <>
        "#{length(Map.keys(tools))} promoted tool(s) into #{out}" <> removed_detail(removed)
    )

    {:ok,
     %{
       out: out,
       bundle: Path.join(out, basename),
       promotions: Path.join(out, @promotions),
       signers: Path.join(out, @signers),
       policy_name: name,
       component_sha256: sha,
       signer_id: signer_id,
       tools: tools |> Map.keys() |> Enum.sort(),
       bundle_bytes: byte_size(bundle),
       removed: removed
     }}
  end

  defp removed_detail([]), do: ""

  defp removed_detail(removed),
    do: "; removed #{length(removed)} stale bundle(s): " <> Enum.join(removed, ", ")

  defp put(dir, basename, contents) do
    path = Path.join(dir, basename)

    case File.write(path, contents) do
      :ok -> :ok
      {:error, reason} -> {:error, {:export_unwritable, path, reason}}
    end
  end

  # One rename per file. Not a directory swap: `README.md` lives here too and belongs to the
  # repository rather than to an export.
  defp publish(staging, out, names) do
    Enum.reduce_while(names, :ok, fn basename, :ok ->
      source = Path.join(staging, basename)
      destination = Path.join(out, basename)

      case File.rename(source, destination) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, {:export_unwritable, destination, reason}}}
      end
    end)
  end

  # Every other `*.ouro-wasm` in the directory: an earlier export's bundle under a name this
  # policy no longer has. They are not the promoted policy and `Ouroboros.Self.Boot` would
  # read them as if they were.
  defp sweep(out, keep) do
    out
    |> Path.join("*.ouro-wasm")
    |> Path.wildcard()
    |> Enum.map(&Path.basename/1)
    |> Enum.reject(&(&1 == keep))
    |> Enum.sort()
    |> Enum.filter(&(File.rm(Path.join(out, &1)) == :ok))
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
