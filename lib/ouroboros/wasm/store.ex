defmodule Ouroboros.Wasm.Store do
  @moduledoc """
  Content-addressed component bytes at `<data_dir>/wasm/components/sha256-<hex>.wasm`.

  Lane W keeps its bytes, deliberately (docs/WASM.md §7.4). That is a divergence from the
  BEAM lane, where the source dies at promote, and it buys three things that lane cannot
  have: **reboot survival** — a `:live` wasm capability restarts from store plus registry —
  **re-forge**, because v2 can diff against v1's actual bytes, and **rollback material that
  never expires**, because rollback here is "stop the instances" and the old bytes are still
  on disk if an operator wants them back.

  ## Plain functions, and why that is safe

  There is no process here. Two callers publishing the same component concurrently is the
  normal case — a rollout stages the same sha on the same node twice, a retry repeats a
  put — and content addressing plus publish-once makes it benign without a lock: each writer
  writes its own uniquely-named temporary file, syncs it, and then *links* it into place.
  Exactly one link wins; every loser reads the published file back, checks its digest, and
  succeeds because the bytes under a sha are the bytes of that sha or the file is corrupt.
  Nothing is ever overwritten, so no writer can be interrupted into publishing a partial
  component, and a reader mid-put sees either the old file or the whole new one.

  The write discipline is `Ouroboros.Release.PackageStager`'s, for the same reason it has
  one: the digest is validated against the bytes before anything is written, the data is
  synced before it is published, the publish is a link rather than a rename because a rename
  would silently overwrite, and the directory is synced before success is claimed.

  ## Reading is verifying

  `fetch/2` re-derives the digest from what it read. A file whose bytes no longer hash to
  its own name is an error naming that sha, never bytes handed back quietly: the whole
  security story downstream — the signed manifest, the helper's own `sha_mismatch` refusal —
  rests on the name of a component meaning its content.

  ## Manifests live here too, and that is what makes reboot survival real

  Bytes alone do not restart a capability. `put_manifest/2` writes the signed
  `Ouroboros.Wasm.Artifact` beside them as `manifest-<hex>.manifest`, where the hex is the
  sha256 of the **artifact id** — a name that is path-safe by construction, injective, and
  resolvable from the one field a rollout registry entry already carries. The registry
  keeps the component sha and nothing else (docs/WASM.md D6, §3.4): bytes and manifest
  survive in the store, and the register stays a register.

  The manifest is written with the same publish-once discipline as the bytes, and two
  different manifests under one artifact id is `{:manifest_conflict, id}` rather than a
  silent overwrite. It is read back with `[:safe]`, so a manifest file cannot intern an
  atom into a rebooting VM; an atom this VM has never heard of makes the read a named
  refusal instead. See `decode_manifest/2` for why this boundary is *not*
  `Ouroboros.Upgrade.Wire`, which the registry and the signing journal both use.

  Manifests are **not** pruned. They are on the order of a kilobyte, one per rollout that
  ever reached a checkpoint, and they are evidence for exactly the reason §7.4 keeps
  quarantined bytes: the record of what a node was told to run outlives the decision to
  stop running it.

  Not pruned is not the same as not counted. `list/1` reports them beside the components,
  tagged `kind: :manifest`, and their bytes count against the prune budget — a budget that
  ignored a whole class of files in the directory it governs was a budget the store
  exceeded quietly. What a prune *evicts* is still components only.

  A manifest is also bounded on the way in, at the same ceiling `fetch_manifest/2` reads
  under: publishing one this store would later refuse to read is publishing a durable,
  unprunable file that no reboot can use.

  ## Two forms, both content-addressed (W8)

  `put_precompiled/3` publishes wasmtime's serialized form of a component under the digest of
  the artifact itself, `cwasm-<hex>.cwasm`. It is the same discipline as the bytes — digest
  validated before the write, synced, linked into place, never overwritten — because it is the
  same problem: the helper is about to `Component::deserialize` this file, which is `unsafe`,
  and what makes that sound is that the file's name is its content and its content is what a
  trusted signer signed (D24).

  `form/4` is where a node decides which of the two to hand the helper. It answers
  `{:precompiled, path, sha}` only when the manifest declares a block, this node's helper
  reports **exactly** that wasmtime and that target triple, and the file is on disk; anything
  else is `{:source, path}` with a reason naming which half disagreed. Falling back is not a
  failure — every node can always compile the source form under §7.3's bounds — so the reason
  is for a log line, never for a refusal.

  ## Pruning fails closed

  The store is bounded by a byte budget (`:store_budget_bytes`, see `Ouroboros.Wasm`) and
  `prune/1` evicts oldest-first to get back under it. It never evicts a sha that a rollout
  registry entry references while it is `:live` or `:deploying`, and it keeps `:quarantined`
  bytes because those are evidence about an ambiguous deploy. If the registry cannot be
  read at all, nothing is evicted: bytes on disk are cheap and evicting a referenced
  component to save them is not a trade this store gets to make on its own.

  ## No data directory, no store

  A node with no `:data_dir` — a library start, most of the test suite — gets
  `{:error, :no_data_dir}` rather than a temp-directory fallback. Every other caller of this
  store wants reboot survival; a store under `/tmp` would be one that quietly is not one.
  """

  alias Ouroboros.Upgrade.Rollout
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Artifact

  @prefix "sha256-"
  @suffix ".wasm"
  @manifest_prefix "manifest-"
  @manifest_suffix ".manifest"
  # W8. The precompiled form of a component, content-addressed by **its own** digest and not by
  # the component's: one component can have several, one per wasmtime-and-triple pair a signer
  # ever compiled it for, and naming them after the component would make two honest artifacts a
  # conflict. Publish-once, verified on read, exactly like the bytes beside them.
  @precompiled_prefix "cwasm-"
  @precompiled_suffix ".cwasm"
  @temp_infix ".tmp-"

  # A manifest is roughly a kilobyte: an id, an epoch, a digest, and a bounded eval spec
  # (`Rollout.Evaluation` caps a spec at 16 KiB). This ceiling is generous by three orders
  # of magnitude and exists so a file in this directory cannot be read into memory unbounded.
  @max_manifest_bytes 1024 * 1024

  # How old a `.tmp-*` file must be before `prune/1` sweeps it. Comfortably longer than any
  # single `put` takes, so a concurrent writer's own in-flight temp — created moments ago —
  # is never mistaken for a crash's leftover and removed out from under it.
  @temp_grace_seconds 3_600

  # The registry states whose components must survive a prune. `:live` and `:deploying` are
  # referenced now; `:quarantined` is the evidence for a deploy nobody has resolved.
  @protected_states [:live, :deploying, :quarantined]

  @typedoc """
  One file the store holds.

  `kind` says which: `:component` for bytes, whose `sha256` is the digest of the content;
  `:precompiled` for wasmtime's serialized form of one, whose `sha256` is likewise the digest
  of the content; `:manifest` for a signed manifest, whose `sha256` is the digest of the
  artifact id the file is named for. All three are "the name this file is published under",
  which is what a listing is about; a manifest is never a prune candidate and the other two
  always are.
  """
  @type entry :: %{
          kind: :component | :manifest | :precompiled,
          sha256: String.t(),
          path: String.t(),
          size: non_neg_integer(),
          mtime: integer()
        }

  @doc """
  The directory this node's components live in, without creating it.

  `:root` in `opts` names a different directory, which is how tests get one of their own.
  It is honoured only where `Ouroboros.Wasm.allow_store_root_override?/0` is true — the
  same gate `Capability`, `PolicyEngine`, `Rollout` and `Boot` already applied — so a
  caller that forgets the gate cannot point this store at an arbitrary directory. A
  seeded root on a node that has not said so is `{:error, :store_root_override_denied}`,
  not a silent fall-through to `:data_dir`.
  """
  @spec root(keyword()) ::
          {:ok, String.t()} | {:error, :no_data_dir | :store_root_override_denied}
  def root(opts \\ []) do
    case Keyword.get(opts, :root) do
      dir when is_binary(dir) and dir != "" ->
        if Wasm.allow_store_root_override?(),
          do: {:ok, dir},
          else: {:error, :store_root_override_denied}

      _unset ->
        case Application.get_env(:ouroboros, :data_dir) do
          dir when is_binary(dir) and dir != "" -> {:ok, Path.join([dir, "wasm", "components"])}
          _unset -> {:error, :no_data_dir}
        end
    end
  end

  @doc """
  Publishes `bytes` under the sha they actually hash to.

  `expected_sha256` is checked against the recomputed digest and refused on mismatch; it is
  the caller saying which component it believes it is holding, and a mismatch means one of
  the two is wrong. Publishing is once: an existing file for that sha is verified, never
  rewritten, and `published: false` says so.
  """
  @spec put(binary(), String.t() | nil, keyword()) ::
          {:ok,
           %{sha256: String.t(), path: String.t(), size: non_neg_integer(), published: boolean()}}
          | {:error, term()}
  def put(bytes, expected_sha256 \\ nil, opts \\ []) when is_binary(bytes) do
    actual = digest(bytes)

    with :ok <- check_expected(expected_sha256, actual),
         {:ok, dir} <- root(opts),
         :ok <- ensure_directory(dir),
         path = component_path(dir, actual),
         {:ok, published} <- publish_once(path, bytes, actual, :component, actual) do
      {:ok, %{sha256: actual, path: path, size: byte_size(bytes), published: published}}
    end
  end

  @doc """
  Publishes one precompiled artifact under the digest it actually hashes to (W8).

  `expected_sha256` is the digest the signed manifest names for this form, checked against the
  recomputed one and refused on mismatch — the same posture `put/3` takes, and for a stronger
  reason: these bytes are machine code a helper will map without validating them, so the one
  moment to find out they are not the signed ones is before they are on disk under a name that
  says they are.
  """
  @spec put_precompiled(binary(), String.t(), keyword()) ::
          {:ok,
           %{sha256: String.t(), path: String.t(), size: non_neg_integer(), published: boolean()}}
          | {:error, term()}
  def put_precompiled(bytes, expected_sha256, opts \\ [])
      when is_binary(bytes) and is_binary(expected_sha256) do
    actual = digest(bytes)

    with :ok <- check_expected(expected_sha256, actual),
         {:ok, dir} <- root(opts),
         :ok <- ensure_directory(dir),
         path = precompiled_path_at(dir, actual),
         {:ok, published} <- publish_once(path, bytes, actual, :precompiled, actual) do
      {:ok, %{sha256: actual, path: path, size: byte_size(bytes), published: published}}
    end
  end

  @doc """
  Publishes the signed manifest for a rollout, beside the bytes it describes.

  Keyed by the artifact id, so one rollout has one manifest and a redeploy of the same
  component under a new manifest does not have to displace an older one. Publishing is
  once: an identical manifest already on disk is `published: false`, and a *different*
  manifest under the same artifact id is `{:manifest_conflict, id}` — the register refuses
  a duplicate artifact id for the same reason, and the store does not get to disagree.
  """
  @spec put_manifest(Artifact.t(), keyword()) ::
          {:ok, %{artifact_id: String.t(), path: String.t(), published: boolean()}}
          | {:error, term()}
  def put_manifest(artifact, opts \\ [])

  def put_manifest(%Artifact{id: id} = artifact, opts) when is_binary(id) and id != "" do
    with {:ok, payload} <- encode_manifest(artifact),
         :ok <- ensure_writable_size(payload, id),
         {:ok, dir} <- root(opts),
         :ok <- ensure_directory(dir),
         path = manifest_path(dir, id),
         {:ok, published} <- publish_once(path, payload, digest(payload), :manifest, id) do
      {:ok, %{artifact_id: id, path: path, published: published}}
    end
  end

  def put_manifest(artifact, _opts), do: {:error, {:invalid_manifest, describe(artifact)}}

  @doc """
  The signed manifest recorded under `artifact_id`, or a named reason it is unusable.

  Decoding is `[:safe]`, so a manifest naming an atom this VM has never interned comes
  back as a manifest whose signature no longer verifies rather than as an atom this VM
  now holds. Both outcomes are refusals downstream; only one of them writes to the atom
  table.
  """
  @spec fetch_manifest(String.t(), keyword()) :: {:ok, Artifact.t()} | {:error, term()}
  def fetch_manifest(artifact_id, opts \\ []) when is_binary(artifact_id) do
    with {:ok, dir} <- root(opts) do
      path = manifest_path(dir, artifact_id)

      with :ok <- ensure_manifest_size(path, artifact_id),
           {:ok, payload} <- read_manifest(path, artifact_id) do
        decode_manifest(payload, artifact_id)
      end
    end
  end

  @doc "The bytes for `sha256`, with the digest re-derived from what was read."
  @spec fetch(String.t(), keyword()) :: {:ok, binary()} | {:error, term()}
  def fetch(sha256, opts \\ []) when is_binary(sha256) do
    with {:ok, sha} <- normalize(sha256),
         {:ok, dir} <- root(opts),
         path = component_path(dir, sha),
         {:ok, bytes} <- read(path, sha) do
      if digest(bytes) == sha,
        do: {:ok, bytes},
        else: {:error, {:corrupt_component, sha}}
    end
  end

  @doc "Where `sha256` is on disk, if it is there at all. The helper is handed this path."
  @spec path(String.t(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def path(sha256, opts \\ []) when is_binary(sha256) do
    with {:ok, sha} <- normalize(sha256),
         {:ok, dir} <- root(opts) do
      path = component_path(dir, sha)
      if regular_file?(path), do: {:ok, path}, else: {:error, {:unknown_component, sha}}
    end
  end

  @doc """
  Where the precompiled artifact `sha256` is on disk, if it is there **and still hashes to its
  own name** (W8).

  `verify: false` skips the digest and answers on presence alone.

  The default verifies, and that is not belt and braces: the helper is about to
  `Component::deserialize` this file, which wasmtime does not validate, so "the name of a file
  means its content" is load-bearing here in a way it is not for a component — a component that
  rotted is refused by the helper's own `sha_mismatch` before anything is compiled, and a
  rotted *artifact* would be mapped. It costs one read and one sha256: 0.4 ms for the 258 KiB
  reference artifact and about 25 ms for the 11 MiB worst case, against a 37 ms mapping, and it
  happens once per component per helper lifetime because the helper caches what it holds.

  `wasm.list` asks with `verify: false`, because a listing that digested fifty artifacts to
  draw a column would be a `:read` verb doing a second's work.
  """
  @spec precompiled_path(String.t(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def precompiled_path(sha256, opts \\ []) when is_binary(sha256) do
    with {:ok, sha} <- normalize(sha256),
         {:ok, dir} <- root(opts) do
      path = precompiled_path_at(dir, sha)

      cond do
        not regular_file?(path) -> {:error, {:unknown_precompiled, sha}}
        Keyword.get(opts, :verify, true) != true -> {:ok, path}
        true -> verified_precompiled(path, sha)
      end
    end
  end

  defp verified_precompiled(path, sha) do
    case File.read(path) do
      {:ok, bytes} ->
        if digest(bytes) == sha,
          do: {:ok, path},
          else: {:error, {:corrupt_precompiled, sha}}

      {:error, reason} ->
        {:error, {:precompiled_unreadable, sha, reason}}
    end
  end

  @doc """
  Which form of `component_sha256` this node should hand the helper, and why (W8, D22/D24).

  `precompiled` is the signed manifest's block or `nil`; `helper` is what this node's own helper
  reported — `%{"wasmtime" => version, "target" => triple}` out of its `doctor` — or `nil` when
  no helper has answered yet, or a **zero-arity function** answering one of those.

  The function form is the one every caller uses, and it is not a style: asking the pool is a
  `GenServer.call` that connects a lazy helper, and a manifest with no `precompiled` block has
  no comparison to make. So the question is asked only when there is something to compare,
  which keeps "a component the store does not hold never reaches the helper" true — it is what
  a wrapper does on the message path, and spawning a helper to discover a missing file would be
  the opposite of that. The precompiled form is chosen only when **every** one of those
  agrees: a block exists, the version matches exactly, the triple matches exactly, and the file
  is on disk. Otherwise the source form, with a reason.

  The comparison is string equality on both halves and nothing cleverer. A version ordering
  would be a policy about which wasmtime can read which artifact, and wasmtime does not make
  that promise: its serialized form is checked against an exact build and an exact configuration
  hash, so "close enough" is a decision nobody here is entitled to make.

  This function decides *which bytes*, never *whether to trust them*: by the time it is called
  the manifest has been verified against this node's own trust policy, which is where the signer
  is bound (D24). It is a private seam of lane W rather than a general lookup for that reason.
  """
  @spec form(String.t(), map() | nil, map() | nil | (-> map() | nil), keyword()) ::
          {:precompiled, String.t(), String.t()}
          | {:source, String.t(), atom() | tuple()}
          | {:error, term()}
  def form(component_sha256, precompiled, helper, opts \\ []) when is_binary(component_sha256) do
    case path(component_sha256, opts) do
      {:ok, source} -> {:source, source, why(precompiled, helper)} |> upgrade(precompiled, opts)
      {:error, reason} -> {:error, reason}
    end
  end

  # The precompiled branch, taken only when nothing disagreed and the file is there and still
  # hashes to its name. Written as an upgrade of the source answer rather than as a branch in
  # front of it so the source path is resolved either way: a node whose store lost the component
  # has a problem the fast form does not fix, and it should hear about that one.
  defp upgrade({:source, source, :usable}, %{sha256: sha}, opts) do
    case precompiled_path(sha, opts) do
      {:ok, path} -> {:precompiled, path, sha}
      {:error, {:unknown_precompiled, _sha}} -> {:source, source, :precompiled_not_stored}
      {:error, reason} -> {:source, source, {:precompiled_unusable, reason}}
    end
  end

  defp upgrade(answer, _precompiled, _opts), do: answer

  # The block first, so a manifest that declares none never asks the pool anything and never
  # renders as though an operator had refused something that was not offered. Then the
  # operator's fleet-wide switch, because a node that refuses the form has nothing to compare
  # (docs/WASM.md D24).
  defp why(nil, _helper), do: :not_precompiled

  defp why(precompiled, helper) do
    if Wasm.accept_precompiled?(),
      do: compare(precompiled, helper),
      else: :precompiled_refused_here
  end

  defp compare(nil, _helper), do: :not_precompiled

  defp compare(precompiled, helper) when is_function(helper, 0),
    do: compare(precompiled, helper.())

  defp compare(_precompiled, nil), do: :helper_build_unknown

  defp compare(%{wasmtime: wasmtime, target: target}, helper) when is_map(helper) do
    cond do
      Map.get(helper, "wasmtime") != wasmtime ->
        {:wasmtime_mismatch, wasmtime, Map.get(helper, "wasmtime")}

      Map.get(helper, "target") != target ->
        {:target_mismatch, target, Map.get(helper, "target")}

      true ->
        :usable
    end
  end

  defp compare(_precompiled, _helper), do: :helper_build_unknown

  @doc """
  Every file held, oldest first, with sizes and a `:kind`.

  Manifests are listed beside components and precompiled artifacts. They are never evicted,
  but they are bytes on the disk this store's budget is about, and a listing that did not
  show them was a listing an operator could not reconcile against `du`. Filter on `:kind`
  for one of the three; `components/1` is the shorthand for the source form.
  """
  @spec list(keyword()) :: {:ok, [entry()]} | {:error, term()}
  def list(opts \\ []) do
    with {:ok, dir} <- root(opts) do
      case File.ls(dir) do
        {:ok, names} -> {:ok, names |> Enum.flat_map(&entry(dir, &1)) |> Enum.sort_by(& &1.mtime)}
        {:error, :enoent} -> {:ok, []}
        {:error, reason} -> {:error, {:store_unreadable, dir, reason}}
      end
    end
  end

  @doc "The evictable half of `list/1`: the files a prune may consider."
  @spec components(keyword()) :: {:ok, [entry()]} | {:error, term()}
  def components(opts \\ []) do
    with {:ok, entries} <- list(opts) do
      {:ok, Enum.filter(entries, &(&1.kind == :component))}
    end
  end

  @doc "Forgets one component. Idempotent: a sha that is not held is already forgotten."
  @spec delete(String.t(), keyword()) :: :ok | {:error, term()}
  def delete(sha256, opts \\ []) when is_binary(sha256),
    do: delete(sha256, :component, opts)

  @doc """
  Forgets one file of either evictable kind. Idempotent, for `delete/2`'s reason.

  `kind` is `:component` or `:precompiled` (W8). Both are content-addressed, both are prune
  candidates, and both therefore need a way to be let go by name.
  """
  @spec delete(String.t(), :component | :precompiled, keyword()) :: :ok | {:error, term()}
  def delete(sha256, kind, opts)
      when is_binary(sha256) and kind in [:component, :precompiled] and is_list(opts) do
    with {:ok, sha} <- normalize(sha256),
         {:ok, dir} <- root(opts) do
      path =
        case kind do
          :component -> component_path(dir, sha)
          :precompiled -> precompiled_path_at(dir, sha)
        end

      case File.rm(path) do
        :ok -> :ok
        {:error, :enoent} -> :ok
        {:error, reason} -> {:error, {undeletable(kind), sha, reason}}
      end
    end
  end

  defp undeletable(:component), do: :component_undeletable
  defp undeletable(:precompiled), do: :precompiled_undeletable

  @doc """
  Evicts unreferenced bytes — components and precompiled artifacts alike — oldest first,
  until the store is under its byte budget.

  Also sweeps stale `.tmp-*` files, because a crash mid-`put` leaves one behind:
  `sha256-<hex>.wasm.tmp-<rand>`, which `list/1` does not see (it does not end in `.wasm`)
  and which nothing else removes, so real bytes on disk would exceed the budget while this
  otherwise reported success. Only temps older than a grace window are swept, so a
  concurrent `put`'s own in-flight temp is never removed.

  Fails closed: an unreadable registry evicts nothing (but stale temps are still swept —
  a leaked temp references nothing).
  """
  @spec prune(keyword()) ::
          {:ok,
           %{
             evicted: [String.t()],
             reclaimed: non_neg_integer(),
             bytes: non_neg_integer(),
             swept: [String.t()]
           }}
          | {:error, term()}
  def prune(opts \\ []) do
    with {:ok, dir} <- root(opts),
         swept = sweep_stale_temps(dir, opts),
         {:ok, entries} <- list(opts),
         {:ok, protected} <- protected_shas(opts) do
      budget = budget(opts)

      # Every file counts against the budget, manifests included: they are not evictable,
      # but they are on the disk, and a budget that ignored them was a budget the store
      # exceeded quietly. What is *evictable* is the two content-addressed kinds.
      held = Enum.reduce(entries, 0, &(&1.size + &2))

      {evicted, reclaimed} =
        entries
        # W8. Both content-addressed kinds are candidates. A precompiled artifact is several
        # times the component it came from, so a budget that could not evict one was a budget
        # the fast path would quietly walk through.
        |> Enum.filter(&(&1.kind in [:component, :precompiled]))
        |> Enum.reject(&MapSet.member?(protected, &1.sha256))
        |> Enum.reduce_while({[], 0}, fn entry, {shas, freed} ->
          if held - freed <= budget do
            {:halt, {shas, freed}}
          else
            case delete(entry.sha256, entry.kind, opts) do
              :ok -> {:cont, {[entry.sha256 | shas], freed + entry.size}}
              {:error, _reason} -> {:cont, {shas, freed}}
            end
          end
        end)

      {:ok,
       %{
         evicted: Enum.reverse(evicted),
         reclaimed: reclaimed,
         bytes: held - reclaimed,
         swept: swept
       }}
    end
  end

  @doc """
  The shas no prune may evict, read from what the rollout registry records.

  Checkpoint v3 carries `component_sha256` on every entry (docs/WASM.md §7.6), so a
  `:live`, `:deploying`, or `:quarantined` lane-W rollout protects the bytes it names. The
  field is still read tolerantly: a lane-B entry carries `nil` and protects nothing, which
  is correct — it deployed modules, not components.

  W8 adds the second form. The register does not name it — identity is the component (D2) —
  so the protected artifact digest is read out of the **manifest** the entry's `artifact_id`
  points at, which is one small file per protected row. An entry whose manifest cannot be read
  protects its component and nothing else, which is the fail-open direction for a *prune* and
  costs a recompile rather than a capability.
  """
  @spec protected_shas(keyword()) :: {:ok, MapSet.t(String.t())} | {:error, :registry_unavailable}
  def protected_shas(opts \\ []) do
    registry = Keyword.get(opts, :registry, Rollout.Registry)

    entries = Rollout.Registry.list(registry)

    protected =
      entries
      |> Enum.filter(&(Map.get(&1, :state) in @protected_states))
      |> Enum.flat_map(&(component_shas(&1) ++ precompiled_shas(&1, opts)))
      |> MapSet.new()

    {:ok, protected}
  rescue
    # A registry whose entries this build cannot read is as unavailable as one that is not
    # running: either way nothing here knows what is referenced, so nothing here evicts.
    _error -> {:error, :registry_unavailable}
  catch
    # A registry that is not running is not a registry that says "nothing is referenced".
    :exit, _reason -> {:error, :registry_unavailable}
  end

  defp component_shas(entry) do
    case normalize(Map.get(entry, :component_sha256)) do
      {:ok, sha} -> [sha]
      _absent_or_malformed -> []
    end
  end

  defp precompiled_shas(entry, opts) do
    with id when is_binary(id) <- Map.get(entry, :artifact_id),
         {:ok, %Artifact{precompiled: %{sha256: sha}}} <- fetch_manifest(id, opts),
         {:ok, normalized} <- normalize(sha) do
      [normalized]
    else
      _absent_or_unreadable -> []
    end
  end

  defp budget(opts) do
    case Keyword.get(opts, :budget_bytes) do
      value when is_integer(value) and value >= 0 -> value
      _absent -> Wasm.config(:store_budget_bytes)
    end
  end

  defp sweep_stale_temps(dir, opts) do
    cutoff = System.os_time(:second) - temp_grace_seconds(opts)

    case File.ls(dir) do
      {:ok, names} ->
        names
        |> Enum.filter(&temp_name?/1)
        |> Enum.flat_map(fn name -> sweep_one(Path.join(dir, name), name, cutoff) end)

      # No directory yet is no temps to sweep. An unreadable one is not this function's to
      # report; `list/1` right after it surfaces that.
      {:error, _reason} ->
        []
    end
  end

  # The shape a temporary carries: the published basename, then `.tmp-`, then random bytes.
  # Real components end in `.wasm` and real manifests in `.manifest`, so neither matches.
  # Manifest temps are swept for the same reason component temps are: a crash mid-publish
  # leaves one, `list/1` does not see it, and nothing else would ever remove it.
  defp temp_name?(name) do
    (String.starts_with?(name, @prefix) and String.contains?(name, @suffix <> @temp_infix)) or
      (String.starts_with?(name, @precompiled_prefix) and
         String.contains?(name, @precompiled_suffix <> @temp_infix)) or
      (String.starts_with?(name, @manifest_prefix) and
         String.contains?(name, @manifest_suffix <> @temp_infix))
  end

  defp sweep_one(path, name, cutoff) do
    with {:ok, %{type: :regular, mtime: mtime}} when mtime <= cutoff <-
           File.lstat(path, time: :posix),
         :ok <- File.rm(path) do
      [name]
    else
      _kept_or_gone -> []
    end
  end

  defp temp_grace_seconds(opts) do
    case Keyword.get(opts, :temp_grace_seconds) do
      value when is_integer(value) and value >= 0 -> value
      _absent -> @temp_grace_seconds
    end
  end

  defp check_expected(nil, _actual), do: :ok

  defp check_expected(expected, actual) when is_binary(expected) do
    case normalize(expected) do
      {:ok, ^actual} -> :ok
      {:ok, other} -> {:error, {:sha_mismatch, other, actual}}
      {:error, _reason} -> {:error, {:invalid_sha256, expected}}
    end
  end

  defp check_expected(other, _actual), do: {:error, {:invalid_sha256, other}}

  defp normalize(sha) when is_binary(sha) do
    lower = String.downcase(sha)
    if lower =~ ~r/\A[0-9a-f]{64}\z/, do: {:ok, lower}, else: {:error, {:invalid_sha256, sha}}
  end

  defp normalize(other), do: {:error, {:invalid_sha256, other}}

  defp component_path(dir, sha), do: Path.join(dir, @prefix <> sha <> @suffix)

  defp precompiled_path_at(dir, sha),
    do: Path.join(dir, @precompiled_prefix <> sha <> @precompiled_suffix)

  # Derived, never interpolated: an artifact id is a caller-supplied string, and the one
  # safe thing to build a filename out of is its digest. It is injective, it is 64 hex
  # characters whatever the id was, and it cannot walk out of this directory.
  defp manifest_path(dir, artifact_id),
    do: Path.join(dir, @manifest_prefix <> digest(artifact_id) <> @manifest_suffix)

  # The same ceiling `fetch_manifest/2` reads under, applied on the way in. A store that
  # accepted a manifest it would later refuse to read published a file that is durable,
  # protected from pruning, and useless: the reboot restart that needs it reports
  # `{:manifest_unusable, {:manifest_too_large, _, _}}` forever, and nothing rewrites it.
  # One bound, both directions.
  defp ensure_writable_size(payload, artifact_id) do
    if byte_size(payload) <= @max_manifest_bytes,
      do: :ok,
      else: {:error, {:manifest_too_large, artifact_id, byte_size(payload)}}
  end

  # The rest of this store validates a digest before it reads bytes; a manifest has no name
  # to check itself against, so what bounds it is its size. A real one is on the order of a
  # kilobyte, and nothing that reaches a megabyte is a manifest this build wrote.
  defp ensure_manifest_size(path, artifact_id) do
    case File.stat(path) do
      {:ok, %{type: :regular, size: size}} when size <= @max_manifest_bytes ->
        :ok

      {:ok, %{type: :regular, size: size}} ->
        {:error, {:manifest_too_large, artifact_id, size}}

      {:ok, %{type: type}} ->
        {:error, {:invalid_manifest_file, artifact_id, type}}

      {:error, :enoent} ->
        {:error, {:unknown_manifest, artifact_id}}

      {:error, reason} ->
        {:error, {:manifest_unreadable, artifact_id, reason}}
    end
  end

  defp read_manifest(path, artifact_id) do
    case File.read(path) do
      {:ok, payload} -> {:ok, payload}
      {:error, :enoent} -> {:error, {:unknown_manifest, artifact_id}}
      {:error, reason} -> {:error, {:manifest_unreadable, artifact_id, reason}}
    end
  end

  defp encode_manifest(%Artifact{} = artifact) do
    {:ok, :erlang.term_to_binary(artifact, [:deterministic])}
  rescue
    error -> {:error, {:invalid_manifest, Exception.message(error)}}
  end

  # `[:safe]`, like every other file boundary in this codebase: a manifest must not be able
  # to intern an atom into the VM that reads it.
  #
  # Deliberately *not* through `Ouroboros.Upgrade.Wire`, which the rollout registry and the
  # signing journal both use. Wire encodes an atom map key as a string and resolves any
  # string key back to an existing atom, which is exact for a checkpoint whose keys are all
  # atoms and lossy for a manifest whose keys are not: a signed eval spec's `input` is a
  # JSON body with **string** keys, and turning `%{"n" => 1}` into `%{n: 1}` would silently
  # change the thing the signature covers. Wire exists because a lane-B checkpoint names
  # forged module atoms a rebooted VM has never interned; a lane-W manifest names no
  # forged atom at all (docs/WASM.md D2), so the plain round-trip is both exact and safe.
  #
  # An atom this VM has genuinely never interned makes `[:safe]` raise, and that is a
  # refusal here rather than a repair: the caller gets `{:unreadable_manifest, id}`.
  defp decode_manifest(payload, artifact_id) do
    case :erlang.binary_to_term(payload, [:safe]) do
      %Artifact{id: ^artifact_id} = artifact -> {:ok, artifact}
      %Artifact{id: other} -> {:error, {:manifest_identity_mismatch, artifact_id, other}}
      _other -> {:error, {:invalid_manifest, artifact_id}}
    end
  rescue
    _error -> {:error, {:unreadable_manifest, artifact_id}}
  catch
    _kind, _reason -> {:error, {:unreadable_manifest, artifact_id}}
  end

  defp entry(dir, name) do
    case published_name(name) do
      {:ok, kind, sha} -> stat_entry(dir, name, kind, sha)
      :error -> []
    end
  end

  defp published_name(@prefix <> rest = _component) do
    with true <- String.ends_with?(rest, @suffix),
         hex = binary_part(rest, 0, byte_size(rest) - byte_size(@suffix)),
         {:ok, sha} <- normalize(hex) do
      {:ok, :component, sha}
    else
      _not_a_component -> :error
    end
  end

  defp published_name(@precompiled_prefix <> rest = _precompiled) do
    with true <- String.ends_with?(rest, @precompiled_suffix),
         hex = binary_part(rest, 0, byte_size(rest) - byte_size(@precompiled_suffix)),
         {:ok, sha} <- normalize(hex) do
      {:ok, :precompiled, sha}
    else
      _not_a_precompiled_artifact -> :error
    end
  end

  defp published_name(@manifest_prefix <> rest = _manifest) do
    with true <- String.ends_with?(rest, @manifest_suffix),
         hex = binary_part(rest, 0, byte_size(rest) - byte_size(@manifest_suffix)),
         {:ok, sha} <- normalize(hex) do
      {:ok, :manifest, sha}
    else
      _not_a_manifest -> :error
    end
  end

  defp published_name(_other), do: :error

  # `lstat`, not `stat`: a symlink planted at a published name is not a published file. It
  # is rejected here so `list`/`prune` never report its target's size as a component's
  # (F10). Digest verification on `fetch` is the guarantee against wrong bytes; this is
  # the guarantee the store's byte accounting is about files it actually holds.
  defp stat_entry(dir, name, kind, sha) do
    path = Path.join(dir, name)

    case File.lstat(path, time: :posix) do
      {:ok, %{type: :regular, size: size, mtime: mtime}} ->
        [%{kind: kind, sha256: sha, path: path, size: size, mtime: mtime}]

      _not_a_regular_file ->
        []
    end
  end

  defp regular_file?(path) do
    match?({:ok, %{type: :regular}}, File.lstat(path))
  end

  defp read(path, sha) do
    case File.read(path) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, :enoent} -> {:error, {:unknown_component, sha}}
      {:error, reason} -> {:error, {:component_unreadable, sha, reason}}
    end
  end

  defp ensure_directory(dir) do
    case File.mkdir_p(dir) do
      :ok ->
        _ = File.chmod(dir, 0o700)
        :ok

      {:error, reason} ->
        {:error, {:store_unavailable, dir, reason}}
    end
  end

  # `digest` is what the published file must hash to; `kind` selects the vocabulary the
  # refusals are named in, and `label` is what those refusals name — the sha for a
  # component, the artifact id for a manifest. The discipline is one and the same, which is
  # the point of writing it once.
  defp publish_once(path, bytes, expected, kind, label) do
    temporary = temporary_path(path)

    with {:ok, device} <- open_exclusive(temporary),
         :ok <- write_sync_close(device, bytes) do
      publish_link(temporary, path, expected, kind, label)
    else
      {:error, reason} ->
        _ = File.rm(temporary)
        {:error, {write_failed(kind), label, reason}}
    end
  end

  defp write_failed(:component), do: :component_write_failed
  defp write_failed(:precompiled), do: :precompiled_write_failed
  defp write_failed(:manifest), do: :manifest_write_failed

  defp open_exclusive(path) do
    :file.open(String.to_charlist(path), [:write, :binary, :raw, :exclusive])
  end

  defp write_sync_close(device, bytes) do
    write_result =
      with :ok <- :file.write(device, bytes) do
        :file.sync(device)
      end

    close_result = :file.close(device)

    case {write_result, close_result} do
      {:ok, :ok} -> :ok
      {{:error, reason}, _close} -> {:error, reason}
      {:ok, {:error, reason}} -> {:error, reason}
    end
  end

  # A link, not a rename: rename overwrites, and publish-once means the first writer of a
  # sha is the only one. `:eexist` is the expected outcome of a second put, so the existing
  # file is verified rather than replaced.
  defp publish_link(temporary, path, expected, kind, label) do
    result =
      case File.ln(temporary, path) do
        :ok ->
          with :ok <- sync_directory(Path.dirname(path)), do: {:ok, true}

        {:error, :eexist} ->
          with :ok <- verify_existing(path, expected, kind, label), do: {:ok, false}

        {:error, reason} ->
          {:error, {publish_failed(kind), label, reason}}
      end

    _ = File.rm(temporary)
    result
  end

  defp publish_failed(:component), do: :component_publish_failed
  defp publish_failed(:precompiled), do: :precompiled_publish_failed
  defp publish_failed(:manifest), do: :manifest_publish_failed

  defp verify_existing(path, expected, kind, label) do
    # `lstat` first, so a symlink at the published name is rejected rather than followed and
    # read (F10); `PackageStager.verify_existing` takes the same posture.
    with {:ok, %{type: :regular}} <- File.lstat(path),
         {:ok, bytes} <- File.read(path),
         true <- digest(bytes) == expected do
      :ok
    else
      {:ok, %{type: type}} -> {:error, {invalid_file(kind), label, type}}
      false -> {:error, {mismatch(kind), label}}
      {:error, reason} -> {:error, {unreadable(kind), label, reason}}
    end
  end

  defp invalid_file(:component), do: :invalid_component_file
  defp invalid_file(:precompiled), do: :invalid_precompiled_file
  defp invalid_file(:manifest), do: :invalid_manifest_file

  # A component whose published bytes do not hash to its own name is corrupt; a manifest
  # under an id that already names a *different* manifest is a conflict, not corruption —
  # publish-once refuses to choose between two honest records of two different rollouts.
  defp mismatch(:component), do: :corrupt_component
  defp mismatch(:precompiled), do: :corrupt_precompiled
  defp mismatch(:manifest), do: :manifest_conflict

  defp unreadable(:component), do: :component_unreadable
  defp unreadable(:precompiled), do: :precompiled_unreadable
  defp unreadable(:manifest), do: :manifest_unreadable

  defp sync_directory(directory) do
    case :file.open(String.to_charlist(directory), [:read, :raw, :directory]) do
      {:ok, device} ->
        sync_result = :file.sync(device)
        close_result = :file.close(device)

        case {sync_result, close_result} do
          {:ok, :ok} -> :ok
          {{:error, reason}, _close} -> {:error, {:directory_sync_failed, directory, reason}}
          {:ok, {:error, reason}} -> {:error, {:directory_close_failed, directory, reason}}
        end

      {:error, reason} ->
        {:error, {:directory_open_failed, directory, reason}}
    end
  end

  defp temporary_path(path) do
    path <> ".tmp-" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
  end

  defp digest(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)
end
