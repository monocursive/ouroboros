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

  @prefix "sha256-"
  @suffix ".wasm"
  @temp_infix ".tmp-"

  # How old a `.tmp-*` file must be before `prune/1` sweeps it. Comfortably longer than any
  # single `put` takes, so a concurrent writer's own in-flight temp — created moments ago —
  # is never mistaken for a crash's leftover and removed out from under it.
  @temp_grace_seconds 3_600

  # The registry states whose components must survive a prune. `:live` and `:deploying` are
  # referenced now; `:quarantined` is the evidence for a deploy nobody has resolved.
  @protected_states [:live, :deploying, :quarantined]

  @typedoc "One component the store holds."
  @type entry :: %{
          sha256: String.t(),
          path: String.t(),
          size: non_neg_integer(),
          mtime: integer()
        }

  @doc """
  The directory this node's components live in, without creating it.

  `:root` in `opts` overrides it, which is how tests get a directory of their own.
  """
  @spec root(keyword()) :: {:ok, String.t()} | {:error, :no_data_dir}
  def root(opts \\ []) do
    case Keyword.get(opts, :root) do
      dir when is_binary(dir) and dir != "" ->
        {:ok, dir}

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
         {:ok, published} <- publish_once(path, bytes, actual) do
      {:ok, %{sha256: actual, path: path, size: byte_size(bytes), published: published}}
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

  @doc "Every component held, oldest first, with sizes."
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

  @doc "Forgets one component. Idempotent: a sha that is not held is already forgotten."
  @spec delete(String.t(), keyword()) :: :ok | {:error, term()}
  def delete(sha256, opts \\ []) when is_binary(sha256) do
    with {:ok, sha} <- normalize(sha256),
         {:ok, dir} <- root(opts) do
      case File.rm(component_path(dir, sha)) do
        :ok -> :ok
        {:error, :enoent} -> :ok
        {:error, reason} -> {:error, {:component_undeletable, sha, reason}}
      end
    end
  end

  @doc """
  Evicts unreferenced components, oldest first, until the store is under its byte budget.

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
      held = Enum.reduce(entries, 0, &(&1.size + &2))

      {evicted, reclaimed} =
        entries
        |> Enum.reject(&MapSet.member?(protected, &1.sha256))
        |> Enum.reduce_while({[], 0}, fn entry, {shas, freed} ->
          if held - freed <= budget do
            {:halt, {shas, freed}}
          else
            case delete(entry.sha256, opts) do
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
  The shas no prune may evict, read from whatever the rollout registry records today.

  Today that is nothing: `Ouroboros.Upgrade.Rollout.Registry.Entry` has no component sha,
  because checkpoint v3 is what widens it with `component_sha256` (docs/WASM.md §7.6, slice
  W3). So this reads the field tolerantly — an entry that does not name a component protects
  nothing — and W3 has only to widen the extraction below, not to change how pruning reads
  the registry.
  """
  @spec protected_shas(keyword()) :: {:ok, MapSet.t(String.t())} | {:error, :registry_unavailable}
  def protected_shas(opts \\ []) do
    registry = Keyword.get(opts, :registry, Rollout.Registry)

    entries = Rollout.Registry.list(registry)

    protected =
      entries
      |> Enum.filter(&(Map.get(&1, :state) in @protected_states))
      |> Enum.flat_map(&component_shas/1)
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

  # The shape `publish_once/3`'s temporary carries: the component basename, then `.tmp-`,
  # then random bytes. Real components end in `.wasm`, so they never match.
  defp temp_name?(name) do
    String.starts_with?(name, @prefix) and String.contains?(name, @suffix <> @temp_infix)
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

  defp entry(dir, name) do
    with @prefix <> rest <- name,
         true <- String.ends_with?(rest, @suffix),
         sha = binary_part(rest, 0, byte_size(rest) - byte_size(@suffix)),
         {:ok, sha} <- normalize(sha),
         path = Path.join(dir, name),
         # `lstat`, not `stat`: a symlink planted at a component name is not a component. It
         # is rejected here so `list`/`prune` never report its target's size as a component's
         # (F10). Digest verification on `fetch` is the guarantee against wrong bytes; this is
         # the guarantee the store's byte accounting is about files it actually holds.
         {:ok, %{type: :regular, size: size, mtime: mtime}} <- File.lstat(path, time: :posix) do
      [%{sha256: sha, path: path, size: size, mtime: mtime}]
    else
      _not_a_component -> []
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

  defp publish_once(path, bytes, sha) do
    temporary = temporary_path(path)

    with {:ok, device} <- open_exclusive(temporary),
         :ok <- write_sync_close(device, bytes) do
      publish_link(temporary, path, sha)
    else
      {:error, reason} ->
        _ = File.rm(temporary)
        {:error, {:component_write_failed, sha, reason}}
    end
  end

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
  defp publish_link(temporary, path, sha) do
    result =
      case File.ln(temporary, path) do
        :ok -> with :ok <- sync_directory(Path.dirname(path)), do: {:ok, true}
        {:error, :eexist} -> with :ok <- verify_existing(path, sha), do: {:ok, false}
        {:error, reason} -> {:error, {:component_publish_failed, sha, reason}}
      end

    _ = File.rm(temporary)
    result
  end

  defp verify_existing(path, sha) do
    # `lstat` first, so a symlink at the published name is rejected rather than followed and
    # read (F10); `PackageStager.verify_existing` takes the same posture.
    with {:ok, %{type: :regular}} <- File.lstat(path),
         {:ok, bytes} <- File.read(path),
         true <- digest(bytes) == sha do
      :ok
    else
      {:ok, %{type: type}} -> {:error, {:invalid_component_file, sha, type}}
      false -> {:error, {:corrupt_component, sha}}
      {:error, reason} -> {:error, {:component_unreadable, sha, reason}}
    end
  end

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
end
