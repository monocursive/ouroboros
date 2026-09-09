defmodule Ouroboros.Storage.DurableFile do
  @moduledoc """
  A Jido storage adapter whose checkpoint commits are durable before success.

  Checkpoints are serialized to an exclusive temporary file, synced, atomically
  renamed over the checkpoint, and followed by a parent-directory sync. A failure
  before rename is an ordinary error and leaves the old checkpoint standing. A failure
  after rename is `{:error, {:commit_outcome_unknown, reason}}`: the new inode is visible,
  but the directory entry was not proven durable. Callers must reconcile that outcome,
  never report it as a definite refusal while continuing with old in-memory state.

  Thread operations fail closed because this adapter is intentionally limited to
  Ouroboros mutation journals, which use checkpoint operations only.

  A commit that dies between opening its temporary file and renaming it — the process is
  killed, the node goes down — leaves that file behind. Randomized names mean an orphan
  wedges nothing, so this is hygiene rather than correctness: the first write a process
  makes into a checkpoint directory sweeps the orphans it finds there. Only files older
  than #{div(60_000, 1_000)} seconds are swept, so a temporary file another process has
  open right now is never one of them.

  `:durability_hook` is a deterministic fault-observation seam for tests. A hook
  returning `{:error, reason}` aborts before the named operation.

  Checkpoints are read with `:erlang.binary_to_term(binary, [:safe])`, which refuses to
  create an atom, so a file naming an atom this build does not have fails to decode
  entirely. `Ouroboros.Storage.RetiredAtoms` holds the names the core reduction removed
  that a written checkpoint may still carry; `retired_atoms/0` below compiles that list
  into this module, so loading the adapter interns them and a store written by an older
  build reads back.

  ## The build, before the first decode

  `[:safe]` asks whether an atom is *interned*, not whether this build spells it. Elixir's
  default `:interactive` code loading loads a module the first time something calls it, so
  under `mix run` and `make dev` the atom table at any instant is a function of boot order:
  the integration fixture measured between 36 and 117 `Ouroboros.*` modules loaded at the
  effect ledger's first read, run to run, against identical bytes. A checkpoint holding a
  name whose only speller has not loaded yet then fails to decode — and the store either
  refuses to boot or, since the fix wave, quarantines the file and starts empty, which is
  the same data loss without the crash. The shipped release boots in `:embedded` mode with
  every module already loaded, so this never reached production; every development daemon
  and every test that boots a data directory has it.

  `ensure_build_loaded/0` closes that: before the first `[:safe]` decode in a VM it loads
  every module of `:ouroboros` and of the applications it depends on, once, and records
  that in `:persistent_term`. In embedded mode the modules are already loaded and the call
  costs a membership check each; in interactive mode it makes a checkpoint's readability a
  property of the build rather than of the order the boot happened to take.

  The three mechanisms are disjoint and all three are needed. `RetiredAtoms` covers a name
  **no module of this build spells any more**. The quarantine covers a name **no build can
  spell**, minted at runtime. This covers a name **this build spells in a module that has
  not loaded yet**.

  ## Quarantine

  `get_checkpoint/2` decodes with `[:safe]`, which refuses to *create* an atom. A
  checkpoint written by an older build can therefore hold a name this build has never
  interned — a module it deleted, or, worse, a name that was minted at runtime and was
  never in anyone's source — and the whole file stops decoding. A store that answers
  `{:stop, _}` to that turns one unreadable file into a node that does not boot.

  `get_checkpoint_or_quarantine/2` is the same read for a store that would rather keep
  running: an *undecodable term* moves aside with every byte intact and reads as
  `:not_found`. This is `Ouroboros.Storage.Records`' doctrine — "quarantine an unreadable
  individual record, keeping its bytes for inspection" (docs/SIMPLIFICATION.md,
  "Checkpoint publication") — applied to a store that keeps one aggregate checkpoint
  rather than a record per id, so the unit of quarantine is the file. Every other failure
  (I/O, a content-integrity failure, a missing directory) still fails exactly as before,
  because those say nothing about whether this build can interpret the bytes.
  """

  require Logger

  @behaviour Jido.Storage

  # Old enough that no live commit could still be writing it, short enough that an
  # orphan does not outlive the boot that follows the crash which made it.
  @stale_temporary_ms 60_000

  # Read at compile time on purpose: the names land in *this* module's atom table, so they
  # are interned by the time `get_checkpoint/2` below can run, in a VM that never loaded
  # `Ouroboros.Storage.RetiredAtoms` itself. See that module for why.
  @retired_atoms Ouroboros.Storage.RetiredAtoms.all()

  @doc """
  The atoms `Ouroboros.Storage.RetiredAtoms` keeps alive for `safe_binary_to_term/1`.

  Nothing in the decode path calls this. It exists so the list is a value this module
  holds rather than a comment claiming it does.
  """
  @spec retired_atoms() :: [atom()]
  def retired_atoms, do: @retired_atoms

  # Per VM, not per process: the atom table every store decodes against is the VM's.
  @build_loaded {__MODULE__, :build_loaded}

  @doc """
  Loads this build's modules once per VM, so a `[:safe]` decode sees the whole build.

  Every module of `:ouroboros` and of every application in its transitive `:applications`
  closure that the application controller has loaded. An application that is not loaded
  contributes nothing and is skipped: nothing of it can be running, so nothing of it can
  have written the checkpoint being read. A module that will not load is not an error
  here — this is about which names exist, and the modules that do load still intern theirs.

  Idempotent, and cheap after the first call. Two stores decoding at once may both do the
  work; loading a module twice is the code server's own no-op, so the race costs time and
  never correctness.
  """
  @spec ensure_build_loaded() :: :ok
  def ensure_build_loaded do
    if :persistent_term.get(@build_loaded, false) do
      :ok
    else
      _ = load_build()
      :persistent_term.put(@build_loaded, true)
      :ok
    end
  end

  defp load_build do
    :ouroboros
    |> application_closure(MapSet.new())
    |> Enum.flat_map(&(Application.spec(&1, :modules) || []))
    |> Code.ensure_all_loaded()
  rescue
    # A decode must not become the place a code-path problem is reported. The names that
    # did get interned still count; the ones that did not were not going to help.
    error ->
      Logger.warning("could not preload this build before a checkpoint decode: #{inspect(error)}")
      :ok
  end

  defp application_closure(app, seen) do
    # `nil` is the application controller's answer for an application it has not loaded.
    case {MapSet.member?(seen, app), Application.spec(app, :applications)} do
      {true, _applications} ->
        seen

      {false, nil} ->
        seen

      {false, applications} ->
        Enum.reduce(applications, MapSet.put(seen, app), &application_closure/2)
    end
  end

  @impl true
  def get_checkpoint(key, opts) do
    with {:ok, path} <- checkpoint_path(key, opts) do
      case Ouroboros.Audit.Content.read(path) do
        {:ok, binary} -> safe_binary_to_term(binary)
        {:error, :enoent} -> :not_found
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @doc """
  `get_checkpoint/2`, except that a checkpoint whose bytes do not decode is quarantined.

  The file is renamed aside as `<name>.quarantined-<unix>.term` — every byte kept, nothing
  rewritten — one error line is logged naming that path and the reason, and the read
  answers `:not_found`, which is the caller's "no checkpoint yet" branch. The name keeps
  its `.term` suffix on purpose: `Ouroboros.Audit.Content.inventory/2` globs
  `*/checkpoints/*.term`, and a quarantined file that dropped out of the operational
  content inventory would be bytes on disk nobody is accounting for.

  Only `{:error, :invalid_term}` is quarantined. An unreadable file is otherwise returned
  as the error it is, and a rename that fails returns the original `:invalid_term` rather
  than reporting an absent checkpoint while the unreadable one is still standing.

  A caller that uses this instead of `get_checkpoint/2` is saying that an uninterpretable
  checkpoint should narrow it, not stop it. That is only true of a store whose empty state
  is the safe one; a store whose empty state would fail open must keep failing closed.
  """
  @spec get_checkpoint_or_quarantine(term(), keyword()) ::
          {:ok, term()} | :not_found | {:error, term()}
  def get_checkpoint_or_quarantine(key, opts) do
    case get_checkpoint(key, opts) do
      {:error, :invalid_term} -> quarantine(key, opts)
      other -> other
    end
  end

  @impl true
  def put_checkpoint(key, data, opts) do
    with {:ok, path} <- checkpoint_path(key, opts),
         :ok <- ensure_directory(Path.dirname(path)),
         :ok <- sweep_once(Path.dirname(path)),
         temporary = temporary_path(path),
         :ok <- hook(opts, :before_open_temp),
         {:ok, device} <-
           :file.open(String.to_charlist(temporary), [:write, :binary, :raw, :exclusive]),
         :ok <- write_checkpoint(device, temporary, path, data, opts) do
      :ok
    else
      {:error, _reason} = error -> error
    end
  rescue
    error -> {:error, error}
  end

  @impl true
  def delete_checkpoint(key, opts) do
    with {:ok, path} <- checkpoint_path(key, opts),
         :ok <- hook(opts, :before_delete) do
      case remove_if_present(path) do
        {:ok, false} ->
          :ok

        {:ok, true} ->
          case sync_directory(Path.dirname(path), opts) do
            :ok -> :ok
            {:error, reason} -> {:error, {:commit_outcome_unknown, reason}}
          end

        {:error, _reason} = error ->
          error
      end
    end
  rescue
    error -> {:error, error}
  end

  @impl true
  def load_thread(_thread_id, _opts), do: {:error, :thread_operations_not_supported}

  @impl true
  def append_thread(_thread_id, _entries, _opts),
    do: {:error, :thread_operations_not_supported}

  @impl true
  def delete_thread(_thread_id, _opts), do: {:error, :thread_operations_not_supported}

  defp write_checkpoint(device, temporary, path, data, opts) do
    binary = :erlang.term_to_binary(data) |> Ouroboros.Audit.Content.encode()

    precommit =
      with :ok <- File.chmod(temporary, 0o600),
           :ok <- hook(opts, :before_write),
           :ok <- :file.write(device, binary),
           :ok <- hook(opts, :before_file_sync),
           :ok <- :file.sync(device),
           :ok <- hook(opts, :before_close),
           :ok <- :file.close(device) do
        :ok
      end

    result =
      case precommit do
        :ok ->
          with :ok <- hook(opts, :before_rename),
               :ok <- File.rename(temporary, path) do
            directory_result =
              with :ok <- hook(opts, :before_directory_sync),
                   :ok <- sync_directory(Path.dirname(path), opts) do
                :ok
              end

            case directory_result do
              :ok -> :ok
              {:error, reason} -> {:error, {:commit_outcome_unknown, reason}}
            end
          end

        {:error, _reason} = error ->
          error
      end

    if precommit != :ok do
      _ = :file.close(device)
    end

    if result != :ok do
      _ = File.rm(temporary)
    end

    result
  end

  # Once per process per directory: the store that owns a checkpoint directory is a
  # single serialized process, so this runs on its first write and never again. A sweep
  # that cannot read the directory or remove a file changes nothing about the commit
  # that is about to happen.
  defp sweep_once(directory) do
    if Process.get({__MODULE__, :swept, directory}) do
      :ok
    else
      Process.put({__MODULE__, :swept, directory}, true)
      sweep_stale_temporaries(directory)
      :ok
    end
  end

  defp sweep_stale_temporaries(directory) do
    horizon = System.os_time(:second) - div(@stale_temporary_ms, 1_000)

    directory
    |> Path.join("*.tmp-*")
    |> Path.wildcard()
    |> Enum.each(fn temporary ->
      case File.stat(temporary, time: :posix) do
        {:ok, %File.Stat{type: :regular, mtime: mtime}} when mtime <= horizon ->
          _ = File.rm(temporary)

        _newer_or_unreadable ->
          :ok
      end
    end)
  rescue
    _error -> :ok
  end

  defp ensure_directory(directory) do
    case File.mkdir_p(directory) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp sync_directory(directory, opts) do
    with :ok <- hook(opts, :directory_sync),
         {:ok, device} <- :file.open(String.to_charlist(directory), [:read, :raw, :directory]) do
      result = :file.sync(device)
      close_result = :file.close(device)

      case {result, close_result} do
        {:ok, :ok} -> :ok
        {{:error, reason}, _close} -> {:error, {:directory_sync_failed, reason}}
        {:ok, {:error, reason}} -> {:error, {:directory_close_failed, reason}}
      end
    end
  end

  defp checkpoint_path(key, opts) do
    case Keyword.fetch(opts, :path) do
      {:ok, path} when is_binary(path) and path != "" ->
        hash =
          :crypto.hash(:sha256, :erlang.term_to_binary(key))
          |> Base.url_encode64(padding: false)

        {:ok, Path.join([Path.expand(path), "checkpoints", hash <> ".term"])}

      _other ->
        {:error, :invalid_storage_path}
    end
  end

  defp temporary_path(path) do
    suffix = :crypto.strong_rand_bytes(12) |> Base.url_encode64(padding: false)
    path <> ".tmp-" <> suffix
  end

  # The one call site, immediately before the one decode, so the invariant is local: no
  # `[:safe]` decode in this module can run against an atom table this build has not filled.
  defp safe_binary_to_term(binary) do
    ensure_build_loaded()
    {:ok, :erlang.binary_to_term(binary, [:safe])}
  rescue
    ArgumentError -> {:error, :invalid_term}
  end

  defp quarantine(key, opts) do
    with {:ok, path} <- checkpoint_path(key, opts) do
      destination = quarantine_path(path)

      case File.rename(path, destination) do
        :ok ->
          Logger.error(
            "checkpoint #{inspect(key)} at #{path} could not be decoded (:invalid_term); " <>
              "quarantining it at #{destination} and starting from no checkpoint"
          )

          :not_found

        {:error, :enoent} ->
          # Somebody else moved or removed it between the read and the rename. There is no
          # checkpoint here either way, and no bytes were lost by this process.
          :not_found

        {:error, reason} ->
          Logger.error(
            "checkpoint #{inspect(key)} at #{path} could not be decoded (:invalid_term) and " <>
              "could not be quarantined (#{inspect(reason)}); it is still standing"
          )

          {:error, :invalid_term}
      end
    end
  end

  # `.term` is kept as the extension so the file stays inside the operational content
  # inventory's glob. A second quarantine of the same key in the same second cannot happen
  # in a single store's lifetime — the first one leaves nothing to read — but two nodes
  # sharing a data directory is a mistake that must not eat the evidence, so an occupied
  # destination gets a random discriminator rather than being overwritten.
  defp quarantine_path(path) do
    base = Path.rootname(path, ".term")
    candidate = "#{base}.quarantined-#{System.os_time(:second)}.term"

    if File.exists?(candidate) do
      suffix = :crypto.strong_rand_bytes(6) |> Base.url_encode64(padding: false)
      "#{base}.quarantined-#{System.os_time(:second)}-#{suffix}.term"
    else
      candidate
    end
  end

  defp remove_if_present(path) do
    case File.rm(path) do
      :ok -> {:ok, true}
      {:error, :enoent} -> {:ok, false}
      {:error, reason} -> {:error, reason}
    end
  end

  defp hook(opts, event) do
    case Keyword.get(opts, :durability_hook) do
      nil -> :ok
      hook when is_function(hook, 1) -> hook.(event)
      _invalid -> {:error, :invalid_durability_hook}
    end
  end
end
