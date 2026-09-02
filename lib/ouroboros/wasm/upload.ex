defmodule Ouroboros.Wasm.Upload do
  @moduledoc """
  The staging area a component or a bundle crosses the gateway in (docs/WASM.md D16).

  A JSON-RPC frame is a line, and `Ouroboros.Gateway.Config` bounds one at
  `OUROBOROS_GATEWAY_MAX_FRAME` — a mebibyte by default, with the Rust client refusing to
  *send* more than the same number. A component is bounded at sixteen mebibytes, which is
  twenty-one after base64. So there is no honest way to put one in a parameter, and the
  choice is between shrinking what an operator may deploy to whatever fits one frame and
  cutting the bytes into frames that do. This is the second one.

  ## Files, and one file that is a lock

  There is still no process. What there is, and what the first version of this module got
  wrong, is that **counting is not claiming**: `File.ls/1` and then `File.write/3` is a
  read-then-write across two syscalls, and thirty-two concurrent openers all counted seven
  and all created a file. The ceiling was a number in a comment.

  So a slot is claimed the only way a filesystem makes atomic: `slot-<n>` is created with
  `[:exclusive]`, which is `O_CREAT|O_EXCL`, and exactly one caller can win each of the
  eight. The slot file *is* the claim, and it carries the two facts an upload's lifetime
  needs — which id holds it, and when it was opened. An upload with no slot is litter and
  the next sweep removes it.

  `take/2` is a `File.rename/2` before it is a read, for the same reason: read-then-remove
  let two `wasm.deploy` frames naming the same upload both receive the bytes, which is
  exactly the replay this module says cannot happen. A rename to a private name either
  wins or fails with `:enoent`; the winner reads what it moved.

  ## Every bound, and why each one is where it is

    * **The id is minted here.** Sixteen random bytes as hex. A client-chosen id would be
      a client-chosen filename, and no amount of validation afterwards is as good as never
      having taken one. It is still validated on the way back in — `[0-9a-f]{32}` and
      nothing else reaches `Path.join/2` — because a value that made a round trip through
      a client is a value that arrived from a client.
    * **One chunk is 512 KiB** of decoded bytes. Base64 makes that about 683 KiB on the
      wire, which clears the default frame with a third to spare, and a node whose operator
      lowered `OUROBOROS_GATEWAY_MAX_FRAME` refuses the frame before this module ever sees
      it. The reply states the number so a client sizes its chunks from the node's answer
      rather than from a constant compiled into it.
    * **The total is `Ouroboros.Wasm.Bundle.max_bytes/0`** — the largest thing that could
      legitimately be uploaded, which is a bundle at the component ceiling. Checked before
      each append against the size the file already has, so the ceiling cannot be reached
      and then exceeded.
    * **Eight uploads may be in flight per node**, and that is now a fact about eight slot
      files rather than about a count somebody took.
    * **Two clocks, and neither is `File.touch/1`.** Ten minutes idle — the mtime, which a
      write moves on its own and nothing here moves artificially — and **thirty minutes
      total from the moment the slot was claimed**, whatever the client does in between.
      Without the second one, a client that sends one byte every nine minutes holds a slot
      for as long as it likes, and eight such clients hold the node. Every entry point
      sweeps, including the two that only read: an upload past either clock must not be
      consumable, and a sweep that only ran on the write path left `take/2` reading files
      the module had already promised were gone.
    * **Nothing here follows a symlink.** The staging root must be a real directory and a
      staged file must be a regular file, both checked with `File.lstat/1` — otherwise
      `chmod` and `write` are operations on somebody else's target, chosen by whoever could
      create a name in that directory.

  ## An upload carries no authority

  Nothing in this module verifies, signs, stores, or loads. What comes out of `take/2` is
  a bag of bytes that a client chose, and every caller treats it as one:
  `wasm.sign` hands it to the signing policy, which recomputes the digest and the size
  rather than believing them, and `wasm.deploy` hands it to
  `Ouroboros.Wasm.Bundle.verify/2` before the store or the helper hears about it. The
  sha256 this module reports at commit is a **receipt for the transfer** — it says the
  bytes that arrived are the bytes that arrived — and it is never a statement that
  anybody should run them.
  """

  require Logger

  alias Ouroboros.Wasm.Bundle

  @id_bytes 16
  @id_pattern ~r/\A[0-9a-f]{32}\z/

  @part ".part"
  @done ".done"
  @taken ".taken-"
  @slot "slot-"

  @max_chunk_bytes 512 * 1024
  @max_in_flight 8

  # Idle: how long a transfer may go untouched before the node reclaims it.
  @ttl_ms 10 * 60 * 1_000

  # Total: how long one transfer may exist at all, however busy it looks. A client that
  # writes one byte a minute is not making progress worth a slot.
  @max_lifetime_ms 30 * 60 * 1_000

  # How young a slot or a staged file may be and still be nobody's business but its opener's.
  # A claim is two writes (`slot-<n>`, then `<id>.part`) and a slot's contents land a moment
  # after the file exists; a sweep running in a concurrent call can read the slot empty, or
  # see the part before its slot, and would take either for litter. Nothing regular and
  # younger than this is reclaimed on the strength of what it looks like — an opener that has
  # stalled that long between two syscalls is a machine with bigger problems than one slot.
  @claim_grace_ms 30_000

  @type receipt :: %{
          upload: String.t(),
          received: non_neg_integer(),
          complete: boolean(),
          sha256: String.t() | nil,
          chunk_bytes: pos_integer()
        }

  @doc "The most decoded bytes one `wasm.upload` frame may carry."
  @spec max_chunk_bytes() :: pos_integer()
  def max_chunk_bytes, do: @max_chunk_bytes

  @doc "The most bytes one upload may total, which is the largest legal bundle."
  @spec max_total_bytes() :: pos_integer()
  def max_total_bytes, do: Bundle.max_bytes()

  @doc "The most uploads one node holds at once before a new one is refused."
  @spec max_in_flight() :: pos_integer()
  def max_in_flight, do: @max_in_flight

  @doc "How long one upload may exist, from the moment its slot was claimed."
  @spec max_lifetime_ms() :: pos_integer()
  def max_lifetime_ms, do: @max_lifetime_ms

  @doc "How long an upload may go unwritten before the node reclaims it."
  @spec idle_ms() :: pos_integer()
  def idle_ms, do: @ttl_ms

  @doc """
  Where this node stages uploads, or `{:error, :no_data_dir}` on a node with none.

  `opts[:root]` names one explicitly, for tests that must not touch a real data
  directory — the same seam `Ouroboros.Wasm.Store.root/1` offers, and for the same reason.
  """
  @spec root(keyword()) :: {:ok, Path.t()} | {:error, :no_data_dir}
  def root(opts \\ []) do
    case Keyword.get(opts, :root) do
      dir when is_binary(dir) and dir != "" ->
        {:ok, dir}

      _unset ->
        case Application.get_env(:ouroboros, :data_dir) do
          dir when is_binary(dir) and dir != "" -> {:ok, Path.join([dir, "wasm", "uploads"])}
          _unset -> {:error, :no_data_dir}
        end
    end
  end

  @doc """
  Appends `chunk` to an upload, starting one when `id` is `nil`.

  `offset` must equal what the upload already holds. It is not a seek — the file is only
  ever appended to — it is the client stating where it believes it is, so a retried or
  reordered frame is refused rather than silently producing bytes nobody sent. A refusal
  names the offset the node actually holds, which is what a client needs to resume.

  `final?` closes the upload: the bytes stop being appendable and become readable by
  `take/2`, and the receipt carries their sha256.
  """
  @spec append(String.t() | nil, non_neg_integer(), binary(), boolean(), keyword()) ::
          {:ok, receipt()} | {:error, term()}
  def append(id, offset, chunk, final?, opts \\ [])

  def append(id, offset, chunk, final?, opts)
      when is_integer(offset) and offset >= 0 and is_binary(chunk) and is_boolean(final?) and
             is_list(opts) do
    with :ok <- bound_chunk(chunk),
         {:ok, dir} <- prepared(opts),
         {:ok, id, path} <- opened(id, dir),
         {:ok, held} <- held(path),
         :ok <- positioned(held, offset, byte_size(chunk)),
         :ok <- written(path, chunk) do
      settle(id, dir, path, held + byte_size(chunk), final?)
    end
  end

  def append(_id, offset, chunk, final?, _opts),
    do: {:error, {:invalid_upload_request, describe({offset, byte_size_of(chunk), final?})}}

  @doc """
  Reads a finished upload and removes it, or refuses one that is not finished.

  Consume-once, and it is the `File.rename/2` that makes it so rather than the sentence:
  two callers naming the same upload both rename it to private names of their own, one
  gets `:enoent`, and only the winner reads anything. A caller that needs the bytes twice
  uploads them twice.
  """
  @spec take(String.t(), keyword()) :: {:ok, binary()} | {:error, term()}
  def take(id, opts \\ []) when is_binary(id) do
    with {:ok, dir} <- swept(opts),
         {:ok, id} <- valid_id(id),
         {:ok, done} <- committed(dir, id) do
      claim = Path.join(dir, id <> @taken <> unique())

      case File.rename(done, claim) do
        :ok ->
          result = File.read(claim)
          _ignored = File.rm(claim)
          release(dir, id)
          bytes(result)

        {:error, :enoent} ->
          {:error, {:unknown_upload, id}}

        {:error, reason} ->
          {:error, {:upload_unreadable, reason}}
      end
    end
  end

  @doc """
  Where a finished upload's bytes are, without reading or removing them.

  Kept for a caller that has a use for the file rather than its contents. Nothing in this
  build parses a staged file — `wasm.sign` never hands unsigned bytes to the helper
  (docs/WASM.md D15) — so this exists for the same reason `sweep/1` is public: a seam
  worth being able to ask about directly.
  """
  @spec path(String.t(), keyword()) :: {:ok, Path.t()} | {:error, term()}
  def path(id, opts \\ []) when is_binary(id) do
    with {:ok, dir} <- swept(opts),
         {:ok, id} <- valid_id(id) do
      committed(dir, id)
    end
  end

  @doc """
  Removes every upload past either clock, returning how many went.

  Called at the head of every entry point — including the two that only read — which is
  the only reason this module needs no timer.
  """
  @spec sweep(keyword()) :: non_neg_integer()
  def sweep(opts \\ []) do
    case root(opts) do
      {:ok, dir} -> expire(dir)
      {:error, _no_data_dir} -> 0
    end
  end

  ## Plumbing

  defp swept(opts) do
    with {:ok, dir} <- root(opts) do
      _swept = expire(dir)
      {:ok, dir}
    end
  end

  defp prepared(opts) do
    with {:ok, dir} <- root(opts),
         :ok <- ensure_directory(dir) do
      _swept = expire(dir)
      {:ok, dir}
    end
  end

  # `File.lstat/1`, never `File.stat/1`: a root that is a symlink is a root whose owner is
  # whoever created the link, and `chmod` through it is a mode set on their target.
  defp ensure_directory(dir) do
    case File.lstat(dir) do
      {:ok, %File.Stat{type: :directory}} ->
        _ignored = File.chmod(dir, 0o700)
        :ok

      {:ok, %File.Stat{type: type}} ->
        {:error, {:upload_directory_not_a_directory, type}}

      {:error, :enoent} ->
        create_directory(dir)

      {:error, reason} ->
        {:error, {:upload_directory_unwritable, reason}}
    end
  end

  defp create_directory(dir) do
    case File.mkdir_p(dir) do
      :ok ->
        _ignored = File.chmod(dir, 0o700)
        :ok

      {:error, reason} ->
        {:error, {:upload_directory_unwritable, reason}}
    end
  end

  # A slot is claimed before a byte is written, and it is claimed with `O_CREAT|O_EXCL`,
  # so the ceiling is enforced by the filesystem rather than by a count somebody took.
  defp opened(nil, dir) do
    id = @id_bytes |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)

    case claim_slot(dir, id, 0) do
      :ok ->
        path = Path.join(dir, id <> @part)

        # `[:exclusive]` here is a belt and is honestly labelled as one: `id` is sixteen
        # bytes of `:crypto.strong_rand_bytes/1`, so there is no reachable input that makes
        # this file already exist, and no test in this suite can tell it from `[:write]`.
        # The exclusivity that actually bounds this node is the slot claim above, which is
        # reachable, contended, and proved by the concurrent-opener test. What keeps an
        # *existing* upload from being clobbered is `written/2`'s `[:append]` and the offset
        # check, both of which are reachable and both of which are proved.
        case File.write(path, "", [:exclusive]) do
          :ok ->
            _ignored = File.chmod(path, 0o600)
            {:ok, id, path}

          {:error, reason} ->
            release(dir, id)
            {:error, {:upload_not_created, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp opened(id, dir) when is_binary(id) do
    with {:ok, id} <- valid_id(id) do
      case staged(dir, id, @part) do
        {:ok, path} ->
          {:ok, id, path}

        {:error, {:unknown_upload, _id}} = absent ->
          if File.exists?(Path.join(dir, id <> @done)),
            do: {:error, {:upload_closed, id}},
            else: absent

        error ->
          error
      end
    end
  end

  defp opened(id, _dir), do: {:error, {:invalid_upload_id, describe(id)}}

  defp claim_slot(_dir, _id, n) when n >= @max_in_flight,
    do: {:error, {:too_many_uploads, @max_in_flight, @max_in_flight}}

  defp claim_slot(dir, id, n) do
    contents = "#{id} #{now_ms()}\n"

    case File.write(Path.join(dir, @slot <> Integer.to_string(n)), contents, [:exclusive]) do
      :ok -> :ok
      {:error, :eexist} -> claim_slot(dir, id, n + 1)
      {:error, reason} -> {:error, {:upload_not_created, reason}}
    end
  end

  defp release(dir, id) do
    Enum.each(0..(@max_in_flight - 1), fn n ->
      path = Path.join(dir, @slot <> Integer.to_string(n))

      case slot_holder(path) do
        {^id, _opened_ms} -> File.rm(path)
        _other -> :ok
      end
    end)
  end

  defp slot_holder(path) do
    with {:ok, contents} <- File.read(path),
         [id, opened] <- contents |> String.trim() |> String.split(" ", parts: 2),
         {opened_ms, ""} <- Integer.parse(opened) do
      {id, opened_ms}
    else
      _unreadable -> nil
    end
  end

  # Hex and exactly the minted length. Nothing else reaches `Path.join/2`, so no id — however
  # it was spelled — can name a file outside this directory or a file that is not an upload.
  defp valid_id(id) when is_binary(id) do
    if Regex.match?(@id_pattern, id),
      do: {:ok, id},
      else: {:error, {:invalid_upload_id, describe(id)}}
  end

  # A committed upload, or the reason it is not one. "You have not finished sending this"
  # and "there is nothing here" are different mistakes and a client fixes them differently.
  defp committed(dir, id) do
    case staged(dir, id, @done) do
      {:error, {:unknown_upload, _id}} = absent ->
        case staged(dir, id, @part) do
          {:ok, _part} -> {:error, {:upload_incomplete, id}}
          _no_part -> absent
        end

      other ->
        other
    end
  end

  # A staged file must be a regular file. A symlink under this name was put there by
  # whoever could write in this directory, and appending to it appends to their target.
  defp staged(dir, id, suffix) do
    path = Path.join(dir, id <> suffix)

    case File.lstat(path) do
      {:ok, %File.Stat{type: :regular}} -> {:ok, path}
      {:ok, %File.Stat{type: type}} -> {:error, {:upload_not_a_file, type}}
      {:error, :enoent} -> {:error, {:unknown_upload, id}}
      {:error, reason} -> {:error, {:upload_unreadable, reason}}
    end
  end

  defp bound_chunk(chunk) do
    cond do
      chunk == "" -> {:error, :empty_chunk}
      byte_size(chunk) > @max_chunk_bytes -> {:error, {:chunk_too_large, @max_chunk_bytes}}
      true -> :ok
    end
  end

  defp held(path) do
    case File.lstat(path) do
      {:ok, %File.Stat{type: :regular, size: size}} -> {:ok, size}
      {:ok, %File.Stat{type: type}} -> {:error, {:upload_not_a_file, type}}
      {:error, reason} -> {:error, {:upload_unreadable, reason}}
    end
  end

  defp positioned(held, offset, chunk_bytes) do
    cond do
      offset != held -> {:error, {:offset_mismatch, held, offset}}
      held + chunk_bytes > max_total_bytes() -> {:error, {:upload_too_large, max_total_bytes()}}
      true -> :ok
    end
  end

  defp written(path, chunk) do
    case File.write(path, chunk, [:append, :binary]) do
      :ok -> :ok
      {:error, reason} -> {:error, {:upload_not_written, reason}}
    end
  end

  defp settle(id, _dir, _path, received, false) do
    {:ok,
     %{
       upload: id,
       received: received,
       complete: false,
       sha256: nil,
       chunk_bytes: @max_chunk_bytes
     }}
  end

  defp settle(id, dir, path, received, true) do
    done = Path.join(dir, id <> @done)

    with {:ok, bytes} <- File.read(path),
         :ok <- File.rename(path, done) do
      {:ok,
       %{
         upload: id,
         received: received,
         complete: true,
         sha256: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower),
         chunk_bytes: @max_chunk_bytes
       }}
    else
      {:error, reason} -> {:error, {:upload_not_committed, reason}}
    end
  end

  defp bytes({:ok, bytes}), do: {:ok, bytes}
  defp bytes({:error, reason}), do: {:error, {:upload_unreadable, reason}}

  # One pass over the eight slots, then one over the directory. A slot past either clock
  # takes its files with it; a file with no slot is litter from a crash between the two
  # writes and goes on its own.
  defp expire(dir) do
    now = now_ms()
    slots = Enum.map(0..(@max_in_flight - 1), &Path.join(dir, @slot <> Integer.to_string(&1)))

    {held, expired, unattributed?} =
      Enum.reduce(slots, {MapSet.new(), MapSet.new(), false}, &sweep_slot(&1, &2, dir, now))

    case File.ls(dir) do
      {:ok, names} ->
        names
        |> Enum.filter(&upload?/1)
        |> Enum.count(&orphaned(dir, &1, held, expired, unattributed?, now))

      {:error, _unreadable} ->
        0
    end
  end

  defp sweep_slot(path, {held, expired, unattributed?}, dir, now) do
    case slot_holder(path) do
      nil ->
        # Unreadable and young is a claim in progress whose id this pass cannot learn;
        # unreadable and old is litter.
        if young?(path, now) do
          {held, expired, true}
        else
          _ignored = File.rm(path)
          {held, expired, unattributed?}
        end

      {id, opened_ms} ->
        if expired?(dir, id, opened_ms, now) do
          _ignored = File.rm(path)
          {held, MapSet.put(expired, id), unattributed?}
        else
          {MapSet.put(held, id), expired, unattributed?}
        end
    end
  end

  # A regular file written inside the grace window. A symlink or anything else is never
  # young: no opener creates one, so there is no claim in progress it could belong to.
  defp young?(path, now) do
    case File.lstat(path, time: :posix) do
      {:ok, %File.Stat{type: :regular, mtime: mtime}} when is_integer(mtime) ->
        now - mtime * 1_000 < @claim_grace_ms

      _other ->
        false
    end
  end

  defp upload?(name) do
    String.ends_with?(name, @part) or String.ends_with?(name, @done) or
      String.contains?(name, @taken)
  end

  # Held is kept. The files of a slot this pass expired are reclaimed whatever their age,
  # because their id is known. A slotless file is reclaimed only when this pass read every
  # slot — a slot it could not read holds an id it does not know — and the file is not a
  # claim's second write still in flight.
  defp orphaned(dir, name, held, expired, unattributed?, now) do
    id = name |> String.split(".") |> List.first()
    path = Path.join(dir, name)

    cond do
      MapSet.member?(held, id) -> false
      MapSet.member?(expired, id) -> reclaim(path, name)
      unattributed? -> false
      young?(path, now) -> false
      true -> reclaim(path, name)
    end
  end

  defp reclaim(path, name) do
    # Never the bytes, never the sha: what an operator needs from this line is that a
    # transfer was reclaimed, and the id is the whole of that.
    Logger.debug("wasm upload #{name} reclaimed")
    File.rm(path) == :ok
  end

  # Two clocks, checked together. The idle one is the file's own mtime, which a write moves
  # and nothing here moves artificially; the total one is the slot's claim time, which
  # nothing moves at all.
  defp expired?(dir, id, opened_ms, now) do
    cond do
      now - opened_ms > @max_lifetime_ms -> true
      true -> idle?(dir, id, opened_ms, now)
    end
  end

  # No staged file at all is a claim's second write still in flight while the claim is
  # young, and an upload whose file went missing once it is not.
  defp idle?(dir, id, opened_ms, now) do
    [Path.join(dir, id <> @part), Path.join(dir, id <> @done)]
    |> Enum.map(&File.lstat(&1, time: :posix))
    |> Enum.find_value(:absent, fn
      {:ok, %File.Stat{type: :regular, mtime: mtime}} when is_integer(mtime) -> mtime
      _other -> nil
    end)
    |> case do
      :absent -> now - opened_ms > @claim_grace_ms
      mtime -> now - mtime * 1_000 > @ttl_ms
    end
  end

  defp unique, do: Integer.to_string(System.unique_integer([:positive, :monotonic]))

  defp now_ms, do: System.system_time(:millisecond)

  defp byte_size_of(bytes) when is_binary(bytes), do: byte_size(bytes)
  defp byte_size_of(other), do: other

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)
end
