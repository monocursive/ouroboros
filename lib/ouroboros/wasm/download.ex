defmodule Ouroboros.Wasm.Download do
  @moduledoc """
  The other half of the staging area: bytes this node made, going out in frames (W19, D28).

  `Ouroboros.Wasm.Upload` exists because a component is sixteen mebibytes and a JSON-RPC
  frame is one. This module exists because W8 gave the *reply* the same problem. Since W8
  the bundle carries a second section — wasmtime's serialized form of the component,
  compiled here at sign time — and the operator running `ouro wasm sign` holds the
  component and has never seen the artifact. So the artifact is the half that has to
  travel, it is 258 093 bytes for the 48 KiB reference guest and eleven mebibytes for the
  worst shape §7.3 admits, and one gateway reply is not a file transfer.

  The answer W8 shipped was a ceiling: past three quarters of the gateway's own frame the
  signer dropped the artifact and signed the source form alone. That was honest — the
  capability still deployed, it just compiled on every node — and it was a ceiling nobody
  had chosen for a reason anybody wanted. This module removes it the way D16 removed the
  other one: not by making a reply bigger, by cutting the bytes into the frames that
  already exist.

  ## It is `Ouroboros.Wasm.Upload`, in the other direction

  Deliberately, and not by accident of style. Every bound that module states is stated
  here for the same reason and with the same number, read from that module rather than
  copied: `max_chunk_bytes/0` is its chunk, `max_in_flight/0` its slot count,
  `idle_ms/0` and `max_lifetime_ms/0` its two clocks. A second set of numbers here would
  be a second place for the two to disagree, and there is nothing about the direction of
  travel that makes 512 KiB the wrong chunk.

  That inherits the upload's honest limit too, and it is worth saying rather than leaving
  to be discovered: a chunk is 512 KiB of decoded bytes, which is about 683 KiB of base64
  on the wire, and a node whose operator set `OUROBOROS_GATEWAY_MAX_FRAME` below that
  refuses the frame before this module sees it (D16). Such a node cannot run `wasm.upload`
  either, so it could not have got a component to this one in the first place. What the
  frame *does* decide is which side of `Ouroboros.Wasm.Deploy.max_receipt_precompiled_bytes/0`
  an artifact falls on, and therefore whether a slot is minted at all.

  So: `<data_dir>/wasm/download/`, created 0700 and held to `File.lstat/1`; a slot is a
  file created `O_CREAT|O_EXCL` and the slot file *is* the claim; the id is sixteen bytes
  of `:crypto.strong_rand_bytes/1` as hex and is validated as `[0-9a-f]{32}` on the way
  back in, because a value that made a round trip through a client is a value that arrived
  from a client; files are 0600; two clocks — idle by mtime and total from the moment the
  slot was claimed — and every entry point sweeps, including the ones that only read.
  Nothing here follows a symlink.

  ## What a slot holds, and why the digest lives in it

  A slot line is `<id> <claimed_ms> <sha256>`. The digest is computed once, at `put/2`,
  over the bytes in hand, and every chunk's answer repeats it out of the slot rather than
  re-hashing an eleven-mebibyte file twenty-two times. That also makes the slot the
  authority rather than the file: a download with no live slot is not readable at all,
  whatever is lying in the directory under its name.

  ## Whose bytes these are

  Only this node's own. There is no verb that puts — `Ouroboros.Gateway.Methods` routes
  `wasm.download` to `read/3` and to nothing else — and the one caller of `put/2` is
  `Ouroboros.Wasm.Deploy.sign/2`, handing over an artifact its own helper compiled from a
  component its own signing service just signed. A node therefore hands out only bytes it
  made, under `:operate`, bound by a digest that is also in the signed manifest, in the
  frames uploads already use. Nothing a client sends is ever readable through here.

  ## The final chunk releases the slot

  Stated because the alternative was reasonable too. `wasm.download`'s parameters are
  closed at `download`, `offset` and `node` (C12), so there is no frame in which a client
  says "I am done" other than the one in which it asks for the last chunk — and a slot
  held until its clock runs out is thirty minutes of ceiling a finished transfer is still
  spending. Eight of those and the ninth `sign` mints no slot at all and falls back to the
  source form, which is a node denying itself the feature for half an hour because
  somebody signed nine large capabilities in a row.

  So the read that returns `final: true` releases the slot on the way out, and `release/2`
  is public for a caller that abandons one. The honest cost is the other end of it: a
  client that never receives that last answer cannot ask again, and re-signing is what it
  does instead — a compile and a rate-limit slot. That is one lost frame against a
  half-hour of held ceiling, and the clocks are still the backstop for everything else.
  """

  require Logger

  alias Ouroboros.Wasm.{Bundle, Upload}

  @id_bytes 16
  @id_pattern ~r/\A[0-9a-f]{32}\z/

  @bin ".bin"
  @slot "slot-"

  # See `Upload`'s own note: a claim is two writes and a sweep in a concurrent call can land
  # between them. Nothing regular and younger than this is reclaimed on the strength of what
  # it looks like.
  @claim_grace_ms 30_000

  @type receipt :: %{
          download: String.t(),
          size: pos_integer(),
          sha256: String.t(),
          chunk_bytes: pos_integer()
        }

  @type chunk :: %{
          download: String.t(),
          offset: non_neg_integer(),
          data: String.t(),
          size: pos_integer(),
          sha256: String.t(),
          final: boolean()
        }

  @doc "The most decoded bytes one `wasm.download` frame carries, which is the upload's."
  @spec max_chunk_bytes() :: pos_integer()
  def max_chunk_bytes, do: Upload.max_chunk_bytes()

  @doc """
  The most bytes one download may hold: the largest artifact a bundle may carry.

  Not the receipt's own ceiling and not the frame — those bound what fits in *one reply*,
  which is the question this module exists to stop asking. What bounds a slot is what a
  signed bundle could legitimately contain (`Ouroboros.Wasm.Bundle.max_precompiled_bytes/0`),
  because a slot holding more than that is holding bytes no bundle could carry.
  """
  @spec max_total_bytes() :: pos_integer()
  def max_total_bytes, do: Bundle.max_precompiled_bytes()

  @doc "The most downloads one node holds at once, which is the upload's slot count."
  @spec max_in_flight() :: pos_integer()
  def max_in_flight, do: Upload.max_in_flight()

  @doc "How long one download may exist, from the moment its slot was claimed."
  @spec max_lifetime_ms() :: pos_integer()
  def max_lifetime_ms, do: Upload.max_lifetime_ms()

  @doc "How long a download may go unread before the node reclaims it."
  @spec idle_ms() :: pos_integer()
  def idle_ms, do: Upload.idle_ms()

  @doc """
  Where this node stages downloads, or `{:error, :no_data_dir}` on a node with none.

  `opts[:root]` names one explicitly, for tests that must not touch a real data directory —
  the same seam `Ouroboros.Wasm.Upload.root/1` offers, and for the same reason.
  """
  @spec root(keyword()) :: {:ok, Path.t()} | {:error, :no_data_dir}
  def root(opts \\ []) do
    case Keyword.get(opts, :root) do
      dir when is_binary(dir) and dir != "" ->
        {:ok, dir}

      _unset ->
        case Application.get_env(:ouroboros, :data_dir) do
          dir when is_binary(dir) and dir != "" -> {:ok, Path.join([dir, "wasm", "download"])}
          _unset -> {:error, :no_data_dir}
        end
    end
  end

  @doc """
  Mints a slot over `bytes` and answers what a client needs to fetch them.

  The digest is computed here, over the bytes in hand, and is the same number the signed
  manifest's `precompiled.sha256` carries — which is what makes it worth checking on the
  far side: a client that reassembles to a different digest has not been handed this
  artifact, and the manifest it is about to write a bundle around says so.
  """
  @spec put(binary(), keyword()) :: {:ok, receipt()} | {:error, term()}
  def put(bytes, opts \\ [])

  def put(bytes, opts) when is_binary(bytes) and is_list(opts) do
    sha = :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

    with :ok <- bound(bytes),
         {:ok, dir} <- prepared(opts),
         {:ok, id, path} <- opened(dir, sha),
         :ok <- written(dir, id, path, bytes) do
      {:ok,
       %{
         download: id,
         size: byte_size(bytes),
         sha256: sha,
         chunk_bytes: max_chunk_bytes()
       }}
    end
  end

  def put(bytes, _opts), do: {:error, {:invalid_download, describe(bytes)}}

  @doc """
  Answers one chunk of a download, and releases the slot when that chunk is the last.

  `offset` is a **chunk boundary** — a multiple of `max_chunk_bytes/0`, strictly below the
  size — and not a seek. A client walks the file with the offsets this module's own answers
  hand it, so an offset that is not one of them is a client that has lost its place or a
  frame that arrived out of order, and either is refused rather than answered with bytes
  from the middle of something. `data` is base64, because that is what the frame carries;
  it decodes to at most `max_chunk_bytes/0`.
  """
  @spec read(String.t(), non_neg_integer(), keyword()) :: {:ok, chunk()} | {:error, term()}
  def read(id, offset, opts \\ [])

  def read(id, offset, opts)
      when is_binary(id) and is_integer(offset) and offset >= 0 and
             is_list(opts) do
    with {:ok, dir} <- swept(opts),
         {:ok, id} <- valid_id(id),
         {:ok, sha} <- claimed(dir, id),
         {:ok, path, size} <- staged(dir, id),
         :ok <- positioned(offset, size),
         {:ok, chunk} <- chunk_at(path, offset, size) do
      final? = offset + byte_size(chunk) >= size

      # The last chunk is the only "I am done" this verb's closed parameters can express.
      if final?, do: discard(dir, id)

      {:ok,
       %{
         download: id,
         offset: offset,
         data: Base.encode64(chunk),
         size: size,
         sha256: sha,
         final: final?
       }}
    end
  end

  def read(id, offset, _opts),
    do: {:error, {:invalid_download_request, describe({id, offset})}}

  @doc """
  Ends a download before its clocks do, for a caller that has finished with it.

  `read/3` calls this itself on the chunk that completes a transfer; it is public for the
  caller that abandons one — a `sign/2` that has minted a slot and then failed on the way
  to a receipt, which would otherwise leave the ceiling spent on bytes nobody will ask for.
  """
  @spec release(String.t(), keyword()) :: :ok | {:error, term()}
  def release(id, opts \\ []) when is_binary(id) do
    with {:ok, dir} <- root(opts),
         {:ok, id} <- valid_id(id) do
      if File.exists?(Path.join(dir, id <> @bin)) or holder?(dir, id) do
        discard(dir, id)
        :ok
      else
        {:error, {:unknown_download, id}}
      end
    end
  end

  @doc """
  Removes every download past either clock, returning how many went.

  Called at the head of every entry point, which is the only reason this module needs no
  timer — `Ouroboros.Wasm.Upload`'s own reasoning, and a sweep that ran only where bytes
  were written would leave `read/3` handing back files this module had promised were gone.
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
        {:error, {:download_directory_not_a_directory, type}}

      {:error, :enoent} ->
        create_directory(dir)

      {:error, reason} ->
        {:error, {:download_directory_unwritable, reason}}
    end
  end

  defp create_directory(dir) do
    case File.mkdir_p(dir) do
      :ok ->
        _ignored = File.chmod(dir, 0o700)
        :ok

      {:error, reason} ->
        {:error, {:download_directory_unwritable, reason}}
    end
  end

  defp bound(bytes) do
    cond do
      bytes == "" -> {:error, :empty_download}
      byte_size(bytes) > max_total_bytes() -> {:error, {:download_too_large, max_total_bytes()}}
      true -> :ok
    end
  end

  # The slot is claimed before a byte is written, with `O_CREAT|O_EXCL`, so the ceiling is
  # enforced by the filesystem rather than by a count somebody took.
  defp opened(dir, sha) do
    id = @id_bytes |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)

    case claim_slot(dir, id, sha, 0) do
      :ok ->
        path = Path.join(dir, id <> @bin)

        # `[:exclusive]` is a belt: `id` is sixteen random bytes, so no reachable input makes
        # this file already exist. The exclusivity that bounds this node is the slot claim.
        case File.write(path, "", [:exclusive]) do
          :ok ->
            _ignored = File.chmod(path, 0o600)
            {:ok, id, path}

          {:error, reason} ->
            discard(dir, id)
            {:error, {:download_not_created, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp claim_slot(dir, id, sha, n) do
    if n >= max_in_flight() do
      {:error, {:too_many_downloads, max_in_flight(), max_in_flight()}}
    else
      contents = "#{id} #{now_ms()} #{sha}\n"

      case File.write(Path.join(dir, @slot <> Integer.to_string(n)), contents, [:exclusive]) do
        :ok -> :ok
        {:error, :eexist} -> claim_slot(dir, id, sha, n + 1)
        {:error, reason} -> {:error, {:download_not_created, reason}}
      end
    end
  end

  # The mode was set when the file was created and a write does not change it, so there is no
  # second `chmod` here: a check no test can tell from its absence is a sentence, not a
  # defence. A failure *does* take the slot with it — a claim whose bytes never landed is
  # ceiling spent on nothing.
  defp written(dir, id, path, bytes) do
    case File.write(path, bytes, [:binary]) do
      :ok ->
        :ok

      {:error, reason} ->
        discard(dir, id)
        {:error, {:download_not_written, reason}}
    end
  end

  # Hex and exactly the minted length. Nothing else reaches `Path.join/2`.
  defp valid_id(id) when is_binary(id) do
    if Regex.match?(@id_pattern, id),
      do: {:ok, id},
      else: {:error, {:invalid_download_id, describe(id)}}
  end

  # The live slot's digest, or the reason there is no live slot. This is what makes the slot
  # the authority: a file in this directory whose slot the clocks took is not a download,
  # however readable it still is.
  defp claimed(dir, id) do
    case Enum.find_value(slots(dir), fn path ->
           case slot_holder(path) do
             {^id, _opened_ms, sha} -> sha
             _other -> nil
           end
         end) do
      nil -> {:error, {:unknown_download, id}}
      sha -> {:ok, sha}
    end
  end

  defp holder?(dir, id), do: match?({:ok, _sha}, claimed(dir, id))

  # A staged file must be a regular file. A symlink under this name was put there by whoever
  # could write in this directory, and reading through it reads their target.
  defp staged(dir, id) do
    path = Path.join(dir, id <> @bin)

    case File.lstat(path) do
      {:ok, %File.Stat{type: :regular, size: size}} when size > 0 -> {:ok, path, size}
      {:ok, %File.Stat{type: :regular}} -> {:error, {:unknown_download, id}}
      {:ok, %File.Stat{type: type}} -> {:error, {:download_not_a_file, type}}
      {:error, :enoent} -> {:error, {:unknown_download, id}}
      {:error, reason} -> {:error, {:download_unreadable, reason}}
    end
  end

  # Two refusals, and they are different mistakes. An offset off a boundary is a client that
  # has lost its place; an offset at or past the size is a client asking for bytes that are
  # not there. Neither is answered with a slice.
  defp positioned(offset, size) do
    chunk = max_chunk_bytes()

    cond do
      rem(offset, chunk) != 0 -> {:error, {:offset_not_a_chunk_boundary, offset, chunk}}
      offset >= size -> {:error, {:offset_past_size, offset, size}}
      true -> :ok
    end
  end

  # `pread` and not `File.read/1`: the whole point of this module is that the file does not
  # fit in a reply, so nothing here reads more of it than one frame carries.
  defp chunk_at(path, offset, size) do
    length = min(max_chunk_bytes(), size - offset)

    case :file.open(path, [:read, :binary, :raw]) do
      {:ok, fd} ->
        result = :file.pread(fd, offset, length)
        _ignored = :file.close(fd)
        read_result(result)

      {:error, reason} ->
        {:error, {:download_unreadable, reason}}
    end
  end

  defp read_result({:ok, data}) when is_binary(data), do: {:ok, data}
  defp read_result(:eof), do: {:error, :download_truncated}
  defp read_result({:error, reason}), do: {:error, {:download_unreadable, reason}}

  defp slots(dir),
    do: Enum.map(0..(max_in_flight() - 1), &Path.join(dir, @slot <> Integer.to_string(&1)))

  defp slot_holder(path) do
    with {:ok, contents} <- File.read(path),
         [id, opened, sha] <- contents |> String.trim() |> String.split(" ", parts: 3),
         {opened_ms, ""} <- Integer.parse(opened) do
      {id, opened_ms, sha}
    else
      _unreadable -> nil
    end
  end

  defp discard(dir, id) do
    _ignored = File.rm(Path.join(dir, id <> @bin))

    Enum.each(slots(dir), fn path ->
      case slot_holder(path) do
        {^id, _opened_ms, _sha} -> File.rm(path)
        _other -> :ok
      end
    end)
  end

  # One pass over the slots, then one over the directory. A slot past either clock takes its
  # file with it; a file with no slot is litter from a crash between the two writes.
  defp expire(dir) do
    now = now_ms()

    {held, expired, unattributed?} =
      Enum.reduce(slots(dir), {MapSet.new(), MapSet.new(), false}, &sweep_slot(&1, &2, dir, now))

    case File.ls(dir) do
      {:ok, names} ->
        names
        |> Enum.filter(&String.ends_with?(&1, @bin))
        |> Enum.count(&orphaned(dir, &1, held, expired, unattributed?, now))

      {:error, _unreadable} ->
        0
    end
  end

  defp sweep_slot(path, {held, expired, unattributed?}, dir, now) do
    case slot_holder(path) do
      nil ->
        if young?(path, now) do
          {held, expired, true}
        else
          _ignored = File.rm(path)
          {held, expired, unattributed?}
        end

      {id, opened_ms, _sha} ->
        if expired?(dir, id, opened_ms, now) do
          _ignored = File.rm(path)
          {held, MapSet.put(expired, id), unattributed?}
        else
          {MapSet.put(held, id), expired, unattributed?}
        end
    end
  end

  defp young?(path, now) do
    case File.lstat(path, time: :posix) do
      {:ok, %File.Stat{type: :regular, mtime: mtime}} when is_integer(mtime) ->
        now - mtime * 1_000 < @claim_grace_ms

      _other ->
        false
    end
  end

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
    # Never the bytes and never the digest: what an operator needs is that a slot went.
    Logger.debug("wasm download #{name} reclaimed")
    File.rm(path) == :ok
  end

  # Two clocks. The idle one is the file's own mtime — which nothing here moves artificially,
  # so a download nobody reads ages exactly as a download nobody reads should. The total one
  # is the slot's claim time, which nothing moves at all.
  defp expired?(dir, id, opened_ms, now) do
    cond do
      now - opened_ms > max_lifetime_ms() -> true
      true -> idle?(dir, id, opened_ms, now)
    end
  end

  defp idle?(dir, id, opened_ms, now) do
    case File.lstat(Path.join(dir, id <> @bin), time: :posix) do
      {:ok, %File.Stat{type: :regular, mtime: mtime}} when is_integer(mtime) ->
        now - mtime * 1_000 > idle_ms()

      _absent ->
        now - opened_ms > @claim_grace_ms
    end
  end

  defp now_ms, do: System.system_time(:millisecond)

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)
end
