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

  Deliberately, and not by accident of style. Most of what that module bounds is bounded
  here with the *same number*, read from it rather than copied: `max_in_flight/0` is its
  slot count and `idle_ms/0` and `max_lifetime_ms/0` are its two clocks. A second set of
  numbers would be a second place for the two to disagree.

  ## The chunk is the one number that could not be inherited (W19 review, H1)

  The first cut of this module took the upload's 512 KiB chunk as well, and wrote down that
  a node whose `OUROBOROS_GATEWAY_MAX_FRAME` could not carry one "refuses the frame before
  this module sees it". Both halves of that were wrong, and the direction of travel is
  exactly why.

  `Ouroboros.Gateway.Conn` sets `packet_size` on the socket it **receives** on; nothing
  holds an outbound reply to `max_frame` at all. And an upload's chunk is the *client's*
  to size — it sends what it likes up to the ceiling, and the node's own reply states that
  ceiling so a client can shrink — whereas a download's chunk is the *node's*, and it is
  always maximal. So a node configured with a 64 KiB frame answered `wasm.download` with a
  699 260-byte line: measured, not reasoned about. A client that mirrors the frame it was
  advertised — which is what `tui/src/transport.rs` documents itself as doing — reads that
  as `FrameTooLarge` and the transfer dies. And this is not a corner: lowering `max_frame`
  is precisely what pushes an artifact onto this path in the first place.

  So the chunk is derived from the node's own frame:

      chunk = min(Upload.max_chunk_bytes(), (max_frame - #{1024}) * 3 / 4)

  Three quarters because base64 is four bytes to three, and #{1024} bytes held back for the
  JSON object around it — an id, an offset, a size, a 64-character digest, a flag and the
  JSON-RPC envelope, measured at 208 bytes on this build, with the rest as room for a field
  a later build adds. At the default mebibyte frame the upload's 512 KiB is the smaller of
  the two and nothing changes; below it, the chunk shrinks with the frame, and the number is
  fixed in the slot at mint time so an operator who changes the setting mid-transfer cannot
  move a boundary out from under a client walking one.

  Below `#{4 * 1024}` decoded bytes `put/2` refuses by name rather than shrinking further:
  a node whose frame cannot carry four kibibytes of artifact at a time would need nearly
  three thousand round trips for the worst artifact §7.3 admits, and that is not a transfer,
  it is a refusal wearing a progress bar. The signature then falls back to the source form
  with `artifact_not_staged`, which is the same answer every other unstageable node gets.

  ## Everything else is the upload's, verbatim

  `<data_dir>/wasm/download/`, created 0700 and held to `File.lstat/1`; a slot is a file
  created `O_CREAT|O_EXCL` and the slot file *is* the claim; the id is sixteen bytes of
  `:crypto.strong_rand_bytes/1` as hex and is validated as `[0-9a-f]{32}` on the way back
  in, because a value that made a round trip through a client is a value that arrived from a
  client; files are 0600; two clocks; and every entry point sweeps, including the ones that
  only read. Nothing here follows a symlink.

  ## Two clocks, and why a read moves one of them

  Idle is ten minutes and the total lifetime is thirty, both `Upload`'s. The difference is
  what moves the idle one. An upload's mtime moves because bytes arrive and nothing has to
  move it artificially; a download is written once and then only read, so if the idle clock
  were left to the file it would measure *time since minting* under a different name — and
  the first cut did exactly that: a client walking a large artifact was reclaimed at ten
  minutes mid-transfer, and the thirty-minute lifetime could not be reached by any sequence
  of calls (W19 review, M3). So `read/3` touches the file. The idle clock now means what it
  says — ten minutes with nobody reading — and the lifetime is what bounds a client that
  reads one chunk every nine minutes forever.

  ## What a slot holds, and why the digest lives in it

  A slot line is `<id> <claimed_ms> <chunk_bytes> <sha256>`. The digest is computed once, at
  `put/2`, over the bytes in hand, and every chunk's answer repeats it out of the slot rather
  than re-hashing an eleven-mebibyte file twenty-two times. The chunk is fixed there for the
  reason above: a transfer's boundaries are decided when it is minted, not re-derived on each
  read from a setting an operator may have changed since. That also makes the slot the
  authority rather than the file: a download with no live slot is not readable at all,
  whatever is lying in the directory under its name.

  The line is trusted as read, and that is a statement about the directory rather than about
  the line: it lives 0700 under this node's own data directory, written by this process, and
  anybody who could rewrite it could equally replace the artifact beside it. What that trust
  does **not** extend to is the client — the digest a client checks against is the one in the
  *signed manifest*, and `ouro wasm sign` holds the two to each other before it writes a file
  (W19 review, M4).

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
  held until its clocks run out is ten minutes of ceiling a finished transfer is still
  spending — thirty for a client that keeps reading and never finishes. Eight of those and
  the ninth `sign` mints no slot at all and falls back to the source form, which is a node
  denying itself the feature for ten minutes because somebody signed nine large capabilities
  in a row.

  So the read that returns `final: true` releases the slot on the way out, and `release/2`
  is public for a caller that abandons one. The honest cost is the other end of it: a
  client that never receives that last answer cannot ask again, and re-signing is what it
  does instead — a compile and a rate-limit slot. That is one lost frame against ten minutes
  of held ceiling, and the clocks are still the backstop for everything else.

  Two residuals about those clocks, stated rather than left to be found. **There is no
  timer**: every reclamation happens inside somebody's `put/2`, `read/3` or `release/2`, so
  eight abandoned artifacts sit on disk — up to eight times
  `Ouroboros.Wasm.Bundle.max_precompiled_bytes/0` — until the next call to this module, which
  on a quiet node may be never. That is `Ouroboros.Wasm.Upload`'s posture and the reason
  neither module needs a process; what it costs is disk on an idle node, and §12 counts it.
  And **the id is the whole of what a reclamation logs** — one debug line naming a slot that
  is already gone, never the bytes and never the digest, because that is all an operator
  needs and anything more would be this module writing out somebody's machine code.
  """

  require Logger

  alias Ouroboros.Wasm.{Bundle, Upload}

  @id_bytes 16
  @id_pattern ~r/\A[0-9a-f]{32}\z/

  @bin ".bin"
  @slot "slot-"

  # What the JSON object around one chunk costs on the wire: an id, an offset, a size, a
  # 64-character digest, a flag, and the JSON-RPC envelope. Measured at 208 bytes on this
  # build; a kibibyte is that with room for a field a later build adds.
  @envelope_slack 1_024

  # The smallest chunk worth answering with. A node whose frame cannot carry four kibibytes
  # of artifact at a time would need nearly three thousand round trips for the worst artifact
  # §7.3 admits; that is not a transfer, and `put/2` says so rather than shrinking further.
  @min_chunk_bytes 4 * 1_024

  # The frame this node falls back to, mirroring `Ouroboros.Gateway.Config`'s own default
  # rather than inventing a second one — the same mirror `Ouroboros.Wasm.Deploy` keeps.
  @default_gateway_max_frame 1_048_576

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

  @doc """
  The most decoded bytes one `wasm.download` reply carries on this node (W19 review, H1).

  The upload's chunk, or what this node's own frame will hold — whichever is smaller.
  Nothing on the outbound path is held to `OUROBOROS_GATEWAY_MAX_FRAME`, so a chunk larger
  than the frame is a line this node writes and its own client refuses; see the moduledoc for
  the measurement. At the default mebibyte frame the upload's 512 KiB is the smaller of the
  two and this is exactly `Ouroboros.Wasm.Upload.max_chunk_bytes/0`.

  This is what a *new* slot is minted with. A slot already in flight keeps the number it was
  minted with, so an operator who changes the setting cannot move a boundary out from under a
  client walking one.
  """
  @spec max_chunk_bytes() :: non_neg_integer()
  def max_chunk_bytes do
    frame = max(gateway_max_frame() - @envelope_slack, 0)
    min(Upload.max_chunk_bytes(), div(frame * 3, 4))
  end

  @doc "The smallest chunk this node will mint a slot for; below it `put/2` refuses."
  @spec min_chunk_bytes() :: pos_integer()
  def min_chunk_bytes, do: @min_chunk_bytes

  defp gateway_max_frame do
    with settings when is_list(settings) <- Application.get_env(:ouroboros, :gateway, []),
         bytes when is_integer(bytes) and bytes > 0 <- Keyword.get(settings, :max_frame) do
      bytes
    else
      _unset_or_invalid -> @default_gateway_max_frame
    end
  end

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
    chunk = max_chunk_bytes()

    with :ok <- bound(bytes),
         :ok <- framed(chunk),
         {:ok, dir} <- prepared(opts),
         {:ok, id, path} <- opened(dir, sha, chunk),
         :ok <- written(dir, id, path, bytes) do
      {:ok,
       %{
         download: id,
         size: byte_size(bytes),
         sha256: sha,
         chunk_bytes: chunk
       }}
    end
  end

  def put(bytes, _opts), do: {:error, {:invalid_download, describe(bytes)}}

  @doc """
  Answers one chunk of a download, and releases the slot when that chunk is the last.

  `offset` is a **chunk boundary** — a multiple of the `chunk_bytes` this slot was minted
  with, strictly below the size — and not a seek. A client walks the file with the offsets this module's own answers
  hand it, so an offset that is not one of them is a client that has lost its place or a
  frame that arrived out of order, and either is refused rather than answered with bytes
  from the middle of something. `data` is base64, because that is what the frame carries;
  it decodes to at most the slot's own `chunk_bytes`.

  A read that is not the last one **moves the idle clock**: see the moduledoc for why a
  download's is not the file's own mtime the way an upload's is.
  """
  @spec read(String.t(), non_neg_integer(), keyword()) :: {:ok, chunk()} | {:error, term()}
  def read(id, offset, opts \\ [])

  def read(id, offset, opts)
      when is_binary(id) and is_integer(offset) and offset >= 0 and
             is_list(opts) do
    with {:ok, dir} <- swept(opts),
         {:ok, id} <- valid_id(id),
         {:ok, chunk_bytes, sha} <- claimed(dir, id),
         {:ok, path, size} <- staged(dir, id),
         :ok <- positioned(offset, size, chunk_bytes),
         {:ok, chunk} <- chunk_at(path, offset, size, chunk_bytes) do
      final? = offset + byte_size(chunk) >= size

      if final? do
        # The last chunk is the only "I am done" this verb's closed parameters can express.
        discard(dir, id)
      else
        # W19 review, M3. Nothing writes to a download after it is minted, so the idle clock
        # has to be moved by the only progress there is. Without this a client walking a large
        # artifact is reclaimed mid-transfer at ten minutes and the lifetime below is
        # unreachable by any sequence of calls.
        _touched = File.touch(path)
      end

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
    with {:ok, dir} <- swept(opts),
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

  # A frame too small to carry a usable chunk is refused where the slot would be claimed,
  # so the signature falls back to the source form rather than minting a transfer nobody
  # could finish (W19 review, H1).
  defp framed(chunk) when chunk >= @min_chunk_bytes, do: :ok

  defp framed(chunk),
    do: {:error, {:frame_too_small, gateway_max_frame(), chunk, @min_chunk_bytes}}

  defp bound(bytes) do
    cond do
      bytes == "" -> {:error, :empty_download}
      byte_size(bytes) > max_total_bytes() -> {:error, {:download_too_large, max_total_bytes()}}
      true -> :ok
    end
  end

  # The slot is claimed before a byte is written, with `O_CREAT|O_EXCL`, so the ceiling is
  # enforced by the filesystem rather than by a count somebody took.
  defp opened(dir, sha, chunk) do
    id = @id_bytes |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)

    case claim_slot(dir, id, sha, chunk, 0) do
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

  defp claim_slot(dir, id, sha, chunk, n) do
    if n >= max_in_flight() do
      {:error, {:too_many_downloads, max_in_flight(), max_in_flight()}}
    else
      contents = "#{id} #{now_ms()} #{chunk} #{sha}\n"

      case File.write(Path.join(dir, @slot <> Integer.to_string(n)), contents, [:exclusive]) do
        :ok -> :ok
        {:error, :eexist} -> claim_slot(dir, id, sha, chunk, n + 1)
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
             {^id, _opened_ms, chunk, sha} -> {chunk, sha}
             _other -> nil
           end
         end) do
      nil -> {:error, {:unknown_download, id}}
      {chunk, sha} -> {:ok, chunk, sha}
    end
  end

  defp holder?(dir, id), do: match?({:ok, _chunk, _sha}, claimed(dir, id))

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
  defp positioned(offset, size, chunk) do
    cond do
      rem(offset, chunk) != 0 -> {:error, {:offset_not_a_chunk_boundary, offset, chunk}}
      offset >= size -> {:error, {:offset_past_size, offset, size}}
      true -> :ok
    end
  end

  # `pread` and not `File.read/1`: the whole point of this module is that the file does not
  # fit in a reply, so nothing here reads more of it than one frame carries.
  defp chunk_at(path, offset, size, chunk_bytes) do
    length = min(chunk_bytes, size - offset)

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
         [id, opened, chunk, sha] <- contents |> String.trim() |> String.split(" ", parts: 4),
         {opened_ms, ""} <- Integer.parse(opened),
         {chunk_bytes, ""} <- Integer.parse(chunk) do
      {id, opened_ms, chunk_bytes, sha}
    else
      _unreadable -> nil
    end
  end

  defp discard(dir, id) do
    _ignored = File.rm(Path.join(dir, id <> @bin))

    Enum.each(slots(dir), fn path ->
      case slot_holder(path) do
        {^id, _opened_ms, _chunk, _sha} -> File.rm(path)
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

      {id, opened_ms, _chunk, _sha} ->
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
