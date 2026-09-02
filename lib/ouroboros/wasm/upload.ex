defmodule Ouroboros.Wasm.Upload do
  @moduledoc """
  The staging area a component or a bundle crosses the gateway in (docs/WASM.md D16).

  A JSON-RPC frame is a line, and `Ouroboros.Gateway.Config` bounds one at
  `OUROBOROS_GATEWAY_MAX_FRAME` — a mebibyte by default, with the Rust client refusing to
  *send* more than the same number. A component is bounded at sixteen mebibytes, which is
  twenty-one after base64. So there is no honest way to put one in a parameter, and the
  choice is between shrinking what an operator may deploy to whatever fits one frame and
  cutting the bytes into frames that do. This is the second one.

  ## What it is, and what it deliberately is not

  Files in `<data_dir>/wasm/uploads`, and no process. An upload is `<id>.part` while it is
  being written and `<id>.done` once its author has said it is finished; `take/2` reads a
  `.done` and removes it. There is no supervisor entry, no ETS table and no GenServer,
  because there is no state here that outlives a file: the offset is the file's size, the
  membership test is `File.exists?/1`, and the expiry is the file's mtime. A registry of
  in-flight uploads would be a second answer to every one of those questions, and the two
  would disagree the first time a node restarted mid-upload.

  ## Every bound, and why each one is where it is

    * **The id is minted here.** Sixteen random bytes as hex. A client-chosen id would be
      a client-chosen filename, and no amount of validation afterwards is as good as never
      having taken one. It is still validated on the way back in — `[0-9a-f]{32}` and
      nothing else reaches `Path.join/2` — because a value that made a round trip through
      a client is a value that arrived from a client.
    * **One chunk is #{div(512 * 1024, 1024)} KiB** of decoded bytes. Base64 makes that
      about 683 KiB on the wire, which clears the default frame with a third to spare, and
      a node whose operator lowered `OUROBOROS_GATEWAY_MAX_FRAME` refuses the frame before
      this module ever sees it. The reply states the number so a client sizes its chunks
      from the node's answer rather than from a constant compiled into it.
    * **The total is `Ouroboros.Wasm.Bundle.max_bytes/0`** — the largest thing that could
      legitimately be uploaded, which is a bundle at the component ceiling. Checked before
      each append against the size the file already has, so the ceiling cannot be reached
      and then exceeded.
    * **#{8} uploads may be in flight per node.** An `:operate` client is an operator, but
      a client that has stopped talking still owns disk until something reclaims it, and
      "the disk filled up" is not an outcome a socket gets to cause.
    * **Ten minutes.** Every call sweeps the directory first and removes what is older,
      which is why no timer exists: the thing that would fire one is the thing that would
      notice, and it is already here.

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

  @max_chunk_bytes 512 * 1024
  @max_in_flight 8
  @ttl_ms 10 * 60 * 1_000

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

  Consume-once on purpose: an upload is a transfer, and a transfer that could be replayed
  into two deployments is a name two callers can disagree about. A caller that needs the
  bytes twice uploads them twice.
  """
  @spec take(String.t(), keyword()) :: {:ok, binary()} | {:error, term()}
  def take(id, opts \\ []) when is_binary(id) do
    with {:ok, dir} <- root(opts),
         {:ok, id} <- valid_id(id) do
      path = Path.join(dir, id <> @done)

      case File.read(path) do
        {:ok, bytes} ->
          _ignored = File.rm(path)
          {:ok, bytes}

        {:error, :enoent} ->
          if File.exists?(Path.join(dir, id <> @part)),
            do: {:error, {:upload_incomplete, id}},
            else: {:error, {:unknown_upload, id}}

        {:error, reason} ->
          {:error, {:upload_unreadable, reason}}
      end
    end
  end

  @doc """
  Where a finished upload's bytes are, without reading or removing them.

  For the one caller that has a use for the file rather than its contents:
  `Ouroboros.Wasm.Pool.inspect/2` reads a component off disk, and handing it this path
  saves writing sixteen mebibytes to a second one. It is still `take/2` that consumes the
  upload, so nothing here changes what a caller ends up holding.
  """
  @spec path(String.t(), keyword()) :: {:ok, Path.t()} | {:error, term()}
  def path(id, opts \\ []) when is_binary(id) do
    with {:ok, dir} <- root(opts),
         {:ok, id} <- valid_id(id) do
      done = Path.join(dir, id <> @done)

      cond do
        File.regular?(done) -> {:ok, done}
        File.exists?(Path.join(dir, id <> @part)) -> {:error, {:upload_incomplete, id}}
        true -> {:error, {:unknown_upload, id}}
      end
    end
  end

  @doc """
  Removes every upload older than the retention window, returning how many went.

  Called at the head of every append, which is the only reason this module needs no timer.
  """
  @spec sweep(keyword()) :: non_neg_integer()
  def sweep(opts \\ []) do
    case root(opts) do
      {:ok, dir} -> expire(dir, now_ms() - @ttl_ms)
      {:error, _no_data_dir} -> 0
    end
  end

  ## Plumbing

  defp prepared(opts) do
    with {:ok, dir} <- root(opts),
         :ok <- ensure_directory(dir) do
      _swept = expire(dir, now_ms() - @ttl_ms)
      {:ok, dir}
    end
  end

  defp ensure_directory(dir) do
    case File.mkdir_p(dir) do
      :ok ->
        # 0700 for the same reason the data directory is: these bytes are somebody's
        # unreleased capability, and the directory they land in should not be a place
        # every account on the host can read from.
        _ignored = File.chmod(dir, 0o700)
        :ok

      {:error, reason} ->
        {:error, {:upload_directory_unwritable, reason}}
    end
  end

  # A new upload is admitted only if the node is under its in-flight ceiling *after* the
  # sweep, so a client whose previous attempts timed out is not permanently locked out by
  # its own litter.
  defp opened(nil, dir) do
    case in_flight(dir) do
      count when count >= @max_in_flight ->
        {:error, {:too_many_uploads, count, @max_in_flight}}

      _room ->
        id = @id_bytes |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)
        path = Path.join(dir, id <> @part)

        case File.write(path, "", [:exclusive]) do
          :ok ->
            _ignored = File.chmod(path, 0o600)
            {:ok, id, path}

          {:error, reason} ->
            {:error, {:upload_not_created, reason}}
        end
    end
  end

  defp opened(id, dir) when is_binary(id) do
    with {:ok, id} <- valid_id(id) do
      path = Path.join(dir, id <> @part)

      cond do
        File.exists?(path) -> {:ok, id, path}
        File.exists?(Path.join(dir, id <> @done)) -> {:error, {:upload_closed, id}}
        true -> {:error, {:unknown_upload, id}}
      end
    end
  end

  defp opened(id, _dir), do: {:error, {:invalid_upload_id, describe(id)}}

  # Hex and exactly the minted length. Nothing else reaches `Path.join/2`, so no id — however
  # it was spelled — can name a file outside this directory or a file that is not an upload.
  defp valid_id(id) when is_binary(id) do
    if Regex.match?(@id_pattern, id),
      do: {:ok, id},
      else: {:error, {:invalid_upload_id, describe(id)}}
  end

  defp bound_chunk(chunk) do
    cond do
      chunk == "" -> {:error, :empty_chunk}
      byte_size(chunk) > @max_chunk_bytes -> {:error, {:chunk_too_large, @max_chunk_bytes}}
      true -> :ok
    end
  end

  defp held(path) do
    case File.stat(path) do
      {:ok, %File.Stat{type: :regular, size: size}} -> {:ok, size}
      {:ok, _other} -> {:error, :upload_not_a_file}
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

  defp settle(id, _dir, path, received, false) do
    # The mtime is the expiry clock, so an upload still being written must not age out from
    # under its author between chunks.
    _touched = File.touch(path)

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

  defp in_flight(dir) do
    case File.ls(dir) do
      {:ok, names} -> Enum.count(names, &upload?/1)
      {:error, _unreadable} -> @max_in_flight
    end
  end

  defp upload?(name), do: String.ends_with?(name, @part) or String.ends_with?(name, @done)

  defp expire(dir, floor_ms) do
    case File.ls(dir) do
      {:ok, names} ->
        names
        |> Enum.filter(&upload?/1)
        |> Enum.count(&expired?(Path.join(dir, &1), floor_ms))

      {:error, _unreadable} ->
        0
    end
  end

  defp expired?(path, floor_ms) do
    case File.stat(path, time: :posix) do
      {:ok, %File.Stat{mtime: mtime}} when is_integer(mtime) ->
        if mtime * 1_000 < floor_ms do
          # Never the bytes, never the sha: what an operator needs from this line is that
          # a transfer was abandoned, and the id is the whole of that.
          Logger.debug("wasm upload #{Path.basename(path)} expired unread")
          File.rm(path) == :ok
        else
          false
        end

      _unreadable ->
        false
    end
  end

  defp now_ms, do: System.system_time(:millisecond)

  defp byte_size_of(bytes) when is_binary(bytes), do: byte_size(bytes)
  defp byte_size_of(other), do: other

  defp describe(term), do: inspect(term, limit: 10, printable_limit: 200)
end
