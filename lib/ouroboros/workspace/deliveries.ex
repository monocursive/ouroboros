defmodule Ouroboros.Workspace.Deliveries do
  @moduledoc "Bounded regular-file deliveries, carried as uncompressed ustar archives."
  alias Ouroboros.Provider.Native.Exec
  alias Ouroboros.Workspace.{Bundle, Git}
  @max_bytes 32 * 1024 * 1024
  @max_files 128
  @chunk 64 * 1024

  def max_bytes, do: @max_bytes

  def prepare(worktree) do
    Enum.reduce_while([".ouroboros", ".ouroboros/deliver"], :ok, fn relative, :ok ->
      path = Path.join(worktree, relative)

      case File.mkdir(path) do
        :ok ->
          {:cont, :ok}

        {:error, :eexist} ->
          case File.lstat(path) do
            {:ok, %{type: :directory}} -> {:cont, :ok}
            _ -> {:halt, {:error, {:unsafe_delivery_path, relative}}}
          end

        error ->
          {:halt, error}
      end
    end)
  end

  def capture(worktree, task_id, commit, opts \\ []) do
    limit = min(Keyword.get(opts, :deliver_max_bytes, @max_bytes), @max_bytes)

    with {:ok, temporary} <- Git.temp_directory() do
      stage = Path.join(temporary, "files")
      File.mkdir_p!(stage)

      result =
        with {:ok, files} <- inventory(worktree, stage, limit),
             :ok <- archive(stage, files, Path.join(temporary, "deliveries.tar")),
             {:ok, metadata} <- archive_metadata(temporary, files, commit, task_id, limit) do
          {:ok,
           %{
             temporary: temporary,
             path: Path.join(temporary, "deliveries.tar"),
             files: files,
             metadata: metadata
           }}
        end

      if match?({:error, _}, result), do: File.rm_rf(temporary)
      result
    end
  end

  def inventory(worktree, stage \\ nil, limit \\ @max_bytes) do
    with :ok <- directory_or_missing(Path.join(worktree, ".ouroboros")),
         :ok <- directory_or_missing(Path.join(worktree, ".ouroboros/deliver")) do
      root = Path.join(worktree, ".ouroboros/deliver")

      case walk(root, "", stage, %{files: [], bytes: 0, entries: 0}, min(limit, @max_bytes)) do
        {:ok, acc} -> {:ok, Enum.sort_by(acc.files, & &1.path)}
        error -> error
      end
    end
  end

  @doc "Verify an already-installed delivery directory before retrying an acknowledgment."
  def verify_directory(directory, expected) do
    with true <- valid_manifest?(expected),
         {:ok, %{type: :directory}} <- File.lstat(directory),
         {:ok, acc} <- walk(directory, "", nil, %{files: [], bytes: 0, entries: 0}, @max_bytes),
         files = Enum.sort_by(acc.files, & &1.path),
         true <- files == Enum.sort_by(expected, & &1.path) do
      {:ok, files}
    else
      false -> {:error, :delivery_manifest_mismatch}
      {:ok, _} -> {:error, :unsafe_delivery_destination}
      error -> error
    end
  end

  defp directory_or_missing(path) do
    case File.lstat(path) do
      {:ok, %{type: :directory}} -> :ok
      {:error, :enoent} -> :ok
      _ -> {:error, {:unsafe_delivery_path, path}}
    end
  end

  defp walk(_root, _relative, _stage, %{entries: n}, _limit) when n >= 1024,
    do: {:error, :too_many_delivery_entries}

  defp walk(root, relative, stage, acc, limit) do
    acc = %{acc | entries: acc.entries + 1}
    path = if relative == "", do: root, else: Path.join(root, relative)

    case File.lstat(path) do
      {:error, :enoent} when relative == "" ->
        {:ok, acc}

      {:ok, %{type: :directory}} ->
        with true <- length(Path.split(relative)) <= 16,
             {:ok, names} <- File.ls(path) do
          Enum.reduce_while(Enum.sort(names), {:ok, acc}, fn name, {:ok, current} ->
            next = if relative == "", do: name, else: relative <> "/" <> name

            result =
              if valid_path?(next),
                do: walk(root, next, stage, current, limit),
                else: {:error, :unsafe_delivery_path}

            case result do
              {:ok, _} = ok -> {:cont, ok}
              error -> {:halt, error}
            end
          end)
        else
          false -> {:error, :delivery_path_too_deep}
          error -> error
        end

      {:ok, %{type: :regular} = stat} ->
        cond do
          length(acc.files) >= @max_files ->
            {:error, {:too_many_deliveries, @max_files}}

          acc.bytes + stat.size > limit ->
            {:error, {:deliveries_too_large, limit}}

          true ->
            target = if stage, do: Path.join(stage, relative)

            with {:ok, digest} <- read_file(path, stat, target, limit - acc.bytes) do
              {:ok,
               %{
                 acc
                 | files: [%{path: relative, bytes: stat.size, sha256: digest} | acc.files],
                   bytes: acc.bytes + stat.size
               }}
            end
        end

      {:ok, _} ->
        {:error, {:unsafe_delivery_path, relative}}

      error ->
        error
    end
  end

  # Compare the opened inode with lstat, and lstat again after reading. A file that
  # changes size or is replaced while being captured cannot authorize cleanup.
  defp read_file(path, stat, target, remaining) do
    if target, do: File.mkdir_p!(Path.dirname(target))

    with {:ok, input} <- File.open(path, [:read, :binary, :raw]) do
      try do
        with {:ok, record} <- :file.read_file_info(input, time: :universal),
             true <- same_file?(stat, File.Stat.from_record(record)),
             {:ok, output} <- open_output(target) do
          try do
            with {:ok, size, digest} <-
                   copy(input, output, remaining, 0, :crypto.hash_init(:sha256)),
                 {:ok, after_stat} <- File.lstat(path),
                 true <- size == stat.size and same_file?(stat, after_stat) do
              {:ok, Base.encode16(:crypto.hash_final(digest), case: :lower)}
            else
              false -> {:error, :delivery_changed_during_capture}
              error -> error
            end
          after
            if output, do: File.close(output)
          end
        else
          false -> {:error, :delivery_changed_during_capture}
          error -> error
        end
      after
        File.close(input)
      end
    end
  end

  defp same_file?(a, b),
    do:
      b.type == :regular and
        Map.take(a, [:inode, :major_device, :minor_device, :size, :mtime, :ctime]) ==
          Map.take(b, [:inode, :major_device, :minor_device, :size, :mtime, :ctime])

  defp open_output(nil), do: {:ok, nil}
  defp open_output(path), do: File.open(path, [:write, :binary, :raw, :exclusive])

  defp copy(input, output, remaining, size, digest) do
    case :file.read(input, min(@chunk, remaining + 1)) do
      :eof ->
        {:ok, size, digest}

      {:ok, chunk} when byte_size(chunk) <= remaining ->
        with :ok <- if(output, do: :file.write(output, chunk), else: :ok),
             do:
               copy(
                 input,
                 output,
                 remaining - byte_size(chunk),
                 size + byte_size(chunk),
                 :crypto.hash_update(digest, chunk)
               )

      {:ok, _} ->
        {:error, :delivery_grew_during_capture}

      error ->
        error
    end
  end

  defp archive(_stage, [], _path), do: :ok

  defp archive(stage, files, path) do
    args = ["--format=ustar", "-cf", path, "-C", stage, "--" | Enum.map(files, & &1.path)]

    case Exec.run("tar", args, timeout_ms: 30_000, max_bytes: 8192) do
      {:ok, %{status: 0, timed_out?: false}} -> :ok
      other -> {:error, {:delivery_archive_failed, other}}
    end
  end

  defp archive_metadata(_temporary, [], _commit, _task_id, _limit), do: {:ok, nil}

  defp archive_metadata(temporary, _files, commit, task_id, limit),
    do: Bundle.metadata(Path.join(temporary, "deliveries.tar"), commit, task_id, limit)

  @doc "Extracts only bounded regular ustar entries, never links or special files."
  def extract(archive, destination, expected, limit \\ @max_bytes) do
    with true <- valid_manifest?(expected),
         {:ok, %{type: :regular, size: size}} <- File.lstat(archive),
         true <- size <= min(limit, @max_bytes),
         :ok <- File.mkdir(destination),
         {:ok, input} <- File.open(archive, [:read, :binary, :raw]) do
      result =
        try do
          read_entries(input, destination, [], 0, min(limit, @max_bytes), min(limit, @max_bytes))
        after
          File.close(input)
        end

      case result do
        {:ok, files} ->
          if Enum.sort_by(files, & &1.path) == Enum.sort_by(expected, & &1.path),
            do: {:ok, files},
            else: cleanup_error(destination, :delivery_manifest_mismatch)

        {:error, reason} ->
          cleanup_error(destination, reason)
      end
    else
      false -> {:error, :invalid_delivery_manifest_or_size}
      error -> error
    end
  end

  defp cleanup_error(path, reason),
    do:
      (
        File.rm_rf(path)
        {:error, reason}
      )

  defp read_entries(_input, _destination, _files, _total, _limit, remaining) when remaining < 512,
    do: {:error, :delivery_archive_bounds_exceeded}

  defp read_entries(input, destination, files, total, limit, remaining) do
    case :file.read(input, 512) do
      {:ok, <<0::4096>>} ->
        case zero_tail(input, remaining - 512) do
          :ok -> {:ok, files}
          error -> error
        end

      {:ok, header} when byte_size(header) == 512 ->
        with {:ok, path, size} <- header(header),
             padded = size + rem(512 - rem(size, 512), 512),
             true <-
               length(files) < @max_files and total + size <= limit and padded + 512 <= remaining,
             false <- Enum.any?(files, &(&1.path == path)),
             target = Path.join(destination, path),
             :ok <- File.mkdir_p(Path.dirname(target)),
             {:ok, output} <- File.open(target, [:write, :binary, :raw, :exclusive]) do
          result =
            try do
              copy_entry(input, output, size, :crypto.hash_init(:sha256))
            after
              File.close(output)
            end

          with {:ok, digest} <- result,
               :ok <- skip_padding(input, size) do
            entry = %{
              path: path,
              bytes: size,
              sha256: Base.encode16(:crypto.hash_final(digest), case: :lower)
            }

            read_entries(
              input,
              destination,
              [entry | files],
              total + size,
              limit,
              remaining - 512 - padded
            )
          end
        else
          true -> {:error, :duplicate_delivery_path}
          false -> {:error, :delivery_archive_bounds_exceeded}
          error -> error
        end

      _ ->
        {:error, :truncated_delivery_archive}
    end
  end

  defp header(header) do
    <<name::binary-size(100), _mode::binary-size(8), _uid::binary-size(8), _gid::binary-size(8),
      size::binary-size(12), _mtime::binary-size(12), checksum::binary-size(8), type,
      _link::binary-size(100), magic::binary-size(6), _version::binary-size(2),
      _uname::binary-size(32), _gname::binary-size(32), _major::binary-size(8),
      _minor::binary-size(8), prefix::binary-size(155), _rest::binary>> = header

    prefix = cstring(prefix)
    path = if prefix == "", do: cstring(name), else: prefix <> "/" <> cstring(name)

    computed =
      header
      |> :binary.bin_to_list()
      |> Enum.with_index()
      |> Enum.reduce(0, fn {byte, i}, sum -> sum + if(i in 148..155, do: 32, else: byte) end)

    with true <- magic == <<"ustar", 0>> and type in [0, ?0] and valid_path?(path),
         {:ok, expected} <- octal(checksum),
         true <- expected == computed,
         {:ok, bytes} <- octal(size) do
      {:ok, path, bytes}
    else
      _ -> {:error, :unsafe_delivery_archive_entry}
    end
  end

  defp cstring(value), do: value |> String.split(<<0>>, parts: 2) |> hd()

  defp octal(value) do
    case Integer.parse(String.trim(cstring(value)), 8) do
      {n, ""} when n >= 0 -> {:ok, n}
      _ -> {:error, :invalid_tar_number}
    end
  end

  defp copy_entry(_input, _output, 0, digest), do: {:ok, digest}

  defp copy_entry(input, output, remaining, digest) do
    case :file.read(input, min(@chunk, remaining)) do
      {:ok, chunk} when byte_size(chunk) > 0 ->
        with :ok <- :file.write(output, chunk),
             do:
               copy_entry(
                 input,
                 output,
                 remaining - byte_size(chunk),
                 :crypto.hash_update(digest, chunk)
               )

      _ ->
        {:error, :truncated_delivery_archive}
    end
  end

  defp skip_padding(input, size) do
    case rem(512 - rem(size, 512), 512) do
      0 ->
        :ok

      n ->
        case :file.read(input, n) do
          {:ok, bytes} when byte_size(bytes) == n -> :ok
          _ -> {:error, :truncated_delivery_archive}
        end
    end
  end

  defp zero_tail(input, remaining) do
    case :file.read(input, min(@chunk, remaining + 1)) do
      :eof ->
        :ok

      {:ok, bytes} ->
        if byte_size(bytes) <= remaining and bytes == :binary.copy(<<0>>, byte_size(bytes)),
          do: zero_tail(input, remaining - byte_size(bytes)),
          else: {:error, :trailing_delivery_archive_data}

      error ->
        error
    end
  end

  def valid_manifest?(files) when is_list(files) and length(files) <= @max_files do
    Enum.all?(files, fn
      %{path: path, bytes: bytes, sha256: sha} ->
        valid_path?(path) and is_integer(bytes) and bytes >= 0 and bytes <= @max_bytes and
          is_binary(sha) and Regex.match?(~r/\A[a-f0-9]{64}\z/, sha)

      _ ->
        false
    end) and Enum.sum(Enum.map(files, & &1.bytes)) <= @max_bytes
  end

  def valid_manifest?(_), do: false

  def valid_path?(path),
    do:
      is_binary(path) and String.valid?(path) and byte_size(path) in 1..255 and
        not String.contains?(path, [<<0>>, "\n", "\\"]) and
        Enum.all?(String.split(path, "/"), &(&1 not in ["", ".", ".."]))
end
