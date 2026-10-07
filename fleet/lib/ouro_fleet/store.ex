defmodule OuroFleet.Store do
  @moduledoc "Durable, private controller/worker checkpoints; errors poison the caller."
  import Bitwise

  def directory!(path) do
    case File.lstat(path) do
      {:error, :enoent} ->
        File.mkdir!(path)
        File.chmod!(path, 0o700)
        sync_dir!(Path.dirname(path))

      {:ok, %{type: :directory, mode: mode}} when band(mode, 0o777) == 0o700 ->
        :ok

      _ ->
        raise "unsafe fleet directory"
    end

    path
  end

  def read!(path) do
    case File.lstat(path) do
      {:error, :enoent} ->
        nil

      {:ok, %{type: :regular, mode: mode, links: 1, size: size}}
      when band(mode, 0o777) == 0o600 and size <= 1_048_576 ->
        path |> File.read!() |> OuroFleet.JSON.decode()

      _ ->
        raise "unsafe or oversized fleet checkpoint"
    end
  end

  def write!(path, record) do
    bytes = record |> OuroFleet.JSON.encode() |> IO.iodata_to_binary()
    if byte_size(bytes) > 1_048_576, do: raise("fleet checkpoint too large")
    temp = path <> ".new-" <> Base.encode16(:crypto.strong_rand_bytes(12), case: :lower)
    {:ok, fd} = :file.open(String.to_charlist(temp), [:raw, :binary, :write, :exclusive])

    try do
      File.chmod!(temp, 0o600)
      :ok = :file.write(fd, bytes)
      :ok = :file.sync(fd)
    after
      :file.close(fd)
    end

    File.rename!(temp, path)
    sync_dir!(Path.dirname(path))
    record
  end

  defp sync_dir!(path) do
    {:ok, fd} = :file.open(String.to_charlist(path), [:raw, :read, :directory])

    try do
      :ok = :file.sync(fd)
    after
      :file.close(fd)
    end
  end

  def digest(value),
    do: "sha256:" <> Base.encode16(:crypto.hash(:sha256, canonical(value)), case: :lower)

  # Only JSON values are accepted. Sort object pairs recursively for a stable
  # request identity across retries and hosts, without persisting raw argv.
  defp canonical(map) when is_map(map) do
    pairs =
      map
      |> Enum.sort()
      |> Enum.map(fn {k, v} -> [OuroFleet.JSON.encode(k), ":", canonical(v)] end)

    ["{", Enum.intersperse(pairs, ","), "}"]
  end

  defp canonical(list) when is_list(list),
    do: ["[", Enum.intersperse(Enum.map(list, &canonical/1), ","), "]"]

  defp canonical(value), do: OuroFleet.JSON.encode(value)
end
