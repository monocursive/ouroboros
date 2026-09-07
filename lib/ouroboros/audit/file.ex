defmodule Ouroboros.Audit.File do
  @moduledoc false
  import Bitwise

  def directory(path) do
    case File.lstat(path) do
      {:ok, %{type: :directory, mode: mode}} when band(mode, 0o077) == 0 ->
        :ok

      {:ok, _} ->
        {:error, :audit_directory_not_private}

      {:error, :enoent} ->
        with :ok <- parent(path),
             :ok <- File.mkdir(path),
             :ok <- File.chmod(path, 0o700),
             :ok <- sync_directory(Path.dirname(path)),
             do: :ok

      error ->
        error
    end
  end

  defp parent(path) do
    parent = Path.dirname(path)

    case File.lstat(parent) do
      {:ok, %{type: :directory}} -> no_symlinks(parent)
      {:error, :enoent} -> directory(parent)
      _ -> {:error, :unsafe_audit_parent}
    end
  end

  def no_symlinks("/"), do: :ok

  def no_symlinks(path) do
    with {:ok, %{type: :directory}} <- File.lstat(path),
         :ok <- no_symlinks(Path.dirname(path)) do
      :ok
    else
      _ -> {:error, :unsafe_audit_parent}
    end
  end

  def append(path, contents, hook \\ nil) do
    with :ok <- regular_or_missing(path),
         :ok <- observe(hook, :before_open),
         {:ok, fd} <- :file.open(String.to_charlist(path), [:append, :binary, :raw]) do
      try do
        with :ok <- File.chmod(path, 0o600),
             :ok <- observe(hook, :before_write),
             :ok <- :file.write(fd, contents),
             :ok <- observe(hook, :before_sync),
             :ok <- :file.sync(fd),
             :ok <- observe(hook, :before_directory_sync),
             :ok <- sync_directory(Path.dirname(path)),
             do: :ok
      after
        :file.close(fd)
      end
    end
  end

  def atomic(path, contents, hook \\ nil) do
    temporary =
      path <> ".tmp-" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)

    result =
      with :ok <- regular_or_missing(path),
           {:ok, fd} <-
             :file.open(String.to_charlist(temporary), [:write, :exclusive, :binary, :raw]) do
        try do
          with :ok <- File.chmod(temporary, 0o600),
               :ok <- observe(hook, :before_write),
               :ok <- :file.write(fd, contents),
               :ok <- observe(hook, :before_sync),
               :ok <- :file.sync(fd),
               :ok <- observe(hook, :before_rename),
               :ok <- File.rename(temporary, path),
               :ok <- sync_directory(Path.dirname(path)),
               do: :ok
        after
          :file.close(fd)
        end
      end

    if result != :ok, do: File.rm(temporary)
    result
  end

  def read(path) do
    with {:ok, %{type: :regular}} <- File.lstat(path), do: File.read(path)
  end

  def sync_directory(path) do
    with {:ok, fd} <- :file.open(String.to_charlist(path), [:read, :raw, :directory]) do
      try do
        :file.sync(fd)
      after
        :file.close(fd)
      end
    end
  end

  defp regular_or_missing(path) do
    case File.lstat(path) do
      {:ok, %{type: :regular, mode: mode}} when band(mode, 0o077) == 0 -> :ok
      {:error, :enoent} -> :ok
      _ -> {:error, :unsafe_audit_file}
    end
  end

  defp observe(nil, _point), do: :ok
  defp observe(hook, point), do: hook.(point)
end
