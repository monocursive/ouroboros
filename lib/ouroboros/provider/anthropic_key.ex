defmodule Ouroboros.Provider.AnthropicKey do
  @moduledoc """
  The node-owned Anthropic API key used by the direct Native model transport.

  `ANTHROPIC_API_KEY` remains the operator-controlled first choice. When it is absent,
  the web surface may store one private key at `<data_dir>/anthropic.key`; Native reads
  that file only when it is about to make an Anthropic request. The key never enters a
  session option, checkpoint, event, provider-status reply, or page assign.

  The stored file is an exclusive temporary inode whose mode becomes `0600` before key
  bytes are written. It is synced, atomically renamed, and followed by a directory sync.
  Reads accept only a same-user regular mode-0600 file beneath the already-private
  Ouroboros data directory.
  """

  alias Ouroboros.DataDir

  @env "ANTHROPIC_API_KEY"
  @filename "anthropic.key"
  @max_bytes 8 * 1024

  @type source :: :environment | :stored
  @type status :: %{
          provider: :anthropic,
          env: String.t(),
          present: boolean(),
          source: source() | nil
        }

  @doc "The non-secret credential state exposed to provider-status clients."
  @spec status(keyword()) :: status()
  def status(opts \\ []) when is_list(opts) do
    case fetch(opts) do
      {:ok, _key, source} -> projection(true, source)
      {:error, _reason} -> projection(false, nil)
    end
  end

  @doc "Whether an environment or private stored key is currently usable."
  @spec present?(keyword()) :: boolean()
  def present?(opts \\ []) when is_list(opts), do: match?({:ok, _key, _source}, fetch(opts))

  @doc "Reads the effective key for one request without exposing it through status."
  @spec fetch(keyword()) :: {:ok, String.t(), source()} | {:error, term()}
  def fetch(opts \\ []) when is_list(opts) do
    case normalize(System.get_env(@env)) do
      {:ok, key} -> {:ok, key, :environment}
      {:error, _reason} -> read_stored(path(opts))
    end
  end

  @doc "Atomically stores a private key for immediate use by subsequent requests."
  @spec put(String.t(), keyword()) :: {:ok, status()} | {:error, term()}
  def put(key, opts \\ []) when is_list(opts) do
    with {:ok, key} <- normalize(key),
         path <- path(opts),
         :ok <- publish(path, key) do
      {:ok, status(opts)}
    end
  rescue
    error -> {:error, {:credential_write_failed, Exception.message(error)}}
  end

  @doc "The private stored-key path. The environment key has no path."
  @spec path(keyword()) :: Path.t()
  def path(opts \\ []) when is_list(opts) do
    configured =
      Keyword.get(opts, :path) || Application.get_env(:ouroboros, :anthropic_api_key_file)

    case configured do
      value when is_binary(value) and value != "" ->
        if Path.type(value) == :absolute,
          do: Path.expand(value),
          else: raise(ArgumentError, "Anthropic API key path must be absolute")

      _unset ->
        Path.join(data_dir(), @filename)
    end
  end

  defp projection(present, source) do
    %{provider: :anthropic, env: @env, present: present, source: source}
  end

  defp normalize(value) when is_binary(value) do
    key = String.trim(value)

    cond do
      key == "" -> {:error, :empty_api_key}
      byte_size(key) > @max_bytes -> {:error, {:api_key_too_long, @max_bytes}}
      String.contains?(key, ["\n", "\r", "\0", "\t", " "]) -> {:error, :invalid_api_key}
      true -> {:ok, key}
    end
  end

  defp normalize(_value), do: {:error, :empty_api_key}

  defp read_stored(path) do
    with {:ok, before} <- File.lstat(path, time: :posix),
         :ok <- validate_stat(path, before),
         {:ok, contents} <- File.read(path),
         {:ok, after_read} <- File.lstat(path, time: :posix),
         true <- same_file?(before, after_read),
         {:ok, key} <- normalize(contents) do
      {:ok, key, :stored}
    else
      {:error, :enoent} -> {:error, :not_found}
      false -> {:error, :credential_file_changed}
      {:error, _reason} = error -> error
    end
  rescue
    error -> {:error, {:credential_read_failed, Exception.message(error)}}
  end

  defp validate_stat(path, stat) do
    mode = Bitwise.band(stat.mode, 0o777)
    uid = DataDir.current_uid!()

    cond do
      stat.type != :regular -> {:error, {:unsafe_credential_file, path, :not_regular}}
      stat.uid != uid -> {:error, {:unsafe_credential_file, path, :wrong_owner}}
      mode != 0o600 -> {:error, {:unsafe_credential_file, path, {:mode, mode}}}
      stat.size > @max_bytes -> {:error, {:unsafe_credential_file, path, :too_large}}
      true -> :ok
    end
  end

  defp publish(path, key) do
    directory = Path.dirname(path)
    DataDir.ensure_private!(directory)

    temporary =
      path <>
        ".tmp-#{System.unique_integer([:positive, :monotonic])}-" <>
        Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)

    try do
      File.write!(temporary, "", [:exclusive, :sync])
      File.chmod!(temporary, 0o600)
      before = File.lstat!(temporary, time: :posix)

      File.open!(temporary, [:write, :binary], fn io ->
        IO.binwrite(io, key)
        :ok = :file.sync(io)
      end)

      unless same_file?(before, File.lstat!(temporary, time: :posix)) do
        raise "Anthropic API key temporary inode changed while it was written"
      end

      File.rename!(temporary, path)
      :ok = validate_stat(path, File.lstat!(path, time: :posix))
      sync_directory(directory)
    after
      _ = File.rm(temporary)
    end
  end

  defp sync_directory(directory) do
    with {:ok, device} <- :file.open(String.to_charlist(directory), [:read, :raw, :directory]),
         :ok <- :file.sync(device),
         :ok <- :file.close(device) do
      :ok
    end
  end

  defp same_file?(left, right),
    do:
      left.uid == right.uid and left.major_device == right.major_device and
        left.inode == right.inode

  defp data_dir do
    case Application.get_env(:ouroboros, :data_dir) do
      value when is_binary(value) and value != "" ->
        Path.expand(value)

      _unset ->
        DataDir.resolve!(
          System.get_env("OUROBOROS_DATA_DIR"),
          System.get_env("XDG_DATA_HOME"),
          System.get_env("HOME")
        )
    end
  end
end
