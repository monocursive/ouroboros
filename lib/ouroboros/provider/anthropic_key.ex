defmodule Ouroboros.Provider.AnthropicKey do
  @moduledoc """
  The node-owned Anthropic credentials used by the direct Native model transport.

  `ANTHROPIC_API_KEY` remains the operator-controlled first choice, with the optional
  `ANTHROPIC_WORKSPACE_ID` supplying the workspace for an identity-linked key. When the
  key is absent, the web surface may store one private credential document at
  `<data_dir>/anthropic.key`; Native reads that file only when it is about to make an
  Anthropic request. The key and workspace id never enter a session option, checkpoint,
  event, provider-status reply, or page assign.

  The stored file is an exclusive temporary inode whose mode becomes `0600` before key
  bytes are written. It is synced, atomically renamed, and followed by a directory sync.
  Reads accept only a same-user regular mode-0600 file beneath the already-private
  Ouroboros data directory. A pre-workspace file containing only the raw key remains
  readable and is migrated to the versioned document on the next UI update.
  """

  require Logger

  alias Ouroboros.DataDir

  @env "ANTHROPIC_API_KEY"
  @workspace_env "ANTHROPIC_WORKSPACE_ID"
  @filename "anthropic.key"
  @document_version 1
  @max_key_bytes 8 * 1024
  @max_workspace_bytes 256
  # JSON escaping may expand a valid key byte to a six-byte `\\uXXXX` sequence.
  @max_file_bytes @max_key_bytes * 6 + @max_workspace_bytes + 1024

  @type source :: :environment | :stored
  @type credentials :: %{api_key: String.t(), workspace_id: String.t() | nil}
  @type status :: %{
          provider: :anthropic,
          env: String.t(),
          workspace_env: String.t(),
          present: boolean(),
          source: source() | nil,
          workspace_configured: boolean()
        }

  @doc "The non-secret credential state exposed to provider-status clients."
  @spec status(keyword()) :: status()
  def status(opts \\ []) when is_list(opts) do
    case fetch_credentials(opts) do
      {:ok, credentials, source} ->
        projection(true, source, is_binary(credentials.workspace_id))

      {:error, _reason} ->
        projection(false, nil, false)
    end
  end

  @doc "Whether an environment or private stored key is currently usable."
  @spec present?(keyword()) :: boolean()
  def present?(opts \\ []) when is_list(opts),
    do: match?({:ok, _credentials, _source}, fetch_credentials(opts))

  @doc "Reads the effective key for one request without exposing it through status."
  @spec fetch(keyword()) :: {:ok, String.t(), source()} | {:error, term()}
  def fetch(opts \\ []) when is_list(opts) do
    with {:ok, credentials, source} <- fetch_credentials(opts) do
      {:ok, credentials.api_key, source}
    end
  end

  @doc "Reads the effective key and optional workspace id for one transient request."
  @spec fetch_credentials(keyword()) :: {:ok, credentials(), source()} | {:error, term()}
  def fetch_credentials(opts \\ []) when is_list(opts) do
    case normalize(System.get_env(@env)) do
      {:ok, key} ->
        {:ok, %{api_key: key, workspace_id: environment_workspace()}, :environment}

      {:error, _reason} ->
        read_stored(path(opts))
    end
  end

  @doc "Atomically replaces the private key and clears any stored workspace id."
  @spec put(String.t(), keyword()) :: {:ok, status()} | {:error, term()}
  def put(key, opts \\ []) when is_list(opts) do
    put(key, nil, opts)
  end

  @doc "Atomically replaces the private key and optional workspace id."
  @spec put(String.t(), String.t() | nil, keyword()) :: {:ok, status()} | {:error, term()}
  def put(key, workspace_id, opts) when is_list(opts) do
    path = path(opts)

    with_lock(path, fn ->
      with {:ok, key} <- normalize(key),
           {:ok, workspace_id} <- normalize_workspace(workspace_id),
           :ok <- publish(path, %{api_key: key, workspace_id: workspace_id}) do
        {:ok, status(opts)}
      end
    end)
  rescue
    error -> {:error, {:credential_write_failed, Exception.message(error)}}
  end

  @doc """
  Updates either stored field.

  Omitting the workspace (`nil` or `:keep`) keeps the existing one only when the key is
  also omitted. Replacing the API key clears a stored workspace unless a new one is
  supplied, so a key for another org cannot keep sending the previous
  `anthropic-workspace-id`. Pass `""` or `:clear` to drop the workspace without touching
  the key.
  """
  @spec configure(String.t() | nil, String.t() | nil | :keep | :clear, keyword()) ::
          {:ok, status()} | {:error, term()}
  def configure(key, workspace_id, opts \\ []) when is_list(opts) do
    path = path(opts)

    with_lock(path, fn ->
      replaced? = key_replaced?(key)

      with :ok <- require_update(key, workspace_id),
           {:ok, current} <- stored_or_empty(path),
           {:ok, key} <- configured_key(key, current.api_key),
           {:ok, workspace_id} <-
             configured_workspace(workspace_id, current.workspace_id, replaced?),
           :ok <- publish(path, %{api_key: key, workspace_id: workspace_id}) do
        {:ok, status(opts)}
      end
    end)
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

  defp projection(present, source, workspace_configured) do
    %{
      provider: :anthropic,
      env: @env,
      workspace_env: @workspace_env,
      present: present,
      source: source,
      workspace_configured: workspace_configured
    }
  end

  defp environment_workspace do
    case normalize_workspace(System.get_env(@workspace_env)) do
      {:ok, workspace_id} ->
        workspace_id

      {:error, reason} ->
        Logger.warning("ignoring invalid #{@workspace_env}: #{inspect(reason)}")
        nil
    end
  end

  defp normalize(value) when is_binary(value) do
    key = String.trim(value)

    cond do
      key == "" -> {:error, :empty_api_key}
      byte_size(key) > @max_key_bytes -> {:error, {:api_key_too_long, @max_key_bytes}}
      String.contains?(key, ["\n", "\r", "\0", "\t", " "]) -> {:error, :invalid_api_key}
      true -> {:ok, key}
    end
  end

  defp normalize(_value), do: {:error, :empty_api_key}

  defp normalize_workspace(nil), do: {:ok, nil}

  defp normalize_workspace(value) when is_binary(value) do
    workspace_id = String.trim(value)

    cond do
      workspace_id == "" ->
        {:ok, nil}

      byte_size(workspace_id) > @max_workspace_bytes ->
        {:error, {:workspace_id_too_long, @max_workspace_bytes}}

      not Regex.match?(~r/\Awrkspc_[A-Za-z0-9]+\z/, workspace_id) ->
        {:error, :invalid_workspace_id}

      true ->
        {:ok, workspace_id}
    end
  end

  defp normalize_workspace(_value), do: {:error, :invalid_workspace_id}

  defp require_update(key, workspace_id)
       when key in [nil, ""] and workspace_id in [nil, :keep],
       do: {:error, :credential_update_required}

  defp require_update(_key, _workspace_id), do: :ok

  defp key_replaced?(key) when key in [nil, ""], do: false
  defp key_replaced?(_key), do: true

  defp configured_key(nil, existing), do: normalize(existing)
  defp configured_key("", existing), do: normalize(existing)
  defp configured_key(key, _existing), do: normalize(key)

  defp configured_workspace(:keep, existing, false), do: normalize_workspace(existing)
  defp configured_workspace(:keep, _existing, true), do: {:ok, nil}
  defp configured_workspace(nil, existing, false), do: normalize_workspace(existing)
  defp configured_workspace(nil, _existing, true), do: {:ok, nil}
  defp configured_workspace(:clear, _existing, _replaced), do: {:ok, nil}
  defp configured_workspace("", _existing, _replaced), do: {:ok, nil}

  defp configured_workspace(workspace_id, _existing, _replaced),
    do: normalize_workspace(workspace_id)

  defp with_lock(path, fun) when is_function(fun, 0) do
    # Concurrent operate callers (two tabs, two gateway clients) must not each read the
    # stored document, change one field, and rename over the other. `:global.trans`
    # serializes that read-modify-write on this node the same way worktree markers do.
    case :global.trans({{__MODULE__, path}, self()}, fun, [node()], 20) do
      :aborted ->
        {:error, {:credential_write_failed, "could not lock credential file"}}

      result ->
        result
    end
  end

  defp stored_or_empty(path) do
    case read_stored(path) do
      {:ok, credentials, :stored} -> {:ok, credentials}
      {:error, :not_found} -> {:ok, %{api_key: nil, workspace_id: nil}}
      {:error, _reason} = error -> error
    end
  end

  defp read_stored(path) do
    with {:ok, before} <- File.lstat(path, time: :posix),
         :ok <- validate_stat(path, before),
         {:ok, contents} <- File.read(path),
         {:ok, after_read} <- File.lstat(path, time: :posix),
         true <- same_file?(before, after_read),
         {:ok, credentials} <- decode(contents) do
      {:ok, credentials, :stored}
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
      stat.size > @max_file_bytes -> {:error, {:unsafe_credential_file, path, :too_large}}
      true -> :ok
    end
  end

  defp decode(contents) do
    case Jason.decode(contents) do
      {:ok, %{"version" => @document_version, "api_key" => key} = document} ->
        with {:ok, key} <- normalize(key),
             {:ok, workspace_id} <- normalize_workspace(document["workspace_id"]) do
          {:ok, %{api_key: key, workspace_id: workspace_id}}
        end

      {:ok, _other_json} ->
        {:error, :invalid_credential_document}

      {:error, _not_json} ->
        with {:ok, key} <- normalize(contents) do
          {:ok, %{api_key: key, workspace_id: nil}}
        end
    end
  end

  defp publish(path, credentials) do
    directory = Path.dirname(path)
    DataDir.ensure_private!(directory)

    document =
      Jason.encode!(%{
        "version" => @document_version,
        "api_key" => credentials.api_key,
        "workspace_id" => credentials.workspace_id
      })

    temporary =
      path <>
        ".tmp-#{System.unique_integer([:positive, :monotonic])}-" <>
        Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)

    try do
      File.write!(temporary, "", [:exclusive, :sync])
      File.chmod!(temporary, 0o600)
      before = File.lstat!(temporary, time: :posix)

      File.open!(temporary, [:write, :binary], fn io ->
        IO.binwrite(io, document)
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
