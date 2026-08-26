defmodule Ouroboros.Release.HandlerAdapter do
  @moduledoc """
  Injection boundary around OTP's node-mutating release handler.

  Tests should provide a fake adapter. The production adapter below is the only
  module in this lane that invokes `:release_handler`.
  """

  @type release_status :: :unpacked | :current | :permanent | :old
  @type release_entry :: {charlist(), charlist(), [charlist()], release_status()}

  @callback which_releases() :: [release_entry()] | {:error, term()}
  @callback package_path(charlist()) :: charlist() | {:error, term()}
  @callback unpack_release(charlist()) :: {:ok, charlist()} | {:error, term()}
  @callback check_install_release(charlist(), list()) ::
              {:ok, charlist(), term()} | {:error, term()}
  @callback install_release(charlist(), list()) ::
              {:ok, charlist(), term()}
              | {:continue_after_restart, charlist(), term()}
              | {:error, term()}
  @callback make_permanent(charlist()) :: :ok | {:error, term()}
end

defmodule Ouroboros.Release.HandlerAdapter.OTP do
  @moduledoc """
  Direct adapter for OTP `:release_handler`.

  `unpack_release/1` writes/extracts files and updates the release handler's
  persistent `RELEASES` state. `check_install_release/2` can evaluate relup
  instructions before `point_of_no_return`. `install_release/2` changes the
  running node. `make_permanent/1` changes which release survives reboot.

  Ouroboros passes `unpack_release/1` a content-addressed staged basename. OTP
  requires its own argument to match the archive's top-level
  `releases/<name>.rel`, so this adapter derives that name from the staged bytes,
  exclusively hard-links the same inode to the required alias, calls OTP, and
  removes the alias. The releases directory must be writable only by the
  deployment identity; directory ownership is the operating-system trust
  boundary for this operation.
  """

  @behaviour Ouroboros.Release.HandlerAdapter

  @impl true
  def which_releases, do: :release_handler.which_releases()

  @impl true
  def package_path(package_name) do
    releases_dir =
      case Application.get_env(:sasl, :releases_dir) do
        nil -> System.get_env("RELDIR") || Path.join(:code.root_dir(), "releases")
        directory -> to_string(directory)
      end

    Path.join(releases_dir, List.to_string(package_name) <> ".tar.gz")
    |> String.to_charlist()
  end

  @impl true
  def unpack_release(package_name) do
    unpack_release_with(package_name, &:release_handler.unpack_release/1)
  end

  @doc false
  def unpack_release_with(package_name, unpacker, sync \\ &sync_directory/1)

  # Everything after a successful `File.ln` runs inside the `try`, so the alias is
  # removed on every path out — including a failed directory sync. An alias left behind
  # is not a lost temporary file: the next unpack of the same release gets `:eexist` and
  # fails closed forever until an operator deletes it by hand.
  def unpack_release_with(package_name, unpacker, sync)
      when is_function(unpacker, 1) and is_function(sync, 1) do
    with {:ok, staged_name, expected_sha256} <- staged_identity(package_name),
         staged_path <- package_path(String.to_charlist(staged_name)) |> List.to_string(),
         {:ok, %{type: :regular}} <- File.lstat(staged_path),
         {:ok, binary} <- File.read(staged_path),
         :ok <- verify_digest(binary, expected_sha256),
         {:ok, otp_name} <- otp_release_name(binary),
         alias_path <- package_path(String.to_charlist(otp_name)) |> List.to_string(),
         true <- alias_path != staged_path || {:error, :invalid_release_package_alias},
         :ok <- File.ln(staged_path, alias_path) do
      try do
        with :ok <- sync.(Path.dirname(alias_path)) do
          unpacker.(String.to_charlist(otp_name))
        end
      after
        _ = remove_if_present(alias_path)
        _ = sync.(Path.dirname(alias_path))
      end
    else
      {:ok, %{type: type}} -> {:error, {:invalid_staged_release_file, type}}
      {:error, :eexist} -> {:error, :release_package_alias_exists}
      {:error, reason} -> {:error, reason}
      false -> {:error, :invalid_release_package_alias}
    end
  rescue
    error -> {:error, {:staged_release_adapter_failed, error}}
  catch
    kind, reason -> {:error, {:staged_release_adapter_failed, kind, reason}}
  end

  def unpack_release_with(_package_name, _unpacker, _sync),
    do: {:error, :invalid_release_unpacker}

  @impl true
  def check_install_release(version, options),
    do: :release_handler.check_install_release(version, options)

  @impl true
  def install_release(version, options), do: :release_handler.install_release(version, options)

  @impl true
  def make_permanent(version), do: :release_handler.make_permanent(version)

  defp staged_identity(package_name) when is_list(package_name) do
    with name when is_binary(name) <- List.to_string(package_name),
         "ouroboros-release-sha256-" <> digest <- name,
         true <- byte_size(digest) == 64 and digest =~ ~r/\A[0-9a-f]{64}\z/ do
      {:ok, name, digest}
    else
      _other -> {:error, :invalid_content_addressed_release_name}
    end
  rescue
    _error -> {:error, :invalid_content_addressed_release_name}
  end

  defp staged_identity(_package_name), do: {:error, :invalid_content_addressed_release_name}

  defp verify_digest(binary, expected) do
    actual = :crypto.hash(:sha256, binary) |> Base.encode16(case: :lower)
    if actual == expected, do: :ok, else: {:error, :staged_release_digest_mismatch}
  end

  defp otp_release_name(binary) do
    case :erl_tar.table({:binary, binary}, [:compressed]) do
      {:ok, names} ->
        candidates =
          Enum.flat_map(names, fn name ->
            name = List.to_string(name)

            case Path.split(name) do
              ["releases", filename] ->
                if String.ends_with?(filename, ".rel"),
                  do: [String.trim_trailing(filename, ".rel")],
                  else: []

              _other ->
                []
            end
          end)

        case candidates do
          [name] when name != "" -> {:ok, name}
          [] -> {:error, :missing_top_level_release_metadata}
          _many -> {:error, :multiple_top_level_release_metadata}
        end

      {:error, reason} ->
        {:error, {:invalid_staged_release_archive, reason}}
    end
  end

  defp sync_directory(directory) do
    with {:ok, device} <-
           :file.open(String.to_charlist(directory), [:read, :raw, :directory]) do
      result = :file.sync(device)
      close_result = :file.close(device)

      case {result, close_result} do
        {:ok, :ok} -> :ok
        {{:error, reason}, _close} -> {:error, {:release_directory_sync_failed, reason}}
        {:ok, {:error, reason}} -> {:error, {:release_directory_close_failed, reason}}
      end
    end
  end

  defp remove_if_present(path) do
    case File.rm(path) do
      :ok -> :ok
      {:error, :enoent} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end
end
