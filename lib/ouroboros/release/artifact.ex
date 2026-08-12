defmodule Ouroboros.Release.Artifact do
  @moduledoc """
  A content-addressed, offline-inspected OTP release archive.

  Inspection reads the compressed tar in memory, rejects unsafe or duplicate
  member names and special-file entries, parses release metadata without
  evaluating it, and checks the release, boot, and relup versions agree. It
  never extracts files or calls `:release_handler`.

  Parsing Erlang textual metadata necessarily interns atoms. Metadata files are
  therefore size-capped; this parser is a structural validator, not a sandbox
  for hostile, unauthenticated archives.
  """

  alias Ouroboros.Release.Metadata

  require Record

  Record.defrecordp(
    :file_info,
    Record.extract(:file_info, from_lib: "kernel/include/file.hrl")
  )

  @default_max_archive_bytes 512 * 1024 * 1024
  @default_max_metadata_bytes 2 * 1024 * 1024

  @enforce_keys [
    :id,
    :path,
    :package_name,
    :sha256,
    :size,
    :release_name,
    :version,
    :erts_version,
    :applications,
    :files,
    :relup,
    :appups,
    :inspection_policy
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          id: String.t(),
          path: String.t(),
          package_name: String.t(),
          sha256: String.t(),
          size: non_neg_integer(),
          release_name: String.t(),
          version: String.t(),
          erts_version: String.t(),
          applications: list(),
          files: [map()],
          relup: map(),
          appups: [map()],
          inspection_policy: keyword()
        }

  @spec inspect_package(Path.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def inspect_package(path, opts \\ [])

  def inspect_package(path, opts) when is_binary(path) and is_list(opts) do
    with true <- Keyword.keyword?(opts) || {:error, :invalid_options},
         {:ok, limits} <- limits(opts),
         {:ok, inspection_policy} <- inspection_policy(opts, limits),
         {:ok, absolute_path} <- absolute_path(path),
         :ok <- package_extension(absolute_path),
         {:ok, archive_binary} <- read_regular_binary(absolute_path, limits.max_archive_bytes),
         {:ok, table} <- tar_table(archive_binary),
         {:ok, files} <- validate_table(table, limits.max_archive_bytes),
         {:ok, metadata_names} <- metadata_names(files),
         {:ok, contents} <- extract_metadata(archive_binary, metadata_names, limits),
         {:ok, release} <- validate_release_files(contents),
         {:ok, relup} <- validate_relup(contents, release, opts),
         {:ok, appups} <- validate_appups(contents, release),
         :ok <- validate_boot(contents, release) do
      digest = sha256(archive_binary)

      {:ok,
       %__MODULE__{
         id: "otp-release-sha256:" <> digest,
         path: absolute_path,
         package_name: package_name(absolute_path),
         sha256: digest,
         size: byte_size(archive_binary),
         release_name: release.name,
         version: release.version,
         erts_version: release.erts_version,
         applications: release.applications,
         files: files,
         relup: relup,
         appups: appups,
         inspection_policy: inspection_policy
       }}
    end
  rescue
    error -> {:error, {:package_inspection_failed, error}}
  catch
    kind, reason -> {:error, {:package_inspection_failed, kind, reason}}
  end

  def inspect_package(_path, _opts), do: {:error, :invalid_package_path}

  @doc "Re-inspects a package and proves that its content and release identity did not change."
  @spec revalidate(t()) :: :ok | {:error, term()}
  def revalidate(%__MODULE__{} = artifact) do
    case inspect_package(artifact.path, artifact.inspection_policy) do
      {:ok, current} ->
        if identity(current) == identity(artifact),
          do: :ok,
          else: {:error, {:artifact_changed, artifact.sha256, current.sha256}}

      {:error, _reason} = error ->
        error
    end
  end

  def revalidate(_artifact), do: {:error, :invalid_release_artifact}

  @doc "Reads one opened source file and proves its exact bytes still match the artifact."
  @spec read_verified(t()) :: {:ok, binary()} | {:error, term()}
  def read_verified(%__MODULE__{} = artifact) do
    with :ok <- validate_read_identity(artifact),
         {:ok, binary} <- read_regular_binary(artifact.path, artifact.size),
         true <-
           byte_size(binary) == artifact.size ||
             {:error, {:artifact_size_changed, artifact.size, byte_size(binary)}},
         current_sha256 <- sha256(binary),
         true <-
           current_sha256 == artifact.sha256 ||
             {:error, {:artifact_changed, artifact.sha256, current_sha256}} do
      {:ok, binary}
    end
  rescue
    error -> {:error, {:artifact_read_failed, error}}
  catch
    kind, reason -> {:error, {:artifact_read_failed, kind, reason}}
  end

  def read_verified(_artifact), do: {:error, :invalid_release_artifact}

  @doc false
  @spec summary(t()) :: map()
  def summary(%__MODULE__{} = artifact) do
    Map.take(artifact, [
      :id,
      :package_name,
      :sha256,
      :size,
      :release_name,
      :version,
      :erts_version,
      :applications,
      :relup,
      :appups,
      :inspection_policy
    ])
  end

  defp identity(artifact) do
    Map.take(artifact, [
      :sha256,
      :size,
      :release_name,
      :version,
      :erts_version,
      :applications,
      :files,
      :relup,
      :appups
    ])
  end

  defp limits(opts) do
    archive = Keyword.get(opts, :max_archive_bytes, @default_max_archive_bytes)
    metadata = Keyword.get(opts, :max_metadata_bytes, @default_max_metadata_bytes)

    if is_integer(archive) and archive > 0 and is_integer(metadata) and metadata > 0 do
      {:ok, %{max_archive_bytes: archive, max_metadata_bytes: metadata}}
    else
      {:error, :invalid_size_limit}
    end
  end

  defp inspection_policy(opts, limits) do
    allowed = [:max_archive_bytes, :max_metadata_bytes, :require_relup]

    case Keyword.keys(opts) -- allowed do
      [] ->
        required? = Keyword.get(opts, :require_relup, true)

        if is_boolean(required?) do
          {:ok,
           [
             max_archive_bytes: limits.max_archive_bytes,
             max_metadata_bytes: limits.max_metadata_bytes,
             require_relup: required?
           ]}
        else
          {:error, :invalid_require_relup}
        end

      [unknown | _] ->
        {:error, {:unknown_inspection_option, unknown}}
    end
  end

  defp absolute_path(path), do: {:ok, Path.expand(path)}

  defp package_extension(path) do
    if String.ends_with?(path, ".tar.gz"),
      do: :ok,
      else: {:error, :release_package_must_end_in_tar_gz}
  end

  defp tar_table(binary) do
    case :erl_tar.table({:binary, binary}, [:compressed, :verbose]) do
      {:ok, table} -> {:ok, table}
      {:error, reason} -> {:error, {:invalid_release_archive, reason}}
    end
  end

  defp validate_table(table, max_bytes) when is_list(table) do
    with :ok <- validate_entries(table),
         total <-
           Enum.reduce(table, 0, fn {_name, _type, size, _, _, _, _}, acc -> acc + size end),
         true <- total <= max_bytes || {:error, {:expanded_archive_too_large, total, max_bytes}} do
      {:ok,
       table
       |> Enum.filter(fn {_name, type, _size, _, _, _, _} -> type == :regular end)
       |> Enum.map(fn {name, _type, size, _mtime, _mode, _uid, _gid} ->
         %{name: List.to_string(name), size: size}
       end)
       |> Enum.sort_by(& &1.name)}
    end
  end

  defp validate_table(_table, _max_bytes), do: {:error, :invalid_archive_table}

  defp validate_entries(entries) do
    names = Enum.map(entries, fn {name, _type, _size, _, _, _, _} -> List.to_string(name) end)

    with true <- names == Enum.uniq(names) || {:error, :duplicate_archive_members},
         true <- Enum.all?(names, &safe_member_name?/1) || {:error, :unsafe_archive_member},
         true <-
           Enum.all?(entries, fn {_name, type, _size, _, _, _, _} ->
             type in [:regular, :directory]
           end) || {:error, :special_archive_member} do
      :ok
    end
  end

  defp safe_member_name?(name) do
    parts = Path.split(name)

    name != "" and String.valid?(name) and not String.starts_with?(name, "/") and
      not String.contains?(name, [<<0>>, "\\"]) and
      Enum.all?(parts, &(&1 not in ["", ".", ".."]))
  end

  defp metadata_names(files) do
    names = Enum.map(files, & &1.name)

    selected =
      Enum.filter(names, fn name ->
        String.ends_with?(name, [".rel", ".appup", "/relup", "/start.boot"])
      end)

    {:ok, selected}
  end

  defp extract_metadata(archive_binary, names, limits) do
    opts = [
      :compressed,
      :memory,
      {:files, Enum.map(names, &String.to_charlist/1)},
      {:max_size, limits.max_metadata_bytes}
    ]

    case :erl_tar.extract({:binary, archive_binary}, opts) do
      {:ok, entries} ->
        {:ok, Map.new(entries, fn {name, binary} -> {List.to_string(name), binary} end)}

      {:error, reason} ->
        {:error, {:metadata_extract_failed, reason}}
    end
  end

  defp validate_release_files(contents) do
    versioned =
      contents
      |> Enum.filter(fn {name, _binary} -> versioned_rel_path?(name) end)
      |> Enum.sort()

    with [{versioned_name, versioned_binary}] <- versioned,
         {:ok, {_term, release}} <- Metadata.parse(versioned_binary, :rel),
         :ok <- validate_versioned_rel_path(versioned_name, release),
         top_name <- "releases/#{release.name}.rel",
         {:ok, top_binary} <- fetch_content(contents, top_name),
         true <- top_binary == versioned_binary || {:error, :release_metadata_mismatch} do
      {:ok, Map.put(release, :metadata_path, versioned_name)}
    else
      [] -> {:error, :missing_versioned_rel}
      [_ | _] -> {:error, :multiple_versioned_rel_files}
      {:error, _reason} = error -> error
      false -> {:error, :release_metadata_mismatch}
    end
  end

  defp versioned_rel_path?(name) do
    case Path.split(name) do
      ["releases", _version, filename] -> String.ends_with?(filename, ".rel")
      _other -> false
    end
  end

  defp validate_versioned_rel_path(name, release) do
    expected = "releases/#{release.version}/#{release.name}.rel"
    if name == expected, do: :ok, else: {:error, {:unexpected_rel_path, name, expected}}
  end

  defp validate_relup(contents, release, opts) do
    path = "releases/#{release.version}/relup"
    required? = Keyword.get(opts, :require_relup, true)

    case Map.fetch(contents, path) do
      {:ok, binary} ->
        with {:ok, {_term, relup}} <- Metadata.parse(binary, :relup),
             true <- relup.version == release.version || {:error, :relup_version_mismatch} do
          {:ok, Map.put(relup, :path, path)}
        end

      :error when required? ->
        {:error, :missing_relup}

      :error ->
        {:ok, %{version: release.version, upgrades: [], downgrades: [], path: nil}}
    end
  end

  defp validate_appups(contents, release) do
    expected_paths =
      Map.new(release.applications, fn application ->
        name = application |> elem(0) |> Atom.to_string()
        version = elem(application, 1)
        {"lib/#{name}-#{version}/ebin/#{name}.appup", {name, version}}
      end)

    contents
    |> Enum.filter(fn {name, _binary} -> String.ends_with?(name, ".appup") end)
    |> Enum.sort()
    |> Enum.reduce_while({:ok, []}, fn {name, binary}, {:ok, acc} ->
      with {:ok, {_application, expected_version}} <- fetch_expected_appup(expected_paths, name),
           {:ok, {_term, summary}} <- Metadata.parse(binary, :appup),
           true <-
             summary.version == expected_version ||
               {:error, {:appup_version_mismatch, name, expected_version, summary.version}} do
        {:cont, {:ok, [Map.put(summary, :path, name) | acc]}}
      else
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, appups} -> {:ok, Enum.reverse(appups)}
      {:error, _reason} = error -> error
    end
  end

  defp fetch_expected_appup(expected_paths, path) do
    case Map.fetch(expected_paths, path) do
      {:ok, application} -> {:ok, application}
      :error -> {:error, {:unexpected_appup_path, path}}
    end
  end

  defp validate_boot(contents, release) do
    path = "releases/#{release.version}/start.boot"

    with {:ok, binary} <- fetch_content(contents, path),
         {:ok, boot} <- safe_binary_to_term(binary),
         {:script, {name, version}, instructions} when is_list(instructions) <- boot,
         {:ok, name} <- normalize_boot_text(name),
         {:ok, version} <- normalize_boot_text(version),
         true <- name == release.name || {:error, :boot_release_name_mismatch},
         true <- version == release.version || {:error, :boot_release_version_mismatch} do
      :ok
    else
      {:error, _reason} = error -> error
      _other -> {:error, :invalid_start_boot}
    end
  end

  defp safe_binary_to_term(binary) do
    {:ok, :erlang.binary_to_term(binary, [:safe])}
  rescue
    _error -> {:error, :invalid_start_boot}
  end

  defp normalize_boot_text(value) when is_binary(value), do: {:ok, value}

  defp normalize_boot_text(value) when is_list(value) do
    {:ok, List.to_string(value)}
  rescue
    _error -> {:error, :invalid_start_boot_identity}
  end

  defp normalize_boot_text(_value), do: {:error, :invalid_start_boot_identity}

  defp fetch_content(contents, name) do
    case Map.fetch(contents, name) do
      {:ok, binary} -> {:ok, binary}
      :error -> {:error, {:missing_release_file, name}}
    end
  end

  defp package_name(path) do
    basename = Path.basename(path)
    String.trim_trailing(basename, ".tar.gz")
  end

  defp validate_read_identity(artifact) do
    exact_binary? = fn value -> is_binary(value) and value != "" end

    valid_sha256? =
      is_binary(artifact.sha256) and byte_size(artifact.sha256) == 64 and
        artifact.sha256 =~ ~r/\A[0-9a-f]{64}\z/

    valid_policy? =
      is_list(artifact.inspection_policy) and Keyword.keyword?(artifact.inspection_policy) and
        is_integer(artifact.inspection_policy[:max_archive_bytes]) and
        artifact.inspection_policy[:max_archive_bytes] > 0 and
        artifact.size <= artifact.inspection_policy[:max_archive_bytes]

    expected_id = if valid_sha256?, do: "otp-release-sha256:" <> artifact.sha256, else: nil

    if exact_binary?.(artifact.path) and exact_binary?.(artifact.package_name) and
         exact_binary?.(artifact.release_name) and exact_binary?.(artifact.version) and
         exact_binary?.(artifact.erts_version) and artifact.id == expected_id and
         is_integer(artifact.size) and artifact.size >= 0 and valid_sha256? and valid_policy?,
       do: :ok,
       else: {:error, :invalid_release_artifact}
  end

  defp read_regular_binary(path, max_bytes)
       when is_binary(path) and is_integer(max_bytes) and max_bytes >= 0 do
    case :file.open(String.to_charlist(path), [:read, :binary, :raw]) do
      {:ok, device} ->
        result =
          with {:ok, info} <- :file.read_file_info(device),
               :ok <- ensure_regular_info(info),
               :ok <- archive_size(file_info(info, :size), max_bytes),
               {:ok, binary} <- read_bounded(device, max_bytes) do
            {:ok, binary}
          else
            {:error, :enoent} -> {:error, {:package_unavailable, :enoent}}
            {:error, _reason} = error -> error
          end

        _ = :file.close(device)
        result

      {:error, reason} ->
        {:error, {:package_unavailable, reason}}
    end
  end

  defp read_regular_binary(_path, _max_bytes), do: {:error, :invalid_release_artifact}

  defp ensure_regular_info(info) do
    case file_info(info, :type) do
      :regular -> :ok
      type -> {:error, {:not_regular_file, type}}
    end
  end

  defp archive_size(size, limit) when is_integer(size) and size <= limit, do: :ok
  defp archive_size(size, limit), do: {:error, {:archive_too_large, size, limit}}

  defp read_bounded(device, max_bytes), do: read_bounded(device, max_bytes, [], 0)

  defp read_bounded(device, remaining, chunks, total) when remaining > 0 do
    case :file.read(device, min(remaining, 64 * 1024)) do
      {:ok, binary} ->
        read_bounded(
          device,
          remaining - byte_size(binary),
          [binary | chunks],
          total + byte_size(binary)
        )

      :eof ->
        {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}

      {:error, reason} ->
        {:error, {:package_read_failed, reason}}
    end
  end

  defp read_bounded(device, 0, chunks, total) do
    case :file.read(device, 1) do
      :eof -> {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}
      {:ok, _binary} -> {:error, {:archive_too_large, total + 1, total}}
      {:error, reason} -> {:error, {:package_read_failed, reason}}
    end
  end

  defp sha256(binary), do: :crypto.hash(:sha256, binary) |> Base.encode16(case: :lower)
end
