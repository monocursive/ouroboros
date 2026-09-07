defmodule Ouroboros.Audit.Config do
  @moduledoc "Node-owned audit policy. Session and repository options cannot override it."

  @derive {Inspect, except: [:encryption_keys, :identities, :archive]}
  defstruct mode: :standard,
            capture: :metadata,
            root: nil,
            index: false,
            segment_bytes: 4_194_304,
            capacity_bytes: 1_073_741_824,
            retention_days: 90,
            organization: "local",
            writer_id: nil,
            otlp_endpoint: nil,
            policy_file: nil,
            archive: nil,
            archive_required: false,
            encryption_key_id: nil,
            encryption_keys: %{},
            identities: []

  def current do
    Application.get_env(:ouroboros, :audit, []) |> new!()
  end

  def new!(%__MODULE__{} = config), do: validate!(config)
  def new!(options) when is_list(options), do: struct!(__MODULE__, options) |> validate!()

  def enabled?(config \\ current()), do: config.mode != :standard
  def required?(config \\ current()), do: config.mode == :required

  def public(config \\ current()) do
    config
    |> Map.from_struct()
    |> Map.drop([:encryption_keys, :identities, :archive])
    |> Map.put(
      :identity_policy_sha256,
      Ouroboros.Provider.Native.Journal.digest(config.identities)
    )
    |> Map.put(
      :archive_trust,
      if(config.archive,
        do: %{key_id: config.archive.key_id, public_key: Base.encode64(config.archive.public_key)},
        else: nil
      )
    )
    |> Map.put(:archive_configured, not is_nil(config.archive))
    |> Map.put(
      :operational_content,
      if(config.encryption_key_id,
        do: "encrypted_new_writes_legacy_scan_required",
        else: "plaintext_working_set"
      )
    )
  end

  def revision(config \\ current()),
    do: Ouroboros.Provider.Native.Journal.digest(public(config))

  def from_environment!(data_dir, env \\ System.get_env()) do
    file = env["OUROBOROS_AUDIT_CONFIG"]
    document = if file, do: private_json!(file), else: %{}

    allowed =
      ~w(mode capture root index segment_bytes capacity_bytes retention_days organization writer_id otlp_endpoint archive archive_required encryption_key_id encryption_keys identities)

    unless Enum.all?(Map.keys(document), &(&1 in allowed)), do: invalid!(:unknown_policy_field)

    mode =
      Map.get(
        %{"standard" => :standard, "local" => :local, "required" => :required},
        env["OUROBOROS_AUDIT_MODE"] || document["mode"] || "standard"
      )

    capture =
      Map.get(
        %{"metadata" => :metadata, "redacted" => :redacted, "full" => :full},
        document["capture"] || "metadata"
      )

    base = %__MODULE__{
      mode: mode,
      capture: capture,
      root: document["root"] || if(data_dir, do: Path.join(data_dir, "audit")),
      policy_file: file
    }

    config =
      Enum.reduce(
        [
          :index,
          :segment_bytes,
          :capacity_bytes,
          :retention_days,
          :organization,
          :writer_id,
          :otlp_endpoint,
          :archive_required,
          :encryption_key_id,
          :identities
        ],
        base,
        fn key, config ->
          if Map.has_key?(document, Atom.to_string(key)),
            do: Map.put(config, key, document[Atom.to_string(key)]),
            else: config
        end
      )

    keys =
      Map.new(document["encryption_keys"] || %{}, fn {id, encoded} ->
        case Base.decode64(encoded) do
          {:ok, key} when byte_size(key) == 32 -> {id, key}
          _ -> invalid!(:encryption_keys)
        end
      end)

    archive =
      case document["archive"] do
        nil ->
          nil

        %{"url" => url, "token_file" => token_file, "key_id" => key_id, "public_key" => encoded} ->
          with :ok <- Ouroboros.Audit.Archive.endpoint(url),
               {:ok, key} when byte_size(key) == 32 <- Base.decode64(encoded) do
            %{
              url: String.trim_trailing(url, "/"),
              token: private_file!(token_file) |> String.trim(),
              token_file: token_file,
              key_id: key_id,
              public_key: key,
              previous_keys:
                Map.new(document["archive"]["previous_keys"] || %{}, fn {id, encoded} ->
                  case Base.decode64(encoded) do
                    {:ok, previous} when byte_size(previous) == 32 -> {id, previous}
                    _ -> invalid!(:archive_previous_keys)
                  end
                end)
            }
          else
            _ -> invalid!(:archive)
          end

        _ ->
          invalid!(:archive)
      end

    config = validate!(%{config | encryption_keys: keys, archive: archive})

    if required?(config) and (config.encryption_key_id == nil or config.identities == []),
      do: invalid!(:required_mode_needs_encryption_and_named_identities)

    config
  end

  defp private_json!(file) do
    case file |> private_file!() |> JSON.decode() do
      {:ok, document} when is_map(document) -> document
      _ -> invalid!(:policy_file)
    end
  end

  defp private_file!(path) do
    import Bitwise

    with true <- is_binary(path) and Path.type(path) == :absolute,
         :ok <- Ouroboros.Audit.File.no_symlinks(Path.dirname(path)),
         {:ok, %{type: :regular, mode: mode, size: size}} <- File.lstat(path),
         true <- band(mode, 0o077) == 0 and size <= 1_048_576,
         {:ok, bytes} <- File.read(path) do
      bytes
    else
      _ -> invalid!(:private_policy_file)
    end
  end

  defp validate!(config) do
    unless config.mode in [:standard, :local, :required], do: invalid!(:mode)
    unless config.capture in [:metadata, :redacted, :full], do: invalid!(:capture)
    unless is_boolean(config.index), do: invalid!(:index)
    unless is_boolean(config.archive_required), do: invalid!(:archive_required)

    for key <- [:segment_bytes, :capacity_bytes, :retention_days] do
      value = Map.fetch!(config, key)
      unless is_integer(value) and value > 0, do: invalid!(key)
    end

    unless config.segment_bytes <= config.capacity_bytes, do: invalid!(:segment_bytes)

    if enabled?(config) do
      unless is_binary(config.root) and Path.type(config.root) == :absolute,
        do: invalid!(:root)

      unless is_binary(config.organization) and byte_size(config.organization) in 1..200,
        do: invalid!(:organization)
    end

    if config.archive_required and is_nil(config.archive), do: invalid!(:archive_required)

    unless is_list(config.identities) and
             Enum.all?(config.identities, fn identity ->
               is_map(identity) and is_binary(identity["id"]) and
                 byte_size(identity["id"]) in 1..200 and
                 Ouroboros.Audit.Store.valid_id?(identity["token_sha256"]) and
                 is_list(identity["roles"]) and
                 identity["roles"] != [] and
                 Enum.all?(
                   identity["roles"],
                   &(&1 in ["operator", "approver", "auditor", "administrator"])
                 )
             end),
           do: invalid!(:identities)

    ids = Enum.map(config.identities, & &1["id"])
    hashes = Enum.map(config.identities, & &1["token_sha256"])

    unless length(ids) == length(Enum.uniq(ids)) and length(hashes) == length(Enum.uniq(hashes)),
      do: invalid!(:duplicate_identity)

    if config.encryption_key_id do
      unless is_binary(config.encryption_key_id) and
               byte_size(Map.get(config.encryption_keys, config.encryption_key_id, "")) == 32,
             do: invalid!(:encryption_key_id)
    end

    if config.otlp_endpoint,
      do:
        unless(Ouroboros.Audit.Archive.endpoint(config.otlp_endpoint) == :ok,
          do: invalid!(:otlp_endpoint)
        )

    if config.writer_id != nil and
         (not is_binary(config.writer_id) or byte_size(config.writer_id) not in 1..200),
       do: invalid!(:writer_id)

    config
  end

  def writer_id(config),
    do:
      config.writer_id ||
        Ouroboros.Provider.Native.Journal.digest([
          config.organization,
          to_string(node()),
          config.root
        ])

  defp invalid!(field), do: raise(ArgumentError, "invalid audit configuration: #{field}")
end
