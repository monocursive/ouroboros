import Config

if config_env() == :prod do
  data_dir = System.get_env("OUROBOROS_DATA_DIR")

  unless is_binary(data_dir) and String.trim(data_dir) != "" and Path.type(data_dir) == :absolute do
    raise "OUROBOROS_DATA_DIR must be a nonblank absolute durable directory in production"
  end

  File.mkdir_p!(data_dir)

  probe =
    Path.join(
      data_dir,
      ".ouroboros-storage-probe-#{System.unique_integer([:positive, :monotonic])}"
    )

  probe_target = probe <> ".committed"

  try do
    File.write!(probe, "durability-preflight", [:binary, :sync])
    File.rename!(probe, probe_target)
  after
    _ = File.rm(probe)
    _ = File.rm(probe_target)
  end

  workspace_roots =
    case System.get_env("OUROBOROS_WORKSPACE_ROOTS") do
      nil -> []
      roots -> String.split(roots, ":", trim: true)
    end

  orchestration_concurrency =
    case Integer.parse(System.get_env("OUROBOROS_ORCHESTRATION_CONCURRENCY") || "4") do
      {value, ""} when value > 0 -> value
      _other -> raise "OUROBOROS_ORCHESTRATION_CONCURRENCY must be a positive integer"
    end

  # The forge lane of the orchestration plane is off unless a workspace is named.
  # Nodes default to the local node at execution time rather than here, because
  # distribution may not have started when this file is evaluated.
  forge_workspace =
    case System.get_env("OUROBOROS_ORCHESTRATION_FORGE_WORKSPACE") do
      nil ->
        nil

      workspace ->
        if Path.type(workspace) == :absolute do
          workspace
        else
          raise "OUROBOROS_ORCHESTRATION_FORGE_WORKSPACE must be an absolute path"
        end
    end

  forge_nodes =
    case System.get_env("OUROBOROS_ORCHESTRATION_FORGE_NODES") do
      nil ->
        []

      nodes ->
        nodes |> String.split(",", trim: true) |> Enum.map(&String.to_atom(String.trim(&1)))
    end

  orchestration_forge_options =
    cond do
      is_nil(forge_workspace) -> []
      forge_nodes == [] -> [workspace: forge_workspace]
      true -> [workspace: forge_workspace, nodes: forge_nodes]
    end

  orchestration_forge_options =
    case System.get_env("OUROBOROS_FORGE_SIGNER_ID") do
      nil -> orchestration_forge_options
      signer_id -> Keyword.put(orchestration_forge_options, :signer_id, signer_id)
    end

  # Letting a planner express a forge step is an explicit operator decision, and
  # still not authority to deploy: signing and per-node signature verification
  # are unchanged by it.
  control_allow_forge_steps =
    System.get_env("OUROBOROS_CONTROL_ALLOW_FORGE_STEPS") == "true"

  signer_format =
    "OUROBOROS_UPGRADE_TRUSTED_SIGNERS must be comma-separated " <>
      "\"signer_id:base64_ed25519_public_key\" entries"

  # The fast patch lane is fail-closed: an absent or empty variable trusts nobody and
  # every signed artifact is rejected. A malformed entry raises rather than silently
  # narrowing the trusted set at boot.
  trusted_signers =
    (System.get_env("OUROBOROS_UPGRADE_TRUSTED_SIGNERS") || "")
    |> String.split(",", trim: true)
    |> Enum.reduce(%{}, fn entry, signers ->
      {signer, encoded} =
        case entry |> String.trim() |> String.split(":", parts: 2) do
          [signer, encoded] -> {String.trim(signer), String.trim(encoded)}
          _other -> raise signer_format
        end

      if signer == "" do
        raise signer_format
      end

      if Map.has_key?(signers, signer) do
        raise "OUROBOROS_UPGRADE_TRUSTED_SIGNERS lists signer #{inspect(signer)} more than once"
      end

      public_key =
        case Base.decode64(encoded) do
          {:ok, key} when byte_size(key) == 32 ->
            key

          _other ->
            raise "OUROBOROS_UPGRADE_TRUSTED_SIGNERS entry #{inspect(signer)} must carry a " <>
                    "base64-encoded 32-byte Ed25519 public key"
        end

      Map.put(signers, signer, public_key)
    end)

  config :ouroboros,
    coding_storage: {Jido.Storage.File, path: Path.join(data_dir, "coding")},
    interactive_storage: {Jido.Storage.File, path: Path.join(data_dir, "interactive")},
    team_storage: {Jido.Storage.File, path: Path.join(data_dir, "teams")},
    orchestration_storage: {Jido.Storage.File, path: Path.join(data_dir, "orchestration")},
    control_storage: {Jido.Storage.File, path: Path.join(data_dir, "control")},
    # The effect authority decides what agents may do to the cluster, so it is held to
    # the same synced write the mutation journals use: a grant that was acknowledged
    # must survive the crash that follows it, and a revocation must too.
    grants_storage: {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "grants")},
    upgrade_storage: {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "upgrades")},
    release_storage:
      {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "release-journal")},
    capability_storage:
      {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "capabilities")},
    # The epoch watermark must survive a crash between allocating a number and using it,
    # or the same epoch could be handed out twice.
    epoch_storage: {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "forge-epochs")},
    workspace_allowed_roots: workspace_roots,
    orchestration_max_concurrency: orchestration_concurrency,
    orchestration_team_id: System.get_env("OUROBOROS_ORCHESTRATION_TEAM_ID"),
    orchestration_worker_id: System.get_env("OUROBOROS_ORCHESTRATION_WORKER_ID"),
    orchestration_forge_options: orchestration_forge_options,
    control_allow_forge_steps: control_allow_forge_steps,
    upgrade_trust_policy: [
      allow_unsigned: false,
      trusted_signers: trusted_signers
    ]
end
