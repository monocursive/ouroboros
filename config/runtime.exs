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

  config :ouroboros,
    coding_storage: {Jido.Storage.File, path: Path.join(data_dir, "coding")},
    interactive_storage: {Jido.Storage.File, path: Path.join(data_dir, "interactive")},
    team_storage: {Jido.Storage.File, path: Path.join(data_dir, "teams")},
    orchestration_storage: {Jido.Storage.File, path: Path.join(data_dir, "orchestration")},
    control_storage: {Jido.Storage.File, path: Path.join(data_dir, "control")},
    upgrade_storage: {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "upgrades")},
    release_storage:
      {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "release-journal")},
    workspace_allowed_roots: workspace_roots,
    orchestration_max_concurrency: orchestration_concurrency,
    orchestration_team_id: System.get_env("OUROBOROS_ORCHESTRATION_TEAM_ID"),
    orchestration_worker_id: System.get_env("OUROBOROS_ORCHESTRATION_WORKER_ID"),
    upgrade_trust_policy: [
      allow_unsigned: false,
      trusted_signers: %{}
    ]
end
