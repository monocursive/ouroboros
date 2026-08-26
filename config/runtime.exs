import Config

if config_env() == :prod do
  # `Ouroboros.DataDir` is the one module of this application this file calls, and it is
  # written to be callable here: no application environment, no other module, no process.
  # The derivation it holds is the cross-language contract with `tui/src/runtime.rs`
  # (`Paths::discover`) — the client spawns this daemon and then reads `gateway.json` out
  # of the directory it derived itself, so the two must agree on that path byte for byte
  # or the client starts a daemon it can never find.
  data_dir =
    Ouroboros.DataDir.resolve!(
      System.get_env("OUROBOROS_DATA_DIR"),
      System.get_env("XDG_DATA_HOME"),
      System.get_env("HOME")
    )

  Ouroboros.DataDir.ensure_private!(data_dir)

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

  # Everything below re-parses cluster environment variables that `Ouroboros.Cluster`
  # also understands, rather than calling it. A config provider runs before this
  # application's modules are guaranteed loadable, so a check that must be able to refuse
  # the boot stands on `System` and `:init` alone. `Ouroboros.DataDir` above is the single
  # exception, and it earns it by depending on nothing: `Ouroboros.Cluster` reaches the
  # supervision tree, libcluster, and application environment.
  env_value = fn name ->
    case System.get_env(name) do
      nil -> nil
      value -> if String.trim(value) == "", do: nil, else: String.trim(value)
    end
  end

  # Fleet profiles keep the real distribution cookie in a private file rather than in
  # the release command line or environment. The release launcher uses a fresh decoy for
  # `RELEASE_COOKIE`; replace it here before libcluster starts, after verifying the file
  # is exactly the private, non-symlink credential the profile installer promised. No
  # error or configured value below includes the credential itself.
  cookie_file = env_value.("OUROBOROS_COOKIE_FILE")

  case cookie_file do
    nil ->
      :ok

    cookie_file ->
      unless Path.type(cookie_file) == :absolute do
        raise "OUROBOROS_COOKIE_FILE must be an absolute path"
      end

      cookie_stat =
        case File.lstat(cookie_file, time: :posix) do
          {:ok, %File.Stat{type: :regular} = stat} ->
            stat

          {:ok, %File.Stat{type: type}} ->
            raise "OUROBOROS_COOKIE_FILE must be a regular, non-symlink file, got: #{type}"

          {:error, reason} ->
            raise "OUROBOROS_COOKIE_FILE cannot be inspected: #{:file.format_error(reason)}"
        end

      unless Bitwise.band(cookie_stat.mode, 0o777) == 0o600 do
        raise "OUROBOROS_COOKIE_FILE must have mode 0600"
      end

      data_stat = File.stat!(data_dir, time: :posix)

      unless cookie_stat.uid == data_stat.uid do
        raise "OUROBOROS_COOKIE_FILE must be owned by the same user as OUROBOROS_DATA_DIR"
      end

      cookie = File.read!(cookie_file)

      unless byte_size(cookie) == 64 and String.match?(cookie, ~r/^[a-f0-9]{64}$/) do
        raise "OUROBOROS_COOKIE_FILE must contain exactly 64 lowercase hexadecimal characters"
      end

      unless Node.alive?() do
        raise "OUROBOROS_COOKIE_FILE was set, but this runtime was started without BEAM distribution"
      end

      true = Node.set_cookie(String.to_atom(cookie))
  end

  node_role =
    case env_value.("OUROBOROS_NODE_ROLE") do
      nil -> :core
      "core" -> :core
      "builder" -> :builder
      "signer" -> :signer
      other -> raise "OUROBOROS_NODE_ROLE must be core, builder, or signer, got: #{other}"
    end

  cluster_strategy = env_value.("OUROBOROS_CLUSTER_STRATEGY") || "none"

  unless cluster_strategy in ["none", "epmd", "gossip", "dns"] do
    raise "OUROBOROS_CLUSTER_STRATEGY must be one of none, epmd, gossip, dns, got: " <>
            cluster_strategy
  end

  # `-proto_dist` reaches the emulator through vm.args, ELIXIR_ERL_OPTIONS, or the
  # command line; all three land in `:init`, so this reads the transport the VM is
  # actually running rather than the one someone intended to configure.
  dist_tls? =
    case :init.get_argument(:proto_dist) do
      {:ok, [[proto] | _rest]} -> List.to_string(proto) in ["inet_tls", "inet6_tls"]
      _absent -> false
    end

  # Forming a cluster over cleartext distribution puts the shared cookie — and every
  # message after it — on the wire. Any node that completes the handshake gets full
  # `:erpc` authority over this one, so this refuses the boot instead of warning, and
  # the override has to be typed out on the host that wants it.
  if cluster_strategy != "none" and not dist_tls? and
       env_value.("OUROBOROS_ALLOW_INSECURE_DIST") != "1" do
    tls_guidance =
      if cookie_file do
        "This boot uses an ouro fleet profile, but its generated TLS VM arguments were not applied. " <>
          "Run `ouro fleet doctor`, then start the packaged `ouro` again; do not enable the insecure override."
      else
        "For an advanced operator-managed release, configure distribution TLS as described in " <>
          "Running a cluster in the README, or set OUROBOROS_ALLOW_INSECURE_DIST=1 only to " <>
          "accept cleartext distribution on a trusted network."
      end

    raise """
    OUROBOROS_CLUSTER_STRATEGY=#{cluster_strategy} forms a cluster, but this release is \
    not running TLS distribution (-proto_dist is #{if dist_tls?, do: "tls", else: "cleartext"}).

    #{tls_guidance}
    """
  end

  forge_builder_node =
    case env_value.("OUROBOROS_FORGE_BUILDER_NODE") do
      nil -> nil
      name -> String.to_atom(name)
    end

  # A `:signer` node's whole reason to exist is holding a key this application cannot
  # reach. Checking that here, before any module of this application is guaranteed
  # loadable, means the misconfiguration an operator is most likely to make — deploying
  # the signer role without mounting the key — stops the boot with a message naming the
  # variable rather than with a supervisor start failure. The service re-reads and
  # re-validates the file at init; this is the preflight, not the load.
  signer_key_path = env_value.("OUROBOROS_SIGNER_KEY_PATH")
  signer_id = env_value.("OUROBOROS_SIGNER_ID")

  if node_role == :signer do
    unless is_binary(signer_key_path) and Path.type(signer_key_path) == :absolute do
      raise "OUROBOROS_SIGNER_KEY_PATH must be an absolute path to this signer's Ed25519 " <>
              "seed file on a node booted with OUROBOROS_NODE_ROLE=signer"
    end

    unless File.regular?(signer_key_path) do
      raise "OUROBOROS_SIGNER_KEY_PATH=#{signer_key_path} is not a readable file"
    end

    unless is_binary(signer_id) do
      raise "OUROBOROS_SIGNER_ID must name the identity this signer signs as; it is the " <>
              "id core nodes trust a public key under in OUROBOROS_UPGRADE_TRUSTED_SIGNERS"
    end
  end

  signing_call_timeout =
    case Integer.parse(System.get_env("OUROBOROS_SIGNING_CALL_TIMEOUT_MS") || "15000") do
      {value, ""} when value > 0 -> value
      _other -> raise "OUROBOROS_SIGNING_CALL_TIMEOUT_MS must be a positive integer"
    end

  signing_rate_limit =
    case Integer.parse(System.get_env("OUROBOROS_SIGNING_RATE_LIMIT_PER_MINUTE") || "30") do
      {value, ""} when value > 0 -> value
      _other -> raise "OUROBOROS_SIGNING_RATE_LIMIT_PER_MINUTE must be a positive integer"
    end

  # Requiring a signed evaluation spec is the recommended production posture: it makes
  # "this capability declared, inside the signature, how it would be judged" a
  # precondition of getting a signature at all. It defaults to off so that naming a
  # signer node never silently changes what an existing artifact means.
  signing_require_eval = System.get_env("OUROBOROS_SIGNING_REQUIRE_EVAL") == "true"

  signing_node =
    case env_value.("OUROBOROS_SIGNING_NODE") do
      nil -> nil
      name -> String.to_atom(name)
    end

  # Naming a signer node is the operator action that gives this cluster a signing
  # capability. Without it the forge keeps the shipped refusal, so a production release
  # still acquires signing deliberately rather than by default.
  forge_signer =
    if is_nil(signing_node) do
      Ouroboros.Upgrade.Forge.Signer.Deny
    else
      {Ouroboros.Upgrade.Forge.Signer.Remote, [node: signing_node, timeout: signing_call_timeout]}
    end

  workspace_roots =
    case System.get_env("OUROBOROS_WORKSPACE_ROOTS") do
      nil -> []
      roots -> String.split(roots, ":", trim: true)
    end

  # D7. A worktree is leased through the same admission machinery as any other directory,
  # so the directory this runtime creates worktrees in has to be an allowed root or every
  # `worktree: true` session would fail at the lease. Only the runtime writes there, and
  # only where the operator already granted at least one root — an empty grant stays
  # empty, and the workspace manager does not even start.
  workspace_roots =
    if workspace_roots == [],
      do: [],
      else: workspace_roots ++ [Path.join(data_dir, "worktrees")]

  _ = File.mkdir_p(Path.join(data_dir, "worktrees"))

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
      is_nil(forge_workspace) ->
        []

      true ->
        options =
          if forge_nodes == [] do
            [workspace: forge_workspace]
          else
            [workspace: forge_workspace, nodes: forge_nodes]
          end

        case env_value.("OUROBOROS_FORGE_SIGNER_ID") do
          nil -> options
          signer_id -> Keyword.put(options, :signer_id, signer_id)
        end
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
    node_role: node_role,
    forge_builder_node: forge_builder_node,
    coding_storage: {Jido.Storage.File, path: Path.join(data_dir, "coding")},
    interactive_storage: {Jido.Storage.File, path: Path.join(data_dir, "interactive")},
    team_storage: {Jido.Storage.File, path: Path.join(data_dir, "teams")},
    orchestration_storage: {Jido.Storage.File, path: Path.join(data_dir, "orchestration")},
    control_storage: {Jido.Storage.File, path: Path.join(data_dir, "control")},
    # The effect authority decides what agents may do to the cluster, so it is held to
    # the same synced write the mutation journals use: a grant that was acknowledged
    # must survive the crash that follows it, and a revocation must too.
    grants_storage: {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "grants")},
    # Permission rules decide what a provider may do before a human is asked, so an
    # acknowledged rule has to survive the crash that follows it — the same synced write
    # the grant authority uses. This path is also why workspace rules live here rather
    # than in the repository: a clone must not be able to grant itself permissions.
    permissions_storage:
      {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "permissions")},
    # An admitted effect is not started until this synced checkpoint records it. Outcomes
    # and refusals use the same boundary, so a runtime restart can distinguish an
    # unfinished acknowledged attempt from one that was never requested.
    effect_ledger_storage:
      {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "effect-ledger")},
    upgrade_storage: {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "upgrades")},
    release_storage:
      {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "release-journal")},
    capability_storage:
      {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "capabilities")},
    # The epoch watermark must survive a crash between allocating a number and using it,
    # or the same epoch could be handed out twice.
    epoch_storage: {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "forge-epochs")},
    # A signature is never returned to a requester before its journal entry is
    # acknowledged, so the durability of this adapter is the durability of the record of
    # what this key has ever approved.
    signing_journal_storage:
      {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "signing-journal")},
    forge_signer: forge_signer,
    signing_node: signing_node,
    signing_call_timeout: signing_call_timeout,
    signer_id: signer_id,
    signing_require_eval: signing_require_eval,
    signing_rate_limit_per_minute: signing_rate_limit,
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

  # The data directory has to outlive this file: the gateway publishes its bound port to
  # `gateway.json` there at runtime, and that file is the only way a client finds this
  # node. The section below writes it again from the environment variable, which is the
  # only source it has in the environments this block never runs in.
  config :ouroboros, :data_dir, data_dir

  # An embedded release told nothing at all is configured as a single-machine daemon so
  # the native `ouro` launcher can give it an operator surface. This branch is deliberately
  # narrow — it runs only when no gateway, node name, or cluster strategy was named. A
  # bare `bin/ouroboros start` still fails before durable children because it cannot supply
  # the trusted native process-incarnation/recovery helper; this is configuration fallback,
  # not a supported raw-release lifecycle entrypoint.
  #
  # Nothing here reads an `OUROBOROS_GATEWAY_*` variable. Setting `OUROBOROS_GATEWAY` at
  # all makes this branch unreachable, and that other path is where every one of those
  # variables is read: a host that wants to tune the surface, or to bind it anywhere but
  # loopback, sets `OUROBOROS_GATEWAY=1` and is held to the token requirement that comes
  # with it.
  if is_nil(env_value.("OUROBOROS_GATEWAY")) and is_nil(env_value.("OUROBOROS_NODE")) and
       cluster_strategy == "none" do
    config :ouroboros, :gateway,
      enabled: true,
      port: 0,
      bind: "127.0.0.1",
      allow_remote: false,
      scope: :operate,
      allow_shutdown: true,
      token_file: Path.join(data_dir, "gateway.token"),
      # The only posture allowed to create its own credential, and the only one that can
      # be: an operator who sets `OUROBOROS_GATEWAY=1` names a token source and still gets
      # the refusal when the file is missing, because a missing file there is a mistake.
      # Nobody named one here, so there is nothing to have gotten wrong and no reason to
      # make a first boot a two-step ceremony.
      token_generate: true

    # A client that spawns this node as a child process owns its stdout, and the notice
    # the listener prints on a defaulted boot goes there. stderr is the foreground
    # default; the managed-file block below replaces it for a detached/service spawn.
    config :logger, :default_handler, config: [type: :standard_error]
  end
end

# Everything above runs only in production. Everything below runs in every environment,
# because the gateway is how a laptop attaches to a runtime it started with
# `mix run --no-halt`, and a section that only existed in a release would make the
# development loop a different protocol than the shipped one.
#
# Apart from `Ouroboros.DataDir`, this stands on `System` alone. A config provider runs
# before this application's modules are guaranteed loadable, so a check that must be able
# to refuse the boot cannot call `Ouroboros.Gateway.Config` — which re-validates all of
# this at init, on purpose, for the operator who configures application environment
# directly. `Ouroboros.DataDir` depends only on config-provider-safe standard modules and
# trusted absolute operating-system helpers, so both durable stores and gateway discovery
# can share one path and permission contract this early.
gateway_value = fn name ->
  case System.get_env(name) do
    nil -> nil
    value -> if String.trim(value) == "", do: nil, else: String.trim(value)
  end
end

# In production the block above has already persisted the data directory, including the
# default it derives when the variable is unset. This is the same write for every other
# environment, where the variable is the only source there is.
gateway_data_dir =
  Ouroboros.DataDir.configured!(System.get_env("OUROBOROS_DATA_DIR"))

if gateway_data_dir do
  Ouroboros.DataDir.ensure_private!(gateway_data_dir)
  config :ouroboros, :data_dir, gateway_data_dir
end

# Language servers are a liability as much as an asset — OpenCode turned theirs off by
# default over memory and staleness, and Anthropic tells users to disable plugins under
# pressure (R4 §1). So the two switches an operator reaches for under pressure are
# environment variables, readable in every environment: turn the pool off entirely, and
# lower the per-host memory budget. Everything else stays in `config/config.exs`, where a
# deployment can set it deliberately. A malformed value refuses the boot rather than
# quietly removing the bound it was meant to set.
code_intel_enabled =
  case gateway_value.("OUROBOROS_CODE_INTEL") do
    nil -> true
    value when value in ["1", "true"] -> true
    value when value in ["0", "false"] -> false
    other -> raise "OUROBOROS_CODE_INTEL must be 1, 0, true, or false, got: #{other}"
  end

code_intel_memory_budget =
  case gateway_value.("OUROBOROS_CODE_INTEL_MEMORY_BUDGET_MB") do
    nil ->
      nil

    value ->
      case Integer.parse(value) do
        {megabytes, ""} when megabytes > 0 -> megabytes * 1024 * 1024
        _other -> raise "OUROBOROS_CODE_INTEL_MEMORY_BUDGET_MB must be a positive integer"
      end
  end

config :ouroboros, :code_intel, enabled: code_intel_enabled

if code_intel_memory_budget do
  config :ouroboros, :code_intel, memory_budget_bytes: code_intel_memory_budget
end

# Computer Use is host-privileged. Env 1/0 is the explicit switch; when unset the
# helper-on-disk predicate in `Desktop.enabled?/0` is the opt-in. Do not force
# `enabled: false` here — that made a GUI adopt a daemon that could never show the tools.
case gateway_value.("OUROBOROS_COMPUTER_USE") do
  nil ->
    :ok

  value when value in ["1", "true"] ->
    config :ouroboros, :computer_use, enabled: true

  value when value in ["0", "false"] ->
    config :ouroboros, :computer_use, enabled: false

  other ->
    raise "OUROBOROS_COMPUTER_USE must be 1, 0, true, or false, got: #{other}"
end

if System.get_env("OUROBOROS_GATEWAY") == "1" do
  gateway_port =
    case Integer.parse(gateway_value.("OUROBOROS_GATEWAY_PORT") || "0") do
      {value, ""} when value >= 0 and value <= 65_535 ->
        value

      _other ->
        raise "OUROBOROS_GATEWAY_PORT must be an integer between 0 and 65535; 0 binds an " <>
                "ephemeral port and publishes it in gateway.json"
    end

  gateway_bind = gateway_value.("OUROBOROS_GATEWAY_BIND") || "127.0.0.1"

  gateway_bind_address =
    case :inet.parse_address(String.to_charlist(gateway_bind)) do
      {:ok, address} ->
        address

      {:error, _reason} ->
        raise "OUROBOROS_GATEWAY_BIND must be a literal IPv4 or IPv6 address, got: " <>
                gateway_bind
    end

  gateway_loopback? =
    case gateway_bind_address do
      {127, _, _, _} -> true
      {0, 0, 0, 0, 0, 0, 0, 1} -> true
      _other -> false
    end

  gateway_allow_remote = System.get_env("OUROBOROS_GATEWAY_ALLOW_REMOTE") == "1"

  # The gateway protocol is cleartext and carries the token in its first frame. Leaving
  # loopback therefore puts an operator credential on the network, so this refuses the
  # boot instead of warning, and the override has to be typed out on the host that wants
  # it — the same posture OUROBOROS_ALLOW_INSECURE_DIST takes toward distribution.
  if not gateway_loopback? and not gateway_allow_remote do
    raise """
    OUROBOROS_GATEWAY_BIND=#{gateway_bind} puts the gateway on a network interface, and \
    the gateway protocol is cleartext: the token and every status payload after it cross \
    the wire in the clear.

    Attach over an SSH tunnel instead (ssh -L 4560:127.0.0.1:4560 host), or set \
    OUROBOROS_GATEWAY_ALLOW_REMOTE=1 to accept a cleartext operator surface on a trusted \
    network.
    """
  end

  gateway_token_file = gateway_value.("OUROBOROS_GATEWAY_TOKEN_FILE")
  gateway_token = gateway_value.("OUROBOROS_GATEWAY_TOKEN")

  # No token, no listener. The token file is preferred and is what the spawner writes:
  # the value of OUROBOROS_GATEWAY_TOKEN stays in application environment for the life of
  # the node and is readable by every process this user runs, while a path is just a path.
  if is_nil(gateway_token_file) and is_nil(gateway_token) do
    raise "OUROBOROS_GATEWAY=1 enables an operator surface, so it requires a token. Set " <>
            "OUROBOROS_GATEWAY_TOKEN_FILE to a 0600 file holding at least 32 bytes, or " <>
            "OUROBOROS_GATEWAY_TOKEN for a development loop."
  end

  if is_nil(gateway_data_dir) do
    raise "OUROBOROS_GATEWAY=1 requires OUROBOROS_DATA_DIR: the bound port, protocol " <>
            "version, and scope are published to gateway.json there, and that file is " <>
            "how a client finds this node."
  end

  gateway_scope =
    case gateway_value.("OUROBOROS_GATEWAY_SCOPE") || "read" do
      "read" -> :read
      "operate" -> :operate
      other -> raise "OUROBOROS_GATEWAY_SCOPE must be read or operate, got: " <> other
    end

  gateway_max_frame =
    case Integer.parse(gateway_value.("OUROBOROS_GATEWAY_MAX_FRAME") || "1048576") do
      {value, ""} when value >= 1_024 ->
        value

      _other ->
        raise "OUROBOROS_GATEWAY_MAX_FRAME must be an integer of at least 1024 bytes"
    end

  gateway_queue_limit =
    case Integer.parse(gateway_value.("OUROBOROS_GATEWAY_QUEUE_LIMIT") || "1000") do
      {value, ""} when value > 0 -> value
      _other -> raise "OUROBOROS_GATEWAY_QUEUE_LIMIT must be a positive integer"
    end

  # The queue limit counts frames; these three bound how large one of them gets. A
  # multi-megabyte diff inside an event payload is excerpted to `event_leaf_bytes` with a
  # marker naming its true size, one event's payload strings to `event_payload_bytes`
  # between them, and `interactive.event_detail` re-fetches the same event under the
  # larger `detail_leaf_bytes`. 1024 is the floor on all three, the same floor
  # `Ouroboros.Gateway.Config` enforces: below it an excerpt names nothing.
  gateway_bytes = fn name, default ->
    case Integer.parse(gateway_value.(name) || default) do
      {value, ""} when value >= 1_024 -> value
      _other -> raise "#{name} must be an integer of at least 1024 bytes"
    end
  end

  config :ouroboros, :gateway,
    enabled: true,
    port: gateway_port,
    bind: gateway_bind,
    allow_remote: gateway_allow_remote,
    token_file: gateway_token_file,
    token: gateway_token,
    scope: gateway_scope,
    allow_shutdown: System.get_env("OUROBOROS_GATEWAY_ALLOW_SHUTDOWN") == "1",
    max_frame: gateway_max_frame,
    queue_limit: gateway_queue_limit,
    event_leaf_bytes: gateway_bytes.("OUROBOROS_GATEWAY_EVENT_LEAF_BYTES", "131072"),
    event_payload_bytes: gateway_bytes.("OUROBOROS_GATEWAY_EVENT_PAYLOAD_BYTES", "524288"),
    detail_leaf_bytes: gateway_bytes.("OUROBOROS_GATEWAY_DETAIL_LEAF_BYTES", "4194304")

  # A client that spawns this node as a child process owns its stdout. stderr is the
  # foreground default; the managed-file block below replaces it for a detached/service
  # spawn so neither posture interleaves Logger output with daemon notices.
  config :logger, :default_handler, config: [type: :standard_error]
end

# A packaged detached daemon has two deliberately separate sinks. Its inherited
# stdout/stderr stays on `daemon.log`, where VM bootstrap and crash diagnostics remain
# visible even before Elixir Logger starts. The launcher sets this internal path only
# after securely creating and validating it; from that point onward `:logger_std_h` is
# the sole writer and sole rotator of `runtime.log`.
runtime_log_file = gateway_value.("OUROBOROS_RUNTIME_LOG_FILE")

if runtime_log_file do
  unless gateway_data_dir do
    raise "OUROBOROS_RUNTIME_LOG_FILE requires OUROBOROS_DATA_DIR"
  end

  expected_runtime_log = Path.join(gateway_data_dir, "runtime.log")

  unless Path.type(runtime_log_file) == :absolute and runtime_log_file == expected_runtime_log do
    raise "OUROBOROS_RUNTIME_LOG_FILE must be exactly #{expected_runtime_log}"
  end

  runtime_log_max_bytes =
    case Integer.parse(gateway_value.("OUROBOROS_RUNTIME_LOG_MAX_BYTES") || "2097152") do
      {value, ""} when value > 0 -> value
      _other -> raise "OUROBOROS_RUNTIME_LOG_MAX_BYTES must be a positive integer"
    end

  runtime_log_max_files =
    case Integer.parse(gateway_value.("OUROBOROS_RUNTIME_LOG_MAX_FILES") || "3") do
      {value, ""} when value > 0 -> value
      _other -> raise "OUROBOROS_RUNTIME_LOG_MAX_FILES must be a positive integer"
    end

  data_stat = File.stat!(gateway_data_dir, time: :posix)

  inspect_private_log = fn path ->
    case File.lstat(path, time: :posix) do
      {:ok, %File.Stat{type: :regular} = stat} ->
        unless stat.uid == data_stat.uid and Bitwise.band(stat.mode, 0o777) == 0o600 do
          raise "#{path} must be a mode-0600 regular runtime log owned by OUROBOROS_DATA_DIR's user"
        end

        :present

      {:ok, %File.Stat{type: type}} ->
        raise "#{path} must be a regular, non-symlink runtime log, got: #{type}"

      {:error, :enoent} ->
        :absent

      {:error, reason} ->
        raise "#{path} cannot be inspected: #{:file.format_error(reason)}"
    end
  end

  unless inspect_private_log.(runtime_log_file) == :present do
    raise "OUROBOROS_RUNTIME_LOG_FILE must already exist as a private file created by the packaged launcher"
  end

  # Validate every archive the handler may rename, plus the contiguous overflow it
  # removes at startup. A symlink or foreign/broad file is refused before Logger can
  # mutate any name in the retained set.
  Enum.each(0..(runtime_log_max_files - 1), fn index ->
    inspect_private_log.(runtime_log_file <> ".#{index}")

    compressed = runtime_log_file <> ".#{index}.gz"

    if inspect_private_log.(compressed) == :present do
      raise "unexpected compressed runtime log archive #{compressed}; managed rotation is uncompressed and will not rewrite it"
    end
  end)

  inspect_overflow = fn inspect_overflow, index ->
    plain = inspect_private_log.(runtime_log_file <> ".#{index}")
    compressed = inspect_private_log.(runtime_log_file <> ".#{index}.gz")

    case {plain, compressed} do
      {:absent, :absent} -> :ok
      _present -> inspect_overflow.(inspect_overflow, index + 1)
    end
  end

  inspect_overflow.(inspect_overflow, runtime_log_max_files)

  config :logger, :default_handler,
    config: [
      type: :file,
      file: String.to_charlist(runtime_log_file),
      file_check: 0,
      filesync_repeat_interval: 5_000,
      max_no_bytes: runtime_log_max_bytes,
      max_no_files: runtime_log_max_files,
      compress_on_rotate: false
    ]
end
