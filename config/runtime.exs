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
    raise """
    OUROBOROS_CLUSTER_STRATEGY=#{cluster_strategy} forms a cluster, but this release is \
    not running TLS distribution (-proto_dist is #{if dist_tls?, do: "tls", else: "cleartext"}).

    Configure distribution TLS (see "Running a cluster" in the README: OUROBOROS_DIST_TLS=1 \
    and OUROBOROS_DIST_TLS_OPTFILE at release build time), or set \
    OUROBOROS_ALLOW_INSECURE_DIST=1 to accept a cleartext cluster on a trusted network.
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

  # A release told nothing at all is a single-machine daemon, and a single-machine daemon
  # with no operator surface is a process nobody can talk to: `bin/ouroboros start` would
  # boot, serve nobody, and offer nothing to attach to. This branch is the whole of that
  # convenience and it is deliberately narrow — it runs only when no gateway, no node name
  # and no cluster strategy were named, which is exactly the posture `rel/env.sh.eex`
  # starts without distribution, without epmd, and without a cookie on the host.
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
    # the listener prints on a defaulted boot goes there. Routing the default handler to
    # stderr keeps that stream a log stream and this one clean.
    config :logger, :default_handler, config: [type: :standard_error]
  end
end

# Everything above runs only in production. Everything below runs in every environment,
# because the gateway is how a laptop attaches to a runtime it started with
# `mix run --no-halt`, and a section that only existed in a release would make the
# development loop a different protocol than the shipped one.
#
# This stands on `System` alone. A config provider runs before this application's modules
# are guaranteed loadable, so a check that must be able to refuse the boot cannot call
# `Ouroboros.Gateway.Config` — which re-validates all of this at init, on purpose, for the
# operator who configures application environment directly. The production block makes one
# exception, `Ouroboros.DataDir`, and that module depends on nothing but `Path` and
# `String` precisely so it can be the exception.
gateway_value = fn name ->
  case System.get_env(name) do
    nil -> nil
    value -> if String.trim(value) == "", do: nil, else: String.trim(value)
  end
end

# In production the block above has already persisted the data directory, including the
# default it derives when the variable is unset. This is the same write for every other
# environment, where the variable is the only source there is.
gateway_data_dir = gateway_value.("OUROBOROS_DATA_DIR")

if gateway_data_dir do
  config :ouroboros, :data_dir, gateway_data_dir
end

# A scratch-workspace turn is a first-class path, not a provider escape hatch. Codex's
# non-interactive CLI refuses a directory with no Git metadata unless the host states
# that it already admitted the workspace, and dependency-based work needs network access
# inside the still-bounded workspace-write sandbox. Network is on for the local coding
# product and can be narrowed explicitly at boot; malformed policy never degrades to a
# guess.
codex_network_access =
  case gateway_value.("OUROBOROS_CODEX_NETWORK_ACCESS") do
    nil -> true
    value when value in ["1", "true"] -> true
    value when value in ["0", "false"] -> false
    other -> raise "OUROBOROS_CODEX_NETWORK_ACCESS must be 1, 0, true, or false, got: #{other}"
  end

config :ouroboros, :provider_execution_defaults, %{
  codex: %{
    skip_git_repo_check: true,
    network_access_enabled: codex_network_access
  }
}

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
    queue_limit: gateway_queue_limit

  # A client that spawns this node as a child process owns its stdout. Routing the
  # default handler to stderr keeps that stream a log stream and this one clean, rather
  # than interleaving `Logger` output with anything the daemon is asked to print.
  config :logger, :default_handler, config: [type: :standard_error]
end
