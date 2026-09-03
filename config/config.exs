import Config

# LiveView logs event parameters at debug level. Credential forms therefore use names
# containing `api_key`, and Phoenix must redact those values before any logger sees them.
config :phoenix, :filter_parameters, ["password", "token", "secret", "api_key"]

# Native streams are admitted globally by `Provider.Native.Model.Admission`, eight at a
# time. Keep Finch as one pool with more connections than admitted streams: this removes
# random one-connection shard collisions and leaves two cleanup/headroom connections for a
# cancelled stream whose transport is still unwinding. HTTP/1 remains deliberate because
# ReqLLM supports providers whose HTTP/2 behavior is not uniform and large mixed-protocol
# request bodies hit Finch's ALPN flow-control limitation.
config :req_llm,
  stream_pool_protocols: [:http1],
  stream_pool_size: 10,
  stream_pool_count: 1

# Erlexec's port manager refuses to start without SHELL even when every command is an
# argv list. Service managers and coding harnesses legitimately omit it, so establish the
# Unix release's portable shell before dependency applications start.
if System.get_env("SHELL") in [nil, ""], do: System.put_env("SHELL", "/bin/sh")

# Development and test builds can exercise the local upgrade lane without managing a
# signing key. Production always requires an explicitly trusted signature.
config :ouroboros,
  upgrade_trust_policy: [allow_unsigned: config_env() != :prod],
  # Which supervision tree this node boots. `:core` runs the full runtime; `:builder`
  # and `:signer` run cluster formation and nothing else, so a host that only compiles
  # candidate code or only holds a signing seam has no teams, sessions, schedulers, or
  # control plane on it to lose. An unrecognized value refuses the boot rather than
  # falling back to the privileged tree. See `Ouroboros.Cluster`.
  node_role: :core,
  # Refuse to place agents and team workers on a node that is not a connected `:core`
  # node running this runtime. This is misconfiguration detection — work sent where it
  # cannot run — and explicitly not a boundary against a hostile connected node, which
  # has full `:erpc` authority regardless.
  placement_role_check: true,
  # Where forge builds run. `nil` builds on this node. A named node must be connected,
  # running this runtime, and in the `:builder` role; it must also run an identical
  # ERTS/Elixir/architecture, because the verifier checks the artifact's runtime triple
  # on every loading node.
  forge_builder_node: nil,
  # Relaxes only the builder's *role* requirement, for tests that have a real peer but
  # not a role-shaped fleet. Connectivity and a running runtime are still required.
  forge_builder_allow_any_role: false,
  # Lane W's half of the same question, and unlike the two above it is a check rather than
  # advice (docs/WASM.md D29, contract C14). `:local` — the default — forges where the effect
  # lands, exactly as lane W always did; `:builder` forwards a forge that landed on a
  # non-builder node to a connected `:builder` and refuses by name when there is none, rather
  # than quietly building here. A `:signer` node refuses to forge under **either** setting and
  # is not configurable: a Cargo build is arbitrary code at build time, and it does not run on
  # the machine holding the key. Anything but these two words is refused, not read as the
  # default — a typo asked for a forge not to run here.
  wasm_forge_placement: :local,
  coding_storage: {Jido.Storage.ETS, table: :ouroboros_coding},
  interactive_storage: {Jido.Storage.ETS, table: :ouroboros_interactive},
  team_storage: {Jido.Storage.ETS, table: :ouroboros_teams},
  orchestration_storage: {Jido.Storage.ETS, table: :ouroboros_orchestration},
  control_storage: {Jido.Storage.ETS, table: :ouroboros_control},
  grants_storage: {Jido.Storage.ETS, table: :ouroboros_grants},
  permissions_storage: {Jido.Storage.ETS, table: :ouroboros_permissions},
  # Operator-authored permission rules, the highest scope `Ouroboros.Control.Permissions`
  # consults. Each entry is `{pattern, decision}` or `{pattern, decision, workspace}`;
  # `decision` is `:allow`, `:deny`, or `:ask`. Empty means every tool call this runtime
  # can intercept reaches a human, which is the safe thing for a default to mean.
  #
  #     permissions: [
  #       {"Bash(git status *)", :allow},
  #       {"Bash(rm *)", :deny},
  #       {"WebFetch(domain:github.com)", :allow}
  #     ]
  permissions: [],
  # Stored rules retained per node across the user, workspace, and session scopes. The
  # bound refuses a new rule rather than evicting an old one: evicting a `deny` to make
  # room for an `allow` would be a storage limit that widens authority.
  permissions_limit: 500,
  # Where permission decisions are recorded. The effect ledger is the answer; the key
  # exists so a test can point one engine at a ledger it is allowed to take away.
  permissions_ledger: Ouroboros.Agent.EffectLedger,
  effect_ledger_storage: {Jido.Storage.ETS, table: :ouroboros_effect_ledger},
  # Terminal entries retained per node. In-flight entries are never evicted, and every
  # read has its own smaller bound in `Ouroboros.Agent.EffectLedger`.
  effect_ledger_limit: 1_000,
  upgrade_storage: {Jido.Storage.ETS, table: :ouroboros_upgrades},
  release_storage: {Jido.Storage.ETS, table: :ouroboros_releases},
  capability_storage: {Jido.Storage.ETS, table: :ouroboros_capabilities},
  epoch_storage: {Jido.Storage.ETS, table: :ouroboros_forge_epochs},
  # The forge asks this module to sign what it builds. Refusing by default means a
  # cluster acquires a signing capability only when an operator configures one, and
  # never because a default was convenient. Key custody belongs outside this
  # application; see `Ouroboros.Upgrade.Forge.Signer`.
  forge_signer: Ouroboros.Upgrade.Forge.Signer.Deny,
  # The `:signer` node `Forge.Signer.Remote` submits artifacts to, and how long it waits.
  # `nil` means no remote signer is configured, which is what an unconfigured cluster
  # should mean: the client refuses rather than guessing at a host.
  signing_node: nil,
  signing_call_timeout: 15_000,
  # Everything below is read on the signer node itself, by
  # `Ouroboros.Upgrade.Signing.Service`. The identity this node signs as — the id whose
  # public key core nodes name in OUROBOROS_UPGRADE_TRUSTED_SIGNERS. It cannot be
  # defaulted, and a `:signer` node refuses to boot without it; the key itself is never
  # configuration, it is read at boot from OUROBOROS_SIGNER_KEY_PATH.
  signer_id: nil,
  # The independent gate applied to a full artifact before any signature exists. See
  # `Ouroboros.Upgrade.Signing.Policy`.
  signing_policy: Ouroboros.Upgrade.Signing.Policy.Default,
  # Whether an artifact must carry a valid evaluation spec in `metadata.forge.eval` to be
  # signed at all. False keeps the behaviour that existed before the signing service;
  # production should set it true, because it is the one switch that makes "this
  # capability declared how it would be judged" a precondition of a signature.
  signing_require_eval: false,
  # Admissions per requester per minute, refused beyond. This bounds accidents and retry
  # storms; the requester is self-reported, so it is not a bound on an adversary.
  signing_rate_limit_per_minute: 30,
  # How many signing decisions — issued and refused alike — are retained.
  signing_journal_limit: 500,
  # The largest artifact a signer will accept over `:erpc` before reading any of it.
  signing_max_artifact_bytes: 16 * 1024 * 1024,
  # Where signing decisions are recorded. ETS in dev and test, a synced
  # `Ouroboros.Storage.DurableFile` in production: a signature is never returned unless
  # its journal entry was acknowledged first, so this adapter's durability is the
  # durability of the audit trail.
  signing_journal_storage: {Jido.Storage.ETS, table: :ouroboros_signing_journal},
  # Overall deadline for one isolated build peer: boot, compile, and capability tests.
  forge_build_timeout: 60_000,
  # Deadline for one node's evaluation run during a capability rollout. It bounds an
  # `:erpc` into `Ouroboros.Upgrade.Rollout.Evaluation`, which enforces the artifact's
  # own `budget_ms` internally; this is the outer limit on a node that stops answering,
  # and exceeding it is ambiguity, so it must be comfortably above any spec's budget.
  capability_eval_timeout: 30_000,
  # How much slower than the version it replaces a challenger capability may run its
  # probe set and still be promoted under `compare: true`. Wall-clock over a handful of
  # probes on a shared VM is noisy; a budget near 1.0 rejects honest challengers.
  capability_eval_regression_budget: 1.2,
  # Deadline for one agent effect. Effects run off the agent's process, but they still
  # hold a supervised task and an in-flight audit entry, so every one of them ends.
  effect_timeout: 120_000,
  control_enabled: false,
  # A durable plan is heterogeneous: every step declares a kind and the scheduler
  # resolves one executor per kind. `:orchestration_executors` names them
  # explicitly and overrides what the application derives from
  # `:orchestration_team_id` (the `:coding` executor) and
  # `:orchestration_forge_options` (the `:forge` executor). A kind with no
  # executor is a kind the scheduler refuses to accept plans for, so leaving
  # forge options empty keeps forge steps unschedulable.
  orchestration_executors: %{},
  # Trusted runtime policy for `Ouroboros.Orchestration.ForgeExecutor`: which
  # workspace source is read from, which nodes receive the capability, and which
  # signer identity is requested. A forge step supplies only a module name and a
  # workspace-relative path. Empty means no forge executor.
  orchestration_forge_options: [],
  # Whether a planner may express a forge step at all. This widens what a model
  # can *say*, never what it can deploy: the artifact is still signed by
  # `:forge_signer` (`Signer.Deny` by default) and still verified against each
  # target node's trusted signers.
  control_allow_forge_steps: false,
  # Bound for control-plane session calls (info/replay/subscribe/cancel/steer/
  # respond_approval/interrupt). `await` threads the caller's own timeout instead.
  session_call_timeout: 30_000,
  # Direct model calls are bounded at the node boundary. Per-session requests may choose
  # a model and reasoning effort, but they cannot replace transport/auth configuration.
  # `openai_codex` starts on SSE; a stable session id and the Ouroboros originator are
  # injected for each request by `Provider.Native.Model.ReqLLM`.
  native_model_options: [
    receive_timeout: 120_000,
    stream_idle_timeout: 180_000,
    total_timeout: 300_000,
    max_retries: 0,
    provider_options: [openai_stream_transport: :sse, codex_originator: "ouroboros"]
  ],
  # One node-wide boundary for root sessions, children, and grandchildren. Waiters are
  # monitored and bounded rather than falling into Finch's per-connection checkout queue.
  native_model_max_concurrency: 8,
  native_model_queue_limit: 32,
  native_model_queue_timeout_ms: 120_000,
  # The packaged direct default uses ChatGPT subscription OAuth. API-key deployments may
  # set `OUROBOROS_NATIVE_MODEL=openai:<model>` with `OPENAI_API_KEY`, or select
  # `anthropic:<model>` or `xai:<model>` with the vendor API key or the private credential
  # saved from the web new-session page. Identity-linked Anthropic keys additionally use
  # `ANTHROPIC_WORKSPACE_ID`. Direct Anthropic and xAI lanes are API-key-only; managed
  # Grok subscription access stays in the first-party CLI.
  native_model: "openai_codex:gpt-5.6-sol",
  # How long a terminal coding task or interactive session is retained before the
  # recovery sweep deletes it. `nil` disables the sweep and keeps everything.
  terminal_retention_ms: 7 * 24 * 60 * 60 * 1_000,
  # How long a closed provider session may keep a dispatched turn unresolved before
  # the turn is settled as ambiguous so the session can reach its terminal state.
  interactive_unresolved_turn_deadline_ms: 10 * 60 * 1_000,
  account_adapter:
    if(config_env() == :test,
      do: Ouroboros.Test.OpenAIAccountAdapter,
      else: Ouroboros.Provider.OpenAIAuth
    ),
  grok_account_adapter:
    if(config_env() == :test,
      do: Ouroboros.Test.GrokAccountAdapter,
      else: Ouroboros.Provider.GrokAuth
    ),
  # Language servers, owned by this node rather than by any session. Everything here is a
  # bound; `Ouroboros.CodeIntel.Config` documents each one and refuses a value that would
  # remove it. Nothing is installed by this runtime — a server absent from the user's PATH
  # and from the project's own bin directories resolves to an error carrying an install
  # hint, and that is the end of it.
  code_intel: [
    enabled: true,
    # Operator additions and overrides, merged over the built-in registry by language:
    #   [%{language: :elixir, extensions: [".ex"], root_markers: ["mix.exs"],
    #      candidates: [%{server_id: "expert", command: "expert", args: []}]}]
    servers: []
  ],
  # MCP servers the native agent may call (D4). Same posture as `:code_intel` above and
  # for the same reason — somebody else's program on the end of a pipe — so everything
  # here is a bound and `Ouroboros.Provider.Native.Mcp.Config` refuses a value that would
  # remove one. Empty by default: nothing is spawned that an operator did not name.
  mcp: [enabled: true],
  # Node-scope server definitions, in the Claude-compatible shape and highest precedence
  # of the three sources (node, then `~/.config/ouroboros/mcp.json`, then a *trusted*
  # workspace's `.ouroboros/mcp.json`):
  #   %{"github" => %{command: "npx", args: ["-y", "@modelcontextprotocol/server-github"],
  #                   env: %{"GITHUB_TOKEN" => System.get_env("GITHUB_TOKEN")}}}
  mcp_servers: %{},
  # The LiveView operator surface (docs/WEB.md). The opposite default to `:code_intel`
  # and `:mcp`, and deliberately: those two are bounds on things this runtime already
  # does, while this one is a port a stranger can reach, so absent configuration has to
  # mean no endpoint at all rather than a disabled one. `config/runtime.exs` is the only
  # thing that turns it on, and every other value — a bind, a port, a token path — is a
  # decision that belongs to the machine rather than to the build. Their defaults and the
  # refusals that go with them live in `Ouroboros.Web.Config`.
  web: [enabled: false],
  # Computer Use (docs/COMPUTER_USE.md §4). Tools appear when the helper is on disk
  # unless `OUROBOROS_COMPUTER_USE=0`. A helper is the operator opt-in (they built it).
  # Same hardening as `:mcp` / `:code_intel`: a typo never widens a bound.
  computer_use: [
    enabled: true,
    # Phase 2 ships `desktop_act`. Set false for observe-only.
    act_enabled: true,
    # `:bundled` resolves priv/, checkout priv/, or a sibling of `ouro`.
    # `OUROBOROS_COMPUTER_USE_HELPER=/path` overrides it.
    helper_path: :bundled,
    handshake_timeout_ms: 5_000,
    state_timeout_ms: 5_000,
    act_timeout_ms: 10_000,
    shutdown_grace_ms: 2_000,
    max_frame_bytes: 8 * 1024 * 1024,
    max_image_bytes: 2 * 1024 * 1024,
    max_image_width: 1920,
    max_image_height: 1920,
    max_nodes: 1_000,
    max_depth: 32,
    max_snapshots_per_session: 8,
    jpeg_quality: 80,
    # Node deny, not remember-able (D12). The bundle ids Computer Use never drives: this
    # runtime's own surfaces, every terminal it could shell out of, the panes that draw
    # OS auth and secrets. `Native.Desktop.denied_app_ids/0` unions this with a baked
    # floor, so an operator may add to it but a typo can never remove ouro or a terminal.
    denied_app_ids: [
      "dev.ouroboros.desktop",
      "com.ouroboros.desktop",
      "com.apple.Terminal",
      "com.googlecode.iterm2",
      "com.mitchellh.ghostty",
      "net.kovidgoyal.kitty",
      "com.apple.systempreferences",
      "com.apple.loginwindow",
      "dev.warp.Warp-Stable",
      "org.alacritty",
      "com.github.wez.wezterm",
      "co.zeit.hyper",
      "org.tabby",
      "com.1password.1password",
      "com.apple.keychainaccess",
      "com.apple.SecurityAgent"
    ]
  ],
  # WebAssembly containment (docs/WASM.md §7). Same posture as `:computer_use`: the helper
  # on disk is the operator opt-in — `make wasm` builds it, nothing else does — and
  # everything here is a bound, so a typo falls back to the default rather than widening
  # one. `OUROBOROS_WASM_HELPER=/path` overrides `:bundled`, which resolves the application's
  # own priv/ or a sibling of `ouro` — and nothing derived from the working directory, since
  # the helper is the containment boundary and a cloned repository must not be able to supply
  # it. The guest's own bounds — fuel, deadline, memory — are per-request and never defaulted
  # by the pool; `ouro-wasm` refuses a request that omits one, and inventing a value there
  # would be the transport deciding how much of the machine a guest may have.
  # `:capability_limits` is where that decision is made instead: the bounds
  # `Ouroboros.Wasm.Capability` sends when the state a capability was deployed with names
  # none of its own, and `:capability_limits_max` is the ceiling a deployment's own
  # declaration is clamped to — `initial_state` reaches this node over a remote-reachable
  # start surface, so how much a capability may ask for is the node's answer and not the
  # deployment's. Both are declared whole — all three keys or none — because a half-stated
  # bound is not a bound; two of the three keys falls back to all three defaults.
  wasm: [
    helper_path: :bundled,
    handshake_timeout_ms: 5_000,
    request_timeout_ms: 30_000,
    call_margin_ms: 10_000,
    max_frame_bytes: 8 * 1024 * 1024,
    broken_ms: 15_000,
    store_budget_bytes: 512 * 1024 * 1024,
    capability_limits: [
      fuel: 100_000_000,
      memory_bytes: 64 * 1024 * 1024,
      deadline_ms: 5_000
    ],
    capability_limits_max: [
      fuel: 10_000_000_000,
      memory_bytes: 256 * 1024 * 1024,
      deadline_ms: 30_000
    ],
    # A capability's `initial_state` may name the directory its component bytes are read
    # from only where this is true — which is this repository's own test environment, and
    # nowhere else. It is a test seam, and on a remote-reachable start surface a test seam
    # that names a directory is an arbitrary read of unsigned bytes.
    allow_store_root_override: config_env() == :test
  ]

# W15. The permission engine, and the policy component it may consult (docs/WASM.md §8.2,
# D20). Three keys, and the defaults are the posture:
#
#   * `:permissions_engine` is `Ouroboros.Control.Permissions` unless an operator names
#     another. `Ouroboros.Wasm.PolicyEngine` is `Control.Permissions` plus one thing: where
#     the rules said *nothing* — `{:ask, :no_rule}` — it asks a signed policy component and
#     lets it narrow the answer. Every other outcome passes through untouched.
#   * `:wasm_policy` names the component, by the name it was deployed under. `nil` — the
#     default — makes the engine inert: it delegates and consults nobody, which is what a
#     node that has not been given a policy should do. A name that is not a `:live` lane-W
#     rollout **of kind `:policy`** on this node is a misconfiguration, logged once, and is
#     also inert; a policy is not something to half-have.
#   * `:policy_allowable_tools` is the list of tools whose `allow` this node honours from a
#     component. **Empty by default, and that is the decision, not a placeholder.** A policy
#     component is asked about every call the rules did not decide, so an `allow` honoured
#     unconditionally would be a blanket approval channel with a signature on it — and a
#     signature is provenance, not trust (D5). A `deny` always stands, an `ask` always
#     stands, and an `allow` for a tool nobody listed is read as `ask`. Widening this is an
#     operator's deliberate act, tool by tool.
#   * `:policy_decision_timeout_ms` bounds **one decision**, end to end. This is a synchronous
#     round trip through the node's one shared `Ouroboros.Wasm.Pool`, in front of every tool
#     call the rules did not decide, so the cost is worth stating plainly: one such decision is
#     one helper round trip on a pool every capability on this node also uses, and a wedged
#     helper is bounded here rather than by the pool's instance deadline plus its transport
#     margin. On expiry the answer is `ask` and the instance is dropped; only the refusal that
#     means "the instance I remember is gone" is retried, because any other retry doubles what
#     a wedged helper costs. Five seconds, and a value outside 1..60_000 falls back to it.
config :ouroboros,
  permissions_engine: Ouroboros.Control.Permissions,
  wasm_policy: nil,
  policy_allowable_tools: [],
  policy_decision_timeout_ms: 5_000

# The two facts about the web endpoint that are genuinely compile-time, and no others.
# Everything runtime — the bind, the port, the cookie key, the origin policy — is handed
# to it as a start option by `Ouroboros.Web`, built from one `Ouroboros.Web.Config` that
# has already raised over anything unusable. Phoenix reads this key on the way up and
# warns when a configured endpoint has none, so it is also how a boot stays quiet.
config :ouroboros, Ouroboros.Web.Endpoint,
  adapter: Bandit.PhoenixAdapter,
  render_errors: [formats: [html: Ouroboros.Web.ErrorHTML], layout: false]

# Keep every upstream Codex execution and validation behavior, but normalize the one
# command-start event the pinned Harness currently leaves provider-specific before its
# journal deliberately discards raw provider records. Claude gains the one flag its
# managed transport needs to have a human in the loop at all — `--permission-prompt-tool`
# pointed at `ouro mcp-serve` — and is otherwise the pinned adapter.
#
# Harness bundles a Codex CLI adapter. Override it with an explicit removed boundary so
# deleting Ouroboros's old override cannot silently expose `codex exec` again. `native`
# is the in-process direct provider and the product default.
config :jido_harness,
  providers: %{
    claude: Ouroboros.Provider.ClaudeAdapter,
    codex: Ouroboros.Provider.RemovedCodex,
    grok: Ouroboros.Provider.GrokAdapter,
    kimi: Ouroboros.Provider.KimiAdapter,
    opencode: Ouroboros.Provider.OpenCodeAdapter,
    native: Ouroboros.Provider.Native
  },
  process_driver: Ouroboros.Provider.ProcessDriver
