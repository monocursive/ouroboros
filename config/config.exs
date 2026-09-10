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
  # candidate code or only holds a signing seam has no sessions or stores on it to lose.
  # An unrecognized value refuses the boot rather than falling back to the privileged
  # tree. See `Ouroboros.Cluster`.
  node_role: :core,
  # Refuse to place a mesh agent on a node that is not a connected `:core` node running
  # this runtime. This is misconfiguration detection — work sent where it cannot run —
  # and explicitly not a boundary against a hostile connected node, which has full
  # `:erpc` authority regardless.
  placement_role_check: true,
  # Where forge builds run, and it is a check rather than advice (docs/WASM.md D29,
  # contract C14). `:local` — the default — forges where the effect
  # lands; `:builder` forwards a forge that landed on a
  # non-builder node to a connected `:builder` and refuses by name when there is none, rather
  # than quietly building here. A `:signer` node refuses to forge under **either** setting and
  # is not configurable: a Cargo build is arbitrary code at build time, and it does not run on
  # the machine holding the key. Anything but these two words is refused, not read as the
  # default — a typo asked for a forge not to run here.
  wasm_forge_placement: :local,
  # Whether a model session is shown the `forge` tool at all (docs/SELF.md §S1). `false` is
  # the default and the posture: a session that can forge can change the runtime it is
  # running in, which is the whole claim of self-improvement and not a thing to have on by
  # accident. `OUROBOROS_POSTURE=self` sets it true; nothing else does. Off, the name is
  # absent from every session's tool list and `Tools.lookup/3` answers `:unknown_tool` —
  # the same posture the Computer Use tools take, so a model is never taught a name it
  # cannot use. Read as exactly `true`: a typo leaves it shut rather than widening it.
  native_forge_tool: false,
  interactive_storage: {Jido.Storage.ETS, table: :ouroboros_interactive},
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
  capability_storage: {Jido.Storage.ETS, table: :ouroboros_capabilities},
  epoch_storage: {Jido.Storage.ETS, table: :ouroboros_forge_epochs},
  # The `:signer` node a forge submits manifests to, and how long it waits.
  # `nil` means no remote signer is configured, which is what an unconfigured cluster
  # should mean: the forge refuses rather than guessing at a host.
  signing_node: nil,
  signing_call_timeout: 15_000,
  # Everything below is read on the signer node itself, by
  # `Ouroboros.Upgrade.Signing.Service`. The identity this node signs as — the id whose
  # public key core nodes name in OUROBOROS_UPGRADE_TRUSTED_SIGNERS. It cannot be
  # defaulted, and a `:signer` node refuses to boot without it; the key itself is never
  # configuration, it is read at boot from OUROBOROS_SIGNER_KEY_PATH.
  signer_id: nil,
  # The independent gate applied to a full manifest before any signature exists. See
  # `Ouroboros.Upgrade.Signing.Policy`.
  signing_policy: Ouroboros.Upgrade.Signing.Policy.Default,
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
  # Deadline for one node's evaluation run during a capability rollout. It bounds an
  # `:erpc` into `Ouroboros.Upgrade.Rollout.Evaluation`, which enforces the artifact's
  # own `budget_ms` internally; this is the outer limit on a node that stops answering,
  # and exceeding it is ambiguity, so it must be comfortably above any spec's budget.
  capability_eval_timeout: 30_000,
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
  # Fail closed: `workspace_write` on a node with no OS sandbox backend refuses
  # `bash` rather than running it unsandboxed. `OUROBOROS_ALLOW_UNSANDBOXED_BASH=1`
  # (read in `Ouroboros.Provider.Native.Sandbox`, the same way
  # `OUROBOROS_ALLOW_INSECURE_DIST` is read) or this key set true restores the old
  # posture. `:unrestricted` is unchanged: that mode is the operator asking for no
  # sandbox, not this node failing to find one.
  allow_unsandboxed_bash: false,
  # The packaged direct default uses ChatGPT subscription OAuth. API-key deployments may
  # set `OUROBOROS_NATIVE_MODEL=openai:<model>` with `OPENAI_API_KEY`, or select
  # `anthropic:<model>` or `xai:<model>` with the vendor API key or the private credential
  # saved from the web new-session page. Identity-linked Anthropic keys additionally use
  # `ANTHROPIC_WORKSPACE_ID`. Direct Anthropic and xAI lanes are API-key-only; managed
  # Grok subscription access stays in the first-party CLI.
  native_model: "openai_codex:gpt-5.6-sol",
  # How long a terminal interactive session is retained before the recovery sweep
  # deletes it. `nil` disables the sweep and keeps everything.
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
  # MCP servers the native agent may call (D4). Somebody else's program on the end of a
  # pipe, so everything here is a bound and `Ouroboros.Provider.Native.Mcp.Config`
  # refuses a value that would remove one. Empty by default: nothing is spawned that an
  # operator did not name.
  mcp: [enabled: true],
  # Node-scope server definitions, in the Claude-compatible shape and highest precedence
  # of the three sources (node, then `~/.config/ouroboros/mcp.json`, then a *trusted*
  # workspace's `.ouroboros/mcp.json`):
  #   %{"github" => %{command: "npx", args: ["-y", "@modelcontextprotocol/server-github"],
  #                   env: %{"GITHUB_TOKEN" => System.get_env("GITHUB_TOKEN")}}}
  mcp_servers: %{},
  # The LiveView operator surface (docs/WEB.md). The opposite default to `:mcp`, and
  # deliberately: that one is a bound on something this runtime already
  # does, while this one is a port a stranger can reach, so absent configuration has to
  # mean no endpoint at all rather than a disabled one. `config/runtime.exs` is the only
  # thing that turns it on, and every other value — a bind, a port, a token path — is a
  # decision that belongs to the machine rather than to the build. Their defaults and the
  # refusals that go with them live in `Ouroboros.Web.Config`.
  web: [enabled: false],
  # WebAssembly containment (docs/WASM.md §7). The helper
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
#
# S2 adds four more, and none of them widens anything by existing:
#
#   * `:policy_promotion_storage` is where `Ouroboros.Control.PolicyPromotion` keeps the record
#     of which `(tool, shape)` pairs a component has *earned* the right to resolve — the second
#     and only other input to what an `allow` may resolve. ETS here, so the record dies with
#     the VM and every shape starts unpromoted. Production names a synced
#     `Ouroboros.Storage.DurableFile`; that line lives in `config/runtime.exs` beside
#     `:grants_storage`'s and is S4's to write, because a promotion that was acknowledged must
#     survive the crash that follows it.
#   * `:policy_evidence_root` is where `Ouroboros.Control.PolicyEvidence` writes the corpus a
#     replay measures a candidate against. `nil` — the default — derives it as
#     `<data_dir>/policy`. Naming it is a **test seam**, the same kind as `:wasm_policy_opts`'
#     `:store_root` and `:permissions_ledger`: it is what lets a test write a corpus it
#     controls and read it back, and it is not a setting an operator has any reason to move.
#   * `:policy_evidence_enabled` turns the corpus off. `true` here, and `false` writes nothing
#     at all — no directory, no file, no row — for a node whose operator does not want human
#     command lines on its disk at any bound. Left on, the bounds are the module's: 10 000 rows
#     or 64 MiB, whichever comes first, past which the oldest are dropped by one rewrite to 90%
#     of the bound, in a directory this runtime creates `0700` around a file it creates `0600`.
#     Turning it off means no promotion can ever be earned again; the ones already recorded
#     stand until they are demoted or cleared.
#   * `:policy_shadow_every` is how often an `allow` a promotion would resolve is put to a
#     human anyway: every 10th, per `(tool, shape)`. It is not a safety margin, it is what
#     makes the demotion canary *able to see* — a promoted shape otherwise resolves its calls
#     with nobody in the loop, so nobody is ever asked about the calls a promotion removed and
#     no contradiction can ever be observed. `0` disables it, is honoured, and is documented in
#     S-D24 and S-D29 as blinding the canary; a value outside 1..1_000 falls back to 10.
config :ouroboros,
  permissions_engine: Ouroboros.Control.Permissions,
  wasm_policy: nil,
  policy_allowable_tools: [],
  policy_decision_timeout_ms: 5_000,
  policy_promotion_storage: {Jido.Storage.ETS, table: :ouroboros_policy_promotion},
  policy_evidence_root: nil,
  policy_evidence_enabled: true,
  policy_shadow_every: 10

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
