import Config

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
  coding_storage: {Jido.Storage.ETS, table: :ouroboros_coding},
  interactive_storage: {Jido.Storage.ETS, table: :ouroboros_interactive},
  team_storage: {Jido.Storage.ETS, table: :ouroboros_teams},
  orchestration_storage: {Jido.Storage.ETS, table: :ouroboros_orchestration},
  control_storage: {Jido.Storage.ETS, table: :ouroboros_control},
  grants_storage: {Jido.Storage.ETS, table: :ouroboros_grants},
  upgrade_storage: {Jido.Storage.ETS, table: :ouroboros_upgrades},
  release_storage: {Jido.Storage.ETS, table: :ouroboros_releases},
  capability_storage: {Jido.Storage.ETS, table: :ouroboros_capabilities},
  epoch_storage: {Jido.Storage.ETS, table: :ouroboros_forge_epochs},
  # The forge asks this module to sign what it builds. Refusing by default means a
  # cluster acquires a signing capability only when an operator configures one, and
  # never because a default was convenient. Key custody belongs outside this
  # application; see `Ouroboros.Upgrade.Forge.Signer`.
  forge_signer: Ouroboros.Upgrade.Forge.Signer.Deny,
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
  # How long a terminal coding task or interactive session is retained before the
  # recovery sweep deletes it. `nil` disables the sweep and keeps everything.
  terminal_retention_ms: 7 * 24 * 60 * 60 * 1_000,
  # How long a closed provider session may keep a dispatched turn unresolved before
  # the turn is settled as ambiguous so the session can reach its terminal state.
  interactive_unresolved_turn_deadline_ms: 10 * 60 * 1_000
