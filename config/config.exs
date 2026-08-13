import Config

# Development and test builds can exercise the local upgrade lane without managing a
# signing key. Production always requires an explicitly trusted signature.
config :ouroboros,
  upgrade_trust_policy: [allow_unsigned: config_env() != :prod],
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
