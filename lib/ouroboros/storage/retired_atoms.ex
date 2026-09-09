defmodule Ouroboros.Storage.RetiredAtoms do
  @moduledoc """
  Atoms this build no longer spells, which a checkpoint an older build wrote still holds.

  `Ouroboros.Storage.DurableFile` reads with `:erlang.binary_to_term(binary, [:safe])`,
  which refuses to *create* an atom, so deleting the last line of code that spelled an atom
  is a durable-format change whatever else it is. What that costs depends on the store:

    * A store that is **one file** — the effect ledger, the cluster session-owner
      checkpoint, grants, permissions — loses the whole file. `Agent.EffectLedger.load/2`
      turns the failure into `{:effect_ledger_checkpoint_unreadable, :invalid_term}` out of
      `init/1`, and the ledger is a supervised child of the application, so the node does
      not boot.
    * A store built on `Ouroboros.Storage.Records` — today only `Interactive.Store` — is one
      file per record plus an index. `Records.load_index/3` logs an undecodable record,
      **drops it from the index** and returns the rest, so the cost is one session lost
      silently and permanently, and the node boots. That is quieter than a crash, not
      better than one.

  Listing an atom here is not a shim and keeps no code path alive: it interns the name and
  nothing more. The reader that used to understand the value must treat it as a value that
  matches nothing — an unknown event type presents as a named note, an unknown map key is
  carried and ignored — and never as a reason to crash.

  Journals that route through `Ouroboros.Upgrade.Wire` (the signing journal, the rollout
  registry, the node executor, the WASM store) need no entry here: that boundary writes
  every atom as a tagged binary and reads an unknown one back as its name.

  Two kinds of name no list can hold, and they are the reason a decoder needs a quarantine
  fallback as well as this module: the name of the node that wrote a record
  (`:"ouroboros@some-host"`), and the module name of a capability forged at runtime under
  `Ouroboros.Capability.`. Both were true before this reduction.

  This list is consumed at compile time by `Ouroboros.Storage.DurableFile`, so the atoms are
  interned by the module that does the decoding, whatever loads first. Later slices append
  here rather than starting a second list.
  """

  # Each atom, and the store that may still hold it.
  @retired [
    # ── `Ouroboros.Interactive.Store`: one checkpoint per session (`Storage.Records`) ──
    #
    # `Ouroboros.Interactive.State`'s field for what a conversation delegated. Every
    # interactive checkpoint written before September 2026 has this key.
    :delegations,
    # The transcript event type `/delegate` appended to the parent conversation. Its
    # payload is string-keyed, so the type is the whole atom exposure.
    :delegation,
    # The four keys of a delegation record inside that field that no other line spells.
    # The other five — `id`, `task_id`, `status`, `created_at`, `updated_at` — survive, and
    # so does every `status` value the parent could copy from the team (`:started` at
    # `record_delegation/2`, then `:starting`, `:running`, `:completed`, `:failed`,
    # `:cancelled`, `:lost` from `Team.Snapshot`).
    :team_id,
    :task_node,
    :objective_digest,
    :result_digest,

    # ── `Ouroboros.Cluster`: the session-owner checkpoint, one file ──
    #
    # The second plane's key. Still spelled by `Ouroboros.Provider`'s `@type plane` until
    # that arm goes; listed because the checkpoint outlives the line that spells it.
    :coding,

    # ── `Ouroboros.Control.Grants` and `Ouroboros.Agent.EffectLedger`: module atoms ──
    #
    # The two agent modules `Ouroboros.Mesh.start_agent/2` admitted under the
    # `Elixir.Ouroboros.Agent.` prefix this slice removed. `Worker` was that function's
    # *default* `:agent`, so it is the module a `:start_agent` ledger entry most plausibly
    # names in `attempt.module` and `result.module` (`effect_ledger.ex:85`, `:156`), and
    # either is a legal member of a durable `modules:` allow-list in a grant
    # (`control/grants.ex:84`, `:97`).
    Ouroboros.Agent.Worker,
    Ouroboros.Agent.Coordinator,

    # ── `Ouroboros.Agent.EffectLedger`: one file, and the node does not boot without it ──
    #
    # The ledger stores what an effect *was about* and what it *answered with*, verbatim.
    # `sanitize_result/2` keeps `@result_fields` as they arrive (`effect_ledger.ex:807`)
    # and `sanitize_error/1` stores `classify(error)` (`:833`), which returns an atom as
    # itself and walks tuples element by element. The deleted `Agent.Effects.Runner` was
    # the writer for every agent effect, so its whole vocabulary is on disk wherever a node
    # ran one.
    #
    # `delivery`, in a settled `:delegate` result (`@result_fields.delegate`). The third
    # value of the team's vocabulary, `:pending`, is still spelled elsewhere.
    :delivering,
    :delivered,
    #
    # The runner's own error vocabulary: the guards it refused on, the shapes it wrapped a
    # settlement in, and the two ledger-unavailable failures it settled with.
    :effect_crashed,
    :effect_denied,
    :effect_failed,
    :effect_runner_not_released,
    :effect_settlement_unrecordable,
    :effect_timeout,
    :invalid_effect_result,
    :missing_agent_state,
    :missing_effect_state,
    :runner_audit_unavailable,
    :runner_unavailable,
    :unidentified_principal,
    #
    # The deleted effect actions' own refusals, which settle as `{:effect_failed, :deploy,
    # …}` on a ledger the forge tool still writes.
    :rollout_not_live,
    :unknown_artifact,
    :wrong_lane,
    #
    # The work vocabulary a failed agent effect carries into `classification`. Derived
    # mechanically and deliberately over-inclusively: every atom this build no longer
    # spells that appears as the head of a tuple literal, or as the whole reason of an
    # `{:error, …}`, in the modules a `:delegate` / `:start_agent` / `:deploy` call chain
    # could reach — `agent/effects.ex`, `agent/effects/runner.ex`, `team/`, `team.ex`,
    # `coding/` and `coding_session.ex` at `765bd88`. `classify/1` preserves every one of
    # them; `Team.Server.durable_error/1` preserved them one level further down, which is
    # why the coding plane's names are here too. Pure `handle_info` message tags were the
    # only names dropped, because no error term can carry one.
    :agent_state_call_failed,
    :ambiguous_adoptable_runs,
    :approval_checkpoint_failed,
    :cancellation_checkpoint_failed,
    :cancellation_propagation_failed,
    :coding_identity,
    :coding_start,
    :coding_start_unconfirmed,
    :coding_subscribe,
    :coding_task_checkpoint_migration_failed,
    :coding_task_checkpoint_unreadable,
    :coding_task_not_found,
    :coding_task_owner_conflict,
    :coding_task_owner_verification_failed,
    :coding_task_quarantine_failed,
    :compensation_unavailable,
    :completion_check_failed,
    :coordinator_identity_conflict,
    :coordinator_module_conflict,
    :coordinator_not_found,
    :coordinator_owner_conflict,
    :coordinator_owner_verification_failed,
    :coordinator_start_failed,
    :delegation_checkpoint_failed,
    :delegation_id_conflict,
    :delegation_progress_checkpoint_failed,
    :delegation_setup_failed,
    :delegation_start_retry_failed,
    :exact_remote_stop_failed,
    :existing_task_unavailable,
    :failure_checkpoint_failed,
    :invalid_approval_actor,
    :invalid_cleanup_agents,
    :invalid_coding_node,
    :invalid_coding_task_checkpoint,
    :invalid_coordinator_id,
    :invalid_delegation,
    :invalid_delegation_id,
    :invalid_delegation_options,
    :invalid_objective,
    :invalid_origin_digest,
    :invalid_task_state,
    :invalid_team_checkpoint,
    :invalid_team_id,
    :invalid_team_options,
    :invalid_team_snapshot,
    :invalid_team_storage,
    :invalid_team_store_durability,
    :invalid_worker_id,
    :invalid_worker_node,
    :invalid_worker_options,
    :invalid_worker_role,
    :local_store_unavailable,
    :mesh_visibility_timeout,
    :non_durable_delegation_options,
    :projection_reconcile_failed,
    :provider_has_no_coding_approval_channel,
    :remote_store_unavailable,
    :remote_task_normalization_failed,
    :resubscribe_failed,
    :runtime_function,
    :runtime_pid,
    :runtime_port,
    :runtime_reference,
    :secret_bearing_delegation_options,
    :starting_delegation_recovery_failed,
    :task_call_failed,
    :task_id_conflict,
    :team_checkpoint,
    :team_checkpoint_create_failed,
    :team_checkpoint_failed,
    :team_checkpoint_migration_failed,
    :team_checkpoint_read_failed,
    :team_checkpoint_unreadable,
    :team_close_checkpoint_failed,
    :team_closed,
    :team_closing,
    :team_option_conflict,
    :team_quarantine_failed,
    :team_reconciliation_failed,
    :team_start_fence_failed,
    :team_storage_not_configured,
    :team_store_exception,
    :team_store_unavailable,
    :team_supervisor_unavailable,
    :team_unavailable,
    :unknown_worker_option,
    :unrequestable_task_state,
    :unstorable_task_state,
    :worker_already_added,
    :worker_busy,
    :worker_not_found,
    :worker_owner_conflict,
    :worker_restore_failed,
    :worker_setup_failed,
    :worker_tag_claimed,
    :worker_tag_inconsistent
  ]

  @doc "Every atom this build interns only so an older checkpoint can be read."
  @spec all() :: [atom()]
  def all, do: @retired
end
