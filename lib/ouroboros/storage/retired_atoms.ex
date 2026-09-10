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
  matches nothing — a retired pattern kind matches nothing
  (`Ouroboros.Control.Permissions.Matcher`), an unknown event type presents as a named
  note, a retired ledger subject key is a key nothing reads — and never as a reason to
  crash.

  Two kinds of name are deliberately **not** here. A message tag, a registry key, a
  process-dictionary key or a config key cannot reach a checkpoint at all — C1's F1 dropped
  eleven of those and C2 drops `:session_jsonl`, `:ouroboros_transport`,
  `:ouroboros_service_wait`, `:ouroboros_service_lifetime`, `:grok_auth`,
  `:provider_audit_coverage_insufficient`, `:provider_execution_defaults`,
  `:grok_account_adapter`, `:grok_auth_file` and `:model_catalogs` for the same reason.

  Journals that route through `Ouroboros.Upgrade.Wire` (the signing journal, the rollout
  registry, the WASM store) need no entry here: that boundary writes every atom as a tagged
  binary and reads an unknown one back as its name.

  ## The three mechanisms

  This list is one of three, and they are disjoint — `Ouroboros.Storage.DurableFile`'s
  moduledoc holds the same division beside the code that implements it:

    * **This module** covers a name **no module of this build spells any more**.
    * **The quarantine** (`DurableFile.get_checkpoint_or_quarantine/2`) covers a name **no
      build can spell**: the node that wrote a record (`:"ouroboros@some-host"`) and a
      capability module forged at runtime under `Ouroboros.Capability.`. Both were true
      before this reduction, and no list can hold either.
    * **The preload** (`DurableFile.ensure_build_loaded/0`) covers a name **this build
      spells in a module that has not loaded yet**, which under interactive code loading
      makes readability a function of boot order rather than of the build.

  This list is consumed at compile time by `Ouroboros.Storage.DurableFile`, so the atoms are
  interned by the module that does the decoding, whatever loads first. Later slices append
  here rather than starting a second list, and the comment on each entry says which slice
  removed it and which store held it.
  """

  # Each atom, and the store that may still hold it.
  @retired [
    # ── C5 (plan §4 A4, desktop automation): the permission checkpoint, one file ──
    #
    # The `Pattern.kind` of any persisted `ComputerUse(observe|act|app:…)` rule.
    :computer_use,
    # `Pattern.spec.form` of a persisted `ComputerUse(observe)` rule, same checkpoint.
    :observe,
    # `Pattern.spec.form` of a persisted `ComputerUse(act)` rule, same checkpoint.
    :act,

    # ── C5: `Ouroboros.Agent.EffectLedger`, one file ──
    #
    # A subject key of every `:tool_call` entry a desktop tool wrote.
    :desktop_action,
    # The second such subject key, same checkpoint.
    :window_id,

    # ── C1 (plan §3 D3): `Ouroboros.Interactive.Store`, one checkpoint per session ──
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

    # ── C1: `Ouroboros.Cluster`, the session-owner checkpoint, one file ──
    #
    # The second plane's key. No line of this build spells it any more — the `:coding` arm
    # of `Ouroboros.Provider` went with the plane — so this entry is load-bearing rather
    # than redundant, and the checkpoint outlives every line that used to spell it.
    :coding,

    # ── C1: `Ouroboros.Control.Grants` and `Ouroboros.Agent.EffectLedger`: module atoms ──
    #
    # The two agent modules `Ouroboros.Mesh.start_agent/2` admitted under the
    # `Elixir.Ouroboros.Agent.` prefix this slice removed. `Worker` was that function's
    # *default* `:agent`, so it is the module a `:start_agent` ledger entry most plausibly
    # names in `attempt.module` and `result.module` (`effect_ledger.ex:85`, `:156`), and
    # either is a legal member of a durable `modules:` allow-list in a grant
    # (`control/grants.ex:84`, `:97`).
    Ouroboros.Agent.Worker,
    Ouroboros.Agent.Coordinator,

    # ── C1: `Ouroboros.Agent.EffectLedger` — one file, and the node does not boot without it ──
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
    :worker_tag_inconsistent,

    # ── C2 (plan §3 D2, native is the only provider) ──
    #
    # The provider name itself. It is the `provider` field of every `Interactive.State`
    # checkpoint (`Ouroboros.Interactive.Store`, one file per session), the `provider`
    # field of every `Interactive.Event` inside one, and — the expensive one — the
    # `attempt.provider` of every `:permission` and `:tool_call` entry in
    # `Ouroboros.Agent.EffectLedger`, which is a single file whose loss stops the boot.
    #
    # Nine of these ten are *still* spelled, by `Jido.Harness.Registry`'s `@builtins` in a
    # dependency this build no longer registers those adapters with. That is an accident of
    # a pinned dependency and the guarantee must not rest on one — the same reason C5 listed
    # `:observe` above. `:claude_code` is the tenth and is genuinely gone: it was never a
    # registry key, only the name an event carried.
    :amp,
    :claude,
    :claude_code,
    :codex,
    :gemini,
    :grok,
    :kimi,
    :opencode,
    :pi,
    :zai,

    # The session transport a record's `options.transport` named, same store. `:native`
    # survives; these four were the vendor transports, and `:managed` was the synthetic one
    # the harness substituted for an adapter that declared none.
    :acp,
    :app_server,
    :managed,
    :rpc,
    :stream_json_resume,

    # Keys of `options.provider_options` in the same record. `Interactive.State`'s
    # `@durable_provider_options` was 47 names and is now the eight the native adapter
    # declares; these 26 are the ones no line of this build spells any more. The thirteen
    # not listed — `agent`, `attach`, `base_url`, `continue`, `debug`, `extensions`,
    # `fork`, `no_session`, `offline`, `session_dir`, `skills`, `thinking`, `title` — are
    # spelled by kept code for their own reasons and need no entry.
    :allowed_mcp_server_names,
    :api_timeout_ms,
    :betas,
    :cli_path,
    :dangerously_allow_all,
    :fallback_model,
    :log_file,
    :log_level,
    :max_budget_usd,
    :model_provider,
    :model_reasoning_summary,
    :network_access_enabled,
    :no_color,
    :no_context_files,
    :no_extensions,
    :no_ide,
    :no_jetbrains,
    :no_notifications,
    :no_skills,
    :project_trust,
    :resume_last,
    :session_name,
    :skills_dirs,
    :skip_git_repo_check,
    :visibility,
    :web_search_enabled,

    # The ACP client's own failure vocabulary. `Ouroboros.Interactive.Task` stores a start
    # or dispatch refusal as `durable(reason)` in the session's `error` field and in a
    # turn's, and `State.durable_term/1` keeps an atom as itself — so a session that failed
    # to open a `Ouroboros.Provider.Session.ACP` transport has one of these on disk, inside
    # a `Storage.Records` record.
    :invalid_dialect,
    :invalid_dialect_ask_result,
    :invalid_dialect_configure_result,
    :invalid_handshake_step,
    :no_bound_port,
    :no_modes_announced,
    :no_token_file,
    :not_an_executable_regular_file,
    :port_unavailable,
    :provider_transport_unavailable,
    :provider_workspace_wrapper_unavailable,
    :session_not_open,
    :transport_call_exit,
    :unknown_mode,
    :unknown_session,
    :unmergeable_mcp_config,
    :unsupported_method_message,

    # The per-provider capability matrix's refusal vocabulary. These eleven are the
    # deliberate over-inclusion C1's F1 describes: every path this build had for them ended
    # in a gateway reply rather than in a checkpoint, and none of them is in the fixture —
    # but they are `{:error, reason}` heads and inner `reason:` values in a term the
    # coordinator would have made durable had one ever reached `fail_start/2`, and a word
    # of atom table is cheaper than being wrong about that.
    :at_start_only,
    :native_session,
    :no_approval_channel,
    :no_dynamic_configuration,
    :no_dynamic_model,
    :transport_cannot_fork,
    :transport_cannot_plan,
    :transport_has_no_modes,
    :unforkable_at_turn,
    :unsupported_approval_mode,
    :vendor_forks_at_tail
  ]

  @doc """
  Every atom this build interns only so an older checkpoint can be read.

  The order is the order slices retired them.
  """
  @spec all() :: [atom()]
  def all, do: @retired
end
