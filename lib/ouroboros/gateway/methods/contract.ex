defmodule Ouroboros.Gateway.Methods.Contract do
  @moduledoc "Wire method metadata, parameter envelopes and dispatch targets, defined together."
  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Gateway.Methods.Browse
  @default_timeout 15000
  @wasm_download_timeout 15000
  @wasm_upload_timeout 15000
  @wasm_sign_timeout 60000
  @wasm_deploy_timeout 180_000
  @wasm_rollback_timeout 30000
  @replay_limit 500
  @default_replay_limit 100
  @start_timeout 120_000
  @shell_timeout 10 * 60 * 1000
  @compaction_timeout 120_000
  @forge_timeout 120_000
  @replay_verify_timeout 120_000
  @hello_deadline 10000
  # S2b. `policy.status` reads the whole evidence corpus to count it — at most 10 000 rows or
  # 64 MiB, which is a sequential read and a decode per line rather than a query. `policy.replay`
  # and `policy.promote` ask a wasm component once per row in that corpus, so their ceiling is
  # `wasm.deploy`'s: above the work rather than above one call. `policy.promote` additionally
  # admits `outcome: :unknown`, because the replay it re-runs and the checkpoint it writes do
  # not stop when this socket's ceiling fires.
  @policy_status_timeout 30_000
  @policy_replay_timeout 180_000
  # The bytes a `policy.demote` reason may carry. It is echoed and never stored, so this bounds
  # a reply rather than a record.
  @policy_reason_bytes 512
  # A shape is a `bash` command prefix, bounded exactly as `Control.PolicyPromotion` bounds the
  # one it writes into a checkpoint (`max_shape_bytes/0`), so a shape this boundary accepts is a
  # shape that plane can store.
  @policy_shape_bytes 128
  # `Ouroboros.Wasm.PolicyEngine.promotion_thresholds/0`, restated for the generated reference.
  # Literals rather than a compile-time call into the wasm plane, and held equal to it by
  # `Ouroboros.Gateway.PolicyTest`.
  @policy_thresholds %{
    contradictions: 0,
    unreadable: 0,
    distinct_fingerprints: 20,
    distinct_sessions: 2,
    would_resolve: 1
  }
  @approval_modes %{
    "default" => :default,
    "prompt" => :prompt,
    "auto_edit" => :auto_edit,
    "auto_approve" => :auto_approve
  }
  @sandbox_modes %{
    "default" => :default,
    "read_only" => :read_only,
    "workspace_write" => :workspace_write,
    "unrestricted" => :unrestricted
  }
  @reasoning_efforts %{
    "none" => :none,
    "low" => :low,
    "medium" => :medium,
    "high" => :high,
    "xhigh" => :xhigh,
    "max" => :max
  }
  @approval_decisions %{"approve" => :approve, "deny" => :deny}
  @approval_scopes %{"once" => :once, "session" => :session}
  @plan_exit_choices ["auto_edit", "prompt", "keep_planning"]
  @approval_response_param {"response", :required,
                            {:either,
                             enum_of: @approval_decisions,
                             object: [
                               {"decision", :required, {:enum_of, @approval_decisions}, nil},
                               {"scope", {:optional, "once"}, {:enum_of, @approval_scopes},
                                "`session` additionally writes a session-scoped rule from the pattern the request suggested"},
                               {"reason", :optional, :string, nil},
                               {"actor", {:optional, "human"},
                                {:enum, ["human", "headless", "automation"]},
                                "who answered; the durable approval record preserves it"},
                               {"provider_options", :optional,
                                {:object,
                                 [
                                   {"choice", :optional, {:enum, @plan_exit_choices},
                                    "a plan-exit question's explicit answer"},
                                   {"follow_up", :optional, :string,
                                    "the bounded prompt to run after leaving plan mode"}
                                 ]}, "accepted only for a plan-exit answer"}
                             ]}, "an approval is a yes or a no"}
  @permission_scopes %{
    "node" => :node,
    "user" => :user,
    "workspace" => :workspace,
    "session" => :session
  }
  @permission_rule_scopes %{"user" => :user, "workspace" => :workspace}
  @permission_removable_scopes Map.put(@permission_rule_scopes, "session", :session)
  @permission_decisions %{"allow" => :allow, "deny" => :deny, "ask" => :ask}
  @start_options %{
    "id" => :string,
    "workspace" => :string,
    "model" => :string,
    "system_prompt" => :string,
    "max_turns" => :positive_integer,
    "event_limit" => :event_limit,
    "approval_mode" => {:enum, @approval_modes},
    "sandbox_mode" => {:enum, @sandbox_modes},
    "reasoning_effort" => {:enum, @reasoning_efforts},
    "unknown_compact_tokens" => :positive_integer,
    "runtime_exposure" => :boolean,
    "worktree" => :boolean,
    "plan" => :boolean,
    "machine" => :node,
    "node" => :node
  }
  @configuration_options %{
    "approval_mode" => {:enum, @approval_modes},
    "sandbox_mode" => {:enum, @sandbox_modes},
    "model" => :string,
    "reasoning_effort" => {:enum, @reasoning_efforts},
    "unknown_compact_tokens" => {:nilable, :positive_integer},
    "plan" => :boolean
  }
  @start_option_notes %{
    "id" =>
      "caller-owned; a matching retry adopts the same immutable intent and a conflicting reuse is refused",
    "machine" => "an alias of `node` — provide one or the other, never both",
    "workspace" =>
      "required, and absolute, when `machine`/`node` selects a machine other than this one",
    "worktree" => "provisions a `git worktree` under the data directory before the lease is taken"
  }
  @start_params (for {name, kind} <- Enum.sort(@start_options) do
                   {name, :optional, kind, Map.get(@start_option_notes, name)}
                 end)
  @configuration_option_notes %{
    "plan" => "not a Harness configuration key — it takes its own live surface (B2)",
    "unknown_compact_tokens" =>
      "operator-selected measured-history budget for models whose capacity is unknown; null disables it and never claims a model context window"
  }
  @configuration_params (for {name, kind} <- Enum.sort(@configuration_options) do
                           {name, :optional, kind, Map.get(@configuration_option_notes, name)}
                         end)
  @session_id {"id", :required, :string, "the interactive session id"}
  @session_node {"node", :optional, :node,
                 "the machine that owns the session; this one by default"}
  @authority_node {"node", :optional, :node,
                   "the machine whose authority answers; this one by default"}
  @cursor_param {"cursor", {:optional, 0}, :non_negative_integer,
                 "exclusive — the window starts at the next sequence"}
  @limit_param {"limit", {:optional, @default_replay_limit}, {:integer, 1, @replay_limit}, nil}
  @sequence_param {"sequence", :required, :positive_integer,
                   "the exact sequence; a gap answers `-32007` rather than the next event that exists"}
  @ledger_limit_param {"limit", :optional, {:limits, {EffectLedger, :query_limits, []}},
                       "the ledger's own bound, not this table's"}
  @turn_input_param {"input", :required,
                     {:either,
                      [
                        :string,
                        object: [
                          {"prompt", :required, {:either, [:string, {:const, ""}]},
                           "may be empty when image_attachments is nonempty"},
                          {"attachments", :optional, {:list, :string, 32},
                           "each must be an existing regular file the leased workspace contains"},
                          {"image_attachments", :optional,
                           {:list,
                            {:object,
                             [
                               {"id", :required, :string,
                                "opaque attachment ID returned by attachment.finish/status"}
                             ]}, 32},
                           "opaque managed image references; prompt may be empty with at least one ready image"},
                          {"reasoning_effort", :optional, {:enum_of, @reasoning_efforts}, nil}
                        ]
                      ]}, nil}
  @deployment_operation {"operation_id", :required, :string,
                         "the id `fleet.deployment.prepare` answered with; sixteen lowercase hex characters, because it also names a Unix socket path and `sun_path` is short"}
  @turn_id_param {"turn_id", :optional, :string,
                  "caller-supplied; resending the same `{id, input, turn_id}` returns the same turn rather than starting a second"}
  @methods %{
    "attachment.limits" => %{
      scope: :read,
      timeout: 15_000,
      handler: :handle_attachment_limits,
      params:
        {:closed, [{"node", :optional, :node, "the runtime that owns the image or session"}]}
    },
    "attachment.begin" => %{
      scope: :operate,
      timeout: 15_000,
      handler: :handle_attachment_begin,
      params:
        {:closed,
         [
           {"client_id", :required, :string, nil},
           {"draft_id", :required, :string, nil},
           {"client_attachment_id", :required, :string, nil},
           {"attempt_id", :required, :string, nil},
           {"byte_size", :required, :non_negative_integer, nil},
           {"display_name", :optional, :string, nil},
           {"source", :optional, :string, nil},
           {"session_id", :optional, :string, nil},
           {"client_max_frame", :optional, :non_negative_integer, nil},
           {"node", :optional, :node, "the runtime that owns the image or session"}
         ]}
    },
    "attachment.append" => %{
      scope: :operate,
      timeout: 15_000,
      handler: :handle_attachment_append,
      params:
        {:closed,
         [
           {"upload_id", :required, :string, nil},
           {"offset", :required, :non_negative_integer, nil},
           {"data", :required, :string, nil},
           {"node", :optional, :node, "the runtime that owns the image or session"}
         ]}
    },
    "attachment.finish" => %{
      scope: :operate,
      timeout: 15_000,
      handler: :handle_attachment_finish,
      params:
        {:closed,
         [
           {"upload_id", :required, :string, nil},
           {"sha256", :required, :string, nil},
           {"node", :optional, :node, "the runtime that owns the image or session"}
         ]}
    },
    "attachment.status" => %{
      scope: :read,
      timeout: 15_000,
      handler: :handle_attachment_status,
      params:
        {:closed,
         [
           {"upload_id", :optional, :string, nil},
           {"attachment_id", :optional, :string, nil},
           {"session_id", :optional, :string, nil},
           {"node", :optional, :node, "the runtime that owns the image or session"}
         ]}
    },
    "attachment.bind_draft" => %{
      scope: :operate,
      timeout: 15_000,
      handler: :handle_attachment_bind_draft,
      params:
        {:closed,
         [
           {"draft_id", :required, :string, nil},
           {"session_id", :required, :string, nil},
           {"node", :optional, :node, "the runtime that owns the image or session"}
         ]}
    },
    "attachment.touch_draft" => %{
      scope: :operate,
      timeout: 15_000,
      handler: :handle_attachment_touch_draft,
      params:
        {:closed,
         [
           {"draft_id", :required, :string, nil},
           {"revision", :optional, :non_negative_integer, nil},
           {"node", :optional, :node, "the runtime that owns the image or session"}
         ]}
    },
    "attachment.discard" => %{
      scope: :operate,
      timeout: 15_000,
      handler: :handle_attachment_discard,
      params:
        {:closed,
         [
           {"upload_id", :optional, :string, nil},
           {"attachment_id", :optional, :string, nil},
           {"node", :optional, :node, "the runtime that owns the image or session"}
         ]}
    },
    "attachment.read" => %{
      scope: :read,
      timeout: 15_000,
      handler: :handle_attachment_read,
      params:
        {:closed,
         [
           {"attachment_id", :required, :string, nil},
           {"session_id", :optional, :string, nil},
           {"variant", :required, :string, nil},
           {"offset", :optional, :non_negative_integer, nil},
           {"length", :optional, :non_negative_integer, nil},
           {"node", :optional, :node, "the runtime that owns the image or session"}
         ]}
    },
    "audit.hold" => %{
      scope: :operate,
      timeout: 30_000,
      params:
        {:closed,
         [
           {"stream_id", :required, :string, nil},
           {"held", :required, :boolean, nil},
           {"reason", :required, :string, nil}
         ]},
      handler: :handle_audit_hold
    },
    "audit.purge" => %{
      scope: :operate,
      timeout: 60_000,
      params:
        {:closed, [{"stream_id", :required, :string, nil}, {"reason", :required, :string, nil}]},
      handler: :handle_audit_purge
    },
    "audit.retention" => %{
      scope: :read,
      timeout: 30_000,
      params: {:closed, []},
      handler: :handle_audit_retention
    },
    "audit.status" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:closed, []},
      handler: :handle_audit_status
    },
    "audit.doctor" => %{
      scope: :read,
      timeout: 60_000,
      params: {:closed, []},
      handler: :handle_audit_doctor
    },
    "audit.search" => %{
      scope: :read,
      timeout: 30_000,
      params:
        {:closed,
         [
           {"stream_id", :optional, :string, nil},
           {"session_id", :optional, :string, nil},
           {"provider_session_id", :optional, :string, nil},
           {"turn_id", :optional, :string, nil},
           {"call_id", :optional, :string, nil},
           {"ledger_effect_id", :optional, :string, nil},
           {"actor_id", :optional, :string, nil},
           {"model", :optional, :string, nil},
           {"tool", :optional, :string, nil},
           {"kind", :optional, :string, nil},
           {"status", :optional, :string, nil},
           {"since", :optional, :string, nil},
           {"until", :optional, :string, nil},
           {"limit", {:optional, 100}, :positive_integer, nil},
           {"offset", {:optional, 0}, :non_negative_integer, nil}
         ]},
      handler: :handle_audit_search
    },
    "audit.show" => %{
      scope: :read,
      timeout: 30_000,
      params:
        {:closed,
         [
           {"stream_id", :required, :string, nil},
           {"since_seq", {:optional, 0}, :non_negative_integer, nil},
           {"limit", {:optional, 100}, :positive_integer, nil}
         ]},
      handler: :handle_audit_show
    },
    "audit.artifact" => %{
      scope: :read,
      timeout: 30_000,
      params:
        {:closed, [{"stream_id", :required, :string, nil}, {"blob", :required, :string, nil}]},
      handler: :handle_audit_artifact
    },
    "audit.export" => %{
      scope: :read,
      timeout: 60_000,
      params: {:closed, [{"stream_id", :optional, :string, nil}]},
      handler: :handle_audit_export
    },
    "audit.download" => %{
      scope: :read,
      timeout: 30_000,
      params:
        {:closed,
         [
           {"bundle_id", :required, :string, nil},
           {"path", :required, :string, nil},
           {"offset", {:optional, 0}, :non_negative_integer, nil}
         ]},
      handler: :handle_audit_download
    },
    "audit.reindex" => %{
      scope: :operate,
      timeout: 60_000,
      params: {:closed, []},
      handler: :handle_audit_reindex
    },
    "audit.flush" => %{
      scope: :operate,
      timeout: 60_000,
      params: {:closed, []},
      handler: :handle_audit_flush
    },
    "account.login.cancel" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"login_id", :required, :string,
            "correlates with the `loginId` the start reply carried"}
         ]},
      handler: :handle_account_login_cancel
    },
    "account.login.complete" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"login_id", :required, :string, "the loginId returned by account.login.start"},
           {"code", :required, :string, "the OAuth authorization code"},
           {"state", :required, :string, "the OAuth state returned to the callback"}
         ]},
      handler: :handle_account_login_complete
    },
    "account.login.start" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed, [{"flow", {:optional, "browser"}, {:enum, ["browser", "device_code"]}, nil}]},
      handler: :handle_account_login_start
    },
    "account.logout" => %{
      scope: :operate,
      timeout: @default_timeout,
      params: {:closed, []},
      handler: :handle_account_logout
    },
    "account.read" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:closed, []},
      handler: :handle_account_read
    },
    "capabilities.admit" => %{
      scope: :operate,
      timeout: @forge_timeout,
      params:
        {:closed,
         [
           {"workspace", :required, :string, nil},
           {"path", :required, :string, nil},
           {"session_id", :optional, :string,
            "recorded as `session:<id>` in the admission's authorship"}
         ]},
      handler: :handle_capabilities_admit
    },
    "capabilities.list" => %{
      scope: :operate,
      timeout: @default_timeout,
      params: {:closed, [{"workspace", :required, :string, nil}]},
      handler: :handle_capabilities_list
    },
    "capabilities.preview" => %{
      scope: :operate,
      timeout: @forge_timeout,
      params:
        {:closed, [{"workspace", :required, :string, nil}, {"path", :required, :string, nil}]},
      handler: :handle_capabilities_preview
    },
    "credentials.anthropic.set" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"api_key", {:optional, nil}, :string,
            "replaces the privately stored key; may be omitted when updating an existing stored credential"},
           {"workspace_id", {:optional, nil}, :string,
            "`wrkspc_`-prefixed workspace for an identity-linked key; may be omitted for a single-workspace key"}
         ],
         "updates the node-owned Anthropic credential without returning it; `ANTHROPIC_API_KEY` and `ANTHROPIC_WORKSPACE_ID` still take precedence"},
      handler: :handle_credentials_anthropic_set
    },
    "credentials.xai.set" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed, [{"api_key", :required, :string, "replaces the privately stored xAI API key"}],
         "updates the node-owned xAI API key without returning it; `XAI_API_KEY` still takes precedence"},
      handler: :handle_credentials_xai_set
    },
    "fleet.devices" => %{
      scope: :read,
      timeout: 15_000,
      params:
        {:closed, [],
         "the Devices inventory, answered by this machine about itself and the network it can see. `host` is the deployment host — hostname, local account, os, arch — plus `issuer` (whether the fleet CA *private* key is on this machine, which is what makes it able to admit a member rather than merely describe one) and `capabilities` `{deploy, reasons}`. `deploy` is false with a named reason when this runtime holds no CA key, cannot say where its own `ouro` is, serves no durable data directory, or publishes a cleartext non-loopback web endpoint — the spec decides credential entry on the bind, the one transport fact a server can verify, and a forwarded header never enters it. `discovery` and `devices` are `ouro fleet devices --json` verbatim, bounded and read under a ten-second ceiling: a merge of this machine\'s roster with the peers its network client can see, where a visible peer is never labelled uninstalled because nothing has inspected one. Each **member** row additionally carries what this runtime knows about that machine as a BEAM peer — `connected`, `compatible`, `runtime_running` and `last_probe` — and its `state` becomes `fleet_member_connected` when it is connected. These are the cluster's answers and are kept separate from `online` and `path`, which are the network client's: a member reachable over BEAM but invisible to the network client is a different problem from one that is neither, and reporting only the second is why a machine `fleet doctor` called connected still rendered as \"not visible on this network\". A row that is not a member carries `null` for all four, because this runtime knows nothing about it rather than knowing it is absent. `operations` is the deployment operations this data directory holds journals for — `operation`, `kind`, `state`, `owner`, `created_at`/`updated_at`, whether a worker is `attached`, and the `target` (machine, address, ssh user and port) that puts it on a device row. Newest first by `created_at`, at most 200, with `operations_total` saying how many there are so a surface can say \"and N older\" rather than showing a prefix as if it were the whole. A top-level key `ouro` printed that this build does not read is named in `unknown` rather than passed through. Administrator-only by the identity rule even at read scope: this is every machine on an operator\'s private network. A non-administrator reader sees `fleet.status`\'s membership subset instead"},
      handler: :handle_fleet_devices
    },
    "fleet.deployment.prepare" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"kind", {:optional, "add"}, {:enum, ["setup", "add"]},
            "`add` deploys onto another machine over SSH. `setup` is the first **local** fleet — \"Set up this device\" — which the spec is explicit about: this machine configures itself, without SSH to itself, so it takes no target and no account"},
           {"target", :optional,
            {:object,
             [
               {"address", :required, :string,
                "the private overlay address. Required, because the worker talks to addresses: a peer id is a network client\'s *name* for a device, and resolving one is what `fleet.devices` is for"},
               {"machine", :optional, :string,
                "the roster name for the new member; the peer id or the address when omitted"},
               {"peer_id", :optional, :string,
                "the network client\'s own id, used as the machine name when no `machine` is given"}
             ]}, "required for `add`; unused by `setup`"},
           {"machine", :optional, :string,
            "`setup` only: what this device should be called in its own fleet. This host\'s own name when omitted"},
           {"address", :optional, :string,
            "`setup` only: this machine\'s private overlay address, the one its runtime will bind. The worker refuses `unresolved_address` rather than guessing when it is absent; `fleet.devices` reports it"},
           {"ssh_user", :optional, :string,
            "required for `add`: the account on the target. Never inferred from the network client\'s owner, and never used by `setup`"},
           {"port", {:optional, 22}, {:integer, 1, 65_535}, nil},
           {"identity", :optional,
            {:object,
             [
               {"kind", :required, {:enum, ["default", "agent", "key", "password"]}, nil},
               {"ref", :optional, :string,
                "required for `agent` (the identity\'s public fingerprint) and for `key` (a path on this host) — a reference, never key material"}
             ]},
            "`add` only; omitted means `default`, which is whatever this host\'s own ssh configuration selects"},
           {"install_path", :optional, :string, "where `ouro` goes on the target"},
           {"data_dir", :optional, :string, "the target\'s durable directory"},
           {"service", {:optional, true}, :boolean,
            "whether to install an Ouroboros-owned startup service on the target"}
         ],
         "forks the deployment worker for a new operation and attaches to it, then answers. Inspection, host verification and authentication all happen behind the returned `operation_id` rather than inside this call: the worker is detached, so closing the page and stopping this runtime both leave it running. These parameters reach it in a private 0600 file under the data directory rather than on its command line, because `ps` is readable by every local account and a target hostname is nobody else's business; the worker unlinks that file once it has read it. They are written in the worker's own request shape, which refuses a key it does not know, so what this method accepts and what the worker reads cannot drift apart silently. **Refused `-32003` `deploy_blocked` when this host cannot deploy**, carrying `data.blockers` — the same list `fleet.devices` reports under `capabilities.reasons`. A disabled button is a rendering, not a boundary, so the check is here as well; `.start`, `.authenticate` and `.resume` are held to it too, and `.cancel` never is, because an operator must be able to stop a deployment on a host that may no longer start one. A `setup` is exempt from `no_ca_key` and from that alone: the first local fleet is what creates the key. No secret is a parameter here — an identity is named by reference and a password is only ever answered to its own challenge"},
      handler: :handle_fleet_deployment_prepare
    },
    "fleet.deployment.status" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed, [@deployment_operation],
         "the sanitized snapshot: `source` is `worker` when one is attached and `journal` when none is, which is the operator\'s whole question after an interruption — a journal says what was durably recorded, only a live worker says what is happening now. Carries states, steps, bounded log lines and the metadata of every open challenge; a challenge\'s metadata is secret-free by construction and this reads it defensively anyway. A read cannot obtain or answer a secret"},
      handler: :handle_fleet_deployment_status
    },
    "fleet.deployment.start" => %{
      scope: :operate,
      timeout: @default_timeout,
      outcome: :unknown,
      params:
        {:closed,
         [
           @deployment_operation,
           {"plan_digest", :required, :string,
            "the sha256 of the canonical plan that was reviewed; a plan that changed since is refused `plan_changed` rather than applied"},
           {"idempotency_key", :required, :string,
            "caller-owned. The same key against the same operation replays the recorded answer without touching the worker; a different key while that operation is running is `operation_in_progress`"}
         ],
         "approves the reviewed plan and lets the deployment run. A lost answer is safe to retry under the same key, which is the whole reason the key is required rather than optional"},
      handler: :handle_fleet_deployment_start
    },
    "fleet.deployment.authenticate" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           @deployment_operation,
           {"challenge", :required, :string, "the `password` or `passphrase` challenge answered"},
           {"secret", :required, :string,
            "the password or key passphrase, single use. It is written to the worker\'s socket and referenced nowhere else"}
         ],
         "**the one method in this protocol whose parameters never reach the audit digest.** The spec\'s secret-handling section names `Web.Call` and gateway parameter digests among the places a secret may never appear, *even hashed* — a hash of a human\'s password is that password in a form somebody can look up. Both surfaces therefore log `operation_id` and `challenge` and nothing else for this verb, and the challenge\'s kind and the outcome are logged by the broker, which knows them. Answering requires the identity **and the client session** the challenge was issued to (seam S4): a second tab, a second listener connection, or another administrator is `challenge_not_bound`. A challenge is consumed when it is sent, so a second answer is `challenge_consumed` rather than a second guess"},
      handler: :handle_fleet_deployment_authenticate
    },
    "fleet.deployment.confirm_host" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           @deployment_operation,
           {"challenge", :required, :string, "the `host_trust` challenge answered"},
           {"accept", :required, :boolean,
            "true appends the key to this operation\'s private known-hosts store; false fails the attempt"}
         ],
         "explicit trust for one unknown SSH host key, bound to its session exactly as `authenticate` is. A key that *changed* is never offered here: that is `host_key_changed` and it blocks"},
      handler: :handle_fleet_deployment_confirm_host
    },
    "fleet.deployment.cancel" => %{
      scope: :operate,
      timeout: @default_timeout,
      outcome: :unknown,
      params:
        {:closed, [@deployment_operation],
         "stops at a safe boundary and reports residue. It does not claim to undo anything: the worker finishes or reconciles the durable step it is inside, reaps its SSH children, and a credential already delivered to another machine stays delivered"},
      handler: :handle_fleet_deployment_cancel
    },
    "fleet.deployment.resume" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           @deployment_operation,
           {"takeover", {:optional, false}, :boolean,
            "required to resume an operation another identity started, or one whose owner this build cannot establish. A resume attaches under the resuming identity, so every later challenge binds to *them* — that is inheriting somebody else's credential prompt, and it leaves its own audit line naming who took what from whom"}
         ],
         "forks a new worker for an operation whose previous one is gone, after reading the journal\'s state. Refused when a worker is still attached (`already_attached`), when the journal records a finished operation (`operation_finished`), and when the journal records no state at all (`operation_state_unknown`) — resuming an operation whose record cannot be read would be starting a second worker against a machine whose state nobody knows — and when the journal's `owner` is not this identity and `takeover` was not set (`operation_not_yours`)"},
      handler: :handle_fleet_deployment_resume
    },
    "fleet.doctor" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_fleet_doctor
    },
    "fleet.forget_session_owner" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"machine", :required, :string,
            "must appear in the validated local profile's roster tombstones, and must be offline"},
           {"accept_state_loss", :required, {:const, true},
            "anything else is refused: this retires durable session-owner evidence"}
         ]},
      handler: :handle_fleet_forget_session_owner
    },
    "fleet.tags" => %{
      scope: :operate,
      timeout: 15000,
      params:
        {:closed,
         [
           {"machine", :required, :string, "connected machine name or node"},
           {"operation", :required, :string, "add, remove, or list; tags are advisory"},
           {"tag", :optional, :string, "validated tag for add/remove; omit for list"}
         ]},
      handler: :handle_fleet_tags
    },
    "subagent.spawn" => %{
      scope: :operate,
      timeout: 920_000,
      params:
        {:closed,
         [
           @session_id,
           @session_node,
           {"request_id", :required, :string, "stable id for transport retries"},
           {"input", :required, :object,
            "native agent arguments; posture is inherited from the session"}
         ]},
      handler: :handle_subagent_spawn
    },
    "subagent.result" => %{
      scope: :operate,
      timeout: 920_000,
      params:
        {:closed,
         [
           @session_id,
           @session_node,
           {"request_id", :required, :string, "stable id for transport retries"},
           {"input", :required, :object, "native agent_result arguments"}
         ]},
      handler: :handle_subagent_result
    },
    "subagent.stop" => %{
      scope: :operate,
      timeout: 920_000,
      params:
        {:closed,
         [
           @session_id,
           @session_node,
           {"request_id", :required, :string, "stable id for transport retries"},
           {"task_id", :required, :string, "child tracked by this session"}
         ]},
      handler: :handle_subagent_stop
    },
    "fleet.status" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_fleet_status
    },
    "grants.list" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:open,
         [{"principal", :required, :string, "per-principal by design; there is no list-all"}]},
      handler: :handle_grants_list
    },
    "hello" => %{
      scope: :read,
      timeout: @hello_deadline,
      params:
        {:open,
         [
           {"token", :required, :string,
            "compared against the listener's token by SHA-256 digest, so neither length nor content leaks"},
           {"protocol", :required, {:const, 1},
            "anything else is `-32002` carrying `{\"server_protocol\": 1}`, and the socket closes"},
           {"client", :optional, :string,
            "a display name for the audit line, cut to 120 characters"}
         ]},
      handler: :connection
    },
    "interactive.close" => %{
      scope: :operate,
      timeout: @default_timeout,
      params: {:closed, [@session_id, @session_node]},
      handler: :handle_interactive_close
    },
    "interactive.compact" => %{
      scope: :operate,
      timeout: @compaction_timeout,
      outcome: :unknown,
      params:
        {:closed,
         [
           @session_id,
           {"focus", :optional, :string, "what the fold should keep"},
           {"compaction_id", :optional, :string,
            "caller-owned recovery identity; starts asynchronously and exact retries reconcile"},
           {"action", :optional, {:enum, ["start", "status", "cancel"]},
            "operation action; defaults to start when compaction_id is present"},
           @session_node
         ]},
      handler: :handle_interactive_compact
    },
    "interactive.configure" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed, [@session_id, @session_node | @configuration_params],
         "a strict subset of `interactive.start`'s options; whether any one of them is changeable is the transport's answer, asked per session"},
      handler: :handle_interactive_configure
    },
    "interactive.context" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed, [@session_id, @session_node],
         "for native sessions, `context_state` is `unmeasured` with `context_used: null` before provider measurement, `measured` with the provider-counted request size, or `compacted` with the zero reset sentinel after a successful fold; zero does not claim an empty real prompt. Unknown `context_window` remains null, cumulative `total_tokens` is never substituted, and automatic threshold compaction remains native-session-owned. With unknown capacity, automatic compaction is disabled unless the operator explicitly configures `unknown_compact_tokens`; that is a measured-history budget, not a claimed model window"},
      handler: :handle_interactive_context
    },
    "interactive.safe_status" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed, [@session_id, @session_node],
         "bounded privacy-safe status from the owning session; callers cannot submit facts, ownership, provenance, or freshness"},
      handler: :handle_interactive_safe_status
    },
    "interactive.delete" => %{
      scope: :operate,
      timeout: @default_timeout,
      params: {:closed, [@session_id, @session_node], "terminal sessions only"},
      handler: :handle_interactive_delete
    },
    "interactive.event_detail" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:closed, [@session_id, @sequence_param, @session_node]},
      handler: :handle_interactive_event_detail
    },
    "interactive.follow_up" => %{
      scope: :operate,
      timeout: @default_timeout,
      outcome: :unknown,
      params: {:closed, [@session_id, @turn_input_param, @turn_id_param, @session_node]},
      handler: :handle_interactive_follow_up
    },
    "interactive.fork" => %{
      scope: :operate,
      timeout: @start_timeout,
      outcome: :unknown,
      params:
        {:closed,
         [
           @session_id,
           {"fork_id", :optional, :string, "caller-owned id for the child"},
           {"to_turn", :optional, :turn_target,
            "branch at the end of this turn rather than at the tail; native sessions only, and refused rather than silently widened when the parent no longer holds that boundary"},
           {"model", :optional, :string,
            "the child's model, replacing the parent's rather than inheriting it"},
           @session_node
         ]},
      handler: :handle_interactive_fork
    },
    "interactive.handoff" => %{
      scope: :operate,
      timeout: @start_timeout,
      outcome: :unknown,
      params:
        {:closed,
         [
           @session_id,
           {"prompt", :optional, :string,
            "a prompt forging the `<ouroboros-runtime>` delimiters is refused, not escaped"},
           {"handoff_id", :optional, :string,
            "caller-owned child id, nonblank and at most 128 UTF-8 bytes; exact retry reconciles the durable reservation"},
           @session_node
         ]},
      handler: :handle_interactive_handoff
    },
    "interactive.info" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:closed, [@session_id, @session_node]},
      handler: :handle_interactive_info
    },
    "interactive.interrupt" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           @session_id,
           {"turn_id", :optional, :string, "the running turn by default"},
           @session_node
         ]},
      handler: :handle_interactive_interrupt
    },
    "interactive.journal" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           @session_id,
           {"since_seq", {:optional, 0}, :non_negative_integer,
            "exclusive — the window starts at the next journal sequence"},
           @limit_param,
           @session_node
         ], "native sessions only; every other transport answers `-32006`"},
      handler: :handle_interactive_journal
    },
    "interactive.kill" => %{
      scope: :operate,
      timeout: @default_timeout,
      params: {:closed, [@session_id, @session_node]},
      handler: :handle_interactive_kill
    },
    "interactive.list" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_interactive_list
    },
    "interactive.rename" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           @session_id,
           {"title", :required, :string,
            "trimmed, at most 120 graphemes, and refused rather than stripped if it holds a control character"},
           @session_node
         ]},
      handler: :handle_interactive_rename
    },
    "interactive.replay" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:closed, [@session_id, @cursor_param, @limit_param, @session_node]},
      handler: :handle_interactive_replay
    },
    "interactive.replay_verify" => %{
      scope: :operate,
      timeout: @replay_verify_timeout,
      params:
        {:closed, [@session_id, @session_node],
         "native sessions only; every other transport answers `-32006`. Re-runs the recorded " <>
           "turns through the real turn loop and answers `{verified, turns, records, head, " <>
           "divergence}`. `divergence` is `null`, a `diverged` object naming the record and " <>
           "the field that stopped agreeing, or a `boundary` object naming why verification " <>
           "stops there — `turns` counts what verified either way"},
      handler: :handle_interactive_replay_verify
    },
    "interactive.respond_approval" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           @session_id,
           {"request_id", :required, :string, "the id the `approval_requested` event carried"},
           @approval_response_param,
           @session_node
         ]},
      handler: :handle_interactive_respond_approval
    },
    "interactive.retry_turn" => %{
      scope: :operate,
      timeout: @default_timeout,
      outcome: :unknown,
      params:
        {:closed,
         [
           @session_id,
           {"source_turn_id", :required, :string,
            "the latest failed turn; retries are idempotent per source"},
           @session_node
         ]},
      handler: :handle_interactive_retry_turn
    },
    "interactive.rewind" => %{
      scope: :operate,
      timeout: @compaction_timeout,
      params:
        {:closed,
         [
           @session_id,
           {"to_turn", :required, :turn_target, nil},
           {"what", {:optional, "both"}, {:enum, ["both", "conversation", "files"]}, nil},
           @session_node
         ]},
      handler: :handle_interactive_rewind
    },
    "interactive.rewind_points" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:closed, [@session_id, @session_node]},
      handler: :handle_interactive_rewind_points
    },
    "interactive.send_message" => %{
      scope: :operate,
      timeout: @default_timeout,
      outcome: :unknown,
      params: {:closed, [@session_id, @turn_input_param, @turn_id_param, @session_node]},
      handler: :handle_interactive_send_message
    },
    "interactive.start" => %{
      scope: :operate,
      timeout: @start_timeout,
      outcome: :unknown,
      params: {:closed, @start_params},
      handler: :handle_interactive_start
    },
    "interactive.preview_native" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"provider_session_id", :required, :string,
            "a known native checkpoint id, never a path"},
           @session_node
         ]},
      handler: :handle_interactive_preview_native
    },
    "interactive.import_native" => %{
      scope: :operate,
      timeout: @start_timeout,
      outcome: :unknown,
      params:
        {:closed,
         [
           {"provider_session_id", :required, :string, "the source id returned by preview"},
           {"expected_digest", :required, :string, "the exact digest returned by preview"},
           {"acknowledge_partial_tail", {:optional, false}, :boolean,
            "required true when preview reports a nonzero offset"}
           | @start_params
         ]},
      handler: :handle_interactive_import_native
    },
    "interactive.steer" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed, [@session_id, @turn_input_param, @session_node],
         "no `turn_id`: the harness mints a steer's request id inside its own worker, so this verb has no caller-keyed idempotency"},
      handler: :handle_interactive_steer
    },
    "interactive.subscribe" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed, [@session_id, @cursor_param, @session_node],
         "answered by the connection itself, because the plane registers the calling process"},
      handler: :connection
    },
    "interactive.unsubscribe" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:closed, [@session_id, @session_node]},
      handler: :connection
    },
    "ledger.export" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"since", {:optional, 0}, :non_negative_integer, "the first sequence to export"},
           @authority_node
         ]},
      handler: :handle_ledger_export
    },
    "ledger.get" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed, [{"id", :required, :string, "an unknown id is `-32007`"}, @authority_node]},
      handler: :handle_ledger_get
    },
    "ledger.list" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"principal", :optional, :string, nil},
           {"effect", :optional, {:enum_mfa, {EffectLedger, :effects, []}}, nil},
           {"status", :optional, {:enum_mfa, {EffectLedger, :statuses, []}}, nil},
           {"since_sequence", {:optional, 0}, :non_negative_integer, nil},
           {"order", {:optional, "desc"}, {:enum, ["asc", "desc"]}, nil},
           @ledger_limit_param,
           @authority_node,
           {"fleet", {:optional, false}, :boolean,
            "fans out to every connected core node over the same bounded `:erpc` the `fleet.*` verbs use"}
         ]},
      handler: :handle_ledger_list
    },
    "mcp.list" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"workspace", :optional, :string,
            "narrow the answer to the servers claimed by sessions in this workspace; every workspace by default"},
           @authority_node
         ]},
      handler: :handle_mcp_list
    },
    "permissions.add" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"scope", :required, {:enum_of, @permission_rule_scopes},
            "`node` rules come from `config :ouroboros, :permissions` and are never written over the wire"},
           {"pattern", :required, :string,
            "validated by `Control.Permissions.Pattern` and by nothing else"},
           {"decision", :required, {:enum_of, @permission_decisions}, nil},
           {"workspace", :optional, :string, "required for a `workspace` rule"},
           @authority_node
         ]},
      handler: :handle_permissions_add
    },
    "permissions.list" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"scope", :optional, {:enum_of, @permission_scopes}, nil},
           {"workspace", :optional, :string, nil},
           @authority_node
         ]},
      handler: :handle_permissions_list
    },
    "permissions.remove" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"scope", :required, {:enum_of, @permission_removable_scopes}, nil},
           {"id", :required, :string, "an unknown id is `-32007`"},
           @authority_node
         ]},
      handler: :handle_permissions_remove
    },
    "policy.clear" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed, [],
         "no parameters at all: this forgets the whole record, and a parameter would suggest there is a part of it to keep. The actor is the gateway principal, so an unattributed caller is refused rather than recorded as one"},
      handler: :handle_policy_clear
    },
    "policy.demote" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"name", :required, :string, "the promoted policy; another name narrows nothing"},
           {"tool", :required, :string, "the tool whose promotion is withdrawn"},
           {"shape", :required, :string,
            "the command prefix whose promotion is withdrawn, in at most #{@policy_shape_bytes} bytes. A promotion is per `(tool, shape)`, so a narrowing is too: demoting `mix test` leaves `mix` standing, and `policy.status` names every shape the record holds"},
           {"reason", :required, :string,
            "why, in at most #{@policy_reason_bytes} bytes. It is **echoed and not stored**: a demotion's `reason` in the record is an enumerated atom (`operator_demotion` for this verb, `human_contradiction` for the canary), because a record fsynced on every write is not where free text belongs"}
         ],
         "narrowing, and idempotent: a shape that is not promoted is already where this leaves it. The actor is the gateway principal and an unattributed caller is refused, because a demotion's ledger entry names the person who made it — narrowing is safe, but an audit trail that says `runtime` about a thing a human did is not"},
      handler: :handle_policy_demote
    },
    "policy.promote" => %{
      scope: :operate,
      timeout: @policy_replay_timeout,
      outcome: :unknown,
      params:
        {:closed,
         [
           {"name", :required, :string, "a live lane-W rollout of kind `policy` on this node"},
           {"tool", :required, :string,
            "the one tool this promotion is about. `bash` is the only promotable tool in v1; every other name is refused as `tool_not_promotable`"},
           {"shape", :required, :string,
            "the command prefix this promotion is about — `mix`, `mix test` — in at most #{@policy_shape_bytes} bytes. A request is covered when every one of its sub-commands matches `Bash(<shape> *)`, which is the permission language's own word-prefix rule rather than a second one here"},
           {"report", :required, :object,
            "a `policy.replay` report, whole. It must still name this policy's `component_sha256` and hash to its own `report_sha256`, so a report about other bytes or one somebody edited is refused by name"}
         ],
         "the report's digest binds the file to its own contents and nothing else — it is a plain sha256 anybody can recompute, so it proves the file was not edited on the way here and never who produced it. The gate is the **re-run**: this node replays the corpus itself and writes the re-run's numbers into the record, with the digest stored beside them as `report_sha256_as_submitted`. The re-run must show zero contradictions across the whole tool and, on this shape's definite verdicts, no unreadable verdict, at least #{@policy_thresholds.distinct_fingerprints} distinct requests, at least #{@policy_thresholds.distinct_sessions} distinct sessions and at least #{@policy_thresholds.would_resolve} call it would have resolved. `outcome: unknown` on a ceiling: the replay and the checkpoint do not stop because this socket did"},
      handler: :handle_policy_promote
    },
    "policy.replay" => %{
      scope: :operate,
      timeout: @policy_replay_timeout,
      params:
        {:closed,
         [
           {"name", :required, :string, "a live lane-W rollout of kind `policy` on this node"},
           {"since", :optional, :string,
            "an ISO 8601 instant; only human answers recorded at or after it are replayed. Parsed here and refused as `-32602` when it is not one, because the corpus reads an unparseable instant as *no* filter — a typo would otherwise replay the whole corpus and the sealed report would state the typo as though it had narrowed it"}
         ],
         "`operate` rather than `read` because it stands a component up. It decides nothing: the instance is a dry one under its own name, no `:permission` entry and no evidence row is written, and the live instance is untouched"},
      handler: :handle_policy_replay
    },
    "policy.status" => %{
      scope: :read,
      timeout: @policy_status_timeout,
      params:
        {:closed, [],
         "node-local by construction and therefore without a `node` parameter: the promotion record and the corpus are where the decisions were made, so this asks the machine rather than routing to it. `tools` is one row per promoted `(tool, shape)` with `allowed` beside it, because a shape can be promoted and withdrawn and both facts are the answer. `evidence` is `Ouroboros.Control.PolicyEvidence.count/0`, bounded: a total, the two degraded counts, the **32 busiest tools** by count, and `other_tools`/`other_records` for the rest — the corpus is bounded by rows rather than by how many distinct tools those rows name. No verb serves a row of it: the corpus holds the exact request a policy component would have been shown, command lines and paths included. `durability` is how the record is kept — `ephemeral_checkpoint`, `synced_checkpoint`, `durable_checkpoint`, or `unavailable` when the authority itself did not answer, which is a different fact from an empty record and is why it is a value rather than a missing key"},
      handler: :handle_policy_status
    },
    "runtime.activity" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed, [],
         "the four kinds of work this node counts, and nothing else. `running_turns`, `queued_turns` and `busy_sessions` come from its live native session processes: an active turn, the turns it has accepted and not started, and the session's *own* idle predicate — the one that also refuses a maintenance fence, so a compaction or an unresolved approval is visible here even with no turn running. `in_flight_methods` is the operate-scope calls this node is executing, which is where `workspace.exec` and the other verbs that run in the caller's process rather than in a session are counted; read-scope calls are not. `attachment_transfers` and `attachment_normalizations` are the unexpired uploads and the decoder tasks the attachment service is holding. `operator_clients` is the connections this listener is serving, which includes the one asking. `silent_sessions` is how many live sessions did not answer inside their own deadline, which is the reason `unknown` names what it names. What is *not* counted: another machine's work (this is node-local — no fan-out), a read-scope call, and a session or a port that merely exists. Every counter this build cannot establish is `null` and named in `unknown`, and `idle` is `null` whenever any of them is, because an unknown runtime is not an idle one. `idle` is decided by the work counters alone: a connected client is somebody watching, not work, and the caller is always one of them. Answers may be up to 250ms old; `runtime.shutdown`'s gate reads the same summary freshly instead"},
      handler: :handle_runtime_activity
    },
    "runtime.models" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_runtime_models
    },
    "runtime.providers" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_runtime_providers
    },
    "runtime.shutdown" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"require_idle", {:optional, false}, :boolean,
            "stop only a runtime that is holding no work. The connection reads the same summary `runtime.activity` answers with, freshly rather than from its cache, and unless its `idle` is `true` it refuses `-32004` — before any acknowledgement is written or any stop scheduled — carrying `data.reason` `runtime_busy` or `activity_unknown` and `data.activity`. Unknown activity never authorizes a stop"}
         ],
         "answered by the connection, which requires `OUROBOROS_GATEWAY_ALLOW_SHUTDOWN=1` on top of operate scope. Closed, unlike most connection-answered verbs, because the difference between this envelope's two shapes is a node that stops and a node that does not: a misspelled `requireIdle` must be a refusal naming the key, never an unconditional stop"},
      handler: :connection
    },
    "runtime.status" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_runtime_status
    },
    "signing.decisions" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_signing_decisions
    },
    "wasm.deploy" => %{
      scope: :operate,
      timeout: @wasm_deploy_timeout,
      outcome: :unknown,
      params:
        {:closed,
         [
           {"upload", :required, :string,
            "a committed `wasm.upload` holding one `.ouro-wasm` bundle"},
           {"nodes", :optional, {:list, :node, 32}, "the targets; this node alone by default"},
           @authority_node
         ],
         "the bundle is parsed under its bounds and verified against the driving node's own trust policy before the store, the helper or the rollout register hears about it. A rollout that ran answers with its state — `live`, `rolled_back` or `quarantined` — rather than with an error"},
      handler: :handle_wasm_deploy
    },
    "wasm.download" => %{
      scope: :operate,
      timeout: @wasm_download_timeout,
      params:
        {:closed,
         [
           {"download", :required, :string,
            "the id a `wasm.sign` receipt named under `artifact.download`; this node minted it and no client may choose one"},
           {"offset", :required, :non_negative_integer,
            "a chunk boundary — a multiple of the receipt's `chunk_bytes`, below `size`. It is not a seek: a client walks the file with the offsets these answers hand it, and anything else is refused rather than answered with bytes from the middle of something"},
           @authority_node
         ],
         "the reply direction of `wasm.upload` (docs/WASM.md D28). A node hands out **only** bytes its own `wasm.sign` compiled and signed: there is no verb that puts one here, the slot is minted by `sign/2` alone, and what comes back is bound by the `sha256` the signed manifest already carries — repeated in every chunk, so a client checks each frame as well as the whole. `data` is base64 of at most the slot's `chunk_bytes` decoded bytes, and that number is **this node's own frame**: `min(512 KiB, (OUROBOROS_GATEWAY_MAX_FRAME - 1 KiB) * 3/4)`, because nothing on the outbound path is held to the frame and a reply larger than it is a line this node writes and its own client refuses. `final` marks the chunk that completes the artifact, and reading it **releases the slot** — a client that loses that answer signs again rather than asking twice. The slot count and the two clocks are `Ouroboros.Wasm.Upload`'s, read from that module rather than restated; the idle one is moved by a read, because nothing writes to a download after it is minted"},
      handler: :handle_wasm_download
    },
    "wasm.list" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed, [@authority_node],
         "`components[].sha256` names a component; nothing here is a filesystem path. `rollouts[].form` is which of the two forms this node loads that component from — `precompiled` when the signed manifest names an artifact for exactly this node's wasmtime and target triple and the store holds it, `source` otherwise, `null` where this node cannot say (no readable manifest, or no helper that has reported its build)"},
      handler: :handle_wasm_list
    },
    "wasm.rollback" => %{
      scope: :operate,
      timeout: @wasm_rollback_timeout,
      params:
        {:closed,
         [{"name", :required, :string, "the live lane-W capability to retire"}, @authority_node],
         "stops the wrapper agent on every node the entry names and marks the entry; the component bytes stay in the store (D6), so redeploying needs a new epoch and a new signature but no new build"},
      handler: :handle_wasm_rollback
    },
    "wasm.sign" => %{
      scope: :operate,
      timeout: @wasm_sign_timeout,
      params:
        {:closed,
         [
           {"upload", :required, :string,
            "a committed `wasm.upload` holding the component bytes"},
           {"name", :required, :string,
            "lower case, starting with a letter or digit, then letters, digits, `.`, `_`, `-`, at most 64 bytes; it is the register's module and the durable wrapper's id"},
           {"author", :required, :string, "provenance the signing policy requires"},
           {"imports", :required, {:list, :string, 8},
            "the imports the component declares, computed by the client with the operator's own helper (`ouro wasm inspect`). This node never parses unsigned bytes to find out; a list that does not match what the component imports is refused at stage by the cross-check, which is where a manifest that describes something else has always been caught"},
           {"precompile", {:optional, true}, :boolean,
            "whether this node compiles the component into wasmtime's serialized form at sign time and records its digest in the signed manifest (docs/WASM.md D22–D24). Default true, and honoured only where this node has an `ouro-wasm` on disk; the artifact travels in the bundle beside the source and is loaded on a target **only** where that node's own helper reports exactly this node's wasmtime version and target triple, which turns that node's `load` from a compile into a mapping. Every node that does not match compiles the source form under §7.3's bounds, so a precompiled bundle deploys everywhere an ordinary one does. `false` — `ouro wasm sign --no-precompile` — signs the source form alone, which is also what a node with no helper does and what happens when the artifact is too large to travel in this verb's reply"},
           {"kind", {:optional, "capability"}, {:either, const: "capability", const: "policy"},
            "what this component is, and therefore which of the helper's two closed worlds its bytes are ever admitted to. A `capability` answers mesh messages and is reachable by the `capability` tool; a `policy` answers permission requests for `Ouroboros.Wasm.PolicyEngine` and is reachable by neither. It is part of the **signed** manifest, so a policy deployed as a capability is refused at stage by the helper's world check and so is the reverse; a policy's `eval` is a list of cases rather than a list of probes, and a policy may declare no `start_config`"},
           {"language", :optional, :string, nil},
           {"source_sha256", :optional, :string, "64 lower-case hex"},
           {"start_config", :optional, :string,
            "the config the durable wrapper is started with; the id is derived from `name` and is never a parameter"},
           {"eval", :optional,
            {:object,
             [
               {"probes", :required, {:list, :object, 20},
                "each `{\"input\": <json>, \"expect\": {\"kind\": ..., ...}}` — `input` is the message body handed to the capability, whatever the capability itself calls it. The kinds are `any_reply`, `contains` (takes `substring`), `equals` (takes `value`) and `state_matches` (takes `key`, a state field this build already knows, and `value`). What each one is held against differs: `contains` matches its substring against the answer *rendered* as text, so it reads a decoded JSON object the way `inspect/1` writes one (`%{\"echo\" => …}`), while `equals` and `state_matches` compare terms — a `state_matches` on `last_answer` must be the whole decoded reply as JSON (`{\"echo\": {\"greet\": \"world\"}}`), not a string of it, and `messages_received` is the counter to reach for when the shape of the answer is not the point"},
               {"budget_ms", :optional, :positive_integer, "the deadline every probe runs under"},
               {"max_latency_ms", :optional, :positive_integer,
                "a gate on the latency observed, checked after the answer arrives"},
               {"required", :optional, {:either, [{:const, "all"}, :object]},
                "`\"all\"`, or `{\"at_least\": n}`"}
             ]},
            "the signed evaluation spec; required by default for lane W (D12) and refused by the signer when absent. There is no `initial_state`: what a capability is evaluated as is the deployment's statement, not the test's"},
           @authority_node
         ],
         "answers the bundle's **prefix** rather than the bundle: the client already holds the bytes it uploaded, and a sixteen-mebibyte result would need a chunked download to hand somebody their own file back. There is no `epoch` parameter: it is allocated over the connected cluster with `Ouroboros.Upgrade.Epoch.next/2`, because an epoch a client chose could be placed at the rollout register's plausibility ceiling, which leaves no number that is both fresh and plausible and wedges lane W on that node durably"},
      handler: :handle_wasm_sign
    },
    "wasm.status" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed, [@authority_node],
         "`helper.path` and `store.root` are basenames, not paths: both verbs are `read`, and an absolute path names an install prefix rather than anything about lane W"},
      handler: :handle_wasm_status
    },
    "wasm.upload" => %{
      scope: :operate,
      timeout: @wasm_upload_timeout,
      params:
        {:closed,
         [
           {"upload", :optional, :string,
            "the id a previous frame returned; omitted, this frame opens a new upload and the reply names it"},
           {"offset", :required, :non_negative_integer,
            "must equal what the node already holds; a mismatch answers `-32602` naming the offset it has, which is where to resume"},
           {"data", :required, :string,
            "base64 of at most 512 KiB of the file, bounded before it is decoded"},
           {"final", {:optional, false}, :boolean,
            "closes the upload: the bytes become readable by `wasm.sign` and `wasm.deploy`, and the reply carries their sha256"},
           @authority_node
         ],
         "the transport for bytes a JSON frame cannot carry (docs/WASM.md D16). An upload carries no authority: what comes out of it is verified by whichever verb consumes it, it is consumed once, and it is swept ten minutes after the last frame that touched it"},
      handler: :handle_wasm_upload
    },
    "workspace.browse" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"path", :optional, :string,
            "an absolute path inside one of `roots`; the first root by default, and a relative path is refused rather than resolved against the daemon's working directory"}
         ],
         "directories only, dotfiles excluded, name-sorted, and bounded at " <>
           "#{Browse.limit()} entries with `truncated` saying whether the list was cut"},
      handler: :handle_workspace_browse
    },
    "workspace.exec" => %{
      scope: :operate,
      timeout: @shell_timeout,
      outcome: :unknown,
      params:
        {:closed,
         [
           @session_id,
           {"command", :required, :string,
            "run through `/bin/sh -c` in the session's admitted workspace, on its owner node"},
           @session_node
         ]},
      handler: :handle_workspace_exec
    }
  }
  def approval_decisions, do: @approval_decisions
  def approval_scopes, do: @approval_scopes
  def configuration_options, do: @configuration_options
  def default_replay_limit, do: @default_replay_limit
  def default_timeout, do: @default_timeout
  def permission_decisions, do: @permission_decisions
  def permission_removable_scopes, do: @permission_removable_scopes
  def permission_rule_scopes, do: @permission_rule_scopes
  def permission_scopes, do: @permission_scopes
  def plan_exit_choices, do: @plan_exit_choices
  def policy_reason_bytes, do: @policy_reason_bytes
  def policy_shape_bytes, do: @policy_shape_bytes
  def policy_thresholds, do: @policy_thresholds
  def reasoning_efforts, do: @reasoning_efforts
  def replay_limit, do: @replay_limit
  def start_options, do: @start_options
  def wasm_deploy_timeout, do: @wasm_deploy_timeout
  def wasm_download_timeout, do: @wasm_download_timeout
  def wasm_rollback_timeout, do: @wasm_rollback_timeout
  def wasm_sign_timeout, do: @wasm_sign_timeout
  def wasm_upload_timeout, do: @wasm_upload_timeout

  # Setup belongs to the computer that will run the work. Keep this list explicit:
  # accepting a machine here must never turn into an arbitrary remote RPC facility.
  @machine_scoped ~w(audit.status audit.doctor audit.search audit.show audit.artifact audit.export audit.download audit.reindex audit.flush audit.retention audit.hold audit.purge runtime.providers runtime.models workspace.browse account.read
    account.login.start account.login.complete account.login.cancel account.logout
    credentials.anthropic.set credentials.xai.set)
  @methods Map.new(@methods, fn {name, entry} ->
             if name in @machine_scoped do
               params = Tuple.to_list(entry.params)

               descriptor =
                 {"machine", :optional, :string,
                  "connected fleet machine name or node; omitted means this runtime; never falls back locally"}

               params = List.update_at(params, 1, &(&1 ++ [descriptor])) |> List.to_tuple()
               {name, %{entry | params: params}}
             else
               {name, entry}
             end
           end)

  def machine_scoped?(name), do: name in @machine_scoped

  @table Map.new(@methods, fn {name, entry} -> {name, Map.drop(entry, [:params, :handler])} end)
  def table, do: @table

  def handler(name) do
    case Map.fetch(@methods, name) do
      {:ok, entry} -> {:ok, entry.handler}
      :error -> :error
    end
  end

  def params, do: Map.new(@methods, fn {name, entry} -> {name, normalize(entry.params)} end)

  def params(name) do
    case Map.fetch(@methods, name) do
      {:ok, entry} -> {:ok, normalize(entry.params)}
      :error -> :error
    end
  end

  def connection_answered, do: for({name, %{handler: :connection}} <- @methods, do: name)
  defp normalize({envelope, descriptors}), do: normalize({envelope, descriptors, nil})

  defp normalize({envelope, descriptors, note}) do
    %{
      envelope: envelope,
      note: note,
      params:
        Enum.map(descriptors, fn {name, requirement, type, note} ->
          %{name: name, requirement: requirement, type: type, note: note}
        end)
    }
  end

  # Type conversion, target resolution and domain-specific bounds remain with handlers.
  # This is the wire envelope: no separate accepted-key lists or required-key table.
  def validate(name, values) when is_map(values) do
    with {:ok, contract} <- params(name),
         :ok <- envelope(contract, values) do
      Enum.reduce_while(contract.params, :ok, fn param, :ok ->
        if param.requirement == :required and not Map.has_key?(values, param.name),
          do: {:halt, {:invalid, "params.#{param.name} is required"}},
          else: {:cont, :ok}
      end)
    end
  end

  def validate(_name, _values), do: {:invalid, "params must be an object"}
  defp envelope(%{envelope: :open}, _values), do: :ok

  defp envelope(contract, values) do
    case Map.keys(values) -- Enum.map(contract.params, & &1.name) do
      [] ->
        :ok

      unknown ->
        {:invalid,
         "params contains unsupported fields: #{Enum.sort(unknown) |> Enum.join(", ")}; it accepts " <>
           (contract.params |> Enum.map(& &1.name) |> Enum.sort() |> Enum.join(", "))}
    end
  end
end
