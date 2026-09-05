defmodule Ouroboros.Gateway.Methods.Contract do
  @moduledoc "Wire method metadata, parameter envelopes and dispatch targets, defined together."
  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.CodeIntel
  alias Ouroboros.Gateway.Methods.Browse
  @default_timeout 15000
  @agent_message_timeout 45000
  @default_agent_message_timeout_ms 5000
  @max_agent_message_timeout_ms 30000
  @max_agent_message_bytes 64 * 1024
  @max_agent_id_bytes 512
  @code_intel_max_wait_ms 10000
  @wasm_download_timeout 15000
  @wasm_upload_timeout 15000
  @wasm_sign_timeout 60000
  @wasm_deploy_timeout 180_000
  @wasm_rollback_timeout 30000
  @replay_limit 500
  @default_replay_limit 100
  @start_timeout 120_000
  @approval_prompt_timeout 15 * 60 * 1000
  @delegate_timeout 90000
  @shell_timeout 10 * 60 * 1000
  @compaction_timeout 120_000
  @forge_timeout 120_000
  @replay_verify_timeout 120_000
  @team_timeout 60000
  @hello_deadline 10000
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
    "provider" => :provider,
    "workspace" => :string,
    "model" => :string,
    "system_prompt" => :string,
    "max_turns" => :positive_integer,
    "event_limit" => :event_limit,
    "approval_mode" => {:enum, @approval_modes},
    "sandbox_mode" => {:enum, @sandbox_modes},
    "reasoning_effort" => {:enum, @reasoning_efforts},
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
    "plan" => :boolean,
    "mode" => :string
  }
  @worker_options %{"role" => :string, "node" => :node}
  @delegation_options %{
    "id" => :string,
    "coding_node" => :node,
    "workspace" => :string,
    "provider" => :provider
  }
  @interactive_delegation_options %{"workspace" => :string, "provider" => :provider}
  @control_options %{"id" => :string, "max_revisions" => :non_negative_integer}
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
    "mode" =>
      "the *agent's* own mode id, validated against the `availableModes` it published; refused by name on a transport whose dialect declares none",
    "plan" => "not a Harness configuration key — it takes its own per-transport path (B2)"
  }
  @configuration_params (for {name, kind} <- Enum.sort(@configuration_options) do
                           {name, :optional, kind, Map.get(@configuration_option_notes, name)}
                         end)
  @worker_params (for {name, kind} <- Enum.sort(@worker_options) do
                    {name, :optional, kind,
                     if(name == "node") do
                       "the machine the worker runs on"
                     else
                       nil
                     end}
                  end)
  @delegation_params (for {name, kind} <- Enum.sort(@delegation_options) do
                        {name, :optional, kind,
                         if(name == "id") do
                           "caller-owned delegation id"
                         else
                           nil
                         end}
                      end)
  @interactive_delegation_params (for {name, kind} <-
                                        Enum.sort(@interactive_delegation_options) do
                                    {name, :optional, kind, "defaults to the conversation's own"}
                                  end)
  @control_params (for {name, kind} <- Enum.sort(@control_options) do
                     {name, :optional, kind, nil}
                   end)
  @session_id {"id", :required, :string, "the interactive session id"}
  @session_node {"node", :optional, :node,
                 "the machine that owns the session; this one by default"}
  @task_id {"id", :required, :string, "the coding task id"}
  @task_node {"node", :optional, :node, "the machine that owns the task; this one by default"}
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
                          {"prompt", :required, :string, nil},
                          {"attachments", :optional, {:list, :string, 32},
                           "each must be an existing regular file the leased workspace contains"},
                          {"reasoning_effort", :optional, {:enum_of, @reasoning_efforts}, nil}
                        ]
                      ]}, nil}
  @turn_id_param {"turn_id", :optional, :string,
                  "caller-supplied; resending the same `{id, input, turn_id}` returns the same turn rather than starting a second"}
  @methods %{
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
    "agents.list" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_agents_list
    },
    "agents.message" => %{
      scope: :operate,
      timeout: @agent_message_timeout,
      params:
        {:closed,
         [
           {"to", :required, :string,
            "the agent id, at most #{@max_agent_id_bytes} bytes; a lane-W capability is `wasm/<name>`"},
           {"body", :required, :json,
            "the message body, any JSON value, at most #{@max_agent_message_bytes} bytes encoded"},
           {"from", :optional, :string,
            "who the message is from, at most #{@max_agent_id_bytes} bytes; defaults to `gateway`"},
           {"timeout_ms", :optional, {:integer, 1, @max_agent_message_timeout_ms},
            "how long to wait for the agent; defaults to #{@default_agent_message_timeout_ms}"}
         ],
         "`reply` is the agent's `last_answer` and is **untrusted**: for a lane-W capability it is prose and JSON the component wrote. It is returned whole when it encodes within #{@max_agent_message_bytes} bytes and as a marked, truncated string otherwise, which is what `truncated` distinguishes. A message an agent refused is still a delivered message: this verb says the agent answered nothing, and `agents.state` says why"},
      handler: :handle_agents_message
    },
    "agents.state" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:open, [{"id", :required, :string, "the agent id"}],
         "for a lane-W capability (`wasm/<name>`) the answer additionally carries `untrusted: true` and `truncated`, and `agent.state.last_answer`/`last_message` are bounded at 64 KiB with an in-band marker: both are written by a component, and this verb is `read`"},
      handler: :handle_agents_state
    },
    "agents.stop" => %{
      scope: :operate,
      timeout: @default_timeout,
      params: {:open, [{"id", :required, :string, "the agent id"}]},
      handler: :handle_agents_stop
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
    "code_intel.diagnostics" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"workspace", :required, :string, nil},
           {"path", :required, :string, nil},
           {"wait_ms", :optional, {:integer, 0, @code_intel_max_wait_ms},
            "how long to wait for the cache to describe the file's current content"},
           @authority_node
         ]},
      handler: :handle_code_intel_diagnostics
    },
    "code_intel.request" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"workspace", :required, :string,
            "narrows the marker walk and can never widen it; `/` is refused rather than obeyed"},
           {"operation", :required, {:enum_mfa, {CodeIntel, :operations, []}}, nil},
           {"path", :required, :string, nil},
           {"line", {:optional, 0}, :non_negative_integer, "0-based, as the protocol reports it"},
           {"character", {:optional, 0}, :non_negative_integer, "0-based"},
           {"query", :optional, :string, "for the two symbol searches"},
           @authority_node
         ]},
      handler: :handle_code_intel_request
    },
    "code_intel.touch" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"workspace", :required, :string, nil},
           {"path", :required, :string, nil},
           {"action", :required, {:enum, ["changed", "closed", "ensure_open", "open"]},
            "`ensure_open` is the one to reach for when asking about a file; `open` re-reads it and assigns a new version"},
           @authority_node
         ]},
      handler: :handle_code_intel_touch
    },
    "coding.cancel" => %{
      scope: :operate,
      timeout: @default_timeout,
      params: {:closed, [@task_id, @task_node]},
      handler: :handle_coding_cancel
    },
    "coding.delete" => %{
      scope: :operate,
      timeout: @default_timeout,
      params: {:closed, [@task_id, @task_node], "terminal tasks only"},
      handler: :handle_coding_delete
    },
    "coding.event_detail" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:closed, [@task_id, @sequence_param, @task_node]},
      handler: :handle_coding_event_detail
    },
    "coding.info" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:closed, [@task_id, @task_node]},
      handler: :handle_coding_info
    },
    "coding.list" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_coding_list
    },
    "coding.replay" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:closed, [@task_id, @cursor_param, @limit_param, @task_node]},
      handler: :handle_coding_replay
    },
    "coding.respond_approval" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           @task_id,
           {"request_id", :required, :string, "the id the approval_requested event carried"},
           @approval_response_param,
           @task_node
         ]},
      handler: :handle_coding_respond_approval
    },
    "coding.start" => %{
      scope: :operate,
      timeout: @start_timeout,
      outcome: :unknown,
      params: {:closed, [{"objective", :required, :string, nil} | @start_params]},
      handler: :handle_coding_start
    },
    "coding.subscribe" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed, [@task_id, @cursor_param, @task_node],
         "answered by the connection itself, because the plane registers the calling process"},
      handler: :connection
    },
    "coding.unsubscribe" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:closed, [@task_id, @task_node]},
      handler: :connection
    },
    "computer_use.artifact" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:closed,
         [
           {"sha256", :required, :string,
            "the content hash of a staged screenshot from a tool_result artifact; served as base64 from this node only"},
           {"session_id", :optional, :string,
            "native provider session id whose desktop/ dir to search; omitted, only the live helper pool's session dirs are searched"},
           @authority_node
         ]},
      handler: :handle_computer_use_artifact
    },
    "computer_use.probe" => %{
      scope: :operate,
      timeout: @default_timeout,
      params: {:closed, [@authority_node]},
      handler: :handle_computer_use_probe
    },
    "computer_use.status" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:closed, [@authority_node]},
      handler: :handle_computer_use_status
    },
    "control.cancel" => %{
      scope: :operate,
      timeout: @default_timeout,
      params: {:open, [{"id", :required, :string, "the control run id"}]},
      handler: :handle_control_cancel
    },
    "control.get" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, [{"id", :required, :string, "the control run id"}]},
      handler: :handle_control_get
    },
    "control.list" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_control_list
    },
    "control.submit" => %{
      scope: :operate,
      timeout: @default_timeout,
      params: {:closed, [{"objective", :required, :string, nil} | @control_params]},
      handler: :handle_control_submit
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
    "fleet.revoke" => %{
      scope: :operate,
      timeout: 15000,
      params:
        {:closed, [{"artifact", :required, :string, "CA-attested revocation, at most 16 KiB"}]},
      handler: :handle_fleet_revoke
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
    "grok.account.login.cancel" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed,
         [{"login_id", :required, :string, "the loginId returned by grok.account.login.start"}]},
      handler: :handle_grok_account_login_cancel
    },
    "grok.account.login.start" => %{
      scope: :operate,
      timeout: @default_timeout,
      params:
        {:closed, [],
         "starts `grok login --device-auth`; the first-party CLI owns and refreshes every subscription token"},
      handler: :handle_grok_account_login_start
    },
    "grok.account.read" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:closed, []},
      handler: :handle_grok_account_read
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
      params:
        {:closed,
         [@session_id, {"focus", :optional, :string, "what the fold should keep"}, @session_node]},
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
      params: {:closed, [@session_id, @session_node]},
      handler: :handle_interactive_context
    },
    "interactive.delegate" => %{
      scope: :operate,
      timeout: @delegate_timeout,
      outcome: :unknown,
      params:
        {:closed,
         [
           @session_id,
           {"objective", :required, :string, nil},
           {"delegation_id", :optional, :string,
            "caller-owned; a repeat under the same id answers with the same delegation rather than a second one"},
           @session_node | @interactive_delegation_params
         ]},
      handler: :handle_interactive_delegate
    },
    "interactive.delegations" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:closed, [@session_id, @session_node]},
      handler: :handle_interactive_delegations
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
           {"handoff_id", :optional, :string, "caller-owned id for the child"},
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
    "interactive.request_approval" => %{
      scope: :operate,
      timeout: @approval_prompt_timeout,
      params:
        {:closed,
         [
           @session_id,
           {"request", :required,
            {:object,
             [
               {"tool_name", :required, :string, nil},
               {"input", :optional, :object, "the tool's own arguments"},
               {"tool_use_id", :optional, :string, nil},
               {"cwd", :optional, :string, "the directory the tool would run in"}
             ]}, "a closed object; nothing else is accepted"},
           @session_node
         ]},
      handler: :handle_interactive_request_approval
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
    "plans.get" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, [{"id", :required, :string, "the plan id"}]},
      handler: :handle_plans_get
    },
    "plans.list" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_plans_list
    },
    "runtime.lsp.status" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_runtime_lsp_status
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
        {:open, [],
         "answered by the connection, which requires `OUROBOROS_GATEWAY_ALLOW_SHUTDOWN=1` on top of operate scope"},
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
    "teams.add_worker" => %{
      scope: :operate,
      timeout: @team_timeout,
      params:
        {:closed,
         [
           {"team_id", :required, :string, "must name a team running on this node"},
           {"worker_id", :required, :string, nil} | @worker_params
         ]},
      handler: :handle_teams_add_worker
    },
    "teams.cancel" => %{
      scope: :operate,
      timeout: @team_timeout,
      outcome: :unknown,
      params:
        {:open,
         [
           {"team_id", :required, :string, "must name a team running on this node"},
           {"delegation_id", :required, :string, nil}
         ]},
      handler: :handle_teams_cancel
    },
    "teams.close" => %{
      scope: :operate,
      timeout: @team_timeout,
      outcome: :unknown,
      params: {:open, [{"team_id", :required, :string, "must name a team running on this node"}]},
      handler: :handle_teams_close
    },
    "teams.delegate" => %{
      scope: :operate,
      timeout: @team_timeout,
      params:
        {:closed,
         [
           {"team_id", :required, :string, "must name a team running on this node"},
           {"worker_id", :required, :string, nil},
           {"objective", :required, :string, nil} | @delegation_params
         ]},
      handler: :handle_teams_delegate
    },
    "teams.list" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_teams_list
    },
    "teams.state" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, [{"id", :required, :string, "the team id"}]},
      handler: :handle_teams_state
    },
    "upgrade.history" => %{
      scope: :read,
      timeout: @default_timeout,
      params:
        {:open,
         [
           {"module", :required, :string,
            "a module this node has loaded, with or without the `Elixir.` prefix; an unknown name is `-32602`, never a new atom"}
         ]},
      handler: :handle_upgrade_history
    },
    "upgrade.rollouts" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_upgrade_rollouts
    },
    "upgrade.status" => %{
      scope: :read,
      timeout: @default_timeout,
      params: {:open, []},
      handler: :handle_upgrade_status
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
  def code_intel_max_wait_ms, do: @code_intel_max_wait_ms
  def configuration_options, do: @configuration_options
  def control_options, do: @control_options
  def default_agent_message_timeout_ms, do: @default_agent_message_timeout_ms
  def default_replay_limit, do: @default_replay_limit
  def default_timeout, do: @default_timeout
  def delegation_options, do: @delegation_options
  def interactive_delegation_options, do: @interactive_delegation_options
  def max_agent_id_bytes, do: @max_agent_id_bytes
  def max_agent_message_bytes, do: @max_agent_message_bytes
  def max_agent_message_timeout_ms, do: @max_agent_message_timeout_ms
  def permission_decisions, do: @permission_decisions
  def permission_removable_scopes, do: @permission_removable_scopes
  def permission_rule_scopes, do: @permission_rule_scopes
  def permission_scopes, do: @permission_scopes
  def plan_exit_choices, do: @plan_exit_choices
  def reasoning_efforts, do: @reasoning_efforts
  def replay_limit, do: @replay_limit
  def start_options, do: @start_options
  def wasm_deploy_timeout, do: @wasm_deploy_timeout
  def wasm_download_timeout, do: @wasm_download_timeout
  def wasm_rollback_timeout, do: @wasm_rollback_timeout
  def wasm_sign_timeout, do: @wasm_sign_timeout
  def wasm_upload_timeout, do: @wasm_upload_timeout
  def worker_options, do: @worker_options

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
