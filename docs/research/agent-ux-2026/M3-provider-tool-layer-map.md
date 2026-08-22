# M3 — Provider / Tool / Execution Layer Map

Repo: `/Users/monocursive/code/ouroboros`, branch `review-fixes`. All paths absolute-relative
to that root. Harness pinned at `mix.exs:59-60`
(`{:jido_harness, github: "agentjido/jido_harness", ref: "8bf0d52f4fed0d8a9d2594000d8b3a775da16f8b"}`),
vendored under `deps/jido_harness`. `{:jido_ai, "~> 2.3"}` is at `mix.exs:47`.

---

## 1. Provider architecture — Ouroboros drives external agent CLIs, it does not run a tool loop

### 1.1 What Ouroboros calls

Two planes, both of which hand a *request* to Harness and then poll it:

* **Coding plane** — `lib/ouroboros/coding/task.ex:353` calls `Run.start(task.provider, TaskState.request(task))`.
  One-shot finite run. Request built at `lib/ouroboros/coding/task_state.ex:354-374`.
* **Interactive plane** — `lib/ouroboros/interactive/task.ex:344` calls
  `Session.start(session.provider, State.request(session))`. Long-lived. Request built at
  `lib/ouroboros/interactive/state.ex:151-174`.

After start, the interactive coordinator **pulls** events:
`lib/ouroboros/interactive/task.ex:376-386` calls `Session.replay(harness_session_id, cursor:, limit: 100)`
on a 25 ms poll (`@poll_interval` at `lib/ouroboros/interactive/task.ex:16`), projects them through
`Ouroboros.Interactive.Event.from_harness/2` (`lib/ouroboros/interactive/event.ex:30-46`), checkpoints,
and fans out to subscribers by plain `send/2` (`lib/ouroboros/interactive/task.ex:1308-1310`).
There is no pub/sub bus for provider events.

Nothing in `lib/` calls an LLM with tools. The only `Jido.AI` usage is
`lib/ouroboros/control/jido_ai.ex:35` and `:51`, both `Jido.AI.Actions.LLM.GenerateObject`
(structured planning/evaluation, no tool list). `Ouroboros.Agent.Worker`
(`lib/ouroboros/agent/worker.ex:19`) uses `Jido.Agent`, **not** `Jido.AI.Agent`; its actions are
state projections plus the six grant-gated effects.

### 1.2 Provider registry and overrides

Built-ins: `deps/jido_harness/lib/jido_harness/registry.ex:6-16` —
`amp, claude, codex, gemini, kimi, opencode, grok, pi, zai`. Overrides merged from
`Application.get_env(:jido_harness, :providers)` at `registry.ex:20-21`.
Ouroboros overrides three at `config/config.exs:127-133`:
`codex → Ouroboros.Provider.CodexAdapter`, `kimi → Ouroboros.Provider.KimiAdapter`,
`opencode → Ouroboros.Provider.OpenCodeAdapter`, plus
`process_driver: Ouroboros.Provider.ProcessDriver`.

### 1.3 Per-provider table (transport / options / tool execution)

| provider | run transport | session transport (default) | session adapter | normalized options declared |
|---|---|---|---|---|
| `claude` | `claude --print --output-format stream-json --include-partial-messages --verbose` (`deps/.../adapters/claude.ex:90`) | `:stream_json_resume`, *managed* = re-exec per turn (`claude.ex:33-34`) | `SessionAdapters.Managed` | `claude.ex:35-47` incl. `:mcp_config`, `:allowed_tools`, `:disallowed_tools`, `:add_dirs`, `:approval_mode`, `:sandbox_mode` |
| `codex` (upstream) | `codex exec --json` (`adapters/codex.ex:84`) | `:exec_jsonl_resume` managed (`codex.ex:34-35`) | `SessionAdapters.Managed` | `codex.ex:36-45`; **no `:mcp_config`**, has `:attachments` |
| `codex` (Ouroboros) | same `exec --json` via `CodexAdapter.run/2` (`lib/ouroboros/provider/codex_adapter.ex:45-59`) | **`:app_server`** (`codex_adapter.ex:23-25`), `codex app-server --stdio` (`lib/ouroboros/provider/session/dialect/codex.ex:46`) | `Ouroboros.Provider.CodexSession` (`codex_session.ex:11`) | inherits adapter list (`session_options: :adapter`, `codex_adapter.ex:34`) |
| `gemini` | `gemini --prompt … --output-format stream-json` (`adapters/gemini.ex:81`) | `:stream_json_resume` managed (`gemini.ex:25-26`) | `SessionAdapters.Managed` | `gemini.ex:27-36`; `normalized_values.sandbox_mode` full set; MCP only via provider option `:allowed_mcp_server_names` (`gemini.ex:8, 89`) |
| `amp` | `amp --execute … --stream-json` (`adapters/amp.ex:85`) | `:stream_json_resume` managed (`amp.ex:40-41`) | `SessionAdapters.Managed` | `amp.ex:42` = `[:provider_session_id, :mcp_config, :reasoning_effort]` — **no approval/sandbox at all** |
| `opencode` | `opencode …` (`adapters/opencode.ex:72`) | **`:acp`** (`opencode.ex:39-57`), argv `["acp"]` | upstream `SessionAdapters.ACP`, **replaced** by `Ouroboros.Provider.Session.ACP` (`lib/ouroboros/provider/session.ex:32-33`) | adapter list `opencode.ex:58`; `normalized_values.approval_mode: [:default,:prompt,:auto_approve]` (`:59`). ACP transport `session_options: [:provider_session_id, :mcp_config, :env]` (`:53`) — **no `sandbox_mode`** |
| `kimi` | `kimi -p … --output-format …` | **`:acp`** (`adapters/kimi.ex:47-65`) | ditto (`Ouroboros.Provider.KimiAdapter.spec/0` → `upgrade_acp`, `kimi_adapter.ex:9`) | `kimi.ex:66-77`; `normalized_values` pins `approval_mode: [:default]` and `sandbox_mode: [:default]` |
| `pi` | `pi --mode …` (`adapters/pi.ex` build_argv ~`:216`) | `:rpc` → `SessionAdapters.PiRPC` (`pi.ex` spec ≈ lines 132-161) with `steer: :native`, `dynamic_model: :native`, `dynamic_configuration: :native` | `SessionAdapters.PiRPC` | `normalized_values.approval_mode: [:default, :auto_approve]`, `sandbox_mode: [:default, :read_only, :unrestricted]` — refuses `:prompt` |
| `grok` | `grok -p … --output-format` | `:streaming_json_resume` managed (`adapters/grok.ex:53-54`) | `SessionAdapters.Managed` | `grok.ex:55-65` |
| `zai` | delegates to `Claude.run/2` with rewritten env (`adapters/zai.ex:71`) | `:stream_json_resume` managed | `SessionAdapters.Managed` | `zai.ex:44-56` incl. `:mcp_config` |

**Where tools execute:** entirely inside the vendor CLI child process. Ouroboros never runs a tool.
Sandboxing is whatever the vendor enforces, selected by argv/params:
Codex `--sandbox read-only|workspace-write|danger-full-access` (`adapters/codex.ex:126-129`) or, on
app-server, the tagged `sandboxPolicy` object built at
`lib/ouroboros/provider/session/dialect/codex.ex:413-446`; Claude writes a `--settings` JSON with a
`sandbox` block (`adapters/claude.ex:124-137`); Gemini `sandbox_args`; Amp/OpenCode/Kimi have no
Ouroboros-selectable sandbox at all.

**Steer / interrupt / approvals / attachments per session transport**

* Managed transports (`claude`, `gemini`, `amp`, `grok`, `zai`, `codex` exec fallback):
  `SessionTransportSpec.managed/2` at `deps/.../session/transport_spec.ex:56-83` —
  `process: :per_turn`, `interrupt: :process` (kill the child), `multi_turn: :managed`,
  no `approvals`, no `steer`. `configuration_options: [:model, :reasoning_effort, :approval_mode, :sandbox_mode]`.
* ACP (`kimi`, `opencode`): `process: :persistent`, `interrupt: :native`, `approvals: :native`,
  `multimodal: :native`, `steer: false` (`adapters/kimi.ex:52-60`, `adapters/opencode.ex:44-52`).
* Codex app-server (Ouroboros): `lib/ouroboros/provider/session/dialect/codex.ex:25-36` —
  `interrupt: :native`, `approvals: :native`, `dynamic_model/dynamic_configuration: :managed`,
  **`multimodal` unset ⇒ false**. Consequence: a turn with `attachments` is refused by
  `deps/.../session/request_validator.ex:77-78` even though `turn_options: :adapter`
  (`codex_adapter.ex:35`) inherits `:attachments`. Interactive Codex cannot take image attachments.
* `steer` is declared **unsupported by both Ouroboros dialects** —
  `dialect/acp.ex:107` and `dialect/codex.ex:101` return `{:error, :unsupported}`, and neither
  transport declares the capability, so `SessionWorker` refuses at
  `deps/.../session/worker.ex:169,187`. `Ouroboros.InteractiveSession.steer/3`
  (`lib/ouroboros/interactive_session.ex:194-198`) is therefore live only for `pi`.

### 1.4 `safety_options/3` — the two-plane capability gate

`lib/ouroboros/provider.ex:1223-1249`. Plane defaults are
`[approval_mode: :prompt, sandbox_mode: :workspace_write]` (`provider.ex:46`).
Capability resolution: `provider.ex:1254-1261` reads `Registry.spec/1`, then
`normalized_options/2` picks the *adapter* list for `:coding` (`provider.ex:1278`) and the
*transport* list for `{:interactive, transport}` (`provider.ex:1284-1295`), honouring
`session_options: :adapter` inheritance. `@unset_values [nil, [], %{}, :default]` (`provider.ex:88`)
is always legal. Interactive silently omits an unacceptable default (`provider.ex:1235-1236`);
coding refuses with a named message (`provider.ex:1238-1239`, message at `provider.ex:1329-1343`).
Called from `lib/ouroboros/coding/task_state.ex:170` and, for interactive, via
`TaskState.new/4` with plane `{:interactive, transport}` (`lib/ouroboros/interactive/state.ex:107-115`).

### 1.5 Codex-specific runtime policy owned by Ouroboros

* Execution defaults `%{codex: %{skip_git_repo_check: true, network_access_enabled: true}}`
  (`provider.ex:53-56`), merged under caller options by `execution_options/2` (`provider.ex:92-107`).
* Six managed cache homes (`CARGO_HOME`, `MIX_HOME`, `MIX_ARCHIVES`, `HEX_HOME`,
  `REBAR_CACHE_DIR`, `REBAR_GLOBAL_CONFIG_DIR`) at `provider.ex:61-69`, materialised under
  `<data_dir>/provider-cache/codex` by `configure_runtime_cache/0` (`provider.ex:237-283`), and
  granted as `add_dirs` writable roots by `apply_execution_directories/3` (`provider.ex:204-231`);
  a stated `read_only` sandbox suppresses **all** `add_dirs` (`provider.ex:207-212`).
* A **managed launcher shell script** is written to `<cache>/bin/codex`
  (`provision_codex_launcher/4`, `provider.ex:653-664`) which `exec`s the real Codex with fixed
  `-c shell_environment_policy.set.<VAR>=<path>` args (`codex_cache_policy_args/1`, `provider.ex:458-470`).
  `enforce_managed_cli_path/2` (`provider.ex:183-193`) pins `cli_path` to that launcher on every
  request, so inline `provider_options.cli_path` cannot bypass it. When the effective policy
  cannot be verified (`verify_codex_cache_policy/3`, `provider.ex:478-510`) a **refusal launcher**
  that exits 78 is installed instead (`provider.ex:432-456`, `941-948`).
* `public_execution_policy/3` (`provider.ex:118-158`) is the redacted policy shown to clients;
  `interactive_approvals` is `true` only for app-server (`provider.ex:146-158`).

---

## 2. The ACP dialect (`lib/ouroboros/provider/session/dialect/acp.ex`)

**Client → agent, implemented**

* `initialize` — `initialize_params/1` at `acp.ex:55-68`. `protocolVersion: 1`;
  **`clientCapabilities.fs.readTextFile = false`, `writeTextFile = false`, `terminal = false`**
  (`acp.ex:58-61`). Ouroboros advertises no filesystem or terminal service.
* `session/new` with `{"cwd", "mcpServers"}` (`acp.ex:72-79`), or `session/load` with
  `sessionId` when a `provider_session_id` exists (`acp.ex:76-77`). `mcpServers` comes from
  `request.mcp_config` via `mcp_servers/1` (`acp.ex:286-289`) — list passthrough, map → `Map.values/1`.
* `session/prompt` (`acp.ex:88-94`) with `prompt_blocks/2` (`acp.ex:261-274`): text or structured
  content blocks, plus one `resource_link` block per attachment with `file://` URI (`acp.ex:270-273`).
* `session/cancel` as a notification, used for both interrupt and close
  (`acp.ex:97-104`).

**Agent → client, implemented**

* `session/update` notifications, mapped at `acp.ex:190-200`:
  `agent_message_chunk → :output_text_delta`, `agent_thought_chunk → :thinking_delta`,
  `tool_call → :tool_call`, `tool_call_update → :tool_result`, `plan → :plan_updated`,
  `usage_update → :usage`. **Everything else** — including ACP `diff` and
  `available_commands_update` — falls to the catch-all `:provider_event` with
  `%{"kind" => "acp_update"}` (`acp.ex:198`), i.e. it survives to the client as opaque raw but is
  not a normalized event.
* `session/request_permission` — the only server-to-client **request** served
  (`acp.ex:113-114`). Payload normalization `permission_payload/1` (`acp.ex:214-219`);
  reply `permission_result/2` (`acp.ex:221-235`) picks an `optionId` by kind ranking
  (`acp.ex:237-259`), or `{"outcome":"cancelled"}` when no option matches.
  On close, every pending approval is denied (`jsonl.ex:380-386`, `acp.ex:121-131`).

**Refused / stubbed**

* Any other server-to-client request → JSON-RPC `-32601` with
  `"Ouroboros serves no ACP methods on this connection"` (`acp.ex:16`, emitted by
  `lib/ouroboros/provider/session/jsonl.ex:246-260`). Verified by
  `test/provider/session_acp_test.exs:105-118`. This covers `fs/read_text_file`,
  `fs/write_text_file`, and all `terminal/*`.
* `steer/3` → `{:error, :unsupported}` (`acp.ex:107`).
* `configure/2` → `{:error, :unsupported}` (`acp.ex:110`). There is no `session/set_mode` anywhere.

**Reachable ACP agents today:** `opencode` and `kimi` only — those are the two adapters whose
specs declare an `:acp` transport, and the two Ouroboros re-points at its own runtime
(`lib/ouroboros/provider/session.ex:28-35`; `opencode_adapter.ex:9`, `kimi_adapter.ex:9`).
`gemini` and `claude` have **no** ACP transport in this Harness ref (both are
`stream_json_resume` managed). Codex is reached through app-server JSON-RPC, a different dialect.
`Dialect.ACP.command/2` (`acp.ex:32-48`) is generic: any future ACP CLI works by pointing
`cli_path` at it with argv `["acp"]`.

**Shared JSONL runtime** (`lib/ouroboros/provider/session/jsonl.ex`): one GenServer per session;
routes on `method`-with-`id` first (`jsonl.ex:227-262`) so an approval is never mistaken for an
RPC reply; correlates by id otherwise (`jsonl.ex:264-274`); `{:send,...}` refuses when a turn is
active (`:busy`, `jsonl.ex:91-93`) or the session id is not yet known (`:not_ready`, `:95-97`).
Dialect contract is a **required-callback behaviour** with 18 callbacks
(`lib/ouroboros/provider/session/dialect.ex:57-77`) verified by `Dialect.verify!/1` (`dialect.ex:81-104`);
the shipped list is `[Dialect.Codex, Dialect.ACP]` (`session.ex:22-24`).

---

## 3. Ouroboros vs. vendor CLI — the ownership line

**Vendor CLI owns:** tool selection and execution, file reads/writes/edits, shell command
execution, its own sandbox enforcement, its own MCP client, its own permission prompts
(surfaced to Ouroboros only as `approval_requested` events), its own context/compaction.

**Ouroboros owns:**

* **Durable intent & replay.** Session/turn state in `lib/ouroboros/interactive/state.ex`,
  events in `lib/ouroboros/interactive/event.ex`, checkpointed before dispatch
  (`interactive/task.ex:696-707`).
* **Workspace admission and leases.** `lib/ouroboros/workspace.ex` (`acquire_managed/4` at
  `:71-78`), `lib/ouroboros/workspace/manager.ex`, symlink-safe canonicalization in
  `lib/ouroboros/workspace/path.ex:7-16` (`@max_symlinks 64`, `:4`). Admission at
  `interactive/task.ex:1621-1653`; release at `:1708-1717`. Modes `:exclusive | :shared_read`,
  default derived from sandbox mode (`coding/task_state.ex:405-406`).
* **Attachment authorization.** Every turn attachment must canonicalize *inside* the leased
  workspace root — `interactive/task.ex:859-895`, failure `{:attachment_outside_workspace, path}`.
* **umask at the provider process boundary.** `lib/ouroboros/provider/process_driver.ex:23-34`
  wraps every Harness CLI/ACP child in `priv/provider-exec`, which is literally
  `#!/bin/sh` / `umask 022 || exit 126` / `exec "$@"` (`priv/provider-exec:1-3`). The managed BEAM
  runs at `077`; the child gets conventional `0644/0755` in the operator's workspace.
  The wrapper is verified regular + executable before use (`process_driver.ex:42-54`).
* **Env passing.** Session env = provider config env, merged with dialect env, merged with
  request env (`jsonl.ex:26`), `env_mode: :overlay | :replace`. Inline `env`/`env_mode` are
  **refused** on the durable API (`coding/task_state.ex:28, 195-196` →
  `:inline_environment_not_persisted`).
* **Secret redaction, two lanes.** `lib/ouroboros/harness_event_projection.ex:27-39`
  (`before_journal/2` with an explicit extra-secrets list) and `:43-46` (`durable_fields/1`,
  baseline only). `CodexAdapter.run/2` derives the secret set from the *effective* env
  (`codex_adapter.ex:50`) and redacts both `payload` and `raw` (`codex_adapter.ex:67-78`).
  Every projected event is redacted again at `interactive/event.ex:39`.
* **Approval relay only.** `InteractiveSession.respond_approval/3`
  (`interactive_session.ex:201-205`) → `interactive/task.ex:179-182` → `Session.respond_approval`
  → dialect `approval_reply/2`. Ouroboros does not *decide*; it forwards a human decision.
  Gateway surface `interactive.respond_approval` at `lib/ouroboros/gateway/methods.ex:207`.
* **Public policy projection.** `Provider.public_execution_policy/3` (`provider.ex:118-158`)
  and `State.public/1` (`interactive/state.ex:196-238`).

**Grants do NOT cover vendor tool calls — verified.** `lib/ouroboros/control/grants.ex:68-78`
constrains exactly six effects (`start_agent, stop_agent, send_message, delegate, forge, deploy`),
each against one allow-list. The moduledoc says so explicitly at `grants.ex:36-38`
("Grants gate the *action layer*: the typed signals an agent handles through
`Ouroboros.Agent.Effects`") and `lib/ouroboros/runtime/capabilities.ex:9-10` repeats it
("`Control.Grants` are not consulted — those grants are for mesh agent effect signals").
The effect ledger (`lib/ouroboros/agent/effect_ledger.ex`) records those six effects, not tool calls.
Nothing in `lib/ouroboros/agent/*` observes a `:tool_call` event.

---

## 4. Jido.Harness internals relevant to extension

* **Adapter registration:** static `@builtins` map + application override merge
  (`registry.ex:6-22`). Validity check is duck-typed: `spec/0`, `run/2`, `status/1` exported
  (`registry.ex:74-77`). `Registry.spec/1` re-parses the spec on every call (`registry.ex:42-62`) —
  `Provider.capability/2` caches it per call for that reason (`provider.ex:1254`).
* **Normalized option schema:** `deps/.../adapter_spec.ex:6-23`
  (`normalized_options`, `normalized_values`, `provider_options`, `request_defaults`,
  `session_transports`, `default_session_transport`). Provider options may not shadow
  normalized ones (`adapter_spec.ex:90, 95`). Session request schema:
  `deps/.../session/request.ex:32-59` — includes `mcp_config: Zoi.any()` (`:43`) and the four
  timeouts (`:52-55`). Turn request schema: `deps/.../session/turn_request.ex:7-19`.
* **Validation:** runs against the adapter list (`run/request_resolver.ex:49-85`); sessions against
  the *transport* list, inheriting via `:adapter` (`session/manager.ex:156-158`, and
  `session/request_validator.ex:172-173`).
* **Defaults merge:** run defaults from `provider_config.request_defaults`
  (`request_resolver.ex:28, 36-40`); session defaults from `provider_config.session_defaults`
  (`deps/.../session.ex:117-124`) — note this only applies on the map path, not when a
  `%SessionRequest{}` struct is passed (`session.ex:104-112`).
* **Event normalization:** 29 canonical types at `deps/.../event.ex:15-45`, including
  `:tool_call`, `:tool_result`, `:file_change`, `:plan_updated`, `:approval_requested`,
  `:approval_resolved`, `:provider_event`. `raw` is explicitly not persisted (`event.ex:6-9`).
* **Hooks / middleware:** **none.** There is no pre/post hook, no plugin list, no telemetry
  interception point that can *modify* or *veto* an event. The only interposition points are
  (a) replacing the adapter module in `:jido_harness, :providers` (what
  `CodexAdapter.run/2` already does with `Stream.map/2` at `codex_adapter.ex:53-54`), and
  (b) replacing the `:process_driver` (what `ProcessDriver` already does).
* **In-process adapter:** architecturally supported. `Jido.Harness.Adapter`
  (`deps/.../adapter.ex:15-21`) requires only `spec/0`, `run/2 → {:ok, Enumerable.t(Event.t())}`,
  `status/1`; nothing forces a subprocess — `deps/jido_harness/test/support/test_adapter.ex:47-60`
  is a pure in-memory adapter. `Jido.Harness.SessionAdapter` (`deps/.../session/adapter.ex:18-26`)
  takes an opaque `handle` (a pid) and `open/send/interrupt/close` + optional
  `steer/respond_approval/configure`; `Ouroboros.Provider.Session.Jsonl` is exactly such a
  GenServer, and an in-process one would simply not spawn a child.
* **`jido_ai` gives the loop pieces:** `Jido.AI.Agent` macro with `:tools` as `Jido.Action`
  modules, `:max_iterations`, `:tool_timeout_ms`, `:tool_max_retries`, ReAct strategy
  (`deps/jido_ai/lib/jido_ai/agent.ex:3-60`); `Jido.AI.ToolAdapter.from_actions/2` converting
  actions → `ReqLLM.Tool` (`deps/jido_ai/lib/jido_ai/tool_adapter.ex:38-59`);
  `deps/jido_ai/lib/jido_ai/actions/tool_calling/{call_with_tools,execute_tool,list_tools}.ex`.
  **`jido_ai` has no MCP client** — `grep -rli mcp deps/jido_ai/lib` and `deps/jido/lib` return nothing.

---

## 5. Extension seams

### (a) LSP manager / diagnostics feedback

Nothing exists. `grep -rniE "\blsp\b|language.?server"` over `lib/` and `tui/src` returns only
unrelated "diagnostic" strings (`lib/ouroboros/upgrade/forge/sandbox.ex`, `tui/src/model.rs`).

Concrete injection seams, best first:

1. **Per-turn prompt envelope.** `lib/ouroboros/interactive/task.ex:811-817`
   (`expose_turn_request/2`) already rewrites every turn's prompt through
   `Exposure.wrap_turn_request_capture/2` (`lib/ouroboros/runtime/exposure.ex:149-154`), which
   wraps text in `<ouroboros-runtime …>` (`exposure.ex:158-168`). A diagnostics block appended
   there reaches **every** provider and transport, because it is just prompt text. The delimiter
   discipline is already enforced (`AgentProfile.reserved_delimiter?`, `task.ex:820-826`), and the
   captured envelope is durable (`interactive/state.ex:130-131`, `runtime_snapshot`) so replay
   reproduces bytes exactly. This is the only universally-carryable channel.
2. **`follow_up`** — `interactive_session.ex:148-150` → `Session.follow_up` queues an extra turn.
   Works on every transport (`follow_up: :managed` everywhere) but costs a model turn.
3. **`steer`** — `interactive_session.ex:194-198`. Dead for all Ouroboros providers today
   (§1.3); only `pi` declares `steer: :native`.
4. **Trigger point for running the LSP:** the `:file_change` event
   (`deps/.../event.ex:36`), produced by Codex app-server at
   `dialect/codex.ex:149-151` and `:288-290`, and by exec-JSONL via `CLIMapper.codex`.
   The coordinator sees it in `persist_harness_events/2` (`interactive/task.ex:389-419`).
   ACP does **not** emit `:file_change` — its `diff` update falls to the catch-all
   (`dialect/acp.ex:198`), so an ACP-based LSP trigger would have to match
   `provider_event` payload `%{"kind" => "acp_update"}`.

### (b) MCP client / offering tools to a vendor CLI

What each transport *can* carry:

* **Claude / Zai run+managed session:** `--mcp-config` with a JSON string or a map wrapped as
  `%{"mcpServers" => value}` (`adapters/claude.ex:157-159`, `:98`). Fully capable.
* **Amp:** `CLIArgs.json_pair("--mcp-config", request.mcp_config)` (`adapters/amp.ex:92`).
* **ACP (`opencode`, `kimi`):** `mcpServers` on `session/new`
  (`lib/ouroboros/provider/session/dialect/acp.ex:72`, `:286-289`), and the transport declares
  `:mcp_config` in `session_options` (`adapters/opencode.ex:53`, `adapters/kimi.ex:61`).
* **Gemini:** cannot receive server definitions — only `--allowed-mcp-server-names`
  (`adapters/gemini.ex:8, 89`) filtering servers Gemini already has configured.
* **Codex exec:** `mcp_config` is not in `normalized_options` (`adapters/codex.ex:36-45`);
  the resolver refuses it (`request_resolver.ex:49-68`).
* **Codex app-server:** `thread_params/1` (`dialect/codex.ex:381-386`) sends only
  `cwd/model/approvalPolicy/sandbox(Policy)`; argv is hardcoded `["app-server", "--stdio"]`
  (`dialect/codex.ex:46`). The **only** fixed-argv injection point is
  `codex_cache_policy_args/1` (`lib/ouroboros/provider.ex:458-470`), which emits `-c key=value`
  pairs baked into the managed launcher (`provider.ex:653-664`). Adding
  `-c mcp_servers.<name>.command=…` there would apply to both exec and app-server. Note
  `provider.ex:76-77` states the pinned adapter "deliberately exposes no arbitrary Codex argv
  escape hatch". Codex already reports MCP activity: `mcpToolCall` items map to
  `:tool_call`/`:tool_result` (`dialect/codex.ex:257-259, 271-272, 323-345`).

**The blocking fact: Ouroboros refuses `mcp_config` at its own API.**
`lib/ouroboros/coding/task_state.ex:28` puts it in `@rejected_inline_options`, and `:198-199`
returns `{:error, :inline_mcp_config_not_persisted}` (predicate at `:425`). The interactive plane
lists `:mcp_config` as a *known* option name (`interactive/state.ex:382`) but routes through
`TaskState.new/4` (`interactive/state.ex:107-115`), so it is rejected there too. The gateway does
not expose it either (`lib/ouroboros/gateway/methods.ex:257-259` documents the omission;
`@start_options` at `:262-276`). The seam to relax is those two lines plus a durable-safety story
for server commands.

### (c) Hooks (pre/post tool use)

No hook system, and **no event bus**. `lib/ouroboros/signals.ex` is nine `Jido.Signal` types for
the *agent mesh* (`ouroboros.agent.message`, `…task.assigned`, six `…effect.*`, `…effect.settled`)
— none carries a tool call. Provider events reach consumers only by:

* `Jido.Harness.SessionAdapter.emit/2` → `send(owner, {:session_adapter_event, event})`
  (`deps/.../session/adapter.ex:30-33`) into the Harness `SessionWorker`;
* `Ouroboros.Interactive.Task` polling `Session.replay/2` (`interactive/task.ex:376-386`);
* fan-out `send(pid, {:ouroboros_interactive_event, session_id, event})`
  (`interactive/task.ex:1308-1310`) to processes registered via
  `handle_call({:subscribe, pid, cursor}, …)` (`interactive/task.ex:123-138`).

The two realistic hook attachment points, both *observe-only in-band*:

1. **Adapter wrapper** — `lib/ouroboros/provider/codex_adapter.ex:52-58` already demonstrates
   `Stream.map(events, &before_journal/2)` on the run lane. A post-tool-use hook belongs there
   (and in an equivalent wrapper for other providers). It runs **after** the tool already executed.
2. **Dialect action list** — `lib/ouroboros/provider/session/dialect.ex:22-25` defines an
   `action()` type (`{:assign, …} | {:emit, …} | {:emit_event, …}`) applied at
   `jsonl.ex:366-378`. A hook could be a new action variant. A *pre*-tool-use hook is only
   possible where the vendor asks first — i.e. `approval_request/2`
   (`dialect/acp.ex:113`, `dialect/codex.ex:107-108`), which is the natural place for a
   deny/allow policy engine, since Ouroboros already holds the reply.

### (d) Worktree per session

None. `grep -rni worktree lib/ tui/src` matches exactly two lines, both in a comment:
`lib/ouroboros/workspace.ex:10-13` — "Git worktree creation is intentionally outside this
component. A future provisioner should create a worktree without shell interpolation, verify the
resulting directory here, acquire its lease, and record cleanup as a separate recoverable
operation. Admission never mutates a repository." There is **no other git awareness in `lib/`**.
The seam is `Ouroboros.Workspace.acquire_managed/4` (`workspace.ex:71-78`), called from
`interactive/task.ex:1655-1681`: a provisioner would create the worktree, then hand its path in.
`Workspace.Path.canonicalize/1` (`workspace/path.ex:7-16`) and `within?/2` (`:38-41`) already
give the containment guarantee. Also relevant: Ouroboros forces `skip_git_repo_check: true` for
Codex (`provider.ex:54`) precisely because it does not guarantee a repo.

---

## 6. Non-functional facts

* **Where provider processes run.** On the session's **owner node**. `Interactive.Task.init/1`
  refuses a session whose `node` is not `node()` (`interactive/task.ex:51, 70-71`); remote calls
  are `:erpc` to the owner (`interactive_session.ex:357-369`). Below that:
  Harness `SessionSupervisor → SessionWorker → SessionTransportSupervisor →
  Ouroboros.Provider.Session.Jsonl` → `context.process_manager.start_owned_process/2`
  (`jsonl.ex:21-39`, manager wired at `deps/.../session/worker.ex:41`) →
  `Ouroboros.Provider.ProcessDriver` (`config/config.exs:133`) → erlexec with
  `[:link, {:group, 0}, :kill_group, {:cd, spec.cwd}]`
  (`deps/.../process/driver/erlexec.ex:13`).
* **Surviving client disconnect.** Sessions are caller-independent by construction
  (`interactive_session.ex:24`). The gateway holds nothing; subscribers are monitored and
  dropped (`interactive/task.ex:1470-1476`). A reconnecting client calls
  `interactive.subscribe` with a cursor (`gateway/methods.ex:164`) and gets an atomic
  subscribe+backlog (`interactive_session.ex:126-130`).
* **Crash / restart recovery.** `Ouroboros.Interactive.Recovery` sweeps every 1 s
  (`interactive/recovery.ex:8`), restarting coordinators for non-terminal local sessions older
  than a 2 s grace (`recovery.ex:9, 63-76`). Coordinator restart re-admits the workspace
  (`task.ex:55`) with up to 25 reacquire attempts at 4 ms (`task.ex:19-20, 1655-1681`) to survive
  a stale self-lease.
* **`:lost` semantics.** `lose/2` at `interactive/task.ex:1232-1251`: finalize unresolved turns
  as `{:session_lost, reason}`, status `:lost`, persist, release the workspace lease, answer all
  waiters, schedule retire. Reached when `Session.replay` answers `{:error, :not_found}`
  (`task.ex:384`) — i.e. the Harness session is gone but the Ouroboros checkpoint remains.
  `:lost` is terminal (`interactive/state.ex:99`) and a `start/1` on that id returns
  `{:created, ref, {:session_start_failed, error}}` (`interactive_session.ex:48-51`).
* **Timeouts / limits.**
  * Session transport startup: `@startup_timeout 30_000`
    (`lib/ouroboros/provider/session/adapter.ex:7`).
  * OS process start: `startup_timeout_ms` default `15_000`
    (`deps/.../process/spec.ex:30`), but the JSONL session sets
    `runtime_timeout_ms: :infinity, idle_timeout_ms: :infinity` (`jsonl.ex:29-30`).
  * Harness session/turn timeouts default `:infinity`
    (`deps/.../session/request.ex:52-55`); scheduled in `deps/.../session/timers.ex:8-44`.
    Ouroboros exposes `turn_runtime_timeout_ms`, `turn_idle_timeout_ms`,
    `session_idle_timeout_ms`, `approval_timeout_ms` as session options
    (`interactive/state.ex:8-14`) but the **gateway does not** (`gateway/methods.ex:262-276`).
  * Control-plane calls: `@default_call_timeout 30_000` (`interactive_session.ex:21`,
    config key `:session_call_timeout` at `config/config.exs:111`); `await/3` threads the
    caller's timeout plus `@remote_margin_ms 5_000` (`interactive_session.ex:22, 381`).
  * Gateway ceilings: `interactive.start` / `coding.start` `120_000` with `outcome: :unknown`
    (`gateway/methods.ex:117, 189, 212`); most others `@default_timeout`; handshake `10_000`
    (`:133`); replay page `@replay_limit 500` (`:110`).
  * Readiness / unresolved-turn deadlines both `10 min`
    (`interactive/task.ex:22-23`; config `interactive_unresolved_turn_deadline_ms` at
    `config/config.exs:117`).
  * Output caps: event buffer `1 MiB` default (`deps/.../buffer.ex:9`), journal segments
    `8 MiB`, disk limit `256 MiB` (`deps/.../retention_options.ex:8-9`), text tail bounded by
    `max_bytes` (`deps/.../text_tail.ex:28-34`). Ouroboros retains `event_limit` events per
    session, default `10_000`, max `100_000` (`interactive/state.ex:33`,
    `coding/task_state.ex:398`). Retry backoff caps at `5 s` (`interactive/task.ex:21`).
  * Process cancellation: INT → TERM → KILL with `5 s` grace each
    (`deps/.../process/worker.ex:7, 51-52, 183, 278`).
  * Codex cache-policy probe: `5 s`, clamped to `30 s` (`provider.ex:83, 627-636`).

---

## 7. GAP LIST — code intelligence and tool-surface parity

| # | Gap | Seam it attaches to (file:line) | What the transport can / cannot carry |
|---|---|---|---|
| 1 | **No LSP manager.** Zero language-server code anywhere. | New per-workspace supervisor beside `Ouroboros.Workspace` children (`lib/ouroboros/application.ex:198-203`); lifecycle keyed to the lease (`workspace.ex:71-78`), torn down at `interactive/task.ex:1708-1717`. | Out-of-band: LSP is Ouroboros-local, no transport involvement. |
| 2 | **No diagnostics feedback into a turn.** | Inject at `interactive/task.ex:811-817` (`expose_turn_request/2` → `Exposure.wrap_turn_request_capture/2`, `runtime/exposure.ex:149-154`); trigger on `:file_change` seen in `interactive/task.ex:389-419`. | Prompt text carries everywhere. `steer` is unavailable on every Ouroboros provider (`dialect/acp.ex:107`, `dialect/codex.ex:101`) — do not design around it. `follow_up` works but burns a turn. ACP emits no `:file_change`; you must match `provider_event`/`"acp_update"` (`dialect/acp.ex:198`). |
| 3 | **No MCP client, and MCP config is refused at the API.** | Unblock `lib/ouroboros/coding/task_state.ex:28` + `:198-199` (+ `:425`), then surface it at `lib/ouroboros/gateway/methods.ex:262-276`. | Carriable: Claude/Zai `--mcp-config` (`adapters/claude.ex:157-159`), Amp `--mcp-config` (`adapters/amp.ex:92`), ACP `mcpServers` on `session/new` (`dialect/acp.ex:72`, declared at `adapters/opencode.ex:53`, `adapters/kimi.ex:61`). **Not carriable:** Codex exec (no `:mcp_config` in `adapters/codex.ex:36-45`); Codex app-server (`thread_params/1`, `dialect/codex.ex:381-386`, argv fixed at `:46`) — only via `-c` args baked into the managed launcher at `lib/ouroboros/provider.ex:458-470`; Gemini can only *filter* names (`adapters/gemini.ex:89`). |
| 4 | **No hooks (pre/post tool use) and no event bus.** `lib/ouroboros/signals.ex` is mesh-agent signals only. | Post-hook: adapter wrapper, as `codex_adapter.ex:52-58` already does with `Stream.map/2`; or a new dialect `action()` variant (`dialect.ex:22-25`, applied at `jsonl.ex:366-378`). Pre-hook: `approval_request/2` (`dialect/acp.ex:113`, `dialect/codex.ex:107-108`) — the one point where the vendor asks before acting. | Managed transports have **no approvals capability at all** (`transport_spec.ex:56-71`), so a pre-tool hook is structurally impossible for claude/gemini/amp/grok/zai/codex-exec. Only ACP and Codex app-server can be gated. |
| 5 | **No native tool loop.** No read/edit/bash/grep tool owned by Ouroboros. | `Jido.Harness.Adapter` needs only `spec/0`+`run/2`+`status/1` (`deps/.../adapter.ex:15-21`); `SessionAdapter` needs only a pid handle (`deps/.../session/adapter.ex:18-26`). Register it at `config/config.exs:127-133`. Loop machinery: `Jido.AI.Agent` (`deps/jido_ai/lib/jido_ai/agent.ex:3-60`), `Jido.AI.ToolAdapter.from_actions/2` (`deps/jido_ai/lib/jido_ai/tool_adapter.ex:38-59`), `deps/jido_ai/lib/jido_ai/actions/tool_calling/*`. | Fully in-Ouroboros: normalized events, native approvals, real LSP/MCP integration, real grants. Cost: none of `jido_ai`/`jido` ships an MCP client, so that must be written too. |
| 6 | **No worktree per session.** | `Ouroboros.Workspace.acquire_managed/4` (`workspace.ex:71-78`) called from `interactive/task.ex:1655-1681`; containment already provided by `workspace/path.ex:7-16, 38-41`. Design note is `workspace.ex:10-13`. | Transport-neutral: the vendor only ever sees `cwd` (`jsonl.ex:24`, `dialect/acp.ex:72`, `dialect/codex.ex:382`). Cleanup must be a recoverable operation, and `skip_git_repo_check: true` (`provider.ex:54`) would need revisiting. |
| 7 | **Interactive Codex cannot take attachments.** | `Dialect.Codex.capabilities/0` omits `multimodal` (`lib/ouroboros/provider/session/dialect/codex.ex:25-36`); refused at `deps/.../session/request_validator.ex:77-78`. | One-line capability fix *if* `turn/start` input blocks accept images; `turn_params/1` currently builds only a text block (`dialect/codex.ex:388-397`). |
| 8 | **ACP `diff`, `available_commands`, `session/set_mode` unmapped.** | `map_update/2` catch-all at `dialect/acp.ex:198`; `configure/2` stub at `:110`. | ACP can carry all three; nothing downstream would break — it is purely additive mapping plus a capability flip. |
| 9 | **No `fs/*` or `terminal/*` service to ACP agents.** | Declared off at `dialect/acp.ex:58-61`; any such request is `-32601` (`jsonl.ex:246-260`, message `dialect/acp.ex:16`, test `test/provider/session_acp_test.exs:105-118`). | Serving these would put file reads/writes and terminal execution **inside Ouroboros**, which is the single highest-leverage change: it is the same seam an LSP/MCP/hook layer needs, and it would let Ouroboros mediate ACP tool I/O without a native loop. |
