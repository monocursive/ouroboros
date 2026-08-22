# Ouroboros TUI & Distribution

Status: implemented operator/runtime contract (updated 2026-08-20). Companion to
[ARCHITECTURE.md](ARCHITECTURE.md). Future ideas are labelled explicitly; fleet setup for
normal operators lives in [FLEET.md](FLEET.md) and the README rather than in environment
variables below.

## 0. Summary

One Rust binary, `ouro`, is the product a person downloads. It embeds the Elixir
release, extracts and supervises it as a child daemon, and renders a Ratatui
terminal UI over a narrow, token-authenticated, loopback-default TCP protocol.
The BEAM runtime keeps everything that makes Ouroboros what it is — hot loading,
forged `Ouroboros.Capability.*` modules, cluster roles, the upgrade lanes. The
TUI is a projection, never an authority the runtime depends on.

Design invariants, in the codebase's own idiom:

1. **The gateway is an operator surface and says so.** It is not "an observer".
   Its mutating verbs are scoped and audited. A configured deployment gets the
   listener only by asking (`OUROBOROS_GATEWAY=1`); the one exception is the
   told-nothing prod release — no gateway, node, or cluster variables at all —
   which enables the loopback surface itself, because a single-machine daemon
   nobody can talk to serves nobody. Honest claims only.
2. **Fail closed.** No token, no listener. The defaulted single-machine posture
   satisfies this rather than escaping it: it generates a 0600 `gateway.token`
   before the listener starts, so a credential always exists — the exception is
   who typed it, not whether it is required. Non-loopback bind requires a typed
   override, exactly like `OUROBOROS_ALLOW_INSECURE_DIST` in
   [config/runtime.exs](../config/runtime.exs).
3. **Bounded everything.** The planes are *not* uniformly bounded upstream —
   `InteractiveSession.start/1` waits `:infinity` for provider readiness
   ([interactive_session.ex:37](../lib/ouroboros/interactive_session.ex)),
   `Team.cancel/2` and `close/1` call at `:infinity`
   ([team.ex:92](../lib/ouroboros/team.ex)), `add_worker`/`delegate` bound at
   60s. So the gateway imposes its own per-method ceiling on every call it
   makes (§2.4), runs each request in a supervised task, and answers
   `-32005` when the ceiling passes. Every per-connection queue is bounded
   with an explicit overflow behavior. No `:infinity` escapes onto the wire.
4. **Polymorphism survives as data.** Wire payloads are self-describing trees.
   A forged capability that appears tomorrow renders through the TUI's generic
   value-tree widget today, with zero Rust changes.
5. **The gateway is unpatchable.** `Elixir.Ouroboros.Gateway.` joins
   `@protected_prefixes` in
   [verifier.ex:32](../lib/ouroboros/upgrade/verifier.ex). A runtime that can
   author code must not be able to author its own operator-auth away.

---

## 1. Architecture

```
ouro (Rust, single binary)
├─ embeds: ouroboros release tarball (per-target, sha256-pinned at build)
├─ spawn mode: extract → supervise `bin/ouroboros start` → connect
├─ attach mode: connect only (--addr/--token-file, or local gateway.json)
└─ ratatui UI ── line-framed JSON-RPC 2.0 ── 127.0.0.1 TCP ──┐
                                                             │
ouroboros release (BEAM, unchanged planes)                   │
└─ Ouroboros.Gateway (new, :core role only, tail of tree) ◄──┘
   ├─ Gateway.Listener      (:gen_tcp acceptor)
   ├─ Gateway.ConnSupervisor (DynamicSupervisor)
   └─ Gateway.Conn × N      (per-connection handler; owns socket,
                             subscriptions, bounded outbound queue)
```

Zero new Elixir deps (Elixir ≥ 1.18 ships `JSON`; the project pins `~> 1.20` in
[mix.exs](../mix.exs)). Zero shared state between connections. One slow client
stalls only itself.

### Trust model (honest limits, up front)

- The token is **transport authentication, not a sandbox**. A connection with
  `operate` scope is an operator console, comparable to a remote shell minus
  raw `:erpc`.
- Loopback is the security boundary by default. Remote attach is **SSH tunnel**
  (`ssh -L 4560:127.0.0.1:4560 host`). `OUROBOROS_GATEWAY_ALLOW_REMOTE=1`
  exists for trusted networks and is cleartext — the refusal message says so.
- Event payloads are already redacted at construction
  ([interactive/event.ex:37](../lib/ouroboros/interactive/event.ex)); the
  gateway adds no new raw surface. Status/state maps may still carry workspace
  paths and objectives — same trust domain as the operator.
- One authenticated gateway is the operator entrance to its **connected BEAM
  fleet**. Session lists fan out with bounded calls, session references retain
  their owner node, and calls/subscriptions route to that owner over distribution.
  This does not federate unrelated clusters and does not make the gateway's
  cleartext TCP listener safe to expose; the listener remains loopback-only.

---

## 2. Elixir side: `Ouroboros.Gateway`

### 2.1 Supervision & placement

New files under `lib/ouroboros/gateway/`:

| file | module | role |
|---|---|---|
| `gateway.ex` | `Ouroboros.Gateway` | Supervisor; validates config at init (fail-closed, signer-style) |
| `gateway/config.ex` | `Gateway.Config` | pure env→config parsing + validation (unit-testable) |
| `gateway/listener.ex` | `Gateway.Listener` | `:gen_tcp` listen + accept loop; hands sockets to ConnSupervisor |
| `gateway/conn.ex` | `Gateway.Conn` | per-connection GenServer: framing, auth, dispatch, subscriptions, outbound queue. Requests dispatch to supervised tasks (≤ 8 in flight, ≤ 64 waiting, per connection); responses correlate by id and may return out of order, so one slow method never blocks the event stream or other requests |
| `gateway/writer.ex` | `Gateway.Writer` | the socket's single writer: a process spawned and linked by its `Conn` whose only job is the blocking `:gen_tcp.send/2` the `Conn` must not make (§2.6) |
| `gateway/wire.ex` | `Gateway.Wire` | term → JSON-safe encoding (builds on `Orchestration.Serializable`) |
| `gateway/methods.ex` | `Gateway.Methods` | method table: name → {scope, handler, timeout} |

Started only in `children(:core)`
([application.ex:94](../lib/ouroboros/application.ex)), **at the absolute
tail, after `Ouroboros.Cluster`**. Under `rest_for_one` a gateway crash
restarts nothing; nothing rebuilds from it. `:builder`/`:signer` nodes never
run it.

Enabled when `OUROBOROS_GATEWAY=1`, and by the defaulted single-machine prod
posture (no gateway, node, or cluster variables set), where
[config/runtime.exs](../config/runtime.exs) enables it at `operate` scope
itself. Explicitly enabled without a token source it refuses to start (raises
at init, naming the variable) — the signer-boot posture; the defaulted posture
instead generates `<data_dir>/gateway.token` (0600, never overwriting an
existing file) because nobody named a source there to have gotten wrong.

### 2.2 Configuration (config/runtime.exs additions, same inline-parse style)

| env | default | meaning |
|---|---|---|
| `OUROBOROS_GATEWAY` | unset | `1` enables the listener (core role only). Unset on a prod release that also has no node or cluster variables → enabled by default at `operate` scope, `allow_shutdown` on, with a generated token: the single-machine posture. That branch reads no other `OUROBOROS_GATEWAY_*` variable — tuning anything means setting `OUROBOROS_GATEWAY=1` and being held to the token requirement |
| `OUROBOROS_GATEWAY_PORT` | `0` | `0` = ephemeral; the bound port is published via `gateway.json` |
| `OUROBOROS_GATEWAY_BIND` | `127.0.0.1` | non-loopback additionally requires `OUROBOROS_GATEWAY_ALLOW_REMOTE=1`, else raise |
| `OUROBOROS_GATEWAY_TOKEN_FILE` | — | preferred: file (0600) containing ≥32-byte token; `Inspect`-redacted like the signer key |
| `OUROBOROS_GATEWAY_TOKEN` | — | fallback for dev; discouraged in docs (env is visible to same-user processes) |
| `OUROBOROS_GATEWAY_SCOPE` | `read` | `read` \| `operate`; mutating methods refused under `read` |
| `OUROBOROS_GATEWAY_ALLOW_SHUTDOWN` | unset | `1` additionally enables `runtime.shutdown` (spawner sets it; server operators generally don't) |
| `OUROBOROS_GATEWAY_MAX_FRAME` | `1048576` | max inbound line bytes; oversized → typed error, connection closed |
| `OUROBOROS_GATEWAY_QUEUE_LIMIT` | `1000` | per-connection **outbound** frame cap (see §2.6). The inbound bound — requests accepted and not yet dispatched — is a fixed constant (64) in `Gateway.Conn`, not this variable: one name for two queues is a name an operator cannot reason about |
| `OUROBOROS_GATEWAY_EVENT_LEAF_BYTES` | `131072` | most bytes one string inside an event `payload` may put on the wire; beyond it the string is excerpted (§2.7). Floor 1024 |
| `OUROBOROS_GATEWAY_EVENT_PAYLOAD_BYTES` | `524288` | most bytes *all* of one event's payload strings may put on the wire together, per event (§2.7). Floor 1024 |
| `OUROBOROS_GATEWAY_DETAIL_LEAF_BYTES` | `8388608` | the per-string cap `interactive.event_detail` / `coding.event_detail` encode under (§2.4). Floor 1024 |

Two placement facts the implementation must respect:

- **Everything in [config/runtime.exs](../config/runtime.exs) today sits
  inside `if config_env() == :prod`** (line 3). Gateway env parsing goes in a
  new section *outside* that guard so `ouro --dev` (`mix run --no-halt`) works
  — `runtime.exs` is evaluated in every env.
- **`OUROBOROS_DATA_DIR` is persisted to app env in every environment.** The
  prod block persists the directory it resolved — including the derived
  default (`Ouroboros.DataDir`: `$XDG_DATA_HOME/ouroboros`, else
  `$HOME/.local/share/ouroboros`, the byte-for-byte contract with
  `Paths::discover` in [tui/src/runtime.rs](../tui/src/runtime.rs)) — and the
  gateway section below persists the variable in the environments the prod
  block never runs in. `OUROBOROS_GATEWAY=1` still requires it (raise naming
  the variable otherwise); the spawner always sets it.
- **The durable leaf is private before anything beneath it is touched.** Rust and
  BEAM both require a real same-UID directory at exactly 0700, creating a missing leaf
  atomically at that mode. Before it takes over the terminal, the packaged client can
  safely restrict a same-UID legacy leaf only when it derived that XDG default itself.
  An explicit override, symlink, foreign owner, or non-directory still fails closed
  without replacement and names the safe operator choices: inspect it and repair it
  only if it is truly yours, or choose a fresh absolute `OUROBOROS_DATA_DIR`. Every
  managed child gets umask 077, including Ring output, so
  Jido stores and later log generations cannot inherit a normal caller's 022 posture.
  At the last Harness boundary, Harness-managed provider subprocesses restore workspace
  umask 022, yielding conventional 0644 files and 0755 directories whether the runtime
  uses Ring or service output.

After binding, the gateway writes `Path.join(data_dir, "gateway.json")` through an
exclusive random temporary inode made 0600 before its bytes, synced, inode-checked, and
atomically renamed:
`{"port": .., "protocol": 1, "node": "..", "pid": <os_pid>, "birth": "..", "scope": "..",
"token_file": ".."}`.
This is how spawn-mode `ouro` (and no-arg `ouro attach`) discovers the port;
it also removes the bind-race of pre-choosing ephemeral ports.

`token_file` is the **path** to the token file and is present exactly when a file
supplied the token — `OUROBOROS_GATEWAY_TOKEN_FILE`, or the defaulted posture's own
`gateway.token`, generated there if absent; a listener whose token came from
`OUROBOROS_GATEWAY_TOKEN` omits the key entirely rather than naming a file that does not
exist. It exists so a client that did not spawn the daemon — `ouro attach` with no
arguments — reads the credential's location instead of guessing a convention. The token
*value* is never in this file: `gateway.json` says where to look, and the 0600 file it
points at is the thing that has to be readable. A deployment using the environment token
is, by that same rule, not discoverable — which is one more reason the file is preferred.

`gateway.json` is only discovery. The core runtime separately hard-link-claims a private
`runtime.owner` before durable children start and releases it last on orderly shutdown.
Dead-owner replacement is serialized by the advisory lock on the persistent, versioned
`runtime.owner.recovery` inode. A trusted native helper holds it across the complete
claim, and its Port closing on a claimant or VM crash releases the kernel lock so a
supervised retry can recover unattended. A legacy or malformed gate still fails closed
for one explicit operator inspection because it may belong to an older active runtime.

The Rust client's shorter-lived `spawn.lock` also publishes a fully written private PID
and process-birth inode by atomic hard link. Dead claims are replaced only by the holder
of the advisory lock on the persistent, versioned `spawn.lock.recovery` inode; every
loser re-reads or refuses and never unlinks. Process death releases that kernel lock, so
ordinary crash recovery needs no manual gate removal. Legacy or malformed gates retain
the conservative one-time inspection contract.

### 2.3 Protocol

Line-delimited JSON-RPC 2.0 subset over TCP: requests `{jsonrpc, id, method,
params}`, responses `{jsonrpc, id, result | error}`, server notifications
`{jsonrpc, method, params}` (no id). No batches. One JSON object per `\n`-
terminated line. Protocol version is a single integer, **1**.

**Handshake.** First frame must be `hello`:

```json
{"jsonrpc":"2.0","id":1,"method":"hello",
 "params":{"token":"…","protocol":1,"client":"ouro 0.1.0"}}
```

Result: `{server: "0.1.0", node, role, protocol: 1, scope, methods: [...]}`
(`server` from `Application.spec(:ouroboros, :vsn)`; `methods` is the exact
list this build serves, so the client feature-gates instead of guessing).

**`hello.methods` is the feature gate, and it is the only one.** A client decides whether
an optional verb exists by membership in that list, not by trying it and reading the
error — `ouro`'s quit dialog offers `runtime.shutdown` when it is listed and falls back to
SIGTERM when it is not. Note what the list does *not* encode: scope. A read listener
still advertises the operate verbs it will refuse with `-32003`, because hiding them would
make a deliberately less-authorized listener look like an older build.

- Any frame before a successful `hello` → error `-32001 unauthenticated`,
  socket closed.
- Token check: `:crypto.hash_equals(:crypto.hash(:sha256, presented),
  :crypto.hash(:sha256, expected))` — hashing first makes lengths equal, so
  `hash_equals/2` can neither raise nor leak length.
- `protocol != 1` → error `-32002 protocol_mismatch` with `{server_protocol:
  1}`, socket closed. The client renders the upgrade hint.
- Hello not completed within 10s → close.

**Errors** are JSON-RPC standard (`-32700` parse, `-32601` unknown method,
`-32602` invalid params) plus application codes: `-32001 unauthenticated`,
`-32002 protocol_mismatch`, `-32003 scope_denied`, `-32004 unavailable`
(plane down / not configured), `-32005 upstream_timeout`, `-32006
upstream_error` (with `Wire`-encoded reason), `-32007 not_found` (e.g.
`Scheduler.get/2` returns a bare `:not_found`, not an error tuple).
Malformed input is answered and survived, never crashed on. Honest caveat:
`status.availability` is process liveness
([ouroboros.ex:152](../lib/ouroboros.ex)), so a wedged-but-alive plane
surfaces as `-32005`, not `-32004` — the TUI treats both as "plane
unhealthy".

Two error `data` payloads are **structured and branched on** rather than displayed,
and the golden fixtures (§2.11) pin both: `-32006` carrying
`{"reason": "cursor_pruned", "floor": N}` (§2.5), and `-32005` carrying
`{"outcome": "unknown"}` on the verbs whose upstream call is `:infinity` (§2.4
intro). Every other `data` is a `Wire`-encoded reason meant to be read, not matched.

**`params` is an object or absent — never an array.** JSON-RPC 2.0 allows positional
parameters; this subset does not, and an array answers `-32602` rather than being
interpreted. Every method here names its parameters, and a positional form would be a
second calling convention to keep correct in two languages. Likewise every request must
carry an `id`: there are no client notifications, and a frame without one is `-32600`,
because a request with nowhere to send an answer is a request the client cannot learn the
fate of.

**Inbound hygiene.** Client params are plain JSON. The dispatcher never calls
`String.to_atom/1` on client data: methods dispatch via a literal map, enum
params (e.g. approval responses) validate against explicit allowlists, ids
stay binaries (every plane API already takes string ids).

### 2.4 Method catalog (v1)

Every handler runs in a supervised task under a per-method gateway timeout
(default **15_000ms**; exceptions in the table). Timeout → `-32005`. Every
upstream call is made in the `safe_call` posture (`try/rescue/catch :exit`) —
several planes exit rather than error when down (e.g.
`NodeExecutor.status/1`'s bare `GenServer.call`,
[node_executor.ex:240](../lib/ouroboros/upgrade/node_executor.ex); `Ouroboros.status/0`
itself only survives via its own `safe_value/2`) — a `:noproc`/`:timeout`
exit becomes `-32004`/`-32005`, never a dead Conn.

For verbs whose upstream call is `:infinity` (`teams.cancel`, `teams.close`),
a gateway timeout does **not** cancel the upstream operation — it may still
complete. The response says so (`"outcome": "unknown"`), and the verbs are
observable after the fact via `teams.state`, so the client reconciles by
reading.

**`read` scope**

| method | maps to |
|---|---|
| `runtime.status` | `Ouroboros.status/0` ([ouroboros.ex:13](../lib/ouroboros.ex)) |
| `runtime.providers` | `Ouroboros.providers/0` + per-provider `provider_status/1`, each probed under its own bounded task |
| `account.read` `{}` | `CodexAppServer.read/1` — Codex account identity plus managed-login state. Every account result is projected through an explicit key allowlist inside the provider process (`account.type`/`email`/`planType`, `requiresOpenaiAuth`, and the four-field `login` map), so "no token crosses the gateway" is a property of this module, not of Codex's current response shape. Sign-in URLs and device codes never appear here — they exist only in `account.login.start`'s operate-scoped reply |
| `agents.list` | `Mesh.list_agents/0` |
| `agents.state` `{id}` | `Mesh.state/1` |
| `interactive.list` / `coding.list` | `InteractiveSession.list/0` / `CodingSession.list/0` |
| `interactive.info` `{id}` | `InteractiveSession.info/1`. `options.approval_mode`/`options.sandbox_mode` are `null` when the plane omitted an unenforceable default — the provider's own behavior governs — where they previously always echoed the plane default. Also carries `options.capabilities` and `usage`, described below |
| `interactive.replay` `{id, cursor, limit}` | `InteractiveSession.replay/2` (cursor exclusive, limit ≤ 500) |
| `interactive.event_detail` `{id, sequence, node}` | The one event at `sequence`, whole — `replay` with `cursor: sequence - 1, limit: 1`, same owner routing and the same 15s ceiling. Answers a **bare event object**, not the single-element array `replay` would give. It exists because streamed and replayed events are byte-capped (§2.7), so this is where a client fetches the leaf an `_excerpt` named: the answer is encoded under `detail_leaf_bytes` (8 MiB) rather than `event_leaf_bytes` (128 KiB), and a leaf past even *that* carries the same `_excerpt` marker. Below the retained floor → `-32006` `{"reason": "cursor_pruned", "floor": N}`, the same shape `replay`/`subscribe` answer with; above the high-water mark, or inside a sequence gap, → `-32007` (a window of one starting in a gap returns the *next* event that exists, and answering with an event nobody asked for would be a worse lie than not finding it) |
| `interactive.subscribe` `{id, cursor}` | `InteractiveSession.subscribe/2` **called from the Conn process** so `{:ouroboros_interactive_event, id, event}` lands in its mailbox; returns backlog after cursor atomically |
| `interactive.unsubscribe` `{id}` | `InteractiveSession.unsubscribe/1` |
| `coding.info/replay/subscribe/unsubscribe/event_detail` | `CodingSession` equivalents (`{:ouroboros_coding_event, id, event}`); `coding.event_detail` `{id, sequence, node}` is the coding-plane twin of the row above, refusals and all |
| `teams.list` | `Team.Store.list/0`, projected as in `status/0` |
| `teams.state` `{id}` | `Team.state/1` via `Team.whereis/1` |
| `plans.list` / `plans.get` `{id}` | `Orchestration.Scheduler.list/0` / `Scheduler.get/2` (server is the *first* arg with a default; bare `:not_found` → `-32007`) |
| `control.list` / `control.get` `{id}` | `Ouroboros.Control.list/0`, `get/1` |
| `upgrade.status` | `Upgrade.NodeExecutor.status/0` (exits when the executor is down — safe_call wrapper mandatory) |
| `upgrade.rollouts` | `Upgrade.Rollout.Registry.list/0` |
| `upgrade.history` `{module}` | `Registry.history/1` — module resolved via `String.to_existing_atom` inside a rescue; unknown → `-32602` |
| `signing.decisions` | bounded `:erpc.call(signing_node, Signing.Service, :decisions, [])` — requires `OUROBOROS_SIGNING_NODE` configured **and** `Node.alive?()` (a `OUROBOROS_DIST=none` daemon cannot erpc), else `-32004`. Upstream failure shape is `{:error, {:signing_service_unavailable, _}}`, a nested tuple |
| `grants.list` `{principal}` | `Control.Grants.list/1` (per-principal by design — there is no list-all, and the gateway does not add one). `Grants.list/1` swallows `:exit` into `[]` ([grants.ex:159](../lib/ouroboros/control/grants.ex)), so the handler pre-checks `Process.whereis(Grants)` to answer `-32004` instead of a false empty |
| `permissions.list` `{scope?, workspace?, node?}` | `Control.Permissions.list/1` on the named machine (local by default; a remote one is a bounded `:erpc`, so an unreachable machine is reported as unreachable rather than as a gateway timeout). Returns the `:node` rules read from `config :ouroboros, :permissions` alongside the stored `:user`/`:workspace`/`:session` ones, each with `id`, `pattern`, `kind`, `decision`, `scope`, `workspace`, `session_id`, `created_at`, and `fragile` — the last true for an argument-constraining `Bash` pattern, which is accepted but easy to route around |
| `fleet.status` | `Cluster.fleet_status/0` — expected/connected/offline machines, compatibility, TLS posture |
| `fleet.doctor` | `Cluster.fleet_doctor/0` — live fleet checks merged with host-local certificate/interface/port/log/service facts |

**`operate` scope** (additionally require `scope=operate`; each call emits one
`Logger` audit line: method, param digest, connection peer)

| method | maps to |
|---|---|
| `fleet.forget_session_owner` `{machine, accept_state_loss: true}` | Explicit local retirement of both durable session-owner evidence planes. Requires the exact machine in the validated local profile's signed-roster tombstones, refuses a connected node, and syncs the checkpoint before success. Ordinary invite cancellation/import never invokes it; this removes local discoverability evidence, not remote files or credentials. |
| `interactive.start` `{opts}` | `InteractiveSession.start/1` — opts allowlisted (`id`, `provider`, `workspace`, `model`, `system_prompt`, `max_turns`, `event_limit`, `approval_mode`, `sandbox_mode`, `reasoning_effort`, plus fleet `machine`/`node`). The caller-generated `id` is the durable reconciliation key; a matching retry adopts the same immutable intent and a conflicting reuse is refused. Upstream readiness wait is `:infinity` by design ([interactive_session.ex:37](../lib/ouroboros/interactive_session.ex)); this method's gateway ceiling is **120s**, answers timeout with `outcome: unknown`, and runs in its own task so it never blocks the connection. A remote owner additionally requires an explicit absolute destination `workspace`. |
| `interactive.send_message` / `follow_up` `{id, input, turn_id?}` | idempotent via caller-supplied `turn_id`; `input` remains a legacy nonempty string or a closed `{prompt, attachments?, reasoning_effort?}` object (at most 32 nonempty attachment paths; reasoning `low`/`medium`/`high`). The session canonicalizes every attachment and accepts only an existing regular file contained by its leased workspace; traversal, absolute escape, and symlink escape are refused before Harness dispatch. Two containment limits are inherent to this layer and stated rather than implied away: a hard link inside the workspace to an outside file passes (only symlinks are resolved), and the check races the provider's eventual read (authorize-then-dispatch, no lock) |
| `interactive.steer` `{id, input}` | `steer/3` through a closed envelope (unknown params refused, structured `input` accepted). Steering injects into the running turn and is not durably keyed by the plane: Harness mints the request id inside its worker, so it has no idempotency, and a lost acknowledgement is unreconcilable — the TUI preserves the steer for inspection (restoring it when the editor is empty, otherwise retaining the newer draft and the steer in composer history) and tells the operator to check provider/transcript state before deliberately sending it again. What *is* durable since the steer-text enrichment: the session coordinator remembers the prompt keyed by that request id and writes it, redacted, into the projected `input_accepted(kind=steer)` event, so the transcript quotes every accepted steer in replay exactly once. |
| `interactive.request_approval` `{id, request, node?}` | The other direction: something outside the Harness asking this runtime for a decision. Today's only caller is `ouro mcp-serve` (§3.1), answering Claude Code's `--permission-prompt-tool`. `request` is a closed `{tool_name, input?, tool_use_id?, cwd?}` object; the coordinator mints a `request_id`, checkpoints an `approval_requested` in the shape the Codex/ACP dialects already emit (`tool_call`, `kind: "permissions"`, plus `suggested_rule` where the permission engine offers one), consults that engine, and otherwise blocks until `interactive.respond_approval` names the id. Bounded at 8 outstanding questions per session; the ninth is denied. The gateway ceiling is **15 min** and is the outermost of three — the coordinator denies at 13 and the plane's transport stops waiting at 14 — so the answer a caller gets is a decision, not a killed task. The reply is `{decision: "allow"\|"deny", request_id, source, reason}`; `source` names which rule answered (`human`, `engine`, `timeout`, `capacity`, `session_terminal`, `checkpoint_failed`, `caller_gone`, `coordinator_restart`). Everything that is not a human or the engine saying yes is a denial. |
| `interactive.respond_approval` `{id, request_id, response}` | `response` is `"approve"`, `"deny"`, or `{decision, scope?, reason?}` — exactly what `Jido.Harness.ApprovalResponse` declares, matched against literal terms. `provider_options` is deliberately not accepted. Every answer is recorded in the effect ledger as a `:permission` effect, and `scope: "session"` additionally writes a session-scoped C1 rule from the pattern the `approval_requested` payload suggested, so the same question is not asked twice in that session. There is no `scope: "always"`: the pinned `ApprovalResponse` schema admits only `once` and `session`, and the durable form of "never ask me again" is `permissions.add` with the same `suggested_rule` |
| `permissions.add` `{scope, pattern, decision, workspace?, node?}` | `Control.Permissions.add/1`. `scope` is `"user"` or `"workspace"` (a `"workspace"` rule requires `workspace`, and is stored in the data directory keyed by canonical root — never in the repository); `decision` is `"allow"`, `"deny"`, or `"ask"`; `pattern` is validated by `Control.Permissions.Pattern` and by nothing else, so `Bash(command:…)` and an `allow` on `Tool(name:param=value)` are refused. `"node"` scope is refused outright — those rules come from `config :ouroboros, :permissions`. Ids are derived from the rule, so adding the same rule twice returns the same rule |
| `permissions.remove` `{scope, id, node?}` | `Control.Permissions.remove/2`, `scope` one of `"user"`, `"workspace"`, `"session"`. Unknown id → `-32007`. A failed checkpoint leaves the rule standing and says so, for the reason `Control.Grants` states about revocation |
| `interactive.interrupt` `{id, turn_id?}` | `interrupt/2` (`:active` default) |
| `interactive.close` / `interactive.kill` `{id}` | |
| `interactive.delete` `{id}` | `Interactive.Store.delete/1` — terminal sessions only (`closed`/`failed`/`cancelled`/`lost`). Live sessions are refused `-32006` with `reason: session_not_terminal`; the coordinator is stopped first so a retiring process cannot write the record back. The same `{id, node?}` routing as the other session verbs. |
| `account.login.start` `{flow?}` | `CodexAppServer.login/2` — `flow` is `browser` (default) or `device_code`. The reply is the only surface that carries `authUrl`/`verificationUrl`/`userCode` (allowlisted keys), which is why it is operate-scoped while `account.read` is not |
| `capabilities.list` `{workspace}` / `capabilities.preview` `{workspace, path}` / `capabilities.admit` `{workspace, path, session_id?}` | `Runtime.Capabilities.list/preview/admit` over `.ouroboros/capabilities/<Name>/` proposals. Preview compiles and tests in the isolated build peer; admit forges and rolls out behind the health gate (optionally `Mesh.start_agent/2`) and records `session:<id>` as the author when a session id is supplied. Preview and admit run a build peer whose default deadline is 60s, so both carry the 120s ceiling (`@forge_timeout`) that lets a named forge refusal beat `-32005`. |
| `account.login.cancel` `{login_id}` | `CodexAppServer.cancel/2` — completion/cancel notifications are correlated by `loginId`; a stale completion for a superseded login cannot overwrite the pending one |
| `account.logout` `{}` | `CodexAppServer.logout/1` — reply is `{}`; the account boundary returns nothing it has not named |

The three turn-carrying methods (`send_message`, `follow_up`, `steer`) refuse unknown
params (`only_keys`) where they previously ignored them. `hello.protocol` remains `1`:
the new `account.*` methods are feature-detectable
through `hello.methods`, but the envelope tightening and the structured-`input` capability
are not — the compatibility bet, stated plainly, is that the only deployed client ships in
this repository and moves in lockstep.
| `coding.start` `{objective, opts}` / `coding.cancel` `{id}` / `coding.delete` `{id}` | same start identity, fleet routing, remote-workspace rule, immutable-intent reconciliation, and outcome-unknown 120s ceiling as `interactive.start`. `coding.delete` is the coding-plane twin of `interactive.delete` (terminal `completed`/`failed`/`cancelled`/`lost` only) |
| `teams.add_worker` `{team_id, worker_id, opts?}` / `teams.delegate` `{team_id, worker_id, objective, opts?}` | upstream bound is 60s (`control_call/2`), gateway ceiling 60s. Worker opts: `role`, `node`; delegation opts: `id`, `coding_node`, `workspace`, `provider`. Node names are matched by string against `[node() | Node.list()]` — never converted |
| `teams.cancel` `{team_id, delegation_id}` / `teams.close` `{team_id}` | upstream is `:infinity` — gateway ceiling 60s, and the timeout answers `-32005` with `data` `{"outcome": "unknown"}` (§2.4 intro) |
| `control.submit` `{objective, opts}` / `control.cancel` `{id}` | control opts: `id`, `max_revisions` |
| `agents.stop` `{id}` | `Mesh.stop_agent/1` |
| `runtime.shutdown` | `System.stop/0` — **also** requires `OUROBOROS_GATEWAY_ALLOW_SHUTDOWN=1`, else `-32003`. Answered by the `Conn` rather than a task: the acknowledgement is written *and flushed to the socket* before the stop is called, because the client that asked is owed the ack |

Every option a plane accepts is an atom, and none of them are built from client bytes:
option keys come from one literal table in `Gateway.Methods`, enum values from the exact
terms the upstream schema declares, provider names from the providers this node serves.
An option outside a method's allowlist is `-32602` **naming it**, not silently dropped —
a `sandboxMode` that was ignored would run the session under a policy nobody chose.

Two spec corrections found while implementing, recorded rather than quietly dropped:
`metadata` is *not* an option `InteractiveSession.start/1` accepts — the durable
checkpoint rejects it ([coding/task_state.ex](../lib/ouroboros/coding/task_state.ex)
`@accepted_options`) and the plane sets its own session metadata — so the allowlist above
replaces it with options the plane really takes; and `env`, `mcp_config`, and
`provider_options` stay out entirely, because the checkpoint refuses inline environment
and MCP config outright and provider knobs are node configuration.

**What a session declares about itself.** `interactive.info` and `interactive.list`
carry two blocks a client can trust without probing the provider.

`options.capabilities` is the ten-key map
`transport, process, multi_turn, follow_up, interrupt, approvals, steer, multimodal,
dynamic_model, dynamic_configuration`, each `"native"`/`"managed"`/`"process"`/`false`
(`process` is `"persistent"`/`"per_turn"`, `transport` is the transport's name). It is
derived from the provider spec at projection time, not stored — so a session listed after
a restart declares what its transport can do without a coordinator being up to answer —
and it mirrors `Jido.Harness.Session.Manager`'s own transport resolution, including the
narrowing that stops a managed transport advertising a `model` its adapter does not
normalize. Where Ouroboros replaced a transport's adapter with one of its own dialects
(`Dialect.ACP`, `Dialect.Codex`), the dialect's declaration is the one reported: the
upstream spec still describes code that is no longer running. The whole map is `null`
when neither the provider nor the transport resolves — an absent claim rather than a
false one.

`usage` is what the provider said the session spent: `input_tokens`, `output_tokens`,
`cache_read_tokens`, `cache_creation_tokens`, `total_tokens`, `cost_usd`,
`turns_with_usage`, and `last` (the most recent turn's figures and its `turn_id`). It is
folded from `:usage` events, tolerant of the spellings different transports use, and
durable through the same checkpoint as the events it was read from. Two honesty rules:
`cost_usd` is `null` — never `0` — for a provider that never priced the work, and a turn
that reports repeatedly (Codex's `thread/tokenUsage/updated` is a value being *updated*)
contributes its largest figure once rather than the sum of its notifications.

**`approval_mode: "prompt"` is refused where nobody can answer it.** The managed
transports — `claude`, `gemini`, `grok`, `zai`, and the named `codex` `exec_jsonl_resume`
fallback — re-execute the CLI once per turn and declare no `approvals` capability. Their
adapters still accept the option, so it used to travel through and do nothing:
`claude --print --permission-mode default` is never given a `--permission-prompt-tool`
and denies every permission-needing tool silently. `interactive.start` now answers
`-32006` with `data` `["unsupported_approval_mode", {provider, transport, requested,
supported, reason: "no_approval_channel", message, plane}]` — the same `[tag, map]` shape
as `unsupported_safety_options`, so `model::refusal` renders it as one sentence — whether
`:prompt` was stated or injected by the plane default. `supported` names the modes that
work. Codex on app-server, the ACP providers, `pi`, `amp`, and the whole coding plane are
untouched. This stands until the Claude approval bridge (AGENT_EXPERIENCE Track C2) makes
`:prompt` true for those providers.

Deliberately absent from v1: `agents.start` (arbitrary module start is a
bigger authority than a TUI needs; revisit with an allowlisted spec registry),
`mesh.send_message` (its `from` is caller-supplied — the effects plane made
principals non-spoofable and the gateway won't reintroduce spoofing),
upgrade `prepare/commit/promote/rollback` (stay in the remote console where
they belong).

### 2.5 Event streaming

On `interactive.subscribe` / `coding.subscribe`, the Conn process becomes the
subscriber. Each arriving `{:ouroboros_interactive_event, id, %Interactive.Event{}}`
(delivered at [interactive/task.ex:1003](../lib/ouroboros/interactive/task.ex)) /
`{:ouroboros_coding_event, id, %Coding.Event{}}`
([coding/task.ex:520](../lib/ouroboros/coding/task.ex)) is Wire-encoded and
emitted as notification `interactive.event` / `coding.event` with params
`{id, event}` (`id` is the session/task id; note the coding struct's own
field is `task_id`, not `session_id`). Both event structs carry `sequence` —
the resync cursor.

**Event payloads are byte-capped, and the three paths to an event share one cap.**
A live notification, a `replay` result, and a `subscribe` backlog all reach the same
event-struct clause in `Gateway.Wire`, so a leaf too large to frame arrives as
`{"_excerpt": …, "_bytes": N}` on all three or on none — they cannot drift. The rule and
the marker are in §2.7; `interactive.event_detail` (§2.4) is where a client asks for the
leaf itself. The two `stream.*` control frames carry no event and are unaffected.

The four subscription verbs are answered **by the `Conn` process itself**, not by a
dispatch task, because both planes register `self()` as the subscriber. The cost is
stated rather than hidden: those calls block the connection for as long as the plane's
own control-plane bound allows (30s, `:session_call_timeout`), because a
`GenServer.call` this process must make itself is not one it can put a gateway ceiling
on. Everything else the connection does — every other method — still runs in a task.

Three upstream behaviors the Conn must handle explicitly:

- **Terminal sessions don't register subscribers.** `subscribe` on a terminal
  session returns the backlog but silently skips registration
  ([interactive/task.ex:100](../lib/ouroboros/interactive/task.ex); the coding plane
  mirrors it at [coding/task.ex:82](../lib/ouroboros/coding/task.ex)). After a
  successful subscribe the Conn checks the session's status; if terminal, it
  emits `stream.ended {id, plane, status}` after the backlog so the client renders a
  finished session instead of waiting forever.
- **The coordinator holding the registration can die.** It retires ~100ms after a
  terminal session, and a crash restarts it *without* the subscription. So the Conn
  monitors that process and emits `stream.ended {id, plane, status: "unknown"}` on its
  `:DOWN`. Without it the events would simply stop with nothing said. (`plane` is
  `"interactive"` or `"coding"`; it is on both stream notifications because their method
  names, unlike `interactive.event`/`coding.event`, do not carry it.)
- **`{:error, {:cursor_pruned, floor}}`** is a real return of both `subscribe`
  and `replay` ([interactive/task.ex:1069](../lib/ouroboros/interactive/task.ex))
  — sessions retain a bounded event window. The gateway forwards it as
  `-32006` with `data` `{"reason": "cursor_pruned", "floor": N}` — the one error whose
  `data` a client branches on rather than displays. Resync behavior is the client's
  (§3.3), and the shape is pinned by a golden fixture.

**Subscriber cleanup needs nothing from the gateway on abnormal death.** Both planes
`Process.monitor` the subscriber pid and drop it on `:DOWN`
([interactive/task.ex:1087](../lib/ouroboros/interactive/task.ex),
[coding/task.ex:554](../lib/ouroboros/coding/task.ex)), so a `Conn` that crashes is
released by the plane itself. A graceful close still unsubscribes explicitly, under a
total budget of 1s across all of a connection's subscriptions; the budget is what keeps
a wedged coordinator from delaying an exit that the monitor would have handled anyway.
A connection may hold at most 64 subscriptions.

### 2.6 Backpressure (non-negotiable)

The Conn keeps one outbound queue, counted in **frames**. How large one frame gets is a
separate bound and lives in §2.7 — a thousand-frame queue says nothing about a single
five-megabyte diff, which is why both exist.

Frames are two classes:

- **Responses and the two stream control notifications** — never dropped. The hard cap
  is `OUROBOROS_GATEWAY_QUEUE_LIMIT` plus 72, which is exactly the number of responses
  that can be outstanding at once (8 in flight + 64 waiting). Above it the connection is
  closed (protocol error frame first, best-effort); the client reconnects and
  resubscribes. A client that can't drain its own RPC responses is broken, not throttled.
- **Event notifications** — droppable. When queue length reaches
  `OUROBOROS_GATEWAY_QUEUE_LIMIT`, new event frames for a session are counted
  and discarded. When the queue drains below half, one
  `stream.lagged` `{id, plane, dropped, last_sequence}` notification is sent per lagged
  session — `dropped` is how many frames were discarded, `last_sequence` the sequence of
  the newest one discarded, which is how far ahead the session had run. The client calls
  `replay(cursor: its last seen sequence)` and reconciles.
  Reconciliation is exact while the cursor is inside the retained window; if
  the client fell past it, `replay` answers `cursor_pruned` with the floor and
  the client restarts from the floor showing a "history truncated below N"
  marker (§3.3). Either way the terminal state is truthful — never silently
  missing events.

Socket writes use `:gen_tcp.send` with `send_timeout` set, from a **single writer
process** (`Gateway.Writer`) spawned and linked by its `Conn`, which monitors it in
return so neither outlives the other. The `Conn` cannot make that call itself: it blocks,
and a connection parked in `send` for the fifteen seconds of `send_timeout` would keep
taking plane events into its mailbox the whole time — the real backlog would be
unbounded, in the one place the bound cannot see it. Handing frames to a writer and
counting the unacknowledged ones is what makes the queue depth a number this process can
act on *while* the peer is still slow, which is the entire point of dropping events
rather than accumulating them. A hung peer still becomes a closed connection
(`send_timeout_close`), not a stuck GenServer mailbox. This is the same unbounded-growth
discipline applied everywhere else in the runtime after the 2026-08 review.

### 2.7 Wire encoding (`Gateway.Wire`)

Rendering-oriented, lossy by design, documented as such.

**`Orchestration.Serializable.safe/1` cannot be the mechanism.** It is
all-or-nothing at the top level
([serializable.ex:26](../lib/ouroboros/orchestration/serializable.ex)): one
pid anywhere in a tree replaces the *entire* term with a 20-element-truncated
inspect string. And pids are everywhere by construction —
`Mesh.list_agents/0` returns `%{id, pid, node, replicas}` maps
([mesh.ex:118](../lib/ouroboros/mesh.ex)), which `Ouroboros.status/0` embeds,
and `Mesh.state/1` returns a `%Jido.AgentServer.State{}` dense with pids,
refs, `:queue` tuples, and functions. `safe/1` applied naively would reduce
`runtime.status` — the Dashboard's whole data source — to one opaque string.

So `Gateway.Wire` implements its own recursive walk, replacing at the leaf:

1. pid/port/ref/function → `{"_opaque": inspect(term)}` (the per-leaf analogue
   of `safe/1`'s sentinel); `:queue` and other opaque record tuples fall out
   of this naturally as tuples-of-lists.
2. structs → `Map.from_struct` plus `"_struct": "Ouroboros.Interactive.Event"`,
   then recurse; DateTime/NaiveDateTime → ISO-8601 strings first.
3. atoms → strings; tuples → lists; map keys → strings; non-UTF-8 binaries →
   `{"_b64": …}`; depth cap 32 and node-count cap (protects the Conn from
   pathological state trees) → `{"_truncated": true}` beyond either.
4. a string inside an **event `payload`** longer than its cap →
   `{"_excerpt": <the first bytes>, "_bytes": <full size>}`.
5. `JSON.encode!/1` (stdlib — Elixir 1.20/OTP 29, no new dep).

**The byte cap on event payloads.** Depth and node counts do not bound bytes: fifty
thousand nodes is a cheap tree, and one node holding a five-megabyte diff is not. That
node used to be framed whole on every notification and again on every replay of the same
session. The rule, whole:

> Each string leaf inside an event `payload` may put at most `event_leaf_bytes`
> (128 KiB) on the wire, and one event's payload strings at most
> `event_payload_bytes` (512 KiB) between them. The cap for a leaf is whichever of the
> two is smaller when it is reached — the per-leaf cap, or what is left of the per-event
> budget. A leaf over its cap becomes `{"_excerpt": prefix, "_bytes": full_size}`. The
> budget starts over at each event, so a 500-event replay gives every event its own.

Three things the rule deliberately does not do:

- **The envelope is never excerpted** — `type`, `sequence`, `timestamp`, the `*_id`
  fields, `provider`. A client indexes and resyncs by them, and an excerpted `sequence`
  would break the protocol rather than bound it.
- **A string of ≤512 bytes is never excerpted**, because the marker map replacing it
  would be larger than the string. So a payload of tens of thousands of *short* strings
  is bounded by the node cap, exactly as it was before — this cap is aimed at the leaf
  that is large by itself, which is the shape a diff, a tool result, and a file read all
  have.
- **Nothing outside an event payload changed.** `runtime.status`, `agents.state`, and
  every error's `data` are bounded by depth and node count alone, as before.

The excerpt is cut at a UTF-8 boundary — `binary_part/3` can land inside a multi-byte
character and a client decoding a frame is owed valid UTF-8, so the cut retreats to the
last whole character (never more than three bytes). A non-UTF-8 binary over its cap keeps
the `_b64` spelling it already had and gains the same `_bytes` key; the budget counts
*source* bytes retained, and base64 costs four wire bytes for every three of them.

`interactive_event_excerpt_notification.json` pins the marker's shape for the Rust side,
and `interactive_event_detail_result.json` / `coding_event_detail_result.json` pin what
`event_detail` answers with. The excerpt fixture states 48- and 96-byte caps rather than
the 128 KiB default so the contract file stays a diff a person can read; the arithmetic
is asserted in `Ouroboros.Gateway.WireTest`.

**Honest limit on `detail_leaf_bytes`.** Its 4 MiB default sits under the client's 8 MiB
inbound line ceiling (`DEFAULT_MAX_LINE`, [tui/src/transport.rs:54](../tui/src/transport.rs)),
so a full-size detail frame still decodes, while a cap raised past about 7 MiB produces a
frame the current client cannot read — the envelope and JSON escaping push it past 8 MiB and the line is truncated
rather than decoded. The cap bounds the server's memory and the socket honestly; it does
not promise the client can take delivery of the largest thing it permits. Raising one
without the other buys nothing.

This transform is exactly why a forged `Ouroboros.Capability.*` agent's novel
state renders in the TUI the moment it exists: everything is a tree of
strings, numbers, lists, and maps, and the TUI has a generic tree widget.

### 2.8 Verifier protection

Add to [verifier.ex](../lib/ouroboros/upgrade/verifier.ex):

```elixir
@protected_prefixes [
  "Elixir.Ouroboros.Upgrade.",
  "Elixir.Ouroboros.Release.",
  "Elixir.Ouroboros.Storage.",
  "Elixir.Ouroboros.Control.",
  "Elixir.Ouroboros.Gateway."   # operator surface: patchable auth is no auth
]
```

Plus a verifier test proving a `Gateway.`-targeting artifact is rejected. The
signing policy's hard Capability-namespace rule already refuses to sign such a
patch; this is the second, independent gate, consistent with how the other
control-plane namespaces are treated.

### 2.9 Logging

Whenever the gateway is on — `OUROBOROS_GATEWAY=1` or the defaulted
single-machine posture — the foreground client routes the default logger to stderr so
its bounded in-memory ring owns the visible log stream. stdout is not clean in the
defaulted posture, deliberately: the listener retains a plain notice branch for a future
standalone package (mode, data dir, bound address, how a client attaches). A bare
`bin/ouroboros start` is not currently supported because it cannot supply the trusted
native lifecycle helper. Elixir >= 1.15 idiom (not the legacy `:console` backend):

```elixir
config :logger, :default_handler, config: [type: :standard_error]
```

A packaged detached daemon or recovery service uses two files instead. The inherited
stdout/stderr descriptors write `daemon.log`, retaining pre-Logger bootstrap, VM, and
crash diagnostics; Rust rotates that file before a managed start at 2 MiB and keeps
three private backups. The launcher separately precreates and validates `runtime.log`
plus its archive names, then gives that path only to
[OTP 29 `:logger_std_h`](https://www.erlang.org/docs/29/apps/kernel/logger_std_h.html) with
`file_check: 0`, `max_no_bytes: 2_097_152`, and `max_no_files: 3`. Logger alone writes
and live-rotates it as `runtime.log.0` (newest) through `.2`; the inherited descriptors
never share that inode. A child umask of 077 keeps the new active file private after
each rotation. OTP rotates after a complete event, so an individual generation may
exceed 2 MiB by at most one formatted event.

### 2.10 Distribution-off mode (env.sh.eex)

[rel/env.sh.eex](../rel/env.sh.eex) picks between two postures:

- `OUROBOROS_DIST=none` → `RELEASE_DISTRIBUTION=none`, node/cookie not
  required, **no epmd and no dist listener**. The release launcher uses a fresh
  disposable boot cookie rather than the artifact fallback, but it is not a
  reachable cluster credential in this posture. This
  is also the **default**: a release with no `OUROBOROS_NODE`, no
  `OUROBOROS_CLUSTER_STRATEGY`, and no `OUROBOROS_DIST` boots this posture
  rather than refusing — the refusal existed to block the fallback to the
  baked shared cookie, and a posture with no listener blocks it harder.
- Anything that asks for distribution — `OUROBOROS_NODE` set, `OUROBOROS_DIST`
  set to other than `none`, or a cluster strategy named — takes the strict
  path: a long name plus `OUROBOROS_COOKIE_FILE` (recommended) or legacy
  `OUROBOROS_COOKIE`, with refusals signposting the standalone posture. A fleet
  passes only the private cookie file path and replaces the disposable boot
  cookie before libcluster starts.
- The combination `OUROBOROS_DIST=none` + `OUROBOROS_CLUSTER_STRATEGY` ≠
  `none` is refused at preflight (they contradict; both variables named in the
  error). A strategy *alone* is not that contradiction — it asks for
  distribution and is refused for the node name it was not given.
- The existing `version | "")` exemption arm covers *both* `version` and the
  empty command ([env.sh.eex](../rel/env.sh.eex)) — preserved.

Forge builds keep working: `BuildPeer` runs `:peer` over `standard_io` with
`-start_epmd false` ([build_peer.ex:177](../lib/ouroboros/upgrade/forge/build_peer.ex)),
non-distributed by design, and the local deploy path short-circuits on
`target == node()`. **Known risk to test first:** `Upgrade.Epoch` allocates
under `:global.trans` ([epoch.ex:81](../lib/ouroboros/upgrade/epoch.ex));
`:global` on a `:nonode@nohost` VM should degrade to the local node but this
is the single most likely failure point of the dist-off posture.
**Acceptance test:** the full forge → sign(Local) → deploy → run loop passes
on a `RELEASE_DISTRIBUTION=none` node. Remote builders/signers and
`start_on/2` placement legitimately require distribution — that's clustering,
and clustering keeps the existing posture.

### 2.11 Elixir tests (`test/ouroboros/gateway/`)

- **Config:** every env combination that must raise, raises with the variable
  named (no token; non-loopback without ALLOW_REMOTE; dist contradiction).
- **Conn protocol:** drive `Gateway.Conn` with a fake transport — bad token
  closes; pre-hello frames refused; protocol mismatch; unknown method −32601;
  malformed JSON −32700 answered not crashed; oversized frame; scope_denied on
  operate methods under read scope; shutdown refused without the extra flag.
- **Wire:** golden encoding of nasty terms — pids in nested maps, improper-ish
  tuples, structs, non-UTF-8 binaries, atom keys. Plus the event-payload byte cap
  (§2.7): a 5 MB leaf excerpted with its true size named, the envelope untouched, an
  excerpt cut inside a multi-byte character retreating to a whole one, the per-event
  budget spent exactly and restarted at the next event, a short string left alone, and
  every non-event term unchanged.
- **Streaming, end to end:** a real 5 MB `file_change` on both planes — the live
  notification, the `replay` result, and the `subscribe` backlog carry the identical
  marker (one cap, three paths); `event_detail` answers the same event whole; a sequence
  above the high-water mark is `-32007`; one below the retained floor is `-32006` naming
  the floor; a non-positive-integer `sequence` and an unknown param are `-32602`; a fresh
  `hello` lists both new methods.
- **Integration (real TCP, ephemeral port):** hello→status; subscribe→ live
  event notifications from a real interactive session (deterministic test adapter) and
  from a real coding task; lag: the connection's writer is suspended so frames pile up
  unacknowledged → event frames are dropped → `stream.lagged` → backlog + notifications
  + replay(cursor) reconciles to the exact contiguous history. Suspending the writer
  rather than relying on an unread socket is deliberate: it makes overflow a decision
  the test makes rather than one a kernel buffer size makes. Also: a response flood
  against a suspended writer closes the connection rather than dropping a response;
  cursor below the retained floor → `cursor_pruned` surfaces with the floor and
  resubscribing at the floor works; subscribe to a terminal session →
  backlog then `stream.ended`; killing the coordinator under a live subscription →
  `stream.ended`; `upgrade.status` with the executor stopped →
  `-32004`, connection alive; two clients, one slow, fast one unaffected;
  gateway.json appears with the bound port, 0600.
- **Operate scope:** every method the table marks `:operate` is refused `-32003` on a
  read listener — enumerated from the table, so a verb that loses its scope fails here;
  each operate call leaves exactly one audit line carrying the method, a param digest,
  and the peer, and carrying none of the parameters themselves; an unknown provider name
  is `-32602` and creates no atom; `runtime.shutdown` is refused without
  `OUROBOROS_GATEWAY_ALLOW_SHUTDOWN=1` and, with it, stops the node only after the
  acknowledgement has been written.
- **Verifier:** Gateway-namespace artifact rejected.
- **Golden fixtures:** `mix ouroboros.gateway.golden` regenerates
  `test/support/gateway_golden/*.json` from static, deterministic terms — no clock, no
  random ids, no live plane, so a regeneration on another machine writes the same bytes.
  Sixteen frames: `hello_result`, `runtime_status_result`,
  `interactive_event_notification`, `coding_event_notification`,
  `interactive_event_excerpt_notification` (the `_excerpt`/`_bytes` marker, at stated
  48/96-byte caps so the file is a diff a person can read),
  `interactive_event_detail_result` and `coding_event_detail_result` (one bare event, not
  an array, encoded under `detail_leaf_bytes`),
  `stream_lagged_notification`, `stream_ended_notification`, and the error frames
  `error_unauthenticated` (−32001), `error_protocol_mismatch` (−32002),
  `error_scope_denied` (−32003), `error_upstream_timeout_unknown` (−32005 with
  `outcome: unknown`), `error_cursor_pruned` (−32006 with `reason`/`floor`),
  `error_not_found` (−32007), `error_invalid_request` (−32600).
  These files are the cross-language contract — cargo tests decode the same
  fixtures (§3.5). Objects are written with sorted keys and two-space indent so a
  regeneration that changed nothing is a zero-line diff and a change to the protocol is
  a reviewable one. `golden_test.exs` re-derives every frame through the live
  `Conn` envelope functions and `Wire` encoder and compares against the bytes on disk, so
  a fixture cannot drift from the build that produced it.

---

## 3. Rust side: `tui/` crate, binary `ouro`

Rust ≥ 1.75, 2021 edition. Deps: `ratatui`, `crossterm`, `tokio` (rt +net +
process + signal), `serde`/`serde_json`, `clap`, `anyhow`, `flate2`, `tar`,
`dirs`, `rand`, `rcgen`, `zeroize`, `sha2`. Unix-only in v1 (the release itself is
`include_executables_for: [:unix]`).

### 3.1 CLI

```
ouro                  spawn (or adopt via gateway.json) + attach UI
ouro daemon           spawn only; print port/token-file path; exit
ouro attach [--addr HOST:PORT] [--token-file PATH]   connect only
ouro new [--provider NAME] [--workspace PATH] [--approval-mode MODE]
         [--message TEXT] [--machine NAME] [--print]
                      start an interactive session, then attach focused on it;
                      provider/workspace/approval resolve flag first, then the
                      config file's [defaults]; only a provider neither names
                      is refused, naming both places
ouro run "PROMPT" [--provider NAME] [--workspace PATH] [--approval-mode MODE]
         [--sandbox-mode MODE] [--machine NAME] [--resume SESSION-ID]
         [--json | --stream-json] [--approve-all] [--timeout SECS] [-v]
         [--addr HOST:PORT] [--token-file PATH]
                      headless: run one prompt, stream the normalised events,
                      exit with a documented code. No alternate screen, ever
ouro stop             graceful stop of the locally spawned daemon
ouro fleet create     create private CA/cookie/profile for the first machine
ouro fleet list       Tailscale peers and SSH config hosts this Mac already knows
ouro fleet add TARGET --machine NAME --host HOST [--via ssh|tailscale] [--binary FILE]
                      probe over SSH, copy a matching binary when honest, copy one
                      private invitation as a file, enroll remotely
ouro fleet add --print-script --machine NAME --host HOST
                      write the invitation here and print the enroll recipe
ouro fleet enroll FILE [--delete] [--service]
                      join from a copied invitation and start the daemon
ouro fleet invite --machine NAME --host HOST --out FILE
                      create one private 0600 owner-attested invitation
ouro fleet invite cancel --machine NAME --out ROSTER
                      stop expecting an abandoned invite and sign the new roster
ouro fleet join FILE  import that machine's invitation
ouro fleet sync export --out ROSTER
ouro fleet sync import ROSTER
                      distribute/import a newer signed membership roster
ouro fleet sessions forget --machine NAME --accept-state-loss
                      after signed removal + restart, irreversibly retire this
                      gateway/data-dir's offline session-owner evidence
ouro fleet status     expected/connected/offline machines and TLS posture
ouro fleet doctor     actionable profile/network/runtime/service checks
ouro fleet service install|status|remove
                      generate and inspect launchd/systemd user recovery
ouro fleet leave      remove a stopped non-owner/empty-fleet profile safely
ouro mcp-serve        hidden. An MCP server on stdio, spawned by a vendor CLI, not
                      by a person: it is the permission prompt for a transport
                      that has none of its own
ouro version          client version, embedded release version+sha, protocol
ouro --dev            spawn `mix run --no-halt` in cwd with gateway env (no embed);
                      defaults to an isolated ouroboros-dev data directory
```

#### `ouro mcp-serve` — the approval bridge (`src/mcp_serve.rs`)

A Model Context Protocol server over stdio, hidden from `--help` because the only thing
that should ever start it is a provider process this runtime launched.
`Ouroboros.Provider.ClaudeAdapter` composes an `--mcp-config` naming
`{"command": "<ouro>", "args": ["mcp-serve"], "env": {…}}` and points Claude Code at
`--permission-prompt-tool mcp__ouroboros__approve`; Claude Code then calls that tool
instead of prompting, and reads the decision out of the result.

*Protocol.* Newline-delimited JSON-RPC 2.0 on stdin/stdout, MCP revision **2026-07-28**
([spec](https://modelcontextprotocol.io/specification)) — `initialize`,
`notifications/initialized`, `tools/list`, `tools/call`, `ping`. The `protocolVersion` a
client names is echoed back, so a Claude Code of a different era still negotiates. stdout
carries messages and nothing else; every log goes to stderr and only under
`OUROBOROS_MCP_SERVE_VERBOSE=1`. Inbound lines are capped at 4 MiB.

*The one tool.* `approve` takes the permission-prompt contract's own fields — `tool_name`,
`input`, `tool_use_id` ([CLI reference](https://code.claude.com/docs/en/cli-reference),
[Agent SDK permissions](https://code.claude.com/docs/en/agent-sdk/user-input)) — and
returns the `canUseTool` answer as a JSON text content block:
`{"behavior":"allow","updatedInput":{…}}` or `{"behavior":"deny","message":"…"}`.

*Where it asks.* `OUROBOROS_GATEWAY_ADDR` and `OUROBOROS_GATEWAY_TOKEN_FILE` locate the
runtime, `OUROBOROS_SESSION_ID` and `OUROBOROS_SESSION_NODE` name the session, and
`OUROBOROS_APPROVAL_TIMEOUT_MS` (default 600000) bounds the wait. One connection is held
for the server's lifetime and a transport failure is reopened exactly once; a *timeout*
never is, because a question that ran out of time may be in front of a person.

*Deny by default.* No runtime, an unreadable token, a refused call, a malformed argument
object, a decision this build cannot parse, a deadline, or a bridge started by hand each
produce a denial naming the cause. Nothing in this module can produce an `allow` that a
runtime did not.

Spawn-mode environment assembly: `OUROBOROS_GATEWAY=1`, `_SCOPE=operate`,
`_ALLOW_SHUTDOWN=1`, `_PORT=0`, token: 32 random bytes hex → file 0600 in the
data dir (zeroized in memory after write), `OUROBOROS_DATA_DIR` set to the caller's
explicit absolute value or the mode-specific derived `$XDG_DATA_HOME/ouroboros`
(`ouroboros-dev` with `--dev`) default,
`OUROBOROS_PROCESS_ID_HELPER` set to the product `ouro` binary (never a cargo test
harness) so Mix can run `process-birth` and `hold-runtime-recovery-lock`,
`OUROBOROS_DIST=none` for a standalone machine. A private `fleet/profile.json`
is authoritative when present: spawn supplies its stable node/machine name,
static seed set, one-second reconnect interval, local gateway port, private
cookie-file path, and generated runtime `vm.args` with TLS and distribution
ports. The real cookie is never copied into argv or the environment. Without a
profile, existing operator-managed cluster variables still pass through and
distribution stays on.

A nonblank explicit `OUROBOROS_DATA_DIR` is used exactly in both modes. Before a
`--dev` spawn, attach, stop, or adoption flow uses one, the boot screen (or plain command output)
warns that the normal `ouroboros-dev` isolation is disabled and a release runtime in
that same directory may be adopted. The override is neither rewritten nor refused;
operators who want isolation with an explicit root should name a dedicated dev
directory.

#### `ouro run` — the headless surface (`src/run.rs`)

The scriptable half of `ouro new`. It resolves the runtime the same way — adopt the
publication in this data directory, else spawn one, or attach when `--addr`/`--token-file`
name a listener — and starts the session through the same `StartRequest` and the same
`config::resolve_start` precedence, so a provider neither the flag nor `[defaults]` names
is the same refusal `ouro new` makes, in the same words. A runtime this command spawned is
**left running** on exit, with `the runtime is still running (pid …)` on **stderr**: a
script that calls `ouro run` in a loop should pay one cold start, not one per prompt.

*Stdout is exactly one of three things*, and progress never joins it:

| flag | stdout |
|---|---|
| `--stream-json` | one JSON object per normalised event — **verbatim the `event` object from the `interactive.event` notification** (§2.5), which is the golden-pinned contract and not a second schema — then one `{"type":"result", …}` object |
| `--json` | the result object alone |
| neither | the agent's final text: the `output_text_final` messages of the turn, or the collapsed `output_text_delta`s where no final arrived |

The result object carries `session_id`, `turn_id`, `status`, `provider`, `node`, `usage`,
`files_changed`, `approvals` (`requested`/`answered`), `duration_ms`, and `error` when
there is one. `usage` is **numbers only**, folded from `usage` events by replacement
rather than addition — those payloads are cumulative for the turn — with camelCase keys
normalised and `total_tokens` derived from `input_tokens + output_tokens` exactly as the
Harness mappers derive it, and only when the provider did not send it.

*Ending, and exit codes.* The run stops at `turn_completed`/`turn_failed`/
`turn_interrupted` for its own `turn_id`, at any terminal session event, or at
`stream.ended`. `stream.lagged` — and a hole in the live stream that nothing announced —
is repaired by `interactive.replay {cursor, limit: 500}` from the contiguous high-water
mark, bounded at 40 rounds, with out-of-order frames held until the gap under them fills
so nothing prints twice or out of order.

| code | status | meaning |
|---|---|---|
| 0 | `completed` | |
| 1 | `failed` | |
| 2 | `interrupted` | Ctrl-C, or the runtime interrupted the turn. A second Ctrl-C exits immediately |
| 3 | `lost` | **the turn's outcome was not observed** — the connection closed, the session ended first, or a send whose outcome was unknown was never reconciled. Never rounded up to `completed` |
| 4 | `timeout` | `--timeout` (default 600s) expired; `interactive.interrupt` was sent and briefly awaited |
| 64 | — | usage error or refusal, including a refused `interactive.start`. The `model::refusal` sentence goes to stderr, and under `--json`/`--stream-json` a `{"type":"error", …}` object also goes to stdout |

*Approvals.* There is no approver at a pipe, so an `approval_requested` is answered
`deny`/`once` with reason `ouro run: headless, no approver`, or `approve`/`once` under
`--approve-all`. The request and its resolution are on the event stream like everything
else, and the decision is stated on stderr. This command never waits for a human it does
not have — hanging until CI kills the job is the failure it is replacing.

*`--resume SESSION-ID`.* No start: `interactive.info` first, whose `cursor` field is
`Interactive.State`'s own contiguous high-water mark, then `interactive.subscribe` from
it, so only the new turn's events print. The verb follows the one-in-flight rule —
`interactive.send_message` into an idle session, `interactive.follow_up` otherwise — and a
terminal session is refused rather than sent a turn. The start options are refused
alongside `--resume` rather than ignored: that session's provider and workspace were
chosen when it started.

Reconnect is deliberately **off** for this command. A silent re-handshake would drop the
subscription and leave the run waiting out its whole `--timeout` on a stream that is not
coming back; a closed connection is instead an immediately observable `lost`.

Client-side preferences live in `$XDG_CONFIG_HOME/ouroboros/config.toml`
(else `~/.config/ouroboros/config.toml`): `[defaults]`
provider/workspace/approval_mode and `[onboarding] welcomed`. Loading is
total — a parse failure yields defaults plus a Notice naming the file, never
a crash; unknown keys are ignored on read (and **not** preserved through a
save, stated in the file's own header); saves are temp+fsync+rename at 0600.
This file is user preference, not daemon state: the runtime is configured by
environment, and nothing in this file reaches the spawn env.

### 3.2 Runtime supervisor (`src/runtime.rs`)

- Embedded tarball via `build.rs`: `OUROBOROS_RELEASE_TARBALL` env at compile
  time; its sha256 and the release version are baked in as consts. No tarball
  env → the crate builds in attach/dev-only mode (embed feature off) so cargo
  iteration never waits on `mix release`.
- Extract to `$XDG_CACHE_HOME/ouroboros/releases/<version>+<sha8>/`:
  verify sha256 of the embedded bytes, unpack to `.tmp-<pid>`, rename
  atomically, `chmod +x` bin. Concurrent first-runs are safe (rename loser
  just deletes its tmp). GC keeps the newest 2 versions.
- Spawn `bin/ouroboros start`; stdout/stderr piped. stderr → bounded ring
  buffer (Logs tab). Child exit → prominent status change + last stderr page.
- Serialize the complete read/recheck/spawn window with a fully written 0600
  `spawn.lock` atomically hard-linked into place. Stale publication removal happens
  only after re-reading under that lock; stale-lock replacement has its own crash-releasing
  `spawn.lock.recovery` advisory gate, so concurrent starters and stoppers cannot erase a newer
  runtime's publication or claim. `ouro stop` holds the same lock continuously from its
  live-publication read through owner/token/hello validation and authenticated shutdown request,
  and observed PID exit; no starter can replace the publication while stop acts on it.
- Readiness: poll for `gateway.json` (with a deadline), then TCP hello. On a
  tty this sequence is visible: the client enters the alternate screen first
  and renders the phases (prepare → spawn → publish → connect) as a boot
  screen with the child's own output tailing beneath them, then hands the
  live terminal to the App; a failed boot shows its error and log tail in
  place, waits for a key, and exits nonzero with the error on stderr after
  restore. Every non-tty surface (`daemon`, `--print`, a pipe) emits exactly
  the plain lines it always did — `BootEvent::plain()` is pinned to them by
  test.
- Quit: in spawn mode the quit dialog offers **detach** (leave daemon
  running) or **shutdown** (`runtime.shutdown`, then SIGTERM after grace,
  SIGKILL last). In attach mode quit just disconnects.

### 3.3 Transport (`src/transport.rs`)

Tokio TCP; newline codec with an inbound size guard; JSON-RPC correlation map
(u64 ids); notification fan-out to the UI event loop; auto-reconnect with
exponential backoff; on reconnect, re-`hello`, re-subscribe every watched
session with its last seen `sequence` as cursor, and reconcile via `replay`.
`stream.lagged` triggers the same replay path — one code path for both. That
path also owns the `cursor_pruned` arm: restart from the returned floor and
render a "history truncated below N" divider in the transcript, and treat
`stream.ended` as a terminal marker (stop expecting live events).

**"Last seen `sequence`" is the contiguous high-water mark, not the newest event.** Found
while implementing, and it is the whole correctness of the resync: after a lag the newest
sequence a client holds is a *live* event from after the hole, so replaying from it would
step over the missing history and produce a transcript that looks complete and is not. The
cursor is therefore the largest `N` such that every sequence in `(floor, N]` is held, and
it is the same number for all three causes.

There is a **fourth** cause, and it is the client's own: `Client::dropped_notifications`
counts frames the gateway sent that this process could not take. It is indistinguishable
from `stream.lagged` from the transcript's point of view, so it is repaired identically —
except that the counter does not say *which* session lost frames, so every watched session
is replayed.

Two consequences of `subscribe`/`replay` both answering "the retained events after this
cursor, in order":

- A batch whose first entry is above `cursor + 1` **proves** the ones between are no
  longer retained, and raises the floor without any `cursor_pruned` having been sent. The
  gateway had no reason to send one — the cursor itself was still inside the window.
  Without this the transcript would show a hole that can never fill.
- A prune raises the floor but must **not** discard what the client already holds. Events
  obtained before a prune are real history; the divider is placed where the hole is
  instead of at the top. The same divider marks the client's own window when a long
  session runs past it, so "history truncated below N" means one thing whichever side
  dropped it.

Two more facts the implementation had to add rather than discover at runtime: a second
interruption arriving while a repair is in flight is *remembered*, because responses and
notifications reach the UI on different channels and are not ordered against each other,
and the answer already in flight was asked from a cursor that predates the new
interruption. And the number of replay rounds one interruption may cost is bounded (40 ×
500 events, more than the upstream retention window); past it the transcript keeps its
visible gap rather than looping against a session producing history faster than a client
can read it.

### 3.4 Model & UI (`src/model.rs`, `src/ui/`)

Serde types for the golden-fixture shapes, all tolerant: unknown fields
ignored, every enum has an `Other(String)` arm, and any payload can fall back
to `serde_json::Value` rendered by the **generic tree widget** — the Rust half
of the polymorphism story. Concrete cases the types must carry: availability
is tri-state (`available` / `unavailable` / `disabled` —
[ouroboros.ex:140](../lib/ouroboros.ex)), and `interactive.list`/`info` return
`Ouroboros.Interactive.State` structs (Wire-tagged), not bare maps.

One shape worth stating because the source misleads: **`status.cluster` has no `mode`
key.** `Ouroboros.Cluster.status/0` returns
`{node, role, distributed, connected_nodes, roles, formation, security}`
([cluster.ex:206](../lib/ouroboros/cluster.ex)); the `%{mode: :unavailable}` that appears
next to it in [ouroboros.ex](../lib/ouroboros.ex) is the *fallback* used when the call
fails, not the shape of a successful one. A client must therefore treat `cluster` as
either — which is exactly what the "unknown fields ignored, fall back to the tree widget"
rule already buys it. `runtime_status_result.json` pins the successful shape.

Tabs (build order within §5): **1 Dashboard** (node/role, availability
matrix from `status.availability`, connected nodes, providers), **2 Sessions**
(interactive + coding lists; focused session = conversation-first scrollback via replay +
live tail, input box, approval modal), **3 Agents** (list + state tree +
`last_effects` if present), **4 Teams**, **5 Plans/Control**, **6 Upgrade**
(rollouts, history, signing decisions, grants-by-principal prompt), **7 Logs**
(spawn mode only; attach mode shows "logs live with the spawner").

The focused session opens as **Agent chat**. It renders durable `input_accepted` text as
the user's message, collapses output deltas into the corresponding final agent message,
correlates normalized tool calls/results into compact activity cells, and renders file
changes and bounded unified-diff excerpts without interpreting them as execution authority.
Gaps, pruning, lag, terminal state, approvals, and actual failures remain visible in chat
because hiding them would make an incomplete or failed conversation look healthy. Approval
request IDs remain presentation correlation only: a matching resolution replaces
“Approval needed” with the approved/denied outcome while the raw pair remains in event
details.

**Every normalized event kind is presented; nothing reaches this projection and vanishes.**
`PresentationEvent::from_event` matches all twenty-nine `Jido.Harness.Event` types
exhaustively — adding one without a presentation is a compile error — and the single arm
that draws nothing, `Hidden`, carries the reason it drew nothing.

| Kind | Cell |
|---|---|
| `input_accepted` | the user's message, a steer note, or "[message not recorded]" when the ledger holds no words |
| `output_text_delta` / `_final` | the agent message, deltas collapsed into their final |
| `thinking_delta` | a reasoning cell, accumulated per turn, three-state (below) |
| `tool_call` / `tool_result` | one activity cell correlated by `call_id`, summarised per tool (below); consecutive exploration collapses into one grouped cell |
| `command_output_delta` | a bounded **tail** of command output — the newest rows, with the earlier ones counted above them |
| `file_change` | file rows and a parsed unified diff: per-file grouping, line numbers, word-level emphasis, counted `+N −M`, and the turn's diffstat at its end divider |
| `plan_updated` | a plan cell, and the `Ctrl-T` panel |
| `turn_started` | no cell: its instant is what the turn's own end divider measures elapsed time from |
| `turn_completed` / `_failed` / `_interrupted` | a turn divider stating the outcome and the elapsed time; failures and interruptions keep their own loud cell above it |
| `run_started` | "run started · model · N tools", and the model in the session header — the only event that ever names one |
| `run_completed`, `session_started` / `_ready` / `_idle` / `_closed`, `turn_queued` | one dim lifecycle line; a closed session is a rule across the transcript |
| `run_failed` / `session_failed`, `run_cancelled` / `session_cancelled` | the error or interruption cell |
| `approval_requested` / `_resolved` | the correlated approval cell |
| `queue_changed` | the depth as one line when it changes, and `Watch::queue_len` for the composer chrome |
| `usage` | folded into `Watch::usage`; the per-event line appears under `Ctrl-O` |
| `provider_event`, and any kind a newer harness adds | one dim line naming the kind (and, for ACP, the `sessionUpdate` it wrapped) |

The only hides are payloads that carried no content — an empty output delta, an empty
reasoning delta, an empty command-output delta — and each names itself as the reason.

**A tool row says what the tool did, not what the vendor called it.** Three naming systems
reach this client and none agrees with the others: Claude's tool names, ACP's `kind` enum
(`read | edit | delete | move | search | execute | think | fetch | other`), and the item
types the Codex dialect normalises. One summariser keys on all three, so the same work
reads the same whichever produced it.

| Row | Read from |
|---|---|
| `Read path:12-51` | the path, plus `offset`/`limit` or `start_line`/`end_line` where the call named a window |
| `Edit path (+3 −2)` | the line counts of `old_string`/`new_string`; a tool that describes an edit without carrying it gets no counts |
| `Write path`, `Delete path`, `Move path` | the path |
| `Grep "needle" in lib → 3 matches` | the pattern and scope; the count is of result lines this client holds, with a `+` when the value was bounded |
| `Glob **/*.ex → 12 files` | the pattern, and the same counted result |
| `Bash $ cargo test  exit 1  4s` | the command, an exit code where a payload carried one (`failed` where only `is_error` did), and the elapsed time |
| `Fetch https://…`, `Search "query"` | the url or query |
| `MCP linear.create_issue` | `mcp__server__tool` and `server.tool` both fold to `server.tool` |

Anything unmatched keeps the provider's own name and its own input rather than a verb this
client invented for it.

**Consecutive exploration is one row (Codex).** Read, grep, glob, and list calls with no
other cell drawn between them collapse into `Exploring… (4)` while the run is still
growing, and flip to `Explored 4 files` the moment anything else is drawn — including the
turn's own end divider. The row carries a spinner only while a call in it is actually
running; an open group whose calls have all returned gets Codex's bullet, because a client
that animates finished work is a client claiming something. `Ctrl+O` lists every call —
there is no per-cell focus in this transcript, so the row advertises the key that works
rather than an `Enter` the composer owns. Work the agent *did* — an edit, a command, a
fetch — is never folded into that count. The group lists sixty-four calls and counts the
rest.

**A tool result shows both ends.** The first six and last six lines, with
`… +N lines · ctrl+o` between them: the last rows of a result are where the exit status,
the summary, or the failure is, and a head-only excerpt is why a collapsed tool row used to
be worth nothing. A **failure** gets the head alone — the `is_error` text is written first
and does not belong behind six rows of its own tail. Streaming `command_output_delta` is
the mirror image: a live tail window of the newest rows, because a command still running is
watched at its end.

**Elapsed time comes from the ledger, never from a clock.** A finished call is its result's
instant minus its own; one still running is measured against the newest instant this window
holds, which is a floor rather than a reading. The projection reads no clock at all, which
is what makes one watch render and export to the same bytes — and what makes a running
timer stand still between events.

**Diffs are parsed once.** `ui/diff.rs` reads files, hunks, per-side line numbers,
add/delete/rename/binary status, and the word-level difference between a removed line and
the added one that replaces it — pairing them only when the two runs are the same length,
because emphasis pointing at the wrong words is worse than none. Rendering gets a
two-column line-number gutter (dropped whole, not shrunk, on a pane too narrow to hold it
and the content both), syntax colour on context lines through `code.rs` keyed on the file's
extension, and wrapping rather than truncation — a diff is often the only copy of a change
on screen. Collapsed spends twelve rows and names the key that opens the rest. Each
turn-end divider carries that turn's diffstat, `3 files · +120 −18`. Where a diff is the
subject of an unresolved `approval_requested`, it stays expanded and its header reads
`pending approval` until the matching resolution lands (Warp's rule); the approval modal
itself is a separate surface.

**Every count is counted here.** `Diff::additions` — the provider's own claim — stays on
the payload for `/details` and is never the number on screen. A provider that summarises a
400-line patch and sends a 40-line excerpt would otherwise have this client repeat a number
it cannot see. An excerpted diff says `in excerpt` beside its counts, and so does the
diffstat built from it.

**`/diff` is the review surface**, Claude Code's, scoped to what a client that never reads
the filesystem and never runs git can hold. It lists the files this session changed,
grouped by turn: `←`/`→` between "this session" and each turn, `↑`/`↓` between files,
`Enter` into a pager, `Esc` back out. Turns are counted by the same dividers the transcript
draws, off the same projection, so the list cannot disagree with the conversation about
which turn changed what; a file three turns touched is one row with the counts summed. The
footer names the scope's totals and, when the window has pruned, says the list is partial
and names the floor. Turn numbers count turns *this client holds*, not the session's.

**`/raw` is Codex's copy mode** and a second renderer rather than a flag inside the first:
no frames, no gutters, no glyph columns, no app-side wrapping, ASCII where a glyph would
otherwise be, one output row per logical line. It shows everything a compact cell folds. A
diff keeps its own `+`/`-` column — that is the file format, not this app's gutter — and
loses the line numbers this app adds. Both `/diff` and `/raw` are palette and slash only:
the composer owns the keyboard while a session is open. The honest limit is that this
client owns the screen, so a row wider than the pane is *clipped* rather than soft-wrapped
by the terminal; `/raw` makes a native selection yield clean logical lines, and `ctrl+x [`
and `ctrl+x v` remain the complete escape hatches for anything wider.

**`Ctrl-O` is verbose, `Ctrl-T` is the plan, `/details` is the ledger.** `Ctrl-O` redraws
the same conversation with every collapsible cell expanded in place (reasoning, tool
results, command output, diffs, long messages) and back again — which is what the key means
in Claude Code, Gemini CLI, Kiro, Pi, and Droid. `Ctrl-T` opens the plan/tasks panel above
the composer, showing the newest plan with `◌ ● ✓` for pending / in progress / done; it
stays drawn while the session is idle, because a task list that disappears with the spinner
is the one thing every plan widget of 2026 was criticised for. The complete normalized
event ledger is `/details`, `ctrl+x d`, or the palette, and still discards nothing.

Reasoning has Crush's three states: collapsed to one header row (`◇ thinking · N lines`) by
default, a tail of the last 200 lines with the earlier count named while it is still being
written, and everything under `Ctrl-O`. Collapsed is the default deliberately — reasoning
expanded by default in a long session buries the conversation it is about.

`Ouroboros.Gateway.Wire` markers never reach the screen as JSON: `_excerpt` renders as its
own prefix followed by "… (N bytes; full event via /details)", and `_opaque`, `_b64`, and
`_truncated` render as short labels. An excerpted diff is marked as an excerpt, so its
`+`/`-` counts are never read as a diffstat of the whole patch.

Redraw work is bounded in every view: chat projects the newest 128 entries and bounded
per-cell excerpts with an explicit omission marker, `Ctrl-O` raises the per-cell row ceiling
to 2,000 rather than removing it, and `/details` exposes every event retained by the local
5,000-event window. A tool result's compact ceiling is twelve rows — six of head and six of
tail — raised from the three it was before the head/tail layout; every byte cap on the
underlying values is unchanged. One diff parse keeps sixty-four files and twenty thousand
body lines and marks itself truncated at either ceiling. A ten-thousand-line tool result
projects and renders in a small fraction of one frame, because head/tail is chosen on
*source* lines before anything is wrapped: twelve rows cost one scan and twelve pointers,
not ten thousand wrapped strings.

Everything drawn *around* the transcript reads five accessors on `Watch` rather than
re-deriving the ledger differently: `usage()`, `queue_len()`, `active_turn_elapsed()`,
`latest_plan()`, and `model()`. All five are recomputed from the held events in the walk
that already ran after each absorb — a replay overlaps by design, and a total accumulated as
events arrived would count the overlap twice — and `UsageTotals::complete` is false once
pruning means the numbers are a lower bound.

Keys: `1-7`/`Tab` tabs, `j/k` move, `n` new session (Sessions tab), `i` composer /
`Enter` send, `Ctrl-C` interrupt active turn (never the TUI), `a` approval modal,
`s` steer, `Ctrl-O` expand/collapse the conversation's cells, `Ctrl-T` plan panel,
`/details` (or `ctrl+x d`) the event ledger, `ctrl+x [` transcript into the terminal's
scrollback, `ctrl+x v` transcript in `$EDITOR`, `Ctrl-E` opens `$EDITOR`, `,` settings,
`q` quit dialog, `?` help with the authoritative key map.
`s`, `a`, and the interrupt hint are **conditional**: see
"Capability-driven chrome" below. `/diff` (also `/changes`) opens the review overlay and
`/raw` toggles copy mode; both are reachable from the palette and neither takes a chord,
because the composer owns the keyboard while a session is open.

### The footer

Three rows, in this order from the bottom: the footer itself, an optional scripted status
line above it, and above that the pane.

The footer's left half states what the runtime declared about the **open interactive
session**, and its right half the keys that will actually work on it. Everything on the
row is `·`-separated, and every cell has a rank: when the row runs out of width the
lowest-ranked cell is *dropped* rather than ellipsized, because a truncated `12.3k tok…`
is a fact rendered as noise. The ranking is one list across both halves — deciding each
half against its own budget is how a footer ends up with a `ctrl+q quit` hint and no model
on it.

| Cell | Source | Notes |
|---|---|---|
| `● LIVE` / `● DISCONNECTED` | the transport | never dropped |
| `OWN RUNTIME · operate · 127.0.0.1:4560` | spawn mode, `hello.scope`, the address | the first thing to yield: it is on the Dashboard and in the header |
| model | `interactive.info` `options.model`, else the transcript's `run_started.model` | absent where neither said |
| `⏸ prompt` / `⏵⏵ auto-edit` / `✓ auto-approve` / `⏵ default` | `options.approval_mode` | absent where the start omitted it — the plane's default then applies, and this client does not know what it is |
| `workspace-write` | `options.sandbox_mode` | its own cell, so the mode survives a narrow row without it |
| `⠙ Working 4m 07s` | the session status plus the newest unterminated `turn_started`'s timestamp | Codex's format; ranked with `esc interrupt`, because they are one statement |
| `3 queued` | the newest `queue_changed`'s `queued_turns` | absent, not zero, where no such event has been seen |
| `2 approvals` | the approval requests this client holds unanswered | |
| `42.5k tokens` | `usage.total_tokens` | a `· 34%` share is appended **only** where the runtime reports a context window. Nothing reports one today; `runtime.models` is where it is meant to arrive, and dividing by a client-side table of model windows would be a lie presented as a measurement |
| `$0.42` | `usage.cost_usd` | `<$0.01` for a spend too small to show, never `$0.00` |
| `esc interrupt` | conditional; see below | |
| `ctrl+p commands`, `ctrl+x leader`, `ctrl+q quit` | this client | the last two are also on `?` and in the palette, so they yield first |

The notice line keeps precedence: while a notice is showing it owns the whole row, folded
onto one line, exactly as before.

### Capability-driven chrome (B0, [AGENT_EXPERIENCE.md](AGENT_EXPERIENCE.md) D14/X1/X2)

`Interactive.State.public/1` projects `options.capabilities` — a map the runtime derives
from the transport a session actually selected, with the keys `transport`, `process`,
`multi_turn`, `follow_up`, `interrupt`, `approvals`, `steer`, `multimodal`,
`dynamic_model`, and `dynamic_configuration`, whose values are a mechanism name
(`native` / `managed` / `process`) or `false`. The client decodes it as **three** states,
and the third one is the point:

- a value the runtime gave → *declared*, and the mechanism is kept verbatim, because
  "managed" and "native" are different promises about *when* a control takes effect;
- `false` → the transport cannot do this at all;
- **anything else — no map, an absent key, a shape this build cannot read — is *unknown*,
  never "no".**

Only an explicit `false` takes a control off the screen. An older gateway that sends no
map at all changes nothing, because hiding a key on a gateway's silence would be this
client inventing a ceiling it was never told about.

What that gates today, in all four places a verb is advertised — the footer, the command
palette, the `ctrl+x` which-key overlay, and `/` completion in the composer:

- the Steer verb, `s`, `ctrl+x s`, `/steer`, and the palette's Steer entry exist only
  where `steer` is truthy, which is `pi` alone (X2). Where it is `false` the key answers
  with the transport's name and points at the durable follow-up queue instead;
- `a`, `ctrl+x a`, and the palette's approval entry only where `approvals` is truthy, and
  where it is `false` the key says *why* nothing will ever open that modal rather than
  "not waiting on one" (X1);
- `esc interrupt` in the footer, the palette's Interrupt entry, and `/interrupt` only
  where `interrupt` is truthy — and the footer adds the second condition that a turn is
  actually running;
- `multimodal` has a predicate and no affordance yet. B4 is the slice that builds one; the
  predicate is here so the capability and its consumer arrive together rather than the
  affordance arriving first.

The `n` dialog reads the other half of the same story out of `runtime.providers`, whose
`normalized_options`, `normalized_values`, and `session_transports` the client already
received and never used. It greys a mode the selected provider cannot take, dim and
naming whose limit it is: `prompt — not offered by claude (no approvals channel)`,
`prompt — not offered by pi (takes only default, auto_approve)`. The rule mirrors
`Ouroboros.Provider.safety_options/3` exactly — an option the selected transport does not
normalize takes only `default`; one it normalizes with an allowlist takes only what the
allowlist names; and `prompt` is refused on a transport whose `approvals` is `false`
because a mode that promises a human is asked cannot be honoured with no channel to ask
through. A greyed value stays **selectable**: the runtime is the authority on whether a
start succeeds, and the refusal it returns renders on the form that produced it, as it
always did. Where the spec does not resolve, nothing is greyed — greying on a guess would
be worse than greying none.

### The scriptable status line

`[statusline] command` in `config.toml`, off unless set. Its first line of stdout is drawn
in its own row above the footer; the row does not exist when the command is unset, fails,
or prints nothing.

The contract, narrowed from Claude Code's `statusLine`
([R2 §5](research/agent-ux-2026/R2-display-rendering.md)) to what this client can promise:

- run through `sh -c`, on the machine the **client** is on — which is not necessarily the
  machine a fleet session is on, so a fleet session's `git branch` is not this command's
  to read;
- one JSON object on stdin, with fixed keys and `null` where a fact is unknown:

  ```json
  {
    "session":  {"id": …, "provider": …, "model": …, "workspace": …, "machine": …, "status": …},
    "modes":    {"approval_mode": …, "sandbox_mode": …},
    "usage":    {"input_tokens": …, "output_tokens": …, "cache_read_tokens": …,
                 "cache_creation_tokens": …, "total_tokens": …, "turns_with_usage": …,
                 "context_window": …},
    "cost_usd": …,
    "elapsed_ms": …,
    "connection": {"state": "live"|"lost", "reason": …, "address": …, "scope": …,
                   "node": …, "spawned": true|false}
  }
  ```

  `session`, `modes`, and `usage` are `null` — not empty objects — when there is no open
  interactive session, or when the runtime reported no usage at all: a session that has
  spent nothing and one whose spend was never reported are different facts;
- **bounded**: 2 s, 4 KiB of stdout read at all, first line only, stderr discarded, the
  child killed on abandonment. A command that backgrounds a grandchild is beyond what a
  kill on the shell can reclaim, which is a limit of running arbitrary shell;
- **debounced 300 ms**, one invocation at a time, and re-run only when that object
  *changes*. `elapsed_ms` is deliberately outside the change comparison though it is still
  handed to the command: it moves every tick while a turn runs, and a status line keyed on
  it would never settle and would fork a process twelve times a second;
- ANSI SGR is honoured and becomes cell style. Every **other** escape sequence is removed
  rather than passed through — the row is drawn into a buffer this client owns, and a
  command emitting `ESC [ 2 J` would clear the frame around it. OSC 8 hyperlinks are
  dropped too, because Ratatui has no cell attribute for them;
- a failure renders nothing and is reported **once**. A status line that re-announced a
  broken command every frame would be its failure taking over the row it failed to fill.

It decides nothing. Its output is text on a row; the footer beside it still comes from the
runtime's own declarations.

### Notifications

`[notifications] mode = "auto" | "bell" | "osc9" | "off"` (default `auto`) and
`when = "unfocused" | "always"` (default `unfocused`), following Codex's
`tui.notifications` / `notification_condition`.

`auto` resolves to OSC 9 (`ESC ] 9 ; text BEL`) on the terminals R2 §5 records as
implementing it — iTerm2, WezTerm, Ghostty, kitty, matched on `TERM_PROGRAM`/`TERM` — and
to `BEL` everywhere else. A short allowlist rather than a probe: no query asks a terminal
whether it implements OSC 9, and guessing optimistically produces a notification that
silently never arrives.

Focus comes from CSI `?1004h`, enabled beside mouse capture and disabled on the way out.
A terminal that never reports focus is treated as focused forever, which is the safe
default for what it gates: with `when = "unfocused"` an unreporting terminal is silent
rather than constantly ringing.

Two things ring, both of them things a *session* did: `approval_requested`, and a turn
reaching a terminal state (`turn_completed`, `turn_failed`, `turn_interrupted`). Only for
sessions this client is subscribed to, only from the live stream, and at most two per
frame. A keystroke never rings, and neither does the backlog a replay hands over when a
session is opened — a three-day-old transcript must not become three days of bells.

The window title is OSC 0: `ouro · <glyph> <workspace basename>`, with `✦` working, `✋`
needs input, and `◇` idle (Gemini CLI's `dynamicWindowTitle` vocabulary, which is the one
that already distinguishes "busy" from "blocked on you"). "Needs input" is checked across
every subscribed session, because an approval on a session that scrolled away is exactly
what a title bar exists to surface; "working" is the open session's own status. On exit
the title is emptied, which returns a tab to the terminal's default — there is no portable
way to *read* the previous title back, so this restores the default rather than the exact
string that was there before.

Corrections and additions found while building it, recorded rather than left to be
rediscovered:

- **An ACP edit is a `file_change` now, not an opaque provider event.** ACP v1 carries a
  file edit as a `{"type":"diff","path","oldText","newText"}` block inside a tool call's
  `content` — its `SessionUpdate` union has no `diff` arm — so the ACP dialect reads those
  blocks off `tool_call`/`tool_call_update` and emits a `file_change` beside the unchanged
  tool event, in the item-level `{"changes": [{"path","kind","diff"}], "status"}` shape the
  transcript already parses. The `diff` is generated here, not by the agent: line-wise from
  `oldText`/`newText` with three lines of context and `--- a/<path>` / `+++ b/<path>`
  headers, which is where the client gets the path and the +/- counts. Either side over
  1 MiB is replaced by those headers plus a single `@@ truncated: N bytes @@` line rather
  than a megabyte crossing the socket on every replay. A `kind` is `add` when ACP reports a
  null `oldText`, `delete` on a null `newText`, `update` otherwise.
- **ACP session modes and slash commands arrive as bounded `provider_event`s the client may
  render later.** `available_commands_update` becomes
  `{"kind": "available_commands", "commands": [{"name","description"}, …]}` (names and
  descriptions only, at most 64, each cut to 200 characters); `current_mode_update` becomes
  `{"kind": "mode", "mode": <id>}`; the `modes` an agent returns from `session/new` become
  `{"kind": "modes", "mode": <current id>, "modes": [{"id","name","description"}, …]}`
  emitted next to the session-ready event. Nothing in the TUI renders these yet — they are
  visible in `Ctrl-O` event details, and switching a mode still needs `session/set_mode`,
  which this dialect does not send. `user_message_chunk` stays opaque on purpose: it is the
  agent echoing the prompt the runtime just sent, and `input_accepted` already carries the
  authoritative text.
- **`Enter` alone cannot mean "send".** Typing into an input box and `1`-`7` selecting a
  tab are the same keystrokes, so there is an explicit composer: `i` (or `Enter` on an
  already-open session) opens it, `Enter` sends, `Esc` closes it. Without the mode, the
  letter `s` in a message would steer the session.
- **The composer is a real bounded editor.** It is Unicode-safe (grapheme-aware motion
  and deletion, display-width wrapping), accepts multiline input with the
  terminal-independent `Ctrl+J` — `Shift+Enter` also works, but only where the terminal
  reports the kitty keyboard protocol, and the footer advertises it only then, because a
  terminal that cannot distinguish `Shift+Enter` from `Enter` would send the message
  instead — normalizes bracketed-paste line
  endings, retains bounded history for the current editor, and completes local slash
  commands and `@` paths. The file catalog is a bounded, symlink-safe index of the local
  launch workspace. Selecting `@path` inserts prompt text only; it does not yet create a
  structured attachment or follow an attached runtime's active workspace. The gateway's
  closed turn envelope supports attachments so that later picker can be runtime-aware
  instead of treating a local path as if it necessarily existed remotely.
- **Same-session mutations cross the gateway in Enter order.** JSON-RPC handlers run in
  independent tasks, so the composer sends only one message/follow-up/steer request at a
  time. If Enter is pressed while the preceding acknowledgement is outstanding, the new
  draft remains visibly editable and unsent. After the earlier request is accepted—or
  reconciled under its stable turn ID—the operator presses Enter again to send the draft.
- **`h`/`l` and the arrows** move between the panes of a tab and collapse/expand a tree
  node; `Esc` unwinds one level at a time (composer, then transcript, then the session);
  `ctrl+x x` or `/close` ends the open session, or the highlighted row in the session
  switcher (`ctrl+x l`), behind a confirmation. Live interactive sessions offer close or
  kill; a live coding task offers cancel. A terminal session (`failed`/`lost`/`closed`/
  `completed`/`cancelled`) is removed via `interactive.delete`/`coding.delete` so it
  leaves the list instead of lingering until the seven-day retention sweep. An offline
  last-known row is hidden in this client only; `x` in the switcher is the key because
  the composer owns printable characters. `r` refreshes the visible tab now.
- **`Ctrl-C` on the coding plane is refused rather than translated.** That plane has no
  interrupt — cancelling is what it offers, and cancelling is destructive enough to go
  through the confirmation instead.
- **The approval modal offers exactly four answers** — `approve`/`deny` × `once`/`session`
  — because that is `Jido.Harness.ApprovalResponse`'s two enums crossed. `r` on that
  chooser attaches the optional `reason` the gateway accepts. Interactive Codex sandbox
  escalations (`git commit` writing `.git`, extra writable dirs, network) use this same
  modal over app-server. Deny-for-session is still `decline` — Codex has no persistent
  deny-for-session. Coding `exec --json` never opens it.
- **Session creation states its choices rather than defaulting them.** `n` on the
  Sessions tab opens a form carrying plane, provider, workspace and approval mode;
  `ouro new` is the same request from a shell. Both build their parameters through one
  `model::StartRequest`, which emits a strict subset of `Gateway.Methods`
  `@start_options` — `provider`, `workspace`, `approval_mode`, `sandbox_mode`, and
  `objective` on the coding plane — omits anything unanswered (an empty workspace box is
  *no* workspace, not `""`, which `option_value(_, :string, _)` would refuse), and never
  sends `id`. The plane defaults to workspace write where the provider can take it;
  `--sandbox-mode read_only` and the settings/files row launch a session that cannot
  edit. `/write` (ctrl+x w) starts a new session with `workspace_write` when the open
  one cannot edit. Two places the client is stricter than the gateway, both stated in
  the refusal: a start with no provider from any source is refused here, because letting
  the node's default decide would be a terminal choosing which vendor runs the operator's
  code — the config file's `[defaults] provider` satisfies this by being a choice the
  operator made once, explicitly, and the form it prefills stays editable; and
  `objective` is required on the coding plane and refused on the interactive one.
- **The transcript-first coding home is the front door.** `ouro` lands on the Sessions
  tab instead of an onboarding/provider-picker modal. A ready provider focuses the composer
  immediately. Codex is gated by the managed ChatGPT account flow; Enter connects while
  `/` commands remain available without sign-in. An explicitly configured non-Codex provider
  owns its own authentication and is not blocked by OpenAI account state. Enter then runs the
  same `StartRequest` path as `ouro new`, waits for the new session ID, then sends the
  retained first message with a stable logical turn ID. The draft is cleared only after
  that message is accepted. An outcome-unknown answer restores the exact text and same ID
  for reconciliation; a definite or terminal refusal restores the text with a fresh ID
  (`:busy` switches to the durable follow-up queue). Pending reconciliation IDs are kept
  per session across composer closure and session switches. Recent sessions and account
  state load behind this first frame.
- **Every frame is one synchronized update.** `terminal.draw` is wrapped in DEC mode 2026
  (`ESC [ ? 2026 h` … `ESC [ ? 2026 l`), written through the backend's own writer so the
  bracket cannot race the frame's bytes. Ratatui hides and shows the cursor at the end of
  `draw`, which puts those escapes *inside* the atomic update — leaking them outside is
  what makes a cursor flicker visibly in WezTerm ([R2 §8](research/agent-ux-2026/R2-display-rendering.md)).
  Both sequences are emitted unconditionally: a terminal that does not know the mode
  ignores a private mode set and reset, and probing would buy a round trip and a wrong
  answer from every terminal that lies about `DECRQM`.
- **The alternate screen has two doors back out.** Owning the screen costs `Cmd+F`, tmux
  copy mode, and drag-to-select, and shipping that without an escape hatch produced the
  loudest rendering complaints of 2026. `ctrl+x [` (palette: "Print transcript into
  terminal scrollback") leaves the alternate screen, writes the whole retained
  conversation into the *normal* buffer where the terminal's own scrollback keeps it,
  re-enters, and repaints. `ctrl+x v` ("Open transcript in `$EDITOR`") writes the same
  text 0600 under the data directory, opens it in `$VISUAL`/`$EDITOR` through the same
  suspend/restore the composer's `ctrl+g` uses, then removes the file; it never touches
  the draft. Both render `ui::export`, which projects through the same
  `transcript_cells::project` the pane does and then drops the render caps and the
  gutters: full tool results, full diffs, dividers, notes, and a timestamp on each of the
  operator's own messages. Prose folds to the terminal's current width; diffs, tool
  output, and command output stay **verbatim**, because re-wrapping a unified diff
  destroys it and a terminal's own soft wrap is what makes a selection yield the logical
  line back. The last line states whether the retained window dropped anything — the
  export can only carry what this client still holds.
- **The captured mouse says so, once, and can be turned off.** `[terminal] mouse = false`
  in `config.toml` captures nothing: native selection and the terminal's own wheel
  scrolling work exactly as they do in a shell, and `ouro` scrolls by keyboard only. The
  default stays `true` — a setting that changed behaviour by appearing would be the silent
  screen-model change this client refuses to make — and it is read before the boot screen
  takes the terminal, because a capture enabled there and dropped a second later would
  already have cost the operator their first selection. Where the mouse *is* captured, one
  line says so on the first frame (or on the first wheel event, if something ate that
  notice) and never again: `onboarding.mouse_hint_shown`. It names the modifier only where
  this build knows it — Option on iTerm2, Fn on Terminal.app, Shift on the terminals that
  identify themselves in `TERM_PROGRAM` — and an unidentified terminal is told all three
  rather than the wrong one.
- **`,` opens settings.** Runtime facts labeled as the runtime reports them, beside
  this client's own `[defaults]` — provider picker over the same probed list the `n`
  dialog uses, workspace, approval mode, and sandbox mode — with an explicit
  `[ save ]` row (the `[ start ]` idiom) and "changed, and not written yet" stated
  until it is.
- **Machines is a runnable fleet menu.** `/machines` (also `,` → machines) lists known
  Tailscale/SSH hosts and the rest of the fleet actions. Enter runs the selected row
  after any form/confirm it needs: add (SSH or an enroll recipe), create, join/enroll,
  invite, service install, status, doctor, and roster export. A first create or add on a
  standalone Mac restarts once. Invitation bytes never appear on screen, in argv, or in
  the recipe. A Mac binary is never copied onto Linux. Provider sign-in stays on the
  destination. `y` still copies the equivalent CLI.
- **Machines keeps membership removal and state retirement separate.** Its guidance says
  cancel/import preserves offline session-owner rows. Only after inspecting/exporting the
  removed owner's state, importing the signed roster, and restarting does it show the
  exact local `ouro fleet sessions forget --machine NAME --accept-state-loss` command.
  Operators must repeat it for every gateway/data directory that may have observed the
  owner; it is irreversible local evidence removal, not credential revocation.
- **On a tty, `ouro new` shows the session id rather than printing it.** A `println!`
  would land in the alternate buffer and be overdrawn; the id is on the boot screen,
  the notice line, and the Sessions tab. `--print` and any non-tty stdout print it
  exactly as before.
- **An uninstalled provider is drawn dim and stays selectable.** "Installed" is a probe
  finding an executable; the runtime is the authority on whether a session can start,
  and refusing on a heuristic would be this client overruling it.
- **A refusal is shown on the form that produced it, as a sentence.** Most `-32006`
  messages describe the shape of the failure and leave the actionable part in `data`;
  a client that dropped it would show "the runtime refused the call" where
  `["invalid_workspace", "/srv/nope"]` was available. `model::refusal` is the one
  place a refusal becomes text (the `n` dialog, the coding home, the notice
  line, and `ouro new`'s stderr all call it): a payload shaped `[tag, map]` renders as
  `provider: message (details)`, every key the sentence did not use lands verbatim on
  a dim second line, and the single deliberately dropped key is Wire's
  `__exception__` envelope marker — a fact about the encoding, not the failure. Any
  shape it does not recognise keeps the compact JSON untouched, because a prettifier
  guessing at unknown payloads is a prettifier asserting things the runtime did not
  say.
- **`runtime.providers` is not on the status cadence.** Each entry probes an installed
  executable by shelling out ([methods.ex] `@provider_probe_timeout`), so polling it
  beside `runtime.status` would fork a process per provider every three seconds. It
  refreshes on tab entry, on `r`, and once a minute. Transcript data is never polled at
  all — that is what the subscription is for.
- **`hello.methods` gates the client's own calls, not just its dialogs.** A verb this
  build does not serve is answered locally with `-32601` and the pane says which method is
  missing, in the place the data would have been. A client that discovered the gap by
  trying could not tell an older gateway from a broken one.
- **A list the runtime *refused* says so where the rows would be.** "No control runs" and
  "the control plane is not running on this node" are different facts, and a `-32004`
  rendered as an empty list is the second reported as the first.
- **The Logs tab exists in both modes.** In attach mode it says logs live with the
  spawner, which is a truthful pane rather than a hidden tab; the gateway streams no logs
  (§6 defers it).

### 3.5 Rust tests

Codec framing (split/joined/oversized lines); golden-fixture decode (the
files from `mix ouroboros.gateway.golden` — CI fails if either side drifts);
extractor against a tiny fixture tarball (sha mismatch refuses); reconnect
resubscribe logic against a scripted fake server; integration smoke gated by
`OUROBOROS_TUI_INTEGRATION=1` (spawns a real dev daemon: hello, status,
live UI data, and a typed subscription refusal without starting a provider turn);
config file round-trip, unknown-key tolerance,
corrupt-file fallback, atomic save, and XDG resolution; the boot phase
machine (`BootProgress`) and its pinned plain-line equivalents; the
onboarding suite (the transcript-first account gate, configured non-Codex path,
Enter's full path including stable first-turn ID and prompt recovery, settings prefill,
and `ouro new` resolution order).
Honest gaps: the automated suite neither allocates a pty nor starts a real provider —
every bundled development provider invokes a real CLI and may bill an account.
`Boot::begin/drive/fail/
finish` and `Screen::enter` are exercised only by manual pty runs; a real
successful spawn's phase sequence needs the integration gate, while provider-backed file
editing, commands, and rendered progress need an explicit manual end-to-end run; `ouro new`
`persist`'s unwritable-path branch is untested. The
refusal-rendering suite pins the humanised `[tag, map]` shape, the
no-field-lost remainder, and byte-identical compact JSON for six unrecognised
shapes; `ouro new`'s stderr path shares the function but is not driven
end-to-end.

---

## 4. Packaging & distribution

**Built, not a justfile.** [`Makefile`](../Makefile), because `just` is not a
dependency this repository already has and a second build tool is a worse tax
than a plainer syntax. Same verbs: `dev` (deps if absent + `cargo run -- --dev`),
`test` (mix test; cargo test/fmt/clippy, *twice* — `embed` is off by default, so
one pass never compiles the extractor at all), `golden` (regen + `git diff
--exit-code`), `release-tarball`, `ouro`, `dist`. Recipes compute the version and
target triple in the shell, so the file needs no GNU extensions and the version of
record stays the name `mix release` gave the tarball.

**The tar step.** [`mix.exs`](../mix.exs) gained `steps: [:assemble, :tar]`, which
is what produces `_build/prod/ouroboros-<version>.tar.gz`. `make ouro` passes that
path absolute in `OUROBOROS_RELEASE_TARBALL`; `build.rs` reads the bytes,
sha256s them, and writes `include_bytes!` plus the digest and version into
`OUT_DIR`. The version is parsed from the filename at the first hyphen *followed by
a digit* — splitting from the right reads `ouroboros-0.2.0-rc.1` as version
`rc.1`, which files a prerelease under a directory name sharing nothing with the
release inside it.

**Measured, on a real release** (Apple M-series laptop, OTP 29 / erts-17.0.2,
release 0.1.0):

| | |
|---|---|
| release tarball | 18 MB (2,841 entries, ERTS included) |
| `ouro` with it baked in | 20 MB stripped (19,765,728 bytes) |
| extracted release on disk | 53 MB |
| cold `ouro daemon` (extract + boot + publish) | 2.8–4.0 s |
| warm `ouro daemon` (cache hit + boot + publish) | 1.1 s |
| `ouro attach` start → `runtime.status` rendered | 7 ms |

The warm path does not hash the payload: the cache is keyed by the digest the
build recorded, so recognising an extracted release is a directory lookup rather
than a pass over eighteen megabytes of the binary. Reuse restamps the directory,
so the GC's "newest two" means most recently *started*, not most recently
unpacked — otherwise the release a daemon is running out of ages out from under
it after two upgrades.

- **CI matrix** builds per target — the release must be built on the exact OS/arch
  because ERTS is not cross-compiled: `macos-15` (aarch64-apple-darwin),
  `macos-15-intel` (x86_64-apple-darwin), `ubuntu-24.04` (x86_64-unknown-linux-gnu),
  `ubuntu-24.04-arm` (aarch64-unknown-linux-gnu). Artifact:
  `dist/ouro-<version>-<triple>`, e.g. `ouro-0.1.0-aarch64-apple-darwin`, produced
  by `make dist` so CI and a laptop cannot drift. This is the same ERTS/arch
  identity constraint the forge verifier already enforces for artifacts
  ([mix.exs](../mix.exs) release comment).
  The release workflow downloads the complete matrix, verifies every target,
  writes `SHA256SUMS`, and creates or updates the tag's GitHub Release. **Status:
  written, never executed.** The configured repository remote is not a public GitHub
  release channel, and no tag has reached this workflow. Local builds are evidence about
  the commands, not evidence that downloadable assets already exist. `.gitignore`
  covers `*.tar.gz`, `/tui/target/`, and `/dist/`.
- The supported deployment artifact is `ouro`, including generated fleet services. A
  plain release tarball or raw-release container remains unsupported until it ships the
  trusted native process-incarnation and recovery-lock helper too.
- Version skew: `hello.protocol` is the only compatibility contract. Mismatch
  → the TUI prints both versions and the one-line fix. The runtime's own
  modules may change hourly under the upgrade lanes — the protocol integer is
  what moves slowly and deliberately.
- README: a "Terminal UI" section (spawn vs attach, how a client finds a runtime,
  SSH-tunnel recipe, env passthrough, keys deferred to the in-app `?`) and an
  **Honest limits** block (token ≠ sandbox; loopback boundary and what
  `ALLOW_REMOTE` does *not* add; one-gateway fleet routing; logs-with-spawner;
  env-token deployments not discoverable by a bare `ouro attach`). Both stale
  lines are gone: the intro no longer lists a terminal UI among what this does
  not provide, and "There is no polished terminal UX yet" under Current limits is
  now a description of what the client is and is not, plus the never-run CI.

---

## 5. Execution plan (four PR-sized slices, each green before the next)

1. **Gateway core (Elixir).** `Gateway.{Config,Wire,Listener,Conn,Methods}`,
   read-scope methods, auth + scopes, runtime.exs wiring, logger-to-stderr,
   `env.sh.eex` dist-none posture, verifier prefix + test, gateway.json.
   Gate: full ExUnit suite incl. protocol/integration tests; forge loop passes
   with `RELEASE_DISTRIBUTION=none`.
2. **Streaming + operate scope.** Subscriptions, bounded queue + `stream.lagged`
   + replay-resync integration test, operate methods + audit lines, golden
   fixture mix task. Gate: lag test proves exact reconciliation; slow client
   isolation test.
3. **`ouro` client.** Transport, model, runtime spawner (dev mode first),
   CLI, Dashboard + Sessions tabs. Gate: `ouro --dev` drives a real session
   end-to-end on the laptop; golden decode tests green; reconnect/resubscribe
   test green.
4. **Full surface + packaging.** Tabs 3–7, embed + extract + GC, `ouro stop`/
   `daemon`/`attach`, Makefile, CI matrix, README. Gate: single downloaded
   binary on a clean machine reaches the Dashboard in one command; `ouro
   attach` over an SSH tunnel against a server runtime launched by `ouro` or its generated
   service.
   *Packaging landed against a real release rather than a fixture:* `mix release`
   → tarball → `cargo build --features embed` → the binary run on a scratch
   `XDG_DATA_HOME`/`XDG_CACHE_HOME`, extracting, spawning `bin/ouroboros start`,
   publishing `gateway.json`, answering `hello` and `runtime.status`, surviving
   `ouro attach`, and stopping through `runtime.shutdown`. Collection was proven
   the same way: three releases through one cache, the third start collecting the
   first. The SSH-tunnel half of the gate is still untested — no server has been
   attached to over a real tunnel.

Rough sizing: S1 ≈ 1.5–2k LOC (heavy on tests), S2 ≈ 1k, S3 ≈ 2–3k Rust,
S4 ≈ 1.5–2k mixed (includes greenfield CI across four targets). Each slice is
independently mergeable and leaves main releasable.

## 6. Deferred (recorded so they're chosen, not forgotten)

**The client does not yet know what `_excerpt` means.** The server-side cap and both
`event_detail` methods landed together (§2.4, §2.7); teaching
[tui/src/model/transcript.rs](../tui/src/model/transcript.rs) to render an excerpt as
truncated text with a "fetch the rest" affordance — and wiring `Ctrl+O` details to
`interactive.event_detail` (A9) — is a later slice. Until then the marker map renders as
compact JSON, and the interim cost is worth stating exactly rather than rounding off.

The 128 KiB per-leaf default was chosen against the client's own presentation ceilings in
[tui/src/model/transcript.rs](../tui/src/model/transcript.rs): `PRESENTATION_TEXT_BYTES`
and `PRESENTATION_VALUE_BYTES` are 64 KiB and `PRESENTATION_DIFF_BYTES` is 128 KiB — so
the server cap sits *above* the first two and exactly *at* the third. Content the client
was going to render in full still arrives in full, and nothing that was previously visible
became invisible. What changed is the far end: a payload past the cap used to arrive whole
and be trimmed client-side with "… diff truncated; full diff is available in event
details", and now arrives as a marker the client renders as JSON instead. That is a worse
cell for exactly the payloads this cap exists for, until the client learns the marker —
and it is the trade taken deliberately, because the alternative was five megabytes crossing
the socket on every notification and every replay to be thrown away on arrival.

`agents.start` behind a spec allowlist; a read-only web dashboard reusing the
same gateway; multi-cluster attach
profiles in `ouro`; Windows; log streaming to attach-mode clients; per-token
scopes (today scope is per-listener, set at boot); daemon reconfiguration
from arbitrary settings fields (a private fleet profile is the one implemented
runtime configuration path; Machines deliberately guides secret-bearing create,
invite, and join commands instead of executing them on an accidental keypress);
unknown-key preservation
through config saves; automated pty-level tests for the boot screen and coding home;
graying out approval/sandbox choices a provider cannot take in the `n` dialog
(`runtime.providers` already
Wire-encodes `normalized_options`, `normalized_values`, and
`session_transports`, so the client has the data — and since the runtime began refusing
`approval_mode: "prompt"` on a transport with no approvals channel (§2.4), the cost of
not greying it is one named refusal instead of a dead session, which is why this stayed
deferred rather than urgent); showing `usage` and `options.capabilities` anywhere in the
client (both cross the wire on every `interactive.info`/`list`; no surface reads them
yet); a workspace lease posture
that follows the provider's actual write capability rather than the stated
`sandbox_mode` alone; steer idempotency (the *text* is durable now — the session
coordinator stores the redacted steer prompt keyed by the `request_id`
`Session.steer/3` returned, bounded in memory, and enriches the
`input_accepted(kind=steer)` event carrying it, so replay quotes every accepted
steer exactly once; what remains deferred is a caller-supplied key, which the
pinned Harness worker does not accept — a lost acknowledgement still means the
provider may have received the same text twice); a keyboard path back to the advanced `n` session
dialog from the coding home (the composer owns `n` there, so the dialog is
reachable only with a session open — pinned behavior, chosen by nobody).
