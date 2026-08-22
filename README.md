# Ouroboros

Ouroboros is an experimental BEAM-native runtime for coding-agent teams. It uses
OTP supervision and Erlang distribution for lifecycle and communication, Jido for
inspectable agent/action/signal primitives, and Jido Harness for normalized coding
provider execution.

This repository is an executable architecture slice, not yet a Claude Code-class
product. It currently proves:

- supervised Jido agents addressed by logical ID across connected BEAM nodes;
- typed task and message routing over ordinary Erlang PIDs;
- detached Codex, Claude, Gemini, and other CLI runs through one normalized API;
- durable one-shot and interactive session checkpoints, exclusive-cursor replay,
  cancellation, multi-turn follow-up, and coordinator crash recovery;
- durable supervised teams that rebuild local or remote Jido projections and
  reattach in-flight coding tasks after a team crash;
- a dependency scheduler with fan-out/fan-in, global concurrency, stable execution
  tokens, failure/cancellation propagation, and a real Team execution adapter;
- an opt-in durable control plane that turns an objective into a validated DAG,
  evaluates terminal evidence, revises within a fixed budget, and cancels durably;
- a content-minimized, queryable effect ledger that checkpoints authority and intent
  before an agent action runs, records refusals and outcomes, and recovers unfinished
  attempts as explicitly ambiguous;
- optional symlink-safe workspace admission with read-sharing/write exclusion;
- a bounded, signed BEAM hot-patch lane with a durable node journal, cluster health
  gates, rollback, promotion, restart reconciliation, and explicit quarantine;
- a signing service on a role-isolated node: the key read at boot from a file that node
  mounts, an independent policy applied to the whole artifact before any signature
  exists, and a durable journal of every decision;
- offline OTP release metadata/archive validation plus a deny-by-default,
  write-ahead-journaled `:release_handler` control boundary;
- a token-authenticated loopback operator gateway, and `ouro` — one binary that carries
  a release, extracts it, starts it, and attaches to it, or attaches to one already
  running somewhere else; and
- real two-node behavior in tests using an OTP `:peer` OS process.

It does **not** yet provide partition-safe placement, durable provider execution
across a full BEAM/host restart, signing custody outside the cluster's distribution
trust domain, or aggregate cost budgets. The OTP release adapter is implemented, but a
real packaged-release install/reboot rehearsal remains an external deployment gate.

## Why Jido

Ouroboros deliberately does not reimplement agent structs, actions, CloudEvents-style
signals, AgentServer supervision, or coding-provider CLI adapters. Those come from
[Jido](https://jido.run/) and the pinned upstream
[`jido_harness`](https://github.com/agentjido/jido_harness) commit in `mix.exs`.
Ouroboros owns the boundaries those libraries do not: distribution-aware identity,
durable domain state, reliable replay/subscription, team delivery, workspace
admission, and upgrade policy.

## Run it

The fastest path is the terminal client: build `ouro` once and run it. It carries the
runtime inside it, starts it with zero configuration, and attaches — the first run shows
a welcome panel naming what it set up, and `n` starts a session.

```sh
make ouro
./tui/target/release/ouro
```

Use the `ouro` executable as the lifecycle entrypoint. Its embedded release relies on the
same native executable for exact process-incarnation checks and crash-releasing recovery
locks. A bare extracted `bin/ouroboros start` does not carry that helper and deliberately
fails before opening durable state; raw release and Docker launch packaging are not yet a
supported deployment path. Joining a cluster is deliberate configuration through
`ouro fleet`; see [Running a cluster](#running-a-cluster).

For the library from a checkout, the project currently targets Elixir 1.20 and OTP 29.

```sh
mix deps.get
mix test
iex -S mix
```

Probe a provider without starting a paid inference:

```elixir
Ouroboros.provider_status(:codex)
Ouroboros.providers()
```

Start a safe read-only coding task (providers whose adapters cannot enforce this
posture — amp, opencode, kimi — refuse it by name rather than running without it):

```elixir
{:ok, task} =
  Ouroboros.CodingSession.start("Inspect this project and report the riskiest gap",
    provider: :codex,
    workspace: File.cwd!(),
    sandbox_mode: :read_only,
    approval_mode: :prompt
  )

{:ok, backlog} = Ouroboros.CodingSession.subscribe(task, cursor: 0)

receive do
  {:ouroboros_coding_event, task_id, event} ->
    IO.inspect({task_id, event.type, event.payload})
end

{:ok, final_state} = Ouroboros.CodingSession.await(task, 300_000)
```

For iterative work, use a durable interactive session. A stable logical turn ID
makes retries idempotent, while the returned reference routes over distribution:

```elixir
{:ok, session} =
  Ouroboros.InteractiveSession.start(
    id: "review-session",
    provider: :codex,
    workspace: File.cwd!()
  )

{:ok, first} =
  Ouroboros.InteractiveSession.send_message(
    session,
    "Inspect the supervision tree",
    id: "inspect"
  )

{:ok, _result} = Ouroboros.InteractiveSession.await(session, first.id, 300_000)

{:ok, _queued} =
  Ouroboros.InteractiveSession.follow_up(
    session,
    "Now propose the smallest fix",
    id: "fix"
  )
```

`steer/3`, `respond_approval/3`, and `interrupt/2` route to native Harness
capabilities when the selected provider transport supports them.

Agent behavior can be assembled from a strict, versioned profile without moving
execution authority out of Harness:

```elixir
profile =
  Ouroboros.AgentProfile.new!(
    id: "repository-coder",
    base_prompt: "Work carefully in the requested repository.",
    instructions: [
      %{id: "user-work", text: "Preserve unrelated user changes."}
    ],
    skills: [
      %{id: "verification", version: "1", instructions: "Run the narrowest useful checks."}
    ],
    tools: [
      %{name: "Read", description: "Read files in the admitted workspace."}
    ]
  )

{:ok, task} =
  Ouroboros.CodingSession.start("Review the current change",
    provider: :codex,
    workspace: File.cwd!(),
    agent_profile: profile,
    allowed_tools: ["Read"]
  )
```

Profiles are prompt policy data, not executors. A listed tool grants nothing: its
description enters the assembled prompt only when the request explicitly allows the
same tool, and `disallowed_tools` wins. The runtime records content-free profile and
assembly digests for inspection; the user prompt remains a separate Harness input. At
admission, the profile is compiled into the durable `system_prompt` and the raw profile is
not checkpointed, so a rollback sees only the established Harness request shape. With no
profile, the existing valid `system_prompt` path is preserved byte-for-byte.

Control-plane calls (`info/1`, `replay/2`, `subscribe/2`, `cancel/1`, `steer/3`,
`respond_approval/3`, `interrupt/2`) are bounded by
`:ouroboros, :session_call_timeout` so one wedged coordinator cannot freeze every
caller; `await` keeps the caller's own timeout. If a provider session closes while a
dispatched turn never resolves, the turn is settled as `:ambiguous` with
`{:unresolved_at_session_close, turn_id}` after
`:ouroboros, :interactive_unresolved_turn_deadline_ms` — the provider work may have
happened, and the session is released rather than polled forever.

Writing is the default where the provider can be told so. The planes default to
`approval_mode: :prompt` and `sandbox_mode: :workspace_write`, but only for providers whose
adapters declare those options — the harness refuses any normalized option a provider
has not declared, and four of the nine bundled providers (amp, opencode, kimi, pi)
cannot take the pair in full. The two planes answer that differently: an
*interactive* session omits a default the provider cannot take and runs under the
provider's own behavior (reported as `null` in `interactive.info` options); a *coding*
task refuses at creation rather than silently dropping its documented workspace-write
default, and the refusal names the exact override to type (for example
`sandbox_mode: :default`). Pass `sandbox_mode: :read_only` for a session that cannot
edit files. An option the caller states explicitly is never rewritten or dropped on
either plane: a sandbox the provider cannot enforce fails loudly by name. The one
deliberate exception is Codex `provider_options.cli_path` on a runtime with managed
caches: executable selection is a node boundary, so every initial, recovered, and turn
request is pinned to the runtime-owned launcher. These normalized flags configure the
provider CLI; they are not a substitute for an OS/container sandbox when executing
untrusted work, and a session running under a provider's own behavior still takes the
same workspace lease the omitted default would have taken — the lease posture does not
yet follow the provider's actual write capability.

Per-run environment maps are rejected because task requests are checkpointed. Put
provider credentials in the service environment or a dedicated secret boundary,
never in task options. Persisted normalized event payloads are redacted before they
enter the Ouroboros store.

The bundled Codex policy is usable in a genuinely empty workspace: it passes
`skip_git_repo_check` and enables network access inside Codex's workspace-write sandbox,
so a first turn can create a repository and fetch ordinary dependencies. These are
durable, non-secret execution options and appear as the derived `provider_execution`
summary in public session state. A library caller can explicitly set either boolean to
`false`; explicit options win. Set `OUROBOROS_CODEX_NETWORK_ACCESS=0` to make the node's
default network-off. Network access does not widen the filesystem sandbox or turn the
gateway token into a sandbox.

When the runtime has a data directory, Codex also inherits managed language-tool homes
under `<data-dir>/provider-cache/codex`. Ouroboros provisions and authorizes Cargo, Mix,
Mix archives, Hex, and Rebar cache/config directories independently. Rust and Elixir
dependency downloads therefore neither fail against read-only global caches nor require
project-local tool homes; public session state reports which managed caches were actually
established. An operator-supplied absolute value for any corresponding environment
variable remains authoritative and is authorized explicitly. The managed Codex launcher
pins only these non-secret cache paths through Codex's shell-environment policy. Provider
commands keep the caller's inherited PATH and normal login-shell startup, while startup
hooks cannot replace the effective cache homes. Runtime ownership is claimed before the
launcher or provider configuration is touched; a losing runtime cannot rewrite the live
owner's artifacts, and an owner restart rebuilds the provider boundary before Jido or any
session consumer restarts.

At startup, and again in the eventual request working directory before each provider
invocation, Ouroboros runs the resolved upstream's local `codex sandbox` command with a
five-second bound to verify the *effective* shell policy. The second check covers
workspace-local Codex configuration without authenticating, starting a model turn, or
using the network. Codex applies `set` before `include_only`, so an existing allowlist
must retain its entries and append `CARGO_HOME`, `MIX_HOME`, `MIX_ARCHIVES`, `HEX_HOME`,
`REBAR_CACHE_DIR`, and `REBAR_GLOBAL_CONFIG_DIR`. Ouroboros does not replace or widen
that operator-authored allowlist. If the startup probe is unavailable, times out, filters
a cache, or executable resolution would make the launcher call itself, Ouroboros
installs a clear Codex-only refusal launcher; the core and every other provider still
start. A workspace-only mismatch exits 78 before Codex receives the provider argv. Fix
the named Codex policy or node-level executable and retry or restart as instructed.

Interactive Codex sessions use app-server, so a sandbox escalation — `git commit` writing
`.git`, extra writable directories, network — arrives as the existing approve/deny modal.
Public `provider_execution` reports `interactive_approvals: true` and
`escalation_behavior: :prompt` for those sessions. Deny-for-session is still `decline`:
Codex has no persistent deny-for-session, and Ouroboros does not invent one.

Coding turns still use Harness's managed `exec --json` transport, which cannot carry an
approval question back into Ouroboros. Coding public state, and interactive sessions that
opt into `transport: :exec_jsonl_resume`, therefore report `interactive_approvals: false`
and `escalation_behavior: :deny_when_provider_cannot_prompt`: an action that still needs
provider escalation is denied rather than presenting a button that cannot answer it.
`approval_mode: :prompt` configures Codex's policy; on app-server it is also a prompt this
runtime can complete. Approving once or for the session leaves the sandbox for that
command. Operators who want git without prompts still choose `unrestricted` or
`auto_approve` on purpose.

To enforce workspace admission, configure existing roots before application start:

```elixir
config :ouroboros, workspace_allowed_roots: ["/srv/agent-worktrees"]
```

The task coordinator acquires a lease before Harness can start or adopt a run.
Read-only tasks default to `:shared_read`; write-capable tasks to `:exclusive`.
Nonterminal durable tasks reserve their roots while a coordinator, registry, or the
workspace manager is being rebuilt, and only the exact registered recovery owner can
claim a reservation. These leases are node-local admission, not distributed consensus.

## Terminal UI

`ouro` is the terminal client, in `tui/`. It does two different jobs and the difference
matters: it can **spawn** a runtime — start one as a child process, own its lifecycle,
and attach to it — or it can **attach** to one somebody else started, on this host or
through a tunnel.

```sh
ouro                    # spawn a runtime, or adopt one already running here, then attach
ouro daemon             # spawn only: print the port, pid, and token file, then exit
ouro attach             # connect to the runtime published in this data directory
ouro attach --addr 127.0.0.1:4560 --token-file ~/.ouro-token
ouro new --provider claude --workspace .   # start a session and drop into the UI
ouro new -m "fix the tests"                # the same, with configured defaults filling the rest
ouro stop               # ask the runtime this client started to shut down
ouro version            # client version, embedded release version and digest, protocol
ouro --dev              # start `mix run --no-halt` in this checkout instead
```

Build it from a checkout. ERTS is not cross-compiled, so the binary is only valid for
the machine that built it:

```sh
make ouro    # mix release, then that tarball baked into tui/target/release/ouro
make dist    # the same, copied to dist/ouro-<version>-<target triple>
```

There is no `--token` flag anywhere, deliberately: a secret on a command line is
readable by every process on the host for as long as the command runs. A spawning client
writes 32 bytes of OS randomness to a 0600 file beside `gateway.json` and tells the
gateway the path. The internally extracted release reads that launcher-owned file; a
bare release is not a second supported token-generation or lifecycle path.

### First run and configuration

On a tty, `ouro` boots inside the UI: the extract/start/publish sequence renders as
live progress with the runtime's own output underneath it, and a failed boot shows its
error where it happened instead of after the screen is torn down. Then it opens on a
transcript-first coding home. A ready provider focuses the prompt immediately. Codex uses
the managed ChatGPT sign-in gate, where Enter connects and `/` commands remain available;
an explicitly configured non-Codex provider is not blocked by an unrelated OpenAI account.
Type what you want done and press Enter: an interactive session
starts in the displayed requested workspace, the first message carries a stable logical
turn ID, and the streaming transcript opens as a user/agent conversation. Lifecycle,
provider, usage, and other normalized events stay behind `Ctrl-O` in the complete
event-details view. The composer is Unicode-safe and multiline (`Ctrl+J` everywhere; `Shift+Enter` where the
terminal reports the kitty keyboard protocol, and the footer only advertises it there),
normalizes bracketed paste, keeps bounded in-session history, completes local slash
commands, and completes `@` mentions from a bounded index of the launch workspace. An
`@path` is currently prompt text, not a structured attachment; the gateway already
accepts a closed attachment envelope whose files are canonicalized beneath the leased
session workspace, ready for a future runtime-aware picker.

`,` opens settings: the runtime's facts as it reports them, and this client's own
defaults — provider, workspace, approval mode — which prefill the `n` dialog and stand
in for `ouro new` flags. They live in `~/.config/ouroboros/config.toml`
(`$XDG_CONFIG_HOME` honored), which is user preference, not runtime state: the runtime
itself is configured by environment, exactly as before. `ouro new` resolves provider,
workspace, and approval mode as flag first, then configured default; only a provider
that neither names is refused, and the refusal says where both live.

### How a client finds a runtime

The runtime binds an ephemeral port and publishes it to `gateway.json` in its data
directory — `OUROBOROS_DATA_DIR`, or when that is unset, the same derived default the
client uses (`$XDG_DATA_HOME/ouroboros`, else `~/.local/share/ouroboros`) — alongside its
PID, exact OS process-birth identity, protocol version, and scope. Nothing
pre-chooses a port, so two daemons cannot race for a number one of them picked in
advance. That file is removed on graceful shutdown and left behind by a kill, which is
why it carries a process incarnation: a publication whose PID is absent or whose PID was
reused with a different birth identity is stale and is replaced. An exact live
incarnation is never overwritten — a daemon this client cannot talk to is something to
report, not something to resolve by starting a second one on top of it. Upgrade-era
PID-only publications remain conservative: a live PID blocks, but never authorizes a
signal.

That data-directory leaf is itself a security boundary. Before any lifecycle lock,
storage probe, publication, token, or journal write, Ouroboros requires a real
same-user directory at exactly mode `0700`; a missing leaf is created that way. When
the packaged client chose the normal XDG default itself, it also restricts a same-user
legacy leaf from a broader mode to `0700` in place before taking over the terminal. An
explicit `OUROBOROS_DATA_DIR`, symlink, foreign-owned directory, or non-directory is
never repaired implicitly. Inspect an unsafe explicit directory's ownership and
contents first, then use `chmod 700 <path>` only when it is truly yours, or choose a
fresh absolute path. Every runtime spawned by `ouro`
also starts with umask `077`, including foreground/TUI Ring mode, so later Jido stores,
checkpoints, and rotated logs remain private inside that boundary. Harness-managed
provider subprocesses cross one boundary that restores the conventional workspace umask
`022`, so provider-created files and directories default to `0644` and `0755` in both
foreground and service modes.

`gateway.json` is discovery, not ownership: it can be missing or replaced while a live
runtime still owns the journals. A separate private `runtime.owner` marker is claimed
atomically before any durable core child starts and retained for the VM lifetime. A
second runtime fails closed while that exact PID-and-birth incarnation is alive; a dead
or reused incarnation is recovered once. A live legacy PID-only owner also blocks until
it can be upgraded or stopped through its existing supervisor. This prevents two daemons
from writing the same checkpoint even when publication state is stale.

Stale-owner recovery uses a private, persistent `runtime.owner.recovery` inode whose
advisory lock is held by a native helper for the complete atomic claim. A claimant or VM
crash closes that helper's port and releases the kernel lock, so a generated service can
retry unattended. The inode itself normally remains; its versioned contents let new
clients distinguish this safe coordination primitive from an old or malformed gate.

Client spawn serialization follows the same fail-closed rule. `spawn.lock` appears only
after a complete 0600 PID-and-process-birth claim has been written and atomically
hard-linked into place;
dead-lock replacement is serialized by `spawn.lock.recovery`, so two stale readers can
never unlink one another's replacement. This is also a persistent, versioned inode with
a kernel-held advisory lock: process death releases the claim automatically. Legacy or
malformed recovery files continue to fail closed once, with explicit inspection and
repair guidance, because they might belong to an older active client.

When `OUROBOROS_DATA_DIR` is unset or blank, a `--dev` daemon gets the separate
`ouroboros-dev` directory, because a development runtime and a release that shared
`gateway.json` would each be discoverable as the other. A nonblank explicit
`OUROBOROS_DATA_DIR` remains an exact operator override in both modes; `ouro --dev`
prints a warning before it can start, adopt, attach to, or stop a runtime there, since an
override shared with the release mode intentionally disables that default isolation. Use
a dedicated explicit directory when development isolation is intended.

### Attaching to a server over SSH

The gateway is cleartext and binds loopback. The supported way to reach a remote one is
to forward the port rather than to open the listener:

```sh
# On the server, once: note the port and the token file.
ouro daemon

# On the laptop.
ssh -N -L 4560:127.0.0.1:<port> ops@host &
scp ops@host:~/.local/share/ouroboros/gateway.token /tmp/remote.token
ouro attach --addr 127.0.0.1:4560 --token-file /tmp/remote.token
```

`OUROBOROS_GATEWAY_BIND` can put the listener on a real interface, but the runtime
refuses that boot unless `OUROBOROS_GATEWAY_ALLOW_REMOTE=1` is also set, because the
token and every payload after it would cross the wire in the clear. The refusal names
the tunnel first on purpose.

### What a spawned runtime inherits

`ouro` sets the gateway posture (`OUROBOROS_GATEWAY=1`, scope `operate`, port `0`, the
token file path, `OUROBOROS_DATA_DIR`) and otherwise hands the child the environment it
was called with. Mix/`--dev` and packaged starts also set `OUROBOROS_PROCESS_ID_HELPER`
to the product `ouro` binary so the runtime can read process-birth identity and hold the
owner-recovery lock; cargo test harnesses are never that helper. On a standalone laptop
it also sets `OUROBOROS_DIST=none`: no epmd or
distribution listener. The release launcher uses a fresh disposable boot cookie rather
than the artifact's shared fallback, but with distribution disabled it is not a reachable
cluster credential. That posture is also what the release defaults to when told nothing;
`ouro` states it explicitly anyway, because a stated contract survives a change of
default.

That default steps aside for a real deployment. If the calling environment already
carries `OUROBOROS_CLUSTER_STRATEGY` or `OUROBOROS_NODE`, the cluster variables pass
through untouched and distribution stays on — `rel/env.sh.eex` refuses the combination
of clustering and `OUROBOROS_DIST=none` outright, and an operator who configured a
cluster did not ask a terminal client to reconsider it. Everything else about an
existing server workflow is unchanged, because nothing else is set.

### Keys

`?` opens the help with the current key map. It is the authority; a README that listed
bindings would be the second place they are written down and the first place they go
stale.

### Honest limits

- **The token is transport authentication, not a sandbox.** It decides who may open a
  connection and at what scope. It does not constrain what the runtime does once a
  connection is open: an `operate`-scope client can drive sessions and agents, and the
  gateway's authority is the runtime's authority.
- **Loopback is the security boundary.** The protocol has no transport encryption.
  `OUROBOROS_GATEWAY_ALLOW_REMOTE=1` does not add any — it only stops the runtime from
  refusing to bind a non-loopback address. Use the tunnel.
- **One gateway controls one connected fleet.** The client still authenticates to one
  loopback gateway, but that gateway lists sessions across connected core nodes and routes
  owner-qualified session calls/subscriptions over BEAM distribution. Offline owners stay
  visible in Machines and return an explicit unavailable state; their live streams resume
  from the retained cursor after reconnection. Unrelated Erlang clusters are not
  federated.
- **In attach mode there is no log streaming.** A foreground spawning client pipes the
  runtime's output into a bounded ring it can show you. A packaged detached daemon or
  recovery service writes application logs to `runtime.log`, live-rotated by OTP at
  2 MiB with three archives (`.0` newest through `.2`), and keeps bootstrap/VM/crash
  output separately in restart-rotated `daemon.log`. Other deployments still use the
  sink their operator selected (`journalctl`, a container log driver, and so on).
- **`ouro attach` with no arguments only finds runtimes that published locally.** A
  deployment configured with `OUROBOROS_GATEWAY_TOKEN` in the service environment, or
  one whose data directory this user cannot read, is reachable only by naming `--addr`
  and `--token-file` explicitly. There is no discovery beyond the file.
- **A managed provider cannot ask you before it runs a tool, so it is not offered the
  chance.** Claude, Gemini, Grok, and Z.ai reach an interactive session by re-executing
  their CLI once per turn. That transport has no approvals channel: `claude --print` is
  never given a `--permission-prompt-tool`, so `approval_mode: :prompt` is accepted by
  the CLI and then silently denies every tool call that needs permission — a session
  that looks alive and cannot work. Rather than start one, `interactive.start` refuses
  it by name and says which modes do work (`:default`, `:auto_edit`, `:auto_approve`).
  Codex on app-server and the ACP providers (OpenCode, Kimi) ask for real and are
  unaffected, as is the non-interactive coding plane. The refusal stands until the
  Claude approval bridge lands and `:prompt` becomes true for those providers too.
- **What a session can do and what it has spent are declared, not guessed.**
  `interactive.info` and `interactive.list` carry `options.capabilities` — `transport`,
  `process`, `multi_turn`, `follow_up`, `interrupt`, `approvals`, `steer`, `multimodal`,
  `dynamic_model`, `dynamic_configuration`, each `native`/`managed`/`process`/`false` —
  read from the provider's own spec, so a session listed after a restart declares the
  same thing it started with. They also carry `usage`: input, output, cache-read and
  cache-creation tokens, a total, `turns_with_usage`, and `cost_usd`. Those are the
  numbers providers reported and nothing more — `cost_usd` stays `null` for a provider
  that never priced the work rather than becoming a zero that reads as free.
- The UI is new. The gateway protocol has one version and one implementation of each
  half; `hello.protocol` is the entire compatibility contract, and a mismatch prints
  both numbers rather than guessing.

## Agent mesh

```elixir
{:ok, reviewer} = Ouroboros.Mesh.start_agent("reviewer", role: "reviewer")

{:ok, agent} =
  Ouroboros.Mesh.send_message("root", "reviewer", %{request: "inspect mix.exs"})

{:ok, task_id, agent} =
  Ouroboros.Mesh.assign_task("root", "reviewer", "Find dependency risks")
```

Start on a connected node with `Ouroboros.Mesh.start_agent_on/3`. The target is checked
before anything is placed on it: it must be connected and running this runtime in the
`core` role, or the call returns `{:error, {:placement_refused, node, reason}}` — see
[Running a cluster](#running-a-cluster) for what that check is and, more importantly,
what it is not. The directory uses a named `:pg` scope and monitors local Jido
processes. `:global.trans/2` narrows duplicate-start races in a healthy connected
cluster; it is explicitly not a partition-safe consensus protocol.

Visibility is eventually consistent. `whereis/1` and `members/1` qualify a remote entry
by node connectivity, not by remote process liveness, because probing the owner would
make every lookup a network call. A returned pid is an observation, not a guarantee: a
remote agent can already be dead while `:pg` propagates its leave. Mesh calls therefore
never exit the caller — a dead, unreachable, or slow target returns
`{:error, {:agent_call_failed, kind, reason}}`, and remote placement or shutdown
failures return `{:error, {:remote_start_failed, node, {kind, reason}}}` and
`{:error, {:remote_stop_failed, {kind, reason}}}`.

`start_agent/2` is a remote-reachable start surface, since `:erpc` from any connected
node can invoke it and pick the `:agent` module. Startable modules are restricted to the
`Ouroboros.Agent.` and `Ouroboros.Capability.` namespaces — the latter reserved for
agents forged at runtime — plus any module listed in
`config :ouroboros, mesh_allowed_agent_modules: [...]`. Anything else is refused with
`{:error, {:agent_module_not_allowed, module}}`. An `:initial_state` map option is
merged over the `:role`/`:objective`/`:parent_id` trio so runtime-defined agents can
seed their own schema keys.

Coding task references include their owner node. Calls made with a task reference are
routed through `:erpc`; a disconnected owner returns `{:owner_unavailable, node}`
instead of incorrectly marking its provider run lost. A bare task ID intentionally
means “on this node.”

## Agent teams

```elixir
{:ok, team} = Ouroboros.Team.start(id: "review-team")
{:ok, worker} = Ouroboros.Team.add_worker(team, "reviewer", node: node())

{:ok, delegation} =
  Ouroboros.Team.delegate(team, worker.id, "Review this repository",
    provider: :codex,
    workspace: File.cwd!()
  )

{:ok, delivered} = Ouroboros.Team.await(team, delegation.id, 300_000)
```

Local workers use Jido's real parent/child hierarchy. Because Jido 2.3.3 checks
adopted PIDs with local-only `Process.alive?/1`, remote workers are represented as
`:mesh_remote` relationships while assignment, execution, events, result delivery,
and cleanup cross the distributed boundary. A worker accepts one active delegation.
Team snapshots contain logical IDs and task references, never PIDs. An abnormal team
restart recreates or adopts its Jido projections, resumes each persisted cursor, and
retries terminal delivery without duplicating the provider run. `Team.close/1` first
checkpoints a recoverable `:closing` state and cancellation intent; it becomes
`:closed` and cleans up only after every delegation reaches durable delivery. Public
delegation IDs are local to a team; the underlying coding-task identity is
deterministically namespaced by team and delegation and bound to a private random
origin digest, so a matching foreign task cannot be adopted or cancelled. Coordinator
ownership is claimed inside the Jido agent, monitored, and reverified before signals
or cleanup.

Recovery never compensates a run it merely failed to resubscribe to: a pruned cursor
or unreachable owner degrades that delegation to polling the durable coding
checkpoint, with the reason recorded. Only a fresh `delegate/4` fails fast. Because
the coding-task ID is deterministic, an unreachable owner during startup keeps the
delegation `:starting` and retries within `:delegation_start_retry_ms` (default five
minutes); the durable failure after that bound explicitly records that provider-side
work may exist unconfirmed. `add_worker/3` and `delegate/4` are bounded by
`:team_call_timeout` (default 60s) so one wedged peer cannot freeze the local control
plane. `Team.state/1` reports durability as `:ephemeral_checkpoint`,
`:durable_checkpoint`, or `:synced_checkpoint`, and only the synced level reports
`host_restart_safe?: true` — the default file adapter does not `fsync`.

## Durable orchestration

```elixir
alias Ouroboros.Orchestration.{Plan, Scheduler}

{:ok, plan} =
  Plan.new("review-and-fix", [
    %{id: "review", input: %{objective: "Review the repository"}},
    %{id: "fix", dependencies: ["review"], input: %{objective: "Implement the fix"}},
    %{id: "verify", dependencies: ["fix"], input: %{objective: "Run focused checks"}}
  ])

{:ok, _} = Scheduler.submit(plan)
```

The scheduler persists before dispatch, caps concurrency, unlocks fan-out/fan-in,
uses stable execution tokens across owner or scheduler restart, and propagates
failure and cancellation. Configure `:orchestration_team_id` plus a default worker,
or put a `worker_id` in each step's metadata, to execute ready steps through
`Ouroboros.Orchestration.TeamExecutor`. Without an executor, callers can explicitly
claim and complete steps through `Scheduler.start/4` and `complete/5`.

### Heterogeneous plans

A step declares a kind. `:coding` is the default; `:forge` compiles one capability
module and deploys it through the upgrade lane:

```elixir
{:ok, plan} =
  Plan.new("close-the-loop", [
    %{id: "author", input: %{objective: "Write the capability and its tests"}},
    %{
      id: "build",
      kind: :forge,
      dependencies: ["author"],
      input: %{
        module: "Ouroboros.Capability.Echo",
        source_path: "capabilities/echo.ex"
      }
    }
  ])
```

A forge step says only *what* to build. Where source is read from, which nodes
receive it, and which signer is asked stay in trusted runtime configuration:

```elixir
config :ouroboros,
  orchestration_forge_options: [
    workspace: "/srv/agent-worktrees/project",
    nodes: [:"app@host-a", :"app@host-b"],
    signer_id: "release-signer"
  ]
```

Executors are resolved per kind, and `Scheduler.submit/2` refuses a plan naming a
kind it cannot execute before persisting anything — so a forge step never reaches a
deployment that has no forge executor. `Ouroboros.Orchestration.ForgeExecutor` reads
the source under a shared-read workspace lease and uses the durable rollout registry
as its reattachment anchor: a module already live with the same source digest on the
same nodes completes the step without forging again, and an unsettled `:deploying`
record fails the attempt rather than deploying a second time. Plans written before
step kinds existed load as `:coding`.

## Autonomous control

`Ouroboros.Control` adds a durable planner/evaluator loop above the scheduler. It is
disabled by default so application startup cannot make an inference call. Enable it
only with explicit adapters and runtime execution policy:

```elixir
config :ouroboros,
  control_enabled: true,
  control_planner: {Ouroboros.Control.JidoAI, model: :planning, max_steps: 8},
  control_evaluator: {Ouroboros.Control.JidoAI, model: :reasoning},
  orchestration_team_id: "review-team",
  orchestration_worker_id: "reviewer",
  orchestration_coding_options: [
    provider: :codex,
    workspace: "/srv/agent-worktrees/project",
    sandbox_mode: :workspace_write,
    approval_mode: :prompt
  ]
```

```elixir
{:ok, run} =
  Ouroboros.Control.submit("Repair the failing tests and verify the change",
    id: "repair-42",
    max_revisions: 2
  )

{:ok, current} = Ouroboros.Control.get(run.id)
{:ok, cancelled} = Ouroboros.Control.cancel(run.id, reason: :operator_stop)
```

Planning and evaluation requests, plan IDs, revision history, and cancellation intent
are checkpointed. Model-produced steps may supply only a nonblank execution
objective; provider, worker, sandbox, and approval policy stay in trusted runtime
configuration.

`control_allow_forge_steps: true` additionally lets a plan express a forge step
carrying exactly a capability module name and a workspace-relative source path. The
coding-step schema is unchanged by that flag, and the server validates an accepted
plan against the same per-kind rules `Plan.new/3` applies. It is permission to
*describe* a build, not to deploy one: the artifact is still signed by whatever
`:forge_signer` names — the shipped default refuses — and still verified against each
target node's trusted signers. A run remains `:cancelling` while execution callbacks are pending;
its terminal cancellation evidence distinguishes no active work, a cancellation
request accepted by the execution plane, and an unconfirmed request. Acceptance is
not represented as proof that a provider process has stopped. Stable request IDs
support correlation, not provider-side exactly-once billing: a crash after a model
response and before its checkpoint can repeat a call.

## Hot code evolution

The fast lane accepts precompiled BEAM binaries only:

```elixir
{:ok, artifact} =
  Ouroboros.Upgrade.Artifact.build(
    [
      {MyAgent, new_beam,
       old_binary: current_beam,
       stateful: true,
       migration_extra: %{schema: 2}}
    ],
    epoch: 42
  )

signed = Ouroboros.Upgrade.Artifact.sign(artifact, "release-key", private_key)

{:ok, token} =
  Ouroboros.Upgrade.NodeExecutor.prepare(signed,
    migrations: [{MyAgent, pid, %{schema: 2}}]
  )

{:ok, receipt} = Ouroboros.Upgrade.NodeExecutor.commit(token)
```

The verifier rejects stale preimages, runtime mismatches, unsigned production
artifacts, consolidated protocols, sticky modules, and the modules that enforce this
lane's guarantees: everything under `Ouroboros.Upgrade.*`, `Ouroboros.Storage.*`,
`Ouroboros.Release.*`, and `Ouroboros.Control.*`, plus the application root and its
registry owner. On-load functions are detected by asking the code server to prepare
the batch, in both the new binary and the preimage the rollback path would load back.

### Introducing new modules

An entry's `:disposition` chooses between replacing a loaded module (`:replace`, the
default) and loading one that has never existed in this VM (`:introduce`). One artifact
may mix both, and they commit and roll back together:

```elixir
{:ok, artifact} =
  Ouroboros.Upgrade.Artifact.build(
    [
      {MyAgent, new_beam, old_binary: current_beam},
      {Ouroboros.Capability.Summarize, forged_beam, disposition: :introduce}
    ],
    epoch: 43
  )
```

An introduction has no preimage: every `old_*` field is `nil`, it cannot declare
`stateful: true` or a `migration_extra` (there are no processes to migrate yet), and
rolling it back means unloading the module — `:code.delete/1` followed by a soft purge.
Nothing is ever brutally purged, so a process still executing introduced code produces
`{:introduced_code_in_use, module}` and quarantine rather than a kill. The disposition
is part of the signed manifest, so a signature covers how each module is loaded, not
only its bytes.

Two extra gates apply. The module must be genuinely absent — unloaded, unreachable on
the code path, and not something the node's journal already expects to be present — and
its name must live under `Ouroboros.Capability.`, the namespace `Ouroboros.Mesh` already
reserves for agents forged at runtime.

Loading a new module is **not** safer than replacing one. Any accepted BEAM runs with
full ambient VM authority whichever disposition carried it; the namespace rule is policy
that keeps a new module from silently taking an existing name, not a sandbox, and it
constrains nothing about what the module may then do.

NIF loading is detected only as a static import of `:erlang.load_nif/2`. A module that
resolves that call at runtime is not detected, and no static check would make it so;
this is the policy gate being a policy gate, not a sandbox.

Commit uses OTP's prepared loading plus explicit `:sys.suspend/2`,
`:sys.change_code/5`, and resume. Rollback restores both process state and the
preimage without brutal purge.

Cluster rollout is explicit and best-effort, not a distributed transaction:

```elixir
{:ok, deployment} =
  Ouroboros.Upgrade.Coordinator.deploy(signed, [node() | Node.list()],
    migrations: %{node() => [{MyAgent, pid}]},
    health_check: {MyHealth, :ready?, []}
  )

Ouroboros.Upgrade.Coordinator.promote(deployment)
```

An ambiguous remote outcome is quarantined, never described as rolled back. An
ambiguous *prepare* holds a reservation whose token the lost reply was carrying, so
compensation releases it by artifact id through
`NodeExecutor.abort_prepared_reservation/2` instead of leaving the node unable to
prepare anything again. Fast patches are fully privileged inside their VM: the
verifier is a policy gate, not a security sandbox. Independent authorization and signing
live outside the patchable application, on a `signer` node — see
[The signing service](#the-signing-service).

Epoch, receipts, expected module identities, write-ahead operations, and quarantine
state are durably journaled. After a rolled-back introduction the expected identity is
`:non_existing`: absence is a checked expectation rather than a missing one, so a name
that reappears behind the executor's back fails closed exactly like a wrong hash. A
journal this build cannot interpret is quarantined with its evidence intact rather than
coerced or replaced. On executor restart, opaque prepared loader terms are
declared lost. If a commit was interrupted while stateful processes may be suspended,
the journal's verified migration targets are resumed only after their live callback
modules match; the incomplete commit then remains in inspectable quarantine. Committed
module hashes and retained migration processes are also reconciled, and any mismatch
fails closed. A successful code mutation is never reported before its checkpoint;
journal failure triggers compensation or an explicit reconciliation-required outcome.

A commit that fails after code is already visible first attempts the same compensation
a failed migration gets. If that compensation cannot complete, the terminal journal
record keeps the artifact and its migration targets, so the preimages remain restorable
from the journal alone. A quarantined executor refuses every mutating call, rollback
and promote included; `NodeExecutor.reconcile_quarantine/1` re-runs the startup checks
and clears the quarantine only when loaded code matches the journal again, otherwise
returning the diagnostics unchanged.

This lane changes a running node only. Reboot-persistent changes and ERTS upgrades
still require `.appup`/`.relup` release handling; Mix releases do not generate hot
upgrades automatically. See [Architecture](docs/ARCHITECTURE.md).

## Forging new capabilities

The forge is the path from agent-authored *source* to a live agent module. It is one
call, and every stage of it can refuse:

```elixir
{:ok, source} =
  Ouroboros.Upgrade.Forge.Source.new(
    module: Ouroboros.Capability.Echo,
    author: "planner-agent",
    source: capability_source,
    test_source: capability_test_source
  )

{:ok, signed} = Ouroboros.Upgrade.Forge.forge(source, nodes: nodes, signer_id: "release-key")

{:ok, rollout} = Ouroboros.Upgrade.Rollout.deploy(signed, Ouroboros.Capability.Echo, nodes)
# => rollout.state == :live, and the module is running on every node in `nodes`
```

What happens between those two calls:

1. **Parse-only hygiene.** `Forge.Source.validate/1` reads the module name, parses the
   source and its tests with `Code.string_to_quoted/1`, and walks both ASTs for
   constructs a capability has no business containing: `@on_load`, protocol definitions,
   `Code.*`, `:code.*`, `File.*`, `System.cmd/2`, `Port`, `:os.cmd/1`, `Node.*`, `:erpc`,
   `:rpc`, `Application.put_env/3`, `:persistent_term`, `:ets.give_away/3`,
   `:erlang.load_nif/2`, and spawning onto a named node. Nothing is evaluated or
   compiled, so a rejected source leaves `:code.which/1` answering `:non_existing`.
2. **An isolated build peer.** `Forge.BuildPeer` starts an OTP `:peer` with
   `connection: :standard_io` and `-start_epmd false`. That peer is not distributed —
   `node()` inside it is `:nonode@nohost` — so the candidate compiles and runs its own
   tests where the production cluster is unreachable. The peer is stopped in an `after`
   block on every path, including the build deadline expiring
   (`config :ouroboros, :forge_build_timeout`, 60s by default).
3. **An epoch nobody can reuse.** `Ouroboros.Upgrade.Epoch.next/2` reads `last_epoch`
   from every target node, allocates one above the highest, and writes that number
   durably *before* returning it. A forge that dies between allocating and deploying
   burns the number instead of reissuing it. A node whose status cannot be read is a
   refusal, not a zero.
4. **A signature the forge cannot produce for itself.** `config :ouroboros,
   :forge_signer` names the module asked to sign. The shipped default,
   `Forge.Signer.Deny`, refuses everything; `Forge.Signer.Remote` submits the whole
   artifact to a signing service on a `:signer` node. See
   [The signing service](#the-signing-service).
5. **A health-gated rollout.** `Rollout.deploy/4` checkpoints `:deploying` durably
   before any node is touched, then deploys with
   `health_check: {Rollout.Probe, :ready?, [module]}`. On each target the probe starts
   the new module as a throwaway mesh agent, sends it one synthetic signal, checks the
   answer, and stops it. One failing probe rolls the deployment back everywhere.
6. **An evaluation gate, when the artifact declares one.** Between commit and promotion,
   `Rollout.Evaluation.run/3` drives the artifact's own probe set on every target.

The rollout is recorded in `Ouroboros.Upgrade.Rollout.Registry` as `:deploying`,
`:live`, `:rolled_back`, or `:quarantined`. The last two are never confused: only a
deployment whose every node *proved* it compensated is recorded as rolled back, and any
ambiguity — a lost reply, a node that never answered — is recorded as quarantined.

### The selected model can see the runtime

A coding or interactive session keeps the provider's own prompt. At admission Ouroboros
captures a compact `<ouroboros-runtime>` envelope — identity, the authoring contract, and
the current signer posture, loaded capabilities, and mesh agents. Every dispatch and
recovery reuses those exact bytes, so one logical turn cannot silently observe a different
runtime. Durable user text is not rewritten, so the transcript still shows what the
operator typed.

When explicitly asked for an Ouroboros runtime capability, the selected model authors a
proposal; it cannot sign, deploy, or grant. Ordinary coding objectives stay ordinary
coding work. A capability proposal uses:

```
.ouroboros/capabilities/<Name>/
  manifest.json    # module, description; optional eval; optional start {id, role}
  source.ex        # one `use Jido.Agent` module under Ouroboros.Capability.*
  test.exs         # at least one passing test
```

The operator lists, previews, and admits from `ouro` (`/capabilities`, `/preview`,
`/admit`). Preview compiles and tests in the existing isolated build peer and loads
nothing on this node. Admit runs the forge and health-gated rollout, then optionally
`Mesh.start_agent/2` when the manifest asks. Default nodes use `Forge.Signer.Deny`, so
authoring and preview work and this node cannot admit — that is intentional. Opt out
with `runtime_exposure: false` on session start.

### Evaluation gates

A health probe proves the new module is alive. That is enough to *modify* a running
system and not enough to *improve* one. An evaluation spec is the missing evidence, and
it is data rather than code, so it can live inside the signed manifest next to the bytes
it judges:

```elixir
eval = %{
  probes: [
    %{input: %{op: "ping"}, expect: {:contains, "ping"}},
    %{input: "again", expect: {:state_matches, :messages_received, 2}}
  ],
  budget_ms: 5_000,
  max_latency_ms: 2_000,
  required: :all
}

{:ok, signed} = Forge.forge(source, nodes: nodes, signer_id: "release-key", eval: eval)
signed.metadata.forge.eval
# => the validated spec, inside the manifest the signature covers

{:ok, rollout} = Rollout.deploy(signed, Ouroboros.Capability.Echo, nodes)
rollout.eval_report.nodes[hd(nodes)]
# => %{passed: 2, failed: 0, total_ms: 3, satisfied?: true, failures: [], ...}
```

Expectations are terms, not functions: `:any_reply`, `{:equals, value}`,
`{:contains, substring}` on the rendered reply, and `{:state_matches, key, value}` read
out of the agent's state through `Ouroboros.Mesh.state/1`. Every probe input and
expectation must be portable, the whole spec is size-bounded, and anything else is
refused by `Evaluation.validate/1` before a build peer boots.

`Rollout.deploy/4` runs the spec on every target through a bounded `:erpc` after the
commit and before the promote — while the rollback material still exists — and then

- every node satisfies its spec → `Coordinator.promote/2`, registry `:live`, report
  recorded;
- any node does not → `Coordinator.rollback/2`, and the usual proof rule decides
  `:rolled_back` or `:quarantined`;
- any node's answer is *ambiguous* — transport fault, deadline, unrecognized shape →
  compensation is still attempted and the record is `:quarantined` regardless of how
  cleanly it succeeded. An evaluation nobody received is not evidence of anything.

With no spec, none of this runs and the behaviour is exactly what it was.

### Champion and challenger

`compare: true` deploys a capability *upgrade*: a `:replace` beam for a module already
live. The same spec runs against the current version on every target first, and the
challenger is promoted only if it passes at least as many probes and stays within
`config :ouroboros, :capability_eval_regression_budget` (1.2×) of the champion's total
time. Both reports land in the registry entry. A replacement is accepted through this
path and no other, because promoting a new version of a live capability without
measuring the one it displaces discards the only baseline that will ever exist.

### Honest limits

- **The deny list is hygiene, not a sandbox.** It catches accidents. It cannot catch a
  macro that expands into the same constructs after the walk has finished, `apply/3`
  with a runtime module, or a name built by `Module.concat/1`. The boundaries that do
  work are the build peer's isolation, the verifier's checks on the loading node, and
  the `Ouroboros.Capability.` namespace policy — and even those are policy, not a jail:
  a loaded capability has exactly the same ambient VM authority as any other module.
- **The build peer is process isolation, not OS isolation.** It runs as the same user
  with the same filesystem and network reach. It cannot talk to the cluster; it can
  still write files the build user can write. Compiling genuinely hostile source needs a
  container or VM around the peer, on a host that is not the production host.
- **The build peer must match its targets.** The artifact is verified against the
  loading node's exact OTP release, Elixir version, and system architecture. Starting
  the peer from this VM's own executable and code path is what makes that true here; a
  remote build service has to establish it another way.
- **Key custody belongs outside the patchable application.** `Forge.Signer.Local` reads
  an Ed25519 key from configuration, which is fine for a dev loop and for tests. In
  production it would put the key inside the blast radius of the code it authorizes: an
  agent that can patch this application can read anything this application can read.
  [The signing service](#the-signing-service) is the shipped alternative — and it
  narrows custody rather than achieving it, because a signer node is still a connected
  cluster member.
- **One module per capability.** A forged capability is exactly one BEAM. The sandbox
  rejects a source that compiles to more, because an artifact carrying one binary cannot
  satisfy references to helper modules no target node has loaded. Helpers must already
  exist on the targets — the shipped `Ouroboros.Agent.Worker.ReceiveMessage` action, for
  example, is a legitimate route target for a forged agent.
- **The probe is liveness; the evaluation is the declared spec and nothing more.** The
  probe proves a capability starts, answers one message, and stops. A report proves the
  probes somebody wrote held, once, on each target, against a throwaway instance. It
  says nothing about inputs nobody wrote a probe for, and `total_ms` is wall-clock on a
  shared VM — a champion/challenger comparison over a handful of probes measures the
  probe set, not production behaviour. Cost models, canary cohorts on real traffic, and
  statistical significance are still external.
- **An `:eval` override is not signed.** A spec in `metadata.forge.eval` is covered by
  the signature; one passed to `Rollout.deploy/4` is the caller's word. Both are
  validated identically, which is a statement about runnability, not about authority.

## The signing service

Everything above is the agent's side of the seam. This is the other side: the piece that
makes "an agent cannot approve its own patch" a property of where code runs rather than a
policy someone remembered to configure.

`Ouroboros.Upgrade.Signing.Service` runs **only** on a `:signer`-role node, whose whole
supervision tree is that process and cluster formation. It loads its key at boot, applies
its own policy to the whole artifact, journals every decision durably, and only then
answers.

### Standing one up

```sh
# On the signer host — 32 raw bytes, or their base64. Never in config, never in a release.
head -c 32 /dev/urandom > /etc/ouroboros/signer.seed && chmod 600 /etc/ouroboros/signer.seed

OUROBOROS_NODE_ROLE=signer
OUROBOROS_SIGNER_KEY_PATH=/etc/ouroboros/signer.seed
OUROBOROS_SIGNER_ID=release-key
OUROBOROS_SIGNING_REQUIRE_EVAL=true    # recommended; see below
```

A `:signer` node with no readable key, an unparseable key, no signer id, or an unusable
journal **refuses to boot**. That is deliberate: a signer that starts anyway and errors
per request is indistinguishable, from the outside, from a signer that is deliberately
denying — and those two need very different responses.

Ask it for the public half and give it to the core nodes:

```elixir
{:ok, info} = :erpc.call(:"signer-1@10.0.0.30", Ouroboros.Upgrade.Signing.Service, :public_info, [])
info.trusted_signers_entry
# => "release-key:aG93ZHkgdGhlcmUsIHRoaXMgaXMgbm90IGEgcmVhbCBrZXk="
```

```sh
# On every core host.
OUROBOROS_SIGNING_NODE=signer-1@10.0.0.30
OUROBOROS_UPGRADE_TRUSTED_SIGNERS="release-key:aG93ZHkgdGhlcmUsIHRoaXMgaXMgbm90IGEgcmVhbCBrZXk="
```

Naming `OUROBOROS_SIGNING_NODE` is what configures `Forge.Signer.Remote`; leave it unset
and the forge keeps the shipped `Deny`. Nothing else about forging changes.

### What the signer checks before a signature exists

The forge hands over the **whole artifact**, not just the payload it wants signed — a
payload is a hash of a manifest, and a manifest is a set of claims. `Signing.Policy`
recomputes the claims:

- **the manifest against the bytes.** sha256, md5, module name, and `vsn` are recomputed
  from every BEAM actually submitted (and from the pre-image of a `:replace`), and the
  same offline gates the loading node applies are applied here: the `-on_load` probe via
  `:code.prepare_loading/1`, static `:erlang.load_nif/2` imports, protocol markers. A
  requester that precomputed a flattering manifest is refused on arithmetic;
- **the namespace, structurally.** Every module must be under `Ouroboros.Capability.`.
  There is no configuration that widens this, so there is no code path on a signer node
  that produces a signature for a control-plane module, whoever asks and however they
  ask;
- **provenance.** `metadata.forge` must carry a `source_sha256` and a test report with
  zero failures and at least one pass. Green-because-everything-was-skipped is refused;
- **declared evaluation criteria**, when `:signing_require_eval` is on: the artifact must
  carry a `Rollout.Evaluation` spec the signer can validate. This is the switch that
  turns "this capability declared, inside its own signature, how it would be judged" into
  a precondition of being signed at all;
- **rate**, per requester per minute, in a sliding window.

Every refusal is a typed `{:refused, reason}`, and every one of them is journaled.

What the signer deliberately does **not** check is anything only a target VM knows: epoch
*ordering* (a signer has no view of any cluster's watermark — it checks only that the
number is a positive integer), whether a `:replace` pre-image is current, and whether an
introduced module is really absent. Those belong to the node executor and survive the
signature untouched.

### Every decision, before every answer

```elixir
{:ok, decisions} = :erpc.call(signer, Ouroboros.Upgrade.Signing.Service, :decisions, [])
# => [%{sequence: 1, artifact_id: "019f…", epoch: 42, decision: :issued,
#       modules: [%{module: Ouroboros.Capability.Echo, disposition: :introduce, sha256: "…"}],
#       requester: :"core-1@10.0.0.11", signer_id: "release-key", findings: %{…}, at: "…"}]
```

Refusals are recorded for the same reason issuances are: a log with only successes
cannot tell "nobody asked" from "something asked two thousand times and was turned away".
The entry is checkpointed through `:signing_journal_storage` — a synced
`Storage.DurableFile` in production — **before** the signature is returned, and a journal
that will not accept the entry is a refusal to sign. The one asymmetry is deliberate and
one-directional: the journal may record an issuance whose reply was lost in transit,
never a signature that reached a requester without a record.

### Honest limits

- **A signer node is still a connected cluster member.** Any node that completes the
  distribution handshake — cookie, and TLS if configured — can `:erpc` into the signing
  service exactly like the forge does, and can do everything else `:erpc` allows on that
  host. What it gets from the service is a *policy decision*: the namespace rule has no
  bypass for any caller. TLS distribution and role isolation narrow this surface. They do
  not eliminate it, and true air-gapped custody — a key on a host that is not a cluster
  member, reached over a narrow audited channel — remains outside this runtime.
- **The requester is self-reported.** The client sends its own node name; the service
  journals it as a claim. The per-requester rate limit therefore bounds accidents, retry
  storms, and honest clients, not an adversary who can vary it.
- **The policy cannot re-run the build.** It proves the submitted bytes are internally
  consistent and correctly namespaced, and that a test report claiming green arrived with
  them. The link between that report and those bytes is the forge's assertion, carried
  inside the signed metadata.
- **There is no human in it.** "Independent" here means independent of the patchable
  application, not independent of the cluster. A review queue is a different thing, and
  this is not one.
- **Key material is redacted, not protected.** The keypair is wrapped in a struct whose
  `Inspect` implementation prints `[REDACTED]`, so a crash report or a logged state
  cannot leak it by accident. Anything running on the signer node can still read the
  process state directly. The boundary that matters is the host, not the struct.

## Agent effects

Everything above is something an *operator* can call. `Ouroboros.Agent.Effects` is the
same set of powers reached by an agent, from inside a signal handler, one grant at a
time:

```elixir
# Nothing is permitted until somebody says so, effect by effect and target by target.
{:ok, _grant} = Ouroboros.Control.Grants.grant("planner", :forge, modules: [Ouroboros.Capability.Echo])
{:ok, _grant} = Ouroboros.Control.Grants.grant("planner", :deploy, nodes: nodes)
{:ok, _grant} = Ouroboros.Control.Grants.grant("planner", :start_agent, modules: [Ouroboros.Capability.Echo])

{:ok, signal} =
  Ouroboros.Signals.EffectForgeCapability.new(%{
    from: "planner",
    module: Ouroboros.Capability.Echo,
    source: capability_source,
    test_source: capability_test_source,
    nodes: nodes
  })

{:ok, _agent} = Jido.AgentServer.call(Ouroboros.Mesh.whereis("planner"), signal)
```

Six effects, each with the one allow-list it is checked against: `:start_agent` and
`:forge` take `modules:`, `:stop_agent` and `:send_message` take `agents:`, `:delegate`
takes `teams:`, and `:deploy` takes `nodes:`. Every value may be `:any` or an explicit
list. `granted?/3` is asked about the *concrete attempt*, so a grant to forge
`Ouroboros.Capability.Echo` refuses a request to forge anything else, and a deploy is
refused unless every named node is admitted.

What each effect run does, in order:

1. **Identifies the actor from server-side state.** The principal is the agent's own
   `id`, read from the agent struct the agent server holds. The `from` field on the
   signal is recorded as `claimed_from` and authorizes nothing, so one agent cannot
   spend another's grants by claiming its name.
2. **Asks the authority.** `Ouroboros.Control.Grants` is deny-by-default and durable:
   ETS in development, a synced file checkpoint in production, written before it is
   acknowledged. A refusal is `{:error, {:effect_denied, effect, reason}}`, which Jido
   turns into an error directive — the agent logs it and keeps running.
3. **Runs it off the agent's process, under a deadline.** Effects execute in a
   supervised task bounded by `config :ouroboros, :effect_timeout` (120s). A forge takes
   longer than an agent server should ever sit still, so the signal returns immediately
   and the outcome arrives later.
4. **Records it before execution.** `Agent.EffectLedger` checkpoints the admitted
   attempt, exact grant snapshot, and signal identity before the runner starts. It
   durably settles the outcome, while message bodies, objectives, provider output,
   capability source, and BEAM binaries stay out of the ledger. Refusals are terminal
   entries too. `last_effects` remains a 20-entry agent-local projection; forged
   artifacts stay in `state.forged`, which is what a later `:deploy` resolves.
   If refusal journaling itself is unavailable, the action remains denied and its error
   names the missing audit rather than pretending a durable entry exists.

Inspect the local node's bounded history through `Ouroboros.effects/1`, filter it by
principal, effect, status, or sequence cursor, and resolve one stable ID with
`Ouroboros.effect/1`. An effect-ledger restart marks unfinished attempts `:ambiguous`
rather than claiming they failed or silently starting them again.

Grants are also why `Ouroboros.Control.Grants` lives where it does. The fast patch lane
refuses to load an artifact naming any `Ouroboros.Control.*` module, so a capability an
agent forged cannot patch the authority that decided it could forge.

### Honest limits

- **This is not a sandbox, and grants are not a capability system.** They gate the
  action layer: the signals a well-behaved agent flow travels through. Any loaded BEAM
  can call `Ouroboros.Mesh.start_agent/2`, `Ouroboros.Upgrade.Forge.forge/2`, or
  `Ouroboros.Control.Grants.grant/3` directly, without an effect action anywhere in
  sight. The boundaries that hold against code that does not cooperate are the
  verifier's namespace policy, artifact signing, and the isolated build peer.
- **An agent cannot widen its own authority through this surface**, because no grant
  effect exists. That is a property of the surface, not of the VM.
- **The authority is node-local.** Each node runs its own `Grants` process over its own
  checkpoint, so an agent granted `:forge` on one node is not granted it on another.
  Like every other store here, that is single-node ownership rather than a replicated
  policy service.
- **A failed revocation leaves the grant standing** and says so. An authority that
  forgot a grant it could not durably forget would hand it back at the next restart, so
  an unacknowledged revocation has not happened.
- **The durable ledger is node-local and bounded.** Production uses a synced checkpoint;
  development/test uses ETS. Terminal history is capped by
  `:ouroboros, :effect_ledger_limit` (1,000 by default), while in-flight attempts are
  never evicted. This is not a replicated audit service, and the atomic checkpoint is
  not an append-only external log. `last_effects` and `state.forged` remain short-lived
  agent-local projections; the ledger deliberately cannot restore a forged BEAM.

## Durable OTP releases

The release lane is distinct from fast BEAM patches:

```elixir
alias Ouroboros.Release.{Artifact, RelupBuilder, Runtime}

{:ok, relup} =
  RelupBuilder.build("/staging/ouroboros-0.2.0", ["/staging/ouroboros-0.1.0"], [])

# A controlled packager writes relup.encoded into the release staging tree and
# creates the final .tar.gz. Ouroboros then inspects that exact archive in memory.
{:ok, package} = Artifact.inspect_package("/srv/releases/ouroboros-0.2.0.tar.gz")
{:ok, ^package} = Runtime.inspect_package("/srv/releases/ouroboros-0.2.0.tar.gz")
```

Inspection checks archive paths/types/sizes, `.rel`, `start.boot`, `relup`, and
`.appup` consistency without extracting or loading code. Runtime mutation requires an
ephemeral capability from an independently configured `Release.Authorizer`; the
shipped authorizer denies every mutation. Authorized `unpack`, `check_install`,
`install`, and `make_permanent` operations are write-ahead journaled and reconciled
against `:release_handler.which_releases/0` after restart. Before unpack, the one
verified archive snapshot is durably published under its SHA-256 name; OTP receives a
same-inode alias whose name is derived from the validated top-level `.rel`. The release
directory must be writable only by the deployment identity. An ambiguous result
quarantines the lane.

The tests exercise real archives and a deterministic handler adapter. They do not
prove an actual embedded release installation, restart continuation, ERTS change, or
reboot permanence. Those require a deployment-specific release fixture and rehearsal.

## Production configuration

Production startup uses a durable directory. Unset, it derives
`$XDG_DATA_HOME/ouroboros` (else `~/.local/share/ouroboros`) — right for a
single-machine daemon, wrong for a server, so a deployment names its own:

```sh
export OUROBOROS_DATA_DIR=/var/lib/ouroboros
export OUROBOROS_WORKSPACE_ROOTS=/srv/agent-worktrees
export OUROBOROS_UPGRADE_TRUSTED_SIGNERS="release-key:$(base64 < release-key.pub)"
MIX_ENV=prod mix release
```

Node identity, role, cluster formation, and distribution transport are covered
separately in [Running a cluster](#running-a-cluster).

The forge signs with whatever `config :ouroboros, :forge_signer` names, and the shipped
default refuses to sign anything. Set `OUROBOROS_SIGNING_NODE` to a `:signer` node and
that becomes `Forge.Signer.Remote`, which submits the whole artifact to a key this
application cannot read — see [The signing service](#the-signing-service) for standing
one up. Configuring `Forge.Signer.Local` in production would instead put the key in the
configuration of the application whose code it authorizes, which is the same as letting
the agent approve its own code.

| Variable                                  | Read by | Meaning                                                    |
| ----------------------------------------- | ------- | ---------------------------------------------------------- |
| `OUROBOROS_SIGNER_KEY_PATH`               | signer  | file holding the Ed25519 seed: 32 raw bytes or their base64 |
| `OUROBOROS_SIGNER_ID`                     | signer  | the identity this node signs as; must match the trusted-signers entry |
| `OUROBOROS_SIGNING_REQUIRE_EVAL`          | signer  | `true` refuses to sign an artifact declaring no evaluation spec |
| `OUROBOROS_SIGNING_RATE_LIMIT_PER_MINUTE` | signer  | admissions per requester per minute (default 30)           |
| `OUROBOROS_SIGNING_NODE`                  | core    | the signer node the forge submits to; unset keeps `Signer.Deny` |
| `OUROBOROS_SIGNING_CALL_TIMEOUT_MS`       | core    | signing deadline (default 15000)                           |

A node booted with `OUROBOROS_NODE_ROLE=signer` refuses to start unless the key path
names a readable file and the signer id is set — checked once in `config/runtime.exs`
with a message naming the variable, and again by the service when it loads the key.

Production fails closed on unsigned patches. `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` is the
injection point for trusted Ed25519 public keys: comma-separated
`signer_id:base64_ed25519_public_key` entries, each key exactly 32 raw bytes. A
malformed or duplicated entry stops the boot rather than quietly narrowing the trusted
set, and an unset variable trusts nobody, so every artifact is rejected until keys are
supplied by the deployment's configuration boundary. Release and fast-patch journals use
a file-and-parent-directory-synced checkpoint adapter; the other domain aggregates use
single-owner atomic file checkpoints.

## Running a cluster

The normal multi-machine path is an Ouroboros **fleet**: the same `ouro` executable on
each trusted machine, one private invitation per machine, and no Erlang configuration to
write. Ouroboros generates the membership secret, a private CA, one TLS certificate per
machine, a firewall-friendly distribution range, stable machine identity, and the BEAM
formation arguments. The gateway remains local; one attached `ouro` uses BEAM routing to
start and follow sessions anywhere in the connected fleet.

### Install the same binary

Tagged builds publish one self-contained asset for each supported macOS/Linux architecture
plus `SHA256SUMS` on the repository's Releases page. Download both files, verify the
matching checksum, then put the asset somewhere on `PATH` on every machine:

```sh
ASSET=ouro-VERSION-aarch64-apple-darwin   # choose the one for this OS/CPU

# Linux
grep "  ${ASSET}$" SHA256SUMS | sha256sum -c -

# macOS
grep "  ${ASSET}$" SHA256SUMS | shasum -a 256 -c -

mkdir -p ~/.local/bin
install -m 0755 "$ASSET" ~/.local/bin/ouro
~/.local/bin/ouro version

# Keep this for future shells (zsh); use the equivalent file for another shell.
grep -q 'HOME/.local/bin' ~/.zshrc 2>/dev/null || \
  printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> ~/.zshrc
export PATH="$HOME/.local/bin:$PATH"
```

Use assets from the same tag across the fleet. CPU architecture may differ, but remote
placement requires the same Ouroboros version, OTP release, and fleet protocol revision;
`ouro fleet doctor` names a mismatch and the runtime refuses to place paid/write-capable
work there until the machine is upgraded.

The current Linux artifacts are native Ubuntu 24.04 GNU builds, not static binaries;
use Ubuntu 24.04 or a distribution with a compatible glibc, or run `make ouro` on an
older target. The current macOS workflow has no Developer ID/notarization credentials,
so its artifacts are checksum-verifiable but unsigned. After verifying the official
checksum, Gatekeeper may require `xattr -d com.apple.quarantine ./ouro-*` before the
first run. The release workflow says this plainly until signing is actually configured.

Until the first tagged workflow has run, build the binary on each target platform with
`make ouro` and copy `tui/target/release/ouro`; the release workflow is intentionally
marked unproven in source rather than implying an artifact already exists.

The machines need private, mutually reachable names or addresses. Tailscale is the
easiest first setup; private DNS or private IPv4 addresses work too. On every machine:

```sh
tailscale status           # this machine and the peers it can currently see
tailscale ip -4            # a private address suitable for --host
tailscale ping PEER        # run for each other machine before creating the fleet
```

Use either that Tailscale IPv4 address or a MagicDNS name that resolves to exactly one
private IPv4 address. Ouroboros refuses public, IPv6, `.local`, ambiguous multi-address,
and unresolvable fleet identities instead of creating a profile that only looks usable.

`ouro fleet create` prints the exact TCP ports to permit between fleet devices: one
fleet-specific EPMD port plus the TLS distribution range. Do **not** blindly open the
host-global EPMD port 4369, and do not expose either port set to the public internet. If
you use Tailscale grants, scope those printed ports from your fleet users/devices to the
same fleet users/devices; the current grants syntax accepts entries such as
`"ip": ["tcp:PORT", "tcp:MIN-MAX"]`. See the
[Tailscale CLI reference](https://tailscale.com/docs/reference/tailscale-cli) and
[grant examples](https://tailscale.com/docs/reference/examples/grants). The generated
fleet pins both listeners to the advertised private IPv4 interface and uses mutually
verified TLS in addition to the private network.

### Create, invite, join

The usual first-run path is **from the Mac you already launched**. Start coding immediately
with `ouro`. Then `/machines` (or `,` → machines). That overlay is a menu: known Tailscale
and SSH hosts are rows you can run, plus add, create, join, invite, service, status, and
doctor.

- **This Mac can SSH** (or Tailscale SSH) to the laptop or VPS: confirm the plan. Enter
  runs it. A first add on a still-standalone Mac restarts this runtime once to create the
  fleet, then copies a private invitation as a file and enrolls the destination when that
  is honest.
- **Mac → Linux / different CPU:** this Mac cannot copy its own `ouro`. Leave dest. binary
  empty if that host already has the matching version, or pass a Linux (or other) build
  with `--binary`. Otherwise install `ouro` on the destination and run the printed
  `ouro fleet enroll`. GitHub Linux assets stay unproven until the first tag actually
  publishes them; until then build on that OS with `make ouro`.
- **Laptop asleep, no SSH, or you will set it up yourself:** choose that method. This Mac
  writes a mode-0600 invitation and a short recipe. Copy the `.ouro` file through a
  private channel (never paste it into chat). On the other machine:

```sh
chmod 600 laptop.ouro
ouro fleet enroll laptop.ouro --delete
```

CLI equivalents, still on this first Mac:

```sh
ouro fleet list
# Reachable VPS / Linux box (same OS/CPU can copy this binary; otherwise pass --binary)
ouro fleet add user@vps --machine vps --host vps.example-tailnet.ts.net
# First add while this Mac is still standalone: stop, then --init
ouro stop
ouro fleet add --init --owner-host studio.example-tailnet.ts.net \
  user@vps --machine vps --host vps.example-tailnet.ts.net
# Unreachable or other-arch: invitation + recipe only
ouro fleet add --print-script --machine laptop --host laptop.example-tailnet.ts.net
```

`--init` (and the TUI first-add restart) refuse to rewrite a **live** runtime. Provider
sign-in is per machine and is never copied by an invitation; connect ChatGPT or the
provider on that host after it joins.

The same membership files can still be created by hand. On the first machine:

```sh
# If this data directory is already running standalone, stop it before changing posture.
ouro stop                 # harmless to omit when nothing is running
ouro fleet create
ouro fleet doctor
ouro daemon
```

Fleet creation/join/leave serialize with runtime startup and refuse to rewrite the
posture of a live VM. The refusal tells you to stop it and retry; Ouroboros never leaves a
saved fleet profile beside a still-running standalone runtime.

Ouroboros uses a reachable hostname only when it can verify one. If it cannot, it asks for
the single missing fact instead of guessing:

```sh
ouro fleet create --machine studio --host studio.example-tailnet.ts.net
```

`ouro fleet add` already writes that invitation. The commands below are the explicit
file path if you want to mint it yourself. `ouro fleet enroll FILE --delete` is join
plus starting this machine's daemon.

Still on that first machine, make one invitation for the second machine:

```sh
ouro fleet invite \
  --machine laptop \
  --host laptop.example-tailnet.ts.net \
  --out laptop.ouro
```

Copy `laptop.ouro` through a private channel. It is mode 0600 and contains that machine's
certificate/key plus the fleet membership credential; never paste it into chat or logs.
On the laptop:

```sh
chmod 600 laptop.ouro
ouro fleet join laptop.ouro
rm laptop.ouro
ouro fleet doctor
ouro daemon
```

Delete the creator's copied invitation after the join too. Repeat `fleet invite` once for
each additional machine. Start order does not matter: each daemon keeps retrying absent
members and the connected BEAM nodes form a mesh.

Every invitation is owner-attested: editing its creation time, ports, roster, certificate,
key, or cookie makes join refuse it before installing anything. The seven-day age check
prevents accidentally using stale setup instructions; it is **not** credential expiry,
because an offline invitation necessarily contains a longer-lived node credential.

If an invitation file was lost before join, reissue the same machine identity with
`ouro fleet invite --replace ...`; replacing never makes the previously copied credential
invalid. If an invitation was abandoned or mistyped, the owner may stay running while it
removes the saved expectation and creates a signed roster update:

```sh
ouro fleet invite cancel \
  --machine NAME \
  --out fleet-without-NAME.ouro-roster
```

Copy that mode-0600 roster privately to **every existing fleet machine**, then on each
recipient first inspect who owns restart recovery:

```sh
chmod 600 fleet-without-NAME.ouro-roster
ouro fleet service status
```

If a recovery service is installed, run the exact **deactivation** command printed by
that status command. Otherwise run `ouro stop`. Then install the roster while the runtime
is stopped:

```sh
ouro fleet sync import fleet-without-NAME.ouro-roster
```

If the machine had a recovery service, run its printed **activation** command again;
otherwise run `ouro daemon`. Finish with `ouro fleet doctor`, then delete the copied
roster. This ordering avoids fighting an always-restarting service or accidentally
starting a second runtime.

Cancel is safe while the owner is serving work, but its currently running formation
still has the old boot-time seed list. Restart the owner with the same service-aware
deactivate/reactivate sequence when convenient; the signed profile is already updated
and will take effect on that next boot.

The owner can recreate the current update later with
`ouro fleet sync export --out fleet.ouro-roster`. Imports reject another fleet, unsigned
edits, rollback revisions, and removal of the receiving machine itself. Cancellation and
roster sync are bookkeeping, not credential revocation. Treat a leaked invitation or
member credential as compromise of the fleet trust domain and rebuild/rotate the fleet
rather than pretending that removing a hostname revokes it.

Cancellation also does **not** silently discard session-owner evidence. If `NAME` ran
interactive or coding sessions and is offline, every gateway that previously observed
those sessions keeps its last-known rows and reports the fleet list incomplete. First
bring that machine back if possible and inspect or export the owner-local session state
you need. After the signed roster above has been imported and the runtime restarted, a
permanently lost machine can be retired explicitly on **every gateway/data directory that
may have observed it**:

```sh
ouro fleet sessions forget --machine NAME --accept-state-loss
```

Run that command locally against each member's authenticated, `operate`-scope gateway. It
requires the exact machine name, a matching signed-roster tombstone, the literal
`--accept-state-loss` acknowledgement, and an offline target; it durably updates both
session planes before reporting success. This is irreversible removal of that gateway's
local discoverability evidence, not deletion of the lost machine's files and not
credential revocation. A canceled credential that reconnects is still trusted by this
fleet until you rebuild or rotate it.

Inspect the fleet-wide directory from any running member:

```sh
ouro fleet status
ouro fleet doctor
ouro new --machine laptop --provider codex --workspace /path/on/laptop/project
```

`fleet doctor` combines those live fleet checks with certificate, interface, port, log,
and recovery-service checks that are local to the machine where it runs. Run it locally
on every machine during setup and after changing membership; one member cannot prove
another host's service manager or private files.

The selected provider runs on the selected machine. Install/sign in to that provider on
each machine where it may run work; credentials are deliberately not copied in an
invitation. If a destination is connected but its provider is unavailable, session start
returns that machine's concrete installation or authentication error instead of silently
falling back to the gateway machine. Workspace paths are likewise resolved on the
destination; automatic logical workspace mapping between different machines is not yet
implemented.

The same path is discoverable inside `ouro`: open Settings with `,`, choose
**Machines**, and follow the vocabulary-first create/join/status/membership guides. The
New Session form lists only connected, runtime-compatible machines that can run agents;
friendly names are used in the request while the technical `name@host` identity remains
visible for diagnosis.

### Start after login and recover after crashes

For an unattended fleet member, generate a user-level launchd service on macOS or
systemd user service on Linux:

```sh
ouro fleet service install
ouro fleet service status
```

`install` writes a private unit and prints the exact `launchctl` or `systemctl --user`
activation command; it does not start a persistent service behind your back. Once that
one printed command is run, the OS starts Ouroboros at login and restarts it after a VM
crash or reboot. For planned maintenance, use the printed deactivation command before
`ouro stop`; otherwise the service is doing its job when it starts the runtime again.

`ouro fleet service status` also names two private logs. `runtime.log` is owned and
live-rotated by OTP at 2 MiB with three archives; `daemon.log` retains bootstrap, VM, and
crash output and is rotated before managed starts. Keeping those writers separate avoids
rotation races while bounding ordinary long-running application logs.

`ouro fleet service status` and `ouro fleet doctor` print both managed log paths and
their distinct limits. `runtime.log` is the live application sink: OTP rotates it after
2 MiB and retains three archives (`runtime.log.0` newest through `.2`) even during one
uninterrupted run. `daemon.log` keeps inherited stdout/stderr so early bootstrap and VM
crash diagnostics are not lost; it is checked and rotated before a managed start after
2 MiB, with three private backups. Only OTP writes or renames `runtime.log`, so the two
sinks never race one rotated file.

Recovery has explicit boundaries:

- late boot and temporary network loss heal automatically through supervised libcluster
  retries; BEAM distribution, monitors, and the scoped `:pg` directory resynchronize;
- a restarted remote worker machine is reconciled by its durable team owner after the
  node rejoins, without restarting the whole team;
- coordinator/process crashes recover from the owner machine's durable checkpoints;
- a full machine/BEAM restart restores the runtime and fleet membership, but a live
  provider subprocess is **not migrated to another machine**. Its owner-local checkpoint
  remains inspectable and recovery is only as strong as the provider's resumable session;
- changing a machine's fleet identity strands state owned by the old BEAM node name, so
  leave the generated identity stable;
- formation is not quorum or fencing. A network partition may create two temporarily
  independent views; Ouroboros does not claim partition-safe placement or replicated
  session storage.

Repository contributors can rerun the same packaged three-node acceptance proof used by
Linux CI without touching their normal data directory:

```sh
make fleet-e2e
```

It creates a private temporary lab, boots in reverse order, removes/rejoins the hub,
crashes a service-owned leaf, verifies exactly one automatic replacement and a healed
TLS mesh, then stops only the recorded lab PIDs and removes the lab.

`ouro fleet leave` removes only a stopped machine's recognized fleet credentials. It
does not evict or rewrite the other machines. Deactivate and remove that machine's
recovery service first, then run it only when intentionally making the machine
standalone. The creator is the sole invitation authority and cannot leave while other
members remain; before depending on a fleet, keep an encrypted, offline backup of the
creator's entire private `fleet/` directory while its runtime and service are stopped.
Do not copy only `ca-key.pem`: the profile, cookie, CA, and node identity are one unit.

The remaining environment-variable configuration below is the advanced path for custom
roles, custom discovery, containers, and operator-managed PKI. New installations should
use `ouro fleet`.

### Advanced: node roles

A node boots exactly one role, from `OUROBOROS_NODE_ROLE` (default `core`):

| Role      | Supervision tree                                   | What it is for                          |
| --------- | -------------------------------------------------- | --------------------------------------- |
| `core`    | the full runtime — mesh, teams, sessions, journals, scheduler, control plane | running work |
| `builder` | cluster formation only                              | compiling forged capabilities off the production host |
| `signer`  | cluster formation plus `Upgrade.Signing.Service`    | holding the signing key, policy, and decision journal where nothing else on the host can reach them |

A `builder` and a `signer` run *this same release*, booted differently. That is not
convenience: the forge's artifact is verified against the loading node's exact OTP
release, Elixir version, and architecture, so a builder that is not runtime-identical to
its targets produces BEAMs every target rejects. One artifact, one runtime, three roles.

An unrecognized role refuses the boot rather than falling back to `core`. So does a
`signer` whose key is missing or malformed — see
[The signing service](#the-signing-service).

```sh
OUROBOROS_NODE_ROLE=builder    # this host only compiles
```

Point a core node at a builder and forge builds relocate with no other change:

```sh
OUROBOROS_FORGE_BUILDER_NODE=builder-1@builder-1
```

The build still happens inside a non-distributed `:peer` — it simply happens on the
builder's host now. A builder that is unreachable, not running this runtime, or not
actually in the `builder` role is refused with
`{:error, {:forge_builder_refused, node, reason}}` rather than silently building
locally.

### Formation

`OUROBOROS_CLUSTER_STRATEGY` is `none` by default; nothing forms until you name one.

| Strategy | Variables                                                             |
| -------- | --------------------------------------------------------------------- |
| `none`   | —                                                                     |
| `epmd`   | `OUROBOROS_CLUSTER_HOSTS` (comma-separated node names)                |
| `gossip` | `OUROBOROS_CLUSTER_GOSSIP_SECRET`, `OUROBOROS_CLUSTER_GOSSIP_PORT` (both optional) |
| `dns`    | `OUROBOROS_CLUSTER_DNS_QUERY`, `OUROBOROS_CLUSTER_DNS_BASENAME` (defaults to this node's name) |

`OUROBOROS_CLUSTER_RECONNECT_MS` (default 5000) is the retry interval, not a deadline —
it is what makes boot order irrelevant. A strategy that is named but missing its
variables refuses the boot; it does not quietly run unformed.

### Distribution TLS

Cleartext Erlang distribution puts the shared cookie, and everything after it, on the
wire. Generate a private CA and one certificate per node:

```sh
# One CA for the cluster. Only nodes holding a certificate it signed can handshake.
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout ca.key -out ca.pem -subj "/CN=ouroboros-dist-ca"

# One key and certificate per node.
openssl req -newkey rsa:4096 -nodes -keyout core-1.key -out core-1.csr \
  -subj "/CN=core-1"
openssl x509 -req -in core-1.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 -out core-1.pem
```

The `ssl_dist_optfile` is an Erlang term file — one list, ending in a period, with a
`server` and a `client` section. Both sides must verify, or only half the handshake is
authenticated:

```erlang
%% /etc/ouroboros/dist_tls.conf
[{server, [{certfile, "/etc/ouroboros/tls/core-1.pem"},
           {keyfile,  "/etc/ouroboros/tls/core-1.key"},
           {cacertfile, "/etc/ouroboros/tls/ca.pem"},
           {verify, verify_peer},
           {fail_if_no_peer_cert, true},
           {versions, ['tlsv1.3']}]},
 {client, [{certfile, "/etc/ouroboros/tls/core-1.pem"},
           {keyfile,  "/etc/ouroboros/tls/core-1.key"},
           {cacertfile, "/etc/ouroboros/tls/ca.pem"},
           {verify, verify_peer},
           {versions, ['tlsv1.3']}]}].
```

`ouro fleet` writes this file and a matching private `vm.args` per machine, then selects
them with `RELEASE_VM_ARGS` at launch. That is why the same stock `ouro` binary can use
different certificates, names, and port ranges without a rebuild. Building or launching
a plain Mix release is not a supported substitute: raw releases currently have no
trusted native process-incarnation/recovery helper.

At boot, `config/runtime.exs` reads the transport the VM is actually running. A node
that forms a cluster over cleartext distribution refuses to start unless
`OUROBOROS_ALLOW_INSECURE_DIST=1` says that is intended.

### Three nodes

Create, invite, and join all three through the `ouro fleet` walkthrough above, then
install the generated service on each host. Fleet startup puts only a fresh disposable
boot cookie on the VM command line, validates the 0600 cookie file, and installs the real
credential before libcluster starts; the real fleet cookie is never placed in argv or
the environment. A raw-release Docker Compose topology is intentionally not documented
as runnable until the container packaging includes the trusted native lifecycle helper.

Once up, `Ouroboros.status()` reports the local role, the roles it can see, the
formation strategy, and the distribution posture (`security.cookie` is `:set` or
`:unset`, never the cookie itself):

```elixir
Ouroboros.Cluster.role()               #=> :core
Ouroboros.Cluster.nodes_by_role(:core) #=> [:"core-1@core-1", :"core-2@core-2"]
Ouroboros.status().cluster.security    #=> %{distributed: true, proto_dist: :inet_tls, tls: true, cookie: :set}
```

Topology churn is logged and retained in a secret-free last-known directory. `fleet
status` therefore shows configured or previously observed machines as connected/offline,
their last transition, compatibility, TLS posture, and the supervised retry interval
instead of making a departed machine disappear.

### Honest limits

- **The cookie and TLS are transport authentication, not authorization.** They decide
  who may complete the distribution handshake. They decide nothing about what a node
  may then do — and the answer is *everything*. Any connected node can `:erpc` any
  exported function on any other node, load code, read that node's application
  environment (including a configured signing key), and kill its processes.
- **Placement checks are misconfiguration detection.** `Mesh.start_agent_on/3` and a
  team's `:node` option refuse a target that is not a connected `core` node running this
  runtime, and the forge refuses a builder that is not in the `builder` role. That stops
  work being sent where it cannot run. It stops nothing a hostile connected node decides
  to do, because that node never has to call these functions at all. The same is true of
  the `Ouroboros.Capability.` namespace policy and the protected-module list.
- **Roles reduce blast radius; they do not contain a compromise.** A builder holds no
  teams, sessions, journals, grants, or control plane, so compromising it yields a
  compiler rather than a fleet. A signer holds one process, whose policy refuses a
  control-plane patch to every caller alike — but the host is still a fully authorized
  cluster member, so a connected node can call the signing service, and can reach the
  signer's VM by every other route `:erpc` offers. Real containment needs the build and
  signing hosts outside the cluster's trust domain entirely, reached by something
  narrower than Erlang distribution.
- **Formation is not fencing.** libcluster connects nodes. It has no quorum, no
  partition policy, and no opinion about a node that comes back with stale state.
  `:global.trans/2` narrows duplicate-start races in a *healthy connected* cluster and
  is not partition-safe consensus.
- **Manual releases still own their manual PKI.** `ouro fleet` generates runtime TLS and
  port arguments dynamically. If you bypass it and use the environment path above, you
  own certificate renewal, cookie rotation, and the `RELEASE_VM_ARGS` file or build-time
  flags yourself.
- **EPMD is still in the path** for the `epmd` and `dns` strategies: its port (4369)
  has to be reachable even when the distribution listener is pinned elsewhere.

## Current limits

- The default domain stores are ETS in development/test and one atomic file-backed
  aggregate in production. Release, fast-patch, grants, signing, and effect-ledger
  mutation journals add file and directory sync before acknowledging a checkpoint. All
  remain single-node ownership, not transactional HA databases.
- Terminal coding tasks and interactive sessions are the only durable state that is
  ever retired. Their recovery loops sweep entries older than
  `:ouroboros, :terminal_retention_ms` (seven days by default, `nil` disables the
  sweep), and `Store.delete/1` refuses anything non-terminal. Team, orchestration,
  control, upgrade, and release aggregates still only accumulate; sizing them is an
  operator concern until each plane grows its own retention policy.
- Harness runs survive callers and Ouroboros coordinator crashes, but not a full
  Harness application/BEAM/host restart. Ouroboros retains the task and reports
  `:lost`; automated resume/retry policy is future work.
- Provider installation, authentication, billing, and actual repository effects are
  external gates. The test suite uses a deterministic adapter and does not spend an
  inference call.
- `jido_harness` 2.0 is pinned from Git because it is not currently published on Hex.
- Team, orchestration, interactive-session, control, upgrade, and release state is
  restart-persistent in production's configured stores. Security-sensitive mutation
  journals (including grants, signing, and agent effects) use the stronger synced
  adapter; none of these single-node aggregates is HA consensus.
- Interactive Harness processes, like detached runs, do not survive a full BEAM or
  host restart. Durable Ouroboros intent remains inspectable, but the local session
  becomes `:lost` unless the provider process still exists.
- Workspace admission is node-local and does not provision worktrees or an OS
  sandbox. Shared filesystems need one routed authority or consensus.
- Autonomous evaluation is implemented with bounded revisions and step count, but
  aggregate token/cost/time budgets, independent policy approval, and behavioral
  regression scoring remain.
- Cluster formation is implemented (libcluster: static epmd, gossip, DNS polling) and
  off by default, and nodes boot a role-shaped tree. Formation is not fencing: there is
  no quorum, no partition policy, and no reconciliation of a node that returns with
  stale state. Role separation reduces blast radius and does not contain a compromised
  node, which retains full `:erpc` authority over every node it is connected to.
- The forge compiles and tests candidate capabilities in an isolated, non-distributed
  build peer, and that peer can now run on a least-privileged `builder` node. It still
  shares that host's user, filesystem, and network, and a builder is still a fully
  authorized cluster member. Real OS sandboxing is external. Capability rollout records
  accumulate; only settled `:rolled_back` entries are pruned when the store exceeds
  `:ouroboros, :capability_rollout_limit`.
- Signing runs on a `signer` node: the key is read at boot from a file that host mounts,
  an independent policy recomputes the full artifact and structurally refuses anything
  outside `Ouroboros.Capability.`, and every decision is journaled durably before a
  signature is returned. What is still external is custody *outside the distribution
  trust domain* — a signer node is a connected cluster member, so any node that
  completes the handshake can call the service and reach that VM by other routes. The
  requester identity behind the rate limit is self-reported, and there is no human
  review queue. Signing decisions accumulate up to
  `:ouroboros, :signing_journal_limit`, then trim oldest-first.
- Evaluation gates run a signed, declarative probe set on every target between commit
  and promotion, and champion/challenger holds a replacement to the version it displaces
  on pass count and total time. What that does not do: model cost, sample real traffic,
  run a canary cohort, or say anything statistically meaningful about wall-clock over a
  handful of probes. `:capability_eval_regression_budget` defaults to 1.2× for that
  reason, and a report is evidence about the declared spec and nothing else.
- Agent effect grants and the effect ledger are node-local, deny-by-default, and durable
  per production node. They constrain and explain the agent action layer and nothing
  below it: loaded code reaches the same public APIs directly. The ledger survives the
  acting agent and records restarted in-flight work as ambiguous, but it is a bounded
  aggregate checkpoint, not a replicated or append-only audit service. Per-principal
  rate and cost budgets and replicated policy authority are not implemented.
- Release metadata construction, archive inspection, authorization, and journaling are
  implemented; full tar assembly and a real `HandlerAdapter.OTP` reboot rehearsal are
  deployment gates.
- The terminal remains a client of one loopback gateway, at the scope that listener was
  booted with. In fleet mode that gateway can list, start, route, replay, and follow work
  owned by connected BEAM nodes; it is not a separately exposed remote control port on
  every machine. Its token authenticates a connection and sandboxes nothing. Session
  journals remain owner-local, attached clients do not receive a general runtime log
  stream, and a full owner-host loss does not migrate a live provider subprocess.
- CI exists as two GitHub Actions workflows and has not been proven on a hosted runner.
  The configured repository remote is not a public GitHub release channel, and no tag or
  downloadable release exists yet. The four-target release matrix is a statement about
  ERTS — a release is only valid on the OS and architecture that built it — not a record
  of four hosted builds that happened.

The next architecture steps and stop conditions are tracked in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
