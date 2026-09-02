# WASM: containment lanes for forged capabilities, hooks, and policy

Status: **spec, nothing built.** Written 2026-09-01 against main `c677fe0`. Every
file:line claim below was verified against that tree; if you are reading this much
later, re-verify before building.

## 1. Purpose

Ouroboros has one place left where admission is hygiene rather than containment: code.
A forged BEAM module, a repo-shipped hook, a configured MCP server — each runs with the
ambient authority of the process that loads or spawns it, and everything we do about
that today is policy over *names* (namespace rules, deny lists, trust lists), not a
boundary. This spec adds WebAssembly components as a second lane for exactly those
artifacts: forged capabilities, hooks, and permission policy. A component's authority
is its import list; an import the host does not define **fails to link**. That converts
the sentence "any loaded module has ambient VM authority" — written four times across
ARCHITECTURE.md — into a sentence about one lane instead of the whole system.

This is not a portability project and not a rewrite. The BEAM lane stays, for
everything that must be OTP (supervision, stores, live control-plane evolution). The
native loop is not ported to wasm (see §9.2 for why). The workspace — `bash`, git, LSP
— is a different axis entirely; §10 covers the microVM tier for it, deliberately last.

Goals, in the user's words: agents that are **secure** (containment, not name policy),
**auditable** (an artifact whose maximum authority is statically legible, signed and
content-addressed), and **extensible** (third-party capabilities, hooks, and policy in
any language, safe to install by construction).

## 2. Method

Four explorer agents mapped the subsystems this spec plugs into (forge/sign/deploy
lifecycle; the Rust helper-on-a-pipe pattern; hooks/permissions/MCP; sandbox backends
and fleet placement). Every load-bearing claim was then spot-verified by hand against
the working tree — all checks matched, with two corrections recorded in §13. External
facts (wasmtime, wasmex, fleet KVM) were checked live on 2026-09-01 and are dated in
§5.

## 3. The problem, stated from the code

**3.1 Forge admission is hygiene, and says so.** `Forge.Source`'s deny list
(`lib/ouroboros/upgrade/forge/source.ex:55-65`) bans `Code`, `Port`, `File`, `:erpc`,
`:erlang.load_nif` and friends, and its own moduledoc (`source.ex:11-27`) is candid:
"This is hygiene, not a sandbox… A macro expands after this walk has finished." The
real gates — the capability namespace (six enforcement points, §4.1), the signer's
recomputation (`signing/policy.ex:200-224`), the verifier's import scan for
`load_nif` (`upgrade/beam.ex:147`) — are all checks on names and static properties. A
capability that passes them still runs with full VM authority: every module, every
process, the distribution mesh.

**3.2 Hooks are the one repo-shipped code path with no sandbox at all.** A hook is
`sh -c` through `Exec.run_shell` (`provider/native/hooks.ex:486`,
`provider/native/exec.ex:98-109`) with a filtered-but-ambient environment: `HOME`,
`PATH`, the filesystem, the network. `Sandbox.wrap` has exactly two call sites —
`tools/bash.ex:142` and the ACP terminal service (`session/service.ex:628`) — and
hooks are not one of them (`docs/AGENT_EXPERIENCE.md` C5 row records this). The entire
mitigation is `Hooks.trusted?/2` (`hooks.ex:452-479`): operator-configured
`:trusted_workspaces`, deliberately never an in-repo marker. Consequence: a cloned
repository's hooks and `[checks]` are declined wholesale. Containment would let them
run.

**3.3 The fleet makes BEAM artifacts expensive.** An artifact is loadable on exactly
one OTP/Elixir/architecture triple (`upgrade/verifier.ex:142-151`, exact equality,
checked on every loading node), the triple is stamped from the **forging** node
(`upgrade/artifact.ex:54-56`), and the builder's triple is recorded but never compared
— FLEET.md F6, still unfixed, confirmed. The fleet is macOS + Linux. One forged
capability for the whole fleet means per-triple builds on matching builders; none of
that machinery exists yet. A wasm component is one artifact for every node, forever.

**3.4 Forged bytes do not survive.** After promote, the artifact and any preimage
bytes are deleted with the receipt (`upgrade/node_executor.ex:766` names the
write-ahead record as "the only place preimage bytes are durable";
`node_executor.ex:969` `delete_receipt`). `Rollout.Registry` stores hashes, never
bytes. A forged capability lives in the running VM only; a restart boots the release
without it. This is also the standing blocker for `Forge.reforge` (no durable artifact
archive). A wasm lane stores bytes as data by necessity — and thereby fixes reboot
survival for its lane (§7.4).

## 4. Verified current state — the seams this spec plugs into

### 4.1 Forge / sign / deploy (the BEAM lane as-built)

- Pipeline: `Forge.forge/2` = validate → eval-spec validate → build in a
  non-distributed `:peer` (`-start_epmd false`, `forge/build_peer.ex:177-179`) →
  `Beam.introduce/3` → `Epoch.next/2` → `Artifact.build/2` → sign
  (`upgrade/forge.ex:65-75`).
- Signer behaviour: `sign(payload, signer_id)` + optional
  `sign_artifact(artifact, signer_id)`, 64-byte signature enforced
  (`forge/signer.ex:41-53`, `forge.ex:226-230`). `Signer.Deny` default; `Signer.Remote`
  requires the `:signer` role and re-derives the payload server-side, refusing on
  mismatch (`signing/service.ex:403-418`).
- `Signing.Policy.Default` checks, in order: shape → capability namespace (hard rule,
  no config, `policy.ex:196,260-268`) → per-module recomputation from bytes (sha256,
  md5, vsn, refuses `on_load`/`nif?`/`protocol?`, `policy.ex:333-365`) → provenance
  (`source_sha256` hex, `test_report.failures == 0`, derived `passed >= 1`) → eval
  criteria when `:signing_require_eval`.
- `Rollout.deploy/4`: champion baseline → **checkpoint `:deploying` before any
  effect** (`upgrade/rollout.ex:190-205`) → `Coordinator.deploy` (prepare/commit/health
  phases) → probe-gated health → eval → promote/rollback/quarantine. Ambiguity is
  always quarantine; only proven recoveries earn `:rolled_back` (`rollout.ex:397-407`).
- `Rollout.Probe`: starts the capability as a throwaway mesh agent
  (`Mesh.start_agent(id, agent: module)`, `rollout/probe.ex:101`), sends one
  `ouroboros.agent.message` with `%{probe: id, node: node()}`, requires a map state
  back; a `:last_message` key must echo the body (`probe.ex:132-144`). Budget
  `budget_ms/0` = 22s. `Rollout.Evaluation` starts one agent with
  `initial_state:` and drives declared probes through it (`rollout/evaluation.ex:394-397`);
  expectations `:any_reply | {:equals,..} | {:contains,..} | {:state_matches,..}`.
- `Rollout.Registry`: checkpoint v2, states
  `deploying|live|superseded|rolled_back|quarantined`, quarantine has no automatic
  exit. **`entry.module` is typed `module() | String.t()`**
  (`rollout/registry.ex:86-88`) — already binary-tolerant, which §7.6 leans on.
- What a deployed capability *is*: exactly one `Jido.Agent` under
  `Ouroboros.Capability.*` routing `ouroboros.agent.message` to an answering action
  (`runtime/manifesto.ex:24-27`; reference shape `agent/worker.ex:19-53`, de-facto
  state keys `:last_message`/`:last_answer`). Deploy loads code; it starts no durable
  process. The only durable start is `Runtime.Capabilities.maybe_start/2`, gated on a
  `:live` registry entry.
- Namespace enforcement points (all six): source regex (`source.ex:51,121-129`),
  verifier introduce-prefix (`verifier.ex:68,247-253`), verifier protected set
  (`verifier.ex:40-67,283-291`), signer policy (`policy.ex:196,260-268`), mesh start
  allow-list (`mesh.ex:30`: `["Elixir.Ouroboros.Agent.", "Elixir.Ouroboros.Capability."]`),
  operator entry-point regexes (`runtime/capabilities.ex:258-268`,
  `orchestration/step.ex:152-158`).
- Identity: `Upgrade.ModuleName` exists solely because forged atoms don't survive
  reboot (`upgrade/module_name.ex:1-19`). Content addressing is pervasive (source
  sha256, BEAM sha256/md5, deterministic signing payload
  `artifact.ex:75-77`).
- Effects lane: `ForgeCapability`/`DeployCapability` under `Control.Grants`
  deny-by-default; the principal is server-owned `context.agent.id`, never the
  signal's claim (`agent/effects/runner.ex:126`); a deploy can only ship an artifact
  the same agent's granted forge returned (`agent/effects.ex:304-313`).

### 4.2 The helper-on-a-pipe pattern (the Rust template)

Two variants exist; `ouro-wasm` copies the **server-shaped** one.

- Workspace: `tui/Cargo.toml` members `[".", "computer-use", "sandbox"]`; helpers are
  isolated members, never dependencies of `ouro`, each with hand-rolled argv parsing
  and a written justification per dependency.
- `ouro-computer-use` (server-shaped): line-framed JSON-RPC 2.0 on stdio, 8 MiB frame
  cap **enforced as bytes are read** (`tui/computer-use/src/codec.rs:11-15,27`), noise
  budget 32 lines, `serve`/`doctor` subcommands, private error codes in
  `-32001..-32099`, blocking work in `spawn_blocking` with a `cancel` notification.
- `ouro-sandbox` (exec-shaped): one JSON policy in argv `--request` because the exec
  seam spawns children with `{:stdin, :close}` (`tui/sandbox/src/request.rs:14-18`,
  `provider/native/exec.ex:128`); `deny_unknown_fields` on the request; exit 125 +
  `ouro-sandbox: ` stderr prefix distinguishes backend failure from command failure.
- Elixir owner (server-shaped half): `Native.Desktop.Pool` — one helper per node,
  lazy, spawned via `Port.open({:spawn_executable, ...})` with secret-shaped env
  unset (`desktop/pool.ex:47,548-552`), handshake = a `doctor` request, broken is a
  state with a 15s cooldown (never a crash), port monitored with the double-delivery
  trap handled (`pool.ex:362-366`), kill-by-os-pid before close.
- Supervision: `Desktop.Supervisor` and `Mcp.Supervisor` sit at the tail of the
  `:core` tree after the gateway (`application.ex:244-251`), rationale at
  `application.ex:229-234` ("somebody else's program… on the end of a pipe, spawned
  lazily, owning nothing any plane rebuilds from").
- Binary resolution: env override → configured path → priv candidates → parent walk
  (`desktop.ex:174-239`); presence on disk is the operator opt-in. Built binaries are
  gitignored (`/priv/computer-use/`, `/priv/sandbox/`); `make computer-use` /
  `make sandbox` build into `priv/` and fan out to `_build/*/lib/ouroboros/priv/`;
  both are prerequisites of `release-tarball` (`Makefile:193`) so the embedded `ouro`
  ships them.
- Tests: pool tests use throwaway shell scripts as fake helpers; enforcement tests
  skip loudly when the real binary is absent; Rust integration tests use
  `env!("CARGO_BIN_EXE_...")`.
- **No wasm anything exists in the repo today** — zero matches in `mix.exs`,
  `mix.lock`, all `Cargo.toml`s (only unreachable `wasm-bindgen` transitive entries in
  `Cargo.lock`).

### 4.3 Hooks, permissions, MCP (the policy seams)

- Hook contract: ten events; TOML `[[hooks]]` from `~/.config/ouroboros/hooks.toml`
  (always) and `<workspace>/ouroboros.toml` (trust-gated); **no node-config scope for
  hooks** (unlike MCP and permissions — asymmetry recorded as W-F3). Both chains run,
  user first; deny is final from either.
- Execution seam: `invoke/3` at `hooks.ex:483-516` is the single choke point — stdin
  JSON in, exit-2-deny / exit-0-JSON out (`permissionDecision`/`decision`,
  `updatedInput`, context lines), everything else ignored loudly. The fold
  (`pre_tool_use/4`) and the four ordering invariants live **above** this seam and
  would not change: engine deny ⇒ no hook runs (`loop.ex:1266-1288`); hook `ask`
  outranks `auto_approve` (`loop.ex:1306-1319`); silence is not consent
  (`loop.ex:1338-1351`); `updatedInput` is re-classified and re-evaluated
  (`loop.ex:1360-1405`).
- Permission engine: total `evaluate/1` over a normalized request
  (`tool/command/paths/write_paths/mode/domains/root`), verdicts
  `{:allow,rule}|{:deny,rule}|{:ask,reason}`, protected writes checked before any
  rule, deny→ask→allow ranked before scope, fail-closed on store loss and on
  unrecordable allows (`control/permissions.ex:436-470`). The native loop reaches it
  through a guarded swap seam: `config :ouroboros, :permissions_engine`
  (`provider/native/permissions.ex:67-69`) — **the cleanest existing plug for a wasm
  policy stage**. Note: the ACP lane calls `Control.Permissions` directly through
  `Seam` and is not covered by that seam.
- Classifier auto mode (C6): no code, only the reserved
  `actor: :rule | :human | :classifier` in the ledger entry type
  (`permissions.ex:92`) and AGENT_EXPERIENCE.md rows.
- MCP is the worked precedent for a dynamic tool lane: one seam in
  `tools.ex:262-269` (`resolve_module` returns `{McpTool, name}`), specs appended
  behind a gate, opaque `{module, name}` dispatch, honest `:execute` classification
  for opaque programs (`tools.ex:441-447`). Nothing outside `tools.ex` changed to
  admit MCP.

### 4.4 Sandbox backends and fleet placement (for §10)

- Backend selection: macOS → `sandbox-exec`; Linux → `ouro_sandbox` (Landlock+seccomp
  helper, doctor-gated) → `bwrap` (namespace-probe-gated) → none
  (`provider/native/sandbox.ex:568-604`). Detection cached in `:persistent_term`;
  config override read before the cache.
- The hard interop contract: denials are recognized by exactly three strings —
  "Operation not permitted" (EPERM), "Read-only file system" (EROFS), "Network is
  unreachable" (ENETUNREACH) — and EACCES is deliberately not a sandbox signal
  (`sandbox.ex:751-755,441-448`); inner layers are kept *congruent* with the mount
  layer so the first-consulted layer produces the observable error
  (`sandbox/helper.ex:66-71`).
- Escalation re-runs are **fenced**, not unrestricted: approve re-runs under
  `:workspace_write_escalated` (only the `.git` segment deny lifted;
  `.ouroboros`/data/config/network still enforced, `sandbox.ex:39-43,681-682`,
  `loop.ex:1818-1822`). Network denials are never escalatable; there is no domain
  allowlist ("external network is on or off, never 'these hosts'",
  `sandbox.ex:96-98`).
- Lease rule: any non-`read_only` sandbox mode takes an exclusive workspace lease by
  default (`coding/task_state.ex:477-478`). Worktrees are provisioned idempotently on
  every admission (`workspace/worktree.ex:141-142`); "The provider never learns any of
  this. It receives a `cwd`" (`worktree.ex:137-138`).
- Fleet facts: `local_fleet_posture/0` = `%{node, role, running, machine, runtime}`
  (`cluster.ex:1408-1415`); consumers pattern-match open maps, so **adding keys is a
  rolling-safe change** (FLEET.md verified this); tags are FLEET.md §6 design, not
  code. `ensure_placeable/1` = connected `:core` + runtime contract
  (`fleet_protocol_revision`, `ouroboros_version`, `otp_release`); architecture is
  deliberately inventory, never a placement fence (`cluster.ex:1445-1448`).
- Remote subagents: spec crosses the wire as a plain map; provisioning, validation,
  and session open all run on the child's node (`native/subagent.ex:77-83,174-179`);
  approvals relay to the parent's human. A microVM-executed remote session rides this
  seam unchanged.
- `WebFetch(domain:)` rules exist and match `mode: :network` + `domains`
  (`permissions/matcher.ex:98-100`); a host-side egress proxy consulting
  `Permissions.evaluate/1` with that request shape reuses them verbatim.

## 5. External facts (checked 2026-09-01)

- **wasmtime**: current major 43+ (Aug 2026 release); WASI 0.3.0 shipped 2026-06-11
  with native async in the component model (`async func`, `stream<T>`, `future<T>`);
  wasmtime 43 supports the WASIp3 release-candidate snapshot. Fuel metering, epoch
  interruption, per-store memory limits, and the pooling allocator are stable,
  long-standing APIs.
- **wasmex** 0.15.1 (2026-08-07): component-model support via `Wasmex.Components`, on
  wasmtime 39, as a NIF. Real, maintained — and not chosen here (D3).
- **Guests**: stable Rust targets `wasm32-wasip2` natively; `componentize-js` /
  `componentize-py` exist for TS/Python guests.
- **Fleet KVM**: the Ubuntu VPS (`ouroboros-vps`) has `/dev/kvm` present and usable
  (checked over ssh 2026-09-01; the VPS is itself a KVM guest with nested
  virtualization exposed, kernel 7.0). The Macs will never run Firecracker; libkrun /
  Apple Containerization are the macOS analogues.

## 6. Design overview: lanes, not a migration

| Lane | Artifact | Authority model | Status quo it replaces |
|---|---|---|---|
| **B — BEAM** (unchanged) | signed BEAM modules, `Ouroboros.Capability.*` | ambient VM; namespace + signer + verifier policy | itself |
| **W — wasm capability** (§7) | signed component, content-addressed | import list; instance limits | the default lane for new forged capabilities |
| **H — wasm hooks/policy** (§8) | component per hook / policy module | log-only imports | `sh -c` hooks; the C6 classifier slot |
| **T — wasm tools** (§9.1, deferred) | component per tool | per-call WASI scope | pure native tools / some MCP servers |
| **A — wasm agents** (§9.2, deferred) | component exporting an agent world | host-bound effect imports | nothing — bring-your-own-brain extensibility |

Routing rule for the forge: a capability that is a pure signal handler — receives
`ouroboros.agent.message`, computes, replies, keeps its own state — goes to lane W. A
capability that must supervise processes, own a store, or participate in OTP behavior
evolution stays in lane B and keeps the full epoch/preimage/purge ceremony. The
expectation is that most forged capabilities are lane-W-shaped.

## 7. Lane W: capabilities as components

### 7.1 The world

```wit
package ouroboros:capability@0.1.0;

world capability {
  /// JSON metadata: name, version, declared eval hints. Pure.
  export describe: func() -> string;
  /// Called once per instance with host-supplied JSON config.
  export init: func(config: string) -> result<_, string>;
  /// One mesh message in, one reply out. JSON both ways. State is instance-held.
  export handle-message: func(body: string) -> result<string, string>;
  /// Log line into the daemon's logger. The only import in v1.
  import log: func(level: string, message: string);
}
```

Deliberately synchronous and minimal, although WASIp3 async now exists (D4): no clock,
no random, no state imports, no I/O. `handle-message` is a step function over
instance-held state; determinism is a property, not a promise. `state-dump`/`state-load`
exports for migration are v2 (`@since` on the world), not v1.

### 7.2 Identity: no BEAM module at all

A lane-W capability introduces **no module and no atom**. Its identity is the
component's sha256; its runtime shape is one *static, shipped* wrapper agent —
`Ouroboros.Wasm.Capability`, a `Jido.Agent` whose `initial_state` names
`%{component: <sha256>, config: <json>, name: <string>}` and whose
`ouroboros.agent.message` action forwards the signal body as JSON to the instance and
writes the reply back into agent state as `:last_answer`, keeping `:last_message`
updated. That last sentence is what makes `Rollout.Probe`'s echo check
(`probe.ex:132-144`) and `Rollout.Evaluation`'s whole expectation grammar
(`:equals`/`:contains`/`:state_matches` via `state.last_answer`) work **unchanged**
against a wasm capability.

Consequences, all verified against the seams in §4.1:

- `Upgrade.ModuleName` is unnecessary for this lane — a sha256 string survives any
  reboot and any `binary_to_term(…, [:safe])`.
- The mesh allow-list grows one prefix: `"Elixir.Ouroboros.Wasm."` beside the two in
  `mesh.ex:30`. The namespace is safe to admit because forged code structurally cannot
  enter it (verifier introduce-prefix requires `Ouroboros.Capability.*`; signer policy
  refuses anything else).
- `Ouroboros.Wasm.` joins the verifier's `@protected_prefixes` (`verifier.ex:53-67`):
  the wasm host machinery must not be hot-patchable by the thing it contains — the
  same sentence that puts the permission engine under `Control.` (D10).
- `Probe.ready?/1` and `Evaluation.run/3` take a module today
  (`Mesh.start_agent(id, agent: module, …)`). Both are generalized over a *start
  spec* — `module | {module, initial_state}` — a small additive change; lane B passes
  the bare module and nothing observable changes for it (D7).

### 7.3 The host: `ouro-wasm`

A new isolated workspace member `tui/wasm/`, bin `ouro-wasm`, **server-shaped** —
copied structurally from `ouro-computer-use` (§4.2): `serve`/`doctor` subcommands,
line-framed JSON-RPC with the 8 MiB read-bounded cap and noise budget, hand-rolled
argv, private error codes. The one heavy dependency is `wasmtime` (pinned major, 43+
at time of writing) — and keeping it out of `ouro`'s build graph is the strongest case
the isolated-member discipline has yet had.

Methods:

| method | params | returns |
|---|---|---|
| `doctor` | — | `{usable, wasmtime, worlds: [supported world ids], imports, limits, held: {components, instances, evictions, evicted}, notes}` |
| `inspect` | `{path}` | `{sha256, world, imports, exports, size}` — parsed from bytes |
| `load` | `{sha256, path}` | `{…as inspect, cached, evicted: [sha]}` / refusal (`sha_mismatch`, `unsupported_world`, `undefined_import`, `too_many_components`) |
| `instantiate` | `{instance, sha256, config, limits: {fuel, memory_bytes, deadline_ms}}` | ok / init error |
| `call` | `{instance, export, payload}` | `{payload, fuel_used}` / trap / deadline |
| `drop` | `{instance}` | ok (idempotent) |

Enforcement lives here and is structural: the linker defines exactly the functions the
supported world imports (`log`, in v1) and nothing else, so **an unlisted import fails
instantiation — authority cannot be smuggled past a lying manifest** (D5). Every call
runs under a fuel budget, an epoch deadline, and a store memory cap; exhaustion is a
typed refusal, not a hang. A wasmtime panic or segfault kills a Port, not the node —
which is the point of the helper (D3).

The component cache is bounded and evicts (`MAX_COMPONENTS` = 64; W6). A `load` past the
ceiling evicts the **least recently used** component that no live instance holds — an
instance keeps its own handle on the compiled code, and an owner with an instance up is
still using that component — and names what it let go in its result (`evicted`); `doctor`
reports the count and the last `MAX_EVICTION_LOG` = 16 of them under `held`. The refusal
`too_many_components` is reached only when every held component has a live instance.
Eviction is a reclaim, not a revocation: the sha is simply unknown again, `instantiate`
refuses it `unknown_component`, and the peer re-`load`s — recomputing the digest and the
world check exactly as the first load did. Every peer in this repository loads before it
instantiates. Instances are never evicted: `MAX_INSTANCES` = 256 is a hard ceiling and
`too_many_instances` means "drop one". The pool's per-lifetime hook budget (W4, 16 shas)
stays, as a bound on the churn a repository can cause rather than on the table filling.

Elixir side, copied from the `Desktop.Pool` half: `Ouroboros.Wasm.Pool` (one helper
per node, lazy, `Port.open` spawn with the same `@secret_env` stripping, doctor
handshake, broken-state cooldown, kill-by-os-pid), `Ouroboros.Wasm.Supervisor`
inserted in the `:core` tail beside `Desktop.Supervisor`/`Mcp.Supervisor`
(`application.ex:244-251`), binary resolution env-override → config → priv →
parent-walk, `make wasm` mirroring `Makefile:79-92`, `/priv/wasm/` gitignored,
`release-tarball: computer-use sandbox wasm`.

### 7.4 The store: bytes survive, deliberately

`Ouroboros.Wasm.Store`: content-addressed component bytes at
`<data_dir>/wasm/components/sha256-<hex>.wasm`, written with the
`Release.PackageStager` discipline (`release/package_stager.ex:14-26`: digest
validated against bytes, publish-once, fsync semantics), bounded by a byte budget with
pruning tied to registry states (never prune a sha referenced by a `:live` or
`:deploying` entry; `:quarantined` bytes are kept as evidence).

This is a deliberate divergence from lane B, where bytes die at promote (§3.4). It
buys three things lane B cannot have: **reboot survival** (a `:live` wasm capability
restarts from store + registry at boot), **re-forge** (v2 can diff against v1's actual
bytes), and **rollback material that never expires** (rollback = stop instances; the
old bytes are still in the store if the operator wants them back).

### 7.5 Signing

New artifact struct `Ouroboros.Wasm.Artifact`:

```
id, epoch, name, component_sha256, world, imports, size, created_at,
metadata (author, source_sha256?, language?, test_report?, eval?), signature
```

Signing payload mirrors the BEAM lane's deterministic form (`artifact.ex:75-77`):
`:erlang.term_to_binary({:ouroboros_wasm_v1, signer, manifest}, [:deterministic])`.
The `Signer` behaviour is reused unchanged — `sign_artifact/2` already takes
`struct()`. `Signing.Policy.Default` gains a wasm arm (dispatch on struct), checking:

1. shape (non-empty id, positive epoch, 64-hex sha, size bound —
   `:signing_max_artifact_bytes` applies);
2. world ∈ supported set — the namespace rule's analogue, hard, no config;
3. sha256 recomputed from the submitted bytes (the service already re-derives payloads
   server-side, `service.ex:403-418` — same posture);
4. declared imports ⊆ the world's imports — a *policy* check; the security boundary is
   the linker (D5), so a signer that cannot parse component binaries is still safe;
5. provenance: author present; `eval` spec validated when present, **required** by
   default for lane W (D12) — there is no BuildPeer/ExUnit analogue here, so the
   signed eval spec *is* the test story; `:signing_require_eval` semantics extend
   rather than fork.

Loading-node verification mirrors the BEAM verifier's split: signature verified
against `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` (same key format, `verifier.ex:355-382`
posture), sha recomputed from bytes before staging, and the helper's `inspect` result
cross-checked against the signed manifest at `load` — a mismatch quarantines, it
never "just links less."

### 7.6 Deploy, rollback, registry

`Ouroboros.Wasm.Rollout.deploy(artifact, bytes, nodes, opts)`, keeping every
discipline of `Rollout` (§4.1) with the code-loading machinery deleted:

1. validate nodes (connected, `:core`) and verify signature + sha;
2. **checkpoint `:deploying` before any effect** into the existing
   `Rollout.Registry` — `entry.module` is already `module() | String.t()`
   (`registry.ex:86-88`); lane W writes `"wasm/" <> name`, and checkpoint v3 widens the
   entry with `component_sha256` (same struct-widening idiom as v1→v2's
   `eval_report`);
3. per node: `Wasm.Store.stage` over `:erpc` (content-addressed, idempotent — a node
   that already holds the sha does nothing);
4. probe: the generalized `Rollout.Probe` starts
   `{Ouroboros.Wasm.Capability, %{component: sha, config: cfg}}` on each target,
   same signal, same echo check, same budget;
5. eval: `Rollout.Evaluation` runs the signed spec unchanged;
6. settle exactly as lane B does: pass → `:live`; fail → stop instances +
   `:rolled_back`; any ambiguity → `:quarantined`. `Upgrade.Epoch` is reused for
   ordering, and a stale-epoch deploy is refused at step 2.

Rollback is honest and total: no code was loaded, so "rollback to absence" is *stop
the wrapper agents and mark the entry* — no purge, no old-code residency, nothing that
can answer `{:introduced_code_in_use, …}`. Boot restart: at `:core` boot, a
supervised one-shot task (the `Worktree` reconcile pattern,
`application.ex:86-100`) restarts wrapper agents for `:live` lane-W entries whose
manifest declares a `start` block — the `Runtime.Capabilities.maybe_start/2` rule
applied to a lane that can actually honor it across reboots.

Champion/challenger (`compare: true`) works unchanged — it compares probe outcomes
and latencies, which are lane-agnostic.

### 7.7 Forging and the effect surface (later slices)

Slice 0–3 deploy *operator-supplied* components (the `Runtime.Capabilities` admit
posture: gateway `:operate` is the authority). The agent-reachable path —
`ForgeWasmCapability` (source in Rust/TS → build → sign) and `DeployWasmCapability` —
reuses the `Control.Grants` `:forge`/`:deploy` constraint kinds and the
server-owned-principal discipline verbatim (`runner.ex:126`), and is deferred until
the deploy lane is proven. Building components on `:builder` nodes is a toolchain
question (`cargo component` / `rustup target add wasm32-wasip2` on the builder host),
not a code question; the build subprocess can itself run under `Native.Sandbox`,
which the BEAM lane's `:peer` builds cannot.

## 8. Lane H: hooks and policy as components

### 8.1 Wasm hooks

A `[[hooks]]` entry may declare `component = "<path>"` instead of `command`. The
component world:

```wit
package ouroboros:hook@0.1.0;
world hook {
  /// The exact stdin payload invoke/3 sends today, JSON. Returns the exact
  /// stdout contract parse_output/1 reads today (permissionDecision /
  /// decision / updatedInput / additionalContext), or "" for silence.
  export handle: func(payload: string) -> string;
  import log: func(level: string, message: string);
}
```

The swap happens at exactly one function — `invoke/3` (`hooks.ex:483-516`): a
component hook routes to `Wasm.Pool.call` instead of `Exec.run_shell`, under an epoch
deadline in place of TERM/KILL and the same output-byte cap. Everything above the seam
— the fold, deny-is-final, ask-outranks-auto-approve, silence-is-not-consent,
updatedInput re-evaluation, all ten dispatch sites — is untouched.

**The payoff is the trust gate.** `Hooks.trusted?/2` stays the single chokepoint for
*shell* hooks and workspace MCP servers. Component hooks with the log-only world are
admitted from **untrusted** workspaces (D8): their maximum authority is a log line and
a verdict, and the verdict vocabulary was already designed for an adversarial author
(a hook can deny what a rule allowed, never allow what a rule denied — true by
construction, `loop.ex:1256-1258`). A cloned repo's hooks finally run. The declined
counter and the once-per-turn status event stay for its shell hooks.

Two repairs ride along: hooks gain a node-config scope (W-F3 — an operator must be
able to install a node-wide hook; today only user and workspace scopes exist), and
`[checks]` may name components under the same rule.

### 8.2 Wasm policy (the C6 slot)

`Ouroboros.Wasm.PolicyEngine`: an engine for `config :ouroboros,
:permissions_engine` (`native/permissions.ex:67-69`) that delegates to the real
`Control.Permissions` first and, only on `{:ask, :no_rule}`, consults a signed policy
component (`world ouroboros:policy` — `evaluate: func(request: string) ->
string`, log-only imports) whose verdict may be `allow`/`deny`/`ask` with a stated
rule string. Deterministic, auditable (the component sha goes in the ledger entry's
`rule_ref`; the reserved `actor: :classifier` slot at `permissions.ex:92` finally has
an occupant), and signable with the §7.5 machinery. It can *narrow* as well as
resolve: a deny verdict stands. Scope honesty: this covers the native loop only; the
ACP lane reaches `Control.Permissions` directly through `Seam` and is out of scope
until the seam grows.

A model-backed classifier (the original C6 sketch) remains possible *behind* the same
engine interface; the wasm module is the deterministic, offline-testable version and
should land first.

## 9. Deferred lanes

### 9.1 Tools (lane T)

The MCP lane is the template: one cond arm in `resolve_module`
(`tools.ex:262-269`) returning `{WasmTool, name}`, a specs lane behind a gate, opaque
dispatch. The genuinely new possibility is classification: an opaque *program* is
honestly `:execute` (`tools.ex:441-447`), but a component whose world declares
read-only filesystem access within a handed scope could honestly classify `:read` —
the first tool lane where the declared mode is enforced rather than trusted. Deferred:
the native tools are fine in-process, and the interesting target ("MCP servers
without ambient authority") deserves its own slice after lane W's host exists.

### 9.2 Agents (lane A) — and the eval-replay correction

A `world ouroboros:agent` (`step(state, event) -> effects` with host-bound
`model.complete`/`tool.invoke` imports) is an extensibility feature: third-party agent
brains in any language, structurally contained, signed and placed with machinery that
exists. It is **not** a migration target for the native loop. The 2026-08-30 rewrite
assessment applies with equal force here: the loop's value is its integration surface
(permissions, hooks, checkpoints, subagents, compaction, computer use), all of which
are host-side services either way; and record/replay at the effect seams — shipped in
REPLAY.md — already delivers replay, divergence detection, and forking without giving
up the BEAM.

One claim from the design conversations must be recorded at its true size: replaying
a recorded journal through a *changed* agent yields **divergence-point diffing**, not
offline champion/challenger evaluation. The moment v2 emits an effect v1 did not, the
recorded log has no answer for it — the same truth the R2 verify engine already
encodes as a named refusal. Real challenger evaluation needs live traffic or a model
answering novel calls. Useful, cheaper than a full run, and much smaller than
"champion/challenger on real history for free."

## 10. The microVM tier (separate axis: the hands, not the brain)

Wasm contains forged logic and policy; it does nothing for `bash`, git, or LSP
servers. The next tier there is a microVM backend behind the **existing** sandbox
machinery — it is a backend, not a lane (D9).

- **Slots** (all verified): a probe clause ahead of `probe_linux`'s helper check
  (`sandbox.ex:599-604`), a `wrap/4` clause (`sandbox.ex:394-407`), a `label/1`
  value, doctor-gated with results in `:persistent_term` like `Helper.probe/1`.
- **The denial contract is non-negotiable**: guest denials must surface as
  EROFS/EPERM/ENETUNREACH — the three strings `denial_line?/1` recognizes
  (`sandbox.ex:751-755`) — and inner layers must stay congruent with the mount layer
  (`helper.ex:66-71`), or violations become invisible to the escalation loop. A
  read-only virtio disk naturally produces EROFS; an unplumbed guest NIC produces
  ENETUNREACH. This constraint is easy to meet and easy to forget.
- **Placement**: `kvm`/`hvf` is a probed-and-cached per-node fact following the
  FLEET.md §6 tags design (`local_fleet_posture/0` merge, rolling-safe; the strict
  probe pattern in `fleet_posture/1` must not *require* the new key or old peers fail
  the probe — `cluster.ex:1429-1431`). Verified today: the VPS qualifies
  (`/dev/kvm` present, nested KVM); the Macs never will (libkrun / Apple
  Containerization are the eventual macOS backends — design the backend as "isolated
  execution", not "Firecracker").
- **Hypervisor choice**: Firecracker supports virtio-block and vsock only — the
  worktree cannot be mounted in, so the workspace is a block image or a
  clone-in/diff-out sync. Cloud Hypervisor (same API family) adds virtiofs and makes
  the worktree a mount. Evaluate both in the slice; the backend interface must not
  encode the choice.
- **Egress**: the guest gets no NIC — only vsock — and a host-side HTTP proxy
  consults `Permissions.evaluate/1` with `mode: :network, domains: [host]`, reusing
  `WebFetch(domain:)` rules verbatim (`matcher.ex:98-100`). This is the first backend
  that can close the recorded "no domain allowlist and no proxy" gap
  (`sandbox.ex:96-98`) — and it also closes the LD_PRELOAD residual (`fs_filter.c`'s
  deny-create-of-absent-`.git`, which Landlock structurally cannot express): a
  private disk image has no host inodes to protect.
- **Lifetime**: VM-per-session tied to the worktree lease — provisioned in the same
  idempotent admission slot as `Worktree.provision/3` (`worktree.ex:141-142`),
  exclusive by the existing lease rule (`task_state.ex:477-478`), retired with the
  session. Remote microVM sessions ride the subagent seam unchanged
  (`subagent.ex:174-179`).
- **Rank**: below lanes W and H. The hands already have three containment layers and
  an approval loop; forged code has none. Close the uncontained hole first.

## 11. Decisions

- **D1 — two lanes, routed by need.** Lane W is the default for new forged
  capabilities (pure signal handlers); lane B remains for OTP-shaped capabilities and
  keeps its full ceremony. Neither replaces the other.
- **D2 — no BEAM module in lane W.** Identity is the component sha256; the runtime
  shape is one static protected wrapper agent. No forged atoms, no `ModuleName`, no
  per-triple artifacts, no code loading, and rollback is stop-and-mark. (Rejected
  alternative: generating a shim BEAM module per capability — it re-imports the
  triple problem and the code-loading machinery for zero containment gain.)
- **D3 — helper-on-a-pipe, not the wasmex NIF.** A wasmtime crash kills a Port, not
  the node; the house has three helpers and a written pattern; and a runtime whose
  own forge bans `load_nif` at three layers (`source.ex:60`, `beam.ex:147`,
  `policy.ex:352-353`) should not host untrusted bytes in its own address space.
  wasmex 0.15.1 (components on wasmtime 39) is real and is the recorded fallback if
  per-call round-trips ever measure as the bottleneck — at JSON-step granularity they
  will not.
- **D4 — sync, step-shaped world in v1.** WASIp3 async now exists, so this is a
  choice, not a constraint: sync steps keep determinism trivial, keep the helper's
  dispatch simple, and match how the wrapper agent consumes it. Async is a v2 world
  version, adopted only with a concrete need.
- **D5 — the linker is the boundary; the signer is policy.** The host defines exactly
  the world's imports; an undeclared import fails instantiation. The signed manifest's
  import list is provenance and review surface, not the enforcement mechanism — so a
  signer that cannot fully parse component binaries is still not a hole.
- **D6 — component bytes are durable.** Content-addressed store, `PackageStager`
  discipline. Deliberate divergence from lane B's bytes-die-at-promote: lane W
  capabilities survive reboot, can be re-forged against real bytes, and never lose
  rollback material.
- **D7 — reuse, don't fork, the rollout machinery.** `Rollout.Registry` (checkpoint
  v3, `module` already binary-tolerant), `Upgrade.Epoch`, `Rollout.Probe` and
  `Rollout.Evaluation` (generalized over a start spec) are shared. Only
  `Coordinator`/`NodeExecutor` — the code-loading half — is not used by lane W.
- **D8 — containment replaces trust for workspace components.** A log-only-world
  component hook runs from an untrusted clone; shell hooks keep the
  `trusted_workspaces` gate. The gate function stays the single chokepoint for both.
- **D9 — microVM is a sandbox backend, not part of the wasm design.** It must speak
  the three-string denial vocabulary and stay congruent across layers, or it is
  invisible to the escalation loop.
- **D10 — `Ouroboros.Wasm.` is a protected namespace** (verifier
  `@protected_prefixes`) and joins the mesh agent allow-list. The container must not
  be hot-patchable by its contents.
- **D11 — capability messages are not individually ledgered in v1.** They are mesh
  traffic, like every agent's. The audit story is the signed manifest, the registry,
  and the effect ledger on forge/deploy. A per-instance journal is a later, separate
  decision.
- **D12 — eval is the test story for lane W.** The signer requires a validated eval
  spec for wasm artifacts by default (there is no BuildPeer/ExUnit analogue);
  `test_report` is optional provenance when a guest toolchain produces one.

## 12. What this does not solve

Stated once, so nobody reads more into the lane than is there:

- **Judgment.** The permission engine still decides; a prompt-injected model still
  emits hostile effect *requests*. Wasm bounds what granted authority can reach, it
  does not improve the grant decision.
- **The host functions are the new surface.** Every import added to a world is
  boundary code. v1's answer is austerity: `log` only. Growth of any world's import
  set is a signing-policy event, not a convenience.
- **wasmtime is a dependency, not a proof.** It has had escape CVEs; they are rare
  and patched fast, and the helper process (which can itself be OS-sandboxed later)
  is the second wall. Pin it, watch its advisories.
- **The workspace.** §10 is the axis for `bash`/git/LSP; nothing in lanes W/H/T
  touches it.
- **Signer custody and node-local authority.** A signer is still a cluster member
  reachable by `:erpc`; `Control.Grants` is still one process per node. Unchanged by
  this spec, still on ARCHITECTURE.md's external list.

## 13. Defects and doc drift found during this spec's verification

- **W-F1 (real, model-facing, chip filed):** `provider/native/prompt.ex:218-219`
  tells the model an approved escalation re-runs "outside the sandbox"; the
  implementation re-runs it fenced (`:workspace_write_escalated`, only `.git`
  lifted — `sandbox.ex:39-43`, `loop.ex:1818-1822`). Fix independent of this spec.
- **W-F2 (doc lie, F6 family):** `forge/build_peer.ex:36-37` claims the artifact's
  runtime triple "is whatever the *peer* observed"; it is stamped from the forging
  node (`artifact.ex:54-56`), and `peer_runtime` is recorded but compared nowhere.
  FLEET.md F6 remains unimplemented in code.
- **W-F3 (asymmetry):** hooks have no node-config scope while MCP and permissions
  both do (`hooks.ex:104-105` vs `mcp/servers.ex:214-220`,
  `permissions.ex:328-333`). An operator cannot install a hook a workspace cannot
  also install. Repaired in slice 4.
- **W-F4 (cross-lane, operational; fixed in W6):** the helper's component cache had a
  ceiling and no eviction, while W4's hook lane loads a repository-shipped component on
  every invocation and every edit of one is a new sha — so a long-lived helper filled with
  stale hook components and, once full, every later `load` on that node (the next hook,
  the capability lane's next rollout stage) failed `too_many_components` until a respawn,
  which only a broken transition causes. W4's interim answer was the pool's per-lifetime
  budget of 16 hook shas; W6 makes the helper evict (§7.3) and keeps the budget as a
  bound on churn.

## 14. Slices

Each slice is PR-sized, lands green, and is useful alone.

- **W0 — `ouro-wasm` helper.** New `tui/wasm/` member: `serve`/`doctor`, codec copied
  in shape from `computer-use` (line framing, read-bounded 8 MiB cap, noise budget),
  `inspect`/`load`/`instantiate`/`call`/`drop`, deny-by-default linker, fuel + epoch
  deadline + memory caps, private error codes. Rust tests: refuse undeclared import,
  fuel exhaustion, deadline trap, sha mismatch, oversize frame;
  `env!("CARGO_BIN_EXE_ouro-wasm")`. `make wasm`; `/priv/wasm/` gitignored;
  `release-tarball` prerequisite.
- **W1 — pool + store.** `Ouroboros.Wasm.{Pool,Supervisor,Store}`: `Desktop.Pool`
  discipline (lazy, secret-env stripping, broken cooldown, kill-by-os-pid),
  supervision-tail insertion, content-addressed store with budget + registry-aware
  pruning. Pool tests with fake shell-script helpers.
- **W2 — the wrapper agent, probed live.** `Ouroboros.Wasm.Capability` +
  `Probe`/`Evaluation` start-spec generalization + mesh/verifier namespace lines. A
  hand-written Rust guest (`wasm32-wasip2`) checked in under `test/support/`. Live
  acceptance on this Mac: instantiate, probe echo, eval spec pass.
- **W3 — signing + rollout.** `Wasm.Artifact`, policy arm, journal entries,
  `Wasm.Rollout` (checkpoint-before-effect, registry v3 widening, epoch), boot
  restart of `:live` entries. Two-node `:peer` test proving **one artifact deploys on
  both nodes**; live heterogeneous proof on the VPS when convenient.
- **W4 — hooks lane.** `component =` hooks through the `invoke/3` seam, epoch
  deadlines, untrusted-workspace admission for log-only worlds, node-config scope for
  hooks (W-F3), `[checks]` parity. E2E: a cloned untrusted repo's component hook
  denies a write; its shell hook stays declined.
- **W5 — surface.** Gateway verbs (`wasm.list`/`wasm.status`, `:read`;
  protocol-docs + golden fixtures + Rust decode tests per the integrator rule),
  `ouro wasm doctor`, fleet posture fact.
- **W6 — cache eviction (W-F4).** The helper's component table evicts at its ceiling:
  least recently used, never a component with a live instance, named in the `load`
  result and counted (with the last sixteen) by `doctor`; `too_many_components` only when
  every held component is pinned. No seventh method — reclaim is the helper's decision,
  made with the two facts only it has (recency, and which shas have instances), and every
  peer already loads before it instantiates, so an evicted sha heals itself on next use.
  Rust proofs: a pinned component survives a full table; a capability loads after 64 hook
  loads; a cache hit is recent use; the eviction log is bounded. The pool logs evictions
  at debug; W4's hook budget stays as a churn bound.
- **Deferred, in rough order:** policy engine (§8.2) → agent-reachable forge/deploy
  effects (§7.7) → tools lane (§9.1) → microVM backend (§10, likely its own spec
  once slice-shaped) → agent world (§9.2).

## 15. Prior art and references

- Golem Cloud — durable wasm workers via oplog replay; closest to lane W + REPLAY.md
  combined. wasmCloud — components + capability providers over a lattice (now on
  WASIp3 async); the BEAM already plays the lattice's role here. Extism — the
  plugin-host pattern lane H resembles. Temporal — the replay model, without a
  sandbox. None of them have a supervision tree, a signing forge, or a rollout with
  probes and quarantine; that composition is this codebase's.
- wasmtime: https://github.com/bytecodealliance/wasmtime (releases; fuel/epoch/pooling
  docs). WASI 0.3: https://wasi.dev/roadmap. Component model / WIT:
  https://component-model.bytecodealliance.org. wasmex (fallback path):
  https://hexdocs.pm/wasmex — `Wasmex.Components`, 0.15.1.
- In-repo: ARCHITECTURE.md (milestone 3, "Still external"), FLEET.md (§6 tags, F6),
  REPLAY.md (the record/replay kernel lane A defers to), COMPUTER_USE.md §12/§18 (the
  helper doctrine this spec's host copies), AGENT_EXPERIENCE.md (C5/C6 rows).
