# WASM: containment lanes for forged capabilities, hooks, and policy

Status: **W0–W7 are built**, on branch `wasm`. The spec was written 2026-09-01
against main `c677fe0` and has been kept current with the code since; W7 (2026-09-02)
is the review wave that fixed what W0–W6 shipped wrong. §14 records what each slice
built and what it proved, §13 what the reviews found. Every file:line claim below was
verified against the tree at the time it was written; if you are reading this much
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
content-addressed), and **extensible** (third-party capabilities, hooks, and policy,
safe to install by construction).

"Extensible" has a measured boundary, and it is narrower than "any language". What lane W
admits today is **any language whose toolchain emits a `wasm32-wasip2` component without
an embedded language runtime** — Rust, C/C++, TinyGo and Zig are the known-good set, and
the reference guest is Rust. A JavaScript or Python guest ships its own engine inside the
component, and each of the two that were actually built was refused by a different wall
(§7.3):

- `componentize-js` (StarlingMonkey, three trivial exports, http/random/clocks/stdio
  disabled) produced a 12.5 MB component — 9 224 567 code bytes, 2.2× `MAX_CODE_BYTES`,
  12 660 functions. With every shape bound lifted it compiled in 8.61 s and *still* failed
  `load`: beside `log` it imports `wasi:io/poll@0.2.10`, `wasi:io/streams@0.2.10` and
  `wasi:http/types@0.2.10`, so the world refuses it `undefined_import`. That is the linker
  wall, and it is the one D5 says must hold.
- `componentize-py` (CPython) produced an 18.4 MB component — 11 150 155 segment bytes,
  2.66× `MAX_SEGMENT_BYTES`, 6 569 337 code bytes, 2 088 exports, 2 248 imports. With
  every count bound lifted it failed `compile_failed`: it needs the **extended-const**
  proposal, which §7.3 disables on purpose.

Four independent walls, then — the shape bounds, the single-`log` world, the disabled
proposal set, and compile time on a sequential helper — and no two of them are the same
lever. **Engine-embedding guests are a deferred slice, not a configuration change**
(§14, W8): raising the numbers alone would admit neither of the two above.

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
  policy stage**. Note: at the time of this survey the ACP lane called
  `Control.Permissions` directly through `Seam` and was not covered by that seam; W18
  put it behind the same setting (D27).
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

**Authoring a component.** The world above is what a guest binds against, and `tui/wasm/guest`
(`ouroboros-guest`) is the crate that binds it so an author does not. It owns the `no_std`
ceremony — the allocator, the panic handler, the canonical ABI's `cabi_realloc`, the
`wit_bindgen::generate!` and the instance's state cell — behind one macro call, and offers
four seams over this world: `Capability` (a JSON body in, a JSON reply out) for the mesh,
`Hook` (a typed payload, a `Verdict`) and `Check` for §8.1's two contracts, and `Raw`
underneath them for a reply that must be stated verbatim — plus, since W15, `Policy` over the
*second* world (§8.2). `#![no_std]` stays the author's own
line, because it is the claim and not the ceremony: `std` on `wasm32-wasip2` imports thirteen
`wasi:io`/`wasi:cli` interfaces the helper's linker refuses, and such a build does not
instantiate at all. Five worked components live in `tui/wasm/guest/examples/` — one per seam,
plus a fixture that says every verdict there is — a scaffold in `tui/wasm/guest/template/`, and
the acceptance guest is built on the same crate, which is what keeps the SDK honest (D13). None
of it changes what the helper enforces; containment is the linker (D5).

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
- The mesh allow-list grows one **named module**, not a prefix:
  `"Elixir.Ouroboros.Wasm.Capability"` beside the two namespace prefixes in `mesh.ex`.
  Admitting the whole `Ouroboros.Wasm.` prefix was safe only by accident — no other
  module in that namespace exports `new/0` or `new/1` — and a host module added there
  tomorrow would have become startable from any connected node. Forged code still
  structurally cannot enter the namespace (verifier introduce-prefix requires
  `Ouroboros.Capability.*`; signer policy refuses anything else), but the allow-list no
  longer depends on that.
- `Ouroboros.Wasm.` joins the verifier's `@protected_prefixes` (`verifier.ex:53-67`):
  the wasm host machinery must not be hot-patchable by the thing it contains — the
  same sentence that puts the permission engine under `Control.` (D10).
- `Probe.ready?/1` and `Evaluation.run/3` take a module today
  (`Mesh.start_agent(id, agent: module, …)`). Both are generalized over a *start
  spec* — `module | {module, initial_state}` — a small additive change; lane B passes
  the bare module and nothing observable changes for it (D7).
- The wrapper's `initial_state` is validated where it is used, because
  `Mesh.start_agent/2` is remote-reachable and Jido does not check it against the agent
  schema: `:pool` must resolve to a live local process started as `Ouroboros.Wasm.Pool`,
  `:store_root` is honoured only under `config :ouroboros, :wasm,
  allow_store_root_override: true` (test env only), and `:limits` is clamped
  element-wise to `:capability_limits_max` with the clamp recorded in the agent's
  `:error`.

### 7.3 The host: `ouro-wasm`

A new isolated workspace member `tui/wasm/`, bin `ouro-wasm`, **server-shaped** —
copied structurally from `ouro-computer-use` (§4.2): `serve`/`doctor` subcommands,
line-framed JSON-RPC with the 8 MiB read-bounded cap and noise budget, hand-rolled
argv, private error codes. The one heavy dependency is `wasmtime` — pinned at 48, its
current LTS, whose MSRV is the 1.95 Rust floor this member carries where the rest of the
workspace is on 1.88 — and keeping it out of `ouro`'s build graph is the strongest case
the isolated-member discipline has yet had. `wasmparser` is pinned to the minor wasmtime
itself resolves, because §7.3's pre-compile pass has to read what the compiler will.

Methods:

| method | params | returns |
|---|---|---|
| `doctor` | — | `{usable, wasmtime, target, worlds: [supported world ids], imports, limits, held: {components, instances, evictions, evicted}, notes}` |
| `inspect` | `{path}` | `{precompiled: false, sha256, world, imports, exports, size, shape}` — parsed from bytes; for a `.cwasm`, `{precompiled: true, wasmtime, target, world, kind, component_sha256, component_size, …}` read from its header alone / refusal (`unreadable_component`, `component_too_complex`, `compile_failed`, `precompiled_mismatch`) |
| `load` | `{sha256, path, kind?}`, or `{precompiled: true, sha256: <artifact>, component: <source sha>, path, kind?}` (W8) | `{…as inspect, precompiled, cached, evicted: [sha]}` / refusal (`sha_mismatch`, `unsupported_world`, `undefined_import`, `component_too_complex`, `too_many_components`, `precompiled_mismatch`) |
| `instantiate` | `{instance, sha256, config, kind?, limits: {fuel, memory_bytes, deadline_ms}}` | `{instance, fuel_used, log_lines}` / init error |
| `call` | `{instance, export, payload}` | `{payload, fuel_used, log_lines}` / trap / deadline |
| `drop` | `{instance}` | ok (idempotent) |

`kind` is `"capability"` (the default, and what every request written before W15 meant) or
`"policy"`, and it is which of the helper's two worlds these bytes are being offered as — the
*caller's* assertion, checked here, taken on the deploy path from the signed manifest (D21).
Absent means capability; a spelling this build does not implement is `invalid_params` and never
a silent fallback.

Enforcement lives here and is structural: the linker defines exactly the functions the
supported worlds import — `log`, and in both of them — and nothing else, so **an unlisted
import fails instantiation — authority cannot be smuggled past a lying manifest** (D5). Every call
runs under a fuel budget, an epoch deadline, and a store memory cap; exhaustion is a
typed refusal, not a hang. A wasmtime panic or segfault kills a Port, not the node —
which is the point of the helper (D3).

Since W8 the *usual* answer is that compilation does not happen here at all. `ouro-wasm
precompile` compiles a component once, on the machine that signs it, and a node's `load`
becomes `Component::deserialize` of an artifact bounded by a byte cap — a bound on work,
which is exactly what a byte cap was not while `Component::new` was on this path. The
structural pass below did not go anywhere: it is the *signer* that now applies it, in full,
before it compiles, so an artifact that exists at all is one a node would have admitted
(D23). What follows is therefore two things at once — what a signer applies before it
compiles, and what a node still applies to every component it is handed in source form,
which is every component whose manifest names no artifact and every component on a node
whose wasmtime or target triple is not the signer's.

Compilation is bounded *before* it starts, and it has to be: `Component::new` runs under
no fuel, no deadline and no memory cap, because there is no store yet, and cranelift
cannot be interrupted once it has begun. A valid in-world component of 145 000 small
functions — 61 MiB, exporting exactly what this world asks for — took **tens of seconds**
on this Mac, and the helper is sequential, so that is tens of seconds in which every hook
and every capability on the node waits: long enough for the pool's 30 s `load` deadline
to break it and drop every live instance.

So `tui/wasm/src/shape.rs` walks the component and everything nested in it with
`wasmparser` (the same parser wasmtime itself uses, already in this binary's graph),
reading section headers without decoding an instruction, and refuses
`component_too_complex` on any of: code bytes (4 MiB), functions (20 000), types
(8 192), imports and exports (1 024 each), other index-space definitions (16 384), data
and element segment bytes (4 MiB), nesting depth (8), core modules (64), nested
components (64), and sections (8 192) — every one a total over the whole tree. At the
worst admissible shape the release helper compiles in 1.19 s as `shape.rs` records it and
1.16 s on re-measurement; one function past the bound is refused in 0.14 s without
anything being compiled; and the acceptance guest declares 101 functions against 20 000
and 40 721 code bytes against 4 MiB, two orders of magnitude under the two dimensions
that measure compile cost. `doctor` reports all eleven under `limits`, and the source
pins them by value so moving one is a deliberate act with a fresh measurement behind it.
Custom-section *bytes* are not weighed, only counted — wasmtime skips them, so sixty
mebibytes of custom section costs the read and the digest, not the compile.

For a **precompiled** load none of that runs, and the reason is that there is nothing left
to bound: nothing is compiled, the work is linear in the input, and the input's length is
checked before a byte of it is read. The cap is 128 MiB of serialized artifact (twice the
component read cap), which is an order of magnitude above anything a signer applying the
table above can produce — measured on this build, the worst admissible shape (20 000
functions, 4 035 787 source bytes) serializes to 11 092 495 bytes, 2.75×, and the 48 KiB
reference guest to 258 093, 5.3×, fixed overhead dominating the small one. `doctor` reports
it as `max_precompiled_bytes` beside the eleven structural ceilings.

The methods gained one parameter each and one subcommand. `load` takes `precompiled: true`
with the artifact's digest as `sha256` and the **source** component's as `component`; the
cache stays keyed on the source sha, because lane W's identity is the component's bytes (D2)
and nothing above the pool has to know which form ran. `inspect` on one of these artifacts
answers out of its container header alone — the wasmtime, the triple, the world, and the
component it was compiled from — and maps nothing. `precompile <in.wasm> <out.cwasm>
[--kind]` is the signer's side. `doctor` reports `target` beside `wasmtime`, because those
are the two strings a node compares.

Two honesties about those figures, both from re-measurement. The largest rows of
`shape.rs`'s table do not reproduce — 4.36 s and 28.9 s came back as 2.73 s and 16.29 s —
so read them as the order of magnitude they establish rather than as figures; the
at-bound row does reproduce. And the at-bound figure is measured on **synthetic
straight-line code**, the cheapest thing per byte a component can hold. Real compiler
output is about three times denser in compile cost, so a real guest sitting exactly at
the 4 MiB bound would cost nearer four seconds than one (§12).

The engine speaks the smallest dialect the world needs. wasmtime 48 enables every
proposal it considers stable, which is right for a host running its own code and wrong
for one running nobody's: relaxed SIMD (nondeterministic by design, and so against D4),
tail calls, function references, extended const, multi-memory, memory64, GC and the
optional component-model extensions are all turned off by name, and `max_wasm_stack`,
the cranelift optimisation level, and the per-memory address-space reservation and guard
are set explicitly rather than inherited — the last of which takes the virtual
reservation per memory from 4 GiB + 32 MiB to 64 MiB + 32 MiB, which across the helper's
ceiling of a thousand memories is the difference between four terabytes of address space
and ninety-six gigabytes. Left on, because the reference `wasm32-wasip2` toolchain emits
them and they are deterministic: the component model, SIMD, bulk memory, reference
types, multi-value, sign extension, saturating float conversion, mutable globals. Rust
proofs put a component using each disabled proposal in front of the helper and watch it
be refused.

A JSON-RPC notification — an object with no `id`, which by the protocol gets no reply —
is refused for every method but `doctor`. Running `load`, `instantiate`, `call` or `drop`
with nobody owed an answer is work whose refusals go nowhere and whose failures the peer
cannot see; the refusal goes to the helper's stderr instead. `doctor` is the carve-out
because it reads two table lengths and does nothing.

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
`too_many_instances` means "drop one". The pool's per-lifetime budget (W4, 16 shas)
stays, now scoped to the **untrusted** hook lane alone and counted only when the helper
accepts the load: one counter shared with the operator's own trusted hooks meant a clone
could spend it and make a trusted `deny` fail open, and counting refusals meant sixteen
rejected loads spent a budget on a cache they never touched.

Elixir side, copied from the `Desktop.Pool` half: `Ouroboros.Wasm.Pool` (one helper
per node, lazy, `Port.open` spawn under a **deny-by-default environment allow-list** —
`PATH`, `HOME`, `TMPDIR` and nothing else, with a value check on top, because a
name-shaped deny-list missed `RELEASE_COOKIE`, `AWS_ACCESS_KEY_ID`, `SSH_AUTH_SOCK` and
`DATABASE_URL` — doctor handshake, broken-state cooldown, kill-by-os-pid),
`Ouroboros.Wasm.Supervisor` inserted in the `:core` tail beside
`Desktop.Supervisor`/`Mcp.Supervisor`, binary resolution env-override → configured path
→ `:code.priv_dir/1` → sibling of `ouro` and **nothing derived from the working
directory** (a parent walk let a cloned repository supply the containment boundary
itself; the same walk was removed from the desktop and sandbox helper resolvers),
`make wasm`, `/priv/wasm/` gitignored, `release-tarball: computer-use sandbox wasm`.
Every per-instance limit is range-checked against the helper's own maxima before a frame
is built, and against the connected helper's `doctor.limits` when they are narrower;
every interval the pool hands a timer is clamped to a module constant, because
`limits.deadline_ms` is caller-chosen and reachable over the mesh.

### 7.3a The helper under the OS sandbox

The helper is a separate process, which is what keeps a wasmtime crash off the node (D3).
Since W8 it is also a process that **maps machine code a signer produced** — `deserialize` is
`unsafe` because wasmtime does not validate a serialized artifact against a malicious producer
(D24) — so the separation is worth a wall of its own. Since W16 there is one:
`Ouroboros.Wasm.Pool` spawns the helper through `Ouroboros.Provider.Native.Sandbox.wrap/4`
under `Sandbox.helper_policy/1`, the same closed-on-reads `:builder` policy a forge builds
under, with different lists.

**What it may read.** The platform's own toolchain roots (`Sandbox.platform_readable/0` — the
dynamic loader and the C library, without which the process does not start), the directory its
own binary lives in (bubblewrap has to bind the executable into the namespace before it can
`execve` it; Seatbelt does not need it, and the sentence that once claimed otherwise was
false), this node's **component store** (`Wasm.Store.root/1`), the forge's **build directory**
— `inspect` on a freshly built product is the one path this node hands the helper that is not
a store entry (D18) — and whatever `config :ouroboros, :wasm, helper_readable:` names once
`Wasm.helper_readable/0` has vetted it.

The store and the build directory, and **not** `<data_dir>/wasm`: that subtree also holds the
upload staging area, the sign scratch, the forged bundles and the forge's cargo home, and a
cargo home's `config.toml` on a builder node can name a `rustc-wrapper` and hold a registry
credential. And not the node's **workspace roots**, which the first cut of this slice did name:
the hook lane read a `component =` hook out of the repository it was configured in and handed
the pool that path, so every repository an operator served was readable to a process holding a
signer's machine code. That is closed rather than documented — `Native.Hooks` already had the
bytes and their digest in hand, so it publishes them into the node's own content-addressed
store and the helper reads only from there. A store that will not take them is a hook that does
not run, named `component_not_staged`: a node with no data directory has no store, and a store
over budget fails closed, and both of those are better answers than a component loaded from
somewhere the fence does not cover.

`helper_readable` is the one knob that widens this, so it is vetted whole rather than trusted:
every entry must be an absolute path resolving to a directory that exists, must not be `/` nor
resolve to it, and must not be the data directory nor an ancestor of it. One offending entry
rejects the **whole list** with a warning naming it, because a fence with three roots where
four were configured is a fence nobody can reason about. `helper_readable: ["/"]` was accepted
before this existed and removed both walls in a line.

**What it may write.** A per-child scratch under `<data_dir>/wasm/scratch/`, created `0700` with
ninety-six bits of name and **verified with `lstat`** to be a real directory this process made
rather than a link somebody planted — `Wasm.Deploy`'s sign-scratch discipline verbatim, and
never a shared `/tmp`, where any account on the machine can create a directory first. `$TMPDIR`,
`$TMP` and `$TEMP` point at it, it is removed when the child is, and abandoned ones are swept on
the way in. A sweep takes a directory only when it is six hours old **and** the BEAM named in
the marker beside it is gone: two nodes sharing one data directory is ordinary, a helper that
writes no temp files leaves its scratch's mtime at creation, and age alone had a sibling
deleting a live child's only writable directory. The marker sits beside the scratch rather than
inside it, so the child cannot rewrite it. Nothing else is writable, anywhere.

**What it may do (W21).** Exec itself, and nothing else. On Seatbelt the profile's one
`process-exec` is a literal naming the executable the child was spawned as — by its
**resolved** path, as a `-D` parameter, because Seatbelt matches the literal against the path
the kernel resolves and never against the spelling `execvp` was given, and resolving a
spelling that runs through a symlinked `priv/` needs metadata rights on the link that a sealed
profile does not grant; so `SandboxExec.wrap/4` resolves argv[0] and spawns by that path. A
compromised helper therefore cannot run a `/usr/bin` binary even though `/usr/bin` is a
readable platform root. There is no `process-fork`, so it cannot become two processes; there is
no `mach-lookup`, so launchd and the pasteboard are out of reach; `sysctl-read` is allowed
under the `hw.` prefix only — `hw.pagesize_compat` is what the Rust runtime reads to map a
thread's guard page and aborts without, and `hw.optional.*` is what cranelift reads to detect
the CPU: a helper allowed `hw.pagesize_compat` alone runs, and `precompile`s a **different
artifact** from the same component than the unsealed helper does, which would be a sealed
signer and its loader disagreeing about the machine, so the prefix is the narrowest set that
was measured to keep them agreeing — and `file-read-metadata` is granted on `/` itself and
nowhere the `file-read*` grants do not already reach — plus one literal per **symlink on the
way to a root** (`/var` for a root spelled `/var/folders/…`, `SandboxExec.links/1`), because
the kernel reads a link to follow it and that read is a metadata read on the link; a root
reached through `/var` was unreadable without it and `/var/root` stays absent beside it — so
a `stat` outside the roots answers "absent" and is no longer an existence oracle over the
filesystem. `signal (target self)` stays. The helper is one stdio Rust binary running wasmtime — it never forks, never execs and
never looks up a service — so each of those was a right it did not use and a compromised one
could. The two Linux backends run the helper with the process posture **open**, because
neither can express the seal (D25 names what each leaves), and `wasm.status`'s
`sandbox.process` says which posture the child actually got: `sealed`, `open`, or `off`. The
one way to an open posture on Seatbelt is a pool started with `scripted_helper: true`, which
exists for this repository's own `#!/bin/sh` fake helpers — a script needs its interpreter
exec'd and its `awk` forked — and has no configuration key behind it, on purpose. A sealed
policy also refuses to wrap a `{:shell, _}` command at all, by name.

**And no network at all, loopback included.** Every other policy this runtime makes keeps a
`localhost` exception on macOS, because `mix` and `cargo` coordinate concurrent compilers over
loopback sockets and a build without it fails `:eperm` having reached no other machine. The
helper speaks stdio, so `Sandbox.helper_policy/1` sets `loopback: false` and the Seatbelt
profile is `(deny network*)` with nothing after it. It matters because the exception was not
theoretical: under the first cut a probe connected to a loopback listener, and loopback is every
service on this machine — this node's own gateway among them. The two Linux backends unshare the
network namespace, so there is no host loopback in the child to take away; a `bwrap` that
*cannot* unshare one (`unshare_net: false`, a host without `CLONE_NEWNET`) is a refusal to
spawn rather than a child on the host's network, which is the second question
`Sandbox.fences_network?/1` exists to ask.

**The fence is stated twice.** Every `load` in this repository names a file in this node's own
store, and the one `inspect` names a product the forge just built in this node's own build
directory. The sandbox is only one of the two things that say so. The other is the pool: a
`load` **or an `inspect`** whose path is not under the policy's readable roots is
`{:refused, :path_outside_roots}` **before a frame is built**, so the kernel denies what the
pool has already refused. The pool's half resolves symlinks in a path's directory and not in its
leaf, and a path it cannot resolve is measured as written and therefore refused; the kernel's
half resolves both. That asymmetry is why there are two walls and not one.

**And it does not degrade quietly.** `config :ouroboros, :wasm, helper_sandbox:` is
`:required` by default. Under it a node with no backend, a backend that cannot fence reads
(`Sandbox.fences_reads?/1`, contract C11 — `ouro-sandbox` before W17), a backend that cannot
fence the network (`Sandbox.fences_network?/1`), or no data directory to put a scratch in
**refuses to spawn**: the pool goes broken with `{:helper_sandbox_unavailable, reason}`, every
request answers at once, and `wasm.status` reports
`sandbox: %{posture: :refused, backend: …, reason: …, readable: […]}` beside a helper phase of
`broken`. `:off` spawns the helper plain, says `posture: :off`, and logs one line per spawn.
D25 is why the default is that way round. The `readable` field is the **effective** read set —
four sources and a vetted configuration key are not readable off `config` — rendered as
basenames on the wire for the reason `helper.path` is.

The signing path is the same policy with different lists. `Wasm.Deploy.sign/2` runs
`ouro-wasm precompile` wrapped, with **this signature's own directory** writable and readable
and the shared `<data_dir>/wasm/sign/` root neither: the first cut made that root writable and
wrote every signature's source and output directly into it, and a review read a concurrent
signature's uploaded component out of it and overwrote a concurrent signature's artifact —
which is the file the next signature is issued over. Under `:required` a signer that cannot
apply the policy signs the source form and names `{:helper_sandbox_unavailable, …}` in the
receipt's `precompile_skipped`, exactly as it names every other reason it did not compile.

**What this is not.** It is a second wall around a process that maps unvalidated machine code.
It is not validation. A patched artifact still executes inside the helper with the helper's own
authority; what changed is that the helper's own authority is now the platform roots, this
node's component store, the forge's build directory, a scratch it may write and no network at
all, rather than everything the daemon's user can reach. D24's four mitigations are still four
mitigations and none of them is a fix — and D25 lists, by name, the things the macOS wall does
not close.

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

Manifests are not pruned — but not pruned is not the same as not counted. `list/1`
reports them beside the components, tagged `kind: :manifest`, and their bytes count
against the prune budget — a budget that ignored a whole class of files in the directory
it governs was a budget the store exceeded quietly. What a prune *evicts* is still
components only. A manifest is also bounded on the way **in**, at the ceiling
`fetch_manifest/2` reads under: publishing one the store would later refuse to read is
publishing a durable, unprunable file no reboot can use.

### 7.5 Signing

New artifact struct `Ouroboros.Wasm.Artifact`:

```
id, epoch, name, component_sha256, kind, world, imports, size, created_at,
precompiled?, metadata (author, source_sha256?, language?, test_report?, eval?, start?),
signature
```

Signing payload mirrors the BEAM lane's deterministic form (`artifact.ex:75-77`):
`:erlang.term_to_binary({:ouroboros_wasm_v1, signer, manifest}, [:deterministic])`.
The `Signer` behaviour is reused unchanged — `sign_artifact/2` already takes
`struct()`. `Signing.Policy.Default` gains a wasm arm (dispatch on struct), checking:

1. shape: non-empty id, positive epoch, 64-hex sha, size bound
   (`:signing_max_artifact_bytes` applies), and a **name** matching
   `Ouroboros.Wasm.Artifact.name?/1` — lower case, starting with a letter or digit, then
   letters, digits, `.`, `_`, `-`, at most 64 bytes. The name is not decoration: it is
   the rollout register's `module` field (`"wasm/" <> name`) and the cluster-wide durable
   id a `start` block claims, and both are compared as strings by things that trust them,
   so a name that can hold a path separator, whitespace, or a bidirectional control is a
   name two readers can disagree about;
2. world ∈ supported set — the namespace rule's analogue, hard, no config;
3. sha256 recomputed from the submitted bytes (the service already re-derives payloads
   server-side, `service.ex:403-418` — same posture);
4. declared imports ⊆ the world's imports, **and no import declared twice** — a *policy*
   check; the security boundary is the linker (D5), so a signer that cannot parse
   component binaries is still safe. A duplicate is refused rather than deduplicated: the
   list is what gets signed, and `Wasm.Verifier.cross_check/2` compares the manifest's
   sorted list against the helper's own sorted reading, which can never repeat an import.
   `["log", "log"]` was a manifest signed into a permanent quarantine;
5. provenance: author present; `eval` spec validated when present, **required** by
   default for lane W (D12) — there is no BuildPeer/ExUnit analogue here, so the
   signed eval spec *is* the test story; `:signing_require_eval` semantics extend
   rather than fork;
6. **precompiled block** (W8, D22). `precompiled` is absent, or exactly
   `%{wasmtime, target, sha256, size}`: a 64-hex digest that is *not* the component's own,
   a positive size within the same multiple of the artifact ceiling a bundle admits, and two
   printable bounded strings that are what a helper's `doctor` would have printed. What this
   block authorizes is a loading node calling `Component::deserialize` on machine code it did
   not produce, which is `unsafe` for a reason, so the digest that makes it sound is inside
   what the signature covers. What is deliberately *not* checked is whether the signer
   recognises the version or the triple: that is a fact about a loading node, and a node that
   does not match falls back by itself;
7. **start block.** `metadata.start`, when present, must be exactly
   `%{id: binary, config: binary}` and the id must be exactly `"wasm/" <> name` for the
   name in *this* manifest. Binding it to the `wasm/` prefix alone was not binding it at
   all: a component named `evil` could declare `wasm/greeter`, be signed, be recorded in
   the register as `wasm/evil`, and then claim cluster-wide the durable id everybody
   trusts as `greeter`; `wasm/../../etc/passwd` and a right-to-left-override id were
   signable for the same reason. `Wasm.Rollout.start_block/1` and `Wasm.Boot` *derive*
   the id from the manifest rather than reading it, so the deploy path and the reboot
   path cannot disagree about which process a component owns, and the config is bounded
   at 16 KiB.

Loading-node verification mirrors the BEAM verifier's split: signature verified
against `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` (same key format, `verifier.ex:355-382`
posture), sha recomputed from bytes before staging, and the helper's `inspect` result
cross-checked against the signed manifest at `load` — a mismatch quarantines, it
never "just links less." Since W8 each **form** is bound to its own digest:
`Wasm.Verifier.verify_precompiled/2` holds the bundle's artifact section to
`precompiled.sha256`, because a signature over one digest says nothing about bytes that
merely travelled beside it, and a section the manifest does not declare — or a declaration
with no section — is two statements about one file that disagree.

Compilation happens at signing time now, on the node that builds the manifest, with the same
`ouro-wasm` binary and the same engine configuration a node's `serve` uses (D23). It is
skippable in three ways, and every one of them leaves the source-only path lane W already
had: a node with no helper on disk, `precompile: false` (`ouro wasm sign
--no-precompile`), and an artifact too large to travel in the receipt this verb answers
with. In all three the manifest carries no block, the bundle carries no second section, and
every node compiles the component for itself.

The signer's own admission order is part of the posture. The per-requester rate limit
runs **first**, before the `term_to_binary` over an artifact whose size the requester
chose and before the policy that reads every byte of it: a refusal that skipped the
window was a refusal an attacker could generate at will, for free, forever, and each one
still cost a journal write. And a verdict that does not fit the journal's entry budget is
bounded field by field rather than as one term — a legal 6 KB `test_report` used to
collapse the whole findings map to a rendered string, taking `component_sha256`, `world`,
`imports` and `start` with it, which are exactly the fields a refusal is read for.

### 7.6 Deploy, rollback, registry

`Ouroboros.Wasm.Rollout.deploy(artifact, bytes, nodes, opts)`, keeping every
discipline of `Rollout` (§4.1) with the code-loading machinery deleted:

1. validate nodes (connected, `:core`) and verify signature + sha;
2. **checkpoint `:deploying` before any effect** into the driver's existing `Rollout.Registry` —
   `entry.module` is already `module() | String.t()`; lane W writes `"wasm/" <> name`,
   and checkpoint v3 widens the entry with `component_sha256` (same struct-widening idiom
   as v1→v2's `eval_report`). The epoch gate is inside that same serialized call, and the
   watermark it checks against is a **durable high-water mark** (`lane_w_epoch`, additive,
   no version move) rather than the highest surviving entry: derived from the entries
   alone, `prune/2` could discard the settled rollout that held the highest number and
   free it for replay. Both the entry's epoch and the watermark are held to a plausibility
   ceiling on read, and `deploying/2` shares it: `Epoch` is a counter that adds one per
   allocation, so a number above 10^14 was not minted by this cluster; an entry carrying
   one is dropped like any other unreadable entry and a watermark carrying one is ignored.
   That closes the two unrecoverable shapes (W-F26); it does not make a tampered checkpoint
   safe. `test_report` and `detail` are bounded and portability-checked on
   the way in, the same as `eval_report` — both arrive from a requester, and a durable
   store an attacker sizes is not one;
3. per node: atomically admit the epoch in that target's own `Rollout.Registry`, then
   `Wasm.Store.stage` over `:erpc` (content-addressed, idempotent — a node that already
   holds the sha does nothing). Both forms are published, both content-addressed; the
   target then loads the **precompiled** one when — and only when — the verified manifest
   declares a block, its own helper reports exactly that wasmtime *and* that target triple,
   and the artifact is on its disk. Anything short of all four is the source form under
   §7.3's bounds with one logged line naming which half disagreed, which is a fallback and
   not a fault (D22). `Wasm.Boot` and `Ouroboros.Wasm.PolicyEngine` reach the same rule
   through the same function, `Wasm.Store.form/4`. The claim stored beside the target's high-water mark makes
   a retry of the same artifact idempotent, while a different driver cannot replay an older
   signed manifest to nodes whose local executor never sees lane W;
4. probe: the generalized `Rollout.Probe` starts
   `{Ouroboros.Wasm.Capability, %{component: sha, config: cfg}}` on each target,
   same signal, same echo check, same budget;
5. eval: `Rollout.Evaluation` runs the signed spec unchanged;
6. settle exactly as lane B does: pass → `:live`; fail → stop instances +
   `:rolled_back`; any ambiguity → `:quarantined`. `Upgrade.Epoch` is reused for
   ordering, and a stale-epoch deploy is refused at step 2 or step 3.

Rollback is honest and total: no code was loaded, so "rollback to absence" is *stop
the wrapper agents and mark the entry* — no purge, no old-code residency, nothing that
can answer `{:introduced_code_in_use, …}`. Boot restart: at `:core` boot, a
supervised one-shot task (the `Worktree` reconcile pattern,
`application.ex:86-100`) restarts wrapper agents for `:live` lane-W entries whose
manifest declares a `start` block — the `Runtime.Capabilities.maybe_start/2` rule
applied to a lane that can actually honor it across reboots.

A later live rollout of the same named capability replaces the wrapper held by the entry it
just superseded. The registry relationship is the authority to stop it: an unrelated holder
of the same mesh id remains a conflict and quarantines the challenger.

Every entry is re-validated when the checkpoint is read, against the same validators
`deploying/2` applies. `fetch_epoch/1` also applies the 10^14 plausibility ceiling described
above, so the malformed and unrecoverably high cases are both refused. One bad entry is
**dropped with a logged reason and the rest of the register loads**, because refusing the
whole checkpoint for
one row is how a single unreadable entry stopped a node deploying anything at all; an id
that a pre-tagging checkpoint wrote bare and that spells an atom (`"nil"`, `"error"`) is
migrated to its string rather than dropped. Read is looser than write in exactly two
places, both deliberate: a module name and a node name this VM never interned come back
as binaries, and that is what a rollout of code this node no longer holds looks like.

A deadline is ambiguity in the strong sense, and the two transports are not symmetric.
`:erpc.call/5` with a timeout stops waiting; it does not stop the peer, so a stage or an
evaluation that missed its deadline may still be running there and may finish after the
coordinator has settled — which is precisely what `:quarantined` means. The **local**
branch is killed at its deadline, and `after` does not run for an exit signal from
outside, so `Rollout.Probe` and `Rollout.Evaluation` each keep their throwaway agent's
cleanup in a process the kill does not reach; without it the agent kept a cluster-wide
mesh id and a helper instance with nothing linked to it that would ever notice.

#### The bundle, and the three verbs an operator uses (W12)

Deploying used to be console-only: mint a key by hand, build a manifest in IEx, sign it
through the service, call `Wasm.Rollout.deploy/4`. W12 puts that on the wire without
moving any of the authority.

`Ouroboros.Wasm.Bundle` is the one file an operator moves around, extension
`.ouro-wasm`: a 21-byte header (magic, format version, and the envelope, precompiled and
component lengths), a bounded JSON envelope carrying the manifest as its own
`term_to_binary` plus the signer id and the 64-byte signature, then — since W8 (format 2) —
the precompiled artifact if the manifest declares one — bounded at four times the component
ceiling, and never above what `ouro-wasm` will read — and then the component bytes **raw**.
The artifact sits before the component rather than after it, and that is not a taste:
`wasm.sign` answers with the bundle's *prefix* and the client appends the exact bytes it
uploaded, so the only ordering in which the client still composes nothing is the one where
everything it did not produce comes first. A format-1 file is refused by version — the signed
half gained a field, so one could not have reconstructed anyway, and "your file is from a
build before W8" sends an operator somewhere useful. The big
half is not base64 — that would be twenty-one mebibytes of decoding handed to a parser by
whoever wrote the file, to save nobody anything — and only the KiB-scale envelope is.
Every field is bounded before it is parsed, the total size must equal the header plus the
two declared lengths exactly (so trailing data is a refusal), and the manifest term is read
with `binary_to_term/2`'s `:safe`, so a bundle cannot grow this node's atom table. `:safe`
is not the whole of it: the external term format's tag 80 is `COMPRESSED`, which
`binary_to_term/2` inflates transparently, so a ceiling on the *encoded* field said nothing
about what a decode allocated — forty-two kibibytes of zlib was a sixteen-million-element
list built inside `Bundle.verify/2`, which is what `wasm.deploy` reaches at `:operate`,
before a single trust check had run. A compressed manifest is refused by its tag (this
build's encoder passes `[:deterministic]` and nothing else, so it never writes one), and
what the decode *did* allocate is then measured with `:erts_debug.flat_size/1` against a
heap ceiling — because uncompressed terms are not size-preserving either: a byte list is
one byte an element on the wire and a cons cell in the heap.
Reconstruction is then held to a fixed point: the struct built out of the decoded map must
project back through `Wasm.Artifact.manifest/1` to exactly the map that was decoded, which
is one comparison instead of nine and cannot be satisfied by a manifest carrying a key
this build has no home for. `Bundle.verify/2` adds nothing of its own: the sha binds the
bytes, the signature binds the manifest, and the **reading node's** trust policy binds the
signer — and since W8 there are two shas, one per form, because a node that checked only the
component's would deserialize machine code nobody signed out of a file that was otherwise
perfectly verified.

The verbs are `wasm.sign`, `wasm.deploy` and `wasm.rollback`, all `:operate` and
node-routed like `wasm.status`, plus `wasm.upload` underneath them (D16). `wasm.sign`
builds a manifest over uploaded bytes — recomputing the digest and the size, taking the
**declared** import list from the client, and refusing bytes that do not begin like a
WebAssembly binary at all — and hands it to `Upgrade.Signing.Service`, which applies the
whole policy above and journals the decision. It **never parses the component**: those are
unsigned bytes from a socket, and pointing the helper at them is what this lane exists to
avoid (D15). The epoch is not a parameter either; it is allocated over the connected
cluster.
It answers with the bundle's **prefix** rather than the bundle: the operator already holds
the bytes they uploaded, and sending somebody their own file back is not a transfer worth
building. `wasm.deploy` verifies the bundle against the node's own
trust policy **before** the store, the helper or the register hears about it, then runs
`Wasm.Rollout.deploy/4` unchanged; a rollout that ran answers with its state rather than
with an error, because `:rolled_back` and `:quarantined` are outcomes a client renders.
**What comes back the other way, and how it is bounded (W19, D28).** The prefix stopped being
"a few hundred bytes" at W8: it also carries the precompiled artifact, which is the one part of
the file the client never had — this node compiled it, from bytes it then signed. That is 258 093
bytes for the reference guest and eleven mebibytes for the worst shape §7.3 admits, and one reply
is not a file transfer, so W8 dropped an artifact past three quarters of the frame and signed the
source form alone. W19 hands it over instead. `Wasm.Download` is `Wasm.Upload` in the other
direction — `<data_dir>/wasm/download/`, slots claimed `O_CREAT|O_EXCL`, 0600 files, the same
512 KiB chunk and the same two clocks, all four numbers read from that module rather than
restated — and `wasm.download` `{download, offset}` walks one. The receipt then carries
`artifact: {download, size, sha256, chunk_bytes}` beside a `bundle_prefix` that is the header and
the envelope alone, the manifest keeps its `precompiled` block, the signature still covers it,
and `form` is still `precompiled`. What bounds the verb is that a node hands out **only** bytes
its own `sign/2` produced: there is no verb that puts, the slot is minted by that function alone
and *before* the manifest is signed (so a node that cannot stage one falls back to the source form
rather than signing a promise it cannot keep), the offsets are chunk boundaries below the size
rather than a seek, and what comes out is bound by the sha256 the signed manifest already names.
The client writes `prefix <> artifact <> component`, which is byte for byte what `Bundle.encode/3`
would have written; below the ceiling nothing changed at all. Reading the final chunk releases the
slot, because the verb's closed parameters give a client no other way to say it is finished — the
cost, stated rather than hidden, is that a lost last frame means signing again.

`wasm.rollback` reaches the same `withdraw/2` the eval-failure branch uses — a wrapper
running some other component's sha is left alone and reported `:unchanged` — and marks the
entry `:rolled_back` only where every node proved **absence**. `:unchanged` is not absence:
something is still answering under the id the operator asked to retire, so the entry is
`:quarantined` and the per-node evidence says which node and why. (On the *compensation*
path `:unchanged` remains proof, because there the claim is only that this rollout started
nothing.) Bytes stay in the store (D6).

Champion/challenger (`compare: true`) is **deferred**, not inherited: `Wasm.Rollout`'s
`eval_report` hardcodes `compare: false`. `Upgrade.Rollout` accepts a `:replace`
artifact only against a measured baseline, and what "the version this displaces" means
when identity is a digest rather than a module name still needs a rule. Until then a new
component is a new rollout, and the register's own supersede rule retires the entry it
displaces.

### 7.7 Forging, and the effect surface

Slices 0–3 deploy *operator-supplied* components. W14 closes the loop: a capability is
built here, from source, by an agent or an operator, and it never leaves the fence to do
it.

`Ouroboros.Wasm.Forge.forge/2` is `Ouroboros.Upgrade.Forge`'s shape with one substitution.
Both validate before they compile, compile somewhere the cluster cannot be reached from, hold
the product to the rules the loading node will re-check, and only then allocate a number and
ask for a signature. What differs is what "somewhere" means: lane B's build peer is a separate
BEAM with no distribution, which is isolation from the cluster and not from the machine — its
own moduledoc says that compiling hostile source needs a container around it. A Cargo build
*is* arbitrary code at build time, so this lane does what that sentence asks for and runs the
subprocess under `Ouroboros.Provider.Native.Sandbox`, the same OS sandbox the native agent's
shell runs in.

**The input is C9's, and the three things that make it safe are not "we read the Rust."**

1. **The lock pin.** `Cargo.lock`, minus this project's own `[[package]]` entry, must be
   byte-identical to the SDK's own resolved lock — which is exactly what a scaffolded project
   resolves to, pinned by `test/support/wasm_forge/`. So the dependency set is the SDK's: the
   same crates, versions and checksums, and the only code that runs at build time is the
   SDK's own proc macros, which this repository already builds on every `make wasm-examples`.
2. **The file allow-list.** `Cargo.toml`, `Cargo.lock`, `src/**.rs`, an optional `README.md`,
   and — for a workspace proposal — the operator's own `manifest.json`, which is bounded and
   path-checked like everything else and then left out of the build. At most 32 files and a
   mebibyte, every path relative and free of `..`, no symlinks (`File.lstat/1` at every step,
   never followed), and no `build.rs` — refused by name *and* by refusing the `[package]
   build` key that would give one power, because `src/build.rs` is otherwise a path the
   allow-list admits. The manifest is read by a scanner that refuses every line it cannot
   classify **and** by `Toml`, the parser this repository already reads `ouroboros.toml`
   with, and the two must produce the same document: a scanner that is not a TOML parser is
   the thing an author would write a manifest to fool, and the disagreement is the refusal.
3. **The sandbox.** `cargo build --release --target wasm32-wasip2 --locked --offline` under
   `Sandbox.builder_policy/1`, which is deny-by-default on **reads** as well as on writes:
   a build reads the toolchain, the guest SDK, the `wit` world file beside it and its own
   directories, and nothing else. No network; writes confined to the build directory, a
   node-local cargo home and a private `TMPDIR`; a five-minute ceiling; bounded output. A
   node with no sandbox backend **does not build at all**, and neither does one whose only
   backend cannot express a read allow-set — those are refusals and not weaker postures,
   because the fence is one of the three things this lane's claim rests on.

**And a fourth thing, which is about *which* machine** (W20, D29). The three above bound what
a build may do; `Wasm.Forge.placement/3` decides where it happens, and it is a check rather
than advice. A **`:signer`-role node refuses to forge**, whatever the configuration says and
whatever the fleet looks like: a Cargo build is arbitrary code at build time, the signing key
is on that node, and those two do not share a machine. `config :ouroboros,
:wasm_forge_placement` is `:local` by default — a forge runs where the effect lands, exactly as
before — and `:builder` forwards a forge that landed on a non-builder node to a connected
`:builder`, under the same server-owned principal, where every fence above is that node's own;
with no builder connected it refuses by name rather than quietly building here. What travels is
the **validated project inline** — this node collects and validates C9 itself, and a directory
name, which is a fact about *this* filesystem, never crosses the wire — plus the attrs and two
deadlines and nothing else about this machine. The bundle comes back as bytes, is verified here
against this node's own trust policy and held to the name, the kind and the principal that were
asked for, and is retained here, so a forwarded forge's receipt deploys from the origin exactly
as a local one's does. The decision is a pure function of this node's role, the setting and the
roles `Ouroboros.Cluster` reports, so a test pins all thirty-six combinations and
`capabilities.preview` reports the answer before an operator spends a build finding it out.

**The imports are read, not declared.** `Wasm.Deploy.sign/2` never parses a component,
because those bytes came off a socket (D15). Here the node built them itself, from source it
validated against a dependency set it pinned, inside its own sandbox — so
`Wasm.Pool.inspect/2` reads the import list under the W7 bounds, and it is still cross-checked
against the signed manifest at stage like every other deploy (D18).

Everything downstream is unchanged: `Wasm.Deploy.sign/2` builds the manifest and the signing
service applies the whole policy, `Wasm.Rollout.deploy/4` verifies and gates, the bundle is
the same `.ouro-wasm` W12 defined. The forge writes that bundle into `<data_dir>/wasm/forged/`,
bounded to the newest eight, and `deploy/3` reads it back and holds it to the artifact it was
asked for before staging a byte — it is this node's own output, but it is a file, and a file
is what somebody else can replace.

**The two effects.** `ForgeWasmCapability` and `DeployWasmCapability` go through
`Runner.dispatch(:forge, …)` and `(:deploy, …)` exactly as the BEAM lane's do: the acting
principal is `context.agent.id`, the signal's `from` is recorded as `claimed_from` and
authorizes nothing (`runner.ex:126`), and the author written into the signed manifest is the
principal. The `:forge` grant is asked about `"wasm/<name>"` — the same string the rollout
register calls the module and a signed `start` block claims — so `modules: ["wasm/counter"]`
is a grant to forge that capability and nothing else. A deploy resolves its artifact from the
agent's own `forged` ring and never from the signal, and one ring now holds both lanes'
manifests, so each deploy action refuses the other lane's by name rather than by whatever
would have failed first downstream.

**The operator's half is the same code.** A proposal directory under
`.ouroboros/capabilities/` that holds a `Cargo.toml` is a lane-W proposal;
`capabilities.preview` reports the C9 validation and, where the toolchain is present and the
cache warm, a dry build; `capabilities.admit` forges and deploys it at `:operate`. No new
gateway verb: the three that existed already name the thing being asked for.

**Reaching a capability** (W13). A deployed capability is a mesh agent at `wasm/<name>`,
and there are exactly two ways to reach one. Neither is `Mesh.send_message/4` from a
shell, which remains what it always was: an operator with an IEx prompt has the node.

* **The model** calls the native `capability` tool. `list` answers with the register's own
  facts about every `:live` lane-W rollout **that names this node a target** — name, epoch,
  component sha256, and whether an agent is running — beside each component's own
  `describe`, read from the register entry, labelled `[untrusted, authored by the
  component]` and bounded. `call` takes `{name, message}` and answers with the reply, whose
  **every line** carries that same label, bounded at 64 KiB with a truncation marker. Only a
  name the register calls live is reachable: this is not a mesh client, and a model naming
  any other agent id is refused before anything is sent.
* **A script or the TUI** calls the gateway verb `agents.message` `{to, body, from?,
  timeout_ms?}`, scope `:operate`. That one reaches *any* mesh agent, because the mesh
  already resolves an agent anywhere in the cluster and a second, weaker answer in the
  scope table would not change that. It is `:operate` and not `:read` for the reason
  `wasm.status` is `:read`: sending a message to a capability starts the containment
  helper and runs a component.

**One name, and it is the one the model wrote.** `Tools.Capability.resolve/1` is the single
function that turns a string into a capability, and both the permission engine's question
and the tool's message are asked with the *exact* bytes the model sent. Nothing anywhere
trims. That identity is load-bearing rather than tidy: while classification and execution
normalised differently, a name padded with a non-breaking space resolved to nothing for the
engine — so a `Capability(*)` deny did not match — and to a live capability for the tool, so
the message went anyway and the ledger entry named neither the capability nor its bytes. A
name that is not `Wasm.Artifact.name?/1` is refused before the register is read at all.

**The permission rule keys on the capability, never on the tool.** `Capability(<name>)`
matches a call to that capability, `Capability(*)` matches a call to any, and with no rule
written the engine's own posture applies: ask, once per capability, and the operator's
answer is what persists. An *allow* on those patterns is honest because the name they match
is one this node resolved against its live rollouts before the engine was asked — the same
distinction `ComputerUse(app:…)` draws against `Tool(<name>:<param>=…)`, whose parameter is
whatever the provider reported. A name that does not resolve carries no `capability` in the
request context at all, so `Capability(*)` cannot cover "we could not tell which one".

`Tool(capability)` is **deny-and-ask only**, enforced by `Pattern.decisions/1` and therefore
by every path that creates a rule — node configuration, `permissions.add`, and the
remember-this-answer flow alike. The pattern is perfectly precise about the tool; the
problem is that the tool is not the authority. One call reaches one deployed component, so
an allow on the name is an allow on every capability this node has deployed *and every one
it will deploy later*. Narrowing on the tool stays available, because narrowing is always
honest. `Capability(*)` is how the broad thing is said out loud.

The tool call is ledgered like every other tool call, and its subject carries both the
capability's name and the sha256 of its component bytes. D11 says a mesh message is not
individually ledgered; this entry is therefore the only written record that a model reached
a component, which is why a name without the digest would not have been enough.

**Where a description comes from.** Not from the component, at read time — from the
registry entry, where the deploy that admitted the component put it (D17). `agents.state`
is `:read` and returns a capability's whole state, so for a `wasm/` agent it carries
`untrusted: true` and bounds `last_answer` and `last_message` to the same 64 KiB with the
same in-band marker: the sibling verb labels those two fields, and a read-only listener
must not be the way around the label.

## 8. Lane H: hooks and policy as components

### 8.1 Wasm hooks

A `[[hooks]]` entry may declare `component = "<path>"` instead of `command`.

**The world sketched below is not built.** v1 hook components are
*capability-world* components, and a hook is a strict subset of a capability — one string
in, one string out, log-only. The hook payload goes in through `handle-message`, the
stdout contract comes back as its reply, `init` receives the hook's declared `config`
(or `"{}"`), and `describe` is unused. Containment is identical, because containment is
the linker. The helper has since grown a second world for the *policy* lane (§8.2, D21), so
"a dedicated world" is no longer hypothetical machinery — it is a decision about whether a
hook's contract differs from a capability's enough to be worth a package of its own, and so
far it does not. The sketch is kept here as the deferred design:

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

The swap happens at exactly one function — `invoke/3` in
`provider/native/hooks.ex`: a component hook routes to `Wasm.Pool.call` instead of `Exec.run_shell`, under an epoch
deadline in place of TERM/KILL and the same output-byte cap. Everything above the seam
— the fold, deny-is-final, ask-outranks-auto-approve, silence-is-not-consent,
updatedInput re-evaluation, all ten dispatch sites — is untouched by *which* kind of hook
it was.

The `invoke/3` seam narrows in both directions. On the way *back* it drops `allow` and
`updatedInput` for an untrusted workspace and labels what it keeps — every **line**,
prefixed `[untrusted workspace hook] `, because one `additionalContext` is one string and
a string may carry newlines. On the way *in* it narrows the payload: a `PostToolUse` hook
from an untrusted workspace is handed `tool_response` as `{"is_error": …, "bytes": …}`
and never the output body. `[checks]` is inside the same seam rather than beside it: a
component check's failure is injected into the turn as a user message, so an untrusted
workspace's failure block is labelled per line — the check's own name and path included,
both clipped to 200 bytes, both being repository-authored text.

Three events are not dispatched to an untrusted hook at all: `Notification`,
`FileChanged` and `SessionEnd`. The turn loop discards what they return and
`Hooks.session_end/2` discards by contract, so dispatching one buys a clone's guest a
read of this session's tool names and changed paths in exchange for a verdict nothing
consumes.

`matcher` is a repository-authored regular expression run against a tool name the model
chose. It is bounded to 200 bytes, compiled alone before it is compiled inside
`\A(?:…)\z` — a `)` in the pattern otherwise closes the group the anchoring opened, and
`a)|(x` anchors to an unanchored alternation — and matched under a 10,000-step
backtracking budget: `(a+)+$` against 41 characters was 90 ms per tool call and is now
94 µs.

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

**The narrowing is visible before it is provoked.** `ouro wasm hook <file> --event <Event>
[--trusted]` runs a component exactly the way `invoke/3` does — the same payload shape, the
same `tool_response` narrowing on the way in, the same one-instance-one-message-always-dropped
lifecycle, the same deadline ceiling — and prints *both* verdicts: what the component said,
and what this node would act on. An author who tests a hook by reading its own output is
testing a verdict the runtime may already have dropped, and a dropped `allow` that nobody sees
dropped is a rule that gets rediscovered as a bug report. The rules are implemented once more
in Rust for that display and both implementations are pinned to
`test/support/wasm_golden/hook_narrowing.json` (D14, contract C6), read by a test on each side;
`ouro wasm check` answers the other half of the same question — which of a repository's
`component =` entries this node would admit at all — without instantiating any of them.

### 8.2 Wasm policy (the C6 slot)

**Built (W15).** `Ouroboros.Wasm.PolicyEngine` is an engine for `config :ouroboros,
:permissions_engine` (`native/permissions.ex:67-69`) that stands exactly where
`Control.Permissions` stood and delegates every call to it. It adds one thing: where the rules
said *nothing* — `{:ask, :no_rule}`, which is most calls — it asks a signed policy component,
and lets that component **narrow** the answer.

```wit
package ouroboros:policy@0.1.0;

world policy {
  /// JSON metadata: name, version. Pure.
  export describe: func() -> string;
  /// Called once per instance with host-supplied JSON config.
  export init: func(config: string) -> result<_, string>;
  /// One permission request in, one verdict out. JSON both ways.
  export evaluate: func(request: string) -> string;
  /// Log line into the daemon's logger. The only import, in both worlds.
  import log: func(level: string, message: string);
}
```

The second world the helper speaks, and the first time §8.1's deferred sketch became a real
one. It is not a wider capability: the two packages are disjoint, they declare the *same*
single import, and the helper is told at `load` which of them a set of bytes is being offered
as. A capability offered as a policy is refused `unsupported_world`, and so is the reverse
(D21).

**What a verdict is worth.** A verdict is an object with **exactly** the keys `decision` and
`rule`, neither repeated, `decision` exactly one of the three lower-case words, `rule` a string,
and the whole document at most 1 KiB. Anything else is unreadable, which is `ask`. The grammar
is that strict because two implementations read it: Elixir's JSON decoder keeps the *first*
occurrence of a duplicated key and `serde_json` keeps the *last*, so
`{"decision":"ask","decision":"deny"}` was `ask` on the node and `deny` in `ouro wasm policy` —
a component could show an operator one word and hand the runtime another, and in the other
order it turned a reviewed `ask` into an honoured `allow`. Both readers are pinned to
`test/support/wasm_golden/policy_verdicts.json` by a test on each side, the way W10 pinned the
hook narrowing (D14).
A `deny` stands. An `ask` stands, and is the same question the node was already going to ask.
A `deny` stands, an `ask` stands, and an `allow` is honoured **only** for the tools an operator
listed in `config :ouroboros, :policy_allowable_tools`, which is empty by default; everywhere
else it is read as `ask`. Everything else is `ask` too — a trap, a deadline, a refusal to link,
a verdict outside the grammar, a request too large to hand over whole, a register row this node
cannot tie to a manifest it can verify, and the case where no policy is configured at all.
**There is no failure mode that produces an `allow`** (D20). An honoured verdict whose ledger
entry cannot be written follows `Control.Permissions`' own rule: the `allow` becomes
`{:ask, :unrecordable}`, because an approval nobody can account for has not been granted, while
the `deny` stands, because refusing without an audit entry is still refusing.

**One decision, bounded.** A consulted decision is a synchronous round trip through the node's
one shared helper pool, sitting in front of every tool call the rules did not decide — so the
engine bounds it rather than the pool: `config :ouroboros, :policy_decision_timeout_ms`, five
seconds by default, over the whole decision including a re-instantiate. On expiry the answer is
`ask`, the instance is dropped so the next request stands a fresh one up, and the warning is
said once. Only one refusal is retried — `unknown_instance`, which means the instance this
engine remembers is gone — because every other has already spent the round trip and a second
would only double the wait. The residual is stated rather than solved: the *decision* is bounded
here, and the pool's own queue entry drains on the pool's schedule, so an unrelated pool user
still waits out that one request's deadline.

**Deterministic by construction, not by promise.** The world imports one function, so a policy
component has no clock, no randomness, no filesystem and no network to be nondeterministic
*with*. Instance state is the one thing left and it is the author's; the engine keeps one
long-lived instance per component sha and re-instantiates it after any refusal, under the same
`capability_limits` budget and the same helper eviction rules a capability gets.

**What a component sees.** The JSON form of the request `Control.Permissions` already
normalised — `tool`, `mode`, `input` (the command, the paths, the write paths, the domains),
`principal`, `workspace`, `context` — with **credential-shaped keys and well-known token shapes**
redacted: a map key matching the credential pattern, `Bearer` runs, AWS access key ids, `sk-…`,
GitHub and Slack token prefixes, PEM private-key blocks, `NAME=value` and `NAME: value` where the
name is credential-shaped, and every secret value in this node's own environment. That is a
heuristic and it is worth saying so: a credential in no recognised shape reaches the component,
and it must — a policy that may deny `curl` has to read the `curl`, which is the same sentence
D8 makes about what a hook may see. **It is never truncated**: a document over 64 KiB is not sent at all and the engine answers `ask`, because a
policy shown the first four kilobytes of a command line is one an attacker pads past. Non-scalar
`context` values are dropped rather than serialised and the dropped keys are named in
`context_dropped`, so a partial view is visible to the component rather than silent.

**Signed, and the kind is part of the signature** (contract C7). `Wasm.Artifact` carries
`kind: :capability | :policy`; the world follows from it (`Wasm.world_for/1`), the signer
checks the pair, `Wasm.Verifier` checks it again on the loading node, and `Wasm.Rollout.stage/3`
hands the *manifest's* kind to the helper's `load` — which is where a manifest that says one
thing and bytes that are another meet. A policy manifest may declare no `start` block (there is
no wrapper agent to start) and its signed `eval` spec is a list of `{request, expect:
{decision}}` cases run through `evaluate` at deploy, at least one of which must expect a `deny`
or an `ask`: an `allow` is the verdict this node does not honour by default, so a spec that
certifies only allows certifies nothing.

The register carries the kind too, recorded at deploy from the manifest the rollout verified, so
`Rollout.live/1` filters an index rather than opening a file per entry — the `capability` tool
lists capabilities only, and the engine looks only at policies. That row is a **claim**, and the
engine treats it as one: before it loads a byte it fetches the manifest the row names, verifies
it against this node's own trust policy, and holds the manifest's sha to the row's sha and its
kind to `:policy`. Without that, a planted checkpoint naming a genuine policy manifest and some
other component's bytes was a permission engine made of those bytes.

**Auditable.** Every decision the engine *makes* — an honoured `deny` or `allow` — is recorded
through `Control.Permissions.record/2` with `actor: :classifier`, the slot the answer type
reserved at `permissions.ex:92` and that nothing occupied until now; the entry's `rule_ref`
carries the component's sha and the rule string. A verdict that degraded to `ask` writes
nothing, because the node is about to ask a human and that answer is recorded where every human
answer is. Everything a component authored is untrusted text: the rule is bounded at 200
characters, stripped of every control and format character, and labelled
`[untrusted policy component]` wherever it reaches a model or a person.

**The author's loop has no node in it.** `ouro wasm policy <file> --request <json|file|->`
loads a component as a policy into a local helper, asks it one request, and prints the verdict,
the rule the node would record, and the guest's own log; it exits non-zero on a `deny`.
`tui/wasm/guest`'s `Policy` trait and `export_policy!` are the fourth seam over the SDK's two
worlds, and `examples/no-network-shell` is the worked one — it denies a `bash` whose command
contains `curl`, `wget` or `nc `, with a stated rule, and asks about everything else.

**Every seam reads one setting** (W18, D27). Four readers now: the native loop
(`Provider.Native.Permissions`), the interactive plane's external approvals
(`Interactive.Task.Approvals`), the interactive shell (`Interactive.Task.Shell`, through
`Approvals.permissions_engine/2`) and the ACP lane (`Control.Permissions.Seam` — both the
`session/request_permission` a vendor process sends and the `fs/write_text_file` and
`terminal/create` an agent asks this runtime to perform). A node given a policy component has
one on every lane a permission question arrives on rather than on three seams out of four. The
ACP seam takes `Interactive.Task.Approvals`' tolerance verbatim: an answer in none of the three
shapes, an exception and an exit are each an ask, with the approval reaching the human exactly
as it did before an engine was named. **No engine *failure* widens anything there** — and what
an engine does answer is its own authority, an `{:allow, ref}` included, exactly as on the other
three seams; the bound on a component's `allow` is `PolicyEngine`'s `:policy_allowable_tools`
(D20) and there is deliberately no second one at the seam. `remember/4` and `forget_session/1`
stay on `Control.Permissions` whatever engine is named — rule-store operations, not decisions
(C13) — and so does the *pattern* a `:session` answer is written as, because that row is durable
and its width is not something a named engine may widen from underneath. Proved end to end in
`test/wasm/policy_acp_test.exs` against the real `no-network-shell`, signed and deployed through
the real rollout, and asked both directly at the seam and through a real `Session.Jsonl` driving
a vendor process.

A model-backed classifier (the original C6 sketch) remains possible *behind* the same engine
interface; the wasm module is the deterministic, offline-testable version, and it is the one
that landed.

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
brains in any language §1's boundary admits, structurally contained, signed and placed
with machinery that exists. It is **not** a migration target for the native loop. The
2026-08-30 rewrite assessment applies with equal force here: the loop's value is its integration surface
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
- **D8 — containment replaces trust for workspace components.** A component hook is
  admitted from a workspace nobody trusts; a command hook is not. A component reaches
  nothing on its own — the world's one import is a log line — so everything it learns
  arrives in the payload the seam hands it and everything it can do arrives in the
  verdict the seam reads back, and both are bounded there. *What it may do:* make a
  decision stricter and never looser. `deny` and `ask` stand, `additionalContext` is kept
  and labelled on every line, `allow` is read as silence, `updatedInput` is dropped.
  *What it may see:* at `PreToolUse`, the whole `tool_input` of every matching tool call
  — the command a `bash` is about to run, the path and the content a `write` is about to
  write. That is kept deliberately, because a hook that may deny needs the arguments it is
  denying, and it means an untrusted workspace reads every tool call's **arguments**. It
  does not read their **results**: `PostToolUse` hands an untrusted hook
  `{"is_error": …, "bytes": …}` and no output body, because a hook that can put text into
  the next prompt is a way back out for whatever a tool produced. `FileChanged` would
  carry paths and never contents, and is not dispatched to an untrusted hook at all. A
  trusted hook — the operator's own, or a workspace they named — is handed the full
  response, exactly as before. Nothing here narrows what an operator asked for.
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
- **D13 — the SDK owns the ceremony; the import list is still the claim.**
  `tui/wasm/guest` exists because the only worked component in this repository was the
  acceptance guest, and writing a second one meant copying two hundred lines of `no_std`
  before the first line of logic — with one wrong feature flag enough to make `inspect`
  report `world: "unknown"`. It is a **trust-free** crate: nothing it generates changes what
  the linker defines or what the helper refuses, and a `describe` it produced is exactly as
  untrusted as one written by hand. What it does own is the defaults every author copies —
  `panic = "abort"`, LTO, `opt-level = "s"`, no `std`, no dependency that pulls WASI — so its
  defaults are the ecosystem's posture whether or not anyone says so. That is why the
  acceptance guest was rewritten onto it rather than left beside it: the assertion
  `imports == ["log"]` in `test/wasm/capability_acceptance_test.exs` now runs against a
  component the SDK built, so the SDK cannot quietly grow an import without lane W's own
  acceptance suite going red. `tui/wasm/tests/sdk.rs` holds the four example guests and the
  scaffold template to the same assertion, against the real helper.
- **D14 — the author's loop runs the helper locally, and the helper comes from where `ouro`
  was installed.** `ouro wasm inspect|run|hook|check` need no node: each starts a local
  `ouro-wasm` and speaks its line protocol, and `ouro wasm sign` starts one too — for the
  import list D15 makes the client's to declare, before it opens a socket at all (W10b). That
  they *start* one is the deliberate difference from `ouro wasm doctor`, which asks a gateway
  and starts nothing — a readiness surface that spawned to answer whether spawning works would
  be answering a different question, and a development loop that needed a running node would
  not be a loop. `new` is the fifth local command and the one exception in the other
  direction: it writes files and asks nobody anything.

  The helper is found in exactly three places, in order: `--helper <path>`, an **absolute**
  `$OUROBOROS_WASM_HELPER`, and the `ouro-wasm` beside the **resolved** `ouro` binary. The
  rule is *nothing cwd-derived unless the developer said so* — not "never a repository",
  which the first draft said and which was never true: an absolute `$OUROBOROS_WASM_HELPER`
  pointing into a checkout is honoured, and CI exports exactly that. A person naming a path
  is the only thing that may choose. What is forbidden is a candidate this command derives on
  its own from wherever it happened to be run, which is what W7 removed from
  `Ouroboros.Wasm.helper_path/0` for a reason that applies here with more force: `ouro wasm`
  is typed in the directory a component author is working in, which is the directory the
  component came from.

  Saying that is not enforcing it, and review found three ways the first implementation let
  something other than a person choose. Each is now a mechanism with a test that was red
  before it:

    * **The sibling was the directory `ouro` was *reached through*.** `current_exe` returns
      the path used to start the process, symlinks and all, so a repository shipping
      `./ouro -> /usr/local/bin/ouro` beside its own `./ouro-wasm` had that `ouro-wasm`
      executed — proved with a marker file. `current_exe` is canonicalised *first*
      (`wasm_client::sibling`); pinned by
      `a_symlinked_ouro_does_not_adopt_the_helper_beside_the_symlink`.
    * **The file checked and the file executed could differ.** `--helper ouro-wasm` has no
      path separator, so `is_file()` resolved it against the working directory and
      `Command::new` then did a `$PATH` search and ran something else — also proved with a
      marker. Every accepted candidate is canonicalised and it is the canonical path that is
      spawned, which `HelperBinary` — a newtype only `vet` can construct and the only thing
      `Helper::start` accepts — makes unskippable rather than remembered. Pinned by
      `a_bare_helper_name_is_not_resolved_through_the_path`.
    * **Nothing checked who owned it.** `vet` now applies the shape `fleet.rs`'s
      packaged-EPMD check applies: a regular file, executable, owned by this account **or by
      root**, and not group- or world-writable. Root is accepted because a helper installed
      by a package manager into `/usr/local/bin` is *more* trustworthy than one owned by this
      account, not less, and refusing the safest install would push a developer to `--helper`,
      which this same function vets anyway.

  **A cargo path dependency is executed, so the SDK obeys this decision too (W10b).** `ouro
  wasm new` writes `ouroboros-guest = { path = "…" }`, and the first version computed that
  path by walking up from the *output directory* — on the reasoning that a source path is not
  something that runs. It is: a path dependency's `build.rs` and its proc-macros execute
  during `cargo build`. Review planted an `ouroboros-guest` on a shared ancestor of a working
  directory (`/tmp` is one, a home directory is one, a mounted share is one) and the scaffolded
  project's first build ran its build script. So the SDK now comes from exactly two places, and
  the working directory is not among them: `--sdk-path <PATH>`, or the checkout the running
  `ouro` binary lives in — its ancestors, from a **canonicalised** `current_exe`, which in a
  checkout is `tui/target/{debug,release}/ouro`. Whichever it is, it is vetted the way the
  helper is: no symlink at `guest` or the two levels above it, a regular bounded `Cargo.toml`,
  and a `[package] name` of exactly `ouroboros-guest` — a directory laid out like the SDK is
  not the SDK. The path written into the manifest is **canonical and absolute**, because the
  relative form was byte-identical in the benign case and the planted one, so a manifest an
  author read told them nothing about which SDK they had. With neither source available the
  command refuses and names `--sdk-path`; an installed `ouro` outside a checkout is that case,
  and it is the honest one.

  **Outside the model, stated:** a local attacker who can already write into the directory the
  real `ouro` lives in, or who can hard-link that binary into a directory they control. A hard
  link needs local write access to a directory on the same filesystem, and the link is
  indistinguishable from the file because it *is* the file — no rule about paths can defend
  that, and pretending otherwise would be the kind of claim this spec exists to avoid. What
  the model does cover is a repository, a clone, an archive: anything that arrives as data.

  `run` and `hook` execute attacker-authored components on a developer's machine. That is
  acceptable for one reason and only for it: they run *inside `ouro-wasm`*, under the bounds
  a node uses, with the environment `Ouroboros.Wasm.Pool`'s `@inherited_env` allows and
  nothing more (`PATH`, `HOME`, `TMPDIR`, each dropped when its *value* carries a
  `scheme://user:pass@` or a PEM private-key header). No path reaches wasmtime except through
  the helper; a `--fuel`, `--memory-bytes` or `--deadline-ms` above what `doctor` reports is
  **clamped down** to the helper's own maximum and the clamp is printed. Everything a
  component authors — a reply, a `describe`, a log line — is stripped of control characters
  and ANSI escapes before it reaches a terminal, because a page a component can redraw is a
  verdict a component can forge. The environment is pinned by a canary helper that dumps what
  it was given; the stripping by an assertion on the **raw bytes** of stdout, because a string
  comparison is what would miss a stray `0x1b`.

  Every file these commands read is one a developer *named* and somebody else *wrote*, so
  each is statted for a regular file and then read through a bounded reader: the
  `ouroboros.toml` (256 KiB), a `--messages` file (8 MiB), a `--payload` or its standard input
  (1 MiB), and a component before the helper is told about it (16 MiB). Both halves are
  necessary and review proved it: a bound taken from `metadata().len()` is zero for a
  character device, so `ouroboros.toml -> /dev/zero` passed the size check and then read
  forever — thirteen gigabytes resident after eight seconds. The stat also refuses a FIFO
  without opening one, because `open` on a FIFO with no writer blocks in the kernel and a path
  is somebody else's string. This is the shape `hooks.ex`'s `read_bounded/1` and
  `host.rs`'s `read_component` already had.

  `ouro wasm hook` prints the untrusted narrowing, which means implementing D8's rules a
  second time in Rust. Both implementations are pinned to one fixture,
  `test/support/wasm_golden/hook_narrowing.json` (contract C6), read by
  `test/provider/native/hooks_narrowing_golden_test.exs` — which drives every case through
  the real seam rather than a test hook, so no `@doc false` function was added to `hooks.ex`
  — and by `tui/src/wasm_cli.rs`'s own tests. The byte clip is pinned too, and fixing it was
  a repair rather than a test: `clip/2` cut with `binary_part/3`, which cuts wherever the
  number lands, so eight kilobytes of repository-authored context ending in an accented letter
  produced a binary that is not valid UTF-8 — and `JSON.encode!` raises on one, so a clone
  could stop a turn with a long context line. Both sides now walk back to the character
  boundary at or below the limit and agree byte for byte, and the fixture carries a case whose
  cut lands mid-codepoint on the **trusted** lane, which is where it is observable: the
  untrusted lane clips a second time after labelling and throws the broken tail away.

  `ouro wasm check` reproduces the workspace admission rules rather than asking a node,
  because the point is to answer before there is a node. It judges every entry as an
  **untrusted** workspace, which is the strict case, and it never instantiates anything —
  admission is a question about a path, a size, a world and the count of an entry's siblings.
  Two things review had to correct, both of them the same fault in different clothes: a
  command claiming more than it verified.
- **D15 — deploying over the socket is sound, and the old comment was wrong.**
  `gateway/methods.ex` used to say there would deliberately never be a `wasm.deploy`,
  because "a component runs on somebody's machine under a signature". The premise was
  right and the conclusion did not follow. What decides whether a component runs is the
  signature, verified by the **target** against the target's own
  `upgrade_trust_policy` — twice on the way in, once in the driver's pre-flight and again
  on every node before it stages a byte. A socket that carries a signed bundle therefore
  adds no authority: an `:operate` client that could reach `wasm.deploy` could already
  start any BEAM capability through `capabilities.admit` and any agent through the mesh,
  and none of those check a signature at all. What the reversal does not touch is the
  other half of the old sentence, and it is the half that mattered: there is still no
  `wasm.load`, `wasm.drop`, `wasm.instantiate` or `wasm.call`, because each of those
  *would* be a socket deciding what this node runs rather than a signer deciding what may
  exist. Proved in `test/ouroboros/gateway/wasm_deploy_test.exs` (an unsigned, a tampered
  and an untrusted bundle each refused with the store, the register and the helper pool
  unchanged) and in `test/wasm/deploy_test.exs`, which also asserts the register's durable
  checkpoint is byte-identical after a refusal.

  **The node does not parse what it has not verified.** The first cut of `wasm.sign` read a
  component's import list off the staged file with the node's own helper whenever a caller
  did not declare one. That handed attacker-supplied bytes to the one process whose job is
  running other people's code, at `:operate`, before a signature existed and *upstream* of
  the signing service's rate limit — one staged blob could be fed to it without bound,
  because a failed read did not consume the upload either. So `imports` is required, the
  client computes it with the **operator's** own helper — `ouro wasm sign` resolves and starts
  one itself under this same decision's three-place rule, and `--import` / `--imports-from`
  remain the ways to say it by hand on a machine with no helper (W10b) — and a declared list
  that does not match what the component actually imports is refused at stage by
  `Wasm.Verifier.cross_check/2`, which is D5's posture and always was: the manifest's import
  list is provenance, and the linker is the boundary. Which side of the wire *types* the
  list was never the point; which side *parses the bytes* is, and it is still not the node. `Wasm.Artifact.build/2` does
  check eight bytes of preamble, because every other check a signer makes is about numbers
  computed *from* the bytes and would sign a text file just as happily; whether those bytes
  are a *component* remains the helper's answer, under §7.3's bounds, on the node that will
  run them. The upload is consumed before anything that can refuse.

  **And since W8 the signing node compiles — after the limiter, never before it.** A signer
  that hands its own helper a component is not parsing bytes it has not verified; it is
  compiling bytes it is about to sign, which is D23's whole point. But a compile is 1.4 s of a
  core and a couple of hundred mebibytes at the worst shape §7.3 admits, and the first cut ran
  it *upstream* of the signing service — so a requester the rate limiter was about to refuse
  still spent it, once per request, for free. That is the same defect the limiter-first ordering
  inside `Upgrade.Signing.Service` exists to prevent, arriving through a caller instead of
  through the module.
  So `wasm.sign` is two calls. `Signing.Service.admit/4` charges a rate-limit slot and applies
  the **whole** policy to the *source* manifest — the one with no `precompiled` block, because
  nothing has been compiled — and journals the verdict as `:admitted`; a refusal there stops
  everything, and no byte of the upload reaches the helper. Only then does the node compile.
  `sign_artifact/4` is then presented with a single-use ticket keyed to that admission — same
  requester, same manifest but for the block — and charges no second slot; anything that does
  not match pays the limiter again, which is the direction a mismatch has to fail in. One
  sentence, whole: **the signer is the machine that pays for compilation, under §7.3, for a
  requester the rate limit admitted and a manifest the policy accepted — and a node never
  compiles bytes it did not sign.**

  **And the epoch is not a client's to name.** `Rollout.Registry` admits a lane-W epoch only
  strictly above its watermark and refuses one at its plausibility ceiling, so a single
  deploy *at* the ceiling left no number that was both — on every lane-W capability on that
  node, durably, since the watermark is carried in the checkpoint and pruning cannot lower
  it. One `:operate` call, unrecoverable. There is no `epoch` parameter now: it is allocated
  with `Upgrade.Epoch.next/2`, which also closes the other end of it — a bundle signed on a
  quiet node is no longer refused by a busier peer for a number the signer could not see. The
  register's own boundary became exclusive (`>=`, not `>`), and the signing policy gained a
  second guard in front of it: an epoch more than a million above anything this node has seen
  is refused at signing time, because a signature is what makes a large epoch deployable at
  all. Its honest limit is that a dedicated signer sees no register and no allocator, so its
  floor there is zero and the bound is a flat million. Proved in `test/wasm/epoch_test.exs`.

  **Over which nodes.** Not the connected ones — the ones that could call the number stale.
  `Epoch.next/2` asks every node it is given for `NodeExecutor.status/0` and for its lane-W
  register's watermark, and a node running neither answers neither: the call exits `:noproc`
  and the allocation fails. Allocating over `[node() | Node.list()]` therefore made signing
  impossible on exactly the topology this decision prescribes — the key on a `:signer`-role
  node, whose tree is the signing service and cluster formation and nothing else — and on any
  connected `:builder` or bare client. W11's author hit it on a real two-node cluster and had
  no way past it. So the candidates are still every connected node and the allocation is over
  the subset that runs the rollout plane, probed with a bounded `:erlang.whereis/1` per
  process. A node with no register admits nothing, holds no watermark, and cannot refuse
  anything later, so excluding it changes no outcome; a node that does not *answer* is not
  excluded, because from here "no plane" and "no answer" look alike and the second may be
  hiding a watermark above the one being minted — an unreachable candidate fails the
  allocation closed. With no register among the candidates at all — a fresh fleet, or a lone
  signer — the epoch is 1 and the signature proceeds: nothing has admitted anything, so
  nothing can call 1 stale. The honest cost of that case is that two signatures on such a
  fleet both carry 1; the first deploy to whichever node first grows a register wins and the
  second is an ordinary `{:stale_epoch, 1, 1}` that re-signing clears. Proved in
  `test/wasm/epoch_nodes_test.exs` against real peer VMs: one with no rollout plane (excluded,
  and the signature succeeds), one holding the plane but not answering in time, and one that
  has gone away (both fail closed).
- **D16 — bytes cross the socket in frames, because one frame will not hold them.**
  `Gateway.Config` bounds an inbound frame at `OUROBOROS_GATEWAY_MAX_FRAME`, a mebibyte
  by default, and the Rust client refuses to send more than the same number. A component
  is bounded at sixteen mebibytes, which is twenty-one after base64. So the choice was
  between shrinking what an operator may deploy to roughly 700 KiB — which excludes most
  real components; StarlingMonkey is nine mebibytes (§12) — and cutting the bytes into
  frames that fit. `wasm.upload` is the second: **512 KiB of decoded bytes per frame**
  (about 683 KiB on the wire, a third under the default ceiling), a total bounded by
  `Bundle.max_bytes/0` — the signer's own `:signing_max_artifact_bytes` plus the envelope,
  so a bundle can never carry more than a signer would have looked at — **eight uploads in
  flight per node**, **ten minutes idle** and **thirty minutes total** before one is
  reclaimed. It is files in `<data_dir>/wasm/uploads` and no process, and the two operations
  that have to be atomic are the two a filesystem will do for you. A slot is a file created
  `O_CREAT|O_EXCL`, because counting and then creating is two syscalls and thirty-two
  concurrent openers all counted seven; the slot carries the id and the claim time, so the
  total clock is a fact nothing can touch. `take/2` is a `File.rename/2` before it is a
  read, because read-then-remove let two `wasm.deploy` frames naming one upload both
  receive the bytes. Every entry point sweeps, including the two that only read — a sweep on
  the write path alone left `take/2` handing back files the module had already promised were
  gone — and nothing follows a symlink: the root must be a real directory and a staged file
  a regular file, both by `File.lstat/1`. A sweep also keeps its hands off a claim in
  progress: a claim is two writes with a moment between them, and a sweep in a concurrent
  call once read a slot empty, took it for litter, and reclaimed the part that slot was about
  to name (seven winners of thirty-two on the hosted runner), so nothing regular and younger
  than thirty seconds is reclaimed on the strength of how it looks — an unreadable young
  slot, a young slot with no part yet, a young slotless part — while the files of a slot the
  clocks expired go regardless of age. The id is minted by the
  node — a client-chosen id is a client-chosen filename — and is still validated as 32 hex
  characters on the way back in. An upload carries no authority whatsoever: the sha it
  reports at commit is a receipt for the transfer, and what comes out of it is verified by
  whichever verb consumes it. The **result** direction needed no chunking when this was
  written, because `wasm.sign` answered with a prefix of a few hundred bytes and the client
  appended what it already held; W8 put the precompiled artifact in that prefix and W19 gave
  the other direction the same treatment, in the same frames and with the same slots and
  clocks (D28). The component still never travels outward.

  The same reasoning applies to everything else the SDK *says* about the node. A `Verdict`'s
  documentation of the untrusted narrowing and a `Check`'s "an empty reply is a pass" are
  claims about `provider/native/hooks.ex`, and a test that read them back out of the SDK's own
  reply would prove nothing about either. So `test/wasm/sdk_acceptance_test.exs` runs the built
  components through that module and asserts the decision it reaches — including the difference
  between the trusted and the untrusted lane, which is the shape a deleted narrowing would show
  up as.
- **D17 — a capability is reachable as a tool, and a description is deployment metadata.**
  Two decisions. The first is about *which* names; the second is about *when*.

  *Reachability.* The `capability` tool is a seam between two untrusted parties — the model
  and the component — so it is not a mesh client: only a `:live` lane-W entry that names
  this node is reachable, and the register is consulted again inside the tool. One function
  resolves a name, for classification and for execution, on the exact string the model
  wrote; nothing trims, because two normalisations are two names and the gap between them
  is a bypass. The permission rule is `Capability(<name>)` or `Capability(*)`, matched
  against a name the node resolved, which is what makes an *allow* on it honest;
  `Tool(capability)` is deny-and-ask only, because the tool is not the authority — one call
  reaches one component, and an allow on the tool name is an allow on every component this
  node will ever deploy. The mesh message itself stays unledgered per D11; the **tool call**
  is ledgered like every other, carrying the capability's name and the component's sha256,
  and that entry is therefore the whole written record that a model reached a component.
  `agents.message` is the operator's half of the same reach, at `:operate`, and it is
  deliberately not node-routed: the mesh already resolves an agent anywhere in the cluster,
  so a capability on a peer is reachable today and the boundary that makes that safe is the
  helper's linker.

  *When a description is read.* **At deploy, as a gate, and never on the message path.**
  `Ouroboros.Wasm.Rollout` runs one more gate after stage, probe and eval:
  `Wasm.Capability.capture_describe/2` on every target, on a throwaway instance under its
  own bounds, and the validated document is stored on the registry entry. A component that
  cannot describe itself inside the budget its own deploy gave it does not go live — the
  gate fails like any other, and the deploy is rolled back or quarantined.

  Since W15 that gate is capability-only, and the reason is what a description is *for*:
  contract C1's document exists so the `capability` tool can put a component's own claim
  about itself in front of a model, and a policy component is in no listing a model reads.
  Its `describe` still exists — the world declares it, and `ouro wasm policy` and `inspect`
  read it — but nothing on the node does, so a gate there would be a deploy failing over
  prose nobody will be shown. A policy rollout records `describe: :absent`, which settles as
  a pass rather than as the `:skipped` an earlier gate's failure leaves behind.

  It was on the message path, fetched after the first message, and that was wrong in a way
  only a clock reveals. The fetch is a synchronous pool round trip inside the caller's
  `Jido.AgentServer.call`, and `Rollout.Probe` gives its one message five seconds — so a
  component whose `describe` merely took six, while answering messages instantly and staying
  inside every bound it was deployed under, failed its own health check and was rolled back.
  A capability's liveness must not depend on how fast it can describe itself. Moving the
  read to the deploy puts the cost where taking time is already accounted for, gives every
  reader one source instead of a per-agent cache that only warms after somebody messages it,
  and makes a listing incapable of starting a component. The wrapper no longer calls
  `describe` at all.

  *What a description may contain.* Contract C1, plus a rule the first cut did not have:
  no character in Unicode category **Cc** (every C0 control, tab and newline included, DEL,
  and the C1 block), **Cf** (the zero-width set, the bidirectional overrides and isolates,
  the BOM) or **Zl/Zp**, in any string reached by walking the whole document — `name`,
  `summary`, and every string inside `examples` and `input_schema`. Those are the characters
  that let a component's prose stop looking like a component's prose: a newline puts its next
  sentence on a line of its own, and U+202E reverses what a human reviews relative to what a
  model reads. Refusing them is why the renderers only prefix a label and never have to
  escape anything. The register re-validates on write *and* on read, because a checkpoint is
  a file on disk and a planted summary's next stop is a model's context.

  Proved in `test/wasm/capability_test.exs` (the scripted helper, including a six-second
  `describe` that does not cost a five-second message), `test/wasm/capability_acceptance_test.exs`
  (the real guest), `test/wasm/rollout_test.exs` (the gate, and a deploy stopped by a
  description it could not read), and `test/upgrade/rollout_registry_test.exs` (stored,
  re-validated, refused on read).

    * **The budget is spent the way the node spends it.** `hooks_from/4` runs `build/4` over
      every entry and puts the failures in `errors`; only what survived reaches
      `cap_untrusted/2`. So an entry whose path does not resolve costs a repository *nothing*,
      where the first version charged it a slot — five typos could hide five good components
      behind a budget that was never really spent.
    * **`matcher` is reported, not guessed at.** It is a PCRE, `ouro` carries no regex engine,
      and adding one to decide a single TOML field would put a large dependency in the
      client's graph to answer a question the node answers anyway. The first version guessed
      with a parenthesis-balance check that was wrong in *both* directions: it passed
      `matcher = "*"`, which the node refuses, under a summary line reading "every component
      entry would be admitted" and an exit code of 0; and it refused `matcher = "\Q(\E"`,
      which the node compiles happily, because a quoted literal paren opens no group. What is
      decided here now is the 200-byte bound, exactly; the rest is printed as
      `matcher: unverified`, the summary reports counts of verified rows and unverified
      matchers, and the words "would be admitted" do not appear while any row carries one.
      Unverified is printed, never exited on: the exit code says *refused*, so an author who
      wired this into a pre-commit hook does not have it break on a pattern the node compiles.
- **D18 — a node may read the imports of bytes it built itself, and the build-time boundary
  is three checks and a kernel.** D15 says a node never parses unsigned bytes from a socket:
  `wasm.sign` takes the import list from the client, because pointing the helper at
  attacker-supplied input upstream of every trust check is the shape lane W exists to avoid.
  A forged component is the other case, and the difference is provenance rather than
  optimism. These bytes were produced *here*, by `cargo` this node spawned, from source this
  node validated, against a dependency set this node pinned, inside a sandbox this node
  applied — nobody else chose them. So `Ouroboros.Wasm.Forge` reads the import list with
  `Wasm.Pool.inspect/2` under the W7 bounds instead of asking a caller to declare it, which
  also removes the one thing a caller could have got wrong; and the list is still
  cross-checked at stage by `Wasm.Verifier.cross_check/2`, because the security boundary is
  the linker (D5) and stays there.

  What that provenance rests on is *build-time* code execution, and a Cargo project is
  arbitrary code at build time — build scripts, proc macros, `include!`. Three checks and a
  kernel:

    * **The lock pin.** `Cargo.lock` minus this project's own entry must be byte-identical to
      the SDK's resolved lock, so the crates, versions and checksums are the SDK's and the
      only proc macros that run are the ones `make wasm-sdk-check` already runs.
    * **The file allow-list.** `Cargo.toml`, `Cargo.lock`, `src/**.rs`, `README.md`, and a
      workspace proposal's `manifest.json` (bounded and path-checked, then left out of the
      build). No `build.rs`, refused by name *and* by refusing the `[package] build` key —
      one check without the other is not a rule, because `src/build.rs` is a path the
      allow-list admits and a `build` key is what would make it run. The manifest is read
      twice, by a scanner that refuses every line it cannot classify and by `Toml`, and the
      two must produce the same document: a hand-written scanner is precisely the thing an
      author would write a manifest to fool, so the disagreement is the refusal rather than a
      gap.
    * **The sandbox.** `Native.Sandbox` at `workspace_write`, writable only in the build
      directory and the cargo home, network denied, `--offline` and `--locked` besides, a
      five-minute ceiling and bounded output. A node with no backend refuses to build.

  **Reads are fenced too, and the first cut of this slice got that wrong.** It shipped the
  ordinary `workspace_write` policy, whose filesystem rules bound writes and open reads —
  what a shell needs — and argued in this decision that a `:forge` grant was therefore "no
  wider than a lane-B capability". It was not. That argument holds only for `modules: :any`;
  the narrow grant, the one an operator reaches for precisely because it is narrow, still
  yielded read authority over the whole node. An adversarial review proved it end to end: a
  component that `include_str!`s a planted secret was built, signed, deployed and **answered
  the secret through a mesh message**, and a build that included the real `~/.ssh/id_rsa`
  succeeded.

  A build now runs under `Sandbox.builder_policy/1`, which is `(deny default)` on reads as
  well as on writes. It is not a `sandbox_mode`: no session selects it, no operator
  configures it, and there is no spelling of it a signal can ask for. What a build may read
  is exactly this, and the fence is that there is no more:

    * the platform's own toolchain roots (`Sandbox.platform_readable/0`; on macOS
      `/usr/lib`, `/usr/bin`, `/usr/share`, `/bin`, `/System`, `/private/var/db`, `/dev`,
      `/private/etc`, `/Library/Preferences`, `/Applications/Xcode.app`), plus
      `file-read-metadata` on `/` — a compiler stats its way down a path before it opens
      anything, and a `stat` denial reads as a missing file rather than as a fence;
    * the **cargo executable's own directory**, because `process-exec` still has to read the
      binary, and with rustup that binary is a shim that execs another;
    * the **rustup home**, where the real compiler and everything it links live;
    * the **guest SDK checkout** and the **`wit` directory beside it**, because
      `wit_bindgen::generate!` reads `../wit` at macro-expansion time;
    * the **build directory** and the **cargo home**, which are writable and therefore
      readable, and a private `TMPDIR`.

  `Ouroboros.Wasm.Forge.read_set/2` is that list as one function, so "what can a build read"
  has one answer. `include_str!` of anything else, and a `#[path]` module outside the
  project, are `Operation not permitted` **at compile time** — proved by tests that assert
  the failure and, beside them, that the honest fixture still builds under the same policy,
  because a fence that broke the toolchain would pass the first assertion and be useless.

  What is still readable is the toolchain, the SDK **and the platform roots those lists
  name** — and the last of those includes `/etc`, on every backend. That was written here as
  "`/etc/ssh` … none of them are", and it was never true: an adversarial review put a file at
  `/etc/ouroboros/credentials` and a build read it. `/etc` stays, because a compiler that
  cannot read `ld.so.cache`, `passwd`, `localtime` and the CA bundle does not link; what
  changes is the sentence and the operator advice that follows from it — **anything secret
  belongs outside the platform roots**, which is where this runtime already puts its own
  (the node's data directory is not readable, and is where `wasm_forge_cargo_home` lives).
  The node's data directory, the operator's home, the workspace and another user's files
  are still outside the fence.

  On Linux the same policy is a bubblewrap namespace that binds *only* those roots rather
  than `--ro-bind / /`, and it is **verified**: `scripts/forge-linux-test.sh` runs the forge
  suites in a privileged Ubuntu 24.04 container (bubblewrap 0.9.0, kernel 7.0.14) and CI runs
  them on ubuntu-24.04. It was written blind first, and shipped wrong in the way writing a
  namespace blind is wrong: `/dev` and `/proc` were in the readable list, so the ro-binds
  built from that list landed *on top of* bubblewrap's own `--dev` and `--proc` and replaced
  a fresh devtmpfs with a read-only view of the host's. The first thing every build then did
  was fail to open `/dev/null`, and it died with `SIGABRT` and no output at all. Those two
  are the backend's to provide and are gone from the list.

  The two backends also refuse a read differently, and the difference is worth stating
  because a test that matched one string would have been a test that only ran on one
  platform. Seatbelt denies an `open` on a path that is there: `Operation not permitted`.
  bubblewrap never puts the file in the namespace, so the compiler is told
  `No such file or directory`. Both are the fence; only one of them is a permission error,
  and what the tests assert on both is the pair — the escape failed, and the honest fixture
  built under the same policy.

  `ouro-sandbox`, the backend this runtime prefers on Linux where it is installed, was the
  one without a fence: its request protocol had writable roots, protected roots and denied
  names, and no read allow-set. It has one since W17 (D26), and the forge now builds under
  it in the container — so what is refused is no longer a backend but a *binary*, the
  pre-W17 helper that still answers `doctor` and still has no `readable` field.
  `Sandbox.fences_reads?/1` therefore asks the probed helper rather than the backend name,
  and a node carrying an old one forges under bubblewrap or not at all.
- **D19 — a forge input is bounded before it is read, and a cold cache is a refusal.**
  Thirty-two files and one mebibyte, paths relative and free of `..`, no symlink followed,
  every bound applied *before* a byte is copied into the build directory. The numbers are the
  scaffold's shape with room to grow a module tree, and they are deliberately far below
  anything that could be a vendored dependency, a fixture corpus or a repository: this lane
  builds capabilities, and a capability that needs a thousand files needs a different lane.
  The point of bounding first is the ordinary one — a refusal that happens after the copy is
  a refusal that already wrote the files — and it is what lets the effect surface promise
  that an ungranted forge touches nothing, since the grant is checked before the closure runs
  at all.

  The cache is the other half of it. `--offline` means the build cannot fetch, so every crate
  the SDK's lock names must already be in `$CARGO_HOME/registry/cache` before a forge starts.
  `make wasm-sdk-cache` (`cargo fetch --locked` in `tui/wasm/guest`) warms exactly that set,
  and `CARGO_HOME=` points it at a node-local cache instead of the operator's own. A cache
  missing one crate is **a refusal naming it**, checked before cargo is spawned — 8 ms on
  this Mac, against a build that takes ten seconds — rather than a fetch, a hang, or a
  resolver error somewhere inside a subprocess. The crates it checks for are parsed out of
  the SDK's own embedded lock, so a dependency the SDK adds is a crate the cache has to hold
  and there is no second list to keep in step.

  The cargo home is *writable* inside the sandbox, which is the one place this fence is wider
  than the build directory: cargo extracts `.crate` files into `registry/src` and takes a
  lock file, and a read-only cache is a build that cannot start. What makes that acceptable
  is the lock pin — nothing untrusted runs at build time to abuse it.

  **And whose directory it is decides who runs code inside the build.** A cargo home carries
  `config.toml`, and `[build] rustc-wrapper` in one is a program cargo runs on every crate it
  compiles. `~/.cargo` is a directory a great many things write to, so the default is
  node-local — `<data_dir>/wasm/cargo-home`, which is what `make wasm-sdk-cache` warms — and
  neither `$CARGO_HOME` nor the operator's own home is consulted unless an operator names one
  with `config :ouroboros, :wasm_forge_cargo_home`. A node with no data directory has nowhere
  to keep a cache and says so rather than falling back to somebody's.

  **Two ceilings, and the smaller one has to be the forge's.** The forge's own is five
  minutes and is enforced by `Ouroboros.Provider.Native.Exec`, which signals the sandboxed
  process group and lets the `after` that removes the scratch tree run. The effect surface
  has a second one, `config :ouroboros, :effect_timeout`, and it is not a deadline of the
  same kind: the runner ends an overrunning effect with `Task.shutdown(task, :brutal_kill)`,
  and a killed process runs no `after`. A forge cut there left its build tree on disk and a
  cargo process group still compiling inside it — which is why
  `Ouroboros.Agent.Effects.ForgeWasmCapability` asks for a build budget strictly inside the
  effect's, the same idiom `DelegateTask` uses against the same deadline, and why the test
  for it asserts `pgrep` finds nothing rather than only that the refusal has the right name.

  **`:any` does not cross the lanes.** `Ouroboros.Control.Grants` holds `"wasm/<name>"` in a
  `:forge` allow-list, and it would have been easy to let `modules: :any` cover those too —
  it reads as the broad grant, and this is the broad case. It must not, and the reason is
  that a grant is a durable checkpoint: an operator wrote `modules: :any` when the only thing
  *forge* could do was compile a BEAM module, and a release that made their stored grant also
  mean "build and sign any component this machine can" would have widened their authority
  without them touching it. `:any` keeps its pre-W14 meaning; lane W is reached by
  `"wasm/<name>"` for one capability or `"wasm/*"` for all of them, which is how the broad
  thing gets said out loud.

  **Where a forge runs was placement and is now also a check (D29).** Until W20 nothing here
  read a node's role: a forge ran where the effect landed, an operator who wanted a dedicated
  builder put the toolchain, the warmed cache and the `:forge` grant on that node, and saying
  `:builder` in a sentence about this lane described a deployment. Most of that still holds —
  `:local` is still the default and is still what the paragraph above describes — but one half
  of it was a gap rather than a posture: a `:signer` node, the one machine in a fleet that must
  never run arbitrary code at build time, would forge on request like any other. It refuses now,
  unconditionally, and `config :ouroboros, :wasm_forge_placement: :builder` is the opt-in that
  turns "put the toolchain over there" into routing. D29 is the whole of it.
- **D20 — a policy component may narrow, and may only widen where an operator said so.**
  `Ouroboros.Wasm.PolicyEngine` reaches a signed policy component only on `{:ask, :no_rule}`,
  which is every call `Control.Permissions` had no rule for. Its `deny` stands; its `ask`
  stands and is the question the node was already going to ask; its `allow` is honoured only
  for the tools named in `config :ouroboros, :policy_allowable_tools`, which is empty by
  default. Everything else is `ask`: a trap, a deadline, a refusal to link, a component this
  node cannot load, a verdict that is not JSON, a `decision` outside the three words, a request
  too large to hand over whole, no policy configured, a configured policy that is not a live
  entry of kind `:policy`. **No failure mode of the engine produces an `allow`.**

  The allow list is the part worth arguing, so here is the argument. A hook is dispatched for
  the events its `matcher` matched; a *policy* component is asked about **every** call the
  rules did not decide, which is most of them. An `allow` honoured unconditionally from one
  would therefore be a blanket approval channel with a signature on it — and a signature in
  this lane is provenance, not trust (D5). D8 already says an untrusted hook's `allow` is read
  as silence; this is the same sentence for a component that is asked far more often, with the
  one escape an operator can open tool by tool because they are the authority that a `read` is
  fine to resolve automatically and this node is not.

  **Determinism is a property of the world, not a rule this seam enforces**, and the difference
  matters. What the world guarantees is that there is nothing to be nondeterministic *with*: one
  import, so no clock, no randomness, no filesystem, no network. What it does not guarantee is
  that a given component is a function of its request — the engine keeps one long-lived instance
  per component sha, so a component that holds state can answer two identical requests
  differently, and nothing here stops it. Three things stand in for enforcement: the world's
  poverty, the signed eval spec, which exercises whatever the author is willing to assert about
  their own component at deploy on every target, and the fact that the only verdict a stateful
  drift could turn into authority — `allow` — is the one an operator has to list a tool for. The
  standing proofs are of the stateless example rather than of every component: the same request
  answering the same across two instances, in Rust against the real helper
  (`the_same_request_yields_the_same_verdict_on_two_instances`) and in Elixir against the real
  deploy (`test/wasm/policy_acceptance_test.exs`).

  **One reading of a verdict.** A verdict is an object with exactly `decision` and `rule`,
  neither key repeated, `decision` one of three lower-case words, `rule` a string, the whole
  document ≤ 1 KiB. Strict because there are two readers: Elixir's decoder keeps a duplicated
  key's first occurrence and `serde_json` keeps its last, so one component could show an operator
  one word and hand the node another. `test/support/wasm_golden/policy_verdicts.json` pins both.

  **One decision, bounded.** `config :ouroboros, :policy_decision_timeout_ms` (5 s) bounds the
  whole decision, enforced by the engine in a process it can kill, because the round trip goes
  through the node's one shared sequential pool and sits in front of every undecided tool call.
  Expiry is `ask`, the instance is dropped, and only `unknown_instance` is retried — a blanket
  retry doubled the wait a wedged helper cost.

  **An honoured verdict is one the ledger holds.** `Control.Permissions`' rule, unchanged: an
  `allow` whose entry cannot be written is `{:ask, :unrecordable}`, because an approval nobody
  can account for has not been granted; a `deny` stands, because refusing without an audit entry
  is still refusing and downgrading it would be the one thing this lane never does.

  What a component sees is bounded and **never truncated**. The request document is the
  normalised `Control.Permissions.Request` — tool, mode, the command and paths and domains
  under `input`, the principal, the workspace root, the context keys — with credential-shaped
  *keys* and well-known *token shapes* redacted (`Bearer` runs, AWS key ids, `sk-…`, GitHub and
  Slack prefixes, PEM blocks, `NAME=value` where the name is credential-shaped, and this node's
  own environment secrets). That last pass is a heuristic and is documented as one: a credential
  in no recognised shape reaches the component, and has to, because a policy that may deny
  `curl` needs to read the `curl`. A document over 64 KiB is not sent at all: the engine answers
  `ask` instead. A policy shown the first four kilobytes of a command line is a policy an
  attacker pads past, and a partial view is worse than no view because it produces a confident
  wrong answer. Non-scalar `context` values are dropped and the dropped keys are named, so what
  was withheld is visible to the component rather than silent.

  The record is the ledger's. An honoured verdict is written through
  `Control.Permissions.record/2` with `actor: :classifier` — the slot `permissions.ex:92`
  reserved and nothing occupied until now — and a `rule_ref` carrying the component's sha and
  the rule string. A degraded verdict writes nothing: the node is about to ask a human, and
  that is where the record belongs. The rule itself is untrusted text and is treated as such:
  200 characters, no control or format character, labelled `[untrusted policy component]`
  everywhere it is read.

- **D21 — two closed worlds in one helper, one linker, and the kind is signed.**
  `ouro-wasm` implements `ouroboros:capability@0.1.0` and `ouroboros:policy@0.1.0`. They
  declare the **same single import** and differ in one export — `handle-message: func(string)
  -> result<string, string>` against `evaluate: func(string) -> string` — so containment is
  unchanged by there being two of them: one linker, one host function, and a component that
  wants a clock is refused by name whichever world it was offered as.

  What the second world buys is not authority, it is *identity*. A capability answers messages
  from the mesh and from the `capability` tool; a policy answers permission requests and is
  reachable by neither. Those are different enough jobs that being able to deploy one as the
  other is a defect: a component a model can send strings to and a component that decides
  whether the model may run `rm` should not be interchangeable by an operator's typo.

  So the kind is **in the signed manifest**, not a deploy-time flag. `Wasm.Artifact` carries
  `kind: :capability | :policy`; `Wasm.world_for/1` derives the world from it so the two halves
  cannot disagree; the signer refuses a pair that does; `Wasm.Verifier` refuses it again on the
  loading node; and `Wasm.Rollout.stage/3` hands the manifest's kind to the helper's `load`,
  which checks the bytes against *that* world. A `:policy` manifest over a capability component
  is `unsupported_world` at stage, before the register is marked and before anything is
  instantiated. Signing it rather than configuring it also makes the derived facts follow: a
  policy declares no `start` block, and its eval spec is a list of decision cases rather than a
  probe list over agent state.

  **Where the kind is read, and what that reading is worth.** The rollout records it on the
  register entry, from the manifest it has just verified, and `Rollout.live/1` filters on that —
  which is an *index*, not a proof. A checkpoint is a file on disk: anything that can write one
  can write a row whose `artifact_id` names a genuine policy manifest and whose
  `component_sha256` names other bytes in the store, and the engine loads the row's sha. So
  `Ouroboros.Wasm.PolicyEngine` re-establishes the chain before it loads anything: it fetches
  the manifest the row names, verifies it against **this node's own** trust policy, and holds
  the manifest's sha to the row's sha and its kind to `:policy`. A mismatch, or a manifest this
  node cannot verify, makes the engine inert for that name with one logged warning. An earlier
  cut read the kind from the manifest and the sha from the row without ever comparing them,
  which is the planted-row hole exactly; the fix is not "read it from the signed side" but "tie
  the two together at the point of use".

  Which world a set of bytes is checked against is therefore always the *caller's assertion*,
  never something the helper infers — and a set of bytes has exactly one world to be asserted
  about. Extra exports are otherwise fine, but the *other* world's message export with the
  other world's signature is not an extra export, it is a second claim: a component exporting
  `handle-message` and `evaluate` with both signatures would have been legal in both worlds, so
  which one it *was* depended on which request arrived first, and one sha would have stood for
  two things. `check` refuses such bytes as ambiguous whichever world they are offered as
  (`bytes_that_claim_both_worlds_are_refused_as_ambiguous`), the cache hit is per-world so a
  capability re-offered as a policy is re-read and refused rather than answered out of the
  table, and `instantiate` re-asserts the world so a `load` as one and an `instantiate` as the
  other cannot dispatch against a table nobody checked these bytes for. The two worlds differ in
  exactly one type, so that type is the whole of the distinction: an `evaluate` returning
  `result<string, string>` is not the policy world's `evaluate`, and is refused by name.

  One SDK builds both. `tui/wasm/guest` invokes `wit_bindgen::generate!` twice, and
  `pub_export_macro` keeps each world's encoded custom section inside its own `export!` macro —
  so the macro an author calls, `export_capability!` or `export_policy!`, is what decides which
  world the finished component implements, and a crate cannot claim both by linking the SDK.

- **D22 — what is signed is both forms.** The manifest gains
  `precompiled: %{wasmtime: "<exact version>", target: "<triple>", sha256: "<of the serialized
  artifact>", size: <bytes>}` beside the source component's own sha256, and the bundle carries
  both sets of bytes in two length-prefixed sections. A node admits the precompiled form only
  when its **own** helper's `doctor` reports exactly that version and exactly that triple and
  its own store holds the artifact and the operator has not refused the form
  (`accept_precompiled`); otherwise it compiles the source form under §7.3's bounds, so there is
  no regression for a node that cannot use it — and if the helper then refuses the artifact
  anyway, the source form is loaded rather than the rollout quarantined (D24). The comparison is string equality on
  both halves and nothing cleverer: wasmtime's serialized form is checked against an exact
  build and an exact configuration hash, so "close enough" is not a judgment anybody here is
  entitled to make. `component_sha256` remains the identity — the register, the ledger, the
  labels and the helper's cache key are all unchanged (D2) — and the artifact's digest is
  provenance about a *form*, not a second name for the thing.

- **D23 — compilation runs where the signature is made, after the request has been admitted.**
  `Wasm.Deploy.sign/2` compiles on the node that builds the manifest, with `ouro-wasm
  precompile`: the same binary, the same `Engine` (there is one `host::engine()`, shared by
  `serve` and `precompile`, because a second configuration would be a second world — an
  artifact `precompile` produced that `serve` could not map, discovered at the far end of a
  deploy), and the same structural bounds. It applies §7.3 in full before it compiles: a
  component past a bound is refused at sign time with the same name a node's `load` would have
  used, and so is one that is not in the world it was offered as.

  **The order is half the decision.** The signer is the machine that pays for compilation, and
  it pays only for a requester the rate limit admitted and a manifest the policy accepted —
  `Signing.Service.admit/4` first, on the source manifest, journaled; the compile second; the
  signature third, on a single-use ticket that charges no second slot (D15). Running the compile
  first made the expensive half free to exactly the callers the limiter exists to refuse.

  The compile itself is bounded by §7.3 and not by a timer, which is worth stating rather than
  implying: `shape::check` refuses an expensive shape *before* cranelift starts, because
  cranelift cannot be interrupted once it has. The 30 s the signing node waits stops it
  *waiting*; it does not stop the compile, and it does not need to.

  Its scratch is this node's own — `<data_dir>/wasm/sign/`, created 0700 and held to `lstat`,
  files 0600 — and never a shared `/tmp`, because what is written there is every component a
  client uploads and the machine code compiled from it, and a root under `/tmp` is a directory
  somebody else may have created or symlinked first. A node with no data directory does not
  precompile, which is `Wasm.Store`'s posture for the same reason.

  Skipping is an answer, never an error: no helper on disk, no data directory, a scratch root
  this node will not use, a helper that refuses or does not answer in time or whose report does
  not describe what it wrote, `--no-precompile`, or an artifact too large to travel in the
  receipt. Each one is named in `precompile_skipped`, the receipt says `form: "source"`, and
  each leaves exactly the source-only path lane W already had.

- **D24 — what `deserialize` trusts is the signature, and nothing in the file.**
  `Component::deserialize` is `unsafe` because wasmtime does not validate a serialized artifact
  against a malicious producer: the bytes are machine code and a relocation table, and mapping
  hostile ones is mapping hostile code. So a node deserializes only bytes whose digest is in a
  manifest a trusted signer signed, read from its own content-addressed store, and never bytes
  that arrived any other way. `load` says so structurally: `precompiled: true` is a parameter
  the owner has to assert, it carries both digests, and every check runs in front of the
  `unsafe` block — the digest the manifest named, the container this build wrote, the wasmtime
  and the triple, and the source component the manifest is about. The container is this repo's
  own eighteen-byte framing around wasmtime's output, for one reason: wasmtime checks its own
  compatibility *inside* the unsafe call, and "deserialize it and see what the error says" is
  the order W8 exists to avoid. `world::check` then runs on the deserialized component exactly
  as it does on a compiled one — a form of the bytes is not an exemption from the linker's
  contract — and the refusal for everything else is one name, `precompiled_mismatch`, because
  the answer to all of them is the same: use the source form, which every node can compile.
  That fallback is carried out rather than promised: `Wasm.Pool.load_component/4` is the one
  place a lane-W load happens, and a `precompiled_mismatch`, `sha_mismatch` or
  `unreadable_component` on the artifact loads the source form under §7.3's bounds with one
  logged line saying why. `Store.precompiled_path/2` re-reads the digest before offering a file
  at all, because for an artifact "the name of a file is its content" is load-bearing in a way
  it is not for a component: a rotted component is refused by the helper before anything is
  compiled, and a rotted artifact would be *mapped*.

  **And the residual, in the words it deserves. A compromised signing key now escapes the
  fence.** Before W8 a signer this node trusted could place a *component* on it — bytes
  wasmtime validates, a linker that defines one function, fuel and an epoch deadline and a
  memory ceiling, every one of §7.3's bounds. After W8 the same key can place an **artifact**:
  machine code in an object file, mapped by `Component::deserialize`, which wasmtime does not
  validate against a malicious producer. A thousand bytes patched into its `.text` executes with
  the helper's own authority — measured, on this build, as a SIGILL in the helper process from a
  1 KiB patch that passed the digest, the world check and `Wasm.Verifier.cross_check/2` because
  all three read the *header* and the component type, not the code. So §12's old sentence that
  signer custody is "unchanged by this spec" is false, and this is what changed: the signature
  was always the boundary for *what* a node runs, and it is now also the boundary for *how*.

  Four things bound it and none of them makes it safe. The helper is a separate process, so
  what a patched artifact reaches is a Port and a pool cooldown rather than the node (D3) — and
  since W16 that process runs **inside an OS sandbox** (§7.3a, D25), so within it a patched
  artifact has the platform's toolchain roots, this node's component store, the forge's build
  directory, a scratch it may write and no network at all, rather than everything the daemon's
  user can reach. What that is *not* is validation: the machine code still executes,
  with the helper's own authority, and the wall is around it rather than in front of it. A node
  that cannot apply the wall runs no helper at all, which is D25's whole shape. The artifact is content-addressed and re-digested on every load, so
  tampering *after* signing is refused. `config :ouroboros, :wasm, accept_precompiled: false`
  takes the form away fleet-wide, with no redeploy and no resigning, for an operator whose key
  custody is in doubt. And the source form is always there: a node that refuses artifacts is a
  node that compiles, which is exactly what every node did before W8.
- **D25 — a node that cannot fence its helper is a node that does not run wasm.**
  `config :ouroboros, :wasm, helper_sandbox:` defaults to **`:required`**, and everything about
  this decision is in which way that default falls. The helper holds machine code a signer
  produced (D24) and bytes a repository nobody trusts wrote (D8); it is the one process in this
  runtime whose job is to hold somebody else's code. So the wall around it is not an
  optimisation a node offers when it happens to have a backend — a node with no backend, a
  backend that cannot fence reads (`Sandbox.fences_reads?/1`, contract C11), or no data
  directory to put a private scratch in **refuses to spawn one**, reports `:broken` with
  `{:helper_sandbox_unavailable, reason}`, and says so in `wasm.status`. The alternative — spawn
  it plain and log a line — is the shape this repository has refused everywhere else it has come
  up: `read_only` without a backend is a refusal because a read-only label the shell can step
  out of is a lie about the label, and a forge on a node with no backend does not build. A
  contained helper that is not contained is the same lie with a different noun.

  `:off` exists, is spelled once, and is an operator's statement rather than a fallback this
  code takes on its own: it spawns plain, reports `posture: :off`, and logs one warning per
  spawn. It is for a platform this runtime cannot sandbox and an operator who has read this
  decision. Nothing in the code path can reach it by accident, because there is no path from a
  failure to it — a failure under `:required` is a refusal.

  The policy is `Sandbox.helper_policy/1`, which is `builder_policy/1`'s shape with a scratch
  attached, and its mode is **`:builder`** on purpose: `:builder` is the backend vocabulary for
  "closed by default on reads", all three backends already implement it, and there is still no
  helper arm. What differs between a build and a helper is the lists and — since W21 — the
  **process posture**, and both are arguments (contract C10): `loopback` is a field of the
  policy since W16 and `process` is one since W21, and the Seatbelt profile is a function of
  the policy's fields. The sentence that stood here until W21, that a helper-specific profile
  would be "a fourth profile to keep in step with three others", was wrong for exactly that
  reason: there never was a fourth profile to write, because the profile was already computed
  from the fields the moment `loopback` joined them, and sealing the process cost a fourth
  field and a handful of measured lines, not a fourth text.

  The lists are the whole of it, so they are narrow and they are stated. Readable: the platform
  roots, the helper's own directory, this node's **component store**, the forge's build
  directory, and a vetted `helper_readable`. Not `<data_dir>` — the signing journal, the grants,
  the permissions and the effect ledger live there. Not `<data_dir>/wasm` either, which was the
  first cut's answer: that subtree holds the upload staging area, the sign scratch, the forged
  bundles and the forge's cargo home, and a cargo home's `config.toml` on a builder can hold a
  credential. And not the node's **workspace roots**, which the first cut did name because lane
  H read its hooks out of a repository; `Native.Hooks` stages those bytes into the store now, so
  the lane costs the fence nothing. Writable: a per-child scratch and nothing else. Network:
  none, loopback included — the helper speaks stdio, and a loopback socket is every service on
  this machine.

  The fence is stated twice for the reason the forge's is not: a forge refuses without a
  backend, but the pool has callers on every lane, so the rule "a load names a file in this
  node's own roots" is enforced by the pool *and* by the kernel. A `load` or an `inspect`
  outside the readable roots is `{:refused, :path_outside_roots}` before a frame is built. One
  of the two walls is this node's own and holds wherever it runs.

  **What the wall closes on macOS since W21, and what it still does not, named.** Until W21
  the `:builder` profile left four things open that D25 listed as residuals: `process-exec`
  over the readable `/usr/bin` and `/bin`, `mach-lookup`, `sysctl-read`, and
  `file-read-metadata` over all of `/`. The helper's policy is now **sealed** as a process
  (`process: :sealed`, §7.3a), and each of the four was measured shut under the real
  `helper_policy/1` with the builder policy as the other half of every pair: `bash -c 'exec
  /usr/bin/id'` is `Operation not permitted` sealed and prints a uid open; a `$(…)` is `fork:
  Operation not permitted`; `osascript -e 'do shell script "id"'` — the exact escape the old
  paragraph named — fails sealed even as the target itself, because the scripting addition
  behind `do shell script` is a mach service and a fork away, and prints the uid open;
  `pbpaste` exits 1 sealed and 0 open; and `test -e` on a planted file outside the roots is
  absent sealed and present open, while `stat` inside a readable root still works. What
  remains, named. The helper may exec **itself** — its own resolved path is the one literal —
  so a compromised helper can re-exec `ouro-wasm`, which buys it the same process it already
  is. It may read every `sysctl` under `hw.`: a hardware fact — page size, CPU count, the
  optional ISA features cranelift detects — and not a secret, and the prefix rather than a
  name because `hw.pagesize_compat` alone was measured to change the artifact `precompile`
  emits. It may `stat` the root directory itself. And the two Linux backends do not seal at
  all: inside a bubblewrap namespace `/usr/bin` is readable and executable, so a compromised
  helper there can exec within the namespace (no network, read-only roots, nothing but the
  roots bound, `ENOENT` elsewhere), and Landlock does not fence `stat`, so `ouro-sandbox`
  keeps the existence oracle that bubblewrap — nothing bound, nothing to stat — does not.
  `LANDLOCK_ACCESS_FS_EXECUTE` is the follow-on that would close the exec half on
  `ouro-sandbox`; it is not in this slice, which changes no Rust. A node on either backend
  reports `sandbox.process: "open"` rather than claiming a seal it did not apply, and is
  **not** refused: `:required` means what this decision says — reads and network fenced — and
  the process posture is a third question, `Sandbox.seals_process?/1`, that the status
  answers and the pool does not gate on. What the wall closes is therefore the filesystem —
  the operator's home, `/etc/ssh`, the node's own data directory outside the store, every
  repository it serves — the network, and on macOS the process: those are the reaches D24's
  residual was about, and the machine code still runs.

- **D26 — a read allow-set is a list the daemon widens, and a read denial is Landlock's
  alone.** D18 fenced a build's reads on two backends and refused the third by name, because
  `ouro-sandbox`'s wire format had no way to say what a build may read. It has one now:
  `mode: "builder"` and `readable: [...]`, and the three rules around it are what make the
  field a fence rather than a hint.

  **The daemon widens; the helper never does.** Every root a build can read is one the node
  put in the list — `Sandbox.builder_policy/1`'s `platform_readable/0` plus
  `Wasm.Forge.read_set/2` — and the helper adds nothing of its own except `/dev` and `/proc`,
  which it keeps writable in *every* mode and which a compiler cannot start without. An entry
  that is not absolute is refused with exit 125 rather than resolved against a working
  directory the policy is about to change. And an empty `readable` is an empty read set: not a
  missing one, not a reason to fall back to `/`. Under such a policy `/bin/sh` is not
  executable and the helper's own `execvp` fails, which is the strongest form the rule takes —
  it applied a policy it could have called too narrow to be meant.

  **The read fence is Landlock's alone, and that is this backend's shape rather than an
  omission.** bubblewrap builds a fresh root and simply does not bind what a build may not
  read; `ouro-sandbox` stays in the host's own path namespace, because it has no root to mount
  a placeholder into and would litter a workspace with empty directories if it tried
  (`plan.rs`). A mount can make a path read-*only*. Nothing in a mount can make it unreadable.
  So the write half stays doubly fenced — the writable roots are bound first, everything that
  existed before is swept read-only, and Landlock grants writes on exactly what the mounts
  left writable — and the read half is one layer, the LSM, which cannot be left and governs
  mounts created after it was installed.

  **Which means a builder read denial is `EACCES`, and that is legible here and nowhere
  else.** `Sandbox.violation/3` refuses to read `Permission denied` as a sandbox signal, and
  that rule does not change: it reads the output of an opaque shell line, where an ordinary
  file mode produces the same string and attributing it to the sandbox would be a guess. A
  build is the other case. It is one program this node spawned, with a policy this node wrote,
  from source this node validated — so the forge's own suite matches `Permission denied` for
  this backend the way it matches `Operation not permitted` for Seatbelt and
  `No such file or directory` for bubblewrap, and beside each of those it asserts that the
  honest fixture still builds under the same policy. Three strings, one fence, and the pair of
  assertions is what tells a fence from a broken toolchain.

  **A read fence is not a write fence, and the first cut of this decision confused the two.**
  The mount half of a shell policy keeps `/dev` and `/proc` writable on purpose — a shell
  needs `/dev/null` and its own `/proc/self` knobs, and this helper has no fresh root to
  mount minimal ones into. The builder inherited that, so it inherited the host's `/dev/shm`:
  an adversarial review wrote `/dev/shm/pwned` and read a canary another process of the same
  uid had left there, which is a bidirectional channel to every process on the node out of
  the one policy whose claim is that what a compiler carries into its output is bounded. A
  builder now keeps nothing writable that the policy did not name. `/dev/null` is granted by
  name — a Landlock rule on the file, so it governs that node and grants nothing else in a
  `/dev` the builder has no rule for, which is the same single node
  `Sandbox.SandboxExec`'s builder profile grants and for the same reason. `/dev/zero`,
  `/dev/urandom` and `/dev/random` are readable for `getrandom`'s fallback. `/proc` is
  readable and not writable. `/dev/shm` and `/dev/mqueue` get a fresh **read-only** tmpfs, so
  the host's segments are gone rather than merely refused — which is what bubblewrap gets
  from mounting its own `/dev`, arrived at from the other side. There is no `/dev` listing at
  all.

  **What the fence does not do, said once here so it is not discovered later.** It does not
  keep an operator's secret out of a build if that secret is under a platform root: `/etc` is
  in the read set on every backend, because `ld.so.cache`, `passwd`, `localtime` and the CA
  bundle are what a compiler opens before it compiles anything, and a planted
  `/etc/ouroboros/credentials` was read by a build under all of them. The advice is the
  ordinary one and it is an operator's to take: keep credentials outside the platform roots.
  And it does not hide existence. Landlock governs `open` and `readdir`, not path resolution,
  so `stat` succeeds on anything the ordinary permissions let a process walk to: a build can
  learn that a file is there, how big it is and when it changed, without reading a byte of
  it. `SandboxExec`'s builder profile grants `file-read-metadata` on `/` for exactly that
  reason — a compiler stats its way down a path and a `stat` denial reads as a missing file —
  so the two backends have the same oracle, deliberately, and only bubblewrap's namespace,
  which never held the path at all, answers `ENOENT`.

  **A root that is a symlink is the thing it points at.** Landlock opens a rule's path with
  `O_PATH` and follows it, and Seatbelt's `subpath` resolves the same way, so a `readable`
  naming a link would fence *its target* under a name that does not say so. Two halves:
  `Sandbox.builder_policy/1` canonicalises every root it names, and the helper refuses a
  `readable` entry that is still a symlink rather than following it. The second half is there
  because the first can fail — `Workspace.Path.canonicalize/1` returns an error rather than a
  path in one case this slice found — and a policy whose text and whose effect disagree is
  the shape this whole decision exists to refuse.

  **And the capability is asked of the binary, not of the backend's name.** An `ouro-sandbox`
  installed before this slice speaks protocol version 1, applies every shell policy correctly,
  and would refuse `readable` as an unknown field — which is the right refusal and arrives too
  late, at the first build a node tries. So `doctor` reports
  `"features": {"read_allow_set": true}`, `Helper.probe/1` turns that into `read_fence` in the
  detection map, and `Sandbox.fences_reads?/1` reads it for `:ouro_sandbox` alone. A detection
  with no such key at all — an old cache, a hand-built map — is `false`. Failing closed there
  costs a node its forge; failing open would cost it the fence the forge's claim rests on.

- **D27 — one setting names the permission engine for every seam, and no engine failure
  widens anything.** `config :ouroboros, :permissions_engine` was read by the native loop, by
  the interactive plane's external approvals and by the interactive shell (which asks
  `Approvals.permissions_engine/2` for it). `Ouroboros.Control.Permissions.Seam` — the ACP lane,
  which is both the `session/request_permission` a vendor process sends and the
  `fs/write_text_file` and `terminal/create` an agent asks *this runtime* to perform — called
  `Control.Permissions` by name, so a node that named `Wasm.PolicyEngine` had a policy on three
  of its four seams and §8.2 said so. It now evaluates, records and suggests through the named
  module, with `Interactive.Task.Approvals`' tolerance copied verbatim: `{:allow, ref}`,
  `{:deny, ref}` and `{:ask, reason}` pass through, an answer in none of those shapes is an ask,
  an engine that raises is an ask (the `rescue`), and an engine that exits is an ask (the
  `catch`) — each clause load-bearing on its own, and a `throw` swallowed by neither, exactly as
  in `Approvals`.

  **The invariant, stated precisely, because the first wording of it was wrong.** *No engine
  **failure** widens anything here*: every way of not answering — an unrecognised shape, an
  exception, an exit, a module that is not loaded or does not export what C13 asks for — lands
  on the ask the human was always going to see. What an engine **does** answer is the engine's
  own authority, exactly as it is on the other three readers: `{:allow, ref}` is honoured, `ref`
  and all, including `{:allow, nil}` for a tool nobody listed, and this seam adds no gate on top
  of it. That is deliberate. The bound on an untrusted component's `allow` is `PolicyEngine`'s
  `:policy_allowable_tools`, empty by default (D20); a second, invisible gate at the seam would
  be a refusal an operator could find in neither place, and it would not be reached by the other
  three consumers anyway.

  `remember/4` and `forget_session/1` stay on `Control.Permissions`. They are rule-store
  operations rather than decisions: C13 asks an engine for `evaluate/1`, `record/2` and
  `suggest/1` and for nothing else, and an engine that wrapped the store would have to
  reimplement scopes, session forgetting and `permissions.add` to be asked for them. **So is the
  pattern a `:session` answer is remembered as**, and that one is a correction rather than a
  convenience: this seam writes a durable `:allow` row, and an engine whose `suggest/1` answered
  `Bash(*)` would have turned one human's yes to `ls -la` into a session-wide allow for every
  shell command. The row is phrased by the store that will match it,
  `Control.Permissions.suggest/1`; the engine's `suggest/1` phrases the `suggested_rule` hint on
  an ask, which is a string a client renders and nothing enforces.

  A refusal names the same rule the native loop names. `Seam.refusal/1` flattened anything that
  was not a rule map into "refused by a permission rule" — and a `PolicyEngine` deny is exactly
  that: a sentence naming the component, its sha and the `[untrusted policy component]` label. A
  binary passes through now, and both clauses are bounded at 400 **graphemes** and stripped with
  the engine's own character class (`\p{Cc}\p{Cf}\p{Zl}\p{Zp}`, which `\p{C}` alone would leave
  U+2028 and U+2029 out of), because both carry somebody else's text into a JSON-RPC error a
  client renders. The wording still differs from `deny_message/2`'s — "refused by …" against
  "Refused: permission rule … denies … for this session.", clipped against unbounded — because
  one is a frame a client draws and the other is a tool result a model reads; what is the same
  is the rule they name.

  **What is still not covered.** Nothing on this lane by dialect:
  `Ouroboros.Provider.Session.Dialect` has exactly one implementation, `Dialect.ACP`, and a
  second would reach the same three functions. Two residuals are older than this slice and are
  restated rather than removed. `fs/read_text_file` is not gated on ACP at all —
  `Session.Service` calls `decide_service/3` from its write and terminal paths only, so an
  agent's read of a workspace file reaches the filesystem without a permission question, which
  the native lane's `Read` does not. And plan mode's pre-engine refusal
  (`Provider.Native.Permissions.planning_refusal/1`) is native-lane only: an ACP session in a
  planning posture is not refused writes by that mechanism.

- **D28 — a node hands back what it made, in the frames it was handed things in.** W8 put the
  precompiled artifact into `wasm.sign`'s reply, because the client holds the component and has
  never seen the artifact, and then bounded it at three quarters of the gateway frame and
  dropped anything larger. The ceiling was honest and the reasoning behind it still holds: one
  JSON-RPC reply is not a file transfer, and the answer to bytes that do not fit a frame is the
  one D16 already gave — cut them into frames that do. W19 is that reasoning carried to the end
  rather than a reversal of it.

  `Ouroboros.Wasm.Download` is `Ouroboros.Wasm.Upload` read backwards, and deliberately not a
  second design: `<data_dir>/wasm/download/` created 0700 and held to `lstat`, a slot claimed
  `O_CREAT|O_EXCL` whose file *is* the claim, an id minted here as sixteen random bytes and
  re-validated as `[0-9a-f]{32}` on the way back in, 0600 files, and the slot count and both
  clocks read from `Upload` rather than restated. `wasm.download {download, offset}` is
  `:operate` and node-routed, like the upload it mirrors. A slot line carries the digest and the
  chunk, so every answer repeats the *whole* artifact's sha256 without re-hashing eleven
  mebibytes per frame and a transfer's boundaries are fixed when it is minted, and the slot
  rather than the file is the authority: bytes whose slot the clocks took are not a download,
  whatever is still lying under their name.

  **The chunk is the one number that could not be inherited, and the review is why.** The first
  cut took the upload's 512 KiB as well, and said a node whose frame could not carry one
  "refuses the frame before this module sees it". Both halves were wrong. `Gateway.Conn` sets
  `packet_size` on the socket it *receives* on and nothing holds an outbound reply to
  `max_frame` at all; and an upload's chunk is the **client's** to size, while a download's is
  the **node's** and is always maximal. A node with a 64 KiB frame answered `wasm.download`
  with a 699 260-byte line — measured, not reasoned about — which a client mirroring its
  advertised frame reads as `FrameTooLarge`. That is not a corner: lowering `max_frame` is
  exactly what pushes an artifact onto this path in the first place. So the chunk is
  `min(Upload.max_chunk_bytes(), (max_frame − 1 KiB) × 3/4)` — three quarters for base64, a
  kibibyte held back for the JSON object around it, which measures 208 bytes on this build —
  fixed in the slot at mint time so a setting changed mid-transfer cannot move a boundary out
  from under a client. Below four kibibytes `put/2` refuses by name and the signature falls back
  to the source form. At the default mebibyte frame the upload's number is the smaller of the
  two and nothing changes.

  **A read moves the idle clock, and that is not the upload's rule.** An upload's mtime moves
  because bytes arrive; a download is written once and then only read, so leaving the idle clock
  to the file measured *time since minting* under another name — a client walking a large
  artifact was reclaimed mid-transfer at ten minutes, and the thirty-minute lifetime could not
  be reached by any sequence of calls. `read/3` touches the file. Idle now means ten minutes
  with nobody reading, and the lifetime is what bounds a client that reads one chunk every nine
  minutes forever.

  **What a sign costs this node's heap.** `read_artifact/1`'s cap rose from three quarters of a
  frame to `Bundle.max_precompiled_bytes/0`, because the reply's number is no longer what an
  artifact has to fit inside. So a `wasm.sign` of a worst-shape component holds its artifact in
  the BEAM's heap while it is written to a slot — up to 64 MiB per concurrent signature, and the
  eight slots bound the concurrent case at eight times that. That is a real number and it is
  stated rather than implied; §12 counts the disk beside it.

  **What makes it safe is what it will not do.** There is no verb that *puts*. The only caller
  of `put/2` is `Wasm.Deploy.sign/2`, handing over an artifact this node's own helper compiled
  from a component this node's own signing service has just signed — so a node hands out only
  bytes it made, under `:operate`, bound by a digest that is already inside the signed manifest,
  and never a byte a client sent it. The slot is claimed **before** the manifest is signed,
  which is what keeps the W8 fallback intact: a node with no data directory or with its eight
  slots already spent signs the source form and says `artifact_not_staged`, rather than signing
  a manifest declaring an artifact nobody can fetch. Offsets are chunk boundaries below the
  size and not a seek, because a client walks the file with the offsets the node's own answers
  give it and anything else is a client that has lost its place.

  **Reading the final chunk releases the slot**, and the alternative was reasonable enough to
  say why. The verb's parameters are closed at `download`, `offset` and `node`, so there is no
  frame in which a client says "done" other than the one where it asks for the last chunk; a
  slot held to its clocks after a finished transfer is ten idle minutes of a ceiling of eight
  (thirty for a client that keeps reading and never finishes), and eight of those make the
  ninth signature fall back to the source form until one of them expires. The
  cost is the other end of it and is not hidden: a client that loses that last answer cannot ask
  again and signs again instead, paying a compile and a rate-limit slot. Everything else is what
  the clocks are for.

  What the client does with it is a concatenation, not a composition: `prefix <> artifact <>
  component`, in the order the header's three lengths already fix, checked against the size and
  the sha256 the receipt named before a file is written. `Bundle.prefix_without_artifact/2` is
  the seam that makes it byte-identical to `Bundle.encode/3` — `prefix/2` is *defined* as that
  followed by the artifact, so the two cannot drift — and `test/wasm/deploy_test.exs` pins the
  equality against a real signed artifact travelling over the real verbs. Proved there and in
  `test/wasm/download_test.exs`: chunks that reassemble to the byte, an offset off a boundary or
  past the size or naming an unknown slot each refused by name, a slot past either clock gone
  for a reader too, the ninth `put` refused, files 0600 and roots and staged files never
  followed through a symlink, and no lane-W verb minting a slot whatever it is handed.

- **D29 — a `:signer` never builds, and `:builder` is opt-in routing rather than a default.**
  D18 said role was placement and not a mechanism in this lane, and it was half right. The half
  that was a gap is now closed: `Ouroboros.Wasm.Forge` refuses `{:forge_refused, :signer_node,
  …}` when `Ouroboros.Cluster.role/0` is `:signer`, before a byte of the input is read and
  whatever `config :ouroboros, :wasm_forge_placement` says. The argument is one sentence. A
  Cargo build is arbitrary code at build time by construction (D18, D19) and the three fences
  around it are containment, not proof; a signing key is the thing that makes bytes admissible
  on every node that trusts it. Running the first beside the second is a bet on the fences, and
  the fences were never offered as a bet. There is no configuration that turns this off, because
  an operator who could turn it off is a misconfiguration away from having done so.

  The other half stays placement, and stays `:local` by default. `:local` forges where the
  effect lands, which is what this lane has always done and what a single-machine operator
  wants: the toolchain, the warmed cache and the `:forge` grant are already there, and a
  default that forwarded would make a one-node fleet refuse to do something it can do.
  `:builder` is the fleet-shaped answer: a forge that lands on a non-builder node is forwarded
  by `:erpc` to a connected `:builder`, carrying the same input, the same attrs and the same
  server-owned principal, under the origin's own build budget so the builder's configuration
  cannot widen it. Everything the builder then does is its own — its sandbox backend, its
  cargo home, its role check, its signing service — which is the point of moving the build.
  With no builder connected it refuses `:no_builder_node` by name and does **not** fall back to
  building here, because building here is precisely what the setting was chosen to prevent. A
  setting that is neither word is refused for the same reason: reading `:buidler` as the
  default would build on the node the operator was moving the build off.

  A builder never forwards again. `forge/2` decides and `forge_here/2` builds, which is
  `Ouroboros.Upgrade.Forge.BuildPeer`'s split for the same reason, and the far end never asks
  the placement question with a setting that could forward — so the role check runs there too,
  on the machine that will actually run the compiler, and no option a caller writes can turn
  that entry point back into a dispatcher.

  **The project travels; a path never does.** The origin collects and validates C9 itself and
  what crosses the wire is that validated inline map — at most 32 files and a mebibyte, every
  path relative, no symlink followed, the lock pinned, the manifest read twice. The builder
  re-validates it, because this node is not an authority on that one. The first cut forwarded
  the caller's input verbatim, and the only production caller
  (`Ouroboros.Runtime.Capabilities.admit_lane/2`) passes a **directory** — an absolute path
  this node canonicalised on its own filesystem. Three things followed and all of them were
  wrong: `capabilities.admit` under `:builder` placement could not work at all, a directory
  the builder happened to keep at the same path would have been built and signed under the
  origin's principal, and the builder's own refusals — `enoent`, `eacces`, `not_a_directory`,
  `symlink_refused` — came back to an `:operate` client as a filesystem oracle for a machine
  they had not asked about.

  **The attrs travel and nothing else.** An allow-list — `:author`, `:name`, `:eval`,
  `:start_config`, and the two deadlines below — rather than a filter, because the list of
  options that are facts about *this* machine is the one that grows. A `signing_service`, a
  `cargo_home`, a `pool` or an `sdk_path` that rode along would make "everything the builder
  does is its own" false in the direction nobody notices, because it would still work.

  **The bundle comes back as bytes, and the origin is the node that keeps it.** A forwarded
  forge writes nothing durable on the builder: the `.ouro-wasm` travels in the reply, bounded
  by `Wasm.Bundle.max_bytes/0`, and the origin retains it in its own forged root — so the
  receipt a forwarded forge answers with is deployable by `Forge.deploy/3` exactly as a local
  one's is. Without that the receipt named a file on another machine and both consumers, the
  operator's `capabilities.admit` and the agent's `DeployWasmCapability`, answered
  `{:forged_bundle_unreadable, :enoent}`.

  **And the origin verifies what came back, because it never saw what was signed.** This is
  the trust an operator extends by turning `:builder` on, stated plainly. A peer's role is
  that peer's own claim, answered over the distribution handshake (`Cluster.local_posture/0`);
  the lowest node name wins deterministically; and the node so chosen receives the source of
  every capability this fleet forges and produces the bytes the fleet's signer then signs
  under the **origin's** principal. The origin never sees those bytes before they are signed.
  So the trust is exactly two things — cluster membership, and that builder's own sandbox —
  and naming builders is delegating the forge to whichever member claims the role. What the
  origin can still check, it does: `Bundle.verify/2` against **this** node's trust policy
  (signature, and both forms bound to their own digests), the kind, the name, the author —
  which must be the server-owned principal it sent — and that the receipt describes the bundle
  beside it. A bundle is precisely the thing `Bundle.verify/2` exists for, and a forwarded
  forge is the one place in this lane where a node deploys something another machine produced.

  **Three deadlines, each strictly inside the next.** Cargo gets `budget - 2 * slack`, the
  builder's whole `forge_here/2` gets `budget - slack` in a task it can stop, and the origin
  waits `budget` — which is itself inside the effect runner's own ceiling, because
  `ForgeWasmCapability` asks for `Runner.timeout() - 5 s` (D19). The first cut had the origin
  waiting `budget + 10 s`, which is *past* the runner's brutal kill: the caller was cut down
  five seconds before its own transport gave up, and the builder went on compiling, signing,
  spending an epoch and retaining a bundle for a request that had already reported
  `{:effect_timeout, …}`. The builder is *told* both numbers rather than left to re-derive an
  arithmetic whose meaning is the origin's. An expiry sweeps the build directories that
  appeared while the task ran, because `Task.shutdown/2` runs no `after`; it does not have to
  kill a process group, because cargo's own ceiling is strictly smaller and
  `Ouroboros.Provider.Native.Exec` signals that group at it.

  **The decision is a pure function, and that is not tidiness.** `placement/3` takes this
  node's role, the setting, and the connected nodes with the roles `Cluster` reports for them,
  and answers `:local | {:forward, node} | {:refuse, reason}`. A decision taken inside the build
  path is one nobody can ask about without running a build, and this is a decision an operator
  needs to be able to ask about: `capabilities.preview` reports it, and a preview on a node that
  would refuse says so and does not dry-build. The fleet is read only where the answer can
  change — `:local` needs no probe — because `Cluster.nodes_by_role/1` is a five-second
  multicall and putting one in front of every default forge would be a cost no decision depends
  on. The forward target is the lowest node name among the connected builders, so the choice is
  pinned rather than "whichever peer answered first".

  **Two costs, stated.** `capabilities.preview` is an `:operate` verb and now asks the
  placement question, so on a node configured `:builder` it fans out `Cluster.nodes_by_role/1`
  — an `:erpc` multicall bounded at five seconds — once per preview. That is bounded and it is
  not free; under `:local`, the default, no probe happens at all, which is why the fleet is
  read only where the answer can change. And a node where this runtime never started reports
  `:core` (`Cluster.role/0` falls back to configuration and then to `:core`), which is the
  open direction: such a node forges rather than refusing. It is acceptable here because that
  fallback cannot make a *signer* look like a core node — `config :ouroboros, :node_role` is
  what `boot_role!/0` reads and what the fallback reads, so a signer misreports only if its
  configuration says it is not one — and because every check that consumes a role also requires
  the target to be running this runtime.

  What this is **not** is a boundary against a hostile node. `Ouroboros.Cluster`'s own "Limits"
  section says it: any node that completes the distribution handshake has full `:erpc` authority
  over every other, so a compromised peer ignores every check here by calling `forge_here/2`
  directly — and a compromised *signer* does not need to build at all. What the check stops is
  the accident and the misconfiguration: an effect landing on the key-holding machine, a fleet
  where the builder role was set up and the builds still ran on the core node. Contract C14.

- **D30 — engine-embedding guests stay refused, and `wasi:io` is not admitted to any world.**
  §12 has said since W8 that a JavaScript or Python guest was "one decision away", and named
  the decision without making it. It is made here, in the negative, and the reasons are the
  ones this lane has answered every other widening with. Both worlds import exactly `log`
  (D5), and the helper's linker refuses everything else by name (`world::check`); that refusal
  is the containment claim, and it is what W16's OS sandbox is a second wall *around*, not a
  replacement for. `wasi:io` is not one import: it is pollables and streams whose semantics
  `wasmtime-wasi` implements against real descriptors, and every runtime that wants it wants
  `wasi:clocks` and `wasi:random` beside it — a clock alone breaks the determinism D20 requires
  of a policy component, and the host half would put a second, larger dependency inside the
  helper that D24 already describes as trusting compiler output. Nor does W8 change the
  arithmetic: an engine is millions of code bytes against a 4 MiB cap that now applies at the
  signer, and raising the cap for one kind of guest is a signing-policy widening for every
  guest. What a capability author who wants a scripting language does today is write the
  capability in Rust against the SDK (W9) and keep the script as *data* the capability
  interprets, which is the shape the lane was built for. The decision is revisited only when
  all three are true: a capability an operator needs that cannot be written that way; a
  `wasi:io` implementation in the helper whose every stream is memory-backed and whose every
  pollable resolves without a clock, so that the world stays deterministic and the host reaches
  no descriptor; and a separate signed `kind` with its own cap and its own trust policy, so
  that admitting one engine admits nothing else. None of the three exists, and this spec does
  not schedule them.

## 12. What this does not solve

Stated once, so nobody reads more into the lane than is there:

- **Judgment.** The permission engine still decides; a prompt-injected model still
  emits hostile effect *requests*. Wasm bounds what granted authority can reach, it
  does not improve the grant decision.
- **The host functions are the new surface.** Every import added to a world is
  boundary code. v1's answer is austerity: `log` only. Growth of any world's import
  set is a signing-policy event, not a convenience.
- **A forge's read fence now covers all three backends, and each of them refuses a read in
  its own words.** A build reads only the roots in D18's list, and what remains readable
  inside that list is the toolchain and the guest SDK, which have to be readable for a
  compiler to run. What each backend does with the rest, and where it was watched doing it:
  **Seatbelt** denies an `open` on a path that is there, so the compiler is told
  `Operation not permitted` — observed on macOS, by `include_str!` of a planted secret and a
  `#[path]` module outside the project failing to compile beside the honest fixture that
  builds under the same policy. **bubblewrap** never binds the path into the namespace, so
  the compiler is told `No such file or directory` — the same two tests, observed in a
  privileged Ubuntu 24.04 container on kernel 7.0.14 and on CI's ubuntu-24.04.
  **`ouro-sandbox`** stays in the host's own path namespace and fences reads with Landlock
  alone, so it answers `Permission denied` (`EACCES`) — the same two tests, in the same
  container, under the backend this runtime actually prefers on Linux (W17).

  Three things that fence does **not** do, each proved rather than supposed. It does not keep
  a secret an operator left under `/etc`: the platform roots are inside the allow-set on every
  backend, `/etc` is one of them because a compiler needs `ld.so.cache` and the CA bundle, and
  a planted `/etc/ouroboros/credentials` was read by a build. Keep credentials out of the
  platform roots. It does not hide *existence*: a read fence governs opening a file, so
  `stat` still succeeds on any path the ordinary permissions let a process walk to, and a
  build can learn that `/home/someone/.ssh/id_rsa` is there and how big it is without reading
  a byte — Seatbelt's profile grants `file-read-metadata` on `/` deliberately for the same
  reason, and only bubblewrap, whose namespace never held the path, answers `ENOENT`. And it
  is not, by itself, a bound on *writes*: W17's first cut left `ouro-sandbox`'s builder with
  the host's `/dev` and `/proc` writable, and a build wrote `/dev/shm/pwned` and read a
  canary another process of the same uid had left there. That is closed — a builder gets
  `/dev/null` by name, `/proc` read-only, a sealed tmpfs over `/dev/shm`, and nothing else —
  and it is written here because the sentence "writes only into the build directory" had been
  true of the intent and not of the kernel.

  What is *not* covered is a helper binary older than the allow-set: it applies every other
  part of the policy and has no `readable` field, so the forge asks the helper rather than the
  backend name (`doctor`'s `features.read_allow_set`) and refuses that node by name.
- **Engine-embedding guests are still out, and W8 removed only the first precondition.**
  A JavaScript or Python guest carries an engine, which is millions of code bytes and far past
  §7.3's 4 MiB — a bound that now applies at the *signer* rather than at every node, which is
  what made it a precondition. The second is a world broad enough for `wasi:io`, which those
  runtimes want at instantiation, and that one is a signing-policy decision rather than an
  engineering one: every import added to a world is boundary code, and this lane's answer has
  been austerity. W8 does not admit them and does not bring them closer than one decision away.
- **wasmtime is a dependency, not a proof.** It has had escape CVEs; they are rare and
  patched fast, and the helper process — since W16 an OS-sandboxed one (§7.3a, D25) — is the
  second wall. What that wall bounds is what an escape reaches: the platform's toolchain roots,
  this node's component store, the forge's build directory, a scratch, and no network — not
  loopback either, which is what the first cut of that wall left open.
  What it does not do is make an escape not an escape. Pin it, watch its advisories, and keep
  its dialect small — §7.3's disabled proposal list is surface removed from cranelift, not just
  from the spec.
- **A precompiled artifact is bound to one wasmtime and one triple, and that is the
  lane-B triple problem arriving by another road.** W8 removes the compile from a node's hot
  path only for nodes whose build is the signer's, byte for byte in two strings. A fleet
  running two wasmtime versions gets the fast path on the half that matches and the old path
  on the rest, and a fleet on two architectures needs two signings or accepts the source form
  on one of them. That is stated rather than solved: the alternative — admitting an artifact
  a node's own engine did not vouch for — is the one thing D24 exists to refuse. What the
  design does buy is that the failure is a *fallback*, named in a log line and in
  `wasm.list`'s `form`, rather than a refusal an operator has to diagnose.
- **The artifact reaches an operator in frames, and a node with nowhere to stage one still
  falls back.** This used to say the artifact reached an operator only when it fit one reply.
  W19 built the chunked download that sentence named as the proper fix: past three quarters of
  the gateway's configured frame the signer mints a `Wasm.Download` slot and the receipt names
  it, so the fast form is no longer a function of how large a capability's machine code happens
  to be. What is left is smaller and is still real. A node with no data directory, or already
  holding its eight slots, cannot stage an artifact it cannot fit in a reply, and signs the
  source form with `precompile_skipped: artifact_not_staged` — which is the right fallback and
  is still a fallback. A transfer whose final frame is lost cannot be resumed, because that
  frame released the slot, so the client signs again. And the 512 KiB chunk is `wasm.upload`'s,
  which means a node whose operator set `OUROBOROS_GATEWAY_MAX_FRAME` below what one chunk
  needs can no more download than it can upload.

  And the eight slots are a **shared** ceiling with no per-requester share. An `:operate` client
  may sign eight large capabilities and simply not fetch them, and for the ten idle minutes that
  follow, every other signer on that node — including a different operator — gets the source
  form with `artifact_not_staged`. Nothing here rations: the signing service's rate limit is
  thirty a minute *per requester node*, which bounds how fast the slots can be taken and not who
  holds them, and `:operate` is a scope this lane already trusts to deploy signed bytes and stop
  live capabilities (D15), so a client that wanted to degrade a node has cheaper ways. What
  bounds it is the two clocks and nothing else, the cost is a fallback rather than a refusal —
  the capability still deploys and still runs, compiling on each node as it always did — and
  saying so is better than implying a fairness this has none of.
- **Two forms are two ceilings, and both are staging.** A bundle now carries a component and an
  artifact, so `Wasm.Upload` sizes a slot at `Bundle.max_bytes/0` — 16 MiB of component plus
  64 MiB of artifact plus the envelope, and eight slots in flight. That is 640 MiB one
  `:operate` client can park on a node's disk, up from 128 MiB, and it is stated here because
  D16's "never more than a signer would look at" now needs the second half spelled out: the
  artifact ceiling is **four times** the component ceiling, which clears the worst measured
  ratio (2.75× at the shape §7.3 admits) with half again to spare, and is capped by what
  `ouro-wasm` will read. It was eight times, which put a slot at 144 MiB and the eight of them
  at 1152 MiB, and nobody had chosen that number.

  W19 added a **second** staging area on the same node and this number has to count it: the
  download area holds up to eight artifacts at `Bundle.max_precompiled_bytes/0` each, which is
  another 512 MiB at the default ceilings, for 1152 MiB of staging in total. It is reclaimed by
  the same two clocks and, like the upload area, **by no timer** — every sweep happens inside
  somebody else's call, so eight abandoned artifacts sit there until the next `wasm.sign` or
  `wasm.download` on that node, which on a quiet one may be a long time.
- **And `store_budget_bytes` now has to hold both forms of anything live.** The component store
  keeps the artifact beside the component for every rollout that carried one, and a prune may
  not evict either while the rollout is `:live`, `:deploying` or `:quarantined`. So the
  512 MiB default is a budget over roughly 3.75× the component bytes a fleet deploys rather
  than over the component bytes alone; an operator who sized it by counting components will
  find it tighter than they meant. Pruning still fails closed, so the failure mode is a store
  that stays over budget rather than a capability that loses its bytes.
- **The compile bound is a bound on admission, not a theorem about compile time.**
  §7.3's structural pass bounds what the helper will hand to cranelift, and the worst case
  it admits was measured at 1.19 s on this Mac. Cranelift's cost is not a function of
  those counts alone — a single function of pathological control flow can cost more than
  its bytes suggest, and a future wasmtime may cost differently — so the honest claim is
  that the worst admissible input is bounded and measured, and that the measurement is due
  for a re-run whenever the pin moves.
- **And the bound is calibrated on the cheapest bytes there are.** The at-bound figure
  comes from a synthetic component of 20 000 straight-line arithmetic functions: 4.0 MiB
  in 1.16 s, about 0.29 s per mebibyte. Real compiler output is denser per byte —
  StarlingMonkey's 9 224 567 code bytes compiled in 8.61 s, roughly a second per
  mebibyte, some 3.3× the synthetic rate. So a real engine-dense guest sitting exactly at
  the 4 MiB bound would cost **≈4 s, not ≈1 s**, and the sequential helper would be gone
  for all of it. The bound still holds — nothing is admitted past 4 MiB — but the sentence
  "the worst case is about a second" is true only of the shape it was measured on. Due for
  re-calibration against a real engine-dense guest whenever the numbers move.
- **Refusing a disabled proposal can still cost a compile.** A component using, say,
  `return_call` is refused by the engine, but the refusal arrives from cranelift's
  translator rather than from a pre-pass, so a large module can be compiled up to the
  offending function before it is rejected. Bounded by §7.3's structural pass, not by
  zero.
- **The helper is sequential, and a tool call spends it.** One `ouro-wasm` per node serves
  every capability and every workspace hook, one request at a time. A `capability` tool call
  therefore holds the node's whole containment lane for as long as the target's deadline
  plus the pool's call margin, and a workspace hook that fires meanwhile waits behind it.
  The bound is real — the call returns a tool error rather than hanging the loop — but the
  *cost* is not bounded away, and it is stated in the tool's own description so a model can
  weigh it against a cheaper tool before spending it. A concurrent helper, or one per lane,
  is a later decision and not this one.
- **`describe` is prompt-injection surface, and labelling is the whole defence.** A
  component's `describe` is untrusted text authored by the thing this lane exists to
  contain, and it reaches a model beside the node's own trusted facts. Four things bound it
  and none of them makes it safe: it is refused above 4 KiB *before* it is decoded; it is
  closed to the six keys contract C1 names and its `examples` to two, so a component can
  supply content but never structure; every string in it is refused if it carries a
  character in Unicode category Cc, Cf, Zl or Zp, so it cannot stop looking like one
  component's prose; and every line of it that reaches a reader is prefixed
  `[untrusted, authored by the component]`. What remains is that a model may still be
  persuaded by 200 characters of a component's prose — labelling tells it who is speaking,
  it does not decide for it. The registry's own facts — name, epoch, sha256 — are rendered
  separately and are never mixed into the labelled half.
- **A listing is bounded and says so; the register is not.** `capability list` renders at
  most 50 capabilities, so a large fleet cannot spend a context window on a directory, and
  the heading says when it cut. The cap is on the *listing* only: `resolve/1` reads the
  whole register, so a capability past the cut is still callable by name. There is no cap on
  how many a node may hold.
- **A worker's mailbox is bounded, which means a mailbox is not a history.**
  `agents.message` lets any `:operate` client on any node in the cluster put a 64 KiB body
  into an agent, so `Ouroboros.Agent.Worker` keeps the newest 64 messages and at most 1 MiB
  of them. `messages_received` still counts every one; the bodies of the old ones are gone.
  Nothing in this runtime reads the inbox as an audit trail — the effect ledger is that —
  but a caller that assumed otherwise would now be wrong.
- **The helper's fence is a wall, not a validator; on macOS it is a wall around the process,
  and on Linux a filesystem-and-network wall only.** W16 puts `ouro-wasm` behind
  `Sandbox.helper_policy/1` (§7.3a, D25), which bounds what a compromised artifact or an
  escaped guest *reaches*: the platform's toolchain roots, the helper's own directory, this
  node's component store, the forge's build directory, a scratch the node created `0700`, and
  no network at all. W21 seals the process on Seatbelt: exec only itself, no fork, no
  `mach-lookup`, `sysctl` under `hw.` only, no `stat` outside the roots — so `osascript`'s `do
  shell script` no longer escapes, the pasteboard and launchd are out of reach, and a path
  outside the roots is absent rather than probable. Three honesties. The machine code still
  runs — the wall is around the process, not in front of the bytes, and D24's residual is
  unchanged in kind. The two Linux backends cannot express the seal: a compromised helper under
  bubblewrap can exec what is bound into its namespace, and under `ouro-sandbox` can `stat`
  anything, because Landlock does not fence `stat`; such a node says `sandbox.process: "open"`
  in `wasm.status` and is not refused, since `:required` means reads and network. And
  `helper_readable` is a widening knob, though a vetted one: `/`, a non-directory, and any
  ancestor of the data directory are refused, and one bad entry rejects the list.

- **The workspace.** §10 is the axis for `bash`/git/LSP; nothing in lanes W/H/T
  touches it.
- **Signer custody, and what W8 added to it.** A signer is still a cluster member reachable by
  `:erpc`; `Control.Grants` is still one process per node. Those are unchanged by this spec and
  still on ARCHITECTURE.md's external list. What is **not** unchanged is what a compromised
  signing key reaches: before W8 it could place a contained *component* on every node that
  trusts it; since W8 it can place an **artifact**, which is machine code `Component::deserialize`
  maps without validating, running with the helper's own authority rather than inside the
  guest's fence. Measured: a 1 KiB patch in a legitimate artifact's `.text` passed the digest,
  the world check and the manifest cross-check and executed in the helper. The mitigations are
  in D24 and none of them is a fix: the helper is a separate process and, since W16, an
  OS-sandboxed one — a second wall around a process that maps unvalidated machine code, which
  bounds what a patched artifact *reaches* and not whether it runs (§7.3a, D25) — the artifact
  is re-digested on every load so post-signing tampering is refused, and
  `config :ouroboros, :wasm, accept_precompiled: false` takes the form away fleet-wide without
  a redeploy. The trade is real and it is an operator's to make.
- **A forwarded forge is proved across two VMs on one host, and not across two machines.**
  W22's `test/wasm/forge_two_node_test.exs` watched a `:builder`-placed forge cross real
  distribution: the origin is the test VM in the `:core` role, the builder and the signer are
  full-application peer VMs booted with their own `config :ouroboros, :node_role`, the fleet is
  read off `Ouroboros.Cluster.nodes_by_role/1` and the call is made by the real `:erpc` — no
  `:peers`, no `:rpc` seam, and no option on the origin that names a peer. What crossed the
  wire was the project map and the bundle bytes. The builder built with its own cargo home and
  its own helper pool, asked the signer peer's own named `Ouroboros.Upgrade.Signing.Service`
  — which journaled the signature under the builder's name and never the origin's — and kept
  nothing: no bundle anywhere under its data directory, no forged root, an empty build scratch.
  The origin verified the bytes against its own trust policy and deployed them to `:live`. The
  signer refused `forge_here/2` and `forge/2` over the wire without creating a build
  directory; a fleet with no builder was refused before any RPC; a build the builder could not
  finish came back as the builder's own `{:build_failed, {:timeout, :deadline}}` inside the
  origin's budget, its scratch swept; a builder VM stopped mid-cargo answered
  `{:forge_forward_failed, builder, {:error, "…noconnection…"}}` within seconds of dying rather
  than after the budget, and no compiler of its outlived it. Three honesties. It is **one
  host**: both VMs share a kernel, a toolchain, a sandbox backend and a filesystem — the test
  reads the builder's scratch directory from the origin's side — so a different kernel, a
  different cargo, a different sandbox backend and a bundle the builder produces that the wire
  will not carry are unwatched, and CI's Linux job running the same file on one Linux host is
  the other half of the same limit, not a second machine. The epoch was allocated by the builder
  over the origin's rollout plane alone, because `Ouroboros.Wasm.Deploy`'s plane probe excludes
  a node that runs no register — the signer and the builder itself — and that is read from the
  code and observed as a signature that was issued rather than as a number the test pinned. And
  the first run found W-F31: a `:builder` node had no helper pool and could not finish any forge.

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
  which only a broken transition causes. W4's interim answer was the pool's per-lifetime budget of
  16 hook shas; W6 makes the helper evict (§7.3) and keeps the budget as a bound on churn
  — scoped to `lane: :untrusted_hook`, so a repository's components are budgeted and the
  operator's node- and user-scope hooks are not, and counted on the helper's `{:ok, _}`
  rather than at admission. `wasm.status`'s `hook_components` therefore counts budgeted
  untrusted shas, not every hook component the helper holds.

The W7 review wave (2026-09-02) found the rest. All fixed in W7, W-F26 included — the
re-verification pass found it last, and it closed in the same wave.

- **W-F5 (HIGH):** `Wire.dump/1`'s struct clause matched every map carrying an atom
  `:__struct__`; `%{1 => 2, __struct__: :ok}` raised and `%{__struct__: :ok}` lost its key
  kind under a signature. Reachable from a signed manifest's `test_report`, and the raise
  came out of `Registry.persist/2` outside the one rescue, killing the register. Struct
  form now requires a loaded struct module and an exact field set; encoding moved inside
  the rescue.
- **W-F6 (HIGH):** `start.id` bound to the `wasm/` prefix only, so a signed component
  could claim a durable id it does not describe (§7.5 check 6).
- **W-F7 (MED):** the register never re-validated loaded entries; a planted epoch refused
  every future deploy and a legacy id spelling a word took the whole register down (§7.6).
  The first fix re-ran `deploying/2`'s validators on read, which dropped a *malformed*
  plant and not a well-formed one — `fetch_epoch/1` took any positive integer, so an entry
  at 10^15 still refused every deploy (W-F26). Closed by a ceiling derived from the
  allocator: `Epoch.next/2` is a counter, so a number above 10^14 was not minted here.
- **W-F8 (MED):** the lane-W epoch watermark was derived from surviving entries, so prune
  could lower it (§7.6 step 2). Making it durable introduced the mirror failure — a
  checkpoint with no entries and only a planted watermark refused everything with nothing
  to delete — which the same ceiling closes on read, with a warning.
- **W-F9 (MED):** a local gate deadline skipped probe/eval cleanup, leaking the throwaway
  agent and its helper instance (§7.6).
- **W-F10 (doc lie):** `wasm/rollout.ex` claimed `:erpc.call/5` kills the peer process; it
  demonitors and stops waiting.
- **W-F11 (MED):** `test_report`/`detail` reached the checkpoint unbounded.
  **W-F12 (MED):** the signing rate limit ran after the expensive refusals.
  **W-F13 (MED):** a 6 KB `test_report` collapsed the journal's findings.
  **W-F14 (LOW-MED):** manifests were unbounded on write and outside the prune budget.
  **W-F15 (LOW):** duplicated imports passed the signer.
  **W-F16 (LOW):** `Surface.name_of/1` raised on a tampered module, and
  `wasm.status`/`wasm.list` exposed absolute paths under `:read` (now basenames).
- **W-F17 (CRITICAL class, pool):** `Wasm.helper_path/0` — and the desktop and sandbox
  resolvers — walked six ancestors of the daemon's cwd for the helper binary, so a cloned
  repository could supply the containment boundary itself. Removed; explicit environment
  and configuration overrides must also be absolute.
- **W-F18 (CRITICAL, pool):** a caller-chosen `limits.deadline_ms` reached
  `Process.send_after` unvalidated and crashed the pool, escalating through
  `Wasm.Supervisor`; reachable via a remote `Mesh.start_agent` of the wrapper. Limits are
  range-checked and every timer interval clamped.
- **W-F19 (HIGH, pool):** the wrapper trusted `:pool`, `:store_root` and `:limits` from
  `initial_state` — GenServer-call injection, unsigned bytes from any readable directory,
  self-granted maxima. Validated (§7.2).
- **W-F20 (MED, pool):** the helper's environment filter was a deny-list regex that
  inherited `RELEASE_COOKIE`, `AWS_ACCESS_KEY_ID`, `SSH_AUTH_SOCK` and `DATABASE_URL`; now
  an allow-list (§7.3).
- **W-F21 (HIGH, hooks):** a shared 16-sha hook budget let an untrusted clone silence the
  operator's trusted `deny` hook and fail open, and refused loads counted against it;
  scoped to `lane: :untrusted_hook`, counted on success.
- **W-F22 (HIGH, hooks):** untrusted `[checks]` output reached the model unlabelled and
  the check name unclipped; the untrusted label was per string, not per line; the
  `PostToolUse` payload handed an untrusted guest every tool's full output. §8.1/D8.
- **W-F23 (HIGH, CI):** CI never built the helper, so 25 acceptance tests skipped green on
  every PR; the Elixir job now builds helper and guest and runs under
  `OUROBOROS_REQUIRE_WASM=1`.
- **W-F24 (HIGH, helper):** compilation was unbounded — tens of seconds for a 61 MiB
  in-world component, a node-wide stall (§7.3). **W-F25 (MED, helper):** engine proposals were not
  minimized (relaxed SIMD, tail calls and the rest were accepted) (§7.3).

- **W-F26 (real, MED; fixed):** the register's re-validation on read (W-F7's first fix)
  rejected *malformed* entries only. A well-formed entry carrying an implausible epoch —
  `999_999_999_999_999`, which no `Upgrade.Epoch.next/2` could ever mint, since it
  allocates one above a durable watermark — passed `fetch_epoch/1`'s "positive integer"
  check, was folded into `lane_w_epoch`, and refused every subsequent lane-W deploy on that
  node for **every** module, because the gate is register-wide and not per-component. W-F8
  made the watermark durable, which is right for replay defence and meant this survived
  deleting the entry that planted it. Closed by `@max_plausible_epoch` (10^14) in the
  register: `fetch_epoch/1` refuses above it on both the write and the read path, and
  `watermark/1` ignores an implausible mark with a warning. That closes the two
  *unrecoverable* shapes; it does not make a tampered checkpoint safe — a plant at a merely
  large epoch still gates until the operator deletes the entry, which works again precisely
  because the watermark can no longer be poisoned above the ceiling in its place.

- **W-F27 (HIGH; fixed):** marking a replacement live superseded the old entry before the
  fixed start id was reclaimed, so every started same-name upgrade quarantined itself. A
  holder is replaced only when the registry proves it is that superseded predecessor.
- **W-F28 (HIGH; fixed):** the replay watermark lived only on the driver; a different core
  could replay an older signed component to the same targets. Every target now durably and
  atomically admits the epoch before staging bytes.
- **W-F29 (MED; fixed):** a remotely seeded non-integer `messages_received` raised outside
  the wrapper's rescue, making every message look successful while recording nothing. The
  counter is normalized at use.
- **W-F30 (MED; fixed):** relative helper overrides still resolved from cwd after the
  candidate walk was removed. Wasm, Computer Use and sandbox overrides now require absolute
  paths.
- **W-F31 (HIGH; fixed in W22):** a `:builder` node could not finish a lane-W forge.
  `Ouroboros.Application`'s `:builder` tree was cluster formation alone — the honest minimum
  for a lane-B build peer — and `Ouroboros.Wasm.Forge.forge_here/2` reads the imports off the
  component it just built through this node's helper pool (D18), so every forge forwarded to
  a real builder ran a whole cargo build and then came back `{:forge_refused_by, builder,
  {:imports_unreadable, {:pool_unavailable, {:noproc, …}}}}`. W20's loopback could not see it:
  its builder was the origin's own VM, whose pool the test had started. Watched on the first
  run of `test/wasm/forge_two_node_test.exs`. `Ouroboros.Wasm.Supervisor` now starts on a
  `:builder` too; the pool is lazy and owns nothing durable, so the role's posture is
  unchanged. Regression: the same file boots a `:builder` peer without a toolchain and reads
  its supervision tree — exactly cluster formation and the wasm supervisor — and a `:signer`
  peer runs no pool at all.

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
  at debug; W4's hook budget stays as a churn bound. Since W7, CI's Elixir job builds both
  halves (`make wasm`, `make wasm-guest`) and runs W2–W6's acceptance suites under
  `OUROBOROS_REQUIRE_WASM=1`, where a missing helper or guest is a failure rather than a
  skip — before that, twenty-five acceptance tests skipped green on every PR (W-F23).
- **W7 — the compiler is inside the fence.** The helper's structural pre-compile pass
  (`shape.rs`), the new `component_too_complex` refusal, an engine with every unneeded
  proposal disabled by name and its stack, optimisation level and memory reservations set
  explicitly, and a notification refused for every method that has an effect. Rust proofs:
  a component at every bound is admitted and one past each is refused before wasmtime sees
  it; a relaxed-SIMD and a tail-call component are refused at compile; the acceptance guest
  still loads, instantiates and answers. Plus one targeted test each for the enforcement a
  mutation sweep found untested — the noise budget, the table-element cap, the memory count
  cap, the 64 MiB byte cap, both halves of the import check, the sha case-fold, and the
  per-call log-budget reset. On the Elixir side the same slice removed every cwd-derived
  helper candidate from the wasm, desktop and sandbox resolvers, range-checks limits and
  clamps timers in the pool, validates the wrapper's `initial_state`, moves the helper
  environment to an allow-list, names one module in the mesh allow-list, and scopes the
  hook budget to untrusted components; lane H labels untrusted output per line, narrows the
  untrusted `PostToolUse` payload, stops dispatching discarded events untrusted, bounds the
  matcher, and CI builds the helper; the trust chain makes `Wire` exact for struct-shaped
  maps, binds `start.id` to the artifact name, re-validates the register on read with a
  durable epoch high-water mark, bounds every report that reaches the checkpoint or the
  journal, orders the signer's rate limit first, and keeps probe/eval cleanup in a process
  a deadline kill cannot reach. Every fix landed with a regression test that was red first
  and a mutation that turns it red again.
- **W8 — compiled once, where the signature is made.** `Component::new` on the node's hot
  path was what made §7.3's bounds necessary in the shape they have. The helper grew
  `ouro-wasm precompile <in.wasm> <out.cwasm> [--kind]`, which applies `shape::check` and then
  `Engine::precompile_component` under the **same** engine — one `host::engine()`, shared with
  `serve`, because a second configuration is a second world — reads its own output back to run
  `world::check` on the artifact rather than on the source, and writes it inside an eighteen-byte
  container naming the wasmtime, the triple, the world and the source component. `load` gained
  `precompiled: true`: sha, then header, then the two build strings, then the source component
  the request named, then `Component::deserialize`, then `world::check` on what came out —
  every check in front of the `unsafe` block, whose comment is D24's sentence. `shape::check`
  deliberately does not run there; the bound is the byte cap, 128 MiB, reported as
  `max_precompiled_bytes`. One new refusal, `precompiled_mismatch` (-32021), covers every way
  an artifact is not this node's to map. `doctor` reports `target`.

  **The measurement, on the release helper (aarch64-apple-darwin, wasmtime 48.0.1).** The worst
  component §7.3 admits — 20 000 functions, 4 035 787 bytes, the shape the whole structural pass
  exists to bound — serializes to 11 092 495 bytes (2.75×) and:

  | | `inspect` | `load` | total |
  |---|---|---|---|
  | today, source | 1.416 s | 1.525 s | **2.942 s** |
  | W8, precompiled | 0.040 s | 0.037 s | **0.077 s** |

  Thirty-eight times less, and the remaining cost is linear in the artifact's length rather
  than a function of its shape — which is the claim: the admission question stops being "how
  expensive is this to compile" and becomes "how large is this artifact", which a byte cap
  answers exactly. The signer pays 1.459 s once. The reference guest, for scale: 48 333 bytes
  of wasm to 258 093 of artifact, 5.3×, fixed overhead dominating a small one.

  On the Elixir side `Wasm.Artifact` carries `precompiled: nil | %{wasmtime, target, sha256,
  size}` inside `manifest/1` and therefore inside the signature; the bundle went to format 2
  with a third length and the artifact between the envelope and the component (so the client
  still only appends); `Bundle.verify/2` binds each form to its own sha through
  `Verifier.verify_precompiled/2`; the signing policy's wasm arm validates the block and
  journals it; `Wasm.Store` publishes artifacts content-addressed as `cwasm-<hex>.cwasm`,
  prunes them, protects them through the manifests of protected rows, and owns `form/4` — the
  one place a node decides which bytes to hand the helper; `Wasm.Deploy.sign/2` precompiles
  with this node's helper and records what that helper printed; `Rollout.stage/3`, the wrapper
  agent, `Wasm.Boot` and `PolicyEngine` all reach `form/4`; `wasm.list` reports `form`;
  `ouro wasm sign --no-precompile`, `ouro wasm inspect` on a `.cwasm` (header only, plus one
  line saying whether this helper could map it), and `ouro wasm ls`'s `FORM` column.

  Proofs. Rust: precompile-and-map of the echo guest answers a message; the worst admissible
  component maps faster than it compiles and then works; one flipped byte deep in the machine
  code is `sha_mismatch` before the deserialize; a header rewritten to another wasmtime and to
  another triple is `precompiled_mismatch` **by name** and the source form still loads; source
  bytes offered as an artifact, an artifact offered for another component, an artifact offered
  as source, and a non-boolean `precompiled` are each refused; a header rewritten to claim the
  policy world over a capability payload deserializes and is then refused `unsupported_world`
  by the world check, which is the one case the header comparison cannot catch; and
  `precompile` refuses a component one function past the bound, one that wants a clock, and one
  offered as the wrong world. Elixir: `Store.form/4`'s whole table, including every fallback and
  its reason; sign → bundle → deploy → `precompiled: true` from the helper's own answer; the
  same bundle with another wasmtime recorded falls back on a cold node; an untrusted signature
  never reaches a deserialize and leaves the store empty; a tampered artifact section is refused
  by `Bundle.verify/2`; `wasm.list` says `precompiled`; a reboot restarts a precompiled `:live`
  entry, carries the block into the wrapper's state, and it answers; the policy engine stands a
  precompiled policy up. The two skew tests here craft the mismatch rather than building with
  two toolchains — the container's header is this build's own format, and what a node reads
  *is* the header — and the scripted-`doctor` half is proved separately, on
  `Pool.helper_build/2`; W20 later built the mismatch for real, on two toolchains, and the
  strings a real helper prints are recorded there.
  Then, from the adversarial review: a rate-limited and a policy-refused sign each invoke the
  helper **zero** times, counted through a shim in front of it; the admission is journaled and
  the signature spends no second slot; a ticket is single-use and is honoured only for its own
  requester and its own source manifest; `accept_precompiled: false` answers the source form; a
  rotted artifact is not offered, and when the helper refuses one anyway the source form is
  loaded and the guest answers; a component this node does not hold reaches no helper at all;
  all eight skip reasons are exercised and each signs a whole verifiable bundle; both rollout
  gates hold each form to its own digest; the store's publish, prune and protection of
  artifacts; the bundle's two-halves-one-statement rule and its ceilings; the helper's magic and
  both declared lengths; a source file past the source cap refused under *that* cap;
  `precompile` refusing an artifact as its input; and a reconnect re-reading the helper's build.

  What W8 does **not** remove is in §12: the artifact is bound to one wasmtime and one triple,
  and engine-embedding guests still need `wasi:io`, which is a signing-policy decision and not
  this slice. It also left the artifact reaching an operator only when it fit one gateway
  reply — past three quarters of the frame this slice dropped it and signed the source form
  alone. **W19 removed that one**: the artifact now travels through `wasm.download` in the
  frames `wasm.upload` already uses, the manifest keeps its block, and nothing is skipped for
  being large (D28).
- **W9 — the guest SDK.** `tui/wasm/guest` (`ouroboros-guest`): its own cargo workspace, the
  `no_std` ceremony behind one macro call, and four seams over the one world — `Capability`
  for a mesh capability, `Hook` and `Check` for lane H's two contracts, `Raw` underneath them
  for a reply that must be stated verbatim. `Describe` serialises contract C1 and fills
  `world` in itself, bounding the summary and the example list where C1 bounds them.
  `Verdict` is the stdout contract `hooks.ex` reads, with the untrusted narrowing documented
  on the enum that produces it — `allow` read as silence, `updatedInput` dropped, `deny`,
  `ask` and context kept and labelled per line — plus a `Silent` variant, because an SDK whose
  only way to say nothing was `allow` would have taught every author to resolve an engine
  `ask` by accident. The acceptance guest was rewritten onto the SDK: 48,335 bytes became
  49,140 (+805, +1.7%, on the pinned 1.95 toolchain) and `test/wasm/` stays green. One
  behaviour did change and is written down rather than glossed — it used to log
  `handle-message` *before* checking whether `init` had run, and the SDK refuses first, so
  that line is now only emitted for a message it answers. Nothing observes the difference: the
  pre-`init` path is unreachable through the protocol, because `call` on an instance that was
  never stood up is `unknown_instance`.

  Proved in two places, because neither is sufficient. `tui/wasm/tests/sdk.rs` (eight tests)
  builds the four example guests and the substituted scaffold template with a real toolchain
  and puts them to the real helper: each is `ouroboros:capability@0.1.0` importing exactly
  `log`, every `Verdict` variant survives the round trip, a `[checks]` pass is the empty reply
  and a failure is its text, a body a guest cannot use is a `guest_error` that leaves the
  instance live rather than a trap, and every placeholder a template file uses is one the table
  W10 will read documents. But every assertion there compares this repository's Rust against
  its own, so all of it stays green through a rename in `hooks.ex` — the SDK's claims are about
  the *node*, not about itself. `test/wasm/sdk_acceptance_test.exs` (sixteen tests) is where
  they are settled: the built components run through `Hooks.pre_tool_use/4` and
  `Hooks.run_checks/2` in a clone nobody trusts, and what is asserted is the decision and the
  difference between the two lanes — an untrusted `allow` arriving as silence while the trusted
  one resolves the call, an untrusted `updatedInput` dropped while the trusted one replaces the
  arguments, `deny` and `ask` standing in both, every line of context labelled, and a failing
  check that is a failure rather than the pass an emptied reply would have been. Fourteen host
  unit tests pin the two documents key by key underneath. `make wasm-examples` and
  `make wasm-sdk-check`; both CI jobs gain what they need to run all of it, under
  `OUROBOROS_REQUIRE_WASM`, so a machine that cannot build a guest fails rather than skipping
  green. The scaffold is the placeholder W10's `ouro wasm new` embeds.
- **W10 — the local dev loop.** `ouro wasm` grew five subcommands that need no node:
  `inspect`, `run`, `hook`, `check` and `new`. Each starts a local `ouro-wasm` and speaks its
  line protocol through a new `tui/src/wasm_client.rs`; `doctor` still asks a gateway and
  still starts nothing, and the parsing test that says so now also proves it cannot be handed
  a `--helper`. The helper is resolved from three places and never the working directory
  (D14). `inspect` reports the world, the imports, the exports, the sha, the size, and the
  structural census beside the ceiling each reading was judged against — for which the
  helper's `inspect` learned to report the `shape::check` census it already took, from the
  same walk in the same order, so the numbers shown are the numbers the compiler gate used —
  and one verdict line: admitted as a capability, as a hook component, as both, or as
  neither with the refusal named. `run` loads, instantiates once, and sends every message to
  the *same* instance, printing each reply, the fuel it cost, the guest's own log lines and
  the wall clock; bounds default to `config/config.exs`'s `capability_limits` and are clamped
  down to the helper's maxima. `hook` builds the payload the seam builds, narrows the
  `tool_response` on the way in, and prints the raw verdict beside the one the node would act
  on, naming what was dropped and why. `check` parses an `ouroboros.toml` and judges every
  `[[hooks]]` and `[checks]` component entry as an untrusted workspace — the exactly-one-of
  rule, the workspace-relative path, canonical confinement, the 16 MiB ceiling, the world,
  the shared eight-component budget — and exits non-zero on any refusal without instantiating
  anything. `new` scaffolds a project from a template embedded in the binary, in a capability
  and a hook shape — its own raw-`wit-bindgen` template at the time, carrying the world file
  byte for byte, which W10b replaced with the SDK's.

  Proofs: a Rust integration suite drives the real binary against the real helper and the
  real acceptance guest — the world and shape report, one instance across two messages
  (`"n":2` is the evidence), the D8 narrowing on both lanes, the `PostToolUse` output body
  never reaching the hook, a component that climbs out of the workspace refused with the same
  sentence a missing one gets, a symlink out of the tree refused after being followed, the
  ninth component of an untrusted workspace declined, the budget shared across `[[hooks]]`
  and `[checks]`, a component importing `wasi:cli/environment` refused by name and never run,
  a component refused before the compiler saw it, and a helper planted in the working
  directory never executed. The two hand-built components have a test of their own, because
  every refusal looks alike from outside and a fixture that stopped being a valid component
  would pass for the wrong reason. The narrowing fixture (C6) is red on both sides for the
  same mutation. CI's Rust job now builds the helper and the guest and runs under
  `OUROBOROS_REQUIRE_WASM=1`, so a skip there is a failure exactly as it is on the Elixir
  side.

  **Adversarial review found four ways the slice claimed more than it enforced, and sixteen
  enforcement points with no test that was red without them.** All were fixed in place; the
  detail is in D14 and the shape of it is worth stating here, because three of the four were
  the same mistake — a rule written down in prose and checked by something that did not
  actually check it.

    * **The helper could be chosen by a repository after all.** `current_exe` was not
      canonicalised, so `./ouro -> /real/ouro` beside a planted `./ouro-wasm` ran the plant;
      and `--helper ouro-wasm` passed `is_file()` against the working directory before
      `Command::new` did a `$PATH` search for a different file. Both proved with marker files.
      Candidates are now canonicalised and vetted — regular, executable, owned, not
      group- or world-writable — and the vetted canonical path is carried by a newtype that is
      the only thing `Helper::start` accepts.
    * **A bound taken from a stat is not a bound.** `ouroboros.toml -> /dev/zero` reported zero
      bytes, passed the 256 KiB check, and then read thirteen gigabytes. Every file these
      commands read is now statted for a regular file and read through `take(limit + 1)`.
    * **`check` claimed admission it had not verified.** `matcher = "*"` — which the node
      refuses — passed under "every component entry would be admitted" and exit 0, while the
      valid `\Q(\E` was refused; and the untrusted component budget was charged to entries
      whose paths never resolved, so five typos could hide five good components. The matcher
      heuristic is gone, unverified is printed rather than guessed, and the budget is spent in
      the node's own order.
    * **`clip/2` could emit invalid UTF-8.** A byte cut through a codepoint, on
      repository-authored text, in a string `JSON.encode!` then raises on. Fixed on both sides
      to cut at a character boundary and pinned by a fixture case whose cut lands mid-codepoint
      — the one change this slice made to `hooks.ex`, which is otherwise untouched.

  Sixteen enforcement points gained a test that is red without them, re-run against the
  reviewer's own mutation set: the `||` fallthrough in `parse_output`, a non-object
  `updatedInput`, a non-map `tool_response`, the context clip, the helper environment
  allow-list and its credential-value filter (a canary helper that dumps what it was given),
  the absolute-path rule for `$OUROBOROS_WASM_HELPER` (proved with a *working* relative
  helper, so the rule is what refuses it), the absolute-component and 16 MiB rules in `check`,
  the `ouroboros.toml` byte bound, `hook`'s event vocabulary, config bound, component ceiling
  and deadline ceiling, and the sanitizer — asserted on raw stdout bytes, because a string
  comparison is what would miss a stray `0x1b`. On the helper side, `shape::check` running
  *in front of* `Component::new` is now pinned by the clock rather than by a refusal that
  looks the same either way.
- **W10b — `new` scaffolds on the SDK, and `sign` reads the imports itself.** The two seams
  wave 1 left open, each of them a place where a document said one thing and the code did
  another.

  `ouro wasm new` wrote its own raw-`wit-bindgen` template — two hundred lines of `no_std`,
  a `wit/capability.wit` copied byte for byte out of the helper's, and a `TODO(W9)` saying
  what it was standing in for. W9 shipped the SDK and the scaffold template beside it, and
  for one slice this repository had two scaffolds: the one an author was told to read and
  the one the binary actually wrote. `src/wasm_template/` is gone. `new` now embeds
  `tui/wasm/guest/template/**` with `include_str!` and substitutes the table in that
  directory's `PLACEHOLDERS.md` in one pass — a placeholder that table does not name is a
  refusal rather than a literal `{{…}}` carried into somebody's `Cargo.toml`, and a substituted
  value is never itself substituted, which is what keeps an operator's `--sdk-path` the text
  they typed. (W9's table gave an *ordering* rule instead, `{{name_snake}}` before `{{name}}`,
  and the reason it gave was wrong: `{{name}}` is not a substring of `{{name_snake}}`. The
  single pass needs no ordering, and the sentence is corrected in place.) A scaffolded project
  depends on
  `ouroboros-guest` and carries no world file at all, because the SDK carries the bindings
  and a second copy in every project is a copy that drifts. `--hook` selects
  `src/lib.hook.rs`, a `Hook` on the verdict contract, written as `src/lib.rs`; without it,
  the `Capability`. Three tests hold it: `the_embedded_template_is_the_template_on_disk`
  reads the same paths at run time and compares with what was embedded, `sdk.rs` builds
  **both** shapes with a real toolchain and puts each to the real helper, and the CLI's
  integration suite scaffolds both, builds them with a plain `cargo build --release --target
  wasm32-wasip2`, and asserts `imports: log` and `verdict: admitted` on what came out.

  `ouroboros-guest` is unpublished, so the generated `Cargo.toml` reaches it by **path** — and
  the first cut of this slice computed that path by walking up from the output directory,
  carved out of D14 on the reasoning that a source path is not something that gets executed.
  That reasoning was wrong and adversarial review proved it: a cargo path dependency's
  `build.rs` and proc-macros run during `cargo build`, so an SDK planted on any shared ancestor
  of the directory a developer works in got its build script executed by the scaffolded
  project's first build. The carve-out is gone and D14 applies verbatim (see it there): the SDK
  comes from `--sdk-path` or from the checkout the running `ouro` lives in — never from the
  working or output directory — is vetted for symlinks, a regular bounded manifest and a
  `[package] name` of exactly `ouroboros-guest`, and is written **canonical and absolute**
  because the relative form read the same whether the SDK was the real one or the plant. With
  neither source available the command refuses and names `--sdk-path`.

  Three more ways `new` wrote a file it had not checked, all of them the same shape — an
  operator's argument spliced into a structured document. `--sdk-path` went into a TOML string
  and a `"` or a newline in it wrote a `Cargo.toml` key nobody typed; `--summary` went into a
  Rust string literal, where `x" ; compile_error!("` is a scaffold that hands somebody a crate
  that will not build, and the "at most 200 characters" in the flag's help was not enforced
  anywhere. Both are refused rather than escaped, because neither is a character an SDK path or
  a one-line description has. And the name charset was "letters, digits, `-` and `_`", which
  accepted `MyThing` — a name `Wasm.Artifact.name?/1` refuses, learned only after the component
  was written. It is now that function's charset exactly, plus cargo's narrower rule on top
  (no leading digit, no `.`), with a separate sentence for each so a refusal says which one.

  `ouro wasm sign` required an operator to run `ouro wasm inspect --json` and pipe the answer
  back into `--imports-from`, because D15 makes the import list the client's to declare — the
  node must not hand unsigned bytes to the one process whose job is running other people's
  code. That reasoning is untouched and the verb is unchanged. What was missing was the other
  half of the sentence: if the client declares the list, the client should read it. `sign`
  now resolves a helper by D14's three-place rule, canonicalised and vetted exactly as
  `inspect` resolves one, asks it `inspect` for the imports and `load` for the world, and
  **refuses to sign a component its own helper would not admit** — naming the helper's own
  refusal, rather than spending a signing service's policy decision on a signature nobody could
  use. `--import` and `--imports-from` still override it and are never second-guessed.
  `--no-local-helper` starts nothing and requires one of them, which is the machine that has no
  helper; an empty import list is still a real answer and arrives through a report, now read
  under a 64 KiB bound like every other input.

  **The order is the claim, and the first cut had it only in `--dry-run`.** Three sentences in
  this repository said the helper was asked "before a byte is uploaded" and "before it opens a
  socket at all"; the code connected, read, uploaded and *then* started the helper, and every
  test that asserted the order used `--dry-run` — the one path where it was true. A recording
  gateway and a spy helper showed a refused component reaching the gateway with the helper
  never started. The code moved rather than the documents: reading the component and putting it
  to the helper is now a `plan_sign` that runs before `wasm_connect`, and the same recorder and
  spy assert both halves on the **real** path — a refused component reaches no gateway at all,
  and an admitted one reaches the helper first and the gateway second. `--dry-run` remains the
  only path that opens no socket ever; what it no longer is, is the only path with the
  documented order.

  **And the bytes are bound to the answer.** This command reads the component into memory and
  uploads what it read; the helper opens the path again for itself. A file swapped in that
  window produced a signed manifest whose import list described bytes nobody uploaded — caught
  at stage, by the node's cross-check, on somebody else's machine. The sha the helper reports
  must now equal the sha of the bytes in hand, and that sha is what `load` is asked about, so
  the window is closed at both ends. Proved with a scripted helper that reports a different
  digest: refused, and no gateway contacted.

  The rest of the proofs: the real echo guest gives `["log"]`, a hand-built component importing
  `wasi:cli/environment` is refused by name, a helper reporting nine imports is refused against
  the node's ceiling before an upload, a component past the 17 MiB ceiling is refused before a
  helper is started, and a scripted `ouro-wasm` records that the only two requests `sign` makes
  of a helper are `inspect` and `load` on the path named on the command line — never an
  `instantiate` that would *run* a component nobody has signed yet.
- **W11 — the author guide, with its contracts pinned.** Every author-facing fact in this lane
  lived in module docs, this spec and a test file, which is three places a developer does not
  look and none of them the one they would. `docs/WASM_GUIDE.md` is that reader's document: a
  hook in fifteen minutes and a capability in fifteen minutes, both as transcripts of commands
  that were run rather than commands that ought to work; the contracts (the world, the payload
  per event, the verdict, `[checks]`, `describe`, the `ouroboros.toml` keys); one table of
  every bound beside the constant that holds it and one of every refusal beside what an author
  does about it; and the operator's half — `make wasm`, the config keys, the signer, the store,
  the readiness surfaces. The README gains a lane-W section and `docs/ARCHITECTURE.md`'s hook
  paragraph gains the `component`/`config` keys with the exactly-one-of rule, because that is
  where project hook configuration was documented and a second home for it would drift.

  The payload half is not prose. `test/support/wasm_golden/hook_payloads.json` carries the
  exact JSON object a component receives for every event `hooks.ex` dispatches, plus the
  `[checks]` payload, and every byte of it was read off the wire rather than written;
  `test/provider/native/hooks_payload_golden_test.exs` drives each case back through the
  **public** seam a turn uses — `pre_tool_use/4`, `post_tool_use/5`, `notify/4`,
  `session_start/2`, `session_end/2`, `pre_compact/2`, `run_checks/2` — and asserts the frame
  the helper was handed, so no `@doc false` function was added to `hooks.ex` and the file is
  untouched by this slice. Red for two mutations, both run: handing an untrusted `PostToolUse`
  hook the response itself puts the output body back on the wire, and deleting a key from
  `hook_base/1` in `provider/native/loop.ex` fails the test that reads both callers' key sets
  out of their own source — the drift this guide could otherwise have suffered silently, since
  the base half of every payload belongs to the caller and not to `hooks.ex`.

  Three things the verification found, all reported rather than papered over, and all three
  closed by the slices that followed in the same wave. **`ouro wasm new` still embedded the
  pre-SDK template** — a scaffolded project was hand-rolled ceremony with no `Hook` trait in
  it — until W10b made the SDK template the one source the command embeds. **`wasm.sign`
  could not allocate an epoch on a cluster with a `:signer` node**, because the allocation
  asked every connected node for `Upgrade.NodeExecutor.status` and a signer runs no rollout
  plane; reproduced on a two-node dev cluster, and fixed by W12's follow-up, which allocates
  over the nodes that hold a register and fails closed on the ones that hold half of one. And
  `ouro wasm keygen` **printed back the `--out` path it was given**, so a relative one produced
  an `OUROBOROS_SIGNER_KEY_PATH` line the signer node refused; it now writes and prints the
  absolute path. The guide's transcripts were re-run against the fixed commands.

- **W12 — signing and deploy from the operator's chair.** `Ouroboros.Wasm.Bundle` (the
  `.ouro-wasm` file: framed header, bounded JSON envelope, raw component, `:safe` term
  decode, manifest reconstruction held to a fixed point), `Ouroboros.Wasm.Upload` (the
  chunked, process-free staging area of D16), `Ouroboros.Wasm.Deploy` (the node side of
  the three verbs), `Wasm.Rollout.rollback/2` reusing the eval-failure branch's own
  `withdraw/2`, and `Wasm.Surface.deployment/1`/`rollback/1` projecting a rollout outcome
  onto the wire. Four gateway verbs — `wasm.upload`, `wasm.sign`, `wasm.deploy`,
  `wasm.rollback`, all `:operate` and node-routed — with protocol docs, golden fixtures
  and typed Rust decodes for each, and `ouro wasm keygen | sign | deploy | rollback | ls`
  on top. `keygen` contacts no runtime and writes a seed in exactly the format
  `Signing.Service` reads, printing the `OUROBOROS_SIGNER_KEY_PATH` and
  `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` lines; its derived public half is pinned against the
  RFC 8032 test vector, because a keygen that derived a different public key would print a
  trust line that verifies nothing and no local round trip would catch it. Proved live on
  this Mac end to end: `wasm.sign` over `test/support/wasm/echo.wasm` with the imports read
  off the component, the bundle assembled from the node's prefix and the operator's bytes,
  `wasm.deploy` reaching `:live` with both eval probes passing, the `wasm/<name>` mesh
  agent answering a message, and `wasm.rollback` stopping it with the bytes and the
  manifest still in the store. Refusals proved with the store, the register and the helper
  pool asserted unchanged. The `methods.ex` comment that promised there would never be a
  `wasm.deploy` is corrected in place, with D15 for why.

  An adversarial review of the first cut found three ways in and they are all closed here,
  each with a test that is red without its fix. A **compressed manifest term** made a 42 KiB
  file allocate 292 MB inside `Bundle.verify/2` at `:operate`, before any trust check — tag
  80 is refused by inspection now and the decoded term is measured in heap words rather than
  in the length that was read. A **client-named epoch** at the register's plausibility
  ceiling wedged lane W on a node permanently from one call — the parameter is gone, the
  register's boundary is exclusive, and the signing policy refuses an epoch far above
  anything the node has seen. And **`wasm.sign` handed unsigned bytes to the helper** to
  read their imports: `imports` is the client's to declare now, computed with the operator's
  own helper, and the upload is consumed before anything that can refuse. Three more were
  concurrency: `Upload.take/2` is an atomic rename rather than read-then-remove, the
  in-flight ceiling is eight `O_CREAT|O_EXCL` slot files rather than a count taken before a
  create, and an upload has a total lifetime as well as an idle one. Two claims that outran
  the code were deleted rather than defended: the redundant pre-flight verification in
  `Wasm.Deploy.deploy/3` (the rollout was already verifying before its checkpoint, and no
  test could tell the difference), and `:unchanged` counting as proof for an operator's
  rollback — a capability whose name is still answering is not "rolled back".
- **W13 — a live capability is a tool, and a description is deployment metadata.** Lane W
  could deploy a capability and nothing a model or a user touched could reach one. Two
  things can now, and neither is a mesh client. The native `capability` tool lists the
  `:live` lane-W rollouts that name this node, with the register's facts beside each
  component's labelled, bounded claim about itself, and `call`s one under a 64 KiB body
  bound, a 64 KiB reply bound whose every line is prefixed with the untrusted label, and a
  timeout of the target's own deadline plus the pool's call margin. One function resolves a
  name — for the permission engine and for the message alike, on the exact string the model
  wrote — and a name that is not a rollout name is refused before the register is read. The
  rule language gains `Capability(<name>)` and `Capability(*)`, matched against a name the
  node resolved, which is what lets them carry an allow; `Tool(capability)` is deny-and-ask
  only, because one call reaches one component and an allow on the tool is an allow on every
  component this node will ever deploy. The tool call's ledger entry carries the capability
  and the component's sha256. `agents.message` is the operator's half at `:operate`, bounded
  and labelled the same way, with a marked truncation; `agents.state` labels and bounds the
  same two fields for a `wasm/` agent, because it is `:read` and returns them too.

  A component's `describe` is read **at deploy**, as a fourth rollout gate, on a throwaway
  instance under its own bounds, and stored on the registry entry — which is where every
  reader gets it. It used to be read on the message path, and a component whose `describe`
  took six seconds while answering messages instantly failed the rollout probe's
  five-second budget and was rolled back. Contract C1 now also refuses every Unicode
  control, format and line-separator character in every string of the document, walked
  whole; the register re-validates on write and on read, and holds a lane-W module name to
  the artifact charset so a planted `wasm/a/b` is refused. Proved against the scripted
  helper (including the six-second `describe` that no longer costs a message), the real echo
  guest, the live rollout, the register's checkpoint, and the native loop.

- **W14 — a capability is forged from an agent, inside the fence.** Lane W could deploy
  components somebody else had built. `Ouroboros.Wasm.Forge` builds them here: a Cargo project
  on the guest SDK in, a signed `.ouro-wasm` out, through `Wasm.Deploy.sign/2` and
  `deploy/3` unchanged. What it adds is the fence around a build. C9's input is bounded and
  path-checked before a byte is copied — 32 files, a mebibyte, no `..`, no symlink followed,
  no `build.rs` and no `[package] build` key that would make one of `src/**.rs` run. The
  `Cargo.lock` minus this project's own entry must be byte-identical to the SDK's resolved
  lock, so the dependency set is the SDK's and the only proc macros that run at build time
  are the ones this repository already builds. The manifest is read by a scanner that refuses
  every line it cannot classify *and* by `Toml`, and a disagreement between them is the
  refusal. `cargo build --release --target wasm32-wasip2 --locked --offline` then runs under
  `Sandbox.builder_policy/1` — deny-by-default on reads as well as writes, so a build sees
  the toolchain, the SDK, the `wit` world file and its own directories and nothing else; no
  network; writes only in the build directory, the node-local cargo home and a private
  `TMPDIR`; a five-minute ceiling — and a node with no backend, or whose only backend cannot
  express a read allow-set, refuses to build at all. The registry cache is `<data_dir>/wasm/
  cargo-home`, warmed by `make wasm-sdk-cache` and never the operator's own `~/.cargo` unless
  they name it, because a cargo home's `config.toml` can name a `rustc-wrapper`; a cache
  missing a crate is a refusal naming it in 8 ms, not a fetch.

  The node then reads the product's imports with its own helper, which D18 argues is exactly
  the case D15 does not cover: it built these bytes. Two effects — `ForgeWasmCapability` and
  `DeployWasmCapability` — reach it through `Runner.dispatch/5` with the server-owned
  principal as the signed manifest's author, the `:forge` grant asked about
  `"wasm/<name>"` so one narrow grant admits one capability, and the deploy resolving its
  artifact from the agent's own `forged` ring; that ring now holds both lanes, so each deploy
  action refuses the other lane's manifest by name. `Control.Grants` learned to hold a
  `"wasm/<name>"` in a `:forge` allow-list for that, which is the one widening this slice
  makes explicit: `modules: :any` now reaches both lanes. The operator's half is the same
  code — a proposal directory holding a `Cargo.toml` is lane W, `capabilities.preview` reports
  C9 plus a dry build, `capabilities.admit` forges and deploys at `:operate` — and needs no
  new gateway verb.

  Proved live on this Mac, end to end and twice: the `counter` example forged through the
  agent effect surface (signal in, sandboxed build, imports read off the product, signed,
  deployed `:live`, messaged, rolled back, with the author inside the signature being the
  principal and not the signal's `from`), and the same project forged through
  `capabilities.admit` from a workspace proposal. Every C9 refusal has a test that is red
  without its check, and the sandbox is proved by what the kernel actually did: a probe
  spawned through the same `Sandbox.wrap/4` the build goes through wrote inside the build
  directory, could not write into a root it may only read, could not read a file the fence
  did not name, and could not open a connection.

  **The first cut of this slice did not fence reads, and an adversarial review walked
  through the hole end to end**: a component that `include_str!`s a planted secret was
  signed, deployed and answered the secret through a mesh message, and one that included the
  real `~/.ssh/id_rsa` built fine. The excuse written into D18 — that this was "no wider than
  a lane-B capability" — was true only of `modules: :any`, and the narrow grant is the one an
  operator reaches for *because* it is narrow. Builds now run under a policy that is closed
  on reads (D18 lists what it opens) and the two escapes are tests asserting the refusal
  beside a test that the honest fixture still builds under the same policy. Two more the same
  review proved: a stored `modules: :any` grant silently came to cover lane W — `:any` now
  keeps its pre-W14 meaning and `"wasm/*"` is how the broad thing is said — and a forge on
  the effect path could be cut by the runner's `brutal_kill`, which runs no cleanup, so the
  forge's budget now sits strictly inside the effect's and the test for it asserts `pgrep`
  finds nothing.

  **The Linux half was then run, and it did not work.** The bubblewrap namespace had `/dev`
  and `/proc` in its readable list, so the ro-binds made from that list landed on top of the
  fresh devtmpfs and procfs bubblewrap had just mounted and replaced them with a read-only
  view of the host's. Every build then aborted on `/dev/null` with `SIGABRT` and produced no
  output at all — which is also how a failed build came to report an empty string. Both are
  fixed: those two mounts are the backend's to provide and are gone from the list, and a
  build that says nothing now reports the signal that killed it. The suite is portable now
  too: the probe uses no `nc` and asserts effects rather than one platform's kernel prose,
  and the read denial is matched per backend — `Operation not permitted` from Seatbelt,
  `No such file or directory` from a namespace the file was never in. One test-isolation
  defect came out with them, a test that set `CARGO_HOME` and deleted rather than restored it
  on the way out, invisible on a developer machine and stone cold in a container.
  `scripts/forge-linux-test.sh` (`make forge-linux-test`) runs all of it in a privileged
  Ubuntu 24.04 container from a Mac: **127 passed** on kernel 7.0.14 with bubblewrap 0.9.0,
  beside **131 passed** on macOS.
- **W15 — a policy is a component, and it can only narrow.** The helper grew a **second closed
  world**, `ouroboros:policy@0.1.0`: the same single import, `evaluate: func(string) -> string`
  in place of `handle-message`, and a `load` that is told which of the two a set of bytes is
  being offered as. `Ouroboros.Wasm.PolicyEngine` is an engine for `:permissions_engine` that
  delegates to `Control.Permissions` and, only on `{:ask, :no_rule}`, asks a signed policy
  component: its `deny` stands, its `ask` stands, and its `allow` is honoured only for the
  tools an operator listed in `:policy_allowable_tools` — empty by default — so a policy
  narrows until an operator widens it (D20). Every other outcome is `ask`, including a trap, a
  deadline, a verdict that is not JSON, and a request too large to be handed over **whole**,
  which is not truncated but refused: a policy shown four kilobytes of a command line is one an
  attacker pads past. The manifest gained a signed `kind` (contract C7), the world follows from
  it, and `Wasm.Rollout.stage/3` hands that kind to the helper — so a policy manifest over
  capability bytes is `unsupported_world` before the register is marked, and `Rollout.live/1`
  reads the kind out of the manifest rather than out of a register row, which is what keeps a
  policy out of the `capability` tool's listing (D21). A policy declares no `start` block and
  its signed eval spec is a list of `{request, expect: {decision}}` cases run through
  `evaluate` at deploy. Honoured verdicts are ledgered `actor: :classifier` — the slot
  `permissions.ex:92` reserved and nothing occupied until now — with the component's sha and
  its rule string in `rule_ref`; the rule is bounded at 200 characters, stripped of every
  control and format character, and labelled `[untrusted policy component]` wherever it is
  read.

  The SDK grew a fourth seam over the second world — `Policy`, `export_policy!`, and
  `examples/no-network-shell`, which denies a `bash` containing `curl`, `wget` or `nc ` with a
  stated rule and asks about everything else. One crate, two `generate!` invocations, and the
  macro an author calls is what decides which world the component implements, so a crate cannot
  claim both. `ouro wasm policy <file> --request <json|file|->` runs one against a local helper
  and prints the verdict, the rule the node would record and the guest's log, exiting non-zero
  on a `deny`; `ouro wasm sign --kind policy` puts the kind on the wire, including the default,
  because a parameter the client omits is a claim the node fills in.

  Proved on both sides, because neither is sufficient. Rust: both worlds reported by `doctor`
  and told apart by `inspect`; a policy admitted as `policy` and refused as `capability` and
  the reverse, each naming the export the asked-for world wanted; `call evaluate` on a
  capability instance and `call handle-message` on a policy instance both `unknown_export`,
  with both instances still live afterwards; an absent `kind` meaning capability and an unknown
  one being `invalid_params`; a component whose bytes satisfy **both** worlds admitted to the
  one it was offered as and dispatching that world's export alone; `instantiate` refusing a
  world the `load` did not admit; and the policy world refusing a clock by name. Elixir: the
  kind through the struct, the signing payload, the bundle envelope (including a manifest
  naming an atom this VM happens to hold), the signer's world/eval/start branches, and the
  stage where a `:policy` manifest over capability bytes is refused. The engine: not consulted
  when the rules decide, consulted when they do not, `deny` standing with its rule, `allow`
  degrading for an unlisted tool and honoured for a listed one, trap and deadline and malformed
  verdict all `ask`, the rule bounded and control-free, a credential-shaped context value
  redacted and a non-scalar one dropped by name, an oversize request not sent at all, the
  ledger entry carrying the sha and `actor: :classifier`, and a `:wasm_policy` naming a
  capability-kind entry leaving the engine inert with one warning. And end to end on this Mac:
  the real example signed as a policy with two eval cases, deployed through the real rollout's
  gates, and asked by `Provider.Native.Permissions.evaluate/1` — `curl` denied with the rule,
  `ls` asked, an operator's own allow rule still deciding without the component being reached.
- **Deferred, in rough order:** agent-reachable forge/deploy effects (§7.7) → tools lane
  (§9.1) → microVM backend (§10, likely its own spec once slice-shaped) → agent world (§9.2).
  The policy engine (§8.2) was the first of these and is W15.

  **Adversarial review found four ways in and five enforcement points with no test that was red
  without them.** All are closed here, each with the test that reddens for its mutation.

    * **Two readers of one verdict disagreed.** Elixir's JSON decoder keeps a duplicated key's
      first occurrence and `serde_json` keeps its last, so `{"decision":"ask","decision":"deny"}`
      was `ask` on the node and `deny` in `ouro wasm policy` — and in the other order it turned a
      reviewed `ask` into an honoured `allow` for a listed tool. There is one grammar now,
      written down: exactly `decision` and `rule`, no key twice, three lower-case words, a string
      rule, a kibibyte. Elixir decodes to an ordered pair list rather than a map so a repeat is
      still visible; Rust uses a `serde` visitor that refuses one.
      `test/support/wasm_golden/policy_verdicts.json` pins both, 35 cases, a test on each side.
    * **An honoured verdict rode a dead ledger.** `decided/6` discarded
      `Permissions.record/2`'s answer, so a component's `allow` stood while an operator's own
      rule was already becoming `{:ask, :unrecordable}` two functions away. It follows
      `Control.Permissions` exactly now: an unrecordable allow is an ask, an unrecordable deny
      still denies.
    * **A planted register row was a permission engine.** The kind was read from the store's
      manifest while the sha that got loaded came from the row, and the two were never compared
      — so a row naming a genuine policy manifest and somebody else's bytes ran those bytes. The
      register carries the kind now, recorded at deploy from the manifest the rollout verified
      (which also ends a per-turn file read), and the engine verifies that manifest against this
      node's own trust policy and holds its sha and kind to the row's before loading anything.
    * **The permission path was an unbounded round trip.** A wedged helper cost one decision the
      instance deadline plus the transport margin, twice over for a blanket retry.
      `:policy_decision_timeout_ms` (5 s) bounds the whole decision in a process the engine can
      kill; expiry is `ask` and drops the instance; only `unknown_instance` is retried.
    * **"Every credential-shaped value redacted" was false.** The harness's redaction is by
      *key*; an AWS secret, an `X-Api-Key`, a PEM body and a `GITHUB_TOKEN=…` on a command line
      travelled verbatim, and its `Bearer` pattern ate a closing quote. There is a value-level
      pass now — `Bearer` runs, AWS ids, `sk-`, GitHub and Slack prefixes, PEM blocks,
      credential-shaped `NAME=value`, this node's own env secrets — documented as the heuristic
      it is, and the three headline claims say what it actually does.

  Five more, smaller: `ouro wasm inspect` asked one world and so called every policy component
  `neither` with a non-zero exit — it asks both and names the one that admitted them; `ouro wasm
  policy` refused to send a request the node would not have sent; a policy eval spec must
  certify at least one `deny` or `ask`, because a spec of pure allows certifies nothing this
  lane honours; bytes claiming *both* worlds are refused as ambiguous, so one sha is one world
  and the cache can no longer be asked to hold two; and D20 stopped claiming determinism as a
  property this seam enforces — the world has none of the ingredients, the eval spec exercises
  what an author asserts, and instance state is still theirs.
- **W16 — the helper under the OS sandbox.** §12 said the `ouro-wasm` helper was "a separate
  process but not OS-sandboxed today", and W8 had made that the boundary a compromised signing
  key crosses (D24). It is now sandboxed. `Ouroboros.Wasm.Pool` spawns the helper through
  `Sandbox.wrap/4` under a new `Sandbox.helper_policy/1` — `builder_policy/1`'s closed-on-reads
  `:builder` shape with a scratch attached, so no backend grew an arm (contract C10) — readable
  in the platform's toolchain roots, the helper binary's own directory, this node's **component
  store**, the forge's build directory and a vetted `helper_readable`; writable in a per-child
  scratch under `<data_dir>/wasm/scratch/`, created `0700` and verified with `lstat` exactly as
  `Wasm.Deploy`'s sign scratch is, `$TMPDIR` pointed at it, removed with the child and swept on
  the way in behind an owner marker; **no network at all, loopback included**.
  `Wasm.Deploy.sign/2` runs `ouro-wasm precompile` under the same policy with that signature's
  own directory writable and the shared sign root neither readable nor writable.

  **`config :ouroboros, :wasm, helper_sandbox:` is `:required` by default and does not degrade
  quietly** (D25). No backend, a backend that cannot fence reads (`fences_reads?/1`, C11), a
  backend that cannot fence the network (`fences_network?/1` — a `bwrap` on a host that refuses
  `CLONE_NEWNET` applies every filesystem rule and leaves the child on the host's network), or
  no data directory is a **refusal to spawn**: `{:helper_sandbox_unavailable, reason}`, the pool
  `:broken`, and `wasm.status` carrying `sandbox: %{posture: :refused | :sandboxed | :off,
  backend, reason, readable}` — a new top-level half of that verb, with its fixture, its
  protocol row and its typed decode in `tui/src/model.rs`. `readable` is the **effective** read
  set as basenames, because four sources and a vetted `helper_readable` are not readable off
  `config`. `:off` spawns plain, says so, and logs one line per spawn.

  **The fence is stated twice.** Every `load` in this repository was enumerated: the wrapper
  agent, the policy engine's two, the rollout's staging and boot restart, and the hook lane —
  which was the odd one out, reading a `component =` hook out of the workspace it was configured
  in, and is not any more: `Native.Hooks` already held the bytes and their digest, so it
  publishes them into the node's own store and hands the pool a store path. The pool refuses a
  `load` **or an `inspect`** outside the readable roots `{:refused, :path_outside_roots}` before
  a frame is built, and a source-census test fails if a sixth `load` site appears anywhere in
  `lib/`.

  Proofs, and the mutation each catches. A `/bin/sh` fake helper reads a planted `0600` file
  outside the roots and writes outside its scratch and reports what the kernel did: both
  **denied** under the pool, both **allowed** with `helper_sandbox: :off` — the same script, the
  same file, one setting; spawning `:required` plain turns eight tests red. `:required` with
  `native_sandbox: :none`, and with a planted `:ouro_sandbox` detection, each refuse to spawn
  and name the reason in the status. A `load` whose path is outside the roots is refused with a
  journalling helper proving the helper was never asked; deleting the check turns two tests red.
  The scratch is `0700`, is what `$TMPDIR` names, dies with the child, and a sweep takes
  abandoned directories and leaves fresh ones and directories this pool never made. A hard close
  leaves no process behind, proved by the os pid after the kill — on macOS the pid is the
  helper's because `sandbox-exec` `execve`s in place, and on Linux it is bubblewrap's and the
  helper dies by `--die-with-parent`, so `hard_close/1` did not change. At signing time the
  artifact is still produced under the fence; a shim standing where `precompile` stands cannot
  read a planted file (exit 4) and can with `:off` (exit 3); and a signer with no backend signs
  the source form with `{:helper_sandbox_unavailable, {:no_backend, …}}` in
  `precompile_skipped`, its bundle whole and verifiable.

  **The real helper runs every acceptance suite sandboxed**, by default and with no `:off`
  anywhere in them: `pool_acceptance`, `capability_acceptance`, `hooks_acceptance`,
  `policy_acceptance`, `precompiled`, `boot`, `rollout_two_node` and `sdk_acceptance`, plus the
  scripted-helper suites, 533 tests in `test/wasm/`. What a test has to say to be inside the
  fence is one function, `Ouroboros.Wasm.SandboxFixture.pool_opts/1`, so a suite that forgot
  cannot look like a suite that was exempted.

  **Then an adversarial review took the first cut apart, and this is what it found.** The
  `(deny network*)` was followed by three `localhost` re-allows that exist for `mix`, so a probe
  under the helper's own policy connected to a loopback listener — every service on the machine,
  this node's gateway among them; the policy shape gained `loopback`, `builder_policy/1` keeps
  it and `helper_policy/1` does not, and a kernel probe now proves a listener reachable under
  one and unreachable under the other. The sign-time policy made the whole shared
  `<data_dir>/wasm/sign/` root writable and `compile_in/5` wrote every signature's files
  straight into it, so a wrapped helper read a **concurrent** signature's uploaded component and
  overwrote a concurrent signature's artifact; one signature is one directory now, and the
  shared root is neither readable nor writable. `helper_readable: ["/"]` was accepted and
  removed both walls; the list is vetted whole. A `bwrap` that cannot unshare a network
  namespace satisfied `:required` while the child kept the host network; `fences_network?/1` is
  the second question. The six-hour sweep deleted a *live* sibling node's scratch, because a
  helper's life is not a wall-clock bound; an owner marker beside each scratch is. The comment
  justifying the helper's own directory in the read set was false on Seatbelt — the mutation
  that drops it is green there — and true on Linux, where bubblewrap must bind the binary into
  the namespace; the comment says so and the bwrap option list is pinned. `inspect` was not
  fenced pool-side though it names a path; it is. And the dead third `sandbox/1` clause in
  `Wasm.Surface` that made dialyzer's skip count 91 is gone.

  What W16 does **not** do is in §12 and named in D25: the wall is around a process that maps
  unvalidated machine code and is not validation, and — until W21 — on macOS it was a
  filesystem-and-network wall only: `process-exec`, `mach-lookup` and `sysctl-read` stayed
  unrestricted and `file-read-metadata` stayed open on `/`, so `osascript`'s `do shell script`
  escaped it outright. C10's no-fourth-profile argument did not survive that; W21 is where it
  was answered, with a field rather than a profile.
  The Linux half is CI's: this Mac has Seatbelt, the bubblewrap arm is `Bwrap.options/3`'s
  existing `:builder` branch with different lists, and what proves it is the ubuntu-24.04 job
  running these suites.

  **What the hosted runner found, and no Mac could.** The first push refused every wasm suite
  on Linux: 251 failures, all `bwrap: execvp …: No such file or directory` — the real helper
  and every scripted one. Not the fence refusing; the namespace. W17's `roots/1` resolved every
  root to its canonical spelling, and on a merged-`/usr` Ubuntu `/bin`, `/lib` and `/lib64`
  *are* symlinks into `/usr`, so a list that had resolved them away asked bubblewrap to bind
  `/usr/bin` and `/usr/lib` and nothing else: no `/bin/sh` for a script, no
  `/lib64/ld-linux-*.so` for a binary, and `execvp` says `ENOENT` for a missing interpreter
  exactly as it does for a missing file. Seatbelt never showed it because Seatbelt evaluates
  the host's filesystem, links included. The read set now carries every root under both its
  spellings — the name a process uses and the inode the kernel resolves — and each backend
  takes what it needs: bubblewrap binds the name, Seatbelt matches the canonical form, and the
  `ouro-sandbox` request drops a name that is itself a symlink because that helper refuses one
  by design and the target is already in the list. Two things fell out of stating it that way:
  the pool's load fence had been failing closed by *spelling* (an unresolvable parent compared
  as written never matched a canonical root), and with the named root present it admitted the
  link it exists to refuse, so an unresolvable parent is now a refusal outright; and the Linux
  half of this slice has a proof of its own, `make wasm-linux-test`, which runs the wasm suites
  under bubblewrap in the container with `ouro-sandbox` disabled by name — reproduced the 219
  failures first, then the fix. The second push left one: a forge's product unreadable to the
  helper on Linux and nowhere else. Bubblewrap binds a directory, not a name, and the node's
  store and builds directories are created lazily — so they are created before the child
  spawns now — and a ready, idle pool issued a request without asking whether the roots it
  was fenced to were still the roots the node had, so a data directory that moved between
  two callers left the load fence admitting today's path while yesterday's child answered
  from yesterday's namespace. The ready branch asks now, and the pinned test moves the data
  directory between two `doctor`s and expects a new child for the second and the same one
  for a call where nothing moved.

- **W17 — the preferred Linux backend fences reads, and the forge builds under it.** D18 left
  one residual with a name in it: `ouro-sandbox` had writable roots, protected roots and denied
  names and no way to say what a build may *read*, so a node whose only sandbox was the helper
  this repository ships did not forge at all. The wire format now carries `mode: "builder"` and
  `readable: [...]`, and in that mode the Landlock read set is exactly the allow-set, the
  writable roots, the scratch and the `/dev` and `/proc` every mode keeps — never `/`, and
  never `/` as a fallback when the list is empty. The mount half is unchanged, so writes stay
  fenced twice; `denied_names` and the `LD_PRELOAD` filter are refused in builder mode rather
  than carried unenforced, and a `readable` under any other mode is refused for the mirror
  reason. Every non-builder request is byte-identical to what it was, which the pinned Elixir
  and Rust tests are there to keep true.

  The capability is asked of the binary and not of the backend name (C11): `doctor` reports
  `"features": {"read_allow_set": true}`, `Helper.probe/1` turns it into `read_fence` in the
  detection map, and `Sandbox.fences_reads?/1` reads that for `:ouro_sandbox` alone — so a node
  still carrying a pre-W17 helper is refused the forge by its own report rather than fenced by
  a field that helper would reject as unknown. A detection with no such key is `false`.

  **Proved on a kernel, twice over.** `scripts/sandbox-linux-test.sh` in a privileged container
  on Linux 7.0.14 with Landlock ABI 8: **64 unit tests and 25 enforcement tests passed**, six of
  them new — a build reads the roots it was given and its own tree, cannot read a canary beside
  them (`Permission denied`, and the bytes never appear), an empty allow-set cannot even exec
  `/bin/sh`, a write outside the writable roots and into a merely-readable root both still fail,
  the network is still `Network is unreachable`, and a relative `readable` is exit 125 with the
  `ouro-sandbox: ` prefix. Then `scripts/forge-linux-test.sh`, which now builds the helper in the
  container (`make sandbox`) so detection prefers it: the run records `backend: ouro_sandbox,
  read_fence: true` before the suite starts, and the forge's own escape tests — `include_str!` of
  a planted secret, a `#[path]` module outside the project — now assert *this* backend's own
  denial string, with the honest fixture building beside them under the same policy.
  **123 passed, 18 skipped** in 116.6 s, the two escape tests being real cargo builds of 22.2 s
  and 14.2 s. The 18 are the backend-specific live *shell* tests: Seatbelt's because this is
  Linux, and bubblewrap's because detection now prefers the helper — so this script no longer
  covers bwrap's live denials, and CI's ubuntu-24.04 job, which installs `bwrap` and does not
  build the helper, is what still does.

  A read denial here is `EACCES` and nothing else, because this backend has no fresh root to
  leave a path out of and a mount cannot express a read (D26). `Sandbox.violation/3`'s rule that
  `Permission denied` is not a sandbox signal is unchanged and is a rule about *shell* output,
  where an ordinary file mode says the same thing; the forge reads the string where the program,
  the policy and the source are all this node's own.

  One defect came out of the container with it, in this slice's own change: the line that drops
  the stale `_build/.../ouroboros/priv` symlink before `make` was first written as a `find -name
  priv -type l -delete` over the whole build tree, which also took erlexec's port-binary link
  and left the suite unable to start a single native tool. It names the one path now.

  **Then an adversarial review took the first cut apart on the kernel, and the headline finding
  was that a read fence is not a write fence.** The builder inherited the shell policy's
  `/dev` and `/proc` — writable, because a shell needs `/dev/null` and this helper has no fresh
  root to mount a minimal one into — so a build wrote `/dev/shm/pwned` and read a canary another
  process of the same uid had left in `/dev/shm`, and `/dev/pts` was the same class. Three
  sentences in this repository said "writes only into the build directory, the cargo home and
  `TMPDIR`" while that was true. A builder now keeps nothing writable that its policy did not
  name: `/dev/null` by name as a Landlock rule on the file (the same single node Seatbelt's
  builder profile grants), `/dev/zero`, `/dev/urandom` and `/dev/random` readable for
  `getrandom`'s fallback, `/proc` readable and not writable, a fresh **read-only** tmpfs over
  `/dev/shm` and `/dev/mqueue`, no `/dev` listing at all, and a sweep that spares nothing.
  Proved on the same kernel: the canary is unreadable and its name is not even in the listing,
  `/dev/shm/ouro-pwned` is refused and does not appear on the host, `/dev/null` is still
  writable and `/dev/urandom` still readable — the half that has to hold for a build to build —
  `/proc/self/oom_score_adj` is refused, and a real forge still completes under it.

  Three more from the same review, each with the test that reddens for it. The read set names
  `/etc`, so an operator's secret under a platform root is readable by build-time code on every
  backend — D18 said `/etc/ssh` was outside the fence and it never was; the sentence is fixed
  and the advice is to keep credentials out of the platform roots. The fence is an existence
  oracle: `stat` still succeeds on any path the ordinary permissions reach, which Seatbelt's
  profile grants deliberately and which only bubblewrap's namespace avoids; D26 says so now.
  And the daemon carried `fs_filter_library` on every builder request while the helper silently
  discarded it, which §14 had already described as a refusal — the daemon omits it and the
  helper refuses it now, so the sentence is true from both ends. A symlinked `readable` root
  was granting its target: canonicalised on the daemon, refused by the helper, both tested.

- **W18 — every permission seam reads one setting.** `Control.Permissions.Seam` — the ACP lane,
  and the last seam that called `Control.Permissions` by name — now evaluates, records and
  suggests through the module `config :ouroboros, :permissions_engine` names, so a node given
  `Wasm.PolicyEngine` has a policy component on all four of that setting's readers rather than
  on the native loop, the interactive plane's external approvals and the interactive shell alone
  (D27). The tolerance is `Interactive.Task.Approvals`', copied rather than reinvented: the
  three answer shapes pass through, an answer in none of them is an ask, a raise is an ask by
  the `rescue` and an exit is an ask by the `catch` — proved separately, each clause red on its
  own deletion, against a test-local engine that records what it was asked and can be told to
  answer nonsense, to raise and to exit. What an engine *answers* stays the engine's authority,
  an `allow` included; what it *fails* to answer is always the ask the human was going to see.

  Two things were narrowed on the way. `remember/3` phrased its durable `:session` rule with the
  **engine's** `suggest/1`, so an engine whose suggestion was `Bash(*)` would have turned one
  approval of `ls -la` into a session-wide allow — that row is the store's now, in the store's
  grammar, and a hostile-suggestion test pins it; the engine's suggestion remains the
  `suggested_rule` hint, which nothing enforces. And `Seam.refusal/1` had flattened every non-map
  `rule_ref` into "refused by a permission rule", which is precisely what a policy component's
  deny is, so an ACP refusal named nothing: a binary passes through now, and both it and the
  pre-existing rule-map clause are bounded at 400 graphemes and stripped with the engine's own
  control class, because both put somebody else's text into a JSON-RPC error frame.

  Settled on the real wire in `test/wasm/policy_acp_test.exs`, which is
  `policy_acceptance_test.exs`' harness with the other caller and
  `test/provider/permissions_seam_test.exs`' fake vendor process: the real `no-network-shell`,
  signed by the real signing service and deployed through the real rollout, refusing an ACP
  `session/request_permission` whose `rawInput.command` reaches the network and refusing the
  `terminal/create` that arrives — deliberately — as `tool: "bash"`, each with the component's
  sha in the stated rule and in the ledger row's `rule_ref` under `actor: :classifier` and the
  session's id as the principal; an `ls -la` it does not recognise staying the ask it already
  was, with `suggested_rule` on the payload; `:policy_allowable_tools: ["bash"]` widening nothing
  by itself; an operator's own node rule still deciding; and — through a real `Session.Jsonl`
  driving a vendor process end to end — the component's deny answering the agent with its own
  `reject_once` option, no `approval_requested` ever emitted, and the ledger row attributed to
  the session the dialect bound. What that file cannot show is an `allow` degrading, because the
  example component never says one — that half of D20 is a scripted verdict in
  `policy_engine_test.exs`, which is also where "the component is not reached at all" is
  observable, since only a scripted helper lets a test count frames.

- **W19 — the artifact comes back in the frames the upload used.** The last residual W8 left
  in §12: an artifact past three quarters of the gateway frame was dropped and the source form
  signed alone, so whether a capability got the fast path was a function of how large its
  machine code happened to be. New `Ouroboros.Wasm.Download` — `Wasm.Upload`'s discipline in
  the other direction, with that module's own chunk, slot count and two clocks rather than a
  second set: `<data_dir>/wasm/download/` 0700 and `lstat`-checked, slots claimed
  `O_CREAT|O_EXCL`, 0600 files, an id minted here and re-validated on the way in, and the
  digest in the slot line so a chunk states the whole artifact's sha without re-hashing it.
  `wasm.sign` now claims a slot *before* it signs and answers `artifact: {download, size,
  sha256, chunk_bytes}` beside a `bundle_prefix` that is the header and the envelope alone,
  with `form: precompiled` and `precompile_skipped: null` — nothing is skipped for being large
  any more. `Bundle.prefix_without_artifact/2` is the seam, and `prefix/2` is defined as it
  followed by the artifact, so the split cannot drift from the encoder. `wasm.download` is
  `:operate`, node-routed, closed at three parameters, and answers a chunk of at most
  `Upload.max_chunk_bytes/0`; `ouro wasm sign` walks the slot from the node's own offsets,
  refuses an answer about a different place, holds the reassembled bytes to the receipt's size
  and digest, writes `prefix <> artifact <> component`, and prints which of the two ways the
  artifact arrived.

  Proved. Elixir: put → read → the bytes back to the byte and the digest matching; an offset
  off a chunk boundary, at or past the size, or naming an id this node did not mint each
  refused by its own name; a download past its idle clock and one past its total lifetime both
  gone, for a reader as well as a writer; a file whose slot went is not a download and is
  swept; the ninth `put` refused with eight held; the file and the directory 0600/0700, a
  symlinked root refused rather than `chmod`-ed through and a symlinked staged file never read
  through; the final chunk releasing the slot and a non-final one re-readable; and — the
  threat model's own claim — every lane-W verb given every bytes-shaped parameter shape,
  minting no slot at all, beside the closed three-parameter contract that has nowhere to put
  one. End to end over the real verbs with `max_frame` at 64 KiB and the real helper:
  `wasm.sign` names a download whose digest is the signed manifest's, `wasm.download` chunks
  reassemble to the `OUROCWASM` container, the slot is gone after the final chunk, the composed
  bundle passes `Bundle.verify/2` **and is byte-identical to `Bundle.encode/3`'s output**,
  `Rollout.stage/3` reports `precompiled: true` from the helper's own `load`, and the rollout
  settles `live` with the capability answering a message. The W8 fallback is kept and pinned:
  a node with no data directory to stage into signs the source form with
  `artifact_not_staged` and still produces a whole verifiable bundle. Rust: the three-part
  bundle total, the compose order, a chunk answered about the wrong offset (and one that is
  empty, oversized, or whose size changed under the transfer) refused, a reassembled artifact
  that does not match the manifest's digest or size refused before anything is written, the new
  `wasm_download_result` golden decoded typed, and the receipt's `artifact` block in both its
  shapes.

  What it does **not** remove is in §12, smaller than what it replaced: a node with nowhere to
  stage still falls back to the source form, a transfer whose final frame is lost is a signature
  to make again rather than a chunk to re-ask for, and the chunk is `wasm.upload`'s, so a frame
  too small for one is too small for either direction.

- **W20 — a role is a check, and the second node is real.** Three sentences §12 and §14 had
  written down as true are now false, and this slice is what made them so.

  **`:builder` was placement advice; a `:signer` now refuses to forge.**
  `Ouroboros.Wasm.Forge.placement/3` is a pure function of this node's role, `config :ouroboros,
  :wasm_forge_placement` and the connected nodes with the roles `Ouroboros.Cluster` reports —
  `:local | {:forward, node} | {:refuse, reason}` — and `forge/2` asks it before a byte of the
  input is read. A `:signer` node is `{:forge_refused, :signer_node, …}` under every setting and
  every fleet (D29, contract C14); `:local` stays the default and builds where the effect lands,
  as before; `:builder` forwards a forge that landed on a non-builder node to the lowest-named
  connected `:builder` — same input, same attrs, same server-owned principal, the origin's own
  build budget so the builder's configuration cannot widen it — through `forge_here/2`, which is
  a separate entry point so a builder never forwards again and re-asks the role question on the
  machine that will run the compiler. No builder connected is `:no_builder_node` by name and
  never a fallback to building here; a setting that is neither word is refused rather than read
  as the default. `capabilities.preview` reports the decision — `%{decision: …}` beside the
  toolchain — and a preview on a node that would not forge does not dry-build.

  What a forward carries is the **validated project inline** — the origin runs C9 itself and a
  directory name never crosses the wire — plus `:author`, `:name`, `:eval`, `:start_config` and
  two deadlines, by allow-list. The bundle comes back as bytes, is verified here with
  `Bundle.verify/2` against this node's own trust policy and held to the kind, the name, the
  principal and the receipt beside it, and is retained in the origin's forged root, so
  `Forge.deploy/3` works from the origin exactly as it does after a local forge. Cargo, the
  builder's whole forge and the origin's wait are three deadlines each strictly inside the
  next, the innermost two told to the builder rather than re-derived there, and an expiry stops
  the task and sweeps what it left. D29 has the reasoning and the four defects the first cut of
  this slice shipped.

  Proofs. The **whole** table, thirty-six combinations pinned against an expectation written
  out separately: three roles × four settings (`:local`, `:builder`, a typo, `nil`) × three
  fleets (none, one builder, two). Through the real `Ouroboros.Cluster.role/0` — set through
  the same `:persistent_term` key `boot_role!/0` writes — a `:signer` refuses `forge/2` and
  `forge_here/2`, and refuses **before the input is read**: the same three inputs answer their
  own C9 or filesystem refusals a line earlier and the signer's refusal afterwards, so a role
  check moved behind `collect/1` turns the test red rather than staying green. The scratch
  root, the bundle directory and the whole temporary tree are still empty afterwards.

  The forward is asserted on its contents through a fake `:erpc` target: given a *directory*
  input and an options list poisoned with a signing service, a signing node, epoch nodes, an
  SDK path, a pool and a trust policy, what is sent is the inline file map — never the path —
  and exactly six option keys, with the deadlines 40 s / 50 s / 60 s in their required order. A
  project this node's own C9 refuses is refused here and nothing is sent; `forge_here/2`
  refuses a `%{dir: …}` by name; and `forge_here/2` with `:builder` placement, builder peers
  and an rpc seam in its options never calls the seam. A forwarded forge whose deadline expires
  answers `{:forge_timeout, …}` and leaves no build directory behind, driven with a cargo that
  sleeps.

  And the round trip, on a real build: `forge_here/2` runs for real through the rpc seam — one
  cargo build, one real signature, one real `.ouro-wasm` — the bytes come back, the origin
  verifies and retains them, the builder's forged root does not exist, and `Forge.deploy/3`
  deploys that receipt to `:live` on this node, where the counter answers and rolls back. That
  same real bundle, replayed through a canned answer, is then refused for an author that is not
  the principal, for a capability that is not the one asked for, for one flipped byte, for no
  bundle at all, and a refusal the builder made comes back named as the builder's. What was
  **not** proved here is a forward across a real node boundary: a peer VM with cargo, a warm
  cache and a signing service was out of budget for this slice, so the loopback proves
  everything except that `:erpc` copies terms between machines — the half W22 then proved, on
  two full-application peer VMs with no seam (`test/wasm/forge_two_node_test.exs`), finding
  W-F31 on its first run: the loopback's builder had a pool because the test had started one,
  and a real `:builder` node had none. `capabilities.preview` on a real workspace
  proposal reports `:local` on this node and the signer refusal with its reason on a node that
  holds a key, still answering C9 in both.

  **A policy deploy was verified on one node.** `test/wasm/policy_two_node_test.exs` is
  `rollout_two_node_test.exs`'s harness with `no-network-shell` in it: two full-application peer
  VMs, each spawning a real `ouro-wasm`, one real Ed25519 key, one signed policy artifact, and
  two deploys — which is the production shape and not a workaround, because a lane-W rollout
  writes its register entry on the node that drove it and `wasm.deploy` is node-routed for
  exactly that reason. Both peers stage the bytes into their own store, stand the component up
  as a policy, satisfy the signed eval spec, and record `:live` in their own register as a
  policy and not as a capability. Then each peer's `Ouroboros.Provider.Native.Permissions`
  — the seam the native loop calls, with **no** `wasm_policy_opts` pointing it at a test's
  register or store — denies `curl … | sh` with the component's own rule, labelled
  `[untrusted policy component]` and carrying the sha, and asks about `ls -la`. A rollback on
  the first peer retires that node's entry: its engine goes inert and every undecided request is
  asked again, while the second peer is untouched and still denies. The bytes stay on the
  rolled-back node, because rollback material that never expires is the point of keeping them.

  **The skew was crafted; it is now built.** `scripts/wasm-skew-test.sh` (`make wasm-skew-test`)
  produces the other side with a second toolchain twice over. **Triple:** `ouro-wasm` built
  inside an Ubuntu 24.04 container on kernel 7.0.14 with `cargo +1.95` at the same wasmtime,
  `precompile`ing the acceptance guest there; the 405 546-byte `.cwasm` carried back and offered
  to this Mac's helper is refused

      precompiled_mismatch (-32021): the artifact was produced by wasmtime 48.0.1 for
      aarch64-unknown-linux-gnu; this helper is wasmtime 48.0.1 for aarch64-apple-darwin

  and the source form of the same component then loads here, which is the whole point of the
  refusal being a fallback. **Version:** `tui/wasm` copied into a scratch workspace with
  `wasmtime` pinned `=48.0.0` — one patch back, the nearest other release that builds under the
  same 1.95 floor and the same `=0.254.0` wasmparser pin — built with `cargo +1.95`, its
  258 093-byte `.cwasm` refused

      precompiled_mismatch (-32021): the artifact was produced by wasmtime 48.0.0 for
      aarch64-apple-darwin; this helper is wasmtime 48.0.1 for aarch64-apple-darwin

  Neither half runs in CI and neither is a `mix test` away: only `make wasm-skew-test` produces
  the artifacts, and `test/wasm/skew_test.exs` skips with that target in its reason when they
  are absent — including under `OUROBOROS_REQUIRE_WASM`, because a machine without Docker and a
  spare wasmtime cannot make them and a failure there would say nothing.

  Both artifacts are then put to the Elixir half in `test/wasm/skew_test.exs`, twice each,
  because a deploy is only honest if both fallbacks hold. A manifest recording the *producing*
  build — what a signer on that machine would really have signed — makes `Wasm.Store.form/4`
  answer `{:source, …, {:target_mismatch, …}}` or `{:wasmtime_mismatch, …}` without the helper
  being asked at all, and the rollout still reaches `:live`. The same real bytes under a
  manifest claiming *this* node's build get offered by the store, and the container's own
  header — written by the other toolchain, not rewritten by a test — is what the helper refuses;
  `Wasm.Pool` compiles the source and the guest answers a message. The artifacts are built
  rather than checked in, because a `.cwasm` is a built binary and this repository keeps none of
  those in git; the suite skips with the script's name in the reason when they are absent.

  What W20 does **not** change: role is still not a boundary against a hostile connected node
  (`Ouroboros.Cluster`, "Limits") — a peer that completed the handshake calls `forge_here/2`
  directly, and a compromised signer does not need to build at all. What the check stops is the
  accident. And turning `:builder` on is a trust an operator extends rather than a fence they
  raise: a peer's role is that peer's own claim over the handshake, the lowest name wins, and
  the node so chosen sees the source of every capability the fleet forges and produces bytes
  the fleet's signer signs under the origin's principal. D29 says what the origin can still
  check when the bundle comes back, and what it cannot. And a precompiled artifact is still bound to one wasmtime and one triple; W20 proves
  what §12 says about that with two real toolchains instead of asserting it from one.
- **W21 — the helper's process is sealed.** D25 and §12 had written down, by name, four things
  the macOS wall left open around a process that maps a signer's machine code: `process-exec`
  over the readable `/usr/bin`, so a compromised `ouro-wasm` could run `osascript` and `do
  shell script` its way **out** of the sandbox; `mach-lookup`, which is launchd and the
  pasteboard; `sysctl-read`; and `file-read-metadata` over all of `/`, an existence oracle over
  the whole filesystem. The reason given for leaving them was C10's "a fourth profile to keep in
  step with three others", and that reason was wrong: the Seatbelt profile was already a
  function of the policy's fields the moment W16 added `loopback` to them. So W21 adds a field.
  `Sandbox.helper_policy/1` says `process: :sealed` by default, `builder_policy/1` says `:open`
  (a forge is cargo forking rustc), and the sealed Seatbelt profile allows `process-exec` for
  **one literal** — the executable the child was spawned as, resolved, as `-D OURO_EXEC` — no
  `process-fork`, no `mach-lookup`, `sysctl-read` under `hw.` only, `file-read-metadata` on `/`
  itself plus one literal per symlink on the way to a root, `signal (target self)`, and `(deny
  network*)` with nothing after it. The builder's profile text is unchanged and pinned whole
  beside the sealed one. A sealed policy refuses a `{:shell, _}` and a relative argv[0] in
  `Sandbox.wrap/4`, by name. `Sandbox.seals_process?/1` is the third question beside
  `fences_reads?/1` and `fences_network?/1`, answered by backend — Seatbelt yes, bubblewrap
  and `ouro-sandbox` no — and the pool does **not** gate on it: `:required` still means reads
  and network. `Pool.status/1` and `wasm.status` carry `sandbox.process` — `sealed`, `open`,
  `off`, or `null` where nothing spawned — as the posture the child actually got, with the
  fixture, the protocol row and the golden regenerated. The signer's `precompile` runs under
  the same sealed policy.

  Three things were measured before any of it was designed, and two of them corrected the
  brief. `sandbox-exec` applies the profile and then `execvp`s the target inside it, so a
  profile with no `process-exec` starts nothing: the seal is a literal, not a removal. Seatbelt
  matches that literal against the path the kernel **resolves**, not the spelling `execvp` was
  given — a literal naming `_build/test/lib/ouroboros/priv/wasm/ouro-wasm` never matches, a
  literal naming `priv/wasm/ouro-wasm` matches either spelling, and the spelled one only if the
  kernel may read the `priv` link on the way, which is a metadata read on the link; so the
  "both spellings as parameters" of the first cut is one resolved parameter, `SandboxExec.wrap/4`
  spawns by the resolved path, and the same rule is what makes a store spelled `/var/folders/…`
  readable: `SandboxExec.links/1` names each symlink on the way to a root, and nothing beside
  it — `/var/root` stays absent. And the `sysctl` surface: with none the Rust runtime aborts
  mapping a guard page; with `hw.pagesize_compat` alone it runs `doctor`, `precompile` and
  `serve` — and `precompile` emits a **different artifact** from the same component than the
  unsealed helper, because cranelift reads `hw.optional.*` to detect the CPU, which would be a
  sealed signer and its loader disagreeing about the machine. The prefix is the narrowest set
  that keeps them agreeing, and a hardware fact is not a secret.

  Proofs, each a pair under the real `helper_policy/1` and the real `builder_policy/1` with the
  same roots and scratch, so a denial is a fence and not a broken `bash`: `bash -c 'exec
  /usr/bin/id'` is `Operation not permitted` sealed and a uid open, and a `$(…)` is `fork:
  Operation not permitted`; `osascript -e 'do shell script "id"'` as the target itself fails
  sealed and prints the uid open; `pbpaste` exits 1 sealed and 0 open (chosen over `launchctl
  list`, which exits 1 under both on this macOS and proves nothing); `test -e` on a planted file
  outside the roots is absent sealed and present open, while `stat` inside a root still works;
  a root through a link this test made is readable by both spellings sealed, and a file beside
  the link is absent; the real helper answers `doctor` sealed by its canonical path and through
  a symlinked directory, and dropping the resolution turns the second red; `{:shell, _}` and a
  relative argv[0] are the named refusals sealed and wrap under the builder; the W16 loopback
  probe runs `nc` as the target so it still proves the network denial and not an exec one; the
  sealed profile and the builder's are pinned whole, and a builder policy with no `process`
  field renders the same text; `Bwrap.options/3` and `Helper.request/2` render a sealed policy
  byte-for-byte as an open one. `test/wasm/pool_acceptance_test.exs` and
  `capability_acceptance_test.exs` run the real helper **sealed** with default options — a real
  `load`, `call`, epoch deadline and memory limit under the profile is the proof that `hw.`-only
  sysctl and no fork are enough for wasmtime and tokio — and the status says `sealed` where the
  backend seals and `open` where it cannot. The scripted fake helpers of this repository's own
  suites are `#!/bin/sh` and `awk`, which the seal cannot run — macOS `/bin/sh` re-execs
  `/bin/bash` as its variant, and `awk` is a fork — so they say so:
  `SandboxFixture.scripted_pool_opts/1` and `scripted_helper/0` set `scripted_helper: true`,
  the one opt-out, on the pool and on `Deploy.sign/2`, and it is a fixture with no configuration
  key behind it. Every real-helper suite — the acceptance suites, the forge's `live!`, the
  signer's real `precompile`, the two-node tests — runs sealed; `capability_acceptance_test`'s
  one stderr-reading test keeps its `#!/bin/sh` tee wrapper and is the one pool there that says
  it is scripted.

  What W21 does **not** close, named in D25: the helper may re-exec itself; it reads every
  `sysctl` under `hw.`; it may `stat` `/` and the links on the way to its roots; and neither
  Linux backend seals — bubblewrap's namespace has `/usr/bin` executable, so a compromised
  helper there can exec within it, and Landlock does not fence `stat`, so `ouro-sandbox` keeps
  the existence oracle bubblewrap does not. `LANDLOCK_ACCESS_FS_EXECUTE` is the follow-on for
  the exec half on `ouro-sandbox`; this slice changes no Rust. The Linux half is CI's, as W16's
  was. And the wall is still around the process and not in front of the bytes: D24's residual
  is unchanged in kind, a patched artifact still runs with the helper's authority — an authority
  that is now the roots, the scratch, no network, and one process that can only be itself.

- **W22 — the forward crosses a real node boundary.** W20 left one sentence standing: the
  loopback proved everything about a forwarded forge except that `:erpc` copies terms between
  machines. `test/wasm/forge_two_node_test.exs` is that half, and it is
  `rollout_two_node_test.exs`'s harness with a role in it: the origin is the test VM as `:core`;
  the builder is a full-application peer VM booted with `config :ouroboros, :node_role,
  :builder`, a warm cargo home named in its configuration, an SDK that resolves from the code
  path it runs from, and `:signing_node` pointing at a third peer; the signer is a peer booted
  `:signer`, running the application's own named `Ouroboros.Upgrade.Signing.Service` from a seed
  file `OUROBOROS_SIGNER_KEY_PATH` names in its environment and a `:signer_id` from
  configuration — the shape a signer host has, not a service a test started and named. One
  Ed25519 seed is generated by the test so the origin and every peer trust the same public half
  before anything boots, and the signer's `public_info/1`, asked over `:erpc`, answers that key.
  Nothing the origin passes names a peer: placement is read from `:wasm_forge_placement`, the
  builder from `Ouroboros.Cluster.nodes_by_role/1`'s real multicall, the signer from the
  builder's own configuration. No `:peers`, no `:rpc`.

  Proofs. **The round trip**, on one real cargo build: the origin forwards the counter, the
  builder builds it under its own pool and sandbox, asks the signer peer, and answers with bytes;
  the origin verifies them with `Bundle.verify/2` against its own trust policy, retains them in
  its own forged root with no `:bundle` key in the receipt, deploys that receipt to `:live` on
  itself, and the counter answers `%{"count" => 2}` and rolls back. The signer's journal holds
  the `:issued` decision under the **builder's** node name and none under the origin's. **The
  builder kept nothing**: no `.ouro-wasm` anywhere under its data directory, no forged root, and
  an empty build scratch once its `after` ran. **A `:signer` refuses over the wire**: `forge_here/2`
  and `forge/2` called on the signer peer by `:erpc` with a valid inline project answer
  `{:forge_refused, :signer_node, …}` and its build root never appears — the check is in front of
  the input on a real peer too. **No builder connected** — the origin and the signer peer — is
  `{:forge_refused, :no_builder_node, …}` before any RPC, with neither node's scratch root
  created. **The deadline crosses the wire**: a 22 s budget hands cargo 2 s, the origin sends a
  `%{dir: …}` proposal — the production caller's shape — and the builder's build directory holds
  the origin's `src/lib.rs` byte for byte while cargo runs, so what crossed was the files; the
  refusal that comes back is the builder's own `{:build_failed, {:timeout, :deadline}}` —
  cargo's ceiling, the innermost of the three — named as the builder's, after cargo's two
  seconds and inside the origin's twenty-two, and the builder's scratch is swept. The same peer
  handed a directory name directly refuses `:path_over_the_wire` and builds nothing. **A builder
  that dies mid-build**: the forge runs in a task, the builder's build directory appears, its VM
  is stopped, and the origin answers `{:forge_forward_failed, builder, {:error, "…noconnection…"}}`
  within fifteen seconds of the stop against a 120 s budget — distribution closes the socket, it
  does not wait for the tick — and no cargo or rustc of that builder's survives on the host.
  **Preview reports the decision**: `capabilities.preview` on the origin answers
  `%{decision: :forward, node: builder}` with `build: :not_placed_here` while the builder is
  connected, and `%{decision: :refuse, reason: :no_builder_node, detail: …}` when it is not,
  still answering C9 in both; `Forge.placement_report(Forge.placement_here())` says the same.

  The first run found **W-F31**: a `:builder` node's supervision tree was cluster formation
  alone, and `forge_here/2` reads the imports off the product through this node's helper pool,
  so a real builder ran the whole cargo build and then answered `{:imports_unreadable,
  {:pool_unavailable, …}}`. The loopback could not have seen it — its builder was the origin,
  whose pool the test had started. `Ouroboros.Wasm.Supervisor` now starts on a `:builder`; a
  test without a toolchain boots one and reads its tree, and the `:signer` is proved to run no
  pool. The W11 lesson did not bite: the builder allocated its epoch over the origin's rollout
  plane alone, because the plane probe excludes the signer and the builder itself, and that was
  observed as a signature issued rather than `{:epoch_not_allocated, …}`.

  Honesties. **One host.** Two VMs share a kernel, a toolchain, a sandbox backend and a
  filesystem, and the test leans on the last of these — it watches the builder's scratch from
  the origin's side of the boundary. A second physical machine with a different kernel, cargo
  and sandbox backend on the builder is still unwatched; CI's Linux job running this file on one
  Linux host is the other half of the same limit. **One build.** The `%{dir: …}` shape is proved
  through the deadline test's smaller assertion rather than a second completed forge, so a
  directory proposal that builds to completion over the wire is inferred from the files having
  crossed and the inline shape having completed, not watched end to end. **The dead builder's
  cargo** is watched only on this host's process table; that the builder's own `Exec` signals its
  group when the VM's port closes is what made it true here. And the `nodeup` log line names a
  freshly connected peer `:core` — it is probed before its application has booted and D29's
  fallback answers — which is not what `nodes_by_role/1` reports once the peer is running, and
  is the documented open direction rather than a defect.

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
