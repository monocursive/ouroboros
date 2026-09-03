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

**Authoring a component.** The world above is what a guest binds against, and `tui/wasm/guest`
(`ouroboros-guest`) is the crate that binds it so an author does not. It owns the `no_std`
ceremony — the allocator, the panic handler, the canonical ABI's `cabi_realloc`, the
`wit_bindgen::generate!` and the instance's state cell — behind one macro call, and offers
four seams over the one world: `Capability` (a JSON body in, a JSON reply out) for the mesh,
`Hook` (a typed payload, a `Verdict`) and `Check` for §8.1's two contracts, and `Raw`
underneath them for a reply that must be stated verbatim. `#![no_std]` stays the author's own
line, because it is the claim and not the ceremony: `std` on `wasm32-wasip2` imports thirteen
`wasi:io`/`wasi:cli` interfaces the helper's linker refuses, and such a build does not
instantiate at all. Four worked components live in `tui/wasm/guest/examples/` — one per seam,
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
| `doctor` | — | `{usable, wasmtime, worlds: [supported world ids], imports, limits, held: {components, instances, evictions, evicted}, notes}` |
| `inspect` | `{path}` | `{sha256, world, imports, exports, size}` — parsed from bytes / refusal (`unreadable_component`, `component_too_complex`, `compile_failed`) |
| `load` | `{sha256, path}` | `{…as inspect, cached, evicted: [sha]}` / refusal (`sha_mismatch`, `unsupported_world`, `undefined_import`, `component_too_complex`, `too_many_components`) |
| `instantiate` | `{instance, sha256, config, limits: {fuel, memory_bytes, deadline_ms}}` | `{instance, fuel_used, log_lines}` / init error |
| `call` | `{instance, export, payload}` | `{payload, fuel_used, log_lines}` / trap / deadline |
| `drop` | `{instance}` | ok (idempotent) |

Enforcement lives here and is structural: the linker defines exactly the functions the
supported world imports (`log`, in v1) and nothing else, so **an unlisted import fails
instantiation — authority cannot be smuggled past a lying manifest** (D5). Every call
runs under a fuel budget, an epoch deadline, and a store memory cap; exhaustion is a
typed refusal, not a hang. A wasmtime panic or segfault kills a Port, not the node —
which is the point of the helper (D3).

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
id, epoch, name, component_sha256, world, imports, size, created_at,
metadata (author, source_sha256?, language?, test_report?, eval?, start?), signature
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
6. **start block.** `metadata.start`, when present, must be exactly
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
never "just links less."

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
   holds the sha does nothing). The claim stored beside the target's high-water mark makes
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
`.ouro-wasm`: a 17-byte header (magic, format version, and the envelope and component
lengths), a bounded JSON envelope carrying the manifest as its own `term_to_binary` plus
the signer id and the 64-byte signature, and then the component bytes **raw**. The big
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
signer.

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
the bytes they uploaded, so returning them would mean building a chunked download to hand
somebody their own file back. `wasm.deploy` verifies the bundle against the node's own
trust policy **before** the store, the helper or the register hears about it, then runs
`Wasm.Rollout.deploy/4` unchanged; a rollout that ran answers with its state rather than
with an error, because `:rolled_back` and `:quarantined` are outcomes a client renders.
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
*capability-world* components: the helper implements exactly one world,
`ouroboros:capability@0.1.0`, and a hook is a strict subset of a capability — one string
in, one string out, log-only. The hook payload goes in through `handle-message`, the
stdout contract comes back as its reply, `init` receives the hook's declared `config`
(or `"{}"`), and `describe` is unused. Containment is identical, because containment is
the linker. The dedicated world is kept here as the deferred design, for when the helper
grows a second one — an event of the same kind §12 makes of a world's import set, not a
convenience:

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
  whichever verb consumes it. The **result** direction needs no chunking, because
  `wasm.sign` answers with the bundle's prefix and the client appends the bytes it already
  holds.

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
## 12. What this does not solve

Stated once, so nobody reads more into the lane than is there:

- **Judgment.** The permission engine still decides; a prompt-injected model still
  emits hostile effect *requests*. Wasm bounds what granted authority can reach, it
  does not improve the grant decision.
- **The host functions are the new surface.** Every import added to a world is
  boundary code. v1's answer is austerity: `log` only. Growth of any world's import
  set is a signing-policy event, not a convenience.
- **wasmtime is a dependency, not a proof.** It has had escape CVEs; they are rare and
  patched fast, and the helper process (which can itself be OS-sandboxed later) is the
  second wall. Pin it, watch its advisories, and keep its dialect small — §7.3's disabled
  proposal list is surface removed from cranelift, not just from the spec.
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
- **W8 — ahead-of-time compilation (proposed, not promised).** `Component::new` on the
  node's hot path is what makes §7.3's bounds necessary in the shape they have.
  `Engine::precompile_component` at sign or deploy time and `Component::deserialize` at
  `load` would move cranelift off the node entirely: a `load` becomes an mmap of an
  artifact somebody else already compiled, and the admission question stops being "how
  expensive is this to compile" and becomes "how large is this artifact" — a question a
  byte cap answers exactly. It is also the first of two preconditions for admitting
  engine-embedding guests (§1); the second is a world broad enough for `wasi:io`, or a
  runtime build that does not want it, and that one is a signing-policy decision rather
  than an engineering one (§12). Unbuilt, and carrying its own questions — a precompiled
  artifact is bound to a wasmtime version *and* a target triple, which is the lane-B
  triple problem arriving by another road, and deserializing bytes is trusting a compiler
  output the node did not produce, so what gets signed would have to be the precompiled
  form. Written down because the bounds above are the shape of a host that compiles, and
  a reader should know which constraint is essential and which is a consequence.
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
- **Deferred, in rough order:** policy engine (§8.2) → agent-reachable forge/deploy
  effects (§7.7) → tools lane (§9.1) → microVM backend (§10, likely its own spec
  once slice-shaped) → agent world (§9.2).

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

  Three things the verification found, all reported rather than papered over. **`ouro wasm new`
  still embeds the pre-SDK template**, not `tui/wasm/guest/template/`: the `TODO(W9)` at
  `tui/src/wasm_cli.rs` was never closed, so a scaffolded project is standalone hand-rolled
  ceremony with no `Hook` trait in it, and W9's entry above reads as though the swap had
  happened. The guide documents both routes and says which is which. **`wasm.sign` cannot
  allocate an epoch on a cluster that has a `:signer` node** — the allocation asks every node in
  `[node() | Node.list()]` for `Upgrade.NodeExecutor.status` and the lane-W register, and a
  `:signer` runs neither, so the topology C4 prescribes refuses with `epoch_not_allocated`
  carrying a `noproc`; reproduced on a two-node dev cluster, and the sign→deploy→ls→rollback
  transcript in the guide is therefore from a node running its own signing service. And
  `ouro wasm keygen` **prints back the `--out` path it was given**, so a relative one produces
  an `OUROBOROS_SIGNER_KEY_PATH` line the signer node then refuses as non-absolute.

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
