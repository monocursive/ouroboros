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
| `instantiate` | `{instance, sha256, config, limits: {fuel, memory_bytes, deadline_ms}}` | ok / init error |
| `call` | `{instance, export, payload}` | `{payload, fuel_used}` / trap / deadline |
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
functions compiled in 28.9 s on this Mac — and the helper is sequential, so that is
28.9 s in which every hook and every capability on the node waits, long enough for the
pool's 30 s `load` deadline to break it and drop every live instance. So
`tui/wasm/src/shape.rs` walks the component and everything nested in it with
`wasmparser` (the same parser wasmtime itself uses, already in this binary's graph),
reading section headers without decoding an instruction, and refuses
`component_too_complex` on any of: code bytes (4 MiB), functions (20 000), types
(8 192), imports and exports (1 024 each), other index-space definitions (16 384), data
and element segment bytes (4 MiB), nesting depth (8), core modules (64), nested
components (64), and sections (8 192) — every one a total over the whole tree. The
numbers are measured, not felt: at the worst admissible shape the release helper
compiles in 1.19 s, one function past the bound is refused in 0.14 s without anything
being compiled, and the acceptance guest declares 101 functions against 20 000 and
40 721 code bytes against 4 MiB — two orders of magnitude under the two dimensions that
measure compile cost. `doctor` reports all eleven under `limits`, and the source pins
them by value so moving one is a deliberate act with a fresh measurement behind it.
Custom-section *bytes* are not weighed, only counted — wasmtime skips them, so sixty
mebibytes of custom section costs the read and the digest, not the compile.

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
2. **checkpoint `:deploying` before any effect** into the existing `Rollout.Registry` —
   `entry.module` is already `module() | String.t()`; lane W writes `"wasm/" <> name`,
   and checkpoint v3 widens the entry with `component_sha256` (same struct-widening idiom
   as v1→v2's `eval_report`). The epoch gate is inside that same serialized call, and the
   watermark it checks against is a **durable high-water mark** (`lane_w_epoch`, additive,
   no version move) rather than the highest surviving entry: derived from the entries
   alone, `prune/2` could discard the settled rollout that held the highest number and
   free it for replay. `test_report` and `detail` are bounded and portability-checked on
   the way in, the same as `eval_report` — both arrive from a requester, and a durable
   store an attacker sizes is not one;
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

Every entry is re-validated when the checkpoint is read, against the same validators
`deploying/2` applies: a planted `epoch: 999_999_999_999_999` used to refuse every future
lane-W deploy for as long as the file existed. One bad entry is **dropped with a logged
reason and the rest of the register loads**, because refusing the whole checkpoint for
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
- **Refusing a disabled proposal can still cost a compile.** A component using, say,
  `return_call` is refused by the engine, but the refusal arrives from cranelift's
  translator rather than from a pre-pass, so a large module can be compiled up to the
  offending function before it is rejected. Bounded by §7.3's structural pass, not by
  zero.
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

The W7 review wave (2026-09-02) found the rest. All fixed in W7.

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
- **W-F8 (MED):** the lane-W epoch watermark was derived from surviving entries, so prune
  could lower it (§7.6 step 2).
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
  repository could supply the containment boundary itself. Removed.
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
- **W-F24 (HIGH, helper):** compilation was unbounded — 28.9 s for a 61 MiB in-world
  component, a node-wide stall (§7.3). **W-F25 (MED, helper):** engine proposals were not
  minimized (relaxed SIMD, tail calls and the rest were accepted) (§7.3).

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
