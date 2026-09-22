# Jail v1: first implementation specification

Status: implementation specification, revision 5, 2026-09-22. No implementation
or backend conformance is claimed by this document.

Parent: [North star](../../north-star.md), principally §§3–4 and §7. This document
specifies the complete first jail milestone and its smaller, first executable
slice. It does not implement the ledger or fleet. Linux is the first execution
platform; Linux and macOS are long-term requirements. A macOS build in this
milestone supports policy inspection and reports execution as unsupported.

[Managed teams v1](managed-teams-v1.md) composes this primitive with company
authorization, ledger, isolated inputs and bounded artifacts. Those features
ship later; this milestone provides the policy/receipt/gate seams they require.
Here, "managed gate" means an external launch owner, not proof of organization
policy, authenticated developer identity or a compliant company deployment.

Normative words: **must** is a release gate, **initial** is a tunable default
that must be recorded, and **candidate** is unproved until the named evaluation
passes. The backend choice and observer privilege model remain implementation
gates, not facts established by this specification.

## 1. Outcome and scope

The delivered tool runs an operator-supplied `argv` under an explicit policy,
owns its process tree, observes a documented set of operations, and produces a
receipt describing what actually happened and what remains unknown. It runs
without BEAM, a ledger daemon, a fleet, an agent SDK, or provider credentials.

The complete milestone ships:

- `ouro-jail run`, `explain`, `doctor`, `gc`, and `version`.
- `agent`, `tool`, `build`, and explicit `none` profiles; operator policy files;
  narrowing-only project configuration; declarative launch profiles.
- Linux filesystem, network and syscall enforcement; standalone supervision,
  managed launch gating, limits, tree termination, vendor-state cleanup.
- The jail-owned observer, bounded trace transport, coverage and gap reporting,
  and prepared/enforced/settled receipts.
- Three experimental launch-profile data files and an independent scripted
  conformance suite. Real credentials are not required to pass that suite.
- Portable Rust policy/record code and native macOS compilation and refusal
  tests, so the next platform does not require redesigning the public model.

Excluded: agent protocols, conversation state, approvals, PTY allocation,
workspace cloning/export, remote execution, ledger signing/query/retention,
automatic installation of privileged services, and a production macOS backend.
There is no generic plugin framework or public Rust ABI. The stable boundaries
are the CLI and versioned records.

### 1.1 First executable slice

Before implementing the complete milestone, deliver `tool` execution on one
provisioned Linux host: policy resolution → capability probes → observer attach
→ prepared receipt → release → command → tree termination → settled receipt.

The fixture must write an allowed file, fail a protected access, exec a
descendant, and exceed a wall deadline in a separate run. Check actual syscall
results, output, exit status, receipt phases and tree emptiness. Implement
`--observe off` as well, but an off-only demonstration does not close this
slice. This is the first implementation PR after the bounded feasibility work
in §5, not a declaration that milestone 1 is complete.

## 2. Authority, threat model and invariants

The operator, host kernel, installed Ouroboros binary and pinned backend are
trusted. The child, its descendants, its workspace and project configuration
are untrusted. A malicious administrator, compromised kernel, or another
uncontained process with the operator's authority is outside the containment
claim. A fleet peer will be a trusted operator, not a sandboxed tenant.

In a company-managed deployment the trusted operator is the worker's launch
owner. Developers submit to that owner; they do not receive operator credentials,
gate handles, worker shells or fleet membership. Company policy is resolved by
the owner before calling this tool. A developer-administered laptop can bypass
its local invocation, so the jail alone cannot enforce company-wide usage.

| ID | Invariant |
|---|---|
| I01 | No user command executes before all required boundaries, observation and output preparation succeed, and any managed gate releases. |
| I02 | A missing requirement refuses before exec; it never selects `none` or `observe=off` implicitly. |
| I03 | The supervisor, observer, proxy authority, receipt store and control channels remain outside the contained child. |
| I04 | Exactly one supervisor owns an attempt. No automatic child restart or retry occurs. |
| I05 | Child exit, tree termination, evidence health and cleanup are separate facts. |
| I06 | Events assert only the operation and result actually established by their source. |
| I07 | All buffers, probes and waits have bounds; evidence pressure cannot prevent deadline handling. |
| I08 | `none` always carries `child_protection: unprotected`, including after a clean exit with complete observations. |
| I09 | Credentials and raw argument/environment values never enter receipts or traces. |
| I10 | Linux-only objects stay behind platform interfaces and optional platform record details. |
| I11 | A child-visible policy edit cannot widen a running attempt. |
| I12 | GC acts only on registered, identity-checked attempt resources and never follows child-created links out of them. |

Named limits from the north star remain limits. Writable workspaces can contain
shared inodes or Git alternates. The jail does not turn them into private
repositories. `none` cannot protect same-UID evidence or guarantee cleanup after
its supervisor dies. Removing vendor state unlinks managed files; it neither
erases disk blocks nor finds copies made elsewhere. The syscall set is not a
complete history of file contents, network requests, or all host operations.

## 3. Platform contract

### 3.1 Shared semantics

Shared code owns CLI parsing, configuration provenance, policy narrowing,
profile expansion, capability requirements, lifecycle transitions, redaction,
record encoding, resource budgets and the conformance harness. OS code owns
path identity, launch mechanics, containment, observation, process identity,
tree termination, monotonic clocks and filesystem durability primitives.

An execution capability is a structured result, not `sandbox_available=true`:

```text
Capability {
  name,
  status: available | unavailable | unsupported | error | skipped,
  scope: process | tree | host,
  mechanism,
  reason_code,
  measured_at,
  evidence_ref
}
```

`available` means the relevant probe succeeded on this host with this identity.
`unsupported` means the implementation lacks it; `unavailable` means the
implementation exists but prerequisites are missing. A skipped check cannot
satisfy a requirement. A previous `doctor` result is diagnostic; launch repeats
security-critical preparation for the actual attempt.

The policy expresses semantics such as `network=none`, `wall=30m`, tree-scoped
termination and protected-path coverage. It does not ask for `cgroup_v2=true`
or a Seatbelt expression. The selected platform plan states how it will satisfy
those semantics and refuses when it cannot.

### 3.2 Initial support matrix

| Surface | Linux v1 | macOS in this milestone | Later macOS execution |
|---|---|---|---|
| Parse, resolve, narrow, digest, render policy | Required | Required | Shared |
| Schema encoding and fixture validation | Required | Required | Shared |
| `version`, `explain`, `doctor --json` | Required | Required, execution capabilities unsupported | Shared format, native probes |
| Containment | Selected D8 integration | Unsupported | Native backend, independently evaluated |
| Closed-set observation | Selected observer | Unsupported | Native source with explicit semantic coverage |
| Process identity | pidfd while live plus boot/birth identity | No execution identity | Native stable identity, no synthetic pidfd |
| Tree limits and termination | Namespace/cgroup mechanisms | Unsupported | Must prove the requested scope |
| `run`, including `none` | Required on eligible hosts | Refuse 125 before exec | Per-capability support |
| Active cleanup | Registered Linux resources | Does not touch Linux resources | Native resource identity checks |

Initial Linux conformance target: the reference host, an operator-provisioned
x86_64 virtual private server running Ubuntu 26.04 LTS on its 7.0-series
kernel, pinned to the exact kernel build the manifest records. The host must
run its own kernel under hardware virtualization. A container-based server
that cannot create user namespaces, delegate a cgroup v2 subtree with the
pids, memory and cpu controllers, or permit the observer's attachment is
ineligible, whatever the provider calls it. `doctor --json` on that host
produces the host manifest, which the J0 report and every conformance run
record: kernel release and build, architecture, distribution, bubblewrap and
selected-backend versions and hashes, cgroup v2 delegation as seen from the
operator's session, the values of `kernel.apparmor_restrict_unprivileged_userns`,
`kernel.unprivileged_bpf_disabled`, `kernel.perf_event_paranoid` and
`kernel.yama.ptrace_scope`, any operator-installed AppArmor profile, and the
mechanism by which tracing capabilities were provisioned (§5.2). Until
`doctor` exists, [host-manifest.sh](jail-v1/host-manifest.sh) collects the
same facts read-only; its first run is
[evidence/reference-host-2026-09-22.txt](jail-v1/evidence/reference-host-2026-09-22.txt),
and `doctor --json` output supersedes it. Ubuntu 24.04 and later restrict
unprivileged user namespaces through AppArmor by default. Where the
distribution's own `bwrap-userns-restrict` profile is measured sufficient, as
it is for basic mounts and namespaces on the reference host
([evidence](jail-v1/evidence/bwrap-probe-2026-09-22-ouro-ci.txt)), no operator
change is needed; otherwise the operator either installs a scoped profile
granting `userns` to the required executables or changes that sysctl. All of
these are host policy: the tools report the state and change none of them. Conformance runs on the host as a dedicated operator account,
`ouro-ci`: no sudo, lingering enabled so its `user@` service delegates the
cgroup controllers, the provisioned tracing capabilities, and nothing else
(§16). A VM is acceptable; a container that cannot delegate the required
kernel features is not a substitute for the release runner. Linux aarch64
gets its own native conformance run before it is advertised; it is a later
lane, not the reference host. No promise is made about all kernels newer than
a version.

The native macOS CI lane initially targets Apple Silicon; Intel compilation is
additional evidence, not an execution support claim. Both architectures remain
possible through the platform contract.

### 3.3 macOS work that must remain possible

Containment, observation and lifetime are separate decisions. A future native
backend may use Seatbelt through an evaluated integration, but Apple marks
`sandbox-exec` deprecated in the shipped `sandbox-exec(1)` manual. It is a
candidate with maintenance risk, not a permanent product dependency chosen here.
Paths must be passed as data/parameters, never inserted into policy source.

Endpoint Security is an observation candidate. It requires an Apple-granted
[client entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client);
deployment permission, event availability and distribution must be evaluated
before selecting it. Its native event meanings must be mapped individually.
An authorization request or sandbox denial log is not a successful syscall
result and cannot populate a success coverage class by analogy.

There is no assumed macOS equivalent of a Linux cgroup or PID namespace.
Per-process rlimits, process groups, or polling a list of descendants do not
establish the same tree lifetime guarantee. The macOS implementation must prove
fork/exec/daemonization, stop, supervisor death and resource-limit semantics.
Until it does, a policy requiring those guarantees refuses, including `none`.

Future native tests must also cover `/var` versus `/private/var`, case-sensitive
and case-insensitive APFS, symlinks, application bundles and dynamic libraries,
TCC restrictions, credential-file versus Keychain access, nested vendor
sandboxes, and signed/notarized distribution. macOS support never requires the
operator to disable SIP or silently grant Full Disk Access. Any required host
provisioning must be explicit in that platform's implementation proposal.

## 4. Source layout and ownership

The repository is one workspace (north star D7). Rust crates live under
`crates/`, one per process the north star names, plus a shared records crate,
a test-only fixture crate and a task runner. The Elixir fleet is a sibling Mix
project outside Cargo. Contracts and measured evidence stay under `docs/specs/`.
A directory is created when its milestone starts; its name and the rule that
creates it are fixed here so milestone 2 does not reopen them.

```text
Cargo.toml  Cargo.lock  rust-toolchain.toml  .cargo/config.toml  deny.toml
LICENSE  .gitignore  README.md  north-star.md
crates/
  ouro-jail/          J1   library + the `ouro-jail` binary (this specification)
    src/{lib,main,cli,config,policy,profiles,capability,supervisor,observer,
         network,records,trace,state,cleanup}.rs
    src/platform/{mod.rs,linux/,macos/}
    profiles/launch/  codex.toml, claude.toml, opencode.toml: data only
    tests/            integration and conformance tests; tests/fixtures/
  ouro-fixture/       J1   the conformance child binary (§15) and harness helpers
  ouro-jail-ebpf/     J1   the observer's BPF object, only if J0 selects eBPF
  xtask/              J1   repository tasks: I02 scan, BPF build, conformance driver
  ouro-records/       M2   wire types, canonical bytes, schema identifiers
  ouro-ledger/        M2   library + the `ouro-ledger` binary
  ouro/               D6   the front door; `ouro managed` verbs join it at M4
fleet/                M3   standalone Mix project; no NIF; its own BEAM release (D6)
docs/specs/           now  <name>.md beside <name>/ with schemas, fixtures, validators
docs/specs/jail-v1/evidence/   host manifests, raw fixture output, performance reports
docs/proposals/       ad hoc  proposals for the north star's unscheduled items
.github/workflows/    now  contracts, rust, conformance; release after milestone 3
packaging/            D6   reserved; empty until after milestone 3
```

- Start with one jail crate, library plus binary. `ouro-records` is carved
  out of `ouro-jail` when `ouro-ledger` becomes its second consumer, not
  before. `ouro` is created with D6 packaging, or earlier only if the managed
  client needs a binary first. Managed composition code lives in `ouro` and
  `ouro-ledger`; no `ouro-managed` crate exists until a second consumer does.
- `ouro-fixture` is the compiled child §15 requires. Tests locate it through
  Cargo's built-binary environment variable. It is never packaged, and it is
  exempt from I02 together with `profiles/launch/`, documentation and fixtures.
- `ouro-jail-ebpf` is not a default workspace member: it needs a BPF target
  and linker that portable builds and macOS never have. `xtask` builds it on
  Linux; the Linux platform module embeds the object and records its digest
  (§16). Whether it exists at all is decided by J0.
- Schemas are single-sourced under `docs/specs/`. Rust tests read them by a
  path relative to the crate manifest, and the schema identifiers that
  `ouro version --json` announces are constants tested against those files.
- `fleet/` is outside Cargo. Nothing under `crates/` depends on it, which
  keeps I01 literally true; its own gates (north star §10) run only when it
  changes.
- Every crate sets `publish = false`. Binaries are named exactly `ouro`,
  `ouro-jail` and `ouro-ledger` (D6).
- `xtask` owns checks that are not unit tests: the I02 vendor-name scan over
  `crates/ouro-jail/src` and `crates/ouro-ledger/src`, the BPF build, and the
  conformance driver. Until it exists, the link check is
  `docs/specs/validate_links.py` beside the schema validators.

Use stable Rust, pin the toolchain and dependencies in the implementation PR,
and deny warnings in CI. Keep `unsafe` at small OS/FFI boundaries with stated
preconditions and adversarial tests. No NIF or BEAM dependency enters the jail.
Backend-specific dependencies use target-specific Cargo sections; portable
modules must build on macOS without Linux headers, libbpf or a Linux linker.

Conceptual internal interfaces (not frozen Rust signatures):

```text
resolve(inputs) -> ResolvedPolicy
plan(policy, host) -> PreparedPlan | Refusal
platform.prepare(plan) -> PreparedExecution
observer.attach(prepared_execution, observation_contract) -> Observer
prepared_execution.release() -> RunningExecution
running_execution.request_stop(reason)
running_execution.wait_tree() -> TreeObservation
observer.finish() -> CoverageSummary
state.replace_receipt(receipt) -> DurableWriteResult
```

`PreparedExecution` must own an actual blocked launcher and actual applied
resources, not just backend command arguments. It exposes the child boundary's
identity before release. A containment adapter cannot hide the launch gate,
place the observer inside the jail, or replace the required observer with its
own differently scoped logs.

The shared supervisor coordinates these interfaces. Linux implements the
required execution operations. macOS initially returns typed unsupported
results. Do not fill macOS methods with successful no-ops.

## 5. Backend and observer feasibility gate

Do this before committing to a production backend or freezing schemas. The
evaluation is bounded by the existing milestone requirements; it does not add
new product features.

Order inside J0: provision the reference host and record its manifest (§3.2),
measure the observer privilege model (§5.2) first, then evaluate the
enforcement candidates (§5.1). A blocked observer changes which backend is
worth integrating. The report's skeleton,
[backend-evaluation.md](jail-v1/backend-evaluation.md), is checked in with
every measurement marked `not_started`; a value there is a claim only once the
host manifest and the raw fixture output it cites exist beside it.

### 5.1 Enforcement candidates

Evaluate pinned revisions of [sandbox-runtime](https://github.com/anthropics/sandbox-runtime),
[Greywall](https://github.com/GreyhavenHQ/greywall), and the legacy sandbox
implementation at commit `f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82`.
The first two already wrap OS sandbox mechanisms; their integration remains
subject to Ouroboros's own policy and lifecycle tests. Record exact commits,
licenses, binary/package hashes, transitive executables and runtime dependencies.

For each candidate, record pass/fail/unsupported with fixture evidence for:

1. Closed filesystem view, protected paths, network mediation and seccomp.
2. Literal `argv` and paths, including spaces, quotes, newlines and non-UTF-8.
3. A real prepared gate, visible process identity and reliable exec failure.
4. An outside supervisor, observable descendants and nested sandbox behavior.
5. Deadline, signal, parent-death and verified tree termination behavior.
6. Required resource limits, fd closure, environment and credential isolation.
7. Dependency footprint, cold/warm startup, memory, integration size, license
   obligations and maintenance burden.
8. Whether its macOS code offers reusable mechanisms without dictating shared
   policy or falsely promising equivalent coverage.

The network gate includes pathname Unix sockets already present or created
later in shared mounts, proxy endpoint replacement, and asynchronous socket
creation (§§9.2, 10; S04, N05). An agent candidate must preserve same-attempt
IPC while denying unauthorized host peers. A startup scan of socket paths is
not sufficient. Record the tested enforcement mechanism; refuse the affected
profile when none passes. No socket-isolation mechanism is presumed selected.

Prefer the smallest integration passing the gates. A thin native Rust adapter
over bubblewrap/seccomp is permitted only when a named failure or measured
integration cost justifies the missing mechanism. The existing sandbox is a
source of fixtures and code to inspect, not a conformance oracle. It previously
allowed broader reads and had different network fallback behavior.

The implementation records its decision in
[backend-evaluation.md](jail-v1/backend-evaluation.md). The checked-in skeleton
fixes the report's shape; it contains no measurement, and its presence is not
completion of D8. The completed report must include the host manifest, raw
fixture locations and a gap-to-gate table. Only the chosen integration becomes
a shipping dependency.

### 5.2 Observer candidate and privilege boundary

The first candidate is a Linux eBPF observer owned by the supervisor, filtered
to the attempt before collecting arguments. Evaluate it separately from D8's
enforcement candidates. No audit daemon, vendor protocol or seccomp-notification
service is introduced.

The proof must identify attach points, kernel/configuration dependencies,
required capabilities, attachment lifetime, descendant tracking, event loss,
startup latency and runtime overhead. The reference deployment aims for a
non-root operator process with narrowly provisioned tracing capabilities and a
delegated cgroup. `CAP_BPF`/`CAP_PERFMON` are candidates to measure; their names
alone do not establish that a particular host permits attachment. Kernel
[perf security documentation](https://docs.kernel.org/admin-guide/perf-security.html)
describes capability and host-policy checks that affect tracing.

The first release does not install a setuid helper, run the user's command as
root, change sysctls, grant file capabilities or edit AppArmor. The operator
provisions the documented reference environment. Effective UID 0 execution and
mismatched real/effective UIDs refuse in v1. A provisioned supervisor must clear
ambient/inheritable/effective/permitted tracing capabilities on every backend,
bridge and user-child launch path. Clear the supervisor's no-longer-needed
capabilities after attachment, and set `no_new_privs` before child exec.
Prove the child cannot reacquire privileges; user-namespace capabilities are
separately confined and do not grant host capabilities.

Capability provisioning is the operator's act on the reference host, and J0
records which mechanism was used: ambient capabilities granted by the systemd
service or user unit that starts the supervisor (`AmbientCapabilities=`), or
file capabilities the operator sets on the supervisor binary. Neither is
installed by the tools. Measure the smallest set that attaches: `CAP_BPF` and
`CAP_PERFMON` are the candidates on the pinned kernel; needing `CAP_SYS_ADMIN`
is a failed measurement, not a fallback. Record whether the AppArmor
user-namespace restriction, `perf_event_paranoid` or a hardened
`unprivileged_bpf_disabled` interfered, and how the operator resolved each.

If the eBPF candidate cannot attach under a provisioning the operator accepts,
or cannot satisfy the closed set, J0 measures these fallbacks against the same
§11 semantics before any is selected. None is selected here:

- A ptrace tracer in the supervisor, attached to the launcher before exec with
  `PTRACE_O_TRACEEXEC`, `PTRACE_O_TRACEFORK`, `PTRACE_O_TRACEVFORK`,
  `PTRACE_O_TRACECLONE` and `PTRACE_O_TRACEEXIT`, reading results at
  syscall-exit-stop; the exec event is a confirmed transition. Under the
  default `kernel.yama.ptrace_scope=1` an ancestor needs no capability. Known
  limits to measure: two stops per traced call unless a seccomp filter with
  `SECCOMP_RET_TRACE` narrows stops to the closed set, and a call that reaches
  such a filter with no tracer attached fails with `ENOSYS`, which must be a
  tested failure mode; attachment is per thread and bound to the attaching
  thread; a traced tree cannot be traced by anything inside it; attribution
  across PID namespaces and PID reuse needs its own fixture.
- `fanotify` for the filesystem classes only. It cannot supply a confirmed
  exec transition, `proc.exit` or `net.connect`, so it can at most combine with
  another source and cannot alone make the closed set active.

The kernel audit subsystem, an LSM or BPF-LSM program and a privileged host
daemon are not candidates: each is host-global or needs a separate proposal.
A fallback that passes O01–O06 with its own measured overhead may become the
selected observer for the pinned host. The north star's rule that the sensor
lives in the supervisor, outside the child and outside the enforcement
backend, applies to it unchanged.

No observer attachment means refusal with `--observe on`. An explicit
`--observe off` remains usable wherever the containment/lifetime requirements
can be met. It is not an automatic compatibility fallback. If the candidate
cannot satisfy the closed set, record that blocked gate and revise the observer
choice before marking the first executable slice complete. A general privileged
host service would require a separate proposal.

Measure at least 30 launches each for a no-op command, a descendant-heavy fixture
and a fixed file-operation workload, with observation on/off. Report median/p95
startup, wall time, peak RSS, event counts and losses on the named host. Initial
budgets: under 250 ms p95 added warm startup and under 20% median overhead on the
fixed workload. These are engineering decision thresholds, not customer claims;
exceeding one requires a recorded adjustment before backend freeze. Missing or
incorrect evidence cannot be waived as a performance tradeoff.

## 6. CLI and configuration

### 6.1 Commands

```text
ouro-jail run [--profile agent|tool|build|none|FILE] [--launch NAME]
  [--workspace PATH] [--scratch PATH] [--rw PATH]... [--ro PATH]...
  [--deny-read PATH]... [--allow-host HOST[:PORT]]... [--limit KEY=VALUE]...
  [--observe on|off] [--evidence strict|best-effort]
  [--receipt PATH] [--trace-fd N] [--control-fd N] [--gate-fd N]
  [--attempt-id ID]
  [--label-only] -- PROGRAM [ARG]...
ouro-jail explain [policy selection and override flags] [--json]
ouro-jail doctor [--profile NAME|FILE] [--launch NAME] [--json]
ouro-jail gc [--dry-run] [--json]
ouro-jail version [--json]
```

`PROGRAM` is mandatory except with `--label-only`. Execution accepts literal
OS argument bytes, never a shell command string. Shell semantics require the
operator to explicitly supply a shell and its arguments. Resolve `PROGRAM`
using the resolved child's PATH and cwd, not the supervisor's privileged
environment; the executable must be visible under the final policy. Scripts
and dynamic executables need their interpreter/runtime paths visible as well.

Default profile: `tool`, or the launch profile's `jail` when `--launch` is set.
Default workspace: the invocation directory. Default scratch: a new private
attempt directory. Default observation: `on`. Default evidence: `strict`.
`--profile none` is the only way to select `none`; files and environment cannot
select it. An explicit contained profile may override a launch default only
when its requirements still permit that launch profile's credentials/network.
`tool` and `build` reject launch credentials and proxy grants.

`--label-only` resolves, probes and prints a proposed execution label, without
executing the user command or copying credentials. `explain` does not probe or
execute anything, and distinguishes requested policy from measured capability.
`--label-only` rejects `--gate-fd` and `--attempt-id` as usage errors.
Inspection JSON goes to stdout; diagnostics go to stderr. `run` preserves child
stdout/stderr byte streams and has no `--json` stdout mode.

`--control-fd` carries structured control messages instead of textual launch
diagnostics. `--trace-fd` carries events. Each supplied fd must be open, have the
correct direction, be distinct from all other supplied channels and stdio, and
be owned exclusively for the invocation. The child inherits only validated
stdio, not those channels. Fd validation fails before preparation.

### 6.2 Paths and precedence

On both Unix platforms, configuration defaults to `~/.config/ouro/config.toml`
and runtime state to `~/.local/share/ouro`. `OURO_CONFIG_DIR` and `OURO_DATA_DIR`
override these locations. Runtime state must be a private local directory owned
by the operator and outside every child-visible grant. Files are mode 0600,
directories 0700. Reject symlinked state roots, foreign ownership, unsafe parent
replacement and network filesystems whose required durability is unproved.

Apply configuration in this order:

1. Built-in profile and operator config/selected operator profile.
2. Operator launch profile, if any.
3. Operator environment settings from a fixed documented allow-list:
   `OURO_CONFIG_DIR`, `OURO_DATA_DIR`, `OURO_JAIL_OBSERVE`,
   `OURO_JAIL_EVIDENCE`. No environment-derived path or host grants.
4. Explicit CLI grants and limits.
5. The workspace-root `ouro.toml`, which can only narrow that resolved authority.

Steps 1–4 are trusted operator inputs, not developer-submission authority. A
managed owner must resolve company/project/attempt ceilings first, then supply
the resulting grants through private operator configuration. It must not forward
submitter `OURO_*`, CLI override flags, arbitrary host paths or credential source
paths into those layers. The jail does not load organization identity policy.

Reject unknown keys and duplicate keys; do not silently ignore future policy
keys. Apply paths relative to the file containing them, except CLI paths are
relative to invocation cwd. Only operator files expand a leading `~/` against
the operator home. No variable interpolation, executable includes or recursive
profile inheritance. Custom profiles extend exactly one built-in contained
profile. Built-ins and operator files are separate from project data.

`config.toml` stores jail defaults under `[jail]` and subordinate tables such
as `[jail.limits]`; it may contain `jail.profile = "tool"` or an operator
profile file path. The remaining jail keys are the policy keys below, without
`extends`; `jail.schema` is `ouro.jail.policy/1`. A project `ouro.toml` uses the
same `[jail]` shape but forbids `profile` and `extends`. Selected operator profile
files use the top-level shape below. Launch files are
`<config-dir>/launch/<name>.toml`; names match `[a-z][a-z0-9_-]{0,63}` and never
contain a path separator. Paths in a launch file are relative to that file.
The operator config may also supply `[jail_host.network] translation_prefixes`
as a set of canonical IPv6 CIDRs for the provisioned network. This is host
configuration, forbidden in project/profile files, and is merged into proxy
policy before digest creation. The host manifest records those exact values.

### 6.3 Policy shape and narrowing

The public policy shape is semantic TOML. This complete example is a custom
operator profile that tightens `tool`:

```toml
schema = "ouro.jail.policy/1"
extends = "tool"

[filesystem]
read_only = ["./fixtures"]
deny_read = ["./secrets"]
protected_coverage = "existing_and_root"

[limits]
wall = "5m"
pids = 64

[observation]
mode = "on"
evidence = "strict"
```

File keys: `schema`, `extends`, `filesystem.read_write`, `filesystem.read_only`,
`filesystem.deny_read`, `filesystem.protected_coverage`, `network.mode`,
`network.allow`, `limits.wall`, `limits.pids`, `limits.mem`, `limits.cpu`,
`observation.mode`, and `observation.evidence`.
`extends` is required for custom profiles, forbidden in project config;
project fields live under `[jail]` with the same subordinate tables.
Launch data has a separate grammar (§12). User-supplied seccomp, SBPL, backend
command fragments and arbitrary environment entries are not policy keys.

| Change in a narrowing file | Decision |
|---|---|
| Remove writable/visible authority or make a writable subtree read-only | Allow |
| Add a denied subtree | Allow |
| Require stronger protected-path coverage | Allow; refuse at capability check if unsupported |
| Lower a wall, pids, mem or CPU ceiling | Allow |
| Add a previously absent finite limit | Allow, and require its enforcement |
| Change proxy network to none, or shrink its allowed host set | Allow |
| Enable observation or change best-effort to strict | Allow |
| Add a host/path grant, increase/remove a limit, weaken coverage/evidence | Refuse with the exact key path |
| Add credentials, launch profile, executable, `none` or backend settings | Refuse |

Compare authority after expansion and path resolution, not TOML ordering or
string prefixes. `/work/a` is not an ancestor of `/work/ab`. Denial wins over
an overlapping allow. Read-only carve-outs override writable parents. A host
wildcard is a set of DNS labels, not an arbitrary string suffix. Network and
path normalization must use the same implementation in comparison and launch.
Unknown or ambiguous subset relationships refuse; they do not widen.

The resolver produces an immutable snapshot and separate input provenance.
[Canonical bytes](jail-v1/canonicalization.md) defines the complete digest
input, native-string codec, set ordering, domain labels, argv framing and
golden fixtures. Use RFC 8785, not a language's default JSON serialization.
Store the snapshot privately before child launch; receipts carry its digest.
Equivalent semantic inputs have the same digest despite different provenance.
Digests are consistency identifiers, not a promise that low-entropy secrets
cannot be guessed. P01 must use the checked-in expected bytes and digests.

### 6.4 Limits and errors

Supported `--limit` keys are `wall`, `pids`, `mem`, `cpu`. CLI duplicates refuse.
`wall` is a positive integer with `ms`, `s`, `m` or `h`; `pids` a positive
integer; `mem` positive bytes with optional `KiB`, `MiB`, `GiB`; `cpu` a positive
integer percentage where 100 means one core of aggregate execution capacity.
Integer parsing and unit multiplication check overflow. A zero, negative,
unbounded or unknown value is usage error. CPU is a bandwidth ceiling, not a
CPU-seconds timeout. Wall always exists.

This table is authoritative for initial defaults and requirements:

| Profile | wall (required) | pids (preferred) | mem | cpu | Execution cgroup |
|---|---|---|---|---|---|
| agent | 2h | 512 | Absent unless explicit | Absent unless explicit | Required by observer or explicit tree limit |
| tool | 30m | 256 | Absent unless explicit | Absent unless explicit | Required by observer or explicit tree limit |
| build | 1h | 512 | Explicit ceiling required | Absent unless explicit | Required for memory |
| none | 2h | Absent unless explicit | Absent unless explicit | Absent unless explicit | Required for lifetime, including observe off |

Every explicit limit from CLI, operator or project config is required, even
when it equals a preferred default. Attempt preferred pids enforcement when
delegation and its controller are usable; otherwise record the requested value
with `required=false`, `applied=false`, null mechanism/hit/scope and
an explanatory wrapper note. Missing a preferred controller alone never refuses.
Observer/lifetime requirements can require a cgroup without requiring its pids
controller. `none` may enforce explicit cgroup limits but still cannot protect
them against same-UID interference. No unspecified memory/CPU ceiling is implied.

Linux measures execution wall, preparation/gate/stop budgets and event elapsed
time using `CLOCK_BOOTTIME`: suspend counts, wall-clock adjustments do not.
An expired deadline is acted on when execution resumes; the supervisor cannot
run during suspend. Later macOS uses a native continuous clock with the same
suspend semantics. Pids, memory and CPU use their separate cgroup mechanisms.

Exit codes: child's code on a completed execution; `128 + signal` for a
signal-terminated child; 1 for a tool failure; 2 for invalid CLI/config syntax;
125 for refusal before user exec. A post-launch tool error takes code 1 and
preserves the separately observed child outcome in the receipt. Deadline or
requested termination preserves the observed code/signal and records its cause.
A child exiting 125 is `outcome.kind=exited`, not `refused`.

Inspection commands use 0 for success, 2 for invalid syntax/config, and 1 for
an operational failure. `doctor` and `run --label-only` additionally use 125
when the requested execution plan is unsupported or unavailable, including
macOS execution; their reports still describe each capability. `explain` and
`version` succeed on macOS. `gc` uses 0 for a completed scan (including skips
reported with reasons), and 1 for failed cleanup or state access. JSON output
does not change exit codes.

Errors have a stable code, stage, safe message, optional config-key path and
required `remediation_category`: `configuration`, `host_setup`, `unsupported`,
`retry`, or `inspect_state`. This is guidance, never an automatic retry.
Initial codes include `invalid_config`, `policy_widening`,
`unsafe_state_path`, `unsupported_platform`, `missing_capability`,
`backend_unavailable`, `observer_unavailable`, `nesting_failed`,
`credential_unavailable`, `invalid_fd`, `gate_invalid`, `gate_closed`,
`prepare_timeout`, `attempt_exists`, `exec_failed`, `evidence_lost`, `tree_unknown`, and
`state_write_failed`. Do not include raw credentials, raw argv or environment
values in an error.

## 7. Attempt state and persistence

An attempt id is a cryptographically random UUIDv4 with the RFC 9562 variant,
encoded in lowercase as `att_<uuid>`, allocated once and
never reused. Standalone execution generates it. Managed composition may pass
`--attempt-id ID` only together with `--gate-fd`; this lets a future launch
owner bind a pre-existing reservation to the jail's receipts. Validate the id
grammar before deriving any path. It is not an arbitrary directory argument.
Managed caller-supplied IDs use the same version/variant grammar. IDs identify
attempts; possession of an ID grants no authority.
Local attempts are not deduplicated operator requests.

```text
<data>/attempts/<attempt-id>/
  jail.lock             exclusive live-supervisor lease
  jail-state.json       identity, lifecycle, owned resources, cleanup status
  policy.json           immutable resolved policy and digest
  jail.json             latest receipt, atomically replaced
  trace.ndjson          default bounded standalone event sink
  vendor-state/         only when a launch profile requires it
  scratch/              default child-writable scratch, not the state parent
```

The supervisor holds `jail.lock` through settlement/cleanup. A future owner
uses its own lease, not this lock. An existing attempt root is acceptable only
with validated ownership/permissions and no previous jail state or jail-owned
artifacts. Claim it with exclusive creation of `jail-state.json` while holding
the lock. A prior jail claim, live or dead, refuses `attempt_exists`; the caller
reconciles it rather than spawning again. Test concurrent claims and crashes
after claim creation. The child cannot inherit the lock.
Register resource ownership before populating credentials
or launching helpers. State updates use create-new temporary file, write,
file sync, atomic rename, and parent-directory sync. A successful rename alone
is not a durable acknowledgment. Platform code defines and tests its sync
guarantee. Failed/ambiguous persistence before exec refuses; after exec it
stops the tree and leaves an incomplete receipt if necessary.

`--receipt PATH` is an additional atomically replaced receipt copy; canonical
state stays under the attempt directory. The path must be outside every
child-visible root and may not be a symlink, device or existing unrelated file.
Refuse unsafe overlaps before exec, including a broad grant of the state
directory's ancestor. `none` keeps these ownership checks but cannot enforce
their protection against the child. No path option redirects GC ownership.

State names the OS and backend version, boot identity, live owner birth
identity, registered execution boundary, vendor directory and cleanup progress.
Serialized Linux identity is `{pid, boot_id, start_time_ticks}`; a pidfd is a
live kernel handle, never a serialized integer to reuse after restart. The
portable record uses `process.identity.kind` plus platform details.

## 8. Preparation, gate and execution lifecycle

### 8.1 State machine

```text
resolving → probing → preparing → prepared → released → running
      \________ pre-exec failure → refused                  |
                                                        stopping
                                                           |
                                                       reconciling
                                                           |
                                                        settled
```

Pre-exec failure includes an unsuccessful target `exec`, even when a trusted
launcher or backend helper has already run. Helpers are implementation
processes; `exec_observed` always refers to the operator's target command.
Termination after target exec cannot be reclassified as a pre-exec refusal.
Uncertainty about whether target exec occurred becomes `unknown`, not refused.

Preparation steps, in order:

1. Parse and resolve authority; allocate and lock private state; validate fds,
   workspace and output paths; write the immutable policy snapshot.
2. Probe the selected mechanisms and requirements. Register scratch/vendor
   resources before creating their contents. Prepare trace/control sinks.
3. Create execution boundaries and start only trusted setup helpers. Establish
   the blocked target launcher inside the final boundary. Record its stable
   identity and close opportunities to inherit host fds or capabilities.
4. Attach the observer and verify scope while target exec remains blocked.
   Start an outside proxy and any constrained inside bridge if required.
5. Validate actual mount/filter/limit state and the death chain. Persist the
   prepared receipt; publish a `prepared` control message with attempt id and
   policy digest. No target instruction has run.
6. Wait for a valid external release if `--gate-fd` was supplied; otherwise
   release locally. Start the monotonic wall clock at release.
7. Execute the exact target argv through the blocked launcher. Use a dedicated
   close-on-exec error channel plus backend/observer evidence to distinguish
   success from exec failure. EOF alone is insufficient if launcher death could
   also have closed that fd. Persist the enforced receipt after confirmed exec.
8. Monitor child status, evidence, control, limits and lifetime independently.
   Target exit triggers termination of remaining attempt descendants; background
   children do not become an independent service. Preserve target outcome.
9. Verify tree death, drain observations through the final boundary, persist
   settled receipt, then clean managed vendor state and update cleanup status.

A crash after target exec but before the enforced receipt can leave only a
prepared receipt. That is incomplete evidence, not proof the target never ran.
GC does not relaunch a command or fabricate an execution result.

### 8.2 Managed gate protocol

The owner must compare the prepared receipt's attempt, policy and argv bindings
and applied requirements with its authorized plan before release. A future
company-managed owner also binds its input manifest, service/policy revisions
and business authorization outside the jail. A matching digest proves identity
of the snapshot, not that its permissions were authorized. Withhold/close the
gate on any mismatch; possession of the gate is trusted process authority only.
The generic gate schema remains independent of business identity and fleet.

The inherited gate is a private pipe readable only by the supervisor. Its sole
valid release is one UTF-8 NDJSON frame, followed by writer close:

```json
{"schema":"ouro.jail.gate/1","action":"release","attempt_id":"att_00000000-0000-4000-8000-000000000001","policy_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

Maximum frame: 1,024 bytes. Read through EOF before releasing, so an extra frame
or trailing bytes cannot be accepted after exec. Wrong schema, action, identity,
digest, malformed JSON, empty EOF or oversized frame refuses. The owner keeps
the gate private, waits for `prepared`, durably admits that exact attempt in a
future ledger, sends this frame and closes. A second release never starts a
second child. The supervisor closes the gate before target exec.
The frame must end in exactly one LF; CRLF, a missing LF, blank lines and bytes
after that LF refuse. The byte cap includes LF. JSON whitespace inside the
single line is allowed; parse duplicate object keys as an error.

Initial preparation budget: 30 seconds; external gate wait: 60 seconds after
prepared. Both use monotonic time and are distinct from the execution wall
budget. Expiry refuses and tears down prepared resources. A future owner must
handle a timed-out prepared attempt through reconciliation, not reuse the gate.

For managed Linux mode, verify and record the direct owner's birth identity,
install the parent-death signal, then recheck the parent to close the setup
race. Contained runs must have a tested death chain from owner to supervisor to
namespace init. In `none`, owner/supervisor loss preserves the accepted unknown
lifetime limit; there is no new watchdog.

Control output uses NDJSON, with schema `ouro.jail.control/1`, attempt id,
monotonically increasing message number, and kind `prepared`, `exec_confirmed`,
`refused`, or `settled`. Messages carry receipt phase/digest and safe outcome,
never raw argv. Maximum frame is 64 KiB. This is reporting, not a vendor or
interactive approval protocol.

### 8.3 Fds, stdio and supervision

Foreground stdio is inherited without capture or parsing. The supervisor must
not retain writable copies that postpone EOF. No PTY or interactive job-control
emulation is provided. The command runs in a new session; INT/TERM/HUP received
by the supervisor request termination. Existing terminal fds are explicit I/O
authority; the backend must prevent TIOCSTI-style terminal injection.

Reject socket or directory stdio descriptors for contained runs, and reject
regular-file stdio that resolves into protected supervisor state. Pipes, tty
devices, `/dev/null` and operator-selected ordinary file redirects are allowed;
receipts record descriptor kinds without exposing paths. All other fds close
before exec, including namespace, directory, BPF, proxy-authority, state,
receipt, gate, control and trace fds. Any inside bridge gets only its declared
data-plane socket, never supervisor control authority.

Use a single owner of lifecycle transitions. Signal handlers wake the loop;
they do not allocate, serialize JSON or perform cleanup. The implementation
may use an async event loop or bounded worker threads, but slow disk/trace I/O
must not block signal or deadline handling. After a fork from a multithreaded
process, only async-signal-safe setup may execute before exec; prefer a small
trusted launcher/re-exec path over arbitrary Rust `pre_exec` work.

## 9. Linux containment and process lifetime

### 9.1 Filesystem plan

Every contained run starts from a closed view. Bind only declared system,
workspace, scratch and credential roots; never bind `/` read-only as a shortcut.
Resolve distribution symlinks such as `/bin` into `/usr/bin`. Initial runtime
roots are `/usr`, `/bin`, `/lib*` and the specific `/etc` files listed in the
north star. Extra toolchain roots require explicit operator grants. A broad
system root can itself contain operator-installed files; the receipt lists the
actual mounts rather than claiming every system file is harmless.

The jail grants the supplied objects; it does not copy a repository or isolate
shared writable inodes/Git alternates. A managed owner must materialize and
validate its private input tree before requesting these grants. Its proof of
isolation belongs to managed MT04–MT05, not to a successful workspace mount.

Mount a private `/proc` for the child PID namespace and a minimal `/dev`.
Do not expose host `/proc`, `/sys`, cgroupfs, host namespace handles, Docker or
SSH-agent sockets. Denied subtrees within visible parents are absent or masked
by the backend. Scratch provides the child's temporary directory; generated
`TMPDIR` is a reserved environment variable, not an inherited host path.

Preparation pins source path identity with directory/file handles where the
backend permits it and verifies it at mount handoff. Do not follow an untrusted
symlink between policy validation and grant construction. If the selected
backend cannot bind a validated object without a relevant race, that is a
failing D8 gate. After launch, replacement/rename of host objects is outside
the stable-path claim; the kernel's mounted objects remain the applied grant.

For `tool`, enumerate existing `.git` and `.ouroboros` path segments beneath
each writable root without following symlinks out of it. Initial scan limits:
100,000 directory entries and depth 128. Reaching a bound refuses instead of
claiming complete `existing_and_root` coverage. Root-level protected literals
must also be protected when absent. If the adapter needs temporary mountpoint
placeholders, register their exact inode identities and ownership before use;
remove only unchanged, empty placeholders it created after tree death. Never
remove a pre-existing Git file/directory. The evaluation must record any visible
workspace side effect of this mechanism.

A protected symlink cannot authorize its target. Test file-form `.git`, nested
repositories, symlink replacement and mount replacement separately. A newly
created protected segment below a previously ordinary nested directory remains
outside Linux `existing_and_root` coverage. Requiring `all_descendants` refuses.

### 9.2 Syscall and namespace plan

Use the selected unprivileged bubblewrap integration with user, mount, PID,
network, IPC and UTS namespaces, a new session and a tested parent-death chain.
Install the contained target's filter only after trusted outer setup. The
filter is versioned, architecture-aware and recorded by digest. Set
`no_new_privs` and drop host capabilities before any user instruction executes.

Common baseline denies host tracing/inspection (`ptrace`, `process_vm_*`,
`bpf`, `perf_event_open`), kernel replacement/module interfaces, keyring grants
listed by the north star, and terminal injection. Validate syscall architecture
before syscall numbers; handle x86 compat/x32 explicitly by denial unless
tested. Native aarch64 uses its own verified table. A syscall's absence on one
architecture is not a missing-probe success.

All contained profiles deny `io_uring_setup`, `io_uring_enter` and
`io_uring_register` with EPERM, including compatible ABI variants. No ring fd
may be inherited. `IORING_OP_SOCKET` must not bypass the AF_UNIX restriction;
disclaiming io_uring observation does not enforce this boundary. S04 checks
socket/open/connect paths through io_uring. A later exception needs a revised,
tested enforcement contract; it is not enabled by a launch profile. `none`
installs no such filter and retains the documented closed-set exclusions.

`tool` and `build` forbid mount changes and new/joined namespaces after setup.
Cover both legacy and modern mount interfaces and namespace flags in `clone`.
Because seccomp cannot safely dereference `clone3`'s argument structure, the
initial tool/build policy returns `ENOSYS` for `clone3` and tests the normal
thread-creation fallback; it does not pretend to inspect that pointer. Deny
`AF_UNIX` creation through both `socket` and `socketpair` for those profiles.
Their network namespace and absence of inherited sockets remain the boundary.
The reference conformance toolchain uses glibc. Other runtimes must pass their
own threading fixture; a runtime that cannot fall back is incompatible, not
a reason to silently allow `clone3`.

`agent` uses a separate nesting filter permitting the setup actually needed
by the scripted inner sandbox. It may permit mount/unmount and namespace
creation within the outer restricted authority. It must not recover excluded
paths, make locked read-only mounts writable, join a host namespace or obtain
direct egress. Record the allowed setup operations and probe the real nesting
sequence, not just one successful `unshare`. If safe nesting fails, refuse
`agent`; do not disable the outer or inner sandbox. Seccomp restrictions are
inherited; namespace creation does not remove them.

The backend may use more restrictive mechanisms when their behavior passes
the same contract. There is no arbitrary seccomp expression in user config.
The concrete filter table is part of the pinned backend evaluation.

### 9.3 Lifetime and cgroups

The supervisor remains outside the child's namespace and resource boundary.
Use a live pidfd and recorded boot/birth identity when addressing a process;
never signal a PID recovered from a file without revalidating its identity.

For a contained run, record the namespace-init identity and verify the selected
backend's entire death chain, including any intermediate launcher. Linux kills
remaining namespace processes when its init dies; this is the mechanism behind
the required parent-death test, not an assumption about process groups.
See [PID namespace semantics](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html).

When required by a limit or observer, create a unique cgroup beneath an
operator-delegated v2 subtree. Keep the supervisor outside that execution leaf.
Register its path, filesystem identity and attempt association; place the
blocked target inside before release. Delegation must permit the required
controllers, membership operations, `cgroup.kill` and population checks.
Do not assume the root of a user's existing service cgroup is an empty leaf.
Helpers charged to the attempt must be listed; the outside observer/proxy are
excluded and have their own bounded resources.

`none` creates the supervisor-owned execution cgroup even with observation off.
It mounts no jail, installs no containment filter and inherits the host view.
It still closes private control fds, strips reserved environment variables and
uses the same deadline logic. Same-UID interference remains possible, including
interference with the supervisor's resources; `unprotected` is never upgraded.
Tree termination describes the verified boundary, not proof that an uncontained
malicious child could not tamper with that boundary or launch effects elsewhere.

For `none`, `lifetime.verification_scope=registered_boundary`; `tree_empty=true`
means this identity-checked cgroup was observed unpopulated. It does not certify
that every process ever descended from the target is gone. Target exit remains
an independent wait/pidfd fact: empty population never synthesizes `exited` or
`signaled`. Reap the target before normal settlement; a still-live target after
stop remains nonsettled even if it migrated out. On detected membership escape,
identity replacement or failed verification, set `lifetime.integrity=lost`,
clear `tree_empty`/`verified_at`, retain state and report `tree_unknown`. Preserve
an independently known target outcome; use unknown only for missing facts.
This is detection, not a promise to discover all migrations of an uncontained
descendant. R06 includes both target migration and a migrated descendant after
the target exits; the latter must retain the registered-boundary scope.

Termination triggers are target exit, operator signal, wall expiry, a fatal
backend failure or evidence loss under strict mode. Initially allow 2 seconds
for cooperative termination, then force termination. The grace is included in
the reported stop interval; it does not extend the recorded execution deadline.
For immediate hard limits or an already dead owner, do not wait for a grace.

Terminate the namespace init and/or invoke `cgroup.kill`, then verify the
cgroup's recursive `populated=0` when in use, reap owned children, and close
helper resources. `cgroup.kill` handles concurrent forks within that tree;
the [kernel contract](https://docs.kernel.org/admin-guide/cgroup-v2.html)
does not make a process-group signal an equivalent operation.

Initial forced-stop verification budget: 5 seconds. Uninterruptible processes
can exceed it. Preserve `tree_empty=null`, `outcome=unknown` as appropriate,
retain live resources and return a tool error; do not announce settlement or
delete vendor state. A direct child exit never proves its descendants are gone.

`pids.max`, `memory.max` and `cpu.max` implement requested tree ceilings on the
execution cgroup. CPU uses a 100 ms period initially. Memory OOM and pids
events are read with a launch baseline and attributed only to this attempt.
Do not infer OOM from exit 137, or an exceeded limit merely from a signal.
`cpu.max` throttling is not by itself a failed attempt. The receipt gives
requested value, applied mechanism, scope and observed hit/unknown status.

## 10. Network mediation

`tool` and `build` have no network proxy and no host network access. `agent`
uses an outside HTTP proxy reachable only through an attempt-specific Unix
socket plus a constrained in-namespace loopback bridge. The policy owns the
proxy; a child cannot reconfigure it. `none` uses the host network and makes no
filtering claim. No TLS interception is introduced.

An allowed destination may receive anything the child can read. The proxy does
not enforce model tenant, API method, content classification, geographic location
or provider retention. Managed services must supply those permissions and scoped
credentials outside the jail; an allow-host grant alone never means read-only
service access, DLP or EU-only processing.

The host socket is `<data>/attempts/<id>/proxy/proxy.sock`, under an
operator-owned 0700 directory registered before creation, outside all shared
workspace/scratch/vendor roots. Expose only its dedicated directory at
`/run/ouro/proxy`, read-only to the child; retain pinned directory/socket
identity. The bridge listens only on `127.0.0.1:3128` and connects to
`/run/ouro/proxy/proxy.sock`. Its namespace and path resolution must not be
redirectable by child rename, unlink, symlink or mount changes. Test replacement
before and after the first connection and in a nested namespace. Child-local
overmounts must not alter the trusted bridge's view. Refuse on identity mismatch;
do not reconnect through an unvalidated replacement path.

Network namespaces alone do not isolate pathname AF_UNIX sockets in shared
mounts. For `agent`, deny access to host peers except the authorized proxy,
including sockets present before launch and sockets created later in any
shared/granted root. Same-attempt IPC, including nested sandbox IPC, remains
allowed. The selected backend must prove that distinction in S03/N05, including
socket aliases and SCM_RIGHTS authority from a host peer. Enumerating/masking
only existing socket nodes cannot satisfy it. If this cannot be enforced,
`agent` refuses; do not advertise no-host-sockets based only on TCP/UDP tests.

Set `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and their lowercase equivalents
to `http://127.0.0.1:3128`; set `NO_PROXY` and `no_proxy` to the empty string.
Environment variables offer compatibility; the network namespace and separate
Unix-peer restriction enforce the boundary. Test a client that ignores all
proxy variables.

Host rules use [network rules v1](jail-v1/network-rules.md), including pinned
IDNA processing, numeric parsing and address-prefix data. Normalize names to
lowercase ASCII and remove one terminal dot. Reject embedded userinfo, paths,
control characters and invalid ports. A rule without a port permits 80 and
443 only. `*.example.com` matches one or more labels beneath that domain,
not the apex or `badexample.com`. IPv4/IPv6 literals use parsed addresses;
IPv6 ports require brackets. Do not accept ambiguous numeric IPv4 spellings.

For every CONNECT/plain-HTTP request:

1. Parse one unambiguous destination and validate its host/port rule.
2. Resolve on the host through the proxy's resolver, not inside the jail.
3. Reject destinations in the versioned forbidden-address table (private,
   loopback, link-local, unspecified, multicast, reserved, known translation
   and metadata/service prefixes) unless the operator supplied an explicit address
   grant for that destination and port. A public hostname allow-rule alone
   does not authorize a private resolved address.
   Normalize IPv4-mapped IPv6 before both grant and address checks; reject
   deprecated compatible forms. Hostnames never bypass numeric checks.
4. Reject a mixed allowed/forbidden DNS answer set; select an approved address
   and connect to that numeric address without a second implicit resolution.
5. For plain HTTP, require consistency between absolute URI authority and Host,
   strip proxy credentials/hop-by-hop headers, and reject ambiguous framing.
   A redirect requires a new destination check when the client follows it.

An allowed CONNECT only authorizes a byte tunnel to that destination. The
proxy does not establish what TLS request or application action followed.
Fail closed on proxy/bridge death for a contained agent. Emit safe reasons;
do not log request paths, query strings, headers, tokens or bodies.

Initial budgets per attempt: 128 active connections, 32 KiB request headers,
10-second DNS/connect/header deadline, 1 MiB total bounded relay buffers.
At capacity, reject excess requests with a safe overload reason. Stream data
with backpressure; do not buffer response bodies. Connections close on stop.
These limits are resource budgets, not permission grants.

Emit one proxy `net.connect` result per request: immediately for denial or
connect failure, at close for a successful tunnel so counters are final.
Record request id, destination, decision, connected address, bytes and duration.
An interrupted drain can leave that result missing; coverage must reflect it.
Audit-source `net.connect` is separate evidence and must not be merged into a
second proxy event. No public DNS dependency is required in tests: controlled
resolver and server fixtures cover rebinding, IPv6 and forbidden addresses.

## 11. Observation and event semantics

### 11.1 Scope and attachment

The observer belongs to the supervisor and attaches before target release.
The initial eBPF design filters on the registered execution cgroup and tracks
task birth identity/fork ancestry as needed for attribution. The feasibility
gate must establish namespace-safe descendant tracking, PID reuse handling
and parent-exits-before-child behavior. Setup helpers are tagged as helpers,
not attributed as user target operations.

Read only the arguments needed for the closed set after the attempt filter
matches. Never stream unrelated host processes into user space and filter them
later. Do not persist unredacted paths, argv, environment, socket payloads or
memory snapshots. Raw argument bytes may exist only in bounded transient
buffers before redaction; they must not appear in debug logs or core-dump
artifacts from the test runner.

### 11.2 Closed set `linux-closed-v1`

Attach supported native ABI variants of the operations below. The implementation
must publish its exact hook/syscall table. Calls absent on an architecture are
identified as absent; equivalent variants that exist must be tested.

| Operation | Native evidence | Meaning of a result |
|---|---|---|
| `proc.exec` | `execve`, `execveat` entry plus confirmed exec transition, or failed return | New executable image established, or an exec failure; never infer success from an entry |
| `proc.exit` | Confirmed termination of the entire tracked thread group after a witnessed exec | That process exited with the observed status; not a single thread exit or tree emptiness |
| `fs.create`, `fs.write` | `open`, `openat`, `openat2`, `creat` requesting write/create/truncate | Successful open for possible mutation; not bytes written or proof a file was newly created |
| `fs.rename` | `rename`, `renameat`, `renameat2` | The named rename call succeeded or failed |
| `fs.unlink` | `unlink`, `unlinkat`, `rmdir` | The named removal call succeeded or failed |
| `fs.create` | `mkdir`, `mkdirat`, `link`, `linkat`, `symlink`, `symlinkat` | The named directory-entry creation succeeded or failed |
| `fs.deny` | One call from this set, including `connect`, returned EACCES or EPERM | That covered call was denied; no inference about unobserved read denials |
| `net.connect` | `connect` entry/return | Connect returned the recorded result; EINPROGRESS is not a completed connection |

This spells out native variants of the north star's operation families before
schema freeze. An O_CREAT open emits one `fs.create`, otherwise a mutation open
emits one `fs.write`; do not emit both for the same call. A covered EACCES/EPERM
failure emits one `fs.deny` with `fields.attempted_operation`, not a duplicate
success-shaped filesystem event. EROFS and other failures remain failed results
for the original operation and do not inflate the specified denial count.
For denied `connect`, `attempted_operation` is `net.connect`; count the single
result under `fs.deny`, not `net`. This classification does not lose the event.
Audit `decision` is always null: errno alone cannot identify DAC, LSM, seccomp
or a particular jail policy decision.

For syscall-return observations, correlate entry and exit by task birth
identity, thread and in-flight invocation. Record signed raw return and errno.
Exec success needs special handling: a successful exec replaces the calling
image and is not an ordinary successful return to it. Use the confirmed kernel
exec transition and correlate its entry, including non-leader-thread exec.
Fork/clone/exit hooks used for tracking are internal bookkeeping; they do not
expand the public syscall audit set.
Emit one `proc.exit` only after the last live thread in a tracked process exits.
A leader calling `pthread_exit` while workers remain is not process termination.
Retain the process birth identity and witnessed-exec association across worker
exits and non-leader exec. A fork child that never execs is still tracked for
scope/lifetime but emits no public `proc.exit` in this set. If a required final
status cannot be established, record a gap rather than a worker's status.

An unmatched return, dropped entry, truncated required structure or untracked
descendant is a coverage gap. Never manufacture a result to fill it. Syscall
restarts must not create duplicate successes. `openat2` requires decoding only
the supported size/flags of its argument structure; unknown or unreadable input
is unavailable metadata and, if needed for classification, a gap.

No `write`, `read`, `mmap`, `io_uring`, payload or file-content observation is
claimed. Async operations issued through other interfaces are outside this
set even if they cause similar effects. A field named `fs.write` always carries
its precise action, such as `opened_for_mutation`, to prevent consumers from
presenting it as a content diff.

### 11.3 Paths, arguments and identities

Relative pathname arguments are not blindly appended to a host cwd. Account
for `dirfd`, cwd/root, namespaces and native path bytes. Emit a workspace-relative
path only when its relationship to that workspace is established. Otherwise
emit a digest or unavailable marker, with a reason. Record `path_basis` as
`argument_snapshot` or a specifically proven kernel-resolved observation.
The initial sensor does not claim an argument-memory snapshot is the exact
path later consumed by the kernel under a concurrent mutation.

Path snapshots and return codes are distinct evidence. A rename race does not
change the observed return code, but prevents a stronger path assertion.
Long or unreadable paths have `path_complete=false`. No raw absolute path is
emitted just because redaction failed. Two-path operations treat both paths
independently. Do not resolve a symlink after the event and call it the target
that was accessed at event time.

The wrapper hashes the complete literal operator argv using length-prefixed
native bytes. Descendant argv may only have a complete digest if all bytes were
actually captured. Otherwise `argv_digest=null` with a reason; a prefix hash
cannot be labelled as the full argv digest. Executable identity records the
observed process image identity, not a promise that its file contents remain
unchanged. Public numeric PIDs are diagnostic; internal attribution includes
boot/birth identity and namespace mapping.

### 11.4 Loss and coverage

Each class has exactly the following source and operation assignment:

| Class | Source | Results counted |
|---|---|---|
| exec | audit | proc.exec and proc.exit |
| fs.write | audit | fs.create, fs.write, fs.rename, fs.unlink, including all directory-entry variants |
| fs.deny | audit | EACCES/EPERM results from the closed set, including connect |
| net | audit | net.connect results other than those classified as fs.deny |
| proxy.net | proxy | Proxy net.connect results; never pooled with audit counts |
| limits | wrapper | Number of distinct applied ceilings with a confirmed hit; no limit.hit event in v1 |

Each class has a status:
`supported` before successful attachment/application, `active` once applied,
`degraded` when a required interval is missing, or `unsupported` when disabled
or unimplemented. Each source has its own status and coverage intervals.
Proxy activity alone cannot make syscall network coverage active.
`--observe off` makes all four audit classes unsupported with null counts and
empty source lists. `proxy.net` can remain active only for an applied proxy;
it is unsupported when no proxy exists. Active/supported/degraded classes name
their assigned source; unsupported classes name none. A gap names the affected
classes explicitly, including rename/unlink under `fs.write`. Unsupported and
degraded counts are null. A supported-but-not-started class also has null count.
Operations explicitly outside the closed set are not lost events and do not
alone degrade its coverage; consumers must display the declared set/scope.
`limits` coverage concerns only actually applied ceilings, listed in the
receipt. Its count increments once per key whose hit becomes proven true,
not on each counter poll or repeated pids denial; no hits means zero. Missing
hit evidence makes coverage degraded and the count null. Preferred unapplied
limits remain explicitly absent and are not treated as monitored ceilings.

In a final receipt, `observer.attached` means attachment was established for
that attempt. It does not say a kernel probe remains live after settlement.
Coverage intervals state when observation was active; finishing the observer
does not erase the historical active interval.

Initial bounds: 8 MiB kernel ring, 16,384 in-flight syscall entries, 4 KiB path
snapshots, 4 MiB user-space event queue, 64 KiB serialized event maximum.
Record actual values in the observer plan. Every failed reservation, map
insertion, pairing failure or oversized event increments an independent loss
counter. The [BPF ring-buffer contract](https://docs.kernel.org/bpf/ringbuf.html)
allows reservation failure; a quiet ring is not proof that no event occurred.

Read loss counters continuously and once more after tree death and drain.
Bound the affected interval conservatively from the last known healthy point
to recovery. Counts/ranges are null when exact loss cannot be established.
Coalesce repeated losses into bounded interval summaries. Coverage cannot
return to fully active for the entire run after a historical gap.

On loss under `strict`, stop the attempt and preserve the gap. Under
`best-effort`, continue with degraded coverage and explicit lost intervals.
An observer that cannot attach always refuses before exec, regardless of
evidence mode. `--observe off` emits no audit-source events; wrapper lifecycle
and optional proxy facts still exist with their own limited meaning.

## 12. Launch profiles and credential lifecycle

Launch profiles are operator-owned TOML at `<config-dir>/launch/<name>.toml`,
outside the workspace, mode 0600.
They name environment mappings, credential inputs, allowed hosts and a default
contained jail. They do not supply or rewrite argv and cannot select `none`.
Bundled examples are copied/installed only by an explicit operator action;
the runtime does not discover and mount all files in an agent's home directory.

These are generic operator credential mechanics. Managed teams use company-
approved issuers/gateways to stage only attempt/project-scoped material through
them. Upstream model secrets, source-fetch credentials and publishing/signing/
deployment credentials remain outside the child. Ordinary personal-login
examples below do not establish managed readiness. The owner rejects a launch
profile that needs broader authority than its effective company policy.

Initial declarative fields are `name`, `jail`, `state_var`, `home_is_state`,
`state_subdirs`, `environment`, `credentials.<id>.source`, `dest`, `mode`, and
`network.allow`. `environment` accepts only named string values or managed-state
path references, never commands. Reject every `LD_*` and `DYLD_*` name,
backend-control names and variables carrying Ouroboros credentials.
Any runtime-library need belongs in an explicit evaluated launch configuration,
not a general loader-injection escape hatch. Credential destinations must be
relative paths beneath vendor state, with no `..`, absolute path or symlink
escape. A launch profile path inside any child-writable grant refuses.
`state_subdirs` is a set of relative directory paths under vendor state; reject
empty paths, absolute paths, `.`/`..` components, duplicates and conflicts with
credential files or bind targets. Nested paths create intermediate directories
mode 0700 through anchored no-follow handles before credentials are staged.
They grant no host directory. A pre-existing symlink or special node refuses.

| Initial profile | Managed state mapping | Declared input intent |
|---|---|---|
| `codex` | `CODEX_HOME`, optionally HOME, to vendor state | Node-local auth as `copy_rw`; config as `bind_ro` |
| `claude` | `CLAUDE_CONFIG_DIR` to vendor state | Node-local file credentials and settings; no Keychain extraction |
| `opencode` | XDG config/data subdirectories beneath vendor state | Explicit node-local credential file and config inputs |

Use the north star's initial source paths as experimental profile data. Record
the vendor version and exact tested file/host requirements when a profile first
passes a real run. Agent names must occur only in profile data, documentation
and fixtures, not in policy, supervisor, observer or backend branches. A
dependency/source test enforces this boundary without banning documentation.

`copy_rw` takes a point-in-time private copy; it never writes refreshed tokens
back. `bind_ro` exposes the exact granted source file read-only; it may prevent
credential refresh. Copy regular files through no-follow handles, validate
owner and mode, and reject special files. Initial total credential-copy budget:
16 MiB per attempt; larger inputs refuse before exec. File identity and digest
are computed from the same bytes copied. A readonly bind records source
identity; if stable content cannot be established, its digest is unavailable
rather than invented. Never recurse through a credential directory by default.

Register vendor state before the first copy, create it mode 0700, and keep its
parent unavailable to the contained child. Generated HOME/state paths and
proxy variables are recorded by name only. The contained environment starts
empty and admits PATH, LANG, TERM, TZ, required generated paths and the explicit
launch environment. Unlisted SSH/cloud/provider environment credentials are
absent. `none` inherits the host environment except reserved Ouroboros state,
socket and token names; the receipt lists removed names, never values. This is
hygiene and does not protect uncontained state.

On pre-exec refusal or verified tree death, remove vendor state using anchored
directory traversal that does not follow symlinks or cross mount boundaries.
Delete a child-created link itself; never its external target. Unmount any
readonly credential views first. Keep `state_cleanup=pending` until deletion
and the relevant directory sync complete, then atomically record `complete`.
If no vendor state was created, use `not_needed`. Attempts with unproved live
trees retain state. Cleanup failure does not rewrite a known child exit.

The required `credentials` receipt array reports each successfully staged input
as `{id, mode, digest, digest_unavailable_reason}`; it is empty when none were
staged. IDs are unique logical names, modes are `copy_rw` or `bind_ro`, and a
digest is `sha256:` plus the content hash or null with a safe reason. A present
digest has a null reason. Source identity/paths and credential contents stay in
private operational state, never the receipt. Later cleanup does not erase this
historical provenance. Refusal can report inputs staged before the failure.
No trace, receipt, support bundle or future ledger export includes vendor state.
Credential provenance records local staging facts; it does not prove upstream
token scope, revocation, expiry or service authorization. Those are separately
validated and recorded by the managed owner and registered service integration.

## 13. Wire records, receipts and bounded trace

Draft JSON Schemas accompany this specification:

- [Event envelope](jail-v1/event.schema.json).
- [Jail producer restriction](jail-v1/jail-event.schema.json).
- [Jail receipt](jail-v1/jail-receipt.schema.json).
- [Canonical policy snapshot](jail-v1/policy-snapshot.schema.json) and
  [canonical byte rules](jail-v1/canonicalization.md).

Synthetic examples: [observed open](jail-v1/examples/event-open.json),
[contained completion](jail-v1/examples/receipt-tool.json),
[unprotected completion](jail-v1/examples/receipt-none.json), and
[macOS refusal](jail-v1/examples/receipt-macos-refused.json).
Every example uses fixture identities; none is evidence of an actual run.
Additional fixtures cover prepared contained/none runs, proxy-only observation,
unknown exec with verified settlement, byte-valued paths and credential metadata.
Run `uv run docs/specs/jail-v1/validate_contract.py` from the repository root to
validate schemas, examples, the positive/negative mutation corpus, golden hashes
and address fixtures. This documentation check does not satisfy live Linux or
macOS execution gates. [Review resolutions](jail-v1/review-resolutions.md) maps
the corrected findings to their normative clauses and acceptance IDs.

They are executable contract drafts, not a claim that the runtime exists.
They freeze at milestone 1 after backend/observer evaluation. The schemas
validate structure; semantic invariants and lifecycle ordering also require
the tests below. Additive platform details cannot change a shared field's
meaning. After freeze, a breaking semantic change needs a new schema identifier;
these unpublished revision-2 drafts replace the revision-1 fixtures together.

### 13.1 Event envelope

An event is one UTF-8 JSON object plus newline on the trace pipe or file.
Future socket transport uses a four-byte unsigned big-endian byte length and
the same JSON payload, with the same maximum. There is one writer per trace
stream. `source_seq` starts at 1 independently for each source and never
restarts within an attempt. Events from different sources are not causally
ordered by timestamp or by their eventual ledger sequence.

Required fields: `schema`, `attempt_id`, `source`, `source_seq`, `observed_at`,
`monotonic_ns`, `operation`, `stage`, `decision`, `outcome`, `fields`.
`source` is `wrapper`, `audit`, or `proxy`. Wall time is UTC RFC 3339;
elapsed continuous time (§6.4) is a decimal string of nanoseconds since supervisor
start, so JSON number precision cannot corrupt it. `stage` is `attempt` or
`result`; an attempt has null outcome. `decision` is `allow`, `deny`, or null
when the source establishes no policy decision. Successful syscall completion
does not by itself prove a particular policy decision.

The operation enum remains the north star's shared operation inventory.
Jail emits only its own facts; `intent.*` is reserved for the future ledger
owner and rejected for audit/proxy sources. A coverage gap is a wrapper `note`
with `fields.kind=coverage_gap`, classes, interval, reason and known/null count.
Receipt updates are wrapper `jail.receipt` events referencing receipt digest
and phase. Avoid recursively embedding the entire event stream in a receipt.

Validate jail output with [jail-event.schema.json](jail-v1/jail-event.schema.json),
a producer-specific restriction of the shared envelope. Its wrapper operations
are `note` and `jail.receipt`; lifecycle facts use `note` with
`fields.kind=lifecycle` and a safe named transition. Its proxy operation is
`net.connect` at result stage; audit uses the closed set. `net.dns`, `limit.hit`
and `intent.*` remain shared inventory reserved from all jail v1 writers.
Future ledger-owner wrapper events can use `intent.*` under their own producer
contract. A source label is not authorization; future ingestion also validates
the authenticated producer role. Audit decisions must be null in the shared
schema; the jail proxy supplies allow/deny independently of connect success.

Audit result outcome contains `ok`, `return_value`, `errno`, and completion
kind. Confirmed exec can have null return value with
`completion=exec_transition`; no fictitious return of zero is required.
Proxy outcome instead describes connect status, counters and duration. Sources
have distinct `fields`; consumers must not equate proxy bytes with file bytes,
or an audited loopback connect with a successful remote API request.

### 13.2 Receipt lifecycle and shape

Normal phases are `prepared`, `enforced`, `settled`. A separate `refused` phase
records a proved pre-target-exec refusal; this resolves the north star's
pre-exec receipt case without labelling failed preparation as enforcement.

| Field group | Required meaning |
|---|---|
| Identity | Schema, attempt id, receipt revision starting at 1, phase, creation/update times |
| Platform | OS, architecture, kernel/build string and backend identity/version |
| Policy | Name, canonical digest, observation/evidence choices, grants and requirements |
| Application | Actually applied filesystem/network/syscall mechanisms and limit scopes; null/empty for unapplied requirements |
| Protection | `pending`, `enforced`, or `unprotected`; independent of observation |
| Observer | Backend/set, attached state, per-source health and bounded gap summary |
| Coverage | Each class status, source scopes, missing intervals, unavailable counts |
| Process | Portable identity wrapper and target exec confirmation; nullable before identity exists |
| Lifetime | Boundary kind, native details, verification scope/integrity, `tree_empty` true/false/null and verification time |
| Credentials | Staged logical ids, modes, digest or unavailable reason; no source paths or values |
| Outcome | Pending/refused/exited/signaled/exec_error/unknown; code/signal/cause/error separately |
| Cleanup | Vendor state not_needed/pending/complete plus safe failure reason |

The receipt's `containment` is `pending` before the final policy is established,
`enforced` for an applied contained profile, or `none`. `child_protection` is
pending until a contained boundary is established, enforced when established,
and unprotected for every `none` receipt, even preparation/refusal. Prepared
does not mean the target ran; `exec_observed` is false until confirmed.

`enforced` is the lifecycle phase after target exec, including for a `none`
run; its `containment` still says none. `settled` requires verified tree death,
but can preserve unknown execution outcome if evidence was lost. If tree
death itself is unknown, retain the last nonsettled phase and update its
outcome/coverage/error as unknown. `state_cleanup` can remain pending after
settlement. Receipt revision advances on each successful replacement.

Every applied limit states its scope; every observation count is null when
unsupported or incomplete. Zero is allowed only for a covered interval with
no matching result. An `enforced` child-protection label covers the specified
boundary, not all possible administrator interference or independent custody.
Prepared/refused receipts cannot contain fabricated child outcomes or recorded
operations from a command that never ran. A failed target exec syscall is a
valid launcher observation even though no target instruction ran. An observer can already be attached
while the prepared target is still blocked.

Initial and terminal tuples are normative:

| Situation | phase | containment / protection | exec observed | boundary / scope | tree empty / verified at |
|---|---|---|---|---|---|
| Contained preparation complete | prepared | enforced / enforced | false | actual boundary / attempt_tree | null / null |
| None preparation complete | prepared | none / unprotected | false | actual boundary / registered_boundary | null / null |
| Refusal before boundary creation | refused | pending / pending, or none / unprotected | false | pending / null | null / null |
| Refusal after setup or proved exec error | refused | actual application state | false | actual boundary / actual scope | true / timestamp only after teardown verification; otherwise null / null |
| Verified settlement | settled | actual application state | true, or false if exec is unknown | actual boundary / actual scope | true / timestamp |

`lifetime.integrity` is `pending` before a boundary is validated, `verified`
when its identity and the claimed scope have been checked, or `lost` after
detected tampering/escape. It does not upgrade `none`'s protection or scope.
`boundary=pending` requires null native identity, scope, tree result and time.
Lost integrity requires null tree result/time and forbids settlement/cleanup.
A completed population check finding a live tree may record false plus its
timestamp during stopping; prepared/enforced are retained as the last phase.
Verified settlement with unknown exec evidence is valid. Proved exec failure
remains refused after teardown, not settled. Exited/signaled outcomes require
independent target termination evidence, never inference from population.

Limits report hits in `applied.limits[].hit` with `outcome.cause` and the actual
signal where applicable; there is no separate `outcome.limit_hit`. Requested
but unapplied limits have null mechanism, scope and hit. Native strings in
grant values and mount paths use the same UTF-8/base64 codec as the canonical
appendix; a JSON string-only schema cannot represent all Unix pathnames.

Native lifetime details live under an OS-tagged object. Linux may record cgroup
and namespace identities; macOS will define its own. `pidfd`, `/proc` paths,
cgroup controllers and Linux errno names are not mandatory portable fields.
Policy/record tests must instantiate a hypothetical macOS record without
Linux fields and validate it; that is schema portability, not execution proof.

### 13.3 Storage and pressure

Without `--trace-fd`, write a bounded standalone `trace.ndjson` under private
attempt state. With it, stream to that fd instead; do not silently duplicate
the full trace locally. The canonical receipt is always local. A successful
pipe write proves only byte delivery to the pipe, not future ledger durability.

Initial local trace cap is 64 MiB, including a 256 KiB reserve for bounded final
gap/receipt notes. Payload exhaustion is evidence loss, not endless disk growth.
Strict mode terminates; best-effort keeps a prefix and coalesced gap summaries.
After the reserve is exhausted, the receipt remains the bounded summary and
the trace stays visibly incomplete. A local disk-full failure may prevent even
that summary from persisting; preserve incomplete state and report a tool error.

External writes are nonblocking with a 4 MiB queue and a 1-second no-progress
deadline. Broken pipe, partial-record write followed by failure, queue overflow
or deadline expiry is evidence loss. The writer preserves unwritten offsets;
it never retries a whole partially written JSON frame as a second event.
Strict mode stops the tree; best-effort can continue with the sink marked lost.
A corrupted/truncated last frame must be recognizable at readback.

Control uses a separate bounded queue with reserved terminal-message capacity;
trace backpressure cannot delay a stop. Disk sync runs independently of the
supervision loop with a 5-second progress budget. If persistence cannot finish,
stop the child and keep the transition unacknowledged. Do not wait forever for
a writer while descendants continue running. No disk spool, replay daemon or
external custody service is added to jail v1.

## 14. Doctor and recovery

### 14.1 Doctor

`doctor` executes short, isolated probes, never the user's command. Each probe
has a 5-second deadline and owned temporary resources. Report kernel/OS build,
architecture, binary hashes/versions, operator identity category, relevant
permissions and each result with safe remediation guidance. Aggregate result
is ready only for the selected requirements; execution unsupported is a
normal structured result on macOS, with nonzero readiness exit status.

Required Linux probes:

- Actual user/PID/network namespace creation, readonly/writable mounts and
  denial of the representative protected access.
- Filter loading, an allowed operation and a rejected representative syscall.
- Delegated cgroup creation, target placement, required controllers, force kill
  and empty verification using a tiny owned fixture.
- Observer attachment and a matched fixture operation, plus unavailable/loss
  accounting; loading an empty BPF program is insufficient.
- Proxy/bridge connectivity, allowed and denied destinations, and direct-egress
  rejection for `agent`.
- Scripted nested sandbox setup and attempted outer-boundary reversal for
  `agent`.
- Host AppArmor restrictions when detectable. If effective permission cannot
  be read, the execution probe remains authoritative and the explanation says
  policy details unavailable.
- Launch profile credential existence/type/permissions without printing values
  or user-specific paths; experimental/supported status separately.

`doctor` does not edit user namespaces policy, install dependencies, enable
lingering, alter TCC, change capabilities, start a permanent service or prompt
for provider sign-in. `explain` shows these as unmeasured requirements.

### 14.2 GC and crash handling

`gc --dry-run` enumerates only the registered state root, takes nonblocking
attempt locks, and reports actions/reasons in the same JSON shape as `gc`.
It never discovers deletion targets by searching all of `/tmp`, HOME or cgroupfs.
Active locks, unverifiable identities or foreign-platform resources are retained.

For a dead supervisor, revalidate boot/process identity and every registered
resource. In the same boot, a populated, positively identified orphan execution
cgroup may be killed by this explicit GC invocation, as permitted by the north
star. Record `gc_terminated_orphan` and verify emptiness before deleting state.
After host reboot, the old processes cannot be alive, but any reused cgroup
path must not be treated as the original resource. Never signal from a stale
PID or delete a directory solely because its name looks like an attempt id.

GC may finish interrupted vendor-state/placeholder cleanup and remove an empty
owned cgroup. Default managed scratch is removed only after verified tree death;
operator-supplied `--scratch` and workspace directories are never deleted. The
initial implementation preserves any result the operator needs in the explicit
workspace, not managed scratch. It retains receipts, policy and trace; general evidence retention
is a future ledger concern. If execution evidence was lost, cleanup completion
does not turn the execution outcome into success. A corrupt state file causes
quarantine-by-reporting and retention, not guessed cleanup.

## 15. Acceptance matrix

Tests use a compiled/scripted fixture executable with explicit modes and a
private test-control channel. Fixtures report the actual syscall result to the
harness, which compares it with observed events. Synchronize races on gates or
protocol events, not sleep-based timing. Bounded timeouts catch hangs but do not
replace synchronization. Every live test uses isolated state and cleans only
its own processes. Never test against the operator's actual credentials.

| ID | Test and required result |
|---|---|
| P01 | Both canonical TOML fixtures resolve to the golden snapshot/JCS/digests; provenance and set order do not change hashes; semantic changes and argv order do; native non-UTF-8 paths/argv survive execution and record encoding. |
| P02 | Every widening category refuses with the key path, including path-prefix and wildcard confusion. |
| P03 | Child edits project/profile files after preparation; active authority/digest stays unchanged. |
| P04 | State/scratch/receipt overlap, symlink escape, unsafe owner and credential special files refuse before exec. |
| X01 | Spaces, quotes, newlines and shell metacharacters reach the fixture literally. |
| X02 | Gate withheld, closed, oversized, duplicated, wrong digest, missing/extra LF, CRLF, duplicate JSON keys and timed out: target marker absent; label-only with gate/id and malformed UUIDv4 refuse as usage errors. |
| X03 | Valid gate: one target exec. Owner death races before/during release never cause a second exec. |
| X04 | Missing executable, missing interpreter, permission error and child exit 125 have distinct outcomes. |
| X05 | Large stdout/stderr, binary bytes and EOF match direct execution; control/trace never leak into either stream. |
| X06 | Fixture enumerates fds/environment/capabilities: no private authority or tracing privilege reaches it. |
| X07 | Target exit with background descendants causes verified termination of those descendants. |
| F01 | Allowed workspace write succeeds; protected existing file/directory, HOME secret and symlink escape fail. |
| F02 | Existing deep `.git`, file-form `.git`, mount replacement and root-level missing literals are protected. |
| F03 | New deep protected segment may be created under Linux existing_and_root; report the limit; all_descendants requirement refuses. |
| F04 | Scan-limit exhaustion and source-identity swap refuse without a claimed complete boundary. |
| S01 | Denied syscall and native ABI variants fail; ordinary threads still work with clone3 fallback. |
| S02 | Child cannot reach host processes, cgroups, namespace fds, host sockets or supervisor state. |
| S03 | Nested sandbox starts and restricts its child; attempts to undo each outer boundary fail. |
| S04 | Every contained profile rejects all three io_uring interfaces/ABI variants and inherits no ring; attempted async socket/open/connect cannot bypass policy. None retains explicit observation exclusions. |
| N01 | Direct TCP/UDP/IPv6 egress and environment-proxy bypass fail for contained profiles. |
| N02 | Allowed/denied proxy requests each yield exactly one matching proxy result; audit facts stay distinct. |
| N03 | Frozen address/IDNA fixtures, mapped/compatible IPv6, configured NAT64 prefixes, explicit numeric exceptions, rebinding, mixed answers, wildcard/apex and Host mismatch obey network-rules.md. |
| N04 | Proxy death, bridge death, header overflow, slow headers and connection saturation are bounded and fail closed. |
| N05 | Existing and late-created host Unix sockets/aliases in workspace, scratch, vendor state and extra grants are unreachable; legitimate same-attempt/nested IPC works. Proxy replacement before/after connect and mount changes cannot redirect the bridge. |
| O01 | Each closed-set fixture result agrees with its return code; no event asserts bytes written. |
| O02 | Exec failure/success, worker exits, leader pthread_exit with live workers, non-leader exec, PID reuse, fork-without-exec and nested namespaces preserve attribution; proc.exit means final thread-group death. |
| O03 | Truncation, unmatched exit, map exhaustion and ring loss produce gaps, never fabricated results or zero counts. |
| O04 | `write`, mmap and unrelated host processes do not emit closed-set events. |
| O05 | Observation off emits no audit source and leaves audit net unsupported, even with active proxy.net; unavailable attachment refuses even in best-effort. Directory-operation losses degrade fs.write; denied connect counts only in fs.deny. |
| O06 | Renamed cwd, dirfd, two-path calls, non-UTF-8 names and a racing pathname never produce a falsely resolved path. |
| L01 | Wall expiry, INT/TERM/HUP, SIGTERM-ignoring descendant and fork storm end at verified tree death or explicit unknown. |
| L02 | Kill every actual helper/supervisor link: contained descendants die; none preserves its specified unknown case. |
| L03 | Missing required cgroup/controller refuses; missing preferred pids alone records absent and runs. Exercise cgroup available but pids controller absent, explicit same-value pids, and observe off. None without a usable cgroup refuses. |
| L04 | pids/memory/CPU scopes are measured; exit 137 alone does not claim OOM; BOOTTIME deadlines ignore clock adjustments and include suspend. |
| L05 | Simulated uninterruptible/unknown termination retains vendor state and never says settled/tree_empty=true. |
| R01 | All positive/negative contract fixtures pass validation: phase/scope/integrity tuples, known/unknown exec, credential provenance, native byte paths, remediation fields and per-source coverage. Jail producer validation rejects shared-but-reserved events; future owner envelope remains valid. |
| R02 | Disk-full/short-write/crash at each snapshot/receipt replacement leaves a valid prior file or explicit incomplete state. |
| R03 | Trace partial writes, consumer disconnect, saturation and control backpressure cannot block deadline enforcement. |
| R04 | Strict loss stops; best-effort continues degraded; counts and protection labels remain honest. |
| R05 | None with clean evidence remains unprotected; same-UID tampering is demonstrably outside local evidence assurance. |
| R06 | None target migrates out while live: empty leaf never fabricates exit/settlement. Detected descendant escape loses integrity and retains state. An unobserved migrated descendant is not certified dead by registered-boundary verification. |
| C01 | Copy/readonly-bind preserve sources and emit logical-id/mode/digest provenance without sensitive bytes; byte paths encode losslessly; unsafe state_subdirs and all LD_*/DYLD_* launch keys refuse. |
| C02 | Normal exit/refusal cleans vendor state; interrupted cleanup resumes; symlinks cannot redirect deletion. |
| C03 | GC skips live/foreign/unidentified resources; boot/PID/cgroup reuse does not target an unrelated process. |
| M01 | Shared tests run natively on macOS; run and none refuse without executing the marker. |
| M02 | Portable records validate with macOS identity/backend details and without Linux fields. |
| M03 | macOS explain/doctor distinguish requested policy, unmeasured properties and unsupported execution; inspection and label-only exit codes follow §6.4. |
| I01 | Full jail conformance passes with ledger and fleet absent from PATH and no BEAM installed. |
| I02 | No vendor names/protocol dependencies in the execution core; launch profile selection is data-only. |
| I03 | A scripted trusted owner compares the prepared policy/argv/requirements with its expected plan. Mismatch closes the gate with no target marker; a matching plan releases once. Untrusted request fields cannot mutate the owner's operator inputs. This proves the composition seam, not company identity or authorization. |
| A01 | A real batch agent run records revision, OS, backend, vendor version, profile and receipt, without credential archives. |

`A01` marks only the tested profile/platform/mode supported. Missing binary or
credentials is skipped, never passed. It does not block scripted milestone-1
conformance, and the other profiles stay experimental. Linux conformance does
not imply macOS execution support; a native macOS suite will be required later.

## 16. Implementation order and exit criteria

Each step must leave a buildable tree and a concrete test result. No ledger or
fleet scaffolding is needed to complete these steps.

| Step | Deliverable | Exit criterion |
|---|---|---|
| J0: feasibility | Provision the reference host and record its manifest; measure the observer privilege model first (§5.2); then pin and evaluate the enforcement candidates (§5.1) with the fixture harness and lifecycle integration; fill [backend-evaluation.md](jail-v1/backend-evaluation.md). | §5 report has measured evidence and one chosen viable path or a named blocker. No fabricated backend selection. A blocked observer is a valid exit; it does not license `--observe off` as J1's acceptance run. |
| J1: first execution | Cargo workspace; portable policy/records; Linux tool supervisor, observation, wall and receipts; macOS refusal implementation. | §1.1 runs end to end, with P01–P04, X01–X07, M01–M03, I03 and its relevant F/O/L/R tests. This is the first product implementation slice. |
| J2: authority | Complete mounts/protected paths, filter families, native ABI checks, limits, gate faults and doctor probes. | F01–F04, S01–S02, S04, X02–X06, L01–L05 pass on the named Linux lane. |
| J3: agent execution | Proxy, nested agent profile, data-only launch profiles, credential modes/cleanup and explicit none. | S03, N01–N05, C01–C02 and R05–R06 pass. Profiles remain experimental. |
| J4: evidence/recovery | Complete closed set, loss handling, bounded trace, atomic records and GC. | O01–O06, R01–R06 and C03 pass, including failure injection. |
| J5: milestone proof | Full independent suite, performance report, platform compilation, docs and schema freeze. | All noncredential gates pass; A01 is either recorded or explicitly skipped; no Linux mechanism leaks into portable requirements. |

J0 is the next change to this tree and begins on the reference host. It can
use disposable spike code and fixtures. J1 must keep observations on in
its acceptance run; it cannot ship a launcher first and defer the defining
evidence/lifetime questions indefinitely. Later steps expand the tested surface
without changing those ownership boundaries.

CI runs in three workflows that exist from revision 5: `contracts`
(schema/example validation and the link check, on every push and pull
request); `rust` (`cargo fmt --check`, `cargo clippy --workspace --all-targets
-- -D warnings` and `cargo test --workspace` on a hosted Ubuntu runner for
portable tests and on an Apple Silicon runner as the native macOS
build/refusal lane, skipped until the workspace exists); and `conformance`,
the provisioned Linux job on the reference host with an explicit
expected-capability manifest. A required live capability being skipped makes
the conformance job fail. Generic hosted runners may run portable tests
without pretending they exercised a privileged kernel feature.

The conformance runner model: a GitHub-hosted runner drives the reference host
over SSH as the `ouro-ci` account, with a repository secret for the key and
repository variables for the address, the account and the pinned host key. No
runner agent is installed on the host, nothing on the host polls GitHub, and
the same driver runs from a developer machine. The job triggers on pushes to
`dev` and `main` and on manual dispatch, never on pull requests: a fork's pull
request has no secrets and cannot reach the host, and a collaborator's push is
the trust the repository already extends. Until J1 ships the `xtask`
conformance driver the job only collects the host manifest; once `Cargo.toml`
exists it fails until that driver runs, so the workspace cannot land without it.

Freeze the Rust toolchain, Cargo.lock, backend version/hashes, filter digest,
observer object/build provenance and tested host manifest with the milestone
report. Re-run relevant conformance when any of these change. A dependency
update must not silently broaden mounted files or allow-hosts.

The future `ouro` executable can call the jail library in-process for dispatch;
`ouro-jail` remains independently usable. Elixir fleet and Rust ledger integrate
only after this CLI, gate, event and receipt contract is proved. No release
installer or old-runtime migration is needed to claim the jail milestone.

## 17. Traceability and decisions still requiring evidence

| North-star requirement | This specification |
|---|---|
| D3 vendor-independent argv | §§6, 12; X01, I02 |
| D8 reuse evaluation | §5; J0 |
| D9 Linux first, D12 eventual macOS | §§3–4; M01–M03 |
| D10 jail-owned observation | §§5.2, 11, 13; O01–O06 |
| D11 accepted holes | §§2, 9.3, 12, 14; R05, C02–C03 |
| D13 managed-team composition | §§2, 6.2, 8.2, 9.1, 10, 12; I03. Identity, policy ceilings, isolated input/artifact handling and project access require the later managed MT01–MT16 gates. |
| §4.1 standalone and gated run | §§6, 8; X01–X07 |
| §§4.2–4.7 policy, mounts, nesting, network | §§6, 9–10, 12; P/F/S/N tests |
| §§4.8–4.10 evidence, limits and acceptance | §§9.3, 11, 13–16; O/L/R tests |
| §7.1 future composition | §8.2; gated fixture owner without a ledger |

Before J0 closes: select exact enforcement/observer integrations, privilege
provisioning and initial Linux host manifest from measured results. Before J5:
finish the executable schema constraints, verify all source-specific event
semantics and freeze the wire versions. Before macOS execution: select native
containment/observation/lifetime mechanisms and their deployment model, then
pass the shared semantic suite and macOS-specific fixtures.

These are bounded implementation decisions, not permission to silently weaken
requirements. If none of the candidates can satisfy a required property, record
the failing fixture and revise the product contract explicitly before claiming
that property. No extra watchdog, witness service, vendor adapter or workflow
engine is implied.

## 18. Source references and evidence status

Reviewed 2026-09-21. Primary documentation informs mechanism constraints;
none of these links establishes Ouroboros integration conformance.

- [North star](../../north-star.md): scope and accepted limits.
- [bubblewrap](https://github.com/containers/bubblewrap): namespace/mount backend;
  it is a mechanism on which a policy is built, not proof of this policy.
- [sandbox-runtime](https://github.com/anthropics/sandbox-runtime) and
  [Greywall](https://github.com/GreyhavenHQ/greywall): candidates to pin and test.
- [Linux seccomp filters](https://docs.kernel.org/userspace-api/seccomp_filter.html)
  and [seccomp notification](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html):
  inherited filtering and limits of pre-execution observation.
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html),
  [PID namespaces](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html),
  [execve](https://man7.org/linux/man-pages/man2/execve.2.html),
  [BPF ring buffers](https://docs.kernel.org/bpf/ringbuf.html) and
  [perf security](https://docs.kernel.org/admin-guide/perf-security.html).
- [Pathname Unix sockets](https://man7.org/linux/man-pages/man7/unix.7.html),
  [network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html),
  [io_uring socket creation](https://man7.org/linux/man-pages/man3/io_uring_prep_socket.3.html),
  [thread termination](https://man7.org/linux/man-pages/man3/pthread_exit.3.html),
  and [continuous Linux clocks](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)
  inform the revision-2 containment/lifecycle checks.
- [Apple Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
  and its [client entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client).
  The locally shipped Apple `sandbox-exec(1)` manual explicitly marks the CLI
  deprecated; this was checked as a platform constraint, not a macOS runtime test.
- [Legacy Linux backend](https://github.com/monocursive/ouroboros/blob/f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82/lib/ouroboros/provider/native/sandbox/bwrap.ex)
  and [legacy macOS backend](https://github.com/monocursive/ouroboros/blob/f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82/lib/ouroboros/provider/native/sandbox/sandbox_exec.ex):
  historical mechanisms and fixtures to inspect selectively. No legacy runtime
  dependency is required in the new tree. Both links are reachable from branch
  `legacy` and tag `thesis-4-preserved`, which must be on the remote before
  `dev` is replaced there.
