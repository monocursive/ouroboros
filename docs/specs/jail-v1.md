# Jail v1: first implementation specification

Status: implementation specification, revision 19, 2026-09-25. No implementation
or backend conformance is claimed by this document. Revision 19 records J5, the
milestone proof: the D8 decision (the native bubblewrap adapter and the ptrace
observer; `srt` and Greywall disqualified by named failures; eBPF withdrawn
from v1), the performance budgets' definitions and their adjustment, the
portable requirement `execution_boundary`, `doctor --json` as the host
manifest (`ouro.jail.doctor/1`), build provenance and the architecture refusal,
which bubblewrap runs, the frozen wire schemas and milestone-1 inputs, the
error codes `exec_interpreter_missing` and `exec_unconfirmed`, the
preparation and gate budgets on the boot clock and the preparation budget's
expiry, the refusal of operator grants that expose host `/proc`, `/sys` or
cgroupfs, the supervisor's non-dumpable state, the test seams J5 added, the
L02 row reworded to the lifetime links and §10's network helpers, what the
observer and `none` do beside a process the supervisor was started beside,
and the limits the milestone names (§§3.2, 4, 5, 6.1–6.4, 8.2, 8.3, 9.1, 9.3,
11, 13, 14.1, 15–18); the milestone's evidence, acceptance verdict and named
limits are in [J5 authority](jail-v1/j5-authority.md). Revision 18 has `run` and
`doctor` enter a delegated user scope themselves where the user manager
lingers, so an attempt gets its execution leaf from a plain login session
(§§6.2, 9.3, 14.1). Revision 17 records J4's
third wave, the fixes its adversarial reviews forced: the lease held while
persistence may be in flight, one loss one error, the attempt-named execution
leaf and gc's association check, gc's intent records and finished attempts, the
control digest, and the tracer's exec pairing and restart re-entry (§§6.2, 6.4,
7, 8.1, 8.2, 9.3, 11.2, 11.4, 13.3, 14.2); the J4 evidence and acceptance map
are in [J4 authority](jail-v1/j4-authority.md). Revision 16 records J4's
second wave and its reviews: loss reported whatever its timing, the execution
leaf registered before it exists, gc's own records and leftovers, syscall
restarts, the receipt digest's preimage, trace framing and the no-leaf limit
of supervisor death (§§6.4, 7, 9.3, 11.2, 11.4, 13.1, 13.3, 14.2;
canonicalization.md). Revision 15 records J4's
first wave: atomic records and persistence, GC reconciliation, closed-set
attribution and loss handling (§§6.2, 6.4, 7, 8.2, 9.2, 11.2, 11.3, 11.4, 13.2,
13.3, 14.2). Revision 14 records the
first J4 fixes to records, observation, supervisor death and the trace (§§6.4,
9.2, 9.3, 11.2, 11.4, 13.2, 13.3, 14.2; canonicalization.md). Revision 13 opens J4 and
resolves §8.2's `refused` rule against §8.1 (review-resolutions.md). Revision 12 records what
the first real agent run required (§§6.2, 10, 12;
[agent compatibility](jail-v1/agent-compatibility.md)). Revision 11 records what
the J3 implementation and its reviews settled (§§6.2, 8.1, 9.2, 9.3, 10, 11.4,
12, 14; [J3 authority](jail-v1/j3-authority.md)). Revision 10 names the
host-peer isolation mechanism for `agent` (§10) and records the decisions the
J3 reviews forced (§§6.1, 9.1, 10, 12; review-resolutions.md). Revision 9 makes the jail
work on a stock host: no required host configuration, so `agent` no longer
requires nested user namespaces (§§3.2, 9.2, S03). Revision 8 recorded the
clarifications the first adversarial reviews of the J1 implementation forced
(review-resolutions.md, "J1 review findings"); they correct ambiguities and
add three native variants to the closed set, and they change no guarantee.

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
passes. The backend and observer were chosen from measurement and are recorded
in [backend-evaluation.md](jail-v1/backend-evaluation.md) (D8, revision 19);
this specification states the choice, and conformance, not this text,
establishes that it holds.

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
produces the host manifest, which every conformance run records: the record
`ouro.jail.doctor/1` ([schema](jail-v1/jail-doctor.schema.json)). On Linux its
`host` object carries the kernel release and build, the distribution, the
virtualization, online CPUs, memory and swap, the systemd version, the sysctls
`kernel.apparmor_restrict_unprivileged_userns`,
`kernel.unprivileged_bpf_disabled`, `kernel.perf_event_paranoid`,
`kernel.yama.ptrace_scope`, `user.max_user_namespaces` and
`kernel.io_uring_disabled` (an unreadable restriction sysctl is `unknown`,
distinct from an absent one), whether AppArmor is enabled and the state of its
user-namespace restriction with the installed profile files that name user
namespaces, bubblewrap or this product, the non-empty `local/` overrides and the
top-level profile files no package owns, cgroup v2 delegation as seen from the
operator's session (the root controllers, the delegated root, its controllers
and `subtree_control`), lingering, the operator identity category (§14.1) and
the privileged groups the operator belongs to. `binaries` records this binary's
path and the SHA-256 of the running image, and the bubblewrap a run would
execute (path, SHA-256, version) or null; `build` is `version`'s (§6.1). The
architecture is `platform.arch`. An unreadable fact is null. On macOS the record
has no `host`, no `supervisor_scope` and no backend binary.
[host-manifest.sh](jail-v1/host-manifest.sh) collected the same facts read-only
before `doctor` did (its first run is
[evidence/reference-host-2026-09-22.txt](jail-v1/evidence/reference-host-2026-09-22.txt))
and remains a fallback for a host where the binary cannot run. Ubuntu 24.04 and later restrict
unprivileged user namespaces through AppArmor by default. The
distribution's own `bwrap-userns-restrict` profile is measured sufficient for
the one containment layer every contained profile uses, and insufficient for a
user namespace nested inside it, because it denies capabilities there
([probe](jail-v1/evidence/bwrap-probe-2026-09-22-ouro-ci.txt),
[nesting probe](jail-v1/evidence/bwrap-nesting-probe-2026-09-22-ouro-ci.txt)).
An unprivileged Landlock domain does work inside that layer
([Landlock nesting probe](jail-v1/evidence/landlock-nesting-probe-2026-09-22-ouro-ci.txt)). The jail requires no host configuration: every profile must work
on a stock install of a supported distribution, and the reference host stays
stock so that conformance proves it. Nested user namespaces are therefore a
measured, optional host capability (§9.2), never a requirement. `doctor` names
the host-specific change that would enable them, as an optional remediation. All of
these are host policy: the tools report the state and change none of them.

The backend is the bubblewrap the operator's `PATH` provides, resolved once per
process: the first absolute entry holding an executable regular file named
`bwrap`, canonicalized. Empty and relative entries are never searched, and an
unset `PATH` provides no backend (there is no built-in search path). Every
probe and every run executes exactly that file, and `doctor` records exactly
it; with none, the probes that would execute it are `unavailable`
(`backend_unavailable`) without running, `doctor` is not ready and a contained
`run` refuses with 125 before exec.

Conformance runs on the host as a dedicated operator account,
`ouro-ci`: no sudo, no capability, lingering enabled (a per-user logind
setting, §9.3) so its `user@` service delegates the cgroup controllers, and
nothing else (§16). A VM is acceptable; a container that cannot delegate the required
kernel features is not a substitute for the release runner. Linux aarch64
gets its own native conformance run before it is advertised; it is a later
lane, not the reference host. Every syscall table in v1 (the contained
filters, the mediation filter and the observer's closed set) is x86_64's, so
a build for another architecture compiles, and the probes that rest on those
tables report `unsupported` with reason `unsupported_architecture`:
`syscall_filter`, `closed_set_observation` and `network_proxy` are
unsupported, `doctor` is not ready and `run` refuses with 125 before
preparation. No promise is made about all kernels newer than
a version.

The native macOS CI lane initially targets Apple Silicon; Intel compilation is
additional evidence, not an execution support claim. CI compiles
`aarch64-unknown-linux-gnu` and `x86_64-apple-darwin` (all targets, warnings
denied); neither is executed, and neither is a support claim. Both
architectures remain possible through the platform contract.

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
    build.rs          records the compiler, target, optimisation and build inputs for version/doctor
    profiles/launch/  codex.toml, claude.toml, opencode.toml: data only
    tests/            integration and conformance tests; tests/fixtures/
  ouro-fixture/       J1   the conformance child binary (§15) and harness helpers
  xtask/              J1   repository tasks: I02 scan, conformance driver and acceptance verdict, freeze, perf
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
- There is no BPF object crate: D8 selected the ptrace observer, which is
  compiled into `ouro-jail`, and v1 withdraws eBPF (§5.2).
- Schemas are single-sourced under `docs/specs/`. Rust tests read them by a
  path relative to the crate manifest, and the schema identifiers that
  `ouro version --json` announces are constants tested against those files.
- `fleet/` is outside Cargo. Nothing under `crates/` depends on it, which
  keeps I01 literally true; its own gates (north star §10) run only when it
  changes.
- Every crate sets `publish = false`. Binaries are named exactly `ouro`,
  `ouro-jail` and `ouro-ledger` (D6).
- `xtask` owns checks that are not unit tests: the I02 vendor-name scan over
  `crates/ouro-jail/src` and `crates/ouro-ledger/src`, the conformance driver
  and its per-gate verdict over [acceptance-map.toml](jail-v1/acceptance-map.toml)
  (`gates`, `gates-merge`), the milestone freeze file (`freeze`, §16) and the
  performance harness (`perf`, §5.2). The link check is
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
worth integrating. The report,
[backend-evaluation.md](jail-v1/backend-evaluation.md), records the D8
decision (revision 19); a value there is a claim only where the host manifest
and the raw fixture output it cites exist beside it.

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
[backend-evaluation.md](jail-v1/backend-evaluation.md), with the host manifest,
raw fixture locations and a gap-to-gate table. Only the chosen integration
becomes a shipping dependency.

Decision (D8, recorded 2026-09-25): the thin native Rust adapter over
bubblewrap 0.11.1, seccomp and cgroup v2 delegation, which is what J1 to J4
implement. Each candidate was run on the stock reference host with nothing
installed ([fixture runs](jail-v1/evidence/d8-candidates-2026-09-24-ouro-ci.txt)),
and each fails a gate by name. `srt` 0.0.77 cannot run `true`: its seccomp
helper needs a nested user namespace, which the distribution's
`unpriv_bwrap` profile denies. Greywall 0.3.7 needs `socat` and a downloaded
proxy service (GreyProxy), cannot create its TUN device, and its monitor
reports nothing for a write it denied, so it offers no jail-owned observation
(north star D10). The legacy sandbox is an Elixir module of the legacy runtime
(§18), so it cannot run without BEAM, which I01 excludes; it was not run and
stays a source of fixtures. The criteria those failures leave unevaluated are
recorded as not evaluated, not as passed.

### 5.2 Observer candidate and privilege boundary

The observer is a ptrace tracer in the supervisor (D8, revision 19). It was
measured first, on 2026-09-22, because it needs no provisioning under the
default Yama scope that Ubuntu, Debian, Fedora and Arch ship, and it observes
the whole closed set (§11.2), which O01–O06 test. No audit daemon, vendor protocol or seccomp-notification
service is introduced; `agent`'s `connect` results come from the unix-peer
mediator the supervisor owns (§11.4).

eBPF is withdrawn from the v1 contract. Attaching it needs `CAP_BPF`,
`CAP_PERFMON` and tracefs access provisioned on the host, which the
no-host-configuration requirement (§3.2) rules out: unprovisioned, as
`ouro-ci`, attachment was refused
([ptrace probe §1](jail-v1/evidence/ptrace-probe-2026-09-22-ouro-ci.txt)). The
revision-15 working assumption of two observer backends (ptrace everywhere,
eBPF where provisioned) is withdrawn with it, and so are the file-capability
provisioning path and the capability-clearing contract it needed. An eBPF fast
path is future work: it needs its own proposal, which states its provisioning
as an explicit, optional operator step, passes O01–O06 by itself, and keeps
the receipt's `observer.backend` naming what ran.

The selected tracer, with its limits, each specified where it applies:

- It attaches to the blocked launcher before exec with `PTRACE_O_TRACEEXEC`,
  `PTRACE_O_TRACEFORK`, `PTRACE_O_TRACEVFORK`, `PTRACE_O_TRACECLONE` and
  `PTRACE_O_TRACEEXIT`, reads results at syscall-exit-stop, and takes the exec
  event as the confirmed transition (§11.2). Under the default
  `kernel.yama.ptrace_scope=1` an ancestor needs no capability; a host whose
  Yama scope forbids it cannot attach, and `--observe on` then refuses.
- A seccomp filter returning `SECCOMP_RET_TRACE` narrows its stops to the
  closed set; the filter's digest is published and recorded (§11.2). A
  narrowed call still costs two stops, a seccomp stop and an exit stop, which
  is the observation cost below. A call that reaches the narrowing filter with
  no tracer attached fails with `ENOSYS` (§9.2).
- Attachment is per thread and bound to the attaching thread; a traced tree
  cannot be traced by anything inside it; attribution across PID namespaces
  and PID reuse is specified in §11.3.

`fanotify` was not evaluated: the tracer covers the whole closed set, and
`fanotify` cannot supply a confirmed exec transition, `proc.exit` or
`net.connect`. The kernel audit subsystem, an LSM or BPF-LSM program and a
privileged host daemon are not candidates: each is host-global or needs a
separate proposal. The north star's rule that the sensor lives in the
supervisor, outside the child and outside the enforcement backend, applies
unchanged.

v1 provisions no capability. The first release does not install a setuid
helper, run the user's command as root, change sysctls, grant file
capabilities or edit AppArmor, and the supervisor needs no capability for any
profile. Effective UID 0 execution and mismatched real/effective UIDs refuse in
v1. Set `no_new_privs` before child exec and prove the child cannot reacquire
privileges (X06): every contained target starts with empty inheritable,
permitted, effective, bounding and ambient capability sets, and it must not be
able to trace, or take descriptors from, the supervisor or the observer.
User-namespace capabilities are separately confined and do not grant host
capabilities. `doctor` reports
the operator identity category (§14.1).

No observer attachment means refusal with `--observe on`. An explicit
`--observe off` remains usable wherever the containment/lifetime requirements
can be met. It is not an automatic compatibility fallback. A general
privileged host service would require a separate proposal.

Performance is measured with `cargo xtask perf run` on the reference host, as
the operator, from a plain lingering login session and again inside a
pre-entered delegated user scope: at least 30 valid launches per arm after one
discarded warm-up launch per arm, the arms' order a seeded permutation per
round. Workloads: a no-op (the fixture starts, reports and exits), a
descendant-heavy fixture (200 children, one at a time, each forked and
replaced by `/usr/bin/true`) and a fixed file-operation workload (5,000 rounds
of create, rename and unlink of one name in the workspace: 15,000 closed-set
calls). Arms: direct execution, and `tool` (the budget profile), `agent` and
`none` (informational), each with observation on and off. Report median and
p95 startup, wall time, peak RSS, event counts and losses.

- **Startup** runs from the launcher's `CLOCK_MONOTONIC` reading immediately
  before `fork` to the target's first reading at entry to its workload; the
  launcher and the target must be shown to share a time namespace. **Added
  warm startup** is a jailed launch's startup minus the median startup of
  direct execution of the same workload in the same session.
- **Work** is the target's own end reading minus its entry reading.
  **Teardown** runs from the target's end reading to the launcher's reading
  after `wait4` returns the jail (settlement, tree verification, receipts and
  trace flush). **Post-start** is work plus teardown; **wall** is startup plus
  post-start.
- **Median overhead** is the subject's median over the baseline's median,
  minus one. On the fixed workload it is computed on work, on post-start and
  on end-to-end wall. Post-start carries the budget: startup has its own, and
  post-start leaves no jail time after the target's entry uncounted. Work
  isolates the per-call cost while the target runs; work and wall are
  reported. p95 is the nearest-rank 95th percentile.
- **Peak RSS** reports the supervisor's sampled `VmHWM`, `wait4`'s
  `ru_maxrss`, the execution leaf's sampled `memory.peak` and the target's own
  `ru_maxrss`, each named as what it is; a sampled value is a lower bound.
- **Event counts** are the receipt's per-class `observed_count` and the trace
  frames by source; **losses** are observer and coverage gaps, receipt errors
  and incomplete traces, over every launch.
- A launch counts only if the target completed its workload and, jailed, the
  attempt settled with the arm's profile, observation mode and scope state,
  outcome `exited` 0, no error, verified tree death and no gap or degraded
  class; with observation on, an attached observer, every closed-set class
  active, every event count exactly the workload's (the trace's equal to the
  receipt's) and a complete trace (§13.3). With observation off, a target that
  ends before the supervisor confirms its exec settles `unknown` with
  `exec_unconfirmed` (§6.4); such a launch counts, flagged, because the
  target's own report proves it ran. Every other launch is excluded and counted
  by reason, never averaged.
- A verdict needs at least 30 valid launches on both sides, no excluded
  launch on either side, clean raw data (one run, no duplicate launch, counts
  as planned) and a quiet host (every counted launch taken at or below the
  run's stated load threshold); otherwise the numbers are reported without a
  verdict. A budget holds for a profile only if every session and workload
  cell passes.

Initial budgets, as first written: under 250 ms p95 added warm startup, and
under 20% median overhead on the fixed workload. These are engineering
decision thresholds, not customer claims; exceeding one requires a recorded
adjustment before backend freeze. Missing or incorrect evidence cannot be
waived as a performance tradeoff.

Recorded adjustment (operator decision, 2026-09-25, on the milestone
measurement, [backend-evaluation.md §4](jail-v1/backend-evaluation.md#4-performance-52-budgets);
it supersedes the decision of 2026-09-24, which applied both budgets to the
jail's own overhead):

- The startup budget stays: under 250 ms p95 added warm startup. It is met in
  every judged cell, `tool` 101 to 139 ms.
- The 20% budget on the fixed workload is missed, and is replaced by a
  measured ceiling on the jail's own overhead: `--observe off` against direct
  execution, at most 50% median post-start overhead on this syscall-dense
  worst-case workload, judged on `tool`. `tool` measures 39.5% from a plain
  session and 40.3% in a scope, which meets the ceiling and misses 20% by about
  20 points (the informational profiles: `agent` 42.0% and 42.5%, `none` 3.1%
  and 5.8%). Its work phase (+29.6%, +28.9%) and end-to-end wall (+99.9%,
  +90.7%, startup included) are reported, not budgeted. The dominant cost is
  bubblewrap's containment as the stock distribution confines it: on this
  workload, measured at revision `4380241f` (the later commits change neither
  bubblewrap nor the distribution's confinement), bubblewrap alone, with the
  `tool` profile's namespaces under Ubuntu's `unpriv_bwrap` AppArmor
  confinement, adds 19.0% to the work phase, and the jail with observation off
  22.2%, so the jail's filter and supervisor add about 3 points
  ([attribution](jail-v1/evidence/perf-2026-09-25-attribution-ouro-ci.txt));
  settlement, tree verification, the receipts and the trace flush add a
  median 19.4 ms (plain) and 18.6 ms (scope) of teardown.
- The cost of observation (`--observe on` against off, and against direct) is
  reported per workload with its median, p95 and valid and excluded counts,
  and has no budget. Every closed-set call costs the observer two ptrace
  stops, measured in J0 at about 22 µs each on the reference host, and nothing
  in user space removes them, so the cost scales with the rate of closed-set
  calls: on the fixed workload, about 100,000 such calls per second, `tool`
  with observation on is +423% to +433% on the work phase against direct; it
  is
  small on work that mostly computes, reads or writes, which the set does not
  cover.
- A representative workload, a build or a test run, joins the §5 set as later
  work.

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
Precedence is `--profile`, then `config.toml`'s `jail.profile`, then the launch
profile's `jail`, then `tool`. When `config.toml` selects a profile and the
launch profile's `jail` names a different built-in base, resolution refuses
with both names rather than replacing either; `--profile` settles it.
Default workspace: the invocation directory. Default scratch: a new private
attempt directory. Default observation: `on`. Default evidence: `strict`.
`--profile none` is the only way to select `none`; files and environment cannot
select it. An explicit contained profile may override a launch default only
when its requirements still permit that launch profile's credentials/network.
`tool` and `build` reject launch credentials and proxy grants.

`--label-only` resolves, probes and prints a proposed execution label, without
executing the user command or copying credentials. `explain` does not probe or
execute anything, and distinguishes requested policy from measured capability.
Its output carries environment names, never values (canonicalization.md).
`--label-only` rejects `--gate-fd` and `--attempt-id` as usage errors.
Inspection JSON goes to stdout; diagnostics go to stderr. `run` preserves child
stdout/stderr byte streams and has no `--json` stdout mode. An error that
reaches no durable receipt (a terminal receipt that failed to persist, and
what only it would have recorded) is printed on stderr, one line per error.
A diagnostic that cannot be written to stderr is dropped: diagnostics never
change an exit code.

`--control-fd` carries structured control messages instead of textual launch
diagnostics. `--trace-fd` carries events. Each supplied fd must be open, have the
correct direction, be distinct from all other supplied channels and stdio, and
be owned exclusively for the invocation. The child inherits only validated
stdio, not those channels. Fd validation fails before preparation.

`version --json` announces the schema identifiers this build writes,
`"frozen": true` since the milestone-1 freeze (§13), the running platform's
closed set (`observation.closed_set`: `linux-closed-v1` on a Linux build whose
architecture the syscall tables cover, §3.2, otherwise null, as on macOS in
this milestone) and a `build` object. `build` carries `revision` and `dirty`,
the build environment's claims (`OURO_BUILD_REVISION`, `OURO_BUILD_DIRTY`),
validated: a revision is a full, non-zero 40-hex commit, `dirty` requires a
revision, a malformed or contradictory pair fails the build, where the
repository is present a claim that disagrees with it fails the build, and a
build environment that sets neither records null, never a guess. It also
carries what was measured at compile time: `rustc` (`rustc -V`), `target`,
`opt_level`, `debug_assertions`, and `inputs`, the SHA-256 of the build inputs
(every file under the jail crate's `src`, its build script and manifest, the
workspace manifest, `Cargo.lock` and `rust-toolchain.toml`). The same digest
computed from a commit shows whether a binary's claimed revision is the tree it
was built from. `doctor --json` carries the same `build` (§3.2). `gc --json`
reports what became of an attempt's execution boundary under the key
`execution_boundary`. `gc --json` and `explain --json` are unversioned
diagnostics: their shape can change without a new identifier.

### 6.2 Paths and precedence

On both Unix platforms, configuration defaults to `~/.config/ouro/config.toml`
and runtime state to `~/.local/share/ouro`. `OURO_CONFIG_DIR` and `OURO_DATA_DIR`
override these locations. Runtime state must be a private local directory owned
by the operator and outside every child-visible grant. Files are mode 0600,
directories 0700. Reject symlinked state roots, foreign ownership, unsafe parent
replacement and network filesystems whose required durability is unproved. An
ancestor writable by others without the sticky bit is unsafe; group write
counts as others unless the group is the owner's private group (the owner's
primary group, listing no other member, and no other account's primary
group), as stock Debian and Ubuntu create with a umask of 002.

Apply configuration in this order:

1. Built-in profile and operator config/selected operator profile.
2. Operator launch profile, if any.
3. Operator environment settings from a fixed documented allow-list:
   `OURO_CONFIG_DIR`, `OURO_DATA_DIR`, `OURO_JAIL_OBSERVE`,
   `OURO_JAIL_EVIDENCE`. No environment-derived path or host grants.
   Every `OURO_JAIL_TEST_*` variable is a test-only knob: it can only shrink
   a bound, end an attempt early, make the product take a path it takes on
   other hosts or under a real loss, or hold one named point for a bounded
   time; it never widens authority and leaves the policy digest
   unchanged. The release binary honours them, so the tested binary is the
   shipped binary; [J5 authority](jail-v1/j5-authority.md) lists the gates
   each one proves. At attempt start every such variable set is
   recorded, name to value (a name set more than once with its first value,
   the one `getenv` returns and every consumer applies), in `jail-state.json` `test_seams` and in
   `lifetime.native.details.test_seams` of every receipt that has native
   details (a refusal before a boundary exists has none, so there only jail
   state records them). The knobs: `OURO_JAIL_TEST_MEDIATION_QUEUE` (the
   unix-peer mediation record queue, 1 to 4096), `OURO_JAIL_TEST_TRACE_CAP`
   (the local trace cap, 4096 bytes to 64 MiB, half of it at most 256 KiB
   reserve, and named in every loss it causes), `OURO_JAIL_TEST_ABORT_AT`
   (`<site>:<point>[:<n>]` aborts at one named point, `temp_written`,
   `temp_synced`, `renamed` or `dir_synced`, of the `n`th write, 1 to 10,000
   and the first when omitted, at one persistence site),
   `OURO_JAIL_TEST_GC_MAX_ENTRIES` (gc's per-invocation
   entry bound, reported in gc's `test_seams`), and
   `OURO_JAIL_TEST_TRACER_INFLIGHT` (1 to 16,384) and
   `OURO_JAIL_TEST_TRACER_QUEUE_BYTES` (1 to 4,194,304; the bound in force,
   recorded as `observer_plan.queue_bytes_max`, is at least 256 bytes), which
   are ignored
   unless the value is decimal digits in range and are also named in the
   receipt's `observer_plan.test_seams` with the value applied, or null when
   ignored. `OURO_JAIL_TEST_SUPERVISOR_SCOPE` takes §9.3's outside-a-scope
   branch of the supervisor scope step even inside the delegated subtree
   (`assume-outside`), with `busctl` treated as absent
   (`assume-outside-no-busctl`), with an unreachable bus
   (`assume-outside-no-bus`) or with lingering treated as off
   (`assume-outside-no-linger`); any other value is ignored; it is named in
   `supervisor_scope.test_seam`, with the value applied or null when
   ignored. `OURO_JAIL_TEST_ARCH` makes the probes that rest on the x86_64
   syscall tables refuse as a build for the named architecture would (§3.2);
   it can only add a refusal, and the refusal's evidence names it.
   `OURO_JAIL_TEST_MOUNT_SWAP=<dir>` writes `<dir>/pinned` once every mount
   source is pinned and then waits, at most 10 seconds, for `<dir>/go` before
   §9.1's handoff verification, so a test can replace a pinned source; a value
   that is not a usable directory does nothing.
   `OURO_JAIL_TEST_TRACER_TRUNCATE_PATH=<substring>` makes a covered non-exec
   call whose path contains the substring report a path the observer could not
   read, so a successful one is a `path_unreadable` gap, and
   `OURO_JAIL_TEST_TRACER_UNMATCHED_EXIT=<substring>` follows such a call's
   entry without recording it, so its exit is an `unmatched_exit` gap; each
   manufactures only a gap the observer records for the real loss.
   `OURO_JAIL_TEST_TRACE_FD_WRITE_MAX=<bytes>` makes the external
   `--trace-fd` sink put at most that many bytes into each write, so a frame
   longer than it reaches the consumer in several partial writes, each
   resumed at its offset (§13.3); a value that is not decimal digits without
   a leading zero, from 1 to the event bound, is ignored.
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
operator profile that tightens `tool`; its relative paths resolve against the
directory that holds the file (§6.2), so it narrows the workspace it sits
beside, and a `read_only` entry that lies outside every granted root is a
widening, which refuses:

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
| Add credentials, a launch profile or `none` | Refuse |

No v1 layer has an executable or backend key (the file keys above, §12), so no
file can widen through one: such a key is unknown and refuses
(`invalid_config`). A credential in a project file refuses as the widening it
is, `policy_widening` at `jail.credentials`.

Compare authority after expansion and path resolution, not TOML ordering or
string prefixes. `/work/a` is not an ancestor of `/work/ab`. Denial wins over
an overlapping allow at any depth: a grant beneath a denied subtree is a
widening, not a carve-out. Read-only carve-outs override writable parents.
Paths from an untrusted layer are compared by filesystem identity where the
object exists: a symlink component refuses; an object whose identity equals
or lies beneath a denied object is denied whatever its spelling, case folding
included; an object that cannot be resolved compares as unknown, which
refuses. An unreadable, non-regular or oversized narrowing file is
`invalid_config`, never an absent one; only a missing file means no narrowing. A host
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

| Profile | wall (required) | pids (preferred) | mem | cpu | Execution boundary |
|---|---|---|---|---|---|
| agent | 2h | 512 | Absent unless explicit | Absent unless explicit | Required by an explicit tree limit; the ptrace observer needs none |
| tool | 30m | 256 | Absent unless explicit | Absent unless explicit | Required by an explicit tree limit; the ptrace observer needs none |
| build | 1h | 512 | Explicit ceiling required | Absent unless explicit | Required for memory |
| none | 2h | Absent unless explicit | Absent unless explicit | Absent unless explicit | Required for lifetime, including observe off |

The requirement `execution_boundary` names a tree the supervisor can place the
target in, bound resources on, kill as a whole and verify empty. `none` needs
it for lifetime (observation on or off), and every explicit pids, memory or
CPU ceiling needs it. It names the semantic, not a mechanism (§3.1): the Linux
plan satisfies it with a delegated cgroup v2 leaf, and a platform without one
reports it `unsupported`. Linux-private state and native details keep their
own names (`execution_cgroup` in `jail-state.json` and in
`lifetime.native.details`). The receipt's `lifetime.boundary` values are a
per-OS vocabulary, not portable requirements: `pid_namespace` and
`supervisor_cgroup` are Linux's, `native_tree` is another platform's, and the
receipt schema refuses the Linux values in a macOS receipt (M02).

Every explicit limit from CLI, operator or project config is required, even
when it equals a preferred default. Attempt preferred pids enforcement when
delegation and its controller are usable; otherwise record the requested value
with `required=false`, `applied=false`, null mechanism/hit/scope and
an explanatory wrapper note. Missing a preferred controller alone never refuses.
Lifetime requirements can require an execution boundary without requiring its
pids controller. `none` may enforce explicit cgroup limits but still cannot protect
them against same-UID interference. No unspecified memory/CPU ceiling is implied.

Linux measures execution wall, preparation/gate/stop budgets and event elapsed
time using `CLOCK_BOOTTIME`: suspend counts, wall-clock adjustments do not.
An expired deadline is acted on when execution resumes; the supervisor cannot
run during suspend. The preparation budget covers credential staging, which
waits on the same deadline. Waits that bound I/O or a race rather than the
attempt (the watcher's grace, `gc`'s own verification, trace and persistence
progress, the scope step's wait, proxy deadlines, the observer's internal
waits) may use the monotonic clock; a suspend lengthens them. Later macOS uses
a native continuous clock with the same suspend semantics. Pids, memory and CPU use their separate cgroup mechanisms.

Exit codes: child's code on a completed execution; `128 + signal` for a
signal-terminated child; 1 for a tool failure; 2 for invalid CLI/config syntax;
125 for refusal before user exec. A post-launch tool error takes code 1 and
preserves the separately observed child outcome in the receipt. Deadline or
requested termination preserves the observed code/signal and records its cause.
`outcome.cause` is the first stop reason the supervisor acted on; a later
deadline, loss or signal is recorded (its limit's `hit`, `errors[]`) but does
not replace it. A loss the platform processed after the target's own end is
recorded (`errors[]`, exit 1) but is not a stop the supervisor acted on: it
requests no stop and never becomes `outcome.cause`.
A child exiting 125 is `outcome.kind=exited`, not `refused`. A persistence
failure (`state_write_failed`) before exec is a refusal (125); after exec it
is a tool error (1). With observation off, a target that ends before the
supervisor sees its new image cannot have its exec confirmed (§8.1 step 7:
end-of-file on the error channel alone is insufficient). The outcome is
`unknown`, and the run is a tool error: exit 1 with `exec_unconfirmed` (stage
`running`, remediation `configuration`) in `errors[]` and on stderr.
`--observe on` confirms such an exec. Measured on the reference host,
`/usr/bin/true` under `tool` or `agent` with observation off ends this way on
every launch.

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
`prepare_timeout`, `attempt_exists`, `exec_failed`,
`exec_interpreter_missing` (§13.2), `evidence_lost`, `exec_unconfirmed`,
`tree_unknown`, `state_write_failed`, and `internal_error` (a defect of the
implementation, reported rather than papered over). An error's stage is one of
the §8.1 states. Do not include raw credentials, raw argv or environment
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

The supervisor holds `jail.lock` through settlement/cleanup, and while any of
its persistence steps may still be in flight: after a stalled step it never
unlocks it, and only the end of the supervisor process releases it. A future owner
uses its own lease, not this lock. An existing attempt root is acceptable only
with validated ownership/permissions and no previous jail state or jail-owned
artifacts. Claim it while holding the lock: `jail-state.json` is written and
synced under a temporary name and published by an exclusive link, so the claim
is never visible incomplete. A prior jail claim, live or dead, refuses
`attempt_exists`; the caller
reconciles it rather than spawning again. Test concurrent claims and crashes
after claim creation. The child cannot inherit the lock.
Register resource ownership before populating credentials
or launching helpers. The execution cgroup is registered in jail state by name
before it is created (P15) and by device and inode right after, before anything
is placed in it (P16); a failed registration refuses. The leaf is named
`ouro-<attempt id>.leaf` after its attempt root, directly under the delegated
subtree, and created exclusively; the name is the attempt association §9.3
registers. A leaf that belongs to no attempt (a `doctor` probe's) is named
`ouro-probe-<token>.leaf`. State updates use create-new temporary file, write,
file sync, atomic rename, and parent-directory sync. A successful rename alone
is not a durable acknowledgment. Platform code defines and tests its sync
guarantee. A failed write removes its temporary file; a crash can leave one
(`.<name>.<id>.tmp`), which never replaced anything. Every durable write names
its persistence site (review-resolutions revisions 15 and 16 list P1 to P16), where
faults and crashes are injected in tests. Failed/ambiguous persistence before
exec refuses (125, a refused receipt when one can still be written, and
`refused` only once that receipt is durable); after exec it stops the tree and
leaves an incomplete receipt if necessary.

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
   release locally. Start the wall deadline, on the continuous clock of §6.4, at
   release.
7. Execute the exact target argv through the blocked launcher. Use a dedicated
   close-on-exec error channel plus backend/observer evidence to distinguish
   success from exec failure. EOF alone is insufficient if launcher death could
   also have closed that fd. Persist the enforced receipt after confirmed exec.
8. Monitor child status, evidence, control, limits and lifetime independently.
   Target exit triggers termination of remaining attempt descendants; background
   children do not become an independent service. Preserve target outcome. The
   remaining tree is ended as soon as the target exits, before the supervisor
   waits for receipts still being persisted.
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
prepared. Both run on the continuous clock of §6.4 (`CLOCK_BOOTTIME` on
Linux), so suspend counts against them, and are distinct from the execution
wall budget. A wait for the gate re-checks its deadline at least every 250 ms,
so an expiry is acted on soon after execution resumes. Expiry refuses and
tears down prepared resources. A step of preparation whose own wait the budget
ended refuses with `prepare_timeout` and remediation `retry`, never as the
failure of that step, and an attempt whose budget is spent before its prepared
receipt is persisted refuses without publishing `prepared`. A future owner must
handle a timed-out prepared attempt through reconciliation, not reuse the gate.

For managed Linux mode, verify and record the direct owner's birth identity,
install the parent-death signal, then recheck the parent to close the setup
race. Contained runs must have a tested death chain from owner to supervisor to
namespace init. In `none`, owner/supervisor loss preserves the accepted unknown
lifetime limit; there is no new watchdog.

Control output uses NDJSON, with schema `ouro.jail.control/1`, attempt id,
monotonically increasing message number starting at 1, and kind `prepared`, `exec_confirmed`,
`refused`, `settled`, or `unsettled`. `refused` is sent only while the target
has not executed: before release, or when the released target's `exec` fails,
which §8.1 counts as a pre-exec failure; once the target has executed, the
terminal message is `settled` or `unsettled`. `unsettled` is the terminal
message after exec when tree death could not be
verified, and the receipt then keeps its last nonsettled phase with
`tree_empty: null` and the `tree_unknown` error. A control message
acknowledges only a receipt that is durable. Messages carry the receipt's
phase and its digest (`sha256:` over its RFC 8785 canonical bytes, the digest
its `jail.receipt` note names) and safe outcome, never raw argv. Maximum frame is 64 KiB. This is reporting, not a vendor or
interactive approval protocol.

### 8.3 Fds, stdio and supervision

Foreground stdio is inherited without capture or parsing. The supervisor must
not retain writable copies that postpone EOF: once the attempt is prepared and
every child that needs stdout has it, the `ouro-jail` binary points its own
stdout at `/dev/null`, so under `none` the caller sees end-of-file on stdout
when the target closes it, as in direct execution (a program that runs the
library in-process keeps its stdout). Named limits: the supervisor keeps
stderr, which carries its own diagnostics (§6.1), so end-of-file on stderr
comes when the jail exits; under the contained profiles bubblewrap's outer
process and namespace init hold the stdout and stderr they hand the target
until the jail exits, so the caller's end-of-file on either comes then. A
stdio consumer must not treat end-of-file as the only sign that a run ended
(§9.3). No PTY or interactive job-control
emulation is provided. The command runs in a new session; INT/TERM/HUP received
by the supervisor request termination. Existing terminal fds are explicit I/O
authority; the backend must prevent TIOCSTI-style terminal injection.

Reject socket or directory stdio descriptors for contained runs, and reject
regular-file stdio that resolves into protected supervisor state, which is
the whole runtime state root of §6.2, not only this attempt's directory; a
stdio descriptor that cannot be inspected refuses rather than being skipped. Pipes, tty
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
SSH-agent sockets. An operator grant (`--ro`, `--rw`, an operator profile or a
launch profile) whose resolved source is on a `proc`, `sysfs` or cgroup (v1 or
v2) filesystem, or that is an ancestor of such a mount, refuses before exec
with `policy_widening`, remediation `configuration`, naming the grant's key
path. The decision is by the pinned source's filesystem type (`statfs`) and the
mount topology, never by path spelling, so a symlink onto `/proc` refuses too;
`--ro /` is refused earlier by the state-isolation rule (§§6.2, 7). The
built-in runtime roots are on the root filesystem, and the child's private
`/proc` and `/dev` are made by the backend, not bound from a grant. Denied subtrees within visible parents are absent or masked
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
workspace side effect of this mechanism. Recorded for the bubblewrap
integration: a workspace whose host path lies beneath the scratch mount point
makes the backend create that path's skeleton inside managed scratch, which
is removed with the scratch; the workspace itself is untouched.

A protected symlink cannot authorize its target. Test file-form `.git`, nested
repositories, symlink replacement and mount replacement separately. A newly
created protected segment below a previously ordinary nested directory remains
outside Linux `existing_and_root` coverage. Requiring `all_descendants` refuses.

Vendor state is bound read-write at `/run/ouro/state`, and each `bind_ro`
credential view read-only at its destination beneath it, after every operator
grant; the attempt directory above it is never visible. Vendor state and
scratch are attempt-private and removed at settlement, so the root-level
protected literals above do not apply to them: `existing_and_root` speaks of
the persistent writable roots (workspace and operator grants).

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
thread-creation fallback; it does not pretend to inspect that pointer. Every
contained baseline refuses `clone` with `CLONE_UNTRACED` (EPERM). In `none`
the observer stops on it, and a created task is an `untraced_descendant` gap
in every audit class with no count and no end; that task's closed-set calls
fail with ENOSYS. The observer's filter answers `clone3` with ENOSYS in every
observed profile, so a runtime that cannot fall back to `clone` does not run
under observation. Deny
`AF_UNIX` creation through both `socket` and `socketpair` for those profiles.
They also refuse `seccomp(2)` whose flags contain
`SECCOMP_FILTER_FLAG_NEW_LISTENER` (EPERM), because a child's own notification
listener outranks the observer (§11.4); a filter without a listener stays
permitted.
Their network namespace and absence of inherited sockets remain the boundary.
The reference conformance toolchain uses glibc. Other runtimes must pass their
own threading fixture; a runtime that cannot fall back is incompatible, not
a reason to silently allow `clone3`.

Every contained profile creates sockets only in the AF_UNIX (subject to the
rules above and the `agent` mediation), AF_INET and AF_INET6 families;
`socket` and `socketpair` in any other family fail with EAFNOSUPPORT, because
a network namespace does not isolate every family a kernel offers. The one
exception is the `agent` launcher's own socket-diagnostic netlink socket,
opened before the mediation filter, which then refuses every netlink socket.
Before exec the trusted launcher restores exactly the signal state the jail
itself changed (SIGPIPE to its default, the inherited signal mask); operator
dispositions such as an inherited ignored SIGHUP pass through unchanged.

`agent` uses a separate filter that permits the unprivileged sandboxing an
inner vendor sandbox needs: `no_new_privs`, its own seccomp filters and
Landlock. These work inside the outer layer on every supported host and are
the nesting `agent` guarantees. Where the host also permits nested user
namespaces, the filter additionally permits the namespace creation and
mount/unmount an inner namespace sandbox needs, within the outer restricted
authority. Nothing it permits may recover excluded paths, make locked
read-only mounts writable, join a host namespace or obtain direct egress.
Record the allowed setup operations and the measured nested-namespace
capability in the receipt, and probe the real nesting sequence, not just one
successful `unshare` or `landlock_restrict_self`. Where nested user namespaces
are unavailable, `agent` still runs: an inner sandbox that needs them fails
visibly to the child, the jail never simulates it, and the receipt never
claims it ran. The jail never disables the outer sandbox, and never disables
or rewrites an inner one; running a vendor with its own sandbox off is the
operator's choice of argv or vendor configuration, and its tool commands then
share the agent's jail authority. If a nesting mechanism the host does offer
cannot be permitted safely, `agent` refuses rather than permitting it
unsafely. Seccomp restrictions are inherited; namespace creation and Landlock
domains do not remove them. An inner filter cannot obtain its own seccomp
notification listener while the outer mediation filter (§10) holds one.

The backend may use more restrictive mechanisms when their behavior passes
the same contract. There is no arbitrary seccomp expression in user config.
The concrete filter table is part of the pinned backend evaluation.

### 9.3 Lifetime and cgroups

The supervisor remains outside the child's namespace and resource boundary.
Use a live pidfd and recorded boot/birth identity when addressing a process;
never signal a PID recovered from a file without revalidating its identity.

For a contained run, record the namespace-init identity and verify the selected
backend's entire death chain, including any intermediate launcher. Recorded
limit of the bubblewrap integration (measured 2026-09-22 and 2026-09-23):
bubblewrap clears an inherited parent-death signal during its own startup
before arming its own for `--die-with-parent`, and its namespace init arms its
own later still, after waiting on an event only the outer process sends. A
supervisor killed with SIGKILL inside that window therefore leaves bubblewrap's
outer process, and possibly the namespace init with whatever it started,
orphaned and holding the run's stdio open. J2 and J4 close the window where the
attempt has an execution leaf, with a trusted blocked bootstrap and an outside
watcher holding supervisor/backend pidfds and the leaf's `cgroup.kill` (opened
by the supervisor after the backend is placed in the leaf). The bootstrap
cannot exec bubblewrap until the watcher confirms readiness; supervisor death
makes the watcher kill the whole leaf and then bubblewrap, and watcher death
makes the supervisor stop the boundary. The supervisor releases the watcher,
over a private pipe, as soon as it sees the backend's end; the pipe's
end-of-file, like the supervisor's pidfd, means the supervisor is gone, and a
supervisor that drops the watcher unreleased on an error path gets the same
kill by design. The backend's end without a release starts a short grace
(500 ms) rather than the watcher's exit, because bubblewrap's parent-death
signal follows the supervisor thread that started it and can fire while the
rest of a dying supervisor still looks alive: a supervisor that dies within
the grace still has its leaf killed, and one that outlives it owns the rest.
On Linux, `run` and `doctor` first make sure the supervisor itself is inside
the operator-delegated subtree. Before any thread or other resource exists, a
supervisor whose `/proc/self/cgroup` lies outside `user@<uid>.service` asks
the systemd user manager for a transient scope containing its own pid
(`StartTransientUnit` of `ouro-jail-<pid>-<random>.scope` with `PIDs` and
`CollectMode=inactive-or-failed`, through `busctl` at `/usr/bin/busctl` or
`/bin/busctl`, run as a child with only the bus variables in its environment,
no inherited descriptor and a parent-death signal). The supervisor is never
re-executed: its pid, descriptors, argv, stdio and parent are unchanged. It
then waits up to 2 seconds, call included, to see itself in that very unit
inside the subtree. It does this only where the user manager lingers
(logind's record under `/var/lib/systemd/linger`): a supervisor in the scope
belongs to the user manager, which without lingering stops when the last
session ends and would take the run with it, while a supervisor left in its
session scope survives logout. Every receipt with native details records the
result as `lifetime.native.details.supervisor_scope` (`state`
`already_delegated`, `entered` or `unavailable`; the `unit` requested or
null; `reason_code` and `reason`; the `cgroup` observed at the end), and
`doctor` reports it too (§14.1). The step never fails a run. Where it cannot
enter a scope (no delegated subtree, no lingering or unknown lingering, no
`busctl`, no user bus, a refused call or a move not observed in time), the
attempt lacks an execution leaf unless a required limit demands one; then the
watcher can kill only bubblewrap's outer process, and a supervisor killed
during bubblewrap's startup can leave the namespace init, and under `agent`
its bridge, alive and holding the run's stdout, where `gc` cannot find them
(measured 2026-09-24 from a plain login session before the step existed: 20
of 20 synchronized `agent` kills; with it, 0 of 20). Enabling lingering
(`loginctl enable-linger`) or running in a delegated user scope closes it.
Lingering is a per-user logind setting of the account that runs the jail, an
operator step, not host configuration: it changes no sysctl, security profile
or capability, and whether an account may enable it for itself is the host's
logind policy; `doctor` reports it (`host.linger`, §3.2). A
synchronized fixture covers death before bootstrap release and after a
backend clears its parent-death signal; a stand-in fixture covers a leaf
member that is not the backend. Every process `doctor` starts for a probe
dies with `doctor` (§14.1); the agent probe's jail has the limit above only
when `doctor` could not enter a scope. A stdio consumer must not treat
EOF as the only sign that a run ended. Linux kills
remaining namespace processes when its init dies; this is the mechanism behind
the required parent-death test, not an assumption about process groups.
See [PID namespace semantics](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html).

For a contained run, create a unique cgroup beneath an operator-delegated v2
subtree when one is available. A limit that requires it refuses without one;
otherwise the run proceeds with the cgroup recorded unavailable and without
what depends on it: preferred limits, the cgroup check of tree emptiness and
the watcher's whole-leaf kill above. Keep the supervisor outside that execution leaf.
Register its path, filesystem identity and attempt association (the leaf's
name, §7); place the
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
In every profile the supervisor makes itself non-dumpable (`PR_SET_DUMPABLE`
0) once the target is about to run, after the capability probes and the
observer's attach: a same-UID process can then no longer read its `/proc`
entries (`fd`, `environ`, `mem`, `exe`) or trace it, so it cannot reopen the
operator's live trace or control stream, read the operator's environment or
seize the supervisor. Signals, the shared records in the data directory (R05)
and the cgroup remain open to a same-UID peer.
A narrowing that asks `none` for a restriction it cannot apply (read denials,
read-only grants, protected coverage, network `none`) makes the requirement
unsatisfiable and the run refuses with remediation `configuration`. The
supervisor reads membership from `/proc/<pid>/cgroup`, is a child subreaper,
and checks an exited child's zombie before reaping it; what was below the
supervisor before it started the launcher (a child it was started beside,
such as a shell's process substitution reading `--trace-fd`, and that child's
descendants) is recorded by birth identity then and is not an attempt
descendant: it is never walked, reaped, recorded as an escape or signalled. A
process born into such a subtree after that and orphaned to the supervisor
cannot be told from an escaped attempt process and is treated as one (a named
limit). A detected loss adds a
wrapper note (`fields.kind = lifetime`) and reaches the next receipt, and does
not by itself stop the attempt. `none` adds no watcher of its own.
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

The Linux mechanism, measured on a stock host with no host configuration
([spike](jail-v1/evidence/unixpeer-spike-2026-09-22-ouro-ci.txt)), is seccomp
user-notification mediation. The `agent` filter returns
`SECCOMP_RET_USER_NOTIF` for `connect` and permits AF_UNIX sockets only of
type stream or seqpacket; datagram and raw AF_UNIX sockets are refused at
`socket`/`socketpair`, because a datagram send can name a peer in
`sendmsg`'s `msg_name`, which a filter cannot read. The trusted launcher
installs the filter with its own listener and opens a `NETLINK_SOCK_DIAG`
socket inside the attempt's network namespace; the supervisor takes both from
the blocked launcher by descriptor before release. For each notification the
supervisor reads the address, revalidates the notification, and takes a
duplicate of the child's socket through a pidfd for the notifying thread
itself (`PIDFD_THREAD`), because multi-threaded runtimes connect from worker
threads; on a kernel without it, through the thread group leader's pidfd only
when both share one descriptor table, and otherwise the connect is refused. A
pathname address is resolved in the child's own view without leaving it:
absolute paths begin at the child's root, while relative paths begin at its
cwd and may ascend only as far as that root; absolute symlinks also restart
there. The resolved node is pinned by an `O_PATH` handle and allowed only when
a listener bound to that node's filesystem identity lives
in the attempt's network namespace; the supervisor then connects the child's
socket through the pinned handle, so the kernel reaches exactly the node that
was checked. A node whose inode number does not fit the kernel's 32-bit
socket-diagnostic identity is refused. Non-AF_UNIX and abstract addresses are
connected by the supervisor on the child's own socket, whose network
namespace is fixed at creation. The supervisor never answers with
`SECCOMP_USER_NOTIF_FLAG_CONTINUE` for a security decision. Without a live
listener the filter fails closed.

Named limits of this mechanism: a mediated connect runs in the supervisor's
security context, so an inner sandbox's Landlock network rules and
abstract-socket scope do not compose through it (inner seccomp filters do,
because their denials outrank the notification); the reach of a mediated
connect is still only the attempt's own network namespace. A listener's peer
credentials name the supervisor for a mediated pathname connect. A listener
bound inside a network namespace nested within the attempt is not in the
attempt's diagnostic view and is refused. An inner sandbox cannot install its
own seccomp notification listener while the outer one holds one. A connect
mediated this way is not a ptrace stop; the mediator emits its evidence. When
the kernel offers a native, composable restriction of pathname Unix peers,
prefer it and drop the mediation.

The mediation governs connections the child initiates. A host process that
itself connects to a socket the child bound in a writable shared root talks to
the child, and can pass it descriptors; that is the host tool's choice, like
reading a file the child wrote there. The jail does not protect host tools
from sockets or files the child plants in roots it may write. A later
hardening may refuse socket-node creation in shared roots (Landlock
`MAKE_SOCK` beneath the workspace and operator grants); it is not claimed now.

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
do not log request paths, query strings, headers, tokens or bodies. Proxy death
is a loss of `proxy.net` evidence: strict stops the attempt, best-effort
continues degraded. Bridge death loses no evidence: it is recorded once, when
it happens before settlement, and new connections fail. The bridge is started
by the trusted launcher before the observer's filter, runs under the `agent`
baseline and the mediation filter, is not a descendant of the target, and its
own connects are the jail's plumbing, attributed by its pinned identity (pid
and start time), not to the target. The mediator admits the authorized proxy by
its full pinned device and inode. At capacity the bridge answers
`503 bridge_overload` and closes. A target that signals every process it can
reach can kill its own bridge; the attempt then loses its own network, which
fails closed and is recorded.

Initial budgets per attempt: 128 active connections, 32 KiB request headers,
10-second DNS/connect/header deadline, 1 MiB total bounded relay buffers.
At capacity, reject excess requests with a safe overload reason. Stream data
with backpressure; do not buffer response bodies. Connections close on stop.
These limits are resource budgets, not permission grants. The header deadline
runs from accept and is absolute; resolution and connection each have their
own 10-second deadline. The proxy serves one request per client connection:
bytes after the first request are discarded and the connection closes after
its response. Per-request work is bounded as well: host normalization refuses
an over-long label or name before any encoding, so no request can make the
supervisor do unbounded work. The proxy's descriptors are budgeted against the
supervisor's limit; a request it cannot serve for lack of resources is
recorded as the proxy's failure, never as the client's. A numeric allow rule is
an explicit address grant for that address and port, whatever name resolved
to it (network-rules.md).

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
The ptrace observer (§5.2) attaches to the blocked launcher and follows its
descendants through their fork, vfork and clone events, tracking task birth
identity and fork ancestry for attribution; namespace-safe descendant
tracking, PID reuse handling and parent-exits-before-child behavior are O02's
(§11.3 states what is simulated). Setup helpers are tagged as helpers, not
attributed as user target operations.

The observer's scope is the attempt tree and nothing else the supervisor has.
It ends when every task it traces has been reaped, every child the supervisor
gained after the attach (an orphan of the traced tree) has been reaped and
delivered as an untraced exit, and the backend the launcher
descends through has exited, never on the absence of any child. A process the
supervisor was started beside, a child it already had when it began (such as
a shell's process substitution reading `--trace-fd`), is an unrelated host
process: it is not observed, its state changes are neither events nor loss,
and it does not delay the observer's end. Its exit while the observer owns the
supervisor's waits is delivered as an untraced exit, not recorded as loss; one
still alive when the observer ends is left to its owner.

Read only the arguments needed for the closed set after the attempt filter
matches. Never stream unrelated host processes into user space and filter them
later. Do not persist unredacted paths, argv, environment, socket payloads or
memory snapshots. Raw argument bytes may exist only in bounded transient
buffers before redaction; they must not appear in debug logs or core-dump
artifacts from the test runner.

### 11.2 Closed set `linux-closed-v1`

Attach supported native ABI variants of the operations below. The implementation
must publish its exact hook/syscall table. Calls absent on an architecture are
identified as absent; equivalent variants that exist must be tested. The
x86_64 table is published as
[`evidence/closed-set-x86_64.txt`](jail-v1/evidence/closed-set-x86_64.txt),
generated from the observer's rows and by running the installed narrowing
filter; it names the narrowing-filter digest that receipts record in
`lifetime.native.details.narrowing_filter_digest`, and conformance compares
the table with the build and the digest with a live receipt. A successful
exec's `proc.exec` names its call in `fields.syscall`, unless the observer did
not follow that exec's entry (the in-flight bound refused it, or the process
was taken on inside its own `execve`): then the result names no call and its
path is `{unavailable, argument_not_read}`. A call
under another ABI (a non-native architecture, or the x32 bit) is never decoded
from the native table. Contained baselines refuse those ABIs; in `none` the
observer stops on each, and one the kernel did not reject as nonexistent
(ENOSYS) is a `foreign_abi` gap in every audit class.

| Operation | Native evidence | Meaning of a result |
|---|---|---|
| `proc.exec` | `execve`, `execveat` entry plus confirmed exec transition, or failed return | New executable image established, or an exec failure; never infer success from an entry |
| `proc.exit` | Confirmed termination of the entire tracked thread group after a witnessed exec | That process exited with the observed status; not a single thread exit or tree emptiness |
| `fs.create`, `fs.write` | `open`, `openat`, `openat2`, `creat` requesting write/create/truncate; `truncate` by path (action `truncated`) | Successful open for possible mutation, or a truncation by path; not bytes written or proof a file was newly created |
| `fs.rename` | `rename`, `renameat`, `renameat2` | The named rename call succeeded or failed |
| `fs.unlink` | `unlink`, `unlinkat`, `rmdir` | The named removal call succeeded or failed |
| `fs.create` | `mkdir`, `mkdirat`, `link`, `linkat`, `symlink`, `symlinkat`, `mknod`, `mknodat` | The named directory-entry creation succeeded or failed |
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
A failed open that requested no mutation is outside the set and produces no
event: read denials are excluded, not merely uncounted, and a consumer must
not read the absence of an `fs.deny` as the absence of a read denial.
Audit `decision` is always null: errno alone cannot identify DAC, LSM, seccomp
or a particular jail policy decision.

For syscall-return observations, correlate entry and exit by task birth
identity, thread and in-flight invocation. Record signed raw return and errno.
Exec success needs special handling: a successful exec replaces the calling
image and is not an ordinary successful return to it. Use the confirmed kernel
exec transition and correlate its entry, including non-leader-thread exec.
At a non-leader exec, the leader's call in flight can no longer return: it is
an `entry_abandoned` gap of its classes, never paired with the exec's own
syscall exit, whether or not the exec's entry was followed.
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
restarts must not create duplicate successes, nor hide the result a restart
turns into. A kernel restart code at a syscall exit is not a result: the
observer follows the call to the kernel's decision. A re-entry is the call's
one result; `EINTR` at a signal handler's entry is its result; a thread that
ends before the decision returned nothing and did nothing, which is neither a
result nor a gap; a decision the observer cannot establish is a
`restart_unresolved` gap naming the call's classes. The ptrace observer
settles a restart code by single-stepping. A restart decided at a handler's
entry (for `ERESTARTSYS` read from the `rax`/`rip` saved in the handler's
frame, which the program can rewrite before the observer reads it or before
`rt_sigreturn` restores it) is believed only at the re-entry itself, the
thread's next entry stop at the call's own instruction. Any other entry stop
first, including a covered call made inside an `SA_RESTART` handler, is a
`restart_unresolved` gap; the thread's end first is such a gap when the frame
decided, and neither a result nor a gap when the restart code alone decided
(`ERESTARTNOINTR`). A program that rewrites the frame and then repeats the same
call from the same instruction is indistinguishable from the re-entry: the
repeated call's result is reported and the intervening `EINTR` is not. Under
strict evidence such a gap stops the attempt, for example a handler that exits
while a blocking covered call waits to restart. `openat2` requires decoding only
the supported size/flags of its argument structure; unknown or unreadable input
is unavailable metadata and, if needed for classification, a gap.

No `write`, `read`, `mmap`, `ftruncate`, `io_uring`, payload or file-content
observation is claimed; `ftruncate` is an fd-based mutation of the same class
as `write` and is named here so its absence from the set is deliberate. Async operations issued through other interfaces are outside this
set even if they cause similar effects. A field named `fs.write` always carries
its precise action, such as `opened_for_mutation`, to prevent consumers from
presenting it as a content diff.

### 11.3 Paths, arguments and identities

Relative pathname arguments are not blindly appended to a host cwd. Account
for `dirfd`, cwd/root, namespaces and native path bytes. Emit a path relative
to the workspace (`workspace_relative`) or to the attempt's scratch root
(`scratch_relative`) only when its relationship to that root is established.
Otherwise
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
boot/birth identity and namespace mapping. Every audit result carries
`fields.pid` (host thread-group id) and `fields.pid_start_ticks`, the start
time of that group's leader, read when the observer first takes the group on
(each null if unknown: the `agent` mediator writes null when `/proc` does
not say which thread group a connecting thread belongs to); with the
receipt's `boot_id` the pair names one process on
one boot. A non-leader exec keeps it, and a later process given the same
number has its own. Namespace pids are not recorded per event. PID reuse is
not forced live: on a stock host `ns_last_pid`, `clone3` `set_tid` and a
namespace `pid_max` need `CAP_SYS_ADMIN`, so the evidence is the birth on
every live result plus a unit-level test hook that simulates a recycled tid.
Nested namespaces are evidenced by `none` running the host's bubblewrap,
traced one layer down with host pids and matching births; a pid namespace
inside a contained profile is refused by the host and not claimed.

### 11.4 Loss and coverage

For `agent`, `connect` results come from the unix-peer mediator, not a ptrace
stop (`fields.observation = seccomp_user_notification`), and count under the
same classes below. A mediation-queue overflow is evidence loss for those
classes, handled exactly as tracer loss: strict stops the attempt. The mediator
records a syscall result only when the kernel accepts its notification reply.
If the reply fails, no target return is established: emit no result, record a
`mediation_response_undelivered` gap for both `net` and `fs.deny`, and apply
the same strict/best-effort loss rule. A connect whose notification a signal
withdraws before any mediation worker received it (every worker busy, and a
handler without `SA_RESTART`) returns `EINTR` and never runs. It is a named
exclusion: under `agent`, `net` and `fs.deny` count the connects the mediator
received, and such a connect is neither a result nor a gap.

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

A child's own seccomp filter can outrank the observer's trace stop. Only a
filter installed with a notification listener can let a call take effect
without that stop: when the kernel grants a child a listener, record a
`child_notification_listener` gap in every audit class with a null count and
no end. A listener request the in-flight bound cannot follow is recorded the
same way, and a `clone(CLONE_UNTRACED)` it cannot follow is an
`untraced_descendant` gap: the refused call's return is the only fact that
would say whether it did anything. A call the child's own filter refuses (errno, trap or kill) before the
observer's stop had no effect; it is a named exclusion, neither a result nor a
gap. A trace stop the observer did not request, identified by trace data that
is not the observer's, is continued (the call then runs, as under any tracer)
and is neither a result nor a loss.

Only a call the observer must follow takes an in-flight slot: a call outside
the closed set is classified at its entry and is never `inflight_exhausted`. A
tracee killed at an entry stop the observer has not resumed made no call (the
kernel skips a syscall when a fatal signal is pending after the trace event),
so it is neither a result nor a loss. A call already resumed when the kill
came, including one killed at its exit stop before its return is read, is one
`entry_abandoned` gap of its own classes.

Initial bounds: 8 MiB kernel ring, 16,384 in-flight syscall entries, 4 KiB path
snapshots, 4 MiB user-space event queue accounted in bytes (an event's size is
chosen by the child, so a count is not a bound), 64 KiB serialized event
maximum. A gap caused by a queue drop names the operation classes of the
dropped events. An argument the kernel itself rejected (`EFAULT`, or `EINVAL`
on a structure size) is recorded as unavailable on that result and is not a
coverage loss: the child cannot stop its own attempt by passing bad pointers.
Record actual values in the observer plan: `lifetime.native.details.observer_plan`
names the backend and every bound in force (null with observation off). The
ptrace observer has no kernel ring or map. Its map exhaustion is the in-flight
bound: an entry past it is not followed and is an `inflight_exhausted` gap
naming that call's classes (except the listener and untraced-clone requests
above). `queue_bytes_max` bounds everything the observer holds for its
consumer, buffered or handed over and not yet taken, except the exempt
critical facts, and is at least one 256-byte event; the plan also records
`queue_result_bytes_max` (the budget short of the 64 KiB lifecycle reserve, at
least 256; below about 64 KiB no result carrying a pathname is admitted) and
`queue_lifecycle_reserve_bytes`. Its ring loss is the user-space queue: a result
that cannot be admitted within the one-second bounded wait is dropped into a
`queue_full` gap naming the dropped results' classes. It steps a tracee to a
syscall exit only while it holds that tracee's entry, so an unmatched exit
cannot occur; one would be an `unmatched_exit` gap in every class. Its plan
records `kernel_ring_bytes: null`. Every failed reservation, map
insertion, pairing failure or oversized event increments an independent loss
counter. The [BPF ring-buffer contract](https://docs.kernel.org/bpf/ringbuf.html)
allows reservation failure; a quiet ring is not proof that no event occurred.

Read loss counters continuously and once more after tree death and drain.
A child the observer owed a status for and never reaped is loss
(`unreaped_children`); only the backend the launcher descends through, or an
orphan of the traced tree gained after the attach, can be one, never a child
the supervisor was started beside (§11.1).
Bound the affected interval conservatively from the last known healthy point
to recovery. Counts/ranges are null when exact loss cannot be established.
Coalesce repeated losses into bounded interval summaries. Exit,
untraced-child exit and observer-end facts are exempt from every queue bound;
a gap past a bound is merged into one summary per reason, delivered ahead of
the next fact. Coverage cannot
return to fully active for the entire run after a historical gap.

On loss under `strict`, stop the attempt and preserve the gap. Under
`best-effort`, continue with degraded coverage and explicit lost intervals.
Loss reporting does not depend on timing: any evidence class (the audit
classes and `proxy.net`) degraded in the observer's final account is an
`evidence_lost` error and exit 1 in either mode, even when no run event
carried it. One loss is one error: a class degraded because a lost trace sink
refused its frames is covered by that trace loss's own `evidence_lost` error.
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
owner and mode (the private-group rule of §6.2 applies to the source and its
directories), and reject special files. Initial total credential-copy budget:
16 MiB per attempt; larger inputs refuse before exec. File identity and digest
are computed from the same bytes copied. A readonly bind records source
identity; if stable content cannot be established, its digest is unavailable
rather than invented. Stable content is established only on a filesystem that
cannot change (squashfs, erofs, iso9660) and when the content did not change
while it was hashed; a read-only mount of a writable filesystem does not
qualify. Never recurse through a credential directory by default. A credential
source inside any child-writable grant refuses, compared by identity as for the
launch profile file, and a `bind_ro` source with more than one hard link
refuses, because the child could otherwise alter what it was granted
read-only.

Register vendor state before the first copy, create it mode 0700, and keep its
parent unavailable to the contained child. Generated HOME/state paths and
proxy variables are recorded by name only. The contained environment starts
empty and admits PATH, LANG, TERM, TZ, required generated paths and the explicit
launch environment. Unlisted SSH/cloud/provider environment credentials are
absent. `none` inherits the host environment except reserved Ouroboros state,
socket and token names (every `OURO_*` name); the receipt lists removed names,
never values. This is hygiene and does not protect uncontained state. A launch
profile may not bind the contained environment's own names (PATH, LANG, TERM,
TZ, TMPDIR, HOME), the proxy variables in any case, `LD_*`/`DYLD_*`, or the C
library's loader and runtime controls (for example `GLIBC_TUNABLES`,
`GCONV_PATH`, `MALLOC_*`), because they reach the trusted launcher first.

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

The wire schemas are frozen at milestone 1:

- [Event envelope](jail-v1/event.schema.json) (`ouro.event/1`).
- [Jail producer restriction](jail-v1/jail-event.schema.json) (its events are
  `ouro.event/1` events).
- [Jail receipt](jail-v1/jail-receipt.schema.json) (`ouro.jail.receipt/1`).
- [Canonical policy snapshot](jail-v1/policy-snapshot.schema.json)
  (`ouro.jail.policy-snapshot/1`) and
  [canonical byte rules](jail-v1/canonicalization.md).
- [Gate release frame](jail-v1/jail-gate.schema.json) (`ouro.jail.gate/1`) and
  [control message](jail-v1/jail-control.schema.json) (`ouro.jail.control/1`),
  §8.2.
- [Doctor report](jail-v1/jail-doctor.schema.json) (`ouro.jail.doctor/1`),
  §§3.2, 14.1.

[frozen-schemas.toml](jail-v1/frozen-schemas.toml) pins each file by SHA-256,
and `version --json` announces `"frozen": true`. The freeze covers every
identifier `version` announces: the schemas above by their files, and
`ouro.jail.policy/1`, `ouro.jail.policy-file/1` and `ouro.jail.network/1` by
the artifacts that define them (canonicalization.md and its golden fixtures,
network-rules.md, network-addresses.json and the address fixtures), with the
gate frame corpus and the semantic corpus (and the instances it changes) for
the rules no schema states. A frozen file whose bytes change is, by rule, a new
identifier: its entry is never re-blessed in place. The drift test and the
contract validator refuse any byte change under a recorded SHA-256; they cannot
refuse an edit of the recorded SHA-256 itself, which is visible in review and
which this rule forbids. No two schema files may declare one `$id`. After
freeze, a breaking semantic change needs a new schema identifier. Additive
platform details cannot change a shared field's meaning. `explain --json`,
`gc --json` and the private `jail-state.json` (`ouro.jail.state/1`) are not
wire records and are not frozen (§6.1).

Synthetic examples: one per event kind (`examples/event-*.json`, for example
[observed open](jail-v1/examples/event-open.json)), receipts for the phase and
tuple cases of §13.2 (for example
[contained completion](jail-v1/examples/receipt-tool.json),
[unprotected completion](jail-v1/examples/receipt-none.json) and
[macOS refusal](jail-v1/examples/receipt-macos-refused.json)), the
[gate frame](jail-v1/examples/gate-release.json), each control kind
(`examples/control-*.json`) and a
[Linux](jail-v1/examples/doctor-linux.json) and a
[macOS](jail-v1/examples/doctor-macos.json) doctor report. Every example uses
fixture identities except the doctor reports, which are measured output; none
of them is evidence of a conformance run. The corpora are
`fixtures/validation-cases.json` (positive and negative schema cases),
[gate-frames.json](jail-v1/fixtures/gate-frames.json) and
[semantic-cases.json](jail-v1/fixtures/semantic-cases.json). Run
`uv run docs/specs/jail-v1/validate_contract.py` from the repository root to
validate schemas, examples, the corpora, golden hashes and address fixtures.
This documentation check does not satisfy live Linux or macOS execution gates.
[Review resolutions](jail-v1/review-resolutions.md) maps the corrected findings
to their normative clauses and acceptance IDs.

The schemas state every rule JSON Schema can express, including the
per-source and per-operation event semantics of §§11.2 and 13.1. The rules it
cannot state (canonical native strings, unique ids and keys, gap interval
order, and across a stream: one attempt, `source_seq` from 1 per source with no
hole the stream does not record as a loss, receipt notes in lifecycle order, a
complete trace ending on the final receipt's note, control messages in order)
are `ouro_jail::records::semantic`, ported in `validate_contract.py` and
pinned by the shared semantic corpus. Every live test that reads a receipt,
trace or control transcript runs both. The line citations in the frozen
schemas' `$comment`s and in the semantic rules name lines of revision 18 of
this document (commit `a75225c1`), the text they were written against, and are
read against that text. From revision 19 on, a schema, test, rule or document
cites this specification by section (for example §11.4), never by line
number, so a later revision cannot move a citation silently.

### 13.1 Event envelope

An event is one UTF-8 JSON object plus newline on the trace pipe or file.
Future socket transport uses a four-byte unsigned big-endian byte length and
the same JSON payload, with the same maximum. There is one writer per trace
stream. `source_seq` starts at 1 independently for each source and never
restarts within an attempt; its numbers are consecutive except after the
stream's recorded transport loss (§13.3), because a missing number is a lost
frame. Events from different sources are not causally
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
and phase; the digest is over the receipt's RFC 8785 canonical bytes
([canonicalization](jail-v1/canonicalization.md)), so it can be recomputed from
`jail.json` alone. Avoid recursively embedding the entire event stream in a receipt.

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
Besides `lifecycle` and `coverage_gap` notes, the jail writes `limit` notes (a
limit's application: `key`, `applied`, `reason`), `lifetime` notes (a detected
loss of lifetime integrity: `integrity`, `subject`, `reason`) and `helper`
notes (an `agent` helper's end: `helper`, `transition`); the frozen producer
schema pins the shapes of the first two only.

The shared envelope `ouro.event/1` carries only source semantics that hold on
every platform: an audit result states `ok`, return value, errno and a
syscall-side completion; an exec transition is `proc.exec`'s success and a
process exit is `proc.exit`'s; a syscall success has no errno and a failure
names one; proxy results carry counters. The Linux closed set's conventions
(the signed raw return, EACCES and EPERM classified as `fs.deny`, and the errno
names of `fs.deny`) are the jail producer's, in `jail-event.schema.json`, as
§13.2 keeps Linux errno names out of portable fields.

Audit result outcome contains `ok`, `return_value`, `errno`, and completion
kind. Confirmed exec can have null return value with
`completion=exec_transition`; no fictitious return of zero is required.
Every jail wrapper fact has `completion=wrapper`. Proxy outcome instead
describes connect status, counters and duration. Sources
have distinct `fields`; consumers must not equate proxy bytes with file bytes,
or an audited loopback connect with a successful remote API request.

### 13.2 Receipt lifecycle and shape

Normal phases are `prepared`, `enforced`, `settled`. A run that ends unsettled
without a confirmed target exec stays `prepared`. A separate `refused` phase
records a proved pre-target-exec refusal; this resolves the north star's
pre-exec receipt case without labelling failed preparation as enforcement.

| Field group | Required meaning |
|---|---|
| Identity | Schema, attempt id, receipt revision starting at 1, phase, creation/update times |
| Platform | OS, architecture, kernel/build string and backend identity/version |
| Policy | Name, canonical digest, observation/evidence choices, grants and requirements; `grants` lists the explicit operator grants beyond the profile baseline (`--rw`, `--ro`, `--deny-read`, `--allow-host` and their operator-file equivalents), never the baseline itself |
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

A proved target exec failure has `outcome.kind = exec_error`, the errno name
in `outcome.cause`, and `outcome.error.code = exec_failed`, except that an
`ENOENT` for a target file that exists (its `#!` interpreter or ELF loader is
what is missing) has `outcome.error.code = exec_interpreter_missing`. A missing
executable, a missing interpreter and a permission error are therefore
distinct in machine fields: (`ENOENT`, `exec_failed`), (`ENOENT`,
`exec_interpreter_missing`) and (`EACCES`, `exec_failed`); a child exiting 125
is `exited` with code 125. `refused` is the outcome kind of every other
pre-exec refusal. Both keep the `refused` phase. `enforced` is the lifecycle phase
after target exec, including for a `none`
run; its `containment` still says none. `settled` requires verified tree death,
but can preserve unknown execution outcome if evidence was lost. If tree
death itself is unknown, retain the last nonsettled phase and update its
outcome/coverage/error as unknown. `state_cleanup` can remain pending after
settlement. Receipt revision advances on each replacement and is never
reused: a number is spent once a replacement carrying it may be visible (from
the canonical rename on) or once it is handed to the persistence worker, so a
later failure skips a number. Revisions
increase strictly but need not be contiguous.

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

In a refusal before boundary creation every `applied` field is unapplied and
`applied.network.mode` is `pending`; a `none` receipt is the one exception,
where the mode is `host` by definition (the schema binds `containment: none`
to it) and describes the profile, not an application. Wall deadlines report the clock they use as their
mechanism (`monotonic-deadline` or `boottime-deadline`); the §6.4 suspend
semantics are a J2 requirement (L04) and a receipt never claims them by name
when the implementation uses the plain monotonic clock.

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

External writes are nonblocking with a 4 MiB queue, of which 256 KiB is
reserved for the final gap and receipt notes, and a 1-second no-progress
deadline. Broken pipe, partial-record write followed by failure, queue overflow
or deadline expiry is evidence loss. The writer preserves unwritten offsets;
it never retries a whole partially written JSON frame as a second event.
Strict mode stops the tree; best-effort can continue with the sink marked lost.
The terminal receipt's note is reserve priority whatever its phase. Once a
trace loss is known, every later receipt records it: the wrapper source is
degraded, with one `trace_transport_loss` gap on each covered evidence class
(the audit classes and `proxy.net`), extended on later receipts rather than
repeated; `limits` keeps what the platform reported, since its count comes from
the cgroup counters, not the trace. The loss note names the evidence classes
the attempt covers (the audit classes with observation on, `proxy.net` with a
proxy), and every later receipt records the loss with the note's start and
source on each class the note names.
After any evidence loss a sink keeps a prefix: it refuses and counts ordinary
events and accepts only reserve notes (the gap and receipt notes, and at most
one helper note per `agent` helper, whose end can explain a stop). An
external frame already partly written when the terminal drain gives up ends
the stream: nothing is written after its torn bytes, so the consumer sees a
visibly incomplete last line, never a corrupt one. A reserve note that the
terminal drain cannot deliver also ends the stream: nothing is written after
it, so a consumer never sees a later note after a lost one. The first loss writes one wrapper
`coverage_gap` note (`trace_transport_loss`) with reserve priority, starting
from the last point every accepted frame had been delivered. A local write that
fails part-way is truncated back to the last frame boundary; if that fails,
nothing more is written. A consumer that has already exceeded its deadline gets
no second one at settlement.

A corrupted/truncated last frame must be recognizable at readback. A trace
whose last line is not one complete JSON object ending in LF is visibly
incomplete; a line before the last that is not one is corrupt, which no
conforming writer produces. A trace is complete only if its last frame is the
`jail.receipt` note of the attempt's final receipt.

Control uses a separate bounded queue with reserved terminal-message capacity;
trace backpressure cannot delay a stop. Control is polled on every loop
iteration and gets a final drain bounded by the 1-second no-progress deadline;
every message not fully delivered, a partial frame included, is counted as
dropped. Every durable write after the lease runs on one persistence worker
with a 5-second no-progress budget: a write is stalled when the worker
completes no I/O step for 5 s while it is outstanding. Receipts written while
the target runs are persisted while the loop keeps enforcing deadlines,
signals and evidence; their control message follows durability, in order. On
failure or stall, stop the child with cause `state_write_failed`, keep the
transition unacknowledged, leave the receipt at its last persisted phase, and
start no further step of abandoned work: a replacement given up on during one
step never performs the next, and its temporary file is removed; the step
already in the kernel may still complete, which is why the lease stays held
(§7). Do not wait forever for a writer while
descendants continue running. No disk spool, replay daemon or
external custody service is added to jail v1.

## 14. Doctor and recovery

### 14.1 Doctor

`doctor` executes short, isolated probes, never the user's command. Each probe
has a 5-second deadline and owned temporary resources. Report kernel/OS build,
architecture, binary hashes/versions, operator identity category, relevant
permissions and each result with safe remediation guidance. Aggregate result
is ready only for the selected requirements; execution unsupported is a
normal structured result on macOS, with nonzero readiness exit status.
`doctor --json` is the host manifest `ouro.jail.doctor/1` (§3.2). The binary
hashes are this binary's running image and the bubblewrap a run would execute.

The operator identity category is, first match: `unknown` (credentials
unreadable), `user_namespace` (not the initial user namespace: the uids and
capabilities are namespace-local), `root` (effective uid 0), `set_id` (real,
effective and saved uids or gids differ, including a saved set-uid 0),
`capable` (permitted, effective or ambient capabilities), `privileged_group`
(a member of root, sudo, admin, wheel, docker, lxd, incus-admin, libvirt or
disk), else `unprivileged`. The reference host's `ouro-ci` is `unprivileged`.

Required Linux probes:

- `supervisor_scope`: what §9.3's supervisor scope step did for this
  `doctor`, run before every probe: `available` with `already_delegated` or
  `entered`, `unavailable` with the step's reason code otherwise (including
  `no_linger`). `doctor --json` also carries the full record under
  `supervisor_scope`. The cgroup probes measure from where the step left the
  process. The row is not a requirement and does not change readiness.
- Actual user/PID/network namespace creation, readonly/writable mounts and
  denial of the representative protected access.
- Filter loading, an allowed operation and a rejected representative syscall.
- Delegated cgroup creation, target placement, required controllers, force kill
  and empty verification using a tiny owned fixture.
- Observer attachment to a blocked launcher and a matched fixture operation,
  plus unavailable/loss accounting; attaching without following a real call
  is insufficient.
- Proxy/bridge connectivity, allowed and denied destinations, and direct-egress
  rejection for `agent`.
- Scripted nested sandbox setup (Landlock and seccomp; nested user namespaces
  where the host permits them) and attempted outer-boundary reversal for
  `agent`. An unavailable nested user namespace is reported, not a failure of
  `agent`.
- Host AppArmor restrictions when detectable. If effective permission cannot
  be read, the execution probe remains authoritative and the explanation says
  policy details unavailable.
- Launch profile credential existence/type/permissions without printing values
  or user-specific paths, and the profile's status: the binary reports every
  launch profile `experimental`; a tested combination is recorded as
  supported in [agent compatibility](jail-v1/agent-compatibility.md), not in
  the binary (§15 A01).
- For `agent`, measured by one real run: `seccomp_user_notification`,
  `agent_proxy_bridge` (an allowed and a denied destination, direct egress
  refused), `agent_unix_peer_mediation` (a host socket denied, an attempt
  socket allowed) and `agent_inner_sandbox` (a Landlock and seccomp inner
  sandbox restricts its child; `nested_user_namespace` reported as measured).

`doctor` does not edit user namespaces policy, install dependencies, enable
lingering, alter TCC, change capabilities, start a permanent service (the
transient scope of §9.3 ends with the `doctor` process) or prompt for provider
sign-in. `explain` shows these as unmeasured requirements.

### 14.2 GC and crash handling

`gc --dry-run` enumerates only the registered state root, takes nonblocking
locks on the existing `jail.lock` files of claimed roots only (a root with
`jail-state.json`), never creates one, and reports actions/reasons in the same
JSON shape as `gc`. A root with `jail.lock` but no claim is unclaimed: a
supervisor holds that lock between creating it and claiming, so a lock taken
there would refuse its claim; gc retains the root untouched and reports it
with exit 0. `attempts/` must be a private directory, and an entry that is a
symlink or not a directory is skipped, never followed.
Cleanup is bounded per invocation, the listing of `attempts/` included
(initially 100,000 entries, 128 open directories); a listing the bound ends is
reported incomplete and gc exits 1. Cleanup is resumable; `gc` prints its report even when it exits 1 because a cleanup
stays pending. It removes a dead attempt's proxy directory only through the
socket identity recorded at bind, and reports it in a `proxy_dir` field.
It never discovers deletion targets by searching all of `/tmp`, HOME or cgroupfs.
Active locks, unverifiable identities or foreign-platform resources are retained.
An attempt root without a lock has no lease to take: `gc` retains it untouched
and reports it, so a reserved root stays claimable and a dry run changes
nothing on disk.

For a dead supervisor, revalidate boot/process identity and every registered
resource. The recorded owner is dead when its boot is not the current boot, or
its pid names no process, a process with another birth time, or a zombie
whose thread group has no other thread (a zombie leader with a live thread is
alive: the thread may still be completing a write); an
owner alive with the same boot, pid and birth time is retained whole even
without the lease, and an owner whose liveness cannot be read keeps its
cgroup. In the same boot, a populated, positively identified orphan execution
cgroup may be killed by this explicit GC invocation, as permitted by the north
star. Positive identification: the registration names a direct child of the
operator's delegated subtree with this attempt's execution-leaf name
(`ouro-<attempt id>.leaf`), on cgroup v2, with the recorded device and inode,
and every control file is opened relative to that pinned directory; a
registration naming another attempt's leaf or no execution leaf, by identity or
by name only, is retained, reported and never probed. A leaf is killed only
when the supervisor did not verify the tree's end. gc records
`gc_terminating_orphan` before `cgroup.kill`, verifies emptiness within §9.3's
5-second budget, records `gc_terminated_orphan`, records `gc_removing_cgroup`
(the leaf seen empty) before its `rmdir` and `gc_removed_cgroup` after, then
removes managed scratch (`gc_removed_scratch`). A registered leaf absent after
an earlier `gc_terminated_orphan` or `gc_removing_cgroup` for it verifies the
tree's end. Its reconciliation records go to jail state (`gc_actions`) and its
report, never to the supervisor's receipt; a record gc repeats is kept once with
`count` and `last_at`. Finishing a pending vendor-state cleanup completes the
receipt's `state_cleanup` only when that receipt itself permits the cleanup
(refused, or settled with a verified tree), as J3 specified; permitted only by
gc's own verification, jail state and gc's report record it and the receipt is
left as written. gc reads the leaf from jail state, where the
supervisor registers it by name before creating it and by device and inode
right after, before anything is placed in it; a receipt naming another leaf is
a disagreement and is retained. A leaf registered by name only is removed when
empty, identified by its name and place only, and never killed. gc's records
go to `gc_actions` (persistence site P14). The bound includes each leased
attempt root's listing and the vendor-state resumption. When a pass leaves
nothing for a later one (owner established dead, cgroup settled, no managed
scratch, temporary file, proxy directory or pending vendor state, nothing
failed), gc records `gc_finished`, and later passes spend only the attempt's
name on it. Pending vendor-state
cleanup is permitted by a receipt proving tree death or by gc's own
`gc_terminated_orphan` or `gc_removed_cgroup` record of the registered leaf;
lost integrity refuses. gc removes a crash's temporary files of the root
records (`.<jail-state.json|policy.json|jail.json>.<id>.tmp`) only under the
lease of an attempt whose owner it established dead, and reports them in
`leftover_temp_files`. A cgroup recorded in another boot is never
probed or touched. Records that disagree about the boot, lost integrity, and a
replaced, absent or unverifiable leaf are retained and reported; lost integrity
retains the leaf and managed scratch in every boot. A corrupt
state file or receipt is §6.4's failed state access (exit 1).
After host reboot, the old processes cannot be alive, but any reused cgroup
path must not be treated as the original resource. Never signal from a stale
PID or delete a directory solely because its name looks like an attempt id.

GC may finish interrupted vendor-state/placeholder cleanup and remove an empty
owned cgroup. The supervisor removes default managed scratch at settlement,
after verified tree death, and records the result in `state_cleanup`; when
tree death is unverified the scratch is retained and GC may remove it later.
Operator-supplied `--scratch` and workspace directories are never deleted. The
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
| S03 | A Landlock and seccomp inner sandbox starts inside `agent` on a stock host and restricts its child; where the host permits nested user namespaces, a namespace inner sandbox does too, and where it does not, the failure is visible and the receipt records the capability as unavailable. Attempts to undo each outer boundary fail. |
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
| L02 | Kill every lifetime link (backend, watcher, supervisor): contained descendants die within a bound; an `agent` network helper's death fails closed as §10 specifies (the bridge's is recorded and the tree continues; the proxy's is `proxy.net` evidence loss); none preserves its specified unknown case. |
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

An `A01` record in [agent compatibility](jail-v1/agent-compatibility.md) marks
only the tested profile, vendor version, platform and mode supported. The
support claim lives in that record: the binary reports every launch profile
`experimental` (§14.1). Missing binary or credentials is skipped, never passed.
It does not block scripted milestone-1 conformance, and the other profiles stay
experimental. At milestone 1, A01 is OpenCode under `agent` without a
credential, re-run at the milestone revision. Linux conformance does
not imply macOS execution support; a native macOS suite will be required later.

I01's "ledger and fleet absent from PATH" is the suite's PATH, which the
conformance driver sets to the system directories and records; "no BEAM
installed" means no BEAM entry point on that PATH, no installation directory
under the usual prefixes and no distribution package.

## 16. Implementation order and exit criteria

Each step must leave a buildable tree and a concrete test result. No ledger or
fleet scaffolding is needed to complete these steps.

| Step | Deliverable | Exit criterion |
|---|---|---|
| J0: feasibility | Provision the reference host and record its manifest; measure the observer privilege model first (§5.2); then pin and evaluate the enforcement candidates (§5.1) with the fixture harness and lifecycle integration; fill [backend-evaluation.md](jail-v1/backend-evaluation.md). | §5 report has measured evidence and one chosen viable path or a named blocker. No fabricated backend selection. A blocked observer is a valid exit; it does not license `--observe off` as J1's acceptance run. |
| J1: first execution | Cargo workspace; portable policy/records; Linux tool supervisor, observation, wall and receipts; macOS refusal implementation. | §1.1 runs end to end, with P01–P04, X01–X07, M01–M03, I03 and its relevant F/O/L/R tests. This is the first product implementation slice. P04's "credential special files refuse" sub-clause is scoped to J3, where credential staging exists; J1 refuses every credential-bearing launch profile fail-closed, so the sub-clause has no code path yet. |
| J2: authority | Complete mounts/protected paths, filter families, native ABI checks, limits, gate faults and doctor probes. | F01–F04, S01–S02, S04, X02–X06, L01–L05 pass on the named Linux lane. |
| J3: agent execution | Proxy, agent profile with unprivileged nesting, data-only launch profiles, credential modes/cleanup and explicit none, all on a stock host. | S03, N01–N05, C01–C02 and R05–R06 pass. Profiles remain experimental. |
| J4: evidence/recovery | Complete closed set, loss handling, bounded trace, atomic records and GC. | O01–O06, R01–R06 and C03 pass, including failure injection. |
| J5: milestone proof | Full independent suite, performance report, platform compilation, docs and schema freeze. | All noncredential gates pass, as computed from the suite's own output: the conformance driver evaluates [acceptance-map.toml](jail-v1/acceptance-map.toml) (`ouro.jail.acceptance-map/1`: every §15 row split into its clauses, each with the tests or driver checks that assert it and how) over the run's `test.log`, and the macOS leg evaluates the map's macOS clauses over its own log; a clause the stock reference host cannot produce is recorded by name (`recorded-limit`), never mapped to a weaker test. A01 is either recorded or explicitly skipped; no Linux mechanism leaks into portable requirements; `cargo xtask freeze --check` passes. The milestone report is [J5 authority](jail-v1/j5-authority.md). |

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
the conformance job fail. The job also fails when the contract validator fails
at the same revision, when the I01 probe finds a ledger, fleet or BEAM binary
on the suite's PATH (which is the system directories only) or a BEAM
installation on the host, when the plain-session smoke leg (a `tool` run, a
`none` run and `doctor`, started from the SSH session without `systemd-run`)
does not record that the supervisor entered a delegated scope itself, when the
build provenance `doctor` reports is not the tested revision, clean and
optimised, when any gate clause in the map fails, and when the suite's ignored
set differs from the one the map pins. The per-gate verdict is part of the
evidence (`gates.txt`, `gates.json`). `rust` also compiles
`aarch64-unknown-linux-gnu` and `x86_64-apple-darwin` without executing them
(§3.2). Generic hosted runners may run portable tests
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
The freeze is [milestone-1-freeze.toml](jail-v1/milestone-1-freeze.toml),
written by `cargo xtask freeze --doctor <run>/doctor.json` from the tree and the
milestone conformance run: the toolchain channel and `rust-version`, the
Cargo.lock SHA-256, the tool, agent, agent-namespace and mediation filter
digests and the closed-set narrowing digest with the evidence tables'
SHA-256s, the contained mount baselines and each built-in profile's resolved
baseline, the contained environment names and `PATH`, the bubblewrap
invocation each contained profile's plan renders to, each bundled launch
profile's state, credentials (source, destination, mode), `[environment]` and
`network.allow`, every crate manifest's profiles, dependency selections and
features, the frozen schemas, and the tested run (clean revision, `rustc`,
target, the `ouro-jail` and bubblewrap hashes, the bubblewrap version, and the
host). The observer is compiled into `ouro-jail`, so its build provenance is
that binary's. The tested run is recorded only for a ready, optimised x86_64
Linux run of a clean revision built from exactly the frozen tree; with the
repository present, the revision must be an ancestor of `HEAD`, its own build
inputs must be the binary's, and no other frozen input may have changed since
it. `tests/portable_freeze.rs` fails when an in-tree value drifts from the
file, whose fix is the conformance rerun and then a regenerated file;
`cargo xtask freeze --check` is the milestone gate, and fails unless the file
is exactly the tree's and records such a run.

The future `ouro` executable can call the jail library in-process for dispatch;
`ouro-jail` remains independently usable. Elixir fleet and Rust ledger integrate
only after this CLI, gate, event and receipt contract is proved. No release
installer or old-runtime migration is needed to claim the jail milestone.

## 17. Traceability and decisions still requiring evidence

| North-star requirement | This specification |
|---|---|
| D3 vendor-independent argv | §§6, 12; X01, I02 |
| D8 reuse evaluation | §5; J0; decided in [backend-evaluation.md](jail-v1/backend-evaluation.md) (revision 19) |
| D9 Linux first, D12 eventual macOS | §§3–4; M01–M03 |
| D10 jail-owned observation | §§5.2, 11, 13; O01–O06 |
| D11 accepted holes | §§2, 9.3, 12, 14; R05, C02–C03 |
| D13 managed-team composition | §§2, 6.2, 8.2, 9.1, 10, 12; I03. Identity, policy ceilings, isolated input/artifact handling and project access require the later managed MT01–MT16 gates. |
| §4.1 standalone and gated run | §§6, 8; X01–X07 |
| §§4.2–4.7 policy, mounts, nesting, network | §§6, 9–10, 12; P/F/S/N tests |
| §§4.8–4.10 evidence, limits and acceptance | §§9.3, 11, 13–16; O/L/R tests |
| §7.1 future composition | §8.2; gated fixture owner without a ledger |
| §16 freeze list | [milestone-1-freeze.toml](jail-v1/milestone-1-freeze.toml), `portable_freeze.rs`, `cargo xtask freeze --check`; `doctor --json` (`ouro.jail.doctor/1`); [frozen-schemas.toml](jail-v1/frozen-schemas.toml) |

Before J0 closes: select exact enforcement/observer integrations, privilege
provisioning and initial Linux host manifest from measured results (recorded
in revision 19: [backend-evaluation.md](jail-v1/backend-evaluation.md); no
privilege is provisioned). Before J5: finish the executable schema
constraints, verify all source-specific event semantics and freeze the wire
versions (done in J5: §13, [frozen-schemas.toml](jail-v1/frozen-schemas.toml),
the schema and semantic corpora). Before macOS execution: select native
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
  [Greywall](https://github.com/GreyhavenHQ/greywall): candidates pinned and
  run in D8, disqualified by named failures (§5.1).
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
