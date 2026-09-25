# Operating `ouro-jail`

A guide for the operator who runs `ouro-jail` on Linux, and for the owner
that drives it through the managed gate. The contract is
[jail-v1](../jail-v1.md) (revision 19); where this guide and the
specification differ, the specification governs. The command syntax below
was checked against the built binary's `--help` and its macOS output; the
Linux behaviour is taken from the specification and the conformance tests
(the last section says which is which).

`ouro-jail` runs a command you name under an explicit policy, owns its process
tree, observes a documented set of operations, and writes a receipt that says
what was applied, what happened and what is unknown. It is not an agent and
talks to no model. The profiles are `agent`, `tool`, `build` and the
uncontained `none`.

## Install

Supported for execution: Linux on x86_64, on a host that runs its own kernel
(a virtual machine is fine; a container that cannot create user namespaces or
delegate a cgroup v2 subtree is not). The reference host is Ubuntu 26.04.1 on
kernel 7.0. macOS builds support inspection (`version`, `explain`, `doctor`)
and refuse execution with exit 125. A Linux build for another architecture
compiles and refuses before preparation with 125
(`unsupported_architecture`), because every syscall table in v1 is x86_64's.

Build the binary from the workspace with the pinned toolchain
(`rust-toolchain.toml`):

```sh
cargo build --release -p ouro-jail
install -m 0755 target/release/ouro-jail ~/.local/bin/ouro-jail   # any directory on your PATH
```

Install bubblewrap from your distribution (the reference host has 0.11.1 at
`/usr/bin/bwrap`). `ouro-jail` uses the bubblewrap your `PATH` provides,
resolved once per process: the first **absolute** `PATH` entry holding an
executable file named `bwrap`, canonicalized. Empty and relative entries
(`::`, `.`, `bin`) are never searched, and an unset `PATH` provides no backend;
there is no built-in fallback path. With no backend, `doctor` is not ready and
a contained `run` refuses with 125 before exec. `doctor --json` records the
path, SHA-256 and version of the bubblewrap it resolved.

No host configuration. `ouro-jail` needs no sysctl, AppArmor profile, file
capability, setuid helper or sudo, and it changes none of them. On Ubuntu 24.04
and later the distribution's own `bwrap-userns-restrict` profile allows the
one bubblewrap layer every contained profile uses; it denies a user namespace
nested inside it, which `doctor` reports as `nested_user_namespace:
unavailable`. That is normal on a stock host and does not make `agent`
unready. Effective UID 0 and a set-uid supervisor refuse.

### Lingering and the scope step

The execution leaf, a cgroup v2 directory the supervisor creates for each
attempt, is what gives an attempt its pids, memory and CPU ceilings, its
whole-tree kill and the protection against supervisor death during
bubblewrap's startup. It lives in the cgroup subtree systemd delegates to your
user manager (`user@<uid>.service`).

On Linux, `run` and `doctor` first check whether the supervisor is inside that
subtree. From a plain login shell it is not; the supervisor then asks your
user manager for a transient scope around itself (through `busctl`, never
re-executing itself) and waits up to 2 seconds to see itself inside it. It
does this only where your account **lingers**, because a process in the user
manager's scope is stopped with the user manager when your last session ends
unless you linger. Receipts and `doctor` record what the step did
(`supervisor_scope`: `already_delegated`, `entered` or `unavailable` with a
reason code such as `no_linger`). The step never fails a run.

Enable lingering once for the account that runs the jail:

```sh
loginctl enable-linger "$USER"
```

This is a per-user logind setting, not host configuration; whether an account
may set it for itself is the host's logind policy. `doctor` reports it
(`host.linger`).

Without lingering, from a plain session, the attempt has no execution leaf:

- `none`, and any explicit `--limit pids=…`, `mem=…` or `cpu=…`, refuse with
  125 (they require an execution boundary);
- the preferred pids ceiling of `agent`, `tool` and `build` is recorded as not
  applied, with a wrapper note;
- a supervisor killed during bubblewrap's startup can leave the namespace
  init, and under `agent` its bridge, alive and holding the run's stdout.

Running inside a delegated scope yourself avoids all three, lingering or not,
but without lingering the scope ends, with the run, when your last session
does:

```sh
systemd-run --user --scope --quiet ouro-jail run -- make test
```

## Commands

```text
ouro-jail run [--profile agent|tool|build|none|FILE] [--launch NAME]
  [--workspace PATH] [--scratch PATH] [--rw PATH]... [--ro PATH]...
  [--deny-read PATH]... [--allow-host HOST[:PORT]]... [--limit KEY=VALUE]...
  [--observe on|off] [--evidence strict|best-effort]
  [--receipt PATH] [--trace-fd N] [--control-fd N] [--gate-fd N]
  [--attempt-id ID] [--label-only] [-- PROGRAM [ARG]...]
ouro-jail explain [--profile …] [--launch NAME] [the run overrides] [--json]
ouro-jail doctor [--profile NAME|FILE] [--launch NAME] [--json]
ouro-jail gc [--dry-run] [--json]
ouro-jail version [--json]
```

- **`run`** prepares the boundary, attaches the observer, writes a prepared
  receipt, releases the command, waits for it, ends and verifies its whole
  tree, and writes the settled receipt. `PROGRAM` and its arguments are passed
  as literal bytes, never through a shell; if you want a shell, name it
  (`-- /bin/sh -c '…'`). The program is resolved with the child's `PATH`
  (under a contained profile, `/usr/local/bin:/usr/bin:/bin`) and must be
  visible under the policy, with its interpreter and libraries. Defaults:
  profile `tool` (or the launch profile's), the invocation directory as
  workspace, a private scratch directory, observation on, strict evidence. The child's stdin, stdout and
  stderr are passed through untouched; `run` has no JSON mode. When stderr is
  a terminal, `run` ends by printing `ouro-jail: receipt <path>`.
- **`run --label-only`** resolves and probes, prints the proposed label and
  one `capability …` line per requirement, and executes nothing. It refuses
  `--gate-fd` and `--attempt-id` (exit 2).
- **`explain`** resolves the policy and prints it, with every requirement
  marked unmeasured; it probes and executes nothing. `--json` gives the policy
  snapshot, its digest (`policy.digest`) and the requirement names.
- **`doctor`** runs short, isolated probes for the requirements of the
  selected profile (and every other row it knows), never your command; see
  [doctor](#doctor).
- **`gc`** reconciles attempts whose supervisor is gone; see [gc](#gc).
- **`version`** prints the version, the schema identifiers this build writes,
  `"frozen": true`, the closed set it can observe (null where it cannot) and
  the build provenance: revision and dirty flag as the build environment
  claimed them (null when unknown), and the compiler, target, optimisation
  level and a digest of the build inputs as measured at compile time.

### Exit codes

| Command | Code | Meaning |
|---|---|---|
| `run` | the child's code | the command ran and exited |
| `run` | 128 + signal | the command was ended by a signal |
| `run` | 125 | refused before the command executed (a failed exec of the command included) |
| `run` | 1 | a tool failure after the command started (lost evidence, an unverified tree, a failed state write, `exec_unconfirmed`); the receipt keeps the child's own outcome |
| any | 2 | invalid command line or configuration |
| `explain`, `doctor`, `gc`, `version`, `run --label-only` | 0 | success |
| `explain`, `doctor`, `gc`, `version`, `run --label-only` | 1 | an operational failure (for `gc`: a failed cleanup or state access, or a cleanup that stays pending) |
| `doctor`, `run --label-only` | 125 | the requested plan is unsupported or unavailable on this host (always on macOS) |

A child that itself exits 125 is recorded as `exited` with code 125, not as a
refusal; the receipt tells them apart. JSON output never changes an exit code.

### Errors

An error has a stable code, a stage (the lifecycle state it happened in), a
safe message, an optional configuration key and a remediation category
(`configuration`, `host_setup`, `unsupported`, `retry`, `inspect_state`). On
stderr it reads, for example:

```text
ouro-jail: error invalid_config at resolving [configuration]: the `build` profile requires an explicit memory ceiling (key: limits.mem)
```

The codes: `invalid_config`, `policy_widening`, `unsafe_state_path`,
`unsupported_platform`, `missing_capability`, `backend_unavailable`,
`observer_unavailable`, `nesting_failed`, `credential_unavailable`,
`invalid_fd`, `gate_invalid`, `gate_closed`, `prepare_timeout`,
`attempt_exists`, `exec_failed`, `exec_interpreter_missing`, `evidence_lost`,
`exec_unconfirmed`, `tree_unknown`, `state_write_failed` and `internal_error`.
Two need explaining:

- **`exec_interpreter_missing`**: the program exists but its `#!` interpreter
  or ELF loader does not (the kernel answers `ENOENT` for both this and a
  missing program; `exec_failed` is the missing program). Make the
  interpreter visible, for example with `--ro`.
- **`exec_unconfirmed`**: with `--observe off`, a command that ends before the
  supervisor sees its new image cannot have its exec confirmed, so its outcome
  is `unknown` and the jail exits 1. On the reference host `/usr/bin/true`
  under `tool` or `agent` always ends this way. The command did run if its own
  output says so; `--observe on` confirms the exec.

## Profiles

| Profile | Filesystem | Network | Default limits | Needs an execution boundary |
|---|---|---|---|---|
| `tool` | workspace and scratch writable, system roots read-only, existing `.git` and `.ouroboros` segments beneath writable roots protected (`existing_and_root`) | none | wall 30m (required), pids 256 (preferred) | only for explicit pids, mem or cpu |
| `build` | the workspace's declared inputs read-only, scratch writable | none | wall 1h, pids 512 (preferred), an explicit `mem` is required | yes, for the memory ceiling |
| `agent` | workspace, scratch and vendor state writable, system roots read-only | only through an outside HTTP proxy, allowed hosts from the launch profile and `--allow-host` | wall 2h, pids 512 (preferred) | only for explicit pids, mem or cpu |
| `none` | the host's view, unchanged | the host's | wall 2h | always (observation on or off) |

Every contained profile runs in one bubblewrap layer with its own user, mount,
PID, network, IPC and UTS namespaces, a closed filesystem view built from the
declared roots, a seccomp filter, `no_new_privs` and no capabilities. The
contained environment starts empty and admits `PATH`, `LANG`, `TERM`, `TZ`,
generated paths (`TMPDIR` in scratch, `HOME` where a launch profile maps it)
and the launch profile's environment. `agent` additionally permits the
unprivileged sandboxing an inner vendor sandbox uses (Landlock and seccomp),
mediates Unix-socket `connect` so host sockets are unreachable while the
attempt's own IPC works, and reaches the network only through the proxy
(proxy variables point at a bridge on `127.0.0.1:3128`).

`none` applies no containment: it closes the jail's private descriptors,
removes every `OURO_*` variable, enforces the wall and tracks the tree through
its execution leaf. Its receipts always say `child_protection: unprotected`,
however clean the run.

`--profile FILE` selects an operator profile file that `extends` one built-in
contained profile and may only narrow or add finite limits. A project's
`ouro.toml` at the workspace root can only narrow: it may not select a
profile, add a grant, raise or remove a limit, weaken coverage or evidence,
add credentials or select `none`; each refuses before anything is prepared,
naming the key (`policy_widening`, or `invalid_config` for a key a project
file cannot have). Only `--profile none` selects `none`.

Configuration: `~/.config/ouro/config.toml` (`[jail]`, `[jail.limits]`;
`jail.profile` may name a built-in or an operator profile file), launch
profiles in `~/.config/ouro/launch/<name>.toml`, runtime state in
`~/.local/share/ouro`. `OURO_CONFIG_DIR` and `OURO_DATA_DIR` move them;
`OURO_JAIL_OBSERVE` and `OURO_JAIL_EVIDENCE` set the two modes. No other
environment variable changes policy. Runtime state must be a private local
directory: mode 0700, owned by you, not a symlink, and outside every grant you
give the child.

Limits (`--limit`): `wall` (`ms`, `s`, `m`, `h`), `pids`, `mem` (bytes,
`KiB`, `MiB`, `GiB`) and `cpu` (percent of one core, as a bandwidth ceiling).
Every explicit limit is required: if it cannot be enforced, the run refuses.

## Launch profiles and credentials

A launch profile is operator data for one vendor agent: environment mappings
into vendor state, credential inputs, allowed hosts and a default contained
profile (`jail`). It never supplies argv and cannot select `none`. It lives at
`<config-dir>/launch/<name>.toml`, mode 0600, outside every child-writable
grant. The bundled `codex`, `claude` and `opencode` files under
`crates/ouro-jail/profiles/launch/` are experimental examples that the binary
never reads; copy one and check every path and host against your own
installation. `doctor --launch NAME` checks its credential inputs without
printing values.

`doctor` reports every launch profile `experimental`. Which vendor versions
were run and passed under which profile, platform and mode is recorded in
[agent compatibility](agent-compatibility.md), not in the binary.

Credentials (`[credentials.<id>]`, with `source`, `dest` and `mode`) are
staged into the attempt's private vendor state, which the child sees at
`/run/ouro/state`:

- `copy_rw` copies the file at launch; refreshed tokens are never written back.
- `bind_ro` shows the exact source file read-only; it may prevent the vendor
  from refreshing it. A source with more than one hard link refuses.
- Sources are regular files you own with private permissions, outside every
  child-writable grant; special files refuse; the total copy budget is 16 MiB
  per attempt.
- The receipt lists each staged input as its id, mode and a content digest
  (or, for a `bind_ro` source whose content cannot be pinned, why not); never
  its path or bytes.
- Vendor state is removed after the tree is verified dead (`state_cleanup`
  becomes `complete`); an interrupted cleanup stays `pending` and `gc`
  resumes it. Removal unlinks files; it does not erase disk blocks or copies
  made elsewhere.

## doctor

`doctor` runs short probes (5 seconds each, with owned temporary resources):
namespace creation, read-only and writable mounts and a protected-path
denial, filter loading, cgroup creation, placement, kill and empty
verification, observer attachment with a matched operation, and for `agent`
one real run through the proxy, the Unix-peer mediation and an inner sandbox.
It is ready only if the selected profile's requirements are met; otherwise it
exits 125, and each row says why with a reason code. It never edits host
policy, installs anything, enables lingering or starts a lasting service.

`doctor --json` is the host manifest, the versioned record `ouro.jail.doctor/1`
([schema](jail-doctor.schema.json), [example](examples/doctor-linux.json)):

- `capabilities` and `requirements`: each probe's status, scope, mechanism and
  reason code, and `ready`;
- `supervisor_scope`: what the scope step did;
- `host`: kernel release and build, distribution, virtualization, CPUs, memory
  and swap, systemd version, the sysctls that restrict user namespaces, BPF,
  perf, ptrace and io_uring, AppArmor's user-namespace restriction and the
  profile files involved, cgroup delegation as your session sees it,
  lingering, your identity category (`unprivileged` is the one the product is
  built for; `root`, `set_id`, `capable`, `privileged_group`, `user_namespace`
  or `unknown` otherwise) and the privileged groups you belong to;
- `binaries`: this binary's path and SHA-256, and the bubblewrap it resolved
  (path, SHA-256, version) or null;
- `build`: as in `version`.

An unreadable fact is null. `doctor` killed with SIGKILL leaves its probes'
directories in the system temporary directory; remove them by hand.

## gc

`gc` walks only the registered state root, `<data>/attempts/`. For an attempt
whose supervisor is established dead (another boot, or its recorded process
identity gone), it may kill a positively identified orphan execution leaf in
the same boot, verify it empty and remove it, remove managed scratch and a
crash's temporary files, and finish a pending vendor-state cleanup. It
retains, and reports with a reason, anything live, unidentifiable, foreign,
from another boot, with lost integrity, or with records that disagree. It
never signals a process by a stale PID and never searches `/tmp`, your home or
the cgroup tree. `gc --dry-run` reports the same actions and changes nothing.
Receipts, policy and traces are retained; retention is yours to manage.

`gc --json` is an unversioned diagnostic: one entry per attempt with its
`action`, `reason`, `owner`, `execution_boundary`, `scratch`, `proxy_dir`,
temporary files and the records gc wrote, plus its per-invocation budget.
`gc` exits 0 after a completed scan (skips included) and 1 when a cleanup
failed or stays pending, or state could not be read.

## The managed gate, for owners

A launch owner (a program that authorizes each attempt before it runs) starts
`run` with two inherited pipe ends (jail-v1 §8.2): the read end of a private
gate pipe, and the write end of a control pipe it reads (`--trace-fd` may add
an event stream the same way). Each descriptor must be open, in the right
direction, distinct from the others and from stdio, and owned by this
invocation alone.

```text
ouro-jail run --attempt-id att_<uuid> --gate-fd 3 --control-fd 4 \
  [--receipt PATH] [policy flags] -- PROGRAM [ARG]...
```

1. Allocate the attempt id: `att_` plus a lowercase, random UUIDv4 with the
   RFC 9562 variant. `--attempt-id` is accepted only with `--gate-fd`.
2. Compute your plan from your own inputs, never from the jail's output: the
   policy digest and requirement names from `ouro-jail explain --json` with the
   same profile, workspace and overrides you pass to `run`
   (`policy.digest`, `requirements[].name`), and the argv digest from the argv
   you asked for, framed as [canonicalization.md](canonicalization.md)
   specifies.
3. Read the control stream: NDJSON `ouro.jail.control/1` messages numbered from
   1 (`seq`), each naming the receipt phase and its digest. Wait for
   `prepared`. Nothing of the command has run.
4. Read the prepared receipt (`<data>/attempts/<id>/jail.json`, or your
   `--receipt` copy) and check that its SHA-256 over RFC 8785 canonical bytes
   equals the control message's `receipt_digest`. Compare its `attempt_id`,
   `policy.digest`, `argv_digest` and `policy.requirements` with your plan.
5. On a match, release: write exactly one line and close the gate:

   ```json
   {"schema":"ouro.jail.gate/1","action":"release","attempt_id":"att_…","policy_digest":"sha256:…"}
   ```

   followed by one LF, at most 1,024 bytes including it. CRLF, a second line,
   trailing bytes, duplicate keys, a wrong attempt id or digest, or an empty
   EOF refuse (`gate_invalid`, `gate_closed`).
6. On any mismatch, close the gate without writing: the attempt refuses with
   `gate_closed`, and the command never runs. A gate held open without a frame
   expires 60 seconds after `prepared` (`prepare_timeout`); preparation itself
   has a 30-second budget.
7. Follow the stream to its terminal message: `exec_confirmed`, then `settled`
   or `unsettled` (tree death not verified); `refused` only while the command
   has not executed, including a failed exec. A control message acknowledges
   only a receipt that is durable.

The gate is trusted process authority: keep its write end private. A second
release never starts a second command. If you die before release, the command
never runs; if you die during release, it runs at most once. The supervisor
records its direct parent's identity and arms a parent-death signal, so under
the contained profiles the death of that parent takes the supervisor and the
tree with it, while under `none` it leaves the accepted unknown case. A
timed-out attempt is not retried by reusing its gate; reconcile it (`gc`) and
start a new attempt. Matching digests prove the snapshot's identity, not that
its permissions were authorized: authorization is yours.

## Reading a receipt

The canonical receipt is `<data>/attempts/<attempt-id>/jail.json`, replaced
atomically at each phase (`--receipt PATH` adds a copy). It is
`ouro.jail.receipt/1` ([schema](jail-receipt.schema.json),
[example](examples/receipt-tool.json)). Read, in this order:

- **`phase`**: `prepared` (the boundary exists; `exec_observed` false),
  `enforced` (the command's exec was confirmed), `settled` (the tree was
  verified dead), or `refused` (nothing of the command ran, or its exec
  failed). An attempt whose tree death could not be verified keeps its last
  phase with `tree_unknown` in `errors`; it is not settled.
- **`containment` and `child_protection`**: `enforced` for a contained profile
  once the boundary is established; `none` and `unprotected` for every `none`
  receipt. Protection is independent of observation.
- **`outcome`**: `kind` (`exited`, `signaled`, `exec_error`, `refused`,
  `unknown`, `pending`), `code`, `signal`, `cause` (the first stop reason the
  supervisor acted on, such as `wall_expiry`, `operator_signal` or
  `evidence_loss`; for `exec_error`, the errno name) and `error`.
- **`lifetime`**: `tree_empty` and `verified_at`, the `verification_scope`
  (`attempt_tree` for a contained run; `registered_boundary` for `none`, which
  speaks only of its identity-checked cgroup) and `integrity`
  (`lost` means detected tampering or escape: state is retained).
- **`observer` and `coverage`**: whether the observer attached and each
  source's status; per class (`exec`, `fs.write`, `fs.deny`, `net`,
  `proxy.net`, `limits`) its `status`, `observed_count` and `gaps`. `active`
  means the whole run was covered; `degraded` means an interval is missing and
  the count is null; `unsupported` means not observed (all audit classes under
  `--observe off`). A zero count is a claim only for an active class. Every
  degraded class names its gaps (reason, interval, known or null count).
- **`applied`**: the mounts, network mode, filter digest and limits actually
  applied; a limit's `hit` says whether it was reached. A preferred limit that
  could not be applied says so (`applied: false`).
- **`errors`**, **`state_cleanup`** and **`credentials`**.

The trace (`trace.ndjson` beside the receipt, or the `--trace-fd` stream) is
NDJSON `ouro.event/1` events: audit results from the observer, proxy results,
and the jail's own wrapper notes. It is complete only if its last line is the
`jail.receipt` note naming the final receipt; a last line that is not a whole
JSON object is visibly incomplete, and the receipt then records the loss. The
observed set, `linux-closed-v1`, is exec and exit, file creation, opening for
mutation, truncation by path, rename, unlink and directory-entry creation,
`connect`, and their `EACCES`/`EPERM` denials. Reads, writes, `mmap`, payloads
and read denials are not in it: the absence of an event is not the absence of
an action.

Under `--evidence strict` (the default) any loss of evidence stops the
command; under `best-effort` the command continues and the receipt marks the
lost intervals. In both, a degraded evidence class is an `evidence_lost` error
and exit 1.

## Observation cost

The observer is a ptrace tracer. Each observed call costs two kernel stops,
about 22 µs each on the reference host, and nothing in user space removes
them. The cost therefore scales with the rate of closed-set calls: it is
highest on syscall-dense file work (creating, renaming and deleting thousands
of files) and small on work that mostly computes, reads or writes. The
performance budgets apply to the jail's own overhead (`--observe off` against
direct execution); the cost of observation is measured per workload in
[backend-evaluation.md §4](backend-evaluation.md#4-performance-52-budgets).

`--observe off` removes the audit source and its cost; the receipt then
marks every audit class unsupported. It is an explicit choice, never an
automatic fallback, and a very short command under it ends with
`exec_unconfirmed`.

## Named limits

Each is a property of v1 on a stock host, with its reason. The milestone
report ([J5 authority](j5-authority.md#known-gaps)) holds the complete list
with its evidence.

- **`none` protects nothing.** Same-UID processes can tamper with its
  evidence and its cgroup, and its cleanup is not guaranteed after its
  supervisor dies. It detects a migration out of its cgroup; it does not
  promise to find every one.
- **Without lingering there is no execution leaf** (see
  [Lingering](#lingering-and-the-scope-step)).
- **End-of-file.** Under the contained profiles bubblewrap's outer process and
  namespace init hold the stdout and stderr they hand the command until the
  jail exits, and the supervisor always keeps stderr for its own diagnostics,
  so a reader sees end-of-file when the jail exits. Under `none` stdout's
  end-of-file arrives as in direct execution. Do not treat end-of-file as the
  only sign a run ended.
- **Nested user namespaces are unavailable on stock Ubuntu 24.04 and later.**
  A vendor sandbox that needs one fails visibly inside `agent`; one built on
  Landlock and seccomp works. Running a vendor with its own sandbox off gives
  its tool commands the agent's jail authority, which is your choice.
- **Listing network interfaces fails** inside the contained profiles (netlink
  is not an allowed socket family); name resolution and ordinary sockets work.
- **`clone3` returns `ENOSYS`** under observation and in `tool` and `build`;
  glibc falls back to `clone`, and a runtime that cannot fall back does not
  run there. `io_uring` is refused in every contained profile and unobserved
  under `none`.
- **Protected-path coverage under `tool` is `existing_and_root`:** `.git` and
  `.ouroboros` segments that exist at launch, plus the root-level names; a new
  deep one created during the run is not covered, and `all_descendants`
  refuses on Linux.
- **Strict evidence can stop a real program**: a signal handler that exits
  while a blocking observed call waits to restart is a gap, which stops a
  strict attempt. A program that rewrites its handler frame and repeats the
  call is indistinguishable from a restart.
- **The workspace is not a repository boundary**: shared inodes and Git
  alternates reach whatever they point to.
- **Deadlines.** The execution wall and the preparation and gate budgets run
  on `CLOCK_BOOTTIME`, so a suspend counts and a wall-clock step does not; an
  expired deadline is acted on when the machine resumes. The conformance suite
  simulates suspend and clock steps with a clock shim; a real suspend is not
  produced on the reference host.
- **A killed helper is not named.** A kill of bubblewrap's outer process or of
  the watcher while the command runs leaves a receipt identical to an
  external `SIGKILL` of the command.
- **Credentials**: a `bind_ro` digest is recorded only on an immutable
  filesystem; `copy_rw` never writes refreshed tokens back.
- **Test seams.** Every `OURO_JAIL_TEST_*` variable is a test-only knob that
  the release binary honours and records in jail state and in every receipt
  with native details. Do not set them in production; a receipt that names
  one describes a test.

## What this guide was checked against

Checked against the binary built from revision `8012bae5` on macOS
(aarch64-apple-darwin, debug build): every command's options (`--help`), the
`version` text and JSON (build provenance, `frozen`, a null closed set on
macOS), `explain` text and JSON (policy digest, requirement names, the
`build` profile's refusal without `mem`, exit 2), `doctor` refusing with 125
and `unsupported_platform` rows, `run` refusing with 125 before exec, the
error line format, `run --label-only --gate-fd` as a usage error, and the
`gc --json` entry shape.

Taken from the specification (revision 19) and the conformance tests, not run
for this guide: everything Linux executes (probes, the scope step, profiles'
boundaries, receipts, traces and control messages, the gate protocol,
bubblewrap resolution, exit codes of a real run, `gc`'s reconciliation), the
lingering behaviour and every figure quoted from the reference host.
