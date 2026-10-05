# Get started with Ouroboros Jail

Start with a small command, see what the jail recorded, then use the same
workflow for your own tools. You don't need to change agents or adopt a new
way of working: `ouro-jail` wraps the command you already run.

You choose the files it can read or change, the services it can contact, and
how long it can run. A receipt tells you which controls were applied and how
the run ended.

**You'll need a Linux x86_64 or aarch64 machine to execute commands.** This is
pre-release software, currently installed from source. On a Mac, you can
build the CLI and inspect policies; sandboxed execution is still unavailable.

Already have the binary? Jump to [your first command](#run-your-first-command).
Writing an integration? Start with [agents and scripts](#for-agents-and-scripts).

## Build and check your host

You need Git, Rust 1.98.1, and your distribution's bubblewrap package. The
reference host runs Ubuntu 26.04.1 and bubblewrap 0.11.1. Run as your normal
user; the jail does not install a backend or change host security settings.

```sh
git clone --branch dev https://github.com/monocursive/ouroboros.git
cd ouroboros
cargo +1.98.1 build --release -p ouro-jail
mkdir -p "$HOME/.local/bin"
install -m 0755 target/release/ouro-jail "$HOME/.local/bin/ouro-jail"
export PATH="$HOME/.local/bin:$PATH"

ouro-jail version
ouro-jail doctor --profile tool
```

If you already have the checkout, start at the build command. Install the
binary outside any workspace you'll make writable: the jail refuses a grant
that would let a child modify its executable.

`doctor` checks whether your host can run the selected profile. Read its
report before continuing. A required control must be available; a preferred
limit may be left unapplied and reported as such. Explicit PID, memory, swap, and
CPU limits require a delegated cgroup v2 scope. The
[host setup reference](https://github.com/monocursive/ouroboros/blob/dev/docs/specs/jail-v1/operating.md#lingering-and-the-scope-step)
explains that setup and its effect on process cleanup.

On macOS, `version` and `explain` work; `doctor` reports why execution is
unavailable. Other Linux architectures are not yet supported for execution.
Public jail packages and a Homebrew tap are still being prepared. Older
Ouroboros releases belong to the archived agent runtime.

## Run your first command

Let's write a file in a fresh directory. This example needs no network or
agent credentials.

```sh
jail_demo="$(mktemp -d "$HOME/ouro-jail-demo.XXXXXX")"
cd "$jail_demo"

ouro-jail run --profile tool --workspace "$PWD" --limit wall=30s -- \
  /bin/sh -c 'printf "hello from the jail\n" > greeting.txt'

cat greeting.txt
ouro-jail tail
```

You should see `hello from the jail` when you read the file. `tail` then shows
the journal for the most recently updated attempt. The command had a writable
workspace, no network access, and a 30-second deadline.

Everything after `--` is the program and its literal arguments. This example
names `/bin/sh` because it needs shell redirection. For an ordinary program,
pass its executable and arguments directly.

The workspace is yours after the command exits. Changes persist, so use a
disposable checkout when trying an unfamiliar tool.

## Choose a profile

A profile is a starting policy. Pick the one closest to your task, then add
only the paths and services it needs.

| Profile | Good starting point for | Default access |
| --- | --- | --- |
| `tool` | Tests and local commands | Writable workspace and scratch; no network. Existing `.git` and `.ouroboros` trees are protected from writes. |
| `agent` | Coding agents that call a provider | Writable workspace, scratch, and temporary agent state. Network destinations need explicit grants. Git metadata is writable. |
| `build` | Builds from read-only inputs | Writable scratch; add read-only inputs and writable outputs. No network. Requires an explicit memory limit and host support. |
| `none` | Deliberately uncontained execution | Host access. Filesystem and network containment are disabled. |

Contained profiles also expose system runtime files needed to execute
programs. Inspect the resolved policy before running a new command:

```sh
ouro-jail explain --profile tool --workspace "$PWD" --limit wall=30s --json
```

`explain` resolves configuration without probing the host or executing the
command. It shows what you are requesting; the receipt later records what
was actually applied.

### Add access as the task needs it

- `--ro PATH` makes a file or directory visible for reading.
- `--rw PATH` permits changes to that path.
- `--allow-host HOST:PORT` allows a proxied destination with the `agent`
  profile. Without a port, the grant means port 443.
- `--limit wall=5m` sets a deadline. Resource limits use forms such as
  `--limit mem=512MiB`, `--limit pids=64`, or `--limit cpu=100` for one core's
  worth of CPU bandwidth. Every explicit limit is required.

For tests, start with `tool`, a disposable checkout, and read-only access to
installed dependencies. For a build, keep source inputs read-only and give
the compiler a separate writable output directory. Toolchains installed in
your home directory may need explicit paths; your usual home and environment
are not automatically inherited.

### Bound RAM, swap and writable storage

RAM and swap have separate ceilings. Combine `--limit mem=512MiB` with
`--limit swap=0` to cap charged RAM and disable swap, or use a positive swap
budget such as `--limit swap=128MiB`. An omitted swap limit is not implied by
the memory limit.

`--limit storage=64MiB --limit inodes=4096` requires operator-provisioned
bounded tmpfs volumes or ext4/XFS filesystems with enforced **user hard
quotas**. Their combined capacity must fit those ceilings. The workspace,
explicit `--scratch PATH`, extra writable grants and agent state all count;
aliases of the same filesystem count once. Existing files and concurrent
users of the same budget consume capacity too. The jail does not provision
volumes or copy the workspace automatically.

For disk storage, use a dedicated non-root worker account and a filesystem
with user quota accounting and enforcement already enabled. For example,
on a prepared quota filesystem, an operator with `quota-tools` can set a
64 MiB block hard limit and 4096-inode hard limit with
`sudo setquota -u WORKER 0 65536 0 4096 /WORKER_VOLUME` (block limits are KiB).
Put both workspace and scratch there, owned by `WORKER`. Ouroboros queries
the kernel as that user before releasing the target. Soft limits alone,
disabled enforcement, foreign-owned writable files, idmapped writable mounts
and XFS realtime volumes refuse. This budget covers that uid across the filesystem, including
files outside the granted directories; it is not a per-run reservation.

For storage-bounded runs, `/dev/shm` is read-only and new hard links return
`EPERM`. The hard-link restriction prevents importing another user's inode
into the writable tree; these seccomp denials have no observer event. Existing
hard links within the admitted ownership rules remain usable. The storage ceiling covers
allocated file data; use `mem` to bound charged RAM as well. A storage
receipt's `hit=null` means saturation was not established, not that the limit
was never reached. The [limit specification](specs/jail-v1.md#64-limits-and-errors)
defines the scope and remaining backend limitations. Project quotas and
automatic volume provisioning are not implemented.

## Run an existing agent

Launch profiles supply starter file, environment, credential, and network
settings for an agent. They don't install it or choose its command line.
Fourteen profiles are embedded, including OpenCode, Codex, and Claude Code.
All remain experimental until a compatibility record covers the specific
agent version and jail build.

Here's an OpenCode example. It assumes OpenCode is already installed at
`$HOME/.opencode/bin` and you're still in the disposable directory above:

```sh
git init
ouro-jail doctor --launch opencode
ouro-jail explain --launch opencode --workspace "$PWD" \
  --ro "$HOME/.opencode/bin" --json

ouro-jail run --launch opencode --workspace "$PWD" \
  --ro "$HOME/.opencode/bin" -- \
  "$HOME/.opencode/bin/opencode" run "Create greeting.txt containing hello."
```

Review the resolved file and network grants before the run. Change the
executable path and read-only grant to match your installation. A provider
that needs authentication also needs explicit credential configuration in
your launch profile; normal login state is not exposed automatically. See the
[launch profile reference](https://github.com/monocursive/ouroboros/blob/dev/docs/specs/jail-v1/operating.md#launch-profiles-and-credentials)
for the configuration format.

OpenCode has recorded live runs. The
[compatibility table](https://github.com/monocursive/ouroboros/blob/dev/docs/specs/jail-v1/agent-compatibility.md)
names the tested versions, jail builds, and remaining gaps. Check it before
assuming a profile will work with your setup.

## Inspect a run

Each attempt saves a `jail.json` receipt, its resolved policy, and an event
journal. By default, these live under `~/.local/share/ouro/attempts/`.
`OURO_DATA_DIR` can select a different private data directory.

```sh
ouro-jail tail
ouro-jail tail --follow
ouro-jail tail --json
```

For a particular attempt, use `ouro-jail tail --attempt ID --json`, replacing
`ID` with its receipt's `attempt_id`. This matters when several commands run
at once: the default follows the most recently updated attempt.

When reading the receipt, start with these fields:

| Field | What to check |
| --- | --- |
| `phase` | `settled` means the process tree was verified dead. `refused` means execution was refused or the command could not be started. An unfinished phase needs investigation. |
| `outcome` | The child's result and the reason a run stopped. |
| `containment` and `applied` | The boundary, mounts, network mode, and limits actually applied. |
| `lifetime` | Whether the tree is empty and whether its integrity was verified. |
| `coverage` and `errors` | Which operation classes were observed and where evidence is missing. |

Observation is on by default and covers a defined set of operations. It does
not record every read or every action. Strict evidence is also the default:
loss of required evidence stops the run. A zero event count only means no
observed events when that class had active coverage.

## Learn missing permissions

If a command hits a permission error, `learn` can help identify the access it
needs. It runs the command inside containment and writes a proposal from
that run's evidence:

```sh
ouro-jail learn --launch opencode --workspace "$PWD" \
  --ro "$HOME/.opencode/bin" --out "$HOME/ouro-proposal.toml" -- \
  "$HOME/.opencode/bin/opencode" run "Run this project's tests."
```

The proposal can include exact read-only paths and denied network
destinations. Denied writes are reported without becoming write grants.
Read the proposal, check that the access fits the task, and then apply only
what you intend. `--adopt` shows the change and requires confirmation in an
interactive terminal.

Learning executes real work and can change writable files. Its proposal
covers one observed run; it is not a complete list of everything that program
might ever need. Nothing is adopted automatically.

## When something doesn't work

**The host check refuses the profile.** Read `doctor`'s missing requirements.
Explicit resource limits need host support. On macOS, refusal is the current
expected behavior. Changing to `none` would remove containment.

**The command cannot find a file, executable, or library.** Check `explain`
and the receipt. The program, its interpreter, and its dependencies must be
visible. Add the specific read-only path the task needs, then try again.

**The agent cannot connect or authenticate.** Check the launch profile's
provider hosts and credential configuration. `--allow-host` grants a
network destination; it does not supply a login or an API key.

**A short command reports `exec_unconfirmed`.** With observation off, the
command may finish before the jail independently confirms execution. Keep
the default observation mode for the first run, and inspect the receipt
before repeating work that might have side effects.

**The command returned a nonzero status.** It may be a child failure, a
refusal, or a problem with evidence or cleanup. Read the receipt alongside
the exit code. A child's own exit code can overlap the jail's codes.

## For agents and scripts

The website provides `/guide.md` and `/roadmap.md` from these exact source
documents, plus `/llms.txt` as a short discovery index. Give an agent the
Markdown guide URL directly; automatic discovery depends on the client.
Roadmap entries describe future work, not commands available in the CLI.

Use this sequence when integrating the jail:

1. Read `ouro-jail version --json` to identify the build and its schemas.
2. Run `doctor --profile NAME --json` or `doctor --launch NAME --json` and
   inspect the result. `doctor` does not accept run overrides such as
   `--workspace` or `--limit`; `run` checks the final requested policy.
3. Use `explain --json` with the same policy flags you will pass to `run`.
   Keep the requested access within the user's authorized task.
4. Run the command with an explicit `--receipt PATH`. Use a unique path
   outside every child-writable grant so concurrent runs cannot overwrite it.
5. Read that receipt even when the process exits nonzero. Use its `attempt_id`
   with `tail --attempt ID --json` for the matching journal.

For example, from the disposable workspace:

```sh
jail_records="$(mktemp -d "$HOME/ouro-jail-records.XXXXXX")"
ouro-jail version --json > "$jail_records/version.json"
ouro-jail doctor --profile tool --json > "$jail_records/doctor.json"
ouro-jail explain --profile tool --workspace "$PWD" --limit wall=30s \
  --json > "$jail_records/policy.json"
```

After inspecting those reports, run the command and save its receipt:

```sh
ouro-jail run --profile tool --workspace "$PWD" --limit wall=30s \
  --receipt "$jail_records/receipt.json" -- /usr/bin/true
```

`run` has no `--json` flag. The child's output is passed through, and jail
diagnostics may also appear on stderr.
`tail --json` emits one JSON event per line (NDJSON), not a single JSON array.
A setup error may happen before a receipt is created, so handle a missing
file and retain stderr. Don't fabricate a successful result from the exit
code alone.

On failure, report the requested policy, missing capability or evidence, and
receipt path. Do not silently widen grants, switch to `none`, disable
observation, or weaken evidence requirements to make a run pass. A permission
proposal needs the same review as any other access change. Review output
files and test results separately: containment does not establish that the
agent completed its task correctly.

The [receipt schema](https://github.com/monocursive/ouroboros/blob/dev/docs/specs/jail-v1/jail-receipt.schema.json)
and [exit code reference](https://github.com/monocursive/ouroboros/blob/dev/docs/specs/jail-v1/operating.md#exit-codes)
cover the machine interfaces in detail.

## Performance

Containment adds startup time. Observation also adds work while the command
runs, especially when it creates, renames, or deletes many files.

In the recorded Linux benchmark from 29 September 2026, a plain-session
fixture of 5,000 file-operation rounds had these median total runtimes:

| Execution mode | Median runtime |
| --- | ---: |
| Direct, without the jail | 190 ms |
| Jailed, observation off | 375 ms |
| Jailed, observation on (default) | 1,167 ms |

Each mode had 30 measured samples. This was an earlier development build on
the Ubuntu reference host, using synthetic workloads. It does not predict
the speed of your agent.

Across workloads and sessions, the highest p95 added startup time with
observation off was 131 ms. The full benchmark includes 540 measured launches;
all 60 observation-off no-op runs returned `exec_unconfirmed` and exit 1.
Their timings are included, but they are not successful run receipts. The
[full report](https://github.com/monocursive/ouroboros/blob/dev/docs/benchmarks/jail/followup-2026-09-29.md#k17-results)
includes the method, build, host, raw data, and limitations.

## Understand the boundary

An agent can change files you make writable and send readable data to
services you allow. Keep grants small and review the resulting changes.
Containment relies on the host kernel, and security review remains part of
the work before release.

The network proxy supports HTTP and SOCKS5 TCP connections; UDP is not
supported. Optional HTTP(S) credential vaulting supplies placeholders to the
child and substitutes secrets at the proxy. An authorized upstream could
still return a secret in its response. Command deny-rules help catch mistakes;
another program can perform the same operation under a different name.

For more detail, use the
[operator reference](https://github.com/monocursive/ouroboros/blob/dev/docs/specs/jail-v1/operating.md).
See the [roadmap](https://github.com/monocursive/ouroboros/blob/dev/docs/roadmap.md)
for what we're working on next.
