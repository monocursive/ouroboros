<p align="center">
  <img src="assets/logo/ouroboros-readme-banner.png" width="100%" alt="Ouroboros">
</p>

# Ouroboros Jail

**Give your agent only the access it needs.**

Ouroboros Jail is a standalone Linux sandbox for AI agents and command-line
tools. The `ouro-jail` executable restricts file access, network destinations,
and runtime for a command and its children. Each attempt produces a receipt
of the policy applied, the outcome, and any gaps in observation. Your existing
agent keeps its own models and workflow.

[Website](https://ouroboros.monocursive.com/) · [User guide](docs/guide.md) ·
[Roadmap](docs/roadmap.md) · [Operator reference](docs/specs/jail-v1/operating.md)

**Pre-release.** Linux execution supports x86_64 and aarch64, with a reference
x86_64 conformance host and native Raspberry Pi checks. Available profiles
depend on the host's kernel capabilities; see the [platform requirements](docs/specs/jail-v1.md#32-initial-support-matrix).
macOS builds provide inspection commands and currently refuse sandboxed
execution; other Linux architectures also refuse execution. Installation is from source. Public jail
release artifacts and a Homebrew tap are not configured yet.

## What you can do

- Let a coding agent edit a checkout while keeping unrelated projects and
  credentials outside its file grants. Allow only the provider endpoints it needs.
- Run tests from an unfamiliar repository in a disposable checkout, without
  network access and with a deadline.
- Build from read-only source with separate writable output and scratch paths,
  a memory limit, and no network access.

## Build and run

Install Rust 1.98.1 and your distribution's bubblewrap package. Run as your
normal user. The reference host uses Ubuntu 26.04.1 and bubblewrap 0.11.1.

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

Install the binary outside any workspace you intend to make writable. The jail
refuses a writable grant that exposes its own executable. Read the `doctor`
report before continuing: required controls must be available, while unavailable
preferred limits are reported as unapplied.

Try a command in a fresh directory:

```sh
jail_demo="$(mktemp -d "$HOME/ouro-jail-demo.XXXXXX")"
cd "$jail_demo"

ouro-jail explain --profile tool --workspace "$PWD" --limit wall=30s --json
ouro-jail run --profile tool --workspace "$PWD" --limit wall=30s -- \
  /bin/sh -c 'printf "hello from the jail\n" > greeting.txt'

cat greeting.txt
ouro-jail tail
```

This grants a writable workspace, blocks network access, and sets a 30-second
deadline. Changes persist after the command exits. Arguments after `--` are
passed literally; name a shell explicitly when you need shell syntax.

Explicit PID, memory, and CPU limits require delegated cgroup v2 controls.
Delegation also affects process cleanup during supervisor failure. See the
[host setup reference](docs/specs/jail-v1/operating.md#lingering-and-the-scope-step)
before relying on those controls.

## How enforcement works

The Rust supervisor applies permissions outside the agent:

- **Filesystem:** bubblewrap creates user, mount, PID, network, IPC, and UTS
  namespaces with a filesystem view assembled from declared roots. System runtime
  files remain available; your home directory and environment are not inherited
  wholesale. Use `--ro` and `--rw` for path grants, and `--deny-read` for exclusions.
- **Kernel boundary:** contained profiles use seccomp, `no_new_privs`, and no
  capabilities. Project-local `ouro.toml` configuration can narrow the operator's
  policy but cannot add grants or weaken required controls.
- **Network:** `tool` and `build` have no network access. `agent` uses an outside
  proxy with destination grants, supporting HTTP and SOCKS5 TCP connections.
  UDP is unsupported. `--allow-host HOST[:PORT]` adds a destination; omitted
  ports mean 443. Optional HTTP(S) credential vaulting gives the child
  placeholders and substitutes secrets at the proxy.
- **Lifetime and resources:** wall deadlines are enforced by the supervisor;
  delegated cgroup v2 controls enforce PID, memory, and CPU ceilings. Every
  explicit limit is required, so an unavailable control refuses the run.
  A receipt becomes `settled` only after the process tree is verified dead.
- **Observation:** a ptrace observer records a defined set of exec, filesystem
  mutation, connection, and denial events. Observation and strict evidence are
  on by default; loss of required evidence stops the run. Reads, payloads, and
  every individual write are outside the observed set.

An agent can modify files you make writable and send readable data to services
you allow. An authorized upstream could return a vaulted secret in a response.
Containment relies on the host kernel, and security review remains a release
gate. Inspect grants and review the resulting changes.

### Profiles and agent compatibility

| Profile | Starting policy |
| --- | --- |
| `tool` | Writable workspace and scratch, no network; existing `.git` and `.ouroboros` trees beneath writable roots are protected from writes. |
| `agent` | Writable workspace, scratch, and temporary agent state; proxied network destinations require grants. Git metadata is writable. |
| `build` | Read-only inputs and writable scratch; grant output paths explicitly. No network. Requires an explicit memory ceiling and host support. |
| `none` | Uncontained host access. Receipts mark the child unprotected. |

Fourteen starter launch profiles are embedded, including OpenCode, Codex, and
Claude Code. `--launch NAME` supplies starter environment, credential, and
network settings; you supply the executable and arguments. Profiles do not
install agents, and normal login state is not automatically exposed.

OpenCode has recorded live runs. Every launch profile remains experimental
until the specific agent version and jail build have compatibility evidence.
See the [agent guide](docs/guide.md#run-an-existing-agent) and
[compatibility table](docs/specs/jail-v1/agent-compatibility.md) for tested
combinations and remaining gaps.

## Receipts, journals, and integrations

Each attempt saves a `jail.json` receipt, resolved policy, and `trace.ndjson`
journal under `~/.local/share/ouro/attempts/` by default. `OURO_DATA_DIR` selects
a different private data directory. Receipts record `phase`, `outcome`, actual
`containment` and `applied` controls, process `lifetime`, observation `coverage`,
and `errors`. Missing evidence stays explicit; a zero count only means no
observed events when that class had active coverage.

Use `tail --follow` for live events or `tail --attempt ID --json` for a specific
attempt's NDJSON journal. `version`, `doctor`, and `explain` support JSON output.
`run` passes through the child's standard streams and has no JSON mode; use
`--receipt PATH` with a unique path outside child-writable grants.

Read the receipt alongside the exit code: 125 can mean refusal before exec,
and 1 can mean an evidence or supervision failure after execution. A child's
own exit code can overlap those values. Setup errors may occur before a receipt
exists. The [integration guide](docs/guide.md#for-agents-and-scripts) and
[receipt schema](docs/specs/jail-v1/jail-receipt.schema.json) cover these cases.

`learn` runs a command inside containment and proposes exact read-only paths
and denied network destinations from observed evidence. Denied writes do not
become write grants. Learning can change writable files; review the proposal
before applying it. `--adopt` shows the change and requires interactive
confirmation. See [permission learning](docs/guide.md#learn-missing-permissions).

## Performance and validation

In the recorded **29 September 2026** Linux benchmark, a plain-session fixture
with 5,000 file-operation rounds had these median total runtimes, with 30
measured samples per mode:

| Execution mode | Median runtime |
| --- | ---: |
| Direct, without the jail | 190 ms |
| Jailed, observation off | 375 ms |
| Jailed, observation on (default) | 1,167 ms |

The highest p95 added startup time across tested workloads and sessions was
**131 ms with observation off**. Observation adds ptrace stops and can be
expensive on file-heavy work. These are synthetic workloads on the Ubuntu
reference host using an earlier development build; they do not predict agent
speed or establish performance for the current checkout.

The full benchmark includes 540 measured launches. All 60 observation-off
no-op samples returned `exec_unconfirmed` and exit 1 because execution ended
before it could be confirmed. Their timings are included; they are not
successful run receipts. See the [method and raw results](docs/benchmarks/jail/followup-2026-09-29.md#k17-results)
and [validation record](docs/benchmarks/jail/README.md).

## Local ledger work

The first `ouro-ledger` slice is available in source. It reserves one attempt,
records admission durably before releasing the jail's execution gate, stores
source events and settlement, and supports `runs`, `show`, `verify`, and
`settle-orphans`. Bounded single-run queries retain the stored source events and
their evidence labels; NDJSON export preserves the exact canonical record bytes.
Operator `append` records independent assertions and effect decisions without
changing launch state. `tail -f RUN --json` follows canonical records with
resumable byte positions and explicit coverage/protection labels.
Output capture is opt-in and bounded. Linux owns execution;
macOS supports local store inspection. The jail still works independently.

See the [ledger specification and commands](docs/specs/ledger-v1.md). The full
ledger milestone remains open: cross-run queries, comparisons,
signed bundles, best-effort recovery and managed project authorization are not
implemented. Local consistency is reported separately from coverage and
protection from the child.

## Planned work

- **Next:** complete the ledger acceptance and remaining verbs, signed public
  distribution, more agent/version compatibility records, and benchmarks
  refreshed against a committed build. [Clean-VM onboarding](docs/benchmarks/jail/onboarding-2026-09-30.md)
  completed in 67.32 seconds on the documented Ubuntu 26.04.1 combination.
- **Research:** native macOS execution, including process-tree cleanup when the
  supervising helper dies. Apple entitlement approval is also pending; approval
  alone does not resolve the cleanup blocker.
- **Later:** signed ledger export bundles, and company-managed Linux
  workers, starting with one worker before a fleet.

These are planned features with no release dates. See the [roadmap](docs/roadmap.md),
[north star](north-star.md), and [managed-teams specification](docs/specs/managed-teams-v1.md).

## Development

[Jail v1](docs/specs/jail-v1.md) defines the core contracts.
[Jail v2](docs/specs/jail-v2.md) defines the current additions and remaining
acceptance gates.

```sh
uv run docs/specs/jail-v1/validate_contract.py
uv run docs/specs/ledger-v1/validate_contract.py
uv run docs/specs/managed-teams-v1/validate_policy.py
uv run docs/specs/validate_links.py
cargo +1.98.1 fmt --all -- --check
cargo +1.98.1 clippy --workspace --all-targets -- -D warnings
cargo +1.98.1 test --workspace -- --test-threads=1
```

Contract validators check documents and schemas. Live Linux conformance is
separate and runs on the reference host through the `conformance` workflow.
The other CI workflows are `contracts` and `rust`.

The [Astro website](website/README.md) renders the user guide and roadmap from
the same Markdown files and exposes plain-text versions for agents. The previous
agent runtime remains on `legacy`, also preserved by tag `thesis-4-preserved`;
its releases are not jail releases.

## Contributing

I accept AI-generated and AI-assisted pull requests. All contributions must
meet the same quality standards: focused scope, correct and maintainable code,
alignment with the project contracts, and relevant tests or reproducible
validation. Explain the problem, the change, and how you verified it. Security
and compatibility claims need evidence for the affected build and platform.

**I reserve the right to close any pull request that does not meet the project's
quality standards, without explanation.**

## Licence

Ouroboros Jail is licensed under the [MIT licence](LICENSE).
Copyright © 2026 Monocursive.
