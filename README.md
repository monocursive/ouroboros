# Ouroboros Jail

Give an AI agent only the access it needs. Ouroboros Jail is a Linux sandbox
that restricts file access, network destinations, and runtime for a command
and its children. Each run leaves a receipt of the policy applied, the result,
and any gaps in observation.

The executable is `ouro-jail`. Use it to let a coding agent edit a checkout,
run an unfamiliar test suite without network access, or build from read-only
inputs. Your existing agent keeps its own models and workflow.

**Pre-release.** Execution is validated on Linux x86_64. macOS builds provide
inspection commands and currently refuse sandboxed execution. Public release
artifacts and a Homebrew tap are not configured yet.

## Start here

- [User guide](docs/guide.md): build, check your host, run a command or agent,
  inspect the receipt, and review learned permissions.
- [Roadmap](docs/roadmap.md): installation, compatibility, macOS research,
  and the longer-term managed-worker plan.
- [For agents and scripts](docs/guide.md#for-agents-and-scripts): JSON output,
  per-run receipts, failure handling, and the website's plain-text docs.
- [Operator reference](docs/specs/jail-v1/operating.md): detailed configuration,
  host requirements, errors, and cleanup.

With Rust 1.98.1 and your distribution's bubblewrap installed:

```sh
cargo +1.98.1 build --release -p ouro-jail
target/release/ouro-jail doctor --profile tool
```

Follow the guide to install the binary outside the workspace you intend to
make writable. The jail refuses a writable grant that exposes its own executable.

## What works today

- Filesystem policies, wall deadlines, and host-dependent PID/memory/CPU limits.
- HTTP and SOCKS5 TCP proxying with explicit destination grants.
- Optional HTTP(S) credential vaulting, with placeholders in the child.
- Receipts and an event journal, with coverage and uncertainty recorded.
- `tail` for recorded or live events; `learn` for reviewable permission proposals.
- Fourteen bundled agent starter profiles. Compatibility is recorded per build
  and vendor version, not implied by the presence of a profile.

See the [validation record](docs/benchmarks/jail/README.md) and
[agent compatibility table](docs/specs/jail-v1/agent-compatibility.md) for
measured results and remaining gaps. An agent can still modify writable files
and communicate with services you allow; grants need review.

## Development

[Jail v1](docs/specs/jail-v1.md) defines the core contracts.
[Jail v2](docs/specs/jail-v2.md) defines the current additions and remaining
acceptance gates. [The north star](north-star.md) and
[managed teams](docs/specs/managed-teams-v1.md) describe planned ledger and
worker tooling; they are not implemented features of this jail.

```sh
uv run docs/specs/jail-v1/validate_contract.py
uv run docs/specs/managed-teams-v1/validate_policy.py
cargo +1.98.1 test --workspace
```

Contract validators check documents and schemas. Live Linux conformance is
separate and runs on the reference host through the `conformance` workflow.
The other CI workflows are `contracts` and `rust`.

The [Astro website](website/README.md) renders the user guide and roadmap from
these same Markdown files. The previous agent runtime remains on `legacy`,
also preserved by tag `thesis-4-preserved`; its releases are not jail releases.
