# Ouroboros

Tooling for people running existing agents. The previous implementation is on the `legacy` branch.

The product direction is in [north-star.md](north-star.md). The repository
layout and crate split rules are in [Jail v1 §4](docs/specs/jail-v1.md#4-source-layout-and-ownership).

The first implementation is specified in [Jail v1](docs/specs/jail-v1.md):
a standalone Rust jail on Linux, with shared contracts designed for Linux and macOS.

[Managed teams v1](docs/specs/managed-teams-v1.md) specifies company-controlled
agent execution: organization/project policies, approved services, isolated
inputs, reviewable artifacts and project-scoped evidence. The first team pilot
uses a managed Linux worker with Linux/macOS clients; fleet adds multiple workers.

Validate the specification's schemas, examples and golden fixtures with:

```sh
uv run docs/specs/jail-v1/validate_contract.py
uv run docs/specs/managed-teams-v1/validate_policy.py
```

This checks document contracts; live backend conformance runs on the
reference host through the `conformance` workflow.

J0–J3 of Jail v1 are implemented, on a stock host with no host configuration. J0 measured the reference host (an x86_64
VPS on Ubuntu 26.04 LTS; manifests under `docs/specs/jail-v1/evidence/`) and
the observer privilege model: the ptrace tracer is the working baseline, and
[eBPF remains unselected](docs/specs/jail-v1/backend-evaluation.md). J1 ships
the first execution slice — policy resolution, capability probes, the
bubblewrap containment boundary with source-pinned protected binds, the
ptrace closed-set observer, the managed gate, wall limits,
prepared/enforced/settled receipts, and the macOS refusal lane. J2 adds
cgroup-backed PID/memory/CPU ceilings, isolated build inputs, an outside
parent-death watcher, and measured controller/observer doctor probes.
[J2's acceptance map and operator setup](docs/specs/jail-v1/j2-authority.md)
describe the named Linux lane. J3 adds the `agent` profile (an outside HTTP
proxy as the only network path, host Unix sockets unreachable, unprivileged
inner sandboxes), data-only launch profiles with credential staging and
cleanup, and the explicit uncontained `none` profile
([J3's acceptance map](docs/specs/jail-v1/j3-authority.md)). OpenCode 1.18.32
runs under `agent` on the stock reference host
([agent compatibility](docs/specs/jail-v1/agent-compatibility.md)). J4 (evidence
and recovery) is next. CI is three
workflows, `contracts`, `rust` and `conformance`
([Jail v1 §16](docs/specs/jail-v1.md#16-implementation-order-and-exit-criteria)).
The specifications link to the previous implementation at commit `f3b2dbfd`,
reachable from branch `legacy` and tag `thesis-4-preserved` on the remote.
