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

This checks document contracts; the runtime and live backend conformance are not implemented yet.

Nothing in the specifications is implemented. The next change is J0 of Jail v1:
provision the x86_64 Linux reference host, measure the observer privilege model,
evaluate the enforcement candidates, and fill
[backend-evaluation.md](docs/specs/jail-v1/backend-evaluation.md), which is
checked in with every value `not_started`. The Linux reference host is an
x86_64 VPS on Ubuntu 26.04 LTS; its first manifest is under
`docs/specs/jail-v1/evidence/`. CI is three workflows, `contracts`, `rust` and
`conformance` ([Jail v1 §16](docs/specs/jail-v1.md#16-implementation-order-and-exit-criteria)).
The specifications link to the previous implementation at commit `f3b2dbfd`,
reachable from branch `legacy` and tag `thesis-4-preserved` on the remote.
