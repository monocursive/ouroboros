# Single-worker pilot preparation — 2026-09-30

Status: preparation only. No managed submission service is implemented or
deployed. The local jail and first ledger slice do not establish managed-team
readiness. The release contract is [managed teams v1](../../specs/managed-teams-v1.md),
including MT01–MT14 and the real U01–U03 workflows.

## What an approved model service means

It is a model service the company policy administrator authorizes to receive
that input's code and prompts, within the organization and project ceilings.
The decision is recorded for a particular project and data classification.
An existing provider account or self-hosted model can supply the upstream model.
Managed access requires a company-authorized gateway that keeps upstream secrets
outside the child, accepts attempt/project-scoped credentials and enforces
model/tenant permissions, request/token budgets and expiry.

The model service registry must bind that decision to the actual endpoint,
capabilities, credential source and declared processing location. A service
approved for public source is not automatically approved for confidential
source. Unknown provider/location declarations cannot pass MT08.

The credential-free OpenCode model used in the
[onboarding measurement](../jail/onboarding-2026-09-30.md) received only an empty
project and fixture prompt. That experiment did not authorize sending a real
repository to the same endpoint.

## Decisions needed for a real deployment

| Input | Concrete decision | Current status |
|---|---|---|
| Repository | Logical project id, source repository, pinned input commit and owner-assigned classification | Not selected |
| Team | Organization and authorized principals, with the existing company identity mapping | Not supplied |
| Model service | Scoped company gateway and upstream provider/model, permitted classifications/capabilities and declared processing location | Not selected |
| Worker | Dedicated Linux worker, administrator, execution region and enforced storage quotas | Not provisioned for managed access |
| Result storage | Project-scoped readers, storage/backup location and retention policy | Not supplied |

A possible initial public-source experiment is a pinned Ouroboros checkout and
the already exercised OpenCode version. Repository and service selection still
need the owner's decision. This experiment would exercise a technical path;
it would not replace the confidential-model workflow or the managed gates.

## Implementation sequence

1. Finish the ledger prerequisites in [milestone 2](../../../north-star.md#8-milestones),
   including durable replay/retention anchors and the remaining fault gates.
   Preserve the jail's standalone operation and one Rust launch owner. Add owner
   and output-drain survival across SSH disconnects; the current foreground owner
   explicitly defers that prerequisite.
2. Freeze bounded submission frames and build the Rust single-worker managed
   entry point. Authenticate the principal through restricted, pinned SSH;
   check project access for every operation; prohibit a worker shell or forwarding.
3. Load administrator-owned policy revisions and registered input/service
   manifests. Resolve organization, project and attempt intersections, live
   authorization, classification/location and quota readiness before admission.
4. Materialize isolated pinned inputs, scope gateway credentials, launch through
   the ledger's existing gate, and collect bounded artifacts with project-scoped
   status, cancellation, evidence and fetch operations.
5. Run MT01–MT14 against the provisioned worker, then the actual internal-code,
   untrusted-contribution and confidential-model scenarios. Exercise native Linux
   and macOS submission clients, including disconnect/reconnect while the same
   owner continues draining output. Record provider/location declarations separately
   from kernel-measured containment and lifecycle evidence.

Fleet scheduling and native macOS execution have separate acceptance gates.
One Linux worker does not require Elixir/OTP fleet coordination.
