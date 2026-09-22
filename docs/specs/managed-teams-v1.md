# Managed teams v1: company-controlled agent execution

Status: implementation specification, revision 1, 2026-09-21. Proposed product
behavior and acceptance gates; no managed deployment is implemented or certified.

Parent: [North star](../../north-star.md). Execution primitive:
[Jail v1](jail-v1.md). This specification adds a managed deployment of the same
jail, ledger and optional fleet. It does not add an agent, vendor protocol,
model service, identity provider, publishing service or fourth daemon.

## 1. Outcome and first deployment

A developer submits a batch task with an existing agent. The company controls
the authorized input, effective policy, worker, credentials and result access.
The developer receives an intelligible plan, attempt status, bounded output,
reviewable artifacts and evidence of the boundaries actually applied.

The first deployment uses one company-managed Linux worker, a company-approved
model gateway, one repository class and one engineering team. Linux and macOS
clients submit through a restricted authenticated transport; a Mac client does
not imply native macOS containment. Multi-worker placement uses fleet once it
passes its independent milestone. One worker does not require BEAM.

This is batch execution of the agent's normal command, not transparent routing
of a desktop agent's tools, interactive session migration or remote vendor
approval. Selecting a launch profile remains declarative data. Each approved
agent/version must pass an actual batch compatibility run before support is
advertised. Scripted fixtures remain sufficient for core conformance.

## 2. Workflows and scope

| ID | Workflow | Authorized activity | Boundary and useful result |
|---|---|---|---|
| U01 | Everyday internal coding | Change one repository and run tests | One isolated workspace, approved model/package services, no personal/production credentials; patch and test report |
| U02 | Untrusted contribution | Inspect a pinned contribution and reproduce its failure | No source-control write token, other-project data or host sockets; resource ceilings; proposed fix for review |
| U03 | Confidential IP | Work on company-restricted source | Approved private/on-premises model service and eligible execution pool; no general internet or unapproved processor; same-class result access |
| U04 | Dependency/build work | Fetch dependencies, then build/test | Separate attempts: controlled fetch into immutable inputs, then network-free build; bounded artifacts; no signing/deploy credentials |
| U05 | Support investigation | Analyze an authorized sanitized snapshot | No production mutation credentials or direct production route; reports retain the input's classification |
| U06 | Contractor/client engagement | Work on one assigned project | Independent workspace, credential grants, caches, authorization and results; one client cannot enumerate another's jobs |
| U07 | Repository migration campaign | Execute the same approved task on several pinned inputs | Independent bounded attempts, placement and concurrency limits; no automatic retries or merge authority |
| U08 | Internal documentation/tickets | Access registered tools through an approved gateway | Gateway-enforced tenant/resource/action permissions; hostname reachability alone never means read-only access |

U01–U03 are the pilot release gates. U04–U08 reuse the same contracts but each
requires its own input/service integration and fixtures before being advertised.
No general workflow engine is required: stages are explicit separate requests.

## 3. Trust and deployment boundary

The company platform operator, worker administrator, installed binaries, kernel,
policy administrator and registered external authorization services are trusted.
The submitted argv, agent, its descendants, repository contents, project file,
artifacts and developer-supplied request fields are untrusted.

Developers are **submitters, not fleet peers or worker administrators**. D4's
fully trusted fleet membership remains an infrastructure administration role.
A developer endpoint must not obtain fleet join credentials, the operator API,
a worker shell, ledger producer tokens, gate fds or unrestricted filesystem access.
Worker compromise or a malicious company administrator is outside this claim.

Local jail use on a developer-controlled laptop remains useful containment for
that invocation. It cannot stop that developer running a different command.
Managed enforcement depends on company assets and credentials being accessible
only through company-controlled authorization paths. Signing a local policy
does not prevent bypass. Workers must be dedicated company infrastructure with
no developer login path that bypasses the managed entry point. Sharing a fleet
with developer-administered machines fails managed readiness.

The managed service/owner identity owns private policy and operational state.
Submitters and children cannot modify that state. Sharing a Unix UID with an
uncontained submitter is not isolation and is forbidden. Concurrent attempts
must also prove that workspace, socket, process and credential access cannot
cross attempts; namespaces alone are not presumed sufficient without MT04.
Managed workers require enforced storage byte/inode ceilings covering all child-
writable workspace, scratch and vendor state. These may be provisioned filesystem
quotas or bounded volumes outside the jail implementation; a periodic size scan
is not enforcement. Host/ledger capacity is reserved separately. Missing required
storage isolation refuses before launch, and MT04 exercises exhaustion as well
as access isolation. This is an M4 deployment gate, not a new jail-v1 backend.

## 4. Roles and authorization

| Role | Authority |
|---|---|
| Developer | Plan/submit within assigned projects; inspect and cancel their authorized attempts; retrieve permitted results |
| Project maintainer | Publish project restrictions and input references within the organization ceiling; authorize project members through company identity policy |
| Policy administrator | Publish organization ceilings, approved service/data classifications and time-bounded policy revisions |
| Platform operator | Provision workers, identity mapping, services and deployment; administer trusted fleet membership |
| Reviewer | Read specifically authorized artifacts/evidence; no implied execution, policy or publishing authority |
| Publisher | External source-control/deployment service identity; separate from agent/worker submission privileges |

The first reference transport is SSH with company-provisioned identity, pinned
host verification and a fixed server-side command. Disable shell, PTY, agent
forwarding, port forwarding and arbitrary environment acceptance for submission
accounts. The dispatcher consumes bounded structured frames on stdin; it never
constructs a shell command from argv or trusts SSH_ORIGINAL_COMMAND as authority.
Map principal and organization from server-verified credentials/admin-owned
identity mapping, never from JSON subject/group claims. The exact SSH deployment
and identity integration must pass MT01; no IdP or SSH CA is implemented here.

Authorization is checked for plan, admission, status, cancellation, artifact
fetch and evidence queries, not just for the initial submit. Initial access is
deny-by-default and project scoped. Do not leak another project's existence,
paths, policy details or job identifiers through discovery/errors. A request id
or artifact digest is an identifier, not a bearer capability.

## 5. Policy authority and resolution

Effective permissions are the intersection of organization policy, project
policy and attempt request. An optional repository ouro.toml is a final untrusted
narrowing input. Absence of a project restriction preserves the organization
ceiling, never unlimited authority. Unknown keys or ambiguous subset relations
refuse. Project requests cannot name a worker path, policy file, secret source,
backend command, environment override or wider network grant.

Organization/project policies are immutable revisions installed through an
administrator-controlled channel. Record issuer, revision and content digest;
verify ownership and integrity at load. A distribution signature, if used, is
checked against worker-provisioned trust roots, not a key supplied by the request.
Pin the accepted revisions in each admission. Protected policy loading and
monotonic revision/retirement checks are mandatory; a signature alone is not
authorization. Older retired revisions cannot be selected by a submitter.
Policy files are bounded to 64 KiB of UTF-8 JSON, with duplicate keys rejected.
The content digest is SHA-256 of the exact installed bytes validated and used;
ownership checks, parsing and hashing must refer to the same pinned file content.
Equivalent reordered documents may have different provenance digests; they do
not gain different permissions. Organization revision changes invalidate project
revisions that no longer fit, even if those project files were not changed.

| Dimension | Resolution / enforcement |
|---|---|
| Data classification | Owner-assigned classification on registered inputs; project and service must authorize it; submitter cannot relabel |
| Workspace | Authorized logical input manifest becomes a worker-owned isolated tree; no arbitrary host path mounts |
| Containment | Only contained profiles; none, observe off, best-effort and missing required evidence refuse in managed v1 |
| Resources | Minimum wall/pids/memory/CPU ceilings explicitly required in jail; byte/inode ceilings enforced by managed storage provisioning; missing enforcement refuses |
| Network/services | Intersection of registered service ids and capabilities; worker expands to pinned hosts/ports and scoped service credentials |
| Execution location | Intersection of allowed company pools/regions, then live capability readiness; no fallback outside the eligible set |
| Processing/storage location | Model-service and ledger/capture/artifact/backup declarations must fit their separate allowed-region sets; missing evidence refuses |
| Capture | Only streams allowed by company and project; off unless selected; argv/prompt/environment capture forbidden |
| Artifacts | Intersection of approved output types and size/file limits; all outputs inherit input classification and project authorization |
| Retention | Minimum permitted retention upper bounds for events, captures and artifacts; workspace cleanup follows verified lifetime |
| Concurrency | Organization/project active-attempt and queue quotas enforced at admission, independently of per-attempt cgroups |

The example [organization policy](managed-teams-v1/organization-policy.json) and
[project policy](managed-teams-v1/project-policy.json) use the executable
[policy schema](managed-teams-v1/policy.schema.json). They are illustrative
administrator choices, not legally mandated settings or supported integrations.
The project example explicitly selects a 30-minute wall, 256 pids, 4 GiB memory,
200% CPU, strict evidence, approved service ids, bounded results and retention.
No policy weakens the hard managed-v1 containment/evidence minimums.

The stored policy documents are complete snapshots: every field in the schema
is required, and an inherited restriction is copied from the parent before
publication. Partial authoring syntax is outside this draft. Set values are
unordered; project sets/capabilities must be subsets, numeric ceilings must be
no larger, and boolean permissions may only turn off. Reject attempted widening
instead of silently clipping it. Validity is the half-open interval
`[valid_from, valid_until)` and must fit inside the organization's interval.
Workers recheck validity at admission and use monotonic time for execution limits.
Scopes/organization/project ids must match the trusted installation context;
issuer strings are provenance, not self-authentication. Policy revisions are
positive monotonic integers within a policy id; validity and retirement checks
apply even to an otherwise valid signed older revision.

The same narrowing rules apply to attempt restrictions and repository policy.
Omitted attempt limits inherit the effective ceiling; omitted services grant
none; omitted capture selects no streams. A denied capability is an error.
Registered inputs determine classification and may not be reclassified by the
request. Classification order is public < internal < confidential < restricted;
classification allowlists still require explicit membership rather than assuming
that approval for one level approves all others. The registry determines actual
service/pool eligibility, beyond the syntactic policy subset check.
`--narrow FILE` uploads bounded JSON restriction content, never its client path
as a worker path. Its optional keys are the permission/limit groups in the policy
schema, without identity, issuer, revision or validity fields; absence inherits.
Explicit `--service ID` selects only that service's effective capabilities;
restriction content can narrow them further. A repository `ouro.toml` retains
the jail schema and can only narrow those compiled grants; its paths resolve
within registered input roots and cannot introduce host paths. The managed
request wire schema and native-argv framing freeze with M4 before implementation
is called interoperable; these policy documents are not the submission protocol.

Run `uv run docs/specs/managed-teams-v1/validate_policy.py` to check the schema,
examples and [policy cases](managed-teams-v1/policy-cases.json). This is a document
oracle for future Rust conformance, not an authorization or containment engine.

The resolved jail policy keeps its existing canonical byte format. Business
identity, classification, service authorization and policy provenance belong in
the managed admission record, bound to that jail digest. Do not insert personal
identity into every syscall event or imply the jail verified service permissions.
Compile grants into an owner-controlled launch configuration, then compare the
prepared receipt and actual applied requirements with the authorized plan.
The managed owner alone supplies operator CLI/config/environment to the jail;
developer flags cannot reach the operator override layer directly.

The entire agent process tree receives the outer policy. An inner sandbox or
agent permission prompt can narrow it but is not enforcement of company policy.
Different fetch/build/publish permissions require separate attempts or an
external service that enforces those operation permissions. Do not assume an
agent invokes a restrictive wrapper for every tool call.
Launch templates must also fit the compiled grants: extra default hosts or
personal-login credential sources are refused, never unioned back into an
approved policy during launch-profile resolution.

Broader access requires a policy administrator to publish an explicitly scoped,
time-bounded revision and a new attempt. Managed v1 has no force flag, live policy
widening or vendor-approval interception. An ordinary developer cannot approve
their own broader authority. Administrative emergency access is outside managed
agent execution and must not be labelled a compliant managed attempt.

## 6. Developer interface

The following additions to the Rust ouro front door are the managed-v1 CLI
contract, not currently implemented commands:

```text
ouro managed plan   --project ID --input REF --launch NAME [--narrow FILE]
                    [--service ID]... [--json] -- PROGRAM [ARG]...
ouro managed run    --request-id ID --project ID --input REF --launch NAME
                    [--narrow FILE] [--service ID]... [--capture stdout|stderr]...
                    [--json] -- PROGRAM [ARG]...
ouro managed status JOB [--json]
ouro managed wait JOB [--json]
ouro managed cancel JOB [--json]
ouro managed artifacts JOB [--json]
ouro managed fetch JOB ARTIFACT --output PATH
ouro managed evidence JOB [bounded ledger query flags] [--json]
```

All inspection verbs support --json. `plan` authenticates and resolves current
policy, but starts nothing and reserves no authorization. It reports the input
revision/classification, approved launch profile, readable/writable roots by
logical name, service capabilities, required limits, eligible pool/location,
capture/retention settings and refusal reasons with the restricting policy key.
It also returns the current admission epoch for constructing a stable request id.
It distinguishes operator-declared location/provider facts from kernel-probed
capabilities. Raw credentials, prompt/argv values and private host paths never
appear in the report. `run` rechecks everything; a previous plan is not a token.

The server receives literal argv through the native byte codec, not a remote
shell string. Raw task arguments may exist in bounded private operational
request storage while needed to queue/launch; ledger/status capture only their
digest. Default request frame cap is 256 KiB; excess refuses before reservation.
The operator installs approved agent binaries and launch data on the worker;
clients select logical profile/input/service ids, not arbitrary installation
commands or host credential paths. Client environment is not forwarded.
The launch profile configures startup state; it is not an executable allowlist.
Literal argv and all subsequently executed programs remain within the same
outer grants. An advertised agent profile additionally needs its compatibility
proof, but the security claim must hold for an arbitrary hostile fixture too.

Admission returns after the immutable authorization and launch decision are
durable. Reconnection with the same request id recovers the same job. Status
separates authorization, execution, evidence, cleanup, artifact collection and
reachability; a successful child exit does not mean tests passed or a change is
approved. Artifact output is treated as untrusted data, never executed by the
client. `fetch` authenticates, verifies the manifest/digest and creates the
explicit output path without overwriting existing content or following links.
The launch owner and output drains must survive the SSH client/dispatcher
disconnecting, using the ledger's independently supervised owner contract.
Fail readiness if the host would terminate an admitted task with its SSH session.

## 7. Admission, revocation and reconciliation

1. Authenticate the caller. Check the stable key `(organization, principal,
   request_id)` against durable prior requests. Identical normalized input returns
   the original job; conflicting input refuses. Replays never become new work
   because a token/policy expired. Authorization to read the original job is still
   checked; revocation can hide its details without permitting re-execution.
2. For new work, resolve current project membership, registered input revision,
   data classification, policy revisions, service permissions and eligible node.
   Reserve concurrency/queue capacity durably. Queue waiting grants no execution.
3. The selected worker independently verifies policy revisions, input identity,
   service configuration and live capabilities. Materialize inputs privately;
   obtain scoped credentials through registered integrations. Unknown or stale
   required authorization refuses; no policy/data/credential transfer from an
   untrusted developer endpoint is substituted.
4. Create one ledger launch owner and prepare the jail with its gate closed.
   Bind attempt id, expected policy digest, literal argv digest, input manifest
   digest, launch/service revisions and actual prepared receipt digest. Compare
   both requested and applied boundaries, not only a profile name or hash.
5. Under the worker's admission serialization boundary, recheck the installed
   authorization generation, policy validity, service leases and capacity.
   Persist the authorized admission bound to those values before releasing the
   existing jail gate once. Any pre-admission revision change or expiry refuses;
   it does not silently select a different policy. The commit is the authorization
   point; concurrent later revocations follow the next paragraph.
6. Reconcile by original job/attempt identity after lost acknowledgements. Never
   retry execution automatically. After verified termination, collect bounded
   outputs and remove managed credentials/workspace; preserve unknown lifetime
   and pending cleanup separately from an observed child result.

Revocation prevents new admissions immediately once installed at the worker.
It requests termination of affected active attempts and revokes service leases
where the external service supports it. Report requested, acknowledged and
verified termination separately. A partitioned worker or already-issued remote
effect cannot be made instantly undone. Attempt credentials have a fixed expiry
no later than the authorized maximum lifetime; refresh cannot extend authority
past that bound. Loss of connectivity never yields an asserted successful stop.
High-assurance projects require live authorization at release and fail closed
when that check is unavailable. The pilot uses this setting, with no offline
admission cache.

At release, the execution deadline must fit within both policy validity intervals
and the granted credential/service leases; otherwise refuse before exec. Policy
expiry cannot turn a temporary exception into a longer running authorization.
Revocation or expiry also stops accepting new service operations where the
external integration supports that enforcement; deletion of local token files
alone is not revocation.

Reservations are released only on pre-exec refusal or reconciled termination;
unknown live attempts continue consuming capacity so retries cannot evade quotas.
Administrative reconciliation is identity checked and recorded. Fleet placement
does not confer broader policy or credential authority than local admission.

Retention must not reopen an old idempotency key. Managed request ids include a
server-issued organization admission epoch and a random nonce; the client keeps
the complete id across reconnects. The server durably closes epochs monotonically
and never reuses them. Retain request mappings while their epoch accepts requests
and while an attempt needs reconciliation. Before deleting a mapping under its
retention policy, close its epoch; an absent mapping from a closed/unknown epoch
is `request_expired`, never a fresh launch. Existing authorized mappings may still
return the original job. The client never silently replaces an expired id: a new
id is an explicit new attempt. Opaque replay guards/epoch state have documented
access and retention separate from captured content. MT09 includes replay after
mapping deletion, policy expiry and worker restart.

## 8. Inputs, artifacts and publishing

Each project registry maps a logical input reference to an authorized repository
and pinned commit or immutable sanitized-data manifest. Authenticate source access
outside the child. Reject moving branches as execution identity: resolve and pin
before admission. Record repository logical id, revision and input digest, without
source credentials. Fetching must not execute repository hooks or smudge filters.

Materialize a fresh tree without writable hardlinks, shared Git metadata/alternates,
symlinks escaping the input root or writable cross-project caches. A git worktree
alone is insufficient. Submodules, LFS and external dependencies are disabled
unless explicitly resolved into the authorized manifest. Keep the comparison
baseline outside the child. The materializer's readonly fetch credentials never
enter the agent environment or filesystem. Refuse when these conditions cannot
be established; plain jail workspace grants retain their existing shared-inode
limitations and must not be relabelled isolated copies.

On verified termination with intact boundary identity, a trusted bounded collector
reads only registered output roots via anchored no-follow handles. No traversal,
device, socket, writable hardlink, unexpected mount or symlink can redirect it.
Initial limits are 64 MiB and 10,000 regular files per attempt; project policies
may lower them. Output globs are relative to declared roots, not host paths.
Overflow refuses collection with a reason; it does not truncate a patch silently.

The first artifact types are patch, test_report and regular_files. Generate the
patch outside the child against the registered baseline, without executing Git
hooks or trusting child-written Git config/index as authority. Unsupported path
types/changes refuse export. Treat child test reports as claims; execution facts
and independently run verification belong to separate evidence. A manifest binds
artifact id, job/attempt, project/classification, input digest, relative path/native
codec, size, content digest, retention and collection outcome. The collector does
not certify generated content safe or secret-free.

Artifacts and captured output require project authorization at every read and
inherit the most restrictive input classification; there is no automatic public
download URL. The managed agent has no Git write, signing or production deployment
credential. An existing review/CI/publishing system may consume an artifact after
its own authorization and checks. Ouroboros v1 neither merges nor deploys it.
Do not rely on withholding credentials if the worker network already provides
unauthenticated access to a consequential service: deny that route too.

## 9. Models, credentials and internal services

An administrator-owned service registry binds each service id/revision to exact
proxy destinations, kind, allowed classifications, capability names, credential
issuer/audience, maximum lease, authorization probe and declared processing
locations/evidence reference. The project policy selects a subset of these
capabilities; credentials or request content cannot choose another tenant/endpoint.
Service registration and changes are deployment operations, not agent tools.

The model gateway keeps upstream provider secrets outside the child and accepts
only an attempt/project-scoped credential issued by the approved integration.
It enforces model/tenant access,
request/token budgets, expiry and any content controls. These are external service
facts with their own conformance probes, not claims inferred by the jail. A vendor
that requires broader credentials, unapproved login/telemetry/update endpoints or
cannot use the approved gateway is unsupported for that policy; do not widen the
allowlist silently. No vendor-specific model API is implemented in Ouroboros.

Package/document/ticket services enforce their own repository, tenant and action
permissions. HTTPS CONNECT allows a byte tunnel; it does not prove read-only
HTTP methods or allowed payload contents. Any data the agent can read may be sent
to an allowed model destination. U03 therefore requires that destination to be
authorized for the entire input classification, or requires input minimization
before launch. The jail performs neither TLS inspection nor semantic DLP.

Credential integrations run outside the child and hand scoped material to the
existing launch mechanism through private state, never public argv/ledger fields.
Grant only the capabilities actually requested; never mount the operator's whole
home, cloud config, SSH agent or personal agent login. A copied token remains
readable by that child; lifetime limits and upstream scope/expiry bound its use.
Cleanup unlinks managed state but cannot erase copies or undo past requests.

## 10. Evidence, privacy and location

Managed evidence belongs to the ledger owner and contains these mandatory
groups; unavailable optional facts use explicit null/reason values. Authorization
and prepared bindings are immutable admission facts. Results/cleanup are later
linked lifecycle records, never edits to the authorization that released a gate:

| Group | Facts |
|---|---|
| Identity | schema/version, organization/project, opaque authenticated principal, job/attempt, request digest, authorization decision/time/generation |
| Authority | organization/project policy id/revision/digest, validity, authorized service revisions/capabilities, scoped lease ids/expiry (never secrets) |
| Inputs | registered source revision, manifest digest, assigned classification, materialization result |
| Execution | worker id/pool, declared execution location and inventory provenance, required/live capabilities, jail policy digest, argv digest, prepared receipt digest |
| Results | child outcome, evidence health/gaps, verified lifetime, cleanup, artifact manifest/collection state, publication explicitly external |
| Data handling | selected captures and caps, event/capture/artifact retention deadlines, authorized audience and any retention hold authority |

The future managed-record schema freezes with M4, not jail v1. Managed metadata
must reference the existing jail receipt rather than redefine containment fields.
The ledger must reject a managed admission that lacks these bindings, has an
unapproved policy generation, or attributes a caller-provided principal as
authenticated. Do not collect raw argv/prompt, environment values, credential
contents or model request/response bodies into this record or syscall traces.
Observed metadata, including filenames, can itself contain sensitive information;
there is no claim that a hostile child cannot encode a secret into a filename.
Opt-in captured stdout/stderr and artifacts can contain sensitive data and are
separately protected. Access/retention applies to metadata as well as content.

Provide project-scoped read access, explicit privileged audit access, recorded
policy/result access decisions and configurable retention. Examples use 14 days
for event metadata, 1 day for captures and 7 days for artifacts, not a compliance
default. Expire generated downloads with their source. A retention hold requires
separate company authority and a recorded reason; it cannot be requested by the
agent or silently override a shorter project rule. Unverified live workspace
cleanup requires incident reconciliation rather than unsafe deletion; report
overdue cleanup and revoke credentials independently of filesystem deletion.
Raw queued request material is deleted on launch/refusal; captures and artifacts
expire from creation, and sealed event records from settlement. Live operational
identity/reconciliation state is retained only while needed to prevent unsafe
cleanup or duplicate execution, with overdue cases visible to an authorized
operator. Admission-epoch guards follow §7, so evidence expiry never enables replay.

Execution location, model processing location and storage/backup location are
distinct declared attributes. Worker eligibility uses administrator-controlled
inventory and measured capability, not labels supplied by the caller. Geographic
claims and provider processing/retention commitments require company-provided
evidence; an IP address or an EU worker is not proof of downstream residency.
The policy display must say which facts were declared versus measured.
Admission validates execution_regions against worker inventory,
model_processing_regions against every selected model integration, and
storage_regions against ledger, capture, artifact and backup destinations.
Unknown, stale or outside-policy declarations refuse; routing success is not
substitute evidence. The first deployment has no automatic cross-region fallback.

These controls support company decisions on minimization, access, processors,
retention and transfers. They do not establish GDPR compliance, eliminate the
need for processor agreements/transfer assessment, or certify a deployment.
See [GDPR Articles 25, 28 and Chapter V](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng).
Evidence collection itself needs authorized access and retention; this product
does not introduce employee productivity scoring or record conversation bodies.

## 11. Ownership and implementation stages

| Concern | Owner |
|---|---|
| Local containment, observation, lifetime and native platform mechanics | Rust jail |
| Policy intersection, managed request validation, SSH client/dispatcher, isolated inputs and bounded artifacts | Rust composition code in ouro/ledger launch owner; no new daemon |
| Durable admission, provenance, evidence access and retention | Rust ledger |
| Multiple trusted workers, eligibility, quotas and reconciliation across workers | Elixir fleet; local owner remains authoritative for execution |
| SSO/SSH identities, credential issuance, model/tool permissions and publishing | Company-provisioned external services |

| Stage | Deliverable | Exit |
|---|---|---|
| J0–J5 | Unchanged jail-first sequence, plus managed composition seam tests | Jail v1 gates; no claim of company authorization merely from sandbox success |
| M2 | Ledger/owner prerequisites | Existing ledger gates; immutable admission-to-receipt linkage |
| T1 / M4 single-worker pilot | Restricted identity ingress, policy intersection, registered inputs/services, private credentials, bounded artifacts and project evidence access | MT01–MT14 and actual U01–U03 scenarios on a provisioned Linux worker; macOS client acceptance |
| T2 / M4 fleet deployment | Same contract across multiple eligible workers | M3 fleet prerequisites plus MT15–MT16; no weakening on placement/failover |
| Later native macOS worker | Independently measured native containment | Full jail and managed suite on macOS; no Linux-only field assumptions |

T1 depends on jail and ledger, not on multi-worker fleet or native macOS
execution. The company provisions its approved services; missing integrations
are named blockers, not credentials copied from a developer laptop. A service
simulator closes scripted protocol tests but cannot mark a real deployment ready.

## 12. Managed acceptance matrix

| ID | Required result |
|---|---|
| MT01 | Forged identity/project claims, restricted-SSH shell/forwarding attempts, unknown host identity and unauthorized reads/cancels refuse; developer cannot use fleet membership/operator APIs |
| MT02 | Company → project → attempt intersection rejects wider paths/services/classes/regions/limits, none/off/best-effort, host paths and secret-source overrides with safe policy-key reasons |
| MT03 | Replaced/retired/expired policy and preparation-time revision races refuse before target exec; exact admitted policy/argv/input/receipt digests match |
| MT04 | Concurrent projects cannot access each other's files, caches, sockets, processes, credentials or results; byte/inode exhaustion is contained by enforced storage limits; developer-controlled host cannot join a managed worker pool |
| MT05 | Pinned input is isolated from source, hardlinks/alternates/hooks/submodules cannot introduce authority, and changed branches cannot silently alter admitted input |
| MT06 | Useful coding succeeds: agent edits the authorized project, tests execute, a bounded patch/report is collected and an authorized developer retrieves it |
| MT07 | Host/home/cloud/SSH material, direct egress, host Unix peers and unauthorized gateway capabilities remain denied even when the agent ignores its own permission prompts |
| MT08 | Confidential input refuses a service/classification, execution, processing or storage/backup location mismatch or unknown declaration; an approved private model task succeeds; declared provider/location evidence is displayed honestly |
| MT09 | Replayed request after lost reply, expiry, mapping deletion or restart never creates another child; closed epochs cannot reopen; conflicting replay refuses; revoked requester cannot retrieve another user's job |
| MT10 | Missing ledger, observer, required limit, authorized service or live admission check fails closed; no implicit local/offline/none fallback |
| MT11 | Cancel/revocation/owner death preserves measured death-chain behavior; a partition reports stop pending/unknown; expired gateway credentials cannot be refreshed into broader authority |
| MT12 | Malicious/oversized artifact paths, symlinks, hardlinks, mounts and Git configuration cannot escape collection; failure is distinct from child exit; unauthorized fetch and overwrite refuse |
| MT13 | No argv/environment/model-body collection leaks seeded launch secrets through record fields; filenames remain classified metadata; captures are opt-in and bounded; project evidence ACL, retention, deletion/hold and overdue-cleanup behavior are tested |
| MT14 | Native macOS and Linux clients perform plan, submit, disconnect, reconnect, wait, cancel and fetch against Linux; each advertised real-agent profile passes its batch/gateway scenario |
| MT15 | Placement uses authorized inventory and live required capabilities, respects per-project/organization quotas, refuses forbidden regions and retains capacity for unknown live attempts |
| MT16 | Two-worker restart/partition/lost-admission tests preserve one owner, same authority/input bindings and unknown outcomes; no automatic retry or credential movement |

The pilot report names the build, worker/kernel/backend, policy and input
revisions, identity/service integrations, tested agent versions, measured startup
and task overhead, refusal reasons and evidence/artifact results. Connectivity
alone, a green schema validator or a scripted fake agent does not establish
managed developer readiness. Changes to any authority-bearing dependency rerun
the affected gates before deployment.
