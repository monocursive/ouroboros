# Fleet onboarding over Tailscale

Status: proposed; no implementation or deployment implied. Written 2026-09-14
against `dev` at `af782a4b` in response to the request to refine and plan a first
version of integrated fleet networking.

The outcome is that an operator can add their own Mac or Linux machine to a small
fleet, run a remote agent, and recover from a network interruption without manually
copying cluster secrets or editing addresses, rosters, or service files.

## Product decision and scope

Use the installed Tailscale client for connectivity, including clients already
registered with Headscale. Use ordinary OpenSSH over that private network for setup.
Keep the existing TLS-protected BEAM cluster as the runtime transport. The setup CLI
exits when it finishes; the machines then operate without it.

This deliberately revisits the enrollment portion of [core.md, D4](core.md#3-the-four-decided-cuts)
at the user's request. That historical reduction remains a useful scope constraint:
this proposal adds an operator-side setup tool, not a new fleet control service.
The earlier fleet implementation should be treated as reference material, not restored
wholesale. Existing manual fleet and private-network workflows remain supported.

| Included in the first release | Deferred |
|---|---|
| macOS and Linux, ARM64 and x86-64 where an official matching Ouroboros artifact exists | Windows, unsupported Linux runtimes, mobile nodes |
| One existing Tailscale or Headscale network with OS-bindable IPv4 addresses | Embedded VPN, userspace-only networking, IPv6 distribution |
| Local setup, adding a second or third machine, repeatable repair and cooperative removal | Cloud provisioning, account creation, managed Headscale/DERP hosting |
| Existing OpenSSH access as the bootstrap authority | Invitation codes, public enrollment endpoints, enabling Tailscale SSH |
| Installing a missing Ouroboros binary from an exact official release | Updating an existing fleet or replacing unrelated installations |
| Ouroboros user service installation and observed readiness | Root agents, privileged macOS boot daemons, automatic OS policy changes |
| CLI onboarding and useful existing TUI/web readouts | A new Machines application or browser-based SSH/secret management |

The intended validation envelope is 2–5 trusted machines, not a hard cluster-size
limit. One designated operator machine retains the fleet CA key and the
SSH target mapping for setup. It must be available to admit another member, but is
not required for connectivity or work among other running members. Back up its existing
private data using the current operator backup practice; automatic authority migration
is outside this version.

**Prerequisites are visible:** Tailscale is installed, both devices are signed into
the intended network, and the operator can SSH to the target as its intended non-root
runtime user. If one is missing, show the relevant installation/login/access step and
allow the same command to be rerun. Ouroboros does not install a system VPN, switch an
existing account, collect network admin keys, or edit network-wide access policies.
Headscale support means using an already configured client; its server remains
independently operated. [Tailscale CLI](https://tailscale.com/docs/reference/tailscale-cli),
[Headscale registration](https://headscale.net/stable/usage/getting-started/).

## User journey and proposed commands

All new commands and options below are proposals, not currently available commands.

```sh
# On the operator machine. Detect this device's private address and prepare the fleet.
ouro fleet setup --machine studio

# Add a device selected from the visible network peers, or provide its SSH destination.
ouro fleet add me@buildbox --machine buildbox

# Existing fleet commands gain layered explanations and machine-readable output.
ouro fleet status
ouro fleet doctor --machine buildbox

# Install, inspect, or remove only an Ouroboros-owned local startup service.
ouro fleet service install
ouro fleet service status
ouro fleet service remove

# Gracefully detach a reachable member, retaining its work and session history.
ouro fleet remove buildbox
```

`setup` and `add` offer `--dry-run` to inspect and print an action plan without writing
fleet state or installing software. An interactive application shows one concrete plan
before mutation: target identity/user, resolved private address, version, paths, service
behavior, affected roster members, and any required idle-runtime restart. Acceptance
also explains that joining grants broad authority between the fleet's machines.
Ordinary SSH host verification is a separate prerequisite, not silently bypassed.

For a new runtime, propose a user service by default when its prerequisites are met;
`--no-service` selects explicitly labelled manual startup. If a supervisor is unavailable,
require that choice or completion of the prerequisite, rather than silently promising
automatic recovery. Preserve an existing correctly configured runtime supervisor.

For automation, `--yes` accepts the same resolved actions after preflight; it never
bypasses identity, runtime activity, version, ownership, or network checks. Read-only
discovery must not start a runtime, install a binary, create a profile, or probe every
discovered host with SSH. Contact only operator-selected devices and already recorded
members when adding to an existing fleet.

Calling `setup` on the same configured machine is an inspection/no-op unless a specific
repair is selected. Calling `add` again resumes its recorded operation or verifies the
existing member; it does not mint another certificate. Omitted SSH destinations use an
interactive peer picker; noninteractive calls require an explicit destination. Options
for remote executable and data-directory paths must be explicit, validated data. `status`
and `doctor` gain `--json` with stable reason codes and unknown values for unavailable
facts; incomplete setup returns a nonzero exit code even if some steps succeeded.

The flow is:

1. Detect the local Tailscale client, connection state, and this device's IPv4 address.
   Show login/install guidance when needed. Offer visible eligible peers as candidates.
2. Authenticate the selected SSH destination, verify its network identity and private
   address, inspect its OS/architecture, runtime state, installed version and data path.
3. Prepare the action plan. If Ouroboros is missing, include installation of the exact
   operator release for that architecture. An incompatible existing installation gets
   a specific manual upgrade instruction; it is not replaced by this workflow.
4. Create the target's own key locally on the target, issue its certificate on the
   operator machine, and transfer only the materials that target needs.
5. Install its profile and the required roster entries, configure the requested user
   service, and start the runtime. Check actual mutual cluster connectivity.
6. Report `connected`, then separately report provider/tool/workspace prerequisites.
   Offer an explicit first-task check in an operator-selected scratch workspace.
   A real model call runs only when the operator requests it; report the observed result.

The final display names the next step, for example `Connected; configure a model on
buildbox`, or `Connected; test task completed on buildbox`. A listener or reachable SSH
port is insufficient to report that an agent ran successfully. Existing credentials,
repository contents, SSH agents, model accounts, and grants are not copied as setup
material. Normal workspace transfer remains the existing fleet subagent feature.

## Current implementation to reuse

| Existing code | Role in this version |
|---|---|
| `tui/src/fleet.rs`: `create`, `create_from`, profile locks, TLS validation, EPMD ownership | Keep manual commands; factor shared credential/profile validation for the new path |
| `tui/src/cli.rs`, `tui/src/main.rs` | Thin command dispatch and operator workflow entry points |
| `tui/src/main.rs`: `service_run`, authenticated stop | Reuse foreground runtime ownership and graceful termination |
| `tui/src/runtime.rs` | Keep spawn locks, private data directories, publication/owner checks, environment filtering |
| `tui/src/update.rs`, `update/transport.rs`, `update/install.rs` | Extract only reusable pinned artifact download/verification primitives |
| `lib/ouroboros/cluster.ex`, `cluster/roster_epmd.ex` | Preserve reconnect sweeps, live roster reload, and runtime compatibility semantics |
| `tui/src/ui/app/cluster.rs` and existing web readouts | Preserve known/connected/unknown distinctions and expose useful next steps |

The current runtime contract is fleet protocol revision **5**, Ouroboros version,
and OTP release (`Cluster.runtime_compatible?/2`). Architecture is inventory, not a
compatibility barrier. `docs/FLEET.md` still mentions revision 3; reconcile this when
documenting the implementation. Check the running runtime as well as the installed
binary: replacing a file does not replace a running BEAM process.

Proposed Rust modules: `fleet_network.rs` for discovery and diagnostics,
`fleet_setup/` for SSH orchestration and its resumable operation record, and
`fleet_service.rs` for user services. Keep these dependencies out of the agent loop
and BEAM formation path. Avoid building a generic provider framework for one adapter.

## Connectivity and identity contract

The Tailscale adapter invokes the installed CLI with structured arguments, bounded
output, timeouts, and cancellation. Read `tailscale status --json` and client version;
parse the fields used by this feature, tolerate added fields, and return unknown or
unsupported when required fields are absent. The CLI documents that its JSON format
may change, so freeze sanitized fixtures and record the tested versions.
[Tailscale status](https://tailscale.com/docs/reference/tailscale-cli#status).

Use the selected device's actual overlay IPv4 address as the new profile's canonical
host, and use its human-friendly DNS name as display information. Match it to the
selected peer identity and verify it is bindable on that device. Do not identify
Tailscale by a `100.x` prefix or `.ts.net` suffix alone: Headscale configuration can
differ. The current private-address and IPv4 constraints still apply. Record the peer
identity and selected address in operator setup metadata so a reused name or switched
network is detected. Preserve existing manually configured hostnames.

A normal Wi-Fi/hotspot transition should preserve this identity and reconnect. A
device re-registration that changes its overlay identity/address needs explicit repair;
v1 must report it rather than silently rewriting node names and certificates. No
automatic public-address fallback, subnet-route changes, or proxy transport is added.

Use the ordinary OpenSSH client, with normal host-key verification and the operator's
local SSH configuration. Inspect the effective destination, require the selected
overlay address for this path, and reject unsupported proxy/jump routing in v1 with an
explanation. Never disable strict host checking, enable agent forwarding, or copy SSH
private keys. Unknown hosts require explicit host verification; changed keys refuse.
Peer discovery alone never authorizes issuing credentials.

Ouroboros's setup protocol runs through an ephemeral, hidden CLI helper over SSH
stdin/stdout. It accepts a small versioned set of typed operations (inspect, prepare,
install, roster update, service action, receipt); it opens no network listener. Requests
and responses have size/time bounds. Treat destinations, paths, peer names, and remote
output as data. SSH eventually invokes a remote shell: local argument arrays alone do
not prevent remote-shell injection. Use a fixed helper command, a carefully quoted
verified executable path, and framed input for variable data. The initial binary upload
uses a bounded fixed bootstrap routine and a private user-owned staging directory.

## Enrollment, rosters, and interrupted work

The secure setup path must not automate today's whole-directory copy, which temporarily
transports the CA and another member's private key. Instead:

- Generate the target private key on the target and obtain a signed CSR/proof of key
  possession bound to the prepared machine identity and operation ID.
- On the CA-holding machine, verify the request and issue only a leaf certificate for
  the exact approved node name/address. Ignore caller-requested CA privileges or extra
  certificate names. Reuse the runtime's certificate validation rules.
- Transfer the CA certificate, target leaf certificate, shared BEAM cookie, fleet ID,
  port policy, and roster over authenticated SSH. The CA private key and source node
  private key stay on the operator machine; the target private key stays on the target.
- Install through private staging, ownership/symlink checks, existing spawn/profile
  locks, and atomic file replacement. Existing unrelated profiles are never overwritten.

Before credentials leave the issuer, verify exact runtime compatibility from the
packaged metadata/helper and, where running, authenticated local runtime status. Add
machine-readable build metadata if necessary; do not start a distributed runtime just
to learn the OTP version. Validate that metadata against the embedded package in release
tests. Development builds remain on the manual path for v1.

For a third machine, preflight SSH access to every current member. Read and compare
their fleet identity and roster snapshots. Require compatible, reconciled snapshots;
if a member is unavailable or an operation is unresolved, stop before issuing new
credentials. Add the newcomer on every member and give it the complete agreed roster,
retaining tombstones. This is an explicit CLI operation; it adds no roster consensus
or background reconciliation daemon. Existing running fleet members reload their
rosters without restart.

Persist a private operation record containing an operation ID, source fleet/roster
snapshot, authenticated target identities, selected release digest, intended paths,
and per-machine completed steps. It contains no cookie, key, auth token, or full peer
inventory. Persist before/after each externally visible step and query a target receipt
when a connection is lost after a write. On retry, revalidate identities and state;
reuse an operation only when its target, key, and plan still match. A changed source
roster or conflicting operation requires reconciliation, never overwriting later edits.

| State | Recovery behavior |
|---|---|
| Inspected; nothing changed | Rerun preflight |
| Binary/key staged; fleet credentials not delivered | Remove only owned staging or resume the same verified operation |
| Credentials delivered; profile/rosters partly installed | Report partial admission and exact completed steps; resume by receipt |
| Profile/rosters committed; service/start pending | Resume service/readiness checks without reissuing credentials |
| Connected; agent prerequisites incomplete | Keep the working fleet and give the local configuration step |

Admission is not a distributed transaction. Do not promise full rollback after
credentials have been delivered: deletion cannot prove they were not copied. Handle
cooperative cleanup precisely and name unreachable residue. Do not delete profiles,
session journals, or binaries that predated the operation. Bound subprocesses and
reap them on interruption; a hard-kill recovery uses the durable records.

Serialize setup operations at the issuer. Recheck each target snapshot while holding
its local mutation lock before applying a step. Concurrent ordinary roster edits are
detected; an operator does not get a lost update disguised as successful admission.
Do not hold a runtime spawn lock across network waits or browser authentication.

## Installation and service lifecycle

Automatic binary installation is limited to a missing, explicitly selected per-user
installation. Resolve the exact operator release tag once; obtain the artifact for
the target OS/architecture and its checksum from that same release. Reuse the updater's
HTTPS/size/checksum rules. Verify the transferred bytes and candidate version before
atomic installation. If that release/target is unavailable, stop with instructions;
never substitute `latest`. Existing unowned installations and mismatched releases
remain an explicit manual maintenance step. Checksums provide integrity under the
existing GitHub/HTTPS trust model, not independent publisher signatures.

Services invoke the current foreground `ouro service-run`, not the detaching
`ouro daemon`. Use an absolute executable path, explicit data directory, private logs,
and the existing environment filtering. Inspect and preserve preexisting service
definitions; only manage definitions created by this operation or explicitly adopted
after a content/ownership check.

| Platform | Initial service behavior |
|---|---|
| Linux with a working systemd user manager | User unit with restart/backoff. Boot/logout persistence requires verified lingering; guide the administrator when it is absent. |
| macOS with a logged-in user session | User LaunchAgent with restart throttling. State explicitly that it starts at login and does not provide pre-login execution. |
| No supported user supervisor/session | Explain the prerequisite and retain a clearly labelled manual-start option; do not claim persistent startup. |

These platform distinctions are real deployment constraints.
[systemd lingering](https://www.freedesktop.org/software/systemd/man/252/loginctl.html),
[Apple user agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).

During first setup, profile creation still requires the runtime to be stopped. Show
any required restart in the action plan, refuse while active work is present, and use
authenticated graceful stop only for an idle runtime the operator agreed to transition.
Preserve its data and verify durable sessions after restart. A running compatible fleet
member needs no restart merely to learn a new member.

Wait for the selected private interface before launching BEAM, with cancellable,
throttled retries and an observable `waiting for network` state. Temporary network loss
does not erase credentials, modify membership, kill an otherwise healthy runtime, or
cancel work. On restoration, the existing dialer reconnects. Verify supervisor restart
behavior and avoid duplicate runtimes/EPMD processes. Removing/stopping a managed
runtime first disables its supervisor so it cannot immediately restart.

## Diagnostics and cooperative removal

`doctor` separates observations rather than collapsing them into `offline`:

| Layer | Example result |
|---|---|
| Network client | Not installed; needs login; permission denied; unsupported; running |
| Device route | Reachable; probe timed out; direct/relayed if observed; path unknown |
| Setup access | SSH unavailable; authentication refused; host identity changed |
| Ouroboros installation | Missing; exact compatible package; version/protocol/OTP mismatch |
| Runtime and cluster | Service stopped; waiting for interface; TLS failure; connected |
| Agent prerequisites | Model setup required; workspace unavailable; toolchain missing; test completed |

An overlay ping does not establish that EPMD/distribution ports are allowed. Probe
actual application connectivity in both directions and name untested/unknown causes;
do not assert an ACL or firewall is responsible without evidence. Report exact needed
ports/addresses for operator policy changes. A relay is a valid connection, not a
failed setup. Only report connection path from fresh observed data; never infer it
from the presence of a configured relay region.

Read-only status should not contact every member over SSH automatically. Deeper remote
diagnostics are explicit and bounded. Reuse the existing runtime wire model for TUI/web
cluster observations; detailed local network/setup diagnostics stay in the CLI for v1.
Both interfaces can point to the appropriate CLI command without becoming remote
enrollment endpoints. Diagnostic exports include selected device facts only and redact
credentials, login URLs/tokens, and unrelated network inventory.

`fleet remove NAME` is a cooperative operation on a reachable idle member: inspect
session ownership, disable its managed supervisor, stop its runtime, verify it is
disconnected, remove its fleet credentials, then remove its seed entries on remaining
members with resumable per-machine receipts. Retain all session/workspace data and
historical owner evidence; require explicit separate recovery/export/forget decisions
where that history affects session lists. Refuse automatic removal of active work.

The command does not remove the Tailscale device or claim credential revocation.
An unreachable/lost member uses the existing explicit recovery workflow. A compromised
member requires network access removal and clean-host credential rotation; this version
does not add a certificate revocation service. Connected BEAM nodes still have broad
authority over each other. Restrict EPMD/distribution to admitted private addresses
through operator-managed policy and keep the operator gateway loopback-only.

## Implementation sequence

Implement in a `codex/` branch from current `dev`. Each slice has a reviewable behavior
and focused tests. Keep the proposal and live documentation explicit about which parts
have actually shipped.

| Slice | Deliverable | Exit criterion |
|---|---|---|
| 1. Network discovery and preflight | Tailscale adapter, sanitized fixtures, selected-peer diagnostics, build metadata and dry-run plan | Correct decisions for logged-out, missing/changed JSON, no IPv4, wrong network/peer, occupied ports, stale runtime and incompatible package; no mutations |
| 2. Local admission primitives | Target key/CSR, issuer-side leaf issuance, profile staging, typed SSH helper operations and receipts | No CA/source/target private key crosses its intended boundary; hostile CSR/path, replay/conflict, crash and duplicate cases fail or resume correctly |
| 3. Setup orchestration | `setup`/`add`, verified missing-binary installation, issuer operation lock, multi-member roster updates | A real second and third machine join; interruption at every durable stage is recoverable without lost roster edits or duplicate identity |
| 4. Startup and removal | User supervisor integration, network wait, graceful idle-runtime transition and cooperative removal | One runtime/EPMD owner; reconnect, restart, supported persistence, disable/remove and partial cleanup work on both platforms |
| 5. Onboarding completion and status | Layered CLI results, existing TUI/web guidance, explicit first-task check, updated docs | Users can distinguish connected from usable and complete the documented flow without manual secret/roster/service edits |
| 6. Packaged validation | Automated isolated fixtures plus real multi-network Tailscale and Headscale acceptance | The complete release checklist below passes with artifacts, versions and limitations recorded |

Sequence 1 → 2 → 3 → 4 → 5 → 6. The first engineering checkpoint is one Mac-to-Linux
setup through real SSH and a system Tailscale client after slices 1–3. Use its failures
to refine the remaining service/UX work before expanding the supported environment
matrix. Do not expose incomplete admission commands as production-ready mid-sequence.

## Release acceptance

1. **End-to-end:** from an official packaged Mac operator, admit a Linux VPS on another
   network, add a third member, and run a bounded native task on the selected remote
   machine. Record a separate local model configuration step when needed. Verify the
   same flow with Linux as operator and macOS as target where its login session exists.
   Include a five-member roster/reconnect smoke before claiming the full tested envelope.
2. **Headscale:** repeat admission, connectivity and reconnect with an independently
   configured Headscale network. Record exact tested client/server versions; no blanket
   compatibility claim. Test every documented macOS client variant, or name unsupported
   variants precisely.
3. **Addressing and policy:** no MagicDNS requirement; selected overlay IPv4 binds
   locally. A non-member peer cannot authenticate to BEAM without fleet credentials.
   Blocked SSH or application ports yield useful distinct results. The gateway remains
   loopback-only. Validate relayed operation as well as direct operation.
4. **Recovery:** switch the laptop between Wi-Fi and a hotspot, suspend/resume it, start
   with the VPN unavailable, interrupt SSH and the CLI at each commit boundary, and
   restart a runtime. Restore connectivity without duplicate nodes or lost journals.
   Target reconnection within 30 seconds after network reachability is independently
   confirmed in the test environment; report observed timing, not a universal guarantee.
5. **Supervisor behavior:** Linux survives logout/reboot when lingering is configured;
   macOS resumes after user login. Without the supervisor prerequisites, status names
   the limitation. Stopping/removing a service does not respawn it or affect another
   data directory's runtime. Verify tool/model access under the actual service context.
6. **Failure integrity:** incompatible/missing artifacts, checksum mismatch, malformed
   metadata, changed SSH host keys, switched network, duplicate machine identity,
   existing unrelated installation, active work, symlinks, concurrent admissions and
   concurrent roster edits cannot cause a misleading successful setup or destructive
   overwrite. Rerun completed operations without additional credentials or services.
7. **Work and ownership:** retain and reopen an idle durable session across the initial
   standalone-to-fleet transition. Keep grants and model credentials node-local. Removal
   retains workspace data and explicitly reports unresolved session-owner evidence.
8. **Runtime independence:** after setup, disconnect the operator machine while the
   other two communicate. Test coordination-server unavailability separately and record
   actual behavior; do not promise new admission or arbitrary reconnect without it.
9. **Distribution evidence:** run the relevant Rust/Elixir suites, meaningful helper and
   packaged lifecycle integration tests, supported-platform release smoke checks and
   hosted CI. A local mock, same-host TLS cluster, or successful build is not proof of
   cross-network deployment. No live fleet changes are part of writing this plan.
   Before publication, the test harness can supply exact packaged candidate artifacts;
   this must not introduce a production flag that bypasses release verification.

The release claim is: **guided deployment of a small trusted Ouroboros fleet over an
existing Tailscale or Headscale network**, with explicit SSH and service prerequisites.
