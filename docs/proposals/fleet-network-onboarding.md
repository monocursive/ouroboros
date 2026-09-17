# Fleet onboarding over Tailscale

Status: implemented on the branch `codex/fleet-onboarding` (2026-09-17, from `dev` at
`826a4c51`, source version `0.1.8`), not yet merged or released. Originally written
2026-09-14 against `dev` at `af782a4b`; refreshed 2026-09-17. Slices 1–6 below landed,
each with an adversarial review and a fix wave; slice 7 landed only as far as a local
packaged build and run allow. Of the release acceptance list, items 12–16 were exercised
on one Mac (see "What has been exercised" in [FLEET.md](../FLEET.md)); items 1, 2, 4,
8, 9 and 11 have not been run, item 3 only in its loopback form, item 5 only for macOS,
and item 6 only through the test suites. Implementation departures from the text below
are listed under "Implementation notes" at the end.

The outcome is that an operator can add their own Mac or Linux machine to a small
fleet, run a remote agent, and recover from a network interruption without manually
copying cluster secrets or editing addresses, rosters, or service files.

## Repository refresh: 2026-09-17

The architecture recommendation still stands; the sequence below now includes the
Devices UI, authentication, and its deployment worker. Compared with the original
baseline, the fleet CLI, credentials/profile implementation,
runtime launcher, foreground service bridge, updater, roster dialer, and release
workflow are unchanged; the only movement in those areas is the machine-label helpers
in `cluster.ex` cited below. There is still no Tailscale discovery adapter, SSH
admission flow, or service installer. Existing interrupted-profile staging recovery is
a local `fleet create` feature, not the proposed multi-machine operation journal.

The relevant changes are now part of the plan:

| Current evidence | Consequence for this implementation |
|---|---|
| Both package manifests now say `0.1.8`; `Cluster` still requires protocol revision 5 plus exact Ouroboros/OTP versions | Derive the selected release and compatibility tuple from actual binaries/runtimes. Revision 5 alone cannot establish compatibility or feature readiness. |
| `Cluster.roster_labels/0` and `default_machine_label/1` preserve operator names and distinguish unnamed peers by host | Reuse that label contract, including offline/unprobed peers; keep network addresses separate from friendly names. |
| `priv/ui/commands.json`, web command gates, and rebindable TUI actions now coordinate command discovery | Register Devices in the shared catalogue and existing navigation; gate actions by actual backend capabilities, scope and identity. |
| Web mutations use `Web.Call`, gateway method permissions and `Audit.Identity`; call logging hashes request parameters | Add explicit fleet administration permissions and redact authentication responses before any logging or hashing. Existing generic parameter digests are unsuitable for passwords. |
| Images now use an owner-local attachment service routed through `attachment.*` | Preserve accepted attachment state through restart/removal, and test remote owner routing without assuming a shared filesystem. |
| `make release-tarball` now builds `wasm` and `media`; release smoke checks `ouro-media` | Validate the complete packaged runtime and its helpers under the service environment, not just the `ouro` executable version. |
| `runtime.shutdown` stops the node unconditionally once the launcher sets `OUROBOROS_GATEWAY_ALLOW_SHUTDOWN=1`; `ouro stop` checks no activity first | The idle gate is new work: a bounded `runtime.activity` summary and a `require_idle` shutdown, defined under "Installation and service lifecycle". |
| `Audit.Identity`'s private `required_role/2` maps every read-scope method to `operator`, and with no identities configured every check passes | Add the first read-scope administrator rule for tailnet inventory and the `fleet.deployment.` operate prefix; run authorization acceptance with identities configured. |
| The web endpoint knows `bind`, `allow_remote` and `origin` only; its documented remote posture is `tailscale serve` in front of the loopback bind | Decide credential entry on the bind, never on forwarded headers; refuse it on a cleartext non-loopback bind. |

The runtime's fleet protocol is still **5** (`@fleet_protocol_revision` in
`lib/ouroboros/cluster.ex`). Two other places disagree with it: `docs/FLEET.md` still
calls it **3**, and `ouro fleet protocol` prints a hardcoded **2** (the
`FleetCommand::Protocol` arm in `tui/src/main.rs`). Three numbers for one revision is a
defect independent of this proposal. Fix it as a standalone prerequisite change before
slice 1, not in the documentation slice: make the command print the revision the
runtime advertises, add a release-smoke assertion that the two agree, and correct the
document. That prerequisite is also the seed for the build-metadata output this
proposal needs (see "Current implementation to reuse"). The new admission commands
and flags in this proposal remain unimplemented. The refresh is based on source and
test inspection, not a new fleet deployment or test run.

## Product decision and scope

Use the installed Tailscale client for connectivity, including clients already
registered with Headscale. Use ordinary OpenSSH over that private network for setup.
Keep the existing TLS-protected BEAM cluster as the runtime transport. A Devices
section in web and TUI offers discovery and deployment, with CLI commands using the
same setup engine. A temporary deployment worker exits when finished; fleet operation
does not depend on keeping the UI or that worker open.

This deliberately revisits the enrollment portion of [core.md, D4](core.md#3-the-four-decided-cuts).
That historical reduction remains a useful scope constraint:
this proposal adds operator-side setup with a UI, without a permanent fleet control
service or public enrollment listener.
The earlier fleet implementation should be treated as reference material, not restored
wholesale. Existing manual fleet and private-network workflows remain supported.

| Included in the first release | Deferred |
|---|---|
| macOS and Linux, ARM64 and x86-64 where an official matching Ouroboros artifact exists | Windows, unsupported Linux runtimes, mobile nodes |
| One existing Tailscale or Headscale network with OS-bindable IPv4 addresses | Embedded VPN, userspace-only networking, IPv6 distribution |
| Local setup, adding a second or third machine, repeatable repair and cooperative removal | Cloud provisioning, account creation, managed Headscale/DERP hosting |
| OpenSSH as bootstrap authority, with SSH agent, host-local key and one-use password authentication | Invitation codes, public enrollment endpoints, enabling Tailscale SSH, MFA/keyboard-interactive login automation |
| Installing a missing Ouroboros binary from an exact official release | Updating an existing fleet or replacing unrelated installations |
| Ouroboros user service installation and observed readiness | Root agents, privileged macOS boot daemons, automatic OS policy changes |
| Web/TUI Devices inventory, Deploy workflow, authentication prompts, progress and recovery; equivalent CLI onboarding | Bulk deployment, persistent credential vault, browser private-key uploads and general SSH administration |

The intended validation envelope is 2–5 trusted machines, not a hard cluster-size
limit. One designated operator machine retains the fleet CA key and the
SSH target mapping for setup. It must be available to admit another member, but is
not required for connectivity or work among other running members. Back up its existing
private data using the current operator backup practice; automatic authority migration
is outside this version.

Use the supported artifact matrix in [RELEASING.md](../RELEASING.md#platforms-and-prerequisites):
currently macOS 15+ and the Ubuntu 24.04 / glibc 2.39+ GNU/Linux baseline on ARM64 or
x86-64. Preflight must check OS/runtime-library suitability, not just `uname` and
architecture. A system Tailscale client working on a host does not establish that an
Ouroboros release will run there. Re-read the matrix when implementation starts.

**Prerequisites are visible:** Tailscale is installed, both devices are signed into
the intended network, and the target exposes an accessible ordinary SSH server for
its intended non-root runtime user. Credentials can be supplied in the deployment UI;
a successful manual SSH login is not a required onboarding step. If a prerequisite
is missing, show its installation/login/access guidance and allow the same workflow
to be resumed. Ouroboros does not install a system VPN, switch an
existing account, collect network admin keys, or edit network-wide access policies.
Headscale support means using an already configured client; its server remains
independently operated. [Tailscale CLI](https://tailscale.com/docs/reference/tailscale-cli),
[Headscale registration](https://headscale.net/stable/usage/getting-started/).

## Devices UI and deployment experience

Add **Devices** to the web navigation at proposed route `/devices`, and to TUI
navigation/command discovery. Link it from the existing Runtime settings and status
surfaces. This is part of v1, including the deployment action and authentication form;
a device list that only prints terminal commands does not meet the requirement.

### Inventory

Show **Fleet devices** and **Available on this network** in the same section. Merge
known fleet members with the peers visible to the deployment host's installed
Tailscale client; retain known members when discovery is unavailable. This is the
client's visible peer set, which network policy may limit, not a promise to list every
device registered with the coordination server. Do not request a Tailscale/Headscale
admin API key or scan arbitrary network addresses.

Each row shows the friendly name, OS when reported, private address, network presence
with observation time, and a separate Ouroboros state/action:

| Observed state | Primary action |
|---|---|
| Discovered peer; Ouroboros installation unknown | **Deploy Ouroboros** opens preflight; do not label it uninstalled until inspected |
| Known compatible fleet member | **View device** with readiness, service state and explicit diagnostics |
| Deployment waiting for input, interrupted or partially complete | **Continue setup** for the existing operation |
| Known member disconnected from this runtime | **Diagnose**; disconnected does not establish that the host is powered off |
| Peer offline, unsupported platform, or no usable IPv4 | Explain the blocker and offer refresh/details; disable deployment while the blocker is established |
| Current device without a fleet profile | **Set up this device** locally, without SSH to itself |

Offer refresh, search by name/address and a fleet/available filter. No selection or
refresh authenticates to every peer. Discovered OS/online hints remain provisional
until selected-device preflight; unknown OS does not by itself disable inspection.
Network discovery failures have distinct empty states: client missing, signed out,
permission denied, unavailable data, or no visible peers. Manual destination entry
uses the same selected-peer/address validation; retain the existing manual fleet CLI
for private-network configurations outside this adapter.

### Deploy a selected device

1. **Select and connect.** Show the device name/private address and the permanent
   header `Deploying from <deployment host> · local user <account>`, filled from the
   actual host and account rather than an example.
   Ask for the target SSH username; expose port (default 22), identity selection and
   installation/data paths as advanced fields. Never infer the target account from
   the Tailscale owner. Verify an unknown SSH host fingerprint before sending a
   password or using a key; known verified hosts skip that prompt.
2. **Authenticate.** Offer an available SSH agent or key on the deployment host, or
   **Password for this connection**. Explain unavailable choices and show inline,
   actionable errors. Request an encrypted key's passphrase only when needed. The
   operator can change method without restarting discovery. No secrets are needed
   when existing approved SSH access already works.
3. **Inspect and review.** Inspect only the selected target and any current members
   whose rosters need updating. Display release, machine name, paths, startup behavior,
   affected members, required idle-runtime restarts and the broad fleet trust grant.
   If the local device is not configured, include its setup in this same plan. The
   **Deploy Ouroboros** confirmation applies this concrete plan; changed facts require
   renewed review. A discovered existing compatible installation is verified/adopted
   only with explicit approval; an incompatible installation blocks this flow.
4. **Follow progress.** Show inspect → install if missing → configure membership →
   configure startup → connect → readiness, with per-device results and bounded,
   sanitized details. Authentication and host-verification requests pause the relevant
   step. Prevent duplicate submission with a stable operation ID. Closing the drawer
   or leaving the page does not cancel the operation; the Devices row retains it.
5. **Finish or recover.** Offer **Open device**, **Configure model**, or **Run test task**
   according to observed readiness. Failures show the completed steps, concrete cause
   and **Retry/Continue setup**. **Cancel setup** stops at a safe boundary and reports
   any residue; it does not claim to undo credentials already delivered. Model setup
   opens the selected owner's existing supported settings, or names a required local
   step when that surface cannot configure the owner.

TUI uses the same inventory, fields, confirmations, challenge types and progress
states, with masked secret entry and keyboard navigation. Web forms have visible
labels, accessible error associations, focus restoration after dialogs and a polite
live region for step changes; do not communicate state by color alone. A read-only
endpoint can inspect permitted status, but shows why deployment/authentication is
unavailable. Both surfaces distinguish unavailable backend capability from denied
permission. First-task/model calls remain explicit actions.

## Authentication and deployment authority

### Which machine performs the work

Discovery, SSH, artifact verification, certificate issuance and roster writes run on
the designated CA-holding deployment host. For the web UI, that is the machine hosting
the connected Ouroboros runtime, **not the browser's machine**. Its SSH configuration,
keys, agent availability and Tailscale visibility apply. A browser cannot implicitly
use its laptop's SSH agent or resolve a key path on that laptop. A connected TUI also
uses the selected runtime's deployment host; standalone local fleet CLI commands run
on the machine where invoked. Always identify that host before credentials are entered.

A non-issuer runtime may display fleet status, but cannot deploy by secretly forwarding
its browser session or credentials through the cluster. Explain that the operator must
open Devices on the designated deployment host. First setup designates the local host
and creates its authority as part of the reviewed plan. There is no automatic CA
migration or arbitrary choice of a different execution host in v1.

### SSH methods and host verification

| Method | Experience and lifetime |
|---|---|
| SSH agent | Select an available identity by label/public fingerprint on the deployment host. No private key is exported or agent forwarded. An unavailable service-session agent is shown as unavailable, with key/password alternatives. |
| Existing private key | Select a configured host-local identity or explicitly supply an allowed local key path. Validate ownership/permissions and show public fingerprint only. An encrypted key requests a masked passphrase for that authentication attempt. |
| SSH password | Enter the target account's password in a masked field when needed. Use it only for this target/user/operation; discard after the attempt. Password-disabled servers produce a clear key-required result. |

Passwords and key passphrases are different prompts, labelled with their target or
key. No “remember password”, private-key upload, saved passphrase, `sudo` prompt, SSH
server reconfiguration or account/key installation is included. Password authentication
uses the SSH password method; keyboard-interactive/MFA and hardware-specific interactive
flows are unsupported unless they already work through an available agent without new
prompt types. Report the requirement; never downgrade authentication or change the
target's policy. Each current roster member may require its own authentication during
admission; do not reuse another host's password or assume one username fits all.

Present an unknown host's algorithm and SHA256 fingerprint with the selected peer,
address, port and account; offer **Trust this host and continue** and **Cancel**, with
guidance to verify the fingerprint independently. Record explicitly accepted trust
in a private deployment-host known-hosts store; honor existing trusted/revoked host
records and never override a conflict. A changed fingerprint blocks deployment and
requires a separate verified repair. Discovery is not host-key authentication.
Host trust is a separate explicit action even during a dry run; `--yes` never accepts
an unknown/changed key. OpenSSH supports explicit first-use confirmation and refusal
of changed keys. [OpenSSH host verification](https://man.openbsd.org/ssh_config#StrictHostKeyChecking).

Use the system OpenSSH client with a packaged, narrowly scoped askpass bridge for
password/passphrase entry when no terminal is attached. The bridge exchanges typed,
operation-bound challenges over private local IPC, subject to the secret-placement
list under "Secret handling and authorization". OpenSSH's
`SSH_ASKPASS_REQUIRE=force` supports invoking such a helper without a display; verify
support on each shipped platform. Keep authentication input separate from framed
remote-helper stdin. [OpenSSH askpass](https://man.openbsd.org/ssh#SSH_ASKPASS_REQUIRE).

Normalize challenge labels rather than rendering arbitrary remote prompts as trusted
UI. Bind every response to its initiating authenticated subject/session, operation,
target identity, user, method and expiring single-use challenge ID. Reject replay or
responses from another session. Retry only after explicit input, cap password attempts
per connection (at most three, respecting stricter server limits), and return a clear
result after timeout/cancellation. Select intended identities explicitly so an agent
does not exhaust the server's retry budget by offering every key.

### Secret handling and authorization

Retain only host/user/port, identity reference, public fingerprints, trust decisions
and operation receipts. Passwords/passphrases pass directly from masked input to the
waiting authentication process, are never echoed or broadcast, and are not retained
for reconnection. Clear form values immediately after submission and discard transient
copies when consumed, cancelled, timed out or disconnected. Minimize and zeroize native
buffers where possible; do not promise perfect erasure from browser/BEAM memory.
If another SSH connection needs authentication, prompt again; ongoing authenticated
connections may continue without retaining the secret. Do not add identities to an
agent/keychain automatically.

Use the existing authenticated browser/gateway boundary, adding explicit administrator
authorization for network inventory, SSH inspection, credential challenges and all
deployment mutations. Today the private `required_role/2` in `Audit.Identity` maps
every read-scope method to `operator` and demands `administrator` only for a fixed
prefix list under operate scope, so this needs two additions: the `fleet.deployment.`
prefix in that operate list, and a first read-scope administrator rule for
`fleet.devices` inventory.
With no identities configured every check passes and the local owner is the
administrator, so these gates only bite once identities exist; the authorization
acceptance items run with identities configured. Existing fleet/readiness summaries
retain their current read permissions; a read endpoint cannot start setup or submit a
secret. Revalidate identity, role and operation ownership on each action and at
mutation boundaries; revocation pauses future steps. Only the already authorized local
restart transition described below can complete while the broker is down. These
operations are not agent tools or model-visible prompts.

The new secret-input path must retain authentication, scope, origin/CSRF checks and
audit attribution, while logging only allowlisted metadata such as operation ID,
challenge kind, target and outcome. This is the one list of places a secret may never
appear, and every other section defers to it: command arguments, environment variables,
helper scripts, browser storage, URL/query strings, cookies, LiveView assigns and
serialized state, operation journals and receipts, telemetry, error text, audit
payloads, `Web.Call` and gateway parameter digests, and diagnostic/support exports.
`Web.Call` and the gateway currently digest generic parameters: never pass raw
authentication responses into those digests, even hashed. Add redaction before
hashing/logging across web, gateway, audit and error paths; Phoenix's existing
parameter filter alone is insufficient, and new fields including passphrases must be
covered. Submit a secret only in response to its challenge, without form-change events
that stream keystrokes to the server. Test rejection/error paths as well as success.

Decide credential entry on the web endpoint's bind, the only transport fact the server
can verify. The endpoint knows `bind`, `allow_remote` and `origin`
(`Ouroboros.Web.Config`); it ships no TLS, and its documented remote posture is
`tailscale serve` or an operator's reverse proxy in front of the default loopback bind.
A loopback bind therefore permits secret entry whether the browser is local or reaches
the endpoint through that TLS front, because the server sees the same loopback peer in
both cases. A non-loopback bind under `OUROBOROS_WEB_ALLOW_REMOTE=1` is cleartext by
definition: Devices renders read-only status there and states that credential entry is
refused on a cleartext bind. Forwarded/proxy headers play no part in this decision; a
client-supplied header never establishes transport safety. A declaration that a
non-loopback bind is TLS-terminated elsewhere is out of v1. Keep the operator gateway
loopback-only and do not open listeners or configure TLS exposure during setup. The
fleet's BEAM membership does not itself authorize web access.

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

# Gracefully take a reachable member out of the fleet from here, retaining its work
# and session history: the remote form of today's local `ouro fleet leave`.
ouro fleet leave --machine buildbox
```

`setup` and `add` offer `--dry-run` to inspect and print an action plan without writing
fleet state or installing software. An interactive application shows one concrete plan
before mutation: target identity/user, resolved private address, version, paths, service
behavior, affected roster members, and any required idle-runtime restart. Acceptance
also explains that joining grants broad authority between the fleet's machines.
SSH host verification and authentication use the same challenge flow described above.

For a new runtime, propose a user service by default when its prerequisites are met;
`--no-service` selects explicitly labelled manual startup. If a supervisor is unavailable,
require that choice or completion of the prerequisite, rather than silently promising
automatic recovery. Preserve an existing correctly configured runtime supervisor.

For automation, `--yes` accepts the same resolved actions after preflight; it never
bypasses host verification, authentication, runtime activity, version, ownership, or
network checks. Noninteractive use requires pre-established host trust and usable
noninteractive authentication. No password/passphrase command-line flags: the existing
`no_subcommand_accepts_a_token_on_the_command_line` test in `tui/src/cli.rs` already
lists `fleet service install --token` as a line that must fail to parse; extend it with
`fleet add`/`fleet setup` and `--password`/`--passphrase` spellings. Read-only
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
2. Verify the selected SSH host, authenticate, then verify its network identity and private
   address, inspect its OS/architecture, runtime state, installed version and data path.
3. Prepare the action plan. If Ouroboros is missing, include installation of the exact
   operator release for that architecture. An incompatible existing installation gets
   a specific manual upgrade instruction; it is not replaced by this workflow.
4. Create the target's own key locally on the target, issue its certificate on the
   operator machine, and transfer only the materials that target needs.
5. Install its profile and the required roster entries, configure the requested user
   service, and start the runtime. Check actual mutual cluster connectivity.
6. Report `connected`, then separately report provider/tool/workspace prerequisites
   on the selected remote owner, plus optional feature availability such as images.
   Offer an explicit first-task check in an operator-selected scratch workspace.
   A real model call runs only when the operator requests it; report the observed result.

The final display names the next step, for example `Connected; configure a model on
buildbox`, or `Connected; test task completed on buildbox`. A listener or reachable SSH
port is insufficient to report that an agent ran successfully. Existing credentials,
repository contents, SSH agents, model accounts, and grants are not copied as setup
material. Normal workspace transfer remains the existing fleet subagent feature.
Managed image content uses the existing owner-routed attachment service, separately
from repository transfer. Setup must neither copy the operator's attachment store nor
interpret a remote workspace path as a destination on the client machine.

## Current implementation to reuse

| Existing code | Role in this version |
|---|---|
| `tui/src/fleet.rs`: `create`, `create_from`, profile locks, TLS validation, EPMD ownership | Keep manual commands; factor shared credential/profile validation for the new path |
| `tui/src/cli.rs`, `tui/src/main.rs` | Thin command dispatch and operator workflow entry points |
| `tui/src/main.rs`: `service_run`, authenticated stop | Reuse foreground runtime ownership and graceful termination |
| `tui/src/runtime.rs` | Keep spawn locks, private data directories, publication/owner checks, environment filtering |
| `tui/src/update.rs`, `update/transport.rs`, `update/install.rs` | Extract only reusable pinned artifact download/verification primitives |
| `lib/ouroboros/cluster.ex`, `cluster/roster_epmd.ex` | Preserve reconnect sweeps, live roster reload, and runtime compatibility semantics |
| `tui/src/ui/app/cluster.rs`, `ui/app/mod.rs`, and `ui/app/settings.rs` | Reuse cluster summaries, `App::machine_label`, and the existing Runtime settings section |
| `lib/ouroboros/web/router.ex`, `web/presentation.ex`, `web/status_live.ex`, `web/live/deck_live.ex`, `web/live/new_session_live.ex` | Add Devices navigation while reusing friendly machine/refusal labels, status, vitals, and destination choices |
| `lib/ouroboros/web/call.ex`, `web/config.ex`, `lib/ouroboros/gateway/methods.ex`, `lib/ouroboros/audit/identity.ex` | Add local deployment methods, administrator checks, secure secret input and audit redaction without bypassing existing endpoint permissions |
| `lib/ouroboros/gateway/conn.ex`: `runtime.shutdown`; `tui/src/main.rs`: `stop`, `fleet protocol` | Add `runtime.activity` and the `require_idle` refusal; both stop paths check no activity today. Correct and extend `fleet protocol` as the build-metadata command |
| `priv/ui/commands.json`, `tui/src/keymap.rs`, `tui/src/ui/app/overlays.rs`, `lib/ouroboros/web/commands.ex` | Keep any new surface action discoverable, correctly gated, and rebindable |
| `lib/ouroboros/attachments.ex`, `attachments/normalizer.ex`, gateway `attachment.*` methods | Reuse owner routing and feature availability; preserve durable attachment manifests/content |
| `Makefile`, `scripts/release-smoke.py`, `scripts/test-release-packaging.sh`, `.github/workflows/ci.yml` | Extend current complete-package and containment checks rather than creating a second packaging path |

The current runtime contract is fleet protocol revision **5**, Ouroboros version,
and OTP release (`Cluster.runtime_compatible?/2`). Architecture is inventory, not a
compatibility barrier. Check the running runtime as well as the installed binary:
replacing a file does not replace a running BEAM process. `ouro fleet protocol` is the
existing command that answers without starting a runtime; once its hardcoded `2` is
corrected (see the refresh notes), extend it with `--json` output carrying the
revision, the Ouroboros version and the OTP release, read from build metadata that
release packaging writes beside the embedded tarball if the tarball does not already
carry it, and let the remote helper's `inspect` reuse it. Source version `0.1.8` is
the refresh baseline, not a hardcoded version for future deployment. Optional gateway
methods and owner-local capability answers are separate checks from fleet compatibility;
do not infer image, model, or sandbox support from the protocol revision alone.

Proposed Rust modules: `fleet_network.rs` for discovery and diagnostics,
`fleet_setup/` for SSH orchestration, askpass, worker IPC and its resumable operation
record, and `fleet_service.rs` for user services. Proposed web additions are
`lib/ouroboros/web/live/devices_live.ex` and a runtime-local deployment broker; these do
not exist yet. Keep SSH/install logic in the shared Rust engine and the broker focused
on authorization, challenges and progress. Keep these dependencies out of the agent
loop and BEAM formation path. Avoid a generic provider framework for one adapter.

## UI backend and operation lifecycle

The web/TUI frontends call typed runtime-local methods; they do not construct shell
commands or perform filesystem/SSH operations inside a LiveView callback. Proposed
method names and shapes must enter the normal wire schema, capabilities and permission
registry before either surface advertises them:

| Proposed method family | Purpose and access |
|---|---|
| `fleet.devices` | Bounded discovery snapshot, deployment-host identity/capabilities and observed device states; read-scoped but administrator-only for tailnet inventory |
| `fleet.deployment.prepare` | Start selected-device inspection, emit any auth challenges and produce a versioned, expiring action plan; operate plus administrator |
| `fleet.deployment.start` | Accept the inspected plan ID/digest and idempotency key, recheck it, then return an operation ID promptly; operate plus administrator |
| `fleet.deployment.status` | Sanitized durable steps and pending challenge metadata for an authorized operation owner; read scope cannot obtain or answer secrets |
| `fleet.deployment.authenticate` | Single-use secret response using the dedicated non-retaining, redacted request path; operate plus administrator and initiating-session binding |
| `fleet.deployment.confirm_host`, `.cancel`, `.resume` | Explicit host trust, safe cancellation and identity/state-checked recovery; operate plus administrator |
| `runtime.activity`; `runtime.shutdown` with `require_idle` | Bounded, non-secret owner-local activity summary at read scope, and the idle-gated stop the restart transition uses; defined under "Installation and service lifecycle" |

Existing `fleet.status` remains the read-compatible membership summary; non-admin
readers see that subset in Devices without tailnet inventory or authentication controls.
No deployment method routes through a remote BEAM owner: the endpoint's verified local
worker is the only executor. Return stable reason codes and advertised capability
flags so older runtimes render status with a clear unavailable-action explanation.

Inspection creates an operation ID before the first challenge; starting deployment
continues that operation. Long operations return promptly and expose bounded progress
updates, rather than occupying `Web.Call` until its timeout. Use states `inspecting`,
`awaiting_host_trust`, `awaiting_auth`, `awaiting_review`, `deploying`, `restarting_host`,
`checking_readiness`, `completed`, `interrupted`, `failed` and `cancelled`, with per-step
outcomes and explicit residue. A UI disconnect or request timeout means the result is
unknown until the operation is queried; it must not launch a duplicate deployment.

Run one temporary Rust worker per active issuer operation, independently of the web
request, LiveView/TUI session and BEAM runtime. Independence is a spawn mechanism, not
a promise: a worker started as a BEAM port child dies with the port when the runtime
stops. The broker therefore starts the worker through the `ouro` launcher's existing
detached path in `tui/src/runtime.rs`, which already calls `setsid` on every spawn,
with its own process group, stdio on private logs and no inherited port descriptors,
and then connects to it; the broker never owns the worker's lifetime. Use a private,
same-user authenticated local IPC channel, with verified executable/data-directory/worker
ownership and size/time limits; no TCP listener or arbitrary command API. Reconnection
must verify the worker instance and operation, not trust a recycled PID. The secret-free
operation journal is the durable authority for completed steps; IPC authentication
material, if needed, lives separately in a private short-lived capability file and is
removed on exit. Do not hold issuer mutation locks while an abandoned inspection waits
indefinitely: expire its challenge/plan and release it after a bounded idle timeout.
Inspections may run concurrently; mutations serialize at the issuer as described under
"Enrollment, rosters, and interrupted work".

This worker must survive the **planned restart of the runtime serving the UI** during
first local fleet setup. Before stopping that runtime, record the accepted local
transition and reconnect information. The worker performs only that bounded authorized
stop/profile/start transition while the broker is absent; subsequent remote mutations
wait for restored authority checks. During the transition the worker is the process
that holds the runtime spawn lock and the stopped-fleet mutation lock, the same locks
`ouro stop` and `fleet create` hold today, and it runs as the data directory's owner.
The UI shows the expected interruption, reconnects to the same endpoint, reauthenticates
if necessary and reloads the operation. Test the same behavior for a connected TUI. Do
not ask the operator to finish a normal UI setup in a terminal because the deployment
coordinator died with its own runtime.

Navigation alone does not cancel work. A lost authentication session invalidates its
pending challenge and drops any unconsumed secret; the operation can finish an already
authorized step, then waits if more authority/input is needed. A newly authenticated
authorized operator can explicitly resume with a new challenge after ownership/state
checks. Worker crashes recover by receipts; no password can be recovered from disk.
On explicit cancellation, finish or reconcile the in-flight durable step, reap SSH
children, report residue and exit. Exit the worker on completion or bounded abandonment;
the normal fleet needs no deployment process afterward.

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

Carry the operator's `--machine` name consistently through the target profile,
`OUROBOROS_MACHINE_NAME`, and every member's roster. Current cluster behavior uses the
roster name before the first successful probe and the peer's reported name afterward;
an unnamed peer falls back to the host half of its node name. Existing TUI/web helpers
apply friendly labels. Keep these labels distinct from the peer ID, overlay IP, SSH
destination, and BEAM node used for validation. A reconnect must not replace `buildbox`
with a numeric IP or label two different hosts with the shared release name `ouro`.

A normal Wi-Fi/hotspot transition should preserve this identity and reconnect. A
device re-registration that changes its overlay identity/address needs explicit repair;
v1 must report it rather than silently rewriting node names and certificates. No
automatic public-address fallback, subnet-route changes, or proxy transport is added.

Use the ordinary OpenSSH client, with normal host-key verification and the deployment
host's local SSH configuration. Inspect the effective destination, require the selected
overlay address for this path, and reject unsupported proxy/jump routing in v1 with an
explanation. Never disable strict host checking, enable agent forwarding, or copy SSH
private keys. Unknown hosts require explicit host verification; changed keys refuse.
Peer discovery alone never authorizes issuing credentials.

Normalize effective SSH options so inherited forwarding, remote/local commands or an
unrelated multiplexed connection cannot bypass the selected target/authentication.
Reuse a connection only within the verified operation and host/user identity, using a
private operation-owned socket when needed. Do not forward an agent or automatically
persist a passphrase in a host keychain. Honor explicit identity selection and bound
attempts; do not treat a service process as having the interactive user's agent by default.

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
packaged metadata/helper and, where running, authenticated local runtime status. The
machine-readable build metadata is the extended `ouro fleet protocol --json` described
under "Current implementation to reuse"; do not start a distributed runtime just to
learn the OTP version. Validate that metadata against the embedded package in release
tests. Development builds remain on the manual path for v1.
Feature preflight uses the selected owner's actual methods and readiness replies,
including `runtime.providers`, `runtime.models`, and `attachment.limits` when exposed
at the current scope. Missing methods or unreadable replies mean unknown. A local
gateway's model account or image support does not establish the remote owner's.

For a third machine, preflight SSH access to every current member. Read and compare
their fleet identity and roster snapshots. Require compatible, reconciled snapshots;
if a member is unavailable or an operation is unresolved, stop before issuing new
credentials. Add the newcomer on every member and give it the complete agreed roster,
retaining tombstones. This is an explicit reviewed UI/CLI operation; it adds no roster consensus
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
reap them on the explicit cancellation defined under "UI backend and operation
lifecycle". A hard-kill recovery uses the durable records.
That preservation includes the owner's `attachments/` directory, recovery identity,
accepted manifests/content, and configured content-encryption material. Do not sweep
them as enrollment staging or copy them to the issuer. Incomplete client image bytes
may exist only in memory; recovery must follow the existing attachment contract rather
than promise that every unsent draft survives a process restart.

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

Use the current package shape: `make ouro` embeds a release built with both
`priv/wasm/ouro-wasm` and `priv/media/ouro-media`. Keep the release smoke's media
presence/executable check, and add service-context execution/feature checks where
appropriate. Image preparation additionally needs the existing normalizer's read and
network containment; on Linux, a present `bwrap` alone does not prove its namespaces
are usable. Report unavailable image preparation separately from basic fleet admission.
Do not disable containment or change AppArmor/user-namespace policy during setup.

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
No idle check exists today: `runtime.shutdown` stops the node unconditionally once the
launcher has set `OUROBOROS_GATEWAY_ALLOW_SHUTDOWN=1` (`Ouroboros.Gateway.Conn`), and
`ouro stop` checks nothing before calling it. The gate is therefore new work in two
parts. Slice 1 adds a read-scope `runtime.activity` method returning a bounded,
non-secret owner-local summary: running and queued turns, active attachment transfers
and normalizations, and connected operator clients, with `unknown` for anything the
runtime cannot establish. Slice 5 adds a `require_idle` parameter to `runtime.shutdown`
that refuses with a stable reason code when that summary is not idle; the worker's
transition always passes it. A session count or a listening port is not an activity
signal, and unknown activity cannot authorize an automatic restart. Preserve the
runtime's data and verify durable sessions and accepted image history after restart. A
running compatible fleet member needs no restart merely to learn a new member.

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
| Optional images | Owner method unavailable; normalizer/containment unavailable; selected model supported/unsupported/unknown |

An overlay ping does not establish that EPMD/distribution ports are allowed. Probe
actual application connectivity in both directions and name untested/unknown causes;
do not assert an ACL or firewall is responsible without evidence. Report exact needed
ports/addresses for operator policy changes. A relay is a valid connection, not a
failed setup. Only report connection path from fresh observed data; never infer it
from the presence of a configured relay region.

Read-only status should not contact every member over SSH automatically. Deeper remote
diagnostics are explicit and bounded. Reuse the existing runtime wire model for TUI/web
cluster observations; Devices and the CLI share the new local deployment diagnostics.
The authenticated Devices flow handles normal v1 setup directly; use CLI guidance for
unsupported/manual maintenance rather than as a substitute for the Deploy action.
Diagnostic exports include selected device facts only and redact
credentials, login URLs/tokens, and unrelated network inventory.

Link Devices from the existing TUI Runtime settings/Dashboard and web `/status`,
Settings runtime section, and deck machine labels. Preserve `runtime.status` as the
existing status destination; register the distinct `Devices` navigation action in
`priv/ui/commands.json`, gate
it through the surface's actual method/scope/state checks, and make any shortcut a
rebindable `Action`. Update both catalogue drift tests; a surface-specific action needs
the existing explicit rationale. Expose Deploy only when the actual local worker,
permission and method capabilities support it, and preserve read-scope behavior.
Human refusals use the existing presentation
translator while JSON retains stable reason codes.

For images, `attachment.limits` checks runtime availability on the requested owner;
model catalogue image support is a separate supported/unsupported/unknown fact. A text
task passing is not evidence of image input support. Reuse current attachment RPCs
and scope/owner checks for a requested image check; admission adds no new upload
protocol or automatic model call.

`fleet leave --machine NAME` is the cooperative, orchestrated form of three commands
that already exist and keep their meaning: `fleet leave` removes the local machine's
credentials after its runtime is stopped, `fleet members remove` edits one machine's
roster and records no tombstone, and `fleet sessions forget` records the tombstone that
lets the runtime retire offline owner evidence. The new form runs against a reachable
idle member: inspect session ownership, disable its managed supervisor, stop its
runtime through the idle-gated shutdown, verify it is disconnected, run `leave` on it,
then run `members remove` on every remaining member with resumable per-machine
receipts. It records no tombstone; the separate `sessions forget` decision stays
explicit because it can make sessions undiscoverable. The verb is `leave` with the
existing `--machine` selector rather than a new top-level `remove`, so it cannot be
read as a sibling of `members remove`. Retain all session/workspace/attachment data and
historical owner evidence; require explicit separate recovery/export/forget decisions
where that history affects session lists. Refuse automatic removal of active work.
Current text/NDJSON transcript exports render images as bracketed placeholder lines,
not a bundle of image files. Do not describe such an export as a complete backup or use
it to justify deleting an owner's private store. Making an image-inclusive backup/export
is separate work; cooperative removal retains the original data in place.

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
| 1. Network inventory and preflight | Tailscale adapter, discovery DTOs/fixtures, selected-peer diagnostics, `fleet protocol --json` build metadata, `runtime.activity`, owner readiness and dry-run plan | Correct missing/logged-out/limited-inventory states; reject wrong peer/network, unsuitable OS/library, occupied ports, incompatible package and unknown/busy owner without fleet mutation |
| 2. Deployment worker and authentication | Shared Rust engine entry point, private IPC/askpass bridge, typed local gateway methods, admin/scope gates, host trust and one-use credentials | Real SSH key/agent/password/passphrase cases work; retries, session binding, redaction and stale/replayed challenges are tested; the detached worker survives its broker's runtime stopping |
| 3. Local admission primitives | Target key/CSR, issuer-side leaf issuance, profile staging, typed SSH helper operations and receipts | No CA/source/target private key crosses its intended boundary; hostile CSR/path, replay/conflict, crash and duplicate cases fail or resume correctly |
| 4. Setup orchestration | `setup`/`add`, verified missing-binary installation, issuer operation lock, reviewed plan/idempotency, multi-member roster updates | A real second and third machine join; interruption at every durable stage is recoverable without lost roster edits or duplicate identity |
| 5. Startup and removal | User supervisor integration, network wait, `require_idle` shutdown, the detached worker's idle-runtime transition and cooperative removal | One runtime/EPMD owner; deployment host restart, reconnect, supported persistence and cleanup work on both platforms while retaining sessions and accepted images |
| 6. Devices web/TUI and completion | Inventory, Deploy/auth/review/progress/recovery views, keyboard/accessibility behavior, shared catalogue, owner readiness and explicit first-task check; CLI parity and updated docs | Complete normal onboarding from either UI without terminal handoff; read/admin/capability gates, names, remote deployment-host context and reconnect recovery agree across surfaces |
| 7. Packaged validation | Packaged worker/askpass plus current WASM/media gates, browser/TUI and secret-leak regressions, owner-routed images and real multi-network Tailscale/Headscale acceptance | The complete release checklist below passes with artifacts, versions and limitations recorded |

The protocol-revision prerequisite from the refresh notes lands first, as its own change.
Sequence 1 → 2 → 3 → 4 → 5 → 6 → 7. The first engineering checkpoint is one
Mac-to-Linux setup through real SSH and a system Tailscale client after slices 1–4.
Use its failures to refine service/UI work before expanding the supported environment
matrix. The second checkpoint is the complete Devices flow after slice 6, including
password entry and the hosting runtime's restart. UI and authentication are release
requirements, not a later enhancement. Do not expose incomplete admission commands or
Deploy buttons as production-ready mid-sequence.

Regression anchors now include `test/cluster_test.exs`,
`test/ouroboros/web/live/deck_machine_labels_test.exs`,
`test/ouroboros/web/presentation_labels_test.exs`, `tui/tests/fleet_triage.rs`, both
catalogue suites (`tui/tests/catalogue.rs`, `test/ouroboros/web/catalogue_test.exs`),
`test/ouroboros/gateway/attachments_test.exs`, `test/image_turn_integration_test.exs`,
and `test/browser/images.spec.js`. These are existing checks to preserve and extend,
not evidence that this unimplemented onboarding flow has passed. Use the current CI
toolchain and packaging recipe; its media build and containment setup are now part of
the relevant test environment. Regenerate protocol docs/goldens only when wire methods
or their documented shapes change.

Also extend `test/ouroboros/web/call_test.exs`, `test/ouroboros/web/auth_test.exs`,
`test/ouroboros/web/config_test.exs` (credential entry decided on the bind),
`test/ouroboros/web/live/deck_read_scope_test.exs` and
`test/audit/identity_execution_test.exs` (the read-scope administrator rule, with
identities configured), alongside gateway authorization tests and the `runtime.shutdown`
`require_idle` refusal. Add dedicated proposed `test/browser/devices.spec.js`, Devices
LiveView tests, TUI flow tests, and isolated SSH/worker fixtures. Test packaged askpass
lookup and private IPC under actual service environments, including the absence of an
interactive SSH agent. Update `docs/FLEET.md` with the shipped flow and current protocol
revision only when implementation lands.

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
   with the VPN unavailable, interrupt SSH and the worker at each commit boundary, and
   restart a runtime. Restore connectivity without duplicate nodes or lost journals.
   Target reconnection within 30 seconds after network reachability is independently
   confirmed in the test environment; report observed timing, not a universal guarantee.
5. **Supervisor behavior:** Linux survives logout/reboot when lingering is configured;
   macOS resumes after user login. Without the supervisor prerequisites, status names
   the limitation. Stopping/removing a service does not respawn it or affect another
   data directory's runtime. Verify tool/model access under the actual service context.
   Check the packaged WASM/media helpers and distinguish a missing helper from blocked
   host containment. Unsupported optional images must not prevent a text-only fleet.
6. **Failure integrity:** incompatible/missing artifacts, checksum mismatch, malformed
   metadata, changed SSH host keys, switched network, duplicate machine identity,
   existing unrelated installation, active work, symlinks, concurrent admissions and
   concurrent roster edits cannot cause a misleading successful setup or destructive
   overwrite. Rerun completed operations without additional credentials or services.
7. **Work and ownership:** retain and reopen an idle durable session across the initial
   standalone-to-fleet transition. Keep grants and model credentials node-local. Removal
   retains workspace and attachment data and explicitly reports unresolved session-owner
   evidence. Accepted image history remains readable after restart; incomplete drafts
   obey their existing persistence limits. Running/queued turns and active image
   preparation block an automatic restart/removal, with unknown activity reported.
8. **Runtime independence:** after setup, disconnect the operator machine while the
   other two communicate. Test coordination-server unavailability separately and record
   actual behavior; do not promise new admission or arbitrary reconnect without it.
9. **Distribution evidence:** run the relevant Rust/Elixir suites, meaningful helper and
   packaged lifecycle integration tests, supported-platform release smoke checks and
   hosted CI. A local mock, same-host TLS cluster, or successful build is not proof of
   cross-network deployment. No live fleet changes are part of writing this plan.
   Before publication, the test harness can supply exact packaged candidate artifacts;
   this must not introduce a production flag that bypasses release verification.
10. **Current UI contracts:** preserve the operator's machine name while offline,
    before its first probe, and after reconnect; distinguish unnamed hosts sharing the
    same BEAM release name. Existing TUI/web views agree on these names and unknown
    states. Catalogue, method/scope/identity gates and rebound shortcuts remain correct;
    Deploy is backed by a real local worker, and older/non-issuer runtimes explain why
    it is unavailable rather than advertising an inert action.
11. **Remote image regression:** where image preparation is available, upload a fixture
    from a client to a different session owner through the existing attachment methods,
    with no shared filesystem. Reopen accepted history after an owner restart and test
    owner outage without falling back to a local store. Use deterministic model fixtures
    to verify image delivery; any live multimodal run is separately requested and
    recorded. Report unsupported/unknown model input distinctly from network failure.
12. **Devices end-to-end:** in both web and TUI, select a previously unconfigured
    visible device, verify its host key, authenticate, review and deploy, observe
    readiness, then explicitly run a test task. Include first local fleet setup and a
    third member with a different SSH account. No terminal handoff is needed on the
    supported path. Verify empty, limited, stale and failed discovery; unknown
    installation state; offline known members; keyboard-only and accessible form use.
13. **Authentication matrix:** test an existing trusted host, unknown host confirmation,
    changed/revoked key refusal, available/missing agent, explicit key identity,
    encrypted-key passphrase, correct/incorrect password, password-disabled server,
    unsupported interactive auth, bounded retries and cancellation. Another host's
    password must never be tried automatically; private keys never leave their host.
14. **Web execution and authorization:** use a browser on a different machine and
    verify the labelled host's network/SSH identity is used. Test a local loopback
    browser, a remote browser through `tailscale serve` in front of the loopback bind,
    refusal of secret entry on a non-loopback `OUROBOROS_WEB_ALLOW_REMOTE=1` bind, and
    that forwarded/proxy headers change nothing. Run with identities configured: read
    scope, non-administrator identities, revocation, cross-session challenge replies
    and missing methods. Non-issuer views cannot forward enrollment authority or
    secrets through the fleet.
15. **UI recovery:** close/reopen the page during installation, lose the connection
    during authentication, restart the hosting runtime during first setup and kill
    the worker after a remote write. Recover the existing operation and receipts,
    request fresh credentials when needed, avoid duplicate installation/admission and
    show accurate partial results. Repeat for the connected TUI. Expired plans and
    simultaneous submissions cannot apply an unreviewed or conflicting plan.
16. **Secret non-retention:** inject unique test passwords/passphrases and inspect
    browser persistence/serialized state, process argv/environment, temporary files,
    journals, audit/log/error output and diagnostic exports after success, rejection,
    timeout, crash and cancel. Assert that generic parameter hashing never receives
    the secret, using instrumentation rather than only searching for plaintext.
    Authentication callbacks clear consumed buffers/forms and remove temporary IPC
    capabilities; cancellation reaps children without deleting retained user data.

The release claim is: **discover devices and deploy a small trusted Ouroboros fleet
from the web UI, TUI or CLI over an existing Tailscale or Headscale network**, with
guided SSH authentication, resumable setup and explicit service prerequisites.

## Implementation notes

Where the branch departs from the text above, the code is the record and this list
says why:

- The cooperative removal verb is `fleet leave --machine NAME --user USER`; the member's
  executable is taken from its admission record, with `--remote-executable` to override.
- A CSR that asks for names beyond the approved host is refused, not narrowed; the issuer
  never copies a requested extension.
- The operation namespace is `<data dir>/deploy/` (journal, socket, capability, request
  file, log), because `fleet/` is committed by one atomic rename and a setup journal has
  to exist before the fleet does.
- The broker lifts a challenge's kind-specific facts to the challenge itself; surfaces
  read `challenge["sha256_fingerprint"]`, not a nested object.
- The web binding is per browser tab (an id the page keeps in `sessionStorage` and sends
  on connect), so a reload or reconnect in the same tab keeps answering its challenges
  while a second tab is refused; the listener binding is per connection.
- `capabilities.deploy` is enforced by the broker (`deploy_blocked` with the blocker
  list), not only by which controls a page draws; a first local setup is exempt from the
  missing-CA-key blocker alone.
- `fleet.devices` member rows carry the runtime's live view (`connected`, `compatible`,
  `runtime_running`, `last_probe`) beside the network client's, and the journal list is
  ordered by creation time with a `total`.
- Readiness on a newly admitted member is reported unknown until a gateway method can
  ask that owner about its providers and models; `runtime.providers`/`runtime.models`
  describe the local runtime only.
- `runtime.activity` counts in-flight operate-scope method invocations and each
  session's own idle fence, with a 250 ms cache on the read verb and a fresh walk for
  the gate; `runtime.shutdown` refuses unknown parameters.
