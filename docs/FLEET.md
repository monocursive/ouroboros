# The fleet

A fleet is one BEAM cluster: several machines, one trust domain, sessions and native
subagents placed across it. Every machine that completes the distribution handshake has
unrestricted `:erpc` authority over every other one. There is no containment between
members, no per-member permission and no revocation: joining a VPS to your laptops means
a compromised VPS owns the laptops. The mitigations are perimeter and placement, never
containment, and a hostile connected node ignores every role check by calling whatever it
likes directly.

`OUROBOROS_NODE_ROLE` exists and defaults to `core`. `builder` and `signer` are placement
labels, not security boundaries; [ARCHITECTURE.md](ARCHITECTURE.md) says what each runs.

## 1. The trust model

One fleet is **one shared secret bundle**: a 64-hex cookie and a certificate authority key
pair. Every member holds all of it. Each machine mints its own leaf certificate from that
CA, on its own machine, with its own host in the subject alternative name, because OTP's
TLS distribution verifies the server certificate against the dialed host. A machine's
private key is generated where it lives and is never sent anywhere.

The CA key travels because saying otherwise would be a lie: any connected member can
already read every file this runtime can read, `ca-key.pem` included.

**A machine that is lost or compromised is answered by making a new fleet.** Run
`ouro fleet leave` on every machine you still hold, `ouro fleet setup` on one of them and
`ouro fleet add` for the rest; that rotates the cookie and the CA. Nothing else undoes a
credential already copied — no revocation list, no signed roster, no tombstone.

The roster is not replicated. Distribution is transitive, so a member that dials one node
it knows joins the whole mesh; each profile carries the members it knew when it was
written, as dial hints. Nothing writes another machine's profile, and a stale entry costs
a backed-off dial. Every fleet-wide surface is a read-time merge with unreachable nodes
named: not consensus, quorum or a partition policy.

`<data dir>/fleet/` holds, on every member:

| File | Mode | What |
|---|---|---|
| `profile.json` | 0644 | non-secret facts, schema 2 |
| `cookie` | 0600 | 64 lowercase hex |
| `ca-cert.pem` | 0644 | the fleet CA certificate |
| `ca-key.pem` | 0600 | the fleet CA private key. Shared |
| `node-cert.pem` | 0644 | this machine's leaf, CN `ouro-<machine>@<host>`, SAN `<host>` |
| `node-key.pem` | 0600 | this machine's private key, generated here |
| `ssl_dist.conf`, `vm.args` | 0644 | generated at create and join |

A node name is always `ouro-<machine>@<host>`. Back that directory up privately: those
credentials cannot be reissued from anywhere else. A private network is trusted
infrastructure this runtime does not verify.

## 2. The commands

```sh
ouro fleet setup   --machine NAME [--address IPV4] [--no-service] [--yes] [--json]
                   [--frames] [--dry-run] [--operation ID]
ouro fleet add     [USER@]ADDRESS --machine NAME [--port N]
                   [--key PATH | --agent FINGERPRINT | --ask-password]
                   [--install-path P] [--data-dir P] [--no-service] [--yes] [--json]
                   [--frames] [--dry-run] [--operation ID]
ouro fleet leave   [--machine NAME --user USER [--port N] [--remote-executable PATH]
                   [--key PATH | --agent FINGERPRINT | --ask-password]
                   [--yes] [--json] [--frames] [--dry-run] [--operation ID]]
ouro fleet forget  NAME
ouro fleet status  [--json]
ouro fleet doctor  [--json] [--peer NAME|ADDRESS]
ouro fleet devices [--json]
ouro fleet service install|status|disable|remove [--json]
ouro fleet tag     add|remove|list [--machine NAME]
```

**`setup`** gives this machine its cluster identity from its own private-network address
and arranges for it to start; `--address` overrides the address read from the network
client's report about this device. On a machine that already has a fleet it is an
inspection: it says what is there and changes nothing.

**`add`** brings another machine in over SSH with this fleet's bundle, contacting only the
destination given. That destination is `user@address`, where the address is the target's
private IPv4 or the name its network client reports; the account is never inferred from
the network device's owner, and `--machine` is required when the destination is an
address. `--install-path` (default `.local/bin/ouro`, under the target account's home) and
`--data-dir` say where `ouro` and its data go there.

**`leave`** with no flags removes *this* machine's own credentials after its runtime is
stopped. With `--machine NAME --user USER` it removes a reachable member cooperatively;
`--user` is enforced at parse time, so a missing account is not discovered after the plan
has been reviewed. `--remote-executable` names that member's `ouro` when it is not where
this machine's record of admitting it says.

**`forget NAME`** is the local answer to a machine that cannot be reached: it asks the
runtime to retire that machine's durable session-owner evidence, then takes the name out
of this profile's members. The runtime refuses while that machine is connected, and then
nothing changes. There is no undo — the command name is the operator's statement — and the
roster is not replicated, so run it on every remaining machine.

**`status`** prints the fleet name and id, this machine's name, address and node, the
runtime state, the member list, the gateway port and the distribution port. **`doctor`**
checks local security, and live connectivity and compatibility when a runtime answers.
**`devices`** lists members beside the devices this machine's network client can see.
**`service`** manages the one startup service; **`tag`** edits advisory labels.

`--json` prints a machine-readable result with stable reason codes, and incomplete setup
exits non-zero even when some steps succeeded. `--dry-run` prints the plan and changes
nothing: no journal, no credentials, no installation, no roster edit, no recorded host
trust. `--yes` accepts the resolved plan without a prompt; it never accepts a host key,
never answers a password and never makes a busy runtime idle. `--frames` is the NDJSON
front end in §7 and conflicts with `--json`, `--yes` and `--dry-run`.

Three commands are hidden because nobody should type them: `ouro fleet create`, the
primitive `setup` uses, kept for the lab; `ouro fleet helper`, the fixed command an
operator's `ouro` runs over SSH; and `ouro fleet askpass`, which OpenSSH runs as
`SSH_ASKPASS`.

## 3. What each operation does

Every externally visible step is written to `<data dir>/deploy/<id>.json` — mode 0600,
schema 2 — atomically before and after it happens. Before, so a process that dies mid-step
leaves the statement "this was attempted"; after, so a resume knows not to repeat it. The
journal holds no secret: a release is a version and a sha256, the plan is the lines an
operator read, an error is a stable reason and a sanitized detail. The request for an
operation is argv, and nothing on argv is a secret — an address, an account, a port, a
path, a key path, an agent fingerprint. A password never is.

**`setup`** reviews the plan, stops the running runtime through its idle gate, creates the
fleet, installs the startup service unless `--no-service`, starts it, then waits for the
gateway to publish a port. Steps: `stop_runtime`, `create`, `service`, `start`, `ready`.

**`add`**, in order: inspect this host's effective SSH configuration before connecting;
verify the host key; authenticate and run the fixed preflight (OS, architecture, `$HOME`,
an existing `ouro`?); install the exact matching official release if the target has no
`ouro`; `hello`, and refuse a version that is not ours — `version_mismatch` names both
versions and the upgrade recipe, and nothing is replaced; `inspect` for an existing fleet
and a running runtime; **review**; install the bundle; install and start the service;
append the new member to *this* machine's list; then poll the target's own status for up
to sixty seconds until it reports the fleet connected. Steps: `install`, `inspect`,
`join`, `service`, `remember`, `connect`.

**`leave --machine`** verifies the host key, authenticates, greets the member, reviews,
then asks that member's own `ouro` to stop its runtime through its idle gate, disable and
remove its startup service and delete its `fleet/` directory — and finally takes it off
this machine's list. Steps: `stop`, `remove`, `forget`. A member that cannot be stopped
keeps its credentials and stays on this roster: a removal that only edited the local list
would leave a machine in the fleet the operator believes is out of it.

A resume is `--operation ID`, an id of 8 to 64 characters of lowercase letters, digits and
single hyphens:

```sh
ouro fleet add me@100.64.0.2 --machine buildbox --operation a1b2c3d4e5f6
```

A step recorded `ok` is not repeated, and an install onto a target already in this fleet
as this machine is `skipped`. Argv that contradicts the journal is `plan_changed`: a
resumed operation is the same operation, or it is a new one. Argv that is merely absent is
filled in from the journal's target and paths. Completed and cancelled journals older than
thirty days are pruned, newest fifty kept; failed, interrupted and in-flight work is left
alone.

## 4. Authentication

Four ways, and none takes a value on the command line, because a command line is readable
by every process on the host. The three flags conflict with each other.

| Flag | What it selects |
|---|---|
| *(none)* | this host's own default SSH identities, then — if the target accepts none and offers password authentication — that account's password, through the same masked prompt |
| `--key PATH` | one private key file on this machine, checked for ownership and permissions. Never copied; an encrypted key is asked for its passphrase |
| `--agent FINGERPRINT` | one identity held by this machine's SSH agent, named by its public SHA256 fingerprint. No agent is forwarded and no key is exported |
| `--ask-password` | the target account's password, typed into a masked prompt, for this operation only |

A password or passphrase travels only through the askpass bridge's private socket, in a
`Zeroizing` buffer that lives for one authentication attempt, and reaches no command line,
environment variable, journal, log line or error string.

**The host key is always a separate, explicit question**, showing its algorithm and SHA256
fingerprint. `--yes` accepts a reviewed plan and never a host key, never a password and
never a busy runtime. A changed host key blocks. A dry run still asks — a run that refuses
to connect cannot inspect anything — and its acceptance lasts only for that run. Without a
terminal each question is a refusal with a stable reason rather than a prompt nobody will
see, so noninteractive use needs pre-established host trust and key or agent
authentication. One SSH ControlMaster socket is reused per operation, so a password is
typed once and retried at most three times; a challenge nobody answers within five minutes
fails the operation `challenge_expired`.

## 5. Starting at login

`ouro fleet service` manages one startup service per data directory and nothing else on
the machine. The unit runs the foreground `ouro service-run` with an absolute path to this
exact `ouro` and an explicit `OUROBOROS_DATA_DIR`, never the detaching `ouro daemon`,
which a service manager reads as a crash and answers with a second runtime.

```sh
ouro fleet service install          # generate the unit and hand it to the manager
ouro fleet service status [--json]  # installed / loaded / running / last exit
ouro fleet service disable          # stop it and stop it respawning; keep the unit
ouro fleet service remove           # disable, then delete the one file this wrote
```

The path is deterministic per data directory:
`~/Library/LaunchAgents/dev.ouroboros.runtime.<digest>.plist` on macOS, or
`~/.config/systemd/user/ouroboros-<digest>.service` on Linux, where `<digest>` is the
first twelve hex characters of SHA-256 over the canonical data directory. The same data
directory always gets the same unit, and a unit installed by an earlier release is that
same file.

`install` refuses without a cluster identity, because `service-run` refuses to start
without one and a unit installed first would only crash-loop. It writes that one path and
overwrites the unit it wrote there before. A file at that path this code did not write is
reported with the digest of what is actually there and left alone: `install`, `disable`
and `remove` all refuse it (`unit_foreign`), and none of them touches any other unit. A
unit of ours that has been edited by hand since it was written is still ours — every unit
carries a line naming the data directory it serves and a digest of its own body — so
`install` refuses it `unit_modified` rather than overwriting the edit, while `remove` does
delete it and says in its output that the body no longer matched that digest. `remove`
deletes only the file this code wrote, after gating the runtime with the same idle check
`ouro stop --require-idle` applies and after asking the manager to unload it. `disable` is
the first half of taking a supervised runtime down:

```sh
ouro stop --require-idle
ouro fleet service disable
```

| Platform | What it does, and does not |
|---|---|
| Linux with `systemctl --user` | a user unit with `Restart=on-failure`, `RestartSec=5` and a `StartLimitIntervalSec=300`/`StartLimitBurst=5` ceiling, wanted by `default.target`. Surviving logout and starting at boot needs lingering, so `install` runs `loginctl enable-linger` once the unit is loaded; refused, `status` says this is a login-scoped service and names the administrator's step |
| macOS with a logged-in session | a LaunchAgent with `RunAtLoad`, `KeepAlive` restricted to unsuccessful exits, a 30 second `ThrottleInterval` and `ProcessType` `Adaptive`. It starts at login and stops with the login session: there is **no pre-login execution** |
| Anything else | `install` refuses with the prerequisite named and installs nothing. Start the runtime with `ouro daemon` and supervise it yourself |

The unit's environment is `HOME`, a fixed system `PATH` and `OUROBOROS_DATA_DIR`, and
nothing else: the rest is derived from the profile at every start, so a roster change
never leaves a stale unit behind and an `OUROBOROS_*`, `ERL_*` or `RELEASE_*` variable
exported in the shell that ran `install` reaches neither the unit nor the BEAM. Logs are
`<data dir>/service.out.log` and `service.err.log`, created 0600. `ouro service-run`
proves the profile's advertised address is bindable before it launches the BEAM, retrying
from one second to fifteen and writing `waiting for network` to the service log, so a
laptop that boots before its VPN waits visibly rather than looking hung.

## 6. Status, doctor, devices

`doctor` reports interrupted setup directories, the profile, the security material,
ephemeral-range overlaps, a stopped-runtime listener preflight, every member's address
resolution and the runtime's own state. `[ok]`, `[note]` and `[fix]` are the stable
levels; a problem exits non-zero. Neither command prints a secret, and both say the same
sentence about a profile written by an older Ouroboros (§12). The `--json` form of each
also carries this build's metadata — the Ouroboros version, the OTP and Elixir releases
the embedded release recorded, the OS and the architecture, with `null` rather than a
guess where there is no embedded release — and `status --json` carries the network
inventory beside it.

`--peer NAME|ADDRESS` probes the route to one visible device with a single overlay ping
and reports `reachable`, `timed_out`, `unknown`, `peer_unknown` or `peer_ambiguous`, with
the path `direct`, `relayed` or `unknown` — only ever the one observed, and a relay is a
valid connection. A member resolves through *your* profile, never through a peer's claim
to that name, and an address is probed only if this machine's client reported it for a
device. An overlay probe says nothing about the distribution port.

`devices` merges this machine's members with the peers the installed Tailscale or
Headscale client can see. It runs the client once with a fixed argument array, a five
second deadline and a bounded read; it contacts no device, opens no SSH connection and
writes nothing, so a discovered peer's state is `discovered_installation_unknown` rather
than uninstalled. `OUROBOROS_TAILSCALE` names a different client and must be an absolute
path to an executable file. A member row is matched to a visible device by the
**advertised host** alone; matching on a peer's hostname would let any device claim a
member's row by renaming itself, so a device that adopts a member's name is listed as the
separate device it is, with `name_conflicts_with_roster` in `--json`. Every `--json` row
carries `suggested_machine` for surfaces that offer a name — the member name, that
device's display name folded to a valid one, or `null` — and nothing is named by it until
a person submits it.

**Everything a peer reports is hostile text.** A hostname, a MagicDNS label, an OS string
and a last-seen time are written by the device reporting them, and unsanitized a hostname
is enough to forge a device row, clear the screen or scroll the real rows away. The human
output strips control characters and bidi overrides, collapses whitespace and truncates to
a column budget; `--json` keeps the raw values. Anything the client itself printed is
redacted first: `tailscale` writes `To authenticate, visit: <url>` on stderr when a node
key has expired, and that URL is a credential.

Discovery has six outcomes, each a stable `code` in `--json` with its own repair:
`client_missing`, `signed_out`, `permission_denied`, `unavailable` (with a `reason` such
as `backend_stopped`), `no_visible_peers` and `ok`. Members are listed even when discovery
fails — a client that cannot answer is not evidence that the fleet is empty — and a member
with no matching visible peer is `fleet_member_not_visible`, which is not the same fact as
powered off.

## 7. The frames front end

`ouro fleet setup|add|leave --machine … --frames` speaks NDJSON on its own stdin and
stdout instead of talking to a terminal. It is what the runtime's broker runs as a port
program, and it is documented rather than hidden so an operator can drive it too.

Out, one JSON object per line:

- `{"event":"state","state":"running|waiting|completed|failed|cancelled"}`
- `{"event":"step","step":"install","state":"ok","detail":"…"}`
- `{"event":"log","line":"…"}`
- `{"event":"challenge","challenge":"<id>","kind":"host_trust|password|passphrase|review","expires_at":"…","metadata":{…}}`
- `{"event":"done","state":"completed|failed|cancelled","operation":"…","summary":"…"}`

In: `{"op":"respond","challenge":"<id>","accept":true|false}` for `host_trust` and
`review`, `{"op":"respond","challenge":"<id>","secret":"…"}` for `password` and
`passphrase`, and `{"op":"cancel"}`.

The process calls `setsid` and ignores `SIGHUP` and `SIGPIPE`. Once the review is accepted
it needs nothing more from stdin: **on stdin EOF it finishes the operation, keeps writing
the journal, and stops writing to stdout.** That is how a local `setup` survives the
runtime it was started from, and it is the whole of "survives" — there is no reattach, and
what happened afterwards is in the journal. Stderr goes to `<data dir>/deploy/<id>.log`,
0600, scrubbed like the journal.

The helper at the far end of an SSH connection speaks its own line protocol,
`{"v":1,"id","op",…}` in and `{"v":1,"id","ok":…}` out, 1 MiB per line, 60 second idle
timeout, with the operations `hello`, `inspect`, `install`, `service`, `start`, `status`,
`leave` and `bye`. A frame may omit `v`; a `v` present and not `1` is refused. Nothing it
reads is executed, expanded or interpolated into a command line.

## 8. What the launcher sets

When `<data dir>/fleet/` holds a profile, `ouro daemon` computes the release environment
from it and **strips the caller's** — every `OUROBOROS_*` the operator exported, plus
`ERL_AFLAGS`, `ERL_FLAGS`, `ERL_INETRC`, `ERL_LIBS`, `ERL_ZFLAGS`, `ELIXIR_ERL_OPTIONS`
and every `RELEASE_*`. Exporting one of these beside a profile does nothing at all. This
table is the launcher's contract, not an operator path:

| Variable | Value |
|---|---|
| `OUROBOROS_DIST` | `name` |
| `OUROBOROS_NODE` | `ouro-<machine>@<host>`, from the profile |
| `OUROBOROS_NODE_ROLE`, `OUROBOROS_MACHINE_NAME`, `OUROBOROS_FLEET_ID` | from the profile |
| `OUROBOROS_COOKIE_FILE` | `<data dir>/fleet/cookie` |
| `OUROBOROS_BOOT_COOKIE_DECOY` | a per-boot disposable value, replaced from the private cookie file by `config/runtime.exs` before any cluster child starts, so the real cookie is never in argv or the environment |
| `OUROBOROS_CLUSTER_STRATEGY` | `epmd` — the roster dialer; the name is libcluster's |
| `OUROBOROS_CLUSTER_HOSTS` | every member node except this one |
| `OUROBOROS_CLUSTER_RECONNECT_MS` | `1000` |
| `OUROBOROS_DIST_TLS`, `OUROBOROS_DIST_TLS_OPTFILE` | `1`, and `<data dir>/fleet/ssl_dist.conf` |
| `RELEASE_VM_ARGS` | `<data dir>/fleet/vm.args` — how the generated file is read |
| `OUROBOROS_GATEWAY_PORT` | the profile's gateway port, bound to loopback |
| `OUROBOROS_DIST_PORT` | this node's distribution listener |
| `OUROBOROS_DIST_PORTS` | `ouro-studio@100.64.0.1=13700,…`, one entry per member including this one |

The generated `vm.args` carries `-proto_dist inet_tls`, `-ssl_dist_optfile`,
`-start_epmd false`, `-epmd_module Elixir.Ouroboros.Cluster.Epmd`,
`-kernel inet_dist_use_interface` and `-kernel inet_dist_listen_min P
inet_dist_listen_max P`, with P the profile's distribution port.

**Forming a cluster over cleartext distribution refuses the boot.** `config/runtime.exs`
reads the transport the VM is actually running rather than the one somebody intended, and
raises unless it is `inet_tls`/`inet6_tls`. `OUROBOROS_ALLOW_INSECURE_DIST=1` is the
deliberate override, and has to be typed on the host that wants it.

## 9. Distribution without EPMD

There is no port mapper. `Ouroboros.Cluster.Epmd` is the `-epmd_module`, loaded by the
boot script before kernel starts distribution because releases boot in embedded mode:

| Callback | Answer |
|---|---|
| `start_link/0` | `:ignore` |
| `register_node/2,3` | `{:ok, creation}` with a creation in 1..3; nothing is registered anywhere |
| `listen_port_please/2` | `OUROBOROS_DIST_PORT`, else `{:ok, 0}` |
| `port_please/2,3` | `OUROBOROS_DIST_PORTS`, tried as `name@host` then as a bare `host`, else `OUROBOROS_DIST_PORT`, else `:noport` |
| `address_please/3` | `:inet.getaddr/2` |
| `names/1` | `{:error, :address}` — there is no registry to enumerate |

A host arrives as a charlist, a binary or an IP tuple depending on the caller and is folded
to one spelling before the lookup. The map is re-read on every lookup rather than cached,
because the profile is the authority for membership; a malformed entry is ignored rather
than fatal, and the first entry for a key wins.

One firewall rule: allow the fleet's distribution port (13700 by default) between the
members' private addresses. The gateway port is loopback-only.

## 10. Devices, on the web and in the terminal

**The web page at `/devices`** runs the flow. One list — this machine first, then members,
then visible peers — one action per row, and a drawer that is a state machine over one
operation: fill a short form, verify the host, answer a password, approve a plan, watch it
run, finish or recover. There is no plan digest, no idempotency key, no takeover and no
per-tab binding: a challenge is answered by whoever is an administrator on this runtime,
so a second tab, a reload and the restart a local setup performs all answer the prompt in
front of them. Search and the filter appear only past eight rows. Closing the page cancels
nothing, and reopening at `/devices?operation=<id>` reloads that operation by id.

**The terminal view** (`ctrl+x D`, `/devices`, the palette's Devices row) shows the same
inventory, the same status line and the same words — and **runs nothing**. It issues
`fleet.devices` and `fleet.status` and draws what comes back; the one thing to do about a
row is printed as the command that does it, to be run on the deployment host:

```sh
ouro fleet setup --machine studio-mini
ouro fleet add USER@100.64.0.2 --machine raspberrypi
ouro fleet leave --machine pi --user USER
ouro fleet leave
```

`USER`, `ADDRESS` and `NAME` stay literal capitals wherever this runtime cannot name the
value: a device is not an account, and a plausible-looking account name in a command
somebody is about to run is the invention a deployment must not make for them. A line
under the list carries `ouro fleet add USER@ADDRESS --machine NAME` for a device the
network client never listed, and `Actions run on <host> as <account>.` sits under the
title, because the deployment host is the machine hosting this runtime and not the laptop
the client happens to be on. `↑↓`/`jk` select, `Enter` opens the details pane, `r`
refetches, `/` searches and `f` cycles all → fleet → available past eight rows,
`PageUp`/`PageDown` scroll without moving the selection, `Esc` or `q` closes. An operation
this runtime is already running shows read-only on its own row.

Both surfaces pass every device-supplied string through one scrubber, which drops what a
terminal would obey and the invisible code points that make one device name look like
another's, collapses whitespace and cuts the result to its column.

## 11. Gateway methods

All administrator-only, because this is every machine on an operator's private network. A
non-administrator sees `fleet.status`'s membership subset instead.

| Method | Scope | What it answers |
|---|---|---|
| `fleet.status` | read | machines, connectivity, formation, transport security, posture facts, and `profile` — `null`, or `{reason: unsupported_profile_schema, message}` |
| `fleet.doctor` | read | per-check results with guidance, including the `fleet_profile` check |
| `fleet.tags` | operate | add / remove / list advisory tags on a connected machine |
| `fleet.devices` | read | this deployment host and its `capabilities {deploy, reasons}`, discovery, the merged device rows, and the operations this data directory journals, each with `running` |
| `fleet.deployment.start` | operate | mints an operation id, runs `ouro fleet <kind> … --frames --operation <id>` as a port program, and answers `{operation}` |
| `fleet.deployment.status` | read | `{operation, kind, state, steps, challenge, log, plan, summary, last_error, running, source}` |
| `fleet.deployment.respond` | operate | answers one open challenge with `accept` or `secret` |
| `fleet.deployment.cancel` | operate | stops at a safe boundary and reports residue |
| `fleet.deployment.resume` | operate | runs an interrupted operation's program again against its journal |
| `fleet.forget_session_owner` | operate | retires one machine's durable session-owner evidence. Takes `machine` and nothing else |

`status`'s `source` is `worker` when a process on this runtime holds the program and
`journal` when none does, which is the operator's whole question after an interruption. A
journal answer's `log` is the scrubbed tail of `deploy/<id>.log` — the only thing a program
that died before it could journal anything leaves behind — and its `last_error` is
`{reason: "worker_exited", detail}` when the journal records no error of its own and this
runtime saw the program exit. `resume` rebuilds the command line from the journal's `kind`,
`target` and `paths` when this runtime has forgotten it, with the identity and the service
falling back to their defaults; nothing on that line was ever a secret.

`respond` is the one method whose parameters never reach the audit digest, not even hashed.
The secret goes from the gateway connection's own process straight to the worker process,
never through the broker's mailbox. A challenge is consumed when answered
(`challenge_consumed`), an id the operation is not waiting on is `unknown_challenge`, and
one answered past its deadline is `challenge_expired`.

`fleet.devices` reports whether this host can deploy, and `start`, `respond` and `resume`
enforce the same answer with `deploy_blocked` carrying the same list, because a disabled
button is a rendering and not a boundary; `cancel` is never blocked, since an operator must
be able to stop a deployment on a host that may no longer start one. The reasons are
`no_data_dir`, `ouro_path_unknown`, `cleartext_web_bind` and `dev_runtime`, and the last
blocks `setup` alone: a development runtime cannot boot under a fleet profile, so setting
*this* machine up from one builds a fleet it can never start, while an `add` or a `leave`
from it acts on somebody else's installation. The generated per-method reference is
[PROTOCOL.md](PROTOCOL.md).

## 12. Compatibility

Profiles are **schema 2 only**. A schema-1 profile is refused by the launcher, by every
`ouro fleet` command, by `fleet.status` and by `fleet.doctor`, with one sentence and no
migration: *this fleet was created by an older Ouroboros; run `ouro fleet leave` here and
set the fleet up again.* Every surface says exactly that, so an operator who reads one and
then another is not given two accounts of the same thing.

Runtime compatibility is `{ouroboros_version, otp_release}`, compared **exactly**: two
machines form a fleet when they run the same Ouroboros release on the same OTP release,
and that is the whole fence. `ouro fleet add` refuses a target whose `hello` reports a
different version as `version_mismatch`, naming both versions and the upgrade recipe, and
replaces nothing.

## 13. Facts, tags and placement

`Ouroboros.Cluster.Facts` carries each node's posture: OS, CPU, hostname, operator tags,
toolchain presence. Native distributed sessions get a read-only `fleet` tool and a labelled
snapshot in the opening prompt, and a native child can name `machine: "tag:xcode"` —
exactly one connected match is required, and only its concrete node is retained.

```sh
ouro fleet tag add xcode --machine studio
ouro fleet tag list --machine studio
ouro fleet tag remove xcode --machine studio
```

Omitting `--machine` edits the local profile even while its daemon is stopped; naming one
goes through the authenticated operator gateway. A tag is 1–64 lowercase letters, digits,
dots, underscores, colons or hyphens, starting with a letter or digit, at most 32 per
machine. Connected peers refresh every five seconds in a bounded background batch.

**Tags and facts grant no authority.** Grants stay node-local and deny-by-default: placing
an agent by tag onto another machine produces an agent with no grants there until someone
grants on that node. `docs/proposals/fleet-aware-subagents.md` is the design.
