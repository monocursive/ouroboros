# The cluster

Ouroboros runs as one BEAM cluster: several machines, one trust domain, sessions and
native subagents placed across it. This document is the whole of it — what a node is,
what it reads from its environment, how nodes find each other, and what an operator
types to bring a second machine up.

There is no enrollment product. Nothing here copies a binary to another machine, opens
an SSH connection, mints an invitation, or installs a service. An operator builds `ouro`
on each machine (`make ouro`), copies the binary the way they copy any other binary, and
then either copies one cluster-identity directory between the machines or sets the
environment below by hand. `docs/proposals/core.md` §3 records that decision.

## Roles

Every node boots as exactly one of three roles, from `config :ouroboros, :node_role`
(`OUROBOROS_NODE_ROLE`, default `core`). The role shapes the supervision tree in
`Ouroboros.Application`:

| Role | What it runs |
|---|---|
| `core` | the full runtime: sessions, storage, the mesh, the gateway, the web surface |
| `builder` | `Ouroboros.Cluster` plus `Ouroboros.Wasm.Supervisor`, and nothing that holds durable work — a forwarded lane-W forge reads imports through this node's helper pool |
| `signer` | `Ouroboros.Cluster`, `Upgrade.Signing.Service`, and the durable-directory owner when configured |

An unrecognized role refuses the boot rather than defaulting to the most privileged one.
`OUROBOROS_SIGNING_NODE` on a `core` node names the `signer` peer that lane-W signing is
routed to. `config :ouroboros, :wasm_forge_placement` (`:local`, the default, or
`:builder`) decides whether a forge runs where the effect landed or is forwarded to a
connected `builder`, and refuses by name when there is none.

Role is a *placement* concept, not a security boundary — see "Trust" below.
`Ouroboros.Cluster.ensure_role/2` and `ensure_placeable/1` refuse work sent to a node
that cannot run it; `config :ouroboros, :placement_role_check` (default `true`) turns
that check off for setups that place onto unlabelled nodes deliberately.

## Environment

Read by `rel/env.sh.eex`, `config/runtime.exs` and `Ouroboros.Cluster`, except the two
`ERL_EPMD_*` variables, which no Ouroboros code reads: ERTS consumes them, and
`fleet::runtime_env` is what sets them.

| Variable | Meaning |
|---|---|
| `OUROBOROS_NODE` | this node's fully qualified name, `name@host`. Setting it selects distribution with long names. |
| `OUROBOROS_DIST` | `none` forces a single-machine daemon; anything else selects distribution. Unset with no node name and no strategy is also single-machine. |
| `OUROBOROS_COOKIE_FILE` | absolute path to a mode-0600, same-user, non-symlink file holding exactly 64 lowercase hex characters. `config/runtime.exs` reads it and replaces the release launcher's disposable boot cookie before libcluster starts, so the real cookie never appears in `argv` or the environment. |
| `OUROBOROS_NODE_ROLE` | `core`, `builder` or `signer`. |
| `OUROBOROS_CLUSTER_STRATEGY` | `none` (default), `epmd`, `gossip` or `dns`. |
| `OUROBOROS_CLUSTER_HOSTS` | comma-separated node names, for the `epmd` strategy. |
| `OUROBOROS_CLUSTER_RECONNECT_MS` | dial retry interval (default 5000). |
| `OUROBOROS_CLUSTER_GOSSIP_PORT`, `OUROBOROS_CLUSTER_GOSSIP_SECRET` | for the `gossip` strategy. |
| `OUROBOROS_CLUSTER_DNS_QUERY`, `OUROBOROS_CLUSTER_DNS_BASENAME` | for the `dns` strategy. |
| `OUROBOROS_DIST_TLS`, `OUROBOROS_DIST_TLS_OPTFILE` | `rel/vm.args.eex` turns these into `-proto_dist inet_tls` and an ssl options file. |
| `OUROBOROS_DIST_PORT_MIN`, `OUROBOROS_DIST_PORT_MAX` | pin the distribution listener to a firewall-friendly range. Set together. |
| `ERL_EPMD_ADDRESS`, `ERL_EPMD_PORT` | keep EPMD on one private address and a non-default port. |
| `OUROBOROS_MACHINE_NAME` | the friendly label this node reports in `fleet.status`; `ouro daemon` sets it from the profile's `--machine` name. Unset, the label is the host half of the node name — `ouro@alpha` reads as `alpha` — so two nodes that share a release name never share a label. A roster member that has not answered a probe yet reads as its roster name. |
| `OUROBOROS_FLEET_ID` | with `OUROBOROS_DATA_DIR`, selects the durable cluster directory under `<data dir>/fleet/`. Without it, session-owner evidence is in-memory only. |
| `OUROBOROS_ALLOW_INSECURE_DIST` | `1` accepts cleartext distribution. See below. |

**Forming a cluster over cleartext distribution refuses the boot.** A cluster puts the
shared cookie, and every message after it, on the wire; any node that completes the
handshake holds full `:erpc` authority over this one. `config/runtime.exs` reads the
transport the VM is actually running (`-proto_dist`) rather than the one someone
intended, and raises unless it is `inet_tls`/`inet6_tls`. `OUROBOROS_ALLOW_INSECURE_DIST=1`
is the deliberate override for a trusted network, and has to be typed on the host that
wants it.

## Formation

`Ouroboros.Cluster` owns formation and identity and is the only place that knows either.
`OUROBOROS_CLUSTER_STRATEGY` selects one of:

- **`none`** (default) — no discovery. Nodes are connected by something else, or not
  at all.
- **`epmd`** — a list of node names, retried on `OUROBOROS_CLUSTER_RECONNECT_MS` so boot
  order does not matter. `OUROBOROS_CLUSTER_HOSTS` seeds the list.
- **`gossip`** — libcluster's multicast gossip, optionally keyed by
  `OUROBOROS_CLUSTER_GOSSIP_SECRET`.
- **`dns`** — poll the A records of `OUROBOROS_CLUSTER_DNS_QUERY` and connect
  `basename@ip`.

A strategy that is named but misconfigured refuses the boot; it does not quietly fall
back to an unformed cluster.

`Ouroboros.Cluster.Monitor` keeps the observed roster: who joined, who left, each peer's
role and runtime posture, and which nodes own interactive sessions. Runtime
compatibility is a manual fence — `@fleet_protocol_revision` in `cluster.ex`, plus the
Ouroboros version and OTP release — so a mixed-revision cluster is named rather than
silently trusted.

This build uses protocol revision **5**, the `@fleet_protocol_revision` literal in
`cluster.ex`. Machines on different revisions do not form a fleet: the contract is
compared exactly, so upgrade peers to the same revision before placing work between them.

`ouro fleet protocol` prints that number and starts no runtime, which is what makes it
callable before a machine has one. It reads the revision from `tui/src/fleet_protocol.rs`,
and a test there parses `cluster.ex` and fails the build if the two ever disagree.

```sh
ouro fleet protocol          # 5
ouro fleet protocol --json   # the whole build contract
```

`--json` prints `fleet_protocol_revision`, `ouroboros_version`, `otp_release`,
`elixir_version`, `os`, `arch` and `embedded_release`. The two runtime versions come from
`releases/<version>/ouroboros-build.json`, which `mix release` writes into the release
tree and the packaged client reads back out of the tarball it embeds — a Rust binary
cannot derive an OTP release from bytes it never boots. A development build has no
embedded release: it reports `null` for both and `embedded_release: false` rather than
guessing at a number an operator would compare against a peer.

It also prints what the embedded release itself recorded —
`release_fleet_protocol_revision`, `release_ouroboros_version` — and
`revision_matches_embedded_release`, because those are a different fact from the client's
own. A packaged binary whose two halves disagree cannot form a fleet with anything, and
this is the only place that says so without starting a runtime. `null` there means there
was nothing to compare against, which is not the same answer as `false`.

The command answers before a data directory is discovered. It is what an onboarding
preflight calls on a machine that has no Ouroboros state, so it neither requires that
state nor creates it.

## Two machines, over SSH

`ouro fleet setup` and `ouro fleet add` do the same work as the manual recipe below
without copying the CA key anywhere. The operator machine keeps the fleet's CA and is the
only one that issues; the machine being added generates its own private key and never
sees anyone else's.

```sh
# 1. On the operator machine. Its private-network address is read from the network
#    client's report about this device; --address overrides that.
ouro fleet setup --machine studio

# 2. Add a machine. The destination is its SSH account and its private address (or the
#    name the network client reports for it). Nothing is inferred from the network
#    device's owner.
ouro fleet add me@100.64.0.2 --machine buildbox

# See exactly what it would do, and change nothing — no journal, no credentials, no
# installation, no roster edit, and no recorded host trust:
ouro fleet add me@100.64.0.2 --machine buildbox --dry-run

# Take a reachable member out of the fleet again, from here:
ouro fleet leave --machine buildbox --user me
```

What `add` does, in order: inspect the effective SSH configuration (proxy and jump
routing are refused in v1), verify the host key, authenticate, inspect the target,
install the exact matching official release if it has no `ouro`, read every current
member's roster, then prepare, issue and install credentials, update every member's
roster, arrange startup, and report what it observed. Each externally visible step is
written to a secret-free journal in `<data dir>/deploy/` before and after it happens, so
an interrupted operation resumes from its boundary rather than issuing a second
certificate: rerun the same command with `--operation <id>`.

Authentication is explicit and never takes a value on the command line, because a
command line is readable by every process on the host:

| Flag | What it selects |
|---|---|
| *(none)* | the deployment host's own default SSH identities |
| `--key <PATH>` | one private key file on the deployment host, checked for ownership and mode. An encrypted key is asked for its passphrase in a masked prompt |
| `--agent <FINGERPRINT>` | one identity held by this machine's SSH agent, pinned so the agent offers nothing else. No agent is forwarded and no key is exported |
| `--ask-password` | the target account's password, typed into a masked prompt and used for that operation only |

An unknown host key is always a separate explicit question showing its algorithm and
SHA256 fingerprint; `--yes` accepts a reviewed plan but never a host key, never a
password, and never a busy runtime. A changed host key blocks. Without a terminal, every
one of those questions is a refusal with a stable reason rather than a prompt nobody will
see, so noninteractive use needs pre-established host trust and key or agent
authentication.

`--json` prints the operation's result with stable reason codes; incomplete setup exits
non-zero even when some steps succeeded.

Not yet shipped: the Devices views in web and TUI, and the gateway methods that drive
this engine from them. The commands above are the whole of what works today.

## Two machines, by hand

Nothing below contacts a machine. An operator copies one directory, types four commands,
and the two runtimes find each other.

`ouro fleet create` gives the first machine a cluster identity in `<data dir>/fleet/`: a
fleet id, a node name, a private 64-hex cookie at mode 0600, a self-signed CA, a node
certificate signed by it, a private EPMD port, and generated `ssl_dist.conf` and `vm.args`.
The packaged launcher owns that EPMD for the life of the runtime and retires it on
`ouro fleet leave`.

**The profile is what the launcher trusts, not your environment.** When `<data dir>/fleet/`
holds a profile, `ouro daemon` computes the whole cluster environment from it and *removes*
the caller's — `apply_spawn_environment` (`tui/src/runtime.rs:1828-1866`) strips every
`OUROBOROS_*` variable the operator exported, plus `ERL_AFLAGS`, `ERL_FLAGS`, `ERL_INETRC`,
`ERL_LIBS`, `ERL_ZFLAGS`, `ELIXIR_ERL_OPTIONS` and every `RELEASE_*`, then applies the
profile's. Exporting `OUROBOROS_CLUSTER_HOSTS` beside a profile therefore does nothing at
all, silently. Edit the roster instead, with the commands below.

```sh
# 1. On the first machine.
ouro fleet create --machine studio --host studio.example-tailnet.ts.net

# 2. Copy the whole directory to the second machine, privately: it holds the cluster's
#    CA key and its cookie. Any private transport will do; scp is one.
scp -rp ~/.ouroboros/fleet me@vps.example-tailnet.ts.net:/home/me/carried-fleet

# 3. On the second machine. This signs *its* certificate with the copied CA, and takes
#    the fleet id, the cookie and the roster from the copy. Then delete the copy.
ouro fleet create --from /home/me/carried-fleet \
  --machine vps --host vps.example-tailnet.ts.net
rm -rf /home/me/carried-fleet

# 4. Back on the first machine: tell it about the second.
ouro fleet members add vps --host vps.example-tailnet.ts.net

# 5. Start both.
ouro daemon
```

Then, from either machine:

```sh
ouro fleet status     # this machine's identity, plus the live roster when a runtime answers
ouro fleet doctor     # local security and, when running, live connectivity and compatibility
ouro fleet devices    # the roster beside the devices this machine's network client sees
ouro new --machine vps --workspace /absolute/path/on/vps/project
```

## Seeing the private network

`ouro fleet devices` merges this machine's roster with the peers the installed Tailscale
client can see, so the two questions — *who is in my fleet* and *what is on this network* —
are answered side by side. It runs `tailscale status --json` once, with a five second
deadline and a bounded read. It contacts no device, opens no SSH connection, and writes
nothing. A discovered peer's Ouroboros state is `discovered_installation_unknown`: nothing
here has inspected one, so nothing here calls one uninstalled.

The client is found on `$PATH`, then at the usual macOS and Linux locations. Set
`OUROBOROS_TAILSCALE` to name a different one. It must be **absolute** — a relative name
would let the directory you happen to be standing in decide which program runs as your
network client — and an override that is not an absolute path to an executable file is a
refusal rather than a quiet fall through to another program.

Everything a peer reports — its hostname, its MagicDNS label, its OS, its last-seen
time — is a string that device wrote, and the human output strips control characters and
bidi overrides from all of it, collapses whitespace and truncates to a column budget. A
hostname is otherwise enough to forge a device row, clear the screen, or scroll the real
rows away. `--json` keeps the raw values. Anything the client itself printed is redacted
first: `tailscale` writes `To authenticate, visit: <url>` on stderr when a node key has
expired, and that URL is a credential — whoever opens it joins a device to the tailnet.

Discovery has distinct outcomes, and `--json` reports each under a stable `code`:
`client_missing`, `signed_out`, `permission_denied`, `unavailable` (with a `reason` such
as `backend_stopped` or `timeout`), `no_visible_peers`, and `ok`. They are kept apart
because they have five different repairs. Known roster members are listed even when
discovery fails — a client that cannot answer is not evidence that the fleet has no
members — and a member with no matching visible peer is `fleet_member_not_visible`, which
is not the same fact as powered off.

Tailscale is never identified by a `100.x` address prefix or a `.ts.net` suffix; Headscale
issues its own ranges and suffix, and every decision here comes from the client's own
reported fields. A connection path is reported only when it was observed: a peer's
configured DERP region is inventory, not a claim that traffic is relayed through it.

A roster row is matched to a visible device by the **advertised host** alone — the address
or private DNS name you gave `fleet create` or `fleet members add`. A peer's hostname is
not consulted, because a hostname is whatever that device says it is: matching on it would
let any device on the network claim a member's row by renaming itself, and show its own
platform and presence under your member's address. A device that does adopt a member's
name is listed under **Available on this network** as the separate device it is, with
`name_conflicts_with_roster` in `--json` and a note in the human list.

Human output reads as prose; the snake_case `state` codes are the `--json` contract and
appear only there.

`ouro fleet status --json` and `ouro fleet doctor --json` print the same kind of document.
Unavailable facts are `null`. `status --json` exits non-zero when this machine's setup is
incomplete, even if some steps succeeded; the human `ouro fleet status` is unchanged and
still exits 0.

`ouro fleet doctor` gains a **network client** layer after its existing report: which
client answered, its version, this device's private address, and whether that address is
bindable here. A missing or signed-out client is a note rather than a failure, because a
fleet configured by hand over a private LAN has no client to find.

`ouro fleet doctor --peer NAME|ADDRESS` additionally probes the route to one visible
device with a single `tailscale ping`, and reports `reachable`, `timed_out`, `unknown`,
`peer_unknown` or `peer_ambiguous`, with the path `direct`, `relayed` or `unknown` — only
ever the one that was observed. A relay is a valid connection. An overlay probe does not
establish that the distribution ports are open, so it is a separate layer from the
runtime's own connectivity check, and a probe that was asked for and did not succeed exits
non-zero.

The name is resolved before anything is sent. A machine in your roster resolves through
*your profile* — the address you bound — never through a peer's claim to that name. An
address is probed only if this machine's client actually reported it for a device, so a
well-formed address is not by itself something `--peer` will send a packet to. A name two
visible devices answer to is `peer_ambiguous` with both addresses named, rather than
whichever the map iterated first.

`create --from` refuses a directory that is not a complete copy of a fleet directory, and
refuses a `--machine` name the copied roster already holds. It writes no `ca-key.pem` on the
second machine: the authority to sign a third machine stays where the key already is, so a
third machine is another copy of the *first* machine's directory. Both machines end up with
one CA, one cookie, one fleet id, and a certificate whose common name is
`ouro-<machine>@<host>` with the host in a subject alternative name —
`ouro fleet doctor` refuses a mismatch rather than falling back to cleartext.

The roster is not replicated and there is no membership consensus. `ouro fleet members add`
and `ouro fleet members remove` edit *this* machine's `fleet/profile.json`, under the same
lock and validation `ouro fleet tag` uses, so nobody hand-edits that file; run them once per
machine. A running node re-reads the profile on every reconnect sweep
(`OUROBOROS_CLUSTER_RECONNECT_MS`, 1000 ms from a profile), so a roster edit reaches the
live dialer within about a second, with no restart.

A machine leaves the same way it arrived, by hand: `ouro fleet leave` on the machine itself
retires its own identity and owned EPMD, and `ouro fleet members remove NAME` on every
remaining machine takes it out of their rosters. There is no revocation authority and no
signed roster to distribute; a machine whose credentials leaked is answered by re-creating
the cluster, or by the network ACLs under "Trust".

A profile written by an older Ouroboros can carry a generated `ssl_dist.conf` this build no
longer emits, and startup refuses it by name. `ouro fleet create --regenerate` rewrites only
`ssl_dist.conf` and `vm.args` from the profile, in place, keeping the fleet id, CA, cookie,
roster and tombstones — which `ouro fleet leave` plus `ouro fleet create` would all destroy.

**The alternative: manage the certificates yourself.** With *no* profile in
`<data dir>/fleet/`, none of the above applies and the variables in the table are read
exactly as set, so an operator with their own CA can set `OUROBOROS_NODE`,
`OUROBOROS_COOKIE_FILE`, `OUROBOROS_CLUSTER_STRATEGY=epmd`, `OUROBOROS_CLUSTER_HOSTS`,
`OUROBOROS_DIST_TLS=1` and `OUROBOROS_DIST_TLS_OPTFILE` by hand and cluster without
`ouro fleet` at all. Name each machine with `OUROBOROS_MACHINE_NAME` or accept the default,
the host half of its `OUROBOROS_NODE` — the half that differs between two nodes that both
release as `ouro`. What it costs is stated plainly: there is no `OUROBOROS_FLEET_ID`, so
there is no durable session-owner directory under `<data dir>/fleet/cluster-directory/`
(`Cluster.Monitor.fleet_profile_storage/0`, `lib/ouroboros/cluster.ex:819-836`), session ownership is in-memory only, and
`ouro fleet sessions forget` has nothing to retire. `ouro fleet status` and
`ouro fleet doctor` also have no profile to read. Nothing checks that the optfile you
supply is a mutual-TLS policy either; that check belongs to the profile the launcher
computes from.

Ports: allow the EPMD port and the distribution range between the private addresses only.
The gateway port stays loopback-only.

## Starting at login or at boot

`ouro fleet service` manages one startup service per data directory, and nothing else on
the machine. The unit it writes runs the foreground `ouro service-run` with an absolute
path to this exact `ouro` and an explicit `OUROBOROS_DATA_DIR`, never the detaching
`ouro daemon`: `daemon` hands the runtime off and exits, which a service manager reads as
a crash and answers with a second runtime.

```sh
ouro fleet service install          # generate the unit and hand it to the manager
ouro fleet service status [--json]  # installed / loaded / running / last exit
ouro fleet service disable          # stop it and stop it respawning; keep the unit
ouro fleet service remove           # disable, then delete the one file this wrote
```

| Platform | What the service does, and what it does not |
|---|---|
| Linux with a reachable `systemctl --user` | A user unit with `Restart=on-failure`, `RestartSec=5` and a `StartLimitIntervalSec=300`/`StartLimitBurst=5` ceiling, wanted by `default.target`. Surviving logout and starting at boot requires lingering: `status` reports `loginctl show-user <you> --property=Linger` and, when it is off, says outright that this is a login-scoped service and names `loginctl enable-linger` as the administrator's step. When `loginctl` cannot be asked, lingering is reported as unknown rather than assumed. |
| macOS with a logged-in user session | A LaunchAgent in `~/Library/LaunchAgents` with `RunAtLoad`, `KeepAlive` restricted to unsuccessful exits, and a 30 second `ThrottleInterval`. It starts at login and stops with the login session; there is **no pre-login execution**, so the machine is not reachable between a reboot and the next login. |
| Anything else | `install` refuses with the prerequisite named — log in to the desktop session, or provide a reachable systemd user manager — and installs nothing. Start the runtime with `ouro daemon` and supervise it yourself; nothing here claims persistent startup it cannot deliver. |

**Only our own units.** Every generated unit begins with an ownership marker naming the
data directory it serves and a SHA-256 of the rest of the file:

```text
# ouroboros-managed v1 data-dir=/home/you/.ouroboros content-sha256=<64 hex>
```

`status` and `remove` act only on a file carrying that marker for this data directory.
Anything else at that path — somebody else's unit, or one of ours that has been edited
since it was written — is reported with the digest of what is actually there and left
untouched; `install --adopt` is the operator saying, explicitly and after seeing that
digest, that it may be replaced. `remove` never adopts.

The unit's environment is `HOME`, a fixed system `PATH` and `OUROBOROS_DATA_DIR`, and
nothing else. The runtime's own environment — node name, cookie file, EPMD address,
roster — is derived from the profile at every start, so adding a machine to the roster
never leaves a stale unit behind, and an `OUROBOROS_*`, `ERL_*` or `RELEASE_*` variable
exported in the shell that ran `install` reaches neither the unit nor the BEAM.

Logs go to `<data dir>/service.out.log` and `service.err.log`, created 0600 before the
manager can create them at its own umask.

### Waiting for the private interface

A laptop boots before its VPN, and an overlay address can arrive seconds after login.
`ouro service-run` therefore proves the profile's advertised address is bindable before
it launches the BEAM, retrying on a throttle of one second doubling to fifteen. It writes
one `waiting for network` line to the service log when the first probe fails and one a
minute after that, so the wait is visible in the unit's own log rather than looking like
a hang. `SIGTERM` during the wait exits 0 with a line saying so: nothing was started and
nothing was changed. Losing the network *after* the runtime is up is a different thing
and is not handled here — credentials, membership and work are untouched, and the
existing dialer reconnects.

### Stopping a supervised runtime

A supervisor that is still enabled will restart a runtime the moment it stops, so take it
out of the supervisor's hands first:

```sh
ouro fleet service disable
ouro stop --require-idle
```

`ouro stop --require-idle` sends `runtime.shutdown {"require_idle": true}`. The runtime
reads its own running and queued turns, image transfers and preparation, and connected
operator clients, and refuses if any of it is non-zero — or if it could not establish one
of them, because unknown activity is not idleness. The two refusals have their own exit
codes so a script can tell them apart:

| Exit | Meaning |
|---|---|
| 0 | the runtime accepted the stop and the pid it published is gone |
| 10 | `runtime_busy` — the activity summary is printed, field by field |
| 11 | `activity_unknown` — the runtime could not read one or more counters, and they are named |

Plain `ouro stop` is unchanged: it sends the same request it always has, with no
parameter, and stops the runtime unconditionally.

## Facts, tags and placement

`Ouroboros.Cluster.Facts` carries each node's posture: OS, CPU, hostname, operator tags,
toolchain presence. Native distributed sessions have a read-only `fleet` tool and a
labelled snapshot in the opening prompt, and a native child can name
`machine: "tag:xcode"` — exactly one connected match is required, and only its concrete
node is retained. `docs/proposals/fleet-aware-subagents.md` is the design.

```sh
ouro fleet tag add xcode --machine studio
ouro fleet tag list --machine studio
ouro fleet tag remove xcode --machine studio
```

Omit `--machine` to edit the local profile even while its daemon is stopped; naming one
goes through the authenticated operator gateway. Tags allow 1–64 lowercase
letters/digits plus `. _ : -`, starting with a letter or digit, at most 32 per machine.
Connected peers refresh every five seconds in a bounded background batch. **Tags and
facts grant no authority.** Grants stay node-local and deny-by-default: placing an agent
by tag onto another machine produces an agent with no grants there until someone grants
on that node.

## Session owners

Each node records which machine owns each interactive session, and persists
that evidence under `<data dir>/fleet/cluster-directory/` when `OUROBOROS_FLEET_ID` is
set. An offline owner therefore makes session lists fail closed rather than silently
hide sessions. If a machine is permanently lost, inspect or export any recoverable
owner-local state, then run this locally on every remaining machine:

```sh
ouro fleet sessions forget --machine NAME --accept-state-loss
```

`--accept-state-loss` is the operator saying the machine is gone for good, and that
statement is the only thing that can retire the evidence. The command writes it into this
machine's profile first — the member moves out of `members` into `tombstones` and the
roster revision advances — and only then asks the runtime, which refuses without that
tombstone. Nothing infers one from a disconnect, so a partitioned owner that comes back is
still a member and still owns its sessions.

**The roster edit reaches the live dialer before the gateway is asked.**
`Cluster.membership_hosts/0` (`lib/ouroboros/cluster.ex:1392`) re-reads the profile on
every reconnect sweep, so this machine stops dialing the named
machine within about a second of the write — while the gateway call is still in flight, and
whatever the gateway answers. That is safe (removal from the seed list stops dialing; it
disconnects nothing that is already connected) but it is the opposite order from the way the
command reads.

The runtime also refuses while that node is connected, and the roster edit is rolled back
if it does. On success it syncs the checkpoint before reporting, and the *evidence* loss is
irreversible per machine. The roster half is not: a client that dies between the write and
the reply leaves a tombstone with nothing retired, so

```sh
ouro fleet status                       # names every machine this roster calls gone
ouro fleet sessions restore NAME        # puts one back into `members`
```

`ouro fleet status` and `ouro fleet doctor` both print declared-gone machines — they are out
of `members`, so nothing else would mention them at all — and `restore` is the undo.
`ouro fleet members add` refuses a name this roster records as gone, and names `restore`.
Nothing here deletes a file on the lost machine.

## Gateway methods

| Method | Scope | What it answers |
|---|---|---|
| `fleet.status` | read | the merged roster: machines, roles, connectivity, formation, transport security, posture facts |
| `fleet.doctor` | read | per-node checks with guidance, and the non-answers named |
| `fleet.tags` | operate | add / remove / list advisory tags on a connected machine |
| `fleet.forget_session_owner` | operate | the irreversible local retirement above |
| `fleet.devices` | read, administrator | the Devices inventory: this deployment host, what its network client can see, and whether it may deploy at all |
| `fleet.deployment.status` | read, administrator | one deployment operation, from its worker or from its journal |
| `fleet.deployment.prepare` / `.start` / `.authenticate` / `.confirm_host` / `.cancel` / `.resume` | operate, administrator | the deployment lifecycle below |

Fleet views are *observations*: bounded per-node answers merged at read time, with
unreachable nodes named. Nothing here is membership consensus, quorum, or a partition
policy.

## Deploying onto another machine — not yet shipped in a release

**This section describes work in progress.** The Elixir broker below is in the tree; the
Rust deployment worker it talks to is being built alongside it and is not in a released
`ouro`. On a runtime whose `ouro` does not serve `fleet worker start`, every verb here
answers a stable reason code — it does not appear to work.

A deployment is long, interruptible, and carries an SSH credential, so the work does not
happen inside the runtime that was asked for it. `Ouroboros.Fleet.Deployment` is a broker,
not an executor:

1. **It states the request in a private file.** Which machine, which SSH account, which
   port, which identity *reference*, which paths — written to
   `<data dir>/fleet/deploy/<operation>.request.json`, 0600 in a 0700 directory, atomically
   (an exclusive temporary inode chmodded before the first byte, then renamed) and as
   canonical JSON bounded at 64 KiB. Deliberately **not** on the command line: `ps` is
   readable by every local account, and while a target hostname and an account name are not
   secrets in the sense the list below means, publishing them to every shell on the box buys
   nothing. The worker unlinks the file once it has read it; if the launch itself fails, the
   broker takes it back, because nothing is coming to read it. A resume writes no request —
   the worker already has its journal, and re-stating a target would be a second chance to
   state a different one.
2. **It starts a worker it does not own.** `ouro fleet worker start --operation <id>
   --data-dir <dir>`, and nothing else on the command line, forks a detached worker into its
   own session and process group, with its stdio on a private log, and prints one JSON line
   naming the worker's Unix socket and its instance identity. The broker finds `ouro` at the
   absolute path the launcher exported in `OUROBOROS_PROCESS_ID_HELPER` — never through
   `PATH`, because this is the process that will be handed a password.
3. **It connects, and proves it may.** The worker writes a 32-byte capability into a 0600
   file before its socket listens; the broker reads it — refusing a file anyone else could
   read — and presents it in the first frame, along with the audited identity and the client
   session. Frames are NDJSON, one per line, capped at 1 MiB in both directions; a worker
   that writes past that cap loses its connection and nothing else.
4. **It reconnects by instance, not by path.** A socket that exists is not evidence that the
   worker which printed it is the process listening on it.
5. **It reads the journal when no worker is alive.** `<data dir>/fleet/deploy/<id>.json` is
   the operation's durable authority, written by the worker before and after every
   externally visible step. The broker opens it read-only and sanitizes what it returns; it
   never writes one, because a broker that repaired a journal would be inventing steps the
   target machine never saw.

What that buys: closing the page does not cancel a deployment, and neither does stopping
the runtime — which is what lets the *first local fleet setup* restart the very runtime
serving the UI. What it costs: this runtime is never the authority on what happened.

**Credentials.** A password or key passphrase is answered to its own challenge and nowhere
else. It arrives as a parameter of `fleet.deployment.authenticate`, goes into the frame
encoder, and goes onto the worker's socket; it is not stored in any process state, not put
in an operation journal or receipt, not passed to a command line or an environment variable,
and — uniquely in this protocol — not passed to the audit parameter digest. Hashing a human's
password into a log is not redaction, so that one method's audit line names the operation and
the challenge and nothing else, on both the listener and the browser surface. A challenge is
bound at issue to the identity *and* the client session it was issued to: a second browser
tab or a second listener connection is refused `challenge_not_bound` before anything is
written, and a challenge is consumed the moment it is answered, so there is no second guess.

**Authorization.** Every verb here needs an administrator once identities are configured —
the network inventory as much as the mutations, because a tailnet inventory is every machine
on an operator's private network. A non-administrator sees `fleet.status`'s membership
subset in Devices instead. Credential entry is additionally decided on the web endpoint's
**bind**, the one transport fact the server can verify: a loopback bind permits it whether
the browser is local or arrives through `tailscale serve`, and a non-loopback bind under
`OUROBOROS_WEB_ALLOW_REMOTE=1` is cleartext by definition and refuses it. Forwarded and
proxy headers play no part in that decision.

## Trust

- **One cluster is one trust domain.** Any node that completes the distribution
  handshake — cookie, and TLS if configured — holds full `:erpc` authority over every
  other one (`cluster.ex`, `docs/ARCHITECTURE.md` "Safety boundaries"). Joining a VPS to
  your laptops means a compromised VPS owns the laptops. The mitigations are perimeter
  and placement, not containment: network ACLs restrict which devices reach the
  EPMD/distribution/gateway ports, TLS distribution narrows on-path exposure, and the
  signer lives on the most-trusted host with a key that never crosses the wire. An
  operator who cannot accept that for one machine should run it un-clustered with only
  its gateway reachable, and take the reduced view.
- **Role checks stop misconfiguration, not attackers.** A hostile connected node ignores
  every check in `Ouroboros.Cluster` by calling whatever it likes directly. What holds
  against a hostile *artifact* is the verifier's namespace policy and signature
  verification, not this module.
- **A private network is trusted infrastructure this runtime does not verify.** Address
  ranges are checked; WireGuard, ACLs and DNS answers are taken at face value.
- **Leases, grants, registries and stores stay node-local.** Nothing here replicates
  state. Every "fleet-wide" surface is a read-time merge.
- **Recovering from a compromise means clean hosts and rotated credentials.** Nothing in
  the cluster undoes code execution or secrets already copied.
