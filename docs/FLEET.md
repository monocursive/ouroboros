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

# See exactly what it would do, and change nothing — not the data directory, not a
# journal, not a credential, not a roster, and not a recorded host key:
ouro fleet add me@100.64.0.2 --machine buildbox --dry-run

# Take a reachable member out of the fleet again, from here. `--user` is required: the
# member is reached over SSH and the account is never inferred. Its `ouro` is found from
# this machine's record of admitting it, and `--remote-executable` overrides that.
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

A standalone target must be stopped before admission. If it is running, setup refuses
before issuing credentials; run `ouro stop --require-idle` against that target's data
directory, then retry. The issuer rechecks the reviewed roster under its lifecycle lock,
writes the durable issue receipt, and releases the lock before credentials go over SSH.
Its own membership update takes the lock again and is refused `roster_conflict` if the
local roster moved, rather than silently rebased.

The issuer-wide `operation.lock` covers the mutation phase only — for `add`, from
certificate issue through every roster write; for `setup`, create, stop and start; for
`leave`, from `stop_runtime` through the roster removals. Inspection, host trust,
authentication and review run without it. A waiter that cannot take the lock is told
which operation holds it (`operation_in_progress`, naming the holder and its state).

The Tailscale node key (`nodekey:…`) for the target address is recorded when discovery
or the request can name one, and a later add or resume that sees a different key is
refused `peer_identity_changed`. A manual private-network address with no key is
recorded as unset and the check is skipped.

The request file at `<data dir>/deploy/<id>.request.json` is kept while the operation
is running, failed or interrupted, because resume still needs the identity reference.
On `completed` or `cancelled` the identity choice is folded into the journal's target
record and the request is deleted. Completed and cancelled journals older than thirty
days are pruned, keeping the newest fifty; failed and interrupted work is left alone,
as is anything whose worker lock is still held.

The optional CLI model check requires an explicit target workspace:

```sh
ouro fleet add deploy@buildbox --machine buildbox --run-test-task --test-workspace /srv/project
```

The reviewed plan includes this path. The check starts a planning session, submits one
model turn, and waits up to one minute for that turn to complete. Session and turn IDs
are stable across retries; a failed or unobserved turn is not reported as successful.

Authentication is explicit and never takes a value on the command line, because a
command line is readable by every process on the host:

| Flag | What it selects |
|---|---|
| *(none)* | the deployment host's own default SSH identities, and then — if the target accepts none of them and offers password authentication — the target account's password, through the same masked prompt `--ask-password` uses |
| `--key <PATH>` | one private key file on the deployment host, checked for ownership and mode. An encrypted key is asked for its passphrase in a masked prompt |
| `--agent <FINGERPRINT>` | one identity held by this machine's SSH agent, pinned so the agent offers nothing else. No agent is forwarded and no key is exported |
| `--ask-password` | the target account's password, typed into a masked prompt and used for that operation only |

That fallback is why no surface needs an authentication picker: the ordinary answer is
"this machine, this account", and the connection asks for a password only when it turns
out to need one. It is the same `password` challenge, numbered the same way (*attempt 1
of 3*), and a prompt for an encrypted key's passphrase is still the separate `passphrase`
challenge that names the key. The method list stays `publickey,password` and nothing
else: keyboard-interactive would let the far end compose the prompt text, and prompt text
composed by a far end is never put in front of a person here.

For an explicitly selected key or agent identity, the connection uses the normalized
options with `-F /dev/null`, so additional `IdentityFile` entries cannot offer another
key. The default identity is the one case that reads the deployment host's own
`~/.ssh/config`, because using this host's configured identities is what it means.
Preflight still inspects that configuration and refuses unsupported destination rewriting
or proxy routing.

An unknown host key is always a separate explicit question showing its algorithm and
SHA256 fingerprint; `--yes` accepts a reviewed plan but never a host key, never a
password, and never a busy runtime. A changed host key blocks, and a key this machine has
marked `@revoked` blocks under its own name. Without a terminal, every one of those
questions is a refusal with a stable reason rather than a prompt nobody will see, so
noninteractive use needs pre-established host trust and key or agent authentication.

Every invocation also pins the options that decide *what a host key means* and *who signs
for a connection* — `KnownHostsCommand`, `GlobalKnownHostsFile`, `RevokedHostKeys`,
`CertificateFile`, `PKCS11Provider` and `IdentityAgent` — because each of them is settable
in `~/.ssh/config` and each can supply host keys or signatures from somewhere this
operation did not choose. If `ssh -G` reports any of them still in force, the connection
is refused rather than made.

`--json` prints the operation's result with stable reason codes; incomplete setup exits
non-zero even when some steps succeeded.

One SSH ControlMaster socket is reused for the operation, so a password is typed once and
retried up to three times, with a five-minute window to answer. A connection refused for a
reason that never asked for a password — a key the target will not take — is not retried
three times: there is nothing for anyone to retype. Host-trust and review challenges use
the same five-minute window.

On this branch the Devices views (the web page at `/devices`, the terminal client's
`ctrl+x D`) and the `fleet.devices` / `fleet.deployment.*` gateway methods drive this
same engine through a detached worker; none of it is in a tagged release yet. "What has
been exercised" below says which parts have run against real programs and which rest
on tests alone.

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

The client is looked for at the usual macOS and Linux locations, then on `$PATH`; a
client that runs but answers with no status document, or fails outright, is skipped for
the next candidate, while a permission refusal is the answer and stops the search. Set
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

Every `--json` device row also carries `suggested_machine`: a valid machine name for that
device — its roster name if it has one, otherwise one derived from its display name, or
`null` when nothing valid can be derived — so a surface can pre-fill a setup form without
offering a name the validator will refuse. It is for forms only; the human `ouro fleet
devices` never prints it, and nothing is named by it until a person submits it.

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

Removing a member also marks its issued admissions as retired, preserving their receipts.
A fresh operation can then admit that name again; replaying an old operation remains
refused. If issuance succeeded before delivery or membership was recorded, explicit
`ouro fleet members remove NAME` retires that pending admission too. Retirement does not
revoke any credentials that were copied elsewhere.

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

Repeating `install` preserves an identical loaded service without restarting it. Replacing
an existing unit while its runtime owns the data directory is refused; stop that runtime
with `ouro stop --require-idle` before retrying installation.

| Platform | What the service does, and what it does not |
|---|---|
| Linux with a reachable `systemctl --user` | A user unit with `Restart=on-failure`, `RestartSec=5` and a `StartLimitIntervalSec=300`/`StartLimitBurst=5` ceiling, wanted by `default.target`. Surviving logout and starting at boot requires lingering, so `install` runs `loginctl enable-linger <you>` once the unit is loaded — on a stock polkit policy an account may enable its own — and reports the boot-time start it then has. When that is refused, `status` reports `loginctl show-user <you> --property=Linger`, says outright that this is a login-scoped service, and names `loginctl enable-linger` as the administrator's step. When `loginctl` cannot be asked, lingering is reported as unknown rather than assumed. |
| macOS with a logged-in user session | A LaunchAgent in `~/Library/LaunchAgents` with `RunAtLoad`, `KeepAlive` restricted to unsuccessful exits, and a 30 second `ThrottleInterval`. `ProcessType` is `Adaptive`, not `Background`: a Background job is held to a throttled I/O band, which is right for a backup agent and wrong for a runtime that answers an operator. It starts at login and stops with the login session; there is **no pre-login execution**, so the machine is not reachable between a reboot and the next login. |
| Anything else | `install` refuses with the prerequisite named — log in to the desktop session, or provide a reachable systemd user manager — and installs nothing. Start the runtime with `ouro daemon` and supervise it yourself; nothing here claims persistent startup it cannot deliver. |

**Only our own units.** Every generated unit begins with an ownership marker naming the
data directory it serves and a SHA-256 of the rest of the file:

```text
# ouroboros-managed v1 data-dir=/home/you/.ouroboros content-sha256=<64 hex>
```

The path is percent-encoded, so the marker is one token per field whatever the directory
is called — a space, a `#`, a quote — and it is read back only from the line and the
comment syntax this code writes it on. `status`, `disable` and `remove` act only on a
file carrying that marker for this data directory. A unit that is somebody else's, or
one of ours naming a *different* data directory, is reported with the digest of what is
actually there and left untouched; `install --adopt` is the operator saying, explicitly
and after seeing that digest, that it may be replaced, and `remove` never adopts. A unit
of ours that has been edited since it was written is still ours: `install` refuses to
overwrite it without `--adopt`, and `remove` does delete it — a file left behind comes
back at the next login — while saying in its output that it no longer matched the digest
in its own marker.

When `--adopt` replaces a unit that was not ours, the job *that* file had loaded is
booted out alongside ours, and named in the output: a replaced plist whose label nobody
stopped leaves a job running with no file behind it.

The marker is **not a security boundary**, and nothing here treats it as one. It is a
plain digest over the file with no secret in it, so anything with write access to this
account's service directory can compute one. What it distinguishes is an accident from a
deliberate act — another tool's unit, a hand-written one, an older copy of ours — and an
account whose service directory an attacker can write to has already lost, marker or no
marker.

If `status` finds a second unit in the same directory carrying our marker for the same
data directory — one written by an older `ouro` from a path spelled with a trailing
slash, say — it names it: two units for one runtime is two supervisors racing to start
it, and only one of them can win.

Paths inside the generated unit are escaped for the format they land in: XML escaping in
the plist, and systemd's own quoting grammar in the unit file — quoted `ExecStart=`,
`Environment=` and `WorkingDirectory=`, with `%` doubled everywhere a specifier would
otherwise expand. A directory with a space or a `%` in its name therefore still names one
directory and one program.

The unit's environment is `HOME`, a fixed system `PATH` and `OUROBOROS_DATA_DIR`, and
nothing else. The runtime's own environment — node name, cookie file, EPMD address,
roster — is derived from the profile at every start, so adding a machine to the roster
never leaves a stale unit behind, and an `OUROBOROS_*`, `ERL_*` or `RELEASE_*` variable
exported in the shell that ran `install` reaches neither the unit nor the BEAM.

Logs go to `<data dir>/service.out.log` and `service.err.log`, created 0600 before the
manager can create them at its own umask — and put back, still private, by `install`,
`status` and `start` whenever rotation or a tidy-up has removed them.

On Linux, `remove` also takes out the `default.target.wants` symlink `systemctl --user
enable` installed, so a removal on a machine whose user manager is not answering does not
leave a dangling want behind for the next `daemon-reload` to complain about.

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

A supervisor that is still enabled will restart a runtime the moment it stops, so gate
the runtime first, then take the unit down:

```sh
ouro stop --require-idle
ouro fleet service disable
```

`ouro stop --require-idle` sends `runtime.shutdown {"require_idle": true}`. Exit 0 also
covers a data directory with nothing running. The runtime reads its own running and
queued turns, image transfers and preparation, and connected operator clients, and
refuses if any of it is non-zero — or if it could not establish one of them, because
unknown activity is not idleness. The two refusals have their own exit codes so a
script can tell them apart:

| Exit | Meaning |
|---|---|
| 0 | the runtime accepted the stop and the pid it published is gone, or nothing was running here |
| 10 | `runtime_busy` — the activity summary is printed, field by field |
| 11 | `activity_unknown` — the runtime could not read one or more counters, and they are named |
| 12 | the runtime does not serve `runtime.activity`, so it has no gate to apply. Nothing was sent: a runtime that predates the gate ignores the parameter and stops, which from the outside is indistinguishable from one that checked and found itself idle |
| 13 | the connection closed before an answer arrived, so whether the gate passed, refused or was never reached is unknown |

`disable` and `remove` gate themselves the same way (`stop --require-idle` first); a
second gate on a stopped runtime is a no-op. A unit that is not installed is left
untouched. Cooperative `leave` uses this same order: stop, then disable.

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
| `fleet.devices` | read, administrator | the Devices inventory: this deployment host, what its network client can see, what this runtime knows about each member as a BEAM peer, and whether it may deploy at all |
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
   port, which identity *reference*, which paths — or, for the first *local* fleet, none of
   those: `kind: "setup"` configures this machine without SSH to itself, so it carries only
   what this device should be called and the private address its runtime will bind. A third
   kind, `kind: "leave"`, removes a machine that is already in this machine's roster: it
   carries the member's name and host, the account to reach it with, the port and the
   identity reference, and optionally `install_path` when `ouro` is somewhere unusual on
   that machine. The *address* is read out of this machine's own `fleet/profile.json`
   rather than taken from the caller, so that the machine named is the machine contacted,
   and a member name that is not in the roster is refused with the roster listed.
   Everything else about how the member was deployed — including its
   `OUROBOROS_DATA_DIR` — is read back out of the journal of the operation that admitted
   it, so a surface never has to remember it. Unknown keys are refused, so a request
   carries these and nothing else. Written to
   `<data dir>/deploy/<operation>.request.json`, 0600 in a 0700 directory, atomically
   (an exclusive temporary inode chmodded before the first byte, then renamed) and as
   canonical JSON bounded at 64 KiB. Deliberately **not** on the command line: `ps` is
   readable by every local account, and while a target hostname and an account name are not
   secrets in the sense the list below means, publishing them to every shell on the box buys
   nothing. The request is kept while the operation is running, failed or interrupted
   (resume still needs the identity reference). On `completed` or `cancelled` the identity
   choice is folded into the journal and the request is deleted. A resume writes no new
   request: it reconnects to a surviving worker or starts a replacement using the recorded
   request and journal. An issuer-wide operation lock serializes the mutation phase only
   (issue through roster writes, not inspection or challenges); a waiter is told which
   operation holds it.

   The operation namespace is `<data dir>/deploy/`, deliberately **not** under `fleet/`: a
   fleet profile is committed by one atomic rename of a staging directory, so nothing may
   exist inside `fleet/` beforehand — and a `setup` operation's journal has to exist before
   the fleet it is creating does. Inside it, one operation owns `<id>.sock`, `<id>.cap`,
   `<id>.json`, `<id>.request.json`, `<id>.log` and the worker's `<id>.d/` scratch.
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
5. **It reads the journal when no worker is alive**, and the worker's own log when the
   journal has nothing to say. `<data dir>/deploy/<id>.json` is
   the operation's durable authority, written by the worker before and after every
   externally visible step. The broker opens it read-only and sanitizes what it returns; it
   never writes one, because a broker that repaired a journal would be inventing steps the
   target machine never saw. A worker that dies *before* it can journal anything leaves an
   operation sitting at `inspecting` with no error on it, so a journal answer for an
   unfinished operation also carries `worker_exit.last_lines`: the last three non-empty
   lines of `<id>.log`, read from the tail, sanitized the way a journal is and cut to three
   hundred characters each. Nothing wrote that file under a contract, which is exactly why
   it is read defensively.

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
bound at issue to the identity *and* the client session it was issued to: a second listener
connection or a second LiveView is refused `challenge_not_bound` before anything is written,
and a challenge is consumed the moment it is answered, so there is no second guess. A
browser's *cookie* id is not that session — one cookie per browser, read by every tab — so a
LiveView mints its own with `Ouroboros.Web.Call.view_session/0` and passes it as `session:`
on deployment calls.

The session half of that binding lasts exactly as long as the session. A surface passes its
id to `Ouroboros.Fleet.Deployment.subscribe/2` as well as on its calls, the broker monitors
the subscriber, and when the last process speaking for a session goes down every challenge
still open on it is **unbound**, with an audit line naming the operation and the challenge.
The identity half never lapses — another administrator still needs an explicit takeover — and
a consumed challenge stays consumed. This is what the binding was always for: a *second* tab
open at the same time must not answer the first one's prompt. A tab that has been closed is
not a second tab, and leaving its prompt bound stranded the operation behind a page that no
longer existed, with `resume` refusing `already_attached` because the detached worker was
still perfectly alive. An explicit `unsubscribe` releases nothing: a page that unsubscribed
is a closed drawer, not a closed tab.

Two things are released, not one, because a deployment asks more than once — a review then a
password, a host key then a password, an attempt then a second attempt. The challenges that
are *open* are unbound, and so is the **connection's own binding**, which is what every
challenge issued afterwards would otherwise be stamped with: the connection names the tab
that opened the socket, and that tab may have been closed an hour ago. Releasing only the
open ones let the surviving tab press Remove and then refused it the password a second
later. The first answer after a release says which tab took over and the connection binds to
it again, so the window in which any of that operator's tabs may answer is the gap between
the tab closing and the next answer, and not the rest of the operation.

**Ownership.** The journal records the identity that started an operation. `status` and
`cancel` refuse a different one; `resume` refuses it too, and additionally refuses a journal
whose owner this build cannot establish, because a resume attaches under the *resuming*
identity and every challenge from then on binds to them. `takeover: true` says so out loud:
it is permitted, it leaves an audit line naming who took what from whom, and the worker
records a `takeover` step of its own. An operation nobody can attribute stays *readable* —
a read grants no authority, and refusing every status on a runtime whose `ouro` predates the
field would break recovery without protecting anything.

**Blockers.** `fleet.devices` reports whether this host can deploy and why not, and the
deployment verbs enforce the same answer: `prepare`, `start`, `authenticate` and `resume`
refuse `deploy_blocked` carrying the blockers. A disabled button is a rendering, not a
boundary. `cancel` is never blocked — an operator must be able to stop a deployment on a
host that may no longer start one. Two blockers are exempted by kind rather than applied
flatly: `no_ca_key` does not stop a `setup`, because the first local fleet is what creates
that key, and it does not stop a `leave`, because removing a member issues nothing.
`dev_runtime` runs the other way and stops a `setup` and nothing else — a runtime started
from a checkout cannot boot under a fleet profile, so setting *this* machine up from one
builds a fleet it can never start, while an `add` or a `leave` from the same runtime acts
on another machine's installation and is unaffected.

**Authorization.** Every verb here needs an administrator once identities are configured —
the network inventory as much as the mutations, because a tailnet inventory is every machine
on an operator's private network. A non-administrator sees `fleet.status`'s membership
subset in Devices instead. Credential entry is additionally decided on the web endpoint's
**bind**, the one transport fact the server can verify: a loopback bind permits it whether
the browser is local or arrives through `tailscale serve`, and a non-loopback bind under
`OUROBOROS_WEB_ALLOW_REMOTE=1` is cleartext by definition and refuses it. Forwarded and
proxy headers play no part in that decision.

## What has been exercised

Everything in this section was run on 2026-09-17 on one Mac (macOS 15, arm64) with
both data directories on that machine, so it establishes the mechanics and not the
cross-network behaviour.

- `ouro fleet setup` against a *running* packaged runtime: the runtime was stopped
  through `runtime.shutdown`'s idle gate, the fleet was created, a LaunchAgent was
  installed and the runtime restarted under it; a terminal client attached throughout
  refreshed its Devices view from the restarted runtime.
- `ouro fleet add` over OpenSSH to a non-root `sshd` on loopback with key
  authentication: unknown-host verification with the fingerprint prompt, plan review,
  prepare/issue/install on the target, the roster update on the issuer, and the
  member's runtime connecting afterwards (`fleet doctor` reported it connected and
  compatible). The private known-hosts store, receipts and journals were inspected for
  secret residue and held none.
- The web Devices page and the terminal Devices view against the real gateway, broker
  and `fleet devices` discovery; the deploy drawer and overlays against a scripted
  worker; the broker against the real worker in
  `test/ouroboros/fleet/deployment_real_worker_test.exs`.
- Passphrase entry through the real askpass bridge with real `ssh`. Password entry only
  through a fake `ssh` that invokes `$SSH_ASKPASS` the way OpenSSH does: an
  unprivileged `sshd` cannot authenticate passwords, so a real password login has not
  been observed.

Not exercised: Linux and systemd (the unit text and every `systemctl`/`loginctl`
call are proven against goldens and counting fakes only), Headscale, any target on
another machine or network (the tailnet's Linux peer was listed by discovery and never
contacted), relayed paths, a real release-origin download (the loopback harness only),
`--run-test-task` against a model, hosted CI on this branch. Windows is not supported.

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
