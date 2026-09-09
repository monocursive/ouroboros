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
routed to; `OUROBOROS_FORGE_BUILDER_NODE` names the builder.

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
| `OUROBOROS_MACHINE_NAME` | the friendly label this node reports in `fleet.status`. |
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
role and runtime posture, and which nodes own interactive and coding sessions. Runtime
compatibility is a manual fence — `@fleet_protocol_revision` in `cluster.ex`, plus the
Ouroboros version and OTP release — so a mixed-revision cluster is named rather than
silently trusted.

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
ouro new --machine vps --provider native --workspace /absolute/path/on/vps/project
```

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
`ouro fleet` at all. What it costs is stated plainly: there is no `OUROBOROS_FLEET_ID`, so
there is no durable session-owner directory under `<data dir>/fleet/cluster-directory/`
(`Cluster.Monitor.fleet_profile_storage/0`, `lib/ouroboros/cluster.ex:819-836`), session ownership is in-memory only, and
`ouro fleet sessions forget` has nothing to retire. `ouro fleet status` and
`ouro fleet doctor` also have no profile to read. Nothing checks that the optfile you
supply is a mutual-TLS policy either; that check belongs to the profile the launcher
computes from.

Ports: allow the EPMD port and the distribution range between the private addresses only.
The gateway port stays loopback-only.

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

Each node records which machine owns each interactive and coding session, and persists
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

Fleet views are *observations*: bounded per-node answers merged at read time, with
unreachable nodes named. Nothing here is membership consensus, quorum, or a partition
policy.

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
