# The cluster

Ouroboros runs as one BEAM cluster: several machines, one trust domain, sessions and
native subagents placed across it. This document is the whole of it — what a node is,
what it reads from its environment, how nodes find each other, and what an operator
types to bring a second machine up.

There is no enrollment product. Nothing here copies a binary to another machine, opens
an SSH connection, mints an invitation, or installs a service. An operator builds `ouro`
on each machine (`make ouro`), copies the binary the way they copy any other binary, and
sets the environment below by hand. `docs/proposals/core.md` §3 records that decision.

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

Read by `rel/env.sh.eex`, `config/runtime.exs` and `Ouroboros.Cluster`:

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

`ouro fleet create` gives one machine a cluster identity in `<data dir>/fleet/`: a node
name, a private 64-hex cookie at mode 0600, a self-signed CA and node certificate for
TLS distribution, a private EPMD port, and generated `ssl_dist.conf` and `vm.args`. The
packaged launcher owns that EPMD for the life of the runtime and retires it on
`ouro fleet leave`.

Two machines cluster when they read the *same* cookie and name each other. Copy the
cookie file privately to the second machine (mode 0600, same user), then start both:

```sh
# studio.example-tailnet.ts.net
OUROBOROS_DIST=name \
OUROBOROS_NODE=ouro-studio@studio.example-tailnet.ts.net \
OUROBOROS_COOKIE_FILE=/Users/me/.ouroboros/fleet/cookie \
OUROBOROS_MACHINE_NAME=studio \
OUROBOROS_CLUSTER_STRATEGY=epmd \
OUROBOROS_CLUSTER_HOSTS=ouro-vps@vps.example-tailnet.ts.net \
OUROBOROS_DIST_TLS=1 OUROBOROS_DIST_TLS_OPTFILE=/Users/me/.ouroboros/fleet/ssl_dist.conf \
  ouro daemon

# vps.example-tailnet.ts.net — same cookie file contents, the other name in HOSTS
OUROBOROS_DIST=name \
OUROBOROS_NODE=ouro-vps@vps.example-tailnet.ts.net \
OUROBOROS_COOKIE_FILE=/home/me/.ouroboros/fleet/cookie \
OUROBOROS_MACHINE_NAME=vps \
OUROBOROS_CLUSTER_STRATEGY=epmd \
OUROBOROS_CLUSTER_HOSTS=ouro-studio@studio.example-tailnet.ts.net \
OUROBOROS_DIST_TLS=1 OUROBOROS_DIST_TLS_OPTFILE=/home/me/.ouroboros/fleet/ssl_dist.conf \
  ouro daemon
```

Then, from either machine:

```sh
ouro fleet status     # this machine's identity, plus the live roster when a runtime answers
ouro fleet doctor     # local security and, when running, live connectivity and compatibility
ouro new --machine vps --provider native --workspace /absolute/path/on/vps/project
```

Both TLS certificates must chain to a CA both nodes trust, so the second machine needs
either a node certificate signed by the first machine's CA or a CA of its own that both
`ssl_dist.conf` files trust — `ouro fleet doctor` refuses a mismatch rather than falling
back to cleartext. A profile is validated as a whole: `machine`, `host` and `node` must
agree (`node` is `ouro-<machine>@<host>`), and `members` must contain this machine's own
node, so a copied `fleet/` directory needs `members` edited too, on both sides. An
operator who manages certificates themselves can skip the profile entirely and set
`OUROBOROS_DIST_TLS_OPTFILE` and the variables above directly.

A machine leaves the same way it arrived, by hand: run `ouro fleet leave` on the machine
itself to retire its own identity and owned EPMD, and take it out of `members` in every
remaining machine's `fleet/profile.json` — there is no revocation authority and no signed
roster to distribute.

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

It refuses while that node is connected, syncs the checkpoint before reporting success,
and is irreversible per machine. It changes local discoverability evidence only: it
deletes no files on the lost machine.

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
