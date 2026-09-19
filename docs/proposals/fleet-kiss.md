# Fleet, simplified

Decision record and implementation contract, 2026-09-19. Branch `fleet-kiss`.

This replaces the trust, roster and worker parts of
[fleet-network-onboarding.md](fleet-network-onboarding.md). What that proposal says about
Tailscale as the network, OpenSSH as the bootstrap, secret handling, host-key questions
and the Devices words still holds. What it says about a per-member certificate ceremony,
an issuer, receipts, replicated rosters, tombstones, a detached worker and a protocol
revision is withdrawn by this document.

## 1. The three decisions

**The transport stays.** Ouroboros is one BEAM cluster over mutual TLS distribution.
Every connected member has unrestricted remote-call authority over every other member.
That is what the runtime is built on, and this document does not change it.

**The per-member PKI goes.** Because any connected member can already read every file
the operator's runtime can, the properties "the CA key never leaves the operator" and
"only the operator can admit" were never true after the first connection, and there was
no revocation to make them matter. So: one fleet is one shared secret bundle, the
cookie and the CA key pair, held by every member. Each member mints its own leaf
certificate from that CA, on its own machine, with its own host in the subject
alternative name, because OTP's TLS distribution verifies the server certificate
against the dialed host (`ssl/src/inet_tls_dist.erl`, `server_name_indication` on
connect). The TLS policy file is unchanged. A leaked or lost member is answered the way
the old document already prescribed for a leaked credential: make a new fleet and add
the machines again.

**The replicated roster goes.** Erlang distribution is transitive: a member that dials
one node it knows joins the whole mesh. Each profile therefore carries the members known
when it was written, as dial hints, and nothing ever edits another machine's profile.
Adding a machine appends to the operator's list and writes the new member's list once.
A stale entry costs a backed-off dial and nothing else.

Two things follow that were separately listed as cuts and are now simply consequences:
there is no EPMD daemon, because the fleet has one distribution port and the runtime
resolves peers from its own profile; and the deployment worker is an ordinary port
program of the runtime that asked for it, because nothing it does needs to outlive a
runtime except the local setup transition, which the journal already covers.

## 2. The bundle and the profile

`<data dir>/fleet/` holds, on every member:

| File | Mode | What |
|---|---|---|
| `profile.json` | 0644 | non-secret facts, schema 2, below |
| `cookie` | 0600 | 64 lowercase hex |
| `ca-cert.pem` | 0644 | the fleet CA certificate |
| `ca-key.pem` | 0600 | the fleet CA private key. Shared. See §1 |
| `node-cert.pem` | 0644 | this machine's leaf, CN `ouro-<machine>@<host>`, SAN `<host>`, signed by the CA |
| `node-key.pem` | 0600 | this machine's private key, generated here, never sent anywhere |
| `ssl_dist.conf`, `vm.args` | 0644 | generated at create/join and at every `runtime_env` refresh |

The **bundle** is what travels from the operator to a new member, inside one helper
frame over SSH: `{"schema": 2, "fleet_id", "name", "cookie", "ca_cert_pem", "ca_key_pem",
"dist_port", "members": [...]}`. It is held in a `Zeroizing` struct with a hand-written
`Debug` that prints no secret, exactly as `AdmissionMaterials` did.

`profile.json`, schema 2:

```json
{
  "schema": 2,
  "fleet_id": "<32 hex>",
  "name": "<fleet name>",
  "machine": "<this machine's name>",
  "host": "<advertised IPv4 or private DNS name>",
  "node": "ouro@<host>",
  "role": "core",
  "dist_port": 13700,
  "gateway_port": 17342,
  "members": [
    {"machine": "studio", "host": "100.64.0.1", "node": "ouro@100.64.0.1", "dist_port": 13700},
    {"machine": "pi",     "host": "100.64.0.2", "node": "ouro@100.64.0.2", "dist_port": 13700}
  ],
  "tags": []
}
```

- `members` always includes this machine. It is written by `setup` (self only), by `add`
  on the operator (append the new member) and on the target (the operator's list plus
  itself), and by `leave --machine` and `forget` on the operator (remove). Nothing else
  writes it, and nothing writes it on another machine.
- `dist_port` is one number per fleet in production, `DEFAULT_DIST_PORT` = 13700. The
  per-member `dist_port` exists so two nodes can share one host in the lab and in tests;
  `Ports { dist: Some(p) }` and `ephemeral_ports()` keep working, minus the EPMD field.
- Gone: `tombstones`, `roster_revision`, `epmd_port`, `dist_port_min`, `dist_port_max`.
- A schema-1 profile is refused by the launcher and by every `ouro fleet` command with
  one sentence: *this fleet's profile was written by a different version of Ouroboros
  than the one running here; run `ouro fleet leave` here and set the fleet up again.*
  There is no migration.

## 3. What the launcher sets

`fleet::runtime_env` computes the release environment from the profile and strips the
caller's, as today. The list becomes:

| Variable | Value |
|---|---|
| `OUROBOROS_DIST` | `name` |
| `OUROBOROS_NODE` | `profile.node` |
| `OUROBOROS_NODE_ROLE`, `OUROBOROS_MACHINE_NAME`, `OUROBOROS_FLEET_ID` | as today |
| `OUROBOROS_COOKIE_FILE`, `OUROBOROS_BOOT_COOKIE_DECOY` | as today |
| `OUROBOROS_CLUSTER_STRATEGY` | `epmd` (the roster dialer; the name is libcluster's) |
| `OUROBOROS_CLUSTER_HOSTS` | every member node except self |
| `OUROBOROS_CLUSTER_RECONNECT_MS` | `1000` |
| `OUROBOROS_DIST_TLS`, `OUROBOROS_DIST_TLS_OPTFILE` | as today |
| `OUROBOROS_GATEWAY_PORT` | as today |
| `OUROBOROS_DIST_PORT` | **new**: this node's listen port |
| `OUROBOROS_DIST_PORTS` | **new**: `host=port,host=port,…` for every member including self |

Removed: `ERL_EPMD_ADDRESS`, `ERL_EPMD_PORT`. The generated `vm.args` gains
`-start_epmd false` and `-epmd_module Elixir.Ouroboros.Cluster.Epmd`, and keeps
`-proto_dist inet_tls`, `-ssl_dist_optfile`, `-kernel inet_dist_use_interface` and
`-kernel inet_dist_listen_min P inet_dist_listen_max P` with P = `dist_port`.

`OUROBOROS_CLUSTER_STRATEGY=none|epmd`, `OUROBOROS_CLUSTER_HOSTS`, `OUROBOROS_COOKIE_FILE`,
`OUROBOROS_ALLOW_INSECURE_DIST` and the TLS variables remain what the launcher and the
test suites speak. They stop being documented as an operator path. The `gossip` and `dns`
strategies and their variables are deleted.

## 4. Distribution without EPMD

`Ouroboros.Cluster.Epmd` is the `-epmd_module`. It is loaded by the boot script before
kernel starts distribution, because releases boot in embedded mode.

| Callback | Answer |
|---|---|
| `start_link/0` | `:ignore` |
| `register_node/2,3` | `{:ok, creation}` with a random creation in 1..3 |
| `listen_port_please/2` | `{:ok, p}` from `OUROBOROS_DIST_PORT`, else `{:ok, 0}` |
| `port_please/2,3` | `{:port, p, 5}` with p from `OUROBOROS_DIST_PORTS[host]`, else `OUROBOROS_DIST_PORT`, else `:noport`. `host` arrives as a charlist, a binary or an IP tuple and is normalised before lookup |
| `address_please/3` | `:inet.getaddr(host, family)` |
| `names/1` | `{:error, :address}` |

Nothing else in the runtime changes for this. `Ouroboros.Cluster.RosterEpmd`, the
libcluster strategy that re-reads the profile every sweep, is unchanged. Nothing uses
the release's remote console, so `listen_port_please` needs no special case for one.

## 5. The commands

```
ouro fleet setup   --machine NAME [--address IPV4] [--no-service] [--yes] [--json] [--dry-run] [--operation ID]
ouro fleet add     [USER@]ADDRESS --machine NAME [--port N] [--key PATH | --agent FP | --ask-password]
                   [--install-path P] [--data-dir P] [--no-service] [--yes] [--json] [--dry-run] [--operation ID]
ouro fleet leave   [--machine NAME --user USER [--port N] [--key|--agent|--ask-password] [--yes] [--json] [--operation ID]]
ouro fleet forget  NAME
ouro fleet status  [--json]
ouro fleet doctor  [--json] [--peer NAME|ADDRESS]
ouro fleet devices [--json]
ouro fleet service install|status|disable|remove [--json]
ouro fleet tag     add|remove|list
ouro fleet create  ...            # hidden; the primitive setup uses, kept for the lab
ouro fleet helper                 # never by hand; the fixed remote command
ouro fleet askpass                # never by hand; SSH_ASKPASS
```

Deleted: `fleet protocol`, `fleet create --from`, `fleet create --regenerate`,
`fleet members add|remove`, `fleet sessions forget|restore`, `fleet worker`,
`--run-test-task`, `--test-workspace`.

`ouro fleet forget NAME` is the local answer to a machine that cannot be reached: it
removes NAME from this profile's members and asks the runtime to retire NAME's
session-owner evidence. The runtime refuses while NAME is connected. No tombstone, no
restore; the command name is the operator's statement.

`--frames` is the third front end, described in §8. It is accepted by `setup`, `add` and
`leave --machine`, and it is what the broker runs.

## 6. The engine

Three operations, one journal, the same steps in every front end.

**setup**: `create` (bundle, leaf, profile v2, generated files) → stop the running
runtime through the idle gate → `service install` unless `--no-service` → start →
readiness probe. Steps: `create`, `stop_runtime`, `service`, `start`, `ready`.

**add**: preflight over ssh with the fixed `PREFLIGHT` script (OS, arch, `$HOME`, an
existing `ouro`?) → host trust → authenticate → if no `ouro`: install the exact matching
official release with `BOOTSTRAP` → `hello` (its version must equal ours; a different
version is `version_mismatch`, naming both, with the upgrade recipe; nothing is
replaced) → `inspect` (a fleet already there? which? a runtime running?) → **review**:
the plan lines *Install ouro X (os arch) to PATH · Join FLEET as NAME · Start at login as
a user service · Remember NAME on this machine* → `install` with the bundle → `service`
→ `start` → `status` until connected or the deadline → local append to `members` →
done. Steps: `inspect`, `install`, `join`, `service`, `start`, `connect`.

**leave --machine**: host trust → authenticate → `hello` → **review** (*Stop Ouroboros on
NAME, remove its fleet credentials and its startup service, forget it here. Its sessions
and data stay on that machine.*) → `leave` → local removal → done. Steps: `stop`,
`remove`, `forget`.

**Journal**, `<data dir>/deploy/<id>.json`, mode 0600, rewritten atomically before and
after every step, schema 2:

```json
{"schema": 2, "operation": "…", "kind": "add|setup|leave", "state": "running|waiting|completed|failed|cancelled",
 "created_at": "…", "updated_at": "…",
 "target": {"machine": "…", "address": "…", "ssh_user": "…", "port": 22},
 "release": {"version": "…", "asset": "…", "sha256": "…"},
 "paths": {"install_path": "…", "data_dir": "…"},
 "plan": ["…", "…"],
 "steps": [{"step": "install", "state": "ok|failed|skipped|attempted", "at": "…", "detail": "…"}],
 "residue": ["…"],
 "last_error": {"reason": "snake_case", "detail": "…"}}
```

No `owner`, `roster`, `plan_digest`. Resume is `--operation ID`: a step recorded `ok`
is not repeated; `install` on a target that `inspect` reports as already in this fleet
as this machine is `skipped`. Completed and cancelled journals older than thirty days
are pruned, newest fifty kept, as today.

The request for an operation is argv. Nothing on argv is a secret: an address, an
account, a port, a path, a key path or an agent fingerprint. The password never is.
`deploy/<id>.request.json` is gone.

**Kept unchanged**: `ssh.rs` (normalised options, the pinned `KnownHostsCommand` and
friends, ControlMaster reuse, three attempts), `trust.rs`, `askpass.rs` and its socket,
`bootstrap.rs`, `terminal.rs`, the idle gate, the redaction of everything a target
prints.

## 7. The remote helper

`ouro fleet helper`, one JSON object per line on stdin and stdout, 1 MiB cap, 60 s idle
timeout, `{"v":1,"id","op",…}` in and `{"v":1,"id","ok":true,…}` or
`{"v":1,"id","ok":false,"reason","detail"}` out, exactly as today. The operations:

| op | request | reply |
|---|---|---|
| `hello` | | `version`, `os`, `arch`, `data_dir`, `home` |
| `inspect` | | `fleet`: `null` or `{fleet_id, name, machine, host}`; `runtime_running`; `service`: `null` or `{installed, running}` |
| `install` | `bundle`, `machine`, `host`, `ports?` | `machine`, `node`, `fleet_id`. Refuses `fleet_present` when a different fleet is there, unless `replace: true`; a same-fleet same-machine profile is `already_installed` and not rewritten |
| `service` | `install: bool` | as today's `service` op, on the simplified manager |
| `start` | | starts the daemon from this `ouro`; `pid` |
| `status` | `peer?` | `runtime_running`, `connected_to: [node]`, `version` |
| `leave` | | idle-gated stop, service disable and remove, `fleet/` deleted; `removed: [what]` |
| `bye` | | exit 0 |

Deleted: `prepare`, `discard_preparation`, `roster`, `receipt`, `disable`, `remove`.

## 8. The frames front end

`ouro fleet add … --frames` (and `setup`, `leave --machine`) speaks NDJSON on its own
stdin and stdout. It is what the broker runs as a port program. Frames are the ones the
worker already emits, with the same names:

Out, one per line: `{"event":"state","state":"running|waiting|completed|failed|cancelled"}`,
`{"event":"step","step":"install","state":"ok","detail":"…"}`,
`{"event":"log","line":"…"}`,
`{"event":"challenge","challenge":"<id>","kind":"host_trust|password|passphrase|review","expires_at":"…","metadata":{…}}`,
`{"event":"done","state":"completed|failed|cancelled","summary":"…"}`.

In: `{"op":"respond","challenge":"<id>","accept":true|false}` for `host_trust` and
`review`; `{"op":"respond","challenge":"<id>","secret":"…"}` for `password` and
`passphrase`; `{"op":"cancel"}`.

The process calls `setsid` at start and ignores `SIGHUP` and `SIGPIPE`. Once the review is
accepted it needs nothing more from stdin: on stdin EOF it finishes the operation, keeps
writing the journal, and stops writing to stdout. That is how a local `setup` survives
the runtime it was started from, and it is the whole of "survives"; there is no reattach.
A challenge that is not answered within five minutes fails the operation `challenge_expired`,
as today. Stderr goes to `<data dir>/deploy/<id>.log`, 0600, scrubbed by the same
funnel as the journal.

## 9. The broker and the gateway

`Ouroboros.Fleet.Deployment` keeps a registry `operation → worker process` and answers
`devices/1` and `operations/1` from `ouro fleet devices --json` and the journal directory.
`Ouroboros.Fleet.Deployment.Worker`, one process per running operation, owns
`Port.open({:spawn_executable, ouro}, [:binary, :exit_status, {:line, 1_048_576}, args: […]])`
where `ouro` is `OUROBOROS_PROCESS_ID_HELPER` and never `PATH`. It decodes frames with
`Frame`, keeps the last `state`, the steps, the open challenge and the last fifty log
lines, and forwards every frame to subscribers. When no process is alive for an
operation, status is the journal projection: JSON under 1 MiB, the schema-2 keys and
nothing else, strings cut at 2 000 characters, lists at 200. `Client`, `Launcher`'s
detach dance, the capability file, attach retry, `owner`, takeover and session bindings
are deleted.

Gateway methods, `Gateway.Methods.Contract`, all administrator-only as today:

| Method | Scope | Params | Answer |
|---|---|---|---|
| `fleet.devices` | read | | as today minus `issuer`; `capabilities.reasons` from `no_data_dir`, `ouro_path_unknown`, `cleartext_web_bind`, `dev_runtime` (setup only); each operation row has `running: bool` instead of `owner`/`attached` |
| `fleet.deployment.start` | operate | `kind`, `target {machine, address}`, `ssh_user`, `port`, `identity {kind, ref}`, `install_path`, `data_dir`, `service` | `{operation}` |
| `fleet.deployment.status` | read | `operation` | `{operation, kind, state, steps, challenge, log, plan, last_error, running, source: "worker" or "journal"}` |
| `fleet.deployment.respond` | operate | `operation`, `challenge`, `accept` or `secret` | `{accepted: true}` |
| `fleet.deployment.cancel` | operate | `operation` | `{state}` |
| `fleet.deployment.resume` | operate | `operation` | `{operation}` |
| `fleet.forget_session_owner` | operate | `machine` | as today, without the tombstone precondition |

`fleet.status`, `fleet.doctor`, `fleet.tags` are unchanged. `fleet.deployment.prepare`,
`.authenticate` and `.confirm_host` are deleted. A `secret` still goes from the gateway
connection process straight to the worker process and never through the broker's
mailbox. `make protocol-docs` regenerates `docs/PROTOCOL.md` from the contract.

## 10. Devices

**Web** keeps the design in
[fleet-ux-review-2026-09-18.md §5](../design-qa/fleet-ux-review-2026-09-18.md): one list,
one action per row, the same words. The drawer's steps are the challenges in order:
host trust, password, review, progress, done. No plan digest, no idempotency key, no
takeover, no per-tab binding: a challenge is answered by whoever is an administrator on
this runtime. `test/browser/devices.spec.js` follows.

**TUI** shows the same inventory, the status line and the deploying-from line, and for
each row the one thing to do about it as a command, for example
`ouro fleet add pi@100.64.0.2 --machine pi`, plus the web address of this runtime's
Devices page. It runs no operation. Forms, challenges, progress and the takeover prompt
are deleted. `ctrl+x D` stays.

## 11. The service manager

One unit per data directory at a deterministic path:
`~/Library/LaunchAgents/com.ouroboros.<slug>.plist` or
`~/.config/systemd/user/ouroboros-<slug>.service`, where `<slug>` is the first twelve
hex characters of SHA-256 of the canonical data directory. `install` writes it and loads
it, overwriting whatever is at that path; `status` reads it; `disable` unloads it;
`remove` unloads it and deletes it. Kept: the foreground `service-run`, private logs,
lingering on Linux, the network wait, `Restart=on-failure` and its ceiling, the idle gate
before `disable` and `remove`. Deleted: the ownership marker, `--adopt`, foreign and
modified classification, second-unit detection, and the marker grammar.

## 12. Compatibility

- A machine on a schema-1 profile cannot form a fleet with a schema-2 machine and is
  told so by `ouro fleet status`, `doctor` and the launcher. The repair is `leave` and
  `setup`/`add` again. Runtime compatibility is `{ouroboros_version, otp_release}`,
  compared exactly; `@fleet_protocol_revision` and its drift test are deleted.
- `fleet.status` and `fleet.doctor` documents lose `fleet_protocol_revision`,
  `roster_revision`, `tombstones`, `epmd`. `fleet.devices` loses `issuer`.

## 13. Slices

| Slice | Owns | Depends on |
|---|---|---|
| K1 Rust core | `tui/src/fleet.rs`, `runtime.rs` EPMD lifecycle, `fleet_protocol.rs`, `cli.rs`/`main.rs` for the deleted and renamed commands, `fleet::build_metadata` | §2, §3, §5 |
| K2 Elixir cluster | `Ouroboros.Cluster.Epmd`, `cluster.ex` (profile v2, contract keys, gossip/dns removal, `forget` without tombstones), `config/runtime.exs`, `rel/` | §3, §4, §12 |
| K3 Rust engine | `fleet_setup/*`, `fleet_helper.rs`, `fleet_service.rs`, `--frames`, the CLI for setup/add/leave/forget/service | K1; §6, §7, §8, §11 |
| K4 Elixir broker | `lib/ouroboros/fleet/*`, gateway methods and contract, `make protocol-docs` | K2; §8, §9 (tests against a fake frames worker, then one against the real `ouro`) |
| K5 TUI Devices | `tui/src/ui/app/devices.rs` and its tests | §10 |
| K6 Web Devices | `lib/ouroboros/web/live/devices*.ex`, Playwright | K4; §10 |
| K7 Docs | `docs/FLEET.md` rewrite, README "A second machine", status notes on the two older documents | everything |

Gates per slice: the slice's own suites green, `cargo fmt`/`clippy -D warnings` or
`mix format --check-formatted`, and an adversarial review with a mutation table. Then
the integration gates from `make test`, the packaged `make ouro` binary running `setup`,
`add` and `leave --machine` against the real-OpenSSH loopback rig, and finally a live
second machine.

## 14. Deviations accepted

What the implementation did differently from the text above, as of `7dcbb564`. Where the
two disagree the code is right, and [FLEET.md](../FLEET.md) documents the code.

- **Node names keep the spelling `ouro-<machine>@<host>`.** §2's `ouro@<host>` example was
  wrong: `fleet::member` has always built `ouro-<machine>@<host>`, and `add_member` refuses
  any other spelling by name.
- **`OUROBOROS_DIST_PORTS` is keyed by the full node name**, `ouro-studio@100.64.0.1=13700,…`,
  one entry per member including self. Two lab nodes on one host cannot both be true under
  a host key, and the node name is the one string the dialer holds. A bare `host=port`
  entry is still read as a documented fallback for a hand-written map, and a node-name
  entry wins where the two disagree.
- **The port is answered from `address_please/3`, not `port_please/2`.** §4 puts the lookup
  in `port_please`, but `inet_tcp_dist` calls `address_please/3` first and then hands
  `port_please/2` the *resolved address* — so a member whose `host` is a private DNS name
  would be looked up under a key nobody writes. `address_please/3` answers
  `{:ok, ip, port, 5}` and the dial path skips `port_please/2` entirely; `port_please/2,3`
  keeps §4's answer for every other caller.
- **`RELEASE_VM_ARGS` is still set by the launcher.** §3 left it out of the table, but it
  is how the generated `vm.args` is read at all.
- **Every file in `<data dir>/fleet/` is mode 0600**, not §2's mixed 0644/0600:
  `profile.json`, `ca-cert.pem`, `node-cert.pem`, `ssl_dist.conf` and `vm.args` included.
  They are not secrets, but `fleet.rs` writes and validates the whole directory at one
  mode, and a file at any other mode is refused rather than repaired. The code is stricter
  than the contract and wins.
- **`fleet_id` is 24 hex characters**, `random_hex(12)`. §2's example says 32.
- **The journal's `target` keeps more than the four keys §6 lists.** Beside `machine`,
  `address`, `ssh_user` and `port` it carries `node`, `host_fingerprint`, `identity`,
  `peer_id`, `stable_id`, and `hostname`, `os`, `arch`. Steps carry `machine`, and a step
  may carry a `fingerprint`.
- **The journal has a top-level `service`** beside `target.identity`: the `--no-service`
  choice, written at the start rather than inferred from a `service` step later. §6's
  document does not list it, and the broker's resume cannot work without it — it rebuilds
  argv from those two fields and refuses `operation_request_incomplete` when either is
  absent on an operation whose command line needs it, rather than defaulting.
- **The step lists differ from §6.** `setup` runs `stop_runtime` before `create`, not
  after. `add` has a seventh step, `remember` — the local roster append — and its `install`
  step is the *binary* install, while the bundle install is journaled as `join`.
- **The startup service keeps today's unit label and path** — `dev.ouroboros.runtime.<digest>`
  in `~/Library/LaunchAgents`, `ouroboros-<digest>.service` under `~/.config/systemd/user`
  — rather than §11's `com.ouroboros.<slug>`, so a unit installed by 0.1.9 or 0.1.10 is the
  same file this build manages; renaming it would strand a loaded LaunchAgent at a path
  nothing looks at any more. `<digest>` is what §11 calls `<slug>`. Everything else in §11
  landed as written: no marker, no `--adopt`, no foreign/modified classification, no
  second-unit scan. One thing §11 does not mention and `install` has to do: on macOS it
  reads the `Label` out of a plist it replaces and boots that job out too, because
  overwriting the file would otherwise leave a job running with nothing behind it.
- **`fleet.status` has a `profile` key** — `null`, or `{reason: unsupported_profile_schema,
  message}` — and `fleet.doctor` a `fleet_profile` check, both carrying the one unsupported-
  profile sentence. `fleet.doctor` also gained a live `epmd_module` check §4 does not name:
  it passes only when the node's epmd module is `Ouroboros.Cluster.Epmd` *and*
  `-start_epmd false` is in force, and otherwise names the module actually in use.
- **`fleet.forget_session_owner` takes `machine` only.** No confirmation flag and no
  tombstone precondition. `ouro fleet forget NAME` additionally refuses, before touching
  the profile, when no runtime is answering: the runtime resolves a machine name through
  the profile's members, so the roster edit would strand evidence nothing could name again.
- **`fleet.deployment.status` answers carry `summary`, `residue` and `running`** beyond
  §9's list, and `fleet.deployment.cancel` answers `{state, residue}`. Both status
  projections read `residue` out of the journal, because a program writes residue down
  rather than sending it as a frame. §9's reason codes gained `operation_in_progress`,
  `target_in_progress` (carrying `data.operation`), `operation_request_incomplete`,
  `worker_refused` and `unknown_challenge`; the engine's own refusal for argv that
  contradicts a journal is `resume_mismatch` for the identity or the service choice, and
  `plan_changed` for the target's address, account, port, machine or kind.
- **`fleet.devices` drops `issuer`, `owner` and `attached` from inside each device row** as
  well as from the top of the answer. §12 only asks for the answer; a row is
  `ouro fleet devices --json` verbatim, so an older `ouro` beside a newer runtime would
  otherwise put them back inside the row.
- **Frames need no `v` field**; a `v` that is present and is not `1` is refused. This is
  the helper protocol (§7). The `--frames` protocol (§8) carries no `v` at all.
- **The TUI does not print the web address of this runtime's Devices page.** §10 asks for
  it; `devices.rs` prints the per-row recipe and a manual `ouro fleet add USER@ADDRESS
  --machine NAME` line, and nothing about the web.

### Two places the code disagreed with itself, since resolved

Recorded because the documents follow the code, and for a while these two could not both
be right.

- **The unsupported-profile sentence** existed in two wordings, the runtime's in
  `lib/ouroboros/cluster.ex` and an older one in `tui/src/fleet.rs`. The Rust engine slice
  made the Rust constant the runtime's sentence, which is the one §2 quotes and every
  surface now prints.
- **The journal's `state`** serialised the engine's eleven internal phases while §6 and the
  broker spoke five words. The same slice made `OperationState` exactly
  `running|waiting|completed|failed|cancelled`, keeping the finer phase as a non-serialised
  type for the terminal's progress wording; `interrupted` became `failed` with a stable
  `last_error.reason` (`start_failed`, `not_connected`).
