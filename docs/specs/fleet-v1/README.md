# Fleet v1: trusted-operator batch execution

This is the first execution slice of North Star §6, implemented in the sibling
`fleet/` Mix project and the Rust `crates/ouro` front door. The
[two-node evidence](evidence/2026-10-07-two-node/README.md) exercises the production
CLI, TLS distribution, ledger and Jail on Linux x86_64 and Raspberry Pi aarch64.
The records are versioned but **not frozen**. This is not full milestone-3 closure.

The ledger milestone-2 records remain frozen. Fleet consumes them through an
explicit planning/reservation bridge; it neither observes syscalls nor owns the
child. The independently provisioned Rust launch owner retains the exclusive
launch lease. Restarting the coordinator does not replace that owner.

## What is implemented

- Rust `ouro fleet run`, `status`, `wait`, `kill`, `ledger`, and `doctor`.
- Fixed, operator-provisioned membership; mutually verified TLS distribution,
  a private cookie, fixed distribution ports and no EPMD daemon.
- Capability checks for the resolved request; explicit machine selection or
  placement on the eligible worker with fewest active attempts.
- Durable controller request identity and immutable placement, worker
  reservation and ledger run cross-reference before starting an owner.
- Same-request replay; changed inputs refuse. A missing reply leaves admission
  unconfirmed and never allocates a replacement attempt on another worker.
- Reconciliation through the Rust ledger's boot/start identity checks. Missing
  connectivity returns a stale snapshot with an explicit unreachable label.
- EOF stdin, opt-in bounded capture, independent cleanup and protection labels,
  and read-only, job-scoped ledger routing.

Execution and evidence remain separate. Fleet maps a durably recorded unknown
ledger outcome to `state: outcome_unknown, settlement: unknown`; it preserves the
ledger's own `ledger_settlement` field. A completed uncontained job remains
`child_protection: unprotected`. Evidence gaps can coexist with an observed exit.

## Build and provision a test node

Requirements: Linux with the Jail capabilities needed by the selected policy,
a provisioned lingering systemd user manager, Rust's pinned repository toolchain,
Elixir 1.18+ and Erlang/OTP 27+. `mix` has no external dependencies.

```sh
umask 077
cargo build --release --locked -p ouro -p ouro-jail -p ouro-ledger
(cd fleet && mix compile --warnings-as-errors && mix test)
```

Each node needs its own locally generated TLS private key, a CA-signed certificate
with its distribution hostname/IP in the SAN, the trusted CA certificate, and a
shared 64-character hexadecimal distribution cookie. Provision these through
trusted operator channels. Private keys stay on their owning nodes. Connected
peers have full operator authority over each other; TLS does not create tenant
isolation. No fleet job verb moves credentials or workspace contents.

Use private mode-0700 state and data directories and mode-0600 configuration,
TLS option files, certificates, keys and cookie, all regular files with one link.
A node configuration has this shape (replace every example path and address):

```json
{
  "schema": "ouro.fleet.node/1",
  "fleet_id": "operator-test",
  "machine": "worker-a",
  "node": "ouro-worker-a@10.0.0.1",
  "host": "10.0.0.1",
  "dist_port": 13720,
  "controller": "ouro-worker-a@10.0.0.1",
  "members": [
    {"machine":"worker-a","node":"ouro-worker-a@10.0.0.1","dist_port":13720},
    {"machine":"worker-b","node":"ouro-worker-b@10.0.0.2","dist_port":13720}
  ],
  "cookie": "/private/fleet/cookie",
  "tls": "/private/fleet/ssl_dist.conf",
  "state": "/private/fleet/state",
  "data": "/private/fleet/data",
  "ledger_bin": "/opt/ouro/ouro-ledger",
  "jail_bin": "/opt/ouro/ouro-jail",
  "elixir": "/usr/bin/elixir",
  "ebin": "/opt/ouro/fleet/_build/dev/lib/ouro_fleet/ebin",
  "client_script": "/opt/ouro/fleet/scripts/client.exs"
}
```

Both `server` and `client` entries in the Erlang TLS option file must use
`{verify,verify_peer}`, `certfile`, `keyfile`, and `cacertfile`; the server also
requires `{fail_if_no_peer_cert,true}`. Startup refuses plaintext distribution
and weaker verification. The TLS option-file path cannot contain whitespace.
The fixed-port EPMD adapter is reused from the preserved legacy implementation.

Start the node with the following Erlang arguments, the compiled `ebin` path,
and `fleet/scripts/node.exs /private/fleet/node.json`. Run it as its own user
service; set `OURO_CONFIG_DIR` explicitly for any local Jail/launch profiles.
Do not put this service in the owner or ledger service's lifetime unit.

```text
+S 2:2 -proto_dist inet_tls -start_epmd false
-epmd_module Elixir.Ouroboros.Cluster.Epmd
-ssl_dist_optfile /private/fleet/ssl_dist.conf
```

The node explicitly starts an independent writer with `serve --detach`. It
cannot create a lingering user manager or repair missing host capabilities.
A client uses a private node configuration pointing at its trusted controller:

```sh
ouro fleet --config /private/fleet/node.json doctor --json
ouro fleet --config /private/fleet/node.json run \
  --request-id example-1 --on worker-b --jail tool \
  --limit wall=30s --capture stdout --capture-limit 4096 --json \
  -- /bin/echo example
ouro fleet --config /private/fleet/node.json status JOB --json
ouro fleet --config /private/fleet/node.json wait JOB --timeout 60 --json
ouro fleet --config /private/fleet/node.json ledger JOB show --with-transcript
```

Retry a lost admission response with the exact same request ID and inputs.
`--dir` names an existing directory on the selected worker. With no directory,
the worker creates a private scratch directory for that job. `--jail none` is
explicitly unprotected and still subject to the Jail's unsafe-configuration
refusals. Output capture accepts stdout/stderr only in this slice.

## Limits and remaining milestone-3 work

Membership commands from the legacy fleet are not yet integrated. Configuration,
CA provisioning, node services and membership changes are manual. The job and
attempt records need final compatibility review and freezing. The Rust front door
currently exposes fleet only; packaged three-tool distribution follows that work.
No legacy code or history is removed here. The real-agent second-node test and
historical custody evidence remain required before the legacy cut.

Controller and worker operations are serialized, with bounded request/output
frames and scans refusing more than 4,096 records. There is one configured
controller, no failover or automatic job retry, no PTY/interactive relay, no
workspace transfer and no tenant authorization. Routed `tail` returns one bounded
page; remote following is not implemented. Unreachable data is not an empty result.

The test hosts prove scripted execution and process-failure behavior. They do not
prove production availability, physical power-loss durability, a public release,
managed-worker authorization or support for every external agent/profile.
