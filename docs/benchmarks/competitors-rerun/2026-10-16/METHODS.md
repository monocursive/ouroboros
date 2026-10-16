# Rerun methods, 2026-10-16

This corpus repeats the 2026-10-11 competitor comparison
([competitors/METHODS.md](../../competitors/METHODS.md)) on the same three
hosts with two deliberate changes: the jail product is built from the
current development head after the Ouroboros-to-Ukai rename
(`af2837946a523269eb5cef099d1af80f6da216de`, version 0.1.0, frozen build
provenance, Rust 1.98.1 release build on each Linux host), and OpenShell
moves from 0.1.3 to its 0.1.4 release (published 2026-10-13). Greywall
0.3.7 / Greyproxy 0.4.5, MXC 1.0.0 and the three coding clients (Claude
Code 2.1.295, OpenCode 1.19.0, Codex 0.159.2) are the same installed
versions as 2026-10-11, so their results are comparable across corpora.

Everything else follows the prior methods: same seven fixed workloads,
three discarded warmups and 30 measured samples with the fixed shuffle
seed (advanced to 20261016), same coding tasks, hidden checks and pass
rules, same resource and canary probes, per-host serialization, and no
scoring of failed launches. Workloads validate against the direct
control's operation count and checksum; Ouro/Ukai samples additionally
require an exited outcome, an empty process tree and no coverage gaps.

## Harness deltas from 2026-10-11

One harness copy is kept in this corpus (`harness/`). It differs from the
prior copy only mechanically:

- `OURO_CONFIG_DIR`/`OURO_DATA_DIR` became `UKAI_CONFIG_DIR`/`UKAI_DATA_DIR`
  (rename commit 94273cc82);
- the jail binary path is `bin/ukai-jail`; the tool label in records remains
  `ouro-jail`/`ouro-obs-off` so analysis code reads the same arm names (the
  arm is the renamed product, not a different product);
- shuffle seed 20261011 became 20261016.

The `ukai-jail run --profile …` command surface and the private vendor
profile schema (`name`/`jail`/`state_var`/`[credentials]`/`[network]`) are
unchanged from the version the prior corpus drove.

## Host policy record

- VPS: `kernel.apparmor_restrict_unprivileged_userns` was at the restored
  stock value 1 (set during the credential corpus work, see
  `credentials/2026-10-13-next`). The native suite ran with the value set
  to 0 — the same setting as every arm of the 2026-10-11 cohort — and was
  restored to 1 immediately afterwards (`results/vps-userns-before.txt`,
  `results/vps-userns-after.txt`). All native arms ran under the one
  setting; the long-running natural-expiry soak on the same host was not
  touched and holds no new sandbox launches.
- Pi and Mac: no host policy was changed.

## OpenShell 0.1.4 deployment

0.1.4 is installed side by side (`bench-ouro/bin-0.1.4/`) from the release
tarballs (SHA-256 verified against the release checksum files); the 0.1.3
system packages and the running credential-corpus gateway are untouched.
Each host runs a new 0.1.4 gateway for this corpus (`os14-vps` 127.0.0.1:50617,
`os14-pi` :50618, `os14-mac` :50619) with its own HOME/XDG state and a
`generate-certs` PKI, mTLS user auth, and the docker compute driver. Two
0.1.4 requirements changed the setup relative to 0.1.3: docker-driver
sandboxes require launch-scoped gateway authentication (the gateway's
`jwt/` signing material must be visible through `OPENSHELL_LOCAL_TLS_DIR`),
and the gateway TOML config needs `[openshell] version = 2` with
`guest_tls_ca` set. The fixture image `bench-openshell:latest` from
2026-10-11 is reused without rebuild; 0.1.4 pulls its own
`supervisor:0.1.4`/`sandbox:0.1.4` runtime images.

On the Pi the 0.1.4 startup failure reproduces the 0.1.3 result: sandbox
creation dies with `ControlSupervisorStartFailed: Docker sandbox exited
before supervisor became ready` while the shipped supervisor image's
`--version` executes standalone. As in the prior corpus the deeper cause
stays unconfirmed and Pi OpenShell is recorded as unavailable rather than
as failed enforcement; its container lane measures Docker controls only.

## Credentials

The Anthropic key is the same file as 2026-10-11 (verified against the
Messages API before the runs). The VPS and Pi Codex caches had expired;
both hosts received a read-only copy of the still-valid authorized Mac
cache (access token expires 2026-10-23 09:22:33 UTC — the same real-issuer
grant the natural-expiry soak watches; the copy is staged under the rerun
root and the Mac original is never written). The Mac Codex lane reads its
own `~/.codex/auth.json`. Expiry metadata is recorded through the provider
update before any timed work, as before.

## Known-anomaly expectations

The 2026-10-11 corpus' platform findings should reproduce if they are
platform properties rather than one-off events: Mac Greywall exits 65
(Seatbelt kleene-star), Mac MXC Codex may exit during CFPreferences
synchronization, Mac MXC shows high system Python/Git startup cost, Pi
lacks the memory controller and Landlock, and OpenShell blocks the
container→host egress canary while plain Docker reaches it. This corpus
checks each of them again rather than assuming them.
