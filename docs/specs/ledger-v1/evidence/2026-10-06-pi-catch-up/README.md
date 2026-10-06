# Raspberry Pi feature catch-up, 2026-10-06

Tested source: `41e6457b009065bd4fe4040b3141da291fb29c9b` on `dev`.
The clean Git archive is recorded in `source.json`; `source.sha256` binds all
417 runtime, test and contract files. The source tree is separate from the
previous Pi checkout. Only its existing pinned Rust 1.98.1 toolchain and build
cache are reused.

## Scope

This run updates the Pi from the October 5 ARM64 validation to all current
ledger features: persistent history/capture retention, capture-only expiry,
operator intents, bounded live tail, cross-run queries and count comparisons,
filtered run discovery, comparisons by recorded targets, unsigned portable
bundles, explicit Ed25519 identities and pinned signature verification.
The full ledger suite exercises recovery, corrupted inputs, replay identity,
pagination and trust boundaries as well as real contained launches.

It also reruns native Jail and fixture unit tests, ARM64 tracer precision and
foreign-call handling, command rules, the `tool` and `none` syscall matrices,
published observer tables, native freeze tables and kernel-capability refusal.
The validation procedure is [validate-pi.sh](validate-pi.sh).

## Host boundary

Raspberry Pi 4 Model B Rev 1.2, Debian 13.7, Linux
`6.18.50+rpt-rpi-v8`, native `aarch64-unknown-linux-gnu`.
The host still boots with memory cgroups disabled and its kernel omits
`CONFIG_SECURITY_LANDLOCK` and `CONFIG_UNIX_DIAG`. The native tests prove
that `tool` and `none` work, and that required memory ceilings, requested
Landlock domains and the `agent` profile refuse before a child executes.

The positive Landlock fixture is explicitly excluded here; its refusal path
is exercised. Positive `agent` and `build` conformance belongs to the provisioned
x86_64 VPS. Kernel, boot, networking and default toolchain settings are unchanged.
This is native ARM64 evidence within those capabilities, not full-profile Pi
conformance, physical power-loss testing or real-agent/provider acceptance.

## Portable signed evidence

[signing-smoke.sh](signing-smoke.sh) performs real `tool` and `none` launches,
retains selected truncated captures, signs their canonical snapshots, deletes
the private key and source stores, and verifies using the public identity alone.
Independent OpenSSL verification accepts the exact domain/manifest bytes
and rejects an altered message. The retained identity is ephemeral test data;
it is not an operational trust anchor and no private key is saved.

[cross-platform-pi.sh](cross-platform-pi.sh) verifies earlier VPS-produced
unsigned and signed bundles on the Pi. Pinned and untrusted signed reports
match the original reports exactly. Pi-produced bundles are additionally
verified on macOS using their public pin. These are portable inspection checks,
not evidence of contained macOS execution.

## Installation

[install-pi.py](install-pi.py) requires successful native validation, a ready
doctor report at the exact clean revision, and matching executable hashes.
It installs `ouro-jail` and `ouro-ledger` in
`~/.local/lib/ouroboros/41e6457b/` with commands in `~/.local/bin/`.
Existing commands or release directories cause refusal instead of replacement.
No writer daemon or persistent application service is installed.

## Results

All **1,063 tests passed**, with zero failures and zero live-capability skips.
One evidence-table generator remains deliberately ignored; the positive
Landlock fixture is the explicit exclusion described above. No ARM64-specific
runtime repair was needed: the current implementation passed unchanged.

| Layer | Result |
|---|---|
| Full ledger suite | 167 passed, including all 21 real Linux launch tests |
| Jail, fixture and records unit suites | 622 passed; one evidence generator ignored |
| Task runner | 207 passed |
| ARM64 live checks | 44 passed |
| `tool`/`none` syscall matrices and published table | Three passed |
| Native freeze tables | 13 passed |
| Strace syscall identity | Seven passed; positive Landlock installation explicitly excluded |
| Optimized native build and workspace Clippy | Passed; Clippy denies warnings |
| Source and executable hashes | Pre/post source checks and executable checks passed |
| Native signing smoke | Both profiles passed; private keys and source stores deleted before final verification |
| Independent OpenSSL verification | Both signatures accepted; altered messages rejected |
| VPS-to-Pi portability | Six reports match: unsigned and signed pinned/untrusted, both profiles |
| Pi-to-macOS portability | Four signed reports match: pinned/untrusted, both profiles |
| Installed command smoke | Doctor ready, both profiles launched, both pinned bundles verified |

The [machine-readable summary](validation-summary.json) is derived from the
individual logs, including the [ledger suite](pi/validation/ledger.log). The
[native doctor](pi/validation/doctor.log) reports the clean source revision and
build-input digest
`sha256:4f45c7d14a754af0a72906747725c99cfadd8e673805e2b2412cf90c3e475512`,
which matches the tested reference freeze. The
[agent doctor](pi/validation/doctor-agent.json) exits 125 with
`unix_socket_diagnostics_unavailable`.

The [installation manifest](pi/validation/installation.json) records both
binary hashes and their versioned installation paths. A fresh login resolves
both commands in `~/.local/bin`. The
[installed smoke](pi/validation/installed-smoke.log) uses those commands from
a plain SSH session and retains its [tool](pi/installed-smoke/tool-receipt.json)
and [none](pi/installed-smoke/none-receipt.json) receipts. No test services or
Ouroboros processes remain running after validation.

The macOS verifier's [binary hash](local/binary.sha256) matches the binary
already validated in the [signed-bundle record](../2026-10-06-bundle-signing/README.md).
Runtime code is unchanged between that implementation and this source revision.
[VPS-to-Pi](pi/cross-platform.log) and [Pi-to-macOS](local/cross-platform.log)
reports preserve protection, coverage and signer-trust labels exactly.

This record supersedes the Pi-unavailable status for the October 6 ledger
feature slices. It does not change their historical results or close the
remaining best-effort outage, durability, custody or managed-authorization work.
