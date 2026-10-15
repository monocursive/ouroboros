# Ukai VM 0.1.0-preview.1 — macOS developer preview

This release was published as `ouro-vm` before the Ukai rename. Its signed
package, commands and paths retain that identity.

Ukai VM runs offline Linux ARM64 commands in disposable virtual machines on
Apple Silicon Macs. This is a separate preview from the native Linux
`ouro-jail` release. Native macOS binaries, Xcode, Apple SDKs and online agents
are outside its scope; the native macOS process-lifetime question remains open.

## Install

Requires Apple Silicon, macOS 27+, about 8 GiB free APFS storage, and 2 GiB RAM
plus two virtual CPUs per active attempt. Execution was measured on macOS
27.0.1. Intel Macs and nested VM execution are unsupported.

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://ukai.sh/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"
ouro-vm version
ouro-vm doctor
```

The installer verifies the DMG against its embedded SHA-256 before mounting
or executing its contents. It installs under `~/.local/share/ouro-vm` and links
`~/.local/bin/ouro-vm`. No Python, Rust, Swift, Homebrew, sudo, Minisign or
Endpoint Security permission is required. An existing installation of this
version is preserved and a repeat install refuses.

The `bootstrap.sh` release asset is the same public installer. For an offline
install, put it beside the DMG and run `bash bootstrap.sh --from-dir .`.
Use `--vm-prefix /absolute/path` for a different root containing `bin` and
`share`. Read the [Mac quickstart](https://ukai.sh/guide/#macos-vm-preview)
for a first command, limits and uninstall instructions.

## Package identity

- Artifact: `ouro-vm-0.1.0-preview.1-macos-arm64.dmg`
- Size: 536,341,282 bytes (511.5 MiB).
- SHA-256: `f3a85e14987228bb5271956ce19bb4cb57272c24235b6f8b98db51b68e0c54a0`.
- Developer ID Application: Monocursive (`64SGQ348QJ`).
- Apple notarization: Accepted, `e922f3a3-ce4e-41ed-8fee-549183180ce7`;
  ticket stapled and validated.
- Linux Jail inside the guest: published ARM64 `0.1.0-rc.1`.

These are the exact final bytes tested in the
[package qualification](https://github.com/monocursive/ukai/blob/ouro-vm-v0.1.0-preview.1/docs/benchmarks/jail/macos-vm-preview-package-2026-10-11.md).
The DMG's readme, source archive and build metadata retain their original
pre-publication candidate wording. This release publishes that qualified
artifact without rebuilding it. The tag also includes the later public
installer, documentation and installation test harness.

## Qualified behavior and limits

The installed package passed 14/14 live teardown cases, 5/5 offline installer
cases, and functional `tool` and `build` runs. Fresh macOS VM installation and
CLI launch passed with SIP enabled and Gatekeeper set to App Store & Known
Developers. Actual Linux VM execution was tested on the physical Mac, because
the test macOS VM does not support nested virtualization. Each final fault
case was measured once; this is not a broad reliability claim.

Commands run against a copied workspace, with returned files adopted manually.
Both profiles can write that guest workspace. Protected system paths remain
read-only. No VM network adapter, host directory sharing, credential forwarding,
interactive stdin, save/resume/restart path or agent/provider integration is
provided. The guest includes a shell and Python, rather than a full build SDK.

The guest Jail limits are 512 MiB memory, zero swap, 64 processes and a 1–300
second wall limit. File transfer is limited to 5,000 regular files, 512 KiB each
and 32 MiB total. Symlinks, devices and FIFOs are refused. `.git`, `target`,
`node_modules`, `.venv`, `__pycache__` and `.DS_Store` are excluded; empty
directories are not preserved. Measured startup is about 22 seconds per attempt.

A completed attempt requires a verified Linux receipt and acknowledged VM stop;
incomplete evidence returns 125. A crashed launcher can leave disk data in its
output directory; never boot or reuse it. Simultaneous suspension of all three
host controllers, whole-host sleep/wake, kernel failure, arbitrary guest
compromise and a second physical Mac are outside qualified coverage.

This VM preview does not satisfy native macOS Jail acceptance clauses or claim
production readiness. The existing Linux release and its acceptance scope
remain separate.

## Licenses and source

The DMG contains the preview source, the project's original license, and
Python, PyInstaller and Linux Jail dependency notices. Ubuntu package copyright notices remain in
the guest under `/usr/share/doc`; installed package versions are recorded in
`/usr/local/share/ouro-vm/packages.txt`. Upstream image/archive URLs and hashes
are recorded in `payload/image/image.json`. Ubuntu source packages are available
through the corresponding [Ubuntu archive](https://ports.ubuntu.com/ubuntu-ports/).
The prepared image uses Ubuntu repositories without snapshot pinning; the final
distributed disk and DMG are pinned, but image preparation is not reproducible.
