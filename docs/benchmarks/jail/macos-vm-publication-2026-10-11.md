# macOS VM preview publication — 11 October 2026

**Published:** [Ouro VM 0.1.0-preview.1](https://github.com/monocursive/ouroboros/releases/tag/ouro-vm-v0.1.0-preview.1),
an explicit GitHub prerelease. The public installer, homepage, guide, roadmap,
Markdown documents and agent index describe the Mac VM path. Native macOS
execution remains unavailable; the Linux release is unchanged.

## Identity

The release tag points to `81a7096211689755d86907346d47792a29738cb3`.
The installer received a subsequent compatibility correction for CI's older
ShellCheck in `3d6b8fb5dad4dfb525f48bb97b33e31d83f368db`.
Its SHA-256 is `b817557c25f1f4ea6cafaca96dbcfcbdd704ba1512888a3155f4c4603c47d96e`;
the release's `bootstrap.sh`, repository installer and website copy match.
The earlier tagged installer has the same runtime behavior and DMG pin.

The DMG is unchanged from [package qualification](macos-vm-preview-package-2026-10-11.md):
536,341,282 bytes, SHA-256
`f3a85e14987228bb5271956ce19bb4cb57272c24235b6f8b98db51b68e0c54a0`.
Stapler validation and Gatekeeper's DMG assessment passed again before upload.
All ten checked runtime/build source files match package provenance. GitHub's
digest and size metadata match all seven assets, including the corrected
bootstrap. Installation independently downloaded and verified the public DMG
on two Mac environments.

## Public installation and execution

- **Physical Mac, macOS 27.0.1 ARM64:** the website installer downloaded the
  GitHub DMG, installed into a fresh prefix containing spaces, and passed all
  `doctor` package/host checks.
- **Isolated macOS 27.0 ARM64 VM:** public installation succeeded as UID 501
  with the system PATH, SIP enabled and Gatekeeper assessments enabled. The
  installed CLI launched and reported `0.1.0-preview.1`. All package checks
  passed; virtualization support remained false because nested virtualization
  is unavailable. No host shares or credentials were exposed.
- **Guide quickstart on the physical Mac:** the public executable completed
  the documented `build` command with exit 0, returned `output.txt`, left
  original inputs unchanged, and removed the private disk. Startup was 20.995
  seconds; total elapsed time was 21.324 seconds. The Linux receipt is settled
  with a verified empty tree and no errors; the Mac record acknowledges VM stop.
- **Linux regression:** the same installer downloaded the unchanged x86_64
  `0.1.0-rc.1` package on Ubuntu 26.04.1. Installation, version reporting and
  `doctor --profile tool --json` succeeded. This was not a full conformance run.

The 14/14 teardown cases, 5/5 offline installation cases and both functional
profiles remain in package qualification. Publication adds public delivery and
quickstart proof, rather than repeated fault statistics or another physical Mac.

## Checks and evidence

All 12 bootstrap regressions pass, including Mac tampering before mounting and
ejection after installation failure. The 10 release assembly, 2 version and 8
publication regressions pass. VM boundary tests pass 12/12 and native mechanism
evidence summaries pass 72/72. Contract validators, ShellCheck, Markdown links
and the Astro production build pass.

CI initially rejected trap reachability and conditional syntax under its older
ShellCheck. The correction retains the EXIT trap and explicitly branches on
the Mac version check; the subsequent contracts workflow passed. Raw research
output remains byte-preserved under the existing whitespace-attribute convention.

All 23 served website build files match both the production deployment and
canonical domain byte for byte. The live Mac quickstart was also inspected in
the browser. See the [publication summary](results/macos-vm-publication-2026-10-11/publication.json)
for deployment and asset identities, and the [evidence directory](results/macos-vm-publication-2026-10-11/)
for installation logs, the quickstart receipt and website hashes.

The isolated test VM was stopped after installation. The earlier native
research VM was not changed. Original build qualification metadata retains
its pre-publication state; this record establishes subsequent publication.
