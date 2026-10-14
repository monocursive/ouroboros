# Ouroboros Jail 0.1.0-rc.2 — publication record

[Ouroboros Jail 0.1.0-rc.2](https://github.com/monocursive/ouroboros/releases/tag/ouro-jail-v0.1.0-rc.2)
was published on 14 October 2026 as a GitHub prerelease, not marked latest. It
followed the [release procedure](../../RELEASING.md). Its scope is unchanged
from rc.1: Linux x86_64 and ARM64 only, `linux-preview`, with K22.2, K23.1,
K24.1, K26.1 and K29.1 unsupported.

- Release commit: `531d252a6c56e0403ae7b1937988f2037e294853`, tag `ouro-jail-v0.1.0-rc.2` (annotated).
- Jail build inputs: `sha256:bf40db551f4c3696406853e4acd0b892cd770296c175f6708c0835e83f14947b`.
- Toolchain: rustc 1.98.1.

The release contains the code-quality fix wave
([report](../../code-quality-fixes-2026-10-14.md)) and four fixes the release
gates found:

- `rustls` was raised to 0.23.46 for RUSTSEC-2026-0346 to 0349.
- The reference-host transfer list now carries `LICENSE`, which the package
  test needs (K27.1).
- A C fixture whose cached directory lacked its compiled helper is now rebuilt.
- A ledger test now tolerates macOS refusing a socket option after the peer
  has closed.

## Exact-commit checks

All required workflows passed on the release commit:

| Workflow | GitHub run | Result |
|---|---|---|
| `rust` | 38606899784 | success |
| `contracts` | 38606899712 | success |
| `fleet` | 38606899800 | success |
| `conformance` (reference host) | 38606899678 | success |
| `release-candidate` (native stages) | 38606975928 | success |

**Tested freeze.** The release commit records reference-host conformance of
its parent `e18e8c9f16ad`:

- Run: remote `20261014T165543Z`, GitHub run 38598521714, attempt 2.
- Gates: 65 pass, 8 pass with recorded limits, 1 pass with unsupported, 4
  unsupported, 4 elsewhere, and 1 credential.
- `freeze --check` reports `inputs_match_tree`, `revision_is_ancestor_of_head`,
  `inputs_match_revision` and `frozen_inputs_unchanged_since_revision`.
- The first attempt of that run stopped at the 20-minute build bound. A
  cancelled earlier run's remote build was still running on the same 4-CPU host.

## Clean-VM and real-vendor evidence (K11, K27)

The [record](results/release-preview-2026-10-14-bca/vm.json) comes from a disposable
x86_64 QEMU (TCG) guest on the maintainer's Mac:

- **Image:** the pinned Ubuntu 26.04.1 cloud image, SHA-256
  `8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2`.
- **Binary:** the x86_64 release build of `bca7585886e5`, SHA-256
  `75599b150f4f488ade97693240d8125b92248c9cc603b21a04997922cc8e7554`. It has
  the same build inputs as the release commit, since only evidence,
  documentation and tests changed in between.
- **Run:** the guest installed it through the pinned bootstrap, ran the real
  OpenCode workflow and the learning proposal, and exited 0. The VM was then
  destroyed.
- **Verification:** `verify_preview_evidence.py` passes `onboarding` and
  `learning` for these inputs. `portable_release_evidence` passes with
  `OURO_RELEASE_EVIDENCE=1`.

## Candidate, signing and installation checks

The native stages from the `release-candidate` workflow were assembled locally.
They were signed with the production key (`release.pub`, created on
10 October 2026), and `publish_release.py check` passed. The signed
`SHA256SUMS` lists:

| Asset | SHA-256 |
|---|---|
| `ouro-jail-0.1.0-rc.2-x86_64-unknown-linux-gnu.tar.gz` | `e2e77ffd1a508a2b2b49353b8f2fb2c511eb28fbd6f5af89387d48dd7df15497` |
| `ouro-jail-0.1.0-rc.2-aarch64-unknown-linux-gnu.tar.gz` | `28baa9b51821df4144689a730896ade833b58b8626e00eaf94ff0d4e807c5203` |
| `bootstrap.sh` | `6e057b82f6440dfb7688ef989ecfe60aea4647f16a4522e28ae6996ddabcfba6` |
| `install.sh` | `cfbb0727e9873686672c0115a6b98062289dd806f3753a7b9e87ee507a22997b` |
| `RELEASE_NOTES.md` | `cd582230f2341be7017a4eadee51fab4866300800850cb714c2d4304638eaca3` |
| `release-plan.json` | `f14b0f8d3734d3eb72a9de81cd0098082afc6c8c9d09b215b97bdc414301ece4` |

**Native checks.** The pinned bootstrap was installed into a private bin
directory twice, from the candidate and then from the downloaded draft assets.
Each time, `version`, `doctor --profile tool` and the
[guide's first command](../../guide.md#run-your-first-command) ran, and the
receipt settled with the tree verified. The hosts:

- x86_64: the Ubuntu 26.04.1 reference host.
- ARM64: ouro-dev, an OrbStack Linux VM on Apple Silicon, inside a delegated
  cgroup scope.

The release plan's ARM64 support note (a Raspberry Pi, with memory cgroups and
Landlock unavailable) is the generated support statement. rc.2 was not run on
the Pi.

**Publication.** `publish_release.py draft` created the prerelease and verified
every draft asset. `publish` re-checked the gates, published with
`--latest=false`, and verified all eight public assets through anonymous
downloads.

## Public installer

The root `install.sh` is now the reviewed rc.2 bootstrap. It defaults to
`0.1.0-rc.2` and keeps the rc.1 pins. `dist/release.json` names rc.2.

**Website.** The website was deployed from commit `79ab88d1c`. The live
<https://ouroboros.monocursive.com/install.sh> is byte-identical to the root
installer (SHA-256 `6e057b82…`), and the live `release.pub` matches the
repository.

**Public install.** On the reference host, a fresh `HOME` with
`PATH=/usr/bin:/bin` and no Rust toolchain ran the documented
`curl … | bash`. The result:

- installed release `0.1.0-rc.2`, binary SHA-256
  `b9770dfedd9bb1561c7ea0912887a433f3b9a5f7877a93f1acaf4718050414e8`, revision
  `531d252a6c56`, the inputs above;
- `doctor --profile tool` reported ready;
- the guide's first command wrote `greeting.txt` and settled its receipt.

Minisign was present on that host but is not used by the installer.
