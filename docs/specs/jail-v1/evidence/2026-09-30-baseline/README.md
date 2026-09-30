# Jail baseline validation, 2026-09-30

The committed jail baseline `41d8c230716877b5da6e6db3220017b7eb685344`
passed the Linux reference-host conformance driver. The run is
`20260930T071326Z-41d8c2307168`; `summary.txt`, `test.log`, `doctor.json`,
and the plain-session smoke records are the driver-produced evidence.

This is the jail baseline before the `ouro-records` extraction and new
`ouro-ledger` workspace member. It does not validate that later workspace.

The baseline repairs four Rust formatting failures and pins the two
deliberately ignored Linux helpers omitted from the acceptance map:
the seccomp-table regeneration helper and the private mount-namespace
fixture. Native macOS acceptance exposed that the seccomp regeneration
helper is also compiled on macOS. The saved `acceptance-map.toml` includes
that additional macOS pin; this documentation-only correction was made
after the baseline checkpoint. No gate clause or evidence tag was weakened.

Validation:

- Linux reference-host conformance passed with `OURO_CONFORMANCE=1`,
  serial test execution, a scrubbed system PATH, and the pinned release
  build. Every Linux-lane noncredential gate passes or retains its
  documented limit; the suite reports no live skip.
- The native macOS workspace suite passed with `OURO_CONFORMANCE=1` and
  serial test execution. Its evaluated macOS acceptance clauses pass.
- Combined Linux and macOS acceptance passes every noncredential gate:
  43 pass and 7 pass with existing recorded limits. The real-agent A01
  credential gate is explicitly excluded and remains a separate run.
- Pinned workspace formatting, strict workspace/all-targets Clippy,
  x86_64 macOS workspace/all-targets compilation with warnings denied,
  dependency advisories/bans/licenses, and the I02 vendor-name scan pass.
  Cross-target compilation is compile-only evidence.
- `freeze-check.txt` records a successful milestone freeze check against
  the tested baseline: the binary's build inputs match both this tree and
  the named revision, that revision is an ancestor, and the frozen inputs
  have not changed since it. The generated baseline freeze is retained
  in the validation checkout; the later ledger workspace requires its
  own current conformance run and freeze.

The Linux build reports clean revision
`41d8c230716877b5da6e6db3220017b7eb685344`, Rust 1.98.1, optimization
level 3, debug assertions disabled, and build input digest
`sha256:f5486df5891709f837825bb55d051275c42b2e634165caeb239919247cc0cbfb`.
The pre-suite doctor measured the `ouro-jail` binary SHA-256 as
`1b52abdbd326eb0b422ba7638b4b3fb0fdc0fd0b72628a7a125184b5571037cd`.
The host is Ubuntu 26.04.1 LTS, Linux 7.0.0-31-generic x86_64,
bubblewrap 0.11.1, with the expected delegated cgroup controllers.
`doctor.json` preserves the measured capabilities and existing limits.

A later measurement, before removal of this run's target directory,
found that `cargo test --release` had replaced the release jail executable.
The retained post-suite binary has SHA-256
`3836cda7195da8c2dbc0bc4bfa07386604973870e77070549cea95d7887abf67`.
`post-suite-retained-doctor.json` measures that retained copy separately;
it reports the same clean revision, build-input digest, compiler, target,
and optimized build settings. Workspace test feature unification is the
likely cause of the changed bytes, but this run did not bind individual
test invocations to an executable hash. The original `doctor.json`
therefore records the pre-suite binary, not a proved post-suite identity.
The freeze proves the recorded source inputs and revision; it does not
close this historical executable-byte provenance gap. The updated
conformance driver precompiles the suite before its doctor measurement and
checks all product binary hashes again after execution.

Both executable versions were preserved before deleting only this run's
target directory. The initial doctor version remains in the local
onboarding staging directory; the post-suite jail and fixture are retained
in the reference host's private preliminary-test staging directory. The
retained fixture SHA-256 is
`28b4557896060e2b545c4481e9b2d5989a4c6d3ae56e4a3a430d9859d64cc5e4`.

The exact optimized GNU binary requires glibc 2.39 according to its ELF
version requirements. This run makes no compatibility claim for older
glibc distributions; clean-VM onboarding is recorded separately.

`macos-test-raw.log` preserves the native cargo output byte for byte.
`macos-test.log` adds three acceptance-driver metadata markers before
that same output. Those markers were added after the command completed,
from the recorded invocation (`OURO_CONFORMANCE=1`), the unchanged
baseline commit, and the shell PATH. No cargo output was removed or
rewritten. `macos-gates.*` and `combined-gates.*` evaluate these logs
against the saved acceptance-map snapshot at the explicitly named tested
revision.

The Linux driver is `cargo +1.98.1 xtask conformance` with the reference
host identity supplied externally. This repository evidence includes no
credential archive, and no host configuration changes were needed.
