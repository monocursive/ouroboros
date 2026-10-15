# Ukai rename: preview evidence refresh

The rename changed the Jail build inputs, so the previous K11/K27 records no
longer matched the current binary. This fresh disposable x86_64 QEMU VM run
records the renamed build; the previous evidence remains unchanged.

- Source revision: `fab13b39b2db6bde854e797a413d4d88a8cf08c2`.
- Build inputs: `sha256:54c52eb2ba638d434ded066893c6d03388b1c822866143ca335e3f14de8313a2`.
- Binary SHA-256: `b7aeb92b73629b5dfc7e15e58406b7f198ac0857ee39e0c6db1c82aa53b3145a`.
- Binary source: the clean optimized build from reference-host CI run
  [38733622771](https://github.com/monocursive/ukai/actions/runs/38733622771).
  That run failed its two stale preview-evidence tests; this record supplies
  fresh evidence for the subsequent CI run rather than changing that result.
- Ubuntu image, guest configuration, and teardown: [vm.json](vm.json).
- Onboarding, learning, and distribution results: [guest/result.json](guest/result.json).

Signed installation, contained `true`, and the real OpenCode 1.18.32 task
completed in 80.726 seconds. The timer includes agent download and excludes
VM/dependency setup. The learning workflow and archive/signature corruption
checks passed. No provider retry occurred, no Rust toolchain was installed in
the guest, and no host policy was changed. The disposable VM was destroyed.

The package uses a temporary test signing key and the existing rc.2 version
label for this local qualification. It is not a newly published release or a
production-signed artifact. Both `onboarding` and `learning` checks in
`verify_preview_evidence.py` pass against the input digest above.
