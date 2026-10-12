# Withdrawn startup candidate v3

All files here and the vps/pi candidate-v3 archives are excluded from the final
comparison. V3 reused a process-cached bubblewrap version in receipts, which
could go stale after a backend upgrade in a long-lived process. The final code
restores the original fresh readback. This correction does not relax any
isolation or observer check. The scored Linux benchmark restarts in a separate
owned root with the final source.

The VPS v3 timing run completed; its coding batch and the Pi timing batch were
interrupted. Their rows and interruption records remain. Raw attempts, journals,
build/quota failures, all earlier profiles and Pi instrumented diagnostics are
preserved. Mac controls are unaffected and completed using the frozen images.

Candidate source: ../../source-candidate-v3.patch and its companion hash
manifest. V3 timing analysis takes its inputs from this directory's results/.
All duplicate live snapshots are retained as unselected evidence.
