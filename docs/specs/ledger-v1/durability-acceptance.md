# Ledger durability acceptance map

This maps [North Star §5.4](../../../north-star.md#54-durability) to executable
checks. It is an implementation map, not a declaration that milestone 2 is
complete. Native evidence must identify the tested revision and host. The
[lifecycle crash record](evidence/2026-10-06-lifecycle-crashes/README.md)
binds the implementation below to its full-suite logs and per-case checks.

| Property | Executable checks | Proof boundary |
| --- | --- | --- |
| Child isolation and honest `none` label (§5.4.1) | `contained_child_cannot_read_or_mutate_the_ledger_or_connect_to_its_writer`, `explicit_none_profile_remains_unprotected_after_real_launch_and_verification` in [launch_linux.rs](../../../crates/ouro-ledger/tests/launch_linux.rs) | Actual Linux jail and owner; `none` remains unprotected. |
| Durable acknowledgement (§5.4.2) | `io_errors_at_every_lifecycle_boundary_refuse_ack_until_recovery`, `sigkill_at_every_lifecycle_boundary_preserves_identity_and_canonical_bytes` in [lifecycle_tests.rs](../../../crates/ouro-ledger/src/store/lifecycle_tests.rs) | Five lifecycle mutations at fourteen persistence cuts: 70 injected I/O failures and 70 actual writer-process SIGKILLs. Process crashes do not prove power-loss durability. |
| Ambiguous appends refuse acknowledgement (§5.4.3) | Same matrices; [storage_recovery.rs](../../../crates/ouro-ledger/tests/storage_recovery.rs) | Live retries cannot acknowledge poisoned preparations or appends. Restart preserves every canonical byte; partial frames remain poisoned. Complete tails are synchronized and recovered. |
| Stable identities and no second child (§5.4.4) | Matrices above; `real_launch_gate_survives_admission_settlement_and_lost_reply_crashes` in [launch.rs](../../../crates/ouro-ledger/src/store/lifecycle_tests/launch.rs); `durable_admission_precedes_real_exec_and_replay_never_executes_twice`; `different_payload_cannot_rebind_prepare_or_effect_identity` in [store.rs](../../../crates/ouro-ledger/src/store.rs) | Real production owner/jail against a test-only instrumented writer. Admission and settlement use every persistence cut in both evidence modes; lost replies cover all five mutations. A lost preparation reply may be retried to execute the still-unowned attempt once. |
| Strict live failure (§5.4.5) | `writer_death_stops_the_owner_and_recovery_remains_unknown`, `owner_death_is_reconciled_as_unknown_and_never_relaunched`, detached writer/owner death tests in [launch_linux.rs](../../../crates/ouro-ledger/tests/launch_linux.rs) | Actual process death, tree termination and conservative orphan reconciliation. |
| Best-effort outage (§5.4.5) | `best_effort_writer_restart_reconciles_bounded_overflow_without_reexecution`, exit-during-outage, missing-exit, forged-control and local-journal/file-limit failure tests in [launch_linux.rs](../../../crates/ouro-ledger/tests/launch_linux.rs) | Bounded pending evidence, degraded coverage and recovery after an admitted launch. See the [writer-outage evidence](evidence/2026-10-06-writer-outage/README.md). |
| Historical custody at removal (§5.4.6) | No migration acceptance record yet | A read-only historical export or lossless import preserving original bytes, IDs and receipts is still required at the cut. Signed new bundles do not establish this. |
| Concurrent producers, forged messages, recovery and privacy | `concurrent_operator_ingress_and_lost_reply_keep_one_sequence_per_identity` in [cli_local.rs](../../../crates/ouro-ledger/tests/cli_local.rs), [daemon.rs](../../../crates/ouro-ledger/src/daemon.rs), [storage_recovery.rs](../../../crates/ouro-ledger/tests/storage_recovery.rs), store tests and [contract validator](validate_contract.py) | Protocol authentication and canonical replay are executable checks; schema/privacy fixtures alone prove only the document contract. |

The lifecycle matrix covers `prepared`, `owner_claimed`, `admitted`, `source`
and `settled`. Its persistence cuts are event write, a synchronized partial
event, event sync, after event sync, projection write/sync/rename/directory sync,
manifest write/sync/rename/directory sync, and the final directory sync before
and after completion. The native matrix adds the point immediately before a
successful daemon reply is sent. Each case proves its hook was reached.

All instrumentation is compiled under `cfg(test)` into the library test
executable. Production binaries have no fault configuration, environment
switch or fault IPC request. Native cases use the production ledger launch
owner and jail, then restart the production writer before replay. The test
worker is a subprocess mode of the crash test; no test is marked ignored.

The [pending-journal matrices](../../../crates/ouro-ledger/src/pending/crash_tests.rs)
cover initialization, outage marking, source buffering, local exit, reconciliation
clear and cleanup: 44 injected I/O failures and 44 actual SIGKILLs. Recovery
sync failures cannot import or acknowledge the journal. Cleanup keeps a stable
mutex inode. The [native owner matrix](../../../crates/ouro-ledger/src/pending/crash_tests/launch.rs)
injects save and cleanup faults into the real owner against the production
writer and jail, checking admission, tree termination and replay. The
[pending-journal evidence](evidence/2026-10-07-pending-journal/README.md)
records the tested revision and platform coverage.

Remaining acceptance work is a final cross-check of the full §5.4 acceptance
list before declaring that gate complete, plus historical custody at the cut.
Physical power loss,
independent custody, managed authorization and real-agent/provider acceptance
are outside the evidence described here.
