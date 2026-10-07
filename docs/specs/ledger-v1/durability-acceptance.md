# Ledger durability acceptance map

This maps [North Star §5.4](../../../north-star.md#54-durability) to executable
checks. The October 7 audit covers all five runtime properties and the acceptance
paragraph; historical custody is a separate obligation at the legacy cut. This
does not declare milestone 2 complete: the remaining CLI/privacy contracts are
listed below. Native evidence must identify the tested revision and host. The
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
| Capture beyond its cap | `opted_capture_stops_storing_at_the_cap_and_keeps_draining_the_real_child` in [launch_linux.rs](../../../crates/ouro-ledger/tests/launch_linux.rs) | A real 5,000-byte output stores 64 bytes, keeps draining and records `truncated: true`. Portable bundles preserve that label. |
| Vendor-state cleanup, including unknown outcomes | `vendor_state_is_removed_after_normal_exit_writer_death_and_owner_death` in [vendor_state.rs](../../../crates/ouro-ledger/tests/launch_linux/vendor_state.rs) | A real child populates vendor state before normal exit, writer SIGKILL or owner SIGKILL. Every case requires verified empty-tree evidence, absent vendor state and durable cleanup completion. Faulted runs remain unknown; replay preserves identity and executes no second child. |

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

## Acceptance paragraph cross-check

- Admission, append and settlement: the lifecycle and pending-journal matrices
  above cover durable writes, partial writes, synchronization, replacement,
  cleanup, lost replies and conservative restart. Every native fault must reach
  its hook. Complete unacknowledged records may recover only after validation
  and fresh durability barriers; partial records are never truncated away.
- Concurrent append and forged producers: the concurrent CLI test checks one
  sequence per identity. `forged_producer_role_attempt_and_peer_are_all_refused`
  and `protocol_refuses_caller_claimed_roles_and_oversized_frames` in `daemon.rs`
  reject guessed capabilities, wrong roles/runs/peer births and oversized frames.
- Store and index recovery: `disposable_projections_rebuild_without_rebinding_owner_requests_or_effects`
  and the other eight `storage_recovery.rs` tests preserve canonical history,
  receipts and cursors through missing/corrupt projections and damaged tails.
  The daemon queues the durable response before `flush_index`; the SQLite
  projection is not an acknowledgement authority.
- Privacy: `strict_transport_gap_and_private_metadata_refuse_without_an_ack`
  in `store.rs` and `prepare_cli_refuses_raw_metadata_without_persisting_it`
  in `cli_local.rs` exercise runtime refusal. Contract fixtures separately check
  schemas. The vendor-state test also checks its private content never enters
  canonical metadata.
- Writer death, child isolation, honest `none`, truncated capture and vendor
  cleanup each have explicit real-launch checks in the table. A clean hash
  chain never upgrades coverage, unknown outcomes or child protection.

A writer SIGKILL can leave an interrupted canonical frame even when vendor
cleanup succeeds. The cleanup test requires such a frame to remain poisoned
and byte-for-byte intact; it never requires `verify` to bless that history.

The [October 7 validation record](evidence/2026-10-07-durability-audit/README.md)
binds this cross-check and the added vendor-state test to native host results.
This closes the missing integration coverage identified by the audit; it is
scripted-child evidence, not physical power-loss or real-agent/provider proof.

## Remaining milestone-2 contracts

The broader [§5.2](../../../north-star.md#52-verbs) contract includes the
following completed slices and remaining CLI work:

| Contract | Current behavior | Remaining work |
| --- | --- | --- |
| L5 `show --with-transcript` | Implemented: opt-in terminal display, 64 KiB per stream, reversible byte escaping, explicit capture/retention/availability states. | [Pi/VPS native validation](evidence/2026-10-07-transcript/README.md); live streaming is outside this bounded display. |
| L5 `--capture argv` | Implemented: bounded private NUL-delimited native bytes, admission metadata, explicit bundle selection and both retention paths. Default metadata contains only the digest. | [Encoding/privacy/retention and native launch evidence](evidence/2026-10-07-argv/README.md): real `tool`/`none` launch, cap, replay and owner-death tests. |
| Foreground `--control-fd` | JSON control requires batch mode. | A separate control channel that never mixes JSON with child output, with descriptor and disconnect tests. |
| L9 `--redact` | Existing Jail-redacted metadata and private-field refusal are implemented. | Explicit structured minimization before append; preserve a truthful coverage/provenance record and make no claim to sanitize capture bytes. |

Next implementation slice: foreground control-FD output with descriptor and
disconnect tests. Historical custody remains required before the legacy cut in
North Star §9; this checkout does not perform that cut. Independent custody, managed authorization and
real-agent/provider acceptance remain separate gates.
