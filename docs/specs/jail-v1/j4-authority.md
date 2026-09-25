# J4: evidence and recovery

Implemented on the named x86-64 Linux lane, 2026-09-23 to 2026-09-24, on the
same stock host as J3: Ubuntu 26.04.1, kernel 7.0.0-31, bubblewrap 0.11.1, the
distribution's user-namespace restriction left on, no sysctl, AppArmor profile,
file capability or setuid helper. The unprivileged `ouro-ci` account runs
everything. Live evidence is recorded under [`evidence/`](evidence/):

- [`j4-test-log-2026-09-23-ouro-ci.txt`](evidence/j4-test-log-2026-09-23-ouro-ci.txt):
  the full conformance suite, run `20260923T223358Z-8baec7d635e2` (PASS), 1299
  passed, 0 failed, 13 ignored: ten subprocess helpers invoked by their live
  tests, one documentation example, `bless_the_published_closed_set_table`
  (which writes the evidence table and is run deliberately), and the optional
  Unicode data test. It
  includes every J1, J2, J3 and J4 suite.
- [`j4-doctor-2026-09-23-ouro-ci.json`](evidence/j4-doctor-2026-09-23-ouro-ci.json):
  `doctor --json` in the delegated user scope, 25 rows, 24 available and
  `nested_user_namespace` unavailable, as a stock host should report.
- [`j4-host-manifest-2026-09-23-ouro-ci.txt`](evidence/j4-host-manifest-2026-09-23-ouro-ci.txt):
  the host as measured for that run.
- [`closed-set-x86_64.txt`](evidence/closed-set-x86_64.txt): the published
  closed-set table, generated from the build and the installed narrowing filter,
  with the narrowing-filter digest that live receipts record; the contained
  baselines' tables are
  [`seccomp-table-tool-x86_64.txt`](evidence/seccomp-table-tool-x86_64.txt),
  [`seccomp-table-agent-x86_64.txt`](evidence/seccomp-table-agent-x86_64.txt) and
  [`seccomp-table-agent-namespace-x86_64.txt`](evidence/seccomp-table-agent-namespace-x86_64.txt).

The run name identifies the tested revision. An earlier run on the tree before
the third wave, `20260923T205756Z-17a0533c0273`, also passed (1249, 0, 12).

## How it was built

J4 started from eight defects found by reading the J3 code (two observation
holes, an outbox that could drop critical facts, a `gc` that created locks, a
reused receipt revision, an overwritten stop cause, a canonicalization
mismatch and a spec contradiction). Each was reproduced by a failing test
before its fix. A read-only gap analysis then mapped every J4 gate and split
the rest into five slices: closed set and attribution, loss handling, bounded
trace, atomic records, and GC reconciliation. A second wave fixed what those
slices found in each other's code. Seven adversarial reviews of the merged
code followed (trace sinks, observer, lifetime watcher, loss handling, tracer
restarts, records, gc); they verified 21 findings and the observer review
found none, and a third wave fixed them. Every fix was written test-first and
mutation-checked: the fix reverted, its test red, the fix restored. The
decisions each fix forced are in [review-resolutions.md](review-resolutions.md),
revisions 13 to 17.

## Acceptance map

All tests run live on the reference host unless named portable.

| Gate | Tests |
|---|---|
| O01 | `j4_closed_set_linux`: `j4_o01_every_variant_is_one_event_per_result_{tool,build,none,agent}` (37 fixture results matched one to one per profile), `j4_closed_set_the_published_table_is_the_one_this_build_traces`; `observer_linux` tracer-level comparison of all 22 rows; `j4_tracer_precision_linux`: `j4_o2_*` (interrupted calls give their one result), `j4_w3_a_leaders_entry_is_never_paired_with_a_non_leader_execs_exit` |
| O02 | `j4_o02_every_audit_event_names_the_birth_of_its_process`, `j4_o02_a_nested_pid_namespace_under_none_keeps_host_attribution`, `j4_o02_recycled_tid_carries_nothing_over` (session-level); J2/J3 exec, worker-exit and fork-without-exec cases |
| O03 | `j4_loss_linux`: `j4_o03_a_class_never_returns_to_active_after_an_early_gap`, `j4_o03_unmatched_exit_is_unreachable` (tracer seam), `j4_o03_exhaustion_through_the_product`; `observer_j4_linux`: `j4_d6_critical_facts_survive_a_full_lifecycle_backlog`, `j4_d1_*`, `j4_d2_*`; `j4_tracer_precision_linux`: `j4_o3_*`, `j4_w3_*_refused_a_slot_is_the_open_ended_gap_of_its_kind`, `j4_w3_r1_*` |
| O04 | `j4_o04_an_unrelated_host_process_is_never_observed`; `j4_o1_*` (read-only opens are neither results nor loss); J2 `write`/`mmap` exclusions |
| O05 | `j4_o05_attach_failure_refuses_in_best_effort_{tool,none}`, `j4_o05_directory_operation_losses_degrade_fs_write`, `j4_o05_denied_connect_counts_only_in_fs_deny_{tool,none,agent}`, `j4_observer_plan_is_recorded`; J3 observation-off cases |
| O06 | `j4_o06_{renamed_cwd,foreign_dirfd,two_paths_independent,non_utf8_round_trip,racing_pathname_is_only_a_literal_snapshot}`; the r6 path tests |
| R01 | portable `r01_every_example_validates_against_its_schema`, `r01_every_example_round_trips_through_the_rust_types`, `r01_every_validation_case_gets_the_verdict_the_corpus_expects` (44 corpus cases), `r01_the_semantic_checks_reject_what_the_schema_accepts`. This row said every live test runs the schema and the Rust `semantic_receipt` checks on each product receipt it reads; that was false until J5-C: `j4_loss_linux.rs`'s receipt helper ran the schema only, and two `none` receipts in `observer_j4_linux.rs` ran neither ([J5 authority](j5-authority.md)) |
| R02 | portable `j4_r02_every_site_under_every_fault_leaves_valid_records` (sites P1 to P16 × ENOSPC, short write then EIO, fsync, rename and directory-sync errors), `j4_r02_a_stalled_sync_never_delays_the_wall`, `j4_r02_persistence_that_cannot_finish_in_5s_stops_the_child_unacknowledged`, `j4_w3_p1a_*`, `j4_w3_p1b_*`, `j4_w3_p2_*`, `j4_w3_p3_*`; live `j4_r02_a_crash_at_each_replacement_leaves_a_valid_prior_file` and `j4_r02_a_crash_at_each_point_of_a_gc_record_leaves_valid_records` (abort at every named point) |
| R03 | `j4_trace_linux`: saturation and disconnect in both evidence modes, `j4_r03_the_wall_is_enforced_while_the_trace_is_saturated`, `…_while_the_trace_queue_is_full`, the local-cap and local-write-failure cases, `j4_r03_a_slow_consumer_within_the_deadline_loses_nothing`, `j4_r03_a_trace_fd_is_not_duplicated_locally`; portable `portable_trace` (partial writes, torn tails, `j4_r03_a_drain_that_gives_up_mid_frame_writes_nothing_after_it`), `j4_r03_control_backpressure_*`, `j4_n4_*` |
| R04 | portable `j4_r04_{strict_stops,best_effort_runs_to_the_end_degraded_exits_1,later_loss_keeps_first_cause,protection_labels_never_change}`, `j4_w2s_r1_*`, `j4_w2s_r2_*`; live `j4_r04_ptrace_loss_{strict,best_effort}_{tool,none}`, `j4_r04_a_call_in_flight_at_teardown_is_loss_*` |
| R05 | `conformance_j3_none`: `r05_clean_none_evidence_stays_unprotected`, `r05_same_uid_tampering_is_outside_local_evidence_assurance` |
| R06 | `conformance_j3_none`: the five `r06_*` cases |
| C03 | portable `portable_gc` (live lease, unclaimed roots and the claim race, corrupt and foreign state, symlinks, the per-invocation bound, other boots, owners alive, identity checks, attempt association, intent records, finished attempts, repeated records, lost integrity); live `j4_gc_linux`: `j4_c03_a_populated_orphan_leaf_of_this_boot_is_killed_verified_and_removed`, `j4_c03_a_replaced_leaf_is_never_touched`, `j4_c03_a_simulated_reboot_never_targets_a_reused_cgroup`, `j4_c03_a_stale_owner_pid_never_signals_an_unrelated_process`, `j4_c03_contained_crash_leaves_an_empty_leaf_that_gc_removes`, `j4_n7_*`, `j4_w3_g2_a_forged_registration_of_a_live_attempts_leaf_is_never_acted_on`, `j4_w3_p1c_a_zombie_leader_with_a_live_thread_is_alive` |
| L02 (J4 additions) | `j4_lifecycle_linux` (the watcher kills the whole execution leaf on supervisor death, whichever death it sees first; release protocol); `conformance_j2` `l02_*`; `r7_doctor_leaves_no_orphaned_fixture_process` |

## Known gaps

- A supervisor killed during bubblewrap's startup, in an attempt without an
  execution leaf, can leave the namespace init (and under `agent` its bridge)
  alive; §9.3 states the limit. Since revision 18, `run` and `doctor` enter a
  delegated user scope themselves where the user manager lingers, which closes
  it from a plain login session (20 of 20 synchronized `agent` kills left
  survivors before, 0 of 20 after); without lingering the supervisor stays in
  its session and the limit remains.
- PID reuse is not forced live (it needs `CAP_SYS_ADMIN` in the pid
  namespace); a session-level hook simulates a recycled tid. Nested pid
  namespaces are evidenced only through `none` running the host's bubblewrap.
- A stalled disk cannot be produced on the stock host: the persistence worker's
  stall handling, the lease held across an in-flight step, and tree termination
  before persistence are proven portably through the persistence seam, and the
  platform's "loss after the target's end" flag portably only.
- A program that rewrites its signal frame to `EINTR` and then repeats the same
  call from the same instruction is indistinguishable from a restart: the
  repeated call's result is reported, the intervening `EINTR` is not. A
  handler that exits while a blocking covered call waits to restart is a gap,
  which stops a strict attempt.
- Under `agent`, a connect a signal withdraws from the mediation queue before
  any worker received it is a named exclusion (§11.4); under `none`, `io_uring`
  operations run unobserved (§§9.2, 11.2).
- `gc` retains execution leaves made by builds before the attempt-named leaves;
  a same-uid forgery in another data directory is not detected; attempts
  retained for recovery still count against gc's bound on every pass.
- Test seams (`OURO_JAIL_TEST_*`) exist in the release binary; each one set is
  recorded in jail state and in native details, and a refusal before a
  boundary exists records them in jail state only.
- On macOS, `portable_proxy`'s descriptor-exhaustion helper fails under a full
  parallel workspace run and passes alone; the file is unchanged since J3.
