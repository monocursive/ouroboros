# J5: milestone proof

The milestone report of [jail-v1 §16](../jail-v1.md#16-implementation-order-and-exit-criteria).
Implemented on the named x86-64 Linux lane, 2026-09-24 to 2026-09-25, on the
same stock host as J3 and J4: Ubuntu 26.04.1, kernel 7.0.0-31, bubblewrap
0.11.1, the distribution's user-namespace restriction left on, no sysctl,
AppArmor profile, file capability or setuid helper. The unprivileged, lingering
`ouro-ci` account runs everything.

Milestone 1's evidence, all at revision
`4380241f3195bcc73a5186282400eda3b174ee41`:

- The milestone conformance run `20260925T015603Z-4380241f3195`, driver
  verdict PASS. Linux lane on the reference host: 1679 passed, 0 failed, 14
  ignored, over 68 test binaries
  ([test log](evidence/j5-test-log-2026-09-25-ouro-ci.txt)). macOS lane at the
  same revision, run with `OURO_CONFORMANCE=1` on a local Apple Silicon
  machine: 996 passed, 0 failed, 6 ignored
  ([test log](evidence/j5-test-log-2026-09-25-macos.txt); its PATH marker is
  redacted).
- The per-gate verdict over both lanes
  ([gates.txt](evidence/j5-gates-2026-09-25.txt),
  [gates.json](evidence/j5-gates-2026-09-25.json)); see
  [Acceptance verdict](#acceptance-verdict).
- The run's host manifest, `doctor --json` (`ouro.jail.doctor/1`):
  [j5-doctor-2026-09-25-ouro-ci.json](evidence/j5-doctor-2026-09-25-ouro-ci.json),
  ready, 26 capability rows, all available except `nested_user_namespace`
  (unavailable, as on any stock Ubuntu 24.04 or later), with the manual
  [host manifest](evidence/j5-host-manifest-2026-09-25-ouro-ci.txt) beside it.
- The plain-session smoke leg ([smoke](evidence/j5-smoke-2026-09-25-ouro-ci.txt)):
  a `tool` run, a `none` run and `doctor`, started from the SSH session's own
  `session-8798.scope` without `systemd-run`, each exit 0; the driver requires
  each to have entered a delegated scope itself, and their records show it:
  the [tool](evidence/j5-smoke-tool-receipt-2026-09-25-ouro-ci.json) and
  [none](evidence/j5-smoke-none-receipt-2026-09-25-ouro-ci.json) receipts are
  settled, exit 0, with `supervisor_scope` `entered` and an execution leaf,
  and [doctor](evidence/j5-smoke-doctor-2026-09-25-ouro-ci.json) is ready with
  its scope `entered`.
- The I01 probe ([i01](evidence/j5-i01-2026-09-25-ouro-ci.txt)): the suite's
  PATH is the system directories, and no ledger, fleet or BEAM binary,
  installation directory or package is present.
- The freeze with its tested run ([Freeze](#freeze)), the performance
  measurement ([Performance](#performance)) and the A01 run ([A01](#a01)).
  The conformance run, the performance run and A01 ran the same `ouro-jail`
  binary, SHA-256
  `90dbd434296f8b3679d56fea1c6413f30bf7d8cfe558abc1e6cb2961eef5e898` (the
  build is reproducible from the revision).
- [`d8-candidates-2026-09-24-ouro-ci.txt`](evidence/d8-candidates-2026-09-24-ouro-ci.txt):
  `srt` and Greywall on the stock host, the evidence of the D8 decision
  ([backend-evaluation.md](backend-evaluation.md)).
- Earlier, not milestone evidence:
  [`j5-base-test-log-2026-09-24-ouro-ci.txt`](evidence/j5-base-test-log-2026-09-24-ouro-ci.txt),
  the full suite at `1328c381` before any J5 slice (run
  `20260924T194045Z-1328c38108fa`, 1345 passed, 0 failed, 13 ignored), the log
  the verdict code was first tested against; and
  [`perf-harness-validation-2026-09-24-ouro-ci.md`](evidence/perf-harness-validation-2026-09-24-ouro-ci.md),
  the performance harness on a loaded host with 3 launches per arm.

## How it was built

A read-only gap analysis of `638bb699` mapped every §15 gate to its tests
clause by clause: 19 gates proved, 6 proved only below the command line or by
simulation, 24 partial, and I01 missing. No full conformance run passed at that
revision: three hosted runs had lost their SSH connection mid-suite, and a
fourth failed on a SIGTERM that the integrator's own session sent on the
shared host (the failing test binary passes alone). The
operator took four decisions on 2026-09-24 (the `execution_boundary` rename;
the performance budgets apply to the jail's own overhead, refined on
2026-09-25 on the measurement, see [Performance](#performance); eBPF withdrawn
from v1; A01 re-run without a credential, its support claim in the record),
and the
work was split into slices with disjoint files:

- **J5-A**, the suite driver: the acceptance map, the per-gate verdict over
  the suite's own log, the I01 probe, the plain-session smoke leg and the
  contract validator inside the driver.
- **J5-B1**, the process and gate-protocol gates (P, X, I03) and X04's fix;
  **J5-B3** took its lifetime tests (L01, L02, L03, L04, X07).
- **J5-B2**, the boundary gates (F, S, N01, N05, R06) and the O03 and R03
  seams.
- **J5-C**, the records: gate and control schemas, per-source event rules, the
  library semantic checker with its Python port, and the schema freeze.
- **J5-D**, provenance: `build` in `version` and `doctor`, `doctor --json` as
  the host manifest, the architecture refusal, the freeze file, cross-target
  compilation and the portable renames.
- **J5-E**, the performance harness.
- **J5-T**, the tracer's end and `none`'s children, after the J5-C review
  found `--trace-fd 3 3> >(cat)` refusing every observed run.

The slices were reviewed adversarially before integration, with mutation
replay of their enforcement points, and a fix wave followed each review of
J5-A, J5-B1, J5-B2, J5-C, J5-D and J5-E. The review of J5-T found it sound,
with no blocking issue; its one low-severity finding, a test gap, was closed
by unit tests. Review of J5-B3 and the late waves (J5-B2 waves 3 and 4, J5-C
wave 3): **TO BE FILLED BY THE INTEGRATOR**. Every product fix was written
test-first and mutation-checked: the fix committed,
reverted, its test red, restored. The decisions the fixes forced are in
[review-resolutions.md](review-resolutions.md), revision 19, and in the
specification's revision 19.

## Defects found and fixed

| Defect | How it was found | Fix | Test |
|---|---|---|---|
| Bubblewrap was found by a PATH walk that fell back to the bare name and was searched again at every exec: through an empty PATH entry a `./bwrap` in the working directory ran during `doctor` (18 times) and under `run --profile tool` while `doctor` recorded no backend; with PATH unset the C library's default path ran an unrecorded `/usr/bin/bwrap`; a relative entry was recorded as a relative path | Review of J5-D | Resolved once per process to an absolute canonical path; unset PATH is no backend (`fb5bf5cc`) | `j5_bwrap_resolution_linux.rs` |
| The tracer ended only on `ECHILD`, so a child the supervisor was started beside (a shell's process substitution reading `--trace-fd`) made `doctor` report the observer unavailable and every observed run refuse 125 as `host_setup`; past the probe, a clean strict `tool` run failed settlement after the full 5 s budget, ending `tree_unknown` with an `unreaped_children` gap; the probe's refusal was a false diagnosis of the host | Review of J5-C (a `--trace-fd 3 3> >(cat)` run refused); J5-T found the cause | The tracer ends on its own accounting: every traced task reaped and the backend exited (`8e765511`) | `j5_tracer_foreign_child_linux.rs` (9 tests); `observer_regression_linux.rs::r11` corrected, since it modelled bubblewrap as the launcher's sibling |
| `none`, a child subreaper, classified such an inherited child as an escaped attempt process, refused the run and killed the child | J5-T | Inherited subtrees are recorded by birth identity and never touched (`62276b36`) | the `j5t_none_*` tests |
| After that fix, `none --observe on` left the target's adopted orphans unreaped: 120 children that exited before the target were reaped only as tracees, passed to the supervisor as zombies when the target exited, and the tracer, no longer waiting for `ECHILD`, finished at once | J5-B3's fork-burst test (`l01_a_fork_burst_is_fully_reaped`), red with 120 zombies | The tracer records the children the process has at attach; any other child that is not a tracee is an orphan of the traced tree, owed, reaped and delivered as an untraced exit before it finishes (`acc3cda9`, J5-T); a unit test tells a gained child from a bystander by pid and birth (`8b70be51`) | `j5_lifetime_linux.rs::l01_a_fork_burst_is_fully_reaped`, `j5t_orphans_adopted_while_traced_are_reaped_before_finished` |
| A best-effort run whose `--trace-fd` consumer stalled past the deadline produced a complete-looking trace with no loss note: the terminal drain dropped the queued note and then delivered the final receipt note | The new semantic rule `trace_loss_recorded`, live on the reference host | A reserve note the drain cannot deliver ends the stream (`2dbae36a`) | `j5_records_linux.rs::j5_a_trace_loss_note_and_its_receipt_agree` |
| The first loss note named every stream class (`proxy.net` under `tool`) from the last healthy point, while the receipt's gaps began at 0 with each class's source | Review of J5-C | The note names the covered classes; the receipt takes the note's start and source (`27325dab`) | same, and the semantic corpus |
| A panicked tracer thread, or a result a poisoned trace lock could not take, degraded audit classes with no gap | Review of J5-C | `observer_panicked` and `trace_writer_poisoned` gaps (`27325dab`) | `j5_audit_gaps_linux.rs` |
| A single non-UTF-8 mount point failed the whole mount-table read, and the receipt claimed an empty `applied.filesystem.mounts` | J5-B1's new P01 test | `mountinfo` read and parsed as bytes (`7abb3668`) | `j5_process_linux.rs::p01_a_non_utf8_policy_path_survives_execution_into_the_receipt` |
| The preparation and gate budgets ran on `CLOCK_MONOTONIC`, which stops during suspend, although §6.4 puts them on `CLOCK_BOOTTIME`: with only the boot clock advanced two minutes past `prepared` (an `LD_PRELOAD` clock shim), a gated run still waited its full 60 s | J5-B3 | Both budgets run on the supervisor's boot-clock elapsed time, and a gate wait re-checks its deadline at least every 250 ms (`21ff0362`, J5-B3's patch) | `j5_lifetime_linux.rs::l04_the_gate_wait_follows_the_boot_clock` |
| A credential in a project file was a syntax error at `jail`, not the widening it is | J5-B1's P02 tests through the real file layers | `policy_widening` at `jail.credentials` (`fe40b0d3`) | `portable_policy.rs` P02 cases |
| The supervisor kept the caller's stdout for the whole run: a target that closed stdout gave the caller no EOF until the jail exited | J5-B1's X05 test | The binary points its own stdout at `/dev/null` once the attempt is prepared (`7abb3668`); the first version did so inside the library and silently took stdout from in-process callers, so the release is the binary's opt-in (`8012bae5`) | `j5_process_linux.rs::x05_under_none_eof_reaches_the_caller_when_the_target_closes_its_stdout`, `j5_process_portable.rs` |
| With observation off, a contained target that ended within the supervisor's poll interval settled `unknown` and the jail exited 1 with nothing on stderr and no `errors[]` entry | Reviews of J5-C and J5-E (every `/usr/bin/true` under `tool` or `agent`) | The coded tool error `exec_unconfirmed` (`400eac7a`) | `j5_process_linux.rs::observe_off_an_unconfirmed_fast_exec_is_the_coded_error_exec_unconfirmed` |
| A missing program and a missing interpreter produced identical outcomes (both `ENOENT`); the X04 test only printed the messages | Gap analysis; J5-B1 | The launcher detects an existing target whose interpreter or loader is missing; `exec_interpreter_missing` (`c6708dfc`, `bd75d939`) | `j5_process_linux.rs::x04_*` |
| "Withheld" and "closed" gates sent identical bytes | Gap analysis; review of J5-B1 | Withheld holds the gate open (`prepare_timeout`), closed reaches EOF (`gate_closed`) (`7abb3668`) | `j5_process_linux.rs::x02_a_closed_and_a_withheld_gate_differ_and_neither_runs_the_target` |
| The I03 owner read its expected plan from the prepared receipt it judged, so a wrong argv digest or a dropped requirement passed | Review of J5-B1 (a mutated product stayed green) | The owner's plan comes from its own inputs (`6ce0c7c7`) | `j5_process_linux.rs::i03_*` |
| An unfrozen schema declaring a frozen schema's `$id` replaced it in both registries: an audit event with `decision: allow` and `source_seq: 0` validated, and no frozen SHA-256 changed | Review of J5-C | One `$id` per schema file, refused by both loaders and the freeze test (`57ff7437`) | loaders' negative cases; `portable_version.rs` |
| A frozen entry could be re-blessed by editing the schema and its SHA-256 together; the freeze left `policy/1`, `policy-file/1` and `network/1` without a frozen artifact; Linux conventions sat in the shared envelope | Review of J5-C | The rule: changed bytes are a new identifier; `[[frozen_artifact]]`; conventions moved to the producer schema (`4f322499`) | `frozen-schemas.toml`, `portable_version.rs` |
| `eprintln!` panics when its write fails, so a run whose stderr could not be written (an io_uring descriptor, which S04 refuses before exec) exited 101 instead of the refusal's 125 | J5-B2, wave 4 (S04.6) | Every product diagnostic goes through one macro that ignores a failed write: diagnostics never change an exit code (`472fda77`) | `j5_boundary_linux.rs` S04.6 stderr leg, red at 101 before |
| `explain --help` showed an implementation note from a doc comment ("Boxed: `ExplainArgs` carries the full override set…") | J5-F, documenting the commands | The note is a code comment; a test holds every subcommand's summary free of implementation notes (`a369f0e3`) | the CLI help test, red with the old comment |
| Hosted conformance runs failed when the runner's SSH connection dropped mid-suite (after 4.5, 20 and 10 minutes), while the suite finished on the host | Hosted runs 35883187019, 35884521611, 36033419322 | Build and suite run detached and are polled (`1328c381`) | driver unit tests |
| The driver started the suite from `setsid nohup sh -c … &`, so INT, QUIT and HUP were ignored and inherited, and the jail (which honours an inherited ignore) could not be tested for an operator INT or HUP | Review of J5-B1 (the L01 INT leg failed under the driver) | `setsid -f` (`91a347ad`); the harness resets the three for every program (`4810c48e`) | a script test reads the step's `SigIgn` (7 before, 0 after) |
| The suite's PATH was not the tests' PATH: the rustup proxy prepended `~/.cargo/bin`, where a `cargo install`ed ledger would have been invisible to the I01 probe and a `bwrap` there would have been every test's backend | Review of J5-A | The suite runs the pinned toolchain's binaries under the system PATH (`72661260`) | `i01_under_conformance_the_test_process_has_exactly_the_suite_path` |
| The first acceptance map passed clauses whose tests could not fail on their enforcement point (L01.6, L04.4, O03.2, F04.2 and P02.8, each shown by a mutation or a live probe), and its merge tool could close a clause with no test or cite an invented document | Review of J5-A | Clauses split or marked untested; a limit must cite a passage of a document under `docs/`; a tag rises only with a new test (`72661260`) | `cargo test -p xtask` |
| A Linux build for aarch64 announced `linux-closed-v1` while its `doctor` reported the closed set unsupported | Review of J5-D | `version` announces a closed set only where the tables cover the architecture (`c35e1437`) | unit test; `j5_arch_refusal_linux.rs` |
| The freeze missed baseline broadenings: a writable `build` workspace, an added contained environment name, a launch profile's `[environment]`, a `/sys` mount in a plan; a tested run was optional and accepted a zero revision, a debug build and `ready: false` | Review of J5-D | The freeze pins built-in baselines, rendered plans, environments and manifests; `--check` requires a strict tested run (`bed39844`, `640bbfe9`) | `portable_freeze.rs` |
| A test step whose provenance variables differed from the build step's rebuilt the tested binary under the suite with other claims | Review of J5-D | Identical claims on every cargo step; the driver checks `doctor` confirms them (`8d493560`) | driver tests |

## Acceptance verdict

[acceptance-map.toml](acceptance-map.toml) (`ouro.jail.acceptance-map/1`)
carries every §15 row verbatim, split into the clauses it makes, each with the
tests or driver checks that assert it and a tag: `live-cli` (through
`ouro-jail` on the reference host), `live-lib` (library internals on the
host), `portable`, `simulated` (the real trigger is not produced),
`recorded-limit` (a named limit with its document passage), `credential`, or
`untested` (which fails). `cargo xtask conformance` evaluates it over the
run's `test.log` and fails the run when a clause in its lane fails; the macOS
leg evaluates the macOS clauses over its own log. The map pins the expected
ignored set per lane, so an `#[ignore]` added to a gate test fails the run.

At the milestone revision the map has 267 clauses over the 51 gates: 171
`live-cli`, 53 `portable`, 22 `simulated`, 13 `live-lib`, 7
`recorded-limit`, 1 `credential` and none `untested`. (At the J5-A fix wave it
had 248, 72 of them untested; the slices' tests closed them.)

The verdict ([gates.txt](evidence/j5-gates-2026-09-25.txt),
[gates.json](evidence/j5-gates-2026-09-25.json)) combines the Linux and macOS
lanes of revision `4380241f`, both run with `OURO_CONFORMANCE=1`:

```text
gates: 1 credential, 43 pass, 7 pass+limits
every noncredential gate passes in these lanes: yes
```

The seven gates that pass with limits each have one `recorded-limit` clause:
X05 (X05.4, end-of-file under the contained profiles), S03 (S03.2, a
namespace inner sandbox where the host permits nested user namespaces), L02
(L02.6, supervisor death during bubblewrap's startup without an execution
leaf), L03 (L03.6, a leaf without the pids controller), R03 (R03.6, a wall
while the consumer has disconnected), R06 (R06.3, an unobserved migrated
descendant) and C01 (C01.6, a `bind_ro` digest on an immutable filesystem).
Each cites its passage in a Known gaps section ([below](#known-gaps), J3's
and J4's). A pass is only as strong as its column in `gates.txt`: 22 clauses
are `simulated`, and the table names them.

The verdict was computed offline over the two logs with
`cargo xtask gates --revision 4380241f… --map docs/specs/jail-v1/acceptance-map.toml --log linux=… --log macos=… --check contract_validation --check i01_absent --check i01_scrubbed_path --check i02_scan`.
Those four driver checks exist only inside a driver run, so the offline
verdict is told they passed; the driver run itself passed them (PASS), and
its evidence is the [I01 probe](evidence/j5-i01-2026-09-25-ouro-ci.txt) and
the test log.

A01 is the one credential gate: its record is [A01](#a01), and it does not
block the verdict (§15).

I01 is asserted by the driver: the suite runs with the system directories as
its PATH, the I01 probe looks for ledger, fleet and BEAM binaries on that PATH,
in `~/.cargo/bin` and `~/.local/bin`, and in the usual BEAM installation
prefixes, and a test checks the test process sees exactly the suite's PATH.

## Platform compilation

| Target | Compiled | Tested | Executed |
|---|---|---|---|
| `x86_64-unknown-linux-gnu` | `rust` (hosted Ubuntu) and the reference host | portable suite on hosted Ubuntu; full suite on the reference host | yes, the reference host |
| `aarch64-apple-darwin` | `rust` (macOS leg) and a local Apple Silicon machine | the shared portable tests and the macOS refusal tests (M01–M03); at the milestone revision 996 passed, 0 failed, 6 ignored | inspection only; execution refuses 125 |
| `x86_64-apple-darwin` | `rust` (compile-only check, all targets, warnings denied) | no | no |
| `aarch64-unknown-linux-gnu` | `rust` (compile-only check, all targets, warnings denied) | the refusal only, on x86_64 through `OURO_JAIL_TEST_ARCH` | no |

A Linux build for an architecture the syscall tables do not cover reports
`syscall_filter`, `closed_set_observation` and `network_proxy` unsupported
(`unsupported_architecture`); `doctor` is not ready and `run` refuses with 125
before preparation (jail-v1 §3.2). No compile-only target is a support claim.

## No Linux mechanism in portable requirements

- The portable requirement is `execution_boundary` (jail-v1 §6.4); `jail-state.json`
  and `lifetime.native.details` keep the Linux-private name `execution_cgroup`.
- `gc --json` reports `execution_boundary`, not `cgroup`.
- `version` announces a closed set only where the build can observe it: null
  on macOS.
- `lifetime.boundary` is a per-OS vocabulary; the receipt schema refuses the
  Linux values in a macOS receipt.
- Tests: `portable_vocabulary.rs::derived_requirement_names_name_no_linux_mechanism`
  and `::macos_inspection_output_carries_no_linux_vocabulary` (the macOS
  outputs of `explain`, `doctor`, `version` and `gc` carry no Linux
  vocabulary), `portable_version.rs`, the M02 receipt test and
  `portable_doctor.rs::doctor_json_on_macos_records_no_linux_host_or_backend`.

## Freeze

The freeze list of §16 is [milestone-1-freeze.toml](milestone-1-freeze.toml),
generated by `cargo xtask freeze` and pinned by `tests/portable_freeze.rs`. It
records the toolchain (channel and `rust-version` 1.98.1), the Cargo.lock
SHA-256, the filter digests and their evidence tables, the closed set, the
contained mount baselines and built-in profile baselines, the contained
environment, the bubblewrap invocation each contained profile renders to, the
bundled launch profiles, the crate manifests and the frozen schemas. Filter
digests (x86_64):

| Filter | Digest |
|---|---|
| `tool` (and `build`) baseline | `sha256:d07af2773b3341c4b29dd366c201d492294b4f084744cd1cc023683341dfe237` |
| `agent` baseline | `sha256:6f7b5d4cfbc45831d7737d5ab5ee659523f1c96197e4cd8e10bcab5e76ca3ab9` |
| `agent` namespace variant | `sha256:da4883afce274b6104b0abf3bce3c67c21a8b7a62d83ea91d4b6be1df5005877` |
| `agent` mediation | `sha256:28c98e72b91a22c212d5dfdddfcc1f1ca153c5a8e89c15833c26724b263ebeff` |
| closed-set narrowing | `sha256:9e63101563d550ff9aca317797385047c6af0e62ecfd1352cdbbb191135b0a66` |

The frozen wire schemas ([frozen-schemas.toml](frozen-schemas.toml), which
also pins the artifacts behind `ouro.jail.policy/1`, `ouro.jail.policy-file/1`
and `ouro.jail.network/1` and the gate and semantic corpora):

| File | Identifier | SHA-256 |
|---|---|---|
| `event.schema.json` | `ouro.event/1` | `f11a51654753f9db14bede36a33abee5a7fbfbb66901a9175fd7cd3e45296384` |
| `jail-event.schema.json` | `ouro.event/1` (jail producer) | `08a17e1b2a9a33492038d57202b90acc2ccd1703800225c0cd1c68f35c24a137` |
| `jail-receipt.schema.json` | `ouro.jail.receipt/1` | `7f20ea6830bb81e27d46dd7ac90c69a6d3a4f84b7613bcaa1a375192d59e2c5a` |
| `policy-snapshot.schema.json` | `ouro.jail.policy-snapshot/1` | `94bc81e85522cfa3b81bc7f2dd9504a8a3fd5f412ccac3938c98bdd018c61da4` |
| `jail-gate.schema.json` | `ouro.jail.gate/1` | `cc7156f417929e3e93e842b02ee7630a025025e0856cf6cc3d1eda26666ff201` |
| `jail-control.schema.json` | `ouro.jail.control/1` | `1a7ca84c1839448806becf5e320987e56f373c8bce858841a39943b25e6d4740` |
| `jail-doctor.schema.json` | `ouro.jail.doctor/1` | `bca76df7a6ee259955cfca3d39dd354757d21e9d5bff98f069558f761fbfbbb9` |

The tested run, copied from the milestone run's
[doctor.json](evidence/j5-doctor-2026-09-25-ouro-ci.json) by
`cargo xtask freeze --doctor`, is the file's `[tested]` table: revision
`4380241f3195bcc73a5186282400eda3b174ee41`, `dirty = false`, `opt_level = "3"`,
`debug_assertions = false`, `rustc 1.98.1 (48a229cea 2026-09-01)`, target
`x86_64-unknown-linux-gnu`, `ready = true`, the `ouro-jail` binary's SHA-256
`90dbd434296f8b3679d56fea1c6413f30bf7d8cfe558abc1e6cb2961eef5e898`, bubblewrap
0.11.1 at `/usr/bin/bwrap` with SHA-256
`523da3e7399044be5163aee6f57a77a6bef7454376e28f0a0627920bae1b76b6`, and the
host (Ubuntu 26.04.1 LTS, kernel `7.0.0-31-generic`, kvm, 4 CPUs, systemd 259,
AppArmor's user-namespace restriction on, lingering on, identity
`unprivileged`). The facts the run could not state are listed, not guessed:
the scope step's reason, reason code and unit, because `doctor` ran inside the
driver's scope (`already_delegated`). `cargo xtask freeze --check` passes, with
the verifications `inputs_match_tree`, `revision_is_ancestor_of_head`,
`inputs_match_revision` and `frozen_inputs_unchanged_since_revision`: the
binary was built from exactly the frozen tree, at a revision on this branch,
and no frozen input has changed since. The Cargo.lock SHA-256 it pins is
`83ae607b2762d6d844ea5b370f77bf8e93134a375c10a07acee4fede08696c8e` (125
packages).

## Performance

Measured 2026-09-25, 02:20 to 02:27 UTC, on the reference host as `ouro-ci`
at revision `4380241f` with the tested binary, by
`cargo xtask perf run --launches 30 --warmup 1 --max-load 3.0 --revision 4380241f…`
from a plain SSH session (the harness re-runs itself under
`systemd-run --user --scope` for the scope session). The 1-minute load before
the measured launches was 1.21 / 1.67 / 2.09 (minimum, median, maximum) on 4
CPUs; every one of the 42 arms has 30 valid launches and none excluded
([summary](evidence/perf-2026-09-25-ouro-ci/summary.md), recomputed with
`perf summarize --revalidate` under the rule that counts a flagged
`exec_unconfirmed` no-op launch as valid; the raw records, SHA-256
`ee1ff987f541c367c7d41f8c8e10302ce7bdddd55116ef6f172e5e1075325e73`, are
`launches.ndjson.xz` beside it). The tables are in
[backend-evaluation.md §4](backend-evaluation.md#4-performance-52-budgets).

- **Startup:** p95 added warm startup is under 250 ms in every judged cell;
  `tool` is 92 to 124 ms, `agent` up to 145 ms, `none` up to 72 ms.
- **The jail's own overhead** (`--observe off` against direct) on the fixed
  file workload, median: `tool` work phase +30.8% (plain) and +28.4% (scope),
  post-start +43.4% and +38.7%, end-to-end wall +103.7% and +92.6% (startup
  included); `agent` post-start +39.0% and +38.9%; `none` post-start +6.7% and
  +6.5%. On the descendant-heavy workload `tool`'s post-start is +13.1% and
  +10.4%.
- **Attribution** ([evidence](evidence/perf-2026-09-25-attribution-ouro-ci.txt)):
  on the fixed workload's work phase, direct 155.4 ms, bubblewrap alone with
  the `tool` namespaces under Ubuntu's `unpriv_bwrap` AppArmor confinement and
  no seccomp filter 185.0 ms (+19.0%), `ouro-jail run --profile tool --observe
  off` 189.9 ms (+22.2%). About 19 of the 22 points are bubblewrap's
  containment as the stock distribution confines it; the jail's filter and
  supervisor add about 3. The jail's teardown (settlement, tree verification,
  receipts, trace flush) adds a median 17.5 ms (plain) and 19.2 ms (scope).
- **Observation cost** (`--observe on`): on the fixed workload, +367% to +404%
  on the work phase against direct (+283% to +373% against observation off), from two ptrace stops per closed-set call at about 100,000
  such calls per second; on the descendant-heavy workload about +41% to +71%.
  Every event count was exact and no launch lost evidence.

**The budgets.** The original budget of under 20% median overhead on the fixed
workload is missed: `tool`'s own overhead is 43.4% and 38.7% post-start, 23
and 19 points over, and 30.8% and 28.4% on the work phase alone, mostly
bubblewrap's containment under the distribution's confinement. The operator
decided on 2026-09-25, and jail-v1 §5.2 records, that the startup budget stays
(met) and that the fixed-workload budget becomes a measured ceiling: the
jail's own overhead at most 50% median post-start on this syscall-dense
worst-case workload (met: 43.4% and 38.7%), with the work phase and
end-to-end wall reported and observation cost reported per workload with no
budget. A representative workload, a build or a test run, joins the §5 set as
later work.

## A01

OpenCode 1.18.32 under `agent` with no credential, at the milestone revision
and with the tested binary, on the reference host as the account `ubuntu`
from a plain SSH session (lingering on), on 2026-09-25 at 02:31 UTC: the jail
exited 0 after 9 seconds and `greeting.txt` contained `hello`. The receipt is
settled, outcome `exited` 0, no error, every coverage class active, integrity
verified, `tree_empty` true, the scope step `entered`, and vendor state
cleaned; it records the frozen `agent` filter and narrowing digests. The
record, with its evidence, is in
[agent-compatibility.md](agent-compatibility.md#opencode-agent-no-credential-at-the-milestone-revision).
The start-up stall seen in the J3-era runs did not recur in this one run,
which is not evidence that it is gone. The support claim lives in that record;
the binary reports every launch profile `experimental` (jail-v1 §15).

## Test seams

The release binary honours every `OURO_JAIL_TEST_*` variable (jail-v1 §6.2):
the tested binary is the shipped binary. Each one set is recorded in jail
state and in every receipt with native details.

| Seam | What it does | Gates that rely on it |
|---|---|---|
| `OURO_JAIL_TEST_MEDIATION_QUEUE` | shrinks `agent`'s mediation record queue | a mediation-queue overflow is evidence loss |
| `OURO_JAIL_TEST_TRACE_CAP` | shrinks the local trace cap | R03 local-cap loss |
| `OURO_JAIL_TEST_ABORT_AT` | aborts at one named point of the `n`th write (J5: the optional `:<n>` ordinal) at one persistence site | R02 crash points, gc records (R02.3: gc's later records) |
| `OURO_JAIL_TEST_GC_MAX_ENTRIES` | shrinks gc's per-invocation bound | C03 (portable) |
| `OURO_JAIL_TEST_TRACER_INFLIGHT` | shrinks the observer's in-flight bound | O03 map exhaustion (the ptrace analogue), O05 directory-operation loss, R04 |
| `OURO_JAIL_TEST_TRACER_QUEUE_BYTES` | shrinks the observer's queue | O03 ring loss (the ptrace analogue) |
| `OURO_JAIL_TEST_SUPERVISOR_SCOPE` | takes the outside-a-scope branch of the scope step | L03 `none` without a usable cgroup; the scope tests |
| `OURO_JAIL_TEST_ARCH` (J5) | refuses the table-bound probes as a build for another architecture would | the architecture refusal (platform compilation) |
| `OURO_JAIL_TEST_MOUNT_SWAP` (J5) | holds the §9.1 mount handoff open, at most 10 s, so a test can replace a pinned source | F04 source-identity swap |
| `OURO_JAIL_TEST_TRACER_TRUNCATE_PATH` (J5) | makes a path-marked covered call's path unreadable to the observer | O03 truncation |
| `OURO_JAIL_TEST_TRACER_UNMATCHED_EXIT` (J5) | follows a path-marked call's entry without recording it | O03 unmatched exit, which cannot occur on demand under ptrace |
| `OURO_JAIL_TEST_TRACE_FD_WRITE_MAX` (J5) | caps each `--trace-fd` write, so frames are written in pieces | R03.5: the wall under forced partial writes (simulated) |

## Known gaps

The limits below are recorded, not tested under the clause's name, and each
says why the stock reference host cannot produce the clause. One entry, L04's
suspend and clock steps, is simulated rather than recorded, and says what the
simulation leaves out.

- EOF under the contained profiles. Under the contained profiles bubblewrap's
  outer process and namespace init hold the stdout and stderr they hand the
  target until the jail exits, so the caller's end-of-file comes when the jail
  exits, not when the target closes its streams. The supervisor also keeps
  its own stderr, which carries its diagnostics. Under `none`, end-of-file on
  stdout arrives as in direct execution (X05; jail-v1 §8.3).
- A wall while the trace consumer has disconnected. A closed pipe returns
  EPIPE at once and never blocks a writer, so there is no blocking case for a
  disconnected consumer to create; the disconnect's own handling is tested in
  both evidence modes (`j4_r03_disconnect_strict_stops`,
  `j4_r03_disconnect_best_effort_continues`), and the wall is tested under a
  saturated trace (R03.3) and under forced partial writes through the trace
  write-size seam (R03.5, simulated:
  `j5_records_linux.rs::j5_r03_a_wall_fires_on_time_while_every_trace_frame_is_written_in_pieces`
  and `::j5_r03_a_wall_fires_on_time_while_a_stalled_consumer_holds_a_partial_frame`).
- An unobserved migrated descendant. A test cannot migrate a descendant out of
  the registered cgroup without the supervisor being able to see it: an unseen
  migration is a race jail-v1 §9.3 declines to promise to detect. What the
  receipt claims is the registered-boundary scope on a verified settlement,
  and a detected escape loses integrity and retains state (R06).
- Suspend and clock steps are simulated, not produced (L04.5, L04.6, tagged
  `simulated`): the conformance account can neither suspend the shared VM nor
  set the clock (`CAP_SYS_TIME`). The deadlines are proved on the real
  `ouro-jail run` with an `LD_PRELOAD` `clock_gettime` shim that, from exec on,
  advances only `CLOCK_BOOTTIME` (a suspend's signature: the boot clock moves,
  the monotonic clock does not) or steps only `CLOCK_REALTIME`: the execution
  wall expires with the first and ignores the second
  (`j5_lifetime_linux.rs::l04_the_execution_wall_follows_the_boot_clock_across_a_suspend_sized_jump`,
  `::l04_the_execution_wall_ignores_wall_clock_steps`), and the gate wait
  follows the boot clock (`::l04_the_gate_wait_follows_the_boot_clock`). The
  kernel's own suspend path, timers acted on at resume, is not exercised.
- A leaf without the pids controller cannot be produced through `ouro-jail run`
  on the stock reference host. The supervisor always creates its execution leaf
  directly beneath `user@<uid>.service`, whose `cgroup.subtree_control` enables
  `pids`; that file belongs to the account but is shared by every session and
  service of it, so removing the controller would reconfigure the account's
  shared user-manager tree for everything else running there. The
  controller-absent branch is proved on a real leaf through the library
  (L03.1, L03.2), and the receipt row and wrapper note of an unapplied
  preferred ceiling through the command line with no leaf at all (the leaf's
  name taken by an owner-bound attempt id).
- Under `none`, what was below the supervisor when it started is left alone,
  but a process born into such a subtree after that and orphaned to the
  supervisor cannot be told from an escaped attempt process and is treated as
  one (jail-v1 §9.3).
- With observation off, a target that ends before the supervisor sees its new
  image is `unknown`, and the run exits 1 with `exec_unconfirmed`; on the
  reference host `/usr/bin/true` under `tool` or `agent` always does. Run with
  `--observe on` to confirm such an exec (jail-v1 §6.4).
- Observation costs two ptrace stops per closed-set call, so it has no
  budget and is reported per workload; the jail's own overhead on the fixed
  workload misses the original 20% and is held to the measured 50% post-start
  ceiling instead (jail-v1 §5.2, [Performance](#performance)).
- Truncation and an unmatched exit are forced through path-gated tracer seams:
  the kernel either delivers a structure or fails the call, and the ptrace
  observer steps a tracee to an exit only while it holds the entry. Map
  exhaustion and ring loss are their ptrace analogues, the in-flight bound and
  the event queue, driven by seams (O03).
- A contained target cannot be observed losing a lifetime helper: a kill of
  bubblewrap's outer process or of the watcher while the target runs leaves a
  settled receipt identical to an external SIGKILL of the target (`signaled`,
  9, no cause, no note), although for the watcher the supervisor itself acted.
  Recording it needs a new note field and cause in frozen records; it is left
  open.
- The contained verification requires the execution leaf's population, not
  only the pid namespace, to be seen empty, so a leaf member outside the
  namespace that the kill reaches but that cannot finish dying leaves the
  attempt unsettled with `tree_unknown`, and `gc` reconciles it later. The
  supervisor kills the leaf once; a same-uid process moved into the leaf after
  that kill is killed by `gc`, not the supervisor (X07).
- A `doctor` killed with SIGKILL leaves its probes' directories in the system
  temporary directory; `gc` never searches there (jail-v1 §14.2), so they stay
  until the operator removes them.
- Gaps carried from J3 and J4, still true:
  - [J3](j3-authority.md#known-gaps): the permissive `agent` filter variant is
    unit-tested only; a `bind_ro` digest is recorded only on an immutable
    filesystem, which the host does not mount; listing network interfaces
    fails inside contained profiles; a vendor sandbox that needs a nested user
    namespace cannot start inside `agent` on a stock Ubuntu host.
  - [J4](j4-authority.md#known-gaps): supervisor death during bubblewrap's
    startup without an execution leaf (no lingering); PID reuse is simulated;
    a stalled disk is proved portably only; a rewritten handler frame is
    indistinguishable from a restart; an `agent` connect withdrawn before
    mediation is an exclusion and `none`'s io_uring runs unobserved; `gc`'s
    same-uid and earlier-build limits; the macOS descriptor-exhaustion helper
    under a parallel run.
- Correction of J4: [j4-authority.md](j4-authority.md) said every live test
  ran the Rust semantic checks on each product receipt it read. That was false
  until J5-C: `j4_loss_linux.rs`'s receipt helper ran the schema only, and two
  `none` receipts in `observer_j4_linux.rs` ran neither. Since J5-C every live
  reader checks receipts, traces and control transcripts against the frozen
  schemas and the semantic rules.
