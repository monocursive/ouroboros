# Milestone 2 acceptance

This is the closeout map for North Star §5.2, §5.4 and §7.3. The proof is
scripted children and real process/host failures. It does not establish physical
power-loss durability, managed authorization, independent custody or support
for a particular external agent.

| Contract | Implementation and executable evidence |
| --- | --- |
| L1 preparation and one launch | store writer tests (`store/tests/writer.rs`) for request conflict/replay; `launch_linux.rs` durable gate and detached lost-reply tests; lifecycle fault matrix. |
| L2 attributed canonical events | `daemon.rs` role/peer authentication, source validation, source sequence/replay and private-field refusal; exact canonical export and replay tests. |
| L3 independent intents | `store/operator.rs`, concurrent operator CLI tests, lost-reply replay and immutable effect identities. Operator decisions cannot settle the launch owner. |
| L4 verification and bundles | `storage_recovery.rs`, unsigned/signed bundle tampering and offline cross-platform tests. Consistency, coverage, signer trust and child protection stay separate. |
| L5 bounded capture and display | Native cap/drain/stdin checks; transcript, argv and control-descriptor evidence linked from the durability map. No capture occurs implicitly. |
| L6 queries and comparison | `evidence_reader.rs` filtering, continuation, changed snapshots, unsupported/unobserved classes, target incomparability and corruption refusal. |
| L7 retention and GC | Hold, active/unknown/pending-effect preservation, configured history/capture retention, dry-run, interrupted prune recovery and retained replay anchors. |
| L8 single writer and recovery | Writer flock, canonical segment manifests, global sequence/hash continuity, rotation faults, disposable SQLite projections and restartable cursors. |
| L9 privacy | Runtime raw-metadata refusal; immutable path/destination redaction before both canonical append and pending journals; explicit unchanged captures. |
| §5.4 durability | The [durability map](durability-acceptance.md) names every persistence cut, actual writer/owner death, child isolation, honest `none`, forged ingress and vendor cleanup check. |
| §7.3 composition | Native ledger launches run without fleet. Reference-host Jail conformance uses a scrubbed PATH and independent I01 checks. A killed writer produces degraded evidence or unknown outcomes; unsupported query classes remain unobserved. |

The [contract freeze](milestone-2-contracts.json) pins every ledger schema and
golden fixture. `python3 docs/specs/ledger-v1/freeze.py` checks exact bytes and
the complete inventory; `validate_contract.py` runs it in CI. `--write` is an
explicit contract revision, not an automatic repair of drift. Changes require
review of compatibility and corresponding runtime/fixture validation.
`ouro-ledger version --json` announces the frozen schema identifiers.

The project is pre-release, so a frozen ledger schema may be re-blessed in place
under its identifier by an additive change, regenerating the freeze with its
fixtures and validators in one reviewable commit. Re-blessing record:

- 2026-10-14 re-blessed `bundle-verification.schema.json` and
  `bundle-verification-v2.schema.json` in place under
  `ouro.ledger.bundle-verification/1` and `/2`. Rationale: one additive optional
  field, `projection_rule` (1 or 2), naming the run projection rule an embedded
  run matched, so a bundle exported before the `outcome_unknown` projection
  changed still verifies and says how (ledger-v1 §4, §8.4). No shared field
  changed meaning; a report without the field remains valid. A validator
  pinned to the schemas before this record, which forbid additional
  properties, rejects reports that carry the field.

Historical custody is still required before removal of the legacy stores
(North Star §9), after milestone 3. New signed bundles do not satisfy that
historical obligation. No legacy history is removed by this closeout.

The [closeout evidence](evidence/2026-10-07-closeout/README.md) records CI,
tested sources and the current proof limits.
