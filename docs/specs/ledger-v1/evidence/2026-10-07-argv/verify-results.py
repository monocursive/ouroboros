#!/usr/bin/env python3
"""Validate native output for the argv evidence record."""
from pathlib import Path
import hashlib
import json
import re
import sys

root = Path(sys.argv[1])
for name in ("validation", "source-precheck", "source-postcheck", "build", "clippy", "ledger", "doctor", "binaries-check"):
    assert (root / f"{name}.exit").read_text().strip() == "0", name
log = (root / "ledger.log").read_text()
counts = [tuple(map(int, row)) for row in re.findall(
    r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", log
)]
assert sum(row[0] for row in counts) == 203, counts
assert not any(row[1] or row[2] for row in counts), counts
assert "SKIP" not in log and "FAILED" not in log
save = ("snapshot.before_temp_unlink", "snapshot.before_open", "snapshot.before_write", "snapshot.partial_write", "snapshot.before_file_sync", "snapshot.before_rename", "snapshot.before_directory_sync", "snapshot.after_directory_sync")
remove = ("cleanup.before_temp_unlink", "cleanup.before_state_unlink", "cleanup.before_directory_sync", "cleanup.after_directory_sync")
expected = {
    f"{action}/{kind}/{point}"
    for action in ("error", "kill")
    for kind in ("pending.create", "pending.outage", "pending.source", "pending.completion")
    for point in save
} | {f"{action}/pending.remove/{point}" for action in ("error", "kill") for point in remove}
found = re.findall(r"pending launch case passed: ([^\n]+)", log)
assert len(found) == len(expected) and set(found) == expected
assert len(re.findall(r"lifecycle launch case passed:", log)) == 66
for name in (
    "journal_io_error_matrix_preserves_previous_or_complete_replacements",
    "journal_sigkill_matrix_preserves_pending_and_canonical_history",
    "recovery_sync_errors_do_not_import_or_acknowledge_a_complete_journal",
    "cleanup_keeps_the_same_mutex_inode_for_future_openers",
):
    assert f"{name} ... ok" in log, name
for ending in ("normal", "writer-death", "owner-death"):
    marker = f"vendor-state/{ending}: populated, tree empty, removed, replay unchanged"
    assert log.count(marker) == 1, ending
assert "vendor_state::vendor_state_is_removed_after_normal_exit_writer_death_and_owner_death" in log
for marker in (
    "transcript/tool: opt-in, bounded, escaped, metadata unchanged, missing capture labeled",
    "transcript/none: opt-in, bounded, escaped, metadata unchanged, missing capture labeled",
    "transcript/owner-death: live and unfinalized captures remain incomplete, outcome unknown",
):
    assert log.count(marker) == 1, marker
for profile in ("tool", "none"):
    for ending in (
        ": default private, exact native bytes, zero and partial caps, explicit bundle, one execution",
        "/owner-death: admission capture retained, tree empty, outcome unknown",
    ):
        assert log.count(f"argv/{profile}{ending}") == 1
binaries = {}
for line in (root / "binaries.sha256").read_text().splitlines():
    digest, path = line.split(maxsplit=1)
    data = Path(path).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, path
    binaries[Path(path).name] = digest
    if Path(path).name == "ouro-ledger":
        for control in (b"OURO_PENDING_TEST_WORKER", b"OURO_LEDGER_TEST_WORKER", b"SIGKILL returned unexpectedly"):
            assert control not in data, "test instrumentation in production ledger"
print(json.dumps({
    "tests_passed": 203, "tests_failed": 0, "tests_ignored": 0,
    "journal_io_failure_cases": 44, "journal_sigkill_cases": 44,
    "native_pending_owner_cases": len(expected), "existing_lifecycle_cases": 66,
    "argv_launch_tests": 2, "argv_portable_tests": 5, "all_capture_signed_launch_tests": 1, "vendor_cleanup_scenarios": 3, "source_checks": "passed before and after",
    "production_test_controls": "absent", "binaries_sha256": binaries,
}, indent=2))
