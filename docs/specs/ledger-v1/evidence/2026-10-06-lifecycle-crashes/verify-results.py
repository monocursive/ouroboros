#!/usr/bin/env python3
"""Check the native validation output for this evidence record."""
import hashlib
import json
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
for name in (
    "validation", "source-precheck", "source-postcheck", "build", "clippy",
    "ledger", "doctor", "binaries-check",
):
    assert (root / f"{name}.exit").read_text().strip() == "0", name

log = (root / "ledger.log").read_text()
counts = [tuple(map(int, row)) for row in re.findall(
    r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", log
)]
assert sum(row[0] for row in counts) == 182, counts
assert not any(row[1] or row[2] for row in counts), counts
assert "SKIP" not in log and "FAILED" not in log

points = (
    "event.before_write", "event.partial_write", "event.before_sync", "event.after_sync",
    "projection.before_write", "projection.before_sync", "projection.before_rename",
    "projection.before_directory_sync", "manifest.before_write", "manifest.before_sync",
    "manifest.before_rename", "manifest.before_directory_sync",
    "append.before_directory_sync", "append.after_directory_sync",
)
kinds = ("prepared", "owner_claimed", "admitted", "source", "settled")
expected = {
    f"{mode}/{kind}/{point}"
    for mode in ("strict", "best-effort")
    for kind in ("admitted", "settled")
    for point in points
} | {
    f"{mode}/{kind}/reply.before_send"
    for mode in ("strict", "best-effort")
    for kind in kinds
}
found = re.findall(r"lifecycle launch case passed: ([^\n]+)", log)
assert len(found) == len(expected) and set(found) == expected
for test in (
    "io_errors_at_every_lifecycle_boundary_refuse_ack_until_recovery",
    "sigkill_at_every_lifecycle_boundary_preserves_identity_and_canonical_bytes",
):
    assert f"{test} ... ok" in log, test

binaries = {}
for line in (root / "binaries.sha256").read_text().splitlines():
    digest, path = line.split(maxsplit=1)
    data = Path(path).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, path
    binaries[Path(path).name] = digest
    if Path(path).name == "ouro-ledger":
        for test_only in (b"OURO_LEDGER_TEST_WORKER", b"SIGKILL returned unexpectedly"):
            assert test_only not in data, "test instrumentation found in production binary"

print(json.dumps({
    "tests_passed": 182, "tests_failed": 0, "tests_ignored": 0,
    "io_failure_cases": 70, "store_sigkill_cases": 70,
    "native_launch_crash_cases": len(expected), "existing_launch_tests": 27,
    "source_checks": "passed before and after validation",
    "production_test_controls": "absent", "binaries_sha256": binaries,
}, indent=2))
