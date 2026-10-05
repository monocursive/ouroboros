#!/usr/bin/env python3
"""Real daemon, production 64 MiB rotation, restart and byte-exact export.

Uses only generated fixture records. No jail is launched by this harness;
launch/containment acceptance belongs to launch_linux.rs in the separate suite.
"""
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

root = Path(sys.argv[1]).resolve()
binary = root / "target/release/ouro-ledger"
data = root / "threshold-data"
assert not data.exists(), "refuse to reuse an existing store"
process = None
writer_log = (root / "threshold-writer.log").open("wb")


def exact(sock, length):
    result = bytearray()
    while len(result) < length:
        part = sock.recv(length - len(result))
        if not part:
            raise RuntimeError("writer closed before complete response")
        result.extend(part)
    return bytes(result)


def call(request, expect_error=False):
    body = json.dumps(request, separators=(",", ":")).encode()
    assert len(body) <= 1_048_576
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(15)
        sock.connect(str(data / "ledger/serve.sock"))
        sock.sendall(struct.pack(">I", len(body)) + body)
        length, = struct.unpack(">I", exact(sock, 4))
        assert 0 < length <= 1_048_576
        response = json.loads(exact(sock, length))
    if expect_error:
        assert response["status"] == "error", response
        return
    assert response["status"] == "ok", response
    return response["value"]


def start():
    global process
    process = subprocess.Popen([str(binary), "--data-dir", str(data), "serve"],
                               stdin=subprocess.DEVNULL, stdout=writer_log, stderr=writer_log)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        assert process.poll() is None, "writer exited during recovery"
        try:
            call({"op": "ping"})
            return
        except (OSError, RuntimeError):
            time.sleep(0.05)
    raise RuntimeError("writer did not start within 90 seconds")


def stop():
    if process is not None and process.poll() is None:
        process.terminate()
        process.wait(timeout=10)


def files_digest(directory):
    digest = hashlib.sha256()
    count = 0
    for path in sorted(directory.glob("events-*.ndjson")):
        with path.open("rb") as stream:
            while block := stream.read(1_048_576):
                digest.update(block)
                count += len(block)
    return digest.hexdigest(), count


try:
    started = time.monotonic()
    start()
    payload = json.loads((root / "docs/specs/ledger-v1/fixtures/request.json").read_text())
    payload["profile"] = "none"
    payload["capture"] = {"streams": [], "limit_bytes": 1_048_576}
    run = call({"op": "prepare", "request_id": "threshold-fixture", "payload": payload})
    run_id = run["run_id"]
    claim = call({"op": "claim_owner", "run_id": run_id})
    body = {"padding": "x" * 524_288}
    def append(index, token, request_id=None):
        return call({"op": "append_owner", "run_id": run_id,
                     "request_id": request_id or f"threshold-{index}", "kind": "note",
                     "effect_id": f"effect-{index}", "body": body, "token": token})
    receipts = [append(index, claim["owner_token"]) for index in range(130)]
    directory = data / "ledger" / run_id
    segments = sorted(directory.glob("events-*.ndjson"))
    sizes = [path.stat().st_size for path in segments]
    assert len(segments) == 2, sizes
    assert all(0 < size <= 64 * 1024 * 1024 for size in sizes)
    expected_digest, expected_bytes = files_digest(directory)
    sealed_digest = hashlib.sha256(segments[0].read_bytes()).hexdigest()
    request = {"run_id": run_id, "filter": {"selector": "all", "stage": None,
               "since": None, "until": None}, "cursor": None, "limit": 100}
    first = call({"op": "read", "request": request})
    request["cursor"] = first["next_cursor"]
    second = call({"op": "read", "request": request})
    assert not second["done"]
    snapshot = first["snapshot"]
    assert snapshot["head_seq"] == 132
    stop()
    start()
    replayed_run = call({"op": "prepare", "request_id": "threshold-fixture", "payload": payload})
    assert replayed_run["run_id"] == run_id and replayed_run["attempt_id"] == run["attempt_id"]
    claim = call({"op": "claim_owner", "run_id": run_id})
    assert append(0, claim["owner_token"]) == receipts[0]
    assert append(129, claim["owner_token"]) == receipts[-1]
    append(130, claim["owner_token"])
    assert call({"op": "read", "request": request}) == second
    exported = hashlib.sha256()
    exported_bytes = 0
    for page in (first, second):
        fragment = page["ndjson"].encode()
        exported.update(fragment)
        exported_bytes += len(fragment)
    request["cursor"] = second["next_cursor"]
    pages = 2
    while True:
        page = call({"op": "read", "request": request})
        pages += 1
        assert page["snapshot"] == snapshot
        assert page["local_consistency"] and page["child_protection"] == "unprotected"
        fragment = page["ndjson"].encode()
        exported.update(fragment)
        exported_bytes += len(fragment)
        if page["done"]:
            break
        assert pages < 10_000
        request["cursor"] = page["next_cursor"]
    assert (exported.hexdigest(), exported_bytes) == (expected_digest, expected_bytes)
    assert hashlib.sha256(segments[0].read_bytes()).hexdigest() == sealed_digest
    report = call({"op": "verify", "run_id": run_id})[0]
    assert report["local_consistency"] and report["events"] == 133
    assert report["child_protection"] == "unprotected"
    print(json.dumps({"result": "pass", "segment_bytes_before_restart": sizes,
        "snapshot_records": 132, "records_after_append": 133,
        "export_bytes": exported_bytes, "export_sha256": exported.hexdigest(),
        "pages": pages, "exact_cursor_retry": True, "original_receipt_replay": True,
        "sealed_segment_unchanged": True, "none_remains_unprotected": True,
        "elapsed_seconds": round(time.monotonic() - started, 3)}, indent=2))
finally:
    stop()
    writer_log.close()
