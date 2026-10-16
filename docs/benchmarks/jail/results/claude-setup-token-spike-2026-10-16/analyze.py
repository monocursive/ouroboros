import json, sys, collections, pathlib, os
rd = pathlib.Path(sys.argv[1]); ws = pathlib.Path(sys.argv[2]); data = pathlib.Path(os.path.expanduser("~/spike-oauth/data"))
r = json.loads((rd / "jail.json").read_text())
print("phase", r.get("phase"), "| outcome", json.dumps(r.get("outcome")))
print("errors", [e.get("code") for e in r.get("errors", [])])
lt = r.get("lifetime", {}); print("tree_empty", lt.get("tree_empty"), "| state_cleanup", json.dumps(r.get("state_cleanup")))
print("coverage", {k: v.get("status") for k, v in r.get("coverage", {}).items()})
print("credentials", json.dumps(r.get("credentials")))
g = ws / "greeting.txt"; print("greeting.txt", repr(g.read_text()) if g.exists() else "MISSING")
att = r.get("attempt_id"); tr = [p for p in data.rglob("trace.ndjson") if att and att in str(p)]
print("journal", tr[0] if tr else "NOT FOUND")
if not tr: sys.exit()
net = collections.Counter(); notes = []; deny = collections.Counter()
for line in tr[0].read_text().splitlines():
    try: e = json.loads(line)
    except ValueError: continue
    op, f = e.get("operation"), e.get("fields", {})
    if e.get("source") == "proxy" and op == "net.connect" and e.get("stage") == "result":
        net[(f.get("destination"), e.get("decision"), f.get("reason"), (e.get("outcome") or {}).get("ok"))] += 1
    elif op == "note" and f.get("kind") == "credential":
        notes.append((f.get("credential_id"), f.get("transition")))
    elif op == "fs.deny":
        p = f.get("path") or {}; deny[(f.get("attempted_operation"), p.get("kind"), p.get("value") if p.get("kind") != "digest" else "<digest>")] += 1
print("proxy results (destination, decision, reason, ok): count")
for k, v in sorted(net.items(), key=str): print("  ", k, v)
print("credential notes", notes)
print("fs.deny (op, path kind, path): count")
for k, v in sorted(deny.items(), key=str)[:40]: print("  ", k, v)
