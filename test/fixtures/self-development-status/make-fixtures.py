#!/usr/bin/env python3
import hashlib,json

def digest(v): return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
def item(i,state,settlement="unsettled",accept=False):
 x={"id":i,"step":"Gate "+i,"status":"completed" if state in ("accepted","change_proposed","failed") else "pending","deliverable":"validation","work_state":state,"criteria":["review evidence"],"evidence":["evidence/%s.json"%i] if accept else [],"child_settlement":settlement}
 if accept:x["acceptance"]={"actor":"parent","decision_source":"parent_model","basis":"model_judgment","evidence_validation":"unchecked_references","deterministic":False}
 return x
def checkpoint(path,at,items):
 msgs=[]; plan={"plan":items,"explanation":"fixture"}
 d={"version":3,"digest":digest(msgs),"updated_at":at,"messages":msgs,"plan":plan,"plan_digest":digest(plan),"offset":0,"rewind_floor":0}
 with open(path,"w",encoding="utf-8") as handle: json.dump(d,handle,indent=2); handle.write("\n")
checkpoint("test/fixtures/self-development-status/checkpoint-old.json","2026-09-11T10:00:00Z",[item("gate-a","change_proposed","completed")])
checkpoint("test/fixtures/self-development-status/checkpoint-current.json","2026-09-11T11:00:00Z",[item("gate-a","accepted","completed",True),item("gate-b","change_proposed","completed")])
