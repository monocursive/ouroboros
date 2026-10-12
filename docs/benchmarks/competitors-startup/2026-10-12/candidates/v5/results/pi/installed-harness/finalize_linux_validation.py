#!/usr/bin/env python3
import hashlib,json,sys
from pathlib import Path
root,source=map(Path,sys.argv[1:])
names=['crates/ouro-jail/src/platform/linux/fs.rs','crates/ouro-jail/src/platform/linux/platform.rs','crates/ouro-jail/src/platform/linux/probe.rs','crates/ouro-jail/src/platform/linux/tracer/mod.rs','crates/ouro-jail/tests/linux_mechanisms.rs']
(root/'results/validation/source-files.json').write_text(json.dumps({name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in names},indent=2)+'\n')
before=json.loads((root/'results/doctor-before.json').read_text());after=json.loads((root/'results/validation/doctor-after.json').read_text())
statuses=lambda report:{r['name']:(r['status'],r['reason_code'],r['mechanism']) for r in report['capabilities']}
assert statuses(before)==statuses(after),'Doctor capability declarations changed'
assert after['build']['rustc'].startswith('rustc 1.98.1 ')
assert after['build']['opt_level']=='3' and not after['build']['debug_assertions']
print('All 30 doctor statuses identical; Rust 1.98.1 release build confirmed')
