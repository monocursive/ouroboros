#!/usr/bin/env python3
"""Instrument an owned diagnostic source copy; never a scored build."""
import argparse
import difflib
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path)
    p.add_argument('--patch', type=Path, required=True)
    a = p.parse_args()
    changes = []
    path = a.source / 'crates/ouro-jail/src/supervisor.rs'
    old = path.read_text()
    start = old.index('fn run_inner(')
    prefix, body = old[:start], old[start:]
    anchor = '    crate::platform::mark_supervisor_start();'
    assert anchor in body
    body = body.replace(anchor, anchor + '\n    let bench_start = std::time::Instant::now();', 1)
    for name, anchor in [
        ('resolution', '    let request = plan_request(&plan);'),
        ('validation', '    let attempt_dir = AttemptDir::new(&plan.data_dir, &attempt_id);'),
        ('claim_and_policy', '    let now = SystemTime::now();'),
        ('probes', '    // J3-launch begin: §8.1 step 2 and §12'),
        ('launch_staging', '    // Steps 3 to 5: create the boundary'),
        ('boundary_prepare', '    // J5-B1 begin: X05.3'),
        ('prepared_durability', '    // Step 6: wait for a valid external release'),
        ('release', '    let wall_deadline = wall_deadline(&plan);'),
    ]:
        assert anchor in body, name
        note = '    eprintln!("OURO_STARTUP_DIAGNOSTIC stage=' + name + ' cumulative_us={}", bench_start.elapsed().as_micros());\n'
        body = body.replace(anchor, note + anchor, 1)
    new = prefix + body
    path.write_text(new)
    changes.extend(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                       fromfile='a/' + str(path.relative_to(a.source)),
                                       tofile='b/' + str(path.relative_to(a.source))))
    path = a.source / 'crates/ouro-jail/src/platform/linux/probe.rs'
    old = path.read_text()
    start, end = old.index('pub fn run_selected('), old.index('\nfn run_status_checks(')
    body = old[start:end]
    anchor = '    let shared_check = |name: &str| {'
    body = body.replace(anchor, '    let bench_shared = std::time::Instant::now();\n' + anchor, 1)
    anchor = '    // Keep failed RO setup independent of namespace capability results.'
    body = body.replace(anchor, '    eprintln!("OURO_PROBE_DIAGNOSTIC shared_us={}", bench_shared.elapsed().as_micros());\n' + anchor, 1)
    anchor = '            run_one_backend(name, jail_exe, bwrap)'
    assert anchor in body
    body = body.replace(anchor, '            let bench_probe = std::time::Instant::now();\n'
                        '            let result = run_one_backend(name, jail_exe, bwrap);\n'
                        '            eprintln!("OURO_PROBE_DIAGNOSTIC name={} elapsed_us={}", name, bench_probe.elapsed().as_micros());\n'
                        '            result', 1)
    new = old[:start] + body + old[end:]
    path.write_text(new)
    changes.extend(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                       fromfile='a/' + str(path.relative_to(a.source)),
                                       tofile='b/' + str(path.relative_to(a.source))))
    a.patch.write_text(''.join(changes))


if __name__ == '__main__':
    main()
