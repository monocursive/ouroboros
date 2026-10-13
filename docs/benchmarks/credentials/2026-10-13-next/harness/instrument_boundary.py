#!/usr/bin/env python3
"""Profile a disposable diagnostic source copy, never a scored build."""
import argparse
import difflib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--patch', type=Path, required=True)
    args = parser.parse_args()
    path = args.source / 'crates/ouro-jail/src/platform/linux/platform.rs'
    old = path.read_text()
    start = old.index('    fn create(')
    end = old.index('\n    /// Finds the namespace init', start)
    body = old[start:end]
    assert 'OURO_BOUNDARY_DIAGNOSTIC' not in body
    anchor = '        let snapshot = plan.request.snapshot.clone();'
    assert body.count(anchor) == 1
    body = body.replace(anchor, '        let bench_boundary = std::time::Instant::now();\n' + anchor, 1)
    stages = [
        ('stdio', '        // The scratch directory the child sees as /tmp.'),
        ('scratch', '        let cgroup_required = ['),
        ('cgroup', '        // north-star §4.4 / jail-v1 §9.1:'),
        ('plan_and_grants', '        let (resolv_source, resolv_sanitization) = stage_sanitized_resolv_conf('),
        ('resolver', '        refuse_pseudo_fs_grants(\n'),
        ('pseudo_fs_checks', '        let (scan, pins, pinned_fds, placeholders) = prepare_mounts('),
        ('mounts', '        // J3-launch begin: credential views take the slots after the pins'),
        ('filter_and_argv', '        // J3-launch begin: room for the credential views after the pins'),
        ('fd_map', '        let mut command = Command::new(&exe);'),
        ('verify_pins', '        // §8.3: stdio passes through without capture'),
        ('spawn', '        // In particular close our duplicate of ARGS_FD before streaming:'),
        ('cgroup_placement', '        let watcher =\n'),
        ('watcher_and_payload', '        let bwrap_pid = libc::pid_t::try_from(child.id()).unwrap_or(-1);'),
        ('boundary_state', '        if let Err(err) = boundary.discover('),
        ('discover', '        // Audit 2026-10-08 M2:'),
        ('cgroup_readback', '        if let Some(plan) = boundary.observer_plan.as_ref() {'),
        ('tracer_attach', '        Ok(boundary)'),
    ]
    for name, anchor in stages:
        assert body.count(anchor) == 1, name
        note = ('        eprintln!("OURO_BOUNDARY_DIAGNOSTIC stage=' + name
                + ' cumulative_us={}", bench_boundary.elapsed().as_micros());\n')
        body = body.replace(anchor, note + anchor, 1)
    new = old[:start] + body + old[end:]
    args.patch.write_text(''.join(difflib.unified_diff(
        old.splitlines(True), new.splitlines(True),
        fromfile='a/' + str(path.relative_to(args.source)),
        tofile='b/' + str(path.relative_to(args.source)))))
    path.write_text(new)


if __name__ == '__main__':
    main()
