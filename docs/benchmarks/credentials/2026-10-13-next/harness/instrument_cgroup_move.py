#!/usr/bin/env python3
"""Separate descriptor cleanup, migration and kill-handle work in a diagnostic copy."""
import argparse
import difflib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--patch', type=Path, required=True)
    args = parser.parse_args()
    changes = []
    for filename in ['platform.rs', 'cgroup.rs']:
        path = args.source / 'crates/ouro-jail/src/platform/linux' / filename
        old = path.read_text()
        assert 'OURO_MOVE_DIAGNOSTIC' not in old
        if filename == 'platform.rs':
            start = old.index('    fn create(')
            end = old.index('\n    /// Finds the namespace init', start)
            body = old[start:end]
            anchor = '        drop(fds);'
            assert body.count(anchor) == 1
            body = body.replace(anchor,
                '        let bench_cleanup = std::time::Instant::now();\n' + anchor
                + '\n        eprintln!("OURO_MOVE_DIAGNOSTIC step=fd_cleanup elapsed_us={}", bench_cleanup.elapsed().as_micros());', 1)
            anchor = '        let cgroup_kill = match cgroup'
            assert body.count(anchor) == 1
            body = body.replace(anchor, '        let bench_kill = std::time::Instant::now();\n' + anchor, 1)
            anchor = '        let watcher =\n'
            assert body.count(anchor) == 1
            body = body.replace(anchor,
                '        eprintln!("OURO_MOVE_DIAGNOSTIC step=kill_handle elapsed_us={}", bench_kill.elapsed().as_micros());\n' + anchor, 1)
            new = old[:start] + body + old[end:]
        else:
            anchor = ('    pub fn place(&self, pid: libc::pid_t) -> io::Result<()> {\n'
                      '        self.write("cgroup.procs", &pid.to_string())?;\n'
                      '        self.verify_member(pid)\n'
                      '    }')
            assert old.count(anchor) == 1
            new = old.replace(anchor,
                '    pub fn place(&self, pid: libc::pid_t) -> io::Result<()> {\n'
                '        let bench_move = std::time::Instant::now();\n'
                '        self.write("cgroup.procs", &pid.to_string())?;\n'
                '        eprintln!("OURO_MOVE_DIAGNOSTIC step=write elapsed_us={}", bench_move.elapsed().as_micros());\n'
                '        let bench_member = std::time::Instant::now();\n'
                '        let result = self.verify_member(pid);\n'
                '        eprintln!("OURO_MOVE_DIAGNOSTIC step=verify_member elapsed_us={}", bench_member.elapsed().as_micros());\n'
                '        result\n'
                '    }', 1)
        changes.extend(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
            fromfile='a/' + str(path.relative_to(args.source)),
            tofile='b/' + str(path.relative_to(args.source))))
        path.write_text(new)
    args.patch.write_text(''.join(changes))


if __name__ == '__main__':
    main()
