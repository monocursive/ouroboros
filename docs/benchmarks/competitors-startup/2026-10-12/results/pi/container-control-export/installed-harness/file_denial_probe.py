#!/usr/bin/env python3
"""Reproduce the original file denial, including sibling and symlink checks."""
import argparse
import json
from pathlib import Path
from suite import Suite

SCRIPT = r'''
import errno, os, sys
secret, sibling, link = sys.argv[1:]
assert open(sibling, 'rb').read() == b'original'
for path in [secret, link]:
    for flags in [os.O_RDONLY, os.O_WRONLY, os.O_WRONLY | os.O_TRUNC]:
        try:
            fd = os.open(path, flags)
        except OSError as error:
            assert error.errno in (errno.EACCES, errno.EROFS), error
        else:
            os.close(fd)
            raise AssertionError('denied file opened: ' + path)
    try:
        os.chmod(path, 0o600)
    except OSError as error:
        assert error.errno in (errno.EPERM, errno.EROFS), error
    else:
        raise AssertionError('mask chmod succeeded')
print('FILE-DENIAL-PASS')
'''

class FileSuite(Suite):
    def command(self, tool, payload):
        cmd = super().command(tool, payload)
        cmd[cmd.index('--deny-read') + 1] = str(self.secret)
        return cmd

p = argparse.ArgumentParser()
p.add_argument('--root', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
args = p.parse_args()
if args.out.exists():
    raise SystemExit('Refusing to replace evidence')
s = FileSuite(args.root, args.out, 0, 0, ['ouro-jail'])
try:
    rows = []
    for label in ['before', 'after']:
        s.ouro = args.root / 'bin' / ('ouro-jail-before' if label == 'before' else 'ouro-jail')
        row = s.run('ouro-jail', [s.python, '-c', SCRIPT, str(s.secret),
                                str(s.readonly), str(s.work / 'read-link')],
                    'safety', 'file-denial-' + label)
        rows.append(dict(row, binary_variant=label, original_unchanged=
                         s.secret.read_bytes() == b'owned-fixture-secret'))
    (args.out / 'summary.json').write_text(json.dumps(rows, indent=2) + '\n')
finally:
    s.close()
