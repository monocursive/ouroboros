#!/usr/bin/env python3
"""Keep the original direct-to-install symlink layout; avoid an ungranted hop."""
import json
from pathlib import Path

root = Path.home() / 'bench-ouro-startup-final'
rows = []
for name in ['claude', 'opencode', 'codex', 'codex-code-mode-host']:
    path = root / 'bin' / name
    if path.is_symlink():
        old = str(path.readlink())
        canonical = path.resolve(strict=True)
        path.unlink()
        path.symlink_to(canonical)
        rows.append({'name': name, 'before_link': old, 'after_link': str(canonical),
                     'bytes_unchanged': True})
(root / 'results/client-link-correction.json').write_text(json.dumps(rows, indent=2) + '\n')
print(json.dumps(rows))
