#!/usr/bin/env python3
"""Use the unchanged distro executables in the isolated follow-up layout."""
import hashlib
import json
from pathlib import Path

root = Path.home() / 'bench-ouro-after'
rows = []
for name in ['openshell', 'openshell-gateway']:
    source = (Path('/usr/bin') / name).resolve(strict=True)
    link = root / 'bin' / name
    if link.exists() or link.is_symlink():
        assert link.resolve(strict=True) == source, link
    else:
        link.symlink_to(source)
    rows.append({'name': name, 'source': str(source),
                 'sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'bytes_changed': False})
(root / 'results/container-executable-layout.json').write_text(json.dumps(rows, indent=2) + '\n')
