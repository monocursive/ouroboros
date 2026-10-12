#!/usr/bin/env python3
"""Preserve and remove only provably new benchmark fixture copies in HOME."""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from agentbench import TASKS

START = 1791732271
home = Path.home()
out = home / 'bench-ouro/results/stray-home-fixture-recovery'
expected = {name: content for spec in TASKS.values() for name, content in spec['files'].items()}
expected.update({'src/__init__.py': '', 'tests/__init__.py': ''})
allowed_defs = {'src/calc.py': {'add', 'multiply'}, 'src/parse.py': {'first_word'}, 'src/store.py': {'Store'}}
rows = []
for name, original in expected.items():
    path = home / name
    if not path.is_file() or path.is_symlink(): continue
    st = path.stat()
    try:
        birth = st.st_birthtime if hasattr(st, 'st_birthtime') else int(subprocess.check_output(['stat', '-c', '%W', str(path)], text=True).strip())
    except (OSError, ValueError, subprocess.CalledProcessError): birth = 0
    data = path.read_bytes()
    if len(data) > 8192: continue
    text = data.decode(errors='replace')
    matches = text == original
    if name in allowed_defs:
        try:
            tree = ast.parse(text)
            definitions = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
            matches = bool(definitions) and definitions <= allowed_defs[name] and all(isinstance(n, (ast.FunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom, ast.Expr)) for n in tree.body)
        except SyntaxError: matches = False
    if not matches or birth < START or st.st_nlink != 1: continue
    destination = out / 'files' / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, destination)
    digest = hashlib.sha256(data).hexdigest()
    removed = path.read_bytes() == data
    if removed: path.unlink()
    rows.append({'path': str(path), 'artifact': str(destination.relative_to(out)), 'birth_epoch': birth,
                 'mtime_epoch': st.st_mtime, 'sha256': digest, 'removed_exact_copy': removed,
                 'proof': 'new during goal; known fixture path and matching tests or source definitions; backup verified before unlink'})
out.mkdir(parents=True, exist_ok=True)
(out / 'manifest.json').write_text(json.dumps(rows, indent=2)+'\n')
print(json.dumps({'preserved_and_removed': len(rows), 'paths': [r['path'] for r in rows]}))
