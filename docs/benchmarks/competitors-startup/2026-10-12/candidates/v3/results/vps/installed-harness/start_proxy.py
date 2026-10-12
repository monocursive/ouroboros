#!/usr/bin/env python3
"""Provision the unchanged Greyproxy before any timed native launches."""
from pathlib import Path
from types import SimpleNamespace
from agentbench_v2 import prepare_proxy

root = Path.home() / 'bench-ouro-startup'
out = root / 'results/proxy-setup'
out.mkdir(parents=True, exist_ok=True)
prepare_proxy(SimpleNamespace(root=root, out=out))
