"""Tests for the Terminal-Bench adapter's decidable half.

These import only the modules that do not import Harbor, which is why they run with no
docker, no model key, no Linux dist, and no `harbor` on the path:

    python3 -m unittest discover -s bench/terminal_bench/tests

`test_agent_shape.py` checks the Harbor-facing class without importing it, by parsing it.
"""

import sys
from pathlib import Path

# The package under test sits one level up. Added here rather than in a pyproject so that
# the whole suite is `python3 -m unittest discover` with nothing installed.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
