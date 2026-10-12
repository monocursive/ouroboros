#!/usr/bin/env python3
"""Run the larger fixture with the same native-wrapper protocol as v2."""
import sys
from pathlib import Path
import agentbench_v2 as harness
import workflow_fixture as fixture

harness.TASKS[fixture.NAME] = fixture.SPEC
original_check = harness.independent_check
original_make = harness.make_task_dir
harness.independent_check = lambda path, task: fixture.independent_check(path) if task == fixture.NAME else original_check(path, task)
harness.make_task_dir = lambda base, task: fixture.make_task_dir(base, task) if task == fixture.NAME else original_make(base, task)

if __name__ == '__main__':
    out = Path(sys.argv[sys.argv.index('--out') + 1]).expanduser().resolve()
    harness.write(out / 'workflow-protocol.json', {'entry_sha256': harness.sha(__file__),
                  'fixture_sha256': harness.sha(fixture.__file__), 'native_harness_sha256': harness.sha(harness.__file__),
                  'description': 'Synthetic multi-file CLI feature; one sample per configured lane, descriptive compatibility only'})
    harness.main()
