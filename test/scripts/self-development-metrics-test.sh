#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
fixture="$root/test/fixtures/self-development-metrics"
tmp=${TMPDIR:-/tmp}/self-development-metrics-test.$$
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -m 700 "$tmp"

python3 "$root/scripts/self-development-metrics.py" collect \
  --events "$fixture/events.ndjson" \
  --supervisor-actions "$fixture/supervisor-actions.json" \
  --output "$tmp/candidate.json"
python3 "$root/scripts/self-development-metrics.py" evaluate \
  --candidate "$tmp/candidate.json" --baseline "$fixture/baseline.json" \
  --output "$tmp/evaluation.json"

python3 - "$tmp/candidate.json" "$tmp/evaluation.json" "$fixture/baseline.json" "$tmp" "$root/scripts/self-development-metrics.py" <<'PY'
import json, subprocess, sys
candidate_path, evaluation_path, baseline_path, tmp, script = sys.argv[1:]
with open(candidate_path) as f: candidate = json.load(f)
assert candidate["event_integrity"]["duplicate_replays_ignored"] == 1
assert candidate["event_integrity"]["retained_events"] == 18
assert candidate["tool_calls"]["total"] == 4
assert candidate["tool_calls"]["failed"] == 3
assert candidate["tool_calls"]["unchanged_retries"] == 1
assert candidate["tool_calls"]["repeated_commands"] == 1
assert candidate["tool_calls"]["normalized_errors"] == {"environment": 2, "sandbox_environment": 1}
assert candidate["read_scope"]["unique_files"] == ["lib/example.ex"]
assert candidate["questions"] == {"asked": 2, "answered": 1, "declined": 1, "unresolved": 0}
assert candidate["usage"]["input_tokens"] == 600
assert candidate["usage"]["output_tokens"] == 90
assert candidate["usage"]["cached_input_tokens"] == 0
assert candidate["usage"]["non_cached_input_tokens"] is None
assert candidate["usage"]["aggregate_turn_totals_ignored"] == 1
assert candidate["usage"]["missing_counters"] == {"cached_input_tokens": 1}
assert "cached_input_tokens" in candidate["telemetry_missing"]
assert candidate["context"]["max_utilization"] == 0.35
assert candidate["context"]["compactions"] == 1 and candidate["context"]["handoffs"] == 1
assert candidate["supervision"]["total"] == 4
assert candidate["wall_time_seconds"] == 20.0
with open(evaluation_path) as f: evaluation = json.load(f)
assert evaluation["valid_comparison"] is False
assert evaluation["comparison"] is None
assert evaluation["invalid_confirmations"] == ["F-CONFOUNDED"]
assert "not proof of live-model judgment" in evaluation["note"]

# Removing the false confirmation permits a same-scope, same-environment bounded comparison.
candidate["findings"] = []
valid_path = tmp + "/candidate-valid.json"
with open(valid_path, "w") as f: json.dump(candidate, f)
output = subprocess.check_output([sys.executable, script, "evaluate", "--candidate", valid_path, "--baseline", baseline_path], text=True)
valid = json.loads(output)
assert valid["valid_comparison"] is True
assert valid["comparison"]["tool_calls"]["reduction_fraction"] == 0.6

# A different environment must refuse comparison even without findings.
candidate["metadata"]["environment"]["sandbox"] = "none"
mismatch_path = tmp + "/candidate-mismatch.json"
with open(mismatch_path, "w") as f: json.dump(candidate, f)
output = subprocess.check_output([sys.executable, script, "evaluate", "--candidate", mismatch_path, "--baseline", baseline_path], text=True)
assert json.loads(output)["valid_comparison"] is False

# Retained workspace exports use NDJSON and name actions by JSON-RPC method.
ndjson_actions = tmp + "/actions.ndjson"
usage_events = tmp + "/usage-events.ndjson"
with open(ndjson_actions, "w") as f:
    f.write('{"method":"interactive.steer"}\n{"method":"interactive.interrupt"}\n')
with open(usage_events, "w") as f:
    f.write('{"session_id":"actual-shape","sequence":1,"type":"usage","payload":{"input_tokens":10,"cache_read_tokens":4,"output_tokens":2}}\n')
output = subprocess.check_output([sys.executable, script, "collect", "--events", usage_events, "--supervisor-actions", ndjson_actions], text=True)
actual_shape = json.loads(output)
assert actual_shape["supervision"]["by_type"] == {"interactive.interrupt": 1, "interactive.steer": 1}
assert actual_shape["usage"]["non_cached_input_tokens"] == 6
print("self-development-metrics: assertions passed")
PY
