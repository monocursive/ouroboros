# Self-development benchmark metrics

Status: executable experiment support. This collector measures retained telemetry; it does not change runtime behavior or authority.

## Contract

A run has two explicit inputs:

1. retained Ouroboros events as newline-delimited JSON; and
2. a JSON or NDJSON supervisor-action log. Supervisor steering, answers, declines, approval changes, interrupts, and restarts must be entered in that log rather than inferred from model prose. Retained JSON-RPC action exports use their `method` as the action type.

Run the collector with only Python's standard library:

```sh
python3 scripts/self-development-metrics.py collect \
  --events retained-events.ndjson \
  --supervisor-actions supervisor-actions.json \
  --output candidate.json
```

Events may use `session_id`/`sequence` or `session`/`seq`. A repeated pair is replay and is ignored. Events without both identifiers remain countable because the collector cannot safely infer identity. Malformed lines are disclosed. `payload` holds event-specific fields.

The report includes:

- total/failed tool calls, calls by tool, normalized error classes, adjacent unchanged retries, and repeated identical shell commands;
- unique read paths, broad reads (missing path/limit or a limit over 500), and read events whose path is unavailable;
- asked, genuinely answered, declined, and unresolved questions (an approval without a non-empty answer is not an answer);
- total input, cached-input, derived non-cached input, and output tokens from unique `usage` events;
- maximum observed `context_used / context_window`, compactions, handoffs, and elapsed event wall time;
- explicit supervisor actions by type; and
- missing timestamp, token-counter, usage, or context-utilization telemetry.

Token accounting intentionally ignores counters on `turn_completed`, `run_completed`, `session_completed`, and `summary`: those are aggregate turn/run totals and counting them after usage events would double-count model usage. `non_cached_input_tokens` is derived per usage event as `input_tokens - cache_read_tokens`; it is null if either counter is absent or inconsistent in any usage event. Missing counters are represented in `usage.missing_counters` and `telemetry_missing`; zero does not mean observed zero when a missing marker exists. Token values are telemetry, not billing estimates.

Error normalization is deliberately small and stable: timeout, permission denial, sandbox/environment, invalid argument, not found, cancellation, and an explicit/fallback class. It supports comparisons; the original retained event remains the evidence.

## Bounded evaluation

A candidate and baseline must each contain matching metadata:

```json
{
  "metadata": {
    "scope": "sd-bounded-v1",
    "bounds": {"mission": "fixture-review", "max_tool_calls": 20},
    "environment": {"os": "fixture-os", "sandbox": "workspace_write", "start_mode": "application_started"},
    "environment_evidence": {"valid": true, "source": "recorded manifest or named gate"}
  }
}
```

Evaluate only the repeated bounded exercise against its same-scope bounded baseline:

```sh
python3 scripts/self-development-metrics.py evaluate \
  --candidate candidate.json \
  --baseline baseline.json \
  --output evaluation.json
```

The evaluator refuses comparison (`valid_comparison: false`, `verdict: invalid`) when scope, bounds, or environment are absent or unequal, or either environment-evidence object is absent/not explicitly valid. It also rejects a candidate's confirmed finding unless `finding.evidence.scope_valid` and `finding.evidence.environment_valid` are both true. An invalid result has no comparison table: a confounded startup mode, unsupported host gate, or nested sandbox cannot become false confirmation or an improvement score.

When evidence is valid, the comparison reports candidate/baseline values and reduction fractions for tool calls, supervisor actions, non-cached input tokens, and wall time. Cached input remains separately reported in collected artifacts. Policy targets belong to the benchmark definition and should not be silently baked into collection.

## Evidence limitations

This is a deterministic static collector/evaluator. Its synthetic fixture proves replay deduplication, accounting, normalization, missing-data disclosure, and evidence rejection rules. **Static evaluator behavior is not proof of live-model judgment.** In particular, passing the fixture does not prove that a live model will classify findings honestly, avoid retries, ask useful questions, or improve itself. Those claims require a newly created durable live session running the same bounded mission, human-supervisor records, retained telemetry, and valid host/environment evidence.

Keep the raw event and supervisor logs with both baseline and repeat artifacts. Do not compare an unbounded implementation program with the bounded baseline, substitute aggregate transcript claims for event evidence, infer answers from acknowledgements, or call an unavailable host check a pass.

## Fixture check

```sh
sh test/scripts/self-development-metrics-test.sh
```

The fixture contains one replayed event, two identical environmental failures, a separately normalized nested-sandbox failure, a usage event with a missing cached-input counter, aggregate turn totals that must be ignored, answered and declined questions, compaction/handoff events, explicit supervision, and a deliberately false confirmed finding based on invalid environment evidence. The test first requires refusal, then removes that false finding to exercise valid same-scope comparison, and finally changes the environment to require refusal again.
