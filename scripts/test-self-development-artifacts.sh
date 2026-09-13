#!/bin/sh
# Static contract check only; live benchmark behavior is outside this script's claim.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$ROOT/docs/experiments/self-development-finding-template.md"

for field in ID Severity Classification Expected Observed Command Environment Evidence \
    "Contradictory evidence" Disposition Regression; do
    grep -q "\*\*$field:" "$TEMPLATE" || {
        printf 'self-development-artifacts: missing finding field %s\n' "$field" >&2
        exit 1
    }
done
for metric in "supervisor steering prompts" "failures by normalized reason" \
    "questions asked" "input/cached-input/output tokens" "host-only status"; do
    grep -q "$metric" "$TEMPLATE" || {
        printf 'self-development-artifacts: missing metric %s\n' "$metric" >&2
        exit 1
    }
done
grep -q "not evidence that a live model" "$TEMPLATE"
grep -q "original bounded benchmark" "$TEMPLATE"
printf 'self-development-artifacts: static finding and metrics contract passed\n'