#!/bin/bash
# H1 re-verification: regular-file stdio redirect reopen hole.
# Expects ukai-jail on PATH. Creates an OUTSIDE file, redirects it as stdin
# to a jailed command that appends through /dev/stdin (the reopen vector).
set -u
BASE=$(mktemp -d /tmp/h1reverify.XXXXXX)
JAIL=${1:-ukai-jail}
echo "sentinel-before" > "$BASE/host_secret.txt"
chmod 600 "$BASE/host_secret.txt"

"$JAIL" run --profile tool --workspace "$BASE/ws" --limit wall=10s -- \
  /bin/sh -c 'echo "APPENDED_BY_JAIL" >> /dev/stdin' < "$BASE/host_secret.txt" \
  > "$BASE/run.out" 2> "$BASE/run.err"
echo "exit=$?"
echo "--- host_secret.txt after run:"
cat "$BASE/host_secret.txt"
echo "--- run.err (first 5):"
head -5 "$BASE/run.err"
if grep -q APPENDED_BY_JAIL "$BASE/host_secret.txt"; then
  echo "H1 VERDICT: STILL VULNERABLE — jail appended to host file outside grants"
else
  echo "H1 VERDICT: held (no host-side append)"
fi
rm -rf "$BASE"
