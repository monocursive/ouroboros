#!/bin/sh
# The integration boot gate for the core reduction (docs/proposals/core.md, "Status").
#
# Boots this tree against fresh copies of test/support/integration_fixture/fixture-datadir.tar.gz
# — a data directory `dev` wrote at 3bc8887, holding every durable shape the reduction retired —
# ten times under interactive code loading and ten times with every module preloaded, and fails
# on any `BOOT: FAILED` or on any count that differs from the expected block in
# test/support/integration_fixture/README.md. The `check` function below is that block,
# executable. Run it as `make boot-gate`.
#
#   OUROBOROS_PROCESS_ID_HELPER  the `ouro` binary `Ouroboros.RuntimeOwner` needs before it opens
#                                durable state; defaults to tui/target/release/ouro, then
#                                tui/target/debug/ouro, then a debug build of it
#   BOOT_GATE_RUNS               boots per mode (default 10)
#   BOOT_GATE_OUT                scratch directory (default _build/boot-gate)
#
# Every boot runs under a node name of its own (`boot-gate-<mode>-<n>@<host>`), not the
# `nonode@nohost` that wrote the directory. `Session.Recovery` adopts, and `Workspace.Manager`
# reserves for, only records whose `node` is this node's; under the writer's name the
# coordinators are already resuming the sessions and appending to them by the time the
# store is read, so every count is a snapshot of a moving system (this gate caught `events`
# reading 1 or 2 on the same bytes), and the records' absolute workspace paths would have to
# exist. Under its own name the runtime does what it does with a data directory that moved
# machines: it loads everything and adopts nothing, and the counts are the files'.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
FIXTURE_DIR="$ROOT/test/support/integration_fixture"
TARBALL="$FIXTURE_DIR/fixture-datadir.tar.gz"
EXPECTED_SHA=3d76a84e7d6bac1af3ad40288985e12d62d7454ff5488b4be542e0b016259793
FLEET_ID=0123456789abcdef01234567
RUNS="${BOOT_GATE_RUNS:-10}"
OUT="${BOOT_GATE_OUT:-$ROOT/_build/boot-gate}"

# The record was taken in the development environment, where `RuntimeOwner` requires the real
# helper exactly as a packaged node does. The test environment would wave that requirement.
MIX_ENV=dev
export MIX_ENV

fail() {
  echo "boot-gate: $*" >&2
  exit 1
}

# 1. The bytes are the recorded ones.
if command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$TARBALL" | cut -d' ' -f1)
else
  actual=$(sha256sum "$TARBALL" | cut -d' ' -f1)
fi
[ "$actual" = "$EXPECTED_SHA" ] || fail "fixture sha256 is $actual, expected $EXPECTED_SHA"

# 2. The helper.
HELPER="${OUROBOROS_PROCESS_ID_HELPER:-}"
if [ -z "$HELPER" ]; then
  for candidate in "$ROOT/tui/target/release/ouro" "$ROOT/tui/target/debug/ouro"; do
    if [ -x "$candidate" ]; then
      HELPER="$candidate"
      break
    fi
  done
fi
if [ -z "$HELPER" ]; then
  echo "==> boot-gate: no ouro binary under tui/target; building a debug one"
  (cd "$ROOT/tui" && cargo build --bin ouro) || fail "could not build ouro"
  HELPER="$ROOT/tui/target/debug/ouro"
fi
[ -x "$HELPER" ] || fail "process-id helper $HELPER is not executable"

# 3. Fresh copies, one per boot, and an empty allowed workspace root: no record is this
#    node's, so nothing is reserved under it and the recorded paths need not exist.
rm -rf "$OUT"
mkdir -p "$OUT/workspaces"
tar -xzf "$TARBALL" -C "$OUT"
[ -d "$OUT/fixture-datadir" ] || fail "the tarball did not extract fixture-datadir/"

# `expect LOG PATTERN LABEL`: the log must carry a line matching the pattern.
expect() {
  grep -qE -- "$2" "$1" || {
    echo "  missing: $3  ($2)"
    return 1
  }
}

# `session LOG ID STATUS EVENTS PROVIDER`: the interactive-sessions line must list the record
# with those three values. Map key order is not stable across VMs, so each pair is matched on
# its own inside the record's `%{…}`.
session() {
  map=$(grep '^interactive sessions:' "$1" | grep -oE "%\{[^{}]*\"$2\"[^{}]*\}" | head -1)
  [ -n "$map" ] || {
    echo "  missing: session $2"
    return 1
  }
  rc=0
  printf '%s' "$map" | grep -q "status: $3" || {
    echo "  session $2: status is not $3"
    rc=1
  }
  printf '%s' "$map" | grep -q "events: $4" || {
    echo "  session $2: events is not $4"
    rc=1
  }
  printf '%s' "$map" | grep -q "provider: $5" || {
    echo "  session $2: provider is not $5"
    rc=1
  }
  return $rc
}

# The expected block, from test/support/integration_fixture/README.md.
check() {
  log=$1
  copy=$2
  bad=0
  expect "$log" '^BOOT: ok \([0-9]+ ms\)' 'the boot' || bad=1
  expect "$log" '^BOOT CHECK COMPLETE' 'the run reaching its end' || bad=1
  for store in permissions grants ledger; do
    expect "$log" "^$store\\.durability: :synced_checkpoint" "$store durability" || bad=1
  done
  rules=$(grep '^permission rules' "$log" || true)
  for pair in 'total: 22' 'user: 20' 'workspace: 1' 'session: 1' 'computer_use: 5' 'bash: 3' \
    'tool: 3' 'mcp: 2' 'capability: 2' 'forge: 2' 'read: 1' 'write: 1' 'edit: 1' \
    'web_fetch: 1' 'tool_param: 1'; do
    printf '%s' "$rules" | grep -q "$pair" || {
      echo "  permission rules: no '$pair'"
      bad=1
    }
  done
  expect "$log" '^grants: \[\]$' 'no grants (the file is quarantined)' || bad=1
  ledger=$(grep '^effect ledger entries' "$log" || true)
  for pair in 'total: 18' 'ok: 10' 'denied: 5' 'failed: 3' 'delegate: 8' 'permission: 3' \
    'start_agent: 2' 'tool_call: 2' 'forge: 1' 'approval: 1' 'policy_promotion: 1'; do
    printf '%s' "$ledger" | grep -q "$pair" || {
      echo "  effect ledger entries: no '$pair'"
      bad=1
    }
  done
  status=$(grep '^ledger status' "$log" || true)
  for pair in 'next_sequence: 28' 'retained: 18' 'in_flight: 0' 'ambiguous: 0' \
    'durability: :synced_checkpoint'; do
    printf '%s' "$status" | grep -q "$pair" || {
      echo "  ledger status: no '$pair'"
      bad=1
    }
  done
  session "$log" fixture-session-claude :idle 0 :claude || bad=1
  session "$log" fixture-session-delegating :idle 1 :native || bad=1
  session "$log" fixture-session-native :idle 1 :native || bad=1
  session "$log" fixture-session-read-only :idle 0 :native || bad=1
  expect "$log" '^cluster session owners \(interactive\): \{:ok, MapSet\.new\(\["ouro-fixture@fixture\.invalid"\]\)\}' \
    'the interactive session owner, out of the checkpoint that carries the retired :coding atom' || bad=1
  expect "$log" '^rollout registry: .*\{"artifact-fixture-beam", "Elixir\.Ouroboros\.Capability\.FixtureProbe", :live\}' \
    'the lane-B rollout row, read back as a string' || bad=1
  expect "$log" '^rollout registry: .*\{"artifact-fixture-wasm", "wasm/counter", :live\}' 'the lane-W rollout row' || bad=1
  expect "$log" '^forge epoch watermark: \{:ok, 3\}' 'the epoch watermark' || bad=1
  expect "$log" '^policy promotion: .*"Bash\(mix test \*\)"' 'the promoted shape' || bad=1
  expect "$log" '^policy promotion: .*allowable_tools: \["bash"\]' 'the promoted tool' || bad=1
  expect "$log" '^policy evidence: \{:ok, %\{.*records: 1' 'the evidence row' || bad=1
  audit=$(grep '^audit status' "$log" || true)
  for pair in 'streams: 2' 'bytes: 227277' 'error: nil'; do
    printf '%s' "$audit" | grep -q "$pair" || {
      echo "  audit status: no '$pair'"
      bad=1
    }
  done
  expect "$log" '^signing journal: \[beam: :refused, wasm: :refused\]' 'the two signing decisions' || bad=1
  for plane in interactive effect_ledger cluster mesh workspace; do
    expect "$log" "^    $plane: :available" "availability of $plane" || bad=1
  done
  errors=$(grep -c '\[error\]' "$log" || true)
  [ "$errors" = "1" ] || {
    echo "  [error] lines: $errors, expected exactly 1"
    bad=1
  }
  expect "$log" '\[error\] checkpoint \{:ouroboros, :agent_grants, 1\} at .*grants/checkpoints/.*\.term could not be decoded \(:invalid_term\); quarantining it at .*\.quarantined-[0-9]+\.term and starting from no checkpoint' \
    'the one expected error line: the grants quarantine' || bad=1
  quarantined=$(ls "$copy"/grants/checkpoints/*.quarantined-*.term 2>/dev/null | wc -l | tr -d ' ')
  [ "$quarantined" = "1" ] || {
    echo "  quarantined grants files on disk: $quarantined, expected 1"
    bad=1
  }
  return $bad
}

failed=0
for mode in plain preload; do
  i=1
  while [ "$i" -le "$RUNS" ]; do
    copy="$OUT/copy-$mode-$i"
    log="$OUT/boot-$mode-$i.txt"
    cp -R "$OUT/fixture-datadir" "$copy"
    chmod 700 "$copy"
    if [ "$mode" = preload ]; then
      flags="--no-start --preload-modules"
    else
      flags="--no-start"
    fi
    # shellcheck disable=SC2086
    if OUROBOROS_PROCESS_ID_HELPER="$HELPER" \
      OUROBOROS_DATA_DIR="$copy" \
      OUROBOROS_FLEET_ID="$FLEET_ID" \
      FIXTURE_WORKSPACES_ROOT="$OUT/workspaces" \
      elixir --sname "boot-gate-$mode-$i" -S mix run $flags scripts/fixture/boot_check.exs >"$log" 2>&1 &&
      check "$log" "$copy"; then
      echo "boot-gate: $mode $i ok, $(grep -oE 'BOOT: ok \([0-9]+ ms\)' "$log" | head -1)"
    else
      echo "boot-gate: $mode $i FAILED, see $log"
      failed=1
    fi
    i=$((i + 1))
  done
done

[ "$failed" = 0 ] || fail "a boot failed or a count differed; the logs are under $OUT"
echo "boot-gate: $((RUNS * 2)) boots, every count as recorded"
