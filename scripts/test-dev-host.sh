#!/bin/sh
# Host process-safety half of scripts/test-dev.sh. Run outside an enclosing OS sandbox.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ouro-dev-host.XXXXXX")"
PID=""
cleanup() {
    if [ -n "$PID" ] && kill "$PID" 2>/dev/null; then wait "$PID" 2>/dev/null || true; fi
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$TMP/checkout/scripts" "$TMP/checkout/tui/target/debug" "$TMP/data"
chmod 700 "$TMP/data"
cp "$ROOT/scripts/dev.sh" "$TMP/checkout/scripts/dev.sh"
printf '#!/bin/sh\nexit 1\n' >"$TMP/checkout/tui/target/debug/ouro"
chmod 755 "$TMP/checkout/tui/target/debug/ouro"
sleep 60 & PID=$!
printf '{"pid":%s,"port":1}\n' "$PID" >"$TMP/data/gateway.json"

if ! kill -0 "$PID" 2>/dev/null; then
    printf 'test-dev-host: host process probing unavailable; run from an unsandboxed host shell\n' >&2
    exit 77
fi
if OUROBOROS_DATA_DIR="$TMP/data" sh "$TMP/checkout/scripts/dev.sh" daemon-stop \
    >"$TMP/out" 2>&1; then
    printf 'test-dev-host: daemon-stop unexpectedly succeeded\n' >&2
    exit 1
fi
kill -0 "$PID" 2>/dev/null || {
    printf 'test-dev-host: safe stop failure signalled the published PID\n' >&2
    exit 1
}
# Reap the child immediately after the assertion. Clearing PID prevents the EXIT trap from
# signalling a later process if this short-lived PID were reused.
kill "$PID"
wait "$PID" 2>/dev/null || true
PID=""
printf 'test-dev-host: unrelated published PID survived safe-stop refusal\n'