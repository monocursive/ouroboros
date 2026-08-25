#!/bin/sh
# Destructive-lifecycle regression tests run only against a disposable fake checkout.

set -eu

SOURCE_REPO="$(cd "$(dirname "$0")/.." && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ouro-dev-test.XXXXXX")"
SLEEP_PID=""

cleanup() {
    if [ -n "$SLEEP_PID" ]; then
        kill "$SLEEP_PID" 2>/dev/null || true
        wait "$SLEEP_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_ROOT"
}
trap cleanup EXIT HUP INT TERM

fail() {
    printf 'test-dev: %s\n' "$*" >&2
    exit 1
}

CHECKOUT="$TEST_ROOT/checkout"
mkdir -p "$CHECKOUT/scripts" "$CHECKOUT/tui/target/debug"
cp "$SOURCE_REPO/scripts/dev.sh" "$CHECKOUT/scripts/dev.sh"
printf '#!/bin/sh\nexit 1\n' >"$CHECKOUT/tui/target/debug/ouro"
chmod 755 "$CHECKOUT/tui/target/debug/ouro"

# A safe client-stop failure must never fall back to signalling the published PID.
LIVE_DIR="$TEST_ROOT/live"
mkdir -p "$LIVE_DIR"
chmod 700 "$LIVE_DIR"
sleep 60 &
SLEEP_PID=$!
printf '{"pid":%s,"port":1}\n' "$SLEEP_PID" >"$LIVE_DIR/gateway.json"

if OUROBOROS_DATA_DIR="$LIVE_DIR" sh "$CHECKOUT/scripts/dev.sh" daemon-stop \
    >"$TEST_ROOT/daemon-stop.out" 2>&1; then
    fail "daemon-stop unexpectedly succeeded when the safe client refused"
fi
kill -0 "$SLEEP_PID" 2>/dev/null || fail "daemon-stop signalled a PID after safe stop failed"
kill "$SLEEP_PID"
wait "$SLEEP_PID" 2>/dev/null || true
SLEEP_PID=""

# A name containing "ouro" and path aliases are not evidence that a directory is data.
VICTIM="$TEST_ROOT/ouroboros-victim"
mkdir -p "$VICTIM"
chmod 700 "$VICTIM"
printf 'keep\n' >"$VICTIM/sentinel"
mkdir -p "$TEST_ROOT/alias"

if OUROBOROS_DATA_DIR="$TEST_ROOT/alias/../ouroboros-victim" \
    sh "$CHECKOUT/scripts/dev.sh" reset >"$TEST_ROOT/refused-reset.out" 2>&1; then
    fail "reset accepted an unmarked directory"
else
    status=$?
    [ "$status" -eq 64 ] || fail "unmarked reset exited $status instead of 64"
fi
[ -f "$VICTIM/sentinel" ] || fail "refused reset changed the victim"

# Even a symlink to a marked directory is refused; reset authenticates a real leaf.
printf 'ouro-runtime-recovery-v2\n' >"$VICTIM/runtime.owner.recovery"
chmod 600 "$VICTIM/runtime.owner.recovery"
ln -s "$VICTIM" "$TEST_ROOT/ouroboros-link"
if OUROBOROS_DATA_DIR="$TEST_ROOT/ouroboros-link" \
    sh "$CHECKOUT/scripts/dev.sh" reset >"$TEST_ROOT/refused-link.out" 2>&1; then
    fail "reset accepted a symlink data directory"
fi
[ -f "$VICTIM/sentinel" ] || fail "symlink refusal changed the target"

# A private explicit directory with the runtime's persistent marker can be reset, and
# keeps both credentials and the lock/identity inode needed for the next reset.
CUSTOM="$TEST_ROOT/custom-data"
mkdir -p "$CUSTOM"
chmod 700 "$CUSTOM"
printf 'ouro-runtime-recovery-v2\n' >"$CUSTOM/runtime.owner.recovery"
chmod 600 "$CUSTOM/runtime.owner.recovery"
printf 'credentials\n' >"$CUSTOM/oauth.json"
printf 'discard\n' >"$CUSTOM/delete-me"
OUROBOROS_DATA_DIR="$CUSTOM" sh "$CHECKOUT/scripts/dev.sh" reset \
    >"$TEST_ROOT/custom-reset.out" 2>&1
[ ! -e "$CUSTOM/delete-me" ] || fail "authenticated reset kept ordinary state"
[ -f "$CUSTOM/oauth.json" ] || fail "authenticated reset removed oauth.json"
[ -f "$CUSTOM/runtime.owner.recovery" ] || fail "authenticated reset removed its marker"

# The script-selected default is safe by contract even before a runtime has written its
# marker, provided it is still the private, real directory the runtime requires.
XDG_ROOT="$TEST_ROOT/xdg"
DEFAULT_DIR="$XDG_ROOT/ouroboros-dev"
mkdir -p "$DEFAULT_DIR"
chmod 700 "$DEFAULT_DIR"
printf 'discard\n' >"$DEFAULT_DIR/delete-me"
(
    unset OUROBOROS_DATA_DIR
    XDG_DATA_HOME="$XDG_ROOT" sh "$CHECKOUT/scripts/dev.sh" reset \
        >"$TEST_ROOT/default-reset.out" 2>&1
)
[ ! -e "$DEFAULT_DIR/delete-me" ] || fail "default dev directory was not reset"

printf 'test-dev: reset identity and fail-closed stop checks passed\n'
