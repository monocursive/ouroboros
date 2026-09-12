#!/bin/sh
# Run an application-starting Mix test with fresh private runtime state.
set -eu

[ "$#" -ge 2 ] && [ "$1" = mix ] && [ "$2" = test ] || {
    printf 'usage: scripts/test-isolated.sh mix test [arguments...]\n' >&2
    exit 64
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PARENT="$ROOT/tmp/test-runtime"
DATA=""
cleanup() { if [ -n "$DATA" ]; then rm -rf "$DATA"; fi; }
umask 077
mkdir -p "$ROOT/tmp"
if [ -L "$ROOT/tmp" ] || { [ -e "$PARENT" ] && [ -L "$PARENT" ]; }; then
    printf 'test-isolated: refusing symlinked workspace test-data parent\n' >&2
    exit 64
fi
mkdir -p "$PARENT"
DATA="$(mktemp -d "$PARENT/isolated.XXXXXX")"
trap cleanup EXIT HUP INT TERM
chmod 700 "$DATA"

cd "$ROOT"
OUROBOROS_DATA_DIR="$DATA" "$@"