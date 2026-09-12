#!/bin/sh
# Run an application-starting Mix test with fresh private runtime state.
set -eu

LOOPBACK_PEERS=0
if [ "${1:-}" = --loopback-peers ]; then
    LOOPBACK_PEERS=1
    shift
fi

[ "$#" -ge 2 ] && [ "$1" = mix ] && [ "$2" = test ] || {
    printf 'usage: scripts/test-isolated.sh [--loopback-peers] mix test [arguments...]\n' >&2
    exit 64
}

# The caller owns the private mapper and HOME. Only opt-in runs change BEAM's
# per-process hostname lookup and distribution interface; ordinary Mix is untouched.
if [ "$LOOPBACK_PEERS" = 1 ]; then
    port="${ERL_EPMD_PORT:-}"
    case "$port" in
        ''|*[!0-9]*)
            printf 'test-isolated: --loopback-peers requires a private ERL_EPMD_PORT\n' >&2
            exit 64 ;;
    esac
    if [ "${#port}" -gt 5 ] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ] ||
        [ "$port" -eq 4369 ] || [ "$port" -eq 65358 ]; then
        printf 'test-isolated: refusing default, protected, or invalid EPMD port\n' >&2
        exit 64
    fi
    if [ "${ERL_EPMD_ADDRESS:-}" != 127.0.0.1 ]; then
        printf 'test-isolated: --loopback-peers requires ERL_EPMD_ADDRESS=127.0.0.1\n' >&2
        exit 64
    fi
    # Shell parsing cannot prove that arbitrary ERTS options/config files preserve
    # this interface. Refuse them rather than silently overriding caller settings.
    if [ "${ERL_INETRC+x}" = x ] ||
        [ -n "${ERL_AFLAGS:-}${ERL_FLAGS:-}${ERL_ZFLAGS:-}${ELIXIR_ERL_OPTIONS:-}" ]; then
        printf 'test-isolated: --loopback-peers requires unset ERL_INETRC and empty ERTS option variables (ERL_AFLAGS, ERL_FLAGS, ERL_ZFLAGS, ELIXIR_ERL_OPTIONS)\n' >&2
        exit 64
    fi
    peer_host="$(hostname)"
    peer_host="${peer_host%%.*}"
    case "$peer_host" in
        ''|*[!a-zA-Z0-9_-]*)
            printf 'test-isolated: hostname cannot be encoded as a private shortname alias\n' >&2
            exit 64 ;;
    esac
fi

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

if [ "$LOOPBACK_PEERS" = 1 ]; then
    printf '{lookup, [file]}.\n{host, {127,0,0,1}, ["%s"]}.\n' "$peer_host" >"$DATA/inetrc"
    chmod 600 "$DATA/inetrc"
    ERL_INETRC="$DATA/inetrc"
    ERL_AFLAGS='-kernel inet_dist_use_interface {127,0,0,1}'
    export ERL_INETRC ERL_AFLAGS
fi

cd "$ROOT"
OUROBOROS_DATA_DIR="$DATA" "$@"
