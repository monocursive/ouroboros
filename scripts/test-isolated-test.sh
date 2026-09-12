#!/bin/sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/test-isolated-test.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT HUP INT TERM
mkdir "$TMP/bin"

if "$ROOT/scripts/test-isolated.sh" printf nope >"$TMP/refusal" 2>&1; then
    printf 'test-isolated-test: accepted a non-Mix command\n' >&2
    exit 1
fi
if "$ROOT/scripts/test-isolated.sh" mix run nope >"$TMP/refusal-run" 2>&1; then
    printf 'test-isolated-test: accepted an application-starting non-test Mix command\n' >&2
    exit 1
fi

cat >"$TMP/bin/mix" <<'EOF'
#!/bin/sh
set -eu
[ "$#" -eq 2 ] && [ "$1" = test ] && [ "$2" = sentinel ]
case "$OUROBOROS_DATA_DIR" in "$PWD"/tmp/test-runtime/isolated.*) ;; *) exit 21 ;; esac
[ -d "$OUROBOROS_DATA_DIR" ] && [ ! -L "$OUROBOROS_DATA_DIR" ]
mode="$(stat -f %Lp "$OUROBOROS_DATA_DIR" 2>/dev/null || stat -c %a "$OUROBOROS_DATA_DIR")"
[ "$mode" = 700 ]
printf '%s\n' "$OUROBOROS_DATA_DIR"
EOF
chmod 755 "$TMP/bin/mix"

data="$(PATH="$TMP/bin:$PATH" "$ROOT/scripts/test-isolated.sh" mix test sentinel)"
[ ! -e "$data" ] || {
    printf 'test-isolated-test: private data directory was not removed\n' >&2
    exit 1
}

# These are producer stubs: no Erlang VM, mapper, socket, or credential file is used.
cat >"$TMP/bin/hostname" <<'EOF'
#!/bin/sh
printf '%s\n' "${TEST_HOSTNAME:-ouro-isolated.example.local}"
EOF
chmod 755 "$TMP/bin/hostname"
cat >"$TMP/bin/mix" <<'EOF'
#!/bin/sh
set -eu
[ "$#" -eq 2 ] && [ "$1" = test ]
[ "$HOME" = "$TEST_EXPECTED_HOME" ]
case "$OUROBOROS_DATA_DIR" in "$PWD"/tmp/test-runtime/isolated.*) ;; *) exit 21 ;; esac
[ -d "$OUROBOROS_DATA_DIR" ] && [ ! -L "$OUROBOROS_DATA_DIR" ]
case "$2" in
    sentinel) ;;
    inherited)
        [ "$ERL_INETRC" = "$TEST_CALLER_INETRC" ]
        [ "$ERL_AFLAGS" = '+S 2:2' ]
        [ "$ERL_FLAGS" = '-kernel caller_setting true' ]
        [ "$ERL_ZFLAGS" = '-s caller boot' ]
        [ "$ELIXIR_ERL_OPTIONS" = '+A 2' ]
        [ "$ERL_EPMD_PORT" = 4369 ]
        [ "$ERL_EPMD_ADDRESS" = '::1' ] ;;
    loopback|failure)
        [ "$ERL_INETRC" = "$OUROBOROS_DATA_DIR/inetrc" ] && [ -f "$ERL_INETRC" ]
        mode="$(stat -f %Lp "$ERL_INETRC" 2>/dev/null || stat -c %a "$ERL_INETRC")"
        [ "$mode" = 600 ]
        expected="$(printf '{lookup, [file]}.\n{host, {127,0,0,1}, ["ouro-isolated"]}.\n')"
        [ "$(cat "$ERL_INETRC")" = "$expected" ]
        [ "$ERL_AFLAGS" = '-kernel inet_dist_use_interface {127,0,0,1}' ]
        [ "$ERL_EPMD_PORT" = 54321 ]
        [ "$ERL_EPMD_ADDRESS" = 127.0.0.1 ] ;;
    *) exit 22 ;;
esac
printf '%s\n' "$OUROBOROS_DATA_DIR"
[ "$2" != failure ] || exit 37
EOF

TEST_EXPECTED_HOME="$HOME"
TEST_CALLER_INETRC="$TMP/absent-caller-inetrc"
export TEST_EXPECTED_HOME TEST_CALLER_INETRC
data="$(PATH="$TMP/bin:$PATH" ERL_INETRC="$TEST_CALLER_INETRC" ERL_AFLAGS='+S 2:2' \
    ERL_FLAGS='-kernel caller_setting true' ERL_ZFLAGS='-s caller boot' \
    ELIXIR_ERL_OPTIONS='+A 2' ERL_EPMD_PORT=4369 ERL_EPMD_ADDRESS='::1' \
    "$ROOT/scripts/test-isolated.sh" mix test inherited)"
[ ! -e "$data" ]

(
    unset ERL_INETRC ERL_AFLAGS ERL_FLAGS ERL_ZFLAGS ELIXIR_ERL_OPTIONS TEST_HOSTNAME
    PATH="$TMP/bin:$PATH"
    ERL_EPMD_PORT=54321
    ERL_EPMD_ADDRESS=127.0.0.1
    export PATH ERL_EPMD_PORT ERL_EPMD_ADDRESS

    data="$("$ROOT/scripts/test-isolated.sh" --loopback-peers mix test loopback)"
    [ ! -e "$data" ]
    if data="$("$ROOT/scripts/test-isolated.sh" --loopback-peers mix test failure)"; then
        printf 'test-isolated-test: hid the test command failure\n' >&2
        exit 1
    else
        [ "$?" -eq 37 ]
    fi
    [ ! -e "$data" ]

    expect_refusal() {
        if "$@" >"$TMP/loopback-refusal" 2>&1; then
            printf 'test-isolated-test: accepted incompatible loopback settings\n' >&2
            exit 1
        else
            [ "$?" -eq 64 ]
        fi
    }
    for refused_port in '' 0 4369 04369 65358 65536 100000 -1 invalid; do
        expect_refusal env ERL_EPMD_PORT="$refused_port" \
            "$ROOT/scripts/test-isolated.sh" --loopback-peers mix test loopback
    done
    for refused_address in '' 0.0.0.0 ::1; do
        expect_refusal env ERL_EPMD_ADDRESS="$refused_address" \
            "$ROOT/scripts/test-isolated.sh" --loopback-peers mix test loopback
    done
    expect_refusal env ERL_INETRC="$TEST_CALLER_INETRC" \
        "$ROOT/scripts/test-isolated.sh" --loopback-peers mix test loopback
    expect_refusal env ERL_INETRC= \
        "$ROOT/scripts/test-isolated.sh" --loopback-peers mix test loopback
    for option_variable in ERL_AFLAGS ERL_FLAGS ERL_ZFLAGS ELIXIR_ERL_OPTIONS; do
        expect_refusal env "$option_variable=+S 2:2" \
            "$ROOT/scripts/test-isolated.sh" --loopback-peers mix test loopback
    done
    expect_refusal env TEST_HOSTNAME='invalid"hostname' \
        "$ROOT/scripts/test-isolated.sh" --loopback-peers mix test loopback
    expect_refusal "$ROOT/scripts/test-isolated.sh" --loopback-peers mix run loopback
)

# A symlinked parent in a disposable fake checkout is refused before a leaf is made or
# removed; the target sentinel proves cleanup did not follow it.
fixture="$TMP/fixture"
target="$TMP/symlink-target"
mkdir -p "$fixture/scripts" "$fixture/tmp" "$target"
printf 'keep\n' >"$target/sentinel"
cp "$ROOT/scripts/test-isolated.sh" "$fixture/scripts/test-isolated.sh"
ln -s "$target" "$fixture/tmp/test-runtime"
if PATH="$TMP/bin:$PATH" "$fixture/scripts/test-isolated.sh" mix test sentinel \
    >"$TMP/symlink-refusal" 2>&1; then
    printf 'test-isolated-test: accepted a symlinked test-data parent\n' >&2
    exit 1
fi
[ -L "$fixture/tmp/test-runtime" ] && [ "$(cat "$target/sentinel")" = keep ] || {
    printf 'test-isolated-test: refusal changed the symlink or target\n' >&2
    exit 1
}
printf 'test-isolated-test: command gate, private state, cleanup, caller settings, loopback peer configuration, and refusal checks passed\n'
