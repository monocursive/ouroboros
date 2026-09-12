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
printf 'test-isolated-test: command gate, private mode, location, cleanup, and symlink-parent refusal passed\n'