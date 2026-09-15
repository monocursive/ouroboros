#!/bin/sh
# Exercise the real make recipe with producer stubs, not a Rust/BEAM build or daemon.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ouro-packaging-test.XXXXXX")"
TMP="$(CDPATH= cd -- "$TMP" && pwd)"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

fixture() {
    dir="$TMP/$1 checkout"
    mkdir -p "$dir/bin" "$dir/tui/target/release" "$dir/_build/prod"
    cp "$ROOT/Makefile" "$dir/Makefile"
    cat >"$dir/bin/mix" <<'EOF'
#!/bin/sh
set -eu
[ "$*" = 'release --overwrite' ]
[ "$MIX_ENV" = prod ]
[ "${FAIL_MIX:-0}" = 0 ] || exit 19
if [ "${NO_TARBALL:-0}" = 0 ]; then
    printf 'fixture release\n' > "_build/prod/ouroboros-$VERSION.tar.gz"
fi
EOF
    cat >"$dir/bin/cargo" <<'EOF'
#!/bin/sh
set -eu
[ "$*" = 'build --locked --release --features embed' ]
printf '%s\n' "$OUROBOROS_RELEASE_TARBALL" > ../selected
touch target/release/ouro
EOF
    chmod 700 "$dir/bin/mix" "$dir/bin/cargo"
}

build() {
    (cd "$dir" && NO_TARBALL="${1:-0}" FAIL_MIX="${2:-0}" \
        PATH="$dir/bin:$PATH" make -o wasm -o media ouro MIX=mix CARGO=cargo)
}

VERSION=0.1.0-rc.1
export VERSION
fixture single
build >"$TMP/single.log" 2>&1
[ "$(cat "$dir/selected")" = "$dir/_build/prod/ouroboros-$VERSION.tar.gz" ]

fixture multiple
printf 'old release\n' > "$dir/_build/prod/ouroboros-0.0.1.tar.gz"
if build >"$TMP/multiple.log" 2>&1; then
    echo 'packaging: accepted ambiguous release tarballs' >&2; exit 1
fi
grep -q 'expected one regular release tarball' "$TMP/multiple.log"
[ ! -e "$dir/selected" ]
[ "$(cat "$dir/_build/prod/ouroboros-0.0.1.tar.gz")" = 'old release' ]
[ -f "$dir/_build/prod/ouroboros-$VERSION.tar.gz" ]

fixture missing
if build 1 >"$TMP/missing.log" 2>&1; then
    echo 'packaging: accepted missing release tarball' >&2; exit 1
fi
[ ! -e "$dir/selected" ]

fixture failed
printf 'old release\n' > "$dir/_build/prod/ouroboros-0.0.1.tar.gz"
if build 0 1 >"$TMP/failed.log" 2>&1; then
    echo 'packaging: ignored failed Mix release' >&2; exit 1
fi
[ ! -e "$dir/selected" ]

fixture symlink
printf 'outside artifact\n' > "$dir/outside"
ln -s "$dir/outside" "$dir/_build/prod/ouroboros-$VERSION.tar.gz"
if build 1 >"$TMP/symlink.log" 2>&1; then
    echo 'packaging: accepted symlinked release tarball' >&2; exit 1
fi
grep -q 'expected one regular release tarball' "$TMP/symlink.log"
[ ! -e "$dir/selected" ]
[ "$(cat "$dir/outside")" = 'outside artifact' ]
printf 'release-packaging: 5 recipe cases passed (producer stubs; no product build)\n'
