#!/usr/bin/env bash
# The inside-the-container half of `make dist-linux`. It runs the repository's own
# `make dist` rather than a re-spelling of it: a cross-build that follows a second,
# parallel recipe is a cross-build that drifts from the one it claims to mirror.
#
# Three directories, and the separation is the point:
#
#   /src   the checkout, bind-mounted READ-ONLY. Nothing here is ever written, so a
#          cross-build cannot leave x86-64 objects in a developer's arm64 `_build/`.
#   /work  a named volume. The source is rsynced here and every derived byte —
#          `deps/`, `_build/`, `tui/target/` — stays here between runs, which is what
#          turns a 2m 34s cold build into a 48s one.
#   /out   the checkout's `dist/`, bind-mounted read-write. The one artifact leaves here.
set -euo pipefail

SRC=${OURO_SRC:-/src}
WORK=${OURO_WORK:-/work}
OUT=${OURO_OUT:-/out}
RELEASE=${OURO_RELEASE_NAME:-ouroboros}
EXPECTED_TRIPLE=x86_64-unknown-linux-gnu

say() { printf '==> dist-linux(container): %s\n' "$*"; }
die() { printf 'dist-linux(container): %s\n' "$*" >&2; exit 1; }

[ -f "$SRC/mix.exs" ] || die "$SRC does not look like an Ouroboros checkout (no mix.exs)"
[ -d "$OUT" ] || die "$OUT is not mounted; the artifact would have nowhere to go"

triple=$(rustc -vV | sed -n 's/^host: //p')
[ "$triple" = "$EXPECTED_TRIPLE" ] ||
    die "this image builds $EXPECTED_TRIPLE, but rustc reports host $triple"

say "toolchain: $(elixir --version | tail -1), $(rustc --version), host $triple"

# The excludes are the reason the repository's working tree can be mounted at all. A
# developer's `_build/`, `deps/`, and `tui/target/` are multi-gigabyte and are also for the
# WRONG architecture; copying them in would be slow and wrong in the same breath. rsync
# protects excluded paths from --delete, so the work volume keeps its own copies of
# exactly those directories — that is the cache.
#
# `dist/` is excluded by artifact name rather than as a directory, because most of it is
# source: `tui/src/update.rs` compiles `dist/release.pub` in with `include_str!`, and a
# tree without it does not build at all.
say "staging source into $WORK (build output excluded, and kept)"
mkdir -p "$WORK"
rsync -a --delete \
    --exclude '.git/' \
    --exclude '.claude/' \
    --exclude '_build/' \
    --exclude 'deps/' \
    --exclude 'cover/' \
    --exclude 'doc/' \
    --exclude 'tmp/' \
    --exclude '.elixir_ls/' \
    --exclude 'tui/target/' \
    --exclude 'priv/computer-use/' \
    --exclude '/dist/ouro-*' \
    --exclude '/dist/.ouro-dist-linux-artifact' \
    "$SRC/" "$WORK/"

cd "$WORK"

# release.yml gets hex and rebar from `erlef/setup-beam`; a container has to ask for them.
say "hex and rebar"
mix local.hex --force >/dev/null
mix local.rebar --force >/dev/null

say "mix deps.get"
mix deps.get

# The same verb a laptop runs (Makefile `dist`): computer-use helper, MIX_ENV=prod
# mix release, cargo --release --features embed with OUROBOROS_RELEASE_TARBALL, then the
# copy to dist/ouro-<version>-<host triple>. On Linux the Computer Use helper compiles its
# honest "unsupported platform" stub — the same thing the release runner produces.
say "make dist"
make dist

version=$(ls "_build/prod/$RELEASE"-*.tar.gz | head -1 | sed -e "s|.*/$RELEASE-||" -e 's|\.tar\.gz$||')
[ -n "$version" ] || die "could not read a release version out of _build/prod"

name="ouro-$version-$triple"
[ -f "dist/$name" ] || die "make dist did not produce dist/$name"

install -m 0755 "dist/$name" "$OUT/$name"

# The host half prints the artifact; it should not have to guess the name it just built.
printf '%s\n' "$name" > "$OUT/.ouro-dist-linux-artifact"

say "$name  $(sha256sum "$OUT/$name" | cut -d' ' -f1)"
