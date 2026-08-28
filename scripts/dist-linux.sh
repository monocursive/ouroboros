#!/bin/sh
# `make dist-linux` — the host half. Cross-builds the Linux x86-64 `ouro` in Docker so a
# developer on an Apple Silicon Mac has something `ouro fleet add` can copy to a Linux
# machine. It is a development convenience, not the release path: see docs/DISTRIBUTION.md §9.
#
# Two invariants shape everything below.
#
# 1. The Docker BUILD CONTEXT is `dist/docker/`, not the repository. A working tree carries
#    multi-gigabyte `_build/`, `deps/`, and `tui/target/` directories, and `docker build`
#    would tar every byte of them up before reading the first line of the Dockerfile. The
#    checkout reaches the build as a read-only bind mount instead, and the container rsyncs
#    the source (never the derived output) into a named volume it owns.
#
# 2. Nothing writes into the checkout except `dist/`. The container's `_build/` and
#    `tui/target/` are x86-64; a developer's are arm64. Letting the two share a directory
#    would corrupt both, so they never meet.
#
# Environment overrides, all optional:
#   OURO_DIST_LINUX_IMAGE        image tag to build/use
#   OURO_DIST_LINUX_ERL_FLAGS    ERL_FLAGS for the in-container BEAM (see the preflight)
#   OURO_DIST_LINUX_RUST_VERSION rustup toolchain to bake into the image
#   DOCKER                       docker command
set -eu

DOCKER=${DOCKER:-docker}
PLATFORM=linux/amd64
IMAGE=${OURO_DIST_LINUX_IMAGE:-ouroboros-dist-linux-x86_64:otp29-elixir1.20.2}
RUST_VERSION=${OURO_DIST_LINUX_RUST_VERSION:-1.88}

VOLUME_WORK=ouro-dist-linux-x86_64-work
VOLUME_CARGO=ouro-dist-linux-x86_64-cargo
VOLUME_HOME=ouro-dist-linux-x86_64-home

# The BEAM's JIT normally writes machine code through one mapping and executes it through
# another. Apple's Rosetta (OrbStack's and Docker Desktop's x86-64 emulator on Apple
# Silicon) does not invalidate its translation cache for the second mapping, so OTP >= 28
# boots into a `prim_tty` whose NIFs never took effect and the node dies before `mix` runs.
# `+JMsingle true` asks the JIT for a single read-write-execute mapping, which Rosetta does
# follow. It is an ordinary supported emulator flag, it applies only to the VM that RUNS
# the build, and it has no effect on the ERTS inside the artifact.
ERL_FLAGS_DEFAULT='+JMsingle true'
ERL_FLAGS_VALUE=${OURO_DIST_LINUX_ERL_FLAGS:-$ERL_FLAGS_DEFAULT}

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

say()  { printf '==> dist-linux: %s\n' "$*"; }
die()  { printf 'dist-linux: %s\n' "$*" >&2; exit 1; }

if command -v sha256sum >/dev/null 2>&1;   then SHA256_TOOL=sha256sum
elif command -v shasum >/dev/null 2>&1;    then SHA256_TOOL=shasum
elif command -v openssl >/dev/null 2>&1;   then SHA256_TOOL=openssl
else SHA256_TOOL=""
fi

sha256_of() {
    case "$SHA256_TOOL" in
        sha256sum) sha256sum "$1" | cut -d' ' -f1 ;;
        shasum)    shasum -a 256 "$1" | cut -d' ' -f1 ;;
        openssl)   openssl dgst -sha256 "$1" | sed 's/.*= *//' ;;
        *)         echo "(no sha256 tool on this host)" ;;
    esac
}

if [ "${1:-}" = "--clean" ]; then
    say "removing the build caches ($VOLUME_WORK, $VOLUME_CARGO, $VOLUME_HOME)"
    $DOCKER volume rm -f "$VOLUME_WORK" "$VOLUME_CARGO" "$VOLUME_HOME" >/dev/null 2>&1 || true
    say "removing the image ($IMAGE)"
    $DOCKER image rm -f "$IMAGE" >/dev/null 2>&1 || true
    exit 0
fi

command -v "$DOCKER" >/dev/null 2>&1 ||
    die "no '$DOCKER' on PATH. This target cross-builds in a container; there is no other way to get an x86-64 ERTS from an arm64 machine."
$DOCKER version >/dev/null 2>&1 ||
    die "'$DOCKER version' failed — is the daemon running?"

mkdir -p "$root/dist"

started=$(date +%s)

say "image: $IMAGE (rust $RUST_VERSION, $PLATFORM)"
$DOCKER build \
    --platform "$PLATFORM" \
    --build-arg "RUST_VERSION=$RUST_VERSION" \
    -f "$root/dist/docker/Dockerfile.linux-x86_64" \
    -t "$IMAGE" \
    "$root/dist/docker"

# Fail here rather than part-way through a release build. An x86-64 emulator that cannot
# boot the BEAM cannot run `mix` either, and the symptom deep inside `mix deps.get` is an
# unreadable kernel crash dump.
say "preflight: can the emulator boot OTP 29?"
if ! $DOCKER run --rm --platform "$PLATFORM" \
        -e ERL_FLAGS="$ERL_FLAGS_VALUE" \
        --entrypoint erl "$IMAGE" -noshell -eval 'halt(0).' >/dev/null 2>&1; then
    printf '%s\n' \
        "dist-linux: the x86-64 emulator on this host cannot boot OTP 29." \
        "" \
        "  ERL_FLAGS was: $ERL_FLAGS_VALUE" \
        "" \
        "  Apple Silicon + Rosetta needs '+JMsingle true' (the default here) because the" \
        "  BEAM's JIT writes code through a second mapping that Rosetta does not invalidate." \
        "  If that is already set and it still fails, the emulator is the problem, not the" \
        "  flag: QEMU 8.2 crashes on the BEAM outright. Override with" \
        "  OURO_DIST_LINUX_ERL_FLAGS, or build on a real x86-64 Linux machine." >&2
    exit 1
fi

say "building (emulated x86-64; a cold run rebuilds every dependency in both languages)"
$DOCKER run --rm \
    --platform "$PLATFORM" \
    -e ERL_FLAGS="$ERL_FLAGS_VALUE" \
    -v "$root:/src:ro" \
    -v "$root/dist:/out" \
    -v "$VOLUME_WORK:/work" \
    -v "$VOLUME_CARGO:/opt/cargo/registry" \
    -v "$VOLUME_HOME:/root" \
    "$IMAGE"

marker="$root/dist/.ouro-dist-linux-artifact"
[ -f "$marker" ] || die "the container did not report an artifact name; nothing was produced"
name=$(cat "$marker")
rm -f "$marker"

artifact="dist/$name"
[ -f "$root/$artifact" ] || die "$artifact is missing after a build that claimed to write it"

elapsed=$(( $(date +%s) - started ))

say "done in $((elapsed / 60))m $((elapsed % 60))s"
printf '    %s\n' "$artifact"
printf '    %s bytes\n' "$(wc -c < "$root/$artifact" | tr -d ' ')"
printf '    sha256 %s\n' "$(sha256_of "$root/$artifact")"
if command -v file >/dev/null 2>&1; then
    printf '    %s\n' "$(file -b "$root/$artifact")"
fi
