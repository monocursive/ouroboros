#!/usr/bin/env bash
# Install a published Ouroboros binary. Bash 3.2+; no sudo or build toolchain.
# Keep execution inside main so a truncated download cannot execute half a script.
main() (
    set -euo pipefail
    umask 022
    repository=https://github.com/monocursive/ouroboros
    version=latest
    bin_dir=${HOME:?HOME must be set}/.local/bin
    temporary=
    staged=
    trap 'rm -rf -- "${temporary:-}"; rm -f -- "${staged:-}"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' HUP TERM

    fail() { printf 'ouro installer: %s\n' "$*" >&2; exit 1; }
    usage() {
        cat <<'EOF'
Usage: bash install.sh [--version vX.Y.Z] [--bin-dir /absolute/path]

Default: latest stable release, installed to ~/.local/bin/ouro.
Also accepts vX.Y.Z-alpha.N, vX.Y.Z-beta.N and vX.Y.Z-rc.N.
Run again to upgrade or select an older release. No runtime is started or stopped.
EOF
    }
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version) [ "$#" -ge 2 ] || fail '--version needs a tag'; version=$2; shift 2 ;;
            --bin-dir) [ "$#" -ge 2 ] || fail '--bin-dir needs a path'; bin_dir=$2; shift 2 ;;
            -h|--help) usage; exit 0 ;;
            *) fail "unknown argument: $1 (see --help)" ;;
        esac
    done
    number='(0|[1-9][0-9]*)'
    tag_pattern="^v${number}\\.${number}\\.${number}(-(alpha|beta|rc)\\.${number})?$"
    [ "$version" = latest ] || [[ "$version" =~ $tag_pattern ]] || fail "invalid version: $version"
    case "$bin_dir" in /*) ;; *) fail '--bin-dir must be an absolute path' ;; esac
    for command in curl uname awk mktemp chmod mv cp; do
        command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
    done
    if command -v sha256sum >/dev/null 2>&1; then
        digest() { sha256sum "$1" | awk '{print $1}'; }
    elif command -v shasum >/dev/null 2>&1; then
        digest() { shasum -a 256 "$1" | awk '{print $1}'; }
    else
        fail 'install sha256sum or shasum to verify downloads'
    fi

    case "$(uname -s)" in
        Darwin) os=apple-darwin ;;
        Linux)
            os=unknown-linux-gnu
            # The release includes ERTS but uses the host GNU C library.
            command -v getconf >/dev/null 2>&1 || fail 'Linux releases require glibc 2.39 or newer'
            libc=$(getconf GNU_LIBC_VERSION 2>/dev/null) || fail 'musl/Alpine is unsupported; use a glibc Linux system'
            read -r libc_name libc_version <<<"$libc"
            [ "$libc_name" = glibc ] || fail 'Linux releases require glibc'
            awk -v v="$libc_version" 'BEGIN {split(v, n, "."); exit !(n[1] > 2 || (n[1] == 2 && n[2] >= 39))}' ||
                fail "glibc $libc_version is too old; releases require glibc 2.39 or newer"
            ;;
        *) fail 'supported platforms: macOS and GNU/Linux, x86-64 or ARM64' ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) arch=x86_64 ;;
        arm64|aarch64) arch=aarch64 ;;
        *) fail 'supported architectures: x86-64 and ARM64' ;;
    esac
    # Prefer the native ARM binary when invoked from a Rosetta terminal.
    if [ "$os" = apple-darwin ] && [ "$arch" = x86_64 ] &&
       [ "$(sysctl -in sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
        arch=aarch64
    fi
    download() {
        curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
            --tlsv1.2 --connect-timeout 15 --max-time 600 --retry 3 "$@"
    }
    if [ "$version" = latest ]; then
        # Resolve once, then fetch both files from that exact tag even if latest changes.
        resolved=$(download --head --output /dev/null --write-out '%{url_effective}' "$repository/releases/latest") ||
            fail "no stable release is available; see $repository/releases"
        case "$resolved" in "$repository/releases/tag/"*) version=${resolved##*/} ;; *) fail 'unexpected latest release redirect' ;; esac
        [[ "$version" =~ $tag_pattern ]] || fail 'latest release has an invalid version tag'
        [[ "$version" != *-* ]] || fail 'latest must resolve to a stable release'
    fi
    asset="ouro-${version#v}-$arch-$os"
    base="$repository/releases/download/$version"
    temporary=$(mktemp -d "${TMPDIR:-/tmp}/ouro-install.XXXXXX")
    printf 'Downloading Ouroboros %s (%s)...\n' "$version" "$arch-$os"
    download --output "$temporary/SHA256SUMS" "$base/SHA256SUMS" || fail "checksums unavailable for $version"
    expected=$(awk -v name="$asset" '$2 == name {count++; hash=$1} END {if (count != 1) exit 1; print hash}' "$temporary/SHA256SUMS") ||
        fail "release checksums must contain exactly one entry for $asset"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || fail 'invalid SHA-256 checksum'
    download --output "$temporary/ouro" "$base/$asset" || fail "binary unavailable for $version on $arch-$os"
    [ "$(digest "$temporary/ouro")" = "$expected" ] || fail 'checksum mismatch; existing installation was not changed'

    mkdir -p -- "$bin_dir"
    destination="$bin_dir/ouro"
    [ ! -L "$destination" ] || fail "$destination is a symlink; choose another --bin-dir or remove the link yourself"
    [ ! -e "$destination" ] || [ -f "$destination" ] || fail "$destination is not a regular file"
    # Stage on the destination filesystem: rename replaces a running binary atomically.
    staged=$(mktemp "$bin_dir/.ouro-install.XXXXXX")
    cp -- "$temporary/ouro" "$staged"
    chmod 755 "$staged"
    mv -f -- "$staged" "$destination"
    staged=
    printf 'Installed %s to %s\n' "$version" "$destination"
    case ":${PATH:-}:" in
        *":$bin_dir:"*) ;;
        *) printf 'Add it to your PATH: export PATH=%q:%s\n' "$bin_dir" "\"\$PATH\"" ;;
    esac
    printf 'Run ouro from your project directory. If a runtime is already running, stop it before using the new version.\n'
)

main "$@"
