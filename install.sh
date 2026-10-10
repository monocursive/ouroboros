#!/usr/bin/env bash
# Public developer installer. Bash 3.2+; execution waits for the complete script.
main() (
    set -euo pipefail
    umask 077
    export LC_ALL=C
    repository=https://github.com/monocursive/ouroboros
    version=0.1.0-rc.1
    # Production identity: crates/ouro-jail/dist/release.pub.
    public_key='RWRiwzSgdll+x5sLSP9cMZjjHRPIecme3XyjrMWqAnlmEx7KzppXscDI'
    prefix=${HOME:?HOME must be set}/.local/bin
    base=
    source_dir=
    work=
    allow_downgrade=false
    trap 'rm -rf -- "${work:-}"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' HUP TERM

    fail() { printf 'ouro installer: %s\n' "$*" >&2; exit 1; }
    usage() {
        cat <<'EOF'
Usage: bash install.sh [--version VERSION] [--bin-dir /absolute/path]
                       [--public-key KEY] [--allow-downgrade]

Installs Ouroboros Jail's Linux developer preview into ~/.local/bin.
The default version is 0.1.0-rc.1; --version also accepts vVERSION or
ouro-jail-vVERSION. Run again to upgrade. Downgrades require --allow-downgrade.
Requires curl, minisign, tar, and sha256sum or shasum. No sudo or Rust compiler.
Linux binaries require glibc 2.39 or newer; Alpine/musl is unsupported.
Execution requires a compatible Linux host and bubblewrap; check doctor after
installation. macOS execution is not available in this preview.

Local testing: --from-dir DIR --public-key KEY
Other mirrors: --base-url HTTPS_URL --public-key KEY
EOF
    }
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version|--bin-dir|--prefix|--public-key|--base-url|--from-dir)
                [ "$#" -ge 2 ] && [ -n "$2" ] || fail "$1 needs a value"
                case "$1" in
                    --version) version=$2 ;;
                    --bin-dir|--prefix) prefix=$2 ;;
                    --public-key) public_key=$2 ;;
                    --base-url) base=$2 ;;
                    --from-dir) source_dir=$2 ;;
                esac
                shift 2 ;;
            --allow-downgrade) allow_downgrade=true; shift ;;
            -h|--help) usage; exit 0 ;;
            *) fail "unknown argument: $1 (see --help)" ;;
        esac
    done
    version=${version#ouro-jail-v}
    version=${version#v}
    number='(0|[1-9][0-9]*)'
    identifier='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
    pattern="^${number}\\.${number}\\.${number}(-${identifier}(\\.${identifier})*)?(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$"
    [[ "$version" =~ $pattern ]] || fail "invalid semantic version: $version"
    [ -n "$public_key" ] || fail 'production signing key is not configured; provide --public-key from a trusted source'
    case "$prefix" in /*) ;; *) fail '--bin-dir must be an absolute path' ;; esac
    [ -z "$base" ] || [ -z "$source_dir" ] || fail 'choose --base-url or --from-dir'
    case "$base" in ''|https://*) ;; *) fail '--base-url must use HTTPS' ;; esac
    for command in uname awk mktemp minisign tar; do
        command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
    done
    case "$(uname -s):$(uname -m)" in
        Linux:x86_64|Linux:amd64) target=x86_64-unknown-linux-gnu ;;
        Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-gnu ;;
        *) fail 'this preview supports Linux x86_64 and ARM64; macOS sandbox execution is unavailable' ;;
    esac
    command -v getconf >/dev/null 2>&1 || fail 'glibc 2.39 or newer is required; getconf is missing'
    libc=$(getconf GNU_LIBC_VERSION 2>/dev/null) || fail 'glibc 2.39 or newer is required; Alpine/musl is unsupported'
    read -r libc_name libc_version <<<"$libc"
    [ "$libc_name" = glibc ] && [[ "$libc_version" =~ ^[0-9]+\.[0-9]+$ ]] || fail 'cannot determine the glibc version'
    awk -v v="$libc_version" 'BEGIN {split(v,n,"."); exit !(n[1]>2 || (n[1]==2 && n[2]>=39))}' ||
        fail "glibc $libc_version is too old; this preview requires glibc 2.39 or newer"
    if command -v sha256sum >/dev/null 2>&1; then
        digest() { sha256sum "$1" | awk '{print $1}'; }
    elif command -v shasum >/dev/null 2>&1; then
        digest() { shasum -a 256 "$1" | awk '{print $1}'; }
    else
        fail 'install sha256sum or shasum to verify downloads'
    fi
    if [ -n "$source_dir" ]; then
        [ -d "$source_dir" ] || fail '--from-dir must name an artifact directory'
    else
        command -v curl >/dev/null 2>&1 || fail 'required command not found: curl'
        base=${base:-$repository/releases/download/ouro-jail-v$version}
    fi
    work=$(mktemp -d "${TMPDIR:-/tmp}/ouro-install.XXXXXX")
    fetch() {
        if [ -n "$source_dir" ]; then
            cp -- "$source_dir/$1" "$work/$1" || fail "missing release asset: $1"
        else
            curl --disable --fail --silent --show-error --location \
                --proto '=https' --proto-redir '=https' --tlsv1.2 \
                --connect-timeout 15 --max-time 600 --retry 3 \
                "$base/$1" --output "$work/$1" ||
                fail "cannot download $1 for ouro-jail-v$version; see $repository/releases"
        fi
    }
    fetch SHA256SUMS
    fetch SHA256SUMS.minisig
    minisign -Vm "$work/SHA256SUMS" -x "$work/SHA256SUMS.minisig" -P "$public_key" >/dev/null ||
        fail 'release signature verification failed'
    artifact="ouro-jail-$version-$target.tar.gz"
    # Verify the downloaded installer BEFORE executing any of its code.
    for asset in install.sh "$artifact"; do
        expected=$(awk -v name="$asset" '$2 == name {print $1; count++} END {if (count != 1) exit 1}' "$work/SHA256SUMS") ||
            fail "signed manifest must name exactly one $asset"
        [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || fail "invalid checksum for $asset"
        fetch "$asset"
        [ "$(digest "$work/$asset")" = "$expected" ] || fail "checksum verification failed: $asset"
    done
    # Use the verified snapshot, including the archive, so no download races
    # with a mutable mirror between bootstrap verification and installation.
    set -- --from-dir "$work" --public-key "$public_key" --prefix "$prefix" --upgrade
    if [ "$allow_downgrade" = true ]; then set -- "$@" --allow-downgrade; fi
    sh "$work/install.sh" "$@"
    printf '\nCheck host support: %s/ouro-jail doctor --profile tool\n' "$prefix"
    case ":${PATH:-}:" in
        *":$prefix:"*) ;;
        *) printf 'Add this directory to PATH: export PATH="%s:%s"\n' "$prefix" "\$PATH" ;;
    esac
)
main "$@"
