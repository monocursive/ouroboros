#!/usr/bin/env bash
# Public developer installer. Bash 3.2+; execution waits for the complete script.
main() (
    set -euo pipefail
    umask 077
    export LC_ALL=C
    repository=https://github.com/monocursive/ouroboros
    version=0.1.0-rc.1
    prefix=${HOME:?HOME must be set}/.local/bin
    base=
    source_dir=
    work=
    staged=
    notice=
    record=
    allow_downgrade=false
    trap 'rm -rf -- "${work:-}"; rm -f -- "${staged:-}" "${notice:-}" "${record:-}"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' HUP TERM

    fail() { printf 'ouro installer: %s\n' "$*" >&2; exit 1; }
    usage() {
        cat <<EOF
Usage: bash install.sh [--version VERSION] [--bin-dir /absolute/path]
                       [--allow-downgrade]

Installs Ouroboros Jail's Linux developer preview into ~/.local/bin.
The default version is $version; --version also accepts vVERSION or
ouro-jail-vVERSION, but only releases with embedded SHA-256 pins are accepted.
Run again to upgrade. Downgrades require --allow-downgrade.
Requires curl, tar, and sha256sum or shasum. No sudo or Rust compiler.
Linux binaries require glibc 2.39 or newer; Alpine/musl is unsupported.
Execution requires a compatible Linux host and bubblewrap; check doctor after
installation. macOS execution is not available in this preview.

Offline installation: --from-dir DIR
Other mirrors: --base-url HTTPS_URL
Offline files and mirrors must match the embedded release hashes.
EOF
    }
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version|--bin-dir|--prefix|--base-url|--from-dir)
                if [ "$#" -lt 2 ] || [ -z "${2-}" ]; then fail "$1 needs a value"; fi
                case "$1" in
                    --version) version=$2 ;;
                    --bin-dir|--prefix) prefix=$2 ;;
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
    valid_version() { [[ "$1" =~ $pattern ]]; }
    valid_version "$version" || fail "invalid semantic version: $version"
    case "$prefix" in /*) ;; *) fail '--bin-dir must be an absolute path' ;; esac
    [ -z "$base" ] || [ -z "$source_dir" ] || fail 'choose --base-url or --from-dir'
    case "$base" in ''|https://*) ;; *) fail '--base-url must use HTTPS' ;; esac
    for command in uname awk mktemp tar sed mkdir chmod cat mv; do
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
    if [ "$libc_name" != glibc ] || ! [[ "$libc_version" =~ ^[0-9]+\.[0-9]+$ ]]; then
        fail 'cannot determine the glibc version'
    fi
    awk -v v="$libc_version" 'BEGIN {split(v,n,"."); exit !(n[1]>2 || (n[1]==2 && n[2]>=39))}' ||
        fail "glibc $libc_version is too old; this preview requires glibc 2.39 or newer"
    if command -v sha256sum >/dev/null 2>&1; then
        digest() { sha256sum "$1" | awk '{print $1}'; }
    elif command -v shasum >/dev/null 2>&1; then
        digest() { shasum -a 256 "$1" | awk '{print $1}'; }
    else
        fail 'install sha256sum or shasum to verify downloads'
    fi
    # BEGIN SHA256 PINS
    case "$version:$target" in
        0.1.0-rc.1:aarch64-unknown-linux-gnu) expected='100d0e8e78d27c08372b18352de987da447f157ef75c8ebeac0cf5e24dd0400a' ;;
        0.1.0-rc.1:x86_64-unknown-linux-gnu) expected='9413e8fd0cea1417c1ba47e5e0fad07edf3a26b8615e68a5aa642662f1209da8' ;;
        *) fail "no pinned SHA-256 for $version ($target); download the current installer" ;;
    esac
    # END SHA256 PINS
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
    artifact="ouro-jail-$version-$target.tar.gz"
    fetch "$artifact"
    [ "$(digest "$work/$artifact")" = "$expected" ] || fail "checksum verification failed: $artifact"
    # Extract only the binary and notices from the checksum-verified archive.
    tar -xOzf "$work/$artifact" ouro-jail > "$work/ouro-jail"
    tar -xOzf "$work/$artifact" ouro-jail.LICENSES.txt > "$work/ouro-jail.LICENSES.txt"
    chmod 755 "$work/ouro-jail"
    # Legacy installs have only the package version the binary reports.
    version_of() {
        "$1" version 2>/dev/null | sed -n 's/^ouro-jail \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\([-+][0-9A-Za-z.+-]\{1,\}\)\{0,1\}\)$/\1/p'
    }
    binary_version=$(version_of "$work/ouro-jail")
    valid_version "$binary_version" || { echo 'The staged binary does not report a release version.' >&2; exit 1; }
    # Prints -1 when $1 is older than $2, 0 when equal, 1 when newer: semver's
    # numeric triple, then a pre-release suffix that is older than no suffix.
    version_relation() {
        printf '%s\n%s\n' "$1" "$2" | LC_ALL=C awk '
            function integer_relation(a, b) {
                if (length(a) != length(b)) return length(a) < length(b) ? -1 : 1
                if ("v" a == "v" b) return 0
                return ("v" a < "v" b) ? -1 : 1
            }
            {
                value = $0
                sub(/\+.*/, "", value)
                full = value
                if (sub(/-.*/, "", value)) suffix[NR] = substr(full, length(value) + 2)
                split(value, part, ".")
                for (field = 1; field <= 3; field++) number[NR, field] = part[field]
            }
            END {
                for (field = 1; field <= 3; field++) {
                    relation = integer_relation(number[1, field], number[2, field])
                    if (relation) { print relation; exit }
                }
                if (suffix[1] == suffix[2]) { print 0; exit }
                if (suffix[1] == "") { print 1; exit }
                if (suffix[2] == "") { print -1; exit }
                a_count = split(suffix[1], a, ".")
                b_count = split(suffix[2], b, ".")
                for (i = 1; i <= a_count && i <= b_count; i++) {
                    a_numeric = a[i] ~ /^[0-9]+$/; b_numeric = b[i] ~ /^[0-9]+$/
                    if (a_numeric && b_numeric) relation = integer_relation(a[i], b[i])
                    else if (a_numeric != b_numeric) relation = a_numeric ? -1 : 1
                    else relation = ("v" a[i] == "v" b[i]) ? 0 : (("v" a[i] < "v" b[i]) ? -1 : 1)
                    if (relation) { print relation; exit }
                }
                print (a_count == b_count ? 0 : (a_count < b_count ? -1 : 1))
            }'
    }
    mkdir -p "$prefix"
    for name in ouro-jail ouro-jail.release ouro-jail.LICENSES.txt; do
        [ ! -L "$prefix/$name" ] || { echo "Refusing a symlinked installation file: $name" >&2; exit 1; }
        [ ! -e "$prefix/$name" ] || [ -f "$prefix/$name" ] || { echo "Installation destination must be a regular file: $name" >&2; exit 1; }
    done
    [ ! -L "$prefix/ouro-jail" ] || { echo 'Refusing to replace a symlink.' >&2; exit 1; }
    [ ! -L "$prefix/ouro-jail.release" ] || { echo 'Refusing a symlinked release record.' >&2; exit 1; }
    if [ -e "$prefix/ouro-jail" ]; then
        if [ -e "$prefix/ouro-jail.release" ]; then
            installed_version=$(sed -n '1p' "$prefix/ouro-jail.release")
            installed_digest=$(sed -n '2p' "$prefix/ouro-jail.release")
            actual=$(digest "$prefix/ouro-jail")
            if [ "$installed_digest" != "$actual" ]; then
                # A crash between the two renames, or a manual binary replacement,
                # must fail closed. The explicit downgrade override also permits
                # recovery by reinstalling the checksum-verified staged release.
                [ "$allow_downgrade" = true ] || { echo 'Existing release record does not match the installed binary; use --allow-downgrade to reinstall the verified release.' >&2; exit 1; }
                installed_version=$version
            fi
        else
            installed_version=$(version_of "$prefix/ouro-jail")
        fi
        valid_version "$installed_version" || { echo 'Existing binary has no valid version record.' >&2; exit 1; }
        relation=$(version_relation "$version" "$installed_version")
        if [ "$relation" = -1 ] && [ "$allow_downgrade" != true ]; then
            echo "Refusing to downgrade $installed_version to $version; pass --allow-downgrade to replace it." >&2
            exit 1
        fi
    fi
    # Same-directory temporary file and rename keep the final install atomic.
    staged=$(mktemp "$prefix/.ouro-jail.XXXXXX")
    notice=$(mktemp "$prefix/.ouro-jail-license.XXXXXX")
    record=$(mktemp "$prefix/.ouro-jail-release.XXXXXX")
    cat "$work/ouro-jail" > "$staged"
    chmod 755 "$staged"
    [ ! -L "$prefix/ouro-jail.LICENSES.txt" ] || { echo 'Refusing a symlinked license notice.' >&2; exit 1; }
    cat "$work/ouro-jail.LICENSES.txt" > "$notice"
    chmod 644 "$notice"
    binary_digest=$(digest "$staged")
    printf '%s\n%s\n' "$version" "$binary_digest" > "$record"
    chmod 644 "$record"
    mv -f "$notice" "$prefix/ouro-jail.LICENSES.txt"
    mv -f "$record" "$prefix/ouro-jail.release"
    mv -f "$staged" "$prefix/ouro-jail"
    "$prefix/ouro-jail" version
    printf 'Installed release %s in %s. Add that directory to PATH if needed.\n' "$version" "$prefix"
    printf '\nCheck host support: %s/ouro-jail doctor --profile tool\n' "$prefix"
    case ":${PATH:-}:" in
        *":$prefix:"*) ;;
        *) printf 'Add this directory to PATH: export PATH="%s:%s"\n' "$prefix" "\$PATH" ;;
    esac
)
main "$@"
