#!/bin/sh
# Release coordinates and signing identity are explicitly configured until publication is set up.
set -eu
prefix="$HOME/.local/bin"
base=''
source_dir=''
public_key=''
upgrade=false
allow_downgrade=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix) prefix=$2; shift 2 ;;
        --base-url) base=$2; shift 2 ;;
        --from-dir) source_dir=$2; shift 2 ;;
        --public-key) public_key=$2; shift 2 ;;
        --upgrade) upgrade=true; shift ;;
        --allow-downgrade) allow_downgrade=true; shift ;;
        --yes) shift ;;
        *) echo "Usage: install.sh (--base-url HTTPS_URL | --from-dir DIR) --public-key KEY [--prefix DIR] [--upgrade] [--allow-downgrade]" >&2; exit 2 ;;
    esac
done
[ -n "$public_key" ] || { echo 'A trusted minisign public key is required.' >&2; exit 2; }
[ -n "$base" ] || [ -n "$source_dir" ] || { echo 'Release location is not configured.' >&2; exit 2; }
[ -z "$base" ] || [ -z "$source_dir" ] || { echo 'Choose one release location.' >&2; exit 2; }
case "$base" in ''|https://*) ;; *) echo 'Release URL must use HTTPS.' >&2; exit 2 ;; esac
command -v minisign >/dev/null || { echo 'minisign is required for signature verification.' >&2; exit 2; }
case "$(uname -s):$(uname -m)" in
    Linux:x86_64) target=x86_64-unknown-linux-gnu ;;
    Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-gnu ;;
    Darwin:x86_64) target=x86_64-apple-darwin ;;
    Darwin:arm64) target=aarch64-apple-darwin ;;
    *) echo 'Unsupported operating system or architecture.' >&2; exit 2 ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fetch() {
    if [ -n "$source_dir" ]; then cp "$source_dir/$1" "$work/$1"
    else curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' "$base/$1" -o "$work/$1"; fi
}
fetch SHA256SUMS
fetch SHA256SUMS.minisig
minisign -Vm "$work/SHA256SUMS" -x "$work/SHA256SUMS.minisig" -P "$public_key" >/dev/null || { echo 'SHA256SUMS signature verification failed.' >&2; exit 1; }
# Archive names carry the release version; the manifest must name exactly one
# archive for this platform, so a directory never installs a surprising one.
artifact=$(awk -v suffix="-$target.tar.gz" '
    $2 ~ suffix "$" { name = $2; count++ }
    END { if (count == 1) print name; if (count != 1) exit 1 }' "$work/SHA256SUMS") || {
    echo "The release manifest must carry exactly one archive for $target." >&2; exit 1;
}
# Use the release coordinate authenticated by the signed manifest, rather
# than the Cargo package version shared by multiple release candidates.
case "$artifact" in
    ouro-jail-*"-$target.tar.gz")
        staged_version=${artifact#ouro-jail-}
        staged_version=${staged_version%"-$target.tar.gz"} ;;
    *) echo 'Invalid release archive name.' >&2; exit 1 ;;
esac
valid_version() {
    printf '%s\n' "$1" | LC_ALL=C awk '
        NR != 1 { exit 1 }
        {
            if ($0 !~ /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/) exit 1
            split($0, build, /\+/)
            if (length(build[2])) {
                n = split(build[2], ids, ".")
                for (i = 1; i <= n; i++) if (ids[i] !~ /^[0-9A-Za-z-]+$/) exit 1
            }
            value = build[1]
            suffix = value
            if (sub(/-.*/, "", value)) {
                suffix = substr(suffix, length(value) + 2)
                n = split(suffix, ids, ".")
                for (i = 1; i <= n; i++)
                    if (ids[i] !~ /^[0-9A-Za-z-]+$/ || ids[i] ~ /^0[0-9]+$/) exit 1
            }
            split(value, parts, ".")
            for (i = 1; i <= 3; i++) if (parts[i] ~ /^0[0-9]+$/) exit 1
        }'
}
valid_version "$staged_version" || { echo 'Invalid semantic release version in the manifest.' >&2; exit 1; }
fetch "$artifact"
expected=$(awk -v name="$artifact" '$2 == name { print $1; count++ } END { if (count != 1) exit 1 }' "$work/SHA256SUMS")
[ "${#expected}" -eq 64 ] || { echo "Invalid checksum for $artifact" >&2; exit 1; }
actual=$(shasum -a 256 "$work/$artifact" | awk '{print $1}')
[ "$actual" = "$expected" ] || { echo "Checksum verification failed: $artifact" >&2; exit 1; }
# The signed manifest covers the installer itself; the copy beside the
# artifacts must match the script being run, so an old or doctored installer
# cannot set up a release it does not belong to.
if awk '$2 == "install.sh" { found = 1 } END { exit !found }' "$work/SHA256SUMS"; then
    fetch install.sh
    expected=$(awk '$2 == "install.sh" { print $1; count++ } END { if (count != 1) exit 1 }' "$work/SHA256SUMS")
    actual=$(shasum -a 256 "$work/install.sh" | awk '{print $1}')
    [ "$actual" = "$expected" ] || { echo 'Checksum verification failed: install.sh' >&2; exit 1; }
    cmp -s "$work/install.sh" "$0" || { echo 'This installer does not match the release it installs.' >&2; exit 1; }
fi
# Extract named members to stdout; never materialize arbitrary archive paths.
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
[ ! -L "$prefix/ouro-jail" ] || { echo 'Refusing to replace a symlink.' >&2; exit 1; }
[ ! -L "$prefix/ouro-jail.release" ] || { echo 'Refusing a symlinked release record.' >&2; exit 1; }
if [ -e "$prefix/ouro-jail" ]; then
    [ "$upgrade" = true ] || { echo 'Already installed; use --upgrade to replace it.' >&2; exit 1; }
    if [ -e "$prefix/ouro-jail.release" ]; then
        installed_version=$(sed -n '1p' "$prefix/ouro-jail.release")
        installed_digest=$(sed -n '2p' "$prefix/ouro-jail.release")
        actual=$(shasum -a 256 "$prefix/ouro-jail" | awk '{print $1}')
        if [ "$installed_digest" != "$actual" ]; then
            # A crash between the two renames, or a manual binary replacement,
            # must fail closed. The explicit downgrade override also permits
            # recovery by reinstalling the authenticated staged release.
            [ "$allow_downgrade" = true ] || { echo 'Existing release record does not match the installed binary; use --allow-downgrade to reinstall the verified release.' >&2; exit 1; }
            installed_version=$staged_version
        fi
    else
        installed_version=$(version_of "$prefix/ouro-jail")
    fi
    valid_version "$installed_version" || { echo 'Existing binary has no valid version record.' >&2; exit 1; }
    relation=$(version_relation "$staged_version" "$installed_version")
    if [ "$relation" = -1 ] && [ "$allow_downgrade" != true ]; then
        echo "Refusing to downgrade $installed_version to $staged_version; pass --allow-downgrade to replace it." >&2
        exit 1
    fi
fi
# Same-directory temporary file and rename keep the final install atomic.
staged=$(mktemp "$prefix/.ouro-jail.XXXXXX")
notice=$(mktemp "$prefix/.ouro-jail-license.XXXXXX")
record=$(mktemp "$prefix/.ouro-jail-release.XXXXXX")
trap 'rm -rf "$work"; rm -f "$staged" "$notice" "$record"' EXIT HUP INT TERM
cat "$work/ouro-jail" > "$staged"
chmod 755 "$staged"
[ ! -L "$prefix/ouro-jail.LICENSES.txt" ] || { echo 'Refusing a symlinked license notice.' >&2; exit 1; }
cat "$work/ouro-jail.LICENSES.txt" > "$notice"
chmod 644 "$notice"
digest=$(shasum -a 256 "$staged" | awk '{print $1}')
printf '%s\n%s\n' "$staged_version" "$digest" > "$record"
chmod 644 "$record"
mv -f "$notice" "$prefix/ouro-jail.LICENSES.txt"
mv -f "$record" "$prefix/ouro-jail.release"
mv -f "$staged" "$prefix/ouro-jail"
"$prefix/ouro-jail" version
printf 'Installed release %s in %s. Add that directory to PATH if needed.\n' "$staged_version" "$prefix"
