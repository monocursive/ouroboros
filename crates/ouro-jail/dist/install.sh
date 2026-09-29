#!/bin/sh
# Release coordinates and signing identity are explicitly configured until publication is set up.
set -eu
prefix="$HOME/.local/bin"
base=''
source_dir=''
public_key=''
upgrade=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix) prefix=$2; shift 2 ;;
        --base-url) base=$2; shift 2 ;;
        --from-dir) source_dir=$2; shift 2 ;;
        --public-key) public_key=$2; shift 2 ;;
        --upgrade) upgrade=true; shift ;;
        --yes) shift ;;
        *) echo "Usage: install.sh (--base-url HTTPS_URL | --from-dir DIR) --public-key KEY [--prefix DIR] [--upgrade]" >&2; exit 2 ;;
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
artifact="ouro-jail-$target.tar.gz"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fetch() {
    if [ -n "$source_dir" ]; then cp "$source_dir/$1" "$work/$1"
    else curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' "$base/$1" -o "$work/$1"; fi
}
fetch SHA256SUMS
fetch SHA256SUMS.minisig
minisign -Vm "$work/SHA256SUMS" -x "$work/SHA256SUMS.minisig" -P "$public_key" >/dev/null || { echo 'SHA256SUMS signature verification failed.' >&2; exit 1; }
fetch "$artifact"
expected=$(awk -v name="$artifact" '$2 == name { print $1; count++ } END { if (count != 1) exit 1 }' "$work/SHA256SUMS")
[ "${#expected}" -eq 64 ] || { echo "Invalid checksum for $artifact" >&2; exit 1; }
actual=$(shasum -a 256 "$work/$artifact" | awk '{print $1}')
[ "$actual" = "$expected" ] || { echo "Checksum verification failed: $artifact" >&2; exit 1; }
# Extract named members to stdout; never materialize arbitrary archive paths.
tar -xOzf "$work/$artifact" ouro-jail > "$work/ouro-jail"
tar -xOzf "$work/$artifact" ouro-jail.LICENSES.txt > "$work/ouro-jail.LICENSES.txt"
chmod 755 "$work/ouro-jail"
"$work/ouro-jail" version >/dev/null
mkdir -p "$prefix"
[ ! -L "$prefix/ouro-jail" ] || { echo 'Refusing to replace a symlink.' >&2; exit 1; }
if [ -e "$prefix/ouro-jail" ]; then
    [ "$upgrade" = true ] || { echo 'Already installed; use --upgrade to replace it.' >&2; exit 1; }
    "$prefix/ouro-jail" version >/dev/null || { echo 'Existing binary has no valid version record.' >&2; exit 1; }
fi
# Same-directory temporary file and rename keep the final install atomic.
staged=$(mktemp "$prefix/.ouro-jail.XXXXXX")
notice=$(mktemp "$prefix/.ouro-jail-license.XXXXXX")
trap 'rm -rf "$work"; rm -f "$staged" "$notice"' EXIT HUP INT TERM
cat "$work/ouro-jail" > "$staged"
chmod 755 "$staged"
[ ! -L "$prefix/ouro-jail.LICENSES.txt" ] || { echo 'Refusing a symlinked license notice.' >&2; exit 1; }
cat "$work/ouro-jail.LICENSES.txt" > "$notice"
chmod 644 "$notice"
mv -f "$notice" "$prefix/ouro-jail.LICENSES.txt"
mv -f "$staged" "$prefix/ouro-jail"
"$prefix/ouro-jail" version
printf 'Installed in %s. Add that directory to PATH if needed.\n' "$prefix"
