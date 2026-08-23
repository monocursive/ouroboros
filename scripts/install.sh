#!/bin/sh
# Install `ouro` from a published release, verifying what can be verified and saying
# plainly what cannot.
#
# WHAT THIS CHECKS, AND WHAT EACH CHECK IS WORTH
#
#   1. SHA-256 of the downloaded asset against a SHA256SUMS file. On its own this is
#      worth very little: both files come from the same place, so whoever can replace
#      one can replace the other. It catches a truncated or corrupted download and
#      nothing an attacker would be stopped by. It always runs, and a mismatch is fatal.
#
#   2. A minisign Ed25519 signature over that SHA256SUMS file, against the public key in
#      dist/release.pub. This is the check that is worth something: it says the project's
#      offline signing key produced this manifest, so check 1 inherits its authority.
#      It runs only when `minisign` is installed, because this is POSIX sh and Ed25519 is
#      not something to hand-roll here. When minisign is missing, the script says so in
#      as many words, and what you are left with is check 1 — which is a corruption
#      check, not a security one.
#
#   3. TLS, when the download is over https. That authenticates the host and hides the
#      bytes in flight. It is not a statement about who built them.
#
# The strong version of this is `ouro update`, which has the release public key compiled
# into it and refuses outright when it cannot verify a signature. This script exists for
# the machine that does not have `ouro` yet.
#
# Never runs sudo. Installs under $HOME by default. `--dry-run` prints the plan.

set -eu

VERSION_DEFAULT="latest"

# The release location. Empty on purpose: this repository does not publish to a public
# host yet, and a default that 404s would be worse than a refusal that explains itself.
# Set OURO_BASE_URL, pass --from, or edit this line to
# https://github.com/<owner>/<repo>/releases/latest/download once one exists.
BASE_URL_DEFAULT=""

SUMS_NAME="SHA256SUMS"
SIG_NAME="SHA256SUMS.minisig"

# Bounds. A download that has not finished in fifteen minutes is not going to.
CONNECT_TIMEOUT=20
MAX_TIME=900
MAX_ASSET_BYTES=536870912   # 512 MiB
MAX_SMALL_BYTES=1048576     # 1 MiB

self=$(basename "$0")

say()  { printf '%s\n' "$*"; }
note() { printf '%s\n' "$*" >&2; }
die()  { printf '%s: %s\n' "$self" "$*" >&2; exit 1; }

usage() {
    cat <<USAGE
Usage: $self [options]

  --from URL       Release directory: https://, http://, file:///, or a path.
                   Also OURO_BASE_URL. Required while this build has no default.
  --version V      Install this version instead of the latest. Also OURO_VERSION.
                   Only meaningful with a --from that is not a "latest" alias.
  --dir PATH       Install into PATH instead of \$HOME/.local/bin.
                   Also OURO_INSTALL_DIR.
  --dry-run        Print what would happen; download nothing, install nothing.
  --help           This.

Exit status: 0 installed (or, with --dry-run, planned); 1 refused or failed.

There is no --channel. This project publishes one tag stream; see docs/DISTRIBUTION.md.
USAGE
}

BASE_URL=${OURO_BASE_URL:-$BASE_URL_DEFAULT}
VERSION=${OURO_VERSION:-$VERSION_DEFAULT}
INSTALL_DIR=${OURO_INSTALL_DIR:-}
DRY_RUN=0

while [ $# -gt 0 ]; do
    case $1 in
        --from)     [ $# -ge 2 ] || die "--from needs a URL";  BASE_URL=$2;    shift 2 ;;
        --from=*)   BASE_URL=${1#--from=};                                     shift ;;
        --version)  [ $# -ge 2 ] || die "--version needs a value"; VERSION=$2; shift 2 ;;
        --version=*) VERSION=${1#--version=};                                  shift ;;
        --dir)      [ $# -ge 2 ] || die "--dir needs a path"; INSTALL_DIR=$2;  shift 2 ;;
        --dir=*)    INSTALL_DIR=${1#--dir=};                                   shift ;;
        --dry-run)  DRY_RUN=1;                                                 shift ;;
        --help|-h)  usage; exit 0 ;;
        *)          usage >&2; die "unknown option: $1" ;;
    esac
done

if [ -z "$BASE_URL" ]; then
    note "$self: no release location is configured, so there is nothing to install from."
    note ""
    note "This repository does not publish releases to a public host yet. Pass one:"
    note "    $self --from https://example/releases/latest/download"
    note "    $self --from /path/to/a/release/directory"
    note "or set OURO_BASE_URL. See docs/DISTRIBUTION.md."
    exit 1
fi

# ---------------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------------

detect_triple() {
    _os=$(uname -s)
    _arch=$(uname -m)

    case $_arch in
        arm64|aarch64) _arch=aarch64 ;;
        x86_64|amd64)  _arch=x86_64 ;;
    esac

    case $_os in
        Darwin) _osname=apple-darwin ;;
        Linux)  _osname=unknown-linux-gnu ;;
        *)      _osname="" ;;
    esac

    case "$_arch/$_osname" in
        aarch64/apple-darwin)      printf 'aarch64-apple-darwin' ;;
        x86_64/apple-darwin)       printf 'x86_64-apple-darwin' ;;
        x86_64/unknown-linux-gnu)  printf 'x86_64-unknown-linux-gnu' ;;
        aarch64/unknown-linux-gnu) printf 'aarch64-unknown-linux-gnu' ;;
        *) return 1 ;;
    esac
}

TRIPLE=$(detect_triple) || die "releases are built for macOS and Linux on x86_64 and aarch64; this is $(uname -s)/$(uname -m)"

# ---------------------------------------------------------------------------------
# Fetching. A local directory is read with cp so the tests need no network and no
# server; anything with a scheme goes through curl or wget.
# ---------------------------------------------------------------------------------

case $BASE_URL in
    file://*)
        LOCAL_DIR=${BASE_URL#file://}
        case $LOCAL_DIR in
            /*) ;;
            *)  die "only file:///absolute/path URLs are read; $BASE_URL names a host" ;;
        esac
        ;;
    http://*|https://*) LOCAL_DIR="" ;;
    *://*)              die "$BASE_URL is not a scheme this script fetches" ;;
    *)                  LOCAL_DIR=$BASE_URL ;;
esac

BASE_URL=${BASE_URL%/}

# Returns non-zero and leaves the reason in FETCH_ERROR rather than exiting, because one
# of the four artifacts is optional and `exit` inside a function ends the whole script
# even when the call is the condition of an `if`.
fetch_try() {
    # fetch_try <name> <destination> <max-bytes>
    _name=$1; _destination=$2; _cap=$3
    FETCH_ERROR=""

    if [ -n "$LOCAL_DIR" ]; then
        if [ ! -f "$LOCAL_DIR/$_name" ]; then
            FETCH_ERROR="$LOCAL_DIR/$_name does not exist"
            return 1
        fi

        if ! cp "$LOCAL_DIR/$_name" "$_destination" 2>/dev/null; then
            FETCH_ERROR="could not read $LOCAL_DIR/$_name"
            return 1
        fi
    elif command -v curl >/dev/null 2>&1; then
        # --proto keeps a redirect from walking down to another scheme; -L is needed
        # because release hosts redirect downloads to an object store.
        case $BASE_URL in
            https://*) _protos='=https' ;;
            *)         _protos='=http,https' ;;
        esac

        if ! curl --fail --silent --show-error --location \
                  --proto "$_protos" --proto-redir "$_protos" \
                  --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
                  --max-filesize "$_cap" \
                  --user-agent "ouro-install.sh" \
                  --output "$_destination" -- "$BASE_URL/$_name" 2>/dev/null
        then
            FETCH_ERROR="could not download $BASE_URL/$_name"
            return 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget --quiet --tries=1 --timeout="$MAX_TIME" \
                  --output-document="$_destination" -- "$BASE_URL/$_name" 2>/dev/null
        then
            FETCH_ERROR="could not download $BASE_URL/$_name"
            return 1
        fi
    else
        FETCH_ERROR="neither curl nor wget is installed; cannot download $_name"
        return 1
    fi

    # curl can only enforce a cap the server declared, and wget cannot enforce one at
    # all, so the cap is also applied to what actually landed.
    _size=$(file_size "$_destination")

    if [ "$_size" -gt "$_cap" ]; then
        rm -f "$_destination"
        FETCH_ERROR="$_name is $_size bytes and the cap for it is $_cap"
        return 1
    fi

    return 0
}

fetch() {
    fetch_try "$@" || die "$FETCH_ERROR"
}

file_size() {
    # BSD and GNU stat disagree about everything except that both are present.
    if _size=$(stat -f '%z' "$1" 2>/dev/null); then
        printf '%s' "$_size"
    elif _size=$(stat -c '%s' "$1" 2>/dev/null); then
        printf '%s' "$_size"
    else
        wc -c < "$1" | tr -d ' '
    fi
}

# Chosen once, up front. Discovering that no tool exists inside a command substitution
# would kill only the subshell, and the caller would compare against an empty string.
if command -v sha256sum >/dev/null 2>&1;   then SHA256_TOOL=sha256sum
elif command -v shasum >/dev/null 2>&1;    then SHA256_TOOL=shasum
elif command -v openssl >/dev/null 2>&1;   then SHA256_TOOL=openssl
else
    die "no sha256 tool found (sha256sum, shasum, or openssl); refusing to install bytes nothing can check"
fi

sha256_of() {
    case $SHA256_TOOL in
        sha256sum) sha256sum "$1" | cut -d' ' -f1 ;;
        shasum)    shasum -a 256 "$1" | cut -d' ' -f1 ;;
        openssl)   openssl dgst -sha256 "$1" | sed 's/.*= *//' ;;
    esac
}

# ---------------------------------------------------------------------------------
# Where it goes
# ---------------------------------------------------------------------------------

if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="${HOME:?HOME is not set and no --dir was given}/.local/bin"
fi

say "ouro installer"
say "  platform    $TRIPLE"
say "  source      $BASE_URL"
say "  install to  $INSTALL_DIR/ouro"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/ouro-install.XXXXXX") || die "could not create a temporary directory"
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT INT TERM

# ---------------------------------------------------------------------------------
# The manifest, and the signature over it
# ---------------------------------------------------------------------------------

fetch "$SUMS_NAME" "$WORK/$SUMS_NAME" "$MAX_SMALL_BYTES"

SIGNED=0
if fetch_try "$SIG_NAME" "$WORK/$SIG_NAME" "$MAX_SMALL_BYTES"; then
    SIGNED=1
else
    note ""
    note "$self: this release has no $SIG_NAME beside its $SUMS_NAME."
    note "$self: there is therefore no signature to check, and the checksum below proves"
    note "$self: only that the download was not corrupted in transit."
fi

# dist/release.pub as committed in this repository, or wherever --pubkey points. The
# script is meant to be run standalone (curl | sh) as well as from a checkout, so the key
# is looked for beside the script and then in the checkout it belongs to.
PUBKEY=""
for candidate in \
    "${OURO_PUBKEY_FILE:-}" \
    "$(dirname "$0")/../dist/release.pub" \
    "$(dirname "$0")/release.pub"
do
    [ -n "$candidate" ] || continue
    [ -f "$candidate" ] || continue
    PUBKEY=$candidate
    break
done

# The committed file may be the unprovisioned placeholder. Pull out the first line that
# is neither a `#` annotation nor minisign's comment header; if there is none, there is
# no key.
PUBKEY_BASE64=""
if [ -n "$PUBKEY" ]; then
    PUBKEY_BASE64=$(
        sed -e '/^[[:space:]]*#/d' \
            -e '/^[[:space:]]*untrusted comment:/d' \
            -e '/^[[:space:]]*$/d' \
            "$PUBKEY" | head -n 1
    )
fi

VERIFIED=0

if [ "$SIGNED" -eq 1 ] && [ -n "$PUBKEY_BASE64" ] && command -v minisign >/dev/null 2>&1; then
    # -P takes the key inline, so the `#` annotations in dist/release.pub never reach
    # minisign's own parser.
    if minisign -V -P "$PUBKEY_BASE64" -x "$WORK/$SIG_NAME" -m "$WORK/$SUMS_NAME" >/dev/null 2>&1
    then
        VERIFIED=1
        say "  signature   ok, minisign Ed25519 against $PUBKEY"
    else
        die "the release signature does not check out against $PUBKEY. These bytes were not signed by the Ouroboros release key. Nothing was installed."
    fi
else
    note ""
    note "$self: NOT VERIFYING A SIGNATURE. What is missing:"
    [ "$SIGNED" -eq 1 ]        || note "  - the release published no $SIG_NAME"
    [ -n "$PUBKEY_BASE64" ]    || note "  - no release public key (dist/release.pub is unprovisioned or absent)"
    command -v minisign >/dev/null 2>&1 || \
        note "  - minisign is not installed  (brew install minisign / apt install minisign)"
    note ""
    note "$self: the SHA-256 check below still runs, and it is a corruption check only:"
    note "$self: the manifest came from the same place as the binary, so anyone able to"
    note "$self: replace one could replace the other. This is a weaker install than the"
    note "$self: signed one, and it is weaker in a specific way, not vaguely."
fi

# ---------------------------------------------------------------------------------
# Which asset
# ---------------------------------------------------------------------------------

if [ "$VERSION" = "latest" ]; then
    # The manifest names the version, so no second, unsigned source has to be asked.
    ASSET=$(sed -n "s/^[0-9a-fA-F]\{64\}[ *]*\(ouro-.*-$TRIPLE\)$/\1/p" "$WORK/$SUMS_NAME" | head -n 1)
    [ -n "$ASSET" ] || die "$SUMS_NAME names no ouro-<version>-$TRIPLE asset"
else
    ASSET="ouro-$VERSION-$TRIPLE"
    grep -q "[ *]$ASSET\$" "$WORK/$SUMS_NAME" || die "$SUMS_NAME does not list $ASSET"
fi

EXPECTED=$(sed -n "s/^\([0-9a-fA-F]\{64\}\)[ *]*$ASSET\$/\1/p" "$WORK/$SUMS_NAME" | head -n 1)
[ -n "$EXPECTED" ] || die "no checksum for $ASSET in $SUMS_NAME"

say "  asset       $ASSET"

if [ "$DRY_RUN" -eq 1 ]; then
    say ""
    say "--dry-run: would download $BASE_URL/$ASSET"
    say "--dry-run: would check sha256 $EXPECTED"
    if [ "$VERIFIED" -eq 1 ]; then
        say "--dry-run: the manifest's signature was verified"
    else
        say "--dry-run: NO signature was verified (see above)"
    fi
    say "--dry-run: would install to $INSTALL_DIR/ouro"
    exit 0
fi

# ---------------------------------------------------------------------------------
# Download, check, install
# ---------------------------------------------------------------------------------

fetch "$ASSET" "$WORK/$ASSET" "$MAX_ASSET_BYTES"

ACTUAL=$(sha256_of "$WORK/$ASSET")

# Both spellings, because sha256sum and shasum print lowercase but a hand-written
# manifest might not.
if [ "$(printf '%s' "$ACTUAL" | tr 'A-Z' 'a-z')" != "$(printf '%s' "$EXPECTED" | tr 'A-Z' 'a-z')" ]; then
    die "$ASSET hashes to $ACTUAL and $SUMS_NAME says $EXPECTED. Nothing was installed."
fi

say "  sha256      ok, matches $SUMS_NAME"

mkdir -p "$INSTALL_DIR" || die "could not create $INSTALL_DIR"
[ -w "$INSTALL_DIR" ] || die "$INSTALL_DIR is not writable by this user, and this script never runs sudo. Pass --dir to a directory you own."

# Write beside the target and rename over it: a running `ouro` keeps the inode it was
# started from, and the name never refers to a half-written file.
STAGED="$INSTALL_DIR/.ouro.install-$$"
cp "$WORK/$ASSET" "$STAGED" || die "could not write to $INSTALL_DIR"
chmod 755 "$STAGED"
mv -f "$STAGED" "$INSTALL_DIR/ouro" || { rm -f "$STAGED"; die "could not install into $INSTALL_DIR"; }

say "  installed   $INSTALL_DIR/ouro"

if [ "$(uname -s)" = "Darwin" ]; then
    # Only bytes that came over the network carry a quarantine attribute, and only an
    # unsigned/unnotarized binary is stopped by it. Both are true of today's macOS
    # artifacts, so say it rather than letting Gatekeeper say it less clearly.
    xattr -d com.apple.quarantine "$INSTALL_DIR/ouro" 2>/dev/null || true
fi

case ":${PATH}:" in
    *":$INSTALL_DIR:"*)
        say ""
        say "Run: ouro version"
        ;;
    *)
        say ""
        say "$INSTALL_DIR is not on your PATH. Add it:"
        say ""
        say "    export PATH=\"$INSTALL_DIR:\$PATH\""
        say ""
        say "and put that line in your shell's startup file (~/.zshrc, ~/.bashrc, ...)."
        say "Then: ouro version"
        ;;
esac

if [ "$VERIFIED" -eq 0 ]; then
    note ""
    note "$self: reminder — no signature was verified for this install."
fi
