#!/bin/sh
# Tests scripts/install.sh against a release directory this script builds.
#
# No network, no server, no privileged directory: the "release" is a temp directory read
# through install.sh's own local-path branch, and every install lands in another temp
# directory. Nothing under $HOME is touched, and `sudo` is never within reach.
#
# What this cannot cover: the curl branch (no network in CI by contract) and the minisign
# branch on a machine without minisign, which is loudly reported rather than silently
# skipped. Run it as `sh scripts/test-install.sh`.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
install_sh="$here/install.sh"

[ -f "$install_sh" ] || { echo "cannot find install.sh beside this test" >&2; exit 1; }

root=$(mktemp -d "${TMPDIR:-/tmp}/ouro-install-test.XXXXXX")
trap 'rm -rf "$root"' EXIT INT TERM

passed=0
failed=0

ok()   { passed=$((passed + 1)); printf '  ok    %s\n' "$1"; }
bad()  { failed=$((failed + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        openssl dgst -sha256 "$1" | sed 's/.*= *//'
    fi
}

triple() {
    _arch=$(uname -m)
    case $_arch in arm64|aarch64) _arch=aarch64 ;; x86_64|amd64) _arch=x86_64 ;; esac
    case $(uname -s) in
        Darwin) printf '%s-apple-darwin' "$_arch" ;;
        Linux)  printf '%s-unknown-linux-gnu' "$_arch" ;;
        *)      printf 'unsupported' ;;
    esac
}

TRIPLE=$(triple)
[ "$TRIPLE" != "unsupported" ] || { echo "this platform has no release triple; nothing to test" >&2; exit 1; }

# A "binary" that starts with this platform's executable magic, so nothing downstream has
# to special-case a fixture.
make_binary() {
    # $1 destination, $2 marker
    if [ "$(uname -s)" = "Darwin" ]; then
        printf '\317\372\355\376%s' "$2" > "$1"
    else
        printf '\177ELF%s' "$2" > "$1"
    fi
    # Pad, so a truncation is visible as a size change too.
    dd if=/dev/zero bs=1 count=512 >> "$1" 2>/dev/null
}

make_release() {
    # $1 directory, $2 version, $3 marker
    mkdir -p "$1"
    asset="ouro-$2-$TRIPLE"
    make_binary "$1/$asset" "$3"
    printf '%s  %s\n' "$(sha256_of "$1/$asset")" "$asset" > "$1/SHA256SUMS"
    printf '%s' "$asset"
}

printf 'install.sh\n'

# ---------------------------------------------------------------------------------
# Unsigned releases are refused. A checksum from the same place as the binary is
# not a signature, and this installer will not pretend it is.
# ---------------------------------------------------------------------------------

release="$root/release"
asset=$(make_release "$release" "9.9.9" "the released one")
target="$root/bin1"

if output=$(sh "$install_sh" --from "$release" --dir "$target" 2>&1); then
    bad "refuses an unsigned install" "it installed anyway"
else
    case $output in
        *"no verified minisign signature"*"Nothing was installed"*)
            ok "refuses an unsigned install" ;;
        *)
            bad "refuses an unsigned install" "$output" ;;
    esac
fi

if [ -e "$target/ouro" ]; then
    bad "an unsigned install leaves nothing behind" "$target/ouro exists"
else
    ok "an unsigned install leaves nothing behind"
fi

case $output in
    *"NOT VERIFYING A SIGNATURE"*)
        ok "names the missing signature check instead of implying one ran" ;;
    *)
        bad "names the missing signature check" "$output" ;;
esac

target="$root/bin2"
if output=$(sh "$install_sh" --from "file://$release" --dir "$target" 2>&1); then
    bad "refuses an unsigned file:// release" "it installed anyway"
else
    case $output in
        *"no verified minisign signature"*) ok "refuses an unsigned file:// release" ;;
        *) bad "refuses an unsigned file:// release" "$output" ;;
    esac
fi

if output=$(sh "$install_sh" --from "file://host/path" --dir "$root/bin-x" 2>&1); then
    bad "refuses file://host URLs" "it accepted one"
else
    case $output in
        *"names a host"*) ok "refuses file://host URLs" ;;
        *) bad "refuses file://host URLs" "$output" ;;
    esac
fi

if output=$(OURO_BASE_URL= sh "$install_sh" --dir "$root/bin8" 2>&1); then
    bad "refuses with no release location" "it did something"
else
    case $output in
        *"no release location is configured"*) ok "refuses with no release location" ;;
        *) bad "refuses with no release location" "$output" ;;
    esac
fi

case $(grep -c 'sudo' "$install_sh") in
    # The only mentions are the two sentences promising not to use it.
    2) ok "the script never invokes sudo" ;;
    *) bad "the script never invokes sudo" "grep found $(grep -c sudo "$install_sh") mentions; check them" ;;
esac

# ---------------------------------------------------------------------------------
# The signature branch, where minisign exists
# ---------------------------------------------------------------------------------

if command -v minisign >/dev/null 2>&1; then
    minisign -G -W -p "$root/test.pub" -s "$root/test.key" >/dev/null 2>&1

    signed="$root/signed"
    asset2=$(make_release "$signed" "9.9.9" "the signed one")
    minisign -S -s "$root/test.key" -m "$signed/SHA256SUMS" >/dev/null 2>&1

    target="$root/bin9"
    if output=$(OURO_PUBKEY_FILE="$root/test.pub" sh "$install_sh" --from "$signed" --dir "$target" 2>&1); then
        case $output in
            *"signature   ok"*) ok "verifies a real minisign signature when minisign is installed" ;;
            *) bad "verifies a real minisign signature" "$output" ;;
        esac
        if [ -x "$target/ouro" ] && cmp -s "$target/ouro" "$signed/$asset2"; then
            ok "installs a signed asset for this platform"
        else
            bad "installs a signed asset for this platform" "$target/ouro is missing or differs"
        fi
    else
        bad "verifies a real minisign signature" "$output"
    fi

    case $output in
        *"sha256      ok"*) ok "reports the checksum check after the signature" ;;
        *) bad "reports the checksum check after the signature" "$output" ;;
    esac

    target="$root/bin5"
    if output=$(OURO_PUBKEY_FILE="$root/test.pub" sh "$install_sh" --from "$signed" --dir "$target" --dry-run 2>&1); then
        if [ -e "$target/ouro" ]; then
            bad "--dry-run installs nothing" "$target/ouro exists"
        else
            ok "--dry-run installs nothing"
        fi

        case $output in
            *"would install to $target/ouro"*) ok "--dry-run names the destination" ;;
            *) bad "--dry-run names the destination" "$output" ;;
        esac

        case $output in
            *"the manifest's signature was verified"*) ok "--dry-run reports a verified signature" ;;
            *) bad "--dry-run reports a verified signature" "$output" ;;
        esac
    else
        bad "--dry-run succeeds for a signed release" "$output"
    fi

    target="$root/bin6"
    if output=$(OURO_PUBKEY_FILE="$root/test.pub" sh "$install_sh" --from "$signed" --dir "$target" --version 9.9.9 2>&1) \
       && cmp -s "$target/ouro" "$signed/$asset2"; then
        ok "installs an explicitly named signed version"
    else
        bad "installs an explicitly named signed version" "$output"
    fi

    if output=$(OURO_PUBKEY_FILE="$root/test.pub" sh "$install_sh" --from "$signed" --dir "$root/bin7" --version 1.2.3 2>&1); then
        bad "refuses a version the manifest does not list" "it installed something"
    else
        case $output in
            *"does not list ouro-1.2.3-$TRIPLE"*) ok "refuses a version the manifest does not list" ;;
            *) bad "refuses a version the manifest does not list" "$output" ;;
        esac
    fi

    empty="$root/empty"
    mkdir -p "$empty"
    zeroes=0000000000000000000000000000000000000000000000000000000000000000
    printf '%s  ouro-9.9.9-sparc-solaris\n' "$zeroes" > "$empty/SHA256SUMS"
    minisign -S -s "$root/test.key" -m "$empty/SHA256SUMS" >/dev/null 2>&1

    if output=$(OURO_PUBKEY_FILE="$root/test.pub" sh "$install_sh" --from "$empty" --dir "$root/bin4" 2>&1); then
        bad "refuses a release with no asset for this platform" "it installed something"
    else
        case $output in
            *"names no ouro-<version>-$TRIPLE asset"*) ok "refuses a release with no asset for this platform" ;;
            *) bad "refuses a release with no asset for this platform" "$output" ;;
        esac
    fi

    corrupt="$root/corrupt"
    cp -R "$signed" "$corrupt"
    make_binary "$corrupt/$asset2" "something else"

    target="$root/bin3"
    if output=$(OURO_PUBKEY_FILE="$root/test.pub" sh "$install_sh" --from "$corrupt" --dir "$target" 2>&1); then
        bad "refuses an asset whose checksum does not match" "it installed anyway"
    else
        case $output in
            *"Nothing was installed"*) ok "refuses an asset whose checksum does not match" ;;
            *) bad "refuses an asset whose checksum does not match" "$output" ;;
        esac
    fi

    if [ -e "$target/ouro" ]; then
        bad "a refused checksum leaves nothing behind" "$target/ouro exists"
    else
        ok "a refused checksum leaves nothing behind"
    fi

    locked="$root/locked"
    mkdir -p "$locked"
    chmod 500 "$locked"

    if [ "$(id -u)" = "0" ]; then
        printf '  SKIP  refuses an unwritable directory (running as root, where it is writable)\n'
    else
        if output=$(OURO_PUBKEY_FILE="$root/test.pub" sh "$install_sh" --from "$signed" --dir "$locked" 2>&1); then
            bad "refuses an unwritable directory" "it installed into one"
        else
            case $output in
                *"never runs sudo"*) ok "refuses an unwritable directory and says it will not escalate" ;;
                *) bad "refuses an unwritable directory" "$output" ;;
            esac
        fi
    fi

    chmod 700 "$locked"

    # And a signature by a key the caller does not trust is fatal.
    minisign -G -W -p "$root/other.pub" -s "$root/other.key" >/dev/null 2>&1
    target="$root/bin10"
    if output=$(OURO_PUBKEY_FILE="$root/other.pub" sh "$install_sh" --from "$signed" --dir "$target" 2>&1); then
        bad "refuses a signature by an untrusted key" "it installed anyway"
    else
        case $output in
            *"not signed by the Ouroboros release key"*) ok "refuses a signature by an untrusted key" ;;
            *) bad "refuses a signature by an untrusted key" "$output" ;;
        esac
    fi
else
    printf '  SKIP  the minisign branch: minisign is not installed here, so the signature\n'
    printf '        path in install.sh is UNTESTED on this machine. Install it (brew install\n'
    printf '        minisign / apt install minisign) and re-run to cover it. Unsigned installs\n'
    printf '        are refused regardless.\n'
fi

# ---------------------------------------------------------------------------------
# 11. The committed dist/release.pub is read as unprovisioned, not as a key
# ---------------------------------------------------------------------------------

pubkey="$here/../dist/release.pub"
if [ -f "$pubkey" ]; then
    extracted=$(
        sed -e '/^[[:space:]]*#/d' \
            -e '/^[[:space:]]*untrusted comment:/d' \
            -e '/^[[:space:]]*$/d' \
            "$pubkey" | head -n 1
    )

    if [ -z "$extracted" ]; then
        ok "dist/release.pub is unprovisioned, and the extractor says so rather than guessing"
    else
        case $extracted in
            RW*) ok "dist/release.pub holds a minisign public key ($extracted)" ;;
            *)   bad "dist/release.pub holds something that is not a minisign key" "$extracted" ;;
        esac
    fi
else
    bad "dist/release.pub exists" "not found at $pubkey"
fi

printf '\n%s passed, %s failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
