#!/bin/bash
set -euo pipefail
cd /home/monocursive/ouro-pi-41e6457b
ouro_binary=/home/monocursive/ouro-ledger-pruning-20261005-pi-r1/target/release/ouro-ledger
ouro_signed=docs/specs/ledger-v1/evidence/2026-10-06-bundle-signing/linux/signing-smoke
ouro_unsigned=docs/specs/ledger-v1/evidence/2026-10-06-portable-bundles/linux/portable-smoke
mkdir cross-platform
for ouro_profile in tool none; do
    "$ouro_binary" verify-bundle "$ouro_signed/$ouro_profile" --trusted-key "$ouro_signed/public-key.json" --json > "cross-platform/vps-$ouro_profile-pinned.json"
    cmp "cross-platform/vps-$ouro_profile-pinned.json" "$ouro_signed/$ouro_profile-verified.json"
    "$ouro_binary" verify-bundle "$ouro_signed/$ouro_profile" --json > "cross-platform/vps-$ouro_profile-untrusted.json"
    cmp "cross-platform/vps-$ouro_profile-untrusted.json" "$ouro_signed/$ouro_profile-untrusted.json"
    "$ouro_binary" verify-bundle "$ouro_unsigned/$ouro_profile" --json > "cross-platform/vps-$ouro_profile-unsigned.json"
    cmp "cross-platform/vps-$ouro_profile-unsigned.json" "$ouro_unsigned/$ouro_profile-verified.json"
done
printf 'Six VPS-to-Pi reports match: signed pinned/untrusted and unsigned tool/none bundles.\n'
