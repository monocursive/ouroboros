#!/usr/bin/env bash
# Called only after CI and all native package smokes pass.
set -euo pipefail
: "${TAG:?release tag required}" "${GH_REPO:?repository required}" "${PRERELEASE:?required}"
assets=_build/release-assets
python3 scripts/release.py check "$TAG" > /dev/null

# Read all published stable versions so a backport cannot displace a newer latest.
# A failed API request aborts publication; it is not interpreted as an empty history.
gh api --paginate "repos/$GH_REPO/releases?per_page=100" > _build/releases.json
latest=$(python3 scripts/release.py latest "$TAG" --history _build/releases.json)

# A previous failed upload can leave a draft. Resume only drafts; never mutate a
# published release (also works when GitHub immutable releases are enabled).
existing=$(python3 scripts/release.py status "$TAG" --history _build/releases.json)
if [ "$existing" = published ]; then
    echo "Release $TAG is already published; use a new version." >&2
    exit 1
fi
if [ "$existing" != draft ]; then
    cat > _build/release-notes.md <<EOF
Native binaries with the Ouroboros runtime and WebAssembly helper embedded.

Install this exact version:
\`\`\`sh
curl -fsSL https://github.com/$GH_REPO/releases/download/$TAG/install.sh | bash -s -- --version $TAG
\`\`\`

Linux builds target Ubuntu 24.04 / glibc 2.39 or newer; macOS builds use macOS 15 runners.
For future stable upgrades, run \`ouro update --check\` and \`ouro update\`. Finish active work, then run \`ouro stop\` and \`ouro\` to activate the installed runtime. Older binaries without \`update\` need one installer rerun first.
See the [installation and release guide](https://github.com/$GH_REPO/blob/$TAG/docs/RELEASING.md) for prerequisites, checksums, upgrades and older versions.

Source commit: $GITHUB_SHA. Each target passed packaged startup, helper, web authentication refusal and shutdown checks. These checks do not establish every model/provider journey or OS version.
EOF
    gh release create "$TAG" --verify-tag --draft --prerelease="$PRERELEASE" \
        --latest=false --title "Ouroboros $TAG" --generate-notes --notes-file _build/release-notes.md
fi
gh release upload "$TAG" "$assets"/* --clobber
# Refuse unexpected leftovers on a pre-existing draft.
gh release view "$TAG" --json assets --jq '.assets[].name' | LC_ALL=C sort > _build/uploaded-assets
(cd "$assets" && printf '%s\n' *) | LC_ALL=C sort > _build/expected-assets
diff -u _build/expected-assets _build/uploaded-assets
gh release edit "$TAG" --draft=false --prerelease="$PRERELEASE" --latest="$latest"
