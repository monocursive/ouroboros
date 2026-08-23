#!/bin/sh
# Structural checks on .github/workflows/release.yml.
#
# This is not a substitute for running the workflow — no tag has ever run it, and this
# script cannot tell you whether `minisign` installs on a hosted runner or whether
# `gh release create` accepts the arguments it is given. What it *can* tell you is that
# the file parses as YAML, that every name it refers to exists, that the signing steps
# are wired the way the documentation claims, and that the fail-closed refusals are
# actually in the file. Those are the mistakes that would otherwise be found by pushing a
# tag, which is the one experiment that cannot be repeated.
#
# Run: sh scripts/check-release-workflow.sh

set -eu

here=$(cd "$(dirname "$0")" && pwd)
workflow="$here/../.github/workflows/release.yml"

[ -f "$workflow" ] || { echo "no workflow at $workflow" >&2; exit 1; }

if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1; then
    exec python3 "$here/check-release-workflow.py" "$workflow"
fi

if command -v ruby >/dev/null 2>&1; then
    echo "python3 with PyYAML is not available; falling back to a parse-only check." >&2
    echo "The structural checks were NOT run. Install PyYAML (pip install pyyaml) to run them." >&2
    ruby -ryaml -e 'YAML.unsafe_load_file(ARGV[0]); puts "release.yml parses as YAML (parse-only)"' "$workflow"
    exit 0
fi

echo "no YAML parser available (python3 + PyYAML, or ruby). Cannot check release.yml." >&2
exit 1
