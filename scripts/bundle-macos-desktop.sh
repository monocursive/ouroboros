#!/usr/bin/env bash
set -euo pipefail

profile=${1:-debug}
case "$profile" in
  debug|release) ;;
  *)
    echo "usage: $0 [debug|release]" >&2
    exit 2
    ;;
esac

repo_root=$(cd "$(dirname "$0")/.." && pwd)
target_dir="$repo_root/tui/target/$profile"
app="$target_dir/Ouroboros.app"
contents="$app/Contents"
macos="$contents/MacOS"

if [[ $(uname -s) != Darwin ]]; then
  echo "Ouroboros.app can only be assembled on macOS" >&2
  exit 1
fi

for executable in ouro ouro-desktop; do
  if [[ ! -x "$target_dir/$executable" ]]; then
    echo "missing $target_dir/$executable; build both binaries first" >&2
    exit 1
  fi
done

mkdir -p "$macos" "$contents/Resources"
install -m 0755 "$target_dir/ouro" "$macos/ouro"
install -m 0755 "$target_dir/ouro-desktop" "$macos/ouro-desktop"
install -m 0644 "$repo_root/tui/macos/Info.plist" "$contents/Info.plist"

# A local ad-hoc signature gives macOS one coherent bundle identity. Distribution still
# needs a Developer ID signature and notarization; this script deliberately claims neither.
codesign --force --deep --sign - --timestamp=none "$app" >/dev/null
echo "$app"
