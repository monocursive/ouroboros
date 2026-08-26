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
resources="$contents/Resources"
icon_assets="$repo_root/assets"
if [[ "$profile" == debug ]]; then
  icon_prefix="ouroboros-icon-dev"
else
  icon_prefix="ouroboros-icon"
fi
icon_source="$icon_assets/$icon_prefix"

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

for size in 16 32 128 1024; do
  if [[ ! -f "$icon_source-$size.png" ]]; then
    echo "missing $icon_source-$size.png" >&2
    exit 1
  fi
done

mkdir -p "$macos" "$resources"
install -m 0755 "$target_dir/ouro" "$macos/ouro"
install -m 0755 "$target_dir/ouro-desktop" "$macos/ouro-desktop"
if [[ -x "$repo_root/priv/computer-use/ouro-computer-use" ]]; then
  install -m 0755 "$repo_root/priv/computer-use/ouro-computer-use" "$macos/ouro-computer-use"
elif [[ -x "$target_dir/ouro-computer-use" ]]; then
  install -m 0755 "$target_dir/ouro-computer-use" "$macos/ouro-computer-use"
fi
install -m 0644 "$repo_root/tui/macos/Info.plist" "$contents/Info.plist"

# Preserve the hand-tuned small masters where macOS asks for them, and derive only the
# intermediate sizes that do not have an optical master in the design source.
icon_workdir=$(mktemp -d "${TMPDIR:-/tmp}/ouroboros-icon.XXXXXX")
trap 'rm -rf "$icon_workdir"' EXIT
iconset="$icon_workdir/Ouroboros.iconset"
mkdir -p "$iconset"

install -m 0644 "$icon_source-16.png" "$iconset/icon_16x16.png"
install -m 0644 "$icon_source-32.png" "$iconset/icon_16x16@2x.png"
install -m 0644 "$icon_source-32.png" "$iconset/icon_32x32.png"
sips -z 64 64 "$icon_source-128.png" \
  --out "$iconset/icon_32x32@2x.png" >/dev/null
install -m 0644 "$icon_source-128.png" "$iconset/icon_128x128.png"
sips -z 256 256 "$icon_source-1024.png" \
  --out "$iconset/icon_128x128@2x.png" >/dev/null
install -m 0644 "$iconset/icon_128x128@2x.png" "$iconset/icon_256x256.png"
sips -z 512 512 "$icon_source-1024.png" \
  --out "$iconset/icon_256x256@2x.png" >/dev/null
install -m 0644 "$iconset/icon_256x256@2x.png" "$iconset/icon_512x512.png"
install -m 0644 "$icon_source-1024.png" "$iconset/icon_512x512@2x.png"
iconutil -c icns "$iconset" -o "$resources/Ouroboros.icns"

# A local ad-hoc signature gives macOS one coherent bundle identity. Distribution still
# needs a Developer ID signature and notarization; this script deliberately claims neither.
codesign --force --deep --sign - --timestamp=none "$app" >/dev/null
echo "$app"
