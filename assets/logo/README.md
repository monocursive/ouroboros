# Ouroboros Ink Crown logo exports

These are deterministic exports of the approved editable Figma artwork. The source nodes and dimensions are recorded in `manifest.json`.

The macOS app icon uses the approved pale rounded tile (`12:30`) with the matching mark master for each output size. Release and development icon filenames intentionally contain identical artwork so both builds use the approved identity without an added development badge.

The macOS bundle pipeline consumes the four PNG masters in the parent `assets/` directory and assembles `Ouroboros.icns` in `scripts/bundle-macos-desktop.sh`.
