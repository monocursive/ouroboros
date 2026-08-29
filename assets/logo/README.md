# Ouroboros Ink Crown logo exports

These are deterministic exports of the approved editable Figma artwork. The source nodes and dimensions are recorded in `manifest.json`.

The macOS app icon uses the approved pale rounded tile (`12:30`) with the matching mark master for each output size. Release and development icon filenames intentionally contain identical artwork so both builds use the approved identity without an added development badge.

> **No bundle pipeline consumes these today.** `scripts/bundle-macos-desktop.sh` assembled `Ouroboros.icns` from the four PNG masters in the parent `assets/` directory for the GPUI desktop client's `.app`; that client and its bundle script were removed in W9 (see [`docs/DESKTOP.md`](../../docs/DESKTOP.md)). The masters are kept as the approved identity for whatever packages the product next.
