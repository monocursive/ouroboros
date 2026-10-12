The complete startup evidence archive is committed as ordered parts to stay below GitHub's per-file limit. Every part and the reconstructed archive are bound by `2026-10-12-evidence.tar.gz.manifest.json`. The dated evidence directory and its existing SHA256SUMS are unchanged.

Reconstruct from this directory:

```sh
cat 2026-10-12-evidence.tar.gz.part00 2026-10-12-evidence.tar.gz.part01 2026-10-12-evidence.tar.gz.part02 > /tmp/2026-10-12-evidence.tar.gz
shasum -a 256 /tmp/2026-10-12-evidence.tar.gz
```

Expected SHA-256: `9cbe8bb69cd7d345b398be9f462d2a12ad2a24275e998bbdfe5274d6fdac6152`. The identical complete local archive is retained at `~/.local/share/ouro-benchmark-archives/2026-10-12-evidence.tar.gz`.
