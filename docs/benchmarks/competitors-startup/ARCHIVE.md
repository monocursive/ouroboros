The complete startup evidence archive was committed as three ordered parts (`2026-10-12-evidence.tar.gz.part00`–`part02`) to stay below GitHub's per-file limit. Every part and the reconstructed archive are bound by `2026-10-12-evidence.tar.gz.manifest.json`. The dated evidence directory and its existing SHA256SUMS are unchanged.

The parts are retired from HEAD: every one of the archive's 23,758 members is byte-identical (SHA-256 and git blob) to the tracked file at the same path under `2026-10-12/`, as recorded in [2026-10-12-evidence.tar.gz.retired.json](2026-10-12-evidence.tar.gz.retired.json). The commit that added that record removed the parts; their blobs stay in git history and the record names each part's blob id. Re-check the proof with `python3 docs/benchmarks/retired_archives.py verify` in a clone with full history.

Reconstruct from the repository root:

```sh
for part in 56346954d442115d724180793a3ce704a737a8ca 6d123679c51493c0c7868b5527f1ccf767631060 8a221111cb750fcab1e664577c34978109f96c67; do
  git cat-file blob "$part"
done > /tmp/2026-10-12-evidence.tar.gz
shasum -a 256 /tmp/2026-10-12-evidence.tar.gz
```

Expected SHA-256: `9cbe8bb69cd7d345b398be9f462d2a12ad2a24275e998bbdfe5274d6fdac6152`. The identical complete local archive is retained at `~/.local/share/ouro-benchmark-archives/2026-10-12-evidence.tar.gz` on the machine that produced it.
