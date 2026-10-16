# Benchmark and evidence records

Each directory holds one line of measurement: [jail](jail/README.md) (the
jail's own acceptance, performance and release evidence),
[sandboxes](sandboxes/README.md), the comparison corpora
([competitors](competitors/README.md), `competitors-after`,
`competitors-startup`, [credentials](credentials/2026-10-13-next/README.md),
[competitors-rerun](competitors-rerun/2026-10-16/README.md)) and the
[greywall scripts](greywall-2026-09-28/) of the 2026-09-28 record. The
[competitive analysis](competitive-analysis-2026-10-12.md) summarizes the
corpora through 2026-10-11.

These directories are most of the repository by weight. The rules below stop
that growth without rewriting history: thousands of evidence files name
commit SHAs, so every committed blob stays reachable.

## Evidence store rules

New evidence follows these rules. Existing corpora are not rewritten.

1. **A corpus is a dated directory**: the outermost directory here whose
   name starts with a date, such as `credentials/2026-10-13/` or
   `sandboxes/results/2026-10-01/`. Git keeps its narrative, analysis, a
   `SHA256SUMS` manifest of every file, and a `bundle.json`. The bulk (raw
   exports, logs, binaries) goes into one archive published as a release
   asset under an immutable `evidence/<corpus>` tag, never into git.
2. **`bundle.json`** names that archive:

   ```json
   {"url": "https://github.com/monocursive/ukai/releases/download/…",
    "sha256": "<archive SHA-256>", "bytes": 123, "files": 456,
    "root_manifest_sha256": "<SHA-256 of this corpus's SHA256SUMS>"}
   ```

   `files` counts the archive's files and `root_manifest_sha256` ties the
   archive to the manifest kept in git.
3. **Never commit a tree and an archive of it.** One copy, in git or in the
   bundle.
4. **One harness copy per hash.** Keep each distinct harness file once per
   corpus and record its `harness_sha256` in the run records. Do not copy the
   harness into every run directory.
5. **Repository-relative paths in machine-read fields.** JSON, CSV and other
   fields that tools read name files relative to the repository root (or to
   the corpus), never as absolute host paths such as `/Users/…` or
   `/home/ubuntu/…`. Logs and narrative may still quote the host paths they
   observed.
6. **Bytes are preserved.** [.gitattributes](../../.gitattributes) marks
   everything here `-text`, so no clone converts line endings and every
   `SHA256SUMS` stays valid.

`contracts` CI runs [check_evidence_store.py](check_evidence_store.py). It
fails on a tracked file over 5 MiB, or on a dated corpus without a
`bundle.json`, unless
[evidence-store-allowlist.toml](evidence-store-allowlist.toml) lists it. That
list holds what predates these rules and may only shrink.

## Retired archives

Archives that duplicated a tracked tree member for member were removed from
HEAD. Each left a `<archive>.retired.json` record where it was. The record
holds:

- the archive's size and SHA-256;
- the blob id of each part;
- the commit that added it;
- the tracked directory it duplicates;
- the member counts.

The commit that added a record removed the archive. Find it with
`git log --diff-filter=A -1 -- <record>`.

To recover an archive in a clone with full history, concatenate its parts in
order:

```sh
git cat-file blob <git_blob> > archive.tar.gz
```

`python3 docs/benchmarks/retired_archives.py verify` re-derives every record
from the archive blobs. It also checks that HEAD still holds every member. Corpus
`SHA256SUMS` files and the READMEs they bind are unchanged, so they still list
the retired archives' hashes. The link checker accepts a link to a retired
archive only when its record is in place.
