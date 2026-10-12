# Reproduce the credential follow-up

The report supplements the startup evidence at commit `cf98e6a1` and uses
its saved, unchanged Linux binaries and baseline result files. Restore the
startup archive from its verified parts if needed; see
[startup archive reconstruction](../../competitors-startup/ARCHIVE.md).

Verify this dated directory's `SHA256SUMS`, then recompute the analysis from
the repository root:

```sh
python3 docs/benchmarks/credentials/2026-10-12/harness/analyze.py \
  docs/benchmarks/credentials/2026-10-12
```

The raw sanitized host archives have export manifests binding every retained
file, its original/sanitized hashes, and redaction flags. Do not copy private
host auth/state trees into public evidence. Pattern and exact credential audits
must precede packaging.

To rerun on a Linux host, use a new private root and fresh output directories.
Install the saved harness files and unchanged binaries, linking directly to
their installed objects; preserve the same client/library grants. Set the
systemd session variables as recorded in the original host run scripts.
The key file and authorized Codex auth cache remain private source inputs.

```sh
python3 "$bench_root/harness/vault_mechanisms.py" --root "$bench_root" --samples 30
python3 "$bench_root/harness/vault_agents.py" --root "$bench_root" \
  --out "$bench_root/results/vault-native" --key-file "$private_key_file" \
  --auth-file "$private_auth_file" --runs 2 --only-mode ouro --no-proxy-setup
python3 "$bench_root/harness/vault_agents.py" --workflow --root "$bench_root" \
  --out "$bench_root/results/vault-workflow" --key-file "$private_key_file" \
  --auth-file "$private_auth_file" --tasks inventory-workflow --runs 1 \
  --only-mode ouro --no-proxy-setup
python3 "$bench_root/harness/vault_lifecycle.py" --root "$bench_root"
python3 "$bench_root/harness/verify_profiles.py" --root "$bench_root"
python3 "$bench_root/harness/export_results.py" --root "$bench_root" \
  --key-file "$private_key_file" --auth-file "$private_auth_file" \
  --output "$bench_root/export.tar.gz"
```

Copy the two starter TOML files beside `verify_profiles.py` before running
the starter check. The source token files must be regular, privately owned,
single-link files outside every child grant, with no trailing newline. The
Codex cache needs a currently valid access token; Ouro does not refresh it.
Keep failed expired-token runs as failures, rather than silently substituting
a fresh token within a scored cohort. A later provider/cache recovery is a
separate, explicitly labeled experiment.

No lasting proxy/gateway service is required for this follow-up. Each Ouro
attempt starts its own contained bridge and outside credential proxy and
cleans up after empty-tree settlement. Existing earlier benchmark services
remain stopped.
