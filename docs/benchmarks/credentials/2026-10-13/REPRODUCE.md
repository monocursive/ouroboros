# Reproduce the credential follow-up

Verify `SHA256SUMS` and the preserved 12 October manifest before using the
results. Each host export has a manifest recording original and sanitized
hashes. The source archive and `validation/candidate-inputs.json` bind the
benchmark binaries to the complete build inputs.

Use a new private root on a configured Linux host, the frozen client versions,
Rust 1.98.1, and the unchanged systemd user session/host capabilities. Copy the
saved harness into `$bench_root/harness`. Preserve the original old Ouro binary
in `$before_binary`, and install the candidate in `$bench_root/bin/ouro-jail`.
Credentials and OAuth login caches must remain private and outside child grants.
Native executables declared by a vault policy must not be group/other writable.

```sh
python3 "$bench_root/harness/lifecycle_checks.py" --root "$bench_root"
python3 "$bench_root/harness/vault_mechanisms.py" --root "$bench_root" --samples 30
python3 "$bench_root/harness/startup_pairs.py" --root "$bench_root" \
  --before "$before_binary" --samples 30
python3 "$bench_root/harness/vault_agents.py" --root "$bench_root" \
  --out "$bench_root/results/vault-native" --key-file "$private_key_file" \
  --auth-file "$private_auth_file" --runs 2 --only-mode ouro --no-proxy-setup
python3 "$bench_root/harness/vault_agents.py" --workflow --root "$bench_root" \
  --out "$bench_root/results/vault-workflow" --key-file "$private_key_file" \
  --auth-file "$private_auth_file" --tasks inventory-workflow --runs 1 \
  --only-mode ouro --no-proxy-setup
python3 "$bench_root/harness/export_results.py" --root "$bench_root" \
  --key-file "$private_key_file" --auth-file "$private_auth_file" \
  --output "$bench_root/export.tar.gz"
```

The client harness waits for `private/codex-grant-ready` before scored Codex
calls. Create that non-secret readiness marker only after resolving the private
provider-source lifecycle. Do not replay a grant marked `refresh_pending`.
`provider_refresh.py` is an explicitly destructive-to-the-grant diagnostic:
it forces source expiry metadata and sends one real rotating refresh request.
Use fresh login authority, retain failures, and privately synchronize a rotated
grant back into the authorized login caches with a compare-and-swap. The
access-only diagnostic flag is not the scored configuration.

After extracting the sanitized host exports into `results/vps` and `results/pi`,
run the offline verifier without provider credentials:

```sh
python3 docs/benchmarks/credentials/2026-10-13/harness/analyze.py \
  docs/benchmarks/credentials/2026-10-13
```

The verifier checks schedule/client/fixture identity, receipt isolation and
observation parity, task success, bounded exposure sampling, journal export,
transport diagnostics and paired startup controls. Historical online timings
remain descriptive. Consult `METHODS.md` for exclusions and proof limits.
