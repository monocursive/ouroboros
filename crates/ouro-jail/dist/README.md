# Local release tooling

Publication coordinates and the production signing identity are not configured.
These tools package an existing binary and verify installation locally; they do
not claim a published release or build the four target binaries.

Build with explicit provenance, then package with an operator-selected key:

```sh
OURO_BUILD_REVISION=$(git rev-parse HEAD) OURO_BUILD_DIRTY=true \
  cargo +1.98.1 build --release -p ouro-jail
python3 crates/ouro-jail/dist/package.py \
  --binary target/release/ouro-jail --target aarch64-apple-darwin \
  --out /path/to/artifacts --signing-key /path/to/signing.key
```

Use the actual target triple of the supplied binary. Set `OURO_BUILD_DIRTY=false`
only for a clean checkout. A later invocation against the same artifact directory
signs a manifest covering every staged target archive.

Installation requires `minisign`, `tar`, `shasum`, and `curl` for HTTPS downloads.
It installs no backend or system packages. Obtain the public key through a trusted
channel; downloading a key beside an archive does not authenticate that archive.

```sh
sh crates/ouro-jail/dist/install.sh \
  --from-dir /path/to/artifacts --public-key 'TRUSTED_MINISIGN_PUBLIC_KEY' \
  --prefix /path/to/bin
```

Use `--base-url https://...` instead of `--from-dir` for published artifacts.
Use `--upgrade` to replace an existing installation without a TTY. Failure to
verify the signed manifest or archive checksum preserves the installed binary.
The distribution includes the project license and the CA-data license notice.

The [2026-09-30 fresh-VM onboarding report](../../../docs/benchmarks/jail/onboarding-2026-09-30.md)
records signed non-TTY installation, contained `true`, a real OpenCode run and
corruption/upgrade checks on a clean Ubuntu 26.04 VM without Rust. The tested
reference-built GNU artifact refuses on Ubuntu 22.04 (glibc mismatch), and
stock Ubuntu 24.04's bubblewrap namespace setup fails under its default policy;
the report retains those limits. Public releases and production signing remain
operator choices.

Run the installer regression with an ephemeral test key:

```sh
python3 crates/ouro-jail/dist/test_install.py target/release/ouro-jail
```
