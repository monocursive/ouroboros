# A signer key `ouro wasm keygen` actually wrote

`signer.key` was produced by running the real command:

    ouro wasm keygen --out test/support/wasm_keygen/signer.key --id w12-keygen-fixture

and `keygen.out` is exactly what it printed. Neither file is configuration: nothing in this
repository trusts `w12-keygen-fixture`, no node reads this path, and the seed authorizes
nothing anywhere. It exists so that one test can hold the Rust side and the Elixir side to
each other across a toolchain boundary they cannot call across —
`Ouroboros.Upgrade.Signing.Service.load_key!/1` must read this file, and the public half it
derives must be the one the CLI printed above. A keygen that wrote a format the service
cannot read, or that printed a `trusted_signers` line for a different key, is a keygen whose
output verifies nothing, and no round trip inside either language would notice.

Regenerate it by deleting both files and running the command again; `test/wasm/keygen_test.exs`
reads them exactly as they are.
