# A signer key `ouro wasm keygen` actually wrote

`signer.key` was produced by running the real command, and `keygen.out` is exactly what it
printed:

    ouro wasm keygen --out /tmp/ouro-w12b-keygen/signer.key --id w12-keygen-fixture

It was run outside the repository on purpose. The path in the transcript is **absolute**,
because that is the whole of what the command now guarantees — `config/runtime.exs` refuses a
relative `OUROBOROS_SIGNER_KEY_PATH` and a `:signer` node started with one does not boot — and
a transcript generated *into* this directory would have embedded whoever's checkout produced
it. So the seed was copied here afterwards; `test/wasm/keygen_test.exs` reads it from this
directory and holds the transcript to its shape (absolute, ending in `signer.key`) rather than
to a path that means anything on another machine.

Neither file is configuration: nothing in this repository trusts `w12-keygen-fixture`, no node
reads either path, and the seed authorizes nothing anywhere. They exist so that one test can
hold the Rust side and the Elixir side to each other across a toolchain boundary they cannot
call across — `Ouroboros.Upgrade.Signing.Service.load_key!/1` must read this file, and the
public half it derives must be the one the CLI printed. A keygen that wrote a format the
service cannot read, or that printed a `trusted_signers` line for a different key, is a keygen
whose output verifies nothing, and no round trip inside either language would notice.

Regenerate it by running the command again at any absolute path and copying both files here.
