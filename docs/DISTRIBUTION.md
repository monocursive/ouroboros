# Distribution

How an Ouroboros release is built, signed, published, installed, and updated — and,
because the difference matters more than the mechanism, what each check in that chain
actually defends against.

**Status.** The public repository is `monocursive/ouroboros` on GitHub. The installer
and updater default to its release assets; fleet deployment selects the exact running
version's tag. A release signing key is still unprovisioned in `dist/release.pub`, and
no signed release has been published. Provision the key and the Actions secret below,
then publish a tested tag before advertising download-based installation. Unprovisioned
builds refuse unsigned artifacts; a repository URL does not establish a trust root.

---

## 1. The three checks, and what each is worth

The chain has three links. They are named separately everywhere — in the code, in the
command output, in the installer's warnings — because conflating them is how a project
ends up claiming security it does not have.

| Check | Defends against | Where it runs |
|---|---|---|
| **Ed25519 signature over `SHA256SUMS`** (minisign) | A compromised release host, a hijacked mirror, a stolen publishing token, a malicious proxy — anyone who can hand you different bytes than the project published. The signing key is offline; the public half is compiled into `ouro` and committed here. | `ouro update` always; `scripts/install.sh` always (refuses without a verified signature); the release workflow, against its own output |
| **SHA-256 of the asset against that signed manifest** | A truncated or corrupted download — *and*, because the manifest was signed first, a substituted binary. | `ouro update` always; `scripts/install.sh` always |
| **TLS on the download** | Eavesdropping and a wrong host answering. Says nothing about who *built* the bytes. | Whenever the URL is `https://` |

The second check **on its own is worth almost nothing**: a checksum file fetched from the
same place as the binary is a checksum an attacker who can replace the binary can also
replace. It is a corruption check. It becomes a security check only because the file it
lives in carries a signature made by a key that never touched the release host.

`ouro update` therefore never runs check 2 without check 1, and a build with no public
key refuses every path — including `--check`, because a version number this process
cannot authenticate is not a fact it should report as one. `scripts/install.sh` now
makes the same promise: without a verified minisign signature it names which
prerequisite is missing (no `.minisig`, no key in `dist/release.pub`, or no `minisign`)
and refuses. A checksum from the same place as the binary is not treated as a signature.

---

## 2. Key management

### Generating the pair

```sh
minisign -G -W -p dist/release.pub -s ouro-release.key
```

`-W` writes the secret key with no password, which is what a non-interactive CI signer
needs; the secret's protection is the CI secret store, not a passphrase in a repository.

Then:

1. **Commit `dist/release.pub`.** It is two lines: minisign's comment (carrying the key
   id, so two keys can be told apart by eye) and one base64 line holding 42 bytes —
   `"Ed"`, 8 bytes of key id, 32 bytes of Ed25519 public key. `tui/src/update.rs` reads
   it with `include_str!`, so the file a reader sees in the tree is provably the file in
   the binary, and editing it rebuilds the crate.
2. **Store the contents of `ouro-release.key`** in the GitHub Actions repository secret
   `OURO_RELEASE_SIGNING_KEY`. That name is the only secret the release workflow is
   allowed to read, and `scripts/check-release-workflow.sh` fails if another appears.
3. **Keep an offline copy** somewhere a laptop failure cannot reach, then delete the
   working copy. There is no key rotation story yet — see §8.

The committed file today is the unprovisioned placeholder: annotation lines beginning
with `#` and no key. Every reader (the Rust `PublicKey::parse`, `install.sh`, the release
workflow) skips `#` lines and minisign's `untrusted comment:` header, takes the first
remaining line as the key, and treats *no such line* as "there is no key" rather than as
an error to route around.

### Deploying a locally built cross-platform artifact

`fleet add` verifies every supplied or discovered artifact before issuing an invitation.
Keep the standard filename `ouro-VERSION-TRIPLE`, `SHA256SUMS`, and
`SHA256SUMS.minisig` together. Sign the manifest with the key whose public half was
compiled into the owner binary:

```sh
# Run in a staging directory containing only the release artifacts.
shasum -a 256 ouro-* > SHA256SUMS
minisign -S -s /secure/path/ouro-release.key -m SHA256SUMS
ouro fleet add user@host --binary /absolute/staging/ouro-VERSION-TRIPLE
```

A checksum without a valid signature is refused. The owner copies a private verified
snapshot, so replacing the original file during deployment cannot replace the bytes
being sent. With no local matching artifact, a provisioned build fetches and verifies
its exact version from the configured release host. An unavailable or invalid release
fails before any new machine credential is issued. An unprovisioned source build can
still copy its own running executable to the same platform, or prepare an explicit
manual enrollment recipe; it cannot trust an arbitrary cross-platform binary.

### Building with a different key

A fork can bake its own without editing a tracked file:

```sh
OURO_RELEASE_PUBKEY="RWQf6LRC…" cargo build --release
OURO_RELEASE_BASE_URL="https://example/releases/latest/download" cargo build --release
```

Both are **build-time** inputs. Nothing an already-built binary reads from its
environment can move the trust root, because a trust root the caller can set is not one.

---

## 3. Cutting a release

1. **Bump the version** in `mix.exs`. The tag must match it — the workflow's first real
   step compares `$GITHUB_REF_NAME` against `Mix.Project.config()[:version]` and fails
   otherwise. `tui/Cargo.toml`'s version is what `ouro update` compares against, so it
   moves with it.
2. **Tag and push:** `git tag v0.2.0 && git push origin v0.2.0`.
3. The `build` job runs on four real machines — `macos-15`, `macos-15-intel`,
   `ubuntu-24.04`, `ubuntu-24.04-arm`. This is a matrix of hardware rather than a
   cross-compile matrix because `mix release` bakes the ERTS of the machine that ran it
   and `ouro` carries that release inside itself: a binary is only ever valid for the OS
   and architecture that built it. Each runner runs `make test`, then `make dist`, and
   the Linux x86-64 runner additionally gates on `scripts/fleet-e2e.sh`.
4. The `publish` job checks out the tree (for `dist/release.pub`), collects the four
   artifacts, writes `SHA256SUMS`, installs `minisign` from Ubuntu's archive, signs, and
   **verifies its own signature against the committed public key** before creating the
   release. That last step is what catches a secret that does not belong to the committed
   key — otherwise the first person to find out is whoever downloads it.
5. It publishes exactly: the four `ouro-<version>-<triple>` binaries, `SHA256SUMS`, and
   `SHA256SUMS.minisig`. It does **not** publish `dist/release.pub`. A public key
   downloaded from the same host as the signature it checks proves nothing; the key of
   record is the one in this repository and in the binary you already trust.

The job refuses to publish if `OURO_RELEASE_SIGNING_KEY` is unset, or if
`dist/release.pub` is still the placeholder. An unsigned release published as though it
were signed is worse than no release, because everything downstream is written assuming
the signature exists.

### Regenerating the Homebrew formula

```sh
OURO_BASE_URL=https://…/releases/download/v0.2.0 \
  scripts/homebrew-formula.sh 0.2.0 SHA256SUMS > ouro.rb
```

Digests are read out of the manifest, never typed.

---

## 4. `ouro update`

```
ouro update [--check] [--from URL] [--allow-downgrade]
```

The sequence:

1. Refuse immediately if this build carries no release public key.
2. Fetch `SHA256SUMS` (cap 1 MiB) and `SHA256SUMS.minisig` (cap 16 KiB).
3. Verify the signature. Three things are checked and all three matter: that the
   signature names *this* key (a valid signature by another key is a refusal, not a
   pass); the Ed25519 signature over the manifest — or over its BLAKE2b-512 hash, for the
   prehashed form current `minisign` writes by default, both of which are accepted; and
   the *global* signature over `signature || trusted comment`, without which the trusted
   comment would be attacker-chosen text this command then printed as though the project
   had written it.
4. Read the release's version out of the asset names in the now-verified manifest. A
   manifest naming two versions is refused rather than resolved.
5. `--check` stops here: exit **10** if the release is newer, **0** otherwise.
6. Refuse a downgrade without `--allow-downgrade`; a rollback is a thing to mean.
7. Refuse if the installed binary is owned by Homebrew or Nix (naming the right upgrade
   command), or if its directory is not writable — this command never asks for root, and
   says where to install instead.
8. Download the asset (cap 512 MiB, 15 minutes) **directly into a staging file beside the
   target**, so the verified bytes never cross a filesystem boundary afterwards.
9. Check its SHA-256 against the signed entry, and that it starts with this platform's
   executable magic — the latter is not security, it turns "a proxy served an HTML error
   page with a 200" into a clear refusal instead of an unrunnable binary on `PATH`.
10. `fsync`, `chmod` to the target's existing mode, `rename(2)` over it, `fsync` the
    directory.

**Why rename, and not write.** A running executable cannot be written into on Linux
(`ETXTBSY`) and must not be on macOS, where pages may still be faulted in. Its *directory
entry* can be replaced at any time: `rename(2)` is atomic within a filesystem, the
running image keeps the inode it was started from, and the next `exec` finds the new one.
No window exists in which the destination name refers to a partially written file, and a
failure at any earlier point leaves the installed binary untouched.

**Symlinks** are resolved (`canonicalize`) and the real file is replaced, so a
`~/.local/bin/ouro` pointing into a read-only prefix is a clear refusal rather than a
half-performed swap of the link.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Updated, already current, or `--check` found nothing newer |
| 10 | `--check`: a newer release exists |
| 11 | This build carries no release public key |
| 12 | Verification failed: signature, digest, or the shape of a signed file |
| 13 | Refused as a downgrade |
| 14 | The installed binary is not this command's to replace |
| 15 | Nothing could be fetched: no source configured, or the transport failed |
| 16 | The release has no asset for this platform |

`ouro version` is unchanged and still prints the client version, the embedded release,
and the protocol. Track J1 lists `ouro version --check`; that check lives on `ouro update
--check` instead, because it is the same work — fetch the manifest, verify it, compare —
and two commands that do it would be two places for the answer to differ.

### There is no `--channel`

The scorecard research (`docs/research/agent-ux-2026/R5-landscape-and-scorecard.md`,
row 22) puts `stable`/`latest` channels at level 3, and Claude Code's own channel
plumbing is scrutinised precisely because it once served the wrong version on `latest`.
This project publishes **one** tag stream, published as one GitHub Release each, with no
second track that skips regressions. A `--channel` flag would therefore be a scheme
invented at the CLI rather than one followed. Adding it honestly means first: two tag
streams (or a `stable` marker moved deliberately after a soak period), a per-channel
`SHA256SUMS`, and a documented promotion rule. Until then the flag would be a lie with a
default value.

### Why `curl`, and not an HTTP crate

This client has no HTTP stack — the gateway transport is raw TCP. Adding one
(`reqwest`/`ureq` + `rustls` + a root store) to fetch four files occasionally is a large
new dependency tree carrying the *transport* half of the problem, which per §1 is not the
half that makes an update safe. So the transport is `curl`, then `wget`: present on every
target platform, already correct about `http_proxy`/`https_proxy`/`no_proxy`, and easy to
bound (`--max-time`, `--max-filesize`, `--proto` so a redirect cannot walk down to another
scheme). The part that cannot be delegated — the signature — is verified in-process by
`ring`, which this crate already depends on for the fleet's TLS identities. If neither
tool is installed, the command says so and tells you to download by hand and pass
`--from <directory>`.

---

## 5. `scripts/install.sh`

POSIX `sh`. Detects the triple from `uname`, reads a release from `https://`, `http://`,
`file:///`, or a plain directory path, verifies the minisign signature, then checks
SHA-256, installs to `~/.local/bin` (`OURO_INSTALL_DIR` or `--dir`), never runs `sudo`,
stages beside the target and renames over it, and prints the `PATH` line when the
directory is not on `PATH`. `--dry-run` prints the plan, including that the signature
was verified. `OURO_VERSION` pins a version; without it the version comes from the
manifest's own asset names.

When it cannot verify a signature it prints which of the three prerequisites is missing
(no `.minisig` published, no key in `dist/release.pub`, or no `minisign` installed) and
refuses. Nothing is installed.

`scripts/test-install.sh` drives it against a release directory it builds in a temp
directory — no network, no server, nothing under `$HOME` — covering unsigned refusal,
the checksum refusal on a signed-but-corrupt asset, a signed release with no asset for
this platform, signed `--dry-run`, an explicit `--version`, an unwritable directory,
`file://host` rejection, and that the word `sudo` appears only in the sentences
promising not to use it.

---

## 6. Homebrew

`dist/homebrew/ouro.rb` is a template; `scripts/homebrew-formula.sh <version>
[SHA256SUMS]` fills in the four digests and the URL and prints the finished formula.

The tap flow, which this project deliberately does not perform:

1. Create a separate repository named `homebrew-ouroboros` under the same owner. Homebrew
   requires the `homebrew-` prefix; `brew tap <owner>/ouroboros` finds it by convention.
2. Put the generated formula at `Formula/ouro.rb` in that repository and commit it.
3. Users then run `brew tap <owner>/ouroboros && brew install ouro`.
4. On each release, regenerate and commit. There is no automation here on purpose:
   pushing to a second repository from a release workflow needs a cross-repository token,
   which is a standing credential with write access to a distribution channel.

**What Homebrew's check is worth.** It verifies the `sha256` in the formula against what
it downloads. That is a real check, because the digest lives in the tap and the binary
lives on the release host — an attacker needs both. It is *not* the release-signature
check; Homebrew has no notion of one. A formula is as trustworthy as its tap's commit
history, which is a weaker statement than "the Ouroboros release key signed this".

`ouro update` refuses to replace a Homebrew- or Nix-installed binary and names the right
upgrade command, because replacing a file a package manager owns leaves its manifest
disagreeing with the disk and the next `upgrade` silently reverts yours.

---

## 7. What is tested, and what is not

**Tested** (`cargo test` in `tui/`, and `make dist-check` for the two shell suites):

- 27 unit tests in `tui/src/update.rs`: SemVer ordering including pre-releases, triple
  detection for platforms this run is not on, the `sha256sum` parser (both spellings,
  duplicate names, two digests for one name, names that are really paths), BLAKE2b-512
  against the published RFC 7693 vectors, minisign verification in both algorithm modes,
  tampering, a signature by another key, a forged trusted comment, malformed signature
  files, the atomic replace and its mode preservation, and the no-key refusal.
- 17 integration tests in `tui/tests/update.rs`: `--check` both ways, a real
  download-verify-rename against a signed fixture release, and six refusal paths each
  asserting the installed binary is byte-identical afterwards and no staged file survived.
  The signing side is re-implemented there from the format rather than shared with the
  verifier, so a mistake in one does not cancel out in the other.
- 18 shell assertions for `install.sh`, and 54 structural checks on `release.yml`. Both
  run under `make dist-check`, which is deliberately not part of `make test`: the
  workflow check needs a YAML parser (python3 with PyYAML, or ruby), and a release whose
  four native runners fail because one of them lacks PyYAML is worse than a check
  somebody has to type.

**Not tested, and it needs CI or network to be:**

- **The release workflow has never run.** No tag has executed it; the remote is not
  GitHub. Unproven in particular: that `minisign` installs from Ubuntu's archive on a
  hosted runner, that `actions/download-artifact` into `dist` composes with a prior
  checkout the way this assumes, that `gh release create` accepts the argument list, and
  that the four runner labels still exist. `scripts/check-release-workflow.sh` checks
  that every name in the file resolves and that the signing pipeline is ordered and
  fail-closed; it prints `UNPROVEN` on success so nobody mistakes it for a runner.
- **The `curl`/`wget` transport in `ouro update` and `install.sh`.** Every test uses the
  local-directory branch, on purpose, so the suite is network-free. The HTTP branch is
  built and reviewed but has never fetched anything.
- **Interoperability with the reference `minisign`.** `minisign` is not installed on the
  machine this was written on. The Rust verifier and this repository's test signer are
  independent implementations, so a bug in one shows up — but a *shared misreading of
  minisign's byte layout* would not. Two things are in place for whoever has the tool:
  `tui/tests/update.rs::a_real_minisign_signature_verifies` generates a key with
  `minisign -G -W`, signs with `minisign -S`, and verifies with this crate (it prints a
  `SKIPPED` line naming this gap where minisign is absent), and `scripts/test-install.sh`
  covers `install.sh`'s `minisign -V` branch the same way. The release workflow's own
  `minisign -V` step would also catch it on the first tag. Install `minisign` and re-run
  both to close this.
- **A fresh-machine install per triple**, which is J1's acceptance criterion and needs
  four VMs.

---

## 8. `make dist-linux` — a Linux client from a Mac

```
make dist-linux         → dist/ouro-<version>-x86_64-unknown-linux-gnu
make dist-linux-clean   → drops the image and the three cache volumes
```

### What it is

The development path for one specific problem: `ouro fleet add` wants to copy an `ouro`
onto a Linux x86-64 machine, and the developer is sitting at an Apple Silicon Mac, where
`make dist` can only ever produce `aarch64-apple-darwin`. `make dist-linux` runs the
repository's own `make dist` inside an emulated x86-64 Linux container and copies the one
artifact out.

It is deliberately not a second recipe. `dist/docker/build.sh` stages the source and then
calls `make dist` — the same target a laptop runs, for the same reason the release workflow
does: a command only CI (or only a container) knows is a command nobody can reproduce when
it breaks.

### What it is not

**Not the release path.** The artifact of record is the one a tagged build uploads from a
real `ubuntu-24.04` runner (§3). Nothing here is signed, nothing here appears in
`SHA256SUMS`, and `ouro update` will never fetch it. A binary from this target is
hand-carried and hand-trusted; if you want the signature chain of §1, use a release.

**Not a cross-compile.** ERTS is not cross-compiled — `mix release` bakes the runtime
system of the machine that ran it — so this emulates an x86-64 machine rather than
targeting one from arm64. Everything downstream of that, including the `c_src` NIF and
`cargo build --features embed`, is a native build inside that emulated machine.

### Pinning, and why it is exact

`dist/docker/Dockerfile.linux-x86_64` pins
`hexpm/elixir:1.20.2-erlang-29.0.5-ubuntu-noble-20260730.1` and rustup 1.95 by exact tag,
because the fleet does not treat a runtime as interchangeable:

- **Placement** compares `{fleet_protocol_revision, ouroboros_version, otp_release}`
  (`lib/ouroboros/cluster.ex`). A node built on OTP 28 is a node the fleet refuses to
  place work on, however well the binary runs.
- **The forge verifier** additionally compares `elixir_version` and `system_architecture`
  (`lib/ouroboros/upgrade/verifier.ex`) and refuses an artifact whose triple does not
  match, which is why one image builds one triple and says so out loud.

So the image tracks `.github/workflows/ci.yml`'s `ELIXIR_VERSION: "1.20"`,
`OTP_VERSION: "29"`, `RUST_VERSION: "1.95"` and `release.yml`'s `ubuntu-24.04` runner.
When those move, this moves with them; a floating tag would let them drift apart silently.

Ubuntu 24.04 (glibc 2.39) is also the ABI floor. glibc symbol versioning is
forward-compatible, so a binary linked against 2.39 runs on a newer target — Ubuntu 26.04's
glibc 2.43, for instance — while the reverse does not hold. Same trade-off §9's "Linux ABI"
note describes for the release artifacts, because it is the same distribution.

One entry in the image's package list looks like padding and is not. Without `libsctp1`,
OTP's socket NIF cannot open `libsctp.so.1` and prints an `=ESOCK WARNING MSG=` block on
**stdout** — a `-noshell` node's group leader is stdout, not stderr. `deps/erlexec`'s
`c_src/Makefile` captures `erl -noshell -eval '…system_architecture…'` into a make variable
and then uses it as a target name, so the warning lands inside a target and the build dies
with `Makefile:133: *** multiple target patterns`, an error that mentions neither SCTP nor
Erlang. Installing the library is the fix; silencing the logger would only move it.

### The build context, and why the checkout is read-only

A working tree carries multi-gigabyte `_build/`, `deps/`, and `tui/target/` directories.
`docker build` would tar all of them up as context before reading the first Dockerfile
line, so the context is `dist/docker/` — a few kilobytes — and the checkout reaches the
build as a **read-only bind mount** instead. Inside, `rsync` copies the source (with those
directories excluded, and `.git/` and `.claude/` with them) into a named volume the
container owns.

That read-only mount is not caution for its own sake. The container's `_build/` and
`tui/target/` hold x86-64 objects and the developer's hold arm64 ones; a shared directory
would corrupt both. The only thing written back into the checkout is `dist/`.

Three named volumes carry the caches between runs:
`ouro-dist-linux-x86_64-work` (source, `deps/`, `_build/`, `tui/target/`),
`ouro-dist-linux-x86_64-cargo` (the crates.io registry), and
`ouro-dist-linux-x86_64-home` (hex packages). `make dist-linux-clean` removes all three.

### The emulation caveat

Emulation is cheaper than it sounds and less transparent than it looks, and the second
half is the one that matters.

Measured on an Apple M5 Pro (18 cores to the Docker VM), under OrbStack's Rosetta: a run
with all three volumes deleted — 40 hex packages fetched, 231 crates downloaded, 188 of
them compiled, plus `mix release` and the whole `ouro` binary — takes **2m 34s**, and a
run that only has to notice the source changed takes **48s**. Building the image itself
from scratch (apt, then rustup) adds about a minute the first time. Expect worse on fewer
cores or a colder network; the point is that this is a target you can afford to type, not
an overnight job.

The lack of transparency is the real cost, and one instance is load-bearing enough to
name.
**Apple's Rosetta cannot run OTP ≥ 28 as shipped.** The BEAM's JIT writes machine code
through one mapping and executes it through another; Rosetta does not invalidate its
translation cache for the second one, so `prim_tty`'s NIFs never take effect and the node
dies in `user_drv` before `mix` gets a turn. `scripts/dist-linux.sh` therefore runs the
in-container BEAM with `ERL_FLAGS='+JMsingle true'`, which asks the JIT for a single
read-write-execute mapping that Rosetta does follow. It is an ordinary supported emulator
flag, it applies only to the VM that *runs* the build, and it does not touch the ERTS
inside the artifact. Override it with `OURO_DIST_LINUX_ERL_FLAGS` if some other emulator
needs something else. Switching emulators is not the obvious escape it looks like: the
`qemu-x86_64` that ships with Ubuntu 24.04 (8.2.2) dies on the same BEAM with
`QEMU internal SIGSEGV` before it reaches the JIT at all.

A preflight runs `erl -noshell -eval 'halt(0).'` in the image before the build starts, so
an emulator that cannot boot OTP 29 fails in seconds with that explanation, rather than
part-way through `mix deps.get` inside an unreadable crash dump.

### What it found on its first run

The first thing this target did was fail, and the failure was in the repository rather
than in the container. `tui/Cargo.toml` declared `flate2`, `tar`, and `sha2` — the entire
`embed` feature — inside the `[target.'cfg(target_os = "macos")'.dependencies]` table,
separated from it only by a blank line, which TOML does not treat as a boundary. So
`cargo build --release --features embed` could never have produced a Linux binary: it
compiled `src/runtime/embed.rs` against three crates that were not in the graph. `make
dist` on the release workflow's `ubuntu-24.04` runner would have failed on exactly those
three errors, and §7 already says why nobody knew — the workflow has never run.

That is the argument for a Linux build a laptop can run. A platform whose only build
happens on a runner nobody has triggered is a platform nobody has built.

### What is verified, and what is not

Verified, by running it on an Apple Silicon Mac under OrbStack/Rosetta: `make dist-linux`
completes from deleted caches, `file` reports the artifact as `ELF 64-bit LSB pie
executable, x86-64 … dynamically linked … stripped`, and

```
$ docker run --rm --platform linux/amd64 \
    -v "$PWD/dist/ouro-0.1.0-x86_64-unknown-linux-gnu:/ouro:ro" ubuntu:24.04 /ouro version
ouro 0.1.0
  protocol  1
  release   0.1.0 (sha256 e64e5d53068623b3)
```

exits 0 in a container that has nothing installed. The third line is the one worth
reading: `release   none embedded` would mean the tarball never made it into the binary
and the whole exercise produced a client that can only attach to a runtime somebody else
started.

Not verified: nothing has run this on a **real** x86-64 Linux machine, so "runs under
emulation" is the claim, not "runs on the hardware you are about to copy it to". `make
test` and `scripts/fleet-e2e.sh` are not run inside the container either — the release
workflow gates on both, this target does not, and a binary from here has therefore passed
no suite on the platform it targets. Successive builds are also not byte-reproducible: the
release tarball differs run to run, so its digest differs, and the binary that embeds it
differs with it.

---

## 9. Open questions

- **Key rotation.** There is none. The public key is compiled in, so rotating it means
  every older binary can no longer verify a new release and must be replaced by hand. The
  usual answer is to sign a new key with the old one and teach the client to accept a
  signed key transition, or to compile in two keys during an overlap window. Neither
  exists. Decide before the first key ships, not after it leaks.
- **Windows.** This crate does not build on Windows (it uses `std::os::unix` throughout),
  so `ouro update` has no Windows path — not a refused one, an absent one. `rename(2)`
  semantics do not carry over: Windows will not rename over a running executable, and the
  usual workaround (rename the running binary aside, put the new one in place, delete the
  old on next boot) is a different design with different failure modes. It is not
  implemented and not claimed.
- **macOS notarization.** The artifacts are unsigned and unnotarized; there are no
  Developer ID credentials. `install.sh` clears the quarantine attribute after its own
  checks pass, and the README says so. A minisign signature is not a substitute for
  notarization to Gatekeeper, only to a person.
- **Linux ABI.** Artifacts are native Ubuntu 24.04 GNU builds, not static binaries. An
  older glibc needs `make ouro`. A musl target would need its own matrix entry and its
  own ERTS.
- **The trusted comment is informational.** `ouro update` prints it only after verifying
  the global signature over it, so it is authentic — but nothing compares it to the tag
  or the version. Binding the manifest to a tag cryptographically would mean checking
  that comment's contents, which is worth doing once there is a tag to check against.
- **Channels**, per §4.
