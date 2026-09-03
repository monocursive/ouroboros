defmodule Ouroboros.Wasm.SandboxFixture do
  @moduledoc """
  What a test has to tell a pool before its helper can be spawned wrapped (W16, D25).

  Since W16 `Ouroboros.Wasm.Pool` spawns the helper under
  `Ouroboros.Provider.Native.Sandbox.helper_policy/1` by default, and that policy is closed on
  reads and writable only in a scratch this node created under `<data_dir>/wasm/scratch/`. A
  test has neither: its components, its fake helpers and its journals live in a directory it
  made under `System.tmp_dir!()`, and most of this repository's wasm suites never set a data
  directory at all.

  So a test says where its own roots are, the way a node says where its own are — and it says
  it *once*, here, so that "what does a test have to widen" has one answer and a suite that
  forgot cannot look like a suite that was exempted. Nothing here turns the sandbox off:
  `helper_sandbox: :off` appears only in the two W16 tests that prove the difference between
  the postures — the pool's kernel probe and the signer's — and nowhere else in this
  repository.

  **`pool_opts/1` is wider than production in one way, deliberately.** It names a writable
  root, because a scripted helper journals what it was asked; a node names none at all, and
  its child's only writable directory is the scratch the pool made. The readable half is the
  same shape as a node's — a directory the node itself put components in — and the pool-side
  load fence measures a path against exactly this list, so a test that widened it too far
  would be a test whose fence proves nothing.

  **`scripted_pool_opts/1` is wider in a second way, and only a scripted helper may use it
  (W21).** Since W21 the helper's policy is **sealed** as a process by default: on Seatbelt
  the child may exec only the binary it was spawned as, may not fork, and has no
  `mach-lookup`. A real `ouro-wasm` needs nothing more. A *scripted* fake helper — the
  `#!/bin/sh` + `awk` stand-ins most of this repository's wasm suites drive — is exactly what
  that seals out: its interpreter has to be exec'd, macOS `/bin/sh` re-execs `/bin/bash` as
  its variant, and `awk` is a fork. So a suite that spawns a script says so with
  `scripted_pool_opts/1`, which is `pool_opts/1` plus `scripted_helper: true`, and the pool
  leaves the process posture open (its status says `process: :open`) while the read and
  network fences stay exactly what they are. Every suite that spawns the **real** helper —
  the acceptance suites, the forge, the signer, the two-node tests — uses `pool_opts/1` and
  runs sealed, because a real helper that only passed open would be a seal nobody had proved.
  This is a test-fixture widening like `pool_opts/1`'s writable root: there is no operator
  key behind it, on purpose.
  """

  @doc """
  Pool options that put this test's directory inside the fence.

  `readable` is where its components are, `writable` is where a fake helper's journal goes
  (a real helper writes nothing, and the node's own pool names no writable root at all), and
  `scratch_root` stands in for `<data_dir>/wasm/scratch/` — created and verified by the pool
  exactly as it would be on a node. The process posture is the default — sealed — so this is
  what a suite spawning the real helper uses.
  """
  @spec pool_opts(Path.t()) :: keyword()
  def pool_opts(dir) when is_binary(dir) do
    [readable: [dir], writable: [dir], scratch_root: Path.join(dir, "scratch")]
  end

  @doc """
  `pool_opts/1` for a suite whose helper is a **shell script** (W21).

  Adds `scripted_helper: true`, which leaves the process posture open so the script's
  interpreter can be exec'd and its `awk` forked. Never for the real helper: a suite that
  drives `ouro-wasm` itself uses `pool_opts/1` and proves the seal by passing under it.
  """
  @spec scripted_pool_opts(Path.t()) :: keyword()
  def scripted_pool_opts(dir) when is_binary(dir),
    do: pool_opts(dir) ++ scripted_helper()

  @doc """
  The one option that says a helper is a script, for `Ouroboros.Wasm.Deploy.sign/2` and any
  other caller that takes the helper policy's options directly (W21).

  A `#!/bin/sh` shim standing where `ouro-wasm precompile` stands needs it for the same
  reason a scripted pool does; the real signer's helper runs sealed.
  """
  @spec scripted_helper() :: keyword()
  def scripted_helper, do: [scripted_helper: true]
end
