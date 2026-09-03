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
  """

  @doc """
  Pool options that put this test's directory inside the fence.

  `readable` is where its components are, `writable` is where a fake helper's journal goes
  (a real helper writes nothing, and the node's own pool names no writable root at all), and
  `scratch_root` stands in for `<data_dir>/wasm/scratch/` — created and verified by the pool
  exactly as it would be on a node.
  """
  @spec pool_opts(Path.t()) :: keyword()
  def pool_opts(dir) when is_binary(dir) do
    [readable: [dir], writable: [dir], scratch_root: Path.join(dir, "scratch")]
  end
end
