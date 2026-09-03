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
  `helper_sandbox: :off` appears in exactly one place in this repository, the W16 test that
  proves the difference between the two postures.
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

  @doc """
  The same, for a test that reaches the node's **singleton** pool and cannot pass options.

  Points `:data_dir` at `dir` — which is what gives the pool a scratch root and makes
  `<dir>/wasm` readable — and adds `dir` itself to `helper_readable`, because a suite's store
  root is usually beside the data directory rather than under it. Both are restored when the
  test ends.
  """
  @spec node!(Path.t()) :: :ok
  def node!(dir) when is_binary(dir) do
    restore(:data_dir, dir)
    restore(:wasm, Keyword.put(wasm_config(), :helper_readable, [dir]))
    :ok
  end

  defp wasm_config do
    case Application.get_env(:ouroboros, :wasm, []) do
      configured when is_list(configured) -> configured
      _other -> []
    end
  end

  defp restore(key, value) do
    previous = Application.fetch_env(:ouroboros, key)
    Application.put_env(:ouroboros, key, value)

    ExUnit.Callbacks.on_exit(fn ->
      case previous do
        {:ok, held} -> Application.put_env(:ouroboros, key, held)
        :error -> Application.delete_env(:ouroboros, key)
      end
    end)
  end
end
