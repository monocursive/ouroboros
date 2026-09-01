defmodule Ouroboros.Wasm.ResolutionTest do
  # Not async: the removed-cwd case runs a subprocess, and the plain case reads the global
  # `:ouroboros, :wasm` config. Neither mutates shared state, but they are grouped serial to
  # keep the (heavier) subprocess test off the async schedule.
  use ExUnit.Case, async: false

  alias Ouroboros.Wasm

  test "helper_path/0 is always a string and available?/0 tracks disk" do
    path = Wasm.helper_path()
    assert is_binary(path) and path != ""
    assert Wasm.available?() == File.regular?(path)
  end

  test "OUROBOROS_WASM_HELPER wins over the bundled resolution" do
    override =
      Path.join(System.tmp_dir!(), "ouro-wasm-override-#{System.unique_integer([:positive])}")

    System.put_env("OUROBOROS_WASM_HELPER", override)
    on_exit(fn -> System.delete_env("OUROBOROS_WASM_HELPER") end)

    assert Wasm.helper_path() == override
  end

  @tag :subprocess
  test "helper_path/0 does not raise when the working directory has been removed (F7)" do
    # A bare `Path.expand("priv/wasm/…")` candidate calls `File.cwd!/0`, which raises when the
    # working directory is gone out from under a running node — turning a `Pool.init/1` on the
    # next supervisor restart into a restart storm. That candidate was deleted;
    # `walk_priv_helper/0` (which guards `File.cwd/0`) subsumes it. This boots a subprocess
    # normally, removes its cwd from the inside, and then calls `helper_path/0`: it must return
    # a string and exit cleanly. Revert the deletion and the call raises and this fails.
    elixir = System.find_executable("elixir")

    unless elixir do
      flunk("elixir is not on PATH; the F7 removed-cwd regression needs it to run a subprocess")
    end

    doomed = Path.join(System.tmp_dir!(), "ouro-wasm-gone-#{System.unique_integer([:positive])}")

    code = """
    File.mkdir_p!(#{inspect(doomed)})
    File.cd!(#{inspect(doomed)})
    File.rmdir!(#{inspect(doomed)})

    result =
      try do
        if is_binary(Ouroboros.Wasm.helper_path()), do: "STRING", else: "OTHER"
      rescue
        error -> "RAISED:" <> Exception.message(error)
      end

    IO.puts(result)
    """

    args = Enum.flat_map(:code.get_path(), &["-pa", List.to_string(&1)]) ++ ["-e", code]
    {output, status} = System.cmd(elixir, args, stderr_to_stdout: true)

    assert status == 0, "helper_path/0 crashed with cwd removed:\n#{output}"
    assert output =~ "STRING", output
  end
end
