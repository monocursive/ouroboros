defmodule Ouroboros.Provider.Native.BashSpawnFailureTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.Bash

  test "a caught Exec exit is returned as a Bash spawn diagnostic" do
    root = Path.join(System.tmp_dir!(), "native-bash-spawn-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)

    on_exit(fn -> File.rm_rf(root) end)

    assert {:ok, scope} = Paths.scope(root, [], :unrestricted)
    assert {:ok, _started} = Application.ensure_all_started(:erlexec)
    assert :ok = Application.stop(:erlexec)

    on_exit(fn ->
      assert {:ok, _started} = Application.ensure_all_started(:erlexec)
    end)

    result =
      Tools.execute(
        Bash,
        %{"command" => "echo this-command-must-not-run"},
        %{scope: scope, session_dir: root, reads: %{}},
        5_000
      )

    assert result.is_error
    assert result.output =~ "bash failed: could not start the child process (exit):"
    assert result.output =~ "noproc"
    refute result.output =~ "FunctionClauseError"
    refute result.output =~ "tool raised"
  end
end
