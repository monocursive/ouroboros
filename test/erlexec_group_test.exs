defmodule Ouroboros.ErlexecGroupTest do
  use ExUnit.Case, async: true

  test "failure to establish the requested group prevents the command from executing" do
    # Beyond the PID ranges of supported macOS/Linux hosts, so no such group exists.
    # The command's stdout marker proves an EPERM was not blindly treated as success.
    assert {:error, result} =
             :exec.run(["/bin/echo", "command-was-executed"], [
               :sync,
               :stdout,
               :stderr,
               {:group, 2_147_483_646}
             ])

    assert result[:exit_status] != 0
    refute inspect(result) =~ "command-was-executed"
    assert IO.iodata_to_binary(result[:stderr]) =~ "Cannot set effective group"
  end
end
