defmodule Ouroboros.SessionDeletedCwdTest do
  use ExUnit.Case, async: true

  @tag :subprocess
  test "explicit session directories work after the runtime's working directory is removed" do
    root = Path.join(System.tmp_dir!(), "ouro-session-cwd-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    doomed = Path.join(root, "release")
    File.mkdir_p!(workspace)
    File.mkdir_p!(doomed)
    on_exit(fn -> File.rm_rf(root) end)

    # Cwd belongs to the whole VM. Remove it only in a child, leaving other tests and
    # the workspace intact, as when a running service's cached release is deleted.
    code = """
    File.cd!(#{inspect(doomed)})
    File.rmdir!(#{inspect(doomed)})
    {:error, :enoent} = File.cwd()

    checks = [
      request: fn ->
        {:ok, request} = Ouroboros.Session.Request.new(%{cwd: #{inspect(workspace)}})
        #{inspect(workspace)} = request.cwd
      end,
      interactive: fn ->
        {:ok, state} = Ouroboros.Interactive.State.new("deleted-cwd",
          workspace: #{inspect(workspace)}, runtime_exposure: false)
        #{inspect(workspace)} = state.workspace
        {:ok, request} = state |> Ouroboros.Interactive.State.request()
          |> Ouroboros.Session.Request.new()
        #{inspect(workspace)} = request.cwd
      end
    ]

    Enum.each(checks, fn {name, check} ->
      try do
        check.()
        IO.puts("PASS:" <> Atom.to_string(name))
      rescue
        error -> IO.puts("FAIL:" <> Atom.to_string(name) <> ":" <> Exception.message(error))
      end
    end)
    """

    args = Enum.flat_map(:code.get_path(), &["-pa", List.to_string(&1)]) ++ ["-e", code]
    {output, status} = System.cmd(System.find_executable("elixir"), args, stderr_to_stdout: true)

    assert status == 0, output
    assert output =~ "PASS:request", output
    assert output =~ "PASS:interactive", output
    refute output =~ "FAIL:", output
  end
end
