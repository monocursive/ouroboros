defmodule Ouroboros.Provider.Native.ExecTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Exec

  @release_environment ~w(BINDIR EMU PATH PROGNAME RELEASE_NAME RELEASE_ROOT ROOTDIR)

  test "child commands inherit the host environment without the daemon release context" do
    previous = Map.take(System.get_env(), @release_environment)

    on_exit(fn ->
      Enum.each(@release_environment, &System.delete_env/1)
      Enum.each(previous, fn {name, value} -> System.put_env(name, value) end)
    end)

    System.put_env(%{
      "ROOTDIR" => "/tmp/ouroboros-release",
      "BINDIR" => "/tmp/ouroboros-release/erts-17/bin",
      "EMU" => "beam",
      "PROGNAME" => "erl",
      "RELEASE_NAME" => "ouroboros",
      "RELEASE_ROOT" => "/tmp/ouroboros-release",
      "PATH" => "/tmp/ouroboros-release/erts-17/bin:/tmp/ouroboros-release/bin:/usr/bin:/bin"
    })

    assert {:ok, %{status: 0, output: output}} = Exec.run("/usr/bin/env", [])

    child_environment =
      output
      |> String.split("\n", trim: true)
      |> Map.new(fn line ->
        [name, value] = String.split(line, "=", parts: 2)
        {name, value}
      end)

    for name <- ~w(BINDIR EMU PROGNAME RELEASE_NAME RELEASE_ROOT ROOTDIR) do
      refute Map.has_key?(child_environment, name)
    end

    assert child_environment["PATH"] == "/usr/bin:/bin"
  end

  test "explicit command variables still win after inherited release variables are removed" do
    previous = System.get_env("ROOTDIR")
    on_exit(fn -> restore_env("ROOTDIR", previous) end)
    System.put_env("ROOTDIR", "/tmp/inherited-release")

    assert {:ok, %{status: 0, output: output}} =
             Exec.run("/usr/bin/env", [], env: [{"ROOTDIR", "/tmp/explicit-tool-root"}])

    assert output =~ "ROOTDIR=/tmp/explicit-tool-root\n"
  end

  defp restore_env(name, nil), do: System.delete_env(name)
  defp restore_env(name, value), do: System.put_env(name, value)
end
