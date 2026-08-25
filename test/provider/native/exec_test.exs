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

  test "child commands inherit execution variables but not daemon settings or credentials" do
    environment = %{
      "REVIEW_FAKE_API_KEY" => "review-super-secret-api-key",
      "REVIEW_DATABASE_URL" => "postgres://review:database-password@127.0.0.1/review",
      "REVIEW_SERVICE_SETTING" => "daemon-internal-setting",
      "ERL_AFLAGS" => "-setcookie review-erlang-cookie -kernel shell_history enabled",
      "ERL_FLAGS" => "-setcookie=review-equals-cookie +sbwt none",
      "MIX_ENV" => "exec-filter-test"
    }

    previous = Map.take(System.get_env(), Map.keys(environment))

    on_exit(fn ->
      Enum.each(Map.keys(environment), &System.delete_env/1)
      Enum.each(previous, fn {name, value} -> System.put_env(name, value) end)
    end)

    System.put_env(environment)

    assert {:ok, %{status: 0, output: output}} = Exec.run("/usr/bin/env", [])

    assert output =~ "MIX_ENV=exec-filter-test\n"
    assert output =~ "HOME=#{System.user_home!()}\n"
    refute output =~ "REVIEW_FAKE_API_KEY="
    refute output =~ "review-super-secret-api-key"
    refute output =~ "REVIEW_DATABASE_URL="
    refute output =~ "database-password"
    refute output =~ "REVIEW_SERVICE_SETTING="
    refute output =~ "daemon-internal-setting"
    refute output =~ "ERL_AFLAGS="
    refute output =~ "review-erlang-cookie"
    refute output =~ "ERL_FLAGS="
    refute output =~ "review-equals-cookie"
  end

  test "explicit command variables cross the boundary only when they are safe" do
    assert {:ok, %{status: 0, output: output}} =
             Exec.run("/usr/bin/env", [],
               env: [
                 {"REVIEW_SAFE_OVERRIDE", "command-specific-setting"},
                 {"REVIEW_API_KEY", "explicit-super-secret"},
                 {"REVIEW_ENDPOINT", "postgres://user:password@127.0.0.1/review"}
               ]
             )

    assert output =~ "REVIEW_SAFE_OVERRIDE=command-specific-setting\n"
    refute output =~ "REVIEW_API_KEY="
    refute output =~ "explicit-super-secret"
    refute output =~ "REVIEW_ENDPOINT="
    refute output =~ "user:password"
  end

  defp restore_env(name, nil), do: System.delete_env(name)
  defp restore_env(name, value), do: System.put_env(name, value)
end
