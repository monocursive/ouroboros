defmodule Ouroboros.Provider.Native.ExecTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Exec

  @release_environment ~w(BINDIR EMU PATH PROGNAME RELEASE_NAME RELEASE_ROOT ROOTDIR)

  test "an explicit timeout ceiling bounds a command while defaults stay at ten minutes" do
    assert {:ok, %{timed_out?: true}} =
             Exec.run("/bin/sh", ["-c", "sleep 1"], timeout_ms: 5_000, max_timeout_ms: 30)

    assert Ouroboros.Provider.Native.Tools.Bash.max_timeout_ms(%{}) == 600_000

    assert Ouroboros.Provider.Native.Tools.Bash.max_timeout_ms(%{
             "bash_max_timeout_ms" => 1_800_000
           }) == 1_800_000

    assert Ouroboros.Provider.Native.Tools.Bash.max_timeout_ms(%{
             "bash_max_timeout_ms" => 99_000_000
           }) == 14_400_000
  end

  test "bash passes the node ceiling through to Exec without changing its default" do
    root = Path.join(System.tmp_dir!(), "bash-ceiling-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)

    context = %{
      scope: %{root: root, roots: [root], sandbox_mode: :unrestricted},
      session_dir: root,
      provider_options: %{"bash_max_timeout_ms" => 30}
    }

    assert {:ok, %{output: output}} =
             Ouroboros.Provider.Native.Tools.Bash.run(
               %{command: "sleep 1", timeout_ms: 5_000},
               context
             )

    assert output =~ "timed out after 30 ms"
  end

  test "cancelling the owning execution task terminates its process group and descendants" do
    marker = Path.join(System.tmp_dir!(), "exec-child-#{System.unique_integer([:positive])}")

    owner =
      Task.async(fn ->
        Exec.run("/bin/sh", ["-c", "(sleep 30) & echo $! > #{marker}; wait"], timeout_ms: 30_000)
      end)

    assert eventually(fn -> File.regular?(marker) end)
    assert eventually(fn -> Ouroboros.Provider.Native.Exec.Registry.cancel(owner.pid) == :ok end)
    descendant = marker |> File.read!() |> String.trim() |> String.to_integer()
    assert eventually_not(fn -> os_process_alive?(descendant) end, 50)
    _ = Task.shutdown(owner, 1_000)
    File.rm(marker)
  end

  test "cancelling an owner with no running command is harmless" do
    assert :not_running = Exec.cancel(self())
  end

  test "owner death delegates registered process-group cleanup to erlexec kill_group" do
    marker =
      Path.join(System.tmp_dir!(), "exec-owner-death-#{System.unique_integer([:positive])}")

    owner =
      spawn(fn ->
        Exec.run("/bin/sh", ["-c", "echo $$ > #{marker}; while :; do sleep 1; done"],
          timeout_ms: 30_000
        )
      end)

    assert eventually(fn -> File.regular?(marker) end)
    leader = marker |> File.read!() |> String.trim() |> String.to_integer()
    Process.exit(owner, :kill)
    assert eventually_not(fn -> os_process_alive?(leader) end, 100)
    File.rm(marker)
  end

  test "TERM-resistant process group escalates within the cancellation bound" do
    marker =
      Path.join(System.tmp_dir!(), "exec-term-resistant-#{System.unique_integer([:positive])}")

    owner =
      Task.async(fn ->
        Exec.run(
          "/bin/sh",
          ["-c", "trap '' TERM; echo $$ > #{marker}; while :; do sleep 1; done"],
          timeout_ms: 30_000
        )
      end)

    assert eventually(fn -> File.regular?(marker) end)
    started = System.monotonic_time(:millisecond)
    assert eventually(fn -> Exec.cancel(owner.pid) == :ok end)
    assert System.monotonic_time(:millisecond) - started < 1_500
    leader = marker |> File.read!() |> String.trim() |> String.to_integer()
    assert eventually_not(fn -> os_process_alive?(leader) end, 100)
    _ = Task.shutdown(owner, 1_000)
    File.rm(marker)
  end

  test "cancellation racing normal exit does not signal a later command" do
    owner = Task.async(fn -> Exec.run("/usr/bin/true", [], timeout_ms: 1_000) end)
    result = Exec.cancel(owner.pid)
    assert result in [:ok, :not_running]
    assert {:ok, %{status: 0}} = Exec.run("/usr/bin/true", [])
    _ = Task.shutdown(owner, 1_000)
  end

  test "duplicate owner registration replaces and demonitor old ownership" do
    owner = spawn(fn -> Process.sleep(:infinity) end)
    assert :ok = Exec.register_cancel_owner(owner, 2_000_000_001)
    assert :ok = Exec.register_cancel_owner(owner, 2_000_000_002)
    assert :ok = Ouroboros.Provider.Native.Exec.Registry.unregister(owner, 2_000_000_002)
    assert :not_running = Exec.cancel(owner)
    Process.exit(owner, :kill)
  end

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

  test "an ordinary VM keeps its Erlang runtime directory in child PATH" do
    previous = Map.take(System.get_env(), @release_environment)

    on_exit(fn ->
      Enum.each(@release_environment, &System.delete_env/1)
      Enum.each(previous, fn {name, value} -> System.put_env(name, value) end)
    end)

    root = :code.root_dir() |> List.to_string()
    runtime_bin = Path.join(root, "bin")

    System.put_env(%{
      "ROOTDIR" => root,
      "BINDIR" => runtime_bin,
      "PATH" => Enum.join([runtime_bin, "/usr/bin", "/bin"], ":")
    })

    Enum.each(~w(RELEASE_NAME RELEASE_ROOT), &System.delete_env/1)

    assert {:ok, %{status: 0, output: output}} = Exec.run("/usr/bin/env", [])
    assert output =~ "PATH=#{runtime_bin}:/usr/bin:/bin\n"
    refute output =~ "ROOTDIR="
    refute output =~ "BINDIR="
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

  defp os_process_alive?(pid) do
    case System.cmd("/bin/ps", ["-o", "stat=", "-p", Integer.to_string(pid)],
           stderr_to_stdout: true
         ) do
      {status, 0} -> status |> String.trim() |> String.starts_with?("Z") |> Kernel.not()
      _ -> false
    end
  end

  defp eventually_not(_fun, 0), do: false

  defp eventually_not(fun, attempts) do
    if fun.() do
      Process.sleep(20)
      eventually_not(fun, attempts - 1)
    else
      true
    end
  end

  defp eventually(fun, attempts \\ 100)
  defp eventually(_fun, 0), do: false

  defp eventually(fun, attempts) do
    if fun.() do
      true
    else
      Process.sleep(20)
      eventually(fun, attempts - 1)
    end
  end
end
