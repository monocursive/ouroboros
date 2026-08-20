defmodule Ouroboros.RuntimeOwnerTest do
  use ExUnit.Case, async: false

  import Bitwise
  import ExUnit.CaptureLog

  alias Ouroboros.RuntimeOwner

  @moduletag :tmp_dir

  setup %{tmp_dir: data_dir} do
    File.chmod!(data_dir, 0o700)
    :ok
  end

  test "one owner claims atomically, records its pid at 0600, and excludes a live peer", %{
    tmp_dir: data_dir
  } do
    {:ok, first} = start_owner(data_dir, os_pid: 101, identity: "first-vm")
    path = RuntimeOwner.marker_path(data_dir)

    assert %{"pid" => 101, "owner" => "first-vm"} = read_marker(path)
    assert (File.stat!(path).mode &&& 0o777) == 0o600

    assert {:error, {:runtime_data_dir_owned, message}} =
             refused_owner(data_dir,
               os_pid: 202,
               identity: "second-vm",
               pid_state: fn 101 -> :alive end
             )

    assert message =~ path
    assert message =~ "runtime pid 101"
    assert File.ls!(data_dir) == ["runtime.owner"]

    GenServer.stop(first)
    refute File.exists?(path)
  end

  test "a poisoned PATH cannot declare a live owner dead or authorize recovery", %{
    tmp_dir: data_dir
  } do
    path = RuntimeOwner.marker_path(data_dir)
    shim_dir = Path.join(data_dir, "path-shims")
    shim_log = Path.join(data_dir, "shim-invocations")
    live_pid = System.pid() |> String.to_integer()
    previous_path = System.get_env("PATH")

    File.mkdir_p!(shim_dir)

    Enum.each(["kill", "ps"], fn command ->
      shim = Path.join(shim_dir, command)

      File.write!(
        shim,
        "#!/bin/sh\nprintf '%s\\n' #{command} >> #{shell_quote(shim_log)}\nexit 1\n"
      )

      File.chmod!(shim, 0o700)
    end)

    write_marker(path, live_pid, "live-owner")
    System.put_env("PATH", shim_dir)

    on_exit(fn ->
      if previous_path,
        do: System.put_env("PATH", previous_path),
        else: System.delete_env("PATH")
    end)

    name = String.to_atom("runtime_owner_path_test_#{System.unique_integer([:positive])}")
    previous_trap = Process.flag(:trap_exit, true)

    result =
      try do
        RuntimeOwner.start_link(
          data_dir: data_dir,
          name: name,
          os_pid: live_pid,
          identity: "replacement-owner"
        )
      after
        Process.flag(:trap_exit, previous_trap)
      end

    assert {:error, {:runtime_data_dir_owned, message}} = result
    assert message =~ "runtime pid #{live_pid}"
    refute File.exists?(shim_log)
    assert %{"pid" => ^live_pid, "owner" => "live-owner"} = read_marker(path)
    assert Enum.sort(File.ls!(data_dir)) == ["path-shims", "runtime.owner"]
  end

  test "a dead holder is removed once and replaced by the new runtime", %{tmp_dir: data_dir} do
    path = RuntimeOwner.marker_path(data_dir)
    write_marker(path, 303, "dead-vm")

    {:ok, owner} =
      start_owner(data_dir,
        os_pid: 404,
        identity: "replacement-vm",
        pid_state: fn 303 -> :dead end
      )

    assert %{"pid" => 404, "owner" => "replacement-vm"} = read_marker(path)
    assert File.ls!(data_dir) == ["runtime.owner"]

    GenServer.stop(owner)
    refute File.exists?(path)
  end

  test "normal linked port completion is quiet while the lifetime owner traps exits", %{
    tmp_dir: data_dir
  } do
    {:ok, owner} = start_owner(data_dir, os_pid: 414, identity: "port-probe-vm")
    port = Port.open({:spawn_executable, "/usr/bin/true"}, [:exit_status])

    log =
      capture_log(fn ->
        send(owner, {:EXIT, port, :normal})
        assert Process.alive?(owner)
        assert %{identity: "port-probe-vm"} = :sys.get_state(owner)
      end)

    refute log =~ "unexpected message"

    GenServer.stop(owner)
  end

  test "an owner crash leaves the claim and the same VM identity can resume it", %{
    tmp_dir: data_dir
  } do
    previous = Process.flag(:trap_exit, true)
    path = RuntimeOwner.marker_path(data_dir)

    try do
      {:ok, owner} = start_owner(data_dir, os_pid: 505, identity: "stable-vm")
      Process.exit(owner, :kill)
      assert_receive {:EXIT, ^owner, :killed}

      assert %{"pid" => 505, "owner" => "stable-vm"} = read_marker(path)

      {:ok, replacement} =
        start_owner(data_dir,
          os_pid: 505,
          identity: "stable-vm",
          pid_state: fn _pid -> flunk("the same VM does not need a liveness probe") end
        )

      GenServer.stop(replacement)
      refute File.exists?(path)
    after
      Process.flag(:trap_exit, previous)
    end
  end

  test "an orderly supervisor shutdown reaches the owner and releases its marker", %{
    tmp_dir: data_dir
  } do
    name = String.to_atom("runtime_owner_test_#{System.unique_integer([:positive, :monotonic])}")

    child =
      {RuntimeOwner,
       data_dir: data_dir,
       name: name,
       os_pid: 515,
       identity: "supervised-vm",
       pid_state: fn _pid -> :alive end}

    {:ok, supervisor} = Supervisor.start_link([child], strategy: :one_for_one)
    Process.unlink(supervisor)
    assert File.exists?(RuntimeOwner.marker_path(data_dir))

    :ok = Supervisor.stop(supervisor, :shutdown)
    refute File.exists?(RuntimeOwner.marker_path(data_dir))
  end

  test "graceful cleanup never removes a marker that no longer names this owner", %{
    tmp_dir: data_dir
  } do
    {:ok, owner} = start_owner(data_dir, os_pid: 606, identity: "original-vm")
    path = RuntimeOwner.marker_path(data_dir)

    write_marker(path, 707, "other-vm")
    GenServer.stop(owner)

    assert %{"pid" => 707, "owner" => "other-vm"} = read_marker(path)
  end

  test "an invalid marker fails closed and a failed claim leaves no temporary debris", %{
    tmp_dir: data_dir
  } do
    path = RuntimeOwner.marker_path(data_dir)
    File.write!(path, "{}")
    File.chmod!(path, 0o600)

    assert {:error, {:runtime_owner_marker_invalid, message}} =
             refused_owner(data_dir, os_pid: 808, identity: "new-vm")

    assert message =~ path
    assert message =~ "positive integer pid"
    assert File.read!(path) == "{}"
    assert File.ls!(data_dir) == ["runtime.owner"]
  end

  test "a process birth identity with path or whitespace characters fails closed", %{
    tmp_dir: data_dir
  } do
    path = RuntimeOwner.marker_path(data_dir)
    write_marker(path, 809, "old-vm", "../bad birth")

    assert {:error, {:runtime_owner_marker_invalid, message}} =
             refused_owner(data_dir,
               os_pid: 810,
               identity: "new-vm",
               pid_state: fn _pid ->
                 flunk("an invalid birth must not trigger a liveness probe")
               end
             )

    assert message =~ "process birth identity is malformed"
    assert read_marker(path)["birth"] == "../bad birth"
  end

  test "a symlink marker fails closed without consulting or replacing its target", %{
    tmp_dir: data_dir
  } do
    target = Path.join(data_dir, "attacker-controlled")
    path = RuntimeOwner.marker_path(data_dir)
    write_marker(target, 818, "other-vm")
    File.ln_s!(target, path)

    assert {:error, {:runtime_owner_marker_invalid, message}} =
             refused_owner(data_dir,
               os_pid: 819,
               identity: "new-vm",
               pid_state: fn _pid ->
                 flunk("a symlink marker must not trigger a liveness probe")
               end
             )

    assert message =~ path
    assert message =~ "not a regular file"
    assert File.lstat!(path).type == :symlink
    assert %{"pid" => 818, "owner" => "other-vm"} = read_marker(target)
    assert Enum.sort(File.ls!(data_dir)) == ["attacker-controlled", "runtime.owner"]
  end

  test "an unavailable hard-link primitive fails clearly and leaves no temporary debris", %{
    tmp_dir: data_dir
  } do
    path = RuntimeOwner.marker_path(data_dir)

    assert {:error, {:runtime_owner_atomic_claim_failed, message}} =
             refused_owner(data_dir,
               os_pid: 909,
               identity: "new-vm",
               link: fn _existing, _new -> {:error, :enotsup} end
             )

    assert message =~ path
    assert File.ls!(data_dir) == []
  end

  test "a busy recovery lock fails closed before touching the owner namespace", %{
    tmp_dir: data_dir
  } do
    path = RuntimeOwner.marker_path(data_dir)
    write_marker(path, 910, "stale-vm")

    recovery_lock = fn locked_dir, _fun ->
      {:error,
       {:runtime_owner_recovery_busy,
        "#{Path.join(locked_dir, "runtime.owner.recovery")}: another startup holds the lock"}}
    end

    assert {:error, {:runtime_owner_recovery_busy, message}} =
             refused_owner(data_dir,
               os_pid: 911,
               identity: "new-vm",
               recovery_lock: recovery_lock
             )

    assert message =~ "another startup holds the lock"
    assert %{"pid" => 910, "owner" => "stale-vm"} = read_marker(path)
  end

  test "a reused live pid with a different birth is recovered as a stale incarnation", %{
    tmp_dir: data_dir
  } do
    path = RuntimeOwner.marker_path(data_dir)
    write_marker(path, 920, "old-vm", "old-birth")

    {:ok, owner} =
      start_owner(data_dir,
        os_pid: 920,
        identity: "new-vm",
        birth: "new-birth",
        pid_state: fn 920 -> :alive end,
        birth_state: fn 920, "old-birth" -> :dead end
      )

    assert %{"pid" => 920, "owner" => "new-vm", "birth" => "new-birth"} =
             read_marker(path)

    GenServer.stop(owner)
  end

  test "two serialized claimants cannot unlink the recovery winner", %{tmp_dir: data_dir} do
    path = RuntimeOwner.marker_path(data_dir)
    write_marker(path, 930, "stale-vm")

    recovery_lock = fn locked_dir, fun ->
      :global.trans({{__MODULE__, locked_dir}, self()}, fun)
    end

    pid_state = fn
      930 -> :dead
      pid when pid in [931, 932] -> :alive
    end

    claim = fn pid, identity ->
      Task.async(fn ->
        previous = Process.flag(:trap_exit, true)

        try do
          result =
            start_owner(data_dir,
              os_pid: pid,
              identity: identity,
              pid_state: pid_state,
              recovery_lock: recovery_lock
            )

          if match?({:ok, _owner}, result) do
            {:ok, owner} = result
            Process.unlink(owner)
          end

          result
        after
          Process.flag(:trap_exit, previous)
        end
      end)
    end

    first = claim.(931, "first-vm")
    second = claim.(932, "second-vm")
    results = [Task.await(first), Task.await(second)]
    assert [{:ok, owner}] = Enum.filter(results, &match?({:ok, _owner}, &1))

    assert [{:error, {:runtime_data_dir_owned, _message}}] =
             Enum.filter(results, &match?({:error, _reason}, &1))

    assert read_marker(path)["pid"] in [931, 932]

    GenServer.stop(owner)
  end

  test "helper death during replacement aborts the claim and the next start recovers", %{
    tmp_dir: data_dir
  } do
    parent = self()
    path = RuntimeOwner.marker_path(data_dir)
    helper = Path.join(data_dir, "crashing-lock-helper")
    previous_helper = System.get_env("OUROBOROS_PROCESS_ID_HELPER")

    File.write!(helper, "#!/bin/sh\nprintf 'locked\\n'\n/bin/sleep 0.2\nexit 73\n")
    File.chmod!(helper, 0o700)
    System.put_env("OUROBOROS_PROCESS_ID_HELPER", helper)

    on_exit(fn ->
      if previous_helper,
        do: System.put_env("OUROBOROS_PROCESS_ID_HELPER", previous_helper),
        else: System.delete_env("OUROBOROS_PROCESS_ID_HELPER")
    end)

    write_marker(path, 940, "stale-vm")

    link = fn existing, new ->
      count = Process.get(:runtime_owner_link_count, 0)
      Process.put(:runtime_owner_link_count, count + 1)

      if count == 1 do
        send(parent, :replacement_link_reached)

        receive do
          :never_sent -> File.ln(existing, new)
        end
      else
        File.ln(existing, new)
      end
    end

    assert {:error, {:runtime_owner_recovery_lock_lost, message}} =
             refused_owner(data_dir,
               os_pid: 941,
               identity: "interrupted-vm",
               pid_state: fn 940 -> :dead end,
               link: link
             )

    assert_receive :replacement_link_reached
    assert message =~ "lock helper exited"
    assert !File.exists?(path) or read_marker(path)["pid"] == 940

    System.delete_env("OUROBOROS_PROCESS_ID_HELPER")
    {:ok, replacement} = start_owner(data_dir, os_pid: 942, identity: "replacement-vm")
    assert %{"pid" => 942, "owner" => "replacement-vm"} = read_marker(path)
    GenServer.stop(replacement)
  end

  test "a normal claim worker exit through the helper path leaves the runtime owner alive", %{
    tmp_dir: data_dir
  } do
    helper = Path.join(data_dir, "normal-lock-helper")
    previous_helper = System.get_env("OUROBOROS_PROCESS_ID_HELPER")

    File.write!(
      helper,
      "#!/bin/sh\nprintf 'locked\\n'\n/bin/cat >/dev/null\nexit 0\n"
    )

    File.chmod!(helper, 0o700)
    System.put_env("OUROBOROS_PROCESS_ID_HELPER", helper)

    on_exit(fn ->
      if previous_helper,
        do: System.put_env("OUROBOROS_PROCESS_ID_HELPER", previous_helper),
        else: System.delete_env("OUROBOROS_PROCESS_ID_HELPER")
    end)

    {:ok, owner} = start_owner(data_dir, os_pid: 950, identity: "stable-helper-vm")
    monitor = Process.monitor(owner)

    refute_receive {:DOWN, ^monitor, :process, ^owner, _reason}, 100
    assert Process.alive?(owner)

    assert %{pid: 950, owner: "stable-helper-vm", birth: "test-birth"} =
             RuntimeOwner.claim(owner)

    Process.demonitor(monitor, [:flush])
    GenServer.stop(owner)
  end

  defp start_owner(data_dir, overrides) do
    name = String.to_atom("runtime_owner_test_#{System.unique_integer([:positive, :monotonic])}")
    pid_state = Keyword.get(overrides, :pid_state, fn _pid -> :alive end)

    defaults = [
      data_dir: data_dir,
      name: name,
      os_pid: 999,
      identity: "test-vm",
      birth: "test-birth",
      pid_state: pid_state,
      birth_state: fn pid, _birth -> pid_state.(pid) end
    ]

    RuntimeOwner.start_link(Keyword.merge(defaults, overrides))
  end

  defp refused_owner(data_dir, overrides) do
    previous = Process.flag(:trap_exit, true)

    try do
      result = start_owner(data_dir, overrides)
      assert {:error, _reason} = result
      result
    after
      Process.flag(:trap_exit, previous)
    end
  end

  defp write_marker(path, pid, owner, birth \\ nil) do
    marker = %{"pid" => pid, "owner" => owner}
    marker = if birth, do: Map.put(marker, "birth", birth), else: marker
    File.write!(path, JSON.encode!(marker) <> "\n")
    File.chmod!(path, 0o600)
  end

  defp read_marker(path), do: path |> File.read!() |> JSON.decode!()

  defp shell_quote(value), do: "'" <> String.replace(value, "'", "'\"'\"'") <> "'"
end
