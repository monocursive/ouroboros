defmodule Ouroboros.Provider.ProcessDriverTest do
  use ExUnit.Case, async: false

  import Bitwise

  @moduletag :tmp_dir
  @probe Path.expand("support/provider_umask_probe.exs", __DIR__)
  @repo_root Path.expand("..", __DIR__)

  setup %{tmp_dir: tmp_dir} do
    File.chmod!(tmp_dir, 0o700)
    :ok
  end

  for runtime_mode <- ["ring", "service"] do
    test "provider workspace permissions are conventional under #{runtime_mode} runtime output",
         %{tmp_dir: tmp_dir} do
      runtime_mode = unquote(runtime_mode)
      workspace = Path.join(tmp_dir, "#{runtime_mode}-workspace")
      runtime_state_dir = Path.join(tmp_dir, "#{runtime_mode}-runtime-state")
      service_log = Path.join(tmp_dir, "#{runtime_mode}-runtime.log")
      provider = Path.join(tmp_dir, "fake provider; touch must-not-run")
      provider_dir = Path.join(workspace, "provider directory")
      provider_file = Path.join(workspace, "provider-$(touch injected)-file")
      provider_pid_file = Path.join(workspace, "provider.pid")
      sentinel = "literal spaces; $(touch injected)"

      File.mkdir!(workspace)
      File.chmod!(workspace, 0o755)
      write_provider!(provider, runtime_mode)

      {output, status} =
        run_runtime_probe(
          runtime_mode,
          service_log,
          provider,
          workspace,
          runtime_state_dir,
          provider_dir,
          provider_file,
          provider_pid_file,
          sentinel
        )

      diagnostic =
        if runtime_mode == "service" and File.exists?(service_log),
          do: File.read!(service_log),
          else: output

      assert status == 0, diagnostic

      runtime_output = if runtime_mode == "service", do: File.read!(service_log), else: output
      assert runtime_output =~ "provider-umask-probe-ok:#{runtime_mode}"
      assert File.read!(provider_file) == sentinel
      assert private_mode(runtime_state_dir) == 0o700
      assert private_mode(Path.join(runtime_state_dir, "beam-owned-state")) == 0o600
      assert private_mode(provider_dir) == 0o755
      assert private_mode(provider_file) == 0o644
      refute File.exists?(Path.join(workspace, "injected"))
      refute File.exists?(Path.join(workspace, "must-not-run"))
      refute File.exists?(Path.join(tmp_dir, "must-not-run"))

      if runtime_mode == "service", do: assert(private_mode(service_log) == 0o600)
    end
  end

  test "provider cancellation still targets the exec-preserved process group", %{tmp_dir: tmp_dir} do
    workspace = Path.join(tmp_dir, "cancellation-workspace")
    provider = Path.join(tmp_dir, "cancellable provider")
    descendant = Path.join(tmp_dir, "provider descendant")
    leader_pid_file = Path.join(tmp_dir, "leader.pid")
    descendant_pid_file = Path.join(tmp_dir, "descendant.pid")
    File.mkdir!(workspace)

    original_manager = Application.get_env(:jido_harness, :process_manager)

    Application.put_env(
      :jido_harness,
      :process_manager,
      original_manager
      |> then(&Map.new(&1 || %{}))
      |> Map.merge(%{cancel_grace_ms: 50, term_grace_ms: 50, output_drain_ms: 10})
    )

    on_exit(fn ->
      if is_nil(original_manager),
        do: Application.delete_env(:jido_harness, :process_manager),
        else: Application.put_env(:jido_harness, :process_manager, original_manager)
    end)

    write_cancellable_provider!(provider, descendant)

    assert {:ok, process_id} =
             Jido.Harness.Process.start(%{
               executable: provider,
               argv: [leader_pid_file, descendant_pid_file],
               cwd: workspace,
               stdin: false,
               pty: false,
               metadata: %{purpose: "provider-group-cancellation"}
             })

    on_exit(fn ->
      _ = Jido.Harness.Process.kill(process_id)
      _ = Jido.Harness.Process.prune(process_id)
    end)

    leader_pid = eventually_value(fn -> read_pid(leader_pid_file) end)
    descendant_pid = eventually_value(fn -> read_pid(descendant_pid_file) end)
    {:ok, running} = Jido.Harness.Process.info(process_id)

    assert running.os_pid == leader_pid
    assert running.metadata == %{purpose: "provider-group-cancellation"}
    assert os_process_group(leader_pid) == leader_pid
    assert os_process_group(descendant_pid) == leader_pid

    assert :ok = Jido.Harness.Process.cancel(process_id)
    assert {:ok, %{state: :cancelled}} = Jido.Harness.Process.await(process_id, 10_000)

    assert eventually_value(fn ->
             if not os_process_alive?(leader_pid) and not os_process_alive?(descendant_pid),
               do: :reaped,
               else: nil
           end) == :reaped

    assert :ok = Jido.Harness.Process.prune(process_id)
  end

  test "provider stdin and EOF pass through the custom driver", %{tmp_dir: workspace} do
    assert {:ok, process_id} =
             Jido.Harness.Process.start(%{
               executable: "/bin/cat",
               cwd: workspace,
               stdin: true,
               pty: false
             })

    on_exit(fn ->
      _ = Jido.Harness.Process.kill(process_id)
      _ = Jido.Harness.Process.prune(process_id)
    end)

    assert :ok = Jido.Harness.Process.send_input(process_id, "stdin-through-wrapper\n")
    assert :ok = Jido.Harness.Process.close_input(process_id)

    assert {:ok, %{state: :exited, exit_status: 0}} =
             Jido.Harness.Process.await(process_id, 5_000)

    assert {:ok, events} = Jido.Harness.Process.replay(process_id, limit: 20)

    output =
      events
      |> Enum.filter(&(&1.type == :stdout))
      |> Enum.map_join(& &1.data)

    assert output == "stdin-through-wrapper\n"
    assert :ok = Jido.Harness.Process.prune(process_id)
  end

  defp run_runtime_probe(
         runtime_mode,
         service_log,
         provider,
         workspace,
         runtime_state_dir,
         provider_dir,
         provider_file,
         provider_pid_file,
         sentinel
       ) do
    mix = System.find_executable("mix") || raise "mix executable not found"

    mix_command = [
      mix,
      "run",
      "--no-start",
      "--no-compile",
      @probe,
      "--",
      provider,
      workspace,
      runtime_state_dir,
      provider_dir,
      provider_file,
      provider_pid_file,
      runtime_mode,
      sentinel
    ]

    {script, argv} =
      case runtime_mode do
        "ring" ->
          {~S(umask 077 || exit 126; exec "$@"), ["ouroboros-ring" | mix_command]}

        "service" ->
          {~S(umask 077 || exit 126; output=$1; shift; exec "$@" >>"$output" 2>&1),
           ["ouroboros-service", service_log | mix_command]}
      end

    System.cmd("/bin/sh", ["-c", script | argv],
      cd: @repo_root,
      env: [{"MIX_ENV", "test"}],
      stderr_to_stdout: true
    )
  end

  defp write_provider!(path, runtime_mode) do
    File.write!(
      path,
      """
      #!/bin/sh
      set -eu
      mkdir "$1"
      printf '%s' "$4" > "$2"
      printf '%s\n' "$$" > "$3"
      printf 'provider-ok:%s\n' #{runtime_mode}
      """
    )

    File.chmod!(path, 0o700)
  end

  defp write_cancellable_provider!(provider, descendant) do
    File.write!(
      descendant,
      """
      #!/bin/sh
      trap 'exit 0' TERM HUP
      while :; do sleep 1; done
      """
    )

    File.write!(
      provider,
      """
      #!/bin/sh
      set -eu
      trap ':' INT
      trap 'exit 0' TERM HUP
      "#{descendant}" &
      descendant_pid=$!
      printf '%s\n' "$$" > "$1"
      printf '%s\n' "$descendant_pid" > "$2"
      while :; do sleep 1; done
      """
    )

    File.chmod!(descendant, 0o700)
    File.chmod!(provider, 0o700)
  end

  defp read_pid(path) do
    case File.read(path) do
      {:ok, contents} ->
        case contents |> String.trim() |> Integer.parse() do
          {pid, ""} -> pid
          _other -> nil
        end

      {:error, :enoent} ->
        nil
    end
  end

  defp eventually_value(fun, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 5_000

    case fun.() do
      value when value in [false, nil] ->
        if System.monotonic_time(:millisecond) < deadline do
          Process.sleep(20)
          eventually_value(fun, deadline)
        else
          flunk("condition did not become true before its deadline")
        end

      value ->
        value
    end
  end

  defp os_process_alive?(pid) do
    match?(
      {_, 0},
      System.cmd("/bin/kill", ["-0", Integer.to_string(pid)], stderr_to_stdout: true)
    )
  end

  defp os_process_group(pid) do
    case System.cmd("/bin/ps", ["-p", Integer.to_string(pid), "-o", "pgid="],
           stderr_to_stdout: true
         ) do
      {output, 0} -> output |> String.trim() |> String.to_integer()
      {_output, _status} -> nil
    end
  end

  defp private_mode(path), do: File.stat!(path).mode &&& 0o777
end
