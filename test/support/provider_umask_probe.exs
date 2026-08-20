defmodule Ouroboros.Test.ProviderUmaskProbe do
  @moduledoc false

  def run do
    argv =
      case System.argv() do
        ["--" | rest] -> rest
        rest -> rest
      end

    [
      provider,
      workspace,
      runtime_state_dir,
      provider_dir,
      provider_file,
      provider_pid_file,
      runtime_mode,
      sentinel
    ] = argv

    File.mkdir!(runtime_state_dir)
    File.write!(Path.join(runtime_state_dir, "beam-owned-state"), "private")

    {:ok, _started} = Application.ensure_all_started(:jido_harness)

    {:ok, process_id} =
      Jido.Harness.Process.start(%{
        executable: provider,
        argv: [provider_dir, provider_file, provider_pid_file, sentinel],
        cwd: workspace,
        stdin: false,
        pty: false,
        runtime_timeout_ms: 5_000,
        metadata: %{"runtime_mode" => runtime_mode}
      })

    {:ok, info} = Jido.Harness.Process.await(process_id, 10_000)

    ensure!(info.state == :exited, "provider state was #{inspect(info.state)}")
    ensure!(info.exit_status == 0, "provider exit status was #{inspect(info.exit_status)}")
    ensure!(info.metadata == %{"runtime_mode" => runtime_mode}, "provider metadata changed")

    provider_pid =
      provider_pid_file
      |> File.read!()
      |> String.trim()
      |> String.to_integer()

    ensure!(provider_pid == info.os_pid, "wrapper did not exec into the managed process")

    {:ok, events} = Jido.Harness.Process.replay(process_id, limit: 20)

    ensure!(
      Enum.any?(events, fn event ->
        event.type == :stdout and is_binary(event.data) and
          String.contains?(event.data, "provider-ok:#{runtime_mode}")
      end),
      "provider stdout was not retained"
    )

    IO.puts("provider-umask-probe-ok:#{runtime_mode}")
  end

  defp ensure!(true, _message), do: :ok
  defp ensure!(false, message), do: raise(message)
end

Ouroboros.Test.ProviderUmaskProbe.run()
