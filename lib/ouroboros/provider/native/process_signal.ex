defmodule Ouroboros.Provider.Native.ProcessSignal do
  @moduledoc false

  # Exec starts commands in a fresh process group. Signal the whole group so child
  # shells and tools cannot survive interruption of their immediate parent.
  def signal(os_pid, signal) when is_integer(os_pid) do
    case :os.type() do
      {:unix, _name} -> signal_process_group(os_pid, signal)
      _other -> :exec.kill(os_pid, signal)
    end
  end

  def signal(process, signal), do: :exec.kill(process, signal)

  defp signal_process_group(os_pid, signal) do
    executable = System.find_executable("kill") || "/bin/kill"

    case System.cmd(executable, ["-s", signal_name(signal), "--", "-#{os_pid}"],
           stderr_to_stdout: true
         ) do
      {_output, 0} -> :ok
      {output, status} -> {:error, {:signal_failed, signal, status, String.trim(output)}}
    end
  rescue
    error -> {:error, {:signal_failed, signal, error}}
  end

  defp signal_name(:sigint), do: "INT"
  defp signal_name(:sigterm), do: "TERM"
  defp signal_name(:sigkill), do: "KILL"
  defp signal_name(signal) when is_integer(signal), do: Integer.to_string(signal)
end
