defmodule Ouroboros.CodeIntel.Memory do
  @moduledoc """
  Reads the resident-set size of a language server's OS process.

  `ps -o rss= -p <pid>` is the only reader portable across the platforms this runtime
  targets, and it is a program that can hang, so the call is bounded and every failure
  answers `:unknown` rather than raising. An unknown RSS is treated by the pool as "not
  over the limit": a watchdog that cannot measure must not start killing servers.

  The pid is formatted from an integer, never interpolated from a string, and `ps` is
  resolved on PATH — there is no shell in this path.
  """

  @timeout_ms 2_000

  @spec rss_bytes(pos_integer()) :: {:ok, non_neg_integer()} | :unknown
  def rss_bytes(os_pid) when is_integer(os_pid) and os_pid > 0 do
    case System.find_executable("ps") do
      nil ->
        :unknown

      executable ->
        task =
          Task.async(fn ->
            System.cmd(executable, ["-o", "rss=", "-p", Integer.to_string(os_pid)],
              stderr_to_stdout: true
            )
          end)

        case Task.yield(task, @timeout_ms) || Task.shutdown(task, :brutal_kill) do
          {:ok, {output, 0}} -> parse(output)
          _other -> :unknown
        end
    end
  end

  def rss_bytes(_os_pid), do: :unknown

  # `ps` reports kilobytes on every platform this runs on.
  defp parse(output) do
    case output |> String.trim() |> Integer.parse() do
      {kilobytes, _rest} when kilobytes >= 0 -> {:ok, kilobytes * 1024}
      _other -> :unknown
    end
  end
end
