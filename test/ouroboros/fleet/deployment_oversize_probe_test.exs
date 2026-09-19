defmodule Ouroboros.Fleet.DeploymentOversizeProbeTest do
  @moduledoc """
  What the port actually delivers around `{:line, 1_048_576}`, and what
  `Ouroboros.Fleet.Deployment.Worker`'s two `oversize?` clauses then do with the frames that
  follow.

  The worker refuses the first `{:noeol, …}` piece and then swallows the **next** `{:eol, …}`
  message, on the reasoning that it is the tail of the line already refused. That reasoning
  holds only where an over-cap line is delivered as one or more `{:noeol, …}` followed by
  exactly one `{:eol, …}` carrying its tail. This probes the boundary directly: a body of
  `L - 1`, `L` and `L + 1` bytes, each followed by two real frames.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log
  @moduletag :ke_review

  alias Ouroboros.Fleet.Deployment.Frame

  @cap Frame.max_bytes()

  for {label, body} <- [
        {"one under the cap", @cap - 1},
        {"exactly the cap", @cap},
        {"one over the cap", @cap + 1}
      ] do
    @label label
    @body body

    test "a line of #{label} (#{body} bytes) does not eat the frames after it" do
      {shapes, kept} = run(@body)

      frames =
        kept
        |> Enum.map(&Frame.decode/1)
        |> Enum.flat_map(fn
          {:ok, frame} -> [Frame.event(frame)]
          {:error, _reason} -> []
        end)

      assert frames == ["step", "done"], """
      A body of #{@body} bytes (#{@label}) plus its newline arrived as:

          #{inspect(shapes)}

      `Worker.handle_info/2` drops exactly one `{:eol, _}` after a `{:noeol, _}`. With this
      split the frames it would have kept are #{inspect(frames)} rather than ["step", "done"],
      so a program — or a target whose output a program echoes into one `log` line — can
      make the runtime miss the frame that follows, up to and including the `done` frame
      that says the operation failed.
      """
    end
  end

  # The port's message shapes, and the lines the worker's own state machine would have kept.
  defp run(body_bytes) do
    script = Path.join(System.tmp_dir!(), "okdover#{System.unique_integer([:positive])}.sh")

    File.write!(script, """
    #!/bin/sh
    awk 'BEGIN { for (i = 0; i < #{body_bytes}; i++) printf "x"; printf "\\n" }'
    printf '%s\\n' '{"event":"step","step":"install","state":"ok","detail":null}'
    printf '%s\\n' '{"event":"done","state":"failed","summary":"after the long line"}'
    """)

    File.chmod!(script, 0o755)
    on_exit(fn -> File.rm(script) end)

    port =
      Port.open({:spawn_executable, script}, [
        :binary,
        :exit_status,
        :hide,
        {:line, @cap}
      ])

    shapes = collect(port, System.monotonic_time(:millisecond) + 20_000, [])

    {_oversize?, kept} =
      Enum.reduce(shapes, {false, []}, fn
        {:noeol, _size}, {_any, kept} -> {true, kept}
        {:eol, _size, _body}, {true, kept} -> {false, kept}
        {:eol, size, body}, {false, kept} when size <= @cap -> {false, kept ++ [body]}
        {:eol, _size, _body}, {false, kept} -> {false, kept}
      end)

    {Enum.map(shapes, fn
       {:noeol, size} -> {:noeol, size}
       {:eol, size, _body} -> {:eol, size}
     end), kept}
  end

  defp collect(port, deadline, acc) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, {:eol, line}}} ->
        collect(port, deadline, acc ++ [{:eol, byte_size(line), line}])

      {^port, {:data, {:noeol, chunk}}} ->
        collect(port, deadline, acc ++ [{:noeol, byte_size(chunk)}])

      {^port, {:exit_status, _status}} ->
        acc
    after
      remaining -> acc
    end
  end
end
