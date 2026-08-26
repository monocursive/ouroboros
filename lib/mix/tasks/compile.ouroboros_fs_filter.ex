defmodule Mix.Tasks.Compile.OuroborosFsFilter do
  @moduledoc false
  use Mix.Task.Compiler

  @source "c_src/fs_filter.c"
  @library "libouro_fs_filter.so"

  def run(_args) do
    if linux?() do
      compile()
    else
      {:noop, []}
    end
  end

  defp compile do
    dest_dir = Path.join(Mix.Project.app_path(), "priv/native")
    dest = Path.join(dest_dir, @library)
    source = Path.expand(@source)

    cond do
      not File.exists?(source) ->
        {:noop, []}

      File.exists?(dest) and newer?(dest, source) ->
        {:noop, []}

      cc() == nil ->
        {:noop, []}

      true ->
        File.mkdir_p!(dest_dir)

        {output, status} =
          System.cmd(cc(), ["-shared", "-fPIC", "-ldl", "-o", dest, source],
            stderr_to_stdout: true
          )

        if status == 0 do
          {:ok, []}
        else
          Mix.shell().error("ouroboros fs filter: cc failed\n#{output}")
          {:noop, []}
        end
    end
  end

  defp linux?, do: match?({:unix, :linux}, :os.type())

  defp cc do
    Enum.find(["cc", "gcc", "clang"], &(System.find_executable(&1) != nil))
  end

  defp newer?(left, right) do
    case {File.stat(left), File.stat(right)} do
      {{:ok, a}, {:ok, b}} -> a.mtime >= b.mtime
      _missing -> false
    end
  end
end
