defmodule OuroFleet.Reader do
  @moduledoc "One bounded read from the job's own run. No store or selector overrides."
  def args(run, [verb | flags]) when verb in ["show", "verify", "query", "tail"] do
    {switches, values} =
      case verb do
        "show" ->
          {["--json", "--with-transcript"], []}

        "verify" ->
          {["--json"], []}

        "query" ->
          {["--json", "--execs", "--paths", "--hosts", "--denials"],
           ["--stage", "--since", "--until", "--cursor", "--limit"]}

        "tail" ->
          {["--json"], ["--cursor"]}
      end

    if length(flags) <= 32 and valid?(flags, switches, values) do
      selector = if verb == "query", do: ["--run", run], else: [run]
      {:ok, [verb] ++ selector ++ Enum.reject(flags, &(&1 == "--json")) ++ ["--json"]}
    else
      {:error, "invalid_reader_flags"}
    end
  end

  def args(_, _), do: {:error, "invalid_reader"}
  defp valid?([], _, _), do: true

  defp valid?([flag | rest], switches, values) when is_binary(flag) do
    cond do
      flag in switches ->
        valid?(rest, switches -- [flag], values)

      flag in values ->
        case rest do
          [value | tail] when is_binary(value) and byte_size(value) in 1..8192 ->
            not String.starts_with?(value, "-") and not String.contains?(value, <<0>>) and
              valid?(tail, switches, values -- [flag])

          _ ->
            false
        end

      true ->
        false
    end
  end

  defp valid?(_, _, _), do: false
end
