defmodule Ouroboros.Provider.Native.Tools do
  @moduledoc """
  The tool set, its schemas, and the classification the permission engine reasons about.

  Pi's four — `read`, `write`, `edit`, `bash` — plus `plan`, which produces the
  `plan_updated` event and touches nothing. Four is a deliberate floor, not a stub:
  Pi ships exactly these and is "the most token-efficient coding harness"; `grep`,
  `glob`, `web_fetch` and the rest are D2's later groups and each one costs context in
  every request whether it is used or not (R3 §8d, Advanced tool use).

  The schemas the model sees come from each tool's `Jido.Action` schema, converted by
  `Jido.AI.ToolAdapter.from_action/2`. That conversion is the only part of `jido_ai`
  this provider uses, and it is used precisely because a hand-written JSON Schema beside
  a `Jido.Action` schema is two declarations that drift.

  `classify/2` is what the permission engine is asked about: the tool name, the mode it
  needs (`:read`, `:write`, `:execute`), the paths it touches, and the command when
  there is one. Nothing here decides — it describes.
  """

  alias Jido.AI.ToolAdapter
  alias Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools.Bash
  alias Ouroboros.Provider.Native.Tools.Edit
  alias Ouroboros.Provider.Native.Tools.Plan
  alias Ouroboros.Provider.Native.Tools.Read
  alias Ouroboros.Provider.Native.Tools.Write

  # 25k tokens is Claude Code's documented cap on a single tool result and the number
  # Anthropic's own guidance recommends; 100 KB is a generous byte proxy that no tool
  # here reaches under its own limits, and it is the last line of defence if one does.
  @max_result_bytes 100 * 1024

  @doc "Every tool module, in the order the model sees them."
  @spec modules() :: [module()]
  def modules, do: [Read, Write, Edit, Bash, Plan]

  @doc """
  The tool specs for one session, after `allowed_tools`/`disallowed_tools`.

  `disallowed_tools` always wins. An empty or absent `allowed_tools` means every tool,
  which matches how the option reads everywhere else in this runtime.
  """
  @spec specs(list() | nil, list() | nil) :: [Model.tool_spec()]
  def specs(allowed, disallowed) do
    allowed = normalize(allowed)
    disallowed = normalize(disallowed)

    modules()
    |> Enum.filter(fn module ->
      name = module.name()
      name not in disallowed and (allowed == [] or name in allowed)
    end)
    |> Enum.map(&spec/1)
  end

  @doc "One tool's spec as the model sees it."
  @spec spec(module()) :: Model.tool_spec()
  def spec(module) do
    tool = ToolAdapter.from_action(module)

    %{
      name: tool.name,
      description: tool.description,
      parameters: tool.parameter_schema
    }
  end

  @doc "The module a tool name resolves to, honouring the session's tool filters."
  @spec lookup(String.t(), list() | nil, list() | nil) :: {:ok, module()} | {:error, :unknown_tool}
  def lookup(name, allowed, disallowed) do
    allowed = normalize(allowed)
    disallowed = normalize(disallowed)

    module = Enum.find(modules(), &(&1.name() == name))
    visible? = name not in disallowed and (allowed == [] or name in allowed)

    # A filtered tool answers exactly like a tool that does not exist. The model was
    # never shown it in the schema list, so "unknown" is the truthful answer and does
    # not teach it that a hidden tool is worth retrying.
    if module && visible?, do: {:ok, module}, else: {:error, :unknown_tool}
  end

  @doc """
  Describes one attempted call for the permission engine.

  Paths are resolved with the session's own scope, so a request the engine sees is the
  canonical path the tool would actually touch and not the string the model typed. A
  path that will not resolve is reported unresolved: the engine may still deny it, and
  the tool refuses it a moment later anyway.
  """
  @spec classify(String.t(), map(), map()) :: %{
          tool: String.t(),
          mode: :read | :write | :execute,
          paths: [String.t()],
          command: String.t() | nil
        }
  def classify(name, input, scope) do
    %{
      tool: name,
      mode: mode(name),
      paths: paths(name, input, scope),
      command: command(name, input)
    }
  end

  defp mode("bash"), do: :execute
  defp mode(name) when name in ["write", "edit"], do: :write
  defp mode(_name), do: :read

  defp paths(name, input, scope) when name in ["read", "write", "edit"] do
    case Map.get(input, "path") do
      path when is_binary(path) ->
        case Paths.resolve(path, scope) do
          {:ok, resolved} -> [resolved]
          {:error, _reason} -> [path]
        end

      _absent ->
        []
    end
  end

  defp paths(_name, _input, _scope), do: []

  defp command("bash", input) do
    case Map.get(input, "command") do
      command when is_binary(command) -> command
      _absent -> nil
    end
  end

  defp command(_name, _input), do: nil

  @doc """
  Runs one tool and normalizes whatever it returned into the loop's result shape.

  A tool that raises becomes an error *result*, not a crashed turn: the model gets to
  see what went wrong and try something else, which is the whole reason tool errors are
  in-band. A tool that runs past its timeout is killed and reported the same way.
  """
  @spec execute(module(), map(), map(), timeout()) :: map()
  def execute(module, input, context, timeout_ms) do
    task =
      Task.async(fn ->
        try do
          module.run(atomize(module, input), context)
        rescue
          error -> {:error, {:tool_raised, Exception.message(error)}}
        catch
          :exit, reason -> {:error, {:tool_exited, inspect(reason)}}
          value -> {:error, {:tool_threw, inspect(value)}}
        end
      end)

    case Task.yield(task, timeout_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> normalize_result(result)
      nil -> %{output: "#{module.name()} timed out after #{timeout_ms} ms.", is_error: true}
      {:exit, reason} -> %{output: "#{module.name()} crashed: #{inspect(reason)}", is_error: true}
    end
  end

  # `Jido.Action` schemas validate atom keys; the model sends strings. Only keys the
  # tool actually declares are converted, so a hallucinated argument is dropped rather
  # than becoming a new atom on this node.
  defp atomize(module, input) do
    declared = Keyword.keys(module.schema())

    Enum.reduce(declared, %{}, fn key, acc ->
      case Map.fetch(input, Atom.to_string(key)) do
        {:ok, value} -> Map.put(acc, key, value)
        :error -> maybe_default(acc, module, key)
      end
    end)
  end

  defp maybe_default(acc, module, key) do
    case module.schema() |> Keyword.get(key, []) |> Keyword.fetch(:default) do
      {:ok, default} -> Map.put(acc, key, default)
      :error -> acc
    end
  end

  defp normalize_result({:ok, %{output: output} = result}) do
    %{
      output: bound(to_string(output)),
      is_error: Map.get(result, :is_error, false) == true,
      changes: Map.get(result, :changes, []),
      reads: Map.get(result, :reads, %{}),
      plan: Map.get(result, :plan)
    }
  end

  defp normalize_result({:ok, result}) when is_map(result),
    do: %{output: bound(inspect(result)), is_error: false, changes: [], reads: %{}, plan: nil}

  defp normalize_result({:error, reason}),
    do: %{output: bound(describe(reason)), is_error: true, changes: [], reads: %{}, plan: nil}

  defp normalize_result(other),
    do: %{output: bound(inspect(other)), is_error: true, changes: [], reads: %{}, plan: nil}

  defp describe({:tool_raised, message}), do: "tool raised: #{message}"
  defp describe({:tool_exited, reason}), do: "tool exited: #{reason}"
  defp describe({:tool_threw, value}), do: "tool threw: #{value}"

  defp describe(%{__exception__: true} = error), do: Exception.message(error)
  defp describe(reason) when is_binary(reason), do: reason
  defp describe(reason), do: inspect(reason)

  defp bound(output) when byte_size(output) <= @max_result_bytes, do: output

  defp bound(output) do
    binary_part(output, 0, @max_result_bytes) <>
      "\n… tool result truncated at #{@max_result_bytes} bytes"
  end

  defp normalize(nil), do: []

  defp normalize(list) when is_list(list),
    do: list |> Enum.filter(&is_binary/1) |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))

  defp normalize(_other), do: []
end
