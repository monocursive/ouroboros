defmodule Ouroboros.Provider.Native.Tools do
  @moduledoc """
  The tool set, its schemas, and the classification the permission engine reasons about.

  D1 shipped Pi's four — `read`, `write`, `edit`, `bash` — plus `plan`. D2 completes the
  set every leader has (R3 §8a): search (`grep`, `glob`, `ls`), a second edit format
  (`apply_patch`, V4A), the network (`web_fetch`), a way to ask (`ask_user`), the Agent
  Skills loader (`skill`), and the language server (`code_intel`). `todo` is an alias of
  `plan` rather than a second tool, because two names for one behaviour in the schema
  list costs context in every request and teaches the model that they differ.

  The schemas the model sees come from each tool's `Jido.Action` schema, converted by
  `Jido.AI.ToolAdapter.from_action/2`. That conversion is the only part of `jido_ai`
  this provider uses, and it is used precisely because a hand-written JSON Schema beside
  a `Jido.Action` schema is two declarations that drift.

  A module may override its description per session by exporting `description/1` — one
  tool does, `skill`, because the Agent Skills convention is names-in-the-prompt and
  bodies-on-demand, and the names are a property of the workspace rather than of the
  code. A module may also declare itself `interactive?/0`, which means the loop answers
  it through the approval path instead of running it in the tool task; `ask_user` is the
  only one, and it is how a question can block on a human.

  `classify/3` is what the permission engine is asked about: the tool name, the mode it
  needs (`:read`, `:write`, `:execute`, `:network`), the paths it touches, the domains it
  reaches, and the command when there is one. Nothing here decides — it describes.
  """

  alias Jido.AI.ToolAdapter
  alias Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools.ApplyPatch
  alias Ouroboros.Provider.Native.Tools.AskUser
  alias Ouroboros.Provider.Native.Tools.Bash
  alias Ouroboros.Provider.Native.Tools.CodeIntel
  alias Ouroboros.Provider.Native.Tools.Edit
  alias Ouroboros.Provider.Native.Tools.Glob
  alias Ouroboros.Provider.Native.Tools.Grep
  alias Ouroboros.Provider.Native.Tools.Ls
  alias Ouroboros.Provider.Native.Tools.Plan
  alias Ouroboros.Provider.Native.Tools.Read
  alias Ouroboros.Provider.Native.Tools.Skill
  alias Ouroboros.Provider.Native.Tools.WebFetch
  alias Ouroboros.Provider.Native.Tools.Write

  # 25k tokens is Claude Code's documented cap on a single tool result and the number
  # Anthropic's own guidance recommends; 100 KB is a generous byte proxy that no tool
  # here reaches under its own limits, and it is the last line of defence if one does.
  @max_result_bytes 100 * 1024

  # One name resolves to another module. Kept to aliases the field has actually
  # standardised on, so this does not become a place where hallucinated names are
  # forgiven into working.
  @aliases %{"todo" => "plan", "todowrite" => "plan"}

  @doc "Every tool module, in the order the model sees them."
  @spec modules() :: [module()]
  def modules,
    do: [
      Read,
      Write,
      Edit,
      ApplyPatch,
      Bash,
      Grep,
      Glob,
      Ls,
      WebFetch,
      CodeIntel,
      AskUser,
      Skill,
      Plan
    ]

  @doc "Names this tool set accepts that are not a module's own name."
  @spec aliases() :: %{String.t() => String.t()}
  def aliases, do: @aliases

  @doc """
  The tool specs for one session, after `allowed_tools`/`disallowed_tools`.

  `disallowed_tools` always wins. An empty or absent `allowed_tools` means every tool,
  which matches how the option reads everywhere else in this runtime.

  `opts` may carry `workspace:` and `context_window:`, which the tools that build their
  description per session read. Omitting them is not an error — the static description
  stands — so a caller that only wants the names, like the system prompt's tool list, is
  not obliged to know about them.
  """
  @spec specs(list() | nil, list() | nil, keyword()) :: [Model.tool_spec()]
  def specs(allowed, disallowed, opts \\ []) do
    allowed = normalize(allowed)
    disallowed = normalize(disallowed)

    modules()
    |> Enum.filter(fn module ->
      name = module.name()
      name not in disallowed and (allowed == [] or name in allowed)
    end)
    |> Enum.map(&spec(&1, opts))
  end

  @doc "One tool's spec as the model sees it."
  @spec spec(module(), keyword()) :: Model.tool_spec()
  def spec(module, opts \\ []) do
    tool = ToolAdapter.from_action(module)

    %{
      name: tool.name,
      description: description(module, tool.description, opts),
      parameters: tool.parameter_schema
    }
  end

  defp description(module, static, opts) do
    if function_exported?(module, :description, 1) do
      case module.description(opts) do
        text when is_binary(text) and text != "" -> text
        _unusable -> static
      end
    else
      static
    end
  rescue
    _error -> static
  end

  @doc """
  The module a tool name resolves to, honouring aliases and the session's tool filters.

  A filter is applied to both the name the model used and the name it resolves to, so
  `disallowed_tools: ["plan"]` hides `todo` as well — a filter that an alias walks around
  is not a filter.
  """
  @spec lookup(String.t(), list() | nil, list() | nil) ::
          {:ok, module()} | {:error, :unknown_tool}
  def lookup(name, allowed, disallowed) when is_binary(name) do
    allowed = normalize(allowed)
    disallowed = normalize(disallowed)
    canonical = canonical(name)

    module = Enum.find(modules(), &(&1.name() == canonical))

    visible? =
      name not in disallowed and canonical not in disallowed and
        (allowed == [] or name in allowed or canonical in allowed)

    # A filtered tool answers exactly like a tool that does not exist. The model was
    # never shown it in the schema list, so "unknown" is the truthful answer and does
    # not teach it that a hidden tool is worth retrying.
    if module && visible?, do: {:ok, module}, else: {:error, :unknown_tool}
  end

  def lookup(_name, _allowed, _disallowed), do: {:error, :unknown_tool}

  @doc "The name a tool name resolves to after aliases."
  @spec canonical(String.t()) :: String.t()
  def canonical(name) when is_binary(name), do: Map.get(@aliases, name, name)

  @doc "Whether the loop answers this tool through the approval path rather than a task."
  @spec interactive?(module()) :: boolean()
  def interactive?(module) do
    function_exported?(module, :interactive?, 0) and module.interactive?() == true
  end

  @doc """
  Describes one attempted call for the permission engine.

  Paths are resolved with the session's own scope, so a request the engine sees is the
  canonical path the tool would actually touch and not the string the model typed. A
  path that will not resolve is reported unresolved: the engine may still deny it, and
  the tool refuses it a moment later anyway.

  `write_paths` is the subset the call would *change*. The loop snapshots exactly those
  before the tool runs, which is what makes rewind byte-exact for a multi-file patch and
  for a language-server rename.
  """
  @spec classify(String.t(), map(), map()) :: %{
          tool: String.t(),
          mode: :read | :write | :execute | :network,
          paths: [String.t()],
          write_paths: [String.t()],
          domains: [String.t()],
          command: String.t() | nil
        }
  def classify(name, input, scope) do
    canonical = canonical(name)
    input = if is_map(input), do: input, else: %{}
    write_paths = write_paths(canonical, input, scope)

    %{
      tool: canonical,
      mode: mode(canonical, input),
      paths: Enum.uniq(paths(canonical, input, scope) ++ write_paths),
      write_paths: write_paths,
      domains: domains(canonical, input),
      command: command(canonical, input)
    }
  end

  defp mode("bash", _input), do: :execute
  defp mode("web_fetch", _input), do: :network
  defp mode(name, _input) when name in ["write", "edit", "apply_patch"], do: :write

  defp mode("code_intel", input) do
    if CodeIntel.writing?(Map.get(input, "operation")), do: :write, else: :read
  end

  defp mode(_name, _input), do: :read

  defp paths(name, input, scope) when name in ["read", "grep", "glob", "ls", "code_intel"] do
    case Map.get(input, "path") do
      path when is_binary(path) and path != "" -> [resolve(path, scope)]
      _absent -> []
    end
  end

  defp paths(_name, _input, _scope), do: []

  defp write_paths(name, input, scope) when name in ["write", "edit"] do
    case Map.get(input, "path") do
      path when is_binary(path) -> [resolve(path, scope)]
      _absent -> []
    end
  end

  defp write_paths("apply_patch", input, scope), do: ApplyPatch.paths(input, scope)
  defp write_paths("code_intel", input, scope), do: CodeIntel.write_paths(input, scope)
  defp write_paths(_name, _input, _scope), do: []

  defp resolve(path, scope) do
    case Paths.resolve(path, scope) do
      {:ok, resolved} -> resolved
      {:error, _reason} -> path
    end
  end

  defp domains("web_fetch", input) do
    case WebFetch.host(Map.get(input, "url")) do
      host when is_binary(host) -> [host]
      nil -> []
    end
  end

  defp domains(_name, _input), do: []

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
    input = if is_map(input), do: input, else: %{}

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

  @doc """
  Normalises a result a tool produced outside `execute/4`.

  `ask_user` is the one tool the loop answers itself, on the approval channel, so its
  result never passes through the task runner and still has to arrive in the same shape
  as every other tool's.
  """
  @spec normalize_result_of(map()) :: map()
  def normalize_result_of(result) when is_map(result), do: normalize_result({:ok, result})

  @doc false
  @spec normalize_result(term()) :: map()
  def normalize_result({:ok, %{output: output} = result}) do
    %{
      output: bound(to_string(output)),
      is_error: Map.get(result, :is_error, false) == true,
      changes: Map.get(result, :changes, []),
      reads: Map.get(result, :reads, %{}),
      plan: Map.get(result, :plan)
    }
  end

  def normalize_result({:ok, result}) when is_map(result),
    do: %{output: bound(inspect(result)), is_error: false, changes: [], reads: %{}, plan: nil}

  def normalize_result({:error, reason}),
    do: %{output: bound(describe(reason)), is_error: true, changes: [], reads: %{}, plan: nil}

  def normalize_result(other),
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
