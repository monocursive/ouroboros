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

  ## The one dynamic seam

  D4 adds tools this module cannot enumerate at compile time: every `mcp__<server>__<tool>`
  an MCP server advertises. They enter through exactly one seam and nothing outside this
  file changed to admit them. `specs/3` appends them after the static fifteen, `lookup/3`
  resolves such a name to `{Tools.Mcp, name}` instead of a bare module, and `execute/4`
  and `interactive?/1` accept that pair. The loop treats what `lookup/3` returns as
  opaque — it only ever hands it back to these two functions — so carrying the resolved
  name alongside the module needed no new argument anywhere else, and no per-server
  module (and therefore no per-server atom) is generated from a remote tool list.
  """

  alias Jido.AI.ToolAdapter
  alias Ouroboros.Provider.Native.Desktop
  alias Ouroboros.Provider.Native.Mcp
  alias Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools.Agent, as: AgentTool
  alias Ouroboros.Provider.Native.Tools.AgentResult
  alias Ouroboros.Provider.Native.Tools.ApplyPatch
  alias Ouroboros.Provider.Native.Tools.AskUser
  alias Ouroboros.Provider.Native.Tools.Bash
  alias Ouroboros.Provider.Native.Tools.CodeIntel
  alias Ouroboros.Provider.Native.Tools.DesktopAct
  alias Ouroboros.Provider.Native.Tools.DesktopState
  alias Ouroboros.Provider.Native.Tools.Edit
  alias Ouroboros.Provider.Native.Tools.Glob
  alias Ouroboros.Provider.Native.Tools.Grep
  alias Ouroboros.Provider.Native.Tools.Ls
  alias Ouroboros.Provider.Native.Tools.Mcp, as: McpTool
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
      AgentTool,
      AgentResult,
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

  `subagent_depth:` is G3's cap made visible rather than only enforced: a session already
  at `Tools.Agent.max_depth/0` is shown no `agent` and no `agent_result` at all. A cap the
  model can read off its own tool list is one it does not spend a call discovering, and
  the loop refuses the name as well for the session that invents it anyway.

  MCP tools follow the static ones, and only when `workspace:` was given: a server is
  configured for a workspace, so a caller that named no workspace has not asked for any.
  They come last because a cached prefix is cheapest when the part that never changes is
  first, and the MCP list is the part that can differ between two sessions.
  """
  @spec specs(list() | nil, list() | nil, keyword()) :: [Model.tool_spec()]
  def specs(allowed, disallowed, opts \\ []) do
    allowed = normalize(allowed)
    disallowed = normalize(disallowed)

    hidden = depth_hidden(opts)

    static =
      modules()
      |> Enum.filter(fn module ->
        name = module.name()

        name not in hidden and name not in disallowed and
          (allowed == [] or name in allowed)
      end)
      |> Enum.map(&spec(&1, opts))

    static ++ desktop_specs(allowed, disallowed, opts) ++ mcp_specs(allowed, disallowed, opts)
  end

  @doc """
  The tool names a session at `depth` may not be shown, G3's depth cap in the schema list.

  Depth 0 is a session an operator started. Its children are 1, theirs are 2, and 2 is
  the cap: a grandchild is shown neither `agent` nor `agent_result`, because there is
  nothing it could collect either.
  """
  @spec depth_hidden(keyword()) :: [String.t()]
  def depth_hidden(opts) do
    case Keyword.get(opts, :subagent_depth) do
      depth when is_integer(depth) and depth >= 0 ->
        if depth >= AgentTool.max_depth(), do: ["agent", "agent_result"], else: []

      _absent ->
        []
    end
  end

  # Computer Use's two tools sit after the static prefix and before MCP (D1, §5.1), and
  # only when the feature is genuinely usable on this node *and* a workspace was given —
  # the same host-local gate MCP uses. When it is off `Native.Desktop.enabled?/0` is false
  # and the names never appear, so the model is not taught a name it cannot use (D9). The
  # `allowed`/`disallowed` filters apply by tool name exactly as they do to a static tool.
  defp desktop_specs(allowed, disallowed, opts) do
    with root when is_binary(root) and root != "" <- Keyword.get(opts, :workspace),
         true <- Desktop.enabled?() do
      desktop_modules()
      |> Enum.filter(fn module ->
        name = module.name()
        name not in disallowed and (allowed == [] or name in allowed)
      end)
      |> Enum.map(&spec(&1, opts))
    else
      _off_or_no_workspace -> []
    end
  end

  defp desktop_modules do
    [DesktopState] ++ if(Desktop.act_enabled?(), do: [DesktopAct], else: [])
  end

  # The filters apply to an MCP tool exactly as they apply to a static one, on its full
  # `mcp__server__tool` name. `disallowed_tools: ["mcp__github__create_issue"]` therefore
  # hides that one tool and leaves the rest of the server, which is the granularity an
  # operator writing the list is thinking in.
  defp mcp_specs(allowed, disallowed, opts) do
    case Keyword.get(opts, :workspace) do
      root when is_binary(root) and root != "" ->
        root
        |> Mcp.specs(opts)
        |> Enum.filter(fn %{name: name} ->
          name not in disallowed and (allowed == [] or name in allowed)
        end)

      _absent ->
        []
    end
  end

  @doc "One tool's spec as the model sees it."
  @spec spec(module(), keyword()) :: Model.tool_spec()
  def spec(module, opts \\ []) do
    tool = ToolAdapter.from_action(module)

    %{
      name: tool.name,
      description: description(module, tool.description, opts),
      parameters: model_schema(module, tool.parameter_schema)
    }
  end

  defp model_schema(module, generated) do
    if function_exported?(module, :model_schema, 0), do: module.model_schema(), else: generated
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

  An `mcp__<server>__<tool>` name resolves to `{Tools.Mcp, name}` when some live server
  on this node advertises it. That check is deliberately node-wide rather than
  workspace-exact, because this function is given a name and nothing else; the exact
  resolution happens inside `Tools.Mcp`, which has the session's scope. A name no server
  advertises is `:unknown_tool`, like any other invention.
  """
  @spec lookup(String.t(), list() | nil, list() | nil) ::
          {:ok, module() | {module(), String.t()}} | {:error, :unknown_tool}
  def lookup(name, allowed, disallowed) when is_binary(name) do
    allowed = normalize(allowed)
    disallowed = normalize(disallowed)
    canonical = canonical(name)

    module = resolve_module(canonical)

    visible? =
      name not in disallowed and canonical not in disallowed and
        (allowed == [] or name in allowed or canonical in allowed)

    # A filtered tool answers exactly like a tool that does not exist. The model was
    # never shown it in the schema list, so "unknown" is the truthful answer and does
    # not teach it that a hidden tool is worth retrying.
    if module && visible?, do: {:ok, module}, else: {:error, :unknown_tool}
  end

  def lookup(_name, _allowed, _disallowed), do: {:error, :unknown_tool}

  defp resolve_module(name) do
    cond do
      module = Enum.find(modules(), &(&1.name() == name)) -> module
      module = desktop_module(name) -> module
      Mcp.advertised?(name) -> {McpTool, name}
      true -> nil
    end
  end

  # The desktop tools are not in `modules/0`: they are conditional on the node feature flag,
  # so they resolve here only while `Native.Desktop.enabled?/0`. Off, both names are
  # `:unknown_tool` — the same answer `specs/3` gives by omitting them (D9). `specs/3` also
  # gates on a workspace, which this name-only lookup cannot see; that gate is what keeps
  # the model from being taught the name, so it is enough that a disabled node refuses here.
  defp desktop_module(name) do
    if Desktop.enabled?(), do: Enum.find(desktop_modules(), &(&1.name() == name))
  end

  @doc "The name a tool name resolves to after aliases."
  @spec canonical(String.t()) :: String.t()
  def canonical(name) when is_binary(name), do: Map.get(@aliases, name, name)

  @doc "Whether the loop answers this tool through the approval path rather than a task."
  @spec interactive?(module() | {module(), String.t()}) :: boolean()
  def interactive?({_module, _name}), do: false

  def interactive?(module) do
    function_exported?(module, :interactive?, 0) and module.interactive?() == true
  end

  @doc "Validates a model call against the exact JSON Schema shown in this turn."
  @spec validate_call(String.t(), term(), [Model.tool_spec()]) ::
          {:ok, map()} | {:error, String.t()}
  def validate_call(name, input, specs)
      when is_binary(name) and is_map(input) and is_list(specs) do
    canonical = canonical(name)

    case Enum.find(specs, &(&1.name == canonical or &1.name == name)) do
      %{parameters: parameters} -> validate_json_input(canonical, input, parameters)
      _not_advertised -> {:error, "Invalid arguments for `#{canonical}`: no schema is available."}
    end
  end

  def validate_call(name, input, _specs),
    do:
      {:error,
       "Invalid arguments for `#{canonical(to_string(name))}`: expected an object, got #{value_kind(input)}. " <>
         "Retry with a JSON object matching the advertised schema; do not repeat the unchanged call."}

  defp validate_json_input(name, input, parameters) do
    case ReqLLM.Schema.validate(input, parameters) do
      {:ok, validated} when is_map(validated) ->
        {:ok, validated}

      {:ok, other} ->
        {:error, "Invalid arguments for `#{name}`: expected an object, got #{value_kind(other)}."}

      {:error, reason} ->
        {:error, validation_message(name, parameters, reason)}
    end
  rescue
    error ->
      {:error,
       "Invalid arguments for `#{name}`: #{Exception.message(error)} Retry with corrected " <>
         "arguments matching the advertised schema; do not repeat the unchanged call."}
  end

  defp validation_message(name, parameters, reason) do
    required = parameters |> value(:required) |> List.wrap() |> Enum.map(&to_string/1)

    details =
      [
        validation_reason(reason),
        required_summary(required),
        property_summary(parameters, required),
        "Retry with corrected arguments; do not repeat the unchanged call."
      ]
      |> Enum.reject(&(&1 in [nil, ""]))
      |> Enum.join(" ")

    "Invalid arguments for `#{name}`: #{details}"
  end

  defp validation_reason(%{__exception__: true} = reason),
    do: reason |> Exception.message() |> validation_reason()

  defp validation_reason(reason) when is_map(reason) do
    case value(reason, :errors) do
      errors when is_list(errors) ->
        errors
        |> Enum.map(fn
          error when is_map(error) -> value(error, :message)
          error -> error_message(error)
        end)
        |> Enum.filter(&(is_binary(&1) and &1 != ""))
        |> Enum.uniq()
        |> Enum.join("; ")

      _other ->
        error_message(reason)
    end
  end

  defp validation_reason(reason) when is_binary(reason) do
    case Regex.run(~r/message: "([^"]+)"/, reason, capture: :all_but_first) do
      [message] -> message
      _no_embedded_message when byte_size(reason) <= 240 -> reason
      _opaque -> "Arguments do not match the advertised schema."
    end
  end

  defp validation_reason(reason), do: error_message(reason)

  defp required_summary([]), do: "Required arguments: none."
  defp required_summary(required), do: "Required arguments: #{Enum.join(required, ", ")}."

  defp property_summary(parameters, required) do
    required = MapSet.new(required)

    fields =
      parameters
      |> value(:properties)
      |> case do
        properties when is_map(properties) ->
          properties
          |> Enum.map(fn {name, schema} ->
            name = to_string(name)
            necessity = if MapSet.member?(required, name), do: "required", else: "optional"
            "#{name}: #{schema_type(schema)} (#{necessity})"
          end)
          |> Enum.sort()

        _none ->
          []
      end

    if fields == [], do: nil, else: "Argument schema: #{Enum.join(fields, ", ")}."
  end

  defp schema_type(schema) when is_map(schema) do
    cond do
      values = value(schema, :enum) ->
        "one of #{Enum.map_join(values, ", ", &inspect/1)}"

      type = value(schema, :type) ->
        type |> List.wrap() |> Enum.map_join(" or ", &to_string/1)

      variants = value(schema, :anyOf) ->
        variants |> Enum.map(&schema_type/1) |> Enum.join(" or ")

      variants = value(schema, :oneOf) ->
        variants |> Enum.map(&schema_type/1) |> Enum.join(" or ")

      true ->
        "value"
    end
  end

  defp schema_type(_schema), do: "value"

  defp value_kind(value) when is_list(value), do: "an array"
  defp value_kind(value) when is_binary(value), do: "a string"
  defp value_kind(value) when is_number(value), do: "a number"
  defp value_kind(value) when is_boolean(value), do: "a boolean"
  defp value_kind(nil), do: "null"
  defp value_kind(_value), do: "a non-object value"

  @doc """
  Describes one attempted call for the permission engine.

  Paths are resolved with the session's own scope, so a request the engine sees is the
  canonical path the tool would actually touch and not the string the model typed. A
  path that will not resolve is reported unresolved: the engine may still deny it, and
  the tool refuses it a moment later anyway.

  `write_paths` is the subset the call would *change*. The loop snapshots exactly those
  before the tool runs, which is what makes rewind byte-exact for a multi-file patch and
  for a language-server rename.

  An MCP tool is `:execute` and keeps its full `mcp__server__tool` name. `:execute`
  because this runtime cannot know what somebody else's server does with the arguments —
  the honest classification of an opaque program is the one that asks — and the full
  name because that is what the C1 rule language matches on, so `mcp__github__*` in a
  rule means what its author meant. No paths, no domains, and no command are claimed:
  inventing any of them would put a fact in front of the engine that this node cannot
  actually know.
  """
  @spec classify(String.t(), map(), map()) :: %{
          tool: String.t(),
          mode: :read | :write | :execute | :network,
          paths: [String.t()],
          write_paths: [String.t()],
          domains: [String.t()],
          command: String.t() | nil,
          context: map()
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
      command: command(canonical, input),
      context: context(canonical, input)
    }
  end

  defp mode("bash", _input), do: :execute
  defp mode("mcp__" <> _rest, _input), do: :execute

  # Computer Use (D3): observing the screen is a read, operating it is an execute. Plan mode
  # allows the first and refuses the second, which is the correct split — a plan may look
  # and must not click.
  defp mode("desktop_state", _input), do: :read
  defp mode("desktop_act", _input), do: :execute

  # G3. Spawning a child that will run tools of its own is an effect, and the honest
  # classification of "a program whose actions this call authorises but does not name" is
  # the one that asks. `agent_result` is `:read` by the default clause below, deliberately:
  # collecting a summary of work that already happened must never need a second approval.
  defp mode("agent", _input), do: :execute
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

  # D4/§6.3: Computer Use puts app identity and the desktop action into the permission
  # `context`, under atom keys the matcher reads via `context_value/2`, so a
  # `ComputerUse(app:…)` rule can allow on the app this node measured. In Phase 0 `app` is
  # the caller's *claimed* string (or nil); the resolved-app second evaluate is Phase 1 and
  # is deliberately not implemented here. Every other tool carries an empty context.
  defp context("desktop_state", input),
    do: %{app: claimed_app(input), desktop_action: "state"}

  defp context("desktop_act", input),
    do: %{app: claimed_app(input), desktop_action: claimed_action(input)}

  defp context(_name, _input), do: %{}

  defp claimed_app(input) do
    case Map.get(input, "app") || Map.get(input, :app) do
      app when is_binary(app) and app != "" -> Desktop.app_alias(app)
      _absent -> nil
    end
  end

  defp claimed_action(input) do
    case Map.get(input, "action") do
      action when is_binary(action) and action != "" -> action
      _absent -> nil
    end
  end

  @doc """
  Runs one tool and normalizes whatever it returned into the loop's result shape.

  A tool that raises becomes an error *result*, not a crashed turn: the model gets to
  see what went wrong and try something else, which is the whole reason tool errors are
  in-band. A tool that runs past its timeout is killed and reported the same way.

  The second form is the dynamic seam. `{module, name}` — only ever `{Tools.Mcp,
  "mcp__server__tool"}` — is what `lookup/3` returns for an MCP tool, and its arguments
  are handed to the server exactly as the model wrote them: there is no compile-time
  schema to atomize against, and the server is the thing that validates.
  """
  @spec execute(module() | {module(), String.t()}, map(), map(), timeout()) :: map()
  def execute(module, input, context, timeout_ms) do
    task = Task.async(fn -> invoke(module, input, context) end)

    if module == DesktopAct do
      await_interruptible(task, timeout_ms, label(module))
    else
      case Task.yield(task, timeout_ms) || Task.shutdown(task, :brutal_kill) do
        {:ok, result} ->
          normalize_result(result)

        nil ->
          %{output: "#{label(module)} timed out after #{timeout_ms} ms.", is_error: true}

        {:exit, reason} ->
          %{output: "#{label(module)} crashed: #{inspect(reason)}", is_error: true}
      end
    end
  end

  defp await_interruptible(task, timeout_ms, label) do
    ref = Process.monitor(task.pid)
    task_ref = task.ref
    deadline = System.monotonic_time(:millisecond) + timeout_ms
    await_interruptible_loop(task, task_ref, ref, deadline, label)
  end

  defp await_interruptible_loop(task, task_ref, ref, deadline, label) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^task_ref, result} ->
        Process.demonitor(ref, [:flush])
        normalize_result(result)

      {:DOWN, ^ref, :process, _pid, reason} ->
        %{output: "#{label} crashed: #{inspect(reason)}", is_error: true}

      :native_interrupt ->
        Desktop.cancel()
        send(self(), :native_interrupt)
        _ = Task.yield(task, 2_000) || Task.shutdown(task, :brutal_kill)
        %{output: "#{label} was cancelled", is_error: true}
    after
      remaining ->
        Desktop.cancel()
        _ = Task.shutdown(task, :brutal_kill)
        %{output: "#{label} timed out after the act deadline.", is_error: true}
    end
  end

  defp invoke(module, input, context) do
    case module do
      {module, name} ->
        module.run(name, if(is_map(input), do: input, else: %{}), context)

      module ->
        with {:ok, params} <- module.validate_params(atomize(module, input)) do
          module.run(params, context)
        end
    end
  rescue
    error -> {:error, {:tool_raised, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:tool_exited, inspect(reason)}}
    value -> {:error, {:tool_threw, inspect(value)}}
  end

  defp label({_module, name}), do: name
  defp label(module), do: module.name()

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
      plan: Map.get(result, :plan),
      # C-U (§8.1). Tool results may carry staged images: `[%{path, media_type, sha256,
      # size}]`. Absent or `[]` for every existing tool; only `desktop_state` fills it. This
      # is the loop's vision seam — `bound/1` caps `output` and never touches an image,
      # because a screenshot is bytes on disk fetched by sha, not text to truncate.
      images: images(Map.get(result, :images, [])),
      # C5+. `bash` is the one tool that can come back saying "the OS sandbox stopped
      # this, and it is a denial an operator could lift". It is carried here rather than
      # buried in the output text because the loop has to *act* on it — it owns the only
      # approval channel — and parsing a decision back out of prose is how that kind of
      # seam rots. Every other tool leaves it `nil`.
      escalation: Map.get(result, :escalation)
    }
  end

  def normalize_result({:ok, result}) when is_map(result), do: empty(inspect(result), false)
  def normalize_result({:error, reason}), do: empty(describe(reason), true)
  def normalize_result(other), do: empty(inspect(other), true)

  defp empty(output, error?),
    do: %{
      output: bound(output),
      is_error: error?,
      changes: [],
      reads: %{},
      plan: nil,
      escalation: nil,
      images: []
    }

  # Keep only well-formed image parts (§8.1). A tool that returns junk here gets `[]` rather
  # than a malformed part the model encoder would then have to defend against.
  defp images(list) when is_list(list), do: Enum.filter(list, &image_part?/1)
  defp images(_other), do: []

  defp image_part?(%{path: path, media_type: media_type, sha256: sha256, size: size})
       when is_binary(path) and is_binary(media_type) and is_binary(sha256) and is_integer(size),
       do: true

  defp image_part?(_part), do: false

  defp describe({:tool_raised, message}), do: "tool raised: #{message}"
  defp describe({:tool_exited, reason}), do: "tool exited: #{reason}"
  defp describe({:tool_threw, value}), do: "tool threw: #{value}"

  defp describe(%{__exception__: true} = error), do: Exception.message(error)
  defp describe(reason) when is_binary(reason), do: reason
  defp describe(reason), do: inspect(reason)

  defp error_message(reason) when is_binary(reason), do: reason
  defp error_message(reason), do: inspect(reason)

  defp value(map, key) when is_map(map),
    do: Map.get(map, key) || Map.get(map, Atom.to_string(key))

  defp value(_not_a_map, _key), do: nil

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
