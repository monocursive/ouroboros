defmodule Ouroboros.Control.Permissions.Matcher do
  @moduledoc """
  Whether one parsed pattern covers one normalised request. Pure, and the whole of it.

  ## The quantifier is the decision

  A request usually carries more than one thing to judge — several paths, several
  sub-commands in a compound line, several domains. Which quantifier applies over that
  list is decided by what the rule *says*, not by the rule's shape:

    * an **allow** rule must cover **every** element. `Bash(ls *)` does not permit
      `ls && rm -rf /`, and `Write(/src/**)` does not permit a write that also touches
      `/etc`. This is Claude Code's compound-command rule and Kiro's per-sub-command
      evaluation, and it is the reason obfuscated chaining defeated a denylist-only
      design (R3 §8d).
    * a **deny** or **ask** rule matches if **any** element is covered. One refused part
      refuses the whole request.

  `matches?/3` therefore takes the quantifier explicitly; `Ouroboros.Control.Permissions.Rules`
  passes `:all` for allow and `:any` for the other two, and nothing else picks.

  ## Which pattern kinds look at which requests

  | pattern | applies to |
  |---|---|
  | `Bash(…)` | a request carrying a command line |
  | `Read(…)` | `mode: :read` |
  | `Edit(…)` | `mode: :write` whose tool is an editing tool, or is unrecognised |
  | `Write(…)` | `mode: :write` whose tool is a creating tool, or is unrecognised |
  | `WebFetch(domain:…)` | `mode: :network` |
  | `mcp__server__tool` | a tool named `mcp:server:tool` or `mcp__server__tool` |
  | `Tool(name)` | a tool with that name |
  | `Tool(name:param=value)` | that tool when `context[param]` equals `value` |
  | `ComputerUse(observe)` | the `desktop_state` tool |
  | `ComputerUse(act)` | the `desktop_act` tool |
  | `ComputerUse(app:<id>)` | either desktop tool when `context.app` equals `<id>` |
  | `ComputerUse(app:*)` | either desktop tool when `context.app` is a nonempty binary |

  `Edit` and `Write` overlap on purpose. A provider that reports a tool this runtime does
  not recognise is judged by both, because the alternative — judging it by neither —
  would let an unfamiliar tool name slip past an operator's write rules.
  """

  alias Ouroboros.Control.Permissions.{Pattern, Paths, Request, Shell}

  @editing_tools ~w(edit multiedit multi_edit apply_patch applypatch str_replace
                    str_replace_editor str_replace_based_edit_tool patch update file_change)
  @creating_tools ~w(write create create_file new_file notebook_edit)

  @type quantifier :: :any | :all

  @doc "Whether `pattern` covers `request` under `quantifier`."
  @spec matches?(Pattern.t(), Request.t(), quantifier()) :: boolean()
  def matches?(%Pattern{} = pattern, %Request{} = request, quantifier)
      when quantifier in [:any, :all] do
    do_matches?(pattern, request, quantifier)
  rescue
    _error -> false
  end

  def matches?(_pattern, _request, _quantifier), do: false

  # ── Bash ───────────────────────────────────────────────────────────────────────────

  defp do_matches?(%Pattern{kind: :bash}, %Request{command: nil}, _quantifier), do: false

  defp do_matches?(%Pattern{kind: :bash, spec: spec}, %Request{command: command}, quantifier) do
    parts =
      command
      |> Shell.split()
      |> Enum.map(&Shell.normalize/1)
      |> Enum.reject(&(&1 == ""))

    case parts do
      [] -> false
      parts -> quantify(quantifier, parts, &command_matches?(spec, &1))
    end
  end

  # ── Paths ──────────────────────────────────────────────────────────────────────────

  defp do_matches?(%Pattern{kind: :read, spec: %{glob: glob}}, request, quantifier) do
    request.mode == :read and path_quantifier(quantifier, request.paths, glob, request.root)
  end

  defp do_matches?(%Pattern{kind: :edit, spec: %{glob: glob}}, request, quantifier) do
    request.mode == :write and tool_class(request.tool) in [:edit, :unknown] and
      path_quantifier(quantifier, request.write_paths, glob, request.root)
  end

  defp do_matches?(%Pattern{kind: :write, spec: %{glob: glob}}, request, quantifier) do
    request.mode == :write and tool_class(request.tool) in [:write, :unknown] and
      path_quantifier(quantifier, request.write_paths, glob, request.root)
  end

  # ── Network ────────────────────────────────────────────────────────────────────────

  defp do_matches?(%Pattern{kind: :web_fetch, spec: %{domain: domain}}, request, quantifier) do
    request.mode == :network and request.domains != [] and
      quantify(quantifier, request.domains, &domain_matches?(domain, &1))
  end

  # ── MCP ────────────────────────────────────────────────────────────────────────────

  defp do_matches?(%Pattern{kind: :mcp, spec: spec}, request, _quantifier) do
    case mcp_parts(request.tool) do
      {server, tool} -> server == spec.server and (spec.tool == :any or spec.tool == tool)
      :error -> false
    end
  end

  # ── Tool ───────────────────────────────────────────────────────────────────────────

  defp do_matches?(%Pattern{kind: :tool, spec: %{name: name}}, request, _quantifier),
    do: same_tool?(name, request.tool)

  defp do_matches?(%Pattern{kind: :tool_param, spec: spec}, request, _quantifier) do
    same_tool?(spec.name, request.tool) and
      context_value(request.context, spec.param) == spec.value
  end

  # ── Computer Use ─────────────────────────────────────────────────────────────────────

  defp do_matches?(%Pattern{kind: :computer_use, spec: %{form: :observe}}, request, _quantifier),
    do: request.tool == "desktop_state"

  defp do_matches?(%Pattern{kind: :computer_use, spec: %{form: :act}}, request, _quantifier),
    do: request.tool == "desktop_act"

  # An allow on `*` must not cover "we did not resolve an app": a missing key reads as nil,
  # never as a nonempty binary. The `:any` clause precedes the exact one so `%{app: :any}`
  # is the wildcard, not an app literally named ":any".
  defp do_matches?(%Pattern{kind: :computer_use, spec: %{app: :any}}, request, _quantifier) do
    case context_value(request.context, "app") do
      app when is_binary(app) -> app != ""
      _other -> false
    end
  end

  defp do_matches?(%Pattern{kind: :computer_use, spec: %{app: app}}, request, _quantifier),
    do: context_value(request.context, "app") == app

  # ── helpers ────────────────────────────────────────────────────────────────────────

  defp quantify(:any, list, fun), do: Enum.any?(list, fun)
  defp quantify(:all, list, fun), do: Enum.all?(list, fun)

  # An allow rule over an empty path list covers nothing; a deny rule over one matches
  # nothing either. Both directions are the narrow answer.
  defp path_quantifier(_quantifier, [], _glob, _root), do: false

  defp path_quantifier(quantifier, paths, glob, root),
    do: quantify(quantifier, paths, &Paths.matches_glob?(&1, glob, root))

  defp command_matches?(%{match: :exact, prefix: prefix}, command),
    do: command == String.trim(prefix)

  # The word boundary: `ls *` covers `ls` and `ls -la`, and never `lsof`.
  defp command_matches?(%{match: :word_prefix, prefix: prefix}, command) do
    prefix = String.trim(prefix)
    command == prefix or String.starts_with?(command, prefix <> " ")
  end

  defp command_matches?(%{match: :literal_prefix, prefix: prefix}, command),
    do: String.starts_with?(command, prefix)

  # `example.com` covers `example.com` and `api.example.com`, never `notexample.com`.
  # An explicit `*.example.com` covers only the subdomains.
  defp domain_matches?("*." <> base, host), do: String.ends_with?(host, "." <> base)

  defp domain_matches?(domain, host),
    do: host == domain or String.ends_with?(host, "." <> domain)

  defp mcp_parts("mcp__" <> rest) do
    case String.split(rest, "__", parts: 2) do
      [server, tool] when server != "" and tool != "" -> {server, tool}
      _other -> :error
    end
  end

  defp mcp_parts("mcp:" <> rest) do
    case String.split(rest, ":", parts: 2) do
      [server, tool] when server != "" and tool != "" -> {server, tool}
      _other -> :error
    end
  end

  defp mcp_parts(_tool), do: :error

  defp same_tool?(name, tool), do: String.downcase(name) == String.downcase(tool)

  defp tool_class(tool) do
    normalized = tool |> String.downcase() |> String.replace("-", "_")

    cond do
      normalized in @editing_tools -> :edit
      normalized in @creating_tools -> :write
      true -> :unknown
    end
  end

  defp context_value(context, param) do
    value = Map.get(context, param) || Map.get(context, safe_atom(param))

    case value do
      nil -> nil
      value when is_binary(value) -> value
      value -> to_string(value)
    end
  rescue
    _error -> nil
  end

  defp safe_atom(param) do
    String.to_existing_atom(param)
  rescue
    ArgumentError -> nil
  end
end
