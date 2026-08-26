defmodule Ouroboros.Control.Permissions.Pattern do
  @moduledoc """
  The rule language `Ouroboros.Control.Permissions` is written in, and nothing else.

  A pattern is one string. Parsing it is pure, total, and independent of the filesystem,
  the clock, and any running process, so the corpus in `test/control/permissions_test.exs`
  is the whole specification of what a rule means.

      Bash(<prefix> *)          a command line whose first tokens are <prefix>
      Bash(<exact command>)     that command line and no other
      Read(<glob>)              a path read
      Edit(<glob>)              a path edited
      Write(<glob>)             a path written
      WebFetch(domain:<host>)   a network fetch of <host> or any subdomain
      mcp__<server>__<tool>     one MCP tool
      mcp__<server>__*          every tool on one MCP server
      Tool(<name>)              one tool by the name the provider calls it
      Tool(<name>:<param>=<v>)  that tool with that parameter — deny and ask only
      ComputerUse(observe)      the desktop_state tool
      ComputerUse(act)          the desktop_act tool
      ComputerUse(app:<id>)     either desktop tool, when the node resolved that app
      ComputerUse(app:*)        either desktop tool, when the node resolved any app

  ## The two refusals

  `Bash(command:…)` is refused outright. Claude Code documents the form as bypassable —
  it constrains a *field* of the request rather than the command line the shell will run
  — and a rule language that accepts a specifier it cannot enforce is worse than one that
  says no ([R3 §3.2](../../../docs/research/agent-ux-2026/R3-tools-permissions-extensibility.md)).

  `Tool(<name>:<param>=<value>)` parses, but `decision/1` on the parsed pattern reports
  `:deny_or_ask_only`. A parameter equality test is a fine reason to stop; it is not a
  fine reason to proceed, because the parameter a provider reports is not necessarily the
  parameter it will act on.

  ## Fragility, marked rather than hidden

  `fragile?/1` is true for a `Bash` pattern that constrains arguments — a `*` anywhere but
  at the end, or a prefix token that is an option (`-x`) or a URL. Claude Code's own
  documentation calls `Bash(curl http://github.com/ *)` fragile, because options, protocol
  spellings, redirects, and variables all route around it, and recommends a `deny` plus a
  `WebFetch(domain:…)` allow instead (R3 §8d, "denylist-only auto-run"). Such a pattern is
  accepted, because refusing it would push operators to something worse; it is returned
  with the flag set so every surface that shows a rule can say what it is.
  """

  @kinds [:bash, :read, :edit, :write, :web_fetch, :mcp, :tool, :tool_param, :computer_use]

  @wrapped %{"Bash" => :bash, "Read" => :read, "Edit" => :edit, "Write" => :write}

  @max_pattern_bytes 512

  # A resolved app id: `com.apple.Calculator`, `org.mozilla.firefox`. Bounded so a rule
  # cannot smuggle a pattern-length attack past `@max_pattern_bytes` through the app slot.
  @computer_use_app ~r/\A[A-Za-z0-9._-]{1,128}\z/

  @enforce_keys [:raw, :kind, :spec, :fragile?]
  defstruct @enforce_keys

  @type kind ::
          :bash | :read | :edit | :write | :web_fetch | :mcp | :tool | :tool_param | :computer_use
  @type t :: %__MODULE__{
          raw: String.t(),
          kind: kind(),
          spec: map(),
          fragile?: boolean()
        }

  @doc "Every kind a pattern can have."
  @spec kinds() :: [kind()]
  def kinds, do: @kinds

  @doc """
  Parses one pattern string.

  Returns `{:error, reason}` for anything this language does not contain, including the
  empty string, an unbalanced parenthesis, and a pattern longer than
  #{@max_pattern_bytes} bytes. There is no permissive arm: an unparseable rule is not
  silently treated as a tool name.
  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, term()}
  def parse(pattern) when is_binary(pattern) and byte_size(pattern) <= @max_pattern_bytes do
    trimmed = String.trim(pattern)

    cond do
      trimmed == "" -> {:error, :empty_pattern}
      String.starts_with?(trimmed, "mcp__") -> parse_mcp(trimmed)
      true -> parse_wrapped(trimmed)
    end
  end

  def parse(pattern) when is_binary(pattern),
    do: {:error, {:pattern_too_long, byte_size(pattern)}}

  def parse(other), do: {:error, {:invalid_pattern, other}}

  @doc "Parses and raises on refusal. For literals in configuration and tests."
  @spec parse!(String.t()) :: t()
  def parse!(pattern) do
    case parse(pattern) do
      {:ok, parsed} -> parsed
      {:error, reason} -> raise ArgumentError, "invalid permission pattern: #{inspect(reason)}"
    end
  end

  @doc """
  Which decisions this pattern may carry.

  `:any` for everything except `Tool(<name>:<param>=<value>)`, which is
  `:deny_or_ask_only`. `ComputerUse(app:…)` is `:any` — an app allow is honest —
  because the app is a fact the node resolved from the live window before `evaluate/1`,
  not a parameter the provider merely reported (the `Tool(…:param=)` distinction).
  """
  @spec decisions(t()) :: :any | :deny_or_ask_only
  def decisions(%__MODULE__{kind: :tool_param}), do: :deny_or_ask_only
  def decisions(%__MODULE__{}), do: :any

  @doc "Whether this pattern constrains arguments, and is therefore routed around easily."
  @spec fragile?(t()) :: boolean()
  def fragile?(%__MODULE__{fragile?: fragile?}), do: fragile?

  # ── Wrapped forms: Name(inner) ─────────────────────────────────────────────────────

  defp parse_wrapped(pattern) do
    case Regex.run(~r/\A([A-Za-z][A-Za-z0-9_]*)\((.*)\)\z/s, pattern) do
      [_whole, name, inner] -> parse_named(name, inner, pattern)
      _no_match -> {:error, {:unrecognized_pattern, pattern}}
    end
  end

  defp parse_named("Bash", inner, raw) do
    trimmed = String.trim(inner)

    cond do
      trimmed == "" ->
        {:error, :empty_bash_pattern}

      # The specifier Claude Code rejects, rejected here for the same reason.
      String.starts_with?(trimmed, "command:") ->
        {:error, :bash_command_specifier_refused}

      true ->
        {:ok,
         %__MODULE__{
           raw: raw,
           kind: :bash,
           spec: bash_spec(trimmed),
           fragile?: bash_fragile?(trimmed)
         }}
    end
  end

  defp parse_named(name, inner, raw) when is_map_key(@wrapped, name) do
    kind = Map.fetch!(@wrapped, name)
    trimmed = String.trim(inner)

    if trimmed == "",
      do: {:error, {:empty_path_pattern, kind}},
      else: {:ok, %__MODULE__{raw: raw, kind: kind, spec: %{glob: trimmed}, fragile?: false}}
  end

  defp parse_named("WebFetch", inner, raw) do
    case String.trim(inner) do
      "domain:" <> host ->
        case normalize_host(host) do
          {:ok, host} ->
            {:ok, %__MODULE__{raw: raw, kind: :web_fetch, spec: %{domain: host}, fragile?: false}}

          {:error, reason} ->
            {:error, reason}
        end

      other ->
        {:error, {:web_fetch_requires_domain, other}}
    end
  end

  defp parse_named("Tool", inner, raw) do
    trimmed = String.trim(inner)

    case String.split(trimmed, ":", parts: 2) do
      [""] ->
        {:error, :empty_tool_pattern}

      [name] ->
        {:ok, %__MODULE__{raw: raw, kind: :tool, spec: %{name: name}, fragile?: false}}

      [name, constraint] ->
        parse_tool_param(raw, String.trim(name), String.trim(constraint))
    end
  end

  # `app:*` is the explicit any-app form; `app:<id>` an exact resolved id. A bare
  # `ComputerUse` never reaches here — the wrapping regex requires `Name(inner)` — and an
  # empty or unrecognised inner is a parse error, so there is no permissive arm.
  defp parse_named("ComputerUse", inner, raw) do
    case String.trim(inner) do
      "observe" ->
        {:ok,
         %__MODULE__{raw: raw, kind: :computer_use, spec: %{form: :observe}, fragile?: false}}

      "act" ->
        {:ok, %__MODULE__{raw: raw, kind: :computer_use, spec: %{form: :act}, fragile?: false}}

      "app:*" ->
        {:ok, %__MODULE__{raw: raw, kind: :computer_use, spec: %{app: :any}, fragile?: false}}

      "app:" <> id ->
        if Regex.match?(@computer_use_app, id),
          do:
            {:ok, %__MODULE__{raw: raw, kind: :computer_use, spec: %{app: id}, fragile?: false}},
          else: {:error, {:invalid_computer_use_app, id}}

      other ->
        {:error, {:invalid_computer_use_pattern, other}}
    end
  end

  defp parse_named(name, _inner, pattern), do: {:error, {:unknown_pattern_kind, name, pattern}}

  defp parse_tool_param(_raw, "", _constraint), do: {:error, :empty_tool_pattern}

  defp parse_tool_param(raw, name, constraint) do
    case String.split(constraint, "=", parts: 2) do
      [param, value] when param != "" ->
        {:ok,
         %__MODULE__{
           raw: raw,
           kind: :tool_param,
           spec: %{name: name, param: param, value: value},
           fragile?: true
         }}

      _other ->
        {:error, {:tool_parameter_requires_value, constraint}}
    end
  end

  # ── MCP ────────────────────────────────────────────────────────────────────────────

  defp parse_mcp(pattern) do
    case String.split(pattern, "__", parts: 3) do
      ["mcp", server, tool] when server != "" and tool != "" ->
        {:ok,
         %__MODULE__{
           raw: pattern,
           kind: :mcp,
           spec: %{server: server, tool: if(tool == "*", do: :any, else: tool)},
           fragile?: false
         }}

      ["mcp", server] when server != "" ->
        {:ok,
         %__MODULE__{
           raw: pattern,
           kind: :mcp,
           spec: %{server: server, tool: :any},
           fragile?: false
         }}

      _other ->
        {:error, {:invalid_mcp_pattern, pattern}}
    end
  end

  # ── Bash prefix semantics ──────────────────────────────────────────────────────────

  # Three shapes, in the order they are distinguished:
  #
  #   "ls *"          → prefix ["ls"], word boundary. `ls -la` matches; `lsof` does not.
  #   "npm run test:*" → literal prefix "npm run test:", no boundary. Claude Code's
  #                     colon form, where the star continues the last token.
  #   "npm run build" → exactly that command line.
  defp bash_spec(inner) do
    cond do
      String.ends_with?(inner, " *") ->
        %{match: :word_prefix, prefix: String.trim_trailing(inner, " *")}

      String.ends_with?(inner, "*") ->
        %{match: :literal_prefix, prefix: String.trim_trailing(inner, "*")}

      true ->
        %{match: :exact, prefix: inner}
    end
  end

  # A star anywhere but the tail, an option token, or a URL token: all of them are
  # attempts to constrain arguments, and all of them are documented as routable-around.
  defp bash_fragile?(inner) do
    body = inner |> String.trim_trailing("*") |> String.trim_trailing()

    String.contains?(body, "*") or
      Enum.any?(String.split(body, ~r/\s+/, trim: true), fn token ->
        String.starts_with?(token, "-") or String.contains?(token, "://")
      end)
  end

  defp normalize_host(host) do
    host = host |> String.trim() |> String.downcase() |> String.trim_leading(".")

    if host != "" and Regex.match?(~r/\A[a-z0-9.*-]+\z/, host),
      do: {:ok, host},
      else: {:error, {:invalid_domain, host}}
  end
end
