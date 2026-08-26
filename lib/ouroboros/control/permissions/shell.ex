defmodule Ouroboros.Control.Permissions.Shell do
  @moduledoc """
  What a `Bash(…)` rule has to understand about a command line before it can match it.

  This module reads shell syntax; it never runs it. Everything here is pure and total,
  and every function answers with what it could work out rather than raising on syntax it
  does not model.

  Three transformations, in the order a rule applies them:

    1. **Split.** `a && b`, `a || b`, `a ; b`, `a | b`, `a |& b`, `a & b`, and newlines
       separate sub-commands. Every sub-command must match its own rule for the compound
       to be permitted — Claude Code's rule and Kiro's alike, and the reason obfuscated
       chaining defeated Cursor's denylist (R3 §8d).
    2. **Strip wrappers.** `timeout`, `time`, `nice`, `nohup`, `stdbuf`, `command`,
       `builtin`, `noglob`, and a bare `xargs` are prefixes that decide *how* a command
       runs, not *which*. They and their own options are removed so `timeout 5s ls` is
       evaluated as `ls`. `xargs` with options is not bare and is not stripped: at that
       point the command being run is genuinely `xargs`.
    3. **Collect redirects.** `> f`, `>> f`, `2> f`, `&> f`, `>| f`, and `n>&m`-free
       variants name a file the command will write. Those targets are evaluated as write
       paths in addition to the command itself, so `echo x > .git/config` is refused by
       the protected-path rule even though `echo` is harmless.

  ## What it does not model

  Command substitution (`$(…)`, backticks), `eval`, variable expansion, aliases, and
  `sh -c "…"` all defeat prefix matching by construction, and this module does not
  pretend otherwise: the substituted text is never expanded, so a rule matches the
  literal command line the provider reported. That is exactly why the engine's honest
  posture is an allowlist plus protected paths, and why a rule language is not a sandbox.
  """

  @separators ["&&", "||", "|&", ";", "|", "&", "\n"]

  # Prefixes that alter how a command runs, not which command runs.
  @wrappers ~w(timeout time nice nohup stdbuf command builtin noglob)

  # Wrapper options whose value is a separate token, so that `nice -n 10 ls` strips to
  # `ls` rather than to `10 ls`.
  @value_options %{
    "timeout" => ~w(-s --signal -k --kill-after),
    "nice" => ~w(-n --adjustment),
    "stdbuf" => ~w(-i -o -e --input --output --error)
  }

  @redirect_operators ~w(> >> >| 2> 2>> &> &>> 1> 1>>)

  @max_command_bytes 8_192
  @max_parts 64

  @doc "The most bytes one command line contributes to matching."
  @spec max_command_bytes() :: pos_integer()
  def max_command_bytes, do: @max_command_bytes

  @doc "The most sub-commands one command line is judged by."
  @spec max_parts() :: pos_integer()
  def max_parts, do: @max_parts

  @doc """
  Whether a command line exceeds the bounds matching honours.

  A truncated line is judged only by what fit inside the bound, and what did not fit is
  invisible to every rule. `Ouroboros.Control.Permissions.Rules` therefore never lets an
  allow rule win over a truncated request: an unchecked 65th sub-command must not ride a
  rule that only ever saw 64.
  """
  @spec truncated?(String.t() | nil) :: boolean()
  def truncated?(command) when is_binary(command) do
    if byte_size(command) > @max_command_bytes do
      true
    else
      # The part count `split/1` reports is already capped, so count without the cap:
      # exactly #{@max_parts} parts are judged whole and are not a truncation.
      command
      |> do_split("", [], nil)
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))
      |> length() > @max_parts
    end
  end

  def truncated?(_command), do: false

  @doc """
  Splits a command line into the sub-commands a rule must each match.

  Quoting is respected: `echo "a && b"` is one sub-command. A line longer than
  #{@max_command_bytes} bytes, or one that splits into more than #{@max_parts} parts, is
  truncated to that bound — the caller sees a shorter list than the input, and
  `truncated?/1` says so; `Ouroboros.Control.Permissions.Rules` refuses to let an allow
  rule win over a truncated request rather than judging the tail nobody could read.
  """
  @spec split(String.t()) :: [String.t()]
  def split(command) when is_binary(command) do
    command
    |> binary_part(0, min(byte_size(command), @max_command_bytes))
    |> do_split("", [], nil)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.take(@max_parts)
  end

  def split(_command), do: []

  @doc """
  Removes leading wrapper commands and their options.

  Nested wrappers are removed to a fixed depth, because `nohup nice nohup nice …` is a
  cheap way to ask for unbounded work.
  """
  @spec strip_wrappers(String.t()) :: String.t()
  def strip_wrappers(command) when is_binary(command), do: strip_wrappers(command, 8)
  def strip_wrappers(_command), do: ""

  defp strip_wrappers(command, 0), do: command

  defp strip_wrappers(command, depth) do
    case tokens(command) do
      [head | rest] ->
        cond do
          base_name(head) in @wrappers ->
            rest |> drop_wrapper_options(base_name(head)) |> rejoin() |> strip_wrappers(depth - 1)

          # Bare `xargs` — no options at all — is a wrapper around whatever follows it.
          base_name(head) == "xargs" and not Enum.any?(rest, &String.starts_with?(&1, "-")) ->
            rest |> rejoin() |> strip_wrappers(depth - 1)

          true ->
            command
        end

      [] ->
        command
    end
  end

  @doc """
  The file paths this command line redirects output into.

  Only targets are returned, never the command. `>&2` and `2>&1` name a descriptor rather
  than a file and are excluded.
  """
  @spec redirect_targets(String.t()) :: [String.t()]
  def redirect_targets(command) when is_binary(command) do
    command
    |> split()
    |> Enum.flat_map(&sub_command_redirects/1)
    |> Enum.uniq()
  end

  def redirect_targets(_command), do: []

  @doc """
  Splits a command line into tokens, respecting single and double quotes.

  Quotes are removed from the token they surround, so `cat "a b"` is `["cat", "a b"]`.
  """
  @spec tokens(String.t()) :: [String.t()]
  def tokens(command) when is_binary(command), do: do_tokens(command, "", [], nil, false)
  def tokens(_command), do: []

  @doc """
  The form a `Bash` rule matches against: wrappers stripped, whitespace collapsed.

  Quoting is *preserved* here — unlike `tokens/1` — because the rule text an operator
  wrote is compared to a command line, and rewriting the operator's quoting would change
  which lines match.
  """
  @spec normalize(String.t()) :: String.t()
  def normalize(command) when is_binary(command) do
    command
    |> strip_wrappers()
    |> String.split(~r/\s+/, trim: true)
    |> Enum.join(" ")
  end

  def normalize(_command), do: ""

  # ── splitting ──────────────────────────────────────────────────────────────────────

  defp do_split(<<>>, current, acc, _quote), do: Enum.reverse([current | acc])

  defp do_split(<<?\\, next::utf8, rest::binary>>, current, acc, nil) do
    do_split(rest, current <> <<?\\, next::utf8>>, acc, nil)
  end

  defp do_split(<<char::utf8, rest::binary>>, current, acc, quote) when char in [?', ?"] do
    cond do
      quote == char -> do_split(rest, current <> <<char::utf8>>, acc, nil)
      is_nil(quote) -> do_split(rest, current <> <<char::utf8>>, acc, char)
      true -> do_split(rest, current <> <<char::utf8>>, acc, quote)
    end
  end

  defp do_split(binary, current, acc, nil) do
    case Enum.find(@separators, &String.starts_with?(binary, &1)) do
      nil ->
        <<char::utf8, rest::binary>> = binary
        do_split(rest, current <> <<char::utf8>>, acc, nil)

      separator ->
        rest = binary_part(binary, byte_size(separator), byte_size(binary) - byte_size(separator))
        do_split(rest, "", [current | acc], nil)
    end
  end

  defp do_split(<<char::utf8, rest::binary>>, current, acc, quote) do
    do_split(rest, current <> <<char::utf8>>, acc, quote)
  end

  # ── tokenising ─────────────────────────────────────────────────────────────────────

  defp do_tokens(<<>>, current, acc, _quote, started?) do
    if current == "" and not started?, do: Enum.reverse(acc), else: Enum.reverse([current | acc])
  end

  defp do_tokens(<<?\\, next::utf8, rest::binary>>, current, acc, nil, _started?) do
    do_tokens(rest, current <> <<next::utf8>>, acc, nil, true)
  end

  defp do_tokens(<<char::utf8, rest::binary>>, current, acc, quote, started?)
       when char in [?', ?"] do
    cond do
      quote == char -> do_tokens(rest, current, acc, nil, true)
      is_nil(quote) -> do_tokens(rest, current, acc, char, true)
      true -> do_tokens(rest, current <> <<char::utf8>>, acc, quote, started?)
    end
  end

  defp do_tokens(<<char::utf8, rest::binary>>, current, acc, nil, started?)
       when char in [?\s, ?\t, ?\n, ?\r] do
    if current == "" and not started?,
      do: do_tokens(rest, "", acc, nil, false),
      else: do_tokens(rest, "", [current | acc], nil, false)
  end

  defp do_tokens(<<char::utf8, rest::binary>>, current, acc, quote, _started?) do
    do_tokens(rest, current <> <<char::utf8>>, acc, quote, true)
  end

  # ── wrappers ───────────────────────────────────────────────────────────────────────

  # `timeout 5s cmd`, `nice -n 10 cmd`, `stdbuf -o0 cmd`: drop the wrapper's own options,
  # the separate value of an option that takes one, and for `timeout` the bare duration
  # that is not spelled as an option at all.
  defp drop_wrapper_options(tokens, wrapper) do
    tokens = drop_options(tokens, Map.get(@value_options, wrapper, []))

    case {wrapper, tokens} do
      {"timeout", [duration | rest]} ->
        if Regex.match?(~r/\A\d+(\.\d+)?[smhd]?\z/, duration), do: rest, else: tokens

      _other ->
        tokens
    end
  end

  defp drop_options([], _value_options), do: []

  defp drop_options([token | rest] = tokens, value_options) do
    cond do
      token in value_options -> rest |> Enum.drop(1) |> drop_options(value_options)
      String.starts_with?(token, "-") -> drop_options(rest, value_options)
      true -> tokens
    end
  end

  defp rejoin(tokens), do: Enum.join(tokens, " ")

  defp base_name(token), do: token |> String.split("/") |> List.last()

  # ── redirects ──────────────────────────────────────────────────────────────────────

  defp sub_command_redirects(sub_command) do
    sub_command
    |> spaced_redirects()
    |> tokens()
    |> collect_redirects([])
  end

  # `ls>out` and `ls 2>out` are the same redirect as `ls > out`; give the tokeniser a
  # boundary to see it at.
  defp spaced_redirects(sub_command) do
    Regex.replace(~r/(\d?)(>>|>\||>)/, sub_command, " \\1\\2 ")
  end

  defp collect_redirects([], acc), do: Enum.reverse(acc)

  defp collect_redirects([operator, target | rest], acc) do
    if operator in @redirect_operators and not String.starts_with?(target, "&") do
      collect_redirects(rest, [target | acc])
    else
      collect_redirects([target | rest], acc)
    end
  end

  defp collect_redirects([_token], acc), do: Enum.reverse(acc)
end
