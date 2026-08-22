defmodule Ouroboros.Provider.Native.Skills do
  @moduledoc """
  Agent Skills discovery: `SKILL.md` files, listed cheaply and loaded on demand.

  The Agent Skills convention is implemented by Claude Code, Codex, Gemini, Cursor,
  OpenCode, Crush, Pi, Amp, Factory, Kiro and Cline, and their search paths converged on
  `.agents/skills/` (R3 §4.3). So that is where this looks, plus the user scope beside
  every other Ouroboros configuration:

      <workspace>/.agents/skills/<name>/SKILL.md     project
      ~/.config/ouroboros/skills/<name>/SKILL.md     user

  A project skill and a user skill with the same name resolve to the project one, which
  is the ordering every configuration in this runtime uses.

  ## The budget is the design

  Only names and descriptions go into the model's context, and only up to **the smaller
  of 2% of the context window and 8,000 characters** — Codex's published budget, and the
  reason it exists is Anthropic's own measurement of 72K tokens spent on tool definitions
  before tool search (R3 §2, §8d). Descriptions are clipped at 1,024 characters each
  (Claude Code clips at 1,536). The body is read only when `skill` is called for it, and
  is itself capped.

  ## Frontmatter, parsed narrowly on purpose

  `SKILL.md` starts with a `---` fenced block of `key: value` lines. This reads exactly
  two keys out of it — `name` and `description` — with a hand-written scanner rather than
  a YAML parser. A repository-supplied file is untrusted input; handing it to a general
  parser to extract two strings is more surface than the job needs, and a YAML feature
  nobody asked for is not a feature this runtime wants a repository to be able to reach.

  ## What a skill is not

  A skill is instructions, not permission. Loading one appends text to a tool result;
  it grants nothing, runs nothing, and changes no rule. A repository can therefore say
  what it likes in a `SKILL.md`, and the model reads it as it reads any other file in
  the tree — which is stated in the README rather than papered over.
  """

  @skill_file "SKILL.md"
  @max_skills 100
  @max_description_bytes 1_024
  @max_body_bytes 32 * 1024
  @max_frontmatter_lines 60
  @default_budget 8_000
  @name_pattern ~r/\A[a-z0-9][a-z0-9_-]{0,63}\z/

  @type skill :: %{
          name: String.t(),
          description: String.t(),
          path: String.t(),
          scope: :project | :user
        }

  @doc """
  Every skill visible to a session, project scope first, deduplicated by name.

  Never raises and never returns an error: a directory that cannot be read contributes
  nothing. Skills are a convenience, and a broken one must not be able to fail a turn.
  """
  @spec discover(String.t() | nil) :: [skill()]
  def discover(workspace_root) do
    (scan(project_dir(workspace_root), :project) ++ scan(user_dir(), :user))
    |> Enum.uniq_by(& &1.name)
    |> Enum.sort_by(& &1.name)
    |> Enum.take(@max_skills)
  end

  @doc """
  The catalogue line the `skill` tool's description carries, bounded.

  Empty when there are no skills, so the tool's description says so and the model does
  not spend a call finding out.
  """
  @spec catalogue([skill()], keyword()) :: String.t()
  def catalogue(skills, opts \\ [])

  def catalogue([], _opts), do: ""

  def catalogue(skills, opts) do
    budget = budget(opts)

    {lines, dropped} =
      Enum.reduce(skills, {[], 0}, fn skill, {lines, dropped} ->
        line = "  " <> skill.name <> " — " <> skill.description

        if IO.iodata_length(lines) + byte_size(line) + 1 <= budget,
          do: {[line | lines], dropped},
          else: {lines, dropped + 1}
      end)

    note =
      if dropped > 0,
        do: "\n  (#{dropped} more not listed — the budget is #{budget} characters)",
        else: ""

    case Enum.reverse(lines) do
      [] -> ""
      listed -> Enum.join(listed, "\n") <> note
    end
  end

  @doc """
  Reads one skill's body by name.

  `{:error, {:unknown_skill, name, available}}` names what there is, so a model that
  guessed a name gets the list rather than a second guess.
  """
  @spec load(String.t(), String.t() | nil) :: {:ok, map()} | {:error, term()}
  def load(name, workspace_root) when is_binary(name) do
    skills = discover(workspace_root)
    wanted = String.trim(name)

    case Enum.find(skills, &(&1.name == wanted)) do
      nil ->
        {:error, {:unknown_skill, wanted, Enum.map(skills, & &1.name)}}

      skill ->
        case File.read(skill.path) do
          {:ok, content} ->
            {:ok, Map.put(skill, :body, clip(strip_frontmatter(content), @max_body_bytes))}

          {:error, reason} ->
            {:error, {:unreadable_skill, skill.path, reason}}
        end
    end
  end

  def load(name, _workspace_root), do: {:error, {:unknown_skill, inspect(name), []}}

  @doc "Where project skills live for a workspace, or `nil` without one."
  @spec project_dir(String.t() | nil) :: String.t() | nil
  def project_dir(root) when is_binary(root) and root != "",
    do: Path.join([root, ".agents", "skills"])

  def project_dir(_root), do: nil

  @doc """
  Where user skills live on this node.

  `config :ouroboros, :native_user_skills_dir` moves it, the same way
  `:native_data_dir` moves the session directory — an operator running several runtimes
  on one account needs the option, and it is what the tests point at a temporary
  directory so they never read the machine's real skills.
  """
  @spec user_dir() :: String.t() | nil
  def user_dir do
    case Application.get_env(:ouroboros, :native_user_skills_dir) do
      path when is_binary(path) and path != "" ->
        path

      _unset ->
        case System.user_home() do
          home when is_binary(home) and home != "" ->
            Path.join([home, ".config", "ouroboros", "skills"])

          _unknown ->
            nil
        end
    end
  end

  # ---------------------------------------------------------------- internals

  defp scan(nil, _scope), do: []

  defp scan(directory, scope) do
    case File.ls(directory) do
      {:ok, entries} ->
        entries
        |> Enum.sort()
        |> Enum.take(@max_skills)
        |> Enum.flat_map(&read_skill(Path.join(directory, &1), &1, scope))

      {:error, _reason} ->
        []
    end
  end

  defp read_skill(directory, entry, scope) do
    path = Path.join(directory, @skill_file)

    with true <- File.dir?(directory),
         {:ok, %File.Stat{size: size}} when size <= @max_body_bytes * 4 <- File.stat(path),
         {:ok, content} <- File.read(path),
         true <- String.valid?(content) do
      front = frontmatter(content)
      name = front |> Map.get("name", entry) |> normalize_name(entry)

      if name do
        [
          %{
            name: name,
            description: front |> Map.get("description", "") |> clip(@max_description_bytes),
            path: path,
            scope: scope
          }
        ]
      else
        []
      end
    else
      _not_a_skill -> []
    end
  end

  # A skill's name becomes a lookup key the model types; anything that is not the
  # documented shape falls back to the directory name, and a directory name that is not
  # the documented shape is skipped rather than sanitized into something else.
  defp normalize_name(declared, fallback) do
    candidate = declared |> to_string() |> String.trim() |> String.downcase()

    cond do
      Regex.match?(@name_pattern, candidate) -> candidate
      Regex.match?(@name_pattern, String.downcase(fallback)) -> String.downcase(fallback)
      true -> nil
    end
  end

  @doc false
  @spec frontmatter(binary()) :: %{optional(String.t()) => String.t()}
  def frontmatter(content) do
    case String.split(content, "\n") do
      ["---" | rest] ->
        rest
        |> Enum.take(@max_frontmatter_lines)
        |> Enum.take_while(&(String.trim(&1) != "---"))
        |> Enum.reduce(%{}, &collect_pair/2)

      _no_frontmatter ->
        %{}
    end
  end

  defp collect_pair(line, acc) do
    case String.split(line, ":", parts: 2) do
      [key, value] ->
        key = key |> String.trim() |> String.downcase()

        if key in ["name", "description"],
          do: Map.put(acc, key, unquote_value(String.trim(value))),
          else: acc

      _not_a_pair ->
        acc
    end
  end

  defp unquote_value(<<?", _rest::binary>> = value), do: String.trim(value, "\"")
  defp unquote_value(<<?', _rest::binary>> = value), do: String.trim(value, "'")
  defp unquote_value(value), do: value

  defp strip_frontmatter(content) do
    case String.split(content, "\n") do
      ["---" | rest] ->
        case Enum.split_while(rest, &(String.trim(&1) != "---")) do
          {_front, ["---" | body]} -> body |> Enum.join("\n") |> String.trim_leading()
          _unterminated -> content
        end

      _no_frontmatter ->
        content
    end
  end

  # 2% of the context window, in characters, or 8,000 — whichever is smaller. The window
  # is in tokens; four characters per token is the ratio every vendor's own estimator
  # uses, and being wrong about it in this direction costs a listed skill, not a turn.
  defp budget(opts) do
    case Keyword.get(opts, :context_window) do
      window when is_integer(window) and window > 0 ->
        min(@default_budget, max(div(window * 4 * 2, 100), 200))

      _unknown ->
        case Keyword.get(opts, :budget) do
          value when is_integer(value) and value > 0 -> min(value, @default_budget)
          _unset -> @default_budget
        end
    end
  end

  defp clip(text, limit) when is_binary(text) do
    trimmed = String.trim(text)
    if byte_size(trimmed) <= limit, do: trimmed, else: binary_part(trimmed, 0, limit) <> "…"
  end

  defp clip(text, limit), do: text |> to_string() |> clip(limit)
end
