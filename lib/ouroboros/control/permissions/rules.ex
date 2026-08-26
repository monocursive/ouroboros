defmodule Ouroboros.Control.Permissions.Rules do
  @moduledoc """
  The decision algorithm, and the protected paths no rule can talk over.

  Pure: given a request and a list of rules, this module answers. It reads application
  configuration for the protected-path list (the data directory is where it is because an
  operator put it there) and nothing else.

  ## The algorithm, exactly

  1. **Protected writes first.** If any path this request would write is protected, the
     answer is `{:deny, %{scope: :node, id: "protected-path", pattern: …}}`, and no rule
     is consulted. There is no rule that turns this off; an engine whose own store could
     be rewritten by the sessions it governs is not an authority.
  2. Every rule whose scope applies to this principal is matched against the request.
     An `allow` rule must cover **every** path and **every** sub-command; a `deny` or
     `ask` rule matches on **any** (see `Ouroboros.Control.Permissions.Matcher`).
  3. Among the matches, **decision rank decides first**: any `deny` wins, then any `ask`,
     then `allow`. This is Claude Code's deny → ask → allow order and Kiro's
     deny-override, and it is why adding a rule can only ever narrow what a lower scope
     permitted.
  4. **Scope breaks ties within one rank only.** `:node` (operator configuration) beats
     `:user`, which beats `:workspace`, which beats `:session`. A `:session` `deny` still
     beats a `:node` `allow`, because rank comes first — the strictest reading of two
     rules that disagree is the one that gets used.
  5. Nothing matched: `{:ask, :no_rule}`. Deny by default means *ask* by default here,
     not *refuse*: the human is the fallback authority, and a runtime that answered
     "denied" to everything unlisted would be a runtime nobody could use.

  ## Protected paths

  Writes to these are denied whatever the rules say:

    * any path with a `.git` segment — the repository's own history and hooks
    * any path with a `.ouroboros` segment — a workspace's runtime state
    * the node's data directory and everything beneath it — sessions, journals, the
      permission store itself, the effect ledger
    * `$XDG_CONFIG_HOME/ouroboros/**`, or `~/.config/ouroboros/**` when that is unset

  Reads are *not* protected. Refusing to read `.git` would break every honest use of a
  repository, and the threat this list answers is a session rewriting the authority that
  governs it, not a session looking at it.
  """

  alias Ouroboros.Control.Permissions.{Matcher, Paths, Request, Rule, Shell}

  @protected_segments [".git", ".ouroboros"]

  @rank %{deny: 0, ask: 1, allow: 2}
  @scope_rank %{node: 0, user: 1, workspace: 2, session: 3}

  @protected_ref %{scope: :node, id: "protected-path", pattern: "protected"}

  @type outcome :: {:allow, map()} | {:deny, map()} | {:ask, atom()}

  @doc "The protected write locations on this node, as human-readable strings."
  @spec protected_paths() :: [String.t()]
  def protected_paths do
    Enum.map(@protected_segments, &("**/" <> &1 <> "/**")) ++
      Enum.map(protected_roots(), &(&1 <> "/**"))
  end

  @doc """
  Whether writing `path` is refused regardless of rules.
  """
  @spec protected_write?(String.t()) :: boolean()
  def protected_write?(path) when is_binary(path) do
    Enum.any?(@protected_segments, &Paths.has_segment?(path, &1)) or
      (Enum.any?(protected_roots(), &Paths.within?(path, &1)) and not worktree_write?(path))
  end

  def protected_write?(_path), do: false

  # D7 keeps the workspaces it provisions under `<data_dir>/worktrees`: a workspace a
  # session was given to write in, not runtime state, and the one place beneath the data
  # directory a session is *meant* to write. Without this exemption no session on a node
  # with a data directory — every release — could write inside its worktree at all, which
  # G3's subagent tests were the first to notice. A worktree's own `.git` and
  # `.ouroboros` stay protected by the segment rules above, exactly as in any workspace.
  defp worktree_write?(path) do
    case worktree_root() do
      nil -> false
      root -> Paths.within?(path, root)
    end
  end

  defp worktree_root do
    case Paths.canonicalize(Ouroboros.Workspace.Worktree.root(), nil) do
      {:ok, canonical} -> canonical
      {:error, _reason} -> nil
    end
  end

  @doc "The protected write paths this request would touch, if any."
  @spec protected_targets(Request.t()) :: [String.t()]
  def protected_targets(%Request{} = request),
    do: Enum.filter(request.write_paths, &protected_write?/1)

  def protected_targets(_request), do: []

  @doc """
  Decides one request against `rules`.

  `rules` is every rule that could apply; scope filtering for principal (which workspace,
  which session) has already happened in the caller, because only the caller knows which
  session asked.
  """
  @spec decide(Request.t(), [Rule.t()]) :: outcome()
  def decide(%Request{} = request, rules) when is_list(rules) do
    case protected_targets(request) do
      [target | _rest] ->
        {:deny, Map.put(@protected_ref, :pattern, protected_pattern(target))}

      [] ->
        rules |> Enum.filter(&applies?(&1, request)) |> best(request)
    end
  end

  def decide(_request, _rules), do: {:ask, :invalid_request}

  @doc "Whether one rule's scope makes it applicable to this request's principal."
  @spec scoped?(Rule.t(), Request.t()) :: boolean()
  def scoped?(%Rule{scope: :workspace} = rule, %Request{} = request),
    do: is_binary(request.root) and rule.workspace == request.root

  def scoped?(%Rule{scope: :session} = rule, %Request{} = request),
    do:
      is_binary(request.principal.session_id) and rule.session_id == request.principal.session_id

  def scoped?(%Rule{}, %Request{}), do: true
  def scoped?(_rule, _request), do: false

  defp applies?(%Rule{} = rule, request) do
    scoped?(rule, request) and
      Matcher.matches?(rule.pattern, request, quantifier(rule.decision))
  end

  defp applies?(_rule, _request), do: false

  # Allow has to cover everything; deny and ask need only cover something.
  defp quantifier(:allow), do: :all
  defp quantifier(_decision), do: :any

  defp best([], _request), do: {:ask, :no_rule}

  defp best(matches, request) do
    winner =
      Enum.min_by(matches, fn rule ->
        {Map.fetch!(@rank, rule.decision), Map.fetch!(@scope_rank, rule.scope), rule.id}
      end)

    case winner.decision do
      :ask ->
        {:ask, :rule}

      # Allow quantifies over what the parser could read; a command truncated at the
      # bound carries a tail no rule ever saw, and covering the readable prefix is not
      # covering the line. Deny and ask already match fail-closed over the same prefix,
      # so only an allow win is downgraded.
      :allow ->
        if Shell.truncated?(request.command),
          do: {:ask, :truncated_request},
          else: {:allow, Rule.ref(winner)}

      decision ->
        {decision, Rule.ref(winner)}
    end
  end

  defp protected_pattern(target) do
    cond do
      Paths.has_segment?(target, ".git") -> "**/.git/**"
      Paths.has_segment?(target, ".ouroboros") -> "**/.ouroboros/**"
      true -> (Enum.find(protected_roots(), &Paths.within?(target, &1)) || "") <> "/**"
    end
  end

  defp protected_roots do
    [data_dir(), config_dir()]
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.flat_map(fn root ->
      case Paths.canonicalize(root, nil) do
        {:ok, canonical} -> [canonical]
        {:error, _reason} -> []
      end
    end)
    |> Enum.uniq()
  end

  defp data_dir, do: Application.get_env(:ouroboros, :data_dir)

  defp config_dir do
    case System.get_env("XDG_CONFIG_HOME") do
      dir when is_binary(dir) and dir != "" ->
        Path.join(dir, "ouroboros")

      _unset ->
        case System.user_home() do
          home when is_binary(home) and home != "" -> Path.join([home, ".config", "ouroboros"])
          _no_home -> nil
        end
    end
  end
end
