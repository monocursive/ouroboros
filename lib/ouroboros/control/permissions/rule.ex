defmodule Ouroboros.Control.Permissions.Rule do
  @moduledoc """
  One durable permission rule: a pattern, a decision, and the scope that holds it.

  The id is derived, not random: `scope`, workspace, session, decision, and the pattern
  text hash to it. Two operators who add the same rule twice get one rule, a retry of a
  `remember/4` after a lost acknowledgement is the same rule rather than a second one,
  and `remove/2` names something stable across restarts.
  """

  alias Ouroboros.Control.Permissions.Paths
  alias Ouroboros.Control.Permissions.Pattern

  @scopes [:node, :user, :workspace, :session]
  @decisions [:allow, :deny, :ask]

  @enforce_keys [:id, :scope, :decision, :pattern, :workspace, :session_id, :created_at]
  defstruct @enforce_keys ++ [fragile?: false]

  @type scope :: :node | :user | :workspace | :session
  @type decision :: :allow | :deny | :ask
  @type t :: %__MODULE__{
          id: String.t(),
          scope: scope(),
          decision: decision(),
          pattern: Pattern.t(),
          workspace: String.t() | nil,
          session_id: String.t() | nil,
          created_at: String.t(),
          fragile?: boolean()
        }

  @doc "The four scopes, highest authority first."
  @spec scopes() :: [scope()]
  def scopes, do: @scopes

  @doc "The three decisions a rule may carry."
  @spec decisions() :: [decision()]
  def decisions, do: @decisions

  @doc """
  Builds one rule, refusing anything the language does not admit.

  A `:workspace` rule without a workspace root, a `:session` rule without a session id,
  and a `Tool(name:param=value)` pattern carrying `:allow` are all refused here rather
  than at the point they would have mattered.
  """
  @spec new(keyword() | map()) :: {:ok, t()} | {:error, term()}
  def new(attrs) when is_list(attrs), do: attrs |> Map.new() |> new()

  def new(attrs) when is_map(attrs) do
    with {:ok, scope} <- scope(Map.get(attrs, :scope)),
         {:ok, decision} <- decision(Map.get(attrs, :decision)),
         {:ok, pattern} <- pattern(Map.get(attrs, :pattern)),
         :ok <- allowed_decision(pattern, decision),
         {:ok, workspace} <- workspace(scope, Map.get(attrs, :workspace)),
         {:ok, session_id} <- session_id(scope, Map.get(attrs, :session_id)) do
      {:ok,
       %__MODULE__{
         id: id(scope, decision, pattern, workspace, session_id),
         scope: scope,
         decision: decision,
         pattern: pattern,
         workspace: workspace,
         session_id: session_id,
         created_at: Map.get_lazy(attrs, :created_at, &now/0),
         fragile?: Pattern.fragile?(pattern)
       }}
    end
  end

  def new(other), do: {:error, {:invalid_rule, other}}

  @doc "The rule reference `evaluate/1` answers with. Content-free by construction."
  @spec ref(t()) :: map()
  def ref(%__MODULE__{} = rule),
    do: %{scope: rule.scope, id: rule.id, pattern: rule.pattern.raw}

  @doc "The wire-facing projection: JSON-safe, no structs, no parsed pattern."
  @spec public(t()) :: map()
  def public(%__MODULE__{} = rule) do
    %{
      id: rule.id,
      scope: rule.scope,
      decision: rule.decision,
      pattern: rule.pattern.raw,
      kind: rule.pattern.kind,
      workspace: rule.workspace,
      session_id: rule.session_id,
      created_at: rule.created_at,
      fragile: rule.fragile?
    }
  end

  @doc false
  @spec valid?(term()) :: boolean()
  def valid?(%__MODULE__{} = rule) do
    rule.scope in @scopes and rule.decision in @decisions and
      match?(%Pattern{}, rule.pattern) and is_binary(rule.id) and rule.id != "" and
      is_binary(rule.created_at) and
      (rule.scope != :workspace or is_binary(rule.workspace)) and
      (rule.scope != :session or is_binary(rule.session_id))
  end

  def valid?(_rule), do: false

  defp scope(scope) when scope in @scopes, do: {:ok, scope}
  defp scope(other), do: {:error, {:unknown_permission_scope, other}}

  defp decision(decision) when decision in @decisions, do: {:ok, decision}
  defp decision(other), do: {:error, {:unknown_permission_decision, other}}

  defp pattern(%Pattern{} = pattern), do: {:ok, pattern}
  defp pattern(pattern) when is_binary(pattern), do: Pattern.parse(pattern)
  defp pattern(other), do: {:error, {:invalid_pattern, other}}

  defp allowed_decision(pattern, :allow) do
    case Pattern.decisions(pattern) do
      :any -> :ok
      :deny_or_ask_only -> {:error, {:pattern_cannot_allow, pattern.raw}}
    end
  end

  defp allowed_decision(_pattern, _decision), do: :ok

  # Canonicalised here, through the same resolver `Permissions.Request` puts a request's
  # own root through. `Rules.scoped?/2` compares the two by equality, so a rule stored
  # under `/tmp/project` and a session admitted at `/private/tmp/project` — which is the
  # same directory on macOS, and on any host with a symlinked prefix — would never meet.
  # It also makes the derived id stable: two operators naming one directory by two paths
  # get one rule rather than two that disagree.
  defp workspace(:workspace, workspace) when is_binary(workspace) and workspace != "",
    do: canonical_workspace(workspace)

  defp workspace(:workspace, _workspace), do: {:error, :workspace_rule_requires_workspace}

  defp workspace(_scope, workspace) when is_binary(workspace) and workspace != "",
    do: canonical_workspace(workspace)

  defp workspace(_scope, _workspace), do: {:ok, nil}

  defp canonical_workspace(workspace) do
    case Paths.canonicalize(workspace, nil) do
      {:ok, canonical} -> {:ok, canonical}
      {:error, _reason} -> {:ok, workspace}
    end
  end

  defp session_id(:session, session_id) when is_binary(session_id) and session_id != "",
    do: {:ok, session_id}

  defp session_id(:session, _session_id), do: {:error, :session_rule_requires_session}
  defp session_id(_scope, _session_id), do: {:ok, nil}

  defp id(scope, decision, pattern, workspace, session_id) do
    digest =
      [to_string(scope), to_string(decision), pattern.raw, workspace || "", session_id || ""]
      |> Enum.join("\n")

    "rule-" <>
      (:crypto.hash(:sha256, digest) |> Base.encode16(case: :lower) |> binary_part(0, 24))
  end

  defp now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
