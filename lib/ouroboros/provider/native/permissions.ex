defmodule Ouroboros.Provider.Native.Permissions do
  @moduledoc """
  The one call the native loop makes into the permission engine, and the only thing it
  knows about whether that engine exists.

  The shared engine adapter maps unavailable engines and unknown answers to an ask.
  This native policy adds plan-mode refusal before consulting that adapter.

  ## Plan mode (B2)

  A session the operator put into plan mode is read-only for the duration, and that is
  decided *here* rather than by each tool, for two reasons. The loop routes every tool
  call through `evaluate/1` before it reaches a tool, so this is the one place a posture
  can be enforced once; and a refusal that comes back from the permission layer carries a
  `rule_ref` the loop already renders with `deny_message/2`, so the model is told **why**
  it may not write in words that name planning rather than in a sandbox error that does
  not.

  The signal is `context.approval_mode == :plan`, which
  `Ouroboros.Provider.Native.Loop.permission_request/2` copies straight off the loop's own
  `approval_mode` — set to `:plan` by `Ouroboros.Provider.Native.Session` for exactly the
  turns a planning session runs. It is not a value the harness's `SessionRequest` accepts
  (its `approval_mode` is a four-member `Zoi.enum`), which is why plan mode is its own
  `plan` key everywhere a caller can reach and only ever `:plan` on the loop's internal
  struct.

  **Plan mode outranks the engine in the deny direction only.** A rule that would have
  allowed a write does not un-plan a session: the operator asked for a read-only posture
  and a repository-scoped rule is not the authority that revokes it. A rule that would
  have denied is not consulted, because the answer is the same and the reason a planning
  session gives is the more useful one. Nothing here can *allow* anything.

  `:read` and `:network` are untouched. Reading the workspace and fetching a page are the
  work of planning; refusing them would produce plans written from memory, which is the
  failure this mode exists to avoid.
  """

  # The same node-level key the interactive plane reads for external approvals, so one
  # setting names the engine for every seam; absent, the durable engine is the default.
  alias Ouroboros.Control.Permissions.Engine

  @type decision :: {:allow, term()} | {:deny, term()} | {:ask, term()}

  # The two effects a planning session refuses. `:read` and `:network` are how a plan gets
  # written; refusing them would leave the model guessing at the workspace it is planning
  # against.
  @planning_refuses [:write, :execute]

  @doc """
  Evaluates one tool attempt. `{:ask, :no_engine}` when no engine is loaded.

  A request whose `context.approval_mode` is `:plan` and whose `mode` is `:write` or
  `:execute` is refused here, before the engine is asked at all — see the module doc for
  why the posture outranks a rule in that one direction.
  """
  @spec evaluate(map()) :: decision()
  def evaluate(request) when is_map(request) do
    case planning_refusal(request) do
      {:deny, _rule} = refusal -> refusal
      :ok -> engine_decision(request)
    end
  end

  @doc """
  Whether a permission request describes a session that is planning.

  Exposed so a caller can ask the same question this module answers rather than
  re-deriving the convention from `context.approval_mode` somewhere else.
  """
  @spec planning?(map()) :: boolean()
  def planning?(request) when is_map(request) do
    case Map.get(request, :context) do
      context when is_map(context) -> Map.get(context, :approval_mode) == :plan
      # A request with no context, or one whose context is not a map, is not a planning
      # request — and saying so is the whole answer. Raising here would turn a malformed
      # request into a crashed turn, which is the one direction this module never takes.
      _absent -> false
    end
  end

  def planning?(_request), do: false

  defp planning_refusal(request) do
    if planning?(request) and Map.get(request, :mode) in @planning_refuses do
      {:deny, {:plan_mode, Map.get(request, :mode)}}
    else
      :ok
    end
  end

  defp engine_decision(request), do: Engine.evaluate(request)

  @doc """
  Records a resolved decision in the engine's ledger.

  `{:error, :no_engine}` when there is nothing to record into. The loop keeps going: an
  unrecorded decision is a gap in the audit trail, not a reason to refuse work the
  operator already approved — and the session's own events still carry
  `approval_requested`/`approval_resolved`.
  """
  @spec record(String.t(), map()) :: :ok | {:error, term()}
  defdelegate record(decision_id, attrs), to: Engine

  @doc "Whether a rule engine is available on this node."
  @spec engine?() :: boolean()
  def engine?, do: Engine.exported?(:evaluate, 1)

  @doc """
  How a refusal reads in a tool result. Names the rule, never invents one.

  The plan-mode refusal is the one that does not name a rule, because no rule produced it.
  It says what the posture is, what is still available, and what happens at the end of the
  turn — a model told only "denied" retries the same write, and a model told "this session
  is planning" writes the plan instead.
  """
  @spec deny_message(String.t(), term()) :: String.t()
  def deny_message(tool, {:plan_mode, mode}) do
    "Refused: this session is in **plan mode**, so `#{tool}` cannot run — plan mode " <>
      "refuses every #{mode} until the operator leaves it. Keep exploring with the " <>
      "read-only tools, then record your plan with the `plan` tool and stop. When your " <>
      "turn ends the operator is asked whether to accept the plan and how to run it; " <>
      "nothing is written or executed before they answer."
  end

  def deny_message(tool, rule_ref) do
    "Refused: permission rule #{format_rule(rule_ref)} denies #{tool} for this session."
  end

  @doc """
  The rule a human approval would create, offered alongside the ask. The engine's own
  pattern, or `nil`.

  This module used to build a *shape* of a rule here — `%{"tool" => …, "command_prefix" =>
  …}` — from the command's first whitespace token. Nothing could use it. The only thing a
  client's "don't ask again" row can call is `permissions.add`, whose `pattern` is
  "validated by `Control.Permissions.Pattern` and by nothing else"
  (`Ouroboros.Gateway.Methods`), and `Rule.new/1` refuses a map outright with
  `{:invalid_pattern, …}`. A map on that key therefore reached every client as a rule row
  it could not draw and a rule nobody could save, and one token of a command line
  (`"dir=$(printf"`) was not a rule in the first place.

  So it is asked for rather than built: `suggest/1` is the engine's, the grammar is the
  engine's, and this module — the loop's one door to the engine — carries the answer
  across unchanged. That is what every other emitter in the tree already does
  (`Control.Permissions.Seam.suggested/2`, `Interactive.Task.Approvals`,
  `Interactive.Task.Shell`), each guarding `is_binary` exactly as this now does.

  `nil` where no engine is loaded, where it exports no `suggest/1`, or where it had
  nothing honest to say. The caller omits the key rather than inventing one: this surface
  never writes the rule language itself.

  The argument is the same request `evaluate/1` takes, so the suggestion is derived from
  the mode, the domains and the context the engine was asked about — including the
  resolved `context.app` a Computer Use ask carries, which is where
  `ComputerUse(app:…)` comes from.
  """
  @spec suggested_rule(map()) :: String.t() | nil
  def suggested_rule(request), do: Engine.suggest(request)

  defp format_rule(nil), do: "(unnamed)"
  defp format_rule(rule) when is_binary(rule), do: rule
  defp format_rule(rule), do: inspect(rule)
end
