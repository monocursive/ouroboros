defmodule Ouroboros.Provider.Native.Tools.Agent do
  @moduledoc """
  Spawn a child native session with its own context, and get its answer back (G3).

  Every leader has this tool — Claude Code's `Task`, Codex's and Amp's subagents (R1 §4,
  R3 §6) — and all of them exist for one reason: a search that reads forty files costs
  forty files' worth of the *parent's* context, and the parent only needed the answer.
  A subagent spends its own window and hands back a summary.

  ## What a child is, exactly

  A child is a native session — the same `Ouroboros.Provider.Native.Session`, the same
  loop, the same permission engine, the same hooks, the same effect ledger — opened
  inside the parent's interactive session and owned by
  `Ouroboros.Provider.Native.Subagent`. It is **not** a second interactive session and
  it is **not** a delegated coding task (G1): no rail row, no coordinator, no separate
  workspace lease. Its progress reaches the client as `provider_event`s of the parent
  with `kind: "subagent"`, and its own transcript lives under its own session directory,
  addressable by the `provider_session_id` those events name.

  ## A child may never be more permissive than its parent

  That is enforced by construction rather than by review, and this tool has **no
  parameter that could widen anything**:

    * `approval_mode` is the parent's own effective mode. A planning parent hands its
      child `plan: true`, so the child plans too.
    * `sandbox_mode` is the parent's *resolved* scope mode — already `:read_only` when
      the parent is planning.
    * the tool set is the **intersection** of what the caller asked for and what the
      parent actually has, so a `tools:` naming something the parent was denied buys
      nothing.
    * the workspace is the parent's root, or a git worktree of it. `add_dirs` are
      inherited only when there is no worktree; a worktree means isolation, and quietly
      re-attaching the parent's extra roots to it would be the opposite.
    * `agent` itself disappears from the child's tool list at the depth cap.

  ## Bounds, all of them

    * **Depth 2.** The root session is depth 0. It may spawn children (depth 1), and they
      may spawn children (depth 2). A depth-2 session has no `agent` in its schema list
      and its loop refuses the call by name if it invents one.
    * **Four running children per parent session.** A fifth is **refused, not queued**: a
      queue would block the parent's turn on work it cannot see, and the honest answer —
      "collect one first" — is something the model can act on. Settled-but-uncollected
      children do not count towards it; a parent may track at most 32 in total.
    * **`max_turns`** — the child's model round-trips — defaults to 12 and is capped at 30.
    * **A wall-clock deadline** of 300 s by default, at most 900 s, settable per node
      with `provider_options["subagent_deadline_ms"]`. `background: false` blocks the
      parent's tool call for at most that long, and reports `timed_out` when it fires.
    * **A 16 KiB summary**, of which at most 12 KiB is the child's own final message.

  ## Background children, and why one can be refused at spawn

  `background: true` returns a `task_id` immediately; `agent_result` collects it later.
  The child then outlives the turn that spawned it, which means the parent's approval
  channel — a loop process, which ends with the turn — is not there any more. A child
  that could raise an approval nobody can answer would hang until its own deadline, so
  it is **refused at spawn** unless it cannot raise one: either the parent runs in
  `auto_approve`, or the child's tools are all read-only. The refusal names the fix.

  A background child is stopped when the **parent session closes** — not when the turn
  ends — and a collection after that says `stopped` rather than pretending it finished.
  """

  use Jido.Action,
    name: "agent",
    description:
      "Spawn a child agent with its own context window and get a summary back. Use it " <>
        "for work whose *findings* you need but whose *reading* you do not — searching a " <>
        "large codebase, checking a hypothesis in unfamiliar files, running several " <>
        "independent explorations at once. The child sees no part of this conversation " <>
        "except the prompt you write, so put everything it needs in that prompt. It can " <>
        "never use a tool you do not have, and never run more permissively than you do.",
    schema: [
      prompt: [
        type: :string,
        required: true,
        doc:
          "The child's entire instruction. It shares none of your context, so state the " <>
            "goal, the constraints, and exactly what to report back."
      ],
      description: [
        type: :string,
        default: "",
        doc: "A three- to five-word label for this child, shown in the transcript."
      ],
      tools: [
        type: {:list, :string},
        default: [],
        doc:
          "Tool names the child may use. Empty means every tool you have. The child " <>
            "always gets the intersection with your own tools, never more."
      ],
      worktree: [
        type: :boolean,
        default: false,
        doc:
          "Run the child in its own git worktree of this workspace, so its edits cannot " <>
            "touch your tree. Refused with a reason when this node cannot provision one."
      ],
      background: [
        type: :boolean,
        default: false,
        doc:
          "Return a task_id immediately instead of waiting. Collect it with agent_result. " <>
            "A background child cannot ask anyone for permission."
      ],
      max_turns: [
        type: :pos_integer,
        default: 12,
        doc: "How many model round-trips the child may take. Maximum 30."
      ]
    ]

  alias Jido.Harness.SessionRequest
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Workspace.Worktree

  @max_depth 2
  @max_concurrent 4
  @max_tracked 32
  @default_max_turns 12
  @max_turns 30
  @default_deadline_ms 300_000
  @min_deadline_ms 1_000
  @max_deadline_ms 900_000
  @max_prompt_bytes 32 * 1024
  @max_description_bytes 200
  @max_tools 64

  # The tools whose `Ouroboros.Provider.Native.Tools.classify/3` mode is `:read` for every
  # possible argument, which is what makes them unable to raise an approval under any
  # posture (`Loop.decide/5` allows `:read` outright). `code_intel` is deliberately absent
  # — its `rename` writes — and so is `web_fetch`, which is `:network`, and `ask_user`,
  # whose whole purpose is to reach a person.
  @never_asking ~w(read grep glob ls plan skill)

  @doc "The maximum nesting depth: a child may spawn children, a grandchild may not."
  @spec max_depth() :: pos_integer()
  def max_depth, do: @max_depth

  @doc "How many children of one parent session may run at once."
  @spec max_concurrent() :: pos_integer()
  def max_concurrent, do: @max_concurrent

  @doc "How many children of one parent session may be tracked, running or settled."
  @spec max_tracked() :: pos_integer()
  def max_tracked, do: @max_tracked

  @doc "This tool is driven by the loop process, not by the tool task."
  @spec interactive?() :: boolean()
  def interactive?, do: true

  @doc """
  Turns one `agent` call plus the parent's posture into a child specification.

  Every refusal is a sentence the model can act on, because the alternative — a tool
  result that says "invalid arguments" — teaches it to retry the same call. Returns
  `{:ok, spec}` for `Ouroboros.Provider.Native.Subagent.spawn/1`, or `{:error, message}`.
  """
  @spec plan(map(), map()) :: {:ok, map()} | {:error, String.t()}
  def plan(input, parent) when is_map(input) and is_map(parent) do
    with {:ok, prompt} <- prompt(input),
         :ok <- depth_ok(parent),
         :ok <- capacity_ok(parent),
         {:ok, tools} <- tools(input, parent),
         background? = truthy(Map.get(input, "background")),
         :ok <- background_ok(background?, tools, parent),
         {:ok, workspace, worktree} <- workspace(input, parent) do
      child_id = Paths.new_session_id()
      subscriber = subscriber(parent, background?)

      request =
        SessionRequest.new!(%{
          provider: :native,
          cwd: workspace,
          model: model(parent),
          provider_session_id: child_id,
          system_prompt: parent.request.system_prompt,
          allowed_tools: tools,
          disallowed_tools: parent.request.disallowed_tools,
          add_dirs: add_dirs(parent, worktree),
          approval_mode: child_approval_mode(parent.approval_mode),
          sandbox_mode: parent.scope.sandbox_mode,
          reasoning_effort: parent.request.reasoning_effort,
          approval_timeout_ms: parent.request.approval_timeout_ms,
          provider_options: child_options(parent, input, child_id)
        })

      {:ok,
       %{
         task_id: task_id(),
         prompt: prompt,
         description: description(input),
         subscriber: subscriber,
         request: request,
         # The parent's own harness context, so the child belongs to the parent's
         # interactive session — the same `session_id`, the same principal in every ledger
         # entry the child writes. `Subagent` replaces `owner` with itself; nothing else
         # about it changes, which is what makes a child the parent's and not a stranger's.
         context: parent.context,
         worktree: worktree,
         background: background?,
         depth: parent.depth + 1,
         tools: tools,
         deadline_ms: deadline_ms(parent)
       }}
    end
  end

  @doc "The `provider_event` payload emitted when a child is spawned."
  @spec spawned_payload(map(), map()) :: map()
  def spawned_payload(spec, started) do
    %{
      "phase" => "spawned",
      "task_id" => spec.task_id,
      "description" => spec.description,
      "provider_session_id" => started.provider_session_id,
      "workspace" => spec.request.cwd,
      "worktree" => spec.worktree != nil,
      "tools" => spec.tools,
      "background" => spec.background,
      "depth" => spec.depth,
      "max_turns" => Map.get(spec.request.provider_options, "max_iterations"),
      "deadline_ms" => spec.deadline_ms
    }
  end

  @doc "What the model is told when it calls `agent` past the depth cap."
  @spec depth_refusal(non_neg_integer()) :: String.t()
  def depth_refusal(depth),
    do:
      "Refused: this session is #{depth} levels deep and the subagent depth cap is " <>
        "#{@max_depth}. A grandchild may not spawn children — do this work yourself and " <>
        "report it to the agent that spawned you."

  @impl true
  def run(_params, _context) do
    {:ok,
     %{
       output:
         "agent cannot run outside an interactive native session: there is no parent to " <>
           "own the child or to carry its approvals. Do the work in this session instead.",
       is_error: true
     }}
  end

  # ---------------------------------------------------------------- validation

  defp prompt(input) do
    case input |> Map.get("prompt") |> text() do
      "" ->
        {:error,
         "agent needs a `prompt`. The child shares none of your context, so the prompt " <>
           "has to state the goal, the constraints, and what to report back."}

      prompt ->
        {:ok, clip(prompt, @max_prompt_bytes)}
    end
  end

  defp depth_ok(%{depth: depth}) when depth >= @max_depth, do: {:error, depth_refusal(depth)}
  defp depth_ok(_parent), do: :ok

  defp capacity_ok(%{running: running}) when running >= @max_concurrent,
    do:
      {:error,
       "Refused: #{running} subagents of this session are already running and the limit " <>
         "is #{@max_concurrent}. Collect one with `agent_result` before spawning another " <>
         "— a queued spawn would block this turn on work you cannot see."}

  defp capacity_ok(%{tracked: tracked}) when tracked >= @max_tracked,
    do:
      {:error,
       "Refused: this session is already tracking #{tracked} subagents, the maximum. " <>
         "Collect the finished ones with `agent_result` first."}

  defp capacity_ok(_parent), do: :ok

  # The intersection, and the reason it is an intersection rather than a check: a child
  # given a name its parent does not have would be a session that can do something the
  # session that spawned it cannot, which is the one property this tool must not have.
  defp tools(input, parent) do
    available = parent.tool_names -- child_forbidden(parent)

    requested =
      input
      |> Map.get("tools")
      |> List.wrap()
      |> Enum.map(&text/1)
      |> Enum.reject(&(&1 == ""))
      |> Enum.uniq()
      |> Enum.take(@max_tools)

    case requested do
      [] ->
        {:ok, available}

      names ->
        case Enum.filter(names, &(&1 in available)) do
          [] ->
            {:error,
             "Refused: none of #{inspect(names)} is a tool this session has. A child can " <>
               "only be given tools you already have: #{Enum.join(available, ", ")}."}

          allowed ->
            {:ok, allowed}
        end
    end
  end

  # A child one level below the cap gets no `agent` and no `agent_result`, so the cap is
  # visible in the child's own schema list rather than only in a refusal it has to
  # discover.
  defp child_forbidden(%{depth: depth}) when depth + 1 >= @max_depth,
    do: ["agent", "agent_result"]

  defp child_forbidden(_parent), do: []

  defp background_ok(false, _tools, _parent), do: :ok

  defp background_ok(true, _tools, %{session_pid: nil}),
    do:
      {:error,
       "Refused: this run has no session process to hold a background child past the end " <>
         "of the turn. Spawn it with `background: false`."}

  defp background_ok(true, _tools, %{approval_mode: :auto_approve}), do: :ok

  defp background_ok(true, tools, _parent) do
    asking = Enum.reject(tools, &(&1 in @never_asking))

    if asking == [] do
      :ok
    else
      {:error,
       "Refused: a background child outlives the turn that spawned it, so an approval it " <>
         "raises has nobody to reach and would hang until its deadline. " <>
         "#{Enum.join(asking, ", ")} can ask. Either give it only read-only tools " <>
         "(#{Enum.join(@never_asking, ", ")}), or spawn it with `background: false`."}
    end
  end

  # ---------------------------------------------------------------- workspace

  defp workspace(input, parent) do
    if truthy(Map.get(input, "worktree")) do
      provision_worktree(parent)
    else
      {:ok, parent.scope.root, nil}
    end
  end

  # A refusal here is never a silent fall back to the parent's tree. A model that asked
  # for isolation and got the parent's working copy would make edits it believes are
  # contained, which is the worst of the three possible outcomes.
  defp provision_worktree(parent) do
    if Worktree.admissible?() do
      case Worktree.create(parent.scope.root, worktree_id()) do
        {:ok, worktree} ->
          {:ok, worktree.root, Worktree.public(worktree)}

        {:error, reason} ->
          {:error,
           "Refused: a worktree was asked for and could not be provisioned " <>
             "(#{inspect(reason)}). The child was not started in this session's own tree " <>
             "instead — you asked for isolation, and running without it would not be that."}
      end
    else
      {:error,
       "Refused: this node's worktree root is not inside `workspace_allowed_roots`, so a " <>
         "worktree cannot be leased. An operator can add it with OUROBOROS_WORKSPACE_ROOTS. " <>
         "Spawn the child without `worktree: true` if sharing this tree is acceptable."}
    end
  end

  defp add_dirs(_parent, worktree) when is_map(worktree), do: []
  defp add_dirs(parent, _none), do: parent.scope.roots -- [parent.scope.root]

  # Who the child reports to, and the whole of the foreground/background difference. The
  # loop can put an approval in front of a person and cannot outlive the turn; the session
  # outlives the turn and has no approval channel of its own. A child gets exactly one of
  # them, which is why a background child is refused above unless it cannot ask.
  defp subscriber(parent, true), do: parent.background_subscriber
  defp subscriber(parent, false), do: parent.subscriber

  # ---------------------------------------------------------------- options

  defp child_options(parent, input, child_id) do
    parent.options
    |> Map.new(fn {key, value} -> {to_string(key), value} end)
    |> Map.take(["tool_timeout_ms", "checkpoint_limit", "subagent_deadline_ms", "subagent_model"])
    |> Map.merge(%{
      "max_iterations" => max_turns(input),
      "subagent_depth" => parent.depth + 1,
      "subagent_parent" => parent.provider_session_id,
      "subagent_task_id" => child_id
    })
    |> then(fn options ->
      if parent.approval_mode == :plan, do: Map.put(options, "plan", true), else: options
    end)
  end

  # `:plan` is a loop-only mode: `Jido.Harness.SessionRequest` validates `approval_mode`
  # against four members and would refuse it. A planning parent therefore hands its child
  # `plan: true` in `provider_options` — the same channel a planning session is started
  # through anywhere else — and `:prompt` as the mode underneath it.
  defp child_approval_mode(:plan), do: :prompt
  defp child_approval_mode(mode) when mode in [:prompt, :auto_edit, :auto_approve], do: mode
  defp child_approval_mode(_other), do: :prompt

  defp model(parent) do
    case option(parent.options, "subagent_model") do
      spec when is_binary(spec) and spec != "" -> spec
      _unset -> parent.model_spec
    end
  end

  defp deadline_ms(parent) do
    case option(parent.options, "subagent_deadline_ms") do
      value when is_integer(value) and value > 0 ->
        value |> max(@min_deadline_ms) |> min(@max_deadline_ms)

      _unset ->
        @default_deadline_ms
    end
  end

  defp max_turns(input) do
    case Map.get(input, "max_turns") do
      value when is_integer(value) and value > 0 -> min(value, @max_turns)
      _unset -> @default_max_turns
    end
  end

  # `provider_options` may arrive with either key spelling — the harness accepts both —
  # so both are looked up, and never by minting an atom from a string.
  defp option(options, key) when is_map(options) do
    Map.get(options, key) ||
      Enum.find_value(options, fn {candidate, value} ->
        if to_string(candidate) == key, do: value
      end)
  end

  defp option(_options, _key), do: nil

  # ---------------------------------------------------------------- helpers

  defp description(input) do
    case input |> Map.get("description") |> text() do
      "" -> "subagent"
      text -> clip(text, @max_description_bytes)
    end
  end

  # Embeds `node()` for the reason every other id in this runtime does: a task id is read
  # across a fleet, and a random value alone collides with the same one minted elsewhere.
  defp task_id do
    node_tag =
      :sha256
      |> :crypto.hash(Atom.to_string(node()))
      |> Base.url_encode64(padding: false)
      |> binary_part(0, 8)

    "sub-" <> node_tag <> "-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)
  end

  # `Ouroboros.Workspace.Worktree` validates this as a directory name, so it is minted in
  # the shape that validator accepts rather than borrowed from a caller.
  defp worktree_id,
    do: "subagent-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

  defp truthy(true), do: true
  defp truthy("true"), do: true
  defp truthy(_other), do: false

  defp text(value) when is_binary(value), do: String.trim(value)
  defp text(nil), do: ""
  defp text(value), do: value |> to_string() |> String.trim()

  defp clip(text, limit) when byte_size(text) <= limit, do: text
  defp clip(text, limit), do: binary_part(text, 0, limit) <> "…"
end
