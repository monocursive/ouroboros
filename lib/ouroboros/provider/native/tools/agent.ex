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

  That is enforced by construction rather than by review. No parameter of this tool widens
  the child's **posture**, and the two placement parameters — `machine:` and `workspace:` —
  do not widen it either: they move where the posture is applied, and the node they move it
  to enforces its own fences on top (see "A child on another machine"). What a child gets
  is therefore always the intersection:

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

  ## A child on another machine

  `machine:` places the child on another connected node of this fleet, and `workspace:`
  names the absolute path it works in **there**. The two are one parameter in two halves:
  a remote child without a workspace has nothing to work in — this session's paths name
  directories on *this* machine — and a workspace without a machine is refused, because a
  local child works in this session's own tree by construction and that is the containment
  rule rather than a default worth overriding.

  What travels is the parent's **posture**: the approval mode, the resolved sandbox mode,
  the plan flag, the tool intersection, the model, the turn and deadline bounds. What does
  not travel, and cannot, is the parent machine's *filesystem authority*: the child is
  fenced by the workspace root it was given **there**, judged by the target node's own
  permission rules, engine and hooks, sandboxed by the target's sandbox, and its transcript
  and ledger entries are written on the target. A worktree asked for with `worktree: true`
  is leased against the target's `workspace_allowed_roots`, not this node's. `add_dirs` is
  empty for a remote child for the same reason a worktree child gets none — a root of this
  machine is not a root of that one. Approvals still reach **this** session's human,
  relayed back by `Ouroboros.Provider.Native.Subagent`.

  Depth is unchanged by distance: a remote child is one level deeper than its parent, and
  its own `machine:` resolves against the nodes *it* can see.

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
      machine: [
        type: :string,
        default: "",
        doc:
          "Run the child on another machine of this fleet. Name a connected machine; omit " <>
            "to run it on this one."
      ],
      workspace: [
        type: :string,
        default: "",
        doc:
          "Absolute path of the child's workspace on that machine. Required with " <>
            "`machine:`; refused without it."
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

  alias Ouroboros.Cluster
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Subagent

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

  The spec carries `request_attrs` — a plain map — rather than a
  `Jido.Harness.SessionRequest`, and `worktree` is the *request* for one rather than a
  provisioned one. Both are deliberate and both are the same reason: `SessionRequest.new/1`
  validates `File.dir?(cwd)`, and a worktree is a directory on a disk. Building either here
  would answer a question about the **target's** filesystem by looking at this node's — the
  defect `docs/FLEET.md` records as F2. `Subagent`'s launch, which runs on the child's own
  node, does both.
  """
  @spec plan(map(), map()) :: {:ok, Subagent.spec()} | {:error, String.t()}
  def plan(input, parent) when is_map(input) and is_map(parent) do
    with {:ok, prompt} <- prompt(input),
         :ok <- depth_ok(parent),
         :ok <- capacity_ok(parent),
         {:ok, tools} <- tools(input, parent),
         background? = truthy(Map.get(input, "background")),
         :ok <- background_ok(background?, tools, parent),
         {:ok, placement} <- placement(input, parent) do
      child_id = Paths.new_session_id()
      subscriber = subscriber(parent, background?)

      request_attrs =
        %{
          provider: :native,
          cwd: placement.root,
          model: model(parent),
          provider_session_id: child_id,
          system_prompt: parent.request.system_prompt,
          allowed_tools: tools,
          disallowed_tools: parent.request.disallowed_tools,
          add_dirs: add_dirs(parent, placement),
          approval_mode: child_approval_mode(parent.approval_mode),
          sandbox_mode: parent.scope.sandbox_mode,
          reasoning_effort: parent.request.reasoning_effort,
          approval_timeout_ms: parent.request.approval_timeout_ms,
          provider_options: child_options(parent, input, child_id)
        }
        |> portable(placement.remote?)

      validate_spec(%{
        task_id: task_id(),
        prompt: prompt,
        description: description(input),
        subscriber: subscriber,
        node: placement.node,
        remote: placement.remote?,
        request_attrs: request_attrs,
        # The parent's own harness context, so the child belongs to the parent's
        # interactive session — the same `session_id`, the same principal in every ledger
        # entry the child writes. `Subagent` replaces `owner` with itself; nothing else
        # about it changes, which is what makes a child the parent's and not a stranger's.
        #
        # For a remote child the context is scrubbed first: a closure, a port or a
        # reference in it names something only this VM has, and shipping one would hand
        # the target a value that cannot mean there what it means here.
        context: context(parent, placement.remote?),
        worktree: placement.worktree?,
        background: background?,
        depth: parent.depth + 1,
        tools: tools,
        deadline_ms: deadline_ms(parent)
      })
    end
  end

  # `plan/2` is public because the loop uses it, but its parent map is assembled from
  # live session state rather than a struct. Validate the boundary before handing the
  # result to `Subagent.spawn/1`; this keeps a malformed internal parent from becoming a
  # crashed child and makes the cross-module contract truthful to Dialyzer as well.
  defp validate_spec(
         %{
           task_id: task_id,
           prompt: prompt,
           description: description,
           subscriber: subscriber,
           node: node,
           remote: remote?,
           request_attrs: request_attrs,
           context: context,
           worktree: worktree?,
           background: background?,
           depth: depth,
           tools: tools,
           deadline_ms: deadline_ms
         } = spec
       )
       when is_binary(task_id) and is_binary(prompt) and is_binary(description) and
              is_pid(subscriber) and is_atom(node) and is_boolean(remote?) and
              is_map(request_attrs) and is_map(context) and is_boolean(worktree?) and
              is_boolean(background?) and is_integer(depth) and depth >= 0 and
              is_list(tools) and is_integer(deadline_ms) and deadline_ms > 0 do
    if Enum.all?(tools, &is_binary/1) do
      {:ok, spec}
    else
      invalid_parent_spec()
    end
  end

  defp validate_spec(_spec), do: invalid_parent_spec()

  defp invalid_parent_spec,
    do:
      {:error,
       "Refused: the parent session could not provide a valid subagent execution context. " <>
         "Nothing ran and there is no task to collect."}

  @doc """
  The `provider_event` payload emitted when a child is spawned.

  `workspace` and `worktree` are read from `started` rather than from the spec, because
  for a remote child the spec only asked: the directory the child actually runs in — the
  worktree's root, or the target path as the target's own filesystem resolved it — is
  known on the target and returned from the launch.
  """
  @spec spawned_payload(map(), map()) :: map()
  def spawned_payload(spec, started) do
    child_node = Map.get(started, :node) || spec.node

    %{
      "phase" => "spawned",
      "task_id" => spec.task_id,
      "description" => spec.description,
      "provider_session_id" => started.provider_session_id,
      "workspace" => Map.get(started, :workspace) || spec.request_attrs.cwd,
      "worktree" => Map.get(started, :worktree) != nil,
      "tools" => spec.tools,
      "background" => spec.background,
      "depth" => spec.depth,
      "max_turns" => Map.get(spec.request_attrs.provider_options, "max_iterations"),
      "deadline_ms" => spec.deadline_ms,
      "node" => Atom.to_string(child_node),
      "remote" => child_node != node()
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

  # ---------------------------------------------------------------- placement

  # Where the child runs, and in which directory. One function because the two questions
  # are one question: `workspace` is admissible exactly when the child runs on a *different*
  # node, and refused in both of the other cases for reasons that are opposites of each
  # other — nothing to inherit there, everything already inherited here.
  defp placement(input, parent) do
    machine = text(Map.get(input, "machine"))
    workspace = text(Map.get(input, "workspace"))
    worktree? = truthy(Map.get(input, "worktree"))

    with {:ok, target} <- chosen_machine(machine),
         remote? = target != node(),
         {:ok, root} <- placement_root(remote?, machine, workspace, parent, target) do
      {:ok, %{node: target, remote?: remote?, root: root, worktree?: worktree?}}
    end
  end

  defp chosen_machine(""), do: {:ok, node()}

  defp chosen_machine(name) do
    if Node.alive?() do
      match_machine(name)
    else
      {:error, not_distributed_refusal(name)}
    end
  end

  # `Cluster.ensure_placeable/1` runs on the **chosen** target and never on the candidates.
  # Probing every connected node to answer one spawn would put a fleet-wide round trip in
  # front of every tool call, and the answer about the nodes nobody named is not wanted.
  defp match_machine(name) do
    with {:ok, target} <- resolve_machine(name, [node() | Node.list()]),
         do: ensure_placeable(target)
  end

  @doc """
  Resolves one `machine:` argument against a list of candidate nodes.

  Full node name first, then an unambiguous fragment, and the order matters: `core@a` is
  both the whole name of one machine and part of `core@a2`, and a caller who typed the
  whole name meant the whole name.

  Public and pure because resolution is a fact about a name and a list rather than about a
  fleet, and a refusal that names the candidates has to be readable back without one.
  `{:error, message}` is the sentence the model is shown.
  """
  @spec resolve_machine(String.t(), [node()]) :: {:ok, node()} | {:error, String.t()}
  def resolve_machine(name, candidates) when is_binary(name) and is_list(candidates) do
    case Enum.filter(candidates, &(Atom.to_string(&1) == name)) do
      [target] ->
        {:ok, target}

      _none_or_ambiguous ->
        case Enum.filter(candidates, &String.contains?(Atom.to_string(&1), name)) do
          [target] -> {:ok, target}
          [] -> {:error, unknown_machine_refusal(name, candidates)}
          many -> {:error, ambiguous_machine_refusal(name, many)}
        end
    end
  end

  # A `machine:` naming this node is simply local: there is no erpc, no remote workspace,
  # and nothing to place — so there is also nothing to check.
  defp ensure_placeable(target) when target == node(), do: {:ok, target}

  defp ensure_placeable(target) do
    case Cluster.ensure_placeable(target) do
      :ok -> {:ok, target}
      {:error, reason} -> {:error, unplaceable_refusal(target, reason)}
    end
  end

  defp placement_root(false, _machine, "", parent, _target), do: {:ok, parent.scope.root}

  defp placement_root(false, _machine, workspace, _parent, _target),
    do: {:error, local_workspace_refusal(workspace)}

  defp placement_root(true, machine, "", _parent, target),
    do: {:error, missing_workspace_refusal(machine, target)}

  defp placement_root(true, _machine, workspace, _parent, target) do
    if String.starts_with?(workspace, "/") do
      {:ok, workspace}
    else
      {:error, relative_workspace_refusal(workspace, target)}
    end
  end

  # A worktree means isolation and a remote child means another filesystem. In both cases
  # this node's extra roots are roots of the wrong tree, and re-attaching them would be the
  # opposite of what was asked for.
  defp add_dirs(_parent, %{worktree?: true}), do: []
  defp add_dirs(_parent, %{remote?: true}), do: []
  defp add_dirs(parent, _local), do: parent.scope.roots -- [parent.scope.root]

  # ---------------------------------------------------------------- placement refusals

  defp not_distributed_refusal(name),
    do:
      "Refused: `machine: \"#{name}\"` asks for another machine, and this node is not part " <>
        "of a fleet — it runs without distribution, so there is no other machine to reach. " <>
        "An operator forms a fleet with OUROBOROS_CLUSTER_STRATEGY (see docs/FLEET.md). " <>
        "Omit `machine:` to run the child here."

  defp unknown_machine_refusal(name, candidates) do
    case Enum.reject(candidates, &(&1 == node())) do
      [] ->
        "Refused: no machine matches `machine: \"#{name}\"` — this node is distributed but " <>
          "no other machine is connected to it right now, so there is nowhere to place a " <>
          "child. Omit `machine:` to run it here."

      connected ->
        "Refused: no machine matches `machine: \"#{name}\"`. The machines connected to this " <>
          "one are: #{join_nodes(connected)}. Name one of those — in full, or by a fragment " <>
          "that fits only it — or omit `machine:` to run the child here."
    end
  end

  defp ambiguous_machine_refusal(name, matches),
    do:
      "Refused: `machine: \"#{name}\"` matches #{length(matches)} connected machines: " <>
        "#{join_nodes(matches)}. Name one of them in full — a fragment that fits two " <>
        "machines cannot choose between them."

  @doc """
  Renders one `Ouroboros.Cluster.ensure_placeable/1` refusal as the sentence the model sees.

  Public for the same reason `resolve_machine/2` is: the wording is the interface, and a
  reason this runtime already knows how to explain should not need a fleet to read back.
  """
  @spec unplaceable_refusal(node(), term()) :: String.t()
  def unplaceable_refusal(target, reason),
    do:
      "Refused: #{target} is connected but cannot take placed work: #{placement_reason(reason)}. " <>
        "Placement needs a `:core` node running this same Ouroboros and OTP release. Name " <>
        "another machine, or omit `machine:` to run the child here."

  defp placement_reason(:node_not_connected), do: "it is not connected any more"
  defp placement_reason(:runtime_not_running), do: "its Ouroboros runtime is not running"

  defp placement_reason({:role, actual, expected}),
    do: "its role is #{actual}, and placement needs #{expected}"

  defp placement_reason({:runtime_incompatible, actual, expected}),
    do: "its runtime #{inspect(actual)} is not this one's #{inspect(expected)}"

  defp placement_reason({:fleet_probe_failed, detail}),
    do: "it could not be probed (#{inspect(detail)})"

  defp placement_reason(other), do: inspect(other)

  defp local_workspace_refusal(workspace),
    do:
      "Refused: `workspace: \"#{workspace}\"` means something only together with `machine:`. " <>
        "A child running on this machine works in this session's own tree — its root, or a " <>
        "git worktree of it — and that is the containment rule rather than a default worth " <>
        "overriding. Drop `workspace:`, or name the `machine:` that path belongs to."

  defp missing_workspace_refusal(name, target),
    do:
      "Refused: `machine: \"#{name}\"` resolves to #{target}, and a child there needs a " <>
        "`workspace:` — the absolute path of the tree it should work in on that machine. " <>
        "This session's own paths name directories on this machine and mean nothing on that " <>
        "one, so there is nothing for the child to inherit."

  defp relative_workspace_refusal(workspace, target),
    do:
      "Refused: `workspace: \"#{workspace}\"` is not an absolute path. It would be resolved " <>
        "against a working directory on this machine and name something else entirely on " <>
        "#{target} — give the absolute path of the tree there."

  defp join_nodes(nodes),
    do: nodes |> Enum.map(&Atom.to_string/1) |> Enum.sort() |> Enum.join(", ")

  # ---------------------------------------------------------------- start refusals

  @doc """
  Renders one `Ouroboros.Provider.Native.Subagent.spawn/1` failure as a sentence.

  The reasons a launch can fail are now mostly facts about the **target** node — its
  worktree root, its filesystem, its reachability — and each of them has an action
  attached, so each gets said rather than inspected into the transcript.
  """
  @spec start_refusal(term()) :: String.t()
  def start_refusal({:subagent_worktree_root_not_admitted, target}),
    do: worktree_root_refusal(target)

  def start_refusal({:subagent_worktree_unprovisionable, target, reason}),
    do: worktree_create_refusal(target, reason)

  def start_refusal({:subagent_request_invalid, target, cwd, message}),
    do: workspace_unusable_refusal(target, cwd, message)

  def start_refusal({:subagent_unstartable, {:node_unreachable, target, reason}}),
    do:
      "Refused: #{target} could not be reached to start the child (#{inspect(reason)}). " <>
        "No start acknowledgement was received. Name another machine, or omit `machine:` " <>
        "to run the child here."

  def start_refusal({:subagent_unstartable, {:remote_start_ambiguous, target, task_id, detail}}),
    do:
      "Refused: the start of subagent #{task_id} on #{target} is ambiguous after two " <>
        "idempotent attempts (#{inspect(detail)}). It may have started, but no collectible " <>
        "handle reached this session. Any such child still monitors this parent and stops " <>
        "when the parent turn/session disappears; do not assume that nothing ran. Check " <>
        "that machine before retrying materially different work."

  def start_refusal({:subagent_unstartable, {:remote_spawn_failed, target, detail}}),
    do:
      "Refused: #{target} returned an invalid start result (#{inspect(detail)}). No " <>
        "collectible task handle was returned."

  def start_refusal(reason),
    do:
      "Refused: the subagent could not be started (#{inspect(reason)}). Nothing ran, " <>
        "and there is no task to collect."

  # A refusal here is never a silent fall back to the parent's tree. A model that asked
  # for isolation and got the parent's working copy would make edits it believes are
  # contained, which is the worst of the three possible outcomes.
  defp worktree_root_refusal(target) when target == node(),
    do:
      "Refused: this node's worktree root is not inside `workspace_allowed_roots`, so a " <>
        "worktree cannot be leased. An operator can add it with OUROBOROS_WORKSPACE_ROOTS. " <>
        "Spawn the child without `worktree: true` if sharing this tree is acceptable."

  defp worktree_root_refusal(target),
    do:
      "Refused: #{target}'s worktree root is not inside its `workspace_allowed_roots`, so a " <>
        "worktree cannot be leased there. An operator can add it with " <>
        "OUROBOROS_WORKSPACE_ROOTS on that machine. Spawn the child without " <>
        "`worktree: true` if sharing that tree is acceptable."

  defp worktree_create_refusal(target, reason) when target == node(),
    do:
      "Refused: a worktree was asked for and could not be provisioned " <>
        "(#{inspect(reason)}). The child was not started in this session's own tree " <>
        "instead — you asked for isolation, and running without it would not be that."

  defp worktree_create_refusal(target, reason),
    do:
      "Refused: a worktree was asked for on #{target} and could not be provisioned there " <>
        "(#{inspect(reason)}). The child was not started in that machine's tree instead — " <>
        "you asked for isolation, and running without it would not be that."

  defp workspace_unusable_refusal(target, cwd, message) when target == node(),
    do:
      "Refused: #{cwd} is not a usable workspace on this machine (#{message}). Nothing " <>
        "ran and there is no task to collect."

  defp workspace_unusable_refusal(target, cwd, message),
    do:
      "Refused: #{cwd} is not a usable workspace on #{target} (#{message}). A path that " <>
        "exists on this machine does not exist on that one for being named here — give " <>
        "`workspace:` a directory that exists there."

  # Who the child reports to, and the whole of the foreground/background difference. The
  # loop can put an approval in front of a person and cannot outlive the turn; the session
  # outlives the turn and has no approval channel of its own. A child gets exactly one of
  # them, which is why a background child is refused above unless it cannot ask.
  defp subscriber(parent, true), do: parent.background_subscriber
  defp subscriber(parent, false), do: parent.subscriber

  # ---------------------------------------------------------------- portability

  # A local spec is handed on exactly as it always was: nothing about it crosses a node
  # boundary, and scrubbing it would be a behaviour change bought for nothing.
  defp context(parent, false), do: parent.context

  defp context(parent, true), do: portable_context(parent.context)

  @doc """
  The parent's harness context in the shape it can cross a node boundary in.

  Two things happen to it, and each has one reason:

    * every fun, port and reference is dropped, at any depth, because each of them names
      something only the parent's VM has. `config` is where one would arrive — it is
      whatever an operator put in `:jido_harness, :provider_config` — and dropping the
      offending entry rather than the whole map keeps the rest of the operator's
      configuration reaching the child;
    * `owner` is emptied rather than carried. `Ouroboros.Provider.Native.Subagent` sets it
      to itself on the target anyway, and a pid of the parent node left in the field a
      child session emits every raw event to would be one mistake away from a child
      streaming its whole stream across the fleet into the parent's harness worker.

  Everything else — the session id that makes the child's ledger entries the parent's, the
  provider, the adapter and process-manager modules — is atoms and binaries, and means the
  same on any node of one fleet.
  """
  @spec portable_context(map()) :: map()
  def portable_context(context) when is_map(context),
    do: context |> scrub() |> Map.put(:owner, nil)

  defp portable(attrs, false), do: attrs

  defp portable(attrs, true),
    do: Map.update(attrs, :provider_options, %{}, &scrub/1)

  # Everything a term can hold that means something only in the VM that made it. A fun
  # closes over this node's modules and captured state; a port and a reference name
  # something this VM alone has. **Pids are deliberately portable** — the subscriber is
  # one, and reaching back to it across the fleet is the entire point of a remote child.
  defp scrub(map) when is_map(map) and not is_struct(map) do
    map
    |> Enum.flat_map(fn {key, value} ->
      cond do
        not portable?(key) -> []
        is_map(value) and not is_struct(value) -> [{key, scrub(value)}]
        portable?(value) -> [{key, value}]
        true -> []
      end
    end)
    |> Map.new()
  end

  defp scrub(value), do: value

  @doc "Whether one term means on another node what it means here."
  @spec portable?(term()) :: boolean()
  def portable?(value) when is_function(value) or is_port(value) or is_reference(value), do: false
  def portable?(value) when is_list(value), do: Enum.all?(value, &portable?/1)

  def portable?(value) when is_tuple(value),
    do: value |> Tuple.to_list() |> Enum.all?(&portable?/1)

  def portable?(value) when is_map(value),
    do: Enum.all?(value, fn {key, inner} -> portable?(key) and portable?(inner) end)

  def portable?(_value), do: true

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

  defp truthy(true), do: true
  defp truthy("true"), do: true
  defp truthy(_other), do: false

  defp text(value) when is_binary(value), do: String.trim(value)
  defp text(nil), do: ""
  defp text(value), do: value |> to_string() |> String.trim()

  defp clip(text, limit) when byte_size(text) <= limit, do: text
  defp clip(text, limit), do: binary_part(text, 0, limit) <> "…"
end
