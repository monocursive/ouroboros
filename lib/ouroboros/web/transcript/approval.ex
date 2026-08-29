defmodule Ouroboros.Web.Transcript.Approval.Option do
  @moduledoc """
  One answer the provider itself offered, as ACP spells them.

  The `optionId` is kept even though `interactive.respond_approval` refuses
  `provider_options`: it is what the label *means* on the wire, and a card that showed a
  vendor's wording while sending something else would be lying about the button
  (`tui/src/ui/transcript.rs:261-273`).
  """

  defstruct [:option_id, :kind, :answer, name: ""]

  @type t :: %__MODULE__{
          option_id: String.t() | nil,
          name: String.t(),
          kind: String.t() | nil,
          answer: String.t() | nil
        }

  @doc """
  Which of the four accepted answers this vendor label corresponds to, where its `kind`
  says so.

  `nil` for a `kind` this build does not recognize — an unknown option is shown with its
  own words and mapped onto nothing, because guessing whether a novel option approves or
  refuses is the one mistake that cannot be undone. The tables are
  `Dialect.ACP.select_permission_option/2`'s, read in the same direction
  (`tui/src/ui/transcript.rs:284`).
  """
  @spec decision(t()) :: {:approve | :deny, :once | :session} | nil
  def decision(%__MODULE__{kind: kind}) when kind in ["allow_once", "allow", "approve"],
    do: {:approve, :once}

  def decision(%__MODULE__{kind: kind})
      when kind in ["allow_always", "allow_session", "always"],
      do: {:approve, :session}

  def decision(%__MODULE__{kind: kind}) when kind in ["reject_once", "reject", "deny"],
    do: {:deny, :once}

  def decision(%__MODULE__{kind: kind}) when kind in ["reject_always", "deny_always"],
    do: {:deny, :session}

  def decision(%__MODULE__{}), do: nil

  @doc """
  Whether a surface can send this option at all.

  Two shapes answer, for different reasons. A vendor option answers where its `kind` names
  one of the four `interactive.respond_approval` accepts. An `ask_user` option answers
  because it *is* the answer: a bare string carries no `kind` and means nothing to the
  four-way table, and choosing it approves the question once with those words riding
  `reason` — the only key the envelope will carry to
  `Provider.Native.Tools.AskUser.answer_text/1`.

  Everything else is drawn as words and never as a button
  (`tui/src/ui/transcript.rs`).
  """
  @spec answerable?(t()) :: boolean()
  def answerable?(%__MODULE__{answer: answer}) when is_binary(answer), do: true
  def answerable?(%__MODULE__{} = option), do: decision(option) != nil
end

defmodule Ouroboros.Web.Transcript.Approval.Edit do
  @moduledoc """
  One ACP diff content block, described rather than rendered as a patch.

  The ACP v1 schema spells a file edit as the whole `oldText` and `newText`, not as a
  unified diff. This surface does not compute a second one: a patch it derived itself
  could disagree with the one the transcript will show
  (`tui/src/ui/transcript.rs:411-427`).
  """

  defstruct [:path, :kind, old_bytes: 0, new_bytes: 0]

  @type t :: %__MODULE__{
          path: String.t(),
          kind: String.t(),
          old_bytes: non_neg_integer(),
          new_bytes: non_neg_integer()
        }
end

defmodule Ouroboros.Web.Transcript.Approval.Subagent do
  @moduledoc """
  Which child agent relayed this request, where the runtime said so.

  `Native.Loop.subagent_approval/2` forwards the child's own payload whole and adds one
  `subagent` object naming the asker. Every field is optional, and the object's presence
  alone is worth the line: this permission was asked for by a child, not by the session
  itself (`tui/src/ui/transcript.rs:337-354`).
  """

  defstruct [:description, :task_id, :node, :remote]

  @type t :: %__MODULE__{
          description: String.t() | nil,
          task_id: String.t() | nil,
          node: String.t() | nil,
          remote: boolean() | nil
        }

  @doc "`asked by subagent <description> (<task_id>)`, from whatever subset arrived."
  @spec attribution(t()) :: String.t()
  def attribution(%__MODULE__{description: nil, task_id: nil}), do: "asked by a subagent"

  def attribution(%__MODULE__{description: nil, task_id: task_id}),
    do: "asked by subagent (#{task_id})"

  def attribution(%__MODULE__{description: description, task_id: nil}),
    do: "asked by subagent #{description}"

  def attribution(%__MODULE__{description: description, task_id: task_id}),
    do: "asked by subagent #{description} (#{task_id})"

  @doc """
  The machine the child runs on, only where that is news.

  Every child runs *somewhere*, so a node on every line would hide the one case that
  changes the question — an answer here authorizing a write to a machine the approver is
  not looking at (`tui/src/ui/transcript.rs:387`).
  """
  @spec remote_node(t(), String.t() | nil) :: String.t() | nil
  def remote_node(%__MODULE__{} = subagent, session_node) do
    elsewhere =
      case {subagent.node, session_node} do
        {node, local} when is_binary(node) and is_binary(local) -> node != local
        # A node with no local to compare against says nothing about remoteness.
        _unknown -> false
      end

    if subagent.remote == true or elsewhere do
      subagent.node || "another machine"
    end
  end

  @doc "The whole line, for a surface that draws it unstyled."
  @spec line(t(), String.t() | nil) :: String.t()
  def line(%__MODULE__{} = subagent, session_node) do
    case remote_node(subagent, session_node) do
      nil -> attribution(subagent)
      node -> "#{attribution(subagent)} on #{node}"
    end
  end
end

defmodule Ouroboros.Web.Transcript.Approval.PlanChoice do
  @moduledoc """
  The three answers a `plan_exit` question offers, and how each degrades.

  The fallback mapping is not a guess: `Provider.Native.Session.plan_exit_choice/1` falls
  back to exactly this when no explicit `choice` reached it
  (`tui/src/model.rs:2662-2677`).
  """

  @type t :: :auto_edit | :prompt | :keep_planning

  @doc "The `optionId`s this build knows, in the payload's own order."
  @spec all() :: [t()]
  def all, do: [:auto_edit, :prompt, :keep_planning]

  @doc "The wire word for one choice."
  @spec as_string(t()) :: String.t()
  def as_string(:auto_edit), do: "auto_edit"
  def as_string(:prompt), do: "prompt"
  def as_string(:keep_planning), do: "keep_planning"

  @doc "Reads an `optionId`, or `nil` for one this build does not know."
  @spec parse(String.t() | nil) :: t() | nil
  def parse(value) when is_binary(value) do
    case String.trim(value) do
      "auto_edit" -> :auto_edit
      "prompt" -> :prompt
      "keep_planning" -> :keep_planning
      _unknown -> nil
    end
  end

  def parse(_value), do: nil

  @doc "The four-way answer this choice degrades to on a gateway refusing provider options."
  @spec decision(t()) :: {:approve | :deny, :once | :session}
  def decision(:auto_edit), do: {:approve, :session}
  def decision(:prompt), do: {:approve, :once}
  def decision(:keep_planning), do: {:deny, :once}
end

defmodule Ouroboros.Web.Transcript.Approval.PlanOption do
  @moduledoc "One plan-exit answer as a row: the wire choice, and the vendor's words for it."

  alias Ouroboros.Web.Transcript.Approval.PlanChoice

  defstruct [:choice, name: ""]
  @type t :: %__MODULE__{choice: PlanChoice.t(), name: String.t()}
end

defmodule Ouroboros.Web.Transcript.Approval.PlanExit do
  @moduledoc """
  B2. One `plan_exit` question, read out of the payload once.

  Present only where `payload.kind` is exactly `"plan_exit"`. Everything else about the
  approval — its options, its request id, the card it opens — is the ordinary machinery;
  this is the extra the question carries, and its absence is what makes an ordinary
  approval render the ordinary way (`tui/src/ui/transcript.rs:147-259`).
  """

  alias Ouroboros.Web.Presentation.PlanStep
  alias Ouroboros.Web.Transcript.Approval.PlanOption

  defstruct [
    :header,
    :question,
    :source,
    :message,
    steps: [],
    step_count: 0,
    choices: [],
    unmapped: []
  ]

  @type t :: %__MODULE__{
          header: String.t() | nil,
          question: String.t() | nil,
          source: String.t() | nil,
          steps: [PlanStep.t()],
          step_count: non_neg_integer(),
          message: String.t() | nil,
          choices: [PlanOption.t()],
          unmapped: [String.t()]
        }

  @doc "How many steps were sent but not drawn."
  @spec omitted_steps(t()) :: non_neg_integer()
  def omitted_steps(%__MODULE__{step_count: count, steps: steps}),
    do: max(count - length(steps), 0)
end

defmodule Ouroboros.Web.Transcript.Approval.Detail do
  @moduledoc """
  What the approval card draws, read out of the payload once.

  Every field is optional on purpose: the complaint this answers was a modal that showed
  nothing, and the fix is not a modal that *invents* something. A request with no diff
  says it carries no diff; a provider that named no reason gets no reason line
  (`tui/src/ui/transcript.rs:303-335`).
  """

  alias Ouroboros.Web.Presentation
  alias Ouroboros.Web.Transcript.Approval

  defstruct [
    :kind,
    :title,
    :command,
    :cwd,
    :reason,
    :suggested_rule,
    :diff,
    :plan,
    :subagent,
    locations: [],
    options: [],
    edits: [],
    diff_excerpted: false
  ]

  @type t :: %__MODULE__{
          kind: String.t() | nil,
          title: String.t() | nil,
          command: String.t() | nil,
          cwd: String.t() | nil,
          reason: String.t() | nil,
          suggested_rule: String.t() | nil,
          locations: [String.t()],
          options: [Approval.Option.t()],
          diff: Presentation.Diff.t() | nil,
          diff_excerpted: boolean(),
          edits: [Approval.Edit.t()],
          plan: Approval.PlanExit.t() | nil,
          subagent: Approval.Subagent.t() | nil
        }
end

defmodule Ouroboros.Web.Transcript.Approval.Rule do
  @moduledoc "The permission rule the card's fifth answer would write."

  defstruct pattern: "", workspace: ""
  @type t :: %__MODULE__{pattern: String.t(), workspace: String.t()}
end

defmodule Ouroboros.Web.Transcript.Approval do
  @moduledoc """
  One outstanding approval, and everything a card can honestly say about it.

  Port of `ApprovalRequest`'s readers (`tui/src/ui/transcript.rs:429-514`) plus the
  suggested-rule gate (`tui/src/ui/app/streaming.rs:783`).
  """

  alias Ouroboros.Web.Presentation

  alias Ouroboros.Web.Transcript.Approval.{
    Detail,
    Edit,
    Option,
    PlanChoice,
    PlanExit,
    PlanOption,
    Rule
  }

  alias Ouroboros.Web.Transcript.Approval.Subagent, as: ApprovalSubagent

  # How many provider-offered options one card will draw.
  @options 8
  # How many `toolCall.locations` paths one card will draw.
  @locations 8
  # How many array entries are searched for a diff before giving up.
  @diff_candidates 8
  # How many plan steps the plan-exit card will draw before saying how many it left out.
  @plan_exit_steps 32

  defstruct [:request_id, :turn_id, sequence: 0, payload: %{}]

  @type t :: %__MODULE__{
          request_id: String.t(),
          sequence: non_neg_integer(),
          turn_id: String.t() | nil,
          payload: map()
        }

  @doc """
  Whether this request is a question for a person rather than a permission.

  The plan-exit question (B2), or the native agent's `ask_user` tool riding the approval
  channel with `kind: "question"`. Auto-approve reads this before answering: leaving plan
  mode changes what every later turn may do, and a robot `approve` on an `ask_user`
  question carries no `choice`, so the runtime hands the agent "the operator acknowledged
  the question without giving an answer" — the one outcome the tool exists to prevent
  (`tui/src/ui/transcript.rs:441-446`).
  """
  @spec question?(t()) :: boolean()
  def question?(%__MODULE__{payload: payload} = request) do
    text(payload, "kind") in ["plan_exit", "question"] or computer_use?(request)
  end

  @doc "Computer Use observe/act. Auto-approve must not invent an app allow."
  @spec computer_use?(t()) :: boolean()
  def computer_use?(%__MODULE__{payload: payload}) do
    case payload do
      %{"tool_call" => %{"name" => name}} -> name in ["desktop_state", "desktop_act"]
      _otherwise -> false
    end
  end

  @doc """
  The words an `ask_user` question actually asks.

  `Provider.Native.Tools.AskUser.question/1` writes `header`, `question` and `options` and
  nothing a permission carries — no `tool_call`, no `command`, no `reason` — so the generic
  fallback reaches the end of its key list and compacts the whole payload. That is how a
  card headline becomes `{"header":…,"kind":"question",…}`.

  Both fields are the runtime's own and both earn the line: the header is the two or three
  words saying what kind of decision this is, and the question is the decision. `nil` where
  neither arrived, which is the one case with nothing better than the fallback
  (`tui/src/ui/transcript.rs`).
  """
  @spec question_text(map()) :: String.t() | nil
  def question_text(payload) do
    case {text(payload, "header"), text(payload, "question")} do
      {nil, nil} -> nil
      {header, nil} -> header
      {nil, question} -> question
      {header, question} -> "#{header} — #{question}"
    end
  end

  @doc """
  The tool call the provider is asking permission for, as one line.

  A sandbox escalation should read as `git commit … — writes to .git`, not as the raw JSON
  blob of `tool_call` (`tui/src/ui/transcript.rs:462`).
  """
  @spec subject(t()) :: String.t()
  def subject(%__MODULE__{payload: payload}) do
    case text(payload, "kind") do
      # B2. A plan exit names no command and no tool, so the generic fallback would render
      # the whole payload as JSON. Its own header is the sentence a person needs there.
      "plan_exit" ->
        text(payload, "header") || "plan ready — build it, or keep planning"

      # An `ask_user` question names no command and no tool either, and the words it asks
      # are the entire reason it was put to a person.
      "question" ->
        question_text(payload) || fallback_subject(payload)

      _permission ->
        case {command(payload), text(payload, "reason")} do
          {nil, _reason} -> fallback_subject(payload)
          {command, nil} -> command
          {command, reason} -> "#{command} — #{reason}"
        end
    end
  end

  @doc "Everything the payload actually carries, for the card to draw."
  @spec detail(t()) :: Detail.t()
  def detail(%__MODULE__{payload: payload}) do
    call = call_of(payload)
    {diff, diff_excerpted} = diff_of(payload, call)

    kind =
      (text(payload, "kind") || (call && text(call, "kind")) || (call && text(call, "name")))
      |> case do
        nil -> nil
        kind -> String.replace(kind, "_", " ")
      end

    %Detail{
      kind: kind,
      title: call && text(call, "title"),
      command: command(payload),
      cwd: (call && text(call, "cwd")) || text(payload, "cwd"),
      reason: text(payload, "reason"),
      suggested_rule: text(payload, "suggested_rule"),
      locations: if(call, do: locations(call), else: []),
      options: options(payload),
      diff: diff,
      diff_excerpted: diff_excerpted,
      edits: if(call, do: edits(call), else: []),
      plan: plan_exit(payload),
      subagent: subagent(payload)
    }
  end

  @doc """
  The rule the card's fifth answer would write, or the reason there is no fifth answer.

  Three things have to be true at once, and each failure is named rather than swallowed:
  the runtime must have suggested a pattern (only `Control.Permissions` knows the rule
  language, and this surface never invents one), the serving runtime must offer
  `permissions.add`, and the session must name the workspace the rule is scoped to —
  `permissions.add` refuses a `workspace` rule without one. Computer Use remember is
  user-scoped (D4), so a missing workspace does not hide the offer
  (`tui/src/ui/app/streaming.rs:783`).

  `methods` is the serving runtime's method list; `workspace` is the session's own.
  """
  @spec suggested_rule(String.t() | nil, [String.t()], String.t() | nil) ::
          {Rule.t() | nil, String.t() | nil}
  def suggested_rule(nil, _methods, _workspace), do: {nil, nil}

  def suggested_rule(pattern, methods, workspace) when is_binary(pattern) do
    workspace =
      case workspace do
        workspace when is_binary(workspace) ->
          case String.trim(workspace) do
            "" -> nil
            trimmed -> trimmed
          end

        _absent ->
          nil
      end

    cond do
      "permissions.add" not in methods ->
        {nil, "this runtime does not serve permissions.add, so the rule cannot be saved"}

      String.starts_with?(pattern, "ComputerUse(") ->
        {%Rule{pattern: pattern, workspace: workspace || ""}, nil}

      is_binary(workspace) ->
        {%Rule{pattern: pattern, workspace: workspace}, nil}

      true ->
        {nil, "this session names no workspace, so there is no scope to save the rule in"}
    end
  end

  # ------------------------------------------------------------------------------------
  # Payload readers
  # ------------------------------------------------------------------------------------

  defp call_of(payload) do
    Enum.find_value(["tool_call", "toolCall", "tool"], fn key ->
      case fetch(payload, key) do
        {:ok, value} when is_map(value) -> value
        _otherwise -> nil
      end
    end)
  end

  defp command(payload) do
    value =
      Enum.find_value([["tool_call", "command"], ["tool", "command"], ["command"]], fn path ->
        case pointer(payload, path) do
          {:ok, value} -> {:found, value}
          :error -> nil
        end
      end)

    case value do
      {:found, value} -> render_command(value)
      nil -> nil
    end
  end

  defp render_command(value) when is_binary(value), do: nonempty(value)

  defp render_command(value) when is_list(value) do
    value |> Enum.filter(&is_binary/1) |> Enum.join(" ") |> nonempty()
  end

  defp render_command(value), do: rendered(value)

  defp fallback_subject(payload) do
    Enum.find_value(["tool_call", "tool", "command", "text"], fn key ->
      case fetch(payload, key) do
        {:ok, value} -> rendered(value)
        :error -> nil
      end
    end) || Presentation.compact(payload)
  end

  defp rendered(value) do
    case Presentation.compact(value) do
      "" -> nil
      "null" -> nil
      rendered -> rendered
    end
  end

  # ACP's `options: [{optionId, name, kind}]`, in the order the provider listed them —
  # and the native `ask_user`'s `options: ["…", "…"]`, which are not that shape at all.
  #
  # Bounded: these are drawn as rows, and a provider that offered two hundred of them
  # would push the command off the screen.
  defp options(payload) do
    payload
    |> array("options")
    |> Enum.map(&option/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.take(@options)
  end

  # `Provider.Native.Tools.AskUser.question/1` declares `options: {:list, :string}` and
  # writes exactly that. A reader that insists on `name` drops every one of them, and a
  # question whose whole point is "which database?" renders as Allow/Deny. The string is
  # the label and the words to send back; nothing on the wire says what it *means*, so it
  # carries no `optionId` and no `kind` and maps onto none of the four.
  defp option(option) when is_binary(option) do
    case nonempty(option) do
      nil -> nil
      answer -> %Option{option_id: nil, name: answer, kind: nil, answer: answer}
    end
  end

  defp option(option) do
    case text(option, "name") || text(option, "label") do
      nil ->
        nil

      name ->
        %Option{
          option_id: text(option, "optionId") || text(option, "option_id"),
          name: name,
          kind: text(option, "kind")
        }
    end
  end

  # ACP's `toolCall.locations: [{path, line?}]`, paths only.
  defp locations(call) do
    call
    |> array("locations")
    |> Enum.map(fn
      location when is_binary(location) -> nonempty(location)
      location -> text(location, "path")
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.take(@locations)
  end

  # ACP diff content blocks under `toolCall.content`, in the order the provider listed.
  defp edits(call) do
    call
    |> array("content")
    |> Enum.filter(&(is_map(&1) and Map.get(&1, "type") == "diff"))
    |> Enum.map(fn block ->
      case text(block, "path") do
        nil ->
          nil

        path ->
          old = string_at(block, "oldText")
          new = string_at(block, "newText")

          %Edit{
            path: path,
            kind:
              cond do
                is_nil(old) -> "add"
                is_nil(new) -> "delete"
                true -> "update"
              end,
            old_bytes: if(old, do: byte_size(old), else: 0),
            new_bytes: if(new, do: byte_size(new), else: 0)
          }
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.take(@locations)
  end

  # The patch this request is asking about, wherever the dialect put it.
  #
  # Three shapes are known and named: a Codex `file_change` payload's `diff`, an ACP
  # content block `{"type": "diff", …}` under `toolCall.content`, and the `changes` list
  # `Dialect.ACP` maps a `diff` update into. The parse is the transcript's own in every
  # case — not a second one that could disagree with it about what a hunk is.
  #
  # The second half of the pair is whether the gateway had already excerpted the leaf. An
  # excerpt is still worth showing; a diffstat computed from one is not a diffstat.
  defp diff_of(payload, call) do
    [payload, call]
    |> Enum.reject(&is_nil/1)
    |> Enum.flat_map(&diff_candidates/1)
    |> Enum.find_value({nil, false}, &diff_from_candidate/1)
  end

  defp diff_candidates(source) do
    direct =
      Enum.flat_map(["diff", "patch", "unified_diff", "unifiedDiff"], fn key ->
        case fetch(source, key) do
          {:ok, value} -> [value]
          :error -> []
        end
      end)

    nested =
      Enum.flat_map(["content", "changes"], fn key ->
        source
        |> array(key)
        |> Enum.take(@diff_candidates)
        |> Enum.flat_map(fn item ->
          Enum.flat_map(["diff", "patch"], fn key ->
            case fetch(item, key) do
              {:ok, value} -> [value]
              :error -> []
            end
          end)
        end)
      end)

    direct ++ nested
  end

  defp diff_from_candidate(candidate) when is_binary(candidate) do
    case String.trim(candidate) do
      "" -> nil
      trimmed -> {Presentation.parse_diff(trimmed), false}
    end
  end

  defp diff_from_candidate(candidate) when is_map(candidate) and not is_struct(candidate) do
    cond do
      # `{"_excerpt": prefix, "_bytes": n}`: the gateway cut this leaf. Draw the prefix,
      # and say it is a prefix.
      is_binary(excerpt = Map.get(candidate, "_excerpt")) ->
        {%{Presentation.parse_diff(excerpt) | truncated: true}, true}

      is_binary(nested = Map.get(candidate, "diff")) ->
        case String.trim(nested) do
          "" -> nil
          trimmed -> {Presentation.parse_diff(trimmed), false}
        end

      true ->
        nil
    end
  end

  defp diff_from_candidate(_candidate), do: nil

  @doc """
  Reads one `plan_exit` question, or `nil` for every other approval.

  `nil` also for a plan exit whose options this build could not map onto a single known
  choice — which would be a card with no answer it could honestly send, and is better
  rendered as the ordinary four (`tui/src/ui/transcript.rs:191`).
  """
  @spec plan_exit(map()) :: PlanExit.t() | nil
  def plan_exit(payload) do
    if text(payload, "kind") != "plan_exit" do
      nil
    else
      {choices, unmapped} =
        payload
        |> array("options")
        |> Enum.take(@options)
        |> Enum.reduce({[], []}, &read_plan_option/2)

      case Enum.reverse(choices) do
        [] ->
          nil

        choices ->
          plan =
            case fetch(payload, "plan") do
              {:ok, value} -> Presentation.plan_update(value)
              :error -> nil
            end

          %PlanExit{
            header: text(payload, "header"),
            question: text(payload, "question"),
            source: text(payload, "plan_source"),
            steps: if(plan, do: Enum.take(plan.steps, @plan_exit_steps), else: []),
            step_count: if(plan, do: plan.step_count, else: 0),
            message: text(payload, "message"),
            choices: choices,
            unmapped: Enum.reverse(unmapped)
          }
      end
    end
  end

  defp read_plan_option(option, {choices, unmapped}) do
    name = text(option, "name") || text(option, "label") || ""
    id = text(option, "optionId") || text(option, "option_id")

    case {PlanChoice.parse(id), name} do
      {choice, name} when not is_nil(choice) and name != "" ->
        {[%PlanOption{choice: choice, name: name} | choices], unmapped}

      # A named option whose id this build does not know, or one with no name to put on a
      # row. Either way it is reported, not offered.
      {_unknown, ""} ->
        {choices, unmapped}

      {_unknown, name} when is_binary(id) ->
        {choices, ["#{name} (#{id})" | unmapped]}

      {_unknown, name} ->
        {choices, [name | unmapped]}
    end
  end

  defp subagent(payload) do
    case fetch(payload, "subagent") do
      {:ok, subagent} when is_map(subagent) and not is_struct(subagent) ->
        %ApprovalSubagent{
          description: text(subagent, "description"),
          task_id: text(subagent, "task_id"),
          node: text(subagent, "node"),
          remote: bool_at(subagent, "remote")
        }

      _absent ->
        nil
    end
  end

  # ------------------------------------------------------------------------------------
  # Small readers. Deliberately unbounded: an approval card quotes the payload as it is,
  # and the presentation's 64 KiB ceiling is for the transcript's own accumulation.
  # ------------------------------------------------------------------------------------

  defp text(value, key) do
    case string_at(value, key) do
      nil -> nil
      found -> nonempty(found)
    end
  end

  defp string_at(value, key) do
    case fetch(value, key) do
      {:ok, found} when is_binary(found) -> found
      _otherwise -> nil
    end
  end

  defp bool_at(value, key) do
    case fetch(value, key) do
      {:ok, found} when is_boolean(found) -> found
      _otherwise -> nil
    end
  end

  defp nonempty(text) do
    case String.trim(text) do
      "" -> nil
      trimmed -> trimmed
    end
  end

  defp fetch(value, key) when is_map(value) and not is_struct(value), do: Map.fetch(value, key)
  defp fetch(_value, _key), do: :error

  defp pointer(value, path) do
    Enum.reduce_while(path, {:ok, value}, fn key, {:ok, current} ->
      case fetch(current, key) do
        {:ok, found} -> {:cont, {:ok, found}}
        :error -> {:halt, :error}
      end
    end)
  end

  defp array(value, key) do
    case fetch(value, key) do
      {:ok, list} when is_list(list) -> list
      _otherwise -> []
    end
  end
end
