defmodule Ouroboros.Web.Live.ApprovalCard do
  @moduledoc """
  One outstanding approval, drawn with every section it actually has and none it does not.

  `Ouroboros.Web.Transcript.Approval` reads the payload; this module draws what it read.
  The split matters here more than anywhere else on the surface: the reader module is
  locked to the golden corpus, so a field this card wanted and could not find is a
  *missing field*, reported, not a field this card infers from something adjacent.

  ## Every section is optional, and an absent one is silent

  The complaint the desktop's card answered was a modal that showed nothing; the fix is
  not a modal that invents something. A request with no diff draws no diff; a provider that
  named no reason gets no reason line (`tui/src/ui/transcript.rs:303-335`). That is what
  makes the sections a test can drive one fixture at a time.

  ## Which answers are offered, and by whom

  Three cases, in the order the desktop resolves them (`tui/src/ui/app/desktop.rs:366-412`):

  1. **A plan exit** offers its own three choices. Those ride
     `response.provider_options: {choice}`, and the `decision`/`scope` beside them are the
     fallback mapping — a runtime that reads the explicit choice and one that ignores it
     settle the same way (`tui/src/model.rs:2692-2717`).
  2. **Provider-offered options** are offered as the provider worded them, mapped onto one
     of the four accepted answers by `Approval.Option.decision/1`. An option this build
     cannot map is **rendered as text and never as a button** — guessing whether a novel
     vendor option approves or refuses is the one mistake that cannot be undone.
  3. **Otherwise** the four the envelope accepts, in the desktop's own words.

  ## The fifth answer is two calls, and says so

  `interactive.respond_approval` has no `scope: "always"`. The durable form is a
  session-scoped approval *plus* a `permissions.add` rule, which is why the remember row is
  its own control with its own result line rather than a fifth button pretending to be one
  call (`tui/src/ui/app/overlays.rs:671-676`).

  ## Green is not spent here

  A pending approval is the one thing on this surface that needs a person, and the rail's
  eye already says so. The card wears the warning tone for an escalation and ink for
  everything else; an approve button is not a success state.
  """

  use Phoenix.Component

  alias Ouroboros.Web.Live.Cells
  alias Ouroboros.Web.Transcript
  alias Ouroboros.Web.Transcript.Approval
  alias Ouroboros.Web.Transcript.Diff, as: ParsedDiff

  # The four the envelope accepts, in the desktop's order and its words
  # (`tui/src/ui/app/desktop.rs:393-405`).
  @standard [
    {"Allow once", "approve", "once"},
    {"Allow for session", "approve", "session"},
    {"Deny once", "deny", "once"},
    {"Deny for session", "deny", "session"}
  ]

  @doc "The four standard answers, as `{label, decision, scope}`."
  @spec standard_answers() :: [{String.t(), String.t(), String.t()}]
  def standard_answers, do: @standard

  @doc """
  Whether this request can be answered from a rail row.

  A question, a plan exit, and a Computer Use ask all need the card — a yes/no from a
  one-line row would be answering something the row never showed. `Approval.question?/1`
  is the single decision, shared with auto-approve so the two surfaces cannot disagree
  about what a permission is.
  """
  @spec inline?(Approval.t()) :: boolean()
  def inline?(%Approval{} = request), do: not Transcript.question?(request)

  @doc """
  One provider-offered option, by index into `detail.options`, or `nil` for an index the
  page never drew.
  """
  @spec option_at(Approval.t(), integer()) :: Approval.Option.t() | nil
  # Non-negative only. `Enum.at/2` counts a negative index from the end, so a browser
  # sending `-1` for an option this page never drew would answer the *last* one — which is
  # the sort of thing that approves a command by accident exactly once.
  def option_at(%Approval{} = request, index) when is_integer(index) and index >= 0 do
    request
    |> Approval.detail()
    |> Map.get(:options, [])
    |> Enum.at(index)
  end

  def option_at(%Approval{}, _index), do: nil

  @doc """
  The answer one provider-offered option stands for, by index into `detail.options`.

  `nil` for an index that is not there or an option this build cannot map — the caller
  answers nothing rather than answering a guess. An `ask_user` option maps onto nothing
  here on purpose: it carries no `kind`, and what it sends is words rather than a
  four-way answer. `option_response/2` is the one that knows how to send it.
  """
  @spec option_answer(Approval.t(), integer()) ::
          {:approve | :deny, :once | :session} | nil
  def option_answer(%Approval{} = request, index) do
    case option_at(request, index) do
      nil -> nil
      option -> Approval.Option.decision(option)
    end
  end

  @doc """
  The `respond_approval` response one option sends, by index into `detail.options`.

  A vendor option sends whatever the locked decision table says its `kind` means. An
  `ask_user` option sends `approve`/`once` with its own words as the `reason`, because
  that is where `Provider.Native.Tools.AskUser.answer_text/1` reads the answer from and
  the only key the envelope will carry to it: `interactive.respond_approval` accepts
  `provider_options` for a plan-exit `choice` and for nothing else
  (`lib/ouroboros/gateway/methods.ex`, `plan_exit_options/1`). An approve with no words
  reaches the tool as "the operator acknowledged the question without giving an answer",
  which is the outcome the tool exists to prevent.

  `nil` for an index that is not there or an option this build cannot send.
  """
  @spec option_response(Approval.t(), integer()) :: map() | nil
  def option_response(%Approval{} = request, index) do
    case option_at(request, index) do
      %Approval.Option{answer: answer} when is_binary(answer) ->
        %{"decision" => "approve", "scope" => "once", "reason" => answer}

      %Approval.Option{} = option ->
        case Approval.Option.decision(option) do
          nil -> nil
          {decision, scope} -> %{"decision" => to_string(decision), "scope" => to_string(scope)}
        end

      nil ->
        nil
    end
  end

  @doc "The parsed patch a request carries, or `nil` where it carries none."
  @spec parsed_diff(Approval.Detail.t()) :: ParsedDiff.t() | nil
  def parsed_diff(%Approval.Detail{diff: nil}), do: nil

  def parsed_diff(%Approval.Detail{diff: diff}),
    do: ParsedDiff.parse(diff.text, diff.path)

  # ------------------------------------------------------------------------------------
  # The rail's inline answers
  # ------------------------------------------------------------------------------------

  @doc """
  Two buttons on a rail row: the answer a person can give without reading the card.

  Only `once`. A session-scoped allow changes what every later turn may do without asking
  again, and that is a decision the card exists to show the command for.
  """
  attr :request, :any, required: true

  def inline(assigns) do
    ~H"""
    <span class="ouro-inline-answers">
      <button
        type="button"
        class="ouro-quiet-button"
        phx-click="respond"
        phx-value-request={@request.request_id}
        phx-value-decision="approve"
        phx-value-scope="once"
      >
        Allow once
      </button>
      <button
        type="button"
        class="ouro-quiet-button"
        phx-click="respond"
        phx-value-request={@request.request_id}
        phx-value-decision="deny"
        phx-value-scope="once"
      >
        Deny
      </button>
    </span>
    """
  end

  # ------------------------------------------------------------------------------------
  # The card
  # ------------------------------------------------------------------------------------

  @doc """
  The pinned card for the open session's oldest unanswered request.

  `rule` and `rule_refusal` are the locked gate's two halves
  (`Approval.suggested_rule/3`): a rule to offer, or the sentence saying why there is
  none. `node` is the session's own machine, which is what turns a subagent's node into
  news or into noise.
  """
  attr :request, :any, required: true
  attr :detail, :any, required: true
  attr :node, :any, required: true
  attr :rule, :any, required: true
  attr :rule_refusal, :any, required: true
  attr :notice, :any, required: true
  attr :also_waiting, :integer, default: 0
  attr :can_remember, :boolean, default: false

  def card(assigns) do
    detail = assigns.detail

    assigns =
      assigns
      |> assign(:subject, Approval.subject(assigns.request))
      |> assign(:parsed, parsed_diff(detail))
      |> assign(:escalation?, detail.kind == "sandbox escalation")
      |> assign(:kind, kind(detail.kind))
      |> assign(
        :headline,
        if(detail.command,
          do: "Run command",
          else: detail.title || Approval.subject(assigns.request)
        )
      )

    ~H"""
    <section
      class={["ouro-approval", @escalation? && "ouro-approval-warn"]}
      aria-label={"Approval requested: #{@headline}"}
      aria-live="polite"
    >
      <header class="ouro-approval-head">
        <span :if={@kind} class="ouro-approval-kind">{@kind}</span>
        <span class="ouro-approval-subject">{@headline}</span>
        <span :if={@also_waiting > 0} class="ouro-quiet">
          {@also_waiting} more waiting
        </span>
      </header>

      <p :if={@detail.plan && @detail.plan.question} class="ouro-approval-question">
        {@detail.plan.question}
      </p>

      <pre :if={@detail.command} class="ouro-approval-command ouro-mono">{@detail.command}</pre>

      <p :if={@detail.cwd} class="ouro-approval-cwd ouro-mono">in {@detail.cwd}</p>

      <p :if={@detail.reason} class="ouro-approval-reason">{reason(@detail.reason)}</p>

      <p :if={@detail.subagent} class="ouro-approval-subagent">
        {Approval.Subagent.line(@detail.subagent, @node)}
      </p>

      <ul :if={@detail.locations != []} class="ouro-approval-locations ouro-mono">
        <li :for={path <- @detail.locations}>{path}</li>
      </ul>

      <ul :if={@detail.edits != []} class="ouro-approval-edits ouro-mono">
        <li :for={edit <- @detail.edits}>
          {edit.path} · {edit.kind} · {edit.old_bytes} → {edit.new_bytes} bytes
        </li>
      </ul>

      <div :if={@parsed} class="ouro-approval-diff">
        <p :if={@detail.diff_excerpted || @detail.diff.truncated} class="ouro-quiet">
          this patch is an excerpt of the one the runtime holds
        </p>
        <Cells.parsed_diff parsed={@parsed} pending={true} />
      </div>

      <.plan_steps :if={@detail.plan} plan={@detail.plan} />

      <p :if={@detail.plan && @detail.plan.unmapped != []} class="ouro-quiet">
        this build cannot answer: {Enum.join(@detail.plan.unmapped, ", ")}
      </p>

      <.answers request={@request} detail={@detail} />

      <details
        :if={@rule && @can_remember}
        class="ouro-approval-rule"
        data-ouro-disclosure={"rule:#{@request.request_id}"}
      >
        <summary>Remember this permission…</summary>
        <code class="ouro-mono">{@rule.pattern}</code>
        <button
          type="button"
          class="ouro-quiet-button"
          phx-click="remember"
          phx-value-request={@request.request_id}
        >
          Remember for this workspace
        </button>
      </details>

      <p :if={@rule_refusal} class="ouro-quiet" role="status">{@rule_refusal}</p>

      <p
        :if={@notice}
        class={["ouro-approval-notice", tone_class(@notice.tone)]}
        role="status"
      >
        {@notice.text}
      </p>
    </section>
    """
  end

  defp kind("sandbox escalation"), do: "File access request"
  defp kind(value), do: value

  defp reason(value) when value in [":no_rule", "no_rule"],
    do: "This action needs your permission before it can run."

  defp reason(value), do: value

  attr :plan, :any, required: true

  defp plan_steps(assigns) do
    ~H"""
    <ol :if={@plan.steps != []} class="ouro-plan-steps ouro-approval-plan">
      <li :for={step <- @plan.steps} class={"ouro-step-#{step.status}"}>
        <span class="ouro-step-text">{step.text}</span>
      </li>
    </ol>
    <p :if={Approval.PlanExit.omitted_steps(@plan) > 0} class="ouro-quiet">
      {Approval.PlanExit.omitted_steps(@plan)} more steps not shown
    </p>
    """
  end

  attr :request, :any, required: true
  attr :detail, :any, required: true

  defp answers(%{detail: %Approval.Detail{plan: %Approval.PlanExit{}}} = assigns) do
    ~H"""
    <div class="ouro-approval-answers">
      <button
        :for={choice <- @detail.plan.choices}
        type="button"
        class="ouro-button ouro-approval-answer"
        phx-click="plan_choice"
        phx-value-request={@request.request_id}
        phx-value-choice={Approval.PlanChoice.as_string(choice.choice)}
      >
        {choice.name}
      </button>
    </div>
    """
  end

  defp answers(%{detail: %Approval.Detail{options: [_ | _]}} = assigns) do
    assigns =
      assign(
        assigns,
        :rows,
        assigns.detail.options
        |> Enum.with_index()
        |> Enum.map(fn {option, index} ->
          %{index: index, name: option.name, answerable: Approval.Option.answerable?(option)}
        end)
      )

    ~H"""
    <div class="ouro-approval-answers">
      <%= for row <- @rows do %>
        <button
          :if={row.answerable}
          type="button"
          class="ouro-button ouro-approval-answer"
          phx-click="respond_option"
          phx-value-request={@request.request_id}
          phx-value-option={row.index}
        >
          {row.name}
        </button>
        <span :if={not row.answerable} class="ouro-approval-unmapped ouro-quiet">
          {row.name} — this build cannot map this option onto an answer
        </span>
      <% end %>
    </div>
    """
  end

  defp answers(assigns) do
    assigns =
      assigns
      |> assign(:once, Enum.filter(@standard, &(elem(&1, 2) == "once")))
      |> assign(:session, Enum.filter(@standard, &(elem(&1, 2) == "session")))

    ~H"""
    <div class="ouro-approval-answers">
      <button
        :for={{label, decision, scope} <- @once}
        type="button"
        class="ouro-button ouro-approval-answer"
        phx-click="respond"
        phx-value-request={@request.request_id}
        phx-value-decision={decision}
        phx-value-scope={scope}
      >
        {label}
      </button>
    </div>
    <details class="ouro-approval-more" data-ouro-disclosure={"answers:#{@request.request_id}"}>
      <summary>Options for this session</summary>
      <div class="ouro-approval-answers">
        <button
          :for={{label, decision, scope} <- @session}
          type="button"
          class="ouro-quiet-button ouro-approval-answer"
          phx-click="respond"
          phx-value-request={@request.request_id}
          phx-value-decision={decision}
          phx-value-scope={scope}
        >{label}</button>
      </div>
    </details>
    """
  end

  # The projection's tones, as this surface's classes. `:success` is ink, here as
  # everywhere: a rule that saved is a fact, not an attention state.
  defp tone_class(:error), do: "ouro-tone-error"
  defp tone_class(:warning), do: "ouro-tone-warning"
  defp tone_class(_ink), do: "ouro-tone-success"
end
