defmodule Ouroboros.Web.Live.Composer do
  @moduledoc """
  The one place an operator says something, and the two pickers under it.

  ## Which verb, and who decides

  `interactive.send_message` while the session is idle, `interactive.follow_up` while a
  turn is running. That is the runtime's own rule, not this surface's: a second immediate
  `send_message` into a busy session is refused `:busy`, and the refusal names the verb
  to queue with (`lib/ouroboros/gateway/methods/safe.ex:179-188`). Both Rust clients pick
  the verb the same way and both retry on that refusal
  (`tui/src/run.rs:687-697`, `tui/src/acp_serve.rs:972-984`), so this one does too — the
  guess is made from what this view can see, and the runtime's correction is honoured
  rather than shown as a failure.

  What this view can see is `turn_state/1`: the turn boundaries the watch is holding.
  Where the watch has never seen one — a session opened mid-conversation whose
  `turn_started` is below the floor — it says so with `spoke?: false` and the caller falls
  back to the polled session status, which is the only other evidence there is.

  ## The turn envelope is a plain string until it cannot be

  `input` is sent as the bare prompt, which is the common case of the closed envelope
  (`docs/PROTOCOL.md` `interactive.send_message`). The object form
  `{prompt, attachments, reasoning_effort}` appears only where there is something in it a
  string could not carry — which, on this surface, means a per-turn effort and nothing
  else. That is the terminal client's own rule, not a second one invented here
  (`TurnInput::to_value`, `tui/src/model.rs:2789-2815`): sending the object for every turn
  would rewrite the wire for nothing.

  Attachments are still not built here: they must name files inside the leased workspace,
  which a browser cannot enumerate until `workspace.browse` lands.

  ## Steer is the form's second submit button

  It submits `#composer` under `verb=steer`, so the words that travel are the ones in the
  box rather than the debounced copy the LiveView happens to be holding — a steer typed and
  sent inside the 400ms debounce would otherwise inject the *previous* draft into a running
  turn, which is the one mistake this verb must not make.

  It is written before the Send button because that is where it belongs on screen, and
  being first would make it the form's implicit submitter — except that this form has no
  path to implicit submission: its only field is a `<textarea>`, where `Enter` inserts a
  newline, and the `Composer` hook intercepts `Enter` and calls `requestSubmit()` with no
  submitter. **Adding a text `<input>` to this form would give `Enter` to Steer**; put the
  Send button first if that ever happens.

  ## Steer is offered on silence and hidden only on a refusal

  The Steer button appears while a turn is running, where the runtime serves
  `interactive.steer`, and where `options.capabilities.steer` is anything but an explicit
  `false`. An older gateway that never declared the key keeps the control, because hiding
  a working verb on silence would be this surface inventing a ceiling — the reading
  `Capability::offered` takes (`tui/src/model.rs:626`).

  ## The model picker is a `<select>`, and its *label* still is not

  The sandbox and thinking pickers are marked buttons for the reason below. A 113-row
  catalogue is not a button group, so the model control is a searchable `<select>` — but
  the sentence that says which model this session is running is drawn from the session's
  own re-read, exactly like the other two. The widget may move the instant somebody picks;
  the claim does not.

  ## The pickers are absent when the runtime said nothing

  A sandbox picker is offered only where the session **reported** a posture. A picker
  defaulted to `workspace_write` because nothing said otherwise would be this page telling
  an operator what a session is allowed to do on no evidence, which is the one thing a
  security control must never do (the removed `docs/DESKTOP.md`, `docs/WEB.md` §4).

  The thinking picker is always offered because effort is a preference, not a permission,
  and its **label** carries the same honesty: `Default` where nothing reported one. Its
  choices are supplied from the selected model's catalogue row and the provider transport
  vocabulary. There is no `default` to send, only a word for not having been told.

  ## Buttons, not a `<select>`

  Both pickers are marked-button groups rather than form controls, and that is the whole
  of "the label follows the session row after the re-list confirms". A `<select>` carries
  its own client-side value: it would show the operator's pick the instant they made it,
  whether or not the transport accepted it. A button group has no state of its own, so the
  mark only moves when the runtime's next answer says it moved.
  """

  use Phoenix.Component

  alias Ouroboros.Web.Transcript.Entry

  # The four `interactive.configure` accepts, in the order they escalate.
  @sandbox_modes ~w(default read_only workspace_write unrestricted)
  @efforts ~w(none low medium high xhigh max)

  @doc "The sandbox postures `interactive.configure` accepts, least authority first."
  @spec sandbox_modes() :: [String.t()]
  def sandbox_modes, do: @sandbox_modes

  @doc "The reasoning efforts `interactive.configure` accepts."
  @spec efforts() :: [String.t()]
  def efforts, do: @efforts

  @typedoc """
  What the watched ledger says about the turn in progress.

  `spoke?` is the honest half: `false` means no turn boundary is held at all, so
  `running?` is this struct's default rather than an observation and a caller with a
  polled status should prefer that.
  """
  @type turn :: %{
          running?: boolean(),
          spoke?: boolean(),
          failed?: boolean(),
          turn_id: String.t() | nil,
          queued: non_neg_integer()
        }

  @doc """
  The turn state and queue depth the held ledger proves, read in one pass.

  Pure: entries in, a map out. The queue depth is the newest `queue_changed` the view
  holds — the durable one the runtime published, never a count this surface kept of its
  own sends.
  """
  @spec turn_state([Entry.t()]) :: turn()
  def turn_state(entries) when is_list(entries) do
    Enum.reduce(
      entries,
      %{running?: false, spoke?: false, failed?: false, turn_id: nil, queued: 0},
      fn
        %Entry.Event{event: event}, state -> absorb(state, event)
        _divider, state -> state
      end
    )
  end

  defp absorb(state, event) do
    case Map.get(event, :type) do
      :turn_started ->
        %{
          state
          | running?: true,
            spoke?: true,
            failed?: false,
            turn_id: Map.get(event, :turn_id)
        }

      :turn_failed ->
        %{state | running?: false, spoke?: true, failed?: true, turn_id: nil}

      type when type in [:turn_completed, :turn_interrupted] ->
        %{state | running?: false, spoke?: true, failed?: false, turn_id: nil}

      :queue_changed ->
        %{state | queued: queued_of(event)}

      :session_closed ->
        %{state | running?: false, spoke?: true, failed?: false, turn_id: nil}

      :session_idle ->
        %{state | running?: false, spoke?: true, turn_id: nil}

      _other ->
        state
    end
  end

  # The payload's own key, in the order the presentation reads them
  # (`Ouroboros.EventPresentation` `:queue_changed`). Nothing is inferred from a missing
  # one: a `queue_changed` that named no number is a queue this view cannot report.
  defp queued_of(event) do
    payload = Map.get(event, :payload)

    if is_map(payload) do
      Enum.find_value(["queued_turns", "queued", "length", "count"], 0, fn key ->
        case Map.get(payload, key) do
          count when is_integer(count) and count >= 0 -> count
          _absent -> nil
        end
      end)
    else
      0
    end
  end

  @doc """
  Which verb one send should use.

  `status` is the session's polled status, used only where the ledger has never named a
  turn boundary.
  """
  @spec verb(turn(), atom()) :: String.t()
  def verb(%{spoke?: true, running?: true}, _status), do: "interactive.follow_up"
  def verb(%{spoke?: true}, _status), do: "interactive.send_message"
  def verb(_silent, :idle), do: "interactive.send_message"
  def verb(_silent, nil), do: "interactive.send_message"
  def verb(_silent, _busy), do: "interactive.follow_up"

  @doc "Whether an interrupt control belongs on screen, by the same two-source rule."
  @spec working?(turn(), atom()) :: boolean()
  def working?(%{spoke?: true, running?: running}, _status), do: running
  def working?(_silent, status), do: status in [:running, :starting, :awaiting_approval]

  @doc "One file-access posture or effort as a word, never a raw atom."
  @spec word(term()) :: String.t()
  def word(nil), do: "Session default"
  def word("default"), do: "Session default"
  def word("read_only"), do: "Read only"
  def word("workspace_write"), do: "Project files"
  def word("unrestricted"), do: "Full computer access"
  def word(value), do: value |> to_string() |> String.replace("_", " ")

  # ------------------------------------------------------------------------------------
  # Render
  # ------------------------------------------------------------------------------------

  @doc """
  The composer: a draft, one send, and what the runtime said about the last one.

  `sandbox` is `nil` where the session reported no posture, which is what makes the picker
  absent rather than defaulted.
  """
  attr :draft, :string, required: true
  attr :draft_key, :string, default: "standalone"
  attr :error, :any, required: true
  attr :turn, :map, required: true
  attr :status, :any, required: true
  attr :sandbox, :any, required: true
  attr :effort, :any, required: true
  attr :efforts, :list, default: @efforts
  attr :can_send, :boolean, required: true
  attr :can_interrupt, :boolean, required: true
  attr :can_configure, :boolean, required: true
  attr :ended, :boolean, default: false
  attr :can_retry, :boolean, default: false
  # ui-parity W2
  attr :can_steer, :boolean, default: false
  attr :plan, :boolean, default: false
  attr :next_effort, :any, default: nil
  attr :model, :any, default: nil
  attr :models, :any, default: nil
  attr :model_query, :string, default: ""

  def composer(assigns) do
    assigns =
      assigns
      |> assign(:working?, working?(assigns.turn, assigns.status))
      |> assign(:queues?, verb(assigns.turn, assigns.status) == "interactive.follow_up")

    ~H"""
    <div class="ouro-composer">
      <div class="ouro-composer-bar">
        <button
          type="button"
          class="ouro-quiet-button ouro-palette-trigger"
          phx-click="palette-open"
          aria-haspopup="dialog"
        >
          Commands <kbd>⌘K</kbd>
        </button>
        <span :if={@plan} class="ouro-chip ouro-plan-chip" role="status">Planning</span>
        <span :if={@next_effort} class="ouro-chip ouro-mono" role="status">
          next turn: {word(@next_effort)}
        </span>
        <span
          id="ouro-copy-status"
          class="ouro-quiet"
          phx-update="ignore"
          role="status"
          aria-live="polite"
        ></span>
      </div>

      <p :if={@error} class="ouro-refusal ouro-composer-refusal" role="alert">{@error}</p>
      <div :if={@turn.failed?} class="ouro-composer-retry" role="status">
        <span>The agent stopped before completing the last message.</span>
        <button
          :if={@can_retry}
          type="button"
          class="ouro-quiet-button"
          phx-click="retry"
        >
          Retry last message
        </button>
      </div>

      <p :if={@ended} class="ouro-quiet" role="status">
        This session has ended; it takes no further messages.
      </p>

      <p :if={not @ended and not @can_send} class="ouro-quiet" role="status">
        This endpoint was started at read scope, so it can show this session but not speak in it.
      </p>

      <div :if={not @ended} class="ouro-composer-surface">
        <form :if={@can_send} id="composer" phx-submit="send" phx-change="draft">
          <input type="hidden" name="session_key" value={@draft_key} />
          <div class="ouro-composer-box">
            <textarea
              id="ouro-composer-input"
              name="message"
              class="ouro-composer-input"
              phx-hook="Composer"
              data-draft-key={@draft_key}
              required
              phx-debounce="400"
              rows="1"
              aria-label="message"
              placeholder="Ask a question or describe the next step…"
            >{@draft}</textarea>

            <div class="ouro-composer-actions">
              <span :if={@turn.queued > 0} class="ouro-chip ouro-mono">{@turn.queued} queued</span>

              <button
                :if={@can_configure}
                type="button"
                class={["ouro-quiet-button", @plan && "ouro-toggle-on"]}
                phx-click="configure-plan"
                aria-pressed={to_string(@plan)}
                title={
                  if @plan,
                    do: "Leave plan mode",
                    else: "Ask this session to plan rather than edit"
                }
              >
                {if @plan, do: "Planning", else: "Plan"}
              </button>

              <button
                :if={@working? and @can_interrupt}
                type="button"
                class="ouro-quiet-button"
                phx-click="interrupt"
                data-ouro-interrupt
              >
                Interrupt <kbd>esc</kbd>
              </button>

              <button
                :if={@working? and @can_steer}
                type="submit"
                name="verb"
                value="steer"
                class="ouro-quiet-button ouro-steer"
                data-ouro-steer
                disabled={String.trim(@draft) == ""}
                phx-disable-with="Steering…"
              >
                Steer
              </button>

              <button
                type="submit"
                class="ouro-button"
                data-ouro-send
                disabled={String.trim(@draft) == ""}
                phx-disable-with="Sending…"
              >
                {if @queues?, do: "Queue", else: "Send"} <kbd>⏎</kbd>
              </button>
            </div>
          </div>
        </form>

        <details :if={@can_configure} class="ouro-composer-settings" data-ouro-disclosure={@draft_key}>
          <summary phx-click="composer-settings">
            {if @sandbox, do: word(@sandbox), else: "File access not reported"} · {word(@effort)} thinking<span :if={
              @plan
            }>&nbsp;· Planning</span>
            <span>Change</span>
          </summary>
          <div class="ouro-composer-footer">
            <.picker
              :if={@sandbox}
              label="File access"
              current={@sandbox}
              choices={sandbox_modes()}
              field="sandbox_mode"
              warn={to_string(@sandbox) == "unrestricted"}
            />

            <.picker
              label="Thinking"
              current={@effort}
              choices={@efforts}
              field="reasoning_effort"
              warn={false}
            />

            <.next_turn_effort current={@next_effort} choices={@efforts} />

            <.model_picker current={@model} models={@models} query={@model_query} />
          </div>
        </details>
      </div>
    </div>
    """
  end

  @doc """
  One marked-button group.

  `current` is what the runtime last reported, and the mark is on it alone — see the
  moduledoc for why this is not a `<select>`.
  """
  attr :label, :string, required: true
  attr :current, :any, required: true
  attr :choices, :list, required: true
  attr :field, :string, required: true
  attr :warn, :boolean, required: true

  def picker(assigns) do
    ~H"""
    <div class={["ouro-picker", @warn && "ouro-picker-warn"]}>
      <span class="ouro-picker-label">{@label} · {word(@current)}</span>
      <button
        :for={choice <- @choices}
        type="button"
        class={["ouro-picker-option", to_string(@current) == choice && "ouro-picker-on"]}
        aria-pressed={to_string(to_string(@current) == choice)}
        phx-click="configure"
        phx-value-choice={choice}
        phx-value-field={@field}
      >
        {word(choice)}
      </button>
    </div>
    """
  end

  # ------------------------------------------------------------------------------------
  # ui-parity W2
  # ------------------------------------------------------------------------------------

  @doc """
  The per-turn effort: `reasoning_effort` on the **next** send and only that one.

  A different control from the picker above it, and deliberately drawn as one. The picker
  above changes the session; this changes one turn and then forgets, which is the terminal
  client's `/effort` (`tui/src/ui/app/session.rs:1163-1223`) and the same envelope key at
  a different scope. `Session default` is the off position rather than a value — there is
  no `default` effort to send, only a word for not overriding.
  """
  attr :current, :any, required: true
  attr :choices, :list, required: true

  def next_turn_effort(assigns) do
    ~H"""
    <div class="ouro-picker">
      <span class="ouro-picker-label">Next turn only · {word(@current)}</span>
      <button
        type="button"
        class={["ouro-picker-option", is_nil(@current) && "ouro-picker-on"]}
        aria-pressed={to_string(is_nil(@current))}
        phx-click="effort-next-turn"
        phx-value-choice="session"
      >
        Session default
      </button>
      <button
        :for={choice <- @choices}
        type="button"
        class={["ouro-picker-option", to_string(@current) == choice && "ouro-picker-on"]}
        aria-pressed={to_string(to_string(@current) == choice)}
        phx-click="effort-next-turn"
        phx-value-choice={choice}
      >
        {word(choice)}
      </button>
    </div>
    """
  end

  @doc """
  The model this session is running, and the catalogue it can be changed to.

  `models` is `nil` until the disclosure is opened — `runtime.models` is fetched then and
  never on the three-second cadence, which is `/new`'s own rule. A refusal is drawn as the
  runtime's sentence and the control is simply absent: a picker with no rows would be this
  page claiming the runtime knows of no models.
  """
  attr :current, :any, required: true
  attr :models, :any, required: true
  attr :query, :string, default: ""

  def model_picker(%{models: {:error, _message}} = assigns) do
    assigns = assign(assigns, :message, elem(assigns.models, 1))

    ~H"""
    <div class="ouro-picker ouro-model-picker">
      <span class="ouro-picker-label">Model · {present_model(@current)}</span>
      <p class="ouro-quiet">{@message}</p>
    </div>
    """
  end

  def model_picker(%{models: models} = assigns) when is_list(models) do
    assigns = assign(assigns, :rows, search_models(models, assigns.query, assigns.current))

    ~H"""
    <div class="ouro-picker ouro-model-picker">
      <span class="ouro-picker-label">Model · {present_model(@current)}</span>

      <form class="ouro-model-search" phx-change="model-search">
        <input
          type="search"
          name="query"
          value={@query}
          placeholder="Search models"
          aria-label="Search models"
          autocomplete="off"
          phx-debounce="150"
        />
      </form>

      <form phx-change="configure-model">
        <select name="model" size="6" aria-label="Model" class="ouro-model-select">
          <option :for={row <- @rows} value={row.id} selected={row.id == to_string(@current)}>
            {row.label}
          </option>
        </select>
      </form>

      <p :if={@rows == []} class="ouro-quiet">No model in this runtime's list matches.</p>
    </div>
    """
  end

  # Not fetched yet, or fetched and unreadable. Neither is a list to draw.
  def model_picker(assigns) do
    ~H"""
    <div class="ouro-picker ouro-model-picker">
      <span class="ouro-picker-label">Model · {present_model(@current)}</span>
    </div>
    """
  end

  @doc """
  The rows of `runtime.models` this surface can offer, flattened across providers.

  Pure, so the filtering a person types is testable without a runtime. The **current**
  model always survives its own search: a `<select>` whose selected value is not among its
  options draws some other row, which is the one disagreement between widget and state
  worth ruling out.
  """
  @spec search_models([map()], String.t() | nil, term()) :: [map()]
  def search_models(rows, query, current) when is_list(rows) do
    current = current && to_string(current)

    case query |> to_string() |> String.trim() |> String.downcase() do
      "" ->
        rows

      needle ->
        Enum.filter(rows, fn row ->
          row.id == current or String.contains?(String.downcase(row.label), needle) or
            String.contains?(String.downcase(row.id), needle)
        end)
    end
  end

  @doc """
  `runtime.models`' answer, as `[%{id, label}]`.

  Every provider's rows, in the order the runtime listed them, with the id kept verbatim —
  it is what `interactive.configure` takes. Anything this build cannot read is dropped
  rather than drawn as a row that would configure nothing.
  """
  @spec model_rows(term()) :: [map()]
  def model_rows(%{providers: providers}) when is_list(providers) do
    Enum.flat_map(providers, fn provider ->
      provider
      |> Map.get(:models)
      |> List.wrap()
      |> Enum.flat_map(fn model ->
        case model |> Map.get(:id) |> to_string() do
          "" -> []
          id -> [%{id: id, label: model_label(id, model)}]
        end
      end)
    end)
  end

  def model_rows(_unreadable), do: []

  defp model_label(id, model) do
    case model |> Map.get(:name) |> to_string() |> String.trim() do
      "" -> id
      name -> "#{name} · #{id}"
    end
  end

  defp present_model(nil), do: "not reported"
  defp present_model(model), do: to_string(model)
end
