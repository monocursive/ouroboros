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

  ## The turn envelope is a plain string

  `input` is sent as the bare prompt, which is the common case of the closed envelope
  (`docs/PROTOCOL.md` `interactive.send_message`). Attachments and a per-turn
  `reasoning_effort` are the object form and are **not** built here: attachments must name
  files inside the leased workspace, which a browser cannot enumerate until
  `workspace.browse` lands, and a per-turn effort is a different control from the
  session-wide picker in this footer. Both are named in the slice report rather than
  half-built.

  ## The pickers are absent when the runtime said nothing

  A sandbox picker is offered only where the session **reported** a posture. A picker
  defaulted to `workspace_write` because nothing said otherwise would be this page telling
  an operator what a session is allowed to do on no evidence, which is the one thing a
  security control must never do (`docs/DESKTOP.md:63-69`, `docs/WEB.md` §4).

  The thinking picker is always offered because effort is a preference, not a permission,
  and its **label** carries the same honesty: `Default` where nothing reported one. The
  three sendable values are `low`, `medium`, `high` and nothing else, because those are the
  three `interactive.configure` accepts (`lib/ouroboros/gateway/methods.ex:409`) — there is
  no `default` to send, only a word for not having been told.

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
  # The three `interactive.configure` accepts. There is no fourth: see the moduledoc.
  @efforts ~w(low medium high)

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
    Enum.reduce(entries, %{running?: false, spoke?: false, turn_id: nil, queued: 0}, fn
      %Entry.Event{event: event}, state -> absorb(state, event)
      _divider, state -> state
    end)
  end

  defp absorb(state, event) do
    case Map.get(event, :type) do
      :turn_started ->
        %{state | running?: true, spoke?: true, turn_id: Map.get(event, :turn_id)}

      type when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        %{state | running?: false, spoke?: true, turn_id: nil}

      :queue_changed ->
        %{state | queued: queued_of(event)}

      # The session itself went away, whatever the last turn boundary said.
      type when type in [:session_closed, :session_idle] ->
        %{state | running?: false, spoke?: true, turn_id: nil}

      _other ->
        state
    end
  end

  # The payload's own key, in the order the presentation reads them
  # (`Ouroboros.Web.Presentation` `:queue_changed`). Nothing is inferred from a missing
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

  @doc "One sandbox posture or effort as a word, never a raw atom."
  @spec word(term()) :: String.t()
  def word(nil), do: "Default"
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
  attr :error, :any, required: true
  attr :turn, :map, required: true
  attr :status, :any, required: true
  attr :sandbox, :any, required: true
  attr :effort, :any, required: true
  attr :can_send, :boolean, required: true
  attr :can_interrupt, :boolean, required: true
  attr :can_configure, :boolean, required: true
  attr :ended, :boolean, default: false

  def composer(assigns) do
    assigns =
      assigns
      |> assign(:working?, working?(assigns.turn, assigns.status))
      |> assign(:queues?, verb(assigns.turn, assigns.status) == "interactive.follow_up")

    ~H"""
    <div class="ouro-composer">
      <p :if={@error} class="ouro-refusal ouro-composer-refusal">{@error}</p>

      <p :if={@ended} class="ouro-quiet">
        This session has ended; it takes no further messages.
      </p>

      <p :if={not @ended and not @can_send} class="ouro-quiet">
        This endpoint was started at read scope, so it can show this session but not speak in it.
      </p>

      <form :if={not @ended and @can_send} id="composer" phx-submit="send" phx-change="draft">
        <div class="ouro-composer-box">
          <textarea
            id="ouro-composer-input"
            name="message"
            class="ouro-composer-input"
            phx-hook="Composer"
            phx-debounce="400"
            rows="1"
            aria-label="message"
            placeholder="Say something. Enter sends, Shift-Enter is a new line."
          >{@draft}</textarea>

          <div class="ouro-composer-actions">
            <span :if={@turn.queued > 0} class="ouro-chip ouro-mono">{@turn.queued} queued</span>

            <button
              :if={@working? and @can_interrupt}
              type="button"
              class="ouro-quiet-button"
              phx-click="interrupt"
            >
              Interrupt
            </button>

            <button type="submit" class="ouro-button" phx-disable-with="Sending…">
              {if @queues?, do: "Queue", else: "Send"}
            </button>
          </div>
        </div>
      </form>

      <div :if={@can_configure and not @ended} class="ouro-composer-footer">
        <.picker
          :if={@sandbox}
          label="Sandbox"
          current={@sandbox}
          choices={sandbox_modes()}
          field="sandbox_mode"
          warn={to_string(@sandbox) == "unrestricted"}
        />

        <.picker
          label="Thinking"
          current={@effort}
          choices={efforts()}
          field="reasoning_effort"
          warn={false}
        />
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
end
