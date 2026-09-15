defmodule Ouroboros.Web.Live.BacktrackDialog do
  @moduledoc """
  W3.3. Going back through a conversation, and the two things that actually means.

  Port of `App::open_backtrack` / `backtrack_edit` / `backtrack_fork`
  (`tui/src/ui/app/session.rs:940-1115`) and the menu `docs/TUI.md:2155-2181` describes.

  ## The list is the durable ledger's, not this page's

  The last ten user turns are read out of the held `input_accepted` events, exactly as the
  terminal client reads them (`tui/src/ui/transcript.rs:959-987`), so a second client
  watching the same session sees the same list. **Steers are excluded**: a steer is an
  injection into a turn that was already running, not a turn to go back to.

  ## Neither verb is a rewind, and the dialog says so

  * **Edit and resend** puts the message's text in the composer. Nothing is removed — the
    transcript is unchanged and the provider's context is unchanged — and saying otherwise
    is the rewind that silently under-delivers (Claude Code #18516).
  * **Fork** calls `interactive.fork {id, node}`. The verb takes a session and no message,
    so **this client does not promise the branch starts at the highlighted row**: Codex can
    fork a thread from a message, Claude's `--fork-session` branches at the tail, and which
    one a session gets is decided on the other side of the wire. The dialog says that in as
    many words rather than implying a precision it does not have.

  The third answer — rewind, the one that undoes — is its own dialog
  (`Ouroboros.Web.Live.RewindDialog`), because a rewind states what it cannot restore
  before it acts and there is no room for that here.
  """

  use Phoenix.Component

  alias Ouroboros.Web.Transcript.Entry

  @doc "How many user turns the dialog lists. Ten, as Claude Code's rewind does."
  @spec entries() :: pos_integer()
  def entries, do: 10

  @doc """
  The last `limit` user turns the held ledger proves, oldest first.

  Returns `[{sequence, text}]`. Pure: entries in, a list out.
  """
  @spec recent_user_turns([Entry.t()], pos_integer()) :: [{non_neg_integer(), String.t()}]
  def recent_user_turns(held, limit \\ 10) when is_list(held) and is_integer(limit) do
    held
    |> Enum.reverse()
    |> Enum.filter(&match?(%Entry.Event{}, &1))
    |> Enum.filter(fn %Entry.Event{event: event} -> Map.get(event, :type) == :input_accepted end)
    |> Enum.reject(fn %Entry.Event{event: event} -> steer?(event) end)
    |> Enum.flat_map(fn %Entry.Event{event: event} ->
      case said(event) do
        nil -> []
        text -> [{Map.get(event, :sequence), text}]
      end
    end)
    |> Enum.take(limit)
    |> Enum.reverse()
  end

  # The payload's own key. A `kind` this build has not heard of is not a steer: silence
  # and an unknown word both mean "an ordinary accepted input", which is the reading the
  # terminal client takes (`tui/src/ui/transcript.rs:965-972`).
  defp steer?(event) do
    case Map.get(event, :payload) do
      %{"kind" => kind} -> kind == "steer"
      _absent -> false
    end
  end

  defp said(event) do
    case Map.get(event, :payload) do
      %{"text" => text} when is_binary(text) ->
        case String.trim(text) do
          "" -> nil
          trimmed -> trimmed
        end

      _absent ->
        nil
    end
  end

  # ------------------------------------------------------------------------------------
  # Render
  # ------------------------------------------------------------------------------------

  attr :turns, :list, required: true
  attr :can_fork, :boolean, required: true
  attr :can_resend, :boolean, required: true
  attr :error, :any, default: nil

  def dialog(assigns) do
    ~H"""
    <dialog
      id="ouro-backtrack"
      class="ouro-session-dialog ouro-backtrack"
      aria-modal="true"
      aria-labelledby="ouro-backtrack-title"
      phx-hook="Modal"
      data-cancel-event="w3-close"
    >
      <div class="ouro-session-dialog-form">
        <h2 id="ouro-backtrack-title">Go back to an earlier message</h2>

        <p :if={@can_resend}>
          <strong>Edit and resend</strong>
          puts that message back in the composer as a new turn. Nothing between here and there
          is removed: the conversation keeps every word it has.
        </p>

        <p :if={@can_fork}>
          <strong>Fork</strong>
          asks the runtime to branch this session. Where the branch starts is the transport's
          decision, not this page's — this client does not promise it begins at the message you
          picked.
        </p>

        <p :if={@error} class="ouro-refusal" role="alert">{@error}</p>

        <p :if={@turns == []} class="ouro-quiet">
          This page holds no earlier message from you for this session.
        </p>

        <ol class="ouro-backtrack-list">
          <li :for={{sequence, text} <- @turns} class="ouro-backtrack-row">
            <span class="ouro-mono ouro-backtrack-seq">{sequence}</span>
            <span class="ouro-backtrack-text">{text}</span>
            <span class="ouro-backtrack-actions">
              <button
                :if={@can_resend}
                type="button"
                class="ouro-quiet-button"
                phx-click="w3-backtrack-edit"
                phx-value-sequence={sequence}
              >
                Edit and resend
              </button>
            </span>
          </li>
        </ol>

        <%!-- W3 fix wave (L6). **One** Fork control, because the verb takes a session and
              no message: a button on every row would be this dialog implying it branches
              at the row it sits beside, which is the one promise the paragraph above it
              spends three lines refusing to make. The terminal client has one too. --%>
        <div class="ouro-session-dialog-actions">
          <button
            :if={@can_fork}
            type="button"
            class="ouro-button-quiet"
            phx-click="w3-backtrack-fork"
            phx-disable-with="Forking…"
          >
            Fork this session
          </button>
          <button type="button" class="ouro-button" phx-click="w3-close">Close</button>
        </div>
      </div>
    </dialog>
    """
  end
end
