defmodule Ouroboros.Web.Live.VerbDialogs do
  @moduledoc """
  W3.2, W3.5, W3.6. The three W3 verbs that need one answer before they run.

  A compaction takes an optional focus, a handoff an optional prompt, and an export a
  choice of which of the two forms is wanted. None of them is a panel and none of them is
  worth a file: they are one question each, asked in the same `<dialog>` shell the rest of
  this surface uses, so `Esc` closes them through the one `Modal` hook.

  Each says what the verb will do **before** it is pressed, because every one of the three
  is irreversible in a way the composer's Send is not: a fold rewrites the conversation,
  a handoff starts a second session, and an export writes a file to the reader's disk.
  """

  use Phoenix.Component

  @doc """
  `interactive.compact {id, focus?}`.

  The focus is optional and blank means absent: the runtime refuses an empty string
  (`invalid_compaction_focus`) rather than treating it as "no focus", so this sends the
  key only where there are words in it.
  """
  attr :error, :any, default: nil

  def compact(assigns) do
    ~H"""
    <dialog
      id="ouro-compact"
      class="ouro-session-dialog"
      aria-modal="true"
      aria-labelledby="ouro-compact-title"
      phx-hook="Modal"
      data-cancel-event="w3-close"
    >
      <form class="ouro-session-dialog-form" phx-submit="w3-compact">
        <h2 id="ouro-compact-title">Compact this conversation</h2>
        <p>
          The runtime folds the history it is carrying into a summary and archives what it
          replaced. The report says what was archived and what was elided; the conversation
          keeps going from there.
        </p>

        <p :if={@error} class="ouro-refusal" role="alert">{@error}</p>

        <label for="ouro-compact-focus">What should the fold keep? (optional)</label>
        <input
          id="ouro-compact-focus"
          type="text"
          name="focus"
          autocomplete="off"
          placeholder="the migration we are in the middle of"
          autofocus
        />

        <div class="ouro-session-dialog-actions">
          <button type="button" class="ouro-button-quiet" phx-click="w3-close">Cancel</button>
          <button type="submit" class="ouro-button" phx-disable-with="Folding…">Compact</button>
        </div>
      </form>
    </dialog>
    """
  end

  @doc """
  `interactive.handoff {id, prompt?, handoff_id}`.

  The parent keeps running: ending it is the operator's call and this dialog says so
  rather than implying the handoff is a move.
  """
  attr :error, :any, default: nil

  def handoff(assigns) do
    ~H"""
    <dialog
      id="ouro-handoff"
      class="ouro-session-dialog"
      aria-modal="true"
      aria-labelledby="ouro-handoff-title"
      phx-hook="Modal"
      data-cancel-event="w3-close"
    >
      <form class="ouro-session-dialog-form" phx-submit="w3-handoff">
        <h2 id="ouro-handoff-title">Hand off to a new session</h2>
        <p>
          The runtime writes a packet describing where this conversation got to and starts a
          child session from it. This one keeps running — ending it is your call.
        </p>

        <p :if={@error} class="ouro-refusal" role="alert">{@error}</p>

        <label for="ouro-handoff-prompt">What should the child pick up? (optional)</label>
        <textarea
          id="ouro-handoff-prompt"
          name="prompt"
          rows="3"
          placeholder="finish the migration and run the suite"
          autofocus
        ></textarea>

        <div class="ouro-session-dialog-actions">
          <button type="button" class="ouro-button-quiet" phx-click="w3-close">Cancel</button>
          <button type="submit" class="ouro-button" phx-disable-with="Handing off…">
            Hand off
          </button>
        </div>
      </form>
    </dialog>
    """
  end

  @doc """
  Which of the two exports to download.

  Two buttons rather than a picker, because there is no state to hold: the choice *is* the
  action, and what each one contains differs enough to be worth a sentence each.
  """
  def export(assigns) do
    ~H"""
    <dialog
      id="ouro-export"
      class="ouro-session-dialog"
      aria-modal="true"
      aria-labelledby="ouro-export-title"
      phx-hook="Modal"
      data-cancel-event="w3-close"
    >
      <div class="ouro-session-dialog-form">
        <h2 id="ouro-export-title">Export this transcript</h2>
        <p>
          Either form holds only what this runtime still retains, and the file says so on its
          last line.
        </p>

        <div class="ouro-export-choices">
          <button
            type="button"
            class="ouro-button"
            phx-click="w3-export"
            phx-value-format="text"
          >
            Readable text
          </button>
          <p class="ouro-quiet">
            The conversation as it reads, with the screen's own folding and caps removed.
          </p>

          <button
            type="button"
            class="ouro-button-quiet"
            phx-click="w3-export"
            phx-value-format="ndjson"
          >
            The events (NDJSON)
          </button>
          <p class="ouro-quiet">
            One event object per line, exactly as the runtime framed them — nothing added and
            nothing reshaped, wire markers included.
          </p>
        </div>

        <div class="ouro-session-dialog-actions">
          <button type="button" class="ouro-button-quiet" phx-click="w3-close">Close</button>
        </div>
      </div>
    </dialog>
    """
  end
end
