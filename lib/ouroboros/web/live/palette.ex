defmodule Ouroboros.Web.Live.Palette do
  @moduledoc """
  The command palette and the shortcut sheet, and the one element that owns the keyboard.

  ## The list is the server's, and so is the filtering

  `Ouroboros.Web.Commands.available/1` decides what is in the palette and the deck's own
  process does the filtering. Nothing about which verbs exist is sent to the browser to be
  narrowed there: a client-side filter would need the whole ungated catalogue in the DOM,
  and a row the runtime cannot serve would then be one broken selector away from being
  drawn. What the browser owns is the *key*, and only until it has been pushed.

  ## Selection is an index into the flat list

  `Commands.available/1` returns catalogue order, which is group order, and `search/2`
  filters without reordering — so the flat position of a row and its position on screen are
  the same number, and `↑`/`↓` moving one index moves one visible row. `grouped/1` only
  decides where the headings go.

  ## Arrow keys are bound by key, not by handler

  `phx-keydown` with no `phx-key` would send a message for every character typed into the
  query box, on top of the debounced `phx-change` already carrying it. `phx-keydown` also
  fires only on the element the key landed on, never on an ancestor, so the two bindings
  are `phx-window-keydown` on two elements that exist **only while the palette is open** —
  which is what scopes a window binding to a modal. `Enter` is the form's own submit and
  `Esc` is the `<dialog>`'s native cancel, which `app.js`'s `Modal` hook turns into
  `palette-close`. So a printable keystroke costs one debounced round trip and nothing
  else.

  ## One hook owns the document

  `#ouro-keys` is inside the LiveView, so its hook can `pushEvent` into the deck. That is
  the whole reason the document-level shortcuts live on an element rather than on a bare
  `document.addEventListener` beside the LiveSocket: a listener outside a hook has nothing
  to push to.
  """

  use Phoenix.Component

  alias Ouroboros.Web.Commands

  @doc """
  What the deck renders once, immediately under the top bar.

  `palette` is `nil` when closed and `%{query:, selected:, rows:}` when open; `sheet` is
  the shortcut sheet's own boolean. Both are drawn as `<dialog>` elements so the browser
  owns the modality, the backdrop and the focus trap.
  """
  attr :palette, :any, required: true
  attr :sheet, :boolean, required: true

  def overlays(assigns) do
    ~H"""
    <div id="ouro-keys" phx-hook="Keys" data-palette-open={@palette && "true"}>
      <.palette :if={@palette} palette={@palette} />
      <.shortcut_sheet :if={@sheet} />
    </div>
    """
  end

  @doc "The palette itself. Only rendered while it is open."
  attr :palette, :map, required: true

  def palette(assigns) do
    assigns =
      assigns
      |> assign(:grouped, Commands.grouped(assigns.palette.rows))
      |> assign(
        :positions,
        assigns.palette.rows |> Enum.with_index() |> Map.new(fn {row, at} -> {row.id, at} end)
      )
      |> assign(:selected, selected_id(assigns.palette))

    ~H"""
    <dialog
      id="ouro-palette"
      class="ouro-palette"
      aria-modal="true"
      aria-label="Commands"
      phx-hook="Modal"
      data-cancel-event="palette-close"
    >
      <span hidden phx-window-keydown="palette-move" phx-key="ArrowDown" phx-value-direction="next"></span>
      <span hidden phx-window-keydown="palette-move" phx-key="ArrowUp" phx-value-direction="prev"></span>

      <form class="ouro-palette-head" phx-change="palette-filter" phx-submit="palette-run">
        <input
          id="ouro-palette-query"
          type="text"
          name="query"
          value={@palette.query}
          class="ouro-palette-query"
          placeholder="Search commands"
          aria-label="Search commands"
          aria-controls="ouro-palette-list"
          autocomplete="off"
          phx-debounce="120"
          autofocus
        />
        <kbd>esc</kbd>
        <button type="submit" class="ouro-visually-hidden">Run the selected command</button>
      </form>

      <p :if={@palette.rows == []} class="ouro-palette-empty">
        Nothing here matches, and this list only offers what this runtime can actually run.
      </p>

      <div id="ouro-palette-list" class="ouro-palette-list" role="listbox" aria-label="Commands">
        <div :for={{group, rows} <- @grouped} class="ouro-palette-section">
          <p class="ouro-palette-group" role="presentation">{Commands.group_label(group)}</p>
          <button
            :for={row <- rows}
            type="button"
            role="option"
            id={"ouro-palette-row-#{row.id}"}
            class={["ouro-palette-row", row.id == @selected && "ouro-palette-on"]}
            aria-selected={to_string(row.id == @selected)}
            phx-click="palette-run"
            phx-value-id={row.id}
          >
            <span class="ouro-palette-label">{row.label}</span>
            <span class="ouro-palette-slash ouro-mono">{row.slash}</span>
            <span class="ouro-palette-key">
              <kbd :if={row.shortcut}>{row.shortcut}</kbd>
            </span>
          </button>
        </div>
      </div>
    </dialog>
    """
  end

  @doc """
  Every key this surface binds, said once.

  Written here rather than derived from the catalogue because most of these are browser
  keys rather than verbs: `[` and `]` run no command, they move the selection.
  """
  def shortcut_sheet(assigns) do
    assigns = assign(assigns, :rows, shortcuts())

    ~H"""
    <dialog
      id="ouro-shortcuts"
      class="ouro-session-dialog ouro-shortcuts"
      aria-modal="true"
      aria-labelledby="ouro-shortcuts-title"
      phx-hook="Modal"
      data-cancel-event="shortcuts-close"
    >
      <div class="ouro-session-dialog-form">
        <h2 id="ouro-shortcuts-title">Keyboard</h2>
        <dl class="ouro-shortcut-list">
          <div :for={{keys, what} <- @rows} class="ouro-shortcut-row">
            <dt><kbd :for={key <- keys}>{key}</kbd></dt>
            <dd>{what}</dd>
          </div>
        </dl>
        <p class="ouro-quiet">
          A key is only listed here where this page actually binds it. Your browser's own
          shortcuts are left alone.
        </p>
        <div class="ouro-session-dialog-actions">
          <button type="button" class="ouro-button" phx-click="shortcuts-close" autofocus>
            Close
          </button>
        </div>
      </div>
    </dialog>
    """
  end

  @doc "The shortcut sheet's rows, as `{[key], meaning}`."
  @spec shortcuts() :: [{[String.t()], String.t()}]
  def shortcuts do
    [
      {["⌘K"], "Open or close the command palette (ctrl+K elsewhere), from anywhere"},
      {["?"], "This sheet"},
      {["/"], "Search sessions"},
      {["n"], "Start a new session"},
      {["[", "]"], "Open the previous or next session in the rail"},
      {["↑", "↓"], "Move the palette's selection"},
      {["⏎"], "Run the selected command, or send the message you are writing"},
      {["shift", "⏎"], "A new line in the message you are writing"},
      {["esc"], "Close what is open — and in the composer, stop a running turn"}
    ]
  end

  defp selected_id(%{rows: rows, selected: selected}) do
    case Enum.at(rows, selected) do
      nil -> nil
      row -> row.id
    end
  end
end
