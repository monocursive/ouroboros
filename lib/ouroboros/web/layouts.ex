defmodule Ouroboros.Web.Layouts do
  @moduledoc """
  The one HTML document every page is rendered into, and the two chrome controls that sit
  in every page's top row.

  Three files and a font link, all of them named here rather than assembled by a build
  step, because the production asset path has no JavaScript bundler. `phoenix.min.js` and
  `phoenix_live_view.min.js` are copied out of the dependencies verbatim by the
  `web.assets` mix alias; `app.css` and `app.js` are written by hand and read like it.
  Playwright exercises those files in a browser but does not build or transform them.

  ## The one script that is not deferred

  `app.js` is deferred like the two bundles it stands on, because nothing it does needs to
  happen before the page is drawn. `theme_script/0` is the exception and the reason it is
  inline in `<head>` rather than a fourth file: it reads the viewer's stored theme and
  stamps it on `<html>` **before first paint**. Deferred, or fetched, it would run after
  the browser had already painted a dark frame, and a viewer who chose light would see the
  surface blink at them on every navigation. It is the smallest thing that can be correct
  here — one `getItem`, one `setAttribute`, the whole of it inside a `try` — and it is the
  only inline script this surface serves.

  ## Why the theme is not an assign

  Which theme a browser is in is a fact about that browser, not about this runtime, and
  there is one runtime behind an arbitrary number of tabs. Holding it server-side would
  make one viewer's choice everyone's, and would put a round trip between the click and
  the repaint. So the two chrome toggles below are **static markup**: identical on every
  render, carrying no assign, driven entirely by `app.js`. LiveView re-renders cannot
  clobber what they set, because the server never has an opinion to overwrite it with.
  """

  use Phoenix.Component

  import Phoenix.Controller, only: [get_csrf_token: 0]

  alias Ouroboros.Web.Presentation

  @storage_key "ouroboros:theme"

  @doc """
  The `localStorage` key both halves of the theme agree on.

  Named once here so the inline head script and `app.js` cannot drift apart into a page
  that writes a preference it will never read back.
  """
  @spec theme_storage_key() :: String.t()
  def theme_storage_key, do: @storage_key

  @doc """
  The pre-paint theme script, as source.

  A function rather than a heredoc in the markup so a test can assert what it does without
  parsing HTML: the whole contract is that it reads #{@storage_key}, accepts only the two
  words that name a theme, and stamps nothing at all on anything else — including on a
  browser that refuses the read outright, which a private window and a browser set to block
  site data both do. The failure is dark, which is the theme this surface is designed in.
  """
  @spec theme_script() :: String.t()
  def theme_script do
    """
    (function () {
      try {
        var choice = window.localStorage.getItem("#{@storage_key}");
        if (choice === "light" || choice === "dark") {
          document.documentElement.setAttribute("data-theme", choice);
        }
      } catch (error) {
        /* No storage: dark, which is the default this surface is designed in. */
      }
    })();
    """
  end

  @doc """
  The pre-paint theme script wrapped in its `<script>` element, ready to render.

  Built here rather than written into the markup because HEEx treats the contents of a
  `<script>` tag as verbatim text — `{...}` inside one is two braces, not an interpolation
  — so a template cannot reach `theme_script/0` from inside the element. Emitting the whole
  element as a marked-safe string is the way to keep one definition. Nothing here is
  derived from a request, so there is no input for the escaping to be protecting.
  """
  @spec theme_script_tag() :: Phoenix.HTML.safe()
  def theme_script_tag, do: Phoenix.HTML.raw("<script>" <> theme_script() <> "</script>")

  @doc "The document shell."
  def root(assigns) do
    assigns =
      assigns
      |> assign_new(:page_title, fn -> nil end)
      |> assign(:theme_script_tag, theme_script_tag())

    ~H"""
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="referrer" content="no-referrer" />
        <meta name="csrf-token" content={get_csrf_token()} />
        <.live_title default="Ouroboros" suffix=" · Ouroboros">{@page_title}</.live_title>
        {@theme_script_tag}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=EB+Garamond:ital,wght@0,400..800;1,400..800&family=Hanken+Grotesk:ital,wght@0,100..900;1,100..900&family=IBM+Plex+Mono:wght@400;500;600&display=swap"
        />
        <link rel="stylesheet" href="/web/app.css" />
        <script defer src="/web/phoenix.min.js">
        </script>
        <script defer src="/web/phoenix_live_view.min.js">
        </script>
        <script defer src="/web/image-attachments.js">
        </script>
        <script defer src="/web/app.js">
        </script>
      </head>
      <body>
        {@inner_content}
      </body>
    </html>
    """
  end

  @doc """
  The one top bar, on every page this surface serves.

  Until W1 it existed only on the deck (`deck_live.ex:1491-1533`), which is why
  `docs/design-qa/ui-review-2026-09-15.md` §3.1 found three header treatments, no route to
  `/status` at all, and a connection pill and a bell that a person filling in `/new` or
  reading `/audit` could not see. One component, rendered by every LiveView, is the whole
  of the repair; the spokes keep their "← Sessions" breadcrumb *below* it rather than
  instead of it.

  ## What it may say, and what it may not

  `machines` and `today` are the deck's own measurements. Every other page renders this
  bar without them and therefore draws neither — a presence readout on `/settings` would
  be a claim about cluster connectivity made by a page that never asked, and a token total
  would be arithmetic over a session list it does not hold. Absent, not defaulted, applies
  to chrome too.

  The connection pill carries the same classes the deck's did, because the swap between
  "Connected" and "Reconnecting" is `.phx-connected` / `.phx-loading` in `app.css` and
  nothing server-side: the pill is one element in both states and the stylesheet chooses
  which half of it is visible.

  `current` marks the link for the page being read with `aria-current="page"` — **one**
  element per page, which is what the attribute means. The wordmark goes to `/` too and
  deliberately does not carry it: `aria-current` on two elements tells a screen-reader
  user there are two current pages, and the section link is the one that names the
  section. A spoke of a section is marked at its section (`/s/:plane/:id` marks Sessions,
  `/audit/:stream` marks Audit), because that is where the reader is.
  """
  attr :current, :atom, default: nil
  attr :machines, :list, default: []
  attr :today, :map, default: %{tokens: nil, cost: nil}

  def topbar(assigns) do
    connected = Enum.count(assigns.machines, & &1.connected?)

    assigns =
      assign(
        assigns,
        :machines_label,
        "Machines — #{connected} connected of #{length(assigns.machines)}"
      )

    ~H"""
    <header class="ouro-topbar">
      <a class="ouro-wordmark" href="/">Ouroboros</a>

      <nav class="ouro-topbar-nav" aria-label="Sections">
        <a class="ouro-topbar-link" href="/" aria-current={@current == :sessions && "page"}>
          Sessions
        </a>
        <a class="ouro-topbar-link" href="/settings" aria-current={@current == :settings && "page"}>
          Settings
        </a>
        <a class="ouro-topbar-link" href="/audit" aria-current={@current == :audit && "page"}>
          Audit
        </a>
        <a class="ouro-topbar-link" href="/status" aria-current={@current == :status && "page"}>
          Status
        </a>
        <a class="ouro-topbar-link" href="/devices" aria-current={@current == :devices && "page"}>
          Devices
        </a>
      </nav>

      <%!-- Each entry carries its own `:label`, resolved by the caller against the fleet
            roster it holds. The bar deliberately does not re-derive one: two machines in a
            fleet share a release name, so a bar that shortened `ouro@alpha` and
            `ouro@beta` itself would put the same word under both dots. --%>
      <%!-- The machine labels are the link to Devices, which is the proposal's own
            instruction: the row of dots is where an operator is already looking when they
            want to know about a machine. It is an anchor rather than an image role now, so
            the accessible name says both what it reads and where it goes. --%>
      <a
        :if={@machines != []}
        class="ouro-presence"
        href="/devices"
        aria-labelledby="ouro-presence-readout ouro-presence-go"
      >
        <span class="ouro-presence-label">Machines</span>
        <span
          id="ouro-presence-readout"
          class="ouro-presence-dots"
          role="img"
          aria-label={@machines_label}
        >
          <span
            :for={machine <- @machines}
            class={["ouro-dot", machine.connected? && "ouro-dot-on"]}
            title={"#{label(machine)} — #{if machine.connected?, do: "connected", else: "not connected"}"}
          >
            <span class="ouro-visually-hidden">{label(machine)}</span>
          </span>
        </span>
        <span id="ouro-presence-go" class="ouro-visually-hidden">Open Devices</span>
      </a>

      <div class="ouro-topbar-right">
        <span
          :if={Map.get(@today, :tokens)}
          class="ouro-today ouro-mono"
          title="sessions updated today, UTC"
        >
          {@today.tokens} tokens<span :if={Map.get(@today, :cost)}> · ${@today.cost}</span>
        </span>
        <span class="ouro-pill" role="status" aria-live="polite" aria-atomic="true">
          <span class="ouro-pill-on">Connected</span>
          <span class="ouro-pill-off">Reconnecting</span>
        </span>
        <.bell_toggle />
        <.theme_toggle />
        <a class="ouro-button" href="/new" aria-current={@current == :new && "page"}>New session</a>
      </div>
    </header>
    """
  end

  # The caller's own word for a machine. `node_label/1` is the fallback for a caller that
  # has no roster to resolve against — never a second opinion about one that does.
  defp label(machine),
    do: Map.get(machine, :label) || Presentation.node_label(machine.name)

  @doc """
  The theme toggle: one quiet glyph, and no server state behind it.

  A sol — a ring with one half filled — because the thing being switched is which side of
  the page the light is on. It is not the attention green and it is not a filled button:
  rule 3 says the primary action is scarce, and choosing a theme is the least urgent
  control on any page it appears on.

  `data-ouro-theme` is the whole contract with `app.js`; nothing here is interpolated, so
  every render of every page produces the same bytes and a patch never touches it.
  """
  def theme_toggle(assigns) do
    ~H"""
    <button
      type="button"
      class="ouro-icon-button"
      data-ouro-theme
      aria-pressed="false"
      aria-label="Switch to the light theme"
      title="Switch to the light theme"
    >
      <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
        <circle cx="8" cy="8" r="5" fill="none" stroke="currentColor" stroke-width="1.6" />
        <path d="M8 3 a5 5 0 0 1 0 10 z" fill="currentColor" />
      </svg>
    </button>
    """
  end

  @doc """
  The needs-you bell: off by default, and off is the only state it can be born in.

  Asking for notification permission is a thing a person does on purpose, so the button
  starts unpressed on every load and enabling it is what asks the browser. A page that
  restored "on" from storage and then found permission revoked would be claiming a channel
  it does not have; `app.js` re-checks the permission every time it would post, and turns
  the button back off rather than silently keeping a promise it cannot keep.

  Static markup, for `theme_toggle/1`'s reason.
  """
  def bell_toggle(assigns) do
    ~H"""
    <button
      type="button"
      class="ouro-icon-button"
      data-ouro-bell
      aria-pressed="false"
      aria-label="Notify me when a session needs me"
      title="Notify me when a session needs me"
    >
      <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
        <path
          d="M4 11 h8 l-1-2 v-2.5 a3 3 0 0 0 -6 0 v2.5 z"
          fill="none"
          stroke="currentColor"
          stroke-width="1.4"
          stroke-linejoin="round"
        />
        <path d="M6.7 12.4 a1.4 1.4 0 0 0 2.6 0" fill="none" stroke="currentColor" stroke-width="1.4" />
      </svg>
    </button>
    """
  end
end
