defmodule Ouroboros.Web.Layouts do
  @moduledoc """
  The one HTML document every page is rendered into, and the two chrome controls that sit
  in every page's top row.

  Three files and a font link, all of them named here rather than assembled by a build
  step, because this repo has no JavaScript toolchain and adding one to serve four static
  assets would be a second toolchain to keep green. `phoenix.min.js` and
  `phoenix_live_view.min.js` are copied out of the dependencies verbatim by the
  `web.assets` mix alias; `app.css` and `app.js` are written by hand and read like it.

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
    assigns = assign(assigns, :theme_script_tag, theme_script_tag())

    ~H"""
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="referrer" content="no-referrer" />
        <meta name="csrf-token" content={get_csrf_token()} />
        <title>Ouroboros</title>
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
