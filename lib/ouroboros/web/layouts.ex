defmodule Ouroboros.Web.Layouts do
  @moduledoc """
  The one HTML document every page is rendered into.

  Three files and a font link, all of them named here rather than assembled by a build
  step, because this repo has no JavaScript toolchain and adding one to serve four static
  assets would be a second toolchain to keep green. `phoenix.min.js` and
  `phoenix_live_view.min.js` are copied out of the dependencies verbatim by the
  `web.assets` mix alias; `app.css` and `app.js` are written by hand and read like it.
  """

  use Phoenix.Component

  import Phoenix.Controller, only: [get_csrf_token: 0]

  @doc "The document shell."
  def root(assigns) do
    ~H"""
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="referrer" content="no-referrer" />
        <meta name="csrf-token" content={get_csrf_token()} />
        <title>Ouroboros</title>
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
end
