defmodule Ouroboros.Web.Router do
  @moduledoc """
  Every route the web surface serves.

  The router never sees an unauthenticated request: `Ouroboros.Web.Auth` runs in the
  endpoint, above this, so a route added here is authenticated by construction rather
  than by remembering to pipe it through something. `/auth` is not a route for the same
  reason — it is the door, and the door is not inside the house.

  `/` is the deck. `/s/:plane/:id` is the deck with one session open, and it is a
  `live_patch` target rather than a separate page so that opening a session keeps the
  socket, the subscription machinery, and the rail's scroll position — a full navigation
  would tear down a live transcript to draw the same list again.

  `/status` is W0's page, kept rather than folded in: it is one call deep and stands on
  nothing, which makes it the page an operator loads when the deck itself is what looks
  broken.
  """

  use Phoenix.Router, helpers: false

  import Phoenix.Controller
  import Phoenix.LiveView.Router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :put_root_layout, html: {Ouroboros.Web.Layouts, :root}
    plug :protect_from_forgery
    # `put_secure_browser_headers/2` would otherwise write its own, more permissive
    # `referrer-policy` over the one the endpoint set. The token only ever appears in the
    # `/auth` URL, and no page may carry it into a `Referer`.
    plug :put_secure_browser_headers, %{"referrer-policy" => "no-referrer"}
  end

  scope "/", Ouroboros.Web do
    pipe_through :browser

    live_session :authenticated, on_mount: {Ouroboros.Web.Auth, :ensure_session} do
      live "/", Live.DeckLive, :index
      live "/s/:plane/:id", Live.DeckLive, :session
      live "/status", StatusLive, :index
    end

    # Not a LiveView: it answers bytes, and an `<img>` is a plain GET. It is inside the
    # authenticated scope like everything else, so the cookie that opened the deck is the
    # only thing that opens a screenshot.
    get "/artifact/:plane/:id/:sha", ArtifactController, :show
  end
end
