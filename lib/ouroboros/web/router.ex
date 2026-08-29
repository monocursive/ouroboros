defmodule Ouroboros.Web.Router do
  @moduledoc """
  Every route the web surface serves, which in W0 is one.

  The router never sees an unauthenticated request: `Ouroboros.Web.Auth` runs in the
  endpoint, above this, so a route added here is authenticated by construction rather
  than by remembering to pipe it through something. `/auth` is not a route for the same
  reason — it is the door, and the door is not inside the house.
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
      live "/", StatusLive, :index
    end
  end
end
