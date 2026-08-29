defmodule Ouroboros.Web.Auth do
  @moduledoc """
  Token in, cookie out, and one page for everything that is neither.

  A browser cannot hold a token the way `ouro` does, and a token in a URL survives in the
  address bar, in history, and in every `Referer` the page would send. So the token is
  spent exactly once:

      GET /auth?token=…  →  signed HttpOnly SameSite=Lax session cookie  →  302 to /

  Nothing after that carries the credential, and `Referrer-Policy: no-referrer` on every
  response from this endpoint keeps the one URL that did from leaking sideways.

  ## One refusal

  Every failure renders the same page with the same status: no token, a wrong token, a
  token of the wrong length, a missing cookie, a cookie signed by a secret this node no
  longer has. A surface that distinguished them would be telling a stranger which half of
  their guess was right, and there is nothing on the other side of this door worth
  building a probe against it for.

  The page names `ouro web`, because the operator who lands on it is nearly always the
  one who bookmarked `/` and does not have a fresh URL. It is deliberately the only thing
  an unauthenticated request can learn.

  ## The comparison

  `:crypto.hash_equals/2` over SHA-256 digests, which is what
  `Ouroboros.Gateway.Conn.authenticate/2` does. Hashing first is what makes the
  comparison independent of the presented token's length; `hash_equals/2` is what makes
  it independent of where the first differing byte is.
  """

  @behaviour Plug

  import Plug.Conn

  alias Ouroboros.Web.Config

  @session_key "ouroboros_web_session"
  @auth_path ["auth"]

  @doc false
  @impl Plug
  def init(opts) do
    %{
      endpoint: Keyword.get(opts, :endpoint, Ouroboros.Web.Endpoint),
      config: Keyword.get(opts, :config)
    }
  end

  @doc false
  @impl Plug
  def call(%Plug.Conn{} = conn, opts) do
    config = opts[:config] || Config.for_endpoint(opts[:endpoint])

    case {conn.method, conn.path_info} do
      {"GET", @auth_path} -> exchange(conn, config)
      _other -> require_session(conn)
    end
  end

  @doc """
  Whether a presented token is the one this endpoint was started with.

  Public because it is the property worth testing directly: equal tokens match, and a
  prefix, a suffix, and a same-length near-miss are all refused the same way.
  """
  @spec token_matches?(term(), binary()) :: boolean()
  def token_matches?(presented, expected) when is_binary(presented) and is_binary(expected) do
    :crypto.hash_equals(
      :crypto.hash(:sha256, presented),
      :crypto.hash(:sha256, expected)
    )
  end

  def token_matches?(_presented, _expected), do: false

  @doc """
  The session key the authenticated id is stored under.

  Named rather than inlined because the LiveView socket reads the same session the plug
  wrote, and those two must not be able to disagree about the key.
  """
  @spec session_key() :: String.t()
  def session_key, do: @session_key

  @doc """
  The `on_mount` hook every LiveView in this surface runs.

  The LiveView socket connects outside the plug pipeline, so the cookie check has to
  happen again here. It reads the session the plug wrote; a socket without it is
  redirected to `/`, where the plug renders the one unauthenticated page.
  """
  def on_mount(:ensure_session, _params, session, socket) do
    case session do
      %{@session_key => id} when is_binary(id) ->
        {:cont, Phoenix.Component.assign(socket, :web_session, id)}

      _otherwise ->
        {:halt, Phoenix.LiveView.redirect(socket, to: "/")}
    end
  end

  defp exchange(conn, config) do
    conn = fetch_query_params(conn)

    if token_matches?(conn.query_params["token"], config.token) do
      conn
      |> fetch_session()
      # A fresh cookie for a fresh exchange: re-presenting the token must never adopt a
      # session id somebody else already knows.
      |> configure_session(renew: true)
      |> put_session(@session_key, new_session_id())
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("location", "/")
      |> send_resp(:found, "")
      |> halt()
    else
      refuse(conn)
    end
  end

  defp require_session(conn) do
    conn = fetch_session(conn)

    case get_session(conn, @session_key) do
      id when is_binary(id) -> put_private(conn, :ouroboros_web_session, id)
      _otherwise -> refuse(conn)
    end
  end

  # Writes nothing to the session, so no `Set-Cookie` is sent: a refusal must not hand a
  # stranger a cookie, not even an empty one they could watch for a change in.
  defp refuse(conn) do
    conn
    |> put_resp_content_type("text/html")
    |> put_resp_header("cache-control", "no-store")
    |> send_resp(:unauthorized, unauthenticated_page())
    |> halt()
  end

  defp new_session_id, do: 16 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

  # Self-contained on purpose. It links the stylesheet for the sake of a browser that has
  # it, and reads correctly without one, because the page a stranger reaches should not
  # depend on anything the endpoint might not be serving.
  defp unauthenticated_page do
    """
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="referrer" content="no-referrer" />
        <title>Ouroboros</title>
        <link rel="stylesheet" href="/web/app.css" />
      </head>
      <body class="ouro-plain">
        <main class="ouro-gate">
          <h1>Ouroboros</h1>
          <p>This surface needs the operator token for its data directory.</p>
          <p>Run <code>ouro web</code> on the machine running this daemon. It reads the
          published <code>web.json</code>, builds the one-time link, and opens it.</p>
        </main>
      </body>
    </html>
    """
  end
end
