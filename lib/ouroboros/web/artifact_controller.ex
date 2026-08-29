defmodule Ouroboros.Web.ArtifactController do
  @moduledoc """
  Computer-use screenshots, served as bytes to the one browser that is already signed in.

  The transcript's image cells name a picture by the SHA-256 of its content and nothing
  else — that digest is the only key `computer_use.artifact` accepts, and the projection
  is filesystem-free by contract, so a cell never holds a path. This controller is the
  route between that digest and an `<img>`.

  ## Behind the same door as everything else

  `Ouroboros.Web.Auth` runs in the endpoint, above the router, so a request here has
  already presented the session cookie. There is no second credential, no signed URL, and
  no token in the image's address — a URL with a credential in it would be a URL a browser
  puts in history and a page can leak in a `Referer`.

  ## The digest is checked here as well as upstream

  `Ouroboros.Provider.Native.Desktop.artifact/2` refuses anything that is not 64 lowercase
  hex characters, which is what makes a path traversal impossible. This checks it again
  before making the call, for the reason the gateway's own exposure refusal is written
  twice: the property is worth more than the line it costs, and the two checks fail
  independently. A malformed sha is answered exactly as a missing one is.

  ## Caching is safe because the address *is* the content

  A sha-addressed URL can never point at different bytes, so the response is
  `private, max-age=31536000, immutable` — fetched once per browser, forever. `private`
  because a shared cache has no business holding an operator's screen.

  ## Why the owner node is resolved and not accepted

  The path names a plane and a session, not a machine. A screenshot staged on another
  fleet node has to be fetched from that node, so the owner is looked up in the session
  list rather than read out of the URL: an `:erpc` target a browser chose is a hop a
  stranger with a cookie gets to pick. The lookup costs one list call, once per image per
  browser, which the immutable cache header makes it.

  ## Refusals are all one answer

  Missing, oversized, unknown digest, a node that cannot be reached, a scope that may not
  ask: 404 with a plain sentence. A surface that distinguished them would be telling a
  reader which half of their guess was right about a machine they cannot see.
  """

  use Phoenix.Controller, formats: []

  import Plug.Conn

  alias Ouroboros.Web.Call
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Live.Rail

  require Logger

  @sha ~r/\A[a-f0-9]{64}\z/
  @method "computer_use.artifact"
  @planes %{"interactive" => :interactive, "coding" => :coding}

  @doc """
  Serves one staged screenshot by content hash.

  `GET /artifact/:plane/:id/:sha`.
  """
  def show(conn, %{"plane" => plane, "id" => id, "sha" => sha}) do
    with {:ok, plane} <- plane(plane),
         :ok <- digest(sha),
         scope = Config.for_endpoint(conn.private.phoenix_endpoint).scope,
         {:ok, artifact} <- fetch(conn, scope, plane, id, sha) do
      send_artifact(conn, artifact)
    else
      _refused -> missing(conn)
    end
  end

  def show(conn, _params), do: missing(conn)

  # ------------------------------------------------------------------------------------

  defp plane(name) do
    case Map.fetch(@planes, name) do
      {:ok, plane} -> {:ok, plane}
      :error -> :error
    end
  end

  defp digest(sha) when is_binary(sha) do
    if Regex.match?(@sha, sha), do: :ok, else: :error
  end

  defp digest(_sha), do: :error

  defp fetch(conn, scope, plane, id, sha) do
    params =
      case owner(conn, scope, plane, id) do
        owner when is_atom(owner) and not is_nil(owner) ->
          %{"sha256" => sha, "node" => Atom.to_string(owner)}

        # The list did not name an owner — a session this node has never seen, or a list
        # that failed. Ask locally rather than not at all: the artifact is very often
        # here, and a wrong guess is the same 404 as no guess.
        _unknown ->
          %{"sha256" => sha}
      end

    case Call.call(scope, @method, params, session: session(conn)) do
      {:ok, %{bytes: _bytes} = artifact} -> {:ok, artifact}
      _refused -> :error
    end
  end

  # The owner node of one session, from the plane's own list. `nil` where the list refused
  # or does not carry it.
  defp owner(conn, scope, plane, id) do
    method = if plane == :interactive, do: "interactive.list", else: "coding.list"

    case Call.call(scope, method, %{}, session: session(conn)) do
      {:ok, sessions} when is_list(sessions) ->
        Enum.find_value(sessions, fn session ->
          row = row(plane, session)
          if row.id == id, do: row.node
        end)

      _refused ->
        nil
    end
  end

  defp row(:interactive, session), do: Rail.from_interactive(session)
  defp row(:coding, session), do: Rail.from_coding(session)

  defp send_artifact(conn, artifact) do
    case Base.decode64(Map.get(artifact, :bytes, "")) do
      {:ok, bytes} ->
        conn
        |> put_resp_content_type(media_type(artifact))
        |> put_resp_header("cache-control", "private, max-age=31536000, immutable")
        # Bytes a model chose, served from the operator's own origin. Nothing on this
        # surface should ever hand a browser a chance to sniff them into a document.
        |> put_resp_header("x-content-type-options", "nosniff")
        |> send_resp(:ok, bytes)

      :error ->
        Logger.error("web artifact answered bytes that are not base64")
        missing(conn)
    end
  end

  # Only the two the staging directory can hold. Never the string the payload carried: a
  # content type is what decides how a browser reads the bytes, and this one is the one
  # field of a provider's answer that must not be taken on trust.
  defp media_type(artifact) do
    case Map.get(artifact, :media_type) do
      "image/png" -> "image/png"
      "image/jpeg" -> "image/jpeg"
      _unknown -> "application/octet-stream"
    end
  end

  defp missing(conn) do
    conn
    |> put_resp_content_type("text/plain")
    |> put_resp_header("cache-control", "no-store")
    |> send_resp(:not_found, "no such artifact\n")
  end

  defp session(conn), do: conn.private[:ouroboros_web_session]
end
