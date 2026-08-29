defmodule Ouroboros.Web.LiveSocket do
  @moduledoc """
  The LiveView socket, refused at the handshake when there is no session.

  This module exists because of an ordering fact worth writing down: `use
  Phoenix.Endpoint` injects `plug :socket_dispatch` as the *first* plug in the pipeline,
  so a socket path is answered before `Plug.Session` has run and long before
  `Ouroboros.Web.Auth` could refuse it. Moving the `socket` declaration further down the
  endpoint changes nothing — the declaration registers a path, the dispatch position is
  fixed.

  Guarding the mount instead of the connection would have been enough to keep data in:
  the `on_mount` hook in `Ouroboros.Web.Auth` halts a LiveView that has no session, so a
  stranger's socket can join nothing. It would not have been enough to keep a stranger
  from *holding* a socket, which is the thing a token has never been able to stop and a
  handshake refusal can — the same distinction `Ouroboros.Gateway.Listener` draws when it
  caps connections rather than trusting the token to do it.

  So the check is here, on the cookie the browser sends with the upgrade, and it is the
  same session `Ouroboros.Web.Auth` wrote and reads.
  """

  use Phoenix.LiveView.Socket

  alias Ouroboros.Web.Auth

  # `use Phoenix.LiveView.Socket` above already defines the other `Phoenix.Socket`
  # callback, `id/1`, and defines it without `@impl`. Elixir's rule is all-or-nothing per
  # module, so annotating this one would warn about that one. The `@doc` says what the
  # annotation would have.
  @doc "`c:Phoenix.Socket.connect/3`: whether this browser may hold a socket at all."
  def connect(_params, %Phoenix.Socket{} = socket, %{session: session}) when is_map(session) do
    case Map.get(session, Auth.session_key()) do
      id when is_binary(id) -> {:ok, socket}
      _otherwise -> :error
    end
  end

  # No session in `connect_info` at all — an endpoint misconfiguration, or a client that
  # reached this path some way the browser does not. Refused rather than defaulted.
  def connect(_params, _socket, _connect_info), do: :error
end
