defmodule Ouroboros.Web.Endpoint do
  @moduledoc """
  The HTTP surface: a token-authenticated, loopback-default Phoenix endpoint on Bandit.

  Everything runtime about this endpoint — the address, the port, the cookie key, the
  origin policy — comes from one `Ouroboros.Web.Config` built before any socket exists
  and handed in as a start option by `Ouroboros.Web`. Application environment holds only
  the two facts that are genuinely compile-time (the adapter and the error renderer), so
  there is one place a refusal can come from and one place a value can be read back.

  ## The port is sticky

  `OUROBOROS_WEB_PORT` defaults to 0, but 0 does not mean "a different port every boot".
  A bookmark and a session cookie are both origin-scoped, so a daemon that moves its port
  on every restart signs every browser out and breaks every bookmark for no reason. The
  endpoint therefore reads the port it published last time from `web.json` and tries that
  one first, falling back to an ephemeral port when it is taken.

  Two things guard the fallback, because they fail differently:

    * a probe before binding, which catches the ordinary case — another daemon, or
      another data directory's endpoint, already owns that number;
    * one retry at port 0 when the bind itself comes back `:eaddrinuse`, which catches the
      race the probe cannot close: the window between closing the probe socket and
      Bandit opening the real one.

  A pinned `OUROBOROS_WEB_PORT` never does either. An operator who typed a number wants
  that number, and silently serving a different one would be worse than refusing.

  ## Origin

  `check_origin` is never `false`. Unset, it is computed from the address and port this
  endpoint actually bound — which is why it is an MFA rather than a list: at
  configuration time the port may still be 0. `OUROBOROS_WEB_ORIGIN` replaces it with an
  explicit list, which is what a `tailscale serve` or reverse-proxy deployment needs,
  since the browser's origin is then the proxy's and not the loopback socket's.

  ## Body limits

  The gateway bounds a frame; this bounds a request. `Plug.Parsers` is urlencoded-only —
  there is no multipart parser, so this endpoint has no upload handling to secure — and
  its length cap is the ceiling on a body reaching a controller. Code reloading and
  debug error pages are off explicitly rather than by default, because an operator
  surface is the wrong place to discover that a default changed.
  """

  use Phoenix.Endpoint, otp_app: :ouroboros

  require Logger

  alias Ouroboros.Web.Config

  @publication_name "web.json"

  # The most a request body may be before `Plug.Parsers` refuses it. W0 has no request
  # bodies at all; this is the ceiling the composer slice will send a turn under, and a
  # number chosen now is a number an operator can see rather than a default that moves.
  @max_body_bytes 65_536

  # A salt is not a secret — the entropy is `secret_key_base` — so it is a literal, the
  # way `mix phx.new` emits one. Changing it invalidates every session cookie.
  @session_options [
    store: :cookie,
    key: "_ouroboros_web",
    signing_salt: "ouroboros.web.session/1",
    same_site: "Lax",
    http_only: true,
    # The endpoint speaks cleartext HTTP on loopback, so `secure` would make the browser
    # refuse to send the cookie back to us. A TLS terminator in front of this (the
    # documented remote posture) still works: it is the browser's view of the scheme that
    # governs, and behind a proxy that view is https regardless of this flag.
    secure: false,
    # Long enough that an operator is not re-pasting a token every morning, short enough
    # that a forgotten browser is not a permanent console.
    max_age: 14 * 24 * 60 * 60
  ]

  @doc "The session options both `Plug.Session` and the LiveView socket are configured with."
  @spec session_options() :: keyword()
  def session_options, do: @session_options

  # `Referrer-Policy` before anything else can answer, so a static file and the
  # unauthenticated page carry it too. The bootstrap URL has the token in its query
  # string; nothing this surface links to may carry that away with it.
  plug :no_referrer

  # `Ouroboros.Web.LiveSocket` rather than `Phoenix.LiveView.Socket` because
  # `plug :socket_dispatch` is injected above every plug below, so the socket is answered
  # before `Ouroboros.Web.Auth` sees it. That module carries the session check; its
  # moduledoc explains why the position of this declaration cannot fix it.
  #
  # Long polling is off: it is a second transport with a second set of security
  # properties, and nothing here needs a fallback for a browser that cannot open a
  # WebSocket to its own loopback address.
  socket "/live", Ouroboros.Web.LiveSocket,
    websocket: [connect_info: [session: @session_options]],
    longpoll: false

  # Public on purpose, and only these four names. Two are the prebuilt bundles that ship
  # inside `phoenix` and `phoenix_live_view`; the other two are hand-written. None of
  # them says anything a stranger does not already learn from the unauthenticated page,
  # and serving them before the token check is what keeps that page from rendering naked.
  plug Plug.Static,
    at: "/web",
    from: {:ouroboros, "priv/static/web"},
    gzip: false,
    only: ~w(app.css app.js phoenix.min.js phoenix_live_view.min.js)

  plug Plug.Head
  plug Plug.Session, @session_options
  plug Ouroboros.Web.Auth

  # Below the token check on purpose, which is not where a generated endpoint puts them.
  # Reading a request body is work an unauthenticated peer would otherwise get for free,
  # and nothing above this line needs parsed parameters — `Ouroboros.Web.Auth` fetches
  # the query string itself, because the one thing it reads arrives in a URL.
  #
  # Urlencoded only: with no multipart parser there is no upload handling on this surface
  # to secure, and `:length` is the ceiling on a body that reaches a controller at all.
  # `Plug.MethodOverride` reads a parsed parameter, so it follows rather than leads.
  plug Plug.Parsers,
    parsers: [:urlencoded],
    pass: [],
    length: @max_body_bytes

  plug Plug.MethodOverride

  plug Ouroboros.Web.Router

  defp no_referrer(conn, _opts) do
    Plug.Conn.put_resp_header(conn, "referrer-policy", "no-referrer")
  end

  @doc """
  The start options one `Ouroboros.Web.Config` resolves to.

  `:server` is false in tests that dispatch conns without wanting a bound socket; every
  other value is a fact about this node that a refusal has already been raised over.
  """
  @spec options(Config.t(), keyword()) :: keyword()
  def options(%Config{} = config, opts \\ []) do
    server? = Keyword.get(opts, :server, true)
    port = Keyword.get(opts, :port, config.port)

    [
      # The struct the plugs and LiveViews read back, including the token the auth
      # exchange compares against. It never reaches the shared configuration table that
      # `secret_key_base` is dropped from, so treat both the same way: this endpoint's
      # configuration is inside the daemon's own trust domain and nowhere else.
      ouroboros_web: config,
      server: server?,
      # Phoenix's own "Access ... at" line renders the *configured* url, which with a
      # sticky or ephemeral port is `:0` — a URL nothing is listening on. The line that
      # replaces it is `Ouroboros.Web.Publication`'s, which prints the port that was
      # actually bound because it is written after the bind rather than before it.
      log_access_url: false,
      secret_key_base: config.secret_key_base,
      check_origin: check_origin(config),
      url: [host: Config.bind_to_string(config.bind), path: "/"],
      http: if(server?, do: [ip: config.bind, port: port], else: false),
      https: false,
      code_reloader: false,
      debug_errors: false,
      live_view: [signing_salt: signing_salt(config)]
    ]

    # `:adapter` and `:render_errors` are deliberately absent: they are compile-time and
    # live in `config/config.exs`, which Phoenix merges *over* these options. Naming them
    # in both places would be two sources for one value, and the losing one would be this.
  end

  @doc """
  Starts the endpoint on the sticky port, retrying once at 0 if that port was taken.

  This is the child's start function rather than a plain `{Endpoint, opts}` child spec
  because the fallback needs to see the bind fail. A supervisor cannot retry a child with
  different arguments; a start function can.
  """
  @spec start_endpoint(module(), Config.t(), keyword()) :: Supervisor.on_start()
  def start_endpoint(endpoint, %Config{} = config, opts \\ []) do
    port = sticky_port(config)

    case endpoint.start_link(options(config, Keyword.put(opts, :port, port))) do
      {:error, reason} = error ->
        if port != 0 and address_in_use?(reason) do
          Logger.warning(
            "web port #{Config.bind_to_string(config.bind)}:#{port} was taken between the " <>
              "probe and the bind; taking an ephemeral port instead"
          )

          endpoint.start_link(options(config, Keyword.put(opts, :port, 0)))
        else
          error
        end

      other ->
        other
    end
  end

  @doc """
  The port to try first: the one published last time, when it is free.

  A pinned `OUROBOROS_WEB_PORT` is returned unchanged — an operator who typed a number
  gets that number or a boot failure, never a surprise. The probe below is advisory: it
  answers "is this port free right now", and `start_endpoint/3` owns what happens when
  that answer expires.
  """
  @spec sticky_port(Config.t()) :: :inet.port_number()
  def sticky_port(%Config{port: port}) when port != 0, do: port

  def sticky_port(%Config{} = config) do
    with {:ok, published} <- published_port(config),
         true <- bindable?(config.bind, published) do
      published
    else
      _otherwise -> 0
    end
  end

  @doc "The path this endpoint publishes its bound port to."
  @spec publication_path(Path.t()) :: Path.t()
  def publication_path(data_dir), do: Path.join(data_dir, @publication_name)

  @doc """
  Whether an origin the browser presented is one this endpoint serves.

  Named by the `check_origin` MFA rather than expanded into a list at configuration time,
  because until the socket is bound there may be no port to compare against.
  """
  @spec origin_allowed?(URI.t()) :: boolean()
  def origin_allowed?(%URI{} = uri) do
    case bound_address() do
      {:ok, {address, port}} ->
        uri.scheme == "http" and uri.port == port and
          uri.host in allowed_hosts(address)

      :error ->
        false
    end
  end

  @doc "The address and port this endpoint actually bound, once it is serving."
  @spec bound_address() :: {:ok, {:inet.ip_address(), :inet.port_number()}} | :error
  def bound_address do
    case server_info(:http) do
      {:ok, {address, port}} when is_tuple(address) and is_integer(port) -> {:ok, {address, port}}
      _other -> :error
    end
  rescue
    # `server_info/1` reaches into the adapter, which is not there when `server: false`.
    # An endpoint that is not serving has no origin to allow.
    _error -> :error
  end

  defp check_origin(%Config{origin: origins}) when is_list(origins), do: origins
  defp check_origin(%Config{}), do: {__MODULE__, :origin_allowed?, []}

  # A browser reaching a loopback endpoint types `localhost` about as often as it types
  # `127.0.0.1`, and both resolve to the socket this endpoint bound. A non-loopback bind
  # gets only the literal address it was given — anything else would be guessing at a
  # name this node has no way to check.
  defp allowed_hosts(address) do
    literal = Config.bind_to_string(address)

    if Config.loopback?(address) do
      [literal, "localhost", "127.0.0.1", "[::1]", "::1"]
    else
      [literal]
    end
  end

  # Deterministic in the cookie key, so the salt survives restarts exactly as the key
  # does, and one-way, so the configuration table never carries a value the secret can be
  # recovered from.
  defp signing_salt(%Config{secret_key_base: secret}) do
    :sha256
    |> :crypto.hash(["ouroboros.web.live_view/1", secret])
    |> Base.url_encode64(padding: false)
    |> binary_part(0, 20)
  end

  defp published_port(%Config{} = config) do
    with {:ok, body} <- File.read(publication_path(config.data_dir)),
         {:ok, %{"port" => port}} when is_integer(port) and port > 0 <- JSON.decode(body) do
      {:ok, port}
    else
      _otherwise -> :error
    end
  end

  # Advisory only: the socket is closed again immediately, so a racing binder can still
  # win. `reuseaddr` matches what Bandit will ask for, so a port held only by a lingering
  # TIME_WAIT socket answers "free" here exactly as it will there.
  defp bindable?(address, port) do
    case :gen_tcp.listen(port, [:binary, ip: address, active: false, reuseaddr: true]) do
      {:ok, socket} ->
        :gen_tcp.close(socket)
        true

      {:error, _reason} ->
        false
    end
  end

  defp address_in_use?(:eaddrinuse), do: true
  defp address_in_use?(term) when is_tuple(term), do: term |> Tuple.to_list() |> address_in_use?()
  defp address_in_use?(term) when is_list(term), do: Enum.any?(term, &address_in_use?/1)
  defp address_in_use?(_term), do: false
end
