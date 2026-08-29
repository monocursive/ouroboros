defmodule Ouroboros.Web.Config do
  @moduledoc """
  What the web endpoint is allowed to be, decided before a socket exists.

  This is `Ouroboros.Gateway.Config` for the browser surface, and it is deliberately the
  same shape of module for the same reason: `new!/1` takes a keyword list and either
  returns a struct or raises naming the environment variable an operator has to change.
  Nothing here opens a port, reads application state, or logs, which is what makes the
  refusals testable — a refusal only reachable by booting an endpoint is a refusal nobody
  writes a test for.

  ## Fail closed, and name the variable

    * no token — a browser surface with no credential is an open operator console, so
      `OUROBOROS_WEB_TOKEN_FILE` (or the shared default below) must supply one, and it
      must be long enough to be worth checking.
    * a non-loopback bind without `OUROBOROS_WEB_ALLOW_REMOTE=1` — v1 ships no TLS, so
      leaving the host is a decision that has to be typed out, exactly like
      `OUROBOROS_GATEWAY_ALLOW_REMOTE` and `OUROBOROS_ALLOW_INSECURE_DIST`.
    * no `OUROBOROS_DATA_DIR` — `web.json` is how `ouro web` finds the bound port and
      `web.secret` is where the cookie key lives. An endpoint that binds and publishes
      nowhere is an operator surface nobody can reach.

  `config/runtime.exs` re-checks the loopback and token rules before this module is
  guaranteed loadable, the same duplication the gateway carries and for the same reason:
  a config provider runs early enough that it cannot call into this application.

  ## This module reads no files itself

  It needs two private files — the operator token and the cookie secret — and it reads
  neither of them. Both go through `Ouroboros.Gateway.Config.new!/1`, which is this
  tree's single implementation of "a regular 0600 file owned by this uid, at most 4 KiB,
  read without a TOCTOU window, and created — when creation is allowed at all — by an
  exclusive temporary inode that is chmodded before the bytes are written and renamed
  into place, never over an existing file".

  Copying ninety lines of that discipline into a second module would be two
  implementations of the same security property, and the second one is the one that
  drifts. The cost is that its refusals name the gateway's variable; where that happens
  the message here says so and names the web variable beside it.

  ## One credential, two surfaces

  `:token_file` defaults to `gateway.token` in the data directory — the gateway's own
  file. There is one operator credential per data directory and the web surface inherits
  its authority rather than inventing a second one to rotate. A deployment that wants
  them separate sets `OUROBOROS_WEB_TOKEN_FILE` to a different path.

  Because that default is a path *this system chose* rather than one an operator typed,
  an absent file there is refused as "no token source" rather than as a missing named
  file: there is nothing an operator could have gotten wrong. A path they did type keeps
  the gateway's refusal, which is worth having.

  ## The cookie secret is not a credential

  `web.secret` is generated on first boot unconditionally, which `:token_generate` never
  is for the token. Nobody presents this secret to anything; it is the key that signs the
  session cookie, and the only consequence of creating one is that sessions from before
  it existed do not verify. Keeping it in the data directory rather than deriving it from
  the token is what lets a browser stay signed in across daemon restarts without the
  token ever being re-presented.

  ## Honest limits

  The token authenticates a browser. It is not a sandbox, and an authenticated session at
  `:operate` scope is an operator console with the authority of the data directory it
  serves. Loopback is the boundary that does the real work by default; v1 ships no TLS,
  and the documented remote posture is `tailscale serve` or an operator's own reverse
  proxy in front of the loopback bind.

  `:token` and `:secret_key_base` are redacted under `Inspect`, the way
  `Ouroboros.Gateway.Config` and `Ouroboros.Upgrade.Signing.Key` redact theirs.
  """

  @enforce_keys [
    :bind,
    :port,
    :scope,
    :data_dir,
    :token,
    :secret_file,
    :secret_key_base
  ]
  defstruct @enforce_keys ++
              [token_file: nil, token_generate: false, allow_remote: false, origin: nil]

  @type scope :: :read | :operate

  @type t :: %__MODULE__{
          bind: :inet.ip_address(),
          port: :inet.port_number(),
          scope: scope(),
          data_dir: Path.t(),
          token: binary(),
          token_file: Path.t() | nil,
          token_generate: boolean(),
          secret_file: Path.t(),
          secret_key_base: binary(),
          allow_remote: boolean(),
          origin: [String.t()] | nil
        }

  alias Ouroboros.Gateway.Config, as: GatewayConfig

  @default_bind {127, 0, 0, 1}
  @default_port 0
  @default_token_name "gateway.token"
  @default_secret_name "web.secret"

  # The floor `Ouroboros.Gateway.Config` already holds a token to. Repeated here only so
  # this module's own refusals can name a number rather than say "long enough".
  @min_token_bytes 32

  # `Plug.Crypto` derives the session cookie's keys from `secret_key_base` and refuses
  # anything shorter than this. A generated `web.secret` is 32 random bytes hex-encoded,
  # which is exactly 64 characters, so the file this system writes clears the floor and
  # an operator-supplied one is held to it rather than failing later inside Plug.
  @min_secret_bytes 64

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(config, opts) do
      redacted =
        config
        |> Map.from_struct()
        |> Map.put(:token, :redacted)
        |> Map.put(:secret_key_base, :redacted)

      concat(["#Ouroboros.Web.Config<", to_doc(redacted, opts), ">"])
    end
  end

  @doc """
  Whether this node was configured to serve the web surface at all.

  Absent configuration means no endpoint, which is why `Ouroboros.Application` can ask
  this without a fallback: the operator surface is opt-in and a node that was never told
  to serve one contributes no child.
  """
  @spec enabled?() :: boolean()
  def enabled? do
    :ouroboros
    |> Application.get_env(:web, [])
    |> Keyword.get(:enabled, false)
    |> Kernel.==(true)
  end

  @doc """
  Builds the config from application environment, raising on anything unusable.

  Reads `config :ouroboros, :web` and `config :ouroboros, :data_dir`, both written by
  `config/runtime.exs`.
  """
  @spec load!() :: t()
  def load! do
    :ouroboros
    |> Application.get_env(:web, [])
    |> Keyword.put_new(:data_dir, Application.get_env(:ouroboros, :data_dir))
    |> new!()
  end

  @doc """
  Validates one web configuration.

  Recognized keys: `:port`, `:bind`, `:allow_remote`, `:scope`, `:token`, `:token_file`,
  `:token_generate`, `:secret_file`, `:origin`, `:data_dir`. Unknown keys are ignored so
  a later slice can add one without this raising on an older node.
  """
  @spec new!(keyword()) :: t()
  def new!(opts) when is_list(opts) do
    data_dir = data_dir!(opts)

    %__MODULE__{
      bind: bind!(opts),
      port: port!(opts),
      scope: scope!(opts),
      data_dir: data_dir,
      token: token!(opts, data_dir),
      # The path, never the value. It is published in `web.json` so a browser that was
      # not the spawner can be pointed at the credential it must present; a path is not
      # a secret, the 0600 file it names is.
      token_file: token_file(opts, data_dir),
      token_generate: token_generate?(opts),
      secret_file: secret_file(opts, data_dir),
      secret_key_base: secret_key_base!(opts, data_dir),
      allow_remote: allow_remote?(opts),
      origin: origin!(opts)
    }
  end

  @doc """
  The config the running endpoint was started with.

  The struct is passed to `Ouroboros.Web.Endpoint` as a start option and lives in that
  endpoint's own configuration, so a plug or a LiveView reads the values this node
  actually booted with rather than re-resolving application environment that may have
  been rewritten since.
  """
  @spec for_endpoint(module()) :: t()
  def for_endpoint(endpoint \\ Ouroboros.Web.Endpoint), do: endpoint.config(:ouroboros_web)

  @doc "Renders a bind address the way an operator wrote it."
  @spec bind_to_string(:inet.ip_address()) :: String.t()
  defdelegate bind_to_string(address), to: GatewayConfig

  @doc "Whether an address keeps the endpoint on this host."
  @spec loopback?(:inet.ip_address()) :: boolean()
  defdelegate loopback?(address), to: GatewayConfig

  @doc "The default token path for a data directory: the gateway's own credential."
  @spec default_token_file(Path.t()) :: Path.t()
  def default_token_file(data_dir), do: Path.join(data_dir, @default_token_name)

  @doc "The default cookie-secret path for a data directory."
  @spec default_secret_file(Path.t()) :: Path.t()
  def default_secret_file(data_dir), do: Path.join(data_dir, @default_secret_name)

  defp bind!(opts) do
    address =
      case Keyword.get(opts, :bind, @default_bind) do
        address when is_tuple(address) ->
          address

        text when is_binary(text) ->
          case :inet.parse_address(String.to_charlist(text)) do
            {:ok, address} ->
              address

            {:error, _reason} ->
              raise ArgumentError,
                    "OUROBOROS_WEB_BIND must be a literal IPv4 or IPv6 address, got: #{text}"
          end

        other ->
          raise ArgumentError,
                "OUROBOROS_WEB_BIND must be a literal IPv4 or IPv6 address, got: " <>
                  inspect(other)
      end

    if loopback?(address) or allow_remote?(opts) do
      address
    else
      raise ArgumentError, """
      OUROBOROS_WEB_BIND=#{bind_to_string(address)} puts the web surface on a network \
      interface, and it ships no TLS: the session cookie and every page after it cross \
      the wire in the clear, and the cookie is an operator console.

      Put TLS and an identity in front of the loopback bind instead — `tailscale serve` \
      is the documented posture, an operator's own reverse proxy is the other — or set \
      OUROBOROS_WEB_ALLOW_REMOTE=1 to accept a cleartext operator surface on a trusted \
      network.\
      """
    end
  end

  defp allow_remote?(opts), do: Keyword.get(opts, :allow_remote, false) == true

  defp port!(opts) do
    case Keyword.get(opts, :port, @default_port) do
      port when is_integer(port) and port >= 0 and port <= 65_535 ->
        port

      other ->
        raise ArgumentError,
              "OUROBOROS_WEB_PORT must be an integer between 0 and 65535 " <>
                "(0 reuses the port in web.json when it is free and takes an ephemeral " <>
                "one otherwise, publishing whichever it bound), got: " <> inspect(other)
    end
  end

  defp scope!(opts) do
    case Keyword.get(opts, :scope, :read) do
      scope when scope in [:read, :operate] ->
        scope

      other ->
        raise ArgumentError,
              "OUROBOROS_WEB_SCOPE must be read or operate, got: " <> inspect(other)
    end
  end

  defp data_dir!(opts) do
    case Keyword.get(opts, :data_dir) do
      path when is_binary(path) ->
        case String.trim(path) do
          "" -> raise ArgumentError, data_dir_message()
          trimmed -> trimmed
        end

      _other ->
        raise ArgumentError, data_dir_message()
    end
  end

  defp data_dir_message do
    "OUROBOROS_DATA_DIR must name a directory when the web surface is enabled: the " <>
      "bound port and scope are published to web.json there, the session cookie's key " <>
      "lives in web.secret beside it, and that publication is how `ouro web` finds this " <>
      "node"
  end

  # An explicit origin list is what a proxied or tailnet-served deployment needs: the
  # endpoint would otherwise compute `check_origin` from the address it bound, which is
  # loopback, and refuse the socket the proxy forwards.
  defp origin!(opts) do
    case Keyword.get(opts, :origin) do
      nil -> nil
      origin when is_binary(origin) -> [valid_origin!(origin)]
      origins when is_list(origins) -> Enum.map(origins, &valid_origin!/1)
      other -> raise ArgumentError, origin_message(other)
    end
  end

  defp valid_origin!(origin) when is_binary(origin) do
    case URI.parse(origin) do
      %URI{host: host} when is_binary(host) and host != "" -> origin
      _other -> raise ArgumentError, origin_message(origin)
    end
  end

  defp valid_origin!(other), do: raise(ArgumentError, origin_message(other))

  defp origin_message(other) do
    "OUROBOROS_WEB_ORIGIN must be one or more origins with a host, comma-separated " <>
      "(for example https://daemon.tailnet.ts.net or //daemon.tailnet.ts.net:8443), " <>
      "got: " <> inspect(other)
  end

  defp token_generate?(opts), do: Keyword.get(opts, :token_generate, false) == true

  # Only when a file is what supplied the token. A surface configured with
  # `OUROBOROS_WEB_TOKEN` publishes no path, because there is no file to point at and
  # inventing one would send a browser looking for something that does not exist.
  defp token_file(opts, data_dir) do
    case {Keyword.get(opts, :token_file), Keyword.get(opts, :token)} do
      {path, _token} when is_binary(path) -> path
      {_path, token} when is_binary(token) -> nil
      {_path, _token} -> default_token_file(data_dir)
    end
  end

  defp token!(opts, data_dir) do
    case {Keyword.get(opts, :token_file), Keyword.get(opts, :token)} do
      {path, _token} when is_binary(path) ->
        read_private_file!(path, token_generate?(opts), :token)

      {_path, token} when is_binary(token) ->
        literal_token!(String.trim(token))

      {_path, _token} ->
        defaulted_token!(data_dir, token_generate?(opts))
    end
  end

  # Nobody named this path, so an absent file here is not a mistake an operator made and
  # the refusal must not pretend otherwise. It says what it means: there is no credential
  # to check a browser against. `:token_generate` — set only by the defaulted
  # single-machine posture in `config/runtime.exs` — is the one case where a first boot
  # creates it instead, and it is the gateway's own file being created, by the gateway's
  # own writer, so the two surfaces still share exactly one credential.
  defp defaulted_token!(data_dir, generate?) do
    path = default_token_file(data_dir)

    cond do
      generate? ->
        read_private_file!(path, true, :token)

      File.regular?(path) ->
        read_private_file!(path, false, :token)

      true ->
        raise ArgumentError, """
        the web surface is enabled but no token source is configured, and the credential \
        it shares with the gateway by default is not at #{path}.

        Set OUROBOROS_WEB_TOKEN_FILE to a 0600 file holding at least #{@min_token_bytes} \
        bytes, or OUROBOROS_WEB_TOKEN for a dev loop (the environment of a process is \
        readable by every process the same user runs, which is why the file is \
        preferred). Enabling the gateway on this node writes that default file, and the \
        two surfaces are then one operator credential.\
        """
    end
  end

  defp literal_token!(token) when byte_size(token) >= @min_token_bytes, do: token

  defp literal_token!(token) do
    raise ArgumentError,
          "OUROBOROS_WEB_TOKEN is #{byte_size(token)} bytes; at least #{@min_token_bytes} " <>
            "are required. Set it to a value worth checking, or prefer " <>
            "OUROBOROS_WEB_TOKEN_FILE"
  end

  defp secret_file(opts, data_dir) do
    case Keyword.get(opts, :secret_file) do
      path when is_binary(path) ->
        case String.trim(path) do
          "" -> raise ArgumentError, "OUROBOROS_WEB_SECRET_FILE must not be empty"
          trimmed -> trimmed
        end

      nil ->
        default_secret_file(data_dir)

      other ->
        raise ArgumentError,
              "OUROBOROS_WEB_SECRET_FILE must be a path, got: " <> inspect(other)
    end
  end

  # Always generate-if-absent, which the token never is. See the moduledoc: this is a
  # cookie key nobody presents to anything, so a first boot creating one costs a signed-in
  # browser nothing it had, while refusing to boot over it would cost an operator a
  # daemon. It is still never written over an existing file.
  defp secret_key_base!(opts, data_dir) do
    path = secret_file(opts, data_dir)
    secret = read_private_file!(path, true, :secret)

    if byte_size(secret) < @min_secret_bytes do
      raise ArgumentError,
            "#{path} holds #{byte_size(secret)} bytes; the session cookie's key must be " <>
              "at least #{@min_secret_bytes}. Remove the file to have this node write a " <>
              "fresh one (every browser then signs in again), or point " <>
              "OUROBOROS_WEB_SECRET_FILE at a longer secret"
    end

    secret
  end

  # The one place this module touches a private file, and it does not: it hands the path
  # to the gateway's reader, which is the tree's only implementation of the 0600 /
  # same-uid / regular / bounded / TOCTOU-checked read and of the never-overwriting
  # create. Every other field of the struct built here is a value this call cannot refuse
  # over, so the only refusals it can raise are about the file — and those are re-raised
  # with the web variable named beside the gateway's.
  defp read_private_file!(path, generate?, kind) do
    GatewayConfig.new!(
      bind: @default_bind,
      port: 0,
      scope: :read,
      data_dir: Path.dirname(path),
      token_file: path,
      token_generate: generate?
    ).token
  rescue
    error in [ArgumentError, File.Error] ->
      reraise ArgumentError,
              [message: private_file_message(kind, path, error)],
              __STACKTRACE__
  end

  defp private_file_message(:token, path, error) do
    """
    Ouroboros.Web could not read its operator token from #{path}:

    #{Exception.message(error)}

    That file is read by Ouroboros.Gateway.Config, this tree's only reader of a private \
    0600 file, which is why the refusal above names OUROBOROS_GATEWAY_TOKEN_FILE. \
    OUROBOROS_WEB_TOKEN_FILE is what points the web surface at a different path; unset, \
    it shares the gateway's credential.\
    """
  end

  defp private_file_message(:secret, path, error) do
    """
    Ouroboros.Web could not read or create the session cookie's key at #{path}:

    #{Exception.message(error)}

    That file is written and read by Ouroboros.Gateway.Config, this tree's only reader \
    and writer of a private 0600 file, which is why the refusal above names \
    OUROBOROS_GATEWAY_TOKEN_FILE. OUROBOROS_WEB_SECRET_FILE is what names this path. It \
    holds no credential anyone presents — deleting it costs every signed-in browser its \
    session and nothing else.\
    """
  end
end
