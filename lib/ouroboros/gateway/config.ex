defmodule Ouroboros.Gateway.Config do
  @moduledoc """
  What the gateway listener is allowed to be, decided before a socket exists.

  This module is the whole of the gateway's admission policy and it is deliberately
  separable from every process that uses it: `new!/1` takes a keyword list and either
  returns a struct or raises naming the environment variable an operator has to change.
  Nothing here opens a port, reads application state, or logs. That is what makes the
  refusals testable, and a refusal that is only reachable by booting a listener is a
  refusal nobody writes a test for.

  ## Fail closed, and name the variable

  Every raise here describes a configuration an operator plausibly typed, so it names
  the variable rather than the struct field:

    * no token — a listener with no credential is an open shell, so
      `OUROBOROS_GATEWAY_TOKEN_FILE` or `OUROBOROS_GATEWAY_TOKEN` must supply one, and it
      must be long enough to be worth checking.
    * a non-loopback bind without `OUROBOROS_GATEWAY_ALLOW_REMOTE=1` — the protocol is
      cleartext, so leaving the host is a decision that has to be typed out, exactly like
      `OUROBOROS_ALLOW_INSECURE_DIST` for distribution.
    * no `OUROBOROS_DATA_DIR` — `gateway.json` is how a client finds the bound port. A
      gateway that binds and publishes nowhere is an operator surface nobody can reach.

  `config/runtime.exs` re-checks the loopback and token rules before this module is
  guaranteed loadable. That is duplication on purpose: a config provider runs early
  enough that it cannot call into this application, and the check that must be able to
  refuse the boot has to stand on `System` alone.

  ## Honest limits

  The token authenticates a transport. It is not a sandbox and this struct does not
  pretend otherwise — an authenticated connection at `:operate` scope is an operator
  console. Loopback is the boundary that does the real work by default.

  `:token_file` is preferred over `:token` for a reason worth stating: the file path is
  what lands in application environment, and the secret itself only ever exists inside
  this struct, which redacts itself under `Inspect` the way
  `Ouroboros.Upgrade.Signing.Key` does. A token passed as `OUROBOROS_GATEWAY_TOKEN` is
  visible to every same-user process on the host and stays in application environment for
  the life of the node.
  """

  @enforce_keys [:bind, :port, :token, :scope, :max_frame, :queue_limit, :data_dir]
  defstruct @enforce_keys ++ [allow_remote: false, allow_shutdown: false]

  @type scope :: :read | :operate

  @type t :: %__MODULE__{
          bind: :inet.ip_address(),
          port: :inet.port_number(),
          token: binary(),
          scope: scope(),
          max_frame: pos_integer(),
          queue_limit: pos_integer(),
          data_dir: Path.t(),
          allow_remote: boolean(),
          allow_shutdown: boolean()
        }

  # A token shorter than this is not a credential, it is a speed bump. The spawner writes
  # 32 random bytes as hex; a human typing a token into a shell should be held to the
  # same floor rather than to whatever they had patience for.
  @min_token_bytes 32

  # Below this a `hello` frame itself would be chopped, and every connection would fail
  # with an oversized-frame error that names the wrong cause.
  @min_max_frame 1_024

  @default_port 0
  @default_bind {127, 0, 0, 1}
  @default_max_frame 1_048_576
  @default_queue_limit 1_000

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(config, opts) do
      redacted =
        config
        |> Map.from_struct()
        |> Map.put(:token, :redacted)

      concat(["#Ouroboros.Gateway.Config<", to_doc(redacted, opts), ">"])
    end
  end

  @doc """
  Whether this node was configured to run a gateway at all.

  Absent configuration means no gateway, which is why `Ouroboros.Application` can ask
  this without a fallback: the operator surface is opt-in and a node that was never told
  to serve one contributes no child.
  """
  @spec enabled?() :: boolean()
  def enabled? do
    :ouroboros
    |> Application.get_env(:gateway, [])
    |> Keyword.get(:enabled, false)
    |> Kernel.==(true)
  end

  @doc """
  Builds the config from application environment, raising on anything unusable.

  Reads `config :ouroboros, :gateway` and `config :ouroboros, :data_dir`, both written by
  `config/runtime.exs`.
  """
  @spec load!() :: t()
  def load! do
    :ouroboros
    |> Application.get_env(:gateway, [])
    |> Keyword.put_new(:data_dir, Application.get_env(:ouroboros, :data_dir))
    |> new!()
  end

  @doc """
  Validates one gateway configuration.

  Recognized keys: `:port`, `:bind`, `:token`, `:token_file`, `:allow_remote`, `:scope`,
  `:allow_shutdown`, `:max_frame`, `:queue_limit`, `:data_dir`. Unknown keys are ignored
  so a later slice can add one without this raising on an older node.
  """
  @spec new!(keyword()) :: t()
  def new!(opts) when is_list(opts) do
    bind = bind!(opts)

    %__MODULE__{
      bind: bind,
      port: port!(opts),
      token: token!(opts),
      scope: scope!(opts),
      max_frame: max_frame!(opts),
      queue_limit: queue_limit!(opts),
      data_dir: data_dir!(opts),
      allow_remote: allow_remote?(opts),
      allow_shutdown: Keyword.get(opts, :allow_shutdown, false) == true
    }
  end

  @doc "Renders a bind address the way an operator wrote it."
  @spec bind_to_string(:inet.ip_address()) :: String.t()
  def bind_to_string(address), do: address |> :inet.ntoa() |> List.to_string()

  @doc "Whether an address keeps the listener on this host."
  @spec loopback?(:inet.ip_address()) :: boolean()
  def loopback?({127, _, _, _}), do: true
  def loopback?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  def loopback?(_address), do: false

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
                    "OUROBOROS_GATEWAY_BIND must be a literal IPv4 or IPv6 address, got: #{text}"
          end

        other ->
          raise ArgumentError,
                "OUROBOROS_GATEWAY_BIND must be a literal IPv4 or IPv6 address, got: " <>
                  inspect(other)
      end

    if loopback?(address) or allow_remote?(opts) do
      address
    else
      raise ArgumentError, """
      OUROBOROS_GATEWAY_BIND=#{bind_to_string(address)} puts the gateway on a network \
      interface, and the gateway protocol is cleartext: the token and every status \
      payload after it cross the wire in the clear.

      Attach over an SSH tunnel instead (ssh -L 4560:127.0.0.1:4560 host), or set \
      OUROBOROS_GATEWAY_ALLOW_REMOTE=1 to accept a cleartext operator surface on a \
      trusted network.\
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
              "OUROBOROS_GATEWAY_PORT must be an integer between 0 and 65535 " <>
                "(0 binds an ephemeral port and publishes it in gateway.json), got: " <>
                inspect(other)
    end
  end

  defp token!(opts) do
    token =
      case {Keyword.get(opts, :token_file), Keyword.get(opts, :token)} do
        {path, _token} when is_binary(path) -> read_token_file!(path)
        {_path, token} when is_binary(token) -> String.trim(token)
        {_path, _token} -> nil
      end

    cond do
      is_nil(token) ->
        raise ArgumentError,
              "the gateway is enabled but no token source is configured. Set " <>
                "OUROBOROS_GATEWAY_TOKEN_FILE to a 0600 file holding at least " <>
                "#{@min_token_bytes} bytes, or OUROBOROS_GATEWAY_TOKEN for a dev loop " <>
                "(the environment of a process is readable by every process the same " <>
                "user runs, which is why the file is preferred)"

      byte_size(token) < @min_token_bytes ->
        raise ArgumentError,
              "the gateway token is #{byte_size(token)} bytes; at least " <>
                "#{@min_token_bytes} are required. Set OUROBOROS_GATEWAY_TOKEN_FILE or " <>
                "OUROBOROS_GATEWAY_TOKEN to a value worth checking"

      true ->
        token
    end
  end

  defp read_token_file!(path) do
    case File.read(path) do
      {:ok, contents} ->
        String.trim(contents)

      {:error, reason} ->
        raise ArgumentError,
              "OUROBOROS_GATEWAY_TOKEN_FILE=#{path} is not readable: " <>
                (reason |> :file.format_error() |> List.to_string())
    end
  end

  defp scope!(opts) do
    case Keyword.get(opts, :scope, :read) do
      scope when scope in [:read, :operate] ->
        scope

      other ->
        raise ArgumentError,
              "OUROBOROS_GATEWAY_SCOPE must be read or operate, got: " <> inspect(other)
    end
  end

  defp max_frame!(opts) do
    case Keyword.get(opts, :max_frame, @default_max_frame) do
      bytes when is_integer(bytes) and bytes >= @min_max_frame ->
        bytes

      other ->
        raise ArgumentError,
              "OUROBOROS_GATEWAY_MAX_FRAME must be an integer of at least " <>
                "#{@min_max_frame} bytes, got: " <> inspect(other)
    end
  end

  defp queue_limit!(opts) do
    case Keyword.get(opts, :queue_limit, @default_queue_limit) do
      limit when is_integer(limit) and limit > 0 ->
        limit

      other ->
        raise ArgumentError,
              "OUROBOROS_GATEWAY_QUEUE_LIMIT must be a positive integer, got: " <>
                inspect(other)
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
    "OUROBOROS_DATA_DIR must name a directory when the gateway is enabled: the bound " <>
      "port, protocol version, and scope are published to gateway.json there, and that " <>
      "file is how a client finds this node"
  end
end
