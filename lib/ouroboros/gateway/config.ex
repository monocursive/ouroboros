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

  ## The one credential this creates

  `:token_generate` is the single exception to "no token, no listener", and it is set by
  exactly one caller: the branch of `config/runtime.exs` that gives a release nobody
  configured a loopback operator surface. There, `:token_file` is a path this system chose
  rather than one an operator typed, so an absent file is a first boot rather than a
  mistake, and the file is created with 32 random bytes at `0600` instead of stopping the
  daemon. An existing file is read, never replaced. Every other configuration keeps the
  refusal, because a named file that is not there is worth refusing over.

  ## One variable, one queue

  `:queue_limit` (`OUROBOROS_GATEWAY_QUEUE_LIMIT`) is the **outbound** event-frame cap and
  nothing else. A connection also bounds what it will accept inbound and has not yet
  dispatched, but that is a fixed constant in `Ouroboros.Gateway.Conn` rather than a
  setting: the two queues fail differently — the outbound one drops events and tells the
  client to replay, the inbound one refuses requests — and a single variable governing
  both would be a number an operator could not reason about in either direction.

  ## Three byte caps, and what each one bounds

  `:queue_limit` counts *frames*. It says nothing about how large one of them is, which is
  why a single multi-megabyte diff used to cross the socket whole on every notification
  and on every replay. The three byte caps bound the frame itself:

    * `:event_leaf_bytes` (`OUROBOROS_GATEWAY_EVENT_LEAF_BYTES`, 128 KiB) — the most one
      string inside an event `payload` may put on the wire.
    * `:event_payload_bytes` (`OUROBOROS_GATEWAY_EVENT_PAYLOAD_BYTES`, 512 KiB) — the most
      *all* of one event's payload strings may put on the wire together.
    * `:detail_leaf_bytes` (`OUROBOROS_GATEWAY_DETAIL_LEAF_BYTES`, 8 MiB) — the same
      per-string cap, raised, for `interactive.event_detail` / `coding.event_detail`,
      which exist so a client can ask for the one event an excerpt came from.

  All three are read by `Ouroboros.Gateway.Wire` through `event_limits/0` rather than off
  this struct; that function's docstring says why.

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

  @enforce_keys [
    :bind,
    :port,
    :token,
    :scope,
    :max_frame,
    :queue_limit,
    :event_leaf_bytes,
    :event_payload_bytes,
    :detail_leaf_bytes,
    :data_dir
  ]
  defstruct @enforce_keys ++
              [token_file: nil, token_generate: false, allow_remote: false, allow_shutdown: false]

  @type scope :: :read | :operate

  @type t :: %__MODULE__{
          bind: :inet.ip_address(),
          port: :inet.port_number(),
          token: binary(),
          token_file: Path.t() | nil,
          token_generate: boolean(),
          scope: scope(),
          max_frame: pos_integer(),
          queue_limit: pos_integer(),
          event_leaf_bytes: pos_integer(),
          event_payload_bytes: pos_integer(),
          detail_leaf_bytes: pos_integer(),
          data_dir: Path.t(),
          allow_remote: boolean(),
          allow_shutdown: boolean()
        }

  # A token shorter than this is not a credential, it is a speed bump. The spawner writes
  # 32 random bytes as hex; a human typing a token into a shell should be held to the
  # same floor rather than to whatever they had patience for.
  @min_token_bytes 32

  # What a generated credential costs to write, in random bytes before hex encoding. It is
  # the same 32 bytes `ouro` writes when it is the spawner, and hex doubles it, so a
  # generated token clears @min_token_bytes with room to spare.
  @generated_token_bytes 32

  alias Ouroboros.DataDir

  # Below this a `hello` frame itself would be chopped, and every connection would fail
  # with an oversized-frame error that names the wrong cause.
  @min_max_frame 1_024

  # An excerpt shorter than this names nothing a person could read, and a cap below it
  # would turn every event payload into a wall of markers. It is the floor for all three
  # byte caps below.
  @min_leaf_bytes 1_024

  @default_port 0
  @default_bind {127, 0, 0, 1}
  @default_max_frame 1_048_576
  @default_queue_limit 1_000
  @default_event_leaf_bytes 131_072
  @default_event_payload_bytes 524_288
  @default_detail_leaf_bytes 8_388_608

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

  Recognized keys: `:port`, `:bind`, `:token`, `:token_file`, `:token_generate`,
  `:allow_remote`, `:scope`, `:allow_shutdown`, `:max_frame`, `:queue_limit`,
  `:event_leaf_bytes`, `:event_payload_bytes`, `:detail_leaf_bytes`, `:data_dir`.
  Unknown keys are ignored so a later slice can add one without this raising on an older
  node.
  """
  @spec new!(keyword()) :: t()
  def new!(opts) when is_list(opts) do
    bind = bind!(opts)

    %__MODULE__{
      bind: bind,
      port: port!(opts),
      token: token!(opts),
      # The path, never the value. It is published in `gateway.json` so a client that was
      # not the spawner can find the credential it is expected to present without
      # guessing a convention, and a path is not a secret — the 0600 file it names is.
      token_file: token_file(opts),
      token_generate: token_generate?(opts),
      scope: scope!(opts),
      max_frame: max_frame!(opts),
      queue_limit: queue_limit!(opts),
      event_leaf_bytes:
        bytes!(
          opts,
          :event_leaf_bytes,
          @default_event_leaf_bytes,
          "OUROBOROS_GATEWAY_EVENT_LEAF_BYTES"
        ),
      event_payload_bytes:
        bytes!(
          opts,
          :event_payload_bytes,
          @default_event_payload_bytes,
          "OUROBOROS_GATEWAY_EVENT_PAYLOAD_BYTES"
        ),
      detail_leaf_bytes:
        bytes!(
          opts,
          :detail_leaf_bytes,
          @default_detail_leaf_bytes,
          "OUROBOROS_GATEWAY_DETAIL_LEAF_BYTES"
        ),
      data_dir: data_dir!(opts),
      allow_remote: allow_remote?(opts),
      allow_shutdown: Keyword.get(opts, :allow_shutdown, false) == true
    }
  end

  @doc """
  The byte caps `Ouroboros.Gateway.Wire` applies to an outbound event payload.

  Read straight from application environment rather than from a `%__MODULE__{}` because
  the encoder is reached from three directions — a notification fan-out, a `replay`
  result, and a `subscribe` backlog — and only one of them has a connection's config in
  hand. Threading the struct to the other two would be three call sites that can drift;
  one resolver is the thing that cannot.

  This is the lenient half of the same predicate `new!/1` raises on: by the time a frame
  is being encoded the listener has already started, so the refusal has happened, and a
  cap that is somehow still unusable falls back to its default rather than killing the
  connection mid-write.
  """
  @spec event_limits(keyword()) :: %{
          event_leaf_bytes: pos_integer(),
          event_payload_bytes: pos_integer(),
          detail_leaf_bytes: pos_integer()
        }
  def event_limits(opts \\ Application.get_env(:ouroboros, :gateway, [])) do
    %{
      event_leaf_bytes: bytes_or_default(opts, :event_leaf_bytes, @default_event_leaf_bytes),
      event_payload_bytes:
        bytes_or_default(opts, :event_payload_bytes, @default_event_payload_bytes),
      detail_leaf_bytes: bytes_or_default(opts, :detail_leaf_bytes, @default_detail_leaf_bytes)
    }
  end

  defp bytes_or_default(opts, key, default) do
    case usable_bytes(Keyword.get(opts, key, default)) do
      {:ok, bytes} -> bytes
      :error -> default
    end
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
        {path, _token} when is_binary(path) -> read_token_file!(path, token_generate?(opts))
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

  # Only when the file is what supplied the token. A listener configured with
  # `OUROBOROS_GATEWAY_TOKEN` publishes no path, because there is no file to point at and
  # inventing one would send a client looking for something that does not exist.
  defp token_file(opts) do
    case {Keyword.get(opts, :token_file), Keyword.get(opts, :token)} do
      {path, _token} when is_binary(path) -> path
      {_path, _token} -> nil
    end
  end

  defp token_generate?(opts), do: Keyword.get(opts, :token_generate, false) == true

  defp read_token_file!(path, generate?) do
    case File.read(path) do
      {:ok, contents} ->
        String.trim(contents)

      {:error, :enoent} when generate? ->
        generate_token_file!(path)

      {:error, reason} ->
        raise ArgumentError,
              "OUROBOROS_GATEWAY_TOKEN_FILE=#{path} is not readable: " <>
                (reason |> :file.format_error() |> List.to_string())
    end
  end

  # Only reachable with `:token_generate`, which only the defaulted single-machine posture
  # in `config/runtime.exs` sets. Every other configuration keeps the refusal above: a
  # named token file that is not there is a mistake, and inventing a credential to paper
  # over it would turn a fail-closed gateway into one that quietly re-keys itself.
  #
  # The mode is set on the temporary file before the secret is written into it, so the
  # bytes never exist at a mode another user could read, and the rename is what publishes
  # them. An existing file is never replaced — it is read instead — because the token in
  # it may already be the one a running client holds.
  defp generate_token_file!(path) do
    DataDir.ensure_private!(Path.dirname(path))

    tmp = path <> ".tmp-#{System.unique_integer([:positive, :monotonic])}"
    token = @generated_token_bytes |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)

    try do
      File.touch!(tmp)
      File.chmod!(tmp, 0o600)
      File.write!(tmp, token)

      case File.read(path) do
        {:error, :enoent} ->
          File.rename!(tmp, path)
          token

        {:ok, contents} ->
          String.trim(contents)

        {:error, reason} ->
          raise ArgumentError,
                "OUROBOROS_GATEWAY_TOKEN_FILE=#{path} appeared while a token was being " <>
                  "generated and is not readable: " <>
                  (reason |> :file.format_error() |> List.to_string())
      end
    after
      _ = File.rm(tmp)
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

  # The outbound event queue, and only that. Above this many frames waiting for a slow
  # peer, session event notifications are counted and dropped and the client is told with
  # `stream.lagged` so it can replay; responses are never dropped and the connection
  # closes instead. The inbound side — requests accepted but not yet dispatched — is a
  # fixed constant in `Ouroboros.Gateway.Conn`, because one variable naming two queues is
  # a variable an operator cannot reason about.
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

  # The three byte caps that bound an outbound event payload. One predicate decides what
  # a usable value is; `new!/1` raises on anything else because a listener that starts
  # with a cap an operator fat-fingered is a listener that silently un-bounds the wire,
  # and `event_limits/0` falls back to the default because the encoder must never raise
  # inside a frame it is halfway through writing.
  defp bytes!(opts, key, default, variable) do
    value = Keyword.get(opts, key, default)

    case usable_bytes(value) do
      {:ok, bytes} ->
        bytes

      :error ->
        raise ArgumentError,
              "#{variable} must be an integer of at least #{@min_leaf_bytes} bytes, got: " <>
                inspect(value)
    end
  end

  defp usable_bytes(value) when is_integer(value) and value >= @min_leaf_bytes, do: {:ok, value}
  defp usable_bytes(_value), do: :error

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
