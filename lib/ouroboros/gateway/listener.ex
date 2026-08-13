defmodule Ouroboros.Gateway.Listener do
  @moduledoc """
  Binds the port, publishes it, and hands every accepted socket to its own process.

  ## Publishing is part of binding

  `OUROBOROS_GATEWAY_PORT` defaults to `0`, so the kernel picks the port and there is no
  window in which two daemons race for a number one of them chose in advance. The bound
  port is then written to `gateway.json` in the data directory — atomically, `0600`, with
  the mode set on the temporary file *before* the rename so the token-adjacent facts in
  it are never briefly world-readable.

  A failure to publish stops this process, and therefore the boot. A listener nobody can
  find is not a degraded operator surface, it is an absent one, and it would be
  discovered at the worst possible moment.

  The file is removed on graceful termination, best effort. It is not removed when the
  node is killed, which is why it carries the OS pid: a stale file is detectable rather
  than misleading.

  ## Accepting

  A linked acceptor process owns the blocking `:gen_tcp.accept/1` loop so this GenServer
  keeps a responsive mailbox. Transient accept errors are retried in place; only a closed
  listen socket ends the loop. If the acceptor dies for any other reason it is restarted
  here rather than by failing upward, because the listen socket is still perfectly good
  and rebinding would move the published port out from under a connected client.

  Connections are capped. The token is what stops a stranger from being served, but it is
  not what stops a stranger from opening sockets, and "bounded everything" has to include
  the thing an unauthenticated peer can do for free.
  """

  use GenServer

  require Logger

  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Conn

  @publication_name "gateway.json"
  @protocol 1
  @accept_retry_ms 100

  @doc "Starts the listener."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "The port this listener actually bound, which is not the configured one when it was 0."
  @spec port(GenServer.server()) :: :inet.port_number()
  def port(server \\ __MODULE__), do: GenServer.call(server, :port)

  @doc "The path of the file this listener published its port to."
  @spec publication_path(Path.t()) :: Path.t()
  def publication_path(data_dir), do: Path.join(data_dir, @publication_name)

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)

    config = Keyword.fetch!(opts, :config)
    conn_supervisor = Keyword.fetch!(opts, :conn_supervisor)
    task_supervisor = Keyword.fetch!(opts, :task_supervisor)

    case :gen_tcp.listen(config.port, listen_options(config)) do
      {:ok, listen_socket} ->
        {:ok, port} = :inet.port(listen_socket)
        path = publish!(config, port)

        state = %{
          config: config,
          conn_supervisor: conn_supervisor,
          task_supervisor: task_supervisor,
          listen_socket: listen_socket,
          port: port,
          publication: path,
          acceptor: nil
        }

        announce(config, port, path)

        {:ok, %{state | acceptor: start_acceptor(state)}}

      {:error, reason} ->
        {:stop, {:gateway_listen_failed, Config.bind_to_string(config.bind), config.port, reason}}
    end
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, state.port, state}

  @impl true
  def handle_info({:EXIT, acceptor, :normal}, %{acceptor: acceptor} = state) do
    {:stop, :normal, state}
  end

  def handle_info({:EXIT, acceptor, reason}, %{acceptor: acceptor} = state) do
    Logger.warning("gateway acceptor exited (#{inspect(reason, limit: 10)}); accepting again")
    {:noreply, %{state | acceptor: start_acceptor(state)}}
  end

  def handle_info({:EXIT, _pid, reason}, state), do: {:stop, reason, state}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    _ = File.rm(state.publication)
    _ = :gen_tcp.close(state.listen_socket)
    :ok
  end

  defp listen_options(config) do
    [
      :binary,
      ip: config.bind,
      active: false,
      reuseaddr: true,
      backlog: 16,
      packet: :line,
      packet_size: config.max_frame,
      buffer: config.max_frame
    ]
  end

  defp announce(config, port, path) do
    Logger.info(
      "gateway listening on #{Config.bind_to_string(config.bind)}:#{port} " <>
        "at #{config.scope} scope; published to #{path}"
    )

    unless Config.loopback?(config.bind) do
      Logger.warning(
        "gateway is bound to #{Config.bind_to_string(config.bind)}, which is not " <>
          "loopback: the token and every payload after it cross the network in " <>
          "cleartext (OUROBOROS_GATEWAY_ALLOW_REMOTE=1 accepted this)"
      )
    end
  end

  defp publish!(config, port) do
    File.mkdir_p!(config.data_dir)

    path = publication_path(config.data_dir)
    tmp = path <> ".tmp-#{System.unique_integer([:positive, :monotonic])}"

    contents =
      JSON.encode_to_iodata!(%{
        "port" => port,
        "protocol" => @protocol,
        "node" => Atom.to_string(node()),
        "pid" => os_pid(),
        "scope" => Atom.to_string(config.scope)
      })

    try do
      File.write!(tmp, contents)
      File.chmod!(tmp, 0o600)
      File.rename!(tmp, path)
    rescue
      error ->
        _ = File.rm(tmp)
        reraise error, __STACKTRACE__
    end

    File.chmod!(path, 0o600)
    path
  end

  defp os_pid do
    case Integer.parse(System.pid()) do
      {pid, ""} -> pid
      _other -> :os.getpid() |> List.to_string() |> String.to_integer()
    end
  end

  defp start_acceptor(state) do
    listen_socket = state.listen_socket
    conn_supervisor = state.conn_supervisor
    task_supervisor = state.task_supervisor
    config = state.config

    spawn_link(fn ->
      accept_loop(listen_socket, conn_supervisor, task_supervisor, config)
    end)
  end

  defp accept_loop(listen_socket, conn_supervisor, task_supervisor, config) do
    case :gen_tcp.accept(listen_socket) do
      {:ok, socket} ->
        hand_off(socket, conn_supervisor, task_supervisor, config)
        accept_loop(listen_socket, conn_supervisor, task_supervisor, config)

      {:error, reason} when reason in [:closed, :einval] ->
        exit(:normal)

      {:error, reason} ->
        Logger.warning("gateway accept failed: #{inspect(reason)}")
        Process.sleep(@accept_retry_ms)
        accept_loop(listen_socket, conn_supervisor, task_supervisor, config)
    end
  end

  defp hand_off(socket, conn_supervisor, task_supervisor, config) do
    child = {Conn, socket: socket, config: config, task_supervisor: task_supervisor}

    case DynamicSupervisor.start_child(conn_supervisor, child) do
      {:ok, pid} ->
        case :gen_tcp.controlling_process(socket, pid) do
          :ok ->
            send(pid, :socket_ready)

          {:error, _reason} ->
            # The connection process is already armed with its own handshake deadline, so
            # it reaps itself; only the socket needs closing here.
            :gen_tcp.close(socket)
        end

      {:error, :max_children} ->
        Logger.warning("gateway refused a connection: the per-listener cap is reached")
        :gen_tcp.close(socket)

      {:error, reason} ->
        Logger.warning("gateway could not start a connection: #{inspect(reason, limit: 10)}")
        :gen_tcp.close(socket)
    end
  end
end
