defmodule Ouroboros.Gateway.Writer do
  @moduledoc """
  The one process allowed to put bytes on a connection's socket.

  ## Why the connection does not write its own frames

  `:gen_tcp.send/2` blocks. Once the peer stops reading, the kernel send buffer fills and
  the call parks until `send_timeout` elapses — fifteen seconds during which a `Conn` that
  wrote inline would process no messages at all. Its mailbox would keep taking session
  events from the planes the whole time, and the outbound bound in
  `Ouroboros.Gateway.Conn` would be measuring a queue it could not observe: the real
  backlog would be sitting in the mailbox, unbounded, exactly where "bounded everything"
  says it must not be.

  So the blocking half lives here, in a process whose only job is to block. The `Conn`
  hands over one frame at a time and receives `{:frame_written, 1}` when the socket has
  actually taken it. The difference between what it handed over and what came back is the
  outbound queue depth — a number it can act on while a slow peer is still slow, which is
  the whole point of dropping event frames rather than accumulating them.

  ## Lifetime

  Spawned and linked by the `Conn` that owns the socket, and monitoring it in return, so
  neither can outlive the other: the link kills this process if the connection crashes,
  and the monitor stops it if the connection exits normally (a normal exit does not
  propagate over a link, and a writer that survived its connection would hold the socket
  open forever).

  A failed write is reported to the `Conn` rather than raised. The connection is what
  decides that a peer which cannot be written to is a peer that is gone, and it has a
  socket to close and a subscription set to release before it says so.
  """

  @doc """
  Starts the writer for `socket`, linked to and monitoring the calling connection.
  """
  @spec start_link(:gen_tcp.socket()) :: pid()
  def start_link(socket) do
    conn = self()
    spawn_link(fn -> init(conn, socket) end)
  end

  @doc "Hands one already-encoded frame to the writer. Never blocks."
  @spec write(pid(), iodata()) :: :ok
  def write(writer, frame) do
    send(writer, {:write, frame})
    :ok
  end

  @doc """
  Waits until every frame handed over so far has reached the socket.

  Used before a deliberate close so the last frame a client is owed — a protocol error, a
  `runtime.shutdown` acknowledgement — is on the wire before the socket is not. Bounded,
  because a peer that is not reading must not be able to delay a connection's exit.

  A writer that has already exited answers immediately rather than after the timeout: the
  common reason to be flushing is that a write just failed, and waiting a full second for
  a reply from a process that is gone would make every failed connection close slowly.
  """
  @spec flush(pid(), timeout()) :: :ok | :timeout
  def flush(writer, timeout) do
    # The monitor reference doubles as the flush tag, so one `receive` covers both the
    # answer and the writer's death without a second selective receive to get wrong.
    ref = Process.monitor(writer)
    send(writer, {:flush, self(), ref})

    receive do
      {:flushed, ^ref} ->
        Process.demonitor(ref, [:flush])
        :ok

      {:DOWN, ^ref, :process, ^writer, _reason} ->
        :ok
    after
      timeout ->
        Process.demonitor(ref, [:flush])
        :timeout
    end
  end

  defp init(conn, socket) do
    monitor = Process.monitor(conn)
    loop(conn, socket, monitor)
  end

  defp loop(conn, socket, monitor) do
    receive do
      {:write, frame} ->
        case :gen_tcp.send(socket, frame) do
          :ok ->
            send(conn, {:frame_written, 1})
            loop(conn, socket, monitor)

          {:error, reason} ->
            send(conn, {:write_failed, reason})
            exit(:normal)
        end

      {:flush, from, ref} ->
        send(from, {:flushed, ref})
        loop(conn, socket, monitor)

      {:DOWN, ^monitor, :process, ^conn, _reason} ->
        exit(:normal)
    end
  end
end
