defmodule Ouroboros.Test.FleetWorkerFake do
  @moduledoc """
  A counting fake of the Rust deployment worker, speaking seam S3 over a real Unix socket.

  It is a fake rather than a stub in the sense that matters here: it **refuses every frame it
  did not expect** and counts the refusal, so a test that passes because the broker sent
  nothing, or sent the wrong thing, fails instead. `refusals/1` is asserted to be zero on the
  happy paths and asserted to be exactly one where the refusal is the point.

  What it checks for itself, because the real worker does:

    * `attach` is the first frame, and no other frame may be first.
    * the capability presented equals the one written to the operation's 0600 file.
    * `subject` and `session` are both present and nonempty.
    * every frame carries `{"v":1,"id":…,"op":…}`, and an unknown `op` is `unsupported_op`.

  ## Why it does not write its own capability file

  The broker mints the operation id (a deployment is not a thing a caller names), so at the
  moment this process starts, the id of the operation it will serve does not exist yet. The
  fake `ouro` script is what learns it — from its own argv, exactly as the real worker does —
  and the script therefore writes the capability file and records the id where this can read
  it when the `attach` arrives. That keeps the whole path under test: the broker mints, the
  executable is told, and the socket answers for the operation it was actually started for.

  Every frame it receives is forwarded to the owning test as `{:fake_worker, frame}`,
  `respond` frames included with their responses intact — a test that could not see the
  secret arrive could not prove it arrived.
  """

  use GenServer

  @doc """
  Starts a fake worker listening on `:socket_path`.

  Options: `:socket_path`, `:cap` (the capability it will demand), `:instance` (the identity
  it reports), `:operation_file` (where the fake `ouro` records the operation id it was
  started for), and `:owner` (defaults to the calling process).
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc "The JSON line `ouro fleet worker start` prints for this fake."
  @spec spawn_line(pid()) :: String.t()
  def spawn_line(pid), do: GenServer.call(pid, :spawn_line)

  @doc "How many frames this fake refused because it did not expect them."
  @spec refusals(pid()) :: non_neg_integer()
  def refusals(pid), do: GenServer.call(pid, :refusals)

  @doc "The `{subject, session}` that attached, or nil."
  @spec attached(pid()) :: %{subject: String.t(), session: String.t()} | nil
  def attached(pid), do: GenServer.call(pid, :attached)

  @doc "Writes one unsolicited event frame to the attached client."
  @spec emit(pid(), map()) :: :ok
  def emit(pid, event), do: GenServer.call(pid, {:emit, event})

  @doc """
  Issues one challenge, bound by default to the identity and session that attached.

  `extra` carries the kind's own secret-free metadata (S4) and may override `expires_at` or
  `bound_to`, which is how the expiry and cross-session refusals are driven.
  """
  @spec challenge(pid(), String.t(), String.t(), map()) :: :ok
  def challenge(pid, id, kind, extra \\ %{}),
    do: GenServer.call(pid, {:challenge, id, kind, extra})

  @doc "Makes the next `respond` answer `ok:false` with this reason instead of accepting."
  @spec refuse_next(pid(), String.t()) :: :ok
  def refuse_next(pid, reason), do: GenServer.call(pid, {:refuse_next, reason})

  @doc "Writes a line longer than the protocol's frame cap, on purpose."
  @spec emit_oversize(pid()) :: :ok
  def emit_oversize(pid), do: GenServer.call(pid, :emit_oversize)

  @doc "Closes the accepted connection but keeps listening, as a crashed worker's socket does."
  @spec drop_connection(pid()) :: :ok
  def drop_connection(pid), do: GenServer.call(pid, :drop_connection)

  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    socket_path = Keyword.fetch!(opts, :socket_path)
    File.mkdir_p!(Path.dirname(socket_path))
    File.chmod!(Path.dirname(socket_path), 0o700)
    _ = File.rm(socket_path)

    {:ok, listen} =
      :gen_tcp.listen(0, [
        :binary,
        {:ifaddr, {:local, socket_path}},
        packet: :line,
        packet_size: 1024 * 1024,
        active: false,
        reuseaddr: true
      ])

    parent = self()
    acceptor = spawn_link(fn -> accept_loop(listen, parent) end)

    {:ok,
     %{
       socket_path: socket_path,
       cap: Keyword.fetch!(opts, :cap),
       instance: Keyword.fetch!(opts, :instance),
       operation_file: Keyword.fetch!(opts, :operation_file),
       owner: Keyword.get(opts, :owner, self()),
       listen: listen,
       acceptor: acceptor,
       socket: nil,
       attached: nil,
       refusals: 0,
       refuse_next: nil
     }}
  end

  defp accept_loop(listen, parent) do
    case :gen_tcp.accept(listen, 30_000) do
      {:ok, socket} ->
        :ok = :gen_tcp.controlling_process(socket, parent)
        send(parent, {:accepted, socket})
        accept_loop(listen, parent)

      {:error, _reason} ->
        :ok
    end
  end

  @impl true
  def handle_call(:spawn_line, _from, state) do
    {:reply, JSON.encode!(%{"socket" => state.socket_path, "instance" => state.instance}) <> "\n",
     state}
  end

  def handle_call(:refusals, _from, state), do: {:reply, state.refusals, state}
  def handle_call(:attached, _from, state), do: {:reply, state.attached, state}

  def handle_call({:emit, event}, _from, state),
    do: {:reply, write(state, Map.put(event, "v", 1)), state}

  def handle_call({:challenge, id, kind, extra}, _from, state) do
    frame =
      Map.merge(
        %{
          "v" => 1,
          "event" => "challenge",
          "challenge" => id,
          "kind" => kind,
          "expires_at" => nil,
          "bound_to" => %{
            "subject" => state.attached && state.attached.subject,
            "session" => state.attached && state.attached.session
          }
        },
        extra
      )

    {:reply, write(state, frame), state}
  end

  def handle_call({:refuse_next, reason}, _from, state),
    do: {:reply, :ok, %{state | refuse_next: reason}}

  def handle_call(:emit_oversize, _from, state) do
    _ =
      if state.socket,
        do: :gen_tcp.send(state.socket, [String.duplicate("x", 1024 * 1024 + 64), "\n"])

    {:reply, :ok, state}
  end

  def handle_call(:drop_connection, _from, state) do
    _ = if state.socket, do: :gen_tcp.close(state.socket)
    {:reply, :ok, %{state | socket: nil, attached: nil}}
  end

  @impl true
  def handle_info({:accepted, socket}, state) do
    :ok = :inet.setopts(socket, active: :once)
    {:noreply, %{state | socket: socket}}
  end

  def handle_info({:tcp, socket, line}, %{socket: socket} = state) do
    :ok = :inet.setopts(socket, active: :once)
    frame = JSON.decode!(String.trim_trailing(line, "\n"))
    send(state.owner, {:fake_worker, frame})
    {:noreply, dispatch(state, frame)}
  end

  def handle_info({:tcp_closed, socket}, %{socket: socket} = state),
    do: {:noreply, %{state | socket: nil, attached: nil}}

  def handle_info(_other, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    if state.socket, do: :gen_tcp.close(state.socket)
    :gen_tcp.close(state.listen)
    _ = File.rm(state.socket_path)
    :ok
  end

  # ---------------------------------------------------------------------------

  defp dispatch(state, %{"v" => 1, "id" => id, "op" => "attach"} = frame) do
    cond do
      state.attached -> refuse(state, id, "already_attached")
      frame["cap"] != state.cap -> refuse(state, id, "bad_capability")
      not present?(frame["subject"]) -> refuse(state, id, "no_subject")
      not present?(frame["session"]) -> refuse(state, id, "no_session")
      true -> accept_attach(state, id, frame)
    end
  end

  defp dispatch(%{attached: nil} = state, %{"id" => id}), do: refuse(state, id, "not_attached")

  defp dispatch(state, %{"v" => 1, "id" => id, "op" => "respond"} = frame) do
    case state.refuse_next do
      nil ->
        write(state, %{
          "v" => 1,
          "id" => id,
          "ok" => true,
          "accepted" => true,
          "challenge" => frame["challenge"]
        })

        state

      reason ->
        write(state, %{"v" => 1, "id" => id, "ok" => false, "reason" => reason})
        %{state | refuse_next: nil}
    end
  end

  defp dispatch(state, %{"v" => 1, "id" => id, "op" => "status"}) do
    write(state, %{"v" => 1, "id" => id, "ok" => true, "state" => "inspecting"})
    state
  end

  defp dispatch(state, %{"v" => 1, "id" => id, "op" => "cancel"}) do
    write(state, %{"v" => 1, "id" => id, "ok" => true, "cancelled" => true, "residue" => []})
    state
  end

  defp dispatch(state, %{"v" => 1, "id" => id, "op" => op}) when op in ["detach", "bye"] do
    write(state, %{"v" => 1, "id" => id, "ok" => true})
    state
  end

  defp dispatch(state, %{"id" => id}), do: refuse(state, id, "unsupported_op")
  defp dispatch(state, _frame), do: %{state | refusals: state.refusals + 1}

  defp accept_attach(state, id, frame) do
    operation = String.trim(File.read!(state.operation_file))

    write(state, %{
      "v" => 1,
      "id" => id,
      "ok" => true,
      "operation" => operation,
      "instance" => state.instance,
      "state" => "inspecting"
    })

    %{state | attached: %{subject: frame["subject"], session: frame["session"]}}
  end

  defp refuse(state, id, reason) do
    write(state, %{
      "v" => 1,
      "id" => id,
      "ok" => false,
      "reason" => reason,
      "detail" => "the fake worker did not expect that frame"
    })

    %{state | refusals: state.refusals + 1}
  end

  defp present?(value), do: is_binary(value) and value != ""

  defp write(%{socket: nil}, _frame), do: :ok

  defp write(state, frame),
    do: :gen_tcp.send(state.socket, [JSON.encode_to_iodata!(frame), ?\n])
end
