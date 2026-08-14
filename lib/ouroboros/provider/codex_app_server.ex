defmodule Ouroboros.Provider.CodexAppServer do
  @moduledoc """
  The supported ChatGPT account boundary for the Codex provider.

  Ouroboros still executes coding turns through `Jido.Harness`; this process owns only
  the account surface that the Codex app-server deliberately exposes to rich clients.
  It runs on the runtime host, so a terminal attached over a tunnel authenticates the
  CLI that will actually execute the work rather than whichever laptop happens to draw
  the UI.

  The app-server transport is long-lived because a managed ChatGPT login completes by
  notification after the browser or device-code ceremony. Calls are serialized through
  one initialized JSONL connection and every request has its own timeout.

  No token crosses the Ouroboros gateway, and this module enforces that rather than
  assuming it of Codex: every upstream result is projected through an explicit key
  allowlist before it is replied to. What reaches a client is the account's type, email,
  and plan, whether OpenAI auth is still required, the managed login's URL and user code,
  and the login state tracked here. A field Codex adds to either result — including one
  carrying credentials — reaches nobody until it is named in that allowlist.
  """

  use GenServer

  @request_timeout 12_000
  @initialize_id 0

  @idle_login %{"status" => "idle", "loginId" => nil, "flow" => nil, "error" => nil}

  # Exactly what a client may learn from this boundary, key by key. Codex owns the shape
  # of these results and can widen it in any release; the promise that no credential
  # crosses the gateway is kept here, by naming the fields that are allowed through,
  # rather than by trusting that nothing else was ever added upstream.
  @account_keys ["account", "requiresOpenaiAuth"]
  @identity_keys ["type", "email", "planType"]
  @login_keys ["type", "loginId", "authUrl", "verificationUrl", "userCode"]

  defstruct port: nil,
            executable: nil,
            initialized?: false,
            next_id: 1,
            pending: %{},
            queued: :queue.new(),
            partial: "",
            login: @idle_login

  @type flow :: :browser | :device_code
  @type server :: GenServer.server()

  def child_spec(opts) do
    %{
      id: {__MODULE__, Keyword.get(opts, :name, __MODULE__)},
      start: {__MODULE__, :start_link, [opts]},
      type: :worker
    }
  end

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, if(name, do: [name: name], else: []))
  end

  @doc "Reads the current Codex account and the state of any managed login."
  @spec read(server()) :: {:ok, map()} | {:error, term()}
  def read(server \\ __MODULE__) do
    request(server, "account/read", %{"refreshToken" => false}, :account_read)
  end

  @doc "Starts Codex's managed ChatGPT browser or device-code flow."
  @spec login(flow(), server()) :: {:ok, map()} | {:error, term()}
  def login(flow, server \\ __MODULE__)

  def login(:browser, server) do
    request(
      server,
      "account/login/start",
      %{
        "type" => "chatgpt",
        "useHostedLoginSuccessPage" => true,
        "appBrand" => "chatgpt"
      },
      {:login_start, :browser}
    )
  end

  def login(:device_code, server) do
    request(
      server,
      "account/login/start",
      %{"type" => "chatgptDeviceCode"},
      {:login_start, :device_code}
    )
  end

  @doc "Cancels the named managed ChatGPT login."
  @spec cancel(String.t(), server()) :: {:ok, map()} | {:error, term()}
  def cancel(login_id, server \\ __MODULE__) when is_binary(login_id) do
    request(
      server,
      "account/login/cancel",
      %{"loginId" => login_id},
      {:login_cancel, login_id}
    )
  end

  @doc "Clears the Codex account on the runtime host."
  @spec logout(server()) :: {:ok, map()} | {:error, term()}
  def logout(server \\ __MODULE__) do
    request(server, "account/logout", %{}, :logout)
  end

  defp request(server, method, params, kind) do
    GenServer.call(server, {:request, method, params, kind}, @request_timeout + 1_000)
  catch
    :exit, {:noproc, _detail} ->
      {:error, {:unavailable, "the Codex account service is not running on this node"}}

    :exit, {:timeout, _detail} ->
      {:error, {:timeout, method}}
  end

  @impl true
  def init(opts) do
    # The port is linked to this process, and a port whose child has died mid-write ends
    # with `:epipe` — an exit signal, not a message. Trapping is what turns that into
    # something this module can answer its callers about, rather than a GenServer crash
    # that hands them a raw exit and restarts the connection under them.
    Process.flag(:trap_exit, true)

    executable =
      Keyword.get(opts, :executable) ||
        System.get_env("CODEX_PATH") ||
        "codex"

    {:ok, %__MODULE__{executable: executable}}
  end

  @impl true
  def handle_call({:request, method, params, kind}, from, state) do
    queued = :queue.in({from, method, params, kind}, state.queued)
    state = %{state | queued: queued}

    case ensure_started(state) do
      {:ok, state} -> {:noreply, flush(state)}
      {:error, reason, state} -> {:reply, {:error, reason}, drop_queued(state, from)}
    end
  end

  @impl true
  def handle_info({port, {:data, {:noeol, bytes}}}, %{port: port} = state) do
    {:noreply, %{state | partial: state.partial <> bytes}}
  end

  def handle_info({port, {:data, {:eol, bytes}}}, %{port: port} = state) do
    line = state.partial <> bytes
    state = %{state | partial: ""}

    case Jason.decode(line) do
      {:ok, frame} when is_map(frame) -> {:noreply, frame(frame, state)}
      # App-server may write diagnostics to stderr. It shares the port only so a full
      # stderr pipe can never stall the child; a non-JSON diagnostic is not protocol.
      _not_protocol -> {:noreply, state}
    end
  end

  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    reason = {:unavailable, "the Codex app-server exited with status #{status}"}
    {:noreply, reset(reply_all(state, reason), reason)}
  end

  def handle_info({:EXIT, port, exit_reason}, %{port: port} = state) do
    reason = {:unavailable, port_failure(exit_reason)}
    {:noreply, reset(reply_all(state, reason), reason)}
  end

  def handle_info({:request_timeout, id}, state) do
    case Map.pop(state.pending, id) do
      {nil, _pending} ->
        {:noreply, state}

      {%{from: nil}, pending} ->
        reason = {:timeout, "initialize"}
        {:noreply, reset(reply_queued(%{state | pending: pending}, reason), reason)}

      {%{from: from, method: method}, pending} ->
        GenServer.reply(from, {:error, {:timeout, method}})
        {:noreply, %{state | pending: pending}}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{port: port}), do: close_port(port)

  # Closing the port is what ends the `codex` process: it holds the child's stdin, and the
  # app-server exits on EOF. A reset that only forgot the port would leave an OS process
  # alive with nobody able to reach it, and `account/read` is a `:read`-scope call — a
  # read-only token could spawn them without bound. Already-closed is not a failure; the
  # only way to know is to try.
  defp close_port(port) when is_port(port) do
    Port.close(port)
    :ok
  catch
    :error, :badarg -> :ok
  end

  defp close_port(_port), do: :ok

  # A dead port reaches this process two ways, and neither of them is the caller's fault:
  # `:epipe` when a frame was written into a child that had already gone, and the port's
  # own termination otherwise.
  defp port_failure(:epipe), do: "the Codex app-server stopped reading its input"
  defp port_failure(:normal), do: "the Codex app-server connection closed"

  defp port_failure(reason),
    do: "the Codex app-server connection failed: #{inspect(reason)}"

  defp ensure_started(%{port: port} = state) when is_port(port), do: {:ok, state}

  defp ensure_started(state) do
    with {:ok, executable} <- resolve_executable(state.executable),
         {:ok, port} <- open_port(executable) do
      state = %{state | port: port, initialized?: false, executable: executable}

      init = %{
        "method" => "initialize",
        "id" => @initialize_id,
        "params" => %{
          "clientInfo" => %{
            "name" => "ouroboros",
            "title" => "Ouroboros",
            "version" => Application.spec(:ouroboros, :vsn) |> to_string()
          }
        }
      }

      case send_frame(port, init) do
        :ok ->
          timer = Process.send_after(self(), {:request_timeout, @initialize_id}, @request_timeout)

          pending = %{
            @initialize_id => %{
              from: nil,
              method: "initialize",
              kind: :initialize,
              timer: timer
            }
          }

          {:ok, %{state | pending: pending}}

        {:error, reason} ->
          close_port(port)
          {:error, reason, %{state | port: nil}}
      end
    else
      {:error, reason} -> {:error, reason, state}
    end
  end

  defp resolve_executable(executable) do
    path =
      if String.contains?(executable, ["/", "\\"]),
        do: Path.expand(executable),
        else: System.find_executable(executable)

    if is_binary(path) and File.regular?(path) do
      {:ok, path}
    else
      {:error,
       {:unavailable,
        "Codex is not installed on the runtime host; expected executable #{inspect(executable)}"}}
    end
  end

  defp open_port(executable) do
    port =
      Port.open(
        {:spawn_executable, String.to_charlist(executable)},
        [
          :binary,
          :exit_status,
          :use_stdio,
          :stderr_to_stdout,
          {:args, [~c"app-server", ~c"--stdio"]},
          {:line, 1_048_576}
        ]
      )

    {:ok, port}
  rescue
    error ->
      {:error, {:unavailable, "could not start Codex app-server: #{Exception.message(error)}"}}
  end

  defp flush(%{initialized?: false} = state), do: state

  defp flush(state) do
    case :queue.out(state.queued) do
      {:empty, _queued} ->
        state

      {{:value, {from, method, params, kind}}, queued} ->
        id = state.next_id
        timer = Process.send_after(self(), {:request_timeout, id}, @request_timeout)

        pending =
          Map.put(state.pending, id, %{
            from: from,
            method: method,
            kind: kind,
            timer: timer
          })

        frame = %{"method" => method, "id" => id, "params" => params}
        state = %{state | queued: queued, pending: pending, next_id: id + 1}

        case send_frame(state.port, frame) do
          :ok -> flush(state)
          {:error, reason} -> reset(reply_all(state, reason), reason)
        end
    end
  end

  # `Port.command/2` answers `true` or raises; it has no false. It raises exactly when the
  # port is already gone — the child died between two frames — which is the transport
  # disappearing rather than the app-server refusing anything, so it is named as such.
  defp send_frame(port, frame) do
    Port.command(port, [Jason.encode_to_iodata!(frame), "\n"])
    :ok
  rescue
    ArgumentError ->
      {:error, {:unavailable, "the Codex app-server stopped accepting requests"}}
  end

  defp frame(%{"id" => @initialize_id} = response, state) do
    {pending, rest} = Map.pop(state.pending, @initialize_id)
    cancel_timer(pending)

    if Map.has_key?(response, "result") do
      # The child can die between the frame it answered and the one that acknowledges it.
      # Every caller is owed the same honest answer as any other transport failure; a
      # match here would crash this process and hand them a raw exit instead.
      case send_frame(state.port, %{"method" => "initialized", "params" => %{}}) do
        :ok ->
          flush(%{state | initialized?: true, pending: rest})

        {:error, reason} ->
          reset(reply_all(%{state | pending: rest}, reason), reason)
      end
    else
      reason = {:upstream, app_server_error(response)}
      reset(reply_queued(%{state | pending: rest}, reason), reason)
    end
  end

  defp frame(%{"id" => id} = response, state) when is_integer(id) do
    case Map.pop(state.pending, id) do
      {nil, _pending} ->
        state

      {request, pending} ->
        cancel_timer(request)
        state = %{state | pending: pending}

        case response do
          %{"result" => result} -> complete(request, result, state)
          _error -> complete_error(request, app_server_error(response), state)
        end
    end
  end

  defp frame(%{"method" => "account/login/completed", "params" => params}, state) do
    login = %{
      "status" => if(params["success"], do: "succeeded", else: "failed"),
      "loginId" => params["loginId"],
      "flow" => state.login["flow"],
      "error" => params["error"]
    }

    %{state | login: login}
  end

  defp frame(%{"method" => "account/updated", "params" => params}, state) do
    # The next `account/read` remains the source of account identity. This notification
    # only makes a completed sign-in visible immediately while that read is in flight.
    login =
      if params["authMode"] do
        %{state.login | "status" => "succeeded", "error" => nil}
      else
        @idle_login
      end

    %{state | login: login}
  end

  defp frame(_notification, state), do: state

  defp complete(%{from: from, kind: :account_read}, result, state) do
    GenServer.reply(from, {:ok, Map.put(account(result), "login", state.login)})
    state
  end

  defp complete(%{from: from, kind: {:login_start, flow}}, result, state) do
    login = %{
      "status" => "pending",
      "loginId" => result["loginId"],
      "flow" => Atom.to_string(flow),
      "error" => nil
    }

    GenServer.reply(from, {:ok, Map.put(Map.take(result, @login_keys), "login", login)})
    %{state | login: login}
  end

  defp complete(%{from: from, kind: {:login_cancel, login_id}}, _result, state) do
    GenServer.reply(from, {:ok, %{}})

    # A completion for a login that is no longer the pending one says nothing about the
    # one that is. Only the cancelled login's own flow returns this connection to idle.
    if state.login["loginId"] == login_id, do: %{state | login: @idle_login}, else: state
  end

  defp complete(%{from: from, kind: :logout}, _result, state) do
    GenServer.reply(from, {:ok, %{}})
    %{state | login: @idle_login}
  end

  # A kind this module does not name cannot have a projection, so it carries no field at
  # all rather than whatever upstream happened to send.
  defp complete(%{from: from}, _result, state) do
    GenServer.reply(from, {:ok, %{}})
    state
  end

  # The projection that makes "no token ever crosses the gateway" a property of this
  # module rather than of Codex's current response shape.
  defp account(result) do
    projected = Map.take(result, @account_keys)

    case projected do
      %{"account" => account} when is_map(account) ->
        %{projected | "account" => Map.take(account, @identity_keys)}

      _absent_or_null ->
        projected
    end
  end

  defp complete_error(%{from: from, kind: {:login_start, flow}}, error, state) do
    GenServer.reply(from, {:error, {:upstream, error}})

    login = %{
      "status" => "failed",
      "loginId" => nil,
      "flow" => Atom.to_string(flow),
      "error" => error
    }

    %{state | login: login}
  end

  defp complete_error(%{from: from}, error, state) do
    GenServer.reply(from, {:error, {:upstream, error}})
    state
  end

  defp app_server_error(%{"error" => %{"message" => message}}) when is_binary(message),
    do: message

  defp app_server_error(%{"error" => error}), do: inspect(error)
  defp app_server_error(frame), do: "unexpected response: #{inspect(frame)}"

  defp cancel_timer(%{timer: timer}) when is_reference(timer), do: Process.cancel_timer(timer)
  defp cancel_timer(_pending), do: :ok

  defp drop_queued(state, from) do
    queued =
      state.queued
      |> :queue.to_list()
      |> Enum.reject(fn {queued_from, _method, _params, _kind} -> queued_from == from end)
      |> :queue.from_list()

    %{state | queued: queued}
  end

  defp reply_all(state, reason) do
    state
    |> reply_pending(reason)
    |> reply_queued(reason)
  end

  defp reply_pending(state, reason) do
    Enum.each(state.pending, fn {_id, request} ->
      cancel_timer(request)

      if request.from do
        GenServer.reply(request.from, {:error, reason})
      end
    end)

    %{state | pending: %{}}
  end

  defp reply_queued(state, reason) do
    Enum.each(:queue.to_list(state.queued), fn {from, _method, _params, _kind} ->
      GenServer.reply(from, {:error, reason})
    end)

    %{state | queued: :queue.new()}
  end

  defp reset(state, reason) do
    close_port(state.port)

    login =
      if state.login["status"] == "pending" do
        %{state.login | "status" => "failed", "error" => inspect(reason)}
      else
        state.login
      end

    %{
      state
      | port: nil,
        initialized?: false,
        pending: %{},
        queued: :queue.new(),
        partial: "",
        login: login
    }
  end
end
