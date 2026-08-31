defmodule Ouroboros.Provider.GrokAuth do
  @moduledoc """
  Non-secret coordination around the first-party Grok Build CLI's subscription login.

  Ouroboros starts `grok login --device-auth` only after an operator asks it to. The CLI
  obtains, stores, and refreshes SpaceXAI credentials in its own `auth.json`; this module
  parses only the HTTPS verification URL and short user code from its merged output. Raw
  output and token fields never cross the public API.

  Existing readiness is projected from a safe, owner-only CLI credential file. The JSON
  is inspected only to distinguish a first-party session credential from an API key and
  to return an optional account label. The bearer and refresh-token values are never
  returned, logged, copied, or persisted by Ouroboros.
  """

  use GenServer

  alias Ouroboros.DataDir

  @request_timeout_ms 15_000
  @login_timeout_ms 15 * 60 * 1_000
  @start_timeout_ms 12_000
  @max_output_bytes 64 * 1024
  @max_auth_bytes 1024 * 1024
  @idle_login %{"status" => "idle", "loginId" => nil, "error" => nil}

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

  @doc "Returns subscription identity and pending-login state without any credential."
  def read(server \\ __MODULE__), do: GenServer.call(server, :read, @request_timeout_ms)

  @doc "Starts the first-party CLI's device-code login."
  def login(server \\ __MODULE__), do: GenServer.call(server, :login, @request_timeout_ms)

  @doc "Cancels one pending CLI login."
  def cancel(login_id, server \\ __MODULE__) when is_binary(login_id),
    do: GenServer.call(server, {:cancel, login_id}, @request_timeout_ms)

  @doc "Whether a first-party Grok subscription credential is present."
  @spec credential_present?(keyword()) :: boolean()
  def credential_present?(opts \\ []) when is_list(opts),
    do: match?({:ok, _identity}, subscription_identity(credential_path(opts)))

  @doc "The credential file owned by the Grok CLI."
  @spec credential_path(keyword()) :: Path.t() | nil
  def credential_path(opts \\ []) when is_list(opts) do
    configured =
      Keyword.get(opts, :path) || Application.get_env(:ouroboros, :grok_auth_file)

    cond do
      is_binary(configured) and configured != "" ->
        Path.expand(configured)

      grok_home = present(System.get_env("GROK_HOME")) ->
        Path.join(Path.expand(grok_home), "auth.json")

      home = present(System.get_env("HOME")) ->
        Path.join([Path.expand(home), ".grok", "auth.json"])

      true ->
        nil
    end
  end

  @impl true
  def init(opts) do
    {:ok,
     %{
       auth_path: Keyword.get(opts, :auth_path, credential_path()),
       executable: Keyword.get(opts, :executable),
       env: opts |> Keyword.get(:env, %{}) |> Map.new(),
       start_timeout_ms: Keyword.get(opts, :start_timeout_ms, @start_timeout_ms),
       login_timeout_ms: Keyword.get(opts, :login_timeout_ms, @login_timeout_ms),
       login: @idle_login,
       pending: nil
     }}
  end

  @impl true
  def handle_call(:read, _from, state), do: {:reply, {:ok, projection(state)}, state}

  def handle_call(:login, _from, %{pending: pending} = state) when not is_nil(pending) do
    {:reply, {:error, {:login_pending, pending.id}}, state}
  end

  def handle_call(:login, from, state) do
    with {:ok, executable} <- resolve_executable(state.executable),
         {:ok, port} <- open_login(executable, state.env) do
      login_id = random_id()

      start_timer =
        Process.send_after(self(), {:grok_login_start_timeout, login_id}, state.start_timeout_ms)

      login_timer =
        Process.send_after(self(), {:grok_login_timeout, login_id}, state.login_timeout_ms)

      pending = %{
        id: login_id,
        port: port,
        from: from,
        buffer: "",
        url: nil,
        code: nil,
        start_timer: start_timer,
        login_timer: login_timer
      }

      login = %{"status" => "starting", "loginId" => login_id, "error" => nil}
      {:noreply, %{state | pending: pending, login: login}}
    else
      {:error, reason} -> {:reply, {:error, reason}, failed(state, describe(reason))}
    end
  end

  def handle_call({:cancel, login_id}, _from, state) do
    if state.pending && state.pending.id == login_id do
      state = stop_pending(state, {:error, {:upstream, "Grok sign-in was cancelled"}})
      {:reply, {:ok, %{}}, %{state | login: @idle_login}}
    else
      {:reply, {:ok, %{}}, state}
    end
  end

  @impl true
  def handle_info({port, {:data, data}}, %{pending: %{port: port} = pending} = state)
      when is_binary(data) do
    buffer = bounded_output(pending.buffer <> strip_ansi(data))
    url = pending.url || verification_url(buffer)
    code = pending.code || user_code(buffer, url)
    pending = %{pending | buffer: buffer, url: url, code: code}
    {pending, login} = maybe_reply_started(pending)
    {:noreply, %{state | pending: pending, login: login || state.login}}
  end

  def handle_info({port, {:exit_status, status}}, %{pending: %{port: port} = pending} = state) do
    connected? = match?({:ok, _identity}, subscription_identity(state.auth_path))

    state =
      cond do
        status == 0 and connected? ->
          state
          |> clear_pending(pending, fallback_started_reply(pending))
          |> Map.put(:login, %{"status" => "complete", "loginId" => pending.id, "error" => nil})

        true ->
          message = "Grok sign-in exited before a subscription credential was stored"

          state
          |> clear_pending(pending, {:error, {:upstream, message}})
          |> failed(message)
      end

    {:noreply, state}
  end

  def handle_info({:grok_login_start_timeout, id}, %{pending: %{id: id, from: from}} = state)
      when not is_nil(from) do
    message = "Grok sign-in did not provide a verification link in time"
    state = stop_pending(state, {:error, {:timeout, "grok/login/start"}})
    {:noreply, failed(state, message)}
  end

  def handle_info({:grok_login_start_timeout, _id}, state), do: {:noreply, state}

  def handle_info({:grok_login_timeout, id}, %{pending: %{id: id}} = state) do
    message = "Grok sign-in timed out before authorization completed"
    state = stop_pending(state, {:error, {:timeout, "grok/login"}})
    {:noreply, failed(state, message)}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    _ = if state.pending, do: terminate_port(state.pending.port)
    :ok
  end

  defp projection(state) do
    identity =
      case subscription_identity(state.auth_path) do
        {:ok, identity} -> identity
        {:error, _reason} -> nil
      end

    %{
      "account" =>
        if(identity,
          do: %{"type" => "grok_subscription", "label" => identity},
          else: nil
        ),
      "requiresGrokAuth" => is_nil(identity),
      "login" => state.login
    }
  end

  defp maybe_reply_started(%{from: from, url: url, code: code} = pending)
       when not is_nil(from) and is_binary(url) and is_binary(code) do
    reply = %{
      "type" => "grokDeviceCode",
      "loginId" => pending.id,
      "verificationUrl" => url,
      "userCode" => code
    }

    GenServer.reply(from, {:ok, reply})
    _ = Process.cancel_timer(pending.start_timer)

    {%{pending | from: nil}, %{"status" => "pending", "loginId" => pending.id, "error" => nil}}
  end

  defp maybe_reply_started(pending), do: {pending, nil}

  defp fallback_started_reply(%{from: nil}), do: nil

  defp fallback_started_reply(pending) do
    {:ok,
     %{
       "type" => "grokDeviceCode",
       "loginId" => pending.id,
       "verificationUrl" => pending.url,
       "userCode" => pending.code
     }}
  end

  defp clear_pending(state, pending, reply) do
    if pending.from && reply, do: GenServer.reply(pending.from, reply)
    cancel_timers(pending)
    %{state | pending: nil}
  end

  defp stop_pending(%{pending: pending} = state, reply) do
    terminate_port(pending.port)
    clear_pending(state, pending, reply)
  end

  defp cancel_timers(pending) do
    _ = Process.cancel_timer(pending.start_timer)
    _ = Process.cancel_timer(pending.login_timer)
    :ok
  end

  defp terminate_port(port) when is_port(port) do
    case Port.info(port, :os_pid) do
      {:os_pid, pid} when is_integer(pid) ->
        _ = System.cmd("/bin/kill", ["-TERM", Integer.to_string(pid)], stderr_to_stdout: true)

      _unknown ->
        :ok
    end

    try do
      Port.close(port)
    catch
      :error, :badarg -> :ok
    end
  end

  defp open_login(executable, env) do
    options = [
      :binary,
      :exit_status,
      :stderr_to_stdout,
      :use_stdio,
      :hide,
      args: [~c"login", ~c"--device-auth"],
      env: port_env(env)
    ]

    {:ok, Port.open({:spawn_executable, String.to_charlist(executable)}, options)}
  rescue
    error -> {:error, {:unavailable, "the Grok CLI could not start: #{Exception.message(error)}"}}
  end

  defp port_env(env) do
    Enum.flat_map(env, fn
      {key, value} when is_binary(key) and is_binary(value) ->
        [{String.to_charlist(key), String.to_charlist(value)}]

      _invalid ->
        []
    end)
  end

  defp resolve_executable(configured) do
    executable = configured || configured_cli_path() || "grok"

    case Jido.Harness.ProcessSpec.resolve_executable(executable) do
      {:ok, path} -> {:ok, path}
      {:error, _reason} -> {:error, {:unavailable, "the Grok Build CLI is not installed"}}
    end
  end

  defp configured_cli_path do
    config = Application.get_env(:jido_harness, :provider_config, %{})

    row =
      if is_map(config) or is_list(config),
        do: config |> Map.new() |> Map.get(:grok, %{}),
        else: %{}

    if is_map(row) do
      Map.get(row, :cli_path) || Map.get(row, "cli_path")
    end
  end

  defp verification_url(output) do
    ~r/https:\/\/[^\s\e]+/
    |> Regex.scan(output)
    |> List.flatten()
    |> Enum.map(&Regex.replace(~r/[.,)\]]+\z/, &1, ""))
    |> Enum.find(&https?/1)
  end

  defp user_code(output, url) do
    code_from_url(url) ||
      case Regex.run(
             ~r/(?:^|\n)\s*([A-Z0-9]{4,}(?:-[A-Z0-9]{4,})+)\s*(?:\n|$)/m,
             output,
             capture: :all_but_first
           ) do
        [code] -> code
        _none -> nil
      end
  end

  defp code_from_url(url) when is_binary(url) do
    with %URI{query: query} when is_binary(query) <- URI.parse(url),
         code when is_binary(code) <- URI.decode_query(query)["user_code"],
         true <- Regex.match?(~r/\A[A-Z0-9]{4,}(?:-[A-Z0-9]{4,})+\z/, code) do
      code
    else
      _none -> nil
    end
  rescue
    _invalid -> nil
  end

  defp code_from_url(_url), do: nil

  defp https?(url) do
    case URI.new(url) do
      {:ok, %URI{scheme: "https", host: host}} when is_binary(host) and host != "" -> true
      _invalid -> false
    end
  end

  defp strip_ansi(output), do: Regex.replace(~r/\e\[[0-9;]*[[:alpha:]]/, output, "")

  defp bounded_output(output) when byte_size(output) <= @max_output_bytes, do: output

  defp bounded_output(output),
    do: binary_part(output, byte_size(output) - @max_output_bytes, @max_output_bytes)

  defp subscription_identity(nil), do: {:error, :not_found}

  defp subscription_identity(path) when is_binary(path) do
    with {:ok, before} <- File.lstat(path, time: :posix),
         :ok <- validate_auth_stat(path, before),
         {:ok, contents} <- File.read(path),
         {:ok, after_read} <- File.lstat(path, time: :posix),
         true <- same_file?(before, after_read),
         {:ok, document} <- Jason.decode(contents),
         entry when is_map(entry) <- Enum.find(Map.values(document), &subscription_entry?/1) do
      {:ok, account_label(entry)}
    else
      {:error, :enoent} -> {:error, :not_found}
      false -> {:error, :credential_file_changed}
      nil -> {:error, :subscription_not_found}
      {:error, _reason} = error -> error
      _invalid -> {:error, :invalid_credential_document}
    end
  rescue
    error -> {:error, {:credential_read_failed, Exception.message(error)}}
  end

  defp subscription_entry?(entry) when is_map(entry) do
    mode = entry["auth_mode"]
    key? = not is_nil(present(entry["key"]) || present(entry["refresh_token"]))

    key? and
      (mode in ["web_login", "grok", "oidc"] or
         (mode == "external" and xai_issuer?(entry["oidc_issuer"])))
  end

  defp subscription_entry?(_entry), do: false

  defp xai_issuer?(issuer) when is_binary(issuer) do
    case URI.parse(issuer) do
      %URI{scheme: "https", host: host} -> host in ["auth.x.ai", "accounts.x.ai"]
      _invalid -> false
    end
  end

  defp xai_issuer?(_issuer), do: false

  defp account_label(entry) do
    present(entry["email"]) || present(entry["team_name"]) || "SpaceXAI subscription"
  end

  defp validate_auth_stat(path, stat) do
    mode = Bitwise.band(stat.mode, 0o777)

    cond do
      stat.type != :regular ->
        {:error, {:unsafe_credential_file, path, :not_regular}}

      stat.uid != DataDir.current_uid!() ->
        {:error, {:unsafe_credential_file, path, :wrong_owner}}

      Bitwise.band(mode, 0o077) != 0 ->
        {:error, {:unsafe_credential_file, path, {:mode, mode}}}

      stat.size > @max_auth_bytes ->
        {:error, {:unsafe_credential_file, path, :too_large}}

      true ->
        :ok
    end
  end

  defp same_file?(left, right),
    do:
      left.uid == right.uid and left.major_device == right.major_device and
        left.inode == right.inode

  defp failed(state, message) do
    %{state | login: %{"status" => "failed", "loginId" => nil, "error" => message}}
  end

  defp describe({:unavailable, message}) when is_binary(message), do: message

  defp random_id do
    "grok-login-" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
  end

  defp present(value) when is_binary(value) do
    case String.trim(value) do
      "" -> nil
      value -> value
    end
  end

  defp present(_value), do: nil
end
