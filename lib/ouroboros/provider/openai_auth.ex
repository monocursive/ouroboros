defmodule Ouroboros.Provider.OpenAIAuth do
  @moduledoc """
  Node-owned OpenAI authentication without a provider CLI.

  API-key requests continue to read `OPENAI_API_KEY` through ReqLLM. ChatGPT subscription
  requests use a private OAuth file under the Ouroboros data directory. Browser and
  device-code login are implemented against OpenAI's OAuth endpoints directly; access and
  refresh tokens never cross this module's public API.
  """

  use GenServer

  @client_id "app_EMoamEEZ73f0CkXaXp7hrann"
  @issuer "https://auth.openai.com"
  @browser_port 1455
  @browser_timeout_ms 5 * 60 * 1_000
  @device_timeout_ms 15 * 60 * 1_000
  @request_timeout_ms 15_000
  @provider_key "openai-codex"
  @idle_login %{"status" => "idle", "loginId" => nil, "flow" => nil, "error" => nil}

  defmodule HTTP do
    @moduledoc false

    def post_form(url, fields, timeout_ms) do
      request(url, URI.encode_query(fields), "application/x-www-form-urlencoded", timeout_ms)
    end

    def post_json(url, fields, timeout_ms) do
      request(url, JSON.encode!(fields), "application/json", timeout_ms)
    end

    defp request(url, body, content_type, timeout_ms) do
      case Req.post(url,
             body: body,
             headers: [{"content-type", content_type}],
             receive_timeout: timeout_ms,
             retry: false
           ) do
        {:ok, response} -> {:ok, response.status, response.headers, decode(response.body)}
        {:error, reason} -> {:error, reason}
      end
    rescue
      error -> {:error, error}
    end

    defp decode(body) when is_map(body), do: body

    defp decode(body) when is_binary(body) do
      case JSON.decode(body) do
        {:ok, decoded} -> decoded
        _not_json -> body
      end
    rescue
      _error -> body
    end

    defp decode(body), do: body
  end

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

  @doc "Returns non-secret account and login state."
  def read(server \\ __MODULE__), do: GenServer.call(server, :read, @request_timeout_ms)

  @doc "Starts a direct browser-PKCE or device-code login."
  def login(flow, server \\ __MODULE__) when flow in [:browser, :device_code],
    do: GenServer.call(server, {:login, flow}, @request_timeout_ms)

  @doc "Completes a browser login captured by a remote client."
  def complete(login_id, code, state, server \\ __MODULE__)
      when is_binary(login_id) and is_binary(code) and is_binary(state),
      do: GenServer.call(server, {:complete, login_id, code, state}, @request_timeout_ms)

  @doc "Cancels one pending login."
  def cancel(login_id, server \\ __MODULE__) when is_binary(login_id),
    do: GenServer.call(server, {:cancel, login_id}, @request_timeout_ms)

  @doc "Deletes the local ChatGPT OAuth credential."
  def logout(server \\ __MODULE__), do: GenServer.call(server, :logout, @request_timeout_ms)

  @doc "The private OAuth file ReqLLM reads."
  def credential_path do
    configured =
      Application.get_env(:ouroboros, :oauth_file) || System.get_env("OUROBOROS_OAUTH_FILE")

    case configured do
      path when is_binary(path) and path != "" -> Path.expand(path)
      _unset -> Path.join(data_dir(), "oauth.json")
    end
  end

  @doc "Whether a usable OAuth credential is present, without returning it."
  def credential_present? do
    case read_credentials(credential_path()) do
      {:ok, credential} -> present?(credential["access"]) or present?(credential["refresh"])
      _absent -> false
    end
  end

  @impl true
  def init(opts) do
    path = Keyword.get(opts, :credential_path, credential_path()) |> Path.expand()

    with :ok <- ensure_private_parent(path) do
      {:ok,
       %{
         credential_path: path,
         http: Keyword.get(opts, :http, HTTP),
         issuer: Keyword.get(opts, :issuer, @issuer),
         browser_port: Keyword.get(opts, :browser_port, @browser_port),
         request_timeout_ms: Keyword.get(opts, :request_timeout_ms, @request_timeout_ms),
         device_timeout_ms: Keyword.get(opts, :device_timeout_ms, @device_timeout_ms),
         device_poll_margin_ms: Keyword.get(opts, :device_poll_margin_ms, 3_000),
         device_min_interval_ms: Keyword.get(opts, :device_min_interval_ms, 1_000),
         login: @idle_login,
         pending: nil
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:read, _from, state) do
    {:reply, {:ok, account_projection(state)}, state}
  end

  def handle_call({:login, _flow}, _from, %{pending: pending} = state) when not is_nil(pending) do
    {:reply, {:error, {:login_pending, pending.id}}, state}
  end

  def handle_call({:login, :browser}, _from, state) do
    case start_browser(state) do
      {:ok, result, state} ->
        {:reply, {:ok, result}, state}

      {:error, reason} ->
        {:reply, {:error, {:upstream, describe(reason)}}, failed(state, :browser, reason)}
    end
  end

  def handle_call({:login, :device_code}, _from, state) do
    case start_device(state) do
      {:ok, result, state} ->
        {:reply, {:ok, result}, state}

      {:error, reason} ->
        {:reply, {:error, {:upstream, describe(reason)}}, failed(state, :device_code, reason)}
    end
  end

  def handle_call({:complete, login_id, code, returned_state}, _from, state) do
    with %{id: ^login_id, flow: :browser, state: expected, verifier: verifier} <- state.pending,
         true <- secure_equal?(expected, returned_state),
         {:ok, credential} <- exchange_code(state, code, verifier, redirect_uri(state.pending)),
         :ok <- persist_credential(state.credential_path, credential) do
      state = succeed(clear_pending(state))
      {:reply, {:ok, %{}}, state}
    else
      nil ->
        {:reply, {:error, :no_pending_login}, state}

      false ->
        {:reply, {:error, :invalid_oauth_state}, state}

      %{id: _other} ->
        {:reply, {:error, :unknown_login}, state}

      {:error, reason} ->
        {:reply, {:error, {:upstream, describe(reason)}}, failed_pending(state, reason)}
    end
  end

  def handle_call({:cancel, login_id}, _from, state) do
    if state.pending && state.pending.id == login_id do
      {:reply, {:ok, %{}}, clear_pending(state)}
    else
      {:reply, {:ok, %{}}, state}
    end
  end

  def handle_call(:logout, _from, state) do
    state = clear_pending(state)

    case delete_credential(state.credential_path) do
      :ok -> {:reply, {:ok, %{}}, %{state | login: @idle_login}}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_info({:oauth_browser_callback, login_id, code, returned_state}, state) do
    state = complete_async(state, login_id, code, returned_state)
    {:noreply, state}
  end

  def handle_info({:oauth_device_complete, login_id, {:ok, credential}}, state) do
    state =
      if state.pending && state.pending.id == login_id do
        case persist_credential(state.credential_path, credential) do
          :ok -> state |> clear_pending() |> succeed()
          {:error, reason} -> failed_pending(state, reason)
        end
      else
        state
      end

    {:noreply, state}
  end

  def handle_info({:oauth_device_complete, login_id, {:error, reason}}, state) do
    state =
      if state.pending && state.pending.id == login_id,
        do: failed_pending(state, reason),
        else: state

    {:noreply, state}
  end

  def handle_info(
        {:DOWN, monitor, :process, _pid, reason},
        %{pending: %{monitor: monitor}} = state
      ) do
    state = if reason == :normal, do: state, else: failed_pending(state, reason)
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    _ = clear_pending(state)
    :ok
  end

  defp start_browser(state) do
    login_id = random_id("login")
    oauth_state = random_token(32)
    {verifier, challenge} = pkce()

    with {:ok, listener} <- start_listener(self(), login_id, state.browser_port) do
      pending = %{
        id: login_id,
        flow: :browser,
        state: oauth_state,
        verifier: verifier,
        listener: listener,
        task: listener.pid,
        monitor: Process.monitor(listener.pid)
      }

      redirect_uri = listener.redirect_uri

      url =
        authorize_url(state.issuer, redirect_uri, challenge, oauth_state)

      login = pending_login(login_id, :browser)

      result = %{
        "type" => "chatgpt",
        "loginId" => login_id,
        "authUrl" => url,
        "login" => login
      }

      {:ok, result, %{state | pending: pending, login: login}}
    end
  end

  defp start_device(state) do
    url = state.issuer <> "/api/accounts/deviceauth/usercode"

    with {:ok, status, _headers, body} <-
           state.http.post_json(url, %{"client_id" => @client_id}, state.request_timeout_ms),
         true <- status in 200..299,
         {:ok, device_id, user_code, interval_ms} <-
           device_start(body, state.device_min_interval_ms) do
      login_id = random_id("login")
      parent = self()

      {:ok, pid} =
        Task.Supervisor.start_child(Jido.Harness.SessionTaskSupervisor, fn ->
          result = poll_device(state, device_id, user_code, interval_ms)
          send(parent, {:oauth_device_complete, login_id, result})
        end)

      pending = %{
        id: login_id,
        flow: :device_code,
        task: pid,
        monitor: Process.monitor(pid)
      }

      login = pending_login(login_id, :device_code)

      result = %{
        "type" => "chatgptDeviceCode",
        "loginId" => login_id,
        "verificationUrl" => state.issuer <> "/codex/device",
        "userCode" => user_code,
        "login" => login
      }

      {:ok, result, %{state | pending: pending, login: login}}
    else
      false -> {:error, :device_authorization_refused}
      {:error, reason} -> {:error, reason}
    end
  end

  defp poll_device(state, device_id, user_code, interval_ms) do
    deadline = System.monotonic_time(:millisecond) + state.device_timeout_ms
    do_poll_device(state, device_id, user_code, interval_ms, deadline)
  end

  defp do_poll_device(state, device_id, user_code, interval_ms, deadline) do
    if System.monotonic_time(:millisecond) >= deadline do
      {:error, :device_authorization_timed_out}
    else
      Process.sleep(interval_ms + state.device_poll_margin_ms)
      url = state.issuer <> "/api/accounts/deviceauth/token"

      case state.http.post_json(
             url,
             %{"device_auth_id" => device_id, "user_code" => user_code},
             state.request_timeout_ms
           ) do
        {:ok, status, _headers, body} when status in 200..299 ->
          with {:ok, code, verifier} <- device_token(body) do
            exchange_code(state, code, verifier, state.issuer <> "/deviceauth/callback")
          end

        {:ok, status, _headers, _body} when status in [403, 404] ->
          do_poll_device(state, device_id, user_code, interval_ms, deadline)

        {:ok, 429, headers, _body} ->
          delay = retry_after_ms(headers) || interval_ms + 5_000
          do_poll_device(state, device_id, user_code, max(delay, interval_ms), deadline)

        {:ok, status, _headers, body} ->
          {:error, {:device_authorization_failed, status, safe_error(body)}}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp complete_async(state, login_id, code, returned_state) do
    with %{id: ^login_id, flow: :browser, state: expected, verifier: verifier} <- state.pending,
         true <- secure_equal?(expected, returned_state),
         {:ok, credential} <- exchange_code(state, code, verifier, redirect_uri(state.pending)),
         :ok <- persist_credential(state.credential_path, credential) do
      state |> clear_pending() |> succeed()
    else
      reason -> failed_pending(state, reason)
    end
  end

  defp exchange_code(state, code, verifier, redirect_uri) do
    fields = %{
      "grant_type" => "authorization_code",
      "client_id" => @client_id,
      "code" => code,
      "code_verifier" => verifier,
      "redirect_uri" => redirect_uri
    }

    case state.http.post_form(
           state.issuer <> "/oauth/token",
           fields,
           state.request_timeout_ms
         ) do
      {:ok, status, _headers, body} when status in 200..299 ->
        token_credential(body)

      {:ok, status, _headers, body} ->
        {:error, {:token_exchange_failed, status, safe_error(body)}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp token_credential(body) when is_map(body) do
    access = body["access_token"]
    refresh = body["refresh_token"]
    expires_in = body["expires_in"]

    if present?(access) and present?(refresh) and is_number(expires_in) and expires_in > 0 do
      claims = jwt_claims(body["id_token"]) || jwt_claims(access) || %{}
      auth_claims = claims["https://api.openai.com/auth"] || %{}

      {:ok,
       %{
         "type" => "oauth",
         "access" => access,
         "refresh" => refresh,
         "expires" => System.system_time(:millisecond) + round(expires_in * 1_000),
         "accountId" =>
           auth_claims["chatgpt_account_id"] || claims["chatgpt_account_id"] ||
             first_org(claims),
         "email" => claims["email"],
         "planType" => auth_claims["chatgpt_plan_type"] || claims["chatgpt_plan_type"]
       }}
    else
      {:error, :invalid_token_response}
    end
  end

  defp token_credential(_body), do: {:error, :invalid_token_response}

  defp account_projection(state) do
    credential =
      case read_credentials(state.credential_path) do
        {:ok, value} -> value
        _absent -> nil
      end

    account =
      if credential do
        claims = jwt_claims(credential["access"]) || %{}
        auth_claims = claims["https://api.openai.com/auth"] || %{}

        %{
          "type" => "chatgpt",
          "email" => credential["email"] || claims["email"],
          "planType" =>
            credential["planType"] || auth_claims["chatgpt_plan_type"] ||
              claims["chatgpt_plan_type"]
        }
        |> reject_nil_values()
      end

    %{
      "account" => account,
      "requiresOpenaiAuth" => is_nil(credential),
      "login" => state.login
    }
  end

  defp start_listener(parent, login_id, port) do
    options = [:binary, active: false, packet: :raw, reuseaddr: true, ip: {127, 0, 0, 1}]

    with {:ok, socket} <- :gen_tcp.listen(port, options),
         {:ok, {_address, actual_port}} <- :inet.sockname(socket),
         {:ok, pid} <-
           Task.Supervisor.start_child(Jido.Harness.SessionTaskSupervisor, fn ->
             accept_callback(parent, login_id, socket)
           end) do
      {:ok,
       %{
         socket: socket,
         pid: pid,
         redirect_uri: "http://localhost:#{actual_port}/auth/callback"
       }}
    end
  end

  defp accept_callback(parent, login_id, socket) do
    result =
      with {:ok, client} <- :gen_tcp.accept(socket, @browser_timeout_ms),
           {:ok, request} <- :gen_tcp.recv(client, 0, 10_000),
           {:ok, code, state} <- parse_callback(request) do
        send(parent, {:oauth_browser_callback, login_id, code, state})
        _ = :gen_tcp.send(client, success_response())
        _ = :gen_tcp.close(client)
        :ok
      else
        {:error, reason} -> {:error, reason}
      end

    _ = :gen_tcp.close(socket)
    result
  end

  defp parse_callback(request) when is_binary(request) do
    with [request_line | _] <- String.split(request, "\r\n"),
         ["GET", target, _version] <- String.split(request_line, " "),
         %URI{path: "/auth/callback", query: query} when is_binary(query) <- URI.parse(target),
         params <- URI.decode_query(query),
         code when is_binary(code) and code != "" <- params["code"],
         state when is_binary(state) and state != "" <- params["state"] do
      {:ok, code, state}
    else
      _invalid -> {:error, :invalid_oauth_callback}
    end
  end

  defp success_response do
    body = "<!doctype html><title>Ouroboros connected</title><p>You may close this window.</p>"

    "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: #{byte_size(body)}\r\nconnection: close\r\n\r\n#{body}"
  end

  defp authorize_url(issuer, redirect_uri, challenge, state) do
    query =
      URI.encode_query(%{
        "response_type" => "code",
        "client_id" => @client_id,
        "redirect_uri" => redirect_uri,
        "scope" => "openid profile email offline_access",
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
        "state" => state,
        "id_token_add_organizations" => "true",
        "codex_cli_simplified_flow" => "true",
        "originator" => "ouroboros"
      })

    issuer <> "/oauth/authorize?" <> query
  end

  defp pkce do
    verifier = random_token(48)
    challenge = :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)
    {verifier, challenge}
  end

  defp device_start(body, minimum_ms) when is_map(body) do
    device_id = body["device_auth_id"]
    user_code = body["user_code"]

    interval =
      case body["interval"] do
        value when is_integer(value) -> value
        value when is_binary(value) -> parse_integer(value)
        _absent -> 5
      end

    if present?(device_id) and present?(user_code) and is_integer(interval) and interval >= 0,
      do: {:ok, device_id, user_code, max(interval * 1_000, minimum_ms)},
      else: {:error, :invalid_device_authorization_response}
  end

  defp device_start(_body, _minimum_ms), do: {:error, :invalid_device_authorization_response}

  defp device_token(body) when is_map(body) do
    code = body["authorization_code"]
    verifier = body["code_verifier"]

    if present?(code) and present?(verifier),
      do: {:ok, code, verifier},
      else: {:error, :invalid_device_token_response}
  end

  defp device_token(_body), do: {:error, :invalid_device_token_response}

  defp pending_login(id, flow) do
    %{
      "status" => "pending",
      "loginId" => id,
      "flow" => Atom.to_string(flow),
      "error" => nil
    }
  end

  defp failed(state, flow, reason) do
    %{
      state
      | login: %{
          "status" => "failed",
          "loginId" => nil,
          "flow" => Atom.to_string(flow),
          "error" => describe(reason)
        }
    }
  end

  defp failed_pending(state, reason) do
    flow = state.pending && state.pending.flow
    state = clear_pending(state)

    %{
      state
      | login: %{
          "status" => "failed",
          "loginId" => nil,
          "flow" => if(flow, do: Atom.to_string(flow), else: nil),
          "error" => describe(reason)
        }
    }
  end

  defp succeed(state) do
    %{
      state
      | login: %{
          "status" => "succeeded",
          "loginId" => nil,
          "flow" => nil,
          "error" => nil
        }
    }
  end

  defp clear_pending(%{pending: nil} = state), do: state

  defp clear_pending(state) do
    pending = state.pending

    if pending[:monitor], do: Process.demonitor(pending.monitor, [:flush])
    if pending[:task] && Process.alive?(pending.task), do: Process.exit(pending.task, :kill)
    if get_in(pending, [:listener, :socket]), do: :gen_tcp.close(pending.listener.socket)

    %{state | pending: nil, login: @idle_login}
  end

  defp redirect_uri(%{listener: %{redirect_uri: redirect_uri}}), do: redirect_uri
  defp redirect_uri(_pending), do: "http://localhost:#{@browser_port}/auth/callback"

  defp persist_credential(path, credential) do
    with {:ok, payload} <- credential_payload(path) do
      atomic_write(
        path,
        JSON.encode!(Map.put(payload, @provider_key, reject_nil_values(credential)))
      )
    end
  rescue
    error -> {:error, error}
  end

  defp credential_payload(path) do
    case File.read(path) do
      {:ok, json} ->
        case JSON.decode(json) do
          {:ok, value} when is_map(value) -> {:ok, value}
          _invalid -> {:error, :credential_file_corrupt}
        end

      {:error, :enoent} ->
        {:ok, %{}}

      {:error, reason} ->
        {:error, {:credential_read_failed, reason}}
    end
  end

  defp delete_credential(path) do
    case File.read(path) do
      {:ok, json} ->
        with {:ok, payload} when is_map(payload) <- JSON.decode(json) do
          atomic_write(path, JSON.encode!(Map.delete(payload, @provider_key)))
        else
          _invalid -> {:error, :credential_file_corrupt}
        end

      {:error, :enoent} ->
        :ok

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp read_credentials(path) do
    with {:ok, json} <- File.read(path),
         {:ok, payload} when is_map(payload) <- JSON.decode(json),
         credential when is_map(credential) <- payload[@provider_key] do
      {:ok, credential}
    else
      {:error, :enoent} -> {:error, :not_found}
      _missing_or_invalid -> {:error, :not_found}
    end
  rescue
    _error -> {:error, :not_found}
  end

  defp atomic_write(path, contents) do
    temporary = path <> ".tmp-" <> random_token(9)

    result =
      with :ok <- ensure_private_parent(path),
           {:ok, device} <-
             :file.open(String.to_charlist(temporary), [:write, :binary, :raw, :exclusive]),
           :ok <- :file.write(device, contents),
           :ok <- :file.sync(device),
           :ok <- :file.close(device),
           :ok <- File.chmod(temporary, 0o600),
           :ok <- File.rename(temporary, path),
           :ok <- sync_directory(Path.dirname(path)) do
        :ok
      end

    if result != :ok, do: File.rm(temporary)
    result
  rescue
    error -> {:error, error}
  end

  defp ensure_private_parent(path) do
    directory = Path.dirname(path)

    with :ok <- File.mkdir_p(directory),
         :ok <- File.chmod(directory, 0o700) do
      :ok
    end
  end

  defp sync_directory(directory) do
    with {:ok, device} <- :file.open(String.to_charlist(directory), [:read, :raw, :directory]),
         :ok <- :file.sync(device),
         :ok <- :file.close(device) do
      :ok
    end
  end

  defp data_dir do
    case Application.get_env(:ouroboros, :data_dir) do
      path when is_binary(path) and path != "" ->
        Path.expand(path)

      _unset ->
        Ouroboros.DataDir.resolve!(
          System.get_env("OUROBOROS_DATA_DIR"),
          System.get_env("XDG_DATA_HOME"),
          System.get_env("HOME")
        )
    end
  end

  defp jwt_claims(token) when is_binary(token) do
    with [_header, payload, _signature] <- String.split(token, "."),
         {:ok, json} <- Base.url_decode64(payload, padding: false),
         {:ok, claims} when is_map(claims) <- JSON.decode(json) do
      claims
    else
      _invalid -> nil
    end
  rescue
    _error -> nil
  end

  defp jwt_claims(_token), do: nil

  defp first_org(%{"organizations" => [%{"id" => id} | _]}) when is_binary(id), do: id
  defp first_org(_claims), do: nil

  defp retry_after_ms(headers) when is_list(headers) do
    headers
    |> Enum.find_value(fn
      {key, value} when key in ["retry-after-ms", "Retry-After-Ms"] ->
        parse_integer(value)

      {key, value} when key in ["retry-after", "Retry-After"] ->
        case parse_integer(value) do
          seconds when is_integer(seconds) -> seconds * 1_000
          _invalid -> nil
        end

      _header ->
        nil
    end)
  end

  defp retry_after_ms(_headers), do: nil

  defp secure_equal?(left, right)
       when is_binary(left) and is_binary(right) and byte_size(left) == byte_size(right),
       do: :crypto.hash_equals(left, right)

  defp secure_equal?(_left, _right), do: false

  defp parse_integer(value) when is_integer(value), do: value

  defp parse_integer(value) when is_binary(value) do
    case Integer.parse(value) do
      {number, ""} -> number
      _invalid -> nil
    end
  end

  defp parse_integer(_value), do: nil

  defp reject_nil_values(map), do: Map.reject(map, fn {_key, value} -> is_nil(value) end)
  defp present?(value), do: is_binary(value) and String.trim(value) != ""
  defp random_id(prefix), do: prefix <> "_" <> random_token(12)

  defp random_token(bytes),
    do: :crypto.strong_rand_bytes(bytes) |> Base.url_encode64(padding: false)

  defp safe_error(body) when is_map(body) do
    body["error"] || body["message"] || "provider refused the request"
  end

  defp safe_error(body) when is_binary(body), do: String.slice(body, 0, 500)
  defp safe_error(_body), do: "provider refused the request"
  defp describe(reason) when is_binary(reason), do: String.slice(reason, 0, 500)
  defp describe(reason), do: inspect(reason, limit: 20, printable_limit: 500)
end
