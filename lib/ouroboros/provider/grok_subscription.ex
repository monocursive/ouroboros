defmodule Ouroboros.Provider.GrokSubscription do
  @moduledoc """
  Direct subscription inference using the sign-in owned by Grok.

  `grok:<model>` opts into this connection. We read the first-party OAuth entry on each
  request, never copy or refresh its rotating tokens, and never fall back to an API key.
  Run `grok login` on the runtime's computer to establish or renew the sign-in. Grok is
  only needed for authentication; Ouroboros owns the conversation and executes tools.

  Protocol reference: xai-org/grok-build, crates/codegen/xai-grok-shell/README.md,
  "Using auth.json for API Access", and xai-grok-login/src/config.rs.
  """

  @issuer "https://auth.x.ai"
  @client_id "b1a00492-073a-47ea-816f-4c329264a828"
  @entry @issuer <> "::" <> @client_id
  @base_url "https://cli-chat-proxy.grok.com/v1"
  # The proxy gates its wire contract on a Grok client compatibility version. Keep our
  # own identity in client-identifier/User-Agent; this pins the tested protocol baseline.
  @protocol_version "1.0.4"
  @max_bytes 65_536
  @env "OUROBOROS_GROK_AUTH_FILE"

  def credential_path do
    (Application.get_env(:ouroboros, :grok_auth_file) || System.get_env(@env) ||
       Path.join(System.user_home!(), ".grok/auth.json"))
    |> Path.expand()
  end

  @doc "Non-secret local credential observation; not a subscription entitlement check."
  def status do
    state =
      case fetch() do
        {:ok, _token} -> :present
        {:error, :absent} -> :absent
        {:error, :unavailable} -> :unavailable
        {:error, _} -> :invalid
      end

    %{
      provider: :grok,
      env: @env,
      present: state == :present,
      credential_state: state,
      source: if(state == :present, do: :stored)
    }
  end

  @doc false
  def fetch do
    with {:ok, bytes} <- read_private(credential_path()),
         {:ok, document} when is_map(document) <- JSON.decode(bytes),
         {:ok, credential} <- select_credential(document),
         :ok <- validate(credential) do
      {:ok, credential["key"]}
    else
      {:error, reason} when reason in [:absent, :unavailable, :expired] -> {:error, reason}
      _ -> {:error, :invalid}
    end
  rescue
    _ -> {:error, :unavailable}
  end

  defp read_private(path) do
    case File.lstat(path) do
      {:ok, %{type: :regular, size: size, mode: mode}} when size <= @max_bytes ->
        if Bitwise.band(mode, 0o077) == 0, do: bounded_read(path), else: {:error, :invalid}

      {:error, :enoent} ->
        {:error, :absent}

      {:ok, _} ->
        {:error, :invalid}

      {:error, _} ->
        {:error, :unavailable}
    end
  end

  defp bounded_read(path) do
    case File.open(path, [:read, :binary], fn file -> IO.binread(file, @max_bytes + 1) end) do
      {:ok, bytes} when is_binary(bytes) and byte_size(bytes) <= @max_bytes -> {:ok, bytes}
      {:error, _} -> {:error, :unavailable}
      _ -> {:error, :invalid}
    end
  end

  defp select_credential(document) do
    case Map.fetch(document, @entry) do
      {:ok, credential} when is_map(credential) -> {:ok, credential}
      :error -> {:error, :absent}
      _ -> {:error, :invalid}
    end
  end

  defp validate(%{
         "auth_mode" => "oidc",
         "oidc_issuer" => @issuer,
         "oidc_client_id" => @client_id,
         "key" => token,
         "expires_at" => expires
       })
       when is_binary(token) and byte_size(token) > 0 and is_binary(expires) do
    with false <- String.contains?(token, [" ", "\t", "\r", "\n", "\0"]),
         {:ok, expiry, _offset} <- DateTime.from_iso8601(expires) do
      if DateTime.diff(expiry, DateTime.utc_now(), :second) > 60,
        do: :ok,
        else: {:error, :expired}
    else
      _ -> {:error, :invalid}
    end
  end

  defp validate(_), do: {:error, :invalid}

  @doc "Maps only the explicit subscription prefix to the xAI model metadata/encoder."
  def api_model("grok:" <> model), do: "xai:" <> model
  def api_model(model), do: model

  @doc false
  def transport("grok:" <> model, options) do
    with true <- model != "" and not String.contains?(model, ["\r", "\n", "\0"]),
         {:ok, token} <- fetch() do
      version = Application.spec(:ouroboros, :vsn) |> to_string()

      # Endpoint and headers are owned by this connection. Generic endpoint overrides,
      # API keys, custom headers and redirects cannot change the token's destination.
      headers = [
        {"x-xai-token-auth", "xai-grok-cli"},
        {"x-grok-model-override", model},
        {"x-grok-client-identifier", "ouroboros"},
        {"x-grok-client-version", @protocol_version},
        {"user-agent", "ouroboros/" <> version}
      ]

      http =
        options
        |> Keyword.get(:req_http_options, [])
        |> normalize_http_options()
        |> Keyword.drop([:headers, :auth, :base_url, :url, :params])
        |> Keyword.put(:headers, headers)
        |> Keyword.put(:redirect, false)

      options =
        options
        |> Keyword.drop([:auth_file, :oauth_file, :access_token, :api_key, :provider_options])
        |> Keyword.put(:api_key, token)
        |> Keyword.put(:base_url, @base_url)
        |> Keyword.put(:req_http_options, http)
        |> Keyword.put(:provider_options, xai_api: :chat)

      {:ok, api_model("grok:" <> model), options}
    else
      false -> {:error, {:grok_subscription, :invalid_model}}
      {:error, reason} -> {:error, {:grok_subscription, reason}}
    end
  end

  def transport(model, options), do: {:ok, model, options}

  defp normalize_http_options(options) when is_map(options), do: Map.to_list(options)
  defp normalize_http_options(options), do: options
end
