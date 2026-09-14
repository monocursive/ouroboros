defmodule Ouroboros.Test.FirstUseIsolation do
  @moduledoc false

  # Synchronous tests only. Pin every managed credential and registered provider
  # variable before any connected page invokes provider/account methods.
  def setup(dir, model_module \\ Ouroboros.Test.BrowserModel) do
    config = [
      oauth_file: Path.join(dir, "absent-oauth.json"),
      anthropic_api_key_file: Path.join(dir, "anthropic.key"),
      xai_api_key_file: Path.join(dir, "xai.key"),
      grok_auth_file: Path.join(dir, "absent-grok-auth.json"),
      account_adapter: Ouroboros.Test.OpenAIAccountAdapter,
      openai_account_failure: nil,
      anthropic_key_adapter: Ouroboros.Provider.AnthropicKey,
      xai_key_adapter: Ouroboros.Provider.XAIKey,
      workspace_allowed_roots: [dir],
      native_model_module: model_module,
      native_model: "openai_codex:gpt-5.6-sol"
    ]

    old = Enum.map(config, fn {k, _} -> {k, Application.fetch_env(:ouroboros, k)} end)

    variables =
      Enum.uniq(
        Enum.map(ReqLLM.Providers.list(), &ReqLLM.Keys.env_var_name/1) ++
          [
            "OUROBOROS_NATIVE_MODEL",
            "ANTHROPIC_WORKSPACE_ID",
            "OUROBOROS_OAUTH_FILE",
            "OUROBOROS_ANTHROPIC_API_KEY_FILE",
            "OUROBOROS_XAI_API_KEY_FILE",
            "OUROBOROS_GROK_AUTH_FILE"
          ]
      )

    env = Enum.map(variables, &{&1, System.get_env(&1)})
    account = Ouroboros.Provider.OpenAIAuth
    previous_account_path = :sys.get_state(account).credential_path
    :sys.replace_state(account, &%{&1 | credential_path: config[:oauth_file]})

    ExUnit.Callbacks.on_exit(fn ->
      :sys.replace_state(account, &%{&1 | credential_path: previous_account_path})

      Enum.each(old, fn
        {k, {:ok, v}} -> Application.put_env(:ouroboros, k, v)
        {k, :error} -> Application.delete_env(:ouroboros, k)
      end)

      Enum.each(env, fn
        {k, nil} -> System.delete_env(k)
        {k, v} -> System.put_env(k, v)
      end)
    end)

    Enum.each(config, fn {k, v} -> Application.put_env(:ouroboros, k, v) end)
    Enum.each(variables, &System.delete_env/1)
    :ok
  end
end
