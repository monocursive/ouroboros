# Loaded only by Playwright, after the test application boots.
Application.put_env(:ouroboros, :native_model_module, Ouroboros.Test.BrowserModel)
Application.put_env(:ouroboros, :native_model, "openai_codex:fixture-astra")
Application.put_env(:ouroboros, :account_adapter, Ouroboros.Test.BrowserAccount)

# Browser fixtures never consult an operator's account or API-key environment.
# Account readiness is a synthetic projection for the scripted model, not a login.
data = Application.fetch_env!(:ouroboros, :data_dir)

paths = [
  oauth_file: Path.join(data, "browser-absent-oauth.json"),
  anthropic_api_key_file: Path.join(data, "browser-absent-anthropic.key"),
  xai_api_key_file: Path.join(data, "browser-absent-xai.key"),
  grok_auth_file: Path.join(data, "browser-absent-grok-auth.json")
]

Enum.each(paths, fn {key, path} -> Application.put_env(:ouroboros, key, path) end)

Enum.each(
  Enum.uniq(
    Enum.map(ReqLLM.Providers.list(), &ReqLLM.Keys.env_var_name/1) ++
      ["OUROBOROS_NATIVE_MODEL", "ANTHROPIC_WORKSPACE_ID"]
  ),
  &System.delete_env/1
)

:sys.replace_state(Ouroboros.Provider.OpenAIAuth, &%{&1 | credential_path: paths[:oauth_file]})
File.mkdir_p!(Path.join([File.cwd!(), "_build", "playwright-workspace"]))
Ouroboros.Test.BrowserHistory.seed()

# Fleet onboarding, slice 6. `test/browser/devices.spec.js` drives the Deploy drawer, which
# needs `fleet.devices` to answer and `fleet.deployment.prepare` to fork something. Both are
# fakes inside this BEAM; no SSH client, no network and no credential store is involved.
{:ok, _fleet} = Ouroboros.Test.BrowserFleet.seed()

for client <- ["desktop", "mobile"] do
  {:ok, _} = Ouroboros.Test.BrowserHistoryReplay.start("browser-history-replay-#{client}")
end
