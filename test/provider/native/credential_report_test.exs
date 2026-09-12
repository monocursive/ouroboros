defmodule Ouroboros.Provider.Native.CredentialReportTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Model.ReqLLM
  alias Ouroboros.Runtime.SafeStatus

  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    paths = [
      oauth_file: Path.join(dir, "synthetic-oauth.json"),
      anthropic_api_key_file: Path.join(dir, "absent-anthropic.key"),
      xai_api_key_file: Path.join(dir, "absent-xai.key")
    ]

    previous = Enum.map(paths, fn {key, _} -> {key, Application.fetch_env(:ouroboros, key)} end)

    variables =
      (Enum.map(Elixir.ReqLLM.Providers.list(), &Elixir.ReqLLM.Keys.env_var_name/1) ++
         ["ANTHROPIC_API_KEY", "ANTHROPIC_WORKSPACE_ID", "XAI_API_KEY"])
      |> Enum.uniq()

    environment = Enum.map(variables, &{&1, System.get_env(&1)})

    on_exit(fn ->
      Enum.each(previous, fn
        {key, {:ok, value}} -> Application.put_env(:ouroboros, key, value)
        {key, :error} -> Application.delete_env(:ouroboros, key)
      end)

      Enum.each(environment, fn
        {key, nil} -> System.delete_env(key)
        {key, value} -> System.put_env(key, value)
      end)
    end)

    Enum.each(paths, fn {key, path} -> Application.put_env(:ouroboros, key, path) end)
    Enum.each(variables, &System.delete_env/1)
    %{path: paths[:oauth_file]}
  end

  test "Codex OAuth is the only Codex report row and reaches safe status", %{path: path} do
    # Synthetic local bytes only: no sign-in, credential import or model call.
    File.write!(path, JSON.encode!(%{"openai-codex" => %{"access" => "synthetic-access-canary"}}))
    File.chmod!(path, 0o600)
    rows = Enum.filter(ReqLLM.credential_report(), &(&1.provider == :openai_codex))

    assert rows == [
             %{
               provider: :openai_codex,
               env: "OUROBOROS_OAUTH_FILE",
               present: true,
               source: :stored
             }
           ]

    assert {:ok, status} =
             SafeStatus.session(%{owner: "fixture", observed_at_ms: 1, credentials: rows}, 1)

    assert status["credentials"] == [
             %{"provider" => "openai_codex", "present" => true, "source" => "managed"}
           ]

    refute JSON.encode!(status) =~ "synthetic-access-canary"
    refute JSON.encode!(status) =~ path
  end

  test "missing synthetic OAuth still has one row, not a generic Codex API-key row" do
    assert [%{env: "OUROBOROS_OAUTH_FILE", present: false}] =
             Enum.filter(ReqLLM.credential_report(), &(&1.provider == :openai_codex))
  end
end
