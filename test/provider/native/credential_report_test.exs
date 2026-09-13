defmodule Ouroboros.Provider.Native.CredentialReportTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Model.ReqLLM
  alias Ouroboros.Runtime.SafeStatus

  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    Ouroboros.Test.FirstUseIsolation.setup(dir)
    %{path: Application.fetch_env!(:ouroboros, :oauth_file)}
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
               credential_state: :present,
               source: :stored
             }
           ]

    assert {:ok, status} =
             SafeStatus.session(%{owner: "fixture", observed_at_ms: 1, credentials: rows}, 1)

    assert status["credentials"] == [
             %{
               "provider" => "openai_codex",
               "present" => true,
               "source" => "managed",
               "credential_state" => "present"
             }
           ]

    refute JSON.encode!(status) =~ "synthetic-access-canary"
    refute JSON.encode!(status) =~ path
  end

  test "missing synthetic OAuth still has one row, not a generic Codex API-key row" do
    assert [%{env: "OUROBOROS_OAUTH_FILE", present: false}] =
             Enum.filter(ReqLLM.credential_report(), &(&1.provider == :openai_codex))
  end

  test "source states survive account and safe projections without claiming acceptance", %{
    path: path
  } do
    auth = Ouroboros.Provider.OpenAIAuth
    server = start_supervised!({auth, name: nil, credential_path: path})

    for {content, state} <- [
          {"{}", :absent},
          {"[]", :invalid},
          {"not json SECRET", :invalid},
          {JSON.encode!(%{"openai-codex" => "SECRET"}), :invalid},
          {JSON.encode!(%{"openai-codex" => %{"access" => 42}}), :invalid},
          {JSON.encode!(%{"openai-codex" => %{"access" => "  ", "refresh" => ""}}), :absent},
          {JSON.encode!(%{"openai-codex" => %{"refresh" => "SYNTHETIC_SECRET", "expires" => 0}}),
           :present},
          {String.duplicate("é", 40_000), :invalid}
        ] do
      File.write!(path, content)
      assert auth.credential_status() == state
      assert auth.credential_present?() == (state == :present)
      [row] = Enum.filter(ReqLLM.credential_report(), &(&1.provider == :openai_codex))
      assert row.credential_state == state
      assert is_boolean(row.present)

      assert {:ok, status} =
               SafeStatus.session(%{owner: "fixture", observed_at_ms: 1, credentials: [row]}, 1)

      assert hd(status["credentials"])["present"] ==
               if(state == :invalid, do: nil, else: state == :present)

      assert {:ok, account} = auth.read(server)
      assert account["credentialState"] == Atom.to_string(state)

      assert Ouroboros.Web.Live.NewSession.account_card(account, nil).usable? ==
               (state == :present)

      refute JSON.encode!([account, status]) =~ "SECRET"
      refute JSON.encode!([account, status]) =~ path
    end

    File.rm!(path)
    assert auth.credential_status() == :absent
    File.mkdir!(path)
    assert auth.credential_status() == :unavailable
    [row] = Enum.filter(ReqLLM.credential_report(), &(&1.provider == :openai_codex))
    assert row.present == false

    assert {:ok, status} =
             SafeStatus.session(%{owner: "fixture", observed_at_ms: 1, credentials: [row]}, 1)

    assert hd(status["credentials"])["present"] == nil
    assert hd(status["credentials"])["credential_state"] == "unavailable"
    assert {:ok, account} = auth.read(server)
    assert account["credentialState"] == "unavailable"
    assert Ouroboros.Web.Live.NewSession.account_card(account, nil).state == :unavailable
  end
end
