defmodule Ouroboros.Provider.Native.OpenAIRefreshTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Model.ReqLLM, as: Model
  alias Ouroboros.Provider.OpenAIAuth

  @moduletag :tmp_dir
  @moduletag capture_log: true

  setup %{tmp_dir: dir} do
    Ouroboros.Test.FirstUseIsolation.setup(dir)
    %{path: OpenAIAuth.credential_path()}
  end

  for status <- [401, 500] do
    test "a real request-build failure for refresh HTTP #{status} updates readiness appropriately",
         %{
           path: path
         } do
      status = unquote(status)

      File.write!(
        path,
        JSON.encode!(%{
          "openai-codex" => %{
            "access" => "synthetic-access",
            "refresh" => "synthetic-refresh",
            "expires" => 1
          }
        })
      )

      original = File.read!(path)
      parent = self()

      transport = fn conn ->
        send(parent, :refresh_requested)

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(status, JSON.encode!(%{"error" => %{"message" => "SECRET"}}))
      end

      request = %{
        model: "openai_codex:gpt-5.6-sol",
        messages: [%{role: :user, content: "hello"}],
        tools: []
      }

      assert {:error, error} =
               Model.stream(request,
                 oauth_http_options: [plug: transport, retry: false],
                 base_url: "http://127.0.0.1:1"
               )

      assert_receive :refresh_requested
      assert File.read!(path) == original
      assert OpenAIAuth.credential_status() == if(status == 401, do: :invalid, else: :present)
      assert {:ok, account} = OpenAIAuth.read()
      assert account["requiresOpenaiAuth"] == (status == 401)
      refute Model.format_error(error) =~ "SECRET"

      if status == 401 do
        assert Model.format_error(error) =~ "provider_code=openai_oauth_refresh_rejected"
        assert Model.format_error(error) =~ "sign in to OpenAI again"
      else
        refute Model.format_error(error) =~ "sign in to OpenAI again"
      end
    end
  end
end
