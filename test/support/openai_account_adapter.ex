defmodule Ouroboros.Test.OpenAIAccountAdapter do
  @moduledoc false

  # Tests may make the account boundary return one failure shape to every method.
  @failure_key :openai_account_failure

  def read do
    answer(
      {:ok,
       %{
         "account" => nil,
         "requiresOpenaiAuth" => true,
         "login" => %{
           "status" => "idle",
           "loginId" => nil,
           "flow" => nil,
           "error" => nil
         }
       }}
    )
  end

  def login(:browser) do
    answer(
      {:ok,
       %{
         "type" => "chatgpt",
         "loginId" => "browser-login",
         "authUrl" => "https://auth.openai.com/oauth/authorize"
       }}
    )
  end

  def login(:device_code) do
    answer(
      {:ok,
       %{
         "type" => "chatgptDeviceCode",
         "loginId" => "device-login",
         "verificationUrl" => "https://auth.openai.com/codex/device",
         "userCode" => "ABCD-1234"
       }}
    )
  end

  def complete(_login_id, _code, _state), do: answer({:ok, %{}})

  def cancel(login_id), do: answer({:ok, %{"cancelled" => login_id}})
  def logout, do: answer({:ok, %{}})

  @doc "Makes every method answer `failure` until `succeed/0` is called."
  def fail(failure), do: Application.put_env(:ouroboros, @failure_key, failure)

  @doc "Returns this adapter to answering successfully."
  def succeed, do: Application.delete_env(:ouroboros, @failure_key)

  defp answer(success) do
    case Application.get_env(:ouroboros, @failure_key) do
      nil -> success
      failure -> failure
    end
  end
end
