defmodule Ouroboros.Test.CodexAccountAdapter do
  @moduledoc false

  # The real boundary answers four error shapes as well as four success shapes, and the
  # gateway maps each of them differently. `:codex_account_failure` is how a test asks
  # this adapter for the failing half; absent, every method succeeds as before.
  @failure_key :codex_account_failure

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
         "authUrl" => "https://chatgpt.com/auth/ouroboros"
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
