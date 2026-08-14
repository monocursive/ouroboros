defmodule Ouroboros.Test.CodexAccountAdapter do
  @moduledoc false

  def read do
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
  end

  def login(:browser) do
    {:ok,
     %{
       "type" => "chatgpt",
       "loginId" => "browser-login",
       "authUrl" => "https://chatgpt.com/auth/ouroboros"
     }}
  end

  def login(:device_code) do
    {:ok,
     %{
       "type" => "chatgptDeviceCode",
       "loginId" => "device-login",
       "verificationUrl" => "https://auth.openai.com/codex/device",
       "userCode" => "ABCD-1234"
     }}
  end

  def cancel(login_id), do: {:ok, %{"cancelled" => login_id}}
  def logout, do: {:ok, %{}}
end
