defmodule Ouroboros.Test.GrokAccountAdapter do
  @moduledoc false

  @state_key :grok_account_test_state
  @failure_key :grok_account_test_failure

  def read do
    answer(
      {:ok,
       case Application.get_env(:ouroboros, @state_key, :disconnected) do
         :connected ->
           %{
             "account" => %{"type" => "grok_subscription", "label" => "Grok subscriber"},
             "requiresGrokAuth" => false,
             "login" => idle()
           }

         :pending ->
           %{
             "account" => nil,
             "requiresGrokAuth" => true,
             "login" => %{"status" => "pending", "loginId" => "grok-device", "error" => nil}
           }

         _disconnected ->
           %{
             "account" => nil,
             "requiresGrokAuth" => true,
             "login" => idle()
           }
       end}
    )
  end

  def login do
    Application.put_env(:ouroboros, @state_key, :pending)

    answer(
      {:ok,
       %{
         "type" => "grokDeviceCode",
         "loginId" => "grok-device",
         "verificationUrl" => "https://auth.x.ai/device?user_code=WXYZ-5678",
         "userCode" => "WXYZ-5678"
       }}
    )
  end

  def cancel(login_id) do
    Application.put_env(:ouroboros, @state_key, :disconnected)
    answer({:ok, %{"cancelled" => login_id}})
  end

  def connected, do: Application.put_env(:ouroboros, @state_key, :connected)
  def disconnected, do: Application.put_env(:ouroboros, @state_key, :disconnected)
  def fail(failure), do: Application.put_env(:ouroboros, @failure_key, failure)

  def reset do
    Application.delete_env(:ouroboros, @state_key)
    Application.delete_env(:ouroboros, @failure_key)
  end

  defp idle, do: %{"status" => "idle", "loginId" => nil, "error" => nil}

  defp answer(success) do
    case Application.get_env(:ouroboros, @failure_key) do
      nil -> success
      failure -> failure
    end
  end
end
