defmodule Ouroboros.Web.Live.AccountConnection do
  @moduledoc "Device-code login state shared by account cards on session and settings pages."
  import Phoenix.Component, only: [assign: 3]
  alias Ouroboros.Web.Live.NewSession

  def connect(socket, provider, call, interval) do
    {prefix, _account, login, _polling, _message} = fields(provider)
    # The browser may be remote from the daemon. Always use device code for ChatGPT.
    params = if provider == :chatgpt, do: %{"flow" => "device_code"}, else: %{}

    case call.(socket, prefix <> ".login.start", params) do
      {:ok, reply} when is_map(reply) ->
        value = %{
          login_id: reply["loginId"],
          url: reply["verificationUrl"] || if(provider == :chatgpt, do: reply["authUrl"]),
          code: reply["userCode"]
        }

        {:ok, socket |> assign(login, value) |> maybe_poll(provider, interval)}

      refused ->
        {:error, assign(socket, :refusal, NewSession.refusal(refused))}
    end
  end

  def cancel(socket, provider, call) do
    {prefix, _account, login, _polling, _message} = fields(provider)

    case socket.assigns[login] do
      %{login_id: id} when is_binary(id) ->
        _ = call.(socket, prefix <> ".login.cancel", %{"login_id" => id})

      _none ->
        :ok
    end

    socket |> assign(login, nil) |> read(provider, call)
  end

  def read(socket, provider, call) do
    {prefix, account, _login, _polling, _message} = fields(provider)

    case call.(socket, prefix <> ".read", %{}) do
      {:ok, value} when is_map(value) -> assign(socket, account, value)
      _refused -> socket
    end
  end

  def poll(socket, provider, call, interval) do
    {_prefix, account, login, polling, _message} = fields(provider)
    socket = socket |> assign(polling, false) |> read(provider, call)

    socket =
      if settled?(socket.assigns[account], provider), do: assign(socket, login, nil), else: socket

    maybe_poll(socket, provider, interval)
  end

  def maybe_poll(socket, provider, interval) do
    {_prefix, account, login, polling, message} = fields(provider)

    card =
      case provider do
        :chatgpt -> NewSession.account_card(socket.assigns[account], socket.assigns[login])
        :grok -> NewSession.grok_account_card(socket.assigns[account], socket.assigns[login])
      end

    if card.state == :waiting and not socket.assigns[polling] do
      Process.send_after(self(), message, interval)
      assign(socket, polling, true)
    else
      socket
    end
  end

  defp settled?(%{"login" => %{"status" => "pending"}}, _provider), do: false
  defp settled?(%{"login" => %{"status" => "starting"}}, :grok), do: false
  defp settled?(read, _provider), do: is_map(read)

  defp fields(:chatgpt), do: {"account", :account, :login, :polling_account?, :poll_account}

  defp fields(:grok),
    do: {"grok.account", :grok_account, :grok_login, :polling_grok_account?, :poll_grok_account}
end
