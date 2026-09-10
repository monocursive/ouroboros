defmodule Ouroboros.Web.Live.AccountConnection do
  @moduledoc """
  Device-code login state shared by the ChatGPT account card on the session and settings
  pages.

  One account, because there is one subscription this runtime connects: the ChatGPT one
  the native `openai_codex:` model lane calls through. The vendor-CLI logins this module
  used to dispatch over went with the vendor CLIs.
  """
  import Phoenix.Component, only: [assign: 3]
  alias Ouroboros.Web.Live.NewSession

  def connect(socket, call, interval) do
    # The browser may be remote from the daemon. Always use device code.
    case call.(socket, "account.login.start", %{"flow" => "device_code"}) do
      {:ok, reply} when is_map(reply) ->
        value = %{
          login_id: reply["loginId"],
          url: reply["verificationUrl"] || reply["authUrl"],
          code: reply["userCode"]
        }

        {:ok, socket |> assign(:login, value) |> maybe_poll(interval)}

      refused ->
        {:error, assign(socket, :refusal, NewSession.refusal(refused))}
    end
  end

  def cancel(socket, call) do
    case socket.assigns[:login] do
      %{login_id: id} when is_binary(id) ->
        _ = call.(socket, "account.login.cancel", %{"login_id" => id})

      _none ->
        :ok
    end

    socket |> assign(:login, nil) |> read(call)
  end

  def read(socket, call) do
    case call.(socket, "account.read", %{}) do
      {:ok, value} when is_map(value) -> assign(socket, :account, value)
      _refused -> socket
    end
  end

  def poll(socket, call, interval) do
    socket = socket |> assign(:polling_account?, false) |> read(call)

    socket =
      if settled?(socket.assigns[:account]), do: assign(socket, :login, nil), else: socket

    maybe_poll(socket, interval)
  end

  def maybe_poll(socket, interval) do
    card = NewSession.account_card(socket.assigns[:account], socket.assigns[:login])

    if card.state == :waiting and not socket.assigns[:polling_account?] do
      Process.send_after(self(), :poll_account, interval)
      assign(socket, :polling_account?, true)
    else
      socket
    end
  end

  defp settled?(%{"login" => %{"status" => "pending"}}), do: false
  defp settled?(read), do: is_map(read)
end
