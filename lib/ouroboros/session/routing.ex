defmodule Ouroboros.Session.Routing do
  @moduledoc "Owner-node dispatch and transport budgets for session APIs."
  @default_call_timeout 30_000
  @remote_margin_ms 5_000
  def route(owner, module, function, arguments, timeout \\ :infinity) do
    cond do
      owner == node() -> apply(module, function, arguments)
      owner not in Node.list() -> {:error, {:owner_unavailable, owner}}
      true -> :erpc.call(owner, module, function, arguments, timeout)
    end
  catch
    :error, {:erpc, reason} when reason in [:noconnection, :timeout] ->
      {:error, {:owner_unavailable, owner, reason}}

    kind, reason ->
      {:error, {:remote_call_failed, owner, kind, reason}}
  end

  def call_timeout do
    case Application.get_env(:ouroboros, :session_call_timeout, @default_call_timeout) do
      :infinity -> :infinity
      timeout when is_integer(timeout) and timeout > 0 -> timeout
      _invalid -> @default_call_timeout
    end
  end

  def transport_timeout(:infinity), do: :infinity
  def transport_timeout(timeout) when is_integer(timeout), do: timeout + @remote_margin_ms
  def transport_timeout(_timeout), do: call_timeout()
end
