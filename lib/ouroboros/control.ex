defmodule Ouroboros.Control do
  @moduledoc """
  Public facade for the durable autonomous planning and evaluation loop.
  """

  alias Ouroboros.Control.{Run, Server}

  @doc "Submits or idempotently resumes a high-level objective."
  @spec submit(String.t(), keyword()) :: {:ok, Run.t()} | {:error, term()}
  def submit(objective, opts \\ [])

  def submit(objective, opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      id = Keyword.get_lazy(opts, :id, &Jido.Signal.ID.generate!/0)
      max_revisions = Keyword.get(opts, :max_revisions, 2)
      server = Keyword.get(opts, :server, Server)
      safe_call(fn -> Server.submit(server, id, objective, max_revisions) end)
    else
      {:error, :invalid_options}
    end
  end

  def submit(_objective, _opts), do: {:error, :invalid_options}

  @doc "Returns durable state for one objective."
  def get(id, server \\ Server), do: safe_call(fn -> Server.get(server, id) end)

  @doc "Lists durable objective runs."
  def list(server \\ Server), do: safe_call(fn -> Server.list(server) end)

  @doc "Immediately reconciles one run with its orchestration plan."
  def reconcile(id, server \\ Server), do: safe_call(fn -> Server.reconcile(server, id) end)

  @doc "Durably requests cancellation before cancelling the orchestration plan."
  @spec cancel(String.t(), keyword()) :: {:ok, Run.t()} | {:error, term()}
  def cancel(id, opts \\ [])

  def cancel(id, opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      server = Keyword.get(opts, :server, Server)
      reason = Keyword.get(opts, :reason, :cancelled)
      safe_call(fn -> Server.cancel(server, id, reason) end)
    else
      {:error, :invalid_options}
    end
  end

  def cancel(_id, _opts), do: {:error, :invalid_options}

  defp safe_call(fun) do
    fun.()
  catch
    :exit, _reason -> {:error, :control_disabled_or_unavailable}
  end
end
