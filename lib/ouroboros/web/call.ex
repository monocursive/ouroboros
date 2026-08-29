defmodule Ouroboros.Web.Call do
  @moduledoc """
  The one way the web surface reaches the runtime.

  Every page, LiveView, and controller in `Ouroboros.Web` goes through this module and
  none of them calls a plane directly. That is the whole of the authorization design: the
  gateway already owns the decision of what a method costs and who may run it, its answer
  lives in one table, and a second surface that consulted a different table would be a
  second policy nobody remembers to update.

  The seam is three public functions the `Conn` already uses:

      with {:ok, entry} <- Methods.fetch(method),
           true <- Methods.permits?(scope, entry) do
        Task.Supervisor.async_nolink(Ouroboros.Web.TaskSupervisor,
          fn -> Methods.invoke(method, params) end)
      end

  No refactor of `Ouroboros.Gateway.Conn` was needed to share them, and none was wanted:
  the connection owns a socket's lifecycle and a queue, which a browser request has no
  equivalent of.

  ## Scope is the endpoint's, not the session's

  `scope` is a property of the endpoint, fixed at boot from configuration, exactly as it
  is for a listener. A session cookie never carries it — a cookie minted while the
  endpoint served `:operate` would otherwise still claim that authority after a restart
  at `:read`, which is a privilege bug wearing a cache's clothes.

  ## The timeout answer is the honest one

  The ceiling is the method table's, so a browser and a terminal client wait the same
  length of time for the same verb. When it expires this says what it can honestly say:
  the surface stopped waiting, the runtime did not stop working. Methods the table marks
  `outcome: :unknown` carry that marker through, because for those the difference between
  "did not happen" and "happened and was not reported" is the operator's whole question.

  ## What gets logged

  One line per operate method, naming the call and not its contents. An objective, a
  prompt, or a workspace path in a log is a payload the operator did not choose to write
  down; the digest is enough to correlate a log entry with a request that can be
  reproduced. Same shape as the gateway's audit line, with the connection's peer replaced
  by the authenticated web session id.
  """

  require Logger

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Gateway.Wire

  @type scope :: :read | :operate
  @type result ::
          {:ok, term()}
          | {:error, integer(), String.t()}
          | {:error, integer(), String.t(), map()}

  @doc """
  Runs one gateway method on behalf of an authenticated browser session.

  Options: `:session` (the authenticated session id, for the audit line) and
  `:task_supervisor` (defaults to `Ouroboros.Web.TaskSupervisor`).

  Returns exactly what `Ouroboros.Gateway.Methods.invoke/2` returns, or the same error
  shapes the gateway would have produced for a method this build does not serve, a method
  this scope may not run, a handler that crashed, or a ceiling that expired.
  """
  @spec call(scope(), String.t(), map(), keyword()) :: result()
  def call(scope, method, params \\ %{}, opts \\ [])

  def call(scope, method, params, opts)
      when scope in [:read, :operate] and is_binary(method) and is_map(params) and is_list(opts) do
    case Methods.fetch(method) do
      {:ok, entry} ->
        if Methods.permits?(scope, entry) do
          _ = audit(method, params, entry, opts)
          run(method, params, entry, opts)
        else
          {:error, Methods.code(:scope_denied),
           "#{method} mutates the runtime and this endpoint was started with " <>
             "OUROBOROS_WEB_SCOPE=read"}
        end

      :error ->
        {:error, Methods.code(:method_not_found), "this build does not serve #{method}"}
    end
  end

  @doc """
  Whether this build serves a method at all, at this scope.

  The feature gate the whole surface uses: a page shows a verb's control if and only if
  the method exists here and this endpoint's scope may run it. It is the same question
  `hello` answers for a terminal client, asked directly because there is no handshake
  between a LiveView and the table it reads.
  """
  @spec available?(scope(), String.t()) :: boolean()
  def available?(scope, method) when scope in [:read, :operate] and is_binary(method) do
    case Methods.fetch(method) do
      {:ok, entry} -> Methods.permits?(scope, entry)
      :error -> false
    end
  end

  defp run(method, params, entry, opts) do
    supervisor = Keyword.get(opts, :task_supervisor, Ouroboros.Web.TaskSupervisor)
    task = Task.Supervisor.async_nolink(supervisor, fn -> Methods.invoke(method, params) end)

    case Task.yield(task, entry.timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, {:ok, _value} = result} -> result
      {:ok, {:error, _code, _message} = result} -> result
      {:ok, {:error, _code, _message, _data} = result} -> result
      {:ok, other} -> unrecognized(method, other)
      {:exit, reason} -> crashed(method, reason)
      nil -> timeout_answer(method, entry)
    end
  end

  @doc """
  What a browser is told when the ceiling expired.

  Public because it is the honesty this module exists to keep and the one answer a test
  cannot reach through `call/4` — the ceilings are the method table's, and a test that
  could lower one would be testing a hole rather than the behaviour.
  """
  @spec timeout_answer(String.t(), map()) :: result()
  def timeout_answer(method, entry) when is_binary(method) and is_map(entry) do
    message =
      "#{method} exceeded the gateway ceiling of #{entry.timeout}ms; the runtime may " <>
        "still be working on it"

    case Map.get(entry, :outcome) do
      :unknown -> {:error, Methods.code(:upstream_timeout), message, %{"outcome" => "unknown"}}
      _other -> {:error, Methods.code(:upstream_timeout), message}
    end
  end

  # A handler that answers something the contract does not describe is a bug in this
  # build, not in the browser, and it is reported as one rather than rendering garbage.
  defp unrecognized(method, other) do
    Logger.error(
      "web handler for #{method} returned an unrecognized result: #{inspect(other, limit: 10)}"
    )

    {:error, Methods.code(:upstream_error), "#{method} answered something this build cannot read"}
  end

  defp crashed(method, reason) do
    Logger.error("web #{method} failed: #{inspect(reason, limit: 10)}")

    {:error, Methods.code(:upstream_error),
     "#{method} failed inside the runtime; the daemon's log has the reason"}
  end

  # Matches on the *method's* scope, not the endpoint's: the line exists to record that
  # something mutating happened, and a read-scope endpoint cannot reach this at all.
  defp audit(method, params, %{scope: :operate}, opts) do
    Logger.info(
      "web operate #{method} params=#{params_digest(params)} session=#{session_id(opts)}"
    )
  end

  defp audit(_method, _params, _entry, _opts), do: :ok

  defp session_id(opts) do
    case Keyword.get(opts, :session) do
      id when is_binary(id) -> id
      _other -> "unattributed"
    end
  end

  # The gateway's digest, computed the gateway's way, so one request reproduced against
  # either surface leaves the same 16 hex characters in both logs.
  defp params_digest(params) do
    :sha256
    |> :crypto.hash(params |> Wire.to_json() |> JSON.encode_to_iodata!())
    |> Base.encode16(case: :lower)
    |> binary_part(0, 16)
  end
end
