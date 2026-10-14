defmodule OuroFleet.Client do
  @moduledoc "The operator client's call to its controller: protocol first, then the operation."
  alias OuroFleet.{Controller, Protocol}

  @doc """
  Sends `message` to the controller on `node` once it has answered `:version` with
  this build's protocol.

  An unreachable controller or a lost reply leaves the outcome unknown; only the same
  request may be retried. A protocol mismatch is not transient, since no retry can
  succeed until one side is upgraded, so it is reported apart and the operation is
  never sent.
  """
  def call(node, message) do
    case remote(node, :version, 10_000) do
      {:error, _} = unreachable ->
        unreachable

      version ->
        if Protocol.compatible?(version),
          do: remote(node, message, 185_000),
          else: {:error, "controller_schema_mismatch"}
    end
  end

  defp remote(node, message, timeout) do
    :erpc.call(node, Controller, :call, [message], timeout)
  catch
    _, _ -> {:error, "controller_unreachable_or_reply_lost_retry_same_request"}
  end
end
