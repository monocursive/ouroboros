defmodule UkaiFleet.Protocol do
  @moduledoc """
  The wire version a client, controller and worker must share before any other call.

  A peer whose `:version` answer lacks either value speaks a different protocol,
  whatever else it carries.
  """
  @version %{"schema" => "ukai.fleet.rpc/2", "run" => "ukai.ledger.run/1"}

  @doc "This build's answer to `:version`."
  def version, do: @version

  @doc "The ledger run schema this build reads; a worker's ledger must announce it."
  def ledger_run, do: @version["run"]

  @doc "Whether a `:version` reply names this build's protocol. Extra fields are allowed."
  def compatible?({:ok, %{} = version}), do: Map.take(version, Map.keys(@version)) == @version
  def compatible?(_reply), do: false
end
