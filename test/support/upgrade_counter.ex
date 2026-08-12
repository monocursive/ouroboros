defmodule Ouroboros.Test.UpgradeCounter do
  @moduledoc false
  @vsn 1

  use GenServer

  def start_link(initial), do: GenServer.start_link(__MODULE__, initial)
  def value(pid), do: GenServer.call(pid, :value)
  def version, do: 1

  @impl true
  def init(initial), do: {:ok, %{schema_vsn: 1, count: initial}}

  @impl true
  def handle_call(:value, _from, state), do: {:reply, {state.schema_vsn, state.count}, state}

  @impl true
  def code_change(_old_vsn, state, _extra), do: {:ok, state}
end
