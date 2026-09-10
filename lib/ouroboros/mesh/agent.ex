defmodule Ouroboros.Mesh.Agent do
  @moduledoc """
  The domain contract of an allowed mesh agent.

  Callbacks receive validated message data and return the complete next domain state.
  The context contains the logical `:id` and the actual owner `:server_pid`, even when
  the callback runs in a supervised task. Errors leave the last committed state intact.
  """

  @callback init_state(map()) :: {:ok, map()} | {:error, term()}
  @callback handle_message(map(), map(), %{id: String.t(), server_pid: pid()}) ::
              {:ok, map()} | {:error, term()}
end
