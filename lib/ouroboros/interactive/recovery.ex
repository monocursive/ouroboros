defmodule Ouroboros.Interactive.Recovery do
  @moduledoc false

  def child_spec(opts), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}

  def start_link(opts \\ []) do
    Ouroboros.Session.Recovery.start_link(
      Keyword.merge(
        [
          name: __MODULE__,
          store: Ouroboros.Interactive.Store,
          task: Ouroboros.Interactive.Task,
          registry: Ouroboros.Interactive.Registry,
          supervisor: Ouroboros.Interactive.TaskSupervisor
        ],
        opts
      )
    )
  end
end
