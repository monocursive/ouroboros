defmodule Ouroboros.Coding.Recovery do
  @moduledoc false

  def child_spec(opts), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}

  def start_link(opts \\ []) do
    Ouroboros.Session.Recovery.start_link(
      Keyword.merge(
        [
          name: __MODULE__,
          store: Ouroboros.Coding.Store,
          task: Ouroboros.Coding.Task,
          registry: Ouroboros.Coding.Registry,
          supervisor: Ouroboros.Coding.TaskSupervisor
        ],
        opts
      )
    )
  end
end
