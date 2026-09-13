defmodule Ouroboros.Test.DurableFence do
  @moduledoc false

  # Plain mix test also supports an in-memory application. These admission fixtures
  # still exercise the real authority with private durable storage in that posture.
  def ensure_started!(root) do
    case Process.whereis(Ouroboros.Maintenance.Fence) do
      nil ->
        ExUnit.Callbacks.start_supervised!(
          {Ouroboros.Maintenance.Fence, data_dir: Path.join(root, "maintenance")}
        )

      pid ->
        pid
    end
  end
end
