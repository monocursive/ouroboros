defmodule Ouroboros.Workspace.Lease do
  @moduledoc """
  A public, inspectable workspace lease.

  The owning process and release capability are deliberately not stored in this
  value. `owner` is an opaque, node-scoped identity suitable for logs and
  checkpoints; process monitoring remains private to the lease manager.
  """

  @enforce_keys [:id, :root, :task_id, :mode, :owner, :acquired_at]
  defstruct @enforce_keys

  @type mode :: :exclusive | :shared_read

  @type owner :: %{
          required(:id) => String.t(),
          required(:node) => node(),
          required(:type) => :local_process
        }

  @type t :: %__MODULE__{
          id: String.t(),
          root: String.t(),
          task_id: String.t(),
          mode: mode(),
          owner: owner(),
          acquired_at: String.t()
        }

  @doc "Returns a plain durable-facing map containing no process identifiers."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = lease), do: Map.from_struct(lease)
end
