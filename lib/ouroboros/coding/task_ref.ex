defmodule Ouroboros.Coding.TaskRef do
  @moduledoc "A stable coding-task identity paired with its owning BEAM node."

  @enforce_keys [:id, :node]
  defstruct @enforce_keys

  @type t :: %__MODULE__{id: String.t(), node: node()}

  @doc false
  @spec new(String.t(), node()) :: t()
  def new(id, owner_node \\ node()) when is_binary(id) and is_atom(owner_node) do
    %__MODULE__{id: id, node: owner_node}
  end
end
