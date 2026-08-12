defmodule Ouroboros.Interactive.Ref do
  @moduledoc "A distribution-aware reference to an interactive coding session."

  @enforce_keys [:id, :node]
  defstruct @enforce_keys

  @type t :: %__MODULE__{id: String.t(), node: node()}

  @spec new(String.t(), node()) :: t()
  def new(id, owner \\ node()) when is_binary(id) and is_atom(owner) do
    %__MODULE__{id: id, node: owner}
  end
end
