defmodule Ouroboros.Upgrade.ModuleName do
  @moduledoc """
  Module names as they cross a durable checkpoint boundary.

  A capability module's name is created when the forge compiles it. The atom exists in
  the VM that loaded that code and in no other, and it is gone from the VM that reboots.
  A checkpoint holding the atom therefore cannot be read back: `binary_to_term/2` in
  `[:safe]` mode — which `Ouroboros.Storage.DurableFile` uses and keeps using — refuses
  any term naming an atom this VM has never interned, and the store that owns the
  checkpoint reports corruption for what is only a name it has not heard of.

  So names are written as binaries, and read back as atoms only when the atom already
  exists. A name that does not resolve stays a binary, which is the truth about it here:
  that module is not loaded on this node. That is a fact for the reader to act on, not a
  corrupt record to refuse.

  Both directions are idempotent, so a checkpoint written before this boundary existed
  still loads, and a name that never became an atom can be written straight back out.
  """

  @prefix "Elixir."

  @doc "The binary form of a module name, for a term about to be persisted."
  @spec to_wire(term()) :: term()
  def to_wire(name) when is_atom(name) do
    case Atom.to_string(name) do
      @prefix <> _rest = text -> text
      _erlang_module_or_plain_atom -> name
    end
  end

  def to_wire(name), do: name

  @doc "The module a persisted name refers to, when this VM has heard of it."
  @spec from_wire(term()) :: term()
  def from_wire(@prefix <> _rest = text) do
    String.to_existing_atom(text)
  rescue
    ArgumentError -> text
  end

  def from_wire(name), do: name
end
