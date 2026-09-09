defmodule Ouroboros.Storage.RetiredAtomsTest do
  use ExUnit.Case, async: true

  alias Ouroboros.EventPresentation
  alias Ouroboros.Storage.{DurableFile, RetiredAtoms}

  # A term written by a build that still had the deleted planes, captured as bytes rather
  # than built here: a term built in this VM would intern its own atoms and prove nothing.
  # It holds every name in the retired list as both a key and a value.
  @checkpoint "g3QAAAAJdwtkZWxlZ2F0aW9uc3cLZGVsZWdhdGlvbnN3CmRlbGVnYXRpb253CmRlbGVnYXRpb253B3RlYW1faWR3B3RlYW1faWR3CXRhc2tfbm9kZXcJdGFza19ub2RldxBvYmplY3RpdmVfZGlnZXN0dxBvYmplY3RpdmVfZGlnZXN0dw1yZXN1bHRfZGlnZXN0dw1yZXN1bHRfZGlnZXN0dwpkZWxpdmVyaW5ndwpkZWxpdmVyaW5ndwlkZWxpdmVyZWR3CWRlbGl2ZXJlZHcGY29kaW5ndwZjb2Rpbmc="

  test "a checkpoint naming the deleted planes' atoms still decodes" do
    binary = Base.decode64!(@checkpoint)

    decoded = :erlang.binary_to_term(binary, [:safe])

    assert Enum.sort(Enum.map(Map.keys(decoded), &Atom.to_string/1)) ==
             Enum.sort(Enum.map(RetiredAtoms.retired(), &Atom.to_string/1))
  end

  test "the decoding module is the one holding the list" do
    assert DurableFile.retired_atoms() == RetiredAtoms.retired()
  end

  test "a retired event type presents as a named note rather than raising" do
    [type] = Enum.filter(RetiredAtoms.retired(), &(Atom.to_string(&1) == "delegation"))

    presented = EventPresentation.from_event(%{type: type, payload: %{}})

    assert %EventPresentation.ProviderNote{kind: "delegation"} = presented
  end
end
