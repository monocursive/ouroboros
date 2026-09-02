defmodule Ouroboros.Upgrade.WireTest do
  @moduledoc """
  The checkpoint boundary is exact: what an owner dumps is what it loads, keys included.

  The keys are the whole story. Once an atom key and a binary key are both binaries on
  disk, nothing but the encoding can say which was which, and a boundary that guessed
  turned `%{"nil" => 1}` into `%{nil => 1}` — which changed the bytes under a signature
  and, for a rollout id that happened to spell a word, made a registry refuse its own
  checkpoint. Every test here writes the term that would have gone wrong.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Upgrade.{Artifact, Wire}

  # Each of these spells an atom every VM has interned, so a boundary that resolved bare
  # keys would turn each one into that atom.
  @string_keys ["nil", "true", "false", "ok", "error", "input", "version"]

  describe "exactness" do
    test "a string key stays a string, even one that spells an interned atom" do
      term = %{input: Map.new(@string_keys, &{&1, &1})}
      assert Wire.load(Wire.dump(term)) == term
    end

    test "an atom key stays an atom, and a mixed map keeps every kind of key apart" do
      term = %{
        :ok => 1,
        "ok" => 2,
        3 => :three,
        {:a, "b"} => [nil],
        %{"k" => :v} => "map key",
        nil => "the atom",
        "nil" => "the string",
        1.5 => true
      }

      assert Wire.load(Wire.dump(term)) == term
    end

    test "user data shaped like a tag is data" do
      for term <- [
            %{"__atom__" => "ok"},
            %{"__tuple__" => [1, 2]},
            %{"__struct__" => "Elixir.Ouroboros.Upgrade.Artifact"},
            %{"__map__" => [["a", 1]]},
            %{"__dropped__" => "improper_list"},
            %{"__atom__" => "ok", "other" => 1},
            %{__atom__: "ok"},
            %{__tuple__: [1]},
            %{__map__: []},
            %{__dropped__: "x"}
          ] do
        assert Wire.load(Wire.dump(term)) == term, "#{inspect(term)} did not survive"
      end
    end

    test "a tag is exactly one key; a tag's name beside other keys is not a tag" do
      assert is_map(Wire.load(%{"__atom__" => "ok", "other" => 1}))
      assert is_map(Wire.load(%{"__tuple__" => [1], "other" => 1}))
      assert is_map(Wire.load(%{"__map__" => [], "other" => 1}))
    end

    test "nested structures round-trip through every container" do
      {:ok, artifact} = artifact!(%{forge: %{eval: eval_spec()}})

      term = %{
        artifact: artifact,
        tuple: {:ok, %{"greet" => "x"}, [1, {2, "3"}]},
        list: [%{"a" => :b}, {:c}, nil, false],
        nested: %{"outer" => %{inner: %{"leaf" => {:t, %{"z" => nil}}}}}
      }

      assert Wire.load(Wire.dump(term)) == term
    end

    test "a signed manifest hashes the same on both sides of the boundary" do
      {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)
      {:ok, artifact} = artifact!(%{forge: %{eval: eval_spec()}})
      signed = Artifact.sign(artifact, "wire-signer", private_key)

      restored = Wire.load(Wire.dump(signed))

      assert restored == signed

      assert Artifact.signing_payload(restored, "wire-signer") ==
               Artifact.signing_payload(signed, "wire-signer")

      assert :crypto.verify(
               :eddsa,
               :none,
               Artifact.signing_payload(restored, "wire-signer"),
               restored.signature.value,
               [public_key, :ed25519]
             )
    end

    test "what cannot be carried is marked where it stood" do
      assert %{f: %{"__dropped__" => "#Function" <> _}} =
               Wire.load(Wire.dump(%{f: fn -> :ok end}))

      assert Wire.load(Wire.dump(%{l: [1 | 2]})) == %{l: %{"__dropped__" => "improper_list"}}
    end
  end

  describe "the dumped term" do
    test "an all-atom map is a map of bare names, the shape already on disk" do
      assert Wire.dump(%{version: 2, rollouts: %{}}) == %{"version" => 2, "rollouts" => %{}}
      assert Wire.dump(%{nil => 1, ok: :error}) == %{"nil" => 1, "ok" => %{"__atom__" => "error"}}
    end

    test "any other map is a sorted pair list with keys encoded like values" do
      assert Wire.dump(%{"b" => 1, "a" => 2, :c => 3}) ==
               %{"__map__" => [[%{"__atom__" => "c"}, 3], ["a", 2], ["b", 1]]}
    end

    test "needs no atom beyond the three booleans, wherever the term came from" do
      {:ok, artifact} = artifact!(%{"raw" => %{ok: {:t, [nil]}}, forge: %{eval: eval_spec()}})
      dumped = Wire.dump(%{"k" => {:a, %{b: :c}}, artifact: artifact, list: [%{"d" => :e}]})

      assert atoms(dumped) == []

      assert Wire.load(:erlang.binary_to_term(:erlang.term_to_binary(dumped), [:safe])) ==
               %{"k" => {:a, %{b: :c}}, artifact: artifact, list: [%{"d" => :e}]}
    end
  end

  describe "the atom fallback" do
    test "a name this VM lacks stays a binary, and interns nothing" do
      name = "wire_test_never_interned_#{System.unique_integer([:positive])}"

      assert Wire.load(%{"__atom__" => name}) == name
      assert Wire.load(%{"__map__" => [[%{"__atom__" => name}, 1]]}) == %{name => 1}
      assert Wire.load(%{name => 1}) == %{name => 1}
      assert_raise ArgumentError, fn -> String.to_existing_atom(name) end
    end

    test "a struct whose module is not a struct stays a tagged map" do
      # The atom exists (it is written here); the module does not.
      name = "Elixir.Ouroboros.Upgrade.WireTest.NoSuchStruct"
      _ = Ouroboros.Upgrade.WireTest.NoSuchStruct

      assert Wire.load(%{"__struct__" => name, "a" => 1}) == %{"__struct__" => name, a: 1}
    end

    test "an already-decoded struct is returned as it is" do
      {:ok, artifact} = artifact!(%{})
      assert Wire.load(artifact) == artifact
    end
  end

  describe "checkpoints written before keys were tagged" do
    test "a bare key still resolves to the atom it names, as it always did" do
      # What an earlier build wrote for `%{version: 2, rollouts: %{"nil" => ...}}`: a bare
      # `"nil"` that was a string, indistinguishable from the atom. The record was lossy;
      # this build reads it exactly as the previous one did rather than guessing.
      legacy = %{"version" => 2, "rollouts" => %{"nil" => %{"state" => %{"__atom__" => "live"}}}}

      assert Wire.load(legacy) == %{version: 2, rollouts: %{nil => %{state: :live}}}
    end

    test "a malformed pair list is read as the map it is, never raised on" do
      assert is_map(Wire.load(%{"__map__" => [[1, 2, 3]]}))
      assert is_map(Wire.load(%{"__map__" => :not_a_list}))
      assert is_map(Wire.load(%{"__map__" => [1, 2]}))
    end
  end

  # An artifact built the way the forge builds one: real module bytes (a test module
  # has none on disk, so the boundary's own), and a metadata map whose eval spec carries
  # the string-keyed probe input this boundary used to mangle.
  defp artifact!(metadata) do
    {Wire, binary, _filename} = :code.get_object_code(Wire)
    Artifact.build([{Wire, binary, []}], epoch: 1, metadata: metadata)
  end

  defp eval_spec do
    %{
      probes: [
        %{input: %{"greet" => "hello", "nil" => nil}, expect: {:equals, %{"reply" => "hello"}}},
        %{input: "plain", expect: {:state_matches, :last_message, %{"greet" => "hello"}}}
      ],
      initial_state: %{"count" => 0, "error" => "none"}
    }
  end

  defp atoms(term) when term in [nil, true, false], do: []
  defp atoms(term) when is_atom(term), do: [term]
  defp atoms(map) when is_map(map), do: Enum.flat_map(map, fn {k, v} -> atoms(k) ++ atoms(v) end)
  defp atoms(list) when is_list(list), do: Enum.flat_map(list, &atoms/1)
  defp atoms(tuple) when is_tuple(tuple), do: tuple |> Tuple.to_list() |> atoms()
  defp atoms(_other), do: []
end
