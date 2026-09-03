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

  # `%mod{}` matches any map carrying an atom `:__struct__`, which is a much larger set
  # than "the structs". The struct clause used to take all of them: it called
  # `Atom.to_string/1` on every other key, which raises on the first one that is not an
  # atom, and it wrote a struct form for modules that are not struct modules, which comes
  # back as a map with a *binary* `"__struct__"` key. Both were reachable from a signed
  # manifest — `metadata.test_report` is checked for `failures: 0` and nothing else — and
  # the raise came out of `Registry.persist/2` and killed the register.
  describe "struct-shaped maps that are not structs" do
    test "a map holding :__struct__ beside a non-atom key dumps rather than raising" do
      poison = %{1 => 2, __struct__: :ok}

      assert %{"__map__" => _pairs} = Wire.dump(poison)
      assert Wire.load(Wire.dump(poison)) === poison
    end

    test "a module that is not a struct module is a plain map, and stays one" do
      for term <- [
            %{__struct__: :ok},
            %{a: %{__struct__: :ok}},
            %{__struct__: nil},
            %{__struct__: :ok, a: 1},
            # A module that is loaded and is not a struct module: the one shape whose
            # `__struct__/0` is called and raises rather than simply being absent.
            %{__struct__: Wire},
            %{__struct__: Wire, a: 1},
            %{__struct__: "Elixir.Ouroboros.Upgrade.Wire"},
            [%{__struct__: :error}],
            {%{__struct__: :ok}}
          ] do
        assert Wire.load(Wire.dump(term)) === term, "#{inspect(term)} did not survive"
      end
    end

    test "a real struct is still written as a struct, and comes back as one" do
      artifact = %Ouroboros.Wasm.Artifact{
        id: "a",
        epoch: 1,
        name: "greeter",
        component_sha256: String.duplicate("a", 64),
        world: "w",
        imports: [],
        size: 1,
        created_at: "x"
      }

      dumped = Wire.dump(%{artifact: artifact})
      assert dumped["artifact"]["__struct__"] == "Elixir.Ouroboros.Wasm.Artifact"
      assert Wire.load(dumped) === %{artifact: artifact}
    end

    test "a struct with a field added or removed is a map, because struct/2 cannot rebuild it" do
      artifact = %Ouroboros.Wasm.Artifact{
        id: "a",
        epoch: 1,
        name: "greeter",
        component_sha256: String.duplicate("a", 64),
        world: "w",
        imports: [],
        size: 1,
        created_at: "x"
      }

      widened = Map.put(artifact, :extra, 1)
      narrowed = Map.delete(artifact, :world)

      assert %{"__map__" => _} = Wire.dump(widened)
      assert Wire.load(Wire.dump(widened)) === widened
      assert Wire.load(Wire.dump(narrowed)) === narrowed
    end

    test "a struct-shaped test_report is signed metadata, and the boundary carries it" do
      # The exact term the signing policy admits: not a struct at the top level, and
      # `failures` is 0, which is the whole of `fetch_optional_tests/1`.
      report = %{failures: 0, extra: %{1 => 2, __struct__: :ok}}
      manifest = %{id: "x", epoch: 1, metadata: %{author: "a", test_report: report}}

      assert Wire.load(Wire.dump(manifest)) === manifest

      assert :erlang.term_to_binary(
               {:ouroboros_wasm_v1, "s", Wire.load(Wire.dump(manifest))},
               [:deterministic]
             ) ==
               :erlang.term_to_binary({:ouroboros_wasm_v1, "s", manifest}, [:deterministic])
    end
  end

  describe "the promise, swept" do
    # A seeded sweep over terms built out of exactly the pieces this boundary has to tell
    # apart: atoms and binaries that spell each other, this module's own tag names in both
    # kinds, non-atom keys, and struct-shaped maps. One example proves one case; the promise
    # in the moduledoc is universal, so it is checked over a few hundred of them.
    test "load(dump(t)) === t for every generated term" do
      :rand.seed(:exsss, {17, 23, 42})

      failures =
        Enum.reduce(1..600, [], fn _index, acc ->
          term = generate(4)

          case round_trip(term) do
            {:ok, ^term} -> acc
            other -> [{term, other} | acc]
          end
        end)

      assert failures == [],
             "#{length(failures)} terms broke, first: #{inspect(Enum.take(failures, 1))}"
    end

    test "no dumped term needs an atom beyond the three booleans" do
      :rand.seed(:exsss, {5, 5, 5})

      for _index <- 1..300 do
        assert atoms(Wire.dump(generate(4))) == []
      end
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

  defp round_trip(term) do
    {:ok, Wire.load(Wire.dump(term))}
  rescue
    error -> {:raised, error.__struct__}
  end

  # Every atom below is interned by this module, which is the precondition the moduledoc
  # states for exactness. The binaries spell the same names on purpose.
  @gen_atoms [:ok, :error, nil, true, false, :a, :b, :__map__, :__atom__, :__struct__, :""]
  @gen_binaries ["ok", "error", "nil", "true", "a", "b", "__map__", "__atom__", "__struct__", ""]

  defp generate(0) do
    Enum.random([
      Enum.random(@gen_atoms),
      Enum.random(@gen_binaries),
      Enum.random([0, 1, -1, 1.0, 0.5, 1_000_000]),
      []
    ])
  end

  defp generate(depth) do
    case Enum.random(1..6) do
      1 ->
        generate(0)

      2 ->
        for _index <- 1..Enum.random(1..3), do: generate(depth - 1)

      3 ->
        1..Enum.random(1..3) |> Enum.map(fn _index -> generate(depth - 1) end) |> List.to_tuple()

      4 ->
        generated_map(depth)

      5 ->
        generated_map(depth)

      6 ->
        Map.put(generated_map(depth), :__struct__, Enum.random(@gen_atoms))
    end
  end

  defp generated_map(depth) do
    for _index <- 1..Enum.random(0..4),
        into: %{},
        do: {generated_key(depth - 1), generate(depth - 1)}
  end

  defp generated_key(depth) when depth <= 0,
    do: Enum.random(@gen_atoms ++ @gen_binaries ++ [0, 1, 1.0, {:a}, %{a: 1}])

  defp generated_key(depth),
    do: Enum.random([generated_key(0), generate(depth), {generate(depth - 1)}])

  defp atoms(term) when term in [nil, true, false], do: []
  defp atoms(term) when is_atom(term), do: [term]
  defp atoms(map) when is_map(map), do: Enum.flat_map(map, fn {k, v} -> atoms(k) ++ atoms(v) end)
  defp atoms(list) when is_list(list), do: Enum.flat_map(list, &atoms/1)
  defp atoms(tuple) when is_tuple(tuple), do: tuple |> Tuple.to_list() |> atoms()
  defp atoms(_other), do: []
end
