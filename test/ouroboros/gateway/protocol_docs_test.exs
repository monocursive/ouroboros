defmodule Ouroboros.Gateway.ProtocolDocsTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.Ouroboros.Gateway.Golden
  alias Mix.Tasks.Ouroboros.Protocol.Docs
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Gateway.Methods.Contract

  # `docs/PROTOCOL.md` is the exhaustive reference and it is generated; `docs/TUI.md` §2 is
  # the narrative and it is written. This suite is the seam: it proves the generated file
  # is what this build produces, that the data it is generated from is what the validators
  # enforce, and that the two documents name the same set of methods.

  @tui "docs/TUI.md"

  # `hello` is documented in `docs/TUI.md` §2.3 with the rest of the handshake rather than
  # in §2.4's catalog, which is a placement decision and not a gap.
  @tui_catalog_exempt ~w(hello)

  # Methods in `@table` that `docs/TUI.md` §2.4 does not catalogue, each recorded here
  # rather than quietly fixed. Deleting a name from this list is what closing a gap looks
  # like: D6's two rewind verbs sat here until the client slice that wired `/rewind`
  # documented them, and the list has been empty since.
  @tui_catalog_gaps ~w()

  describe "the generated reference" do
    test "on disk is exactly what this build generates" do
      assert File.read!(Docs.path()) == Docs.document(),
             """
             docs/PROTOCOL.md has drifted from the code it is generated from.
             Run `mix ouroboros.protocol.docs` and commit the diff — it is the review
             artifact for a protocol change.
             """
    end

    test "gives every method this build serves a section of its own" do
      document = File.read!(Docs.path())

      for method <- Map.keys(Methods.table()) do
        assert document =~ "\n#### `#{method}`\n",
               "docs/PROTOCOL.md has no section for #{method}"
      end
    end

    test "gives every band a section, and the contents an entry" do
      document = File.read!(Docs.path())

      bands =
        Methods.table()
        |> Map.keys()
        |> Enum.map(fn
          "hello" -> "handshake"
          name -> name |> String.split(".") |> hd()
        end)
        |> Enum.uniq()

      for band <- bands do
        assert document =~ "\n### #{band}\n",
               "docs/PROTOCOL.md has no section for the #{band} band"

        assert document =~ "  - [#{band}](##{band})", "the contents do not link the #{band} band"
      end
    end

    test "embeds every golden fixture, and embeds no fixture that is not there" do
      document = File.read!(Docs.path())
      declared = Enum.map(Golden.fixtures(), fn {name, _frame} -> name end)

      assert Enum.sort(declared) == Enum.sort(Map.keys(Docs.fixture_owners())),
             "mix ouroboros.protocol.docs places fixtures by name; one has appeared or gone"

      for name <- declared do
        assert document =~ "`#{name}.json`", "docs/PROTOCOL.md never names #{name}.json"

        assert document =~ File.read!(Golden.path(name)),
               "docs/PROTOCOL.md does not embed the current bytes of #{name}.json"
      end
    end

    test "names every protocol error a client can be sent" do
      document = File.read!(Docs.path())

      for {name, code} <- Methods.codes() do
        assert document =~ "| `#{code}` | `#{name}` |",
               "docs/PROTOCOL.md does not list #{name} (#{code})"
      end
    end
  end

  describe "the parameter contract" do
    test "covers exactly the methods the table serves" do
      assert Methods.params() |> Map.keys() |> Enum.sort() ==
               Methods.table() |> Map.keys() |> Enum.sort()
    end

    test "closed methods reject unknown fields before dispatch" do
      for {method, %{envelope: :closed}} <- Methods.params() do
        assert {:invalid, message} = Contract.validate(method, %{"unexpected" => true})
        assert message =~ "unsupported fields: unexpected"
      end
    end

    test "every dispatch target is exported and connection owners are explicit" do
      for method <- Methods.names(),
          {:ok, handler} = Contract.handler(method),
          handler != :connection do
        assert function_exported?(Methods, handler, 1), "#{method}: missing #{handler}/1"
      end

      assert Enum.sort(Docs.connection_answered()) == Enum.sort(Contract.connection_answered())
    end
  end

  describe "docs/TUI.md §2.4" do
    test "names no method this build does not serve" do
      assert catalog() -- Map.keys(Methods.table()) == [],
             "docs/TUI.md §2.4 documents a method that is not in Ouroboros.Gateway.Methods"
    end

    test "names every method this build serves, but for the gaps recorded here" do
      missing = (Methods.table() |> Map.keys()) -- catalog()

      assert Enum.sort(missing) == Enum.sort(@tui_catalog_exempt ++ @tui_catalog_gaps),
             """
             docs/TUI.md §2.4 and Ouroboros.Gateway.Methods have moved apart.
             Either document the new method in §2.4, or record it in @tui_catalog_gaps
             with a reason — a gap nobody named is a gap nobody closes.
             """
    end
  end

  # ---------------------------------------------------------------------------

  # Every method `docs/TUI.md` §2.4's two tables name in their first column. A cell may
  # write a family as `coding.info/replay/subscribe` or as `interactive.send_message` /
  # `follow_up`, so a bare word inherits the band of the last dotted name beside it.
  defp catalog do
    @tui
    |> File.read!()
    |> String.split("### 2.4 Method catalog (v1)")
    |> Enum.at(1)
    |> String.split("### 2.5 Event streaming")
    |> hd()
    |> String.split("\n")
    |> Enum.filter(&String.starts_with?(&1, "|"))
    |> Enum.map(fn row -> row |> String.split("|") |> Enum.at(1, "") end)
    |> Enum.flat_map(&methods_named_in/1)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp methods_named_in(cell) do
    ~r/`([^`]+)`/
    |> Regex.scan(cell)
    |> Enum.map(&List.last/1)
    |> Enum.reject(&String.starts_with?(&1, "{"))
    |> Enum.reduce({[], nil}, fn span, acc ->
      span
      |> String.split(~r{[/\s,]+}, trim: true)
      |> Enum.reduce(acc, fn part, {found, band} ->
        cond do
          Regex.match?(~r/^[a-z_]+(\.[a-z_]+)+$/, part) ->
            {[part | found], part |> String.split(".") |> hd()}

          band && Regex.match?(~r/^[a-z_]+$/, part) ->
            {[band <> "." <> part | found], band}

          true ->
            {found, band}
        end
      end)
    end)
    |> elem(0)
  end
end
