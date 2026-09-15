defmodule Ouroboros.Web.CatalogueTest do
  @moduledoc """
  S1. The shared command catalogue, as this surface reads it.

  `priv/ui/commands.json` is the one list of verbs the web palette and the terminal
  palette both draw. This is the web half of the drift fence; the terminal half is
  `tui/tests/catalogue.rs`. Both parse the file for themselves rather than asking the
  module that reads it, because a drift test that trusts one reader can only prove that
  reader agrees with itself.

  The last test is the one that costs something: it pins how many verbs each surface has
  alone. Adding a one-sided verb is a decision about parity, so it is made in the open —
  by editing a number and a list here — rather than by a row quietly appearing.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Web.Commands

  @catalogue_path Path.expand("../../../priv/ui/commands.json", __DIR__)
  @external_resource @catalogue_path

  @rows @catalogue_path |> File.read!() |> Jason.decode!()

  @groups ~w(session turn conversation runtime client)

  defp web_rows, do: Enum.filter(@rows, &is_map(&1["web"]))

  # What this surface spells a row: the shared spelling unless its own block overrides it.
  defp web_spelling(row, key), do: row["web"][key] || row[key]

  # ------------------------------------------------------------------------------------
  # The file itself
  # ------------------------------------------------------------------------------------

  describe "the file" do
    test "is one row per id, filed under one of the five groups" do
      ids = Enum.map(@rows, & &1["id"])

      assert ids == Enum.uniq(ids), "an id is written twice: #{inspect(ids -- Enum.uniq(ids))}"

      for row <- @rows do
        assert is_binary(row["id"]) and row["id"] != ""
        assert is_binary(row["label"]) and row["label"] != ""

        assert row["group"] in @groups,
               "#{row["id"]} is filed under #{inspect(row["group"])}, not one of the five"
      end
    end

    test "gives every row at least one surface" do
      for row <- @rows do
        assert is_map(row["tui"]) or is_map(row["web"]),
               "#{row["id"]} belongs to neither surface"
      end
    end

    test "names the id its palette runs, and a slash spelling this surface can draw" do
      for row <- web_rows() do
        assert row["web"]["event"] == row["id"],
               "#{row["id"]} runs #{inspect(row["web"]["event"])}"

        # `search/2` folds the slash column into the query, so a row without one would
        # raise while somebody typed.
        assert is_binary(web_spelling(row, "slash")),
               "#{row["id"]} has no slash spelling on this surface"
      end
    end

    test "says why, wherever a verb is one-sided or spelled two ways" do
      for row <- @rows, is_nil(row["tui"]) or is_nil(row["web"]) do
        assert is_binary(row["note"]) and row["note"] != "",
               "#{row["id"]} is one-sided and does not say why"
      end

      for row <- web_rows(),
          Map.has_key?(row["web"], "label") or Map.has_key?(row["web"], "slash") do
        assert is_binary(row["note"]) and row["note"] != "",
               "#{row["id"]} is spelled two ways and does not say why"
      end
    end
  end

  # ------------------------------------------------------------------------------------
  # The fence, both ways
  # ------------------------------------------------------------------------------------

  describe "the catalogue and all/0" do
    test "every row this surface draws has a web block in the file" do
      by_id = Map.new(@rows, &{&1["id"], &1})

      for command <- Commands.all() do
        row = Map.get(by_id, command.id)

        assert row, "#{command.id} is drawn here and the file does not carry it"

        assert is_map(row["web"]),
               "#{command.id} is drawn here and the file says this surface lacks it"
      end
    end

    test "every web row in the file is drawn here" do
      drawn = MapSet.new(Commands.all(), & &1.id)

      for row <- web_rows() do
        assert MapSet.member?(drawn, row["id"]),
               "#{row["id"]} has a web block and `all/0` does not return it"
      end
    end

    test "the label, the group and the slash come from the file" do
      by_id = Map.new(@rows, &{&1["id"], &1})

      for command <- Commands.all() do
        row = Map.fetch!(by_id, command.id)

        assert command.label == web_spelling(row, "label"),
               "#{command.id} draws a label the file does not carry"

        assert Atom.to_string(command.group) == row["group"],
               "#{command.id} is drawn under a heading the file does not carry"

        assert command.slash == web_spelling(row, "slash"),
               "#{command.id} spells its verb differently from the file"
      end
    end

    test "the five groups are the file's, in the order `groups/0` fixes" do
      assert Enum.map(Commands.groups(), &Atom.to_string/1) == @groups

      for group <- @groups do
        assert Enum.any?(@rows, &(&1["group"] == group)), "#{group} holds no rows"
      end
    end
  end

  # ------------------------------------------------------------------------------------
  # The parity report
  # ------------------------------------------------------------------------------------

  describe "parity" do
    # Twenty-seven verbs on both surfaces, sixteen only in the terminal, eight only here.
    # These numbers are the report: changing one means a reviewer is looking at a decision
    # about parity rather than at a diff that happens to add a row.
    test "the count of one-sided verbs is what the plan says it is" do
      both = for row <- @rows, is_map(row["tui"]), is_map(row["web"]), do: row["id"]
      tui_only = for row <- @rows, is_map(row["tui"]), is_nil(row["web"]), do: row["id"]
      web_only = for row <- @rows, is_nil(row["tui"]), is_map(row["web"]), do: row["id"]

      assert length(both) == 27
      assert length(tui_only) == 16
      assert length(web_only) == 8

      assert Enum.sort(tui_only) ==
               ~w(client.help client.quit conversation.cost conversation.diff
                  conversation.raw conversation.scrollback conversation.view
                  runtime.capabilities runtime.capability_admit runtime.capability_preview
                  runtime.connect runtime.logs runtime.upgrades session.options
                  session.writable turn.editor)

      assert Enum.sort(web_only) ==
               ~w(client.notifications conversation.history runtime.audit session.delete
                  turn.queue turn.retry turn.send turn.shell)
    end

    test "the verbs the two surfaces spell differently are the ones that say why" do
      divergent =
        for row <- web_rows(),
            Map.has_key?(row["web"], "label") or Map.has_key?(row["web"], "slash"),
            do: row["id"]

      # Six wordings, four of them with a typed spelling of their own — the rows whose
      # notes say the two surfaces mean different things by one verb, not merely say it
      # differently. Converging one is a good change and deleting a line here is how it is
      # declared; letting a new one in without touching this list is the drift the file
      # exists to stop.
      assert Enum.sort(divergent) ==
               ~w(client.shortcuts conversation.copy_source conversation.details
                  runtime.status session.end turn.approval)
    end
  end
end
