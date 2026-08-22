defmodule Ouroboros.Provider.Native.DiffTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Diff

  test "a single-line change produces one small hunk, not a whole-file replacement" do
    before_content = Enum.map_join(1..40, "", &"line #{&1}\n")
    after_content = String.replace(before_content, "line 20\n", "line twenty\n")

    diff = Diff.unified("lib/a.ex", before_content, after_content, :modify)

    assert diff =~ "--- a/lib/a.ex"
    assert diff =~ "+++ b/lib/a.ex"
    assert diff =~ "-line 20"
    assert diff =~ "+line twenty"
    assert diff =~ ~r/@@ -\d+,\d+ \+\d+,\d+ @@/
    # Three lines of context on each side, one changed line: seven context/changed rows,
    # never the other thirty-three.
    refute diff =~ "line 5"
    refute diff =~ "line 35"
  end

  test "two distant changes produce two hunks" do
    before_content = Enum.map_join(1..60, "", &"line #{&1}\n")

    after_content =
      before_content
      |> String.replace("line 5\n", "five\n")
      |> String.replace("line 50\n", "fifty\n")

    diff = Diff.unified("a.txt", before_content, after_content, :modify)
    assert length(Regex.scan(~r/^@@ /m, diff)) == 2
  end

  test "a new file diffs against /dev/null" do
    diff = Diff.unified("new.txt", nil, "hello\n", :add)
    assert diff =~ "--- /dev/null"
    assert diff =~ "+++ b/new.txt"
    assert diff =~ "+hello"
  end

  test "identical content produces no diff" do
    assert Diff.unified("a.txt", "same\n", "same\n", :modify) == ""
  end

  test "binary content is summarized, never dumped" do
    diff = Diff.unified("blob.bin", <<0, 159, 146, 150>>, <<0, 1, 2>>, :modify)
    assert diff =~ "Binary files"
    refute diff =~ "@@"
  end

  test "a file without a trailing newline keeps its last line" do
    diff = Diff.unified("a.txt", "one\ntwo", "one\nTWO", :modify)
    assert diff =~ "-two"
    assert diff =~ "+TWO"
  end

  test "change/5 counts added and removed lines and carries the relative path" do
    change = Diff.change("/abs/lib/a.ex", "lib/a.ex", "a\nb\nc\n", "a\nB\nc\nd\n", :modify)

    assert change["path"] == "/abs/lib/a.ex"
    assert change["relative_path"] == "lib/a.ex"
    assert change["kind"] == "modify"
    assert change["removed_lines"] == 1
    assert change["added_lines"] == 2
    assert change["diff"] =~ "+B"
  end

  test "a file too large to diff is summarized rather than left to run forever" do
    before_content = Enum.map_join(1..40_000, "", &"line #{&1}\n")
    after_content = Enum.map_join(1..40_000, "", &"changed #{&1}\n")

    change =
      Diff.change("/w/big.txt", "big.txt", before_content, after_content, :modify)

    assert change["diff"] =~ "file too large to diff inline"
    assert change["diff"] =~ "-40000 lines"
    assert change["diff"] =~ "+40000 lines"
    assert change["added_lines"] == 40_000
    assert change["removed_lines"] == 40_000
    assert byte_size(change["diff"]) < 1_024
  end

  test "a diff that is computed but enormous is truncated with a stated bound" do
    before_content = Enum.map_join(1..1_500, "", &"line #{&1} #{String.duplicate("x", 200)}\n")
    after_content = Enum.map_join(1..1_500, "", &"line #{&1} #{String.duplicate("y", 200)}\n")

    diff = Diff.unified("big.txt", before_content, after_content, :modify)

    assert byte_size(diff) <= 128 * 1024 + 64
    assert diff =~ "diff truncated at"
  end
end
