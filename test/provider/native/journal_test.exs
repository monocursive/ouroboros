defmodule Ouroboros.Provider.Native.JournalTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Checkpoint
  alias Ouroboros.Provider.Native.Journal

  setup do
    dir = Path.join(System.tmp_dir!(), "native-journal-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    %{dir: dir, path: Journal.path(dir)}
  end

  defp lines(path), do: path |> File.read!() |> String.split("\n", trim: true)
  defp records(path), do: Enum.map(lines(path), &JSON.decode!/1)

  # ---------------------------------------------------------------- the chain

  test "chains records from the published seed and verifies end to end", %{dir: dir, path: path} do
    journal =
      dir
      |> Journal.open()
      |> Journal.append("session_opened", %{"provider_session_id" => "native-a-b"})
      |> Journal.append("turn_started", %{"turn_id" => "t1", "model_spec" => "anthropic:x"})
      |> Journal.append("turn_settled", %{"turn_id" => "t1", "status" => "complete"})

    assert journal.seq == 3
    refute journal.degraded?

    assert {:ok, %{records: records, head: head, verified_through: 3}} = Journal.verify(path)
    assert length(records) == 3
    assert Enum.map(records, & &1["seq"]) == [1, 2, 3]
    assert Enum.map(records, & &1["kind"]) == ~w(session_opened turn_started turn_settled)

    # The first record's `prev` is the seed, every later one is its predecessor's hash, and
    # the handle's own `prev` is the head a reader would compute.
    assert hd(records)["prev"] == Journal.seed()
    assert Enum.at(records, 1)["prev"] == hd(records)["hash"]
    assert Enum.at(records, 2)["prev"] == Enum.at(records, 1)["hash"]
    assert head == Enum.at(records, 2)["hash"]
    assert journal.prev == head

    # Every record carries the framing fields, and `at` is a real recorded instant.
    assert Enum.all?(records, &match?({:ok, _, _}, DateTime.from_iso8601(&1["at"])))
    assert Enum.all?(records, &is_binary(&1["hash"]))
  end

  test "a hash recomputed by hand matches the stored one", %{dir: dir, path: path} do
    dir |> Journal.open() |> Journal.append("prompt", %{"turn_id" => "t1", "content" => "hi"})

    [record] = records(path)
    body = Map.drop(record, ["prev", "hash"])

    expected =
      :sha256
      |> :crypto.hash([Journal.seed(), Journal.canonical_json(body)])
      |> Base.encode16(case: :lower)

    assert record["hash"] == expected
  end

  test "a tampered record is named by its sequence", %{dir: dir, path: path} do
    dir
    |> Journal.open()
    |> Journal.append("turn_started", %{"turn_id" => "t1"})
    |> Journal.append("prompt", %{"turn_id" => "t1", "content" => "original"})
    |> Journal.append("turn_settled", %{"turn_id" => "t1", "status" => "complete"})

    [first, second, third] = records(path)
    forged = %{second | "content" => "forged"}

    File.write!(
      path,
      Enum.map_join([first, forged, third], "", &(Journal.canonical_json(&1) <> "\n"))
    )

    assert {:error, {:chain_broken, 2}} = Journal.verify(path)

    # A reader still gets the prefix, and learns exactly how far it is good for.
    assert {:ok, window} = Journal.window(path)
    assert window.verified_through == 1
    assert window.head_seq == 3
    assert length(window.records) == 3
  end

  test "a truncated line breaks the chain rather than being skipped", %{dir: dir, path: path} do
    dir
    |> Journal.open()
    |> Journal.append("turn_started", %{"turn_id" => "t1"})
    |> Journal.append("prompt", %{"turn_id" => "t1", "content" => "hi"})

    File.write!(path, File.read!(path) <> "{\"seq\": 3, \"kind\": \"pro\n")

    assert {:error, {:chain_broken, 3}} = Journal.verify(path)
  end

  test "a session that has recorded nothing is an empty journal, not a failure", %{path: path} do
    assert {:ok, %{records: [], head: seed, verified_through: 0}} = Journal.verify(path)
    assert seed == Journal.seed()
  end

  # ---------------------------------------------------------------- writers

  test "a second writer picks the chain up where the first left it", %{dir: dir, path: path} do
    loop = dir |> Journal.open() |> Journal.append("turn_started", %{"turn_id" => "t1"})

    # The session's handle was opened before the loop wrote, so it is stale by exactly the
    # records the loop appended. `sync/1` is what makes it current again.
    session = Journal.open(dir)
    assert session.seq == 1

    session = Journal.append(session, "configure", %{"key" => "model", "value" => "x"})

    assert session.seq == 2
    assert {:ok, %{verified_through: 2}} = Journal.verify(path)

    # And the loop's handle, resynced, sees the session's record.
    assert Journal.sync(loop).seq == 2
  end

  test "the file is private and appended to, never rewritten", %{dir: dir, path: path} do
    journal = dir |> Journal.open() |> Journal.append("turn_started", %{"turn_id" => "t1"})
    first = File.read!(path)

    Journal.append(journal, "turn_settled", %{"turn_id" => "t1", "status" => "complete"})

    assert String.starts_with?(File.read!(path), first)
    assert {:ok, %File.Stat{mode: mode}} = File.stat(path)
    assert Bitwise.band(mode, 0o777) == 0o600
  end

  test "a handle whose tail cannot be read stages a gap instead of forging a link", %{
    dir: dir,
    path: path
  } do
    journal = dir |> Journal.open() |> Journal.append("turn_started", %{"turn_id" => "t1"})

    # A directory where the file should be: the tail read fails, so this handle does not
    # know what it would be chaining onto.
    File.rm!(path)
    File.mkdir_p!(path)

    journal = Journal.sync(journal)
    refute journal.synced?

    journal = Journal.append(journal, "model_call", %{"turn_id" => "t1"})
    assert journal.degraded?
    assert File.regular?(path <> ".gap")

    # Nothing was written where a link could not be made — the directory that stood in for
    # the file is still empty, and removing it leaves no journal behind.
    assert File.ls!(path) == []
    File.rm_rf!(path)
    refute File.exists?(path)

    # And the retry recovers: the next append re-reads the tail, finds an empty file, and
    # writes the staged gap ahead of the record.
    journal = Journal.append(journal, "turn_settled", %{"turn_id" => "t1"})
    assert journal.synced?
    assert [gap, settled] = records(path)
    assert gap["kind"] == "gap"
    assert "model_call" in gap["dropped_kinds"]
    assert settled["kind"] == "turn_settled"
    assert {:ok, %{verified_through: 2}} = Journal.verify(path)
  end

  test "journaling is optional: a nil handle is a no-op all the way through" do
    assert Journal.open(nil) == nil
    assert Journal.append(nil, "turn_started", %{"turn_id" => "t1"}) == nil
    assert Journal.sync(nil) == nil
  end

  # ---------------------------------------------------------------- degradation

  test "a failed append degrades the handle and the next success writes the gap", %{
    dir: dir,
    path: path
  } do
    journal = dir |> Journal.open() |> Journal.append("turn_started", %{"turn_id" => "t1"})
    refute journal.degraded?

    # A journal the process can no longer append to — the file is intact, the write is
    # refused. This is the shape a real failure has, and the one the effect must survive.
    File.chmod!(path, 0o400)

    journal = Journal.append(journal, "model_call", %{"turn_id" => "t1", "iteration" => 1})
    assert journal.degraded?
    assert File.regular?(path <> ".gap")
    assert records(path) |> length() == 1

    File.chmod!(path, 0o600)
    journal = Journal.append(journal, "turn_settled", %{"turn_id" => "t1"})

    assert [started, gap, settled] = records(path)
    assert started["kind"] == "turn_started"
    assert gap["kind"] == "gap"
    assert "model_call" in gap["dropped_kinds"]
    assert is_binary(gap["reason"])
    assert settled["kind"] == "turn_settled"
    refute File.exists?(path <> ".gap")

    # The gap is chained like anything else, so a verifier sees the loss inside the chain
    # rather than as a hole in it.
    assert {:ok, %{verified_through: through}} = Journal.verify(path)
    assert through == journal.seq
  end

  test "a gap staged by one writer is written by the next writer that succeeds", %{
    dir: dir,
    path: path
  } do
    journal = dir |> Journal.open() |> Journal.append("turn_started", %{"turn_id" => "t1"})

    File.chmod!(path, 0o400)
    _dead_loop = Journal.append(journal, "tool_result", %{"turn_id" => "t1", "tool" => "read"})
    File.chmod!(path, 0o600)

    # A brand-new handle — the session process, after the loop died — still writes the gap,
    # because it was staged on disk rather than in the struct that died with the loop.
    Journal.open(dir) |> Journal.append("configure", %{"key" => "model"})

    assert [_started, gap, configure] = records(path)
    assert gap["kind"] == "gap"
    assert gap["dropped_kinds"] == ["tool_result"]
    assert configure["kind"] == "configure"
    assert {:ok, %{verified_through: 3}} = Journal.verify(path)
  end

  # ---------------------------------------------------------------- blob spill

  test "a field over the spill threshold becomes a blob pointer", %{dir: dir, path: path} do
    big = String.duplicate("s", 300 * 1024)

    dir
    |> Journal.open(budget_bytes: 64 * 1024 * 1024)
    |> Journal.append("turn_started", %{"turn_id" => "t1", "system" => big, "model" => "x"})

    assert [record] = records(path)
    assert %{"blob" => digest, "bytes" => bytes} = record["system"]
    assert byte_size(digest) == 64
    assert bytes > 300 * 1024
    # Small fields are untouched — spilling is per field, not per record.
    assert record["model"] == "x"

    assert {:ok, ^big} = Journal.resolve_blob(dir, record["system"])
    assert File.regular?(Path.join(Checkpoint.blob_dir(dir), digest))

    # A record whose big field spilled is small, which is the point.
    assert byte_size(Journal.canonical_json(record)) < 2_000
    assert {:ok, %{verified_through: 1}} = Journal.verify(path)
  end

  test "identical spilled fields across turns dedup to one blob", %{dir: dir} do
    big = String.duplicate("p", 300 * 1024)

    dir
    |> Journal.open()
    |> Journal.append("turn_started", %{"turn_id" => "t1", "system" => big})
    |> Journal.append("turn_started", %{"turn_id" => "t2", "system" => big})

    assert {:ok, [_one]} = File.ls(Checkpoint.blob_dir(dir))
  end

  test "a turn_id is never spilled however long it is", %{dir: dir, path: path} do
    long = String.duplicate("t", 300 * 1024)

    dir |> Journal.open() |> Journal.append("turn_started", %{"turn_id" => long})

    assert [record] = records(path)
    assert record["turn_id"] == long
  end

  test "an unresolvable blob is a named marker, never a silent hole", %{dir: dir, path: path} do
    big = String.duplicate("e", 300 * 1024)
    dir |> Journal.open() |> Journal.append("prompt", %{"turn_id" => "t1", "content" => big})

    [record] = records(path)
    File.rm_rf!(Checkpoint.blob_dir(dir))

    assert {:error, {:blob_unavailable, _digest, :enoent}} =
             Journal.resolve_blob(dir, record["content"])
  end

  # ---------------------------------------------------------------- budget

  test "the budget drops the oldest whole turns behind a truncated record", %{
    dir: dir,
    path: path
  } do
    body = String.duplicate("b", 2_000)

    journal =
      Enum.reduce(1..8, Journal.open(dir, budget_bytes: 12_000), fn turn, journal ->
        journal
        |> Journal.append("turn_started", %{"turn_id" => "t#{turn}", "body" => body})
        |> Journal.append("turn_settled", %{"turn_id" => "t#{turn}", "status" => "complete"})
      end)

    all = records(path)
    head = hd(all)

    assert head["kind"] == "truncated"
    assert head["prev"] == Journal.seed()
    assert is_integer(head["dropped_through_seq"])
    assert byte_size(head["prior_head"]) == 64
    assert head["seq"] == head["dropped_through_seq"]

    # Whole turns only: no surviving turn is missing its opening record.
    survivors = tl(all)

    assert Enum.map(survivors, & &1["kind"])
           |> Enum.chunk_every(2)
           |> Enum.all?(&(&1 == ~w(turn_started turn_settled)))

    assert List.last(survivors)["turn_id"] == "t8"

    # Sequences stay contiguous from the head of the file, and the chain restarts at the
    # truncation record and verifies from there.
    assert Enum.map(all, & &1["seq"]) ==
             Enum.to_list(head["seq"]..(head["seq"] + length(all) - 1))

    assert {:ok, %{verified_through: through}} = Journal.verify(path)
    assert through == journal.seq
    assert File.stat!(path).size <= 12_000 + 4_000

    assert {:ok, window} = Journal.window(path)
    assert window.truncated_through == head["dropped_through_seq"]
  end

  test "a journal whose newest turn alone exceeds the budget is kept, not emptied", %{
    dir: dir,
    path: path
  } do
    journal =
      dir
      |> Journal.open(budget_bytes: 200)
      |> Journal.append("turn_started", %{"turn_id" => "t1", "body" => String.duplicate("x", 500)})

    assert [record] = records(path)
    assert record["kind"] == "turn_started"
    assert journal.seq == 1
  end

  # ---------------------------------------------------------------- windowing

  test "a window is bounded and cursored exclusively", %{dir: dir, path: path} do
    Enum.reduce(1..10, Journal.open(dir), fn n, journal ->
      Journal.append(journal, "injected", %{"turn_id" => "t1", "origin" => "steer", "n" => n})
    end)

    assert {:ok, %{records: records, count: 10, head_seq: 10, verified_through: 10}} =
             Journal.window(path, since_seq: 4, limit: 3)

    assert Enum.map(records, & &1["seq"]) == [5, 6, 7]

    assert {:ok, %{records: []}} = Journal.window(path, since_seq: 10, limit: 5)
  end

  # ---------------------------------------------------------------- encoding

  test "canonical json sorts keys so two writes of one record are one byte string" do
    assert Journal.canonical_json(%{"b" => 1, "a" => [2, %{"d" => 3, "c" => 4}]}) ==
             ~s({"a":[2,{"c":4,"d":3}],"b":1})

    assert Journal.canonical_json(%{"a" => 1, "b" => 2}) ==
             Journal.canonical_json(%{"b" => 2, "a" => 1})
  end

  test "terms the journal does not own are coerced rather than raising", %{dir: dir, path: path} do
    dir
    |> Journal.open()
    |> Journal.append("model_result", %{
      "turn_id" => "t1",
      "chunks" => [
        {:text, "hello"},
        {:thinking, "hmm"},
        {:usage, %{input: 10, output: 2}},
        {:finish, :stop}
      ],
      "pid" => self(),
      "binary" => <<0xFF, 0xFE>>
    })

    assert [record] = records(path)

    assert record["chunks"] == [
             ["text", "hello"],
             ["thinking", "hmm"],
             ["usage", %{"input" => 10, "output" => 2}],
             ["finish", "stop"]
           ]

    assert is_binary(record["pid"])
    assert record["binary"] == %{"base64" => Base.encode64(<<0xFF, 0xFE>>)}
    assert {:ok, %{verified_through: 1}} = Journal.verify(path)
  end
end

defmodule Ouroboros.Provider.Native.JournalBudgetConfigTest do
  # Not async: this sets the global `:ouroboros, :native_journal_budget_bytes` key, which
  # `Journal.open/2` reads at call time whenever the caller names no budget. An async
  # writer of that key would hand every journal opened alongside it a 4 KiB budget and
  # trim turns those tests never meant to lose, so the one test that exercises the config
  # fallback lives here, serial, rather than making the whole journal file serial (F8).
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Journal

  setup do
    dir = Path.join(System.tmp_dir!(), "native-journal-cfg-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    %{dir: dir}
  end

  test "the budget is read from application config when the caller names none", %{dir: dir} do
    previous = Application.get_env(:ouroboros, :native_journal_budget_bytes)
    Application.put_env(:ouroboros, :native_journal_budget_bytes, 4_242)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ouroboros, :native_journal_budget_bytes, previous),
        else: Application.delete_env(:ouroboros, :native_journal_budget_bytes)
    end)

    assert Journal.open(dir).budget_bytes == 4_242
  end
end
