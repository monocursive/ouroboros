defmodule Ouroboros.Provider.Native.Journal do
  @moduledoc """
  The append-only, hash-chained record of what a native session actually was.

  `<session dir>/journal.ndjson`, one JSON object per line, mode `0600`, beside
  `conversation.json` / `manifest.json` / `blobs/`. NDJSON rather than a rewritten
  document because append-only is what makes the chain sound: the conversation file's
  whole-rewrite discipline is right for *its* job — it is a cache of the model's context
  — and wrong for this one. The journal is the source of truth for what a session was;
  `conversation.json` is a cache of it for the model's benefit.

  ## Who writes it

  The loop process during a turn; the session process between turns (open, configure,
  compaction, rewind). Turns are sequential per session and session-side records are
  written only while no turn is running, so there is exactly one writer at a time **by
  construction** — the same argument the session already makes for the checkpoint.

  Because the two writers are two processes, a handle is not authoritative on its own:
  `sync/1` re-reads the file's tail and brings a handle current before it writes. The
  loop syncs once at the top of a turn, the session before each of its own records. That
  is one bounded tail read per writing window, never a scan of the whole file.

  Appends use `[:append, :binary, :raw]` with a `:file.sync` per record — one delta-sized
  fsync, where every tool call already costs two whole-ledger fsyncs.

  ## A journal write failure never refuses an effect

  The *effect ledger* is the authority gate ("a ledger that cannot record the call
  refuses it"); the journal is the record. On append failure the handle is marked
  degraded — the caller emits one `journal_degraded` provider event per turn — and a
  `gap` record naming what was lost is written by the next successful append. The pending
  gap is staged in a sidecar (`journal.ndjson.gap`) rather than in memory, so a gap
  survives the loop process dying and is written by whichever writer next succeeds. A
  sidecar write can itself fail, and then the gap is lost; that is the honest floor of a
  filesystem that has stopped accepting writes.

  ## The chain

  `hash = sha256(prev || canonical_json(record minus prev/hash))`, `prev` of the first
  record being 64 ASCII zeros — the same seed and canonical-JSON discipline as
  `Ouroboros.Gateway.Methods.Encode.chain/1`, so one verification idiom serves both. The
  chain is *stored* here because this file, unlike the effect ledger, is append-only and
  never mutates an existing record or evicts from the middle — the two properties whose
  absence makes a stored chain unsound there.

  Lines are written as canonical JSON of the whole record, `prev` and `hash` included, so
  a record read back re-encodes to the bytes on disk. That is what lets `truncate` below
  rewrite the survivors' chain without inventing values.

  ## Budget

  `:native_journal_budget_bytes`, 64 MiB by default. Past it the **oldest whole turns**
  are dropped by rewriting the file once, with a `truncated` record at the head carrying
  `dropped_through_seq` and `prior_head`. The truncation record takes the `seq` of the
  last record it dropped — so it stands in for the prefix rather than leaving a hole, and
  `seq` stays contiguous from the head of the file — and its `prev` is the seed, because
  the chain restarts there. The survivors are rechained onto it. A verifier therefore
  sees an explicit, signed-shape statement of what is missing rather than a silent hole.
  This is the turn manifest's dropped-is-a-recorded-state discipline applied here.

  Any single record field over 256 KiB (system prompts reach ~1.6 MB through instruction
  files) is spilled to the existing content-addressed `<session dir>/blobs/` store and
  replaced by `{"blob": "<sha256>", "bytes": n}`, sharing that store's budget and its
  honesty contract. Identical system prompts across turns dedup to one blob for free. A
  spill that fails is recorded as `{"blob": null, "bytes": n, "unspilled": reason}` —
  degraded, stated, never silent.
  """

  require Logger

  alias Ouroboros.Provider.Native.Checkpoint

  @filename "journal.ndjson"
  @gap_suffix ".gap"
  @journal_version 1

  # The same published seed as `ledger.export`'s chain: the point of a chain is that a
  # reader can recompute it from what it was handed, so the start is a constant rather
  # than a secret.
  @seed String.duplicate("0", 64)

  @default_budget_bytes 64 * 1024 * 1024
  @blob_field_bytes 256 * 1024
  # How far back the tail read looks for the last newline before giving up and scanning
  # the file. A record larger than this is possible only when every large field spilled
  # to a blob and the remainder is still enormous, which the budget would already have
  # caught.
  @tail_window_bytes 256 * 1024

  @kinds ~w(
    session_opened turn_started prompt model_call model_result tool_result injected
    approval configure compaction rewind turn_settled gap truncated
  )

  defstruct [
    :path,
    :session_dir,
    seq: 0,
    prev: @seed,
    bytes: 0,
    budget_bytes: nil,
    degraded?: false
  ]

  @type t :: %__MODULE__{}

  @doc "The seed every journal chain starts from."
  @spec seed() :: String.t()
  def seed, do: @seed

  @doc "Where one session's journal lives."
  @spec path(String.t()) :: String.t()
  def path(session_dir), do: Path.join(session_dir, @filename)

  @doc "The record kinds this version writes."
  @spec kinds() :: [String.t()]
  def kinds, do: @kinds

  @doc "The journal format version, carried by every `session_opened` record."
  @spec version() :: pos_integer()
  def version, do: @journal_version

  @doc """
  Opens (creating if need be) the journal for a session directory.

  Never returns an error: a journal that cannot be opened is a *degraded* handle, because
  the one thing this module must not do is turn a recording failure into a refused
  effect. The caller reads `degraded?` and says so once.
  """
  @spec open(String.t() | nil, keyword()) :: t() | nil
  def open(session_dir, opts \\ [])

  def open(nil, _opts), do: nil

  def open(session_dir, opts) when is_binary(session_dir) do
    %__MODULE__{
      path: path(session_dir),
      session_dir: session_dir,
      budget_bytes: budget_bytes(opts)
    }
    |> sync()
  end

  @doc """
  Brings a handle current with the file another writer may have advanced.

  A bounded tail read, not a scan: only the last complete line is parsed, for its `seq`
  and `hash`. Also clears `degraded?`, which is per writing window — the loop syncs at
  the top of each turn, so "once per turn" falls out of this rather than out of a counter
  somebody has to reset.
  """
  @spec sync(t() | nil) :: t() | nil
  def sync(nil), do: nil

  def sync(%__MODULE__{} = journal) do
    journal = %{journal | degraded?: false}

    case last_record(journal.path) do
      {:ok, nil, bytes} ->
        %{journal | seq: 0, prev: @seed, bytes: bytes}

      {:ok, record, bytes} ->
        %{journal | seq: seq_of(record), prev: Map.get(record, "hash", @seed), bytes: bytes}

      # An unreadable or unparseable tail is not a reason to stop recording, and it is
      # not a reason to guess either: refuse to append onto a file whose head we cannot
      # name, and let the caller report the degradation.
      {:error, reason} ->
        Logger.warning("native journal tail was unreadable (#{inspect(reason)}): #{journal.path}")
        %{journal | degraded?: true}
    end
  end

  @doc """
  Appends one record and returns the advanced handle.

  Never raises and never returns an error. A failed append marks the handle `degraded?`
  and stages a `gap` for the next successful write; the caller's effect proceeds either
  way. `nil` in, `nil` out, which is what makes journaling optional for the coding plane
  and for tests that have no session directory.
  """
  @spec append(t() | nil, String.t() | atom(), map()) :: t() | nil
  def append(nil, _kind, _fields), do: nil

  def append(%__MODULE__{degraded?: true} = journal, kind, fields) do
    # Still try: a transient failure should not disable the journal for the rest of the
    # turn. What `degraded?` buys is that the caller announces it only once.
    do_append(journal, kind, fields)
  end

  def append(%__MODULE__{} = journal, kind, fields), do: do_append(journal, kind, fields)

  defp do_append(journal, kind, fields) do
    journal = flush_gap(journal)

    case write_record(journal, to_string(kind), fields) do
      {:ok, journal} -> enforce_budget(journal)
      {:error, journal} -> journal
    end
  end

  # The staged gap goes in *before* the record that finally succeeded, so the file reads
  # in the order the failures happened.
  defp flush_gap(journal) do
    case read_gap(journal) do
      nil ->
        journal

      staged ->
        case write_record(journal, "gap", staged) do
          {:ok, journal} ->
            _ = File.rm(gap_path(journal))
            journal

          {:error, journal} ->
            journal
        end
    end
  end

  defp write_record(journal, kind, fields) do
    record = build(journal, kind, fields)
    line = canonical_json(record) <> "\n"

    case append_line(journal.path, line) do
      :ok ->
        {:ok,
         %{
           journal
           | seq: record["seq"],
             prev: record["hash"],
             bytes: journal.bytes + byte_size(line)
         }}

      {:error, reason} ->
        {:error, degrade(journal, kind, reason)}
    end
  end

  defp build(journal, kind, fields) do
    seq = journal.seq + 1

    fields
    |> spill(journal)
    |> Map.merge(%{
      "seq" => seq,
      "at" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "turn_id" => turn_id(fields),
      "kind" => kind
    })
    |> seal(journal.prev)
  end

  # `hash` covers the record and the chain, and covers neither of itself: `prev` is
  # hashed as the prefix rather than as a field, exactly as `Encode.chain/1` does it.
  defp seal(body, prev) do
    hash =
      :sha256
      |> :crypto.hash([prev, canonical_json(body)])
      |> Base.encode16(case: :lower)

    body |> Map.put("prev", prev) |> Map.put("hash", hash)
  end

  defp turn_id(fields), do: Map.get(fields, "turn_id") || Map.get(fields, :turn_id)

  # ---------------------------------------------------------------- blob spill

  defp spill(fields, journal) do
    fields
    |> Map.new(fn {key, value} -> {to_string(key), jsonable(value)} end)
    |> Map.drop(["seq", "at", "kind", "prev", "hash"])
    |> Map.new(fn {key, value} -> {key, spill_field(key, value, journal)} end)
  end

  # `turn_id` is an identity every reader indexes by; it is never spilled however long a
  # caller made it.
  defp spill_field("turn_id", value, _journal), do: value

  defp spill_field(_key, value, journal) do
    encoded = canonical_json(value)
    size = byte_size(encoded)

    if size > @blob_field_bytes do
      case Checkpoint.put_blob(journal.session_dir, encoded) do
        digest when is_binary(digest) ->
          %{"blob" => digest, "bytes" => size}

        {:unsnapshotted, reason} ->
          %{"blob" => nil, "bytes" => size, "unspilled" => oneline(reason)}
      end
    else
      value
    end
  end

  @doc """
  Reads a spilled field back, or says why it cannot.

  A blob the store has since evicted is a named marker on replay rather than a silent
  hole, which is the same contract the file checkpoint makes about a dropped turn.
  """
  @spec resolve_blob(String.t(), map()) :: {:ok, term()} | {:error, term()}
  def resolve_blob(session_dir, %{"blob" => digest}) when is_binary(digest) do
    case Checkpoint.get_blob(session_dir, digest) do
      {:ok, content} -> decode(content)
      {:error, reason} -> {:error, {:blob_unavailable, digest, reason}}
    end
  end

  def resolve_blob(_session_dir, %{"blob" => nil} = marker),
    do: {:error, {:blob_never_written, Map.get(marker, "unspilled")}}

  def resolve_blob(_session_dir, other), do: {:error, {:not_a_blob_marker, other}}

  # ---------------------------------------------------------------- degradation

  defp degrade(journal, kind, reason) do
    stage_gap(journal, kind, reason)
    %{journal | degraded?: true}
  end

  # The sidecar rather than the handle, because the writer that failed may not be the
  # writer that next succeeds — the loop dies mid-turn and the session opens the next
  # one. A gap that lived only in a struct would die with it.
  defp stage_gap(journal, kind, reason) do
    staged = read_gap(journal) || %{"reason" => nil, "dropped_kinds" => []}

    merged = %{
      "reason" => Map.get(staged, "reason") || oneline(reason),
      "dropped_kinds" =>
        Enum.uniq(Map.get(staged, "dropped_kinds", []) ++ [kind]) |> Enum.take(32)
    }

    case File.write(gap_path(journal), JSON.encode!(merged), [:binary, :sync]) do
      :ok ->
        _ = File.chmod(gap_path(journal), 0o600)
        :ok

      {:error, sidecar_reason} ->
        Logger.warning(
          "native journal could not stage a gap marker (#{inspect(sidecar_reason)}) after " <>
            "failing to append a #{kind} record (#{inspect(reason)}): #{journal.path}"
        )

        :ok
    end
  end

  defp gap_path(journal), do: journal.path <> @gap_suffix

  defp read_gap(journal) do
    with {:ok, json} <- File.read(gap_path(journal)),
         {:ok, %{"reason" => _reason} = staged} <- decode(json) do
      staged
    else
      _absent_or_unusable -> nil
    end
  end

  # ---------------------------------------------------------------- budget

  defp enforce_budget(%{budget_bytes: budget, bytes: bytes} = journal)
       when is_integer(budget) and budget > 0 and bytes > budget,
       do: truncate(journal)

  defp enforce_budget(journal), do: journal

  # Rewrite once, oldest whole turns first, and never everything: a budget that could
  # drop the turn just written would make a fresh journal unreplayable the moment it was
  # recorded.
  defp truncate(journal) do
    with {:ok, records} <- read_all(journal.path),
         {[_ | _] = dropped, [_ | _] = kept} <- split_turns(records, journal.budget_bytes) do
      dropped_through = dropped |> List.last() |> seq_of()
      prior_head = records |> List.last() |> Map.get("hash", @seed)

      head =
        seal(
          %{
            "seq" => dropped_through,
            "at" => DateTime.utc_now() |> DateTime.to_iso8601(),
            "turn_id" => nil,
            "kind" => "truncated",
            "dropped_through_seq" => dropped_through,
            "prior_head" => prior_head
          },
          @seed
        )

      {lines, {prev, seq}} =
        Enum.map_reduce(kept, {head["hash"], dropped_through}, fn record, {prev, _seq} ->
          rechained = record |> Map.drop(["prev", "hash"]) |> seal(prev)
          {canonical_json(rechained) <> "\n", {rechained["hash"], seq_of(rechained)}}
        end)

      contents = [canonical_json(head) <> "\n" | lines]

      case rewrite(journal.path, contents) do
        :ok ->
          %{journal | seq: seq, prev: prev, bytes: IO.iodata_length(contents)}

        {:error, reason} ->
          degrade(journal, "truncated", reason)
      end
    else
      # Nothing droppable (one turn already fills the budget), or a file we cannot read
      # back. Either way the journal keeps growing and says so rather than deleting a
      # record it could not account for.
      _unsplittable -> journal
    end
  end

  # Whole turns, oldest first. A record with no `turn_id` — `session_opened`, a
  # `configure` between turns — is its own unit, so a session-level record can never pin
  # a turn's worth of bytes in place.
  defp split_turns(records, budget) do
    groups = Enum.chunk_by(records, &Map.get(&1, "turn_id"))
    total = Enum.reduce(records, 0, &(byte_size(canonical_json(&1)) + 1 + &2))

    {dropped, kept, _bytes} =
      Enum.reduce(groups, {[], [], total}, fn group, {dropped, kept, bytes} ->
        group_bytes = Enum.reduce(group, 0, &(byte_size(canonical_json(&1)) + 1 + &2))

        # `kept == []` keeps the drop contiguous at the head; the last group is never
        # offered, which is what "never the newest" means here.
        if kept == [] and bytes > budget and group != List.last(groups) do
          {dropped ++ group, kept, bytes - group_bytes}
        else
          {dropped, kept ++ group, bytes}
        end
      end)

    {dropped, kept}
  end

  # ---------------------------------------------------------------- reading

  @doc """
  Walks the whole file and verifies the chain.

  `{:ok, %{records:, head:, verified_through:}}`, or `{:error, {:chain_broken, seq}}`
  naming the first record whose stored hash is not the one its contents and its
  predecessor produce. A missing file is an empty journal, not a failure: a session that
  has recorded nothing yet is an ordinary state.
  """
  @spec verify(String.t()) :: {:ok, map()} | {:error, term()}
  def verify(path) when is_binary(path) do
    case scan(path) do
      {:ok, %{broken_at: nil} = scanned} ->
        {:ok, Map.take(scanned, [:records, :head, :verified_through])}

      {:ok, %{broken_at: seq}} ->
        {:error, {:chain_broken, seq}}

      {:error, _reason} = error ->
        error
    end
  end

  @doc """
  A window of records for a reader, with the chain state that bounds what it means.

  Unlike `verify/1` a broken chain is reported rather than raised: `verified_through` is
  the last sequence that checked out, and a caller comparing it against `head_seq` learns
  exactly how far the record can be trusted. `truncated_through` is the
  `dropped_through_seq` of a truncation record if the file carries one.
  """
  @spec window(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def window(path, opts \\ []) when is_binary(path) do
    since = Keyword.get(opts, :since_seq, 0)
    limit = Keyword.get(opts, :limit, 200)

    with {:ok, scanned} <- scan(path) do
      window = scanned.records |> Enum.filter(&(seq_of(&1) > since)) |> Enum.take(limit)

      {:ok,
       %{
         head: scanned.head,
         head_seq: scanned.head_seq,
         verified_through: scanned.verified_through,
         truncated_through: scanned.truncated_through,
         count: length(scanned.records),
         records: window
       }}
    end
  end

  defp scan(path) do
    case File.read(path) do
      {:ok, contents} ->
        {:ok, fold(contents)}

      {:error, :enoent} ->
        {:ok,
         %{
           records: [],
           head: @seed,
           head_seq: 0,
           verified_through: 0,
           truncated_through: nil,
           broken_at: nil
         }}

      {:error, reason} ->
        {:error, {:journal_unreadable, reason}}
    end
  end

  defp fold(contents) do
    contents
    |> String.split("\n", trim: true)
    |> Enum.reduce(
      %{
        records: [],
        head: @seed,
        head_seq: 0,
        verified_through: 0,
        truncated_through: nil,
        broken_at: nil,
        prev: @seed
      },
      &fold_line/2
    )
    |> then(fn state ->
      state |> Map.put(:records, Enum.reverse(state.records)) |> Map.delete(:prev)
    end)
  end

  defp fold_line(line, acc) do
    case decode(line) do
      {:ok, %{"hash" => hash, "prev" => prev} = record} when is_binary(hash) ->
        absorb(acc, record, prev, hash)

      _unparseable ->
        %{acc | broken_at: acc.broken_at || acc.head_seq + 1}
    end
  end

  defp absorb(acc, record, prev, hash) do
    body = Map.drop(record, ["prev", "hash"])

    expected =
      :sha256 |> :crypto.hash([prev, canonical_json(body)]) |> Base.encode16(case: :lower)

    # A truncation record restarts the chain from the seed, which is the whole point of
    # writing one: the prefix is gone and the file says so in a shape a verifier checks
    # rather than infers from a hole.
    linked? = prev == acc.prev or (record["kind"] == "truncated" and prev == @seed)

    acc = %{
      acc
      | records: [record | acc.records],
        head: hash,
        head_seq: seq_of(record),
        prev: hash,
        truncated_through: truncated_through(acc, record)
    }

    if is_nil(acc.broken_at) and linked? and expected == hash do
      %{acc | verified_through: seq_of(record)}
    else
      %{acc | broken_at: acc.broken_at || seq_of(record)}
    end
  end

  defp truncated_through(acc, %{"kind" => "truncated", "dropped_through_seq" => through}),
    do: through || acc.truncated_through

  defp truncated_through(acc, _record), do: acc.truncated_through

  defp read_all(path) do
    with {:ok, contents} <- File.read(path) do
      records =
        contents
        |> String.split("\n", trim: true)
        |> Enum.flat_map(fn line ->
          case decode(line) do
            {:ok, record} when is_map(record) -> [record]
            _unparseable -> []
          end
        end)

      {:ok, records}
    end
  end

  # The tail read `sync/1` runs: seek back a bounded window, take the last complete line.
  defp last_record(path) do
    case File.stat(path) do
      {:ok, %File.Stat{size: 0}} ->
        {:ok, nil, 0}

      {:ok, %File.Stat{size: size}} ->
        offset = max(size - @tail_window_bytes, 0)

        with {:ok, device} <- File.open(path, [:read, :binary, :raw]),
             {:ok, chunk} <- :file.pread(device, offset, size - offset),
             :ok <- File.close(device) do
          case chunk |> String.split("\n", trim: true) |> List.last() do
            nil -> {:ok, nil, size}
            line -> with {:ok, record} <- decode(line), do: {:ok, record, size}
          end
        end

      {:error, :enoent} ->
        {:ok, nil, 0}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ---------------------------------------------------------------- io

  defp append_line(path, line) do
    with :ok <- File.mkdir_p(Path.dirname(path)),
         {:ok, device} <- File.open(path, [:append, :binary, :raw]) do
      result =
        case :file.write(device, line) do
          :ok -> :file.sync(device)
          other -> other
        end

      _ = File.close(device)
      _ = File.chmod(path, 0o600)
      result
    end
  end

  # Truncation is the one rewrite this file admits, and it is atomic for the same reason
  # the conversation's is: a reader must never see half a journal.
  defp rewrite(path, contents) do
    temporary = path <> ".tmp-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

    with :ok <- File.write(temporary, contents, [:binary, :sync]),
         :ok <- File.chmod(temporary, 0o600),
         :ok <- File.rename(temporary, path) do
      :ok
    else
      {:error, reason} ->
        _ = File.rm(temporary)
        {:error, reason}
    end
  end

  # ---------------------------------------------------------------- encoding

  @doc """
  Object keys sorted, no whitespace — the canonical form the chain is computed over.

  `JSON.encode!/1` iterates a map in whatever order the term happens to have, which is
  stable enough in practice and not a property worth betting a hash chain on: two writes
  of the same record have to produce the same bytes, on any machine, or the chain a
  reader verifies is a chain over an accident.
  """
  @spec canonical_json(term()) :: binary()
  def canonical_json(value), do: value |> canonical() |> IO.iodata_to_binary()

  defp canonical(map) when is_map(map) and not is_struct(map) do
    inner =
      map
      |> Enum.sort_by(fn {key, _value} -> to_string(key) end)
      |> Enum.map(fn {key, value} -> [JSON.encode!(to_string(key)), ?:, canonical(value)] end)
      |> Enum.intersperse(?,)

    [?{, inner, ?}]
  end

  defp canonical(list) when is_list(list),
    do: [?[, list |> Enum.map(&canonical/1) |> Enum.intersperse(?,), ?]]

  defp canonical(other), do: JSON.encode!(other)

  @doc "A stable SHA-256 over any journal-shaped term, in the chain's own encoding."
  @spec digest(term()) :: String.t()
  def digest(value),
    do: :sha256 |> :crypto.hash(canonical_json(value)) |> Base.encode16(case: :lower)

  @doc """
  Coerces a term into something `canonical_json/1` can encode without raising.

  Records carry chunk lists, tool inputs and provider metadata — terms this module does
  not own and cannot constrain. An atom becomes its name, a tuple a list, a struct a map,
  and anything left over its `inspect`: a record that recorded *something* about a value
  it could not encode is worth more than a turn that failed because a provider returned a
  shape nobody anticipated.
  """
  @spec jsonable(term()) :: term()
  def jsonable(value) when is_binary(value) do
    if String.valid?(value), do: value, else: %{"base64" => Base.encode64(value)}
  end

  def jsonable(value) when is_number(value) or is_boolean(value) or is_nil(value), do: value
  def jsonable(value) when is_atom(value), do: Atom.to_string(value)
  def jsonable(value) when is_list(value), do: Enum.map(value, &jsonable/1)
  def jsonable(value) when is_tuple(value), do: value |> Tuple.to_list() |> jsonable()

  def jsonable(%{__struct__: _module} = value),
    do: value |> Map.from_struct() |> jsonable()

  def jsonable(value) when is_map(value),
    do: Map.new(value, fn {key, inner} -> {to_string(key), jsonable(inner)} end)

  def jsonable(value), do: inspect(value)

  defp decode(json) do
    {:ok, JSON.decode!(json)}
  rescue
    _error -> :error
  end

  defp seq_of(%{"seq" => seq}) when is_integer(seq), do: seq
  defp seq_of(_record), do: 0

  defp oneline(reason), do: reason |> inspect(limit: 6) |> String.slice(0, 200)

  defp budget_bytes(opts) do
    configured =
      Keyword.get(opts, :budget_bytes) ||
        Application.get_env(:ouroboros, :native_journal_budget_bytes)

    case configured do
      value when is_integer(value) and value > 0 -> value
      _unset -> @default_budget_bytes
    end
  end
end
