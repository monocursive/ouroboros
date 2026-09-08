defmodule Ouroboros.Control.PolicyEvidence do
  @moduledoc """
  The decisions humans actually made on this node, in the form a policy component sees them
  (docs/SELF.md §S2, S-D20).

  A signed policy component may only *narrow*: an `allow` it returns is honoured for a tool
  named in `config :ouroboros, :policy_allowable_tools`, which is empty by default (docs/WASM.md
  D20). Widening that list is an operator typing a tool name, and the whole point of S2 is that
  there is one other way — replay the component against decisions a human already made and
  promote a tool only where the component agreed with every one of them.

  Replay needs a corpus, and before this module there was nothing durable to replay. A
  `:permission` ledger entry holds `%{tool, mode, provider, fingerprint}` where the fingerprint
  is a sha256 over the command line, the paths and the domains
  (`Ouroboros.Control.Permissions.fingerprint/1`); the session journal writes the approval
  *question* as a digest too. Both are deliberate — the ledger is content-minimized and stays
  that way — and both mean that nothing on this node held the request a policy would be shown.

  So this file does, and only this file: `<data_dir>/policy/evidence.ndjson`, one JSON object
  per line, directory `0700` and file `0600`, holding for each human answer

      {at, node, session_id, tool, mode, fingerprint, decision, scope, permission_entry_id,
       document}

  where `document` is **exactly** `Ouroboros.Wasm.PolicyEngine.document/1`'s output for the
  request — the same bytes, redacted by the engine's own redaction, that the component would
  have been handed. A replay that built its own document would be replaying a request this node
  never sends.

  ## What is written, and what is not

  One record per answer whose `actor` is `:human` **and** which carries a request. Nothing for
  `actor: :rule` — a rule's answer is the rule, and replaying a component against decisions the
  rules already make would measure the rules — and nothing for `actor: :classifier`, which is
  the policy component's own verdict and would be the component grading itself.

  An answer with no request writes nothing: `Ouroboros.Control.Permissions.record/2` accepts one
  without, and a record with no document is not evidence of anything.

  ## A write failure never refuses the answer

  The effect ledger is the authority ("a ledger that cannot record the call refuses it"); this
  is the corpus. A failed append is logged once per reason for the life of the node and the
  answer stands. The direction that costs is the safe one: a corpus that lost records replays
  with *fewer* decisions, so `promote/4`'s `decisions >= 50` threshold is harder to reach, never
  easier — and there is no failure of this module that can invent an agreement.

  ## Bounds

  #{10_000} records or #{64} MiB, whichever comes first. Past either the oldest records are
  dropped by one rewrite to #{90}% of the bound —
  `Ouroboros.Provider.Native.Journal`'s discipline, without its chain: this file is a bag of
  independent rows rather than a sequence, so a dropped prefix leaves nothing to re-link and a
  reader that must know how much is here asks `count/0` rather than reading a header. The
  low-water mark is what keeps a full corpus from rewriting itself on every subsequent append.

  Appends are `O_APPEND` with one `:file.write` and one `:file.sync`, which is the same atomicity
  the journal relies on. A rewrite that races an append can lose that append; that is stated
  rather than locked away because a lost record costs one decision out of ten thousand and the
  direction is, again, fewer decisions.

  ## Nothing here is served over the gateway

  A record holds a command line. It is node-local, it is read by `PolicyEngine.replay/2` in the
  same VM, and the only thing S2b exposes is the per-tool **count** under `:read`. A fleet-wide
  replay would be a fleet-wide export of command lines and is not in v1 (plan §0 row 9).

  ## Where it lives

  `<data_dir>/policy/` unless `config :ouroboros, :policy_evidence_root` names a directory.
  That key is a **test seam**, the same kind as `:wasm_policy_opts`' `:store_root` and
  `:permissions_ledger`: it is what lets a test write a corpus it controls and read it back.
  Absent a data directory and absent the seam there is nowhere to write, and every write is
  `:skipped` — a node with no durable state has no corpus, which is honest and is also what a
  bare `mix test` looks like.
  """

  require Logger

  alias Ouroboros.Control.Permissions
  alias Ouroboros.Control.Permissions.Request

  @filename "evidence.ndjson"

  # The bound, in records and in bytes. Ten thousand human answers is more than a busy node
  # produces in a month and five times what `promote/4` needs at its threshold; sixty-four
  # mebibytes is the journal's budget, for the same reason — it is the number past which a file
  # nobody rotates becomes a file nobody can read.
  @max_records 10_000
  @max_bytes 64 * 1024 * 1024

  # Where a rewrite drops to. Rewriting to exactly the bound would rewrite the whole file on
  # every append after the first one that crossed it.
  @low_water 0.9

  # A true lower bound on a row this module writes: the ten key names alone are over a hundred
  # bytes, the `at` stamp is twenty-seven and the fingerprint's digest is sixty-four. It is the
  # gate on reading the file back to count its records, so it is deliberately far below the real
  # figure — an over-estimate here would let the record bound go unenforced.
  @min_row_bytes 200

  # The actors whose answers are evidence. `:rule` is the rules deciding, `:classifier` is the
  # policy component deciding — neither is a human, and both would make a replay measure
  # something other than what it claims to.
  @evidence_actors [:human]

  @typedoc "One row of the corpus, as it is read back off disk: string keys, JSON values."
  @type row :: %{String.t() => term()}

  @doc """
  Writes one human answer to the corpus. Never raises, never refuses the answer.

  `:skipped` when the answer is not evidence (no request, or an actor that is not a human) and
  when there is nowhere to write. `{:error, reason}` when there was somewhere and the write
  failed, which the caller ignores and this module logs once.
  """
  @spec write(String.t() | nil, map(), Request.t() | nil) :: :ok | :skipped | {:error, term()}
  def write(permission_entry_id, answer, request)

  def write(permission_entry_id, answer, %Request{} = request) when is_map(answer) do
    if Map.get(answer, :actor, :human) in @evidence_actors do
      append(row(permission_entry_id, answer, request))
    else
      :skipped
    end
  end

  def write(_permission_entry_id, _answer, _request), do: :skipped

  @doc """
  The corpus, oldest first, as a lazy stream of `{:ok, record}` and `:unreadable`.

  `:unreadable` is a line this build cannot decode — a torn append, a file somebody edited. It
  is *yielded* rather than dropped because a replay that silently skipped rows would report a
  corpus size that was not the corpus, and `PolicyEngine.replay/2` counts them.

  Options: `:since`, an ISO 8601 string or a `DateTime`, keeping records at or after it; and
  `:tool`, keeping records for one tool. Both are applied to decoded rows, so a row that is
  unreadable is yielded whatever the filters say — it is exactly the row nobody can filter.
  """
  @spec stream(keyword()) :: Enumerable.t()
  def stream(opts \\ []) when is_list(opts) do
    since = since(Keyword.get(opts, :since))
    tool = Keyword.get(opts, :tool)

    case path() do
      nil ->
        []

      path ->
        if File.regular?(path) do
          path
          |> File.stream!(:line, [{:read_ahead, 64 * 1024}])
          |> Stream.map(&decode/1)
          |> Stream.filter(&keep?(&1, since, tool))
        else
          []
        end
    end
  rescue
    _unreadable -> []
  end

  @doc """
  How much is in the corpus: the total, the per-tool counts, and the two degraded counts.

  `without_document` is answers whose request would not fit in
  `Ouroboros.Wasm.PolicyEngine.document/1`'s bound — the row is kept because "a human answered
  about a request too large to show a component" is itself a fact worth counting, and it is
  counted here rather than folded into the total silently. `unreadable` is lines this build
  could not decode.

  This is the one thing S2b may serve over the gateway, under `:read`: counts, never rows.
  """
  @spec count() :: %{
          records: non_neg_integer(),
          by_tool: %{String.t() => non_neg_integer()},
          without_document: non_neg_integer(),
          unreadable: non_neg_integer()
        }
  def count do
    Enum.reduce(
      stream(),
      %{records: 0, by_tool: %{}, without_document: 0, unreadable: 0},
      fn
        :unreadable, acc ->
          %{acc | unreadable: acc.unreadable + 1}

        {:ok, record}, acc ->
          tool = Map.get(record, "tool", "unknown")

          %{
            acc
            | records: acc.records + 1,
              by_tool: Map.update(acc.by_tool, tool, 1, &(&1 + 1)),
              without_document:
                acc.without_document + if(is_binary(record["document"]), do: 0, else: 1)
          }
      end
    )
  end

  @doc """
  Where the corpus is, or `nil` when this node has nowhere to keep one.

  `config :ouroboros, :policy_evidence_root` first — the test seam — then
  `<data_dir>/policy`.
  """
  @spec path() :: String.t() | nil
  def path do
    case root() do
      nil -> nil
      dir -> Path.join(dir, @filename)
    end
  end

  @doc "The directory `path/0` lives in, or `nil`."
  @spec root() :: String.t() | nil
  def root do
    case Application.get_env(:ouroboros, :policy_evidence_root) do
      dir when is_binary(dir) and dir != "" ->
        dir

      _unset ->
        case Application.get_env(:ouroboros, :data_dir) do
          dir when is_binary(dir) and dir != "" -> Path.join(dir, "policy")
          _unset -> nil
        end
    end
  end

  @doc false
  @spec max_records() :: pos_integer()
  def max_records, do: @max_records

  @doc false
  @spec max_bytes() :: pos_integer()
  def max_bytes, do: @max_bytes

  ## ── the row ───────────────────────────────────────────────────────────────────────────

  # Exactly the ten keys the plan names, and `document` is the engine's own output rather than
  # anything assembled here: the contract a component reads is `PolicyEngine.document/1`'s, and
  # a corpus that encoded its own would be a corpus of requests this node never sends.
  defp row(permission_entry_id, answer, %Request{} = request) do
    document =
      case Ouroboros.Wasm.PolicyEngine.document(request) do
        {:ok, encoded} -> encoded
        :too_large -> nil
      end

    fingerprint = Permissions.fingerprint(request)

    %{
      "at" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "node" => to_string(node()),
      "session_id" => request.principal.session_id,
      "tool" => request.tool,
      "mode" => to_string(request.mode),
      "fingerprint" => %{"sha256" => fingerprint.sha256, "bytes" => fingerprint.bytes},
      "decision" => to_string(Map.get(answer, :decision)),
      "scope" => to_string(Map.get(answer, :scope, :once)),
      "permission_entry_id" => permission_entry_id,
      "document" => document
    }
  end

  ## ── writing ───────────────────────────────────────────────────────────────────────────

  defp append(row) do
    case path() do
      nil ->
        :skipped

      path ->
        line = JSON.encode!(row) <> "\n"

        case append_line(path, line) do
          :ok ->
            enforce_bounds(path)
            :ok

          {:error, reason} ->
            warn_once(reason, "policy evidence could not be appended to #{path}")
            {:error, reason}
        end
    end
  rescue
    # `JSON.encode!/1` on a document field that is not valid UTF-8, a filesystem that raises.
    # A corpus is not an authority: the answer that produced this row has already been made.
    error ->
      warn_once(:exception, "policy evidence write raised: #{Exception.message(error)}")
      {:error, {:policy_evidence_write_failed, Exception.message(error)}}
  end

  # The journal's `append_line/2`, with the directory created private rather than merely
  # created: this file holds command lines, and a `0755` directory around a `0600` file names
  # them to anybody who can list it.
  defp append_line(path, line) do
    dir = Path.dirname(path)

    with :ok <- File.mkdir_p(dir),
         _ = File.chmod(dir, 0o700),
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

  # Both bounds, from one `stat` and — below the cheap gate — no read at all.
  #
  # The byte bound is knowable from the stat. The record bound is not, so the stat also gates
  # the read: every row this module writes carries ten keys, an ISO 8601 stamp and a 64-character
  # digest, so none of them is under #{@min_row_bytes} bytes and a file smaller than
  # #{@max_records} of those cannot hold #{@max_records} records. Past that gate the file is read
  # once and the same read serves both the count and the rewrite.
  defp enforce_bounds(path) do
    case File.stat(path) do
      {:ok, %{size: size}} when size > @max_bytes or size > @max_records * @min_row_bytes ->
        rewrite(path)

      _under_the_gate_or_gone ->
        :ok
    end
  end

  # One rewrite, oldest first, down to the low-water mark. Atomic, for the reason the journal's
  # is: a reader must never see half a corpus.
  #
  # Lines are moved verbatim rather than re-encoded — an unreadable line stays unreadable and
  # keeps its place in the count rather than being silently deleted by the thing that was
  # supposed to bound the file.
  defp rewrite(path) do
    with {:ok, contents} <- File.read(path) do
      lines = String.split(contents, "\n", trim: true)

      if length(lines) <= @max_records and byte_size(contents) <= @max_bytes do
        :ok
      else
        drop_oldest(path, lines)
      end
    else
      {:error, reason} ->
        warn_once(reason, "policy evidence could not be read back to enforce its bound")
        :ok
    end
  end

  defp drop_oldest(path, lines) do
    keep_records = trunc(@max_records * @low_water)
    keep_bytes = trunc(@max_bytes * @low_water)

    # The newest row is kept before the budget is consulted, so a corpus is never emptied by
    # the thing that was supposed to bound it — the journal's "nothing droppable" floor, in the
    # one shape this file can reach it in. Defensive rather than reachable through `write/3`,
    # whose rows are bounded by `PolicyEngine.document/1`'s 64 KiB.
    [newest | older] = Enum.reverse(lines)

    kept =
      older
      |> Enum.reduce_while({[newest], 1, byte_size(newest) + 1}, fn line, {kept, count, bytes} ->
        size = byte_size(line) + 1

        if count >= keep_records or bytes + size > keep_bytes,
          do: {:halt, {kept, count, bytes}},
          else: {:cont, {[line | kept], count + 1, bytes + size}}
      end)
      |> elem(0)

    if kept == lines,
      do: :ok,
      else: replace(path, Enum.map(kept, &(&1 <> "\n")))
  end

  defp replace(path, contents) do
    temporary = path <> ".tmp-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

    with :ok <- File.write(temporary, contents, [:binary, :sync]),
         :ok <- File.chmod(temporary, 0o600),
         :ok <- File.rename(temporary, path) do
      :ok
    else
      {:error, reason} ->
        _ = File.rm(temporary)
        warn_once(reason, "policy evidence could not be rewritten to its bound")
        :ok
    end
  end

  ## ── reading ───────────────────────────────────────────────────────────────────────────

  defp decode(line) do
    case JSON.decode(line) do
      {:ok, record} when is_map(record) -> {:ok, record}
      _not_a_row -> :unreadable
    end
  rescue
    _error -> :unreadable
  end

  defp keep?(:unreadable, _since, _tool), do: true

  defp keep?({:ok, record}, since, tool) do
    (is_nil(tool) or Map.get(record, "tool") == tool) and
      (is_nil(since) or at_or_after?(Map.get(record, "at"), since))
  end

  defp at_or_after?(at, since) when is_binary(at) do
    case DateTime.from_iso8601(at) do
      {:ok, stamp, _offset} -> DateTime.compare(stamp, since) != :lt
      _unparseable -> false
    end
  end

  defp at_or_after?(_at, _since), do: false

  defp since(nil), do: nil
  defp since(%DateTime{} = stamp), do: stamp

  defp since(stamp) when is_binary(stamp) do
    case DateTime.from_iso8601(stamp) do
      {:ok, parsed, _offset} -> parsed
      _unparseable -> nil
    end
  end

  defp since(_other), do: nil

  ## ── odds and ends ─────────────────────────────────────────────────────────────────────

  # Once per reason, for the life of the node. A filesystem that has stopped accepting writes
  # is a fact about the node and not about the answer that discovered it.
  defp warn_once(reason, message) do
    key = {__MODULE__, :warned, reason}

    if :persistent_term.get(key, false) == false do
      :persistent_term.put(key, true)
      Logger.warning(message <> ": #{inspect(reason)}")
    end

    :ok
  end

  @doc false
  @spec forget_warning(term()) :: :ok
  def forget_warning(reason) do
    _ = :persistent_term.erase({__MODULE__, :warned, reason})
    :ok
  end
end
