defmodule Ouroboros.Fleet.Deployment.Journal do
  @moduledoc """
  The port program's durable record, read and never written (§6).

  `<data dir>/deploy/<operation>.json` is the operation's authority for what actually
  happened. The program writes it atomically before and after every step; this runtime reads
  it when no process is alive for the operation, which is the whole of "status of an
  interrupted operation". Nothing in this module opens the file for writing, and there is
  no function here that could: a broker that repaired a journal would be inventing steps
  the machine it deployed to never saw.

  ## Read defensively

  The worker's contract says the journal holds no secret. This module does not take that on
  faith. Every value that reaches a client goes through `sanitize/1`, which keeps an
  allowlist of fields, drops any key whose name reads like a credential wherever it appears,
  bounds the depth and the list lengths, and cuts long strings. The result is that a journal
  written by a future worker — or a corrupted one — can make this answer *less* informative,
  never more dangerous.
  """

  # The file is a record of one operation's steps, not a transcript. A journal larger than
  # this is a worker doing something this build does not understand, and it is refused
  # rather than parsed: the answer is "unreadable", which is true and safe.
  @max_bytes 1024 * 1024
  @max_depth 6
  @max_list 200
  @max_string 2_000

  # §6's schema-2 field list, and nothing else. A key the program adds later is dropped here
  # until this build is taught what it means, which is the direction an operator-facing
  # summary has to fail in.
  #
  # Gone with the per-member ceremony: `owner`, `roster` and `plan_digest`. A challenge is
  # answered by whoever is an administrator on this runtime (§10), so there is no identity to
  # record on an operation; the roster is a dial hint each machine writes for itself (§1); and
  # `plan` is the reviewed lines rather than a digest of a document (§6).
  @fields ~w(
    schema operation kind state created_at updated_at target release paths
    plan steps residue last_error
  )

  # Anywhere, at any depth. These are the names the one list in the spec's "Secret handling
  # and authorization" section forbids; a journal that carries one is a worker bug, and the
  # value is dropped before it can reach a log line or a browser.
  @forbidden ~w(secret password passphrase cookie token credential private_key key_pem)

  # The same vocabulary, matched against free text rather than against object keys: a line of
  # a worker's stdio log has no keys, so this is where a credential would be if one were
  # printed. Discard the whole matching line: shell quoting, JSON strings and truncated
  # diagnostics do not have a common value boundary that is safe to guess at.
  @secret_names Enum.join(@forbidden, "|")

  # Assignments and quoted object keys, including JSON embedded in a diagnostic.
  @secret_assignment ~r/[A-Za-z0-9_.\-]*(?:#{@secret_names})[A-Za-z0-9_.\-]*["']?\s*[:=]/i

  @secret_option ~r/--?[A-Za-z0-9_.\-]*(?:#{@secret_names})[A-Za-z0-9_.\-]*\s+/i

  # Attached and detached values for sshpass's otherwise unrecognizable flag.
  @sshpass_option ~r/\bsshpass\b.*?\s-p/i

  @piped_secret ~r/\b(?:echo|printf)\s+.*?\|\s*sudo\b.*?-S\b/i

  # Escape sequences, stripped as sequences rather than character by character: dropping the
  # `\e` alone out of `\e[1;31m` leaves `[1;31m` on the line, which is noise where the whole
  # thing was meant to be nothing.
  @ansi_csi ~r/\e\[[0-9;:<=>?]*[ -\/]*[@-~]/
  @ansi_osc ~r/\e\][^\a\e]*(?:\a|\e\\)?/
  # Every other escape form: optional intermediate bytes then one final byte, which covers
  # `ESC c`, `ESC 7`, `ESC ( B` and a lone `ESC` at the end of a truncated line.
  @ansi_other ~r/\e[ -\/]*[0-~]?/

  # Then what is left: C0 except tab, DEL, and C1 — which includes the eight-bit CSI at
  # U+009B, so a line that skipped the escape prefix still loses the byte a terminal would
  # have acted on. What follows it stays, as the ordinary text it then is.
  @control_characters ~r/[\x{0000}-\x{0008}\x{000A}-\x{001F}\x{007F}-\x{009F}]/u

  @doc """
  The directory the port program keeps its journals and logs in.

  `<data dir>/deploy/`, deliberately **not** under `fleet/`. A fleet profile is committed by
  one atomic rename of a staging directory, so nothing may exist inside `fleet/` beforehand —
  and a `setup` operation's journal has to exist before the fleet it is creating does. Two
  files per operation now: `<id>.json` and `<id>.log`. The socket, the capability and the
  request file went with the detached worker (§9). Mode 0700, created by whichever side gets
  there first.
  """
  @spec deploy_dir(Path.t()) :: Path.t()
  def deploy_dir(data_dir) when is_binary(data_dir), do: Path.join(data_dir, "deploy")

  @doc "One operation's journal path."
  @spec path(Path.t(), String.t()) :: Path.t()
  def path(data_dir, operation) when is_binary(operation),
    do: Path.join(deploy_dir(data_dir), operation <> ".json")

  @doc """
  The program's own stderr log (§8).

  Neither side's record of the operation: the journal is what the program *says*, and this is
  what it and its children *printed*. Scrubbed by `scrub_line/2` wherever it is read, because
  nothing wrote it under a contract.
  """
  @spec log_path(Path.t(), String.t()) :: Path.t()
  def log_path(data_dir, operation) when is_binary(operation),
    do: Path.join(deploy_dir(data_dir), operation <> ".log")

  @doc """
  Reads one operation's journal, sanitized.

  `{:error, :unknown_operation}` covers both a data directory with no deploy directory and
  an operation nobody ever started: to a client they are the same fact.
  """
  @spec read(Path.t(), String.t()) ::
          {:ok, map()} | {:error, :unknown_operation | {:journal_unreadable, term()}}
  def read(data_dir, operation) when is_binary(data_dir) and is_binary(operation) do
    with :ok <- validate_operation(operation),
         file = path(data_dir, operation),
         {:ok, %File.Stat{type: :regular, size: size}} when size <= @max_bytes <-
           File.lstat(file),
         {:ok, body} <- File.read(file),
         {:ok, document} when is_map(document) <- JSON.decode(body) do
      {:ok, sanitize(document)}
    else
      {:error, :enoent} -> {:error, :unknown_operation}
      {:ok, %File.Stat{}} -> {:error, {:journal_unreadable, :not_a_regular_file_or_too_large}}
      {:error, :invalid_operation} -> {:error, :unknown_operation}
      {:ok, _not_a_map} -> {:error, {:journal_unreadable, :not_an_object}}
      {:error, reason} -> {:error, {:journal_unreadable, reason}}
    end
  end

  # How long a `completed`/`cancelled` journal is kept, and how many of those terminal
  # records survive even when they are younger. `failed`/`waiting`/`running` are resumable and
  # are never swept by this policy.
  @retention_seconds 30 * 24 * 60 * 60
  @max_kept_terminal 50
  @prunable ~w(completed cancelled)

  @doc """
  Every operation this data directory has a journal for, newest first, and how many there are.

  `{operations, total, cache}`. The list is cut to `@max_list`; `total` is what it was cut
  from, so a surface can say "and 40 older" rather than quietly showing a prefix.

  Only the newest `@max_list` files (by mtime) are decoded. A data directory that has
  accumulated years of journals used to be parsed in full on every `fleet.devices` call;
  mtime is the cheap order the filesystem already maintains, and `created_at` then orders
  the decoded window so the page still reads newest-first by the worker's own clock.

  `cache` is keyed by `{path, mtime, size}` so an unchanged file is not parsed again. The
  broker holds it; this module does not.

  An unreadable journal is listed as one rather than skipped: an operation whose record this
  build cannot read is exactly the operation an operator needs to be told about. It sorts
  last, because it has no `created_at` to place it by.
  """
  @spec list(Path.t()) :: {[map()], non_neg_integer(), map()}
  @spec list(Path.t(), map()) :: {[map()], non_neg_integer(), map()}
  def list(data_dir, cache \\ %{}) when is_binary(data_dir) and is_map(cache) do
    case File.ls(deploy_dir(data_dir)) do
      {:ok, names} ->
        entries = journal_entries(data_dir, names)
        total = length(entries)

        newest =
          entries
          |> Enum.sort_by(&{&1.mtime, &1.operation}, :desc)
          |> Enum.take(@max_list)

        {summaries, next_cache} =
          Enum.map_reduce(newest, %{}, fn entry, acc ->
            summary = cached_summary(cache, entry)
            {summary, Map.put(acc, entry.key, summary)}
          end)

        {Enum.sort_by(summaries, &order/1, :desc), total, next_cache}

      {:error, _reason} ->
        {[], 0, %{}}
    end
  end

  defp journal_entries(data_dir, names) do
    names
    |> Enum.filter(&journal_name?/1)
    |> Enum.flat_map(fn name ->
      operation = String.replace_suffix(name, ".json", "")

      with :ok <- validate_operation(operation),
           path = path(data_dir, operation),
           {:ok, %File.Stat{mtime: mtime, size: size, type: :regular}} <- File.lstat(path) do
        [
          %{
            operation: operation,
            data_dir: data_dir,
            path: path,
            mtime: mtime,
            size: size,
            key: {path, mtime, size}
          }
        ]
      else
        _other -> []
      end
    end)
  end

  # Operation ids cannot contain dots, so a name with a second suffix never survives
  # `validate_operation/1`. Matching the suffix the program actually writes is still cheaper
  # than opening the file.
  defp journal_name?(name), do: String.ends_with?(name, ".json")

  defp cached_summary(cache, entry) do
    case Map.fetch(cache, entry.key) do
      {:ok, summary} -> summary
      :error -> summary(entry.data_dir, entry.operation)
    end
  end

  # Newest first by when the worker opened the journal, then by id. `created_at` is ISO-8601
  # from the worker, which sorts correctly as a string; a row without one sorts below every
  # row that has one rather than above them.
  defp order(%{"created_at" => created_at, "operation" => operation})
       when is_binary(created_at),
       do: {created_at, operation}

  defp order(%{"operation" => operation}), do: {"", operation}

  @summary_fields ~w(operation kind state created_at updated_at)

  # Enough to put an open operation on the row it belongs to, and no more.
  #
  # `target` is the reason this is not just a list of ids: a surface showing a device list
  # has to say *which device* an interrupted operation is about, and without it every open
  # operation looked the same. It is the journal's own target, cut to the four fields that
  # name a row — the machine, where it is, and the account and port an `add` is using — and
  # it goes through the same scrubbing as everything else out of here.
  @target_fields ~w(machine address ssh_user port)

  defp summary(data_dir, operation) do
    case read(data_dir, operation) do
      {:ok, document} ->
        document
        |> Map.take(@summary_fields)
        |> Map.put("operation", operation)
        |> Map.put("target", target_summary(document["target"]))
        |> blanks()
        |> Map.put("readable", true)

      {:error, reason} ->
        %{"operation" => operation, "target" => nil}
        |> blanks()
        |> Map.put("readable", false)
        |> Map.put("reason", reason_code(reason))
    end
  end

  # Every field a surface reads is present on every row, `null` where this build could not
  # establish it. A missing key and a null one are the same fact to a renderer, and only one
  # of them is the same fact to a person reading the JSON.
  defp blanks(summary) do
    Enum.reduce(@summary_fields ++ ["target"], summary, &Map.put_new(&2, &1, nil))
  end

  defp target_summary(target) when is_map(target) do
    case Map.take(target, @target_fields) do
      empty when map_size(empty) == 0 -> nil
      fields -> fields
    end
  end

  defp target_summary(_absent), do: nil

  defp reason_code(:unknown_operation), do: "unknown_operation"
  defp reason_code({:journal_unreadable, _detail}), do: "journal_unreadable"

  @doc """
  Removes journals this runtime no longer needs to resume from.

  `completed` and `cancelled` records older than 30 days go, and of what remains of those
  two states only the newest 50 are kept. `failed` and `waiting` are resumable and are not
  touched. A running worker process is the authority on an operation it holds, so those ids
  are skipped even when their journal already says they finished.
  """
  @spec prune(Path.t(), keyword()) :: :ok
  def prune(data_dir, opts \\ []) when is_binary(data_dir) do
    attached = MapSet.new(Keyword.get(opts, :attached, []))
    now = Keyword.get(opts, :now, System.system_time(:second))

    case File.ls(deploy_dir(data_dir)) do
      {:ok, names} ->
        entries = journal_entries(data_dir, names)

        candidates =
          entries
          |> Enum.reject(&MapSet.member?(attached, &1.operation))
          |> Enum.flat_map(fn entry ->
            summary = summary(data_dir, entry.operation)

            if summary["state"] in @prunable do
              [{entry, unix_mtime(entry.mtime), summary}]
            else
              []
            end
          end)
          |> Enum.sort_by(fn {entry, unix, _summary} -> {unix, entry.operation} end, :desc)

        {_kept, drop} = drop_retained(candidates, now)

        Enum.each(drop, fn {entry, _unix, _summary} ->
          delete_operation(data_dir, entry.operation)
        end)

        :ok

      {:error, _reason} ->
        :ok
    end
  end

  defp drop_retained(candidates, now) do
    {kept, drop} =
      Enum.split_with(Enum.with_index(candidates), fn {{_entry, unix, _summary}, index} ->
        index < @max_kept_terminal and now - unix <= @retention_seconds
      end)

    {Enum.map(kept, &elem(&1, 0)), Enum.map(drop, &elem(&1, 0))}
  end

  # `File.lstat/1` answers mtime as an Erlang datetime. Retention compares against the
  # broker's clock, which is unix seconds.
  defp unix_mtime({{year, month, day}, {hour, minute, second}}) do
    case NaiveDateTime.new(year, month, day, hour, minute, second) do
      {:ok, naive} -> naive |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_unix()
      _unreadable -> 0
    end
  end

  defp unix_mtime(seconds) when is_integer(seconds), do: seconds
  defp unix_mtime(_other), do: 0

  defp delete_operation(data_dir, operation) do
    dir = deploy_dir(data_dir)

    Enum.each(
      [Path.join(dir, operation <> ".json"), Path.join(dir, operation <> ".log")],
      &File.rm/1
    )

    _ = File.rm_rf(Path.join(dir, operation <> ".d"))
    :ok
  end

  @doc """
  An operation id this runtime will touch a path with.

  Match the program and the CLI: 8 to 64 lowercase letters, digits and single hyphens,
  with no leading or trailing hyphen. The bounded alphabet excludes path traversal.
  """
  @spec validate_operation(String.t()) :: :ok | {:error, :invalid_operation}
  def validate_operation(operation) when is_binary(operation) do
    if byte_size(operation) in 8..64 and
         String.match?(operation, ~r/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/),
       do: :ok,
       else: {:error, :invalid_operation}
  end

  def validate_operation(_other), do: {:error, :invalid_operation}

  @doc """
  The allowlisted, bounded, credential-free view of one journal document.

  Public because it is what the worker process applies to a live operation's snapshot too:
  the program's frames and its journal describe the same operation, and one sanitizer means
  the two cannot disagree about what a client is allowed to see.
  """
  @spec sanitize(map()) :: map()
  def sanitize(document) when is_map(document) do
    document
    |> Map.take(@fields)
    |> Map.new(fn {key, value} -> {key, scrub(value, 0)} end)
  end

  @doc """
  The same bounding and credential-dropping applied to any one value.

  The broker uses it on the frames a live worker sends, which are not journal documents and
  have no field allowlist of their own: whatever shape a worker event takes, what reaches a
  subscriber is bounded and carries no key that reads like a credential.
  """
  @spec scrub_value(term()) :: term()
  def scrub_value(value), do: scrub(value, 0)

  @doc """
  One line of a worker's private stdio log, made safe to hand to a client.

  That log is not a journal. Nothing writes it under a contract: it is whatever the worker
  and the programs it forked printed on their way out, which on a bad day is an `ssh`
  diagnostic, a shell trace, or bytes that are not text at all. So it gets the journal's own
  forbidden vocabulary — matched against the four shapes a secret takes in free text, since
  a line has no keys — then the journal's bounding, then the caller's own cap.

  Before any of that, every control character goes. `String.printable?/1` counts `\e` as
  printable, so the previous version of this let `"worker died \e[1;31mSPOOFED\e[0m"` through
  unchanged: an operator reading the tail in a terminal saw a sentence the worker did not
  write, in a colour it chose. Escape sequences are removed whole, then C0 (bar tab), DEL and
  C1 individually, so nothing is left to reassemble.

  Bytes that are not text at all are folded to `.` rather than dropped: a line a worker
  printed in a foreign encoding is still evidence of where it stopped, and it must not be
  able to break the encoder that carries it to a browser.
  """
  @spec scrub_line(binary(), pos_integer()) :: String.t()
  def scrub_line(line, max) when is_binary(line) and is_integer(max) and max > 0 do
    line
    |> textual()
    |> strip_controls()
    |> String.trim()
    |> redact()
    |> scrub_value()
    |> String.slice(0, max)
  end

  defp textual(line) do
    if String.valid?(line) do
      line
    else
      for <<byte <- line>>, into: "", do: <<if(byte in 32..126, do: byte, else: ?.)>>
    end
  end

  defp strip_controls(line) do
    line
    |> then(&Regex.replace(@ansi_csi, &1, ""))
    |> then(&Regex.replace(@ansi_osc, &1, ""))
    |> then(&Regex.replace(@ansi_other, &1, ""))
    |> then(&Regex.replace(@control_characters, &1, ""))
  end

  defp redact(line) do
    if Enum.any?(
         [@secret_assignment, @secret_option, @sshpass_option, @piped_secret],
         &Regex.match?(&1, line)
       ) do
      "[redacted credential-bearing diagnostic]"
    else
      line
    end
  end

  defp scrub(value, depth) when depth >= @max_depth and (is_map(value) or is_list(value)),
    do: "[truncated: nested deeper than #{@max_depth}]"

  defp scrub(value, depth) when is_map(value) do
    value
    |> Enum.reject(fn {key, _value} -> forbidden?(key) end)
    |> Enum.take(@max_list)
    |> Map.new(fn {key, inner} -> {to_string(key), scrub(inner, depth + 1)} end)
  end

  defp scrub(value, depth) when is_list(value),
    do: value |> Enum.take(@max_list) |> Enum.map(&scrub(&1, depth + 1))

  defp scrub(value, _depth) when is_binary(value), do: String.slice(value, 0, @max_string)
  defp scrub(value, _depth) when is_number(value) or is_boolean(value) or is_nil(value), do: value
  defp scrub(value, _depth), do: inspect(value, limit: 10) |> String.slice(0, @max_string)

  defp forbidden?(key) when is_binary(key) do
    downcased = String.downcase(key)
    Enum.any?(@forbidden, &String.contains?(downcased, &1))
  end

  defp forbidden?(key) when is_atom(key), do: key |> Atom.to_string() |> forbidden?()
  defp forbidden?(_key), do: true
end
