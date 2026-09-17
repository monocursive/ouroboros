defmodule Ouroboros.Fleet.Deployment.Journal do
  @moduledoc """
  The worker's durable record, read and never written (seam S5).

  `<data dir>/deploy/<operation>.json` is the operation's authority for what actually
  happened. The worker writes it atomically before and after every externally visible step;
  this runtime reads it when no worker is alive, which is the whole of "status of an
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

  # S5's field list. A key the worker adds later is dropped here until this build is taught
  # what it means, which is the direction an operator-facing summary has to fail in.
  #
  # `owner` is the identity that started the operation. It is the worker's to record and this
  # build's to enforce: without it in this allowlist the field was scrubbed out of every
  # journal read, and a second administrator could resume somebody else's deployment and
  # inherit its credential prompts (review F11).
  @fields ~w(
    operation owner kind state created_at updated_at target roster release paths
    plan_digest steps residue last_error
  )

  # Anywhere, at any depth. These are the names the one list in the spec's "Secret handling
  # and authorization" section forbids; a journal that carries one is a worker bug, and the
  # value is dropped before it can reach a log line or a browser.
  @forbidden ~w(secret password passphrase cookie token credential private_key key_pem)

  @doc """
  The directory the worker keeps its sockets, capability files and journals in.

  `<data dir>/deploy/`, deliberately **not** under `fleet/`. A fleet profile is committed by
  one atomic rename of a staging directory, so nothing may exist inside `fleet/` beforehand —
  and a `setup` operation's journal has to exist before the fleet it is creating does. The
  file names inside are unchanged: `<id>.sock`, `<id>.cap`, `<id>.json`, `<id>.request.json`,
  `<id>.log`, and the worker's own `<id>.d/` scratch. Mode 0700, created by whichever side
  gets there first.
  """
  @spec deploy_dir(Path.t()) :: Path.t()
  def deploy_dir(data_dir) when is_binary(data_dir), do: Path.join(data_dir, "deploy")

  @doc "One operation's journal path."
  @spec path(Path.t(), String.t()) :: Path.t()
  def path(data_dir, operation) when is_binary(operation),
    do: Path.join(deploy_dir(data_dir), operation <> ".json")

  @doc """
  Where the broker leaves the request that starts one operation (seam S2).

  A sibling of the journal rather than part of it: the broker writes this one file and the
  worker consumes and unlinks it, which is the opposite ownership from the journal next to
  it. `.request.json` rather than `.request` so that the two are obviously the same family
  when an operator lists the directory.
  """
  @spec request_path(Path.t(), String.t()) :: Path.t()
  def request_path(data_dir, operation) when is_binary(operation),
    do: Path.join(deploy_dir(data_dir), operation <> ".request.json")

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

  @doc """
  Every operation this data directory has a journal for, newest first.

  Bounded by `@max_list`, and an unreadable journal is listed as one rather than skipped:
  an operation whose record this build cannot read is exactly the operation an operator
  needs to be told about.
  """
  @spec list(Path.t()) :: [map()]
  def list(data_dir) when is_binary(data_dir) do
    case File.ls(deploy_dir(data_dir)) do
      {:ok, names} ->
        names
        |> Enum.filter(&String.ends_with?(&1, ".json"))
        |> Enum.map(&String.replace_suffix(&1, ".json", ""))
        |> Enum.filter(&(validate_operation(&1) == :ok))
        |> Enum.sort()
        |> Enum.take(@max_list)
        |> Enum.map(&summary(data_dir, &1))
        |> Enum.sort_by(& &1["updated_at"], :desc)

      {:error, _reason} ->
        []
    end
  end

  @summary_fields ~w(operation owner kind state created_at updated_at plan_digest)

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
  An operation id this runtime will touch a path with.

  The id names a file and a socket, so it is held to hex rather than to "no slashes": a
  validated alphabet is the only form of path safety that does not depend on remembering
  every way a string can escape a directory.
  """
  @spec validate_operation(String.t()) :: :ok | {:error, :invalid_operation}
  def validate_operation(operation) when is_binary(operation) do
    if operation != "" and byte_size(operation) <= 64 and
         String.match?(operation, ~r/\A[0-9a-f]+\z/),
       do: :ok,
       else: {:error, :invalid_operation}
  end

  def validate_operation(_other), do: {:error, :invalid_operation}

  @doc """
  The allowlisted, bounded, credential-free view of one journal document.

  Public because it is what the broker applies to a *live* worker's status reply too: the
  worker and its journal describe the same operation, and one sanitizer means the two
  cannot disagree about what a client is allowed to see.
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
