defmodule Ouroboros.Fleet.Deployment.Journal do
  @moduledoc """
  The worker's durable record, read and never written (seam S5).

  `<data dir>/fleet/deploy/<operation>.json` is the operation's authority for what actually
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
  @fields ~w(
    operation kind state created_at updated_at target roster release paths
    plan_digest steps residue last_error
  )

  # Anywhere, at any depth. These are the names the one list in the spec's "Secret handling
  # and authorization" section forbids; a journal that carries one is a worker bug, and the
  # value is dropped before it can reach a log line or a browser.
  @forbidden ~w(secret password passphrase cookie token credential private_key key_pem)

  @doc "The directory the worker keeps its sockets, capability files and journals in."
  @spec deploy_dir(Path.t()) :: Path.t()
  def deploy_dir(data_dir) when is_binary(data_dir),
    do: Path.join([data_dir, "fleet", "deploy"])

  @doc "One operation's journal path."
  @spec path(Path.t(), String.t()) :: Path.t()
  def path(data_dir, operation) when is_binary(operation),
    do: Path.join(deploy_dir(data_dir), operation <> ".json")

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

  defp summary(data_dir, operation) do
    case read(data_dir, operation) do
      {:ok, document} ->
        document
        |> Map.take(~w(operation kind state created_at updated_at plan_digest))
        |> Map.put("operation", operation)
        |> Map.put_new("state", nil)
        |> Map.put_new("kind", nil)
        |> Map.put_new("created_at", nil)
        |> Map.put_new("updated_at", nil)
        |> Map.put("readable", true)

      {:error, reason} ->
        %{
          "operation" => operation,
          "kind" => nil,
          "state" => nil,
          "created_at" => nil,
          "updated_at" => nil,
          "readable" => false,
          "reason" => reason_code(reason)
        }
    end
  end

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
