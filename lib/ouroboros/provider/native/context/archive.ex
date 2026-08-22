defmodule Ouroboros.Provider.Native.Context.Archive do
  @moduledoc """
  Where a compaction's pre-compaction messages go, so that "what was folded" is a
  question with an answer.

  One file per compaction under the session's own directory,
  `<session_dir>/compaction/<digest>.json`, mode `0600`. Content-addressed on the message
  list itself: the digest in the filename is the digest a reader recomputes, so an
  archive that was edited under the runtime's feet is refused rather than replayed.
  Writing the same message list twice is a no-op that returns the same id, which is what
  makes a retried compaction cheap instead of duplicated.

  Bounded by the same limit `Ouroboros.Provider.Native.Checkpoint` applies to the live
  conversation — `event_limit`, a message count, default 400 — so an archive cannot grow
  past the size of the thing it archived. That bound is a message count rather than a
  byte budget because that is what D1's checkpoint actually enforces; saying "byte
  budget" here would describe a limit this runtime does not have.

  This module writes and reads. It never deletes: a compaction archive is the operator's
  record of a conversation the runtime shortened without asking, and the retention sweep
  that eventually removes it is a separate, stated policy (F5), not a side effect of
  compacting again.
  """

  alias Ouroboros.Provider.Native.Checkpoint

  @version 1
  @dir "compaction"

  @typedoc "One archived compaction as a client sees it."
  @type entry :: %{
          id: String.t(),
          path: String.t(),
          message_count: non_neg_integer(),
          bytes: non_neg_integer(),
          created_at: String.t(),
          truncated: boolean()
        }

  @doc """
  Writes one pre-compaction message list and returns its entry.

  `:event_limit` bounds the message count, defaulting to the checkpoint's own default.
  When the list is longer, the **newest** messages are kept and `truncated: true` says
  so — the same direction `Checkpoint.trim/2` keeps, and stated rather than silent.
  """
  @spec write(String.t(), [map()], keyword()) :: {:ok, entry()} | {:error, term()}
  def write(session_dir, messages, opts \\ [])

  def write(_session_dir, [], _opts), do: {:error, :nothing_to_archive}

  def write(session_dir, messages, opts) when is_binary(session_dir) and is_list(messages) do
    limit = Keyword.get(opts, :event_limit, Checkpoint.limit(%{}))
    kept = Checkpoint.trim(messages, limit)
    truncated? = length(kept) < length(messages)
    encoded = Enum.map(kept, &encode/1)
    id = digest(encoded)

    payload = %{
      "version" => @version,
      "digest" => id,
      "created_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "truncated" => truncated?,
      "original_message_count" => length(messages),
      "messages" => encoded
    }

    with {:ok, dir} <- ensure_dir(session_dir),
         path = Path.join(dir, id <> ".json"),
         {:ok, json} <- encode_json(payload),
         :ok <- write_private(path, json) do
      {:ok,
       %{
         id: id,
         path: path,
         message_count: length(kept),
         bytes: byte_size(json),
         created_at: payload["created_at"],
         truncated: truncated?
       }}
    end
  end

  def write(_session_dir, _messages, _opts), do: {:error, :invalid_archive_request}

  @doc """
  Reads one archive back by id, verifying its digest.

  `{:error, :archive_digest_mismatch}` for a file whose content no longer hashes to its
  own name. Refused rather than repaired, for the same reason the checkpoint refuses:
  this is replayed into a model's context, and half a transcript that looks whole is
  worse than an admitted gap.
  """
  @spec read(String.t(), String.t()) :: {:ok, [map()]} | {:error, term()}
  def read(session_dir, id) when is_binary(session_dir) and is_binary(id) do
    with :ok <- validate_id(id),
         path = Path.join([session_dir, @dir, id <> ".json"]),
         {:ok, json} <- read_file(path),
         {:ok, payload} <- decode_json(json),
         %{"version" => @version, "messages" => encoded} when is_list(encoded) <- payload,
         true <- digest(encoded) == id || {:error, :archive_digest_mismatch} do
      {:ok, Enum.map(encoded, &decode/1)}
    else
      {:error, _reason} = error -> error
      %{"version" => other} -> {:error, {:archive_version, other}}
      _corrupt -> {:error, :archive_corrupt}
    end
  end

  def read(_session_dir, _id), do: {:error, :invalid_archive_id}

  @doc "Every archive this session holds, newest first, as public entries."
  @spec list(String.t()) :: [entry()]
  def list(session_dir) when is_binary(session_dir) do
    dir = Path.join(session_dir, @dir)

    case File.ls(dir) do
      {:ok, entries} ->
        entries
        |> Enum.filter(&String.ends_with?(&1, ".json"))
        |> Enum.flat_map(&describe(Path.join(dir, &1)))
        |> Enum.sort_by(& &1.created_at, :desc)

      {:error, _reason} ->
        []
    end
  end

  def list(_session_dir), do: []

  # ---------------------------------------------------------------- private

  defp describe(path) do
    with {:ok, json} <- read_file(path),
         {:ok, payload} <- decode_json(json),
         %{"digest" => id, "messages" => messages} when is_list(messages) <- payload do
      [
        %{
          id: id,
          path: path,
          message_count: length(messages),
          bytes: byte_size(json),
          created_at: Map.get(payload, "created_at", ""),
          truncated: Map.get(payload, "truncated", false) == true
        }
      ]
    else
      _unreadable -> []
    end
  end

  defp ensure_dir(session_dir) do
    dir = Path.join(session_dir, @dir)

    case File.mkdir_p(dir) do
      :ok ->
        _ = File.chmod(dir, 0o700)
        {:ok, dir}

      {:error, reason} ->
        {:error, {:archive_dir_unavailable, dir, reason}}
    end
  end

  defp write_private(path, json) do
    temporary = path <> ".tmp-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

    with :ok <- File.write(temporary, json, [:binary, :sync]),
         :ok <- File.chmod(temporary, 0o600),
         :ok <- File.rename(temporary, path) do
      :ok
    else
      {:error, reason} -> {:error, {:archive_write_failed, reason}}
    end
  end

  defp read_file(path) do
    case File.read(path) do
      {:ok, json} -> {:ok, json}
      {:error, :enoent} -> {:error, :no_archive}
      {:error, reason} -> {:error, {:archive_unreadable, reason}}
    end
  end

  defp validate_id(id) do
    if Regex.match?(~r/\A[0-9a-f]{64}\z/, id), do: :ok, else: {:error, :invalid_archive_id}
  end

  defp encode_json(payload) do
    {:ok, JSON.encode!(payload)}
  rescue
    error -> {:error, {:archive_unencodable, Exception.message(error)}}
  end

  defp decode_json(json) do
    {:ok, JSON.decode!(json)}
  rescue
    _error -> {:error, :archive_corrupt}
  end

  defp digest(encoded) do
    :sha256
    |> :crypto.hash(JSON.encode!(encoded))
    |> Base.encode16(case: :lower)
  end

  # The same wire shape the checkpoint uses. Two encoders for one message list would be
  # two things to keep in step; this one is deliberately a copy of the checkpoint's rules
  # rather than a call into its private functions, so a change there is a test failure
  # here instead of a silent divergence.
  defp encode(%{role: :assistant} = message) do
    %{
      "role" => "assistant",
      "content" => message[:content] || "",
      "tool_calls" =>
        Enum.map(message[:tool_calls] || [], fn call ->
          %{"id" => call.id, "name" => call.name, "input" => call.input}
        end)
    }
  end

  defp encode(%{role: :tool} = message) do
    %{
      "role" => "tool",
      "tool_call_id" => message.tool_call_id,
      "name" => message.name,
      "content" => message.content,
      "is_error" => message[:is_error] == true
    }
  end

  defp encode(%{role: role} = message),
    do: %{"role" => Atom.to_string(role), "content" => message[:content] || ""}

  defp decode(%{"role" => "assistant"} = message) do
    %{
      role: :assistant,
      content: Map.get(message, "content", ""),
      tool_calls:
        message
        |> Map.get("tool_calls", [])
        |> Enum.map(fn call ->
          %{
            id: Map.get(call, "id", ""),
            name: Map.get(call, "name", ""),
            input: Map.get(call, "input", %{})
          }
        end)
    }
  end

  defp decode(%{"role" => "tool"} = message) do
    %{
      role: :tool,
      tool_call_id: Map.get(message, "tool_call_id", ""),
      name: Map.get(message, "name", ""),
      content: Map.get(message, "content", ""),
      is_error: Map.get(message, "is_error", false) == true
    }
  end

  defp decode(%{"role" => "system"} = message),
    do: %{role: :system, content: Map.get(message, "content", "")}

  defp decode(message), do: %{role: :user, content: Map.get(message, "content", "")}
end
