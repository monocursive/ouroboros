defmodule Ouroboros.Provider.Native.Checkpoint do
  @moduledoc """
  The conversation file that makes `provider_session_id` mean something after a restart.

  Every other provider resumes by handing its own id back to a vendor CLI that kept the
  transcript. This provider *is* the thing that kept the transcript, so it has to write
  it down. One file per session under the session's own directory, mode `0600`,
  rewritten atomically after every turn — **before** the terminal turn event is
  broadcast, so a crash between the two replays a turn rather than losing one.

  Content-addressed: the payload carries a SHA-256 of its own message list and a load
  verifies it. A checkpoint that does not hash to its digest is refused rather than
  repaired — this file is replayed into a model's context, and half a conversation that
  looks whole is worse than a session that admits it cannot resume.

  Bounded by `event_limit` (default 400 messages, newest kept). The trim never splits an
  assistant message from the tool results that answer it: a tool result whose call is
  gone is a message most providers reject outright. What the trim dropped is written down
  beside the conversation as an `offset`, because a session that resumes onto a tail and a
  manifest that counts messages from the beginning are two different coordinate systems,
  and `rewind` has to convert between them rather than assume they agree.

  ## The file checkpoint, beside the conversation

  D10: rewind is Ouroboros's, and its limits are stated up front. Every `write`, `edit`,
  `apply_patch` and language-server rename snapshots the file's prior bytes into a
  content-addressed store under the same session directory before it changes anything:

      <session dir>/blobs/<sha256>     one file's content, once, mode 0600
      <session dir>/manifest.json      one record per turn, mode 0600

  A turn's record is a list of `{path, before, after}` where `before` is a blob digest
  or `:absent` for a file that did not exist, plus the message count at the end of that
  turn — which is what makes `rewind(:conversation)` able to cut the transcript at a turn
  boundary without the message list carrying turn ids.

  Content addressing is what keeps this affordable: a file edited twenty times in a turn
  stores twenty digests and as many blobs as it had distinct contents, and two turns that
  both start from the same file share one blob.

  The store is bounded by a per-session byte budget, #{256} MiB by default. Past it the
  **oldest turns are dropped, and dropped is a recorded state** — the record keeps the
  paths and loses the digests, so a rewind that reaches into a dropped turn reports those
  files as unrestorable by name instead of silently restoring fewer files than it said it
  would. Claude Code issue #18516 is rewind that silently under-delivers; §2.5 of the plan
  names it, and this is the shape that avoids it.

  Commands are recorded as fingerprints, never as effects. `bash` can write anything
  anywhere through a program this runtime does not inspect, so a turn that ran one is
  reported as unrestorable in full. That is the honest warning, and it is given *before*
  the operator commits rather than after.
  """

  require Logger

  alias Ouroboros.Provider.Native.Paths

  @version 2
  @default_limit 400

  @manifest_version 1
  @default_budget_bytes 256 * 1024 * 1024
  @max_manifest_turns 2_000
  # A file larger than this is not snapshotted; it is named as unsnapshotted so a rewind
  # says so rather than quietly skipping it. A repository's generated bundle must not be
  # able to spend the whole budget on one turn.
  @max_blob_bytes 32 * 1024 * 1024

  @typedoc "A conversation read back, and where it sits in the session that wrote it."
  @type conversation :: %{
          messages: [map()],
          offset: non_neg_integer(),
          rewind_floor: non_neg_integer()
        }

  @doc "Where one session's checkpoint lives, and whether that location survives a reboot."
  @spec locate(String.t()) :: {:ok, String.t(), boolean()} | {:error, term()}
  def locate(provider_session_id) do
    case Paths.session_dir(provider_session_id) do
      {:ok, dir, durable?} -> {:ok, Path.join(dir, "conversation.json"), durable?}
      {:error, _reason} = error -> error
    end
  end

  @doc """
  Writes the conversation, atomically and privately, and answers with its digest.

  A temporary file in the same directory is renamed over the target, so a reader never
  sees a partial write and a crashed write leaves the previous checkpoint intact.

  The digest is returned rather than recomputed by whoever wants it: R1's turn journal
  records it on `turn_settled` as the journal↔conversation cross-link, and two digests
  taken over the same list by two callers is one more place for them to disagree. It is
  the same value `load/1` verifies the file against.
  """
  @spec write(String.t(), [map()], keyword()) :: {:ok, String.t()} | {:error, term()}
  def write(path, messages, opts \\ []) do
    limit = Keyword.get(opts, :event_limit, @default_limit)
    trimmed = trim(messages, limit)
    encoded = trimmed |> Enum.map(&encode/1) |> canonical()
    digest = digest(encoded)

    # What the trim costs the *next* session, written down. `messages` starts at absolute
    # message `offset` in this session's conversation, so the list on disk starts at
    # `offset` plus whatever the trim just dropped — and that is the number a rewind needs
    # to turn the manifest's absolute counts into positions in the list it will hold.
    offset = count(opts, :offset) + (length(messages) - length(trimmed))

    payload = %{
      "version" => @version,
      "digest" => digest,
      "offset" => offset,
      "rewind_floor" => max(count(opts, :rewind_floor), offset),
      "updated_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "messages" => encoded
    }

    with {:ok, json} <- encode_json(payload),
         temporary =
           path <> ".tmp-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false),
         :ok <- File.write(temporary, json, [:binary, :sync]),
         :ok <- File.chmod(temporary, 0o600),
         :ok <- File.rename(temporary, path) do
      {:ok, digest}
    else
      {:error, reason} -> {:error, {:checkpoint_write_failed, reason}}
    end
  end

  @doc """
  The digest `write/3` would compute for a message list, without writing anything.

  The same trim and the same canonical encoding, so a value from here and a value from a
  write are comparable. R1's `compaction` journal record uses it for `pre_digest`: what the
  conversation hashed to *before* the fold, which no later write can reconstruct.
  """
  @spec digest_of([map()], keyword()) :: String.t()
  def digest_of(messages, opts \\ []) do
    messages
    |> trim(Keyword.get(opts, :event_limit, @default_limit))
    |> Enum.map(&encode/1)
    |> canonical()
    |> digest()
  end

  @doc """
  Reads a conversation back, or says why it will not.

  `{:error, :no_checkpoint}` for a session id this node has never written, which is the
  ordinary "resume a session that was never here" case and not a failure.
  """
  @spec read(String.t()) :: {:ok, [map()]} | {:error, term()}
  def read(path) do
    with {:ok, conversation} <- load(path), do: {:ok, conversation.messages}
  end

  @doc """
  The conversation, and where it sits in the session that wrote it.

  `offset` is how many messages that session had before the first one still on disk: the
  trim keeps the newest `event_limit` and drops the rest, so a resumed long session holds
  a tail rather than the whole conversation. `rewind_floor` is the oldest message count a
  rewind can still cut that tail at.

  Both exist because the turn manifest counts messages from the start of the session while
  the list here may not: a rewind that compared the two directly would take a slice out of
  the middle of the conversation and call it a turn boundary.
  """
  @spec load(String.t()) :: {:ok, conversation()} | {:error, term()}
  def load(path) do
    with {:ok, json} <- read_file(path),
         {:ok, payload} <- decode_json(json),
         :ok <- verify_version(payload),
         {:ok, encoded} <- fetch_messages(payload),
         :ok <- verify_digest(payload, encoded) do
      messages = Enum.map(encoded, &decode/1)
      {offset, floor} = position(payload, path, length(messages))

      {:ok, %{messages: messages, offset: offset, rewind_floor: floor}}
    end
  end

  @doc "The number of messages a checkpoint keeps, honouring a session's `event_limit`."
  @spec limit(map() | keyword()) :: pos_integer()
  def limit(provider_options) when is_map(provider_options) do
    case Map.get(provider_options, :event_limit) || Map.get(provider_options, "event_limit") do
      value when is_integer(value) and value > 0 -> min(value, 10_000)
      _unset -> @default_limit
    end
  end

  def limit(provider_options) when is_list(provider_options), do: limit(Map.new(provider_options))
  def limit(_other), do: @default_limit

  @doc false
  @spec trim([map()], pos_integer()) :: [map()]
  def trim(messages, limit) when length(messages) <= limit, do: messages

  def trim(messages, limit) do
    messages
    |> Enum.take(-limit)
    |> drop_orphan_tool_results()
  end

  # A tool result whose assistant tool_call was trimmed away is rejected by most
  # providers with a hard 400. Drop the orphans at the head rather than the whole turn.
  defp drop_orphan_tool_results(messages) do
    Enum.drop_while(messages, &(&1[:role] == :tool))
  end

  defp read_file(path) do
    case File.read(path) do
      {:ok, json} -> {:ok, json}
      {:error, :enoent} -> {:error, :no_checkpoint}
      {:error, reason} -> {:error, {:checkpoint_unreadable, reason}}
    end
  end

  defp encode_json(payload) do
    {:ok, JSON.encode!(payload)}
  rescue
    error -> {:error, {:checkpoint_unencodable, Exception.message(error)}}
  end

  defp decode_json(json) do
    {:ok, JSON.decode!(json)}
  rescue
    _error -> {:error, :checkpoint_corrupt}
  end

  defp verify_version(%{"version" => version}) when version in [1, @version], do: :ok
  defp verify_version(%{"version" => other}), do: {:error, {:checkpoint_version, other}}
  defp verify_version(_payload), do: {:error, :checkpoint_corrupt}

  defp fetch_messages(%{"messages" => messages}) when is_list(messages), do: {:ok, messages}
  defp fetch_messages(_payload), do: {:error, :checkpoint_corrupt}

  # `"offset"` present — even as 0 — is a file this runtime wrote. Absent is a file
  # written before the field existed: the sibling manifest still counted messages from
  # the start of the session, and treating that count as an index into a trimmed tail
  # is the mis-slice. Infer the dropped prefix from the last turn when we can; a file
  # with no usable manifest still reads as a whole conversation.
  defp position(payload, path, kept) when is_map(payload) do
    if Map.has_key?(payload, "offset") do
      offset = count(payload, "offset")
      {offset, max(count(payload, "rewind_floor"), offset)}
    else
      offset = inferred_offset(Path.dirname(path), kept)
      {offset, offset}
    end
  end

  defp inferred_offset(session_dir, kept) do
    case last_manifest_count(session_dir) do
      last when is_integer(last) and last > kept -> last - kept
      _unknown -> 0
    end
  end

  defp last_manifest_count(session_dir) do
    case read_manifest(session_dir) do
      {:ok, %{"turns" => turns}} when is_list(turns) and turns != [] ->
        case List.last(turns) do
          %{"message_count" => count} when is_integer(count) and count >= 0 -> count
          _other -> nil
        end

      _unusable ->
        nil
    end
  end

  defp count(opts, key) when is_list(opts), do: non_negative(Keyword.get(opts, key))
  defp count(payload, key) when is_map(payload), do: non_negative(Map.get(payload, key))

  defp non_negative(value) when is_integer(value) and value >= 0, do: value
  defp non_negative(_other), do: 0

  defp verify_digest(%{"digest" => digest}, encoded) do
    if digest == digest(encoded), do: :ok, else: {:error, :checkpoint_digest_mismatch}
  end

  defp verify_digest(_payload, _encoded), do: {:error, :checkpoint_corrupt}

  # Hash the canonical JSON of the message list, not the whole payload: the payload
  # carries a timestamp, and a digest over it would change without the conversation
  # changing.
  defp digest(encoded) do
    :sha256
    |> :crypto.hash(JSON.encode!(encoded))
    |> Base.encode16(case: :lower)
  end

  defp canonical(value), do: value |> JSON.encode!() |> JSON.decode!()

  defp encode(%{role: :assistant} = message) do
    %{
      "role" => "assistant",
      "content" => message[:content] || "",
      "tool_calls" =>
        Enum.map(message[:tool_calls] || [], fn call ->
          %{"id" => call.id, "name" => call.name, "input" => call.input}
        end),
      "reasoning_details" =>
        Enum.map(message[:reasoning_details] || [], &encode_reasoning_detail/1),
      "provider_metadata" => encode_provider_metadata(message[:provider_metadata] || %{})
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
    base = %{
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

    details =
      message
      |> Map.get("reasoning_details", [])
      |> Enum.map(&decode_reasoning_detail/1)

    base
    |> put_nonempty(:reasoning_details, details)
    |> put_nonempty(
      :provider_metadata,
      decode_provider_metadata(Map.get(message, "provider_metadata", %{}))
    )
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

  defp encode_reasoning_detail(detail) when is_map(detail) do
    %{
      "text" => field(detail, :text),
      "signature" => field(detail, :signature),
      "encrypted" => field(detail, :encrypted?) == true,
      "provider" => provider_name(field(detail, :provider)),
      "format" => field(detail, :format),
      "index" => field(detail, :index) || 0,
      "provider_data" => safe_map(field(detail, :provider_data))
    }
  end

  defp encode_reasoning_detail(_detail), do: %{}

  defp decode_reasoning_detail(detail) when is_map(detail) do
    %{
      text: Map.get(detail, "text"),
      signature: Map.get(detail, "signature"),
      encrypted?: Map.get(detail, "encrypted") == true,
      provider: Map.get(detail, "provider"),
      format: Map.get(detail, "format"),
      index: Map.get(detail, "index", 0),
      provider_data: safe_map(Map.get(detail, "provider_data"))
    }
  end

  defp decode_reasoning_detail(_detail), do: %{}

  defp encode_provider_metadata(metadata) when is_map(metadata) do
    metadata
    |> Enum.reduce(%{}, fn
      {key, value}, acc when is_binary(value) or is_number(value) or is_boolean(value) ->
        Map.put(acc, to_string(key), value)

      _other, acc ->
        acc
    end)
  end

  defp encode_provider_metadata(_metadata), do: %{}

  defp decode_provider_metadata(metadata) when is_map(metadata) do
    Map.new(metadata, fn {key, value} -> {safe_metadata_key(key), value} end)
  end

  defp decode_provider_metadata(_metadata), do: %{}

  defp safe_metadata_key("request_id"), do: :request_id
  defp safe_metadata_key("response_id"), do: :response_id
  defp safe_metadata_key("service_tier"), do: :service_tier
  defp safe_metadata_key(key), do: key

  defp field(map, key), do: Map.get(map, key, Map.get(map, Atom.to_string(key)))
  defp provider_name(provider) when is_atom(provider), do: Atom.to_string(provider)
  defp provider_name(provider) when is_binary(provider), do: provider
  defp provider_name(_provider), do: nil

  defp put_nonempty(map, _key, value) when value in [nil, [], %{}], do: map
  defp put_nonempty(map, key, value), do: Map.put(map, key, value)
  defp safe_map(value) when is_map(value), do: value
  defp safe_map(_value), do: %{}

  # ================================================================ file store

  @doc "Where a session's blob store lives."
  @spec blob_dir(String.t()) :: String.t()
  def blob_dir(session_dir), do: Path.join(session_dir, "blobs")

  @doc "Where a session's turn manifest lives."
  @spec manifest_path(String.t()) :: String.t()
  def manifest_path(session_dir), do: Path.join(session_dir, "manifest.json")

  @doc """
  Snapshots one file's current bytes and returns how to name them later.

  `{:ok, digest}` for a file that exists, `{:ok, :absent}` for one that does not — which
  is a real state a rewind restores by deleting the file again — and
  `{:ok, {:unsnapshotted, reason}}` for a file too large or unreadable, which a rewind
  reports rather than pretending to restore.

  Never returns an error: a snapshot that fails must not be able to fail the write it
  precedes. What it does instead is record that it failed.
  """
  @spec snapshot(String.t(), String.t()) :: {:ok, String.t() | :absent | {:unsnapshotted, term()}}
  def snapshot(session_dir, path) do
    case File.stat(path, time: :posix) do
      {:ok, %File.Stat{type: :regular, size: size}} when size <= @max_blob_bytes ->
        case File.read(path) do
          {:ok, content} -> {:ok, put_blob(session_dir, content)}
          {:error, reason} -> {:ok, {:unsnapshotted, reason}}
        end

      {:ok, %File.Stat{type: :regular, size: size}} ->
        {:ok, {:unsnapshotted, {:too_large, size}}}

      {:ok, %File.Stat{type: type}} ->
        {:ok, {:unsnapshotted, {:not_a_regular_file, type}}}

      {:error, :enoent} ->
        {:ok, :absent}

      {:error, reason} ->
        {:ok, {:unsnapshotted, reason}}
    end
  end

  @doc "Writes content into the blob store and returns its digest, or why it could not."
  @spec put_blob(String.t(), binary()) :: String.t() | {:unsnapshotted, term()}
  def put_blob(session_dir, content) do
    digest = :sha256 |> :crypto.hash(content) |> Base.encode16(case: :lower)
    directory = blob_dir(session_dir)
    path = Path.join(directory, digest)

    cond do
      File.regular?(path) ->
        digest

      true ->
        temporary =
          path <> ".tmp-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

        with :ok <- File.mkdir_p(directory),
             _ <- File.chmod(directory, 0o700),
             :ok <- File.write(temporary, content, [:binary]),
             :ok <- File.chmod(temporary, 0o600),
             :ok <- File.rename(temporary, path) do
          digest
        else
          {:error, reason} ->
            _ = File.rm(temporary)
            {:unsnapshotted, reason}
        end
    end
  end

  @doc "Reads one blob back, byte-exact."
  @spec get_blob(String.t(), String.t()) :: {:ok, binary()} | {:error, term()}
  def get_blob(session_dir, digest) when is_binary(digest) do
    path = Path.join(blob_dir(session_dir), digest)

    case File.read(path) do
      {:ok, content} ->
        # The store is content-addressed, so verifying is one hash and it turns a
        # corrupted blob into a named unrestorable file instead of a silently wrong one.
        if :sha256 |> :crypto.hash(content) |> Base.encode16(case: :lower) == digest,
          do: {:ok, content},
          else: {:error, :blob_digest_mismatch}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def get_blob(_session_dir, digest), do: {:error, {:invalid_digest, digest}}

  @doc """
  Appends one turn's record to the manifest and prunes the store to its budget.

  `entries` is a list of `%{path:, before:, after:}`; `opts` takes `message_count:`,
  `commands:` (a list of command fingerprints) and `budget_bytes:`.

  Returns the summary a client uses to offer a rewind menu, or `{:error, reason}` when
  the manifest itself cannot be written — which the caller logs and carries on from,
  because losing the ability to rewind a turn is not a reason to fail it.
  """
  @spec record_turn(String.t(), String.t(), [map()], keyword()) ::
          {:ok, map()} | {:error, term()}
  def record_turn(session_dir, turn_id, entries, opts \\ []) do
    with {:ok, manifest} <- read_manifest(session_dir) do
      record = %{
        "turn_id" => turn_id,
        "at" => DateTime.utc_now() |> DateTime.to_iso8601(),
        "message_count" => Keyword.get(opts, :message_count, 0),
        "commands" =>
          opts |> Keyword.get(:commands, []) |> Enum.map(&to_string/1) |> Enum.take(50),
        "dropped" => false,
        "files" => Enum.map(entries, &encode_entry/1)
      }

      turns = (manifest["turns"] ++ [record]) |> Enum.take(-@max_manifest_turns)
      budget = budget_bytes(opts)
      {turns, dropped} = prune(session_dir, turns, budget)

      manifest = %{manifest | "turns" => turns}

      case write_manifest(session_dir, manifest) do
        :ok -> {:ok, summary(record, dropped)}
        {:error, _reason} = error -> error
      end
    end
  end

  @doc "Every turn record this session has, oldest first."
  @spec turns(String.t()) :: {:ok, [map()]} | {:error, term()}
  def turns(session_dir) do
    with {:ok, manifest} <- read_manifest(session_dir), do: {:ok, manifest["turns"]}
  end

  @doc """
  The message count the conversation had at the end of a turn.

  `:error` for a turn this session never recorded, which is what stops a rewind to a
  turn id from another session truncating this one's transcript.
  """
  @spec message_count_at(String.t(), String.t() | non_neg_integer()) ::
          {:ok, non_neg_integer()} | :error
  def message_count_at(session_dir, to_turn) do
    with {:ok, all} <- turns(session_dir),
         {:ok, index} <- locate_turn(all, to_turn) do
      case index do
        -1 -> {:ok, 0}
        _found -> {:ok, Map.get(Enum.at(all, index), "message_count", 0)}
      end
    else
      _unknown -> :error
    end
  end

  @doc """
  Restores every file changed after `to_turn`, byte-exact, and says what it could not.

  `to_turn` is a turn id, or `0` / `:start` for "before anything in this session".

  `{:ok, %{restored: [...], unrestorable: [...], turns: [turn ids]}}`. Each `restored`
  entry names the path and whether it was rewritten or deleted; each `unrestorable`
  entry names the path — or the turn — and why. The two lists together account for every
  file the manifest says was touched, which is the property that makes the answer usable
  as a warning *before* the operator commits.

  The undone turns are then **dropped from the manifest**, because they are no longer part
  of this session's history. A manifest that kept them would let a later rewind restore a
  file to a state the live timeline never had, and would offer the operator a turn
  boundary the transcript no longer has.
  """
  @spec restore_files(String.t(), String.t() | non_neg_integer() | :start) ::
          {:ok, map()} | {:error, term()}
  def restore_files(session_dir, to_turn) do
    with {:ok, manifest} <- read_manifest(session_dir),
         all = manifest["turns"],
         {:ok, index} <- locate_turn(all, to_turn) do
      after_turn = Enum.drop(all, index + 1)

      # Newest first, assigning as we go: the oldest `before` for a path is written last
      # and therefore wins, which is what "restore to the state at the end of `to_turn`"
      # means for a file changed in three of the turns being undone.
      {targets, unrestorable} =
        after_turn
        |> Enum.reverse()
        |> Enum.reduce({%{}, []}, fn turn, {targets, unrestorable} ->
          unrestorable = unrestorable ++ command_warnings(turn)

          Enum.reduce(turn["files"], {targets, unrestorable}, fn entry, {targets, unrestorable} ->
            cond do
              # A file that did not exist before the turn is restored by deleting it
              # again. That state carries no blob, so it is a flag rather than a digest,
              # and it is checked first for exactly that reason.
              entry["before_absent"] == true and turn["dropped"] != true ->
                {Map.put(targets, entry["path"], :absent), unrestorable}

              is_binary(entry["before"]) ->
                {Map.put(targets, entry["path"], entry["before"]), unrestorable}

              true ->
                {targets,
                 unrestorable ++ [%{path: entry["path"], reason: reason_for(turn, entry)}]}
            end
          end)
        end)

      {restored, failed} = write_back(session_dir, targets)
      prune_manifest(session_dir, manifest, index)

      {:ok,
       %{
         restored: restored,
         unrestorable: Enum.uniq(unrestorable ++ failed),
         turns: Enum.map(after_turn, & &1["turn_id"])
       }}
    else
      :error -> {:error, {:unknown_turn, to_turn}}
      {:error, _reason} = error -> error
    end
  end

  @doc "The rewind menu entry for one turn record."
  @spec summary(map(), non_neg_integer()) :: map()
  def summary(record, dropped \\ 0) do
    files = record["files"] || []

    %{
      "turn_id" => record["turn_id"],
      "at" => record["at"],
      "files" => length(files),
      "paths" => files |> Enum.map(& &1["path"]) |> Enum.take(20),
      "commands" => length(record["commands"] || []),
      "restorable" => Enum.count(files, &(&1["before"] != nil or &1["before_absent"] == true)),
      "dropped_turns" => dropped
    }
  end

  # ---------------------------------------------------------------- internals

  defp encode_entry(entry) do
    %{
      "path" => entry.path,
      "before" => digest_or_nil(entry[:before]),
      "before_absent" => entry[:before] == :absent,
      "after" => digest_or_nil(entry[:after]),
      "note" => note_of(entry[:before])
    }
  end

  # `:absent` is a restorable state and carries no blob, so it is a flag rather than a
  # digest. Anything else that is not a digest is a failure to snapshot, and it keeps its
  # reason so the rewind can say what happened rather than "could not".
  defp digest_or_nil(value) when is_binary(value), do: value
  defp digest_or_nil(_other), do: nil

  defp note_of({:unsnapshotted, reason}), do: "not snapshotted: #{inspect(reason)}"
  defp note_of(_other), do: nil

  defp reason_for(%{"dropped" => true}, _entry),
    do: "its checkpoint was dropped to stay inside the session's storage budget"

  defp reason_for(_turn, %{"note" => note}) when is_binary(note), do: note
  defp reason_for(_turn, _entry), do: "no prior content was recorded for it"

  defp command_warnings(%{"commands" => [_first | _rest] = commands, "turn_id" => turn_id}) do
    [
      %{
        path: nil,
        turn_id: turn_id,
        reason:
          "#{length(commands)} shell #{if length(commands) == 1, do: "command", else: "commands"} " <>
            "ran in this turn (#{Enum.join(Enum.take(commands, 3), "; ")}). " <>
            "Whatever they changed is not checkpointed and cannot be restored."
      }
    ]
  end

  defp command_warnings(_turn), do: []

  # The blobs the dropped turns referenced are left to the next `record_turn/4`'s garbage
  # collection: they are unreachable now, and deleting them here would put a file sweep in
  # front of the answer a rewind already earned.
  defp prune_manifest(session_dir, manifest, index) do
    kept = Enum.take(manifest["turns"], index + 1)

    case write_manifest(session_dir, %{manifest | "turns" => kept}) do
      :ok ->
        :ok

      # The files are already back. Failing the rewind over the bookkeeping would be a
      # worse answer than a warning, so this is the warning.
      {:error, reason} ->
        Logger.warning(
          "native rewind restored files but could not prune the turn manifest: " <>
            "#{inspect(reason)}"
        )
    end
  end

  defp write_back(session_dir, targets) do
    Enum.reduce(targets, {[], []}, fn {path, before}, {restored, failed} ->
      case before do
        # `before_absent` was recorded as a `true` flag with a nil digest; the map here
        # only ever holds digests, so this arm is the flag round-tripped by `restore/2`.
        :absent ->
          case File.rm(path) do
            :ok -> {restored ++ [%{path: path, action: "deleted"}], failed}
            {:error, :enoent} -> {restored ++ [%{path: path, action: "already absent"}], failed}
            {:error, reason} -> {restored, failed ++ [%{path: path, reason: inspect(reason)}]}
          end

        digest when is_binary(digest) ->
          with {:ok, content} <- get_blob(session_dir, digest),
               :ok <- File.mkdir_p(Path.dirname(path)),
               :ok <- File.write(path, content, [:binary]) do
            {restored ++ [%{path: path, action: "restored"}], failed}
          else
            {:error, reason} ->
              {restored, failed ++ [%{path: path, reason: inspect(reason)}]}
          end
      end
    end)
  end

  defp locate_turn(_turns, to_turn) when to_turn in [0, :start], do: {:ok, -1}

  defp locate_turn(turns, to_turn) when is_binary(to_turn) do
    case Enum.find_index(turns, &(&1["turn_id"] == to_turn)) do
      nil -> :error
      index -> {:ok, index}
    end
  end

  defp locate_turn(turns, to_turn) when is_integer(to_turn) and to_turn > 0 do
    if to_turn <= length(turns), do: {:ok, to_turn - 1}, else: :error
  end

  defp locate_turn(_turns, _to_turn), do: :error

  defp budget_bytes(opts) do
    configured =
      Keyword.get(opts, :budget_bytes) ||
        Application.get_env(:ouroboros, :native_checkpoint_budget_bytes)

    case configured do
      value when is_integer(value) and value > 0 -> value
      _unset -> @default_budget_bytes
    end
  end

  # Oldest first, and never the newest: a budget that could drop the turn just recorded
  # would make a fresh checkpoint unrestorable the moment it was written.
  defp prune(session_dir, turns, budget) do
    {turns, dropped} = drop_until(session_dir, turns, budget, 0)
    _ = collect_garbage(session_dir, turns)
    {turns, dropped}
  end

  defp drop_until(session_dir, turns, budget, dropped) do
    if used_bytes(session_dir) <= budget or length(turns) <= 1 do
      {turns, dropped}
    else
      [oldest | rest] = turns

      case oldest["dropped"] do
        true ->
          {kept, more} = drop_until(session_dir, rest, budget, dropped)
          {[oldest | kept], more}

        _live ->
          emptied = %{
            oldest
            | "dropped" => true,
              "files" =>
                Enum.map(oldest["files"], &Map.merge(&1, %{"before" => nil, "after" => nil}))
          }

          _ = collect_garbage(session_dir, [emptied | rest])
          drop_until(session_dir, [emptied | rest], budget, dropped + 1)
      end
    end
  end

  defp collect_garbage(session_dir, turns) do
    referenced =
      turns
      |> Enum.flat_map(fn turn -> turn["files"] || [] end)
      |> Enum.flat_map(fn entry ->
        Enum.filter([entry["before"], entry["after"]], &is_binary/1)
      end)
      |> MapSet.new()

    case File.ls(blob_dir(session_dir)) do
      {:ok, entries} ->
        Enum.each(entries, fn entry ->
          unless MapSet.member?(referenced, entry) do
            _ = File.rm(Path.join(blob_dir(session_dir), entry))
          end
        end)

      {:error, _reason} ->
        :ok
    end
  end

  defp used_bytes(session_dir) do
    case File.ls(blob_dir(session_dir)) do
      {:ok, entries} ->
        Enum.reduce(entries, 0, fn entry, total ->
          case File.stat(Path.join(blob_dir(session_dir), entry)) do
            {:ok, %File.Stat{size: size}} -> total + size
            _gone -> total
          end
        end)

      {:error, _reason} ->
        0
    end
  end

  defp read_manifest(session_dir) do
    path = manifest_path(session_dir)

    case File.read(path) do
      {:ok, json} ->
        case decode_manifest(json) do
          {:ok, manifest} ->
            {:ok, manifest}

          :error ->
            # A corrupt manifest is replaced rather than refused: unlike the conversation,
            # losing it costs the ability to rewind, and refusing to start the session
            # over it would cost the session.
            Logger.warning(
              "native file checkpoint manifest was unreadable and was reset: #{path}"
            )

            {:ok, empty_manifest()}
        end

      {:error, :enoent} ->
        {:ok, empty_manifest()}

      {:error, reason} ->
        {:error, {:manifest_unreadable, reason}}
    end
  end

  defp decode_manifest(json) do
    case JSON.decode!(json) do
      %{"version" => @manifest_version, "turns" => turns} = manifest when is_list(turns) ->
        {:ok, manifest}

      _other ->
        :error
    end
  rescue
    _error -> :error
  end

  defp empty_manifest, do: %{"version" => @manifest_version, "turns" => []}

  defp write_manifest(session_dir, manifest) do
    path = manifest_path(session_dir)

    temporary =
      path <> ".tmp-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

    with {:ok, json} <- encode_manifest(manifest),
         :ok <- File.mkdir_p(Path.dirname(path)),
         :ok <- File.write(temporary, json, [:binary, :sync]),
         :ok <- File.chmod(temporary, 0o600),
         :ok <- File.rename(temporary, path) do
      :ok
    else
      {:error, reason} ->
        _ = File.rm(temporary)
        {:error, {:manifest_write_failed, reason}}
    end
  end

  defp encode_manifest(manifest) do
    {:ok, JSON.encode!(manifest)}
  rescue
    error -> {:error, {:manifest_unencodable, Exception.message(error)}}
  end
end
