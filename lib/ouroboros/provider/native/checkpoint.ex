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
  gone is a message most providers reject outright.
  """

  alias Ouroboros.Provider.Native.Paths

  @version 1
  @default_limit 400

  @doc "Where one session's checkpoint lives, and whether that location survives a reboot."
  @spec locate(String.t()) :: {:ok, String.t(), boolean()} | {:error, term()}
  def locate(provider_session_id) do
    case Paths.session_dir(provider_session_id) do
      {:ok, dir, durable?} -> {:ok, Path.join(dir, "conversation.json"), durable?}
      {:error, _reason} = error -> error
    end
  end

  @doc """
  Writes the conversation, atomically and privately.

  A temporary file in the same directory is renamed over the target, so a reader never
  sees a partial write and a crashed write leaves the previous checkpoint intact.
  """
  @spec write(String.t(), [map()], keyword()) :: :ok | {:error, term()}
  def write(path, messages, opts \\ []) do
    limit = Keyword.get(opts, :event_limit, @default_limit)
    trimmed = trim(messages, limit)
    encoded = Enum.map(trimmed, &encode/1)
    digest = digest(encoded)

    payload = %{
      "version" => @version,
      "digest" => digest,
      "updated_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "messages" => encoded
    }

    with {:ok, json} <- encode_json(payload),
         temporary =
           path <> ".tmp-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false),
         :ok <- File.write(temporary, json, [:binary, :sync]),
         :ok <- File.chmod(temporary, 0o600),
         :ok <- File.rename(temporary, path) do
      :ok
    else
      {:error, reason} -> {:error, {:checkpoint_write_failed, reason}}
    end
  end

  @doc """
  Reads a conversation back, or says why it will not.

  `{:error, :no_checkpoint}` for a session id this node has never written, which is the
  ordinary "resume a session that was never here" case and not a failure.
  """
  @spec read(String.t()) :: {:ok, [map()]} | {:error, term()}
  def read(path) do
    with {:ok, json} <- read_file(path),
         {:ok, payload} <- decode_json(json),
         :ok <- verify_version(payload),
         {:ok, encoded} <- fetch_messages(payload),
         :ok <- verify_digest(payload, encoded) do
      {:ok, Enum.map(encoded, &decode/1)}
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

  defp verify_version(%{"version" => @version}), do: :ok
  defp verify_version(%{"version" => other}), do: {:error, {:checkpoint_version, other}}
  defp verify_version(_payload), do: {:error, :checkpoint_corrupt}

  defp fetch_messages(%{"messages" => messages}) when is_list(messages), do: {:ok, messages}
  defp fetch_messages(_payload), do: {:error, :checkpoint_corrupt}

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
