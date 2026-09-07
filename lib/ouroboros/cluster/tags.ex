defmodule Ouroboros.Cluster.Tags do
  @moduledoc "Operator-only tag edits reuse the installed client's atomic profile writer and lifecycle lock."
  alias Ouroboros.Cluster.Facts
  alias Ouroboros.Provider.Native.Exec

  def change(target, operation, tag) when target == node(), do: local(operation, tag)

  def change(target, operation, tag) do
    if target in Node.list() do
      :erpc.call(target, __MODULE__, :local, [operation, tag], 10_000)
    else
      {:error, :node_not_connected}
    end
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  # No parent filesystem path travels. The launcher publishes the installed ouro path
  # on this node; its profile lock is also used by invite, leave and daemon startup.
  def local("list", _), do: profile_tags()

  def local(operation, tag) when operation in ["add", "remove"] do
    with :ok <- valid_change(operation, tag),
         helper when is_binary(helper) <- System.get_env("OUROBOROS_PROCESS_ID_HELPER"),
         true <- Path.type(helper) == :absolute and File.regular?(helper),
         data when is_binary(data) <- Application.get_env(:ouroboros, :data_dir),
         {:ok, %{status: 0}} <-
           Exec.run(helper, ["fleet", "tag", operation, tag],
             timeout_ms: 5_000,
             max_bytes: 4_096,
             env: [{"OUROBOROS_DATA_DIR", data}]
           ) do
      profile_tags()
    else
      {:error, reason} ->
        {:error, reason}

      nil ->
        {:error,
         "this runtime has no installed ouro helper; run ouro fleet tag on the target or restart it with ouro daemon"}

      {:ok, result} ->
        {:error, Map.get(result, :output, "tag update failed")}

      other ->
        {:error, other}
    end
  end

  def local(_, _), do: {:error, :invalid_tag_operation}

  # A malformed existing string may be removed remotely too. It never becomes a
  # selector or authority; the writer validates the remaining list before saving.
  defp valid_change("remove", tag) when is_binary(tag) and byte_size(tag) <= 1024, do: :ok

  defp valid_change(_operation, tag) do
    case Facts.validate_tags([tag]) do
      %{tags_error: reason} -> {:error, reason}
      %{tags: [_]} -> :ok
    end
  end

  defp profile_tags do
    case Ouroboros.Cluster.Monitor.fleet_profile_storage() do
      {:ok, _, profile, _} ->
        case Map.get(profile, :tag_facts, %{tags: []}) do
          %{tags_error: reason} -> {:error, reason}
          %{tags: tags} -> {:ok, tags}
        end

      _ ->
        {:error, :fleet_profile_unavailable}
    end
  end
end
