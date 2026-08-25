defmodule Ouroboros.Gateway.Methods.Encode do
  @moduledoc false

  # Wire encoding and plane-result mapping that is not on the parameter-contract
  # AST path. Client bytes never become atoms here; enum strings are literals.

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.CodeIntel
  alias Ouroboros.Gateway.Config, as: GatewayConfig
  alias Ouroboros.Gateway.Methods.Safe
  alias Ouroboros.Gateway.Wire

  # Where `ledger.export`'s hash chain starts. A fixed, published seed rather than a random
  # one: the point of the chain is that a client can recompute it from the answer alone.
  @chain_seed String.duplicate("0", 64)

  # Atoms the coordinator chose, rendered as the literal strings this module contains. A
  # decision is never `to_string`d out of whatever the plane happened to answer.
  def approval_answer(answer) do
    %{
      "decision" => if(answer.decision == :allow, do: "allow", else: "deny"),
      "request_id" => answer.request_id,
      "source" => approval_source(answer.source),
      "reason" => answer.reason
    }
  end

  defp approval_source(:engine), do: "engine"
  defp approval_source(:human), do: "human"
  defp approval_source(:timeout), do: "timeout"
  defp approval_source(:capacity), do: "capacity"
  defp approval_source(:session_terminal), do: "session_terminal"
  defp approval_source(:checkpoint_failed), do: "checkpoint_failed"
  defp approval_source(:caller_gone), do: "caller_gone"
  defp approval_source(:coordinator_restart), do: "coordinator_restart"
  defp approval_source(_other), do: "runtime"

  def code_intel_reply({:ok, %{items: items} = answer}) when is_list(items) do
    {:ok, answer |> Map.put(:status, :ok) |> Map.put(:items, code_intel_items(items))}
  end

  def code_intel_reply({:ok, value}), do: {:ok, value}

  # Not an error: the server has not answered for this version of the document yet. A
  # caller that treated "no data yet" as a failure of whatever produced the edit is
  # exactly the regression R4 §2 records against stale diagnostics, so it arrives as an
  # ordinary result carrying no items at all — there is nothing to mistake for "clean".
  def code_intel_reply({:pending, version}), do: {:ok, %{status: :pending, version: version}}

  def code_intel_reply({:error, {:server_unavailable, server_id, hint}}) do
    {:error, Ouroboros.Gateway.Methods.code(:unavailable),
     "no language server is available for that file: #{hint}",
     %{"reason" => "server_unavailable", "server" => server_id, "hint" => hint}}
  end

  def code_intel_reply({:error, {:outside_workspace, path}}) do
    {:error, Ouroboros.Gateway.Methods.code(:invalid_params),
     "that path is not inside a workspace root this node admits",
     %{"reason" => "outside_workspace", "path" => to_string(path)}}
  end

  def code_intel_reply({:error, {:no_project_root, language, markers}}) do
    {:error, Ouroboros.Gateway.Methods.code(:unavailable),
     "no project root for that #{language} file; expected one of #{Enum.join(markers, ", ")}",
     %{"reason" => "no_project_root", "language" => to_string(language), "markers" => markers}}
  end

  # A path that cannot be canonicalised is a path, not an upstream failure: it is missing,
  # it is a directory, it is a symlink that goes nowhere, or it was relative to a directory
  # that means nothing here. Saying `-32006 the runtime failed the call` about any of those
  # sends a caller looking for a fault in the runtime.
  def code_intel_reply({:error, {tag, path, reason}})
      when tag in [:workspace_path_error, :path_unavailable, :symbolic_link_unreadable] do
    unreadable_path(path, reason)
  end

  def code_intel_reply({:error, {tag, path}})
      when tag in [:not_a_directory, :symbolic_link_cycle] do
    unreadable_path(path, tag)
  end

  def code_intel_reply({:error, :too_many_symbolic_links}) do
    unreadable_path("that path", :too_many_symbolic_links)
  end

  def code_intel_reply({:error, {:not_a_regular_file, path}}) do
    {:error, Ouroboros.Gateway.Methods.code(:invalid_params), "params.path is not a regular file",
     %{"reason" => "not_a_regular_file", "path" => to_string(path)}}
  end

  def code_intel_reply({:error, {:invalid_attachment_path, path}}) do
    {:error, Ouroboros.Gateway.Methods.code(:invalid_params),
     "params.path must be a nonempty string",
     %{"reason" => "invalid_path", "path" => inspect(path)}}
  end

  def code_intel_reply({:error, {:unsupported_language, extension}}) do
    {:error, Ouroboros.Gateway.Methods.code(:invalid_params),
     "no language server is registered for #{extension} files",
     %{"reason" => "unsupported_language", "extension" => extension}}
  end

  def code_intel_reply({:error, {:unknown_operation, operation, allowed}}) do
    Safe.invalid_params(
      "params.operation must be one of " <>
        (allowed |> Enum.map(&to_string/1) |> Enum.sort() |> Enum.join(", ")) <>
        ", got: #{inspect(operation)}"
    )
  end

  def code_intel_reply({:error, :disabled}) do
    {:error, Ouroboros.Gateway.Methods.code(:unavailable),
     "code intelligence is disabled on this node", %{"reason" => "disabled"}}
  end

  def code_intel_reply({:error, :broken}) do
    {:error, Ouroboros.Gateway.Methods.code(:unavailable),
     "that language server failed too often and is not being respawned for now",
     %{"reason" => "broken"}}
  end

  def code_intel_reply({:error, :document_not_open}) do
    {:error, Ouroboros.Gateway.Methods.code(:unavailable),
     "no language server holds that document; announce the edit with code_intel.touch first",
     %{"reason" => "document_not_open"}}
  end

  def code_intel_reply({:error, reason}), do: Safe.upstream_error(reason)
  def code_intel_reply(other), do: {:ok, other}

  defp unreadable_path(path, reason) do
    {:error, Ouroboros.Gateway.Methods.code(:invalid_params),
     "params.path could not be read as a file (#{inspect(reason)}); name it absolutely, " <>
       "because a relative path here is expanded against the runtime's own working " <>
       "directory rather than against the workspace",
     %{"reason" => "unreadable_path", "path" => to_string(path)}}
  end

  # Every diagnostic that crosses the wire carries the identity its caller needs to tell a
  # new finding from one that was already there. Navigation items have no severity and are
  # left exactly as the pool returned them.
  defp code_intel_items(items) do
    Enum.map(items, fn
      %{severity: _severity, message: _message, range: _range} = item ->
        Map.put(item, :signature, CodeIntel.Diagnostics.signature(item))

      item ->
        item
    end)
  end

  @spec chain([EffectLedger.Entry.t()]) :: map()
  def chain(entries) when is_list(entries) do
    {lines, head} =
      Enum.map_reduce(entries, @chain_seed, fn entry, previous ->
        line = entry |> Wire.to_json() |> canonical_json()
        hash = :sha256 |> :crypto.hash([previous, line]) |> Base.encode16(case: :lower)

        {%{sequence: entry.sequence, id: entry.id, line: line, previous: previous, hash: hash},
         hash}
      end)

    %{algorithm: "sha256", count: length(lines), seed: @chain_seed, head: head, lines: lines}
  end

  # Object keys sorted, no whitespace. `JSON.encode!/1` iterates a map in whatever order
  # the term happens to have, which is stable enough in practice and not a property worth
  # betting a hash chain on: two exports of the same entry have to produce the same bytes,
  # on any machine, or the chain a client verifies is a chain over an accident.
  defp canonical_json(value), do: value |> canonical() |> IO.iodata_to_binary()

  defp canonical(map) when is_map(map) do
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

  # Encoded here rather than by the `Conn`, because this is the one answer that gets the
  # larger per-leaf cap: the whole point of the method is to hand back the leaf a
  # streamed event could only excerpt. What it returns is already a JSON tree, so the
  # connection's own `Wire.to_json/1` walks plain strings and maps and leaves it alone.
  def detail(event) do
    limits = GatewayConfig.event_limits()

    Wire.to_json(event,
      event_leaf_bytes: limits.detail_leaf_bytes,
      event_payload_bytes: limits.detail_leaf_bytes
    )
  end
end
