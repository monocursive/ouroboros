defmodule Ouroboros.Interactive.CrashDiagnostics do
  @moduledoc false

  # This projection is deliberately an allow-list. Interactive state and the message that
  # killed the coordinator can both contain the transcript, tool arguments, tokens, or an
  # approval/grant. None of those terms is traversed or inspected here.
  @max_ids 32
  @max_stack 12

  defmodule SafeError do
    @moduledoc false
    defexception [:class]

    @impl true
    def message(%__MODULE__{class: class}), do: "crash in #{inspect(class)}"
  end

  @spec format_status(map()) :: map()
  def format_status(status) when is_map(status) do
    status
    |> Map.put(:state, state(Map.get(status, :state)))
    |> Map.put(:message, :redacted)
    |> maybe_reason()
  end

  defp state(%{session: session} = runtime) when is_map(session) do
    %{
      session_id: identifier(Map.get(session, :id)),
      runtime_id: identifier(Map.get(session, :runtime_id)),
      provider_session_id: identifier(Map.get(session, :provider_session_id)),
      status: safe_atom(Map.get(session, :status)),
      turn_ids: ids(Map.keys(Map.get(session, :turns, %{}))),
      approval_ids: ids(Map.keys(Map.get(runtime, :external_approvals, %{})))
    }
  end

  defp state(_), do: :redacted

  defp maybe_reason(status) do
    case Map.fetch(status, :reason) do
      {:ok, reason} -> Map.put(status, :reason, reason(reason))
      :error -> status
    end
  end

  defp reason({:error, value, stack}) when is_list(stack) do
    class = exception_class(value)
    %{kind: :error, reason: %SafeError{class: class}, class: class, stacktrace: stacktrace(stack)}
  end

  defp reason({kind, value, stack}) when kind in [:exit, :throw] and is_list(stack) do
    %{kind: kind, class: exception_class(value), stacktrace: stacktrace(stack)}
  end

  defp reason({:badkey, _key, _term}), do: %SafeError{class: KeyError}
  defp reason({:badmap, _term}), do: %SafeError{class: BadMapError}

  defp reason(%{__struct__: module}) when is_atom(module),
    do: %SafeError{class: module}

  defp reason(reason) when is_atom(reason), do: reason
  defp reason(_), do: :redacted

  defp exception_class(%{__struct__: module}) when is_atom(module), do: module
  defp exception_class(value) when is_atom(value), do: value
  defp exception_class(_), do: :redacted

  defp stacktrace(stack) do
    stack
    |> Enum.take(@max_stack)
    |> Enum.map(fn
      {module, function, arity, location}
      when is_atom(module) and is_atom(function) and (is_integer(arity) or is_list(arity)) ->
        {module, function, if(is_integer(arity), do: arity, else: length(arity)),
         safe_location(location)}

      _ ->
        :redacted
    end)
  end

  defp safe_location(location) when is_list(location) do
    location
    |> Keyword.take([:file, :line])
    |> Keyword.update(:file, nil, fn file -> Path.basename(to_string(file)) end)
  end

  defp safe_location(_), do: []

  defp ids(values), do: values |> Enum.take(@max_ids) |> Enum.map(&identifier/1)
  # IDs can be caller supplied. Preserve correlation without logging their contents or
  # terminal control bytes.
  defp identifier(value) when is_binary(value) do
    digest = :crypto.hash(:sha256, value) |> Base.encode16(case: :lower) |> binary_part(0, 16)
    "sha256:" <> digest
  end

  defp identifier(_), do: :redacted
  defp safe_atom(value) when is_atom(value), do: value
  defp safe_atom(_), do: :redacted
end
