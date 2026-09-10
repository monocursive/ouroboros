defmodule Ouroboros.Session do
  @moduledoc """
  Owner-node boundary to the native execution process. This facade owns no process.

  Runtime IDs, generation-local output cursors, and native conversation IDs are
  distinct from the public logical session identity. Public history and waiters
  belong to InteractiveSession's durable coordinator.
  """
  alias Ouroboros.Provider.Native.Session, as: Native
  alias Ouroboros.Session.{ApprovalResponse, Request, TurnRequest}

  def open(logical_id, request) do
    with {:ok, request} <- request(request),
         :ok <- validate_native_request(request, false),
         do: Native.open(logical_id, request)
  end

  def open_child(logical_id, request, context) do
    with {:ok, request} <- request(request),
         :ok <- validate_native_request(request, true),
         do: Native.open_child(logical_id, request, context)
  end

  def list do
    Registry.select(Ouroboros.SessionRegistry, [{{{:runtime, :_}, :"$1", :_}, [], [:"$1"]}])
    |> Enum.flat_map(fn pid ->
      case Native.runtime_info(pid) do
        {:ok, info} -> [info]
        _ -> []
      end
    end)
  end

  def info(runtime_id), do: Native.runtime_info(runtime_id)
  def attach(runtime_id, coordinator, cursor), do: Native.attach(runtime_id, coordinator, cursor)

  def submit(runtime_id, turn_id, mode, request) do
    with {:ok, request} <- turn(request), do: Native.submit(runtime_id, turn_id, mode, request)
  end

  def steer(runtime_id, request_id, request) do
    with {:ok, request} <- turn(request), do: Native.steer(runtime_id, request_id, request)
  end

  def respond_approval(runtime_id, request_id, response) do
    with {:ok, response} <- approval(response),
         do: Native.respond_approval(runtime_id, request_id, response)
  end

  def configure(runtime_id, changes), do: Native.configure(runtime_id, changes)
  def interrupt(runtime_id, turn_id \\ :active), do: Native.interrupt(runtime_id, turn_id)
  def close(runtime_id), do: Native.close(runtime_id)
  def kill(runtime_id), do: Native.kill(runtime_id)
  def drain(attachment, after_cursor, limit), do: Native.drain(attachment, after_cursor, limit)
  def ack(attachment, cursor), do: Native.ack(attachment, cursor)
  def turn_result(runtime_id, turn_id), do: Native.turn_result(runtime_id, turn_id)
  def bridge_tool(runtime_id, call, emit), do: Native.bridge_tool(runtime_id, call, emit)
  def context_info(runtime_id), do: Native.info(runtime_id)
  def plan_mode(runtime_id, enabled), do: Native.plan_mode(runtime_id, enabled)
  def plan_state(runtime_id), do: Native.plan_state(runtime_id)
  def compact(runtime_id, focus \\ nil), do: Native.compact(runtime_id, focus)
  def handoff(runtime_id, prompt \\ nil, opts \\ []), do: Native.handoff(runtime_id, prompt, opts)
  def journal(runtime_id, opts \\ []), do: Native.journal(runtime_id, opts)
  def rewind(runtime_id, to_turn, what \\ :both), do: Native.rewind(runtime_id, to_turn, what)
  def rewind_points(runtime_id), do: Native.rewind_points(runtime_id)

  defp validate_native_request(request, child?) do
    allowed =
      Ouroboros.Provider.Native.spec().provider_options ++ [:compact_at, :keep_recent_tokens]

    allowed =
      if child?,
        do:
          allowed ++
            [
              :subagent_depth,
              :subagent_parent,
              :subagent_task_id,
              :checkpoint_limit,
              :subagent_max_deadline_ms,
              :bash_max_timeout_ms
            ],
        else: allowed

    names = Enum.map(allowed, &Atom.to_string/1)

    unknown =
      Enum.find_value(Map.keys(request.provider_options), fn key ->
        if to_string(key) not in names, do: {:unknown, key}
      end)

    cond do
      request.provider not in [nil, :native] ->
        {:error,
         Ouroboros.Session.Error.validation("provider is not supported",
           details: %{provider: request.provider}
         )}

      request.transport not in [nil, :native] ->
        {:error,
         Ouroboros.Session.Error.validation("unknown session transport",
           details: %{transport: request.transport}
         )}

      request.env != %{} ->
        {:error,
         Ouroboros.Session.Error.validation(
           "session transport does not support environment overrides",
           details: %{transport: :native, field: :env}
         )}

      request.mcp_config not in [nil, [], %{}] ->
        {:error,
         Ouroboros.Session.Error.validation("provider does not support normalized session option",
           details: %{field: :mcp_config}
         )}

      unknown ->
        {:error,
         Ouroboros.Session.Error.validation("unknown provider option",
           details: %{key: elem(unknown, 1)}
         )}

      true ->
        :ok
    end
  end

  defp request(%Request{} = request), do: Request.new(Map.from_struct(request))

  defp request(request) when is_map(request) or is_list(request) do
    defaults = Map.get(Ouroboros.Provider.Native.config(), :session_defaults, %{})
    defaults = Map.new(defaults, fn {key, value} -> {to_string(key), value} end)
    attrs = Map.new(request, fn {key, value} -> {to_string(key), value} end)
    Request.new(Map.merge(defaults, attrs))
  end

  defp request(request), do: Request.new(request)
  defp turn(%TurnRequest{} = request), do: TurnRequest.new(Map.from_struct(request))
  defp turn(request), do: TurnRequest.new(request)

  defp approval(%ApprovalResponse{} = response),
    do: ApprovalResponse.new(Map.from_struct(response))

  defp approval(response), do: ApprovalResponse.new(response)
end
