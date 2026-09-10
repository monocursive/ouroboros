defmodule Ouroboros.Test.ModelRequest do
  @moduledoc false
  defstruct [
    :prompt,
    :cwd,
    :model,
    :provider_session_id,
    :approval_mode,
    :sandbox_mode,
    :reasoning_effort,
    :system_prompt,
    :allowed_tools,
    :disallowed_tools,
    :provider_options,
    :attachments,
    :metadata,
    :output_schema,
    :max_turns,
    :runtime_timeout_ms,
    :idle_timeout_ms
  ]
end

defmodule Ouroboros.Test.ControlledModel do
  @moduledoc "A controlled model stream inside the real native loop. No provider worker."
  @behaviour Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native

  def available?, do: true
  def credential_report, do: []

  def stream(request, _opts) do
    owner = Native.Session.whereis(request.provider_session_id)
    state = :sys.get_state(owner)
    controller = Map.fetch!(Native.config(), :test_pid)

    prompt =
      request.messages |> Enum.reverse() |> Enum.find(&(&1.role == :user)) |> Map.fetch!(:content)

    input =
      state.request
      |> Map.from_struct()
      |> Map.merge(%{
        prompt: prompt,
        model: request.model,
        reasoning_effort: request.reasoning_effort
      })

    input =
      struct(
        Ouroboros.Test.ModelRequest,
        Map.take(input, Map.keys(%Ouroboros.Test.ModelRequest{}))
      )

    send(controller, {:ouroboros_test_model_started, request.turn_id, input, self()})

    {:ok,
     Stream.resource(
       fn -> false end,
       fn
         true -> {:halt, true}
         false -> next(request, owner)
       end,
       fn _ -> send(controller, {:ouroboros_test_model_closed, request.turn_id}) end
     )}
  end

  defp next(request, owner) do
    receive do
      {:controlled_emit, type, payload, fields} ->
        case type do
          type when type in [:output_text_delta, :output_text_final] ->
            {[{:text, payload["text"] || ""}], false}

          :usage ->
            {[{:usage, payload}], false}

          :run_failed ->
            raise(payload["error"] || "scripted model failure")

          _projection_fact ->
            event = %{
              type: type,
              payload: payload,
              turn_id: request.turn_id,
              request_id: Keyword.get(fields, :request_id)
            }

            :ok = GenServer.call(owner, {:native_event, request.turn_id, event}, :infinity)
            next(request, owner)
        end

      :controlled_finish ->
        {[{:finish, :stop}], true}

      :native_interrupt ->
        # Preserve the signal for the loop's safe boundary after this stream ends.
        send(self(), :native_interrupt)
        {[{:finish, :stop}], true}
    end
  end

  def emit(pid, type, payload \\ %{}, fields \\ []) do
    send(pid, {:controlled_emit, type, payload, fields})
    :ok
  end

  def finish(pid),
    do:
      (
        send(pid, :controlled_finish)
        :ok
      )
end
