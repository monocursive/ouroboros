defmodule Ouroboros.Provider.Native.Tools.AgentResult do
  @moduledoc """
  Collect a background child spawned by `agent` (G3).

  It is a second tool rather than a `collect:` parameter on `agent` for one reason that
  is visible in the schema: `agent`'s `prompt` is required, and a spawn and a collection
  that share one schema must either make the prompt optional — teaching the model that a
  subagent can be spawned without instructions — or carry a mode flag, which is a third
  thing to get wrong. Two tools, each with a schema that is true of every call it accepts.

  ## What "waiting" means here

  This tool runs in the ordinary tool task, so its wait is bounded by the loop's tool
  timeout as well as its own. `wait_ms` defaults to 30 s and is capped at 60 s; a child
  that is still running after that is **not** an error and **not** lost — the answer says
  so, and the same `task_id` is collectable again. That is deliberately different from the
  child's own wall-clock deadline, which is what actually ends it.

  A child that was stopped — because the parent session closed, or because a person
  interrupted it — reports `stopped` with whatever it had done by then, rather than an
  error. "It did four of the six files and then I closed the session" is information; a
  failure would not be.

  A collected child is released: its process ends, its transcript stays on disk under its
  own `provider_session_id`, and a second collection of the same id says it is unknown.
  """

  use Jido.Action,
    name: "agent_result",
    description:
      "Wait for a background subagent and return its summary. Give it the task_id " <>
        "`agent` returned. A child that is still running says so and stays collectable.",
    schema: [
      task_id: [
        type: :string,
        required: true,
        doc: "The task_id `agent` returned when it spawned the child in the background."
      ],
      wait_ms: [
        type: :non_neg_integer,
        default: 30_000,
        doc: "How long to wait for it to finish. Maximum 60000. 0 returns what it has now."
      ]
    ]

  alias Ouroboros.Provider.Native.Subagent

  @max_wait_ms 60_000

  @impl true
  def run(params, context) do
    case context[:subagents] do
      %{lookup: lookup, release: release} when is_function(lookup, 1) ->
        collect(params, lookup, release)

      _absent ->
        {:ok,
         %{
           output:
             "agent_result needs a parent session that tracks subagents, and this run has " <>
               "none. Nothing was collected.",
           is_error: true
         }}
    end
  end

  defp collect(params, lookup, release) do
    task_id = String.trim(params.task_id)

    case lookup.(task_id) do
      {:ok, pid} -> await(task_id, pid, wait_ms(params), release)
      :error -> {:ok, %{output: unknown(task_id), is_error: true}}
    end
  end

  defp await(task_id, pid, wait_ms, release) do
    case Subagent.await(pid, wait_ms) do
      {:ok, summary} ->
        _ = release.(task_id)
        {:ok, %{output: Subagent.render(summary), is_error: summary.status == :failed}}

      {:error, :still_running} ->
        {:ok,
         %{
           output:
             "Subagent #{task_id} is still running after #{wait_ms} ms. It has not been " <>
               "lost — collect it again with the same task_id, or do something else first.",
           is_error: false
         }}

      {:error, reason} ->
        _ = release.(task_id)

        {:ok,
         %{
           output:
             "Subagent #{task_id} could not be reached (#{inspect(reason)}), so no summary " <>
               "is available. Its transcript, if it wrote one, is under its own session id.",
           is_error: true
         }}
    end
  end

  defp unknown(task_id),
    do:
      "No subagent #{task_id} is tracked by this session. Either it was already collected, " <>
        "or the session it belonged to has closed. Spawn a new one if you still need the work."

  defp wait_ms(%{wait_ms: value}) when is_integer(value) and value >= 0,
    do: min(value, @max_wait_ms)

  defp wait_ms(_params), do: 30_000
end
