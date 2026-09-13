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

  A terminal child remains retained after summaries and pages are read, including the final
  page. This makes a lost tool response safely retryable and a page deterministically
  rereadable. The caller explicitly releases it with `release: true`; its process then ends
  while its bounded transcript stays on disk under its own `provider_session_id`.
  """

  use Ouroboros.Action,
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
      stop: [
        type: :boolean,
        default: false,
        doc: "Stop this session's child and collect its summary."
      ],
      wait_ms: [
        type: :non_neg_integer,
        default: 30_000,
        doc: "How long to wait for it to finish. Maximum 60000. 0 returns what it has now."
      ],
      cursor: [
        type: :non_neg_integer,
        doc: "Byte cursor returned by a prior page. Omit for the concise summary."
      ],
      max_bytes: [
        type: :pos_integer,
        default: 12_288,
        doc: "Maximum UTF-8 report bytes to return for a page. Maximum 12288."
      ],
      release: [
        type: :boolean,
        default: false,
        doc: "Explicitly release a terminal child after this successful summary or page read."
      ]
    ]

  alias Ouroboros.Provider.Native.Subagent

  @max_wait_ms 60_000
  @max_page_bytes 12 * 1024

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

    with :ok <- validate_page_params(params) do
      collect_owned(task_id, params, lookup, release)
    else
      {:error, message} -> {:ok, %{output: message, is_error: true}}
    end
  end

  defp collect_owned(task_id, params, lookup, release) do
    case lookup.(task_id) do
      {:ok, pid} when is_pid(pid) ->
        if Map.has_key?(params, :cursor) do
          page(task_id, pid, params, release, wait_ms(params))
        else
          if Map.get(params, :stop, false) do
            case Subagent.stop(pid, :stopped) do
              {:ok, %{status: :returning} = summary} ->
                # The existing session subscriber still owns this return. Keep its
                # registry entry until acknowledgment or a retained-work error settles it.
                release_pending(
                  params,
                  Subagent.render(summary) <>
                    "\nThe return is still in progress; collect it again with the same task_id."
                )

              {:ok, summary} ->
                maybe_release(params, task_id, release)
                {:ok, %{output: Subagent.render(summary), is_error: false}}

              {:error, reason} ->
                {:ok,
                 %{output: "Subagent could not be stopped: #{inspect(reason)}", is_error: true}}
            end
          else
            await(task_id, pid, wait_ms(params), params, release)
          end
        end

      _foreign_or_absent ->
        {:ok, %{output: unknown(task_id), is_error: true}}
    end
  end

  defp validate_page_params(%{cursor: cursor} = params) do
    max_bytes = Map.get(params, :max_bytes, @max_page_bytes)

    cond do
      not is_integer(cursor) or cursor < 0 ->
        {:error,
         "Invalid result cursor #{inspect(cursor)}; it must be a non-negative byte cursor."}

      not is_integer(max_bytes) or max_bytes <= 0 ->
        {:error, "Invalid max_bytes #{inspect(max_bytes)}; it must be a positive byte count."}

      true ->
        :ok
    end
  end

  defp validate_page_params(_params), do: :ok

  defp page(task_id, pid, params, release, wait_ms) do
    cursor = Map.get(params, :cursor)
    max_bytes = min(Map.get(params, :max_bytes, @max_page_bytes), @max_page_bytes)

    case Subagent.result_page(pid, cursor, max_bytes) do
      {:ok, page} ->
        maybe_release(params, task_id, release)

        continuation =
          if page.complete,
            do: "complete",
            else: "continue with cursor #{page.next_cursor}"

        output =
          "Subagent #{task_id} report page #{page.cursor}..#{page.next_cursor || page.total_bytes} " <>
            "of #{page.total_bytes} bytes (#{continuation}; status #{page.status}; " <>
            "original_bytes=#{page.original_bytes}; retained_truncated=#{page.retained_truncated})\n\n#{page.text}"

        {:ok, %{output: output, is_error: false}}

      {:error, {:invalid_result_cursor, cursor, total}} ->
        {:ok,
         %{
           output: "Invalid result cursor #{cursor}; retained report is #{total} bytes.",
           is_error: true
         }}

      {:error, {:result_not_terminal, status}} ->
        await_page(task_id, pid, params, release, wait_ms, status)

      {:error, reason} ->
        {:ok,
         %{
           output: "Subagent #{task_id} report could not be read: #{inspect(reason)}",
           is_error: true
         }}
    end
  end

  defp await_page(task_id, _pid, params, _release, 0, status) do
    running_page(params, task_id, status, 0)
  end

  defp await_page(task_id, pid, params, release, wait_ms, status) do
    case Subagent.await(pid, wait_ms) do
      {:ok, _summary} ->
        page(task_id, pid, params, release, 0)

      {:error, :still_running} ->
        running_page(params, task_id, status, wait_ms)

      {:error, reason} ->
        {:ok,
         %{
           output: "Subagent #{task_id} could not be reached: #{inspect(reason)}",
           is_error: true
         }}
    end
  end

  defp running_page(params, task_id, status, wait_ms) do
    case release_pending(
           params,
           "Subagent #{task_id} is #{status}; no stable report page is available yet."
         ) do
      {:ok, result} ->
        {:ok,
         Map.put(result, :lifecycle, %{
           state: to_string(status),
           terminal: false,
           report_available: false,
           next_action: "await_settlement_event",
           wait_ms: wait_ms
         })}
    end
  end

  defp await(task_id, pid, wait_ms, params, release) do
    case Subagent.await(pid, wait_ms) do
      {:ok, summary} ->
        maybe_release(params, task_id, release)

        if summary.result_bytes > 12 * 1024 do
          {:ok,
           %{
             output:
               Subagent.render(summary) <>
                 "\nThe report is larger than this digest; retrieve the retained report exactly with cursor 0.",
             is_error: summary.status == :failed
           }}
        else
          {:ok, %{output: Subagent.render(summary), is_error: summary.status == :failed}}
        end

      {:error, :still_running} ->
        case Subagent.summary(pid) do
          {:ok, summary} ->
            {:ok,
             %{
               output: Subagent.render(summary),
               is_error: false,
               lifecycle: %{
                 state: "running",
                 terminal: false,
                 report_available: false,
                 next_action: "await",
                 wait_ms: wait_ms,
                 effective_deadline_ms: Map.get(summary, :effective_deadline_ms)
               }
             }}

          {:error, reason} ->
            {:ok,
             %{
               output: "Subagent #{task_id} could not be reached: #{inspect(reason)}",
               is_error: true
             }}
        end

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

  defp maybe_release(params, task_id, release) do
    if Map.get(params, :release, false), do: release.(task_id), else: :ok
  end

  defp release_pending(params, message) do
    if Map.get(params, :release, false) do
      {:ok,
       %{
         output:
           message <> " Release was refused because only a terminal result can be released.",
         is_error: true
       }}
    else
      {:ok, %{output: message, is_error: false}}
    end
  end
end
