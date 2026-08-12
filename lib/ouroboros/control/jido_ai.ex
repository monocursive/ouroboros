defmodule Ouroboros.Control.JidoAI do
  @moduledoc """
  Production planner/evaluator adapter backed by structured Jido.AI actions.

  No provider option is persisted by the control plane. Configure the model,
  timeout, token limit, and other request policy explicitly in this adapter's
  runtime options. Provider errors are returned through Jido.AI's sanitized
  action boundary.

  Stable request IDs provide trace correlation and let a custom adapter add
  deduplication, but ReqLLM does not promise provider-side exactly-once calls.
  A VM crash after a response and before the next checkpoint can repeat and
  bill the same planning or evaluation request during recovery.
  """

  @behaviour Ouroboros.Control.Planner
  @behaviour Ouroboros.Control.Evaluator

  alias Ouroboros.Orchestration.Plan

  @impl Ouroboros.Control.Planner
  def plan(objective, context, opts) do
    with :ok <- validate_options(opts),
         {:ok, params} <- planning_params(objective, context, opts),
         {:ok, result} <-
           Jido.Exec.run(
             Jido.AI.Actions.LLM.GenerateObject,
             params,
             execution_context(context.request_id, context.run_id),
             execution_options(opts)
           ),
         {:ok, object} <- fetch_object(result) do
      {:ok, object}
    end
  end

  @impl Ouroboros.Control.Evaluator
  def evaluate(context, opts) do
    with :ok <- validate_options(opts),
         {:ok, params} <- evaluation_params(context, opts),
         {:ok, result} <-
           Jido.Exec.run(
             Jido.AI.Actions.LLM.GenerateObject,
             params,
             execution_context(context.evaluation_id, context.run_id),
             execution_options(opts)
           ),
         {:ok, object} <- fetch_object(result) do
      {:ok, object}
    end
  end

  defp planning_params(objective, context, opts) do
    previous = summarize_previous(context.previous_plan)

    prompt = """
    Objective: #{objective}
    Revision: #{context.revision}
    Stable request id: #{context.request_id}
    Evaluator feedback: #{inspect(context.feedback)}
    Previous plan summary: #{inspect(previous)}

    Return a dependency DAG. Each step id must match
    [A-Za-z0-9][A-Za-z0-9._:-]{0,127}. Dependencies must reference step ids in
    this same response. Every step input must contain a nonblank `objective`
    describing that step's executable work and must contain no other fields.
    Metadata must be empty if present. Do not choose providers, models, worker
    IDs, sandboxes, or coding/runtime options; those are injected by runtime
    policy. Keep the graph acyclic and within
    #{Keyword.get(opts, :max_steps, 12)} steps.
    """

    schema =
      Zoi.object(%{
        steps:
          Zoi.list(
            Zoi.object(%{
              id: Zoi.string(),
              dependencies: Zoi.list(Zoi.string()),
              input:
                Zoi.object(%{objective: Zoi.string() |> Zoi.min(1)},
                  unrecognized_keys: :error
                ),
              metadata:
                Zoi.object(%{}, unrecognized_keys: :error)
                |> Zoi.optional()
            }),
            min_length: 1,
            max_length: Keyword.get(opts, :max_steps, 12)
          )
      })

    {:ok,
     request_params(
       opts,
       prompt,
       schema,
       "Create only the requested provider-neutral orchestration DAG. Runtime policy owns all provider and coding options."
     )}
  end

  defp evaluation_params(%{plan: %Plan{} = plan} = context, opts) do
    prompt = """
    Objective: #{context.objective}
    Revision: #{context.revision}
    Stable evaluation id: #{context.evaluation_id}
    Completed plan: #{inspect(summarize_plan(plan), limit: :infinity)}

    Decide accept when the objective is satisfied, revise when another bounded
    plan could address a concrete gap, or fail when continuing should stop.
    Put concise revision/failure guidance in feedback and an acceptance summary
    in result.
    """

    schema =
      Zoi.object(%{
        decision: Zoi.enum(["accept", "revise", "fail"]),
        feedback: Zoi.json() |> Zoi.optional(),
        result: Zoi.json() |> Zoi.optional()
      })

    {:ok,
     request_params(
       opts,
       prompt,
       schema,
       "Evaluate the durable execution evidence. Return exactly one bounded decision."
     )}
  end

  defp request_params(opts, prompt, schema, system_prompt) do
    %{
      model: Keyword.get(opts, :model),
      prompt: prompt,
      object_schema: schema,
      system_prompt: system_prompt,
      max_tokens: Keyword.get(opts, :max_tokens, 2_048),
      temperature: Keyword.get(opts, :temperature, 0.1),
      timeout: Keyword.get(opts, :timeout, 60_000)
    }
  end

  defp execution_options(opts) do
    request_timeout = Keyword.get(opts, :timeout, 60_000)

    [
      timeout: Keyword.get(opts, :execution_timeout, request_timeout + 5_000),
      max_retries: Keyword.get(opts, :max_retries, 0),
      backoff: Keyword.get(opts, :backoff, 250)
    ]
  end

  @doc false
  @spec execution_context(String.t(), String.t()) :: %{
          request_id: String.t(),
          run_id: String.t()
        }
  def execution_context(request_id, run_id)
      when is_binary(request_id) and is_binary(run_id) do
    %{request_id: request_id, run_id: run_id}
  end

  defp fetch_object(%{object: object}) when is_map(object), do: {:ok, object}
  defp fetch_object(%{"object" => object}) when is_map(object), do: {:ok, object}
  defp fetch_object(_other), do: {:error, :missing_structured_object}

  defp summarize_previous(nil), do: nil
  defp summarize_previous(%Plan{} = plan), do: summarize_plan(plan)

  defp summarize_plan(%Plan{} = plan) do
    %{
      id: plan.id,
      status: plan.status,
      steps:
        Enum.map(plan.step_order, fn id ->
          step = Map.fetch!(plan.steps, id)

          %{
            id: step.id,
            dependencies: step.dependencies,
            input: step.input,
            metadata: step.metadata,
            state: step.state,
            result: step.result,
            error: step.error
          }
        end)
    }
  end

  defp validate_options(opts) do
    accepted = [
      :model,
      :timeout,
      :execution_timeout,
      :max_tokens,
      :temperature,
      :max_steps,
      :max_retries,
      :backoff
    ]

    cond do
      not is_list(opts) or not Keyword.keyword?(opts) ->
        {:error, :invalid_options}

      unknown = Enum.find(Keyword.keys(opts), &(&1 not in accepted)) ->
        {:error, {:unknown_option, unknown}}

      is_nil(Keyword.get(opts, :model)) ->
        {:error, :model_required}

      not positive_integer?(Keyword.get(opts, :timeout, 60_000)) ->
        {:error, :invalid_timeout}

      not positive_integer?(Keyword.get(opts, :execution_timeout, 65_000)) ->
        {:error, :invalid_execution_timeout}

      not positive_integer?(Keyword.get(opts, :max_steps, 12)) ->
        {:error, :invalid_max_steps}

      not non_negative_integer?(Keyword.get(opts, :max_retries, 0)) ->
        {:error, :invalid_max_retries}

      not non_negative_integer?(Keyword.get(opts, :backoff, 250)) ->
        {:error, :invalid_backoff}

      true ->
        :ok
    end
  end

  defp positive_integer?(value), do: is_integer(value) and value > 0
  defp non_negative_integer?(value), do: is_integer(value) and value >= 0
end
