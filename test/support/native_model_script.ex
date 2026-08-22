defmodule Ouroboros.Test.NativeModelScript do
  @moduledoc """
  A deterministic model for the native provider's tests. No network, no key, no spend.

  Neither `req_llm` nor `jido_ai` ships a stub provider a test can register — their own
  fixtures (`ReqLLM.Step.Fixture`, `ReqLLM.Streaming.Fixtures`) replay recorded HTTP for
  their own suite and need a real request to record first. So the stand-in goes at the
  native loop's own seam: `Ouroboros.Provider.Native.Model` is one callback, and this
  implements it from a script the test writes.

  A script is a list of responses; each response is a list of normalized chunks, and the
  Nth model call of a turn consumes the Nth response:

      script = [
        [{:text, "looking"}, {:tool_call, %{id: "c1", name: "read", input: %{"path" => "a.ex"}}}],
        [{:text, "done"}, {:usage, %{input_tokens: 10, output_tokens: 4}}, {:finish, :stop}]
      ]

  `start/1` returns the model spec that routes to that script. The script lives in an
  agent whose pid is encoded in the spec itself, so there is no global registry, nothing
  to clean up, and tests may run concurrently.

  Every request the loop made is recorded, which is how the steer and system-prompt
  assertions read what the model was actually shown.
  """

  @behaviour Ouroboros.Provider.Native.Model

  @doc "Starts a scripted model and returns `{model_spec, agent}`."
  @spec start([[tuple()]]) :: {String.t(), pid()}
  def start(script) do
    {:ok, agent} = Agent.start_link(fn -> %{script: script, requests: []} end)
    {model_spec(agent), agent}
  end

  @doc "The model spec that routes a session to one script agent."
  @spec model_spec(pid()) :: String.t()
  def model_spec(agent), do: "scripted:" <> (agent |> :erlang.pid_to_list() |> List.to_string())

  @doc "Every request the loop sent, oldest first."
  @spec requests(pid()) :: [map()]
  def requests(agent), do: Agent.get(agent, &Enum.reverse(&1.requests))

  @doc "How many model calls the loop made."
  @spec call_count(pid()) :: non_neg_integer()
  def call_count(agent), do: Agent.get(agent, &length(&1.requests))

  @impl true
  def stream(request, _opts) do
    agent = agent(request.model)

    chunks =
      Agent.get_and_update(agent, fn state ->
        {chunks, rest} =
          case state.script do
            [] -> {[{:text, "(script exhausted)"}, {:finish, :stop}], []}
            [head | tail] -> {head, tail}
          end

        {chunks, %{state | script: rest, requests: [request | state.requests]}}
      end)

    {:ok, chunks}
  end

  @impl true
  def available?, do: true

  @impl true
  def credential_report,
    do: [%{provider: :scripted, env: "OUROBOROS_TEST_SCRIPTED_KEY", present: false}]

  defp agent("scripted:" <> encoded), do: encoded |> String.to_charlist() |> :erlang.list_to_pid()
  defp agent(other), do: raise(ArgumentError, "not a scripted model spec: #{inspect(other)}")
end
