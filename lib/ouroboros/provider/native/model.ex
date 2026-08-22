defmodule Ouroboros.Provider.Native.Model do
  @moduledoc """
  The one seam between the loop and a language model.

  A behaviour with a single call, plus a normalized chunk vocabulary the loop
  understands. Two reasons it exists rather than the loop calling `ReqLLM` directly:

    * **Tests cost nothing.** A scripted module implementing this behaviour replays a
      turn with tool calls, usage, and a finish reason without a network call or a key.
      Every loop test in `test/provider/native/` runs against one.
    * **The loop stays provider-neutral.** `ReqLLM` ships thirty-odd providers whose
      stream chunk shapes differ; normalizing once here means the loop never learns
      which one is answering.

  The default implementation is `Ouroboros.Provider.Native.Model.ReqLLM`. It can be
  replaced for a node with `config :ouroboros, :native_model_module` — node
  configuration, deliberately, and not a session option: a request that could name the
  module this runtime calls would be a way to run arbitrary code by opening a session.
  """

  @typedoc "A message in the loop's own conversation shape. String-keyed on the wire."
  @type message ::
          %{role: :system | :user, content: String.t()}
          | %{role: :assistant, content: String.t() | nil, tool_calls: [tool_call()]}
          | %{
              role: :tool,
              tool_call_id: String.t(),
              name: String.t(),
              content: String.t(),
              is_error: boolean()
            }

  @type tool_call :: %{id: String.t(), name: String.t(), input: map()}

  @typedoc "A tool as the model sees it: name, description, JSON Schema."
  @type tool_spec :: %{name: String.t(), description: String.t(), parameters: map()}

  @typedoc """
  One normalized chunk. `:usage` carries token counts only; cost is computed by
  `Ouroboros.Provider.Native.Cost` from `llm_db` pricing, never by a provider.
  """
  @type chunk ::
          {:text, String.t()}
          | {:thinking, String.t()}
          | {:tool_call, tool_call()}
          | {:usage, map()}
          | {:finish, atom()}

  @type request :: %{
          model: String.t(),
          system: String.t() | nil,
          messages: [message()],
          tools: [tool_spec()],
          reasoning_effort: :low | :medium | :high | nil,
          max_tokens: pos_integer() | nil
        }

  @doc """
  Streams one model response.

  Returns a lazy enumerable of `t:chunk/0`. Errors raised while the stream is consumed
  are caught by the loop and become a `turn_failed`; returning `{:error, reason}` here
  is for failures known before the first byte (an unresolvable model, a missing key).
  """
  @callback stream(request(), keyword()) :: {:ok, Enumerable.t()} | {:error, term()}

  @doc "Whether this node can resolve a model at all. Reported by `status/1`."
  @callback available?() :: boolean()

  @doc "One row per known model provider: its env var name and whether it is set."
  @callback credential_report() :: [%{provider: atom(), env: String.t(), present: boolean()}]

  @optional_callbacks available?: 0, credential_report: 0

  @default_module Ouroboros.Provider.Native.Model.ReqLLM
  @model_env "OUROBOROS_NATIVE_MODEL"

  @doc "The environment variable naming the model a native session uses by default."
  @spec model_env() :: String.t()
  def model_env, do: @model_env

  @doc "The model module this node uses."
  @spec module() :: module()
  def module, do: Application.get_env(:ouroboros, :native_model_module, @default_module)

  @doc "Streams one model response through the configured module."
  @spec stream(module(), request(), keyword()) :: {:ok, Enumerable.t()} | {:error, term()}
  def stream(module, request, opts \\ []), do: module.stream(request, opts)

  @doc "The model spec a session uses when the caller named none."
  @spec configured_model() :: String.t() | nil
  def configured_model do
    case System.get_env(@model_env) do
      value when is_binary(value) ->
        case String.trim(value) do
          "" -> configured_default()
          model -> model
        end

      _unset ->
        configured_default()
    end
  end

  @doc "Whether the default model module can resolve models on this node."
  @spec available?() :: boolean()
  def available? do
    module = module()
    if function_exported?(module, :available?, 0), do: module.available?(), else: true
  end

  @doc "Credential presence per model provider. Names and booleans only, never values."
  @spec credential_report() :: [%{provider: atom(), env: String.t(), present: boolean()}]
  def credential_report do
    module = module()

    if function_exported?(module, :credential_report, 0),
      do: module.credential_report(),
      else: []
  end

  defp configured_default, do: Application.get_env(:ouroboros, :native_model)
end
