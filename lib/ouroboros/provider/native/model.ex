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
          %{role: :system, content: String.t()}
          | %{role: :user, content: String.t() | [map()]}
          | %{
              required(:role) => :assistant,
              required(:content) => String.t() | nil,
              required(:tool_calls) => [tool_call()],
              optional(:reasoning_details) => [map()],
              optional(:provider_metadata) => map()
            }
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
          | {:reasoning_details, [map()]}
          | {:provider_metadata, map()}
          | {:usage, map()}
          | {:finish, atom()}

  @type request :: %{
          model: String.t(),
          system: String.t() | nil,
          messages: [message()],
          tools: [tool_spec()],
          provider_session_id: String.t(),
          turn_id: String.t(),
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

  @doc """
  The wire request this module would send, as plain data, for provenance only.

  R1. The turn journal and the `:inference` ledger entry both digest what the model was
  actually asked, and `state.messages` is not that: a module's own projection is lossy on
  purpose (a tool result carrying an evicted screenshot degrades to a marker; an assistant
  message with no content and no calls is dropped), so a digest over the loop's list would
  claim two different requests were the same one. This returns the projection instead —
  never a credential, never a raw image, and never anything the caller is expected to
  render. `Ouroboros.Provider.Native.Model.project/2` supplies a structural fallback for a
  module that does not implement it, so a test double stays a test double.
  """
  @callback project(request()) :: {:ok, term()} | {:error, term()}

  @doc "Whether this node can resolve a model at all. Reported by `status/1`."
  @callback available?() :: boolean()

  @doc "One row per known model provider: its env var name and whether it is set."
  @callback credential_report() :: [%{provider: atom(), env: String.t(), present: boolean()}]

  @optional_callbacks available?: 0, credential_report: 0, project: 1

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

  @doc """
  The projection a digest is taken over, from the module that would send the request.

  A module that declares no `project/1` gets the structural fallback below: the request's
  own fields, which already carry the two things a digest over `state.messages` would
  miss — the iteration-mutated system suffix and the final round's empty tool list. It is
  weaker than a real projection (it cannot see what the module would drop on the way to
  the wire) and it is stated as such rather than presented as the same thing. A module
  that raises while projecting yields a named marker, because provenance failing must not
  fail the turn the provenance is about.
  """
  @spec project(module(), request()) :: term()
  def project(module, request) do
    if function_exported?(module, :project, 1) do
      case module.project(request) do
        {:ok, projection} -> projection
        {:error, reason} -> %{"unprojectable" => inspect(reason, limit: 6)}
      end
    else
      fallback_projection(module, request)
    end
  rescue
    error -> %{"unprojectable" => Exception.message(error)}
  end

  defp fallback_projection(module, request) do
    %{
      "projection" => "structural",
      "module" => inspect(module),
      "model" => request[:model],
      "system" => request[:system],
      "messages" => request[:messages] || [],
      "tools" =>
        Enum.map(request[:tools] || [], &Map.take(&1, [:name, :description, :parameters])),
      "reasoning_effort" => request[:reasoning_effort],
      "max_tokens" => request[:max_tokens]
    }
  end

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

  @doc "Whether the configured model's own provider has usable credentials."
  @spec credential_ready?(String.t() | nil) :: boolean()
  def credential_ready?(model \\ configured_model())

  def credential_ready?(model) when is_binary(model) do
    case String.split(model, ":", parts: 2) do
      ["ollama", _id] ->
        true

      [provider, _id] ->
        case existing_provider(provider) do
          nil -> false
          provider -> Enum.any?(credential_report(), &(&1.provider == provider and &1.present))
        end

      _invalid ->
        false
    end
  end

  def credential_ready?(_model), do: false

  defp existing_provider(provider) when is_binary(provider) do
    String.to_existing_atom(provider)
  rescue
    ArgumentError -> nil
  end

  defp existing_provider(_provider), do: nil

  defp configured_default, do: Application.get_env(:ouroboros, :native_model)
end
