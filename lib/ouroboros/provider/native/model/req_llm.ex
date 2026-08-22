defmodule Ouroboros.Provider.Native.Model.ReqLLM do
  @moduledoc """
  The production model client: `ReqLLM` behind `Ouroboros.Provider.Native.Model`.

  Translation only. It converts the loop's conversation shape into a
  `ReqLLM.Context`, its tool specs into `ReqLLM.Tool` structs, and the provider's
  `ReqLLM.StreamChunk` stream back into the loop's normalized chunks. No decision about
  a tool, a path, or an approval is made here.

  The tool schemas arrive already in JSON Schema form: `Jido.AI.ToolAdapter.from_action/2`
  converts a `Jido.Action`'s schema, which is the one piece of `jido_ai` this provider
  uses (see `Ouroboros.Provider.Native.Tools`).

  Every model provider `ReqLLM` ships is reachable — `anthropic:…`, `openai:…`,
  `openai_codex:…`, `google:…`, `openrouter:…`, `ollama:…` and the rest. Keys come from
  each provider's own environment variable; this module never reads or forwards one
  itself, so a credential cannot reach an event payload through here.
  """

  @behaviour Ouroboros.Provider.Native.Model

  @impl true
  def stream(request, opts) do
    with {:ok, tools} <- build_tools(request.tools),
         {:ok, context} <- build_context(request) do
      generation_opts =
        opts
        |> Keyword.merge(tools: tools)
        |> put_unless_nil(:reasoning_effort, request[:reasoning_effort])
        |> put_unless_nil(:max_tokens, request[:max_tokens])

      case ReqLLM.stream_text(request.model, context, generation_opts) do
        {:ok, response} -> {:ok, normalize(response)}
        {:error, reason} -> {:error, reason}
      end
    end
  rescue
    error -> {:error, {:model_client_error, Exception.message(error)}}
  end

  @impl true
  def available? do
    Code.ensure_loaded?(ReqLLM) and function_exported?(ReqLLM, :stream_text, 3)
  end

  @impl true
  def credential_report do
    if Code.ensure_loaded?(ReqLLM.Providers) do
      ReqLLM.Providers.list()
      |> Enum.map(fn provider ->
        env = ReqLLM.Keys.env_var_name(provider)
        %{provider: provider, env: env, present: present?(env)}
      end)
      |> Enum.sort_by(& &1.provider)
    else
      []
    end
  rescue
    _error -> []
  end

  # A key is "present" when the variable holds something. Its value never leaves here.
  defp present?(env) when is_binary(env) do
    case System.get_env(env) do
      value when is_binary(value) -> String.trim(value) != ""
      _unset -> false
    end
  end

  defp present?(_env), do: false

  defp build_tools([]), do: {:ok, []}

  defp build_tools(specs) do
    tools =
      Enum.map(specs, fn spec ->
        ReqLLM.Tool.new!(
          name: spec.name,
          description: spec.description,
          parameter_schema: spec.parameters,
          # The loop dispatches every tool itself; this callback exists because
          # `ReqLLM.Tool` requires one and is never reached.
          callback: {__MODULE__, :unused_callback}
        )
      end)

    {:ok, tools}
  rescue
    error -> {:error, {:invalid_tool_schema, Exception.message(error)}}
  end

  @doc false
  @spec unused_callback(map()) :: {:error, :tools_execute_in_the_native_loop}
  def unused_callback(_args), do: {:error, :tools_execute_in_the_native_loop}

  defp build_context(request) do
    messages =
      request.messages
      |> Enum.flat_map(&to_messages/1)

    messages =
      case request[:system] do
        system when is_binary(system) and system != "" ->
          [ReqLLM.Context.system(system) | messages]

        _absent ->
          messages
      end

    {:ok, ReqLLM.Context.new(messages)}
  rescue
    error -> {:error, {:invalid_context, Exception.message(error)}}
  end

  defp to_messages(%{role: :user, content: content}), do: [ReqLLM.Context.user(content)]
  defp to_messages(%{role: :system, content: content}), do: [ReqLLM.Context.system(content)]

  defp to_messages(%{role: :assistant} = message) do
    text = message[:content] || ""
    calls = message[:tool_calls] || []

    cond do
      calls != [] ->
        tool_calls = Enum.map(calls, fn call -> {call.name, call.input, [id: call.id]} end)
        [ReqLLM.Context.assistant(text, tool_calls: tool_calls)]

      text != "" ->
        [ReqLLM.Context.assistant(text)]

      true ->
        []
    end
  end

  defp to_messages(%{role: :tool} = message) do
    [
      ReqLLM.Context.tool_result_message(
        message.name,
        message.tool_call_id,
        message.content,
        %{is_error: message[:is_error] == true}
      )
    ]
  end

  defp to_messages(_other), do: []

  # `ReqLLM` streams argument fragments for tool calls on some providers and complete
  # calls on others. Only complete calls (`name` present, arguments a map) become
  # `{:tool_call, …}`; a fragment without a name is dropped rather than guessed at.
  defp normalize(%ReqLLM.StreamResponse{stream: stream}) do
    Stream.flat_map(stream, &chunk/1)
  end

  defp normalize(stream), do: Stream.flat_map(stream, &chunk/1)

  defp chunk(%ReqLLM.StreamChunk{type: :content, text: text}) when is_binary(text) and text != "",
    do: [{:text, text}]

  defp chunk(%ReqLLM.StreamChunk{type: :thinking, text: text})
       when is_binary(text) and text != "",
       do: [{:thinking, text}]

  defp chunk(%ReqLLM.StreamChunk{type: :tool_call, name: name, arguments: args, metadata: meta})
       when is_binary(name) and name != "" do
    [
      {:tool_call,
       %{
         id: call_id(meta),
         name: name,
         input: stringify(args || %{})
       }}
    ]
  end

  defp chunk(%ReqLLM.StreamChunk{type: :meta, metadata: metadata}) when is_map(metadata) do
    usage =
      case Map.get(metadata, :usage) || Map.get(metadata, "usage") do
        usage when is_map(usage) -> [{:usage, usage}]
        _absent -> []
      end

    finish =
      case Map.get(metadata, :finish_reason) || Map.get(metadata, "finish_reason") do
        nil -> []
        reason -> [{:finish, finish_reason(reason)}]
      end

    usage ++ finish
  end

  defp chunk(_other), do: []

  defp call_id(meta) when is_map(meta) do
    case Map.get(meta, :id) || Map.get(meta, "id") do
      id when is_binary(id) and id != "" -> id
      _absent -> "call_" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)
    end
  end

  defp call_id(_meta),
    do: "call_" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

  defp finish_reason(reason) when is_atom(reason), do: reason

  defp finish_reason(reason) when is_binary(reason) do
    case reason do
      "tool_calls" -> :tool_calls
      "tool_use" -> :tool_calls
      "stop" -> :stop
      "end_turn" -> :stop
      "length" -> :length
      "max_tokens" -> :length
      other -> String.to_atom(sanitize(other))
    end
  end

  defp finish_reason(_reason), do: :stop

  # A provider is free to invent a finish reason; a raw one must not become an atom
  # with arbitrary bytes in it.
  defp sanitize(value) do
    value
    |> String.replace(~r/[^a-zA-Z0-9_]/, "_")
    |> String.slice(0, 40)
  end

  defp stringify(map) when is_map(map) do
    Map.new(map, fn {key, value} -> {to_string(key), value} end)
  end

  defp stringify(other), do: other

  defp put_unless_nil(opts, _key, nil), do: opts
  defp put_unless_nil(opts, key, value), do: Keyword.put(opts, key, value)
end
