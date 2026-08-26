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
  alias Ouroboros.Provider.Native.Model.{Admission, ToolSchema}
  alias ReqLLM.Provider.ChunkAccumulator

  @generation_defaults [
    receive_timeout: 120_000,
    stream_idle_timeout: 180_000,
    total_timeout: 300_000,
    max_retries: 0
  ]
  @generation_option_keys [
    :auth_file,
    :oauth_file,
    :base_url,
    :pool_timeout,
    :receive_timeout,
    :req_http_options,
    :stream_idle_timeout,
    :total_timeout,
    :max_retries,
    :provider_options
  ]
  @codex_option_keys [
    :codex_originator,
    :openai_parallel_tool_calls,
    :openai_stream_transport,
    :service_tier,
    :verbosity
  ]
  @provider_metadata_keys [:request_id, :response_id, :service_tier]

  @impl true
  def stream(request, opts) do
    with {:ok, configured} <- configured_options(),
         {:ok, tools} <- build_tools(request.tools, request.model),
         {:ok, context} <- build_context(request) do
      generation_opts =
        configured
        |> Keyword.merge(opts)
        |> Keyword.merge(tools: tools)
        |> put_unless_nil(:reasoning_effort, request[:reasoning_effort])
        |> put_unless_nil(:max_tokens, request[:max_tokens])
        |> put_transport_options(request)

      Admission.with_stream(fn ->
        case ReqLLM.stream_text(request.model, context, generation_opts) do
          {:ok, response} -> {:ok, normalize(response, request.tools)}
          {:error, reason} -> {:error, reason}
        end
      end)
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
      rows =
        ReqLLM.Providers.list()
        |> Enum.map(fn provider ->
          env = ReqLLM.Keys.env_var_name(provider)
          %{provider: provider, env: env, present: present?(env)}
        end)

      oauth = %{
        provider: :openai_codex,
        env: "OUROBOROS_OAUTH_FILE",
        present: Ouroboros.Provider.OpenAIAuth.credential_present?()
      }

      Enum.sort_by([oauth | rows], &{&1.provider, &1.env})
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

  defp build_tools([], _model_spec), do: {:ok, []}

  defp build_tools(specs, model_spec) do
    {:ok, ToolSchema.prepare(specs, model_spec)}
  rescue
    error -> {:error, {:invalid_tool_schema, Exception.message(error)}}
  end

  @doc false
  @spec unused_callback(map()) :: {:error, :tools_execute_in_the_native_loop}
  def unused_callback(_args), do: {:error, :tools_execute_in_the_native_loop}

  defp build_context(request) do
    vision? = vision?(request.model)

    messages =
      request.messages
      |> Enum.flat_map(&to_messages(&1, vision?))

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

  defp to_messages(%{role: :user, content: content}, _vision?) when is_binary(content),
    do: [ReqLLM.Context.user(content)]

  defp to_messages(%{role: :user, content: content}, _vision?) when is_list(content),
    do: [ReqLLM.Context.user(Enum.map(content, &content_part/1))]

  defp to_messages(%{role: :system, content: content}, _vision?),
    do: [ReqLLM.Context.system(content)]

  defp to_messages(%{role: :assistant} = message, _vision?) do
    text = message[:content] || ""
    calls = message[:tool_calls] || []
    details = Enum.map(message[:reasoning_details] || [], &reasoning_detail/1)
    metadata = provider_metadata(message[:provider_metadata] || %{})

    if text != "" or calls != [] or details != [] do
      tool_calls = Enum.map(calls, fn call -> {call.name, call.input, [id: call.id]} end)

      assistant =
        ReqLLM.Context.assistant(text,
          tool_calls: tool_calls,
          metadata: metadata
        )

      [%{assistant | reasoning_details: empty_to_nil(details)}]
    else
      []
    end
  end

  # §8.2. A tool result whose content is a list of parts (`desktop_state` with a screenshot)
  # is mapped through the same content-part vocabulary as a user attachment, but with two
  # differences: a non-vision model has its image parts dropped (the operator still has the
  # event and the staged file — the model just gets the tree, and the turn does not fail),
  # and a staged image that has gone missing degrades to a text marker rather than raising
  # (Δ2), because eviction can outrun compaction and a lost screenshot must not kill a turn.
  defp to_messages(%{role: :tool, content: content} = message, vision?) when is_list(content) do
    [
      ReqLLM.Context.tool_result_message(
        message.name,
        message.tool_call_id,
        tool_result_parts(content, vision?),
        %{is_error: message[:is_error] == true}
      )
    ]
  end

  defp to_messages(%{role: :tool} = message, _vision?) do
    [
      ReqLLM.Context.tool_result_message(
        message.name,
        message.tool_call_id,
        message.content,
        %{is_error: message[:is_error] == true}
      )
    ]
  end

  defp to_messages(_other, _vision?), do: []

  defp normalize(%ReqLLM.StreamResponse{stream: stream}, specs) do
    normalize(stream, specs)
  end

  # ReqLLM emits a streamed function call in two pieces: a `:tool_call` header with the
  # name/id, followed by one or more `:meta` chunks containing JSON argument fragments.
  # Dispatching the header immediately turns every such call into `{}` and discards the
  # actual input. Use ReqLLM's own accumulator so every provider's fragment convention is
  # reconstructed consistently, while text/thinking/usage still stream through unchanged.
  defp normalize(stream, specs) do
    Stream.transform(
      stream,
      &ChunkAccumulator.new/0,
      fn raw, acc ->
        output = if raw.type == :tool_call, do: [], else: chunk(raw, specs)
        {output, ChunkAccumulator.push(acc, raw)}
      end,
      fn acc -> {finalized_tool_calls(acc, specs), acc} end,
      fn _acc -> :ok end
    )
  end

  defp finalized_tool_calls(acc, specs) do
    acc
    |> ChunkAccumulator.finalize_tool_calls_for_response()
    |> Enum.flat_map(fn
      %{id: id, name: name, arguments: arguments}
      when is_binary(id) and is_binary(name) and name != "" ->
        input =
          arguments
          |> Kernel.||(%{})
          |> stringify()
          |> then(&ToolSchema.restore_input(specs, name, &1))

        [{:tool_call, %{id: id, name: name, input: input}}]

      _invalid ->
        []
    end)
  end

  defp chunk(%ReqLLM.StreamChunk{type: :content, text: text}, _specs)
       when is_binary(text) and text != "",
       do: [{:text, text}]

  defp chunk(%ReqLLM.StreamChunk{type: :thinking, text: text}, _specs)
       when is_binary(text) and text != "",
       do: [{:thinking, text}]

  defp chunk(%ReqLLM.StreamChunk{type: :meta, metadata: metadata}, _specs)
       when is_map(metadata) do
    usage =
      case value(metadata, :usage) do
        usage when is_map(usage) -> [{:usage, usage}]
        _absent -> []
      end

    reasoning =
      case value(metadata, :reasoning_details) do
        details when is_list(details) and details != [] ->
          [{:reasoning_details, Enum.map(details, &encode_reasoning_detail/1)}]

        _absent ->
          []
      end

    provider =
      metadata
      |> provider_metadata()
      |> case do
        empty when empty == %{} -> []
        selected -> [{:provider_metadata, selected}]
      end

    finish =
      case value(metadata, :finish_reason) do
        nil -> []
        reason -> [{:finish, normalize_finish_reason(reason)}]
      end

    usage ++ reasoning ++ provider ++ finish
  end

  defp chunk(_other, _specs), do: []

  @doc false
  @spec normalize_finish_reason(term()) ::
          :stop
          | :tool_calls
          | :length
          | :content_filter
          | :error
          | :cancelled
          | :incomplete
          | :unknown
  def normalize_finish_reason(reason) when is_atom(reason),
    do: reason |> Atom.to_string() |> normalize_finish_reason()

  def normalize_finish_reason(reason) when is_binary(reason) do
    case reason do
      "tool_calls" -> :tool_calls
      "tool_use" -> :tool_calls
      "stop" -> :stop
      "completed" -> :stop
      "end_turn" -> :stop
      "length" -> :length
      "max_tokens" -> :length
      "max_output_tokens" -> :length
      "content_filter" -> :content_filter
      "error" -> :error
      "cancelled" -> :cancelled
      "incomplete" -> :incomplete
      "unknown" -> :unknown
      _provider_extension -> :unknown
    end
  end

  def normalize_finish_reason(_reason), do: :unknown

  defp stringify(map) when is_map(map) do
    Map.new(map, fn {key, value} -> {to_string(key), value} end)
  end

  defp stringify(other), do: other

  defp configured_options do
    configured = Application.get_env(:ouroboros, :native_model_options, [])

    with {:ok, options} <- keyword_options(configured),
         :ok <- validate_option_keys(options, @generation_option_keys),
         {:ok, provider_options} <-
           keyword_options(Keyword.get(options, :provider_options, [])),
         :ok <- validate_option_keys(provider_options, @codex_option_keys) do
      {:ok,
       @generation_defaults
       |> Keyword.merge(options)
       |> Keyword.put(:provider_options, provider_options)}
    end
  end

  defp keyword_options(options) when is_list(options) do
    if Keyword.keyword?(options),
      do: {:ok, options},
      else: {:error, {:invalid_native_model_options, :not_keyword}}
  end

  defp keyword_options(options) when is_map(options), do: {:ok, Map.to_list(options)}
  defp keyword_options(_options), do: {:error, {:invalid_native_model_options, :not_keyword}}

  defp validate_option_keys(options, allowed) do
    case Enum.find(Keyword.keys(options), &(&1 not in allowed)) do
      nil -> :ok
      key -> {:error, {:invalid_native_model_option, key}}
    end
  end

  defp put_transport_options(options, %{model: "openai_codex:" <> _} = request) do
    provider_options =
      options
      |> Keyword.get(:provider_options, [])
      |> Keyword.put_new(:openai_stream_transport, :sse)
      |> Keyword.put_new(:codex_originator, "ouroboros")
      |> Keyword.put(:session_id, request.provider_session_id)

    options
    |> Keyword.put_new(:oauth_file, Ouroboros.Provider.OpenAIAuth.credential_path())
    |> Keyword.put(:provider_options, provider_options)
  end

  defp put_transport_options(options, _request), do: Keyword.delete(options, :provider_options)

  defp reasoning_detail(%ReqLLM.Message.ReasoningDetails{} = detail), do: detail

  defp reasoning_detail(detail) when is_map(detail) do
    %ReqLLM.Message.ReasoningDetails{
      text: value(detail, :text),
      signature: value(detail, :signature),
      encrypted?: value(detail, :encrypted?) == true,
      provider: provider_atom(value(detail, :provider)),
      format: value(detail, :format),
      index: integer(value(detail, :index)),
      provider_data: map(value(detail, :provider_data))
    }
  end

  defp reasoning_detail(_detail), do: %ReqLLM.Message.ReasoningDetails{}

  defp encode_reasoning_detail(%ReqLLM.Message.ReasoningDetails{} = detail) do
    %{
      text: detail.text,
      signature: detail.signature,
      encrypted?: detail.encrypted?,
      provider: detail.provider,
      format: detail.format,
      index: detail.index,
      provider_data: detail.provider_data
    }
  end

  defp encode_reasoning_detail(detail) when is_map(detail) do
    detail
    |> reasoning_detail()
    |> encode_reasoning_detail()
  end

  defp encode_reasoning_detail(_detail), do: %{}

  defp provider_metadata(metadata) when is_map(metadata) do
    Enum.reduce(@provider_metadata_keys, %{}, fn key, selected ->
      case value(metadata, key) do
        value when is_binary(value) or is_number(value) or is_boolean(value) ->
          Map.put(selected, key, value)

        _absent ->
          selected
      end
    end)
  end

  defp provider_metadata(_metadata), do: %{}

  defp provider_atom(provider) when is_atom(provider), do: provider

  defp provider_atom(provider) when is_binary(provider) do
    Enum.find(ReqLLM.Providers.list(), &(Atom.to_string(&1) == provider))
  rescue
    _error -> nil
  end

  defp provider_atom(_provider), do: nil

  defp value(map, key) when is_map(map),
    do: Map.get(map, key, Map.get(map, Atom.to_string(key)))

  @doc """
  Whether `model_spec` accepts image input, best-effort from `llm_db`.

  Returns `false` only when `llm_db` positively lists a model's input modalities without
  `:image`; unknown models and an absent `llm_db` default to `true`. That default keeps the
  common case — the multimodal models a native session runs — working, and the loop only
  ever *omits* an image on a `false`, so a wrong guess degrades a turn rather than failing
  it. This is a hint on the spec, not a claim the model can see.
  """
  @spec vision?(String.t() | nil) :: boolean()
  def vision?(model_spec) when is_binary(model_spec) and model_spec != "" do
    with true <- Code.ensure_loaded?(LLMDB),
         {:ok, model} <- LLMDB.model(model_spec),
         modalities when is_map(modalities) <- Map.get(model, :modalities),
         input when is_list(input) <- Map.get(modalities, :input) do
      :image in input
    else
      _unknown -> true
    end
  rescue
    _error -> true
  catch
    :exit, _reason -> true
  end

  def vision?(_model_spec), do: true

  # Encodes a tool result's list content (§8.2) into `ReqLLM` content parts. Public with
  # `@doc false` — the loop's tool-result seam, exposed for the test that asserts a
  # non-vision model drops image parts and a vision model keeps them.
  @doc false
  @spec tool_result_parts([map()], boolean()) :: [ReqLLM.Message.ContentPart.t()]
  def tool_result_parts(content, vision?) when is_list(content),
    do: Enum.flat_map(content, &tool_content_part(&1, vision?))

  # A tool-result content part (§8.2). Text passes through; an image is included only for a
  # vision model, and a missing or changed staged file degrades to a marker rather than
  # raising — the honesty seam that lets `Ouroboros.Provider.Native.Desktop` evict simply.
  defp tool_content_part(part, vision?) when is_map(part) do
    case value(part, :type) do
      type when type in [:text, "text"] ->
        [ReqLLM.Message.ContentPart.text(value(part, :text) || "")]

      type when type in [:image, "image"] ->
        if vision?, do: tool_image_part(part), else: []

      _other ->
        []
    end
  end

  defp tool_content_part(_part, _vision?), do: []

  defp tool_image_part(part) do
    path = value(part, :path)
    expected = value(part, :sha256)
    media_type = value(part, :media_type) || "application/octet-stream"

    with true <- is_binary(path),
         {:ok, bytes} <- File.read(path),
         true <- digest(bytes) == expected do
      [ReqLLM.Message.ContentPart.image(bytes, media_type)]
    else
      _missing_or_changed ->
        [
          ReqLLM.Message.ContentPart.text(
            "[screenshot #{sha_hint(expected)} is no longer available — call desktop_state again]"
          )
        ]
    end
  end

  defp sha_hint(sha) when is_binary(sha), do: String.slice(sha, 0, 12)
  defp sha_hint(_sha), do: "(unknown)"

  defp content_part(part) when is_map(part) do
    case value(part, :type) do
      type when type in [:text, "text"] ->
        ReqLLM.Message.ContentPart.text(value(part, :text) || "")

      type when type in [:image, "image"] ->
        path = value(part, :path)
        expected = value(part, :sha256)
        media_type = value(part, :media_type) || "application/octet-stream"

        with true <- is_binary(path),
             {:ok, bytes} <- File.read(path),
             true <- digest(bytes) == expected do
          ReqLLM.Message.ContentPart.image(bytes, media_type)
        else
          _invalid -> raise ArgumentError, "staged image attachment is unavailable or changed"
        end

      other ->
        raise ArgumentError, "unsupported native content part: #{inspect(other)}"
    end
  end

  defp content_part(_part), do: raise(ArgumentError, "invalid native content part")

  defp digest(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)

  defp empty_to_nil([]), do: nil
  defp empty_to_nil(value), do: value
  defp integer(value) when is_integer(value), do: value
  defp integer(_value), do: 0
  defp map(value) when is_map(value), do: value
  defp map(_value), do: %{}

  defp put_unless_nil(opts, _key, nil), do: opts
  defp put_unless_nil(opts, key, value), do: Keyword.put(opts, key, value)
end
