defmodule Ouroboros.Provider.Native.Model.ReqLLM do
  @moduledoc """
  The production model client: `ReqLLM` behind `Ouroboros.Provider.Native.Model`.

  Translation only. It converts the loop's conversation shape into a
  `ReqLLM.Context`, its tool specs into `ReqLLM.Tool` structs, and the provider's
  `ReqLLM.StreamChunk` stream back into the loop's normalized chunks. No decision about
  a tool, a path, or an approval is made here.

  The tool schemas arrive already in JSON Schema form: the owned
  `Ouroboros.Provider.Native.Tools.Schema` converter uses `Ouroboros.Action.Schema`, then
  `Ouroboros.Provider.Native.Tools` applies its final model schema overrides.

  Every model provider `ReqLLM` ships is reachable — `anthropic:…`, `openai:…`,
  `openai_codex:…`, `google:…`, `openrouter:…`, `ollama:…` and the rest. Keys normally
  come from each provider's own environment variable. Anthropic additionally has one
  node-owned private file for its key and optional workspace id, read only into the
  transient ReqLLM request options; no credential can reach an event payload through
  here.
  """

  @behaviour Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.{AnthropicKey, GrokSubscription, XAIKey}
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
  # The Anthropic lane's prompt-cache switches. `ReqLLM` writes no `cache_control` unless
  # asked (`ReqLLM.Providers.Anthropic.has_prompt_caching?/1`), so `put_transport_options/2`
  # asks on every Anthropic request; these keys exist so an operator can lengthen the TTL
  # or switch the breakpoints off, never so that caching depends on a node remembering to
  # switch it on.
  @anthropic_option_keys [
    :anthropic_prompt_cache,
    :anthropic_prompt_cache_ttl,
    :anthropic_cache_messages
  ]
  @provider_metadata_keys [:request_id, :response_id, :service_tier]

  @impl true
  def stream(request, opts) do
    {audit, opts} = Keyword.pop(opts, :audit_context)

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
        |> audit_transport(audit)

      Admission.with_stream(fn ->
        # Sign-in may expire or be renewed while this request waits for capacity.
        # Load it only after admission so the outgoing request uses current credentials.
        with {:ok, model, generation_opts} <-
               GrokSubscription.transport(
                 request.model,
                 generation_opts,
                 conversation_id(request)
               ) do
          case ReqLLM.stream_text(model, context, generation_opts) do
            {:ok, response} -> {:ok, normalize(response, request.tools)}
            {:error, reason} -> {:error, reason}
          end
        end
      end)
    end
  rescue
    error in Ouroboros.Audit.Unavailable -> reraise error, __STACKTRACE__
    error -> {:error, {:model_client_error, Exception.message(error)}}
  end

  @doc false
  @impl true
  @spec format_error(term()) :: String.t()
  def format_error(reason) do
    reason
    |> unwrap_error()
    |> error_summary()
  rescue
    _error -> "category=unknown retryable=false diagnostic=model request failed"
  end

  defp unwrap_error(%{errors: [error | _]}), do: unwrap_error(error)

  defp unwrap_error(%ReqLLM.Error.API.Stream{cause: cause}) when not is_nil(cause),
    do: unwrap_error(cause)

  defp unwrap_error(reason), do: reason

  defp error_summary(%ReqLLM.Error.API.Request{} = error) do
    case ReqLLM.Streaming.Failure.classify(error) do
      {:api, status, provider_code, retryable} ->
        fields(
          :api,
          status,
          provider_code,
          retryable,
          api_diagnostic(error, status, provider_code)
        )

      {:transport, transport_reason, retryable} ->
        fields(:transport, nil, nil, retryable, transport_diagnostic(transport_reason))

      :cancelled ->
        fields(:cancelled, nil, nil, false, "model request cancelled")

      :unknown ->
        fields(:unknown, nil, error.provider_code, false, "API request failed")
    end
  end

  defp error_summary({:grok_subscription, reason})
       when reason in [:absent, :invalid, :expired, :unavailable] do
    fields(
      :credentials,
      nil,
      nil,
      false,
      "Grok subscription sign-in #{reason}; run grok login on the Ouroboros computer, then retry"
    )
  end

  defp error_summary(reason) do
    case ReqLLM.Streaming.Failure.classify(reason) do
      {:api, status, provider_code, retryable} ->
        fields(:api, status, provider_code, retryable, "API request failed (#{status})")

      {:transport, transport_reason, retryable} ->
        fields(:transport, nil, nil, retryable, transport_diagnostic(transport_reason))

      :cancelled ->
        fields(:cancelled, nil, nil, false, "model request cancelled")

      :unknown ->
        fields(:unknown, nil, nil, false, "model request failed")
    end
  end

  defp api_diagnostic(%{reason: reason}, status, _code)
       when reason in [:timeout, :closed, :econnrefused],
       do: "API request failed (#{status}): #{reason}"

  defp api_diagnostic(_error, status, code) do
    if policy_code?(code),
      do: "API request failed (#{status}): request rejected by provider policy",
      else: "API request failed (#{status})"
  end

  defp transport_diagnostic(reason)
       when reason in [:timeout, :closed, :econnrefused, :pool_not_available],
       do: "transport failed: #{reason}"

  defp transport_diagnostic(_reason), do: "transport failed"

  defp policy_code?(code) when is_binary(code),
    do:
      code in ~w(content_policy_violation content_filter policy_violation safety_violation request_blocked)

  defp policy_code?(_code), do: false

  defp fields(category, status, provider_code, retryable, diagnostic) do
    [
      "category=#{category}",
      if(is_integer(status), do: "status=#{status}"),
      safe_provider_code(provider_code),
      "retryable=#{retryable}",
      "diagnostic=#{diagnostic}"
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" ")
  end

  defp safe_provider_code(nil), do: nil
  defp safe_provider_code(code) when is_atom(code), do: safe_provider_code(Atom.to_string(code))

  defp safe_provider_code(code) when is_binary(code) do
    # A syntactically tidy string can still be a token or a signed URL fragment.
    # Preserve known operational codes, not arbitrary provider-controlled content.
    if code in ~w(upstream_timeout server_is_overloaded overloaded rate_limit_exceeded
                  insufficient_quota invalid_api_key invalid_request_error model_not_found
                  context_length_exceeded content_policy_violation content_filter
                  policy_violation safety_violation request_blocked) do
      "provider_code=#{code}"
    else
      "provider_code=redacted"
    end
  end

  defp safe_provider_code(_code), do: nil

  defp audit_transport(options, nil) do
    if Ouroboros.Audit.required?(),
      do: raise(Ouroboros.Audit.Unavailable, reason: :missing_model_audit_context)

    options
  end

  defp audit_transport(options, audit) do
    options
    |> Keyword.put(:cache, nil)
    |> Keyword.put(:max_retries, 0)
    |> Keyword.delete(:openai_stream_transport)
    |> Keyword.update(:provider_options, [], fn opts ->
      Keyword.drop(opts, [:openai_stream_transport, :openai_websocket_session])
    end)
    |> Keyword.put(:stream_transport, :http)
    |> Keyword.put(:on_finch_request, fn request ->
      {body, raw_body} =
        case request.body do
          nil ->
            {nil, nil}

          body when is_binary(body) or is_list(body) ->
            bytes = IO.iodata_to_binary(body)

            parsed =
              case JSON.decode(bytes) do
                {:ok, json} -> json
                _ -> %{"content" => bytes, "encoding" => "non_json"}
              end

            {parsed, bytes}

          _ ->
            raise Ouroboros.Audit.Unavailable, reason: :uncapturable_transport_body
        end

      Ouroboros.Provider.Native.Journal.append(audit.journal, "model_transport", %{
        "turn_id" => audit.turn_id,
        "iteration" => audit.iteration,
        "ledger_effect_id" => audit.effect_id,
        "attempt_id" => audit.effect_id <> ":http:1",
        "method" => request.method,
        "endpoint" => %{
          scheme: request.scheme,
          host: request.host,
          port: request.port,
          path: request.path
        },
        "request" => body,
        "request_sha256" =>
          if(raw_body, do: :crypto.hash(:sha256, raw_body) |> Base.encode16(case: :lower)),
        "bytes" => if(raw_body, do: byte_size(raw_body), else: 0),
        "headers" =>
          Enum.filter(request.headers, fn {name, _} ->
            String.downcase(name) in ["content-type", "accept"]
          end),
        "query" => %{"withheld" => "transport_credentials_may_be_present"},
        "capture_boundary" => "finch_request_before_dispatch",
        "max_retries" => 0
      })

      request
    end)
  end

  # R1. The same two builders `stream/2` runs, rendered as plain data for a digest. It is
  # the *projected* request rather than the loop's message list because this translation is
  # lossy on purpose — empty assistant messages and unsupported images are dropped, and
  # missing screenshots become markers. The digest must reflect those projected parts.
  #
  # Nothing here is meant to be read back. Image bytes become a digest of themselves
  # rather than base64, so an attachment changes the request digest without putting a
  # megabyte in a journal record; the tool callback is omitted because it is a function.
  @impl true
  def project(request) do
    with {:ok, tools} <- build_tools(request.tools, request.model),
         {:ok, context} <- build_context(request) do
      {:ok,
       %{
         "model" => to_string(request.model),
         "reasoning_effort" => stringify_option(request[:reasoning_effort]),
         "max_tokens" => request[:max_tokens],
         "messages" => Enum.map(context.messages, &project_message/1),
         "tools" => Enum.map(tools, &project_tool/1)
       }}
    end
  rescue
    error -> {:error, {:unprojectable_request, Exception.message(error)}}
  end

  defp project_message(%ReqLLM.Message{} = message) do
    %{
      "role" => to_string(message.role),
      "name" => message.name,
      "tool_call_id" => message.tool_call_id,
      "tool_calls" => project_any(message.tool_calls),
      "reasoning_details" => project_any(message.reasoning_details),
      "metadata" => project_any(message.metadata),
      "content" => message.content |> List.wrap() |> Enum.map(&project_part/1)
    }
  end

  defp project_message(other), do: project_any(other)

  defp project_part(%ReqLLM.Message.ContentPart{} = part) do
    %{
      "type" => to_string(part.type),
      "text" => part.text,
      "url" => part.url,
      "file_id" => part.file_id,
      "media_type" => part.media_type,
      "filename" => part.filename,
      "metadata" => project_any(part.metadata)
    }
    |> Map.put("data_sha256", data_digest(part.data))
  end

  defp project_part(other), do: project_any(other)

  defp data_digest(data) when is_binary(data),
    do: :sha256 |> :crypto.hash(data) |> Base.encode16(case: :lower)

  defp data_digest(nil), do: nil
  defp data_digest(other), do: project_any(other)

  # `to_json_schema/1` is the shape the provider is actually sent, which is the shape worth
  # digesting; the struct also carries a callback function, and a function has no stable
  # rendering across two builds of the same code.
  defp project_tool(%ReqLLM.Tool{} = tool) do
    ReqLLM.Tool.to_json_schema(tool)
  rescue
    _error -> %{"name" => tool.name, "description" => tool.description}
  end

  defp project_tool(other), do: project_any(other)

  defp stringify_option(value) when is_atom(value) and not is_nil(value),
    do: Atom.to_string(value)

  defp stringify_option(value), do: value

  defp project_any(value), do: Ouroboros.Provider.Native.Journal.jsonable(value)

  @impl true
  def available? do
    Code.ensure_loaded?(ReqLLM) and function_exported?(ReqLLM, :stream_text, 3)
  end

  @impl true
  def credential_report do
    if Code.ensure_loaded?(ReqLLM.Providers) do
      rows =
        ReqLLM.Providers.list()
        # These lanes report their actual managed credential below. In particular,
        # a generic OPENAI_CODEX_API_KEY row can sort before and mask the OAuth row.
        |> Enum.reject(&(&1 in [:openai_codex, :anthropic, :xai]))
        |> Enum.map(fn provider ->
          env = ReqLLM.Keys.env_var_name(provider)
          %{provider: provider, env: env, present: present?(env), source: source(env)}
        end)

      oauth_state = Ouroboros.Provider.OpenAIAuth.credential_status()
      oauth_present? = oauth_state == :present

      oauth = %{
        provider: :openai_codex,
        env: "OUROBOROS_OAUTH_FILE",
        present: oauth_present?,
        credential_state: oauth_state,
        source: if(oauth_present?, do: :stored)
      }

      Enum.sort_by(
        [oauth, GrokSubscription.status(), AnthropicKey.status(), XAIKey.status() | rows],
        &{&1.provider, &1.env}
      )
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

  defp source(env), do: if(present?(env), do: :environment)

  defp build_tools([], _model_spec), do: {:ok, []}

  defp build_tools(specs, model_spec) do
    {:ok, ToolSchema.prepare(specs, GrokSubscription.api_model(model_spec))}
  rescue
    error -> {:error, {:invalid_tool_schema, Exception.message(error)}}
  end

  @doc false
  @spec unused_callback(map()) :: {:error, :tools_execute_in_the_native_loop}
  def unused_callback(_args), do: {:error, :tools_execute_in_the_native_loop}

  defp build_context(request) do
    messages = Enum.flat_map(request.messages, &to_messages(&1, request.model))

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

  defp to_messages(%{role: :user, content: content}, _model) when is_binary(content),
    do: [ReqLLM.Context.user(content)]

  defp to_messages(%{role: :user, content: content}, _model) when is_list(content),
    do: [ReqLLM.Context.user(Enum.map(content, &content_part/1))]

  defp to_messages(%{role: :system, content: content}, _model),
    do: [ReqLLM.Context.system(content)]

  defp to_messages(%{role: :assistant} = message, _model) do
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

  defp to_messages(%{role: :tool} = message, model) do
    # Desktop tools are retired, but their structured results still live in native
    # checkpoints. Project those parts without rewriting the saved conversation.
    content =
      case message.content do
        parts when is_list(parts) ->
          vision? = vision?(model)
          Enum.flat_map(parts, &tool_content_part(&1, vision?))

        text ->
          text
      end

    [
      ReqLLM.Context.tool_result_message(
        message.name,
        message.tool_call_id,
        content,
        %{is_error: message[:is_error] == true}
      )
    ]
  end

  defp to_messages(_other, _model), do: []

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
         :ok <-
           validate_option_keys(provider_options, @codex_option_keys ++ @anthropic_option_keys) do
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

  # OpenAI caches prompts without being asked, keyed on the rendered prefix. What a
  # request can add is the identity that keeps one conversation's entries together, and
  # `session_id` is it: ReqLLM 1.23 sends it as the `session-id` header and as the body's
  # `prompt_cache_key`, which is exactly what the Codex CLI sets from its own session id.
  # Whether the cache then hits is reported as `cached_tokens` on every `usage` event,
  # never assumed.
  defp put_transport_options(options, %{model: "openai_codex:" <> _} = request) do
    provider_options =
      options
      |> Keyword.get(:provider_options, [])
      |> Keyword.drop(@anthropic_option_keys)
      |> Keyword.put_new(:openai_stream_transport, :sse)
      |> Keyword.put_new(:codex_originator, "ouroboros")
      |> Keyword.delete(:session_id)
      |> put_unless_nil(:session_id, conversation_id(request))

    options
    |> Keyword.put_new(:oauth_file, Ouroboros.Provider.OpenAIAuth.credential_path())
    |> Keyword.put(:provider_options, provider_options)
  end

  # The OpenAI API-key lane, same cache identity as the Codex lane. The codex and
  # anthropic keys are kept off it; nothing else in `provider_options` was ever admitted
  # for this lane, so nothing else is carried.
  defp put_transport_options(options, %{model: "openai:" <> _} = request) do
    provider_options = put_prompt_cache_key([], conversation_id(request))

    options
    |> Keyword.delete(:auth_file)
    |> Keyword.delete(:oauth_file)
    |> Keyword.put(:provider_options, provider_options)
  end

  # Ouroboros deliberately exposes no Claude subscription or OAuth lane. ReqLLM supports
  # those modes for other callers, so state the narrower product contract on every
  # Anthropic request instead of relying on the dependency's current default. The
  # environment-first `AnthropicKey` boundary supplies the credential only to this
  # transient request. Identity-linked keys also contribute their workspace header; the
  # auth mode is likewise forced here.
  #
  # Every Anthropic request also asks for the prompt cache. `Ouroboros.Provider.Native.Context`
  # lays the request out so the prefix is stable — system prompt, tools in a fixed order,
  # then the conversation — and that layout earns nothing until a request carries a
  # `cache_control` breakpoint, because the API caches only what it is asked to. ReqLLM
  # places three: on the last tool, on the system block, and on the newest message, so each
  # call reads everything the previous one wrote and pays the write premium only on what
  # this call appended. The default five-minute TTL is the right one for a tool loop whose
  # calls are seconds apart; `anthropic_prompt_cache_ttl: "1h"` in `native_model_options`
  # buys longer idle gaps at twice the write price. Whether it is working is not assumed:
  # the provider's `cache_read_tokens` ride on every `usage` event, and
  # `test/provider/native/direct_sse_test.exs` asserts the breakpoints are on the wire.
  defp put_transport_options(options, %{model: "anthropic:" <> _}) do
    provider_options =
      options
      |> Keyword.get(:provider_options, [])
      |> Keyword.take(@anthropic_option_keys)
      |> Keyword.put_new(:anthropic_prompt_cache, true)
      |> Keyword.put_new(:anthropic_cache_messages, true)
      |> Keyword.put(:auth_mode, :api_key)

    options =
      options
      |> Keyword.delete(:auth_file)
      |> Keyword.delete(:oauth_file)
      |> Keyword.put(:provider_options, provider_options)

    case AnthropicKey.fetch_credentials() do
      {:ok, credentials, _source} ->
        options
        |> Keyword.put(:api_key, credentials.api_key)
        |> put_anthropic_workspace(credentials.workspace_id)

      {:error, _reason} ->
        Keyword.delete(options, :api_key)
    end
  end

  # The xai: prefix always uses API keys. The separate grok: prefix selects subscription
  # credentials and pins its endpoint in GrokSubscription.transport/3, which sets the
  # same conversation header itself. xAI caches prompts on its own and keeps the cache
  # per server; `x-grok-conv-id` is what routes one conversation's requests to the one
  # server that holds its entries.
  defp put_transport_options(options, %{model: "xai:" <> _} = request) do
    options =
      options
      |> Keyword.delete(:auth_file)
      |> Keyword.delete(:oauth_file)
      |> Keyword.delete(:provider_options)
      |> put_request_header("x-grok-conv-id", conversation_id(request))

    case XAIKey.fetch() do
      {:ok, key, _source} -> Keyword.put(options, :api_key, key)
      {:error, _reason} -> Keyword.delete(options, :api_key)
    end
  end

  defp put_transport_options(options, _request), do: Keyword.delete(options, :provider_options)

  # The session id, as the value every lane's cache-identity hint takes: one token of
  # visible ASCII, or nothing at all — a lane sent nothing invents no identity, while a
  # lane sent a `nil` refuses the call. A `provider_session_id` is one of this runtime's
  # own ids (`Ouroboros.Provider.Native.Paths.new_session_id/0`, url-safe base64 under
  # forty bytes) and always passes; the guard is for a request built by hand.
  @doc false
  @spec conversation_id(map()) :: String.t() | nil
  def conversation_id(%{provider_session_id: id}) when is_binary(id) do
    if header_token?(id), do: id
  end

  def conversation_id(_request), do: nil

  # Visible ASCII only, so a value can never carry a line break, a tab, an escape or a
  # space into a header or a JSON string — the same rule `Ouroboros.Provider.GrokSubscription`
  # applies to the header it owns.
  @doc false
  @spec header_token?(term()) :: boolean()
  def header_token?(id) when is_binary(id) and byte_size(id) in 1..256,
    do: Regex.match?(~r/\A[\x21-\x7E]+\z/, id)

  def header_token?(_id), do: false

  defp put_prompt_cache_key(provider_options, nil), do: provider_options

  defp put_prompt_cache_key(provider_options, key),
    do: Keyword.put(provider_options, :prompt_cache_key, key)

  defp put_anthropic_workspace(options, nil), do: options

  defp put_anthropic_workspace(options, workspace_id) when is_binary(workspace_id),
    do: put_request_header(options, "anthropic-workspace-id", workspace_id)

  defp put_request_header(options, _name, nil), do: options

  defp put_request_header(options, name, value) when is_binary(value) do
    http_options = Keyword.get(options, :req_http_options, [])

    headers =
      http_options
      |> request_headers()
      |> Enum.reject(&header_named?(&1, name))
      |> Kernel.++([{name, value}])

    http_options =
      cond do
        is_list(http_options) and Keyword.keyword?(http_options) ->
          Keyword.put(http_options, :headers, headers)

        is_map(http_options) ->
          Map.put(http_options, :headers, headers)

        true ->
          [headers: headers]
      end

    Keyword.put(options, :req_http_options, http_options)
  end

  defp request_headers(http_options) when is_list(http_options) do
    if Keyword.keyword?(http_options) do
      http_options |> Keyword.get(:headers, []) |> normalize_headers()
    else
      []
    end
  end

  defp request_headers(http_options) when is_map(http_options),
    do: http_options |> Map.get(:headers, []) |> normalize_headers()

  defp request_headers(_http_options), do: []

  defp normalize_headers(headers) when is_list(headers), do: headers
  defp normalize_headers(headers) when is_map(headers), do: Map.to_list(headers)
  defp normalize_headers(_headers), do: []

  defp header_named?({header, _value}, name) when is_binary(header),
    do: String.downcase(header) == String.downcase(name)

  defp header_named?(_header, _name), do: false

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

  defp vision?(model) do
    case LLMDB.model(GrokSubscription.api_model(model)) do
      {:ok, %{modalities: %{input: input}}} when is_list(input) -> :image in input
      _unknown -> false
    end
  rescue
    _error -> false
  end

  defp tool_content_part(part, vision?) when is_map(part) do
    case value(part, :type) do
      type when type in [:text, "text"] ->
        [ReqLLM.Message.ContentPart.text(value(part, :text) || "")]

      type when type in [:image, "image"] ->
        if vision?, do: [tool_image_part(part)], else: []

      _other ->
        []
    end
  end

  defp tool_content_part(text, _vision?) when is_binary(text),
    do: [ReqLLM.Message.ContentPart.text(text)]

  defp tool_content_part(_part, _vision?), do: []

  # A staged screenshot can be evicted before its result leaves the retained history.
  # Missing or changed bytes must not prevent the next turn from using the saved tree.
  defp tool_image_part(part) do
    path = value(part, :path)
    expected = value(part, :sha256)
    media_type = value(part, :media_type) || "application/octet-stream"

    with true <- is_binary(path),
         {:ok, bytes} <- Ouroboros.Audit.Content.read(path),
         true <- digest(bytes) == expected do
      ReqLLM.Message.ContentPart.image(bytes, media_type)
    else
      _missing_or_changed ->
        hint = if is_binary(expected), do: String.slice(expected, 0, 12), else: "(unknown)"
        ReqLLM.Message.ContentPart.text("[screenshot #{hint} is no longer available]")
    end
  end

  defp content_part(part) when is_map(part) do
    case value(part, :type) do
      type when type in [:text, "text"] ->
        ReqLLM.Message.ContentPart.text(value(part, :text) || "")

      type when type in [:image, "image"] ->
        path = value(part, :path)
        expected = value(part, :sha256)
        media_type = value(part, :media_type) || "application/octet-stream"

        with true <- is_binary(path),
             {:ok, bytes} <- Ouroboros.Audit.Content.read(path),
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
