defmodule Ouroboros.Provider.Native.DirectSSETest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.{AnthropicKey, XAIKey}
  alias Ouroboros.Provider.Native.Model.ReqLLM, as: DirectModel
  alias Ouroboros.Provider.Native.Tools

  setup do
    previous_options = Application.get_env(:ouroboros, :native_model_options)
    previous_key = System.get_env("OPENAI_API_KEY")
    previous_anthropic_key = System.get_env("ANTHROPIC_API_KEY")
    previous_anthropic_workspace = System.get_env("ANTHROPIC_WORKSPACE_ID")
    previous_xai_key = System.get_env("XAI_API_KEY")
    System.put_env("OPENAI_API_KEY", "test-openai-key")
    System.put_env("ANTHROPIC_API_KEY", "test-anthropic-key")
    System.delete_env("ANTHROPIC_WORKSPACE_ID")
    System.put_env("XAI_API_KEY", "test-xai-key")

    on_exit(fn ->
      if previous_options,
        do: Application.put_env(:ouroboros, :native_model_options, previous_options),
        else: Application.delete_env(:ouroboros, :native_model_options)

      if previous_key,
        do: System.put_env("OPENAI_API_KEY", previous_key),
        else: System.delete_env("OPENAI_API_KEY")

      if previous_anthropic_key,
        do: System.put_env("ANTHROPIC_API_KEY", previous_anthropic_key),
        else: System.delete_env("ANTHROPIC_API_KEY")

      if previous_anthropic_workspace,
        do: System.put_env("ANTHROPIC_WORKSPACE_ID", previous_anthropic_workspace),
        else: System.delete_env("ANTHROPIC_WORKSPACE_ID")

      if previous_xai_key,
        do: System.put_env("XAI_API_KEY", previous_xai_key),
        else: System.delete_env("XAI_API_KEY")
    end)

    :ok
  end

  test "streams xAI chat completions with the private API-key lane" do
    root =
      Path.join(System.tmp_dir!(), "ouroboros-direct-xai-#{System.unique_integer([:positive])}")

    Ouroboros.DataDir.ensure_private!(root)
    path = Path.join(root, "xai.key")
    previous_path = Application.get_env(:ouroboros, :xai_api_key_file)
    Application.put_env(:ouroboros, :xai_api_key_file, path)
    System.delete_env("XAI_API_KEY")
    assert {:ok, %{source: :stored}} = XAIKey.put("test-xai-key", path: path)

    on_exit(fn ->
      if previous_path,
        do: Application.put_env(:ouroboros, :xai_api_key_file, previous_path),
        else: Application.delete_env(:ouroboros, :xai_api_key_file)

      File.rm_rf(root)
    end)

    parent = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])
    {:ok, {_address, port}} = :inet.sockname(listener)

    {:ok, server} =
      Task.start(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        {:ok, request} = read_request(socket, "")
        send(parent, {:xai_http_request, request})

        body =
          [
            "data: {\"id\":\"chatcmpl-xai\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"grok-4.5\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hello from grok\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-xai\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"grok-4.5\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":3,\"total_tokens\":6}}\n\n",
            "data: [DONE]\n\n"
          ]
          |> IO.iodata_to_binary()

        response =
          "HTTP/1.1 200 OK\r\n" <>
            "content-type: text/event-stream\r\n" <>
            "content-length: #{byte_size(body)}\r\n" <>
            "connection: close\r\n\r\n" <> body

        :ok = :gen_tcp.send(socket, response)
        :gen_tcp.close(socket)
        :gen_tcp.close(listener)
      end)

    monitor = Process.monitor(server)

    Application.put_env(:ouroboros, :native_model_options,
      base_url: "http://127.0.0.1:#{port}/v1",
      receive_timeout: 5_000,
      stream_idle_timeout: 5_000,
      total_timeout: 10_000,
      max_retries: 0
    )

    request = %{
      model: "xai:grok-4.5",
      system: "Be concise",
      messages: [%{role: :user, content: "say hello"}],
      tools: [],
      provider_session_id: "native-xai-test",
      turn_id: "turn-xai-test",
      reasoning_effort: :low,
      max_tokens: nil
    }

    assert {:ok, stream} = DirectModel.stream(request, [])
    chunks = Enum.to_list(stream)

    assert {:text, "hello from grok"} in chunks
    assert {:finish, :stop} in chunks
    assert_receive {:xai_http_request, raw}, 5_000
    assert raw =~ "POST /v1/chat/completions HTTP/1.1"
    assert String.downcase(raw) =~ "authorization: bearer test-xai-key"

    payload = request_payload(raw)
    assert payload["model"] == "grok-4.5"

    assert payload["messages"] == [
             %{"role" => "system", "content" => "Be concise"},
             %{"role" => "user", "content" => "say hello"}
           ]

    assert_receive {:DOWN, ^monitor, :process, ^server, :normal}, 5_000
  end

  test "streams Anthropic Messages with API-key auth and no OAuth lane" do
    root =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-direct-anthropic-#{System.unique_integer([:positive])}"
      )

    Ouroboros.DataDir.ensure_private!(root)
    path = Path.join(root, "anthropic.key")
    previous_path = Application.get_env(:ouroboros, :anthropic_api_key_file)
    Application.put_env(:ouroboros, :anthropic_api_key_file, path)
    System.delete_env("ANTHROPIC_API_KEY")

    assert {:ok, %{source: :stored, workspace_configured: true}} =
             AnthropicKey.put("test-anthropic-key", "wrkspc_Direct123", path: path)

    on_exit(fn ->
      if previous_path,
        do: Application.put_env(:ouroboros, :anthropic_api_key_file, previous_path),
        else: Application.delete_env(:ouroboros, :anthropic_api_key_file)

      File.rm_rf(root)
    end)

    parent = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])
    {:ok, {_address, port}} = :inet.sockname(listener)

    {:ok, server} =
      Task.start(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        {:ok, request} = read_request(socket, "")
        send(parent, {:anthropic_http_request, request})

        body =
          [
            ~s(event: message_start\ndata: {"type":"message_start","message":{"id":"msg-direct-1","type":"message","role":"assistant","model":"claude-sonnet-5","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":3,"output_tokens":0}}}\n\n),
            ~s(event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n),
            ~s(event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello from claude"}}\n\n),
            ~s(event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n),
            ~s(event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":3}}\n\n),
            ~s(event: message_stop\ndata: {"type":"message_stop"}\n\n)
          ]
          |> IO.iodata_to_binary()

        response =
          "HTTP/1.1 200 OK\r\n" <>
            "content-type: text/event-stream\r\n" <>
            "content-length: #{byte_size(body)}\r\n" <>
            "connection: close\r\n\r\n" <> body

        :ok = :gen_tcp.send(socket, response)
        :gen_tcp.close(socket)
        :gen_tcp.close(listener)
      end)

    monitor = Process.monitor(server)

    Application.put_env(:ouroboros, :native_model_options,
      base_url: "http://127.0.0.1:#{port}",
      receive_timeout: 5_000,
      stream_idle_timeout: 5_000,
      total_timeout: 10_000,
      max_retries: 0
    )

    request = %{
      model: "anthropic:claude-sonnet-5",
      system: "Be concise",
      messages: [%{role: :user, content: "say hello"}],
      tools: [],
      provider_session_id: "native-anthropic-test",
      turn_id: "turn-anthropic-test",
      reasoning_effort: :low,
      max_tokens: nil
    }

    assert {:ok, stream} = DirectModel.stream(request, [])
    chunks = Enum.to_list(stream)

    assert {:text, "hello from claude"} in chunks
    assert Enum.any?(chunks, &match?({:usage, %{input_tokens: 3}}, &1))
    assert {:finish, :stop} in chunks

    assert_receive {:anthropic_http_request, raw}, 5_000
    assert raw =~ "POST /v1/messages HTTP/1.1"
    assert String.downcase(raw) =~ "x-api-key: test-anthropic-key"
    assert String.downcase(raw) =~ "anthropic-workspace-id: wrkspc_direct123"
    refute String.downcase(raw) =~ "authorization: bearer"
    assert String.downcase(raw) =~ "anthropic-version: 2023-06-01"

    payload = request_payload(raw)
    assert payload["model"] == "claude-sonnet-5"
    assert payload["messages"] == [%{"role" => "user", "content" => "say hello"}]
    assert payload["thinking"] == %{"type" => "adaptive", "display" => "summarized"}
    assert payload["output_config"] == %{"effort" => "low"}

    assert_receive {:DOWN, ^monitor, :process, ^server, :normal}, 5_000
  end

  test "streams an OpenAI Responses call directly over HTTP without a process adapter" do
    parent = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])
    {:ok, {_address, port}} = :inet.sockname(listener)

    {:ok, server} =
      Task.start(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        {:ok, request} = read_request(socket, "")
        send(parent, {:direct_http_request, request})

        body =
          [
            ~s(data: {"type":"response.output_text.delta","delta":"hello"}\n\n),
            ~s(data: {"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc-read-1","call_id":"call-read-1","name":"read","arguments":"","status":"in_progress"}}\n\n),
            ~s(data: {"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","id":"fc-bash-1","call_id":"call-bash-1","name":"bash","arguments":"","status":"in_progress"}}\n\n),
            ~s(data: {"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc-read-1","delta":"{\\"path\\":\\"README.md\\","}\n\n),
            ~s(data: {"type":"response.function_call_arguments.delta","output_index":1,"item_id":"fc-bash-1","delta":"{\\"command\\":\\"pwd\\"}"}\n\n),
            ~s(data: {"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc-read-1","delta":"\\"offset\\":0,\\"limit\\":1}"}\n\n),
            ~s(data: {"type":"response.completed","response":{"id":"resp-direct-1","status":"completed","output":[],"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}\n\n),
            "data: [DONE]\n\n"
          ]
          |> IO.iodata_to_binary()

        response =
          "HTTP/1.1 200 OK\r\n" <>
            "content-type: text/event-stream\r\n" <>
            "content-length: #{byte_size(body)}\r\n" <>
            "connection: close\r\n\r\n" <> body

        :ok = :gen_tcp.send(socket, response)
        :gen_tcp.close(socket)
        :gen_tcp.close(listener)
      end)

    monitor = Process.monitor(server)

    Application.put_env(:ouroboros, :native_model_options,
      base_url: "http://127.0.0.1:#{port}/v1",
      receive_timeout: 5_000,
      stream_idle_timeout: 5_000,
      total_timeout: 10_000,
      max_retries: 0
    )

    request = %{
      model: "openai:gpt-5.6",
      system: "Be concise",
      messages: [%{role: :user, content: "say hello"}],
      tools: Tools.specs(nil, nil),
      provider_session_id: "native-direct-test",
      turn_id: "turn-direct-test",
      reasoning_effort: :low,
      max_tokens: nil
    }

    assert {:ok, stream} = DirectModel.stream(request, [])
    chunks = Enum.to_list(stream)
    assert {:text, "hello"} in chunks

    assert {:tool_call,
            %{
              id: "call-read-1",
              name: "read",
              input: %{"path" => "README.md", "offset" => 0, "limit" => 1}
            }} in chunks

    assert {:tool_call, %{id: "call-bash-1", name: "bash", input: %{"command" => "pwd"}}} in chunks

    assert {:provider_metadata, %{response_id: "resp-direct-1"}} in chunks
    assert Enum.any?(chunks, &match?({:usage, %{input_tokens: 3, output_tokens: 1}}, &1))
    assert {:finish, :stop} in chunks

    assert_receive {:direct_http_request, raw}, 5_000
    assert raw =~ "POST /v1/responses HTTP/1.1"
    assert String.downcase(raw) =~ "authorization: bearer test-openai-key"
    assert raw =~ ~s("model":"gpt-5.6")
    assert raw =~ "Be concise"

    payload = request_payload(raw)
    assert Enum.map(payload["tools"], & &1["name"]) == Enum.map(Tools.specs(nil, nil), & &1.name)

    for tool <- payload["tools"] do
      assert tool["strict"]

      parameters = tool["parameters"]
      assert MapSet.new(parameters["required"]) == MapSet.new(Map.keys(parameters["properties"]))
    end

    read = Enum.find(payload["tools"], &(&1["name"] == "read"))
    refute nullable?(read["parameters"]["properties"]["path"])
    assert nullable?(read["parameters"]["properties"]["offset"])

    assert_receive {:DOWN, ^monitor, :process, ^server, :normal}, 5_000
  end

  defp request_payload(request) do
    [_headers, body] = String.split(request, "\r\n\r\n", parts: 2)
    Jason.decode!(body)
  end

  defp nullable?(%{"type" => "null"}), do: true

  defp nullable?(%{"anyOf" => variants}) when is_list(variants),
    do: Enum.any?(variants, &nullable?/1)

  defp nullable?(_schema), do: false

  defp read_request(socket, acc) do
    case complete_request(acc) do
      true ->
        {:ok, acc}

      false ->
        case :gen_tcp.recv(socket, 0, 5_000) do
          {:ok, data} -> read_request(socket, acc <> data)
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp complete_request(request) do
    case String.split(request, "\r\n\r\n", parts: 2) do
      [headers, body] ->
        length =
          headers
          |> String.split("\r\n")
          |> Enum.find_value(0, fn line ->
            case String.split(line, ":", parts: 2) do
              [name, value] ->
                if String.downcase(name) == "content-length",
                  do: value |> String.trim() |> String.to_integer()

              _other ->
                nil
            end
          end)

        byte_size(body) >= length

      _incomplete ->
        false
    end
  end
end
