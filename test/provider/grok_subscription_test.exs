defmodule Ouroboros.Provider.GrokSubscriptionTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.GrokSubscription
  alias Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native.Model.Admission
  alias Ouroboros.Provider.Native.Model.ReqLLM, as: DirectModel

  @moduletag :tmp_dir
  @entry "https://auth.x.ai::b1a00492-073a-47ea-816f-4c329264a828"

  setup %{tmp_dir: dir} do
    Ouroboros.Test.FirstUseIsolation.setup(dir, DirectModel)
    %{path: Application.fetch_env!(:ouroboros, :grok_auth_file)}
  end

  test "reads only the explicit first-party OAuth entry and reports no secrets", %{path: path} do
    write_credential(path)
    assert {:ok, "subscription-access-canary"} = GrokSubscription.fetch()

    assert %{provider: :grok, present: true, credential_state: :present} =
             GrokSubscription.status()

    assert Model.credential_ready?("grok:grok-4.6")
    refute Model.credential_ready?("xai:grok-4.6")
    refute inspect(DirectModel.credential_report()) =~ "canary"
    refute inspect(DirectModel.credential_report()) =~ path

    assert {:ok, safe} =
             Ouroboros.Runtime.SafeStatus.session(
               %{owner: "fixture", observed_at_ms: 1, credentials: [GrokSubscription.status()]},
               1
             )

    assert [%{"provider" => "grok", "present" => true}] = safe["credentials"]
    refute inspect(safe) =~ "canary"

    before = File.read!(path)
    assert {:ok, _, _} = GrokSubscription.transport("grok:grok-4.6", [])
    assert File.read!(path) == before
    write_credential(path, %{"key" => "renewed-access-canary"})
    assert {:ok, "renewed-access-canary"} = GrokSubscription.fetch()
  end

  test "missing, expired, malformed and non-OAuth sources fail without API fallback", %{
    path: path
  } do
    System.put_env("XAI_API_KEY", "paid-api-canary")

    assert {:error, {:grok_subscription, :absent}} =
             GrokSubscription.transport("grok:grok-4.6", [])

    refute Model.credential_ready?("grok:grok-4.6")

    for change <- [
          %{"key" => ""},
          %{"key" => "token\r\nheader"},
          %{"key" => 42},
          %{"auth_mode" => "api_key"},
          %{"oidc_issuer" => "https://unrelated.test"},
          %{"oidc_client_id" => "unrelated-client"},
          %{"expires_at" => "not-a-date"}
        ] do
      write_credential(path, change)
      assert {:error, :invalid} = GrokSubscription.fetch()
      refute GrokSubscription.status().present
    end

    write_credential(path, %{"expires_at" => "2020-01-01T00:00:00Z"})
    assert {:error, :expired} = GrokSubscription.fetch()
    assert {:error, {:grok_subscription, :expired}} = DirectModel.stream(request(), [])
    assert DirectModel.format_error({:grok_subscription, :expired}) =~ "run grok login"

    for bytes <- ["[]", "malformed-secret-canary", String.duplicate("x", 65_537)] do
      File.write!(path, bytes)
      assert {:error, :invalid} = GrokSubscription.fetch()
    end
  end

  test "refuses public and symlinked credential files", %{path: path} do
    write_credential(path)
    File.chmod!(path, 0o644)
    assert {:error, :invalid} = GrokSubscription.fetch()
    File.chmod!(path, 0o600)
    File.rename!(path, path <> ".original")
    File.ln_s!(path <> ".original", path)
    assert {:error, :invalid} = GrokSubscription.fetch()
  end

  for format <- [:keyword, :map] do
    test "pins subscription transport with #{format} HTTP options", %{path: path} do
      write_credential(path)

      http = [
        headers: [{"authorization", "paid-api-canary"}],
        redirect: true,
        receive_timeout: 1_000
      ]

      http = if unquote(format) == :map, do: Map.new(http), else: http

      assert {:ok, "xai:grok-4.6", opts} =
               GrokSubscription.transport("grok:grok-4.6",
                 api_key: "paid-api-canary",
                 base_url: "https://unrelated.test",
                 oauth_file: "other.json",
                 provider_options: [xai_api: :responses],
                 req_http_options: http
               )

      assert opts[:api_key] == "subscription-access-canary"
      assert opts[:base_url] == "https://cli-chat-proxy.grok.com/v1"
      assert opts[:provider_options] == [xai_api: :chat]
      assert opts[:req_http_options][:redirect] == false
      assert opts[:req_http_options][:receive_timeout] == 1_000
      assert {"x-grok-model-override", "grok-4.6"} in opts[:req_http_options][:headers]
      assert {"x-grok-client-identifier", "ouroboros"} in opts[:req_http_options][:headers]
      refute inspect(opts) =~ "paid-api-canary"
      refute Keyword.has_key?(opts, :oauth_file)

      assert {:ok, "xai:grok-4.6", [api_key: "api"]} =
               GrokSubscription.transport("xai:grok-4.6", api_key: "api")
    end
  end

  test "names the conversation to the proxy, and only with a value fit for a header", %{
    path: path
  } do
    write_credential(path)

    assert {:ok, _, opts} = GrokSubscription.transport("grok:grok-4.6", [], "native-abc123")
    assert {"x-grok-conv-id", "native-abc123"} in opts[:req_http_options][:headers]

    # Without one, none is invented: an empty or absent id sends no header at all.
    for absent <- [nil, ""] do
      assert {:ok, _, opts} = GrokSubscription.transport("grok:grok-4.6", [], absent)
      refute Enum.any?(opts[:req_http_options][:headers], &match?({"x-grok-conv-id", _}, &1))
    end

    # And a value that could smuggle a second header line is dropped, not escaped.
    assert {:ok, _, opts} = GrokSubscription.transport("grok:grok-4.6", [], "id\r\nx-evil: 1")
    refute Enum.any?(opts[:req_http_options][:headers], &match?({"x-grok-conv-id", _}, &1))
    refute inspect(opts) =~ "x-evil"

    # The connection still owns every other header.
    assert {:ok, _, opts} =
             GrokSubscription.transport(
               "grok:grok-4.6",
               [req_http_options: [headers: [{"x-grok-conv-id", "theirs"}]]],
               "ours"
             )

    assert Enum.count(opts[:req_http_options][:headers], &match?({"x-grok-conv-id", _}, &1)) == 1
    assert {"x-grok-conv-id", "ours"} in opts[:req_http_options][:headers]
  end

  test "rejects credentials that become expired while waiting for model capacity", %{path: path} do
    write_credential(path)
    parent = self()

    {waiter, leases} =
      queue_stream(
        on_finch_request: fn _request ->
          send(parent, :unexpected_request)
          raise "unexpected request stopped before network access"
        end
      )

    write_credential(path, %{"expires_at" => "2020-01-01T00:00:00Z"})
    Enum.each(leases, &Admission.release/1)

    assert {:error, {:grok_subscription, :expired}} = Task.await(waiter, 5_000)
    refute_received :unexpected_request
    assert %{active: 0, queued: 0} = Admission.status()
  end

  test "normalizes streamed tool calls and preserves tool results in the next request", %{
    path: path
  } do
    write_credential(path)
    parent = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)

    server =
      Task.async(fn ->
        for round <- 1..2 do
          {:ok, socket} = :gen_tcp.accept(listener, 5_000)
          read_request(socket, "")

          delta =
            if round == 1 do
              %{
                "tool_calls" => [
                  %{
                    "index" => 0,
                    "id" => "call-1",
                    "type" => "function",
                    "function" => %{"name" => "lookup", "arguments" => "{\"path\":\"README.md\"}"}
                  }
                ]
              }
            else
              %{"content" => "Read completed."}
            end

          chunk = %{
            "id" => "grok-fixture",
            "object" => "chat.completion.chunk",
            "created" => 1,
            "model" => "grok-4.6",
            "choices" => [%{"index" => 0, "delta" => delta, "finish_reason" => nil}]
          }

          finish =
            put_in(chunk["choices"], [
              %{
                "index" => 0,
                "delta" => %{},
                "finish_reason" => if(round == 1, do: "tool_calls", else: "stop")
              }
            ])
            |> Map.put("usage", %{
              "prompt_tokens" => 10,
              "completion_tokens" => 5,
              "total_tokens" => 15
            })

          body =
            "data: #{JSON.encode!(chunk)}\n\ndata: #{JSON.encode!(finish)}\n\ndata: [DONE]\n\n"

          :ok =
            :gen_tcp.send(
              socket,
              "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: #{byte_size(body)}\r\nconnection: close\r\n\r\n" <>
                body
            )

          :gen_tcp.close(socket)
        end
      end)

    # Exercise the real encoder and SSE parser. Only synthetic credentials are redirected
    # to a local fixture, after recording the production request the adapter constructed.
    hook = fn req ->
      send(parent, {:outbound, req})
      %{req | scheme: :http, host: "127.0.0.1", port: port}
    end

    {waiter, leases} = queue_stream(on_finch_request: hook)
    write_credential(path, %{"key" => "renewed-access-canary"})
    Enum.each(leases, &Admission.release/1)
    assert {:ok, chunks} = Task.await(waiter, 5_000)

    assert {:tool_call, %{id: "call-1", name: "lookup", input: %{"path" => "README.md"}}} in chunks

    assert {:finish, :tool_calls} in chunks
    assert_receive {:outbound, sent}, 5_000
    assert sent.host == "cli-chat-proxy.grok.com"
    assert sent.path == "/v1/chat/completions"
    assert sent.scheme == :https
    headers = Enum.map(sent.headers, fn {k, v} -> {String.downcase(k), v} end)
    assert {"authorization", "Bearer renewed-access-canary"} in headers
    assert {"x-xai-token-auth", "xai-grok-cli"} in headers

    next =
      Map.update!(
        request(),
        :messages,
        &(&1 ++
            [
              %{
                role: :assistant,
                content: nil,
                tool_calls: [%{id: "call-1", name: "lookup", input: %{"path" => "README.md"}}]
              },
              %{
                role: :tool,
                tool_call_id: "call-1",
                name: "lookup",
                content: "Fixture README contents"
              }
            ])
      )

    assert {:ok, stream} =
             DirectModel.stream(next,
               on_finch_request: hook,
               req_http_options: %{receive_timeout: 5_000}
             )

    assert {:text, "Read completed."} in Enum.to_list(stream)
    assert_receive {:outbound, sent}, 5_000
    payload = JSON.decode!(IO.iodata_to_binary(sent.body))
    assert payload["model"] == "grok-4.6"
    assert List.last(payload["messages"])["content"] == "Fixture README contents"
    assert List.last(payload["messages"])["tool_call_id"] == "call-1"
    Task.await(server, 5_000)
  end

  test "catalogue and context preserve metadata without pretending API prices are subscription costs" do
    Application.put_env(:ouroboros, :native_model, "grok:grok-4.6")
    [row] = Ouroboros.Models.list().providers
    assert %{id: "grok:grok-4.6", pricing: nil, billing: :subscription} = hd(row.models)
    assert Enum.any?(row.models, &String.starts_with?(&1.id, "xai:"))

    assert Ouroboros.Provider.Native.Context.Window.resolve("grok:grok-4.6") ==
             Ouroboros.Provider.Native.Context.Window.resolve("xai:grok-4.6")

    refute Map.has_key?(
             Ouroboros.Provider.Native.Cost.payload(%{input_tokens: 100}, "grok:grok-4.6"),
             "cost_usd"
           )
  end

  defp request do
    %{
      model: "grok:grok-4.6",
      system: "Be concise",
      messages: [%{role: :user, content: "Read README.md"}],
      tools: [
        %{
          name: "lookup",
          description: "Read a file",
          parameters: %{
            "type" => "object",
            "properties" => %{"path" => %{"type" => "string"}},
            "required" => ["path"]
          }
        }
      ],
      provider_session_id: "grok-fixture",
      turn_id: "turn-1",
      reasoning_effort: nil,
      max_tokens: nil
    }
  end

  defp queue_stream(options) do
    assert %{active: 0, queued: 0, limit: limit} = Admission.status()

    leases =
      for _ <- 1..limit do
        {:ok, lease} = Admission.checkout()
        lease
      end

    waiter =
      Task.async(fn ->
        case DirectModel.stream(request(), options) do
          {:ok, stream} -> {:ok, Enum.to_list(stream)}
          error -> error
        end
      end)

    on_exit(fn ->
      Process.exit(waiter.pid, :kill)
      Enum.each(leases, &Admission.release/1)
    end)

    wait_for_queue(System.monotonic_time(:millisecond) + 5_000)
    {waiter, leases}
  end

  defp wait_for_queue(deadline) do
    if Admission.status().queued != 1 do
      assert System.monotonic_time(:millisecond) < deadline,
             "model request did not enter the queue"

      Process.sleep(10)
      wait_for_queue(deadline)
    end
  end

  defp write_credential(path, changes \\ %{}) do
    credential =
      Map.merge(
        %{
          "key" => "subscription-access-canary",
          "refresh_token" => "refresh-canary",
          "auth_mode" => "oidc",
          "oidc_issuer" => "https://auth.x.ai",
          "oidc_client_id" => "b1a00492-073a-47ea-816f-4c329264a828",
          "expires_at" => DateTime.utc_now() |> DateTime.add(3_600) |> DateTime.to_iso8601()
        },
        changes
      )

    File.write!(path, JSON.encode!(%{@entry => credential}))
    File.chmod!(path, 0o600)
  end

  defp read_request(socket, bytes) do
    case String.split(bytes, "\r\n\r\n", parts: 2) do
      [headers, body] ->
        [_, size] = Regex.run(~r/content-length: (\d+)/i, headers)
        if byte_size(body) >= String.to_integer(size), do: :ok, else: read_more(socket, bytes)

      _ ->
        read_more(socket, bytes)
    end
  end

  defp read_more(socket, bytes) do
    {:ok, chunk} = :gen_tcp.recv(socket, 0, 5_000)
    read_request(socket, bytes <> chunk)
  end
end
