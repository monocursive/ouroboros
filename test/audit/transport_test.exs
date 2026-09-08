defmodule Ouroboros.Audit.TransportTest do
  use ExUnit.Case, async: false
  @moduletag :capture_log
  alias Ouroboros.Audit.{Config, Store}
  alias Ouroboros.Provider.Native.Journal
  alias Ouroboros.Provider.Native.Model.ReqLLM, as: Model

  setup do
    {:ok, tmp} = Ouroboros.Workspace.Path.canonicalize(System.tmp_dir!())
    root = Path.join(tmp, "ouro-audit-http-#{System.unique_integer([:positive])}")
    previous = Application.get_env(:ouroboros, :audit)
    options = Application.get_env(:ouroboros, :native_model_options)
    key = System.get_env("XAI_API_KEY")
    System.put_env("XAI_API_KEY", "test-audit-key")
    :ok = Supervisor.terminate_child(Ouroboros.Supervisor, Store)
    config = Config.new!(mode: :required, capture: :full, root: Path.join(root, "evidence"))
    Application.put_env(:ouroboros, :audit, config)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ouroboros, :audit, previous),
        else: Application.delete_env(:ouroboros, :audit)

      if options,
        do: Application.put_env(:ouroboros, :native_model_options, options),
        else: Application.delete_env(:ouroboros, :native_model_options)

      if key, do: System.put_env("XAI_API_KEY", key), else: System.delete_env("XAI_API_KEY")
      Supervisor.restart_child(Ouroboros.Supervisor, Store)
      File.rm_rf(root)
    end)

    %{root: root, config: config}
  end

  test "the committed transport body equals the actual HTTP body and credentials are excluded",
       ctx do
    config = %{
      ctx.config
      | encryption_key_id: "transport-images",
        encryption_keys: %{"transport-images" => :binary.copy(<<6>>, 32)}
    }

    Application.put_env(:ouroboros, :audit, config)
    start_supervised!({Store, config: config})
    source = Path.join(ctx.root, "image.png")
    image_bytes = <<137, 80, 78, 71, 13, 10, 26, 10>> <> "test private pixels"
    File.write!(source, image_bytes)

    {:ok, image_message} =
      Ouroboros.Provider.Native.Attachments.message(
        "say hello",
        [source],
        Path.join(ctx.root, "native/transport")
      )

    [_, image] = image_message.content
    assert Ouroboros.Audit.Content.encrypted?(File.read!(image.path))
    owner = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    server =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5000)
        request = read_request(socket, "")
        send(owner, {:request, request})

        body =
          "data: {\"id\":\"request-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"grok-4.5\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n"

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: #{byte_size(body)}\r\nconnection: close\r\n\r\n" <>
              body
          )

        :gen_tcp.close(socket)
        :gen_tcp.close(listener)
      end)

    Application.put_env(:ouroboros, :native_model_options,
      base_url: "http://127.0.0.1:#{port}/v1",
      max_retries: 5,
      receive_timeout: 5000
    )

    journal = Journal.open(Path.join(ctx.root, "session"))

    request = %{
      model: "xai:grok-4.5",
      system: "brief",
      messages: [image_message],
      tools: [],
      provider_session_id: "test",
      turn_id: "turn",
      reasoning_effort: :low,
      max_tokens: nil
    }

    audit = %{journal: journal, turn_id: "turn", effect_id: "effect", iteration: 1}
    assert {:ok, stream} = Model.stream(request, audit_context: audit)
    assert {:text, "hello"} in Enum.to_list(stream)
    assert_receive {:request, raw}, 5000
    [_, body] = String.split(raw, "\r\n\r\n", parts: 2)
    assert {:ok, %{records: [record]}} = Store.read(Journal.path(Path.join(ctx.root, "session")))
    assert record["kind"] == "model_transport"
    assert {:ok, request_content} = Store.blob(config, record["request"])
    assert request_content == JSON.decode!(body)
    assert body =~ Base.encode64(image_bytes)
    refute body =~ "OUROBOROS-ENCRYPTED"

    assert record["request_sha256"] ==
             :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)

    assert record["bytes"] == byte_size(body)
    assert record["max_retries"] == 0
    refute JSON.encode!(record) =~ "test-audit-key"
    Task.await(server)
  end

  test "a recording failure at the final transport boundary opens no connection", ctx do
    start_supervised!(
      {Store,
       config: ctx.config,
       durability_hook: fn point ->
         if point == :before_write, do: {:error, :enospc}, else: :ok
       end}
    )

    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, packet: :raw, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)

    Application.put_env(:ouroboros, :native_model_options,
      base_url: "http://127.0.0.1:#{port}/v1",
      receive_timeout: 1000
    )

    journal = Journal.open(Path.join(ctx.root, "session"))

    request = %{
      model: "xai:grok-4.5",
      system: "brief",
      messages: [%{role: :user, content: "say hello"}],
      tools: [],
      provider_session_id: "test",
      turn_id: "turn",
      reasoning_effort: :low,
      max_tokens: nil
    }

    result =
      try do
        Model.stream(request,
          audit_context: %{journal: journal, turn_id: "turn", effect_id: "effect", iteration: 1}
        )
      rescue
        e in Ouroboros.Audit.Unavailable -> {:refused, e.reason}
      end

    refute match?({:ok, _}, result)
    assert {:error, :timeout} = :gen_tcp.accept(listener, 100)
  end

  defp read_request(socket, acc) do
    case String.split(acc, "\r\n\r\n", parts: 2) do
      [headers, body] ->
        [_, size] = Regex.run(~r/content-length: (\d+)/i, headers)
        if byte_size(body) >= String.to_integer(size), do: acc, else: receive_more(socket, acc)

      _ ->
        receive_more(socket, acc)
    end
  end

  defp receive_more(socket, acc) do
    {:ok, bytes} = :gen_tcp.recv(socket, 0, 5000)
    read_request(socket, acc <> bytes)
  end
end
