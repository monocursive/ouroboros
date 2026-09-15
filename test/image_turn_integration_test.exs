defmodule Ouroboros.ImageTurnIntegrationTest do
  use ExUnit.Case, async: false
  alias Ouroboros.{Attachments, InteractiveSession}
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "image-turn-#{System.unique_integer([:positive])}")
    File.mkdir!(root)
    old = Application.get_env(:ouroboros, :native_model_module)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      if old,
        do: Application.put_env(:ouroboros, :native_model_module, old),
        else: Application.delete_env(:ouroboros, :native_model_module)

      File.rm_rf(root)
    end)

    %{root: root}
  end

  test "a browser-shaped image-only input reaches the model and durable replay", %{root: root} do
    {model, agent} = NativeModelScript.start([[{:text, "saw image"}, {:finish, :stop}]])
    assert {:ok, session} = InteractiveSession.start(workspace: root, model: model)
    on_exit(fn -> InteractiveSession.kill(session) end)
    id = upload(session)

    params = %{
      "id" => session.id,
      "turn_id" => "image-only",
      "input" => %{"prompt" => "", "image_attachments" => [%{"id" => id}]}
    }

    assert {:ok, _} = Methods.invoke("interactive.send_message", params)
    assert {:ok, _} = Methods.invoke("interactive.send_message", params)
    await(fn -> NativeModelScript.call_count(agent) == 1 end)
    [request] = NativeModelScript.requests(agent)
    user = Enum.find(request.messages, &(&1.role == :user))
    assert Enum.any?(user.content, &(Map.get(&1, :type) == :image))

    await(fn ->
      {:ok, events} = InteractiveSession.replay(session, cursor: 0)

      Enum.any?(
        events,
        &(&1.type == :input_accepted and
            get_in(&1.payload, ["image_attachments", Access.at(0), "id"]) == id)
      )
    end)
  end

  test "an image queued before a model change retains its chosen model", %{root: root} do
    test = self()

    gate = fn _request ->
      Stream.flat_map([:wait], fn _ ->
        send(test, {:model_waiting, self()})

        receive do
          :finish -> [{:text, "first done"}, {:finish, :stop}]
        after
          5_000 -> raise "test did not release model"
        end
      end)
    end

    {original, agent} =
      NativeModelScript.start([gate, [{:text, "saw queued image"}, {:finish, :stop}]])

    {changed, changed_agent} = NativeModelScript.start([[{:text, "new model"}, {:finish, :stop}]])
    assert {:ok, session} = InteractiveSession.start(workspace: root, model: original)
    on_exit(fn -> InteractiveSession.kill(session) end)
    id = upload(session)

    assert {:ok, _} =
             Methods.invoke("interactive.send_message", %{
               "id" => session.id,
               "input" => "first",
               "turn_id" => "first"
             })

    assert_receive {:model_waiting, loop}, 2_000

    params = %{
      "id" => session.id,
      "turn_id" => "queued-image",
      "input" => %{"prompt" => "", "image_attachments" => [%{"id" => id}]}
    }

    assert {:ok, _} = Methods.invoke("interactive.follow_up", params)
    assert {:ok, _} = InteractiveSession.configure(session, model: changed)
    send(loop, :finish)
    await(fn -> NativeModelScript.call_count(agent) == 2 end)
    assert NativeModelScript.call_count(changed_agent) == 0
    queued = List.last(NativeModelScript.requests(agent))
    assert queued.model == original
    assert Enum.any?(List.last(queued.messages).content, &(Map.get(&1, :type) == :image))
    assert {:ok, _} = Methods.invoke("interactive.follow_up", params)
    assert NativeModelScript.call_count(agent) == 2
  end

  defp upload(session) do
    bytes = File.read!("test/support/images/two-pixels.png")
    actor = Ouroboros.Audit.Identity.actor()

    assert {:ok, record} =
             Attachments.operation(
               "begin",
               %{
                 "client_id" => "integration",
                 "draft_id" => session.id,
                 "client_attachment_id" => "one",
                 "attempt_id" => "one",
                 "byte_size" => byte_size(bytes),
                 "session_id" => session.id
               },
               actor
             )

    id = record["id"]

    assert {:ok, _} =
             Attachments.operation(
               "append",
               %{"upload_id" => id, "offset" => 0, "data" => Base.encode64(bytes)},
               actor
             )

    assert {:ok, _} =
             Attachments.operation(
               "finish",
               %{
                 "upload_id" => id,
                 "sha256" => Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
               },
               actor
             )

    await(fn ->
      match?(
        {:ok, %{"state" => "ready"}},
        Attachments.operation("status", %{"upload_id" => id}, actor)
      )
    end)

    id
  end

  defp await(fun, tries \\ 500)
  defp await(_fun, 0), do: flunk("condition did not settle")

  defp await(fun, tries) do
    if fun.(),
      do: :ok,
      else:
        (
          Process.sleep(10)
          await(fun, tries - 1)
        )
  end
end
