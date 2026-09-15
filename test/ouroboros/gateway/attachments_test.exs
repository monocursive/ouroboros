defmodule Ouroboros.Gateway.AttachmentsTest do
  use ExUnit.Case, async: false
  alias Ouroboros.Gateway.Methods

  @tag timeout: 60_000
  test "a relayed upload stays on its owner and never falls back locally" do
    unless Node.alive?() do
      assert {:ok, _} =
               :net_kernel.start([
                 :"image_root_#{System.unique_integer([:positive])}",
                 :shortnames
               ])
    end

    args = [~c"+S", ~c"2:2"] ++ Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    assert {:ok, peer, owner} =
             :peer.start(%{
               name: :"image_peer_#{System.unique_integer([:positive])}",
               args: args,
               wait_boot: 30_000
             })

    on_exit(fn -> if Process.alive?(peer), do: :peer.stop(peer) end)
    root = Path.join(System.tmp_dir!(), "image-peer-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    File.chmod!(root, 0o700)
    on_exit(fn -> File.rm_rf(root) end)
    {:ok, _} = :erpc.call(owner, Application, :ensure_all_started, [:mix])
    :ok = :erpc.call(owner, Mix, :env, [:test])
    :ok = :erpc.call(owner, Application, :put_env, [:ouroboros, :data_dir, root])
    assert {:ok, _} = :erpc.call(owner, Application, :ensure_all_started, [:ouroboros])
    Process.put(:ouroboros_attachment_frame, 1_024)
    node = to_string(owner)
    assert {:ok, limits} = Methods.invoke("attachment.limits", %{"node" => node})
    assert limits.chunk_bytes == 192
    assert limits.image_attachments_v1
    bytes = File.read!("test/support/images/two-pixels.png")

    assert {:ok, record} =
             Methods.invoke("attachment.begin", %{
               "node" => node,
               "client_id" => "peer-test",
               "draft_id" => "draft",
               "client_attachment_id" => "image",
               "attempt_id" => "one",
               "byte_size" => byte_size(bytes)
             })

    id = record["id"]

    assert {:ok, _} =
             Methods.invoke("attachment.append", %{
               "node" => node,
               "upload_id" => id,
               "offset" => 0,
               "data" => Base.encode64(bytes)
             })

    assert {:ok, _} =
             Methods.invoke("attachment.finish", %{
               "node" => node,
               "upload_id" => id,
               "sha256" => Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
             })

    ready(node, id)

    assert {:ok, %{data: data, eof: true}} =
             Methods.invoke("attachment.read", %{
               "node" => node,
               "attachment_id" => id,
               "variant" => "content"
             })

    assert byte_size(Base.decode64!(data)) > 0
    assert File.regular?(Path.join([root, "attachments", id, "content"]))
    assert {:error, -32006, _, _} = Methods.invoke("attachment.status", %{"attachment_id" => id})
    :peer.stop(peer)

    assert {:error, _, _} =
             Methods.invoke("attachment.status", %{"node" => node, "attachment_id" => id})
  end

  defp ready(node, id, count \\ 500)
  defp ready(_, _, 0), do: flunk("remote normalization did not complete")

  defp ready(node, id, count) do
    case Methods.invoke("attachment.status", %{"node" => node, "attachment_id" => id}) do
      {:ok, %{"state" => "ready"}} ->
        :ok

      {:ok, %{"state" => "failed"} = failed} ->
        flunk(inspect(failed))

      _ ->
        Process.sleep(10)
        ready(node, id, count - 1)
    end
  end
end
