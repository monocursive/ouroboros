defmodule Ouroboros.Web.AttachmentController do
  use Phoenix.Controller, formats: []
  import Plug.Conn
  alias Ouroboros.Web.{Call, Config}

  def show(conn, %{"id" => id, "variant" => variant} = params) do
    config = Config.for_endpoint(conn.private.phoenix_endpoint)

    args =
      Map.take(params, ["session_id", "node"])
      |> Map.merge(%{
        "attachment_id" => id,
        "variant" => variant,
        "offset" => 0,
        "length" => 196_608
      })

    conn =
      conn
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("x-content-type-options", "nosniff")
      |> put_resp_header("content-security-policy", "default-src 'none'; sandbox")

    # Verify all chunks before responding. One bounded image is held in this request
    # process; neither its bytes nor a capability URL is persisted in the browser cache.
    case collect(config.scope, args, [], nil) do
      {:ok, bytes} -> conn |> put_resp_content_type("image/png", nil) |> send_resp(200, bytes)
      _ -> send_resp(conn, 404, "Image unavailable")
    end
  end

  defp collect(scope, args, acc, digest) do
    with true <- args["offset"] <= 20 * 1024 * 1024,
         {:ok, answer} <- Call.call(scope, "attachment.read", args),
         answer = Ouroboros.Gateway.Wire.to_json(answer),
         {:ok, bytes} <- Base.decode64(answer["data"]),
         true <- byte_size(bytes) > 0,
         true <- is_nil(digest) or digest == answer["sha256"] do
      acc = [bytes | acc]

      if answer["eof"] do
        content = acc |> Enum.reverse() |> IO.iodata_to_binary()

        if byte_size(content) <= 20 * 1024 * 1024 and
             Base.encode16(:crypto.hash(:sha256, content), case: :lower) == answer["sha256"],
           do: {:ok, content},
           else: {:error, :integrity}
      else
        collect(
          scope,
          Map.update!(args, "offset", &(&1 + byte_size(bytes))),
          acc,
          answer["sha256"]
        )
      end
    else
      _ -> {:error, :unavailable}
    end
  end
end
