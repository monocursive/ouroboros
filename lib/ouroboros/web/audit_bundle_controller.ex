defmodule Ouroboros.Web.AuditBundleController do
  @moduledoc "Streams an authenticated evidence snapshot as an uncompressed portable tar."
  use Phoenix.Controller, formats: []
  import Plug.Conn
  alias Ouroboros.Web.{Call, Config}

  def show(conn, %{"id" => id}) do
    with true <- Ouroboros.Audit.Store.valid_id?(id),
         {:ok, bytes} <- manifest_bytes(conn, id, 0, []),
         {:ok, %{"files" => files}} <- JSON.decode(bytes),
         true <- is_list(files) and length(files) <= 100_000 do
      conn =
        conn
        |> put_resp_content_type("application/x-tar")
        |> put_resp_header("cache-control", "no-store")
        |> put_resp_header(
          "content-disposition",
          "attachment; filename=ouroboros-evidence-#{id}.tar"
        )
        |> send_chunked(200)

      entries = files ++ [%{"path" => "manifest.json", "bytes" => byte_size(bytes)}]

      Enum.reduce_while(entries, {:ok, conn}, fn entry, {:ok, acc} ->
        path = entry["path"]

        with true <- path == "manifest.json" or Ouroboros.Audit.Bundle.safe_path?(path),
             {:ok, acc} <- chunk(acc, header(path, entry["bytes"])),
             {:ok, acc} <- transfer(acc, id, path, 0),
             {:ok, acc} <-
               chunk(acc, :binary.copy(<<0>>, rem(512 - rem(entry["bytes"], 512), 512))) do
          {:cont, {:ok, acc}}
        else
          _ -> {:halt, {:error, acc}}
        end
      end)
      |> case do
        {:ok, conn} ->
          case chunk(conn, :binary.copy(<<0>>, 1024)) do
            {:ok, conn} -> conn
            _ -> conn
          end

        {:error, conn} ->
          conn
      end
    else
      _ ->
        conn
        |> put_resp_header("cache-control", "no-store")
        |> send_resp(404, "Evidence export unavailable")
    end
  end

  defp manifest_bytes(conn, id, offset, parts) when offset <= 16_777_216 do
    with {:ok, part} <- download(conn, id, "manifest.json", offset),
         true <- part.size <= 16_777_216,
         {:ok, bytes} <- Base.decode64(part.data),
         true <- part.next_offset == offset + byte_size(bytes) do
      cond do
        part.done -> {:ok, IO.iodata_to_binary(Enum.reverse([bytes | parts]))}
        byte_size(bytes) > 0 -> manifest_bytes(conn, id, part.next_offset, [bytes | parts])
        true -> {:error, :invalid_manifest_chunk}
      end
    end
  end

  defp manifest_bytes(_, _, _, _), do: {:error, :manifest_too_large}

  defp transfer(conn, id, path, offset) do
    with {:ok, part} <- download(conn, id, path, offset),
         {:ok, bytes} <- Base.decode64(part.data),
         {:ok, conn} <- chunk(conn, bytes) do
      if part.done, do: {:ok, conn}, else: transfer(conn, id, path, part.next_offset)
    end
  end

  defp download(conn, id, path, offset),
    do:
      Call.call(
        Config.for_endpoint(conn.private.phoenix_endpoint).scope,
        "audit.download",
        %{"bundle_id" => id, "path" => path, "offset" => offset},
        session: conn.private[:ouroboros_web_session]
      )

  defp header(path, size) do
    base =
      pad(path, 100) <>
        octal(0o600, 8) <>
        octal(0, 8) <>
        octal(0, 8) <>
        octal(size, 12) <>
        octal(0, 12) <>
        "        " <>
        "0" <>
        pad("", 100) <>
        "ustar\0" <>
        "00" <>
        pad("", 32) <> pad("", 32) <> octal(0, 8) <> octal(0, 8) <> pad("", 155) <> pad("", 12)

    checksum =
      :binary.bin_to_list(base)
      |> Enum.sum()
      |> Integer.to_string(8)
      |> String.pad_leading(6, "0")

    binary_part(base, 0, 148) <> checksum <> <<0, 32>> <> binary_part(base, 156, 356)
  end

  defp octal(n, width), do: String.pad_leading(Integer.to_string(n, 8), width - 1, "0") <> <<0>>
  defp pad(s, width), do: s <> :binary.copy(<<0>>, width - byte_size(s))
end
