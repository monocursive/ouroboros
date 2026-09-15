defmodule Ouroboros.Web.Live.ImageAttachments do
  @moduledoc "Browser image drafts use the same bounded, authenticated calls as the TUI."
  use Phoenix.Component
  alias Ouroboros.Web.Call

  @operations ~w(limits begin append finish status discard touch_draft)

  def action(socket, params, key, node, session_id) do
    with %{"key" => ^key, "operation" => op, "params" => args} <- params,
         true <- op in @operations and is_map(args) do
      args =
        if op == "append",
          do: args |> Map.put("data", args["image_data"]) |> Map.delete("image_data"),
          else: args

      args = args |> Map.delete("node") |> Map.delete("session_id")
      args = if node in [nil, ""], do: args, else: Map.put(args, "node", node)

      args =
        if session_id && op in ["begin", "status"],
          do: Map.put(args, "session_id", session_id),
          else: args

      case Call.call(socket.assigns.scope, "attachment." <> op, args,
             session: socket.assigns[:web_session]
           ) do
        {:ok, result} -> %{ok: Ouroboros.Gateway.Wire.to_json(result)}
        {:error, _, message, _} -> %{error: message}
        {:error, _, message} -> %{error: message}
      end
    else
      _ -> %{error: "The image draft changed. Return to its conversation to continue."}
    end
  end

  def refs(params) do
    case JSON.decode(Map.get(params, "images_json", "[]")) do
      {:ok, refs} when is_list(refs) and length(refs) <= 32 ->
        if Enum.all?(refs, fn
             %{"id" => id} = ref when map_size(ref) == 1 and is_binary(id) ->
               Regex.match?(~r/^att_[A-Za-z0-9_-]{32}$/, id)

             _ ->
               false
           end), do: {:ok, refs}, else: {:error, "Invalid image attachment."}

      _ ->
        {:error, "Invalid image attachment list."}
    end
  end

  def bind(socket, params, session_id, node) do
    with {:ok, refs} <- refs(params) do
      if refs == [] do
        {:ok, []}
      else
        args = %{"draft_id" => params["images_draft"], "session_id" => session_id}
        args = if node in [nil, ""], do: args, else: Map.put(args, "node", node)

        case Call.call(socket.assigns.scope, "attachment.bind_draft", args) do
          {:ok, _} -> {:ok, refs}
          {:error, _, message, _} -> {:error, message}
          {:error, _, message} -> {:error, message}
        end
      end
    end
  end

  attr :id, :string, default: "image-draft"
  attr :draft_key, :string, required: true
  attr :node, :any, default: nil
  attr :session_id, :any, default: nil
  attr :locked, :boolean, default: false

  def tray(assigns) do
    ~H"""
    <div
      id={@id}
      phx-hook="ImageAttachments"
      phx-update="ignore"
      class="ouro-image-draft"
      data-draft-key={@draft_key}
      data-locked={to_string(@locked)}
      data-node={@node}
      data-session-id={@session_id}
    >
      <input type="hidden" name="images_json" value="[]" />
      <input type="hidden" name="images_draft" value="" />
      <div class="ouro-image-tray" role="list" aria-label="Attached images"></div>
      <button type="button" class="ouro-quiet-button" data-attach disabled>Attach images</button>
      <input
        type="file"
        accept="image/png,image/jpeg,image/webp,image/gif"
        multiple
        hidden
        data-image-picker
      />
      <span class="ouro-image-hint" role="status" aria-live="polite">Checking image support…</span>
    </div>
    """
  end

  def url(id, variant, session_id \\ nil, node \\ nil) do
    query =
      %{"session_id" => session_id, "node" => node}
      |> Enum.reject(fn {_, value} -> value in [nil, ""] end)
      |> URI.encode_query()

    "/attachments/" <> URI.encode(id, &URI.char_unreserved?/1) <> "/" <> variant <> "?" <> query
  end
end
