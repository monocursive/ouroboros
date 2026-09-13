defmodule Ouroboros.Web.Launch do
  @moduledoc """
  Invocation-local browser project context. A link seeds one form, never daemon cwd
  or stored preferences. Authentication still precedes the fixed local redirect;
  directory existence and workspace admission remain the start boundary's job.
  """

  @spec workspace(term()) :: {:ok, String.t()} | :error
  def workspace(path) when is_binary(path) and byte_size(path) in 1..4096 do
    if String.valid?(path) and Path.type(path) == :absolute and
         not String.contains?(path, [<<0>>, "\r", "\n"]),
       do: {:ok, path},
       else: :error
  end

  def workspace(_), do: :error

  @spec destination(map()) :: String.t()
  def destination(params) do
    if Map.has_key?(params, "workspace") do
      # Invalid context must not silently fall back to a saved, unrelated project.
      path =
        case workspace(params["workspace"]) do
          {:ok, path} -> path
          :error -> ""
        end

      "/new?" <> URI.encode_query(%{"workspace" => path})
    else
      "/"
    end
  end
end
