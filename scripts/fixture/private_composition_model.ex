defmodule Ouroboros.PrivateComposition.Model do
  @moduledoc false
  @behaviour Ouroboros.Provider.Native.Model
  @prefix "private-composition:"

  @impl true
  def stream(request, _opts) do
    with @prefix <> dir <- request.model,
         prompt when is_binary(prompt) <- latest_user(request.messages),
         {:ok, index} <- read(Path.join(dir, "index.json")),
         %{"script" => script} <-
           index["entries"]
           |> Enum.filter(&String.contains?(prompt, &1["instruction"]))
           |> Enum.max_by(&byte_size(&1["instruction"]), fn -> nil end),
         {:ok, body} <- read(Path.join(dir, script)) do
      {:ok,
       body["responses"] |> Enum.at(call_index(request.messages), []) |> Enum.flat_map(&chunk/1)}
    else
      other -> {:error, {:private_composition_script, inspect(other)}}
    end
  end

  @impl true
  def available?, do: true

  @impl true
  def credential_report,
    do: [%{provider: :private_composition, env: "OUROBOROS_NATIVE_MODEL", present: true}]

  defp latest_user(messages) do
    messages
    |> Enum.reverse()
    |> Enum.find_value(fn message ->
      role = Map.get(message, :role) || Map.get(message, "role")
      if role in [:user, "user"], do: Map.get(message, :content) || Map.get(message, "content")
    end)
  end

  defp call_index(messages) do
    messages
    |> Enum.reverse()
    |> Enum.take_while(fn message ->
      (Map.get(message, :role) || Map.get(message, "role")) not in [:user, "user"]
    end)
    |> Enum.count(fn message ->
      (Map.get(message, :role) || Map.get(message, "role")) in [:assistant, "assistant"]
    end)
  end

  defp chunk(%{"type" => "text", "text" => text}), do: [{:text, text}]

  defp chunk(%{"type" => "tool_call", "id" => id, "name" => name, "input" => input}),
    do: [{:tool_call, %{id: id, name: name, input: input}}]

  defp chunk(%{"type" => "usage"} = usage) do
    counts =
      usage
      |> Map.delete("type")
      |> Enum.map(fn {key, value} -> {String.to_atom(key), value} end)
      |> Map.new()

    [{:usage, counts}]
  end

  defp chunk(%{"type" => "finish", "reason" => reason}), do: [{:finish, String.to_atom(reason)}]
  defp chunk(_), do: []

  defp read(path) do
    with {:ok, %File.Stat{size: size}} when size <= 1_048_576 <- File.stat(path),
         {:ok, body} <- File.read(path),
         {:ok, decoded} when is_map(decoded) <- JSON.decode(body),
         do: {:ok, decoded}
  end
end
