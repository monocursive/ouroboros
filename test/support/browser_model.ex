defmodule Ouroboros.Test.BrowserModel do
  @moduledoc "Deterministic model used only by browser acceptance journeys."
  @behaviour Ouroboros.Provider.Native.Model
  def available?, do: true
  def credential_report, do: []

  def stream(request, _opts) do
    prompt =
      request.messages |> Enum.reverse() |> Enum.find(&(&1.role == :user)) |> Map.fetch!(:content)

    prompt = if is_binary(prompt), do: prompt, else: inspect(prompt)
    after_tool? = List.last(request.messages).role == :tool

    cond do
      after_tool? ->
        {:ok, [{:text, "Browser approval completed."}, {:finish, :stop}]}

      String.contains?(prompt, "browser approval") ->
        {:ok,
         [
           {:tool_call,
            %{
              id: "browser-write-" <> request.turn_id,
              name: "write",
              input: %{"path" => "browser-proof.txt", "content" => "Approved browser proof.\n"}
            }},
           {:finish, :tool_calls}
         ]}

      String.contains?(prompt, "browser interrupt") ->
        {:ok, controlled_stream(List.duplicate("Working on the interrupt proof. ", 100), 100)}

      true ->
        {:ok, controlled_stream(["Streaming ", "proof ", "complete."], 250)}
    end
  end

  defp controlled_stream(chunks, delay) do
    Stream.resource(
      fn -> chunks end,
      fn
        [] ->
          {:halt, []}

        [chunk | rest] ->
          receive do
            :native_interrupt ->
              send(self(), :native_interrupt)
              {[{:finish, :stop}], []}
          after
            delay -> {[{:text, chunk}], rest}
          end
      end,
      fn _ -> :ok end
    )
  end
end
