defmodule Ouroboros.Test.BrowserModel do
  @moduledoc "Deterministic model used only by browser acceptance journeys."
  @behaviour Ouroboros.Provider.Native.Model
  def available?, do: true
  def credential_report, do: []

  def stream(request, _opts) do
    prompt =
      request.messages |> Enum.reverse() |> Enum.find(&(&1.role == :user)) |> Map.fetch!(:content)

    image_count =
      if is_list(prompt), do: Enum.count(prompt, &(Map.get(&1, :type) == :image)), else: 0

    prompt = if is_binary(prompt), do: prompt, else: inspect(prompt)
    after_tool? = List.last(request.messages).role == :tool

    cond do
      image_count > 0 ->
        {:ok,
         [{:text, "Received #{image_count} image(s); model=#{request.model}."}, {:finish, :stop}]}

      String.contains?(prompt, "browser private failure") ->
        {:ok,
         Stream.map([:text, :fail], fn phase ->
           cause =
             ReqLLM.Error.API.Request.exception(
               status: 429,
               provider_code: "rate_limit_exceeded",
               retryable: true,
               reason: "SYNTH_BROWSER_SECRET",
               headers: [{"authorization", "SYNTH_BROWSER_SECRET"}]
             )

           if phase == :fail,
             do: raise(%ReqLLM.Error.API.Stream{reason: "SYNTH_BROWSER_SECRET", cause: cause}),
             else: {:text, "Partial response before failure. "}
         end)}

      String.contains?(prompt, "first-use request proof") ->
        {:ok,
         [
           {:text, "Requested model=#{request.model}; reasoning=#{request.reasoning_effort}"},
           {:finish, :stop}
         ]}

      after_tool? ->
        {:ok, [{:text, "Browser approval completed."}, {:finish, :stop}]}

      String.contains?(prompt, "browser patch approval") ->
        {:ok,
         [
           {:tool_call,
            %{
              id: "browser-patch-" <> request.turn_id,
              name: "apply_patch",
              input: %{
                "patch" =>
                  "*** Begin Patch\n*** Add File: browser-patch-proof.txt\n" <>
                    "+<script>review me, never execute me</script>\n*** End Patch"
              }
            }},
           {:finish, :tool_calls}
         ]}

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

defmodule Ouroboros.Test.BrowserAccount do
  @moduledoc false
  def read do
    {:ok,
     %{
       "account" => %{"type" => "chatgpt"},
       "requiresOpenaiAuth" => false,
       "login" => %{"status" => "idle"}
     }}
  end
end
