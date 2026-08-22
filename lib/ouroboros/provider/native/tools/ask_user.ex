defmodule Ouroboros.Provider.Native.Tools.AskUser do
  @moduledoc """
  Ask the operator a question mid-turn and wait for the answer.

  Every leader has this tool — Claude Code's `AskUserQuestion`, OpenCode's `question`,
  Cline's `ask_question`, Factory's `AskUser` (R3 §1.1) — and all of them exist for the
  same reason: a model that guesses at an ambiguous requirement spends a turn being
  wrong, and a model that asks spends a second.

  ## Why it is not an ordinary tool

  It has no effect and needs no permission, but it must *block* until a human answers,
  and the only thing in this provider that can block on a human is the approval path:
  the loop emits `approval_requested` and waits on its own mailbox for
  `{:native_approval, id, response}`. So this tool does not run in the tool task at all.
  The loop recognises it by `interactive?/0`, builds the payload from `question/1`,
  reuses the approval wait, and turns the response into a tool result with `answer/2`.

  That reuse is the point. The TUI already has a modal that renders an
  `approval_requested` and sends an `ApprovalResponse` back through
  `interactive.respond_approval`; a question carrying `kind: "question"` arrives there
  with no client change at all, and a client that has not learned about questions yet
  shows it as an approval whose approve-with-a-reason is the answer. The answer text is
  read from `provider_options["answer"]` first — where a question-aware client puts it —
  and from `reason` otherwise.

  A denial is not an error. The operator declining to answer is information the model
  should act on, and reporting it as a failed tool would only invite the same question
  again.
  """

  use Jido.Action,
    name: "ask_user",
    description:
      "Ask the operator one question and wait for their answer. Use it when a choice " <>
        "changes what you build and you cannot infer it from the workspace. Do not use " <>
        "it for anything you can find out by reading a file.",
    schema: [
      question: [type: :string, required: true, doc: "The question, in one or two sentences."],
      options: [
        type: {:list, :string},
        default: [],
        doc: "Optional suggested answers. The operator may answer with something else."
      ],
      header: [
        type: :string,
        default: "",
        doc: "A two- or three-word label for the question, shown above it."
      ]
    ]

  @max_options 8
  @max_question_bytes 2_000
  @max_option_bytes 200

  @doc "This tool is answered by the loop's approval path, not by `run/2`."
  @spec interactive?() :: boolean()
  def interactive?, do: true

  @doc """
  The `approval_requested` payload for one question, or why the call is unusable.

  Bounded here rather than at the client: a question is model-authored text on its way
  to a modal, and a modal is the one surface where an unbounded string is a denial of
  service against the person who has to read it.
  """
  @spec question(map()) :: {:ok, map()} | {:error, term()}
  def question(input) when is_map(input) do
    text = input |> Map.get("question") |> to_text()

    if text == "" do
      {:error, :empty_question}
    else
      {:ok,
       %{
         "kind" => "question",
         "question" => clip(text, @max_question_bytes),
         "header" => input |> Map.get("header") |> to_text() |> clip(80),
         "options" => options(Map.get(input, "options"))
       }}
    end
  end

  def question(_input), do: {:error, :empty_question}

  @doc "The tool result for one answered — or unanswered — question."
  @spec answer(map(), Jido.Harness.ApprovalResponse.t()) :: map()
  def answer(payload, %{decision: :approve} = response) do
    case answer_text(response) do
      "" ->
        %{
          output:
            "The operator acknowledged the question without giving an answer. " <>
              "Proceed with your best judgement and say which way you went.",
          is_error: false
        }

      text ->
        %{output: "The operator answered: #{clip(text, @max_question_bytes)}", is_error: false}
    end
    |> Map.put(:question, payload)
  end

  def answer(payload, %{decision: :deny} = response) do
    suffix =
      case answer_text(response) do
        "" -> ""
        text -> " They said: #{clip(text, @max_question_bytes)}"
      end

    %{
      output:
        "The operator declined to answer." <>
          suffix <> " Proceed with your best judgement and say which way you went.",
      is_error: false,
      question: payload
    }
  end

  @doc "The result when nobody answered before the session's approval timeout."
  @spec unanswered(map(), timeout()) :: map()
  def unanswered(payload, timeout_ms) do
    %{
      output:
        "Nobody answered the question within #{timeout_ms} ms. " <>
          "Proceed with your best judgement and say which way you went.",
      is_error: false,
      question: payload
    }
  end

  @impl true
  def run(_params, _context) do
    {:ok,
     %{
       output:
         "ask_user cannot run outside an interactive session: there is nobody to ask. " <>
           "Say what you need to know in your answer instead.",
       is_error: true
     }}
  end

  defp answer_text(response) do
    from_options =
      response
      |> Map.get(:provider_options, %{})
      |> then(fn options when is_map(options) -> options end)
      |> then(&(Map.get(&1, "answer") || Map.get(&1, :answer)))

    case to_text(from_options) do
      "" -> to_text(Map.get(response, :reason))
      text -> text
    end
  end

  defp options(list) when is_list(list) do
    list
    |> Enum.map(&to_text/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.take(@max_options)
    |> Enum.map(&clip(&1, @max_option_bytes))
  end

  defp options(_other), do: []

  defp to_text(value) when is_binary(value), do: String.trim(value)
  defp to_text(nil), do: ""
  defp to_text(value), do: value |> to_string() |> String.trim()

  defp clip(text, limit) when byte_size(text) <= limit, do: text
  defp clip(text, limit), do: binary_part(text, 0, limit) <> "…"
end
