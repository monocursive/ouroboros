defmodule Ouroboros.Web.Live.CellsTest do
  @moduledoc """
  Every cell kind, rendered from the corpus that both toolchains are locked to.

  The words are not this module's to choose — `Ouroboros.Web.Transcript` decides them and
  `Ouroboros.Web.CorpusParityTest` pins them against the Rust implementation. So this file
  asserts two different things, and keeping them apart is the point:

    * **that the words reach the page.** A renderer that projected correctly and then drew
      a cell kind it did not handle would pass every parity test and show an operator
      nothing. Driving the same `event_*.json` fixtures the parity suite uses means a
      fixture added upstream fails here too, rather than rendering as a blank row.
    * **that the pixels obey the rules.** The collapse budget, the ring glyphs, the tones,
      and above all where the attention green may and may not appear.

  Fixtures are read from the checkout, exactly as `corpus_parity_test.exs` reads them, so a
  regeneration is picked up with no copy step.
  """

  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest, only: [render_component: 2]

  alias Mix.Tasks.Ouroboros.Gateway.Golden
  alias Ouroboros.Interactive.Event
  alias Ouroboros.Web.Live.Cells
  alias Ouroboros.Web.Presentation
  alias Ouroboros.Web.Transcript
  alias Ouroboros.Web.Transcript.Cell
  alias Ouroboros.Web.Transcript.Entry

  @types Map.new(
           Presentation.canonical_types() ++ [:delegation, :status],
           &{Atom.to_string(&1), &1}
         )

  @providers %{"claude_code" => :claude_code, "native" => :native}

  # ------------------------------------------------------------------------------------
  # Fixtures in, HTML out — the same decode `corpus_parity_test.exs` uses
  # ------------------------------------------------------------------------------------

  defp event(name) do
    frame = name |> Golden.path() |> File.read!() |> JSON.decode!()
    fields = get_in(frame, ["params", "event"])

    %Event{
      id: fields["id"],
      session_id: fields["session_id"] || fields["task_id"],
      sequence: fields["sequence"],
      type: Map.fetch!(@types, fields["type"]),
      timestamp: fields["timestamp"],
      payload: fields["payload"],
      harness_session_id: fields["harness_session_id"],
      provider: fields["provider"] && Map.fetch!(@providers, fields["provider"]),
      provider_session_id: fields["provider_session_id"],
      turn_id: fields["turn_id"],
      request_id: fields["request_id"]
    }
  end

  defp cells(names),
    do: names |> Enum.map(&%Entry.Event{event: event(&1)}) |> Transcript.project()

  defp paint(cell, opts \\ []) do
    render_component(&Cells.cell/1,
      cell: cell,
      index: Keyword.get(opts, :index, 0),
      expanded: Keyword.get(opts, :expanded, MapSet.new()),
      plane: Keyword.get(opts, :plane, :interactive),
      session_id: Keyword.get(opts, :session_id, "sess-1")
    )
  end

  # Every cell one run of fixtures projects to, drawn, as one string.
  defp draw(names, opts \\ []) do
    names
    |> cells()
    |> Enum.with_index()
    |> Enum.map_join("\n", fn {cell, index} ->
      paint(cell, Keyword.put(opts, :index, index))
    end)
  end

  # ------------------------------------------------------------------------------------
  # The corpus, every fixture of it
  # ------------------------------------------------------------------------------------

  describe "the whole corpus" do
    # `Golden.fixtures/0` is a plain list of `{name, document}`, which is what makes this
    # loop grow on its own when a fixture lands upstream.
    @event_fixtures Golden.fixtures()
                    |> Enum.map(&elem(&1, 0))
                    |> Enum.filter(&String.starts_with?(&1, "event_"))

    test "every event fixture projects and draws without raising" do
      # The blank-row test. A cell kind this module forgot to handle raises a
      # FunctionClauseError here rather than shipping an empty frame to an operator.
      for name <- @event_fixtures do
        html = draw([name])

        assert is_binary(html), "#{name} did not render"
      end
    end

    test "the corpus is not empty, so the loop above is not vacuous" do
      assert length(@event_fixtures) > 25
    end
  end

  # ------------------------------------------------------------------------------------
  # Per kind
  # ------------------------------------------------------------------------------------

  describe "messages" do
    test "what the operator said is a bubble, right-aligned" do
      html = draw(["event_input_accepted"])

      assert html =~ "ouro-said-you"
      assert html =~ "ouro-bubble"
      refute html =~ "ouro-prose"
    end

    test "what the agent said is a reading column, rendered as markdown" do
      html = paint(%Cell.Message{speaker: :agent, text: "# Title\n\nsome **prose**"})

      assert html =~ "ouro-prose"
      assert html =~ "<h1>Title</h1>"
      assert html =~ "<strong>prose</strong>"
    end

    test "a streaming draft pulses" do
      assert paint(%Cell.Message{speaker: :agent, text: "x", streaming: true}) =~ "ouro-streaming"
      refute paint(%Cell.Message{speaker: :agent, text: "x"}) =~ "ouro-streaming"
    end

    test "the corpus's own agent text reaches the page" do
      html = draw(["event_output_text_final"])

      [%Cell.Message{text: text} | _rest] = cells(["event_output_text_final"])
      assert String.trim(text) != ""
      # Whatever the fixture says, the page says.
      assert html =~ text |> String.split("\n") |> hd() |> String.trim()
    end
  end

  describe "a message carrying an attack" do
    test "renders it inert, exactly as the sanitizer's own suite proves" do
      html =
        paint(%Cell.Message{
          speaker: :agent,
          text: "<script>alert(1)</script>\n\n[click](javascript:alert(2))"
        })

      refute html =~ "<script"
      refute html =~ "javascript:"
      # The words survive so the operator can see what the model was asked to do.
      assert html =~ "alert(1)"
      assert html =~ "click"
    end

    test "and an operator's own message is escaped by the template, not interpolated" do
      html = paint(%Cell.Message{speaker: :you, text: "<img src=x onerror=alert(1)>"})

      refute html =~ "<img"
      assert html =~ "&lt;img"
    end
  end

  describe "thinking" do
    test "draws the state the projection chose and never expands it itself" do
      assert paint(%Cell.Thinking{state: :collapsed, lines: 12}) =~ "12 lines"
      assert paint(%Cell.Thinking{state: :collapsed, lines: 1}) =~ "1 line"

      assert paint(%Cell.Thinking{state: :tail, text: "a\nb\nc\nd\ne"}) =~ "ouro-thinking-tail"
      assert paint(%Cell.Thinking{state: :full, text: "reasoned"}) =~ "reasoned"
    end

    test "the corpus's thinking delta lands as a thinking cell" do
      assert [%Cell.Thinking{}] = cells(["event_thinking_delta"])
      assert draw(["event_thinking_delta"]) =~ "ouro-thinking"
    end
  end

  describe "tool rows" do
    test "carry the summariser's verb, subject and outcome, in monospace" do
      names = ["event_tool_call_bash", "event_tool_result_bash"]
      html = draw(names)

      [%Cell.Tool{} = tool] = cells(names)
      summary = Transcript.Tools.summarise(tool)

      assert html =~ "ouro-tool-row"
      assert html =~ "ouro-tool-verb"
      assert summary.verb == "Bash"
      assert html =~ summary.verb
      assert html =~ Phoenix.HTML.html_escape(summary.subject) |> Phoenix.HTML.safe_to_string()
    end

    test "a read folds into an exploration group rather than a row of its own" do
      # Not a quirk of this renderer: `explores?/1` puts read/grep/glob/list into the
      # grouped cell, and a test that asserted a lone Read row would be asserting against
      # the projection rather than about the page.
      assert [%Cell.Exploration{}] = cells(["event_tool_call_read", "event_tool_result_read"])
    end

    test "a failed call takes the danger tone and never a colour of its own" do
      html = paint(%Cell.Tool{call_id: "c", name: "bash", state: :failed, output: "boom"})

      assert html =~ "ouro-tool-failed"
      refute html =~ "attention-green"
    end

    test "a completed call is ink, because success is not an attention state" do
      html = paint(%Cell.Tool{call_id: "c", name: "bash", state: :completed, output: "ok"})

      assert html =~ "ouro-tool-completed"
      refute html =~ "attention-green"
    end
  end

  describe "the collapse budget" do
    setup do
      {budget, head, tail} = Cells.body_budget()
      %{budget: budget, head: head, tail: tail}
    end

    test "a short body is drawn whole", %{budget: budget} do
      body = 1..budget |> Enum.map_join("\n", &"line #{&1}")
      html = paint(%Cell.Tool{call_id: "c", name: "bash", state: :completed, output: body})

      assert html =~ "line 1"
      assert html =~ "line #{budget}"
      refute html =~ "ouro-fold"
    end

    test "a long body folds head and tail, and says how much it hid", ctx do
      %{budget: budget, head: head, tail: tail} = ctx
      count = budget + 20
      body = 1..count |> Enum.map_join("\n", &"line #{&1}")

      html = paint(%Cell.Tool{call_id: "c17", name: "bash", state: :completed, output: body})

      assert html =~ "line #{head}"
      refute html =~ "line #{head + 1}\n"
      # The tail matters as much as the head: the end of a command's output is where its
      # verdict is, and a fold that hid it would hide the reason anyone opened the block.
      assert html =~ "line #{count}"
      assert html =~ "line #{count - tail + 1}"
      assert html =~ "#{count - head - tail} more lines"
    end

    test "the toggle is keyed by call_id, so a poll cannot close what a reader opened" do
      body = 1..40 |> Enum.map_join("\n", &"line #{&1}")
      cell = %Cell.Tool{call_id: "call-abc", name: "bash", state: :completed, output: body}

      folded = paint(cell, index: 3)
      assert folded =~ ~s(phx-value-block="tool:call-abc")

      opened = paint(cell, index: 99, expanded: MapSet.new(["tool:call-abc"]))
      assert opened =~ "line 20"
      assert opened =~ "fold 40 lines"
    end
  end

  describe "exploration" do
    test "is one folded row that says how many calls it stands for" do
      cell = %Cell.Exploration{
        calls: [
          %Cell.Tool{call_id: "a", name: "read", state: :completed},
          %Cell.Tool{call_id: "b", name: "grep", state: :failed}
        ],
        overflow: 6,
        done: true
      }

      html = paint(cell, index: 4)

      assert html =~ "Explored"
      assert html =~ "8 calls"
      assert html =~ "1 failed"
      # Folded: the individual calls are not drawn until asked for.
      refute html =~ "ouro-explore-calls"

      opened = paint(cell, index: 4, expanded: MapSet.new(["explore:4"]))
      assert opened =~ "ouro-explore-calls"
      assert opened =~ "and 6 more not listed"
    end
  end

  describe "diffs" do
    test "draw a file header with counted additions and deletions" do
      html = draw(["event_file_change"])

      assert html =~ "ouro-diff-file"
      assert html =~ "ouro-diff-head"
      assert html =~ "ouro-diff-plus"

      # The number drawn is the parse's, not the provider's claim.
      [%Cell.Diff{parsed: parsed} | _rest] =
        cells(["event_file_change"]) |> Enum.filter(&match?(%Cell.Diff{}, &1))

      file = hd(parsed.files)
      assert html =~ "+#{file.additions}"
      assert html =~ "−#{file.deletions}"
      assert html =~ file.path
    end

    test "hunk lines carry gutters and their own tone" do
      html = draw(["event_file_change"])

      assert html =~ "ouro-line-added"
      assert html =~ "ouro-gutter-old"
      assert html =~ "ouro-gutter-new"
    end

    test "an addition is a neutral emphasis and never the attention green" do
      html = draw(["event_file_change"])

      refute html =~ "attention-green"
      assert html =~ "ouro-line-added"
    end

    test "a diffstat says files and counts at a turn boundary" do
      html = paint(%Cell.DiffStat{files: 3, additions: 120, deletions: 18})

      assert html =~ "3 files"
      assert html =~ "+120"
      assert html =~ "−18"
    end
  end

  describe "plans" do
    test "draw a glyph per step, and say how many they left out" do
      html = draw(["event_plan_updated"])

      assert html =~ "ouro-plan-steps"
      assert html =~ "ouro-step-glyph"

      [%Cell.Plan{plan: plan}] = cells(["event_plan_updated"])

      for step <- plan.steps do
        assert html =~ step.text
      end
    end

    test "a completed step is ink, struck through — not green" do
      html =
        paint(%Cell.Plan{
          plan: %Presentation.PlanUpdate{
            steps: [%Presentation.PlanStep{text: "done thing", status: :completed}],
            step_count: 1
          }
        })

      assert html =~ "ouro-step-completed"
      refute html =~ "attention-green"
    end
  end

  describe "usage" do
    test "is a quiet monospace row" do
      html = draw(["event_usage"])

      assert html =~ "ouro-usage"

      [%Cell.Usage{usage: usage}] = cells(["event_usage"])
      if usage.total_tokens, do: assert(html =~ "#{usage.total_tokens} total")
    end
  end

  describe "subagents" do
    test "fold to one row per task_id, with the node badge only when remote" do
      cell = %Cell.Subagent{
        task_id: "t-1",
        description: "review the diff",
        settled: true,
        status: "completed",
        turns: 3
      }

      html = paint(cell)

      assert html =~ "Subagent review the diff"
      assert html =~ "completed"
      assert html =~ ~s(phx-value-block="subagent:t-1")
      # Local: no machine badge, because "it ran here" is not news.
      refute html =~ "⇄"

      remote = paint(%{cell | remote: true, node: "core@two"})
      assert remote =~ "⇄ core@two"
    end

    test "a failed child takes the error tone, a completed one takes ink" do
      failed = paint(%Cell.Subagent{task_id: "t", settled: true, status: "failed"})
      done = paint(%Cell.Subagent{task_id: "t", settled: true, status: "completed"})

      assert failed =~ "ouro-tone-error"
      assert done =~ "ouro-tone-success"
      refute done =~ "attention-green"
    end

    test "the corpus's subagent event reaches the page" do
      html = draw(["event_provider_event_subagent"])

      assert html =~ "ouro-subagent"
    end
  end

  describe "status rows, notes and dividers" do
    test "carry the projection's tone as a class" do
      assert paint(%Cell.Status{label: "Denied", tone: :error}) =~ "ouro-tone-error"
      assert paint(%Cell.Status{label: "Approved", tone: :success}) =~ "ouro-tone-success"
      assert paint(%Cell.Divider{text: "turn ended", kind: :turn_end}) =~ "ouro-divider-turn_end"
    end

    test "a success row is ink — the green is never a verdict" do
      refute paint(%Cell.Status{label: "Approved", tone: :success}) =~ "attention-green"
    end

    test "an approval request from the corpus renders its words" do
      html = draw(["event_approval_requested_permission"])

      [%Cell.Status{label: label} | _rest] =
        cells(["event_approval_requested_permission"]) |> Enum.filter(&match?(%Cell.Status{}, &1))

      assert html =~ label
    end

    test "a provider event nobody modelled is still a visible note" do
      html = draw(["event_provider_event_unknown"])

      assert html =~ "provider event"
    end
  end

  describe "runtime blocks" do
    test "draw their label, detail and body" do
      html = draw(["event_provider_event_operator_shell"])

      assert html =~ "ouro-runtime"
    end

    test "a delegation is a runtime block, not a message" do
      html = draw(["event_delegation"])

      assert html =~ "ouro-runtime" or html =~ "ouro-subagent"
    end
  end

  describe "images" do
    test "a sha-addressed artifact is an img pointing at the controller route" do
      cell = %Cell.Image{
        named: "desktop capture · abc",
        sha: String.duplicate("a", 64),
        media_type: "image/png",
        pixels: {800, 600},
        format: "png"
      }

      html = paint(cell, plane: :interactive, session_id: "sess-9")

      assert html =~ ~s(src="/artifact/interactive/sess-9/#{String.duplicate("a", 64)}")
      assert html =~ ~s(width="800")
      assert html =~ ~s(loading="lazy")
      # The label is the alt text, not a caption under a picture the reader can see.
      assert html =~ "alt="
      refute html =~ "figcaption"
    end

    test "an image with no digest to fetch by says what it was instead of showing a hole" do
      html = paint(%Cell.Image{named: "a picture", pixels: {10, 10}, format: "png"})

      refute html =~ "<img"
      assert html =~ "figcaption"
      assert html =~ "a picture"
    end

    test "the corpus's computer-use result produces something drawable" do
      html = draw(["event_tool_result_computer_use"])

      assert is_binary(html)
    end
  end

  describe "files and command output" do
    test "a file row names its path and what happened to it" do
      html = paint(%Cell.File{path: "lib/a.ex", kind: "modified"})

      assert html =~ "lib/a.ex"
      assert html =~ "modified"
    end

    test "command output is a monospace block on the same budget" do
      html = paint(%Cell.CommandOutput{text: "hello\nworld"})

      assert html =~ "ouro-command"
      assert html =~ "ouro-body-text"
      assert html =~ "hello"
    end
  end
end
