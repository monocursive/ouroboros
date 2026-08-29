defmodule Ouroboros.Web.Presentation.Hidden do
  @moduledoc """
  Why a presentation drew nothing.

  Every value here is a payload that carried no content, never a *kind* this surface
  declines to show (`tui/src/model/transcript.rs:126-146`).
  """

  defstruct [:reason]

  @type reason :: :empty_text | :empty_thinking | :empty_command_output
  @type t :: %__MODULE__{reason: reason()}

  @doc "The sentence a hidden presentation gives for drawing nothing."
  @spec reason(t() | reason()) :: String.t()
  def reason(%__MODULE__{reason: reason}), do: reason(reason)
  def reason(:empty_text), do: "an output event carrying no text"
  def reason(:empty_thinking), do: "a reasoning delta carrying no text"
  def reason(:empty_command_output), do: "a command-output delta carrying no bytes"
end

defmodule Ouroboros.Web.Presentation.Lifecycle do
  @moduledoc "A lifecycle fact that belongs in the reading path as one dim line."

  defstruct [:marker, detail: ""]

  @type marker ::
          :run_completed
          | :session_started
          | :session_ready
          | :session_idle
          | :session_closed
          | :turn_queued
  @type t :: %__MODULE__{marker: marker(), detail: String.t()}

  @doc "The words one lifecycle marker renders as."
  @spec label(t() | marker()) :: String.t()
  def label(%__MODULE__{marker: marker}), do: label(marker)
  def label(:run_completed), do: "run finished"
  def label(:session_started), do: "session started"
  def label(:session_ready), do: "session ready"
  def label(:session_idle), do: "session idle"
  def label(:session_closed), do: "session closed"
  def label(:turn_queued), do: "turn queued"
end

defmodule Ouroboros.Web.Presentation.PlanStatus do
  @moduledoc """
  One plan step's status, with an unrecognised word kept verbatim.

  Guessing that an unknown status meant "done" is how a panel reports finished work
  that never happened (`tui/src/model/transcript.rs:235-281`).
  """

  @pending ~w(pending todo not_started notstarted queued planned)
  @in_progress ~w(in_progress inprogress in-progress running active started)
  @done ~w(completed complete done finished succeeded)

  @type t :: :pending | :in_progress | :done | {:other, String.t()}

  @doc "Reads a provider's status word, keeping an unknown one as `{:other, word}`."
  @spec parse(String.t() | nil) :: t()
  def parse(nil), do: :pending

  def parse(status) when is_binary(status) do
    trimmed = String.trim(status)

    cond do
      trimmed == "" -> :pending
      String.downcase(trimmed, :ascii) in @pending -> :pending
      String.downcase(trimmed, :ascii) in @in_progress -> :in_progress
      String.downcase(trimmed, :ascii) in @done -> :done
      true -> {:other, trimmed}
    end
  end

  @doc "Warp's plan glyphs: `◌` pending, `●` in progress, `✓` done."
  @spec glyph(t()) :: String.t()
  def glyph(:pending), do: "◌"
  def glyph(:in_progress), do: "●"
  def glyph(:done), do: "✓"
  def glyph({:other, _word}), do: "?"

  @doc "The status as a word a reader can see."
  @spec label(t()) :: String.t()
  def label(:pending), do: "pending"
  def label(:in_progress), do: "in progress"
  def label(:done), do: "done"
  def label({:other, word}), do: word
end

defmodule Ouroboros.Web.Presentation.PlanStep do
  @moduledoc "One step of a model-authored plan."

  alias Ouroboros.Web.Presentation.PlanStatus

  defstruct [:text, :priority, status: :pending]

  @type t :: %__MODULE__{
          text: String.t(),
          status: PlanStatus.t(),
          priority: String.t() | nil
        }
end

defmodule Ouroboros.Web.Presentation.ImageArtifact do
  @moduledoc """
  One image a tool result staged, described but not carried.

  Metadata only: the sha that names it, the media type, the staged byte count, and the
  pixel dimensions. The bytes never travel on the event
  (`tui/src/model/transcript.rs:311-332`).
  """

  defstruct [:sha256, :media_type, :size, :width, :height]

  @type t :: %__MODULE__{
          sha256: String.t(),
          media_type: String.t() | nil,
          size: non_neg_integer() | nil,
          width: non_neg_integer() | nil,
          height: non_neg_integer() | nil
        }
end

defmodule Ouroboros.Web.Presentation.Diff do
  @moduledoc """
  One unified diff as the presentation holds it.

  `additions`/`deletions` here are the cheap prefix scan the presentation does while
  bounding the text. The numbers a surface *prints* come from
  `Ouroboros.Web.Transcript.Diff.parse/2`, which counts them from hunk bodies
  (`tui/src/ui/diff.rs:14-21`).
  """

  defstruct [:text, :path, additions: 0, deletions: 0, truncated: false]

  @type t :: %__MODULE__{
          text: String.t(),
          path: String.t() | nil,
          additions: non_neg_integer(),
          deletions: non_neg_integer(),
          truncated: boolean()
        }
end

defmodule Ouroboros.Web.Presentation.FileChange do
  @moduledoc "One file a `file_change` event named."

  alias Ouroboros.Web.Presentation.Diff

  defstruct [:path, :kind, :diff]

  @type t :: %__MODULE__{
          path: String.t() | nil,
          kind: String.t() | nil,
          diff: Diff.t() | nil
        }
end

defmodule Ouroboros.Web.Presentation.Worktree do
  @moduledoc "The `git worktree` a session or a child agent was given."

  defstruct [:path, :root, :branch, :base_commit, :repository, :retired]

  @type t :: %__MODULE__{
          path: String.t() | nil,
          root: String.t() | nil,
          branch: String.t() | nil,
          base_commit: String.t() | nil,
          repository: String.t() | nil,
          retired: String.t() | nil
        }

  @doc """
  What the badge says: the branch, the detached base commit's short form, or the bare
  word — never a path (`tui/src/model/native.rs:123-129`).
  """
  @spec label(t()) :: String.t()
  def label(%__MODULE__{branch: branch}) when is_binary(branch), do: branch

  def label(%__MODULE__{branch: nil, base_commit: commit}) when is_binary(commit),
    do: String.slice(commit, 0, 8)

  def label(%__MODULE__{}), do: "worktree"

  @doc "Whether the runtime has not retired this worktree."
  @spec live?(t()) :: boolean()
  def live?(%__MODULE__{retired: retired}), do: is_nil(retired)
end

defmodule Ouroboros.Web.Presentation.ShellEvent do
  @moduledoc "The `operator_shell` half of a `provider_event` payload (B7)."

  defstruct [
    :effect_id,
    :command_digest,
    :exit_status,
    :duration_ms,
    :output_bytes,
    :output_excerpt,
    :spilled,
    :error,
    timed_out: false
  ]

  @type t :: %__MODULE__{
          effect_id: String.t() | nil,
          command_digest: String.t() | nil,
          exit_status: integer() | nil,
          duration_ms: non_neg_integer() | nil,
          timed_out: boolean(),
          output_bytes: non_neg_integer() | nil,
          output_excerpt: String.t() | nil,
          spilled: String.t() | nil,
          error: String.t() | nil
        }
end

defmodule Ouroboros.Web.Presentation.Compaction do
  @moduledoc "One fold of a conversation, automatic or asked for (D9)."

  defstruct [
    :trigger,
    :turn,
    :archived_messages,
    :archive_id,
    :elided_tool_results,
    :summary_tokens,
    :before_tokens,
    :after_tokens,
    :summarised
  ]

  @type t :: %__MODULE__{
          trigger: String.t() | nil,
          turn: non_neg_integer() | nil,
          archived_messages: non_neg_integer() | nil,
          archive_id: String.t() | nil,
          elided_tool_results: non_neg_integer() | nil,
          summary_tokens: non_neg_integer() | nil,
          before_tokens: non_neg_integer() | nil,
          after_tokens: non_neg_integer() | nil,
          summarised: boolean() | nil
        }

  @doc """
  One line for a transcript note, carrying only the numbers the report itself carried
  (`tui/src/model/native.rs:192-225`).
  """
  @spec describe(t()) :: String.t()
  def describe(%__MODULE__{} = report) do
    parts =
      []
      |> plural(report.archived_messages, "archived", "message")
      |> plural(report.elided_tool_results, "elided", "tool result")
      |> tokens(report.before_tokens, report.after_tokens)
      |> archive(report.archive_id)
      |> Enum.reverse()

    case parts do
      [] -> "the conversation was folded"
      parts -> Enum.join(parts, " · ")
    end
  end

  defp plural(parts, count, verb, noun) when is_integer(count) and count > 0 do
    ["#{verb} #{count} #{noun}#{if count == 1, do: "", else: "s"}" | parts]
  end

  defp plural(parts, _count, _verb, _noun), do: parts

  defp tokens(parts, before, nil) when is_integer(before), do: ["#{before} tokens before" | parts]
  defp tokens(parts, nil, later) when is_integer(later), do: ["#{later} tokens after" | parts]

  defp tokens(parts, before, later) when is_integer(before) and is_integer(later),
    do: ["#{before} → #{later} tokens" | parts]

  defp tokens(parts, _before, _later), do: parts

  defp archive(parts, id) when is_binary(id), do: ["archive #{id}" | parts]
  defp archive(parts, _id), do: parts
end

defmodule Ouroboros.Web.Presentation.DelegationEvent do
  @moduledoc "A `delegation` event's payload, as the parent's transcript carries it (G1)."

  defstruct [
    :delegation_id,
    :task_id,
    :task_node,
    :team_id,
    :objective_digest,
    :status,
    :result_digest
  ]

  @type t :: %__MODULE__{
          delegation_id: String.t() | nil,
          task_id: String.t() | nil,
          task_node: String.t() | nil,
          team_id: String.t() | nil,
          objective_digest: String.t() | nil,
          status: String.t() | nil,
          result_digest: String.t() | nil
        }
end

defmodule Ouroboros.Web.Presentation.SubagentEvent do
  @moduledoc """
  One `provider_event` whose `kind` is `subagent`: a child agent spawning, reporting, or
  settling in the parent's own transcript.

  Every field is optional and every default is the honest one — an absent `remote` means
  the child ran here, not that its placement is unknown
  (`tui/src/model/native.rs:849-940`).
  """

  alias Ouroboros.Web.Presentation.Worktree

  defstruct [
    :phase,
    :task_id,
    :description,
    :provider_session_id,
    :node,
    :workspace,
    :worktree_detail,
    :depth,
    :max_turns,
    :deadline_ms,
    :turns,
    :tool_calls,
    :files_changed,
    :status,
    :input_tokens,
    :output_tokens,
    :approvals_denied,
    :summary_bytes,
    :cost_usd,
    :error,
    remote: false,
    worktree: false,
    background: false,
    tools: [],
    files: []
  ]

  @type phase :: :spawned | :progress | :settled | {:other, String.t()}
  @type t :: %__MODULE__{
          phase: phase() | nil,
          task_id: String.t() | nil,
          description: String.t() | nil,
          provider_session_id: String.t() | nil,
          node: String.t() | nil,
          remote: boolean(),
          workspace: String.t() | nil,
          worktree: boolean(),
          worktree_detail: Worktree.t() | nil,
          tools: [String.t()],
          background: boolean(),
          depth: non_neg_integer() | nil,
          max_turns: non_neg_integer() | nil,
          deadline_ms: non_neg_integer() | nil,
          turns: non_neg_integer() | nil,
          tool_calls: non_neg_integer() | nil,
          files_changed: non_neg_integer() | nil,
          files: [String.t()],
          status: String.t() | nil,
          input_tokens: non_neg_integer() | nil,
          output_tokens: non_neg_integer() | nil,
          approvals_denied: non_neg_integer() | nil,
          summary_bytes: non_neg_integer() | nil,
          cost_usd: float() | nil,
          error: String.t() | nil
        }

  @doc "The phase this event reports, with `{:other, \"\"}` for one that named none."
  @spec phase(t()) :: phase()
  def phase(%__MODULE__{phase: nil}), do: {:other, ""}
  def phase(%__MODULE__{phase: phase}), do: phase

  @doc "Whether the runtime says this child has finished."
  @spec settled?(phase()) :: boolean()
  def settled?(:settled), do: true
  def settled?(_phase), do: false
end

defmodule Ouroboros.Web.Presentation.UserMessage do
  @moduledoc "An accepted input this ledger holds the words of."
  defstruct [:text]
  @type t :: %__MODULE__{text: String.t()}
end

defmodule Ouroboros.Web.Presentation.UserSteer do
  @moduledoc """
  A steer. The text is optional because a checkpointed event from before the runtime
  carried it, and every recovered turn, arrives without one.
  """
  defstruct [:text]
  @type t :: %__MODULE__{text: String.t() | nil}
end

defmodule Ouroboros.Web.Presentation.UnrecordedInput do
  @moduledoc """
  An accepted input whose words this ledger does not hold. Named rather than dropped: a
  chat that silently omits a turn the operator remembers typing is a chat that cannot be
  trusted about the turns it does show.
  """
  defstruct []
  @type t :: %__MODULE__{}
end

defmodule Ouroboros.Web.Presentation.AgentText do
  @moduledoc "One output delta or final."
  defstruct [:turn_id, :text, final_text: false]

  @type t :: %__MODULE__{
          turn_id: String.t() | nil,
          text: String.t(),
          final_text: boolean()
        }
end

defmodule Ouroboros.Web.Presentation.Thinking do
  @moduledoc "Reasoning the provider chose to publish. Never treated as the agent's answer."
  defstruct [:turn_id, :text]
  @type t :: %__MODULE__{turn_id: String.t() | nil, text: String.t()}
end

defmodule Ouroboros.Web.Presentation.ToolCall do
  @moduledoc "One normalized tool call."

  defstruct [:call_id, :kind, :at, name: "tool", input: %{}]

  @type t :: %__MODULE__{
          call_id: String.t() | nil,
          name: String.t(),
          kind: String.t() | nil,
          input: term(),
          at: integer() | nil
        }
end

defmodule Ouroboros.Web.Presentation.ToolResult do
  @moduledoc "One normalized tool result, with any image artifacts it staged."

  alias Ouroboros.Web.Presentation.ImageArtifact

  defstruct [:call_id, :name, :kind, :output, :at, is_error: false, artifacts: []]

  @type t :: %__MODULE__{
          call_id: String.t() | nil,
          name: String.t() | nil,
          kind: String.t() | nil,
          output: term(),
          is_error: boolean(),
          at: integer() | nil,
          artifacts: [ImageArtifact.t()]
        }
end

defmodule Ouroboros.Web.Presentation.CommandOutput do
  @moduledoc "One command-output delta carrying bytes."
  defstruct [:text]
  @type t :: %__MODULE__{text: String.t()}
end

defmodule Ouroboros.Web.Presentation.FileUpdate do
  @moduledoc "One `file_change` event: the files it named and the patch it carried."

  alias Ouroboros.Web.Presentation.{Diff, FileChange}

  defstruct [:status, :diff, changes: []]

  @type t :: %__MODULE__{
          status: String.t() | nil,
          changes: [FileChange.t()],
          diff: Diff.t() | nil
        }
end

defmodule Ouroboros.Web.Presentation.PlanUpdate do
  @moduledoc "A model-authored task list, bounded."

  alias Ouroboros.Web.Presentation.PlanStep

  defstruct [:explanation, steps: [], step_count: 0]

  @type t :: %__MODULE__{
          explanation: String.t() | nil,
          steps: [PlanStep.t()],
          step_count: non_neg_integer()
        }
end

defmodule Ouroboros.Web.Presentation.UsageReport do
  @moduledoc """
  One `usage` report exactly as the provider phrased it. Absent fields stay absent: a
  zero this surface invented would be indistinguishable from a zero a provider measured.
  """

  defstruct [:input_tokens, :output_tokens, :cached_tokens, :total_tokens, :cost_usd]

  @type t :: %__MODULE__{
          input_tokens: non_neg_integer() | nil,
          output_tokens: non_neg_integer() | nil,
          cached_tokens: non_neg_integer() | nil,
          total_tokens: non_neg_integer() | nil,
          cost_usd: float() | nil
        }

  @doc "Whether the provider reported nothing at all."
  @spec empty?(t()) :: boolean()
  def empty?(%__MODULE__{} = usage) do
    is_nil(usage.input_tokens) and is_nil(usage.output_tokens) and
      is_nil(usage.cached_tokens) and is_nil(usage.total_tokens) and is_nil(usage.cost_usd)
  end
end

defmodule Ouroboros.Web.Presentation.RunStart do
  @moduledoc """
  A provider run began. Claude reports the model and the tool catalogue here; nothing
  else in the stream ever names the model.
  """

  defstruct [:model, :cwd, tools: [], tool_count: 0]

  @type t :: %__MODULE__{
          model: String.t() | nil,
          cwd: String.t() | nil,
          tools: [String.t()],
          tool_count: non_neg_integer()
        }
end

defmodule Ouroboros.Web.Presentation.TurnStarted do
  @moduledoc "A turn began, with the instant the ledger stamped on it."
  defstruct [:turn_id, :at]
  @type t :: %__MODULE__{turn_id: String.t() | nil, at: integer() | nil}
end

defmodule Ouroboros.Web.Presentation.TurnEnded do
  @moduledoc "A turn ended, however it ended."
  defstruct [:turn_id, :at, :outcome, detail: ""]

  @type outcome :: :completed | :failed | :interrupted
  @type t :: %__MODULE__{
          turn_id: String.t() | nil,
          at: integer() | nil,
          outcome: outcome(),
          detail: String.t()
        }

  @doc "The words one outcome renders as."
  @spec label(t() | outcome()) :: String.t()
  def label(%__MODULE__{outcome: outcome}), do: label(outcome)
  def label(:completed), do: "turn complete"
  def label(:failed), do: "turn failed"
  def label(:interrupted), do: "turn interrupted"
end

defmodule Ouroboros.Web.Presentation.QueueChanged do
  @moduledoc "How many turns the runtime is holding behind the running one."
  defstruct queued: 0
  @type t :: %__MODULE__{queued: non_neg_integer()}
end

defmodule Ouroboros.Web.Presentation.ApprovalRequested do
  @moduledoc "The runtime asked for permission."
  defstruct [:request_id, detail: ""]
  @type t :: %__MODULE__{request_id: String.t() | nil, detail: String.t()}
end

defmodule Ouroboros.Web.Presentation.ApprovalResolved do
  @moduledoc "An outstanding permission was answered."
  defstruct [:request_id, :decision, detail: ""]

  @type t :: %__MODULE__{
          request_id: String.t() | nil,
          decision: String.t() | nil,
          detail: String.t()
        }
end

defmodule Ouroboros.Web.Presentation.Failure do
  @moduledoc "A run or a session failed."
  defstruct detail: ""
  @type t :: %__MODULE__{detail: String.t()}
end

defmodule Ouroboros.Web.Presentation.Interrupted do
  @moduledoc "A run or a session was cancelled."
  defstruct detail: ""
  @type t :: %__MODULE__{detail: String.t()}
end

defmodule Ouroboros.Web.Presentation.ProviderNote do
  @moduledoc """
  Something the provider said that this surface does not model. Named by its own kind so
  it is one dim line rather than an invisible event.
  """
  defstruct kind: "", detail: ""
  @type t :: %__MODULE__{kind: String.t(), detail: String.t()}
end

defmodule Ouroboros.Web.Presentation do
  @moduledoc """
  A tolerant, presentation-only reading of normalized Harness events.

  The durable event and its raw payload remain the source of truth. The structs here name
  only the fields a transcript can lay out usefully; missing or newer shapes fall back to
  the complete event-details view instead of becoming server-side state or policy.

  ## Every kind is presented, and a hide is a decision with a reason

  There is deliberately no catch-all "ignore" arm. Each normalized event type names a
  presentation struct, and the one that draws nothing —
  `Ouroboros.Web.Presentation.Hidden` — carries the reason it drew nothing. A kind this
  build did not recognise becomes `Ouroboros.Web.Presentation.ProviderNote` rather than
  disappearing: a transcript that silently omits events is a transcript that cannot be
  trusted about the events it does show.

  Port of `PresentationEvent::from_event` (`tui/src/model/transcript.rs:361`), with the
  display ceilings of `tui/src/model/transcript.rs:22-33` applied here rather than at
  render. The input is the runtime's own `%Ouroboros.Interactive.Event{}` — uncapped — so
  these ceilings are load-bearing, not decorative.

  ## Payload key types, and the one transform this module does before reading

  Payloads are **string-keyed**, with one enumerable exception.

  * Everything that becomes a `Jido.Harness.Event` is string-keyed by construction:
    `Event.new!/1` recursively stringifies payload keys
    (`deps/jido_harness/lib/jido_harness/event.ex:138-149`), and the schema declares
    `payload: Zoi.map(Zoi.string(), Zoi.any())` (`event.ex:63`). That is every
    `tool_call`, `tool_result`, `file_change`, `plan_updated`, `usage`,
    `approval_requested`, `provider_event` and lifecycle event, on both planes.
  * Every runtime-native interactive emitter builds string keys literally —
    `%{"kind" => "configured", …}` (`lib/ouroboros/interactive/task.ex:1481`),
    `%{"kind" => "operator_shell", …}` (`lib/ouroboros/interactive/task/shell.ex:272`),
    the `delegation` payload (`lib/ouroboros/interactive/task.ex:1868-1877`).
  * **The exception:** `Ouroboros.Coding.Event.internal/4`
    (`lib/ouroboros/coding/event.ex:46`) skips that stringification, and all eight of its
    call sites build **atom**-keyed maps — `%{path: …, reason: …, message: …}`
    (`lib/ouroboros/coding/task.ex:368-374`), `%{request_id: …, decision: …, scope: …}`
    (`lib/ouroboros/coding/task.ex:156-162`). `Jido.Harness.Redaction.redact/1` preserves
    key types (`deps/jido_harness/lib/jido_harness/redaction.ex:23-27`), so they arrive
    here as atoms.

  The Rust client never sees those atoms: `Ouroboros.Gateway.Wire` stringifies atom keys
  and atom values on the way out (`lib/ouroboros/gateway/wire.ex:148`, `:292`, `:300-309`),
  keeping `nil` and booleans as themselves. An in-process reader skips that boundary
  entirely (`lib/ouroboros/interactive/task.ex:2152`), so `from_event/1` applies exactly
  that one transform first — see `wire_shape/1`. Doing less would render a coding-plane
  `worktree_retained` as a bare marker on the web and as a sentence in the TUI; doing more
  (reading both key types in every field reader) would be a guess in forty places instead
  of a stated normalization in one.
  """

  import Bitwise, only: [band: 2]

  alias Ouroboros.Web.Presentation.{
    AgentText,
    ApprovalRequested,
    ApprovalResolved,
    CommandOutput,
    Compaction,
    DelegationEvent,
    Diff,
    Failure,
    FileChange,
    FileUpdate,
    Hidden,
    ImageArtifact,
    Interrupted,
    Lifecycle,
    PlanStatus,
    PlanStep,
    PlanUpdate,
    ProviderNote,
    QueueChanged,
    RunStart,
    ShellEvent,
    SubagentEvent,
    Thinking,
    ToolCall,
    ToolResult,
    TurnEnded,
    TurnStarted,
    UnrecordedInput,
    UsageReport,
    UserMessage,
    UserSteer,
    Worktree
  }

  # These ceilings apply only to the derived transcript projection. The event's payload
  # remains complete for event details, replay, and any future presentation.
  @text_bytes 64 * 1024
  @value_bytes 64 * 1024
  @value_nodes 2_048
  @value_depth 32
  @diff_bytes 128 * 1024
  @file_changes 256
  # Plan payloads are model-authored task lists, not data structures: a provider that
  # emits a thousand steps is reporting a runaway, and the panel says so rather than
  # drawing it.
  @plan_steps 64
  # How many tool names a `run_started` header fact keeps.
  @run_tools 128
  # How many image artifacts one tool result mints cells for.
  @max_artifacts 16
  # How long a label from a runtime-native payload may be before it stops being a label.
  @label_bytes 256

  @text_truncation "\n… transcript excerpt truncated; full value is available in event details"
  @diff_truncation "\n… diff truncated; full diff is available in event details"
  @native_truncation "… (truncated by this client)"

  @canonical_types ~w(
    run_started run_completed run_failed run_cancelled
    session_started session_ready session_idle session_closed session_failed session_cancelled
    input_accepted turn_queued turn_started
    output_text_delta output_text_final thinking_delta command_output_delta
    tool_call tool_result file_change plan_updated usage
    turn_completed turn_failed turn_interrupted
    approval_requested approval_resolved queue_changed provider_event
  )a

  @type t ::
          UserMessage.t()
          | UserSteer.t()
          | UnrecordedInput.t()
          | AgentText.t()
          | Thinking.t()
          | ToolCall.t()
          | ToolResult.t()
          | CommandOutput.t()
          | FileUpdate.t()
          | PlanUpdate.t()
          | UsageReport.t()
          | RunStart.t()
          | TurnStarted.t()
          | TurnEnded.t()
          | QueueChanged.t()
          | Lifecycle.t()
          | ApprovalRequested.t()
          | ApprovalResolved.t()
          | Failure.t()
          | Interrupted.t()
          | ShellEvent.t()
          | Compaction.t()
          | DelegationEvent.t()
          | SubagentEvent.t()
          | ProviderNote.t()
          | Hidden.t()

  @doc "Every canonical event type, as the runtime spells them."
  @spec canonical_types() :: [atom()]
  def canonical_types, do: @canonical_types

  @doc """
  Reads one durable event into a presentation struct.

  Accepts an `%Ouroboros.Interactive.Event{}` or any map carrying `:type`, `:payload`,
  `:timestamp`, `:turn_id` and `:request_id` — the coding plane's event struct has the
  same five fields.
  """
  @spec from_event(map()) :: t()
  def from_event(event) do
    payload = payload_of(event)

    case Map.get(event, :type) do
      :input_accepted ->
        input_accepted(payload)

      kind when kind in [:output_text_delta, :output_text_final] ->
        case raw_text(payload, ["text"]) do
          nil ->
            %Hidden{reason: :empty_text}

          text ->
            %AgentText{
              turn_id: bounded_optional(Map.get(event, :turn_id)),
              text: text,
              final_text: kind == :output_text_final
            }
        end

      :thinking_delta ->
        case raw_text(payload, ["text", "thinking", "reasoning"]) do
          nil ->
            %Hidden{reason: :empty_thinking}

          text ->
            %Thinking{turn_id: bounded_optional(Map.get(event, :turn_id)), text: text}
        end

      :tool_call ->
        %ToolCall{
          call_id: text(payload, ["call_id", "tool_call_id", "toolCallId", "id"]),
          name:
            text(payload, ["name", "tool_name", "toolName", "tool", "title", "kind"]) || "tool",
          kind: text(payload, ["kind", "tool_kind", "toolKind"]),
          input:
            case first_value(payload, [
                   "input",
                   "arguments",
                   "parameters",
                   "rawInput",
                   "raw_input"
                 ]) do
              {:ok, value} -> bounded_value(value)
              :error -> %{}
            end,
          at: epoch_millis(Map.get(event, :timestamp))
        }

      :tool_result ->
        %ToolResult{
          call_id: text(payload, ["call_id", "tool_call_id", "toolCallId", "id"]),
          name: text(payload, ["name", "tool_name", "toolName", "tool", "title", "kind"]),
          kind: text(payload, ["kind", "tool_kind", "toolKind"]),
          output:
            case first_value(payload, ["output", "result", "content", "rawOutput", "raw_output"]) do
              {:ok, value} -> bounded_value(value)
              :error -> nil
            end,
          is_error: error_result?(payload),
          at: epoch_millis(Map.get(event, :timestamp)),
          artifacts: image_artifacts(payload)
        }

      :command_output_delta ->
        case raw_text(payload, ["text", "output"]) do
          nil -> %Hidden{reason: :empty_command_output}
          text -> %CommandOutput{text: text}
        end

      :file_change ->
        file_update(payload)

      :plan_updated ->
        plan_update(payload)

      :usage ->
        usage_report(payload)

      :run_started ->
        run_start(payload)

      :turn_started ->
        %TurnStarted{
          turn_id: bounded_optional(Map.get(event, :turn_id)),
          at: epoch_millis(Map.get(event, :timestamp))
        }

      kind when kind in [:turn_completed, :turn_failed, :turn_interrupted] ->
        %TurnEnded{
          turn_id: bounded_optional(Map.get(event, :turn_id)),
          at: epoch_millis(Map.get(event, :timestamp)),
          outcome:
            case kind do
              :turn_failed -> :failed
              :turn_interrupted -> :interrupted
              _completed -> :completed
            end,
          detail: optional_detail(payload) || ""
        }

      :queue_changed ->
        %QueueChanged{queued: count(payload, ["queued_turns", "queued", "length", "count"])}

      :turn_queued ->
        %Lifecycle{marker: :turn_queued, detail: optional_detail(payload) || ""}

      kind
      when kind in [
             :run_completed,
             :session_started,
             :session_ready,
             :session_idle,
             :session_closed
           ] ->
        %Lifecycle{
          marker:
            case kind do
              :run_completed -> :run_completed
              :session_started -> :session_started
              :session_ready -> :session_ready
              :session_idle -> :session_idle
              _closed -> :session_closed
            end,
          detail: lifecycle_detail(payload)
        }

      :provider_event ->
        provider_note(payload)

      :approval_requested ->
        %ApprovalRequested{
          request_id: bounded_optional(Map.get(event, :request_id)),
          detail: subject(payload)
        }

      :approval_resolved ->
        %ApprovalResolved{
          request_id: bounded_optional(Map.get(event, :request_id)),
          decision: text(payload, ["decision"]),
          detail: approval_resolution(payload)
        }

      kind when kind in [:run_failed, :session_failed] ->
        %Failure{detail: detail(payload)}

      kind when kind in [:run_cancelled, :session_cancelled] ->
        %Interrupted{detail: detail(payload)}

      # G1. `delegation` is its own runtime-native event type, not a wrapped provider one:
      # `emit_runtime_event(runtime, :delegation, …)` puts it in the same sequence space as
      # everything else (`lib/ouroboros/interactive/task.ex:1880`).
      :delegation ->
        decode_delegation(payload)

      # A kind this build does not know. It is still an event the runtime recorded, so it
      # reads as one dim line naming itself rather than as nothing at all.
      other ->
        %ProviderNote{
          kind: bounded_copy(to_string(other), @text_bytes, @text_truncation),
          detail: optional_detail(payload) || ""
        }
    end
  end

  defp payload_of(event) do
    case Map.get(event, :payload) do
      payload when is_map(payload) and not is_struct(payload) -> wire_shape(payload)
      _absent -> %{}
    end
  end

  @doc """
  The atom-flattening `Ouroboros.Gateway.Wire` does on the way out, applied in-process.

  Atom keys and atom values become their strings; `nil` and the booleans stay themselves;
  a module name loses its `Elixir.` prefix. Mirrors `wire.ex:147-148` and `:298-309`
  exactly, and nothing else the wire does — no byte caps, no `_opaque` minting, no
  struct tagging. This is what makes a coding-plane internal event
  (`lib/ouroboros/coding/event.ex:46`) read the same in a browser as it does in the TUI.
  """
  @spec wire_shape(term()) :: term()
  def wire_shape(value) when is_map(value) and not is_struct(value) do
    Map.new(value, fn {key, entry} -> {wire_key(key), wire_shape(entry)} end)
  end

  def wire_shape(value) when is_list(value), do: Enum.map(value, &wire_shape/1)
  def wire_shape(value) when is_nil(value) or is_boolean(value), do: value
  def wire_shape(value) when is_atom(value), do: atom_to_string(value)
  def wire_shape(value), do: value

  defp wire_key(key) when is_atom(key), do: atom_to_string(key)
  defp wire_key(key) when is_binary(key), do: key
  defp wire_key(key) when is_integer(key), do: Integer.to_string(key)
  defp wire_key(key), do: inspect(key)

  defp atom_to_string(nil), do: "nil"
  defp atom_to_string(true), do: "true"
  defp atom_to_string(false), do: "false"

  defp atom_to_string(atom) do
    case Atom.to_string(atom) do
      "Elixir." <> rest -> rest
      name -> name
    end
  end

  # What one accepted input was, given that the ledger does not always carry its words.
  #
  # The text is missing for every event checkpointed before the runtime recorded it and
  # for every recovered turn, and those events are not going away. Dropping them deleted
  # real turns from the chat — including every steer, which is the one kind of turn an
  # operator is most likely to be looking for afterwards.
  defp input_accepted(payload) do
    words =
      case raw_text(payload, ["text"]) do
        nil -> nil
        words -> if String.trim(words) == "", do: nil, else: words
      end

    steered = text(payload, ["kind"]) == "steer"

    case {steered, words} do
      {true, words} -> %UserSteer{text: words}
      {false, nil} -> %UnrecordedInput{}
      {false, words} -> %UserMessage{text: words}
    end
  end

  # The provider kind an escape-hatch event is reporting, so it is never invisible.
  #
  # ACP wraps every update it does not map in `{"kind": "acp_update", "update": …}`; the
  # update's own `sessionUpdate` type is the informative half and is lifted out here.
  defp provider_note(payload) do
    # Three kinds this runtime writes itself and this surface draws in full. Matched
    # before the generic path because they are not "something the provider said that this
    # client does not model" — they are Ouroboros's own record of an operator's act (B7),
    # of history it folded away (D9), and of a child agent it started.
    case Map.get(payload, "kind") do
      "operator_shell" ->
        decode_shell(payload)

      # The Rust falls back to a generic note where `Compaction::decode` refuses, which it
      # does only for a payload that is not an object. `payload_of/1` has already turned
      # any such payload into `%{}`, which names no kind and never reaches this clause.
      "compaction" ->
        decode_compaction(payload)

      "subagent" ->
        decode_subagent(payload)

      _other ->
        generic_provider_note(payload)
    end
  end

  defp generic_provider_note(payload) do
    kind = text(payload, ["kind", "type", "item_type", "event", "name"])

    nested =
      case Map.fetch(payload, "update") do
        {:ok, update} -> text(update, ["sessionUpdate", "session_update", "type"])
        :error -> nil
      end

    # Empty when the provider named no kind at all: the cell says "provider event" once,
    # and inventing a second copy of that phrase to sit in this field would only make it
    # say it twice.
    kind =
      case {kind, nested} do
        {nil, nil} -> ""
        {kind, nil} -> kind
        {nil, nested} -> nested
        {kind, nested} -> "#{kind} · #{nested}"
      end

    %ProviderNote{
      kind: bounded_copy(kind, @text_bytes, @text_truncation),
      detail: optional_detail(payload) || ""
    }
  end

  defp run_start(payload) do
    declared = array(payload, "tools")

    %RunStart{
      model: text(payload, ["model", "model_id", "modelId"]),
      cwd: text(payload, ["cwd", "workspace", "working_directory"]),
      tools:
        declared
        |> Enum.take(@run_tools)
        |> Enum.map(fn
          tool when is_binary(tool) -> nonempty(tool)
          other -> text(other, ["name", "tool", "title"])
        end)
        |> Enum.reject(&is_nil/1),
      tool_count: length(declared)
    }
  end

  defp usage_report(payload) do
    %UsageReport{
      input_tokens: number(payload, ["input_tokens", "inputTokens", "prompt_tokens"]),
      output_tokens: number(payload, ["output_tokens", "outputTokens", "completion_tokens"]),
      cached_tokens:
        number(payload, [
          "cache_read_input_tokens",
          "cached_input_tokens",
          "cachedInputTokens",
          "cache_read_tokens"
        ]),
      total_tokens: number(payload, ["total_tokens", "totalTokens"]),
      cost_usd:
        case first_value(payload, ["cost_usd", "total_cost_usd", "costUsd"]) do
          {:ok, value} -> as_float(value)
          :error -> nil
        end
    }
  end

  @doc """
  Both plan shapes this runtime can deliver, read tolerantly.

  Codex sends `{"explanation", "plan": [{"step", "status"}]}`; ACP forwards its `plan`
  session update verbatim, whose entries are `{"content", "priority", "status"}`.

  Public because a `plan_exit` approval's `payload.plan` is *the same `plan_updated`
  payload*, held back by the native session and attached to the question (B2). The
  plan-exit card decodes it through this function rather than through a second reader, so
  the steps a person approves are byte-for-byte the steps the plan panel showed them
  (`tui/src/model/transcript.rs:632`).
  """
  @spec plan_update(term()) :: PlanUpdate.t()
  def plan_update(payload) do
    entries =
      case first_value(payload, ["plan", "entries", "steps", "todos", "tasks"]) do
        {:ok, list} when is_list(list) -> list
        _otherwise -> []
      end

    %PlanUpdate{
      explanation: text(payload, ["explanation", "summary", "description"]),
      steps:
        entries |> Enum.take(@plan_steps) |> Enum.map(&plan_step/1) |> Enum.reject(&is_nil/1),
      step_count: length(entries)
    }
  end

  defp plan_step(value) when is_binary(value) do
    case nonempty(value) do
      nil -> nil
      text -> %PlanStep{text: text, status: :pending, priority: nil}
    end
  end

  defp plan_step(value) when is_map(value) do
    body =
      text(value, ["step", "content", "text", "title", "description", "name"]) ||
        case Map.fetch(value, "content") do
          {:ok, content} -> leaf_text(content)
          :error -> nil
        end

    case body do
      nil ->
        nil

      body ->
        %PlanStep{
          text: body,
          status: PlanStatus.parse(trimmed_string_value(value, ["status", "state"])),
          priority: text(value, ["priority"])
        }
    end
  end

  defp plan_step(_value), do: nil

  defp file_update(payload) do
    changes =
      case Map.fetch(payload, "changes") do
        {:ok, list} when is_list(list) ->
          projected =
            list
            |> Enum.map(&file_change/1)
            |> Enum.reject(&is_nil/1)
            |> Enum.take(@file_changes + 1)

          if length(projected) > @file_changes do
            Enum.take(projected, @file_changes) ++
              [%FileChange{path: "… additional files in event details"}]
          else
            projected
          end

        _absent ->
          case file_change(payload) do
            %FileChange{path: nil, kind: nil} -> []
            nil -> []
            change -> [change]
          end
      end

    %FileUpdate{status: text(payload, ["status"]), changes: changes, diff: diff_field(payload)}
  end

  # A diff leaf, whether the gateway sent the patch or an excerpt of it.
  #
  # An excerpted patch is still a patch worth colouring, but its `+`/`-` counts describe
  # only the prefix — so it is marked truncated, which is what makes the cell say
  # "in excerpt" beside the numbers instead of asserting a diffstat it cannot know.
  defp diff_field(payload) do
    case first_value(payload, ["diff", "patch", "delta"]) do
      :error ->
        nil

      {:ok, text} when is_binary(text) ->
        trimmed = String.trim(text)
        if trimmed == "", do: nil, else: parse_diff(trimmed)

      {:ok, other} ->
        case wire_marker(other) do
          nil -> nil
          excerpt -> %{parse_diff(excerpt) | truncated: true}
        end
    end
  end

  defp file_change(value) when is_binary(value) do
    trimmed = String.trim(value)

    if trimmed == "" do
      nil
    else
      %FileChange{path: bounded_copy(trimmed, @text_bytes, @text_truncation)}
    end
  end

  defp file_change(value) when is_map(value) do
    path = text(value, ["path", "file", "name", "file_path"])
    kind = text(value, ["kind", "action", "change_type", "type", "status"])
    diff = diff_field(value)

    if is_nil(path) and is_nil(kind) and is_nil(diff) do
      nil
    else
      %FileChange{path: path, kind: kind, diff: diff}
    end
  end

  defp file_change(_value), do: nil

  @doc """
  Parses a unified diff into the bounded presentation copy.

  Bounds the owned copy before scanning it: re-projecting a transcript must not
  repeatedly walk a multi-megabyte raw patch. The complete patch is still on the event
  (`tui/src/model/transcript.rs:1076`).
  """
  @spec parse_diff(String.t()) :: Diff.t()
  def parse_diff(text) when is_binary(text) do
    truncated = byte_size(text) > @diff_bytes
    text = bounded_copy(text, @diff_bytes, @diff_truncation)

    {path, additions, deletions} =
      Enum.reduce(lines(text), {nil, 0, 0}, fn line, {path, additions, deletions} ->
        path = scan_diff_path(line, path)

        cond do
          String.starts_with?(line, "+") and not String.starts_with?(line, "+++") ->
            {path, additions + 1, deletions}

          String.starts_with?(line, "-") and not String.starts_with?(line, "---") ->
            {path, additions, deletions + 1}

          true ->
            {path, additions, deletions}
        end
      end)

    %Diff{
      text: text,
      path: path,
      additions: additions,
      deletions: deletions,
      truncated: truncated
    }
  end

  # `path.get_or_insert_with(…)` in the Rust: the first header that names a file wins, and
  # a later one never overwrites it.
  defp scan_diff_path(_line, path) when is_binary(path), do: path

  defp scan_diff_path("diff --git a/" <> rest, nil) do
    case String.split(rest, " b/", parts: 2) do
      [_before, after_path] -> bounded_copy(after_path, @text_bytes, @text_truncation)
      _no_pair -> nil
    end
  end

  defp scan_diff_path("+++ b/" <> rest, nil),
    do: bounded_copy(rest, @text_bytes, @text_truncation)

  defp scan_diff_path(_line, nil), do: nil

  # ------------------------------------------------------------------------------------
  # Runtime-native payload decoders
  # ------------------------------------------------------------------------------------

  defp decode_shell(payload) do
    %ShellEvent{
      effect_id: label_at(payload, "effect_id"),
      command_digest: label_at(payload, "command_digest"),
      exit_status: as_integer(Map.get(payload, "exit_status")),
      duration_ms: strict_count(payload, "duration_ms"),
      timed_out: as_bool(Map.get(payload, "timed_out")) || false,
      output_bytes: strict_count(payload, "output_bytes"),
      # Through `leaf_text` rather than a plain string read: the gateway replaces a long
      # string inside an event payload with `{"_excerpt", "_bytes"}`, and reading this one
      # as a plain string would drop the excerpt on exactly the commands whose output was
      # worth excerpting.
      output_excerpt:
        case Map.fetch(payload, "output_excerpt") do
          {:ok, value} ->
            case leaf_text(value) do
              nil -> nil
              text -> native_bounded(text, 4096)
            end

          :error ->
            nil
        end,
      spilled: label_at(payload, "spilled"),
      error: sentence(payload, "error", 512)
    }
  end

  defp decode_compaction(payload) do
    %Compaction{
      trigger: label_at(payload, "trigger"),
      turn: strict_count(payload, "turn"),
      archived_messages: strict_count(payload, "archived_messages"),
      archive_id: label_at(payload, "archive_id"),
      elided_tool_results: strict_count(payload, "elided_tool_results"),
      summary_tokens: strict_count(payload, "summary_tokens"),
      before_tokens: strict_count(payload, "before_tokens"),
      after_tokens: strict_count(payload, "after_tokens"),
      summarised: as_bool(Map.get(payload, "summarised"))
    }
  end

  defp decode_delegation(payload) do
    %DelegationEvent{
      delegation_id: label_at(payload, "delegation_id"),
      task_id: label_at(payload, "task_id"),
      task_node: label_at(payload, "task_node"),
      team_id: label_at(payload, "team_id"),
      objective_digest: label_at(payload, "objective_digest"),
      status: label_at(payload, "status"),
      result_digest: label_at(payload, "result_digest")
    }
  end

  defp decode_subagent(payload) do
    worktree_detail = decode_worktree(Map.get(payload, "worktree"))

    %SubagentEvent{
      phase: decode_phase(Map.get(payload, "phase")),
      task_id: label_at(payload, "task_id"),
      description: label_at(payload, "description"),
      provider_session_id: label_at(payload, "provider_session_id"),
      node: label_at(payload, "node"),
      remote: as_bool(Map.get(payload, "remote")) || false,
      workspace: label_at(payload, "workspace"),
      # Two shapes for one key: `spawned` sends a bool, `settled` sends the worktree
      # itself. Either one means the child had one.
      worktree: (as_bool(Map.get(payload, "worktree")) || false) or worktree_detail != nil,
      worktree_detail: worktree_detail,
      tools: names(Map.get(payload, "tools"), :infinity),
      background: as_bool(Map.get(payload, "background")) || false,
      depth: strict_count(payload, "depth"),
      max_turns: strict_count(payload, "max_turns"),
      deadline_ms: strict_count(payload, "deadline_ms"),
      turns: strict_count(payload, "turns"),
      tool_calls: strict_count(payload, "tool_calls"),
      files_changed: strict_count(payload, "files_changed"),
      files: names(Map.get(payload, "files"), 16),
      status: label_at(payload, "status"),
      input_tokens: strict_count(payload, "input_tokens"),
      output_tokens: strict_count(payload, "output_tokens"),
      approvals_denied: strict_count(payload, "approvals_denied"),
      summary_bytes: strict_count(payload, "summary_bytes"),
      cost_usd: as_float(Map.get(payload, "cost_usd")),
      error: sentence(payload, "error", 512)
    }
  end

  defp decode_phase("spawned"), do: :spawned
  defp decode_phase("progress"), do: :progress
  defp decode_phase("settled"), do: :settled
  defp decode_phase(word) when is_binary(word), do: {:other, native_bounded(word, @label_bytes)}
  defp decode_phase(_absent), do: {:other, ""}

  defp decode_worktree(value) when is_map(value) do
    %Worktree{
      path: label_at(value, "path"),
      root: label_at(value, "root"),
      branch: label_at(value, "branch"),
      base_commit: label_at(value, "base_commit"),
      repository: label_at(value, "repository"),
      retired: label_at(value, "retired")
    }
  end

  defp decode_worktree(_value), do: nil

  # A JSON array of strings, trimmed, bounded, and with the empties dropped.
  defp names(value, limit) when is_list(value) do
    names = value |> Enum.map(&native_string/1) |> Enum.reject(&is_nil/1)
    if limit == :infinity, do: names, else: Enum.take(names, limit)
  end

  defp names(_value, _limit), do: []

  defp native_string(value) when is_binary(value) do
    case String.trim(value) do
      "" -> nil
      trimmed -> native_bounded(trimmed, @label_bytes)
    end
  end

  defp native_string(_value), do: nil

  defp label_at(map, key), do: native_string(Map.get(map, key))

  # Strict: a runtime-native count is a JSON number or it is absent. A float or a string
  # here would be a payload this build has not seen, and reading one as a count is a guess.
  defp strict_count(map, key) do
    case Map.get(map, key) do
      value when is_integer(value) and value >= 0 -> value
      _otherwise -> nil
    end
  end

  defp sentence(map, key, limit) do
    case Map.get(map, key) do
      value when is_binary(value) ->
        case String.trim(value) do
          "" -> nil
          trimmed -> native_bounded(trimmed, limit)
        end

      _otherwise ->
        nil
    end
  end

  # Cuts on a character boundary, never inside one (`tui/src/model/native.rs:23-35`).
  defp native_bounded(text, limit) do
    if byte_size(text) <= limit do
      text
    else
      cut = char_boundary_at_or_before(text, max(limit - byte_size(@native_truncation), 0))
      binary_part(text, 0, cut) <> @native_truncation
    end
  end

  # ------------------------------------------------------------------------------------
  # Payload readers
  # ------------------------------------------------------------------------------------

  defp error_result?(payload) do
    case Map.get(payload, "is_error") do
      value when is_boolean(value) ->
        value

      _otherwise ->
        text(payload, ["status"]) in ["error", "failed", "declined"]
    end
  end

  # The image artifacts a tool result carried (§8.5), read defensively.
  #
  # An entry with an unknown `kind` is skipped rather than guessed at, and unknown fields
  # are ignored rather than rejected. The one hard requirement is a `sha256`: it is the
  # only key that can fetch the bytes or be checked by containment. A missing `kind` is
  # taken as an image, because that is the only artifact kind the contract defines.
  defp image_artifacts(payload) do
    payload
    |> array("artifacts")
    |> Enum.filter(fn entry ->
      case text(entry, ["kind"]) do
        nil -> true
        kind -> kind == "image"
      end
    end)
    |> Enum.map(&image_artifact/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.take(@max_artifacts)
  end

  defp image_artifact(entry) do
    with sha256 when is_binary(sha256) <- text(entry, ["sha256", "sha", "digest"]),
         true <- byte_size(sha256) == 64,
         true <- hex?(sha256) do
      %ImageArtifact{
        sha256: String.downcase(sha256, :ascii),
        media_type: text(entry, ["media_type", "mediaType", "content_type"]),
        size: number(entry, ["bytes", "size"]),
        width: clamp_u32(number(entry, ["width"])),
        height: clamp_u32(number(entry, ["height"]))
      }
    else
      _otherwise -> nil
    end
  end

  defp hex?(text) do
    text
    |> :binary.bin_to_list()
    |> Enum.all?(fn byte ->
      byte in ?0..?9 or byte in ?a..?f or byte in ?A..?F
    end)
  end

  defp clamp_u32(nil), do: nil
  defp clamp_u32(value), do: min(value, 4_294_967_295)

  defp detail(payload) do
    text(payload, ["error", "reason", "message", "text"]) || bounded_compact(payload)
  end

  # Human-facing words from a payload, or nothing. Unlike `detail/1` this never falls back
  # to compact JSON: a lifecycle marker with `{}` behind it must read as a marker.
  defp optional_detail(payload) do
    text(payload, ["error", "reason", "message", "text", "status", "detail"])
  end

  # A lifecycle line's detail, preferring the words a provider chose over its bookkeeping.
  defp lifecycle_detail(payload) do
    optional_detail(payload) ||
      case text(payload, ["transport"]) do
        nil ->
          ""

        transport ->
          case text(payload, ["maturity"]) do
            nil -> transport
            maturity -> "#{transport} · #{maturity}"
          end
      end
  end

  defp subject(payload) do
    case question_subject(payload) do
      nil ->
        rendered =
          case first_value(payload, ["tool_call", "tool", "command", "text"]) do
            {:ok, value} -> bounded_compact(value)
            :error -> nil
          end

        if is_nil(rendered) or rendered == "" or rendered == "null" do
          bounded_compact(payload)
        else
          rendered
        end

      question ->
        question
    end
  end

  # An `ask_user` question carries none of the keys above — no tool call, no command, no
  # text — so the row would compact the whole payload and read as JSON. Its own words are
  # what the row is for, joined the way the card joins them
  # (`Ouroboros.Web.Transcript.Approval.question_text/1`, `tui/src/model/transcript.rs`).
  #
  # A plan exit is deliberately not folded in here: its `question` is four lines naming the
  # consequence of each answer, which belongs in the card and not in a one-line row.
  defp question_subject(payload) do
    if text(payload, ["kind"]) == "question" do
      case {text(payload, ["header"]), text(payload, ["question"])} do
        {nil, nil} ->
          nil

        {header, nil} ->
          header

        {nil, question} ->
          question

        {header, question} ->
          bounded_copy("#{header} — #{question}", @text_bytes, @text_truncation)
      end
    end
  end

  defp approval_resolution(payload) do
    parts =
      [
        text(payload, ["decision"]),
        text(payload, ["scope"]),
        text(payload, ["reason", "message"])
      ]
      |> Enum.reject(&is_nil/1)

    case parts do
      [] -> bounded_compact(payload)
      parts -> bounded_copy(Enum.join(parts, " · "), @text_bytes, @text_truncation)
    end
  end

  # ------------------------------------------------------------------------------------
  # Value helpers, shared with the projection
  # ------------------------------------------------------------------------------------

  @doc """
  The label a gateway wire marker renders as, if this value is one.

  `Ouroboros.Gateway.Wire` replaces leaves it cannot or will not encode with small tagged
  objects. Rendering those as raw JSON in a transcript is how `{"_opaque":"#PID<0.1.0>"}`
  ends up looking like tool output; each one gets a short label instead
  (`tui/src/model/transcript.rs:828`).
  """
  @spec wire_marker(term()) :: String.t() | nil
  def wire_marker(fields) when is_map(fields) and not is_struct(fields) do
    cond do
      is_binary(prefix = Map.get(fields, "_excerpt")) ->
        bytes =
          case Map.get(fields, "_bytes") do
            value when is_integer(value) and value >= 0 -> "#{value} bytes"
            _otherwise -> "full value"
          end

        "#{prefix}… (#{bytes}; full event via /details)"

      is_binary(opaque = Map.get(fields, "_opaque")) ->
        "[not encodable: #{opaque}]"

      Map.has_key?(fields, "_b64") ->
        "[binary value; full event via /details]"

      Map.get(fields, "_truncated") == true and map_size(fields) == 1 ->
        "[truncated; full event via /details]"

      true ->
        nil
    end
  end

  def wire_marker(_value), do: nil

  @doc "One leaf as text: a plain string, or the label of a wire marker standing in for one."
  @spec leaf_text(term()) :: String.t() | nil
  def leaf_text(value) when is_binary(value), do: nonempty(value)
  def leaf_text(value), do: wire_marker(value)

  @doc "The first of `keys` this map holds, distinguishing an absent key from a null one."
  @spec first_value(term(), [String.t()]) :: {:ok, term()} | :error
  def first_value(value, keys) when is_map(value) and not is_struct(value) do
    Enum.reduce_while(keys, :error, fn key, acc ->
      case Map.fetch(value, key) do
        {:ok, found} -> {:halt, {:ok, found}}
        :error -> {:cont, acc}
      end
    end)
  end

  def first_value(_value, _keys), do: :error

  defp string_value(value, keys) do
    case first_value(value, keys) do
      {:ok, found} when is_binary(found) -> found
      _otherwise -> nil
    end
  end

  defp trimmed_string_value(value, keys) do
    case string_value(value, keys) do
      nil ->
        nil

      found ->
        case String.trim(found) do
          "" -> nil
          trimmed -> trimmed
        end
    end
  end

  @doc """
  Trimmed text under the first of `keys`, or the label of a wire marker under it.

  The search stops at the first key the map holds, whatever its value: reading past a key
  a provider did set would be this surface choosing which field it preferred.
  """
  @spec text(term(), [String.t()]) :: String.t() | nil
  def text(value, keys) do
    case trimmed_string_value(value, keys) do
      nil ->
        case first_value(value, keys) do
          {:ok, found} -> wire_marker(found)
          :error -> nil
        end

      trimmed ->
        bounded_copy(trimmed, @text_bytes, @text_truncation)
    end
  end

  # Like `text/2` but keeps leading and trailing whitespace: a streamed text delta's
  # spacing is the message.
  defp raw_text(value, keys) do
    case string_value(value, keys) do
      nil ->
        case first_value(value, keys) do
          {:ok, found} -> wire_marker(found)
          :error -> nil
        end

      "" ->
        case first_value(value, keys) do
          {:ok, found} -> wire_marker(found)
          :error -> nil
        end

      found ->
        bounded_copy(found, @text_bytes, @text_truncation)
    end
  end

  defp nonempty(text) when is_binary(text) do
    case String.trim(text) do
      "" -> nil
      trimmed -> bounded_copy(trimmed, @text_bytes, @text_truncation)
    end
  end

  defp bounded_optional(nil), do: nil

  defp bounded_optional(text) when is_binary(text),
    do: bounded_copy(text, @text_bytes, @text_truncation)

  defp number(value, keys) do
    case first_value(value, keys) do
      {:ok, found} -> as_number(found)
      :error -> nil
    end
  end

  defp as_number(value) when is_integer(value) and value >= 0, do: value
  defp as_number(value) when is_integer(value), do: nil
  defp as_number(value) when is_float(value) and value >= 0.0, do: trunc(value)
  defp as_number(value) when is_float(value), do: nil

  defp as_number(value) when is_binary(value) do
    case value |> String.trim() |> String.replace_prefix("+", "") |> Integer.parse() do
      {parsed, ""} when parsed >= 0 -> parsed
      _otherwise -> nil
    end
  end

  defp as_number(_value), do: nil

  defp count(value, keys) do
    case number(value, keys) do
      nil ->
        case first_value(value, keys) do
          {:ok, list} when is_list(list) -> length(list)
          _otherwise -> 0
        end

      count ->
        count
    end
  end

  defp as_float(value) when is_integer(value), do: value * 1.0
  defp as_float(value) when is_float(value), do: value
  defp as_float(_value), do: nil

  defp as_bool(value) when is_boolean(value), do: value
  defp as_bool(_value), do: nil

  defp as_integer(value) when is_integer(value), do: value
  defp as_integer(_value), do: nil

  defp array(map, key) do
    case Map.get(map, key) do
      list when is_list(list) -> list
      _otherwise -> []
    end
  end

  @doc """
  Milliseconds since the Unix epoch, for an ISO-8601 instant.

  The runtime stamps every event with `DateTime.to_iso8601/1`, which is always UTC with a
  `Z` suffix; the offset forms are accepted anyway because a timestamp this surface
  cannot read must degrade to "no elapsed time shown", never to a wrong one
  (`tui/src/model/transcript.rs:745`).
  """
  @spec epoch_millis(String.t() | nil) :: integer() | nil
  def epoch_millis(nil), do: nil

  def epoch_millis(timestamp) when is_binary(timestamp) do
    timestamp = String.trim(timestamp)

    with {:ok, date, rest} <- split_on_first(timestamp),
         {:ok, year, month, day} <- civil_date(date),
         {:ok, clock, offset_minutes} <- split_zone(rest),
         {:ok, hour, minute, second, millis} <- clock_parts(clock) do
      days = days_from_civil(year, month, day)

      (days * 86_400 + hour * 3_600 + minute * 60 + second - offset_minutes * 60) * 1_000 +
        millis
    else
      _unreadable -> nil
    end
  end

  def epoch_millis(_timestamp), do: nil

  # The leftmost of `T`, `t` or a space, exactly as `split_once(['T', 't', ' '])` does.
  defp split_on_first(text) do
    case :binary.match(text, ["T", "t", " "]) do
      {at, 1} ->
        {:ok, binary_part(text, 0, at), binary_part(text, at + 1, byte_size(text) - at - 1)}

      :nomatch ->
        :error
    end
  end

  defp civil_date(date) do
    with [year, month, day] <- String.split(date, "-"),
         {:ok, year} <- decimal(year),
         {:ok, month} <- decimal(month),
         {:ok, day} <- decimal(day),
         true <- month >= 1 and month <= 12,
         true <- day >= 1 and day <= 31 do
      {:ok, year, month, day}
    else
      _unreadable -> :error
    end
  end

  # Split the zone off before the clock: `+05:30` and `-08:00` both contain digits and
  # colons that would otherwise read as another field.
  defp split_zone(rest) do
    case zone_index(rest, 0) do
      nil ->
        {:ok, rest, 0}

      {at, :zulu} ->
        {:ok, binary_part(rest, 0, at), 0}

      {at, :offset} ->
        case zone_minutes(binary_part(rest, at, byte_size(rest) - at)) do
          nil -> :error
          minutes -> {:ok, binary_part(rest, 0, at), minutes}
        end
    end
  end

  defp zone_index(<<>>, _at), do: nil

  defp zone_index(<<byte, tail::binary>>, at) do
    cond do
      byte in [?Z, ?z] -> {at, :zulu}
      at > 0 and byte in [?+, ?-] -> {at, :offset}
      true -> zone_index(tail, at + 1)
    end
  end

  defp zone_minutes(<<sign, body::binary>>) when sign in [?+, ?-] do
    multiplier = if sign == ?+, do: 1, else: -1

    {hours, minutes} =
      case String.split(body, ":", parts: 2) do
        [hours, minutes] -> {hours, minutes}
        [_body] when byte_size(body) == 4 -> {binary_part(body, 0, 2), binary_part(body, 2, 2)}
        [body] -> {body, "0"}
      end

    with {:ok, hours} <- decimal(hours),
         {:ok, minutes} <- decimal(minutes) do
      multiplier * (hours * 60 + minutes)
    else
      _unreadable -> nil
    end
  end

  defp zone_minutes(_offset), do: nil

  defp clock_parts(clock) do
    case String.split(clock, ":") do
      parts when length(parts) in 2..3 ->
        [hour, minute | rest] = parts
        seconds = List.first(rest) || "0"
        {second, fraction} = split_seconds(seconds)

        with {:ok, hour} <- decimal(hour),
             {:ok, minute} <- decimal(minute),
             {:ok, second} <- decimal(second),
             true <- hour <= 23 and minute <= 59 and second <= 60 do
          {:ok, hour, minute, second, fractional_millis(fraction)}
        else
          _unreadable -> :error
        end

      _wrong_arity ->
        :error
    end
  end

  defp split_seconds(seconds) do
    case String.split(seconds, ".", parts: 2) do
      [second, fraction] -> {second, fraction}
      [second] -> {second, ""}
    end
  end

  defp fractional_millis(fraction) do
    digits =
      fraction
      |> String.to_charlist()
      |> Enum.filter(&(&1 in ?0..?9))
      |> Enum.take(3)

    case digits do
      [] ->
        0

      digits ->
        scale = Integer.pow(10, max(3 - length(digits), 0))
        List.to_integer(digits) * scale
    end
  end

  defp decimal(text) do
    case Integer.parse(text) do
      {value, ""} -> {:ok, value}
      _otherwise -> :error
    end
  end

  # Howard Hinnant's `days_from_civil`, the standard branch-free proleptic Gregorian
  # conversion. Written out rather than pulled in.
  defp days_from_civil(year, month, day) do
    year = year - if month <= 2, do: 1, else: 0
    era = Integer.floor_div(if(year >= 0, do: year, else: year - 399), 400)
    year_of_era = year - era * 400

    day_of_year =
      Integer.floor_div(153 * (month + if(month > 2, do: -3, else: 9)) + 2, 5) + day - 1

    day_of_era =
      year_of_era * 365 + Integer.floor_div(year_of_era, 4) -
        Integer.floor_div(year_of_era, 100) + day_of_year

    era * 146_097 + day_of_era - 719_468
  end

  @doc """
  Rust's `str::lines`: split on `\\n`, drop the optional final newline, strip a trailing
  `\\r` from each line.
  """
  @spec lines(String.t()) :: [String.t()]
  def lines(text) when is_binary(text) do
    parts = String.split(text, "\n")

    parts =
      case List.last(parts) do
        "" -> Enum.drop(parts, -1)
        _otherwise -> parts
      end

    Enum.map(parts, fn line -> String.replace_suffix(line, "\r", "") end)
  end

  @doc """
  A value rendered the way the transcript quotes one: a string as itself, a wire marker
  as its short label, anything else as JSON with sorted keys
  (`tui/src/model.rs:490`).
  """
  @spec compact(term()) :: String.t()
  def compact(value) when is_binary(value), do: value
  def compact(nil), do: "null"

  def compact(fields) when is_map(fields) and not is_struct(fields) and map_size(fields) == 1 do
    cond do
      is_binary(inspected = Map.get(fields, "_opaque")) -> inspected
      Map.has_key?(fields, "_truncated") -> "<truncated>"
      is_binary(encoded = Map.get(fields, "_b64")) -> "<#{byte_size(encoded)} base64 bytes>"
      true -> encode_json(fields)
    end
  end

  def compact(other), do: encode_json(other)

  @doc """
  JSON with every object's keys in sorted order.

  Deterministic on purpose: this is what a golden fixture compares, and a rendering that
  followed a map's own iteration order would say different things on two runs
  (`tui/src/model.rs:534-547`).
  """
  @spec encode_json(term()) :: String.t()
  def encode_json(nil), do: "null"
  def encode_json(true), do: "true"
  def encode_json(false), do: "false"
  def encode_json(value) when is_integer(value), do: Integer.to_string(value)
  def encode_json(value) when is_float(value), do: Float.to_string(value)
  def encode_json(value) when is_binary(value), do: encode_string(value)

  def encode_json(value) when is_list(value),
    do: "[" <> Enum.map_join(value, ",", &encode_json/1) <> "]"

  def encode_json(value) when is_map(value) and not is_struct(value) do
    body =
      value
      |> Enum.map(fn {key, entry} -> {to_string(key), entry} end)
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map_join(",", fn {key, entry} ->
        encode_string(key) <> ":" <> encode_json(entry)
      end)

    "{" <> body <> "}"
  end

  # An Elixir term with no JSON leaf of its own — an atom value a runtime payload carried,
  # a tuple, a pid. Rendered as its inspected string rather than refused, for the same
  # reason a wire marker is: a transcript that dropped it would be a transcript with an
  # unexplained hole.
  def encode_json(value) when is_atom(value), do: encode_string(Atom.to_string(value))
  def encode_json(value), do: encode_string(inspect(value))

  defp encode_string(text) do
    "\"" <> escape(text, "") <> "\""
  end

  defp escape(<<>>, acc), do: acc
  defp escape(<<?", rest::binary>>, acc), do: escape(rest, acc <> "\\\"")
  defp escape(<<?\\, rest::binary>>, acc), do: escape(rest, acc <> "\\\\")
  defp escape(<<0x08, rest::binary>>, acc), do: escape(rest, acc <> "\\b")
  defp escape(<<0x09, rest::binary>>, acc), do: escape(rest, acc <> "\\t")
  defp escape(<<0x0A, rest::binary>>, acc), do: escape(rest, acc <> "\\n")
  defp escape(<<0x0C, rest::binary>>, acc), do: escape(rest, acc <> "\\f")
  defp escape(<<0x0D, rest::binary>>, acc), do: escape(rest, acc <> "\\r")

  # Lowercase, because `serde_json`'s escape table is `b"0123456789abcdef"`
  # (`serde_json/src/ser.rs:1786`) and a golden fixture compares these bytes.
  defp escape(<<byte, rest::binary>>, acc) when byte < 0x20 do
    hex = byte |> Integer.to_string(16) |> String.downcase(:ascii) |> String.pad_leading(4, "0")
    escape(rest, acc <> "\\u" <> hex)
  end

  defp escape(<<byte, rest::binary>>, acc), do: escape(rest, acc <> <<byte>>)

  defp bounded_compact(value) do
    bounded_copy(compact(bounded_value(value)), @text_bytes, @text_truncation)
  end

  @doc """
  Cuts `text` to `limit` bytes on a character boundary, appending `marker`
  (`tui/src/model/transcript.rs:1122`).
  """
  @spec bounded_copy(String.t(), non_neg_integer(), String.t()) :: String.t()
  def bounded_copy(text, limit, marker) when is_binary(text) do
    cond do
      byte_size(text) <= limit ->
        text

      limit == 0 ->
        ""

      true ->
        marker =
          cond do
            byte_size(marker) <= limit -> marker
            byte_size("…") <= limit -> "…"
            true -> ""
          end

        target = min(max(limit - byte_size(marker), 0), byte_size(text))
        cut = char_boundary_at_or_before(text, target)
        binary_part(text, 0, cut) <> marker
    end
  end

  defp char_boundary_at_or_before(_text, 0), do: 0

  defp char_boundary_at_or_before(text, index) do
    if char_boundary?(text, index) do
      index
    else
      char_boundary_at_or_before(text, index - 1)
    end
  end

  defp char_boundary?(text, index) when index >= byte_size(text), do: index == byte_size(text)

  defp char_boundary?(text, index) do
    <<byte>> = binary_part(text, index, 1)
    band(byte, 0xC0) != 0x80
  end

  @doc """
  A value cut to the projection's node, byte and depth budget.

  The budget is spent left to right with the fields a transcript understands taken first,
  so a provider that puts a megabyte of metadata in front of `text` still gets its text
  drawn (`tui/src/model/transcript.rs:1149`).
  """
  @spec bounded_value(term()) :: term()
  def bounded_value(value) do
    case clone_value(value, %{bytes: @value_bytes, nodes: @value_nodes}, 0) do
      {:ok, projected, _budget} -> projected
      {:truncated, _budget} -> truncated_value()
    end
  end

  @preferred_fields ~w(text content cmd command path file query pattern url error message reason)

  # The budget travels out of a refusal as well as out of a success, because the Rust
  # holds it by `&mut` and a subtree that spent nodes before failing leaves the parent with
  # what it actually spent (`tui/src/model/transcript.rs:1198-1205`).
  #
  # Today the two are equivalent either way: every arm of `clone_taken/3` succeeds, so the
  # only refusals are the depth check and an already-empty node budget, neither of which
  # has spent anything. Threaded explicitly all the same — the equivalence is an accident
  # of which arms can currently fail, and a later arm that refuses after spending would
  # otherwise let a sibling draw more than the TUI draws for the same payload.
  defp clone_value(value, budget, depth) do
    if depth >= @value_depth do
      {:truncated, budget}
    else
      case take_node(budget) do
        :error -> {:truncated, budget}
        {:ok, budget} -> clone_taken(value, budget, depth)
      end
    end
  end

  defp clone_taken(value, budget, _depth) when is_binary(value) do
    {text, budget} = take_string(budget, value)
    {:ok, text, budget}
  end

  defp clone_taken(value, budget, depth) when is_list(value) do
    {projected, budget} = clone_list(value, budget, depth, [])
    {:ok, Enum.reverse(projected), budget}
  end

  defp clone_taken(value, budget, depth) when is_map(value) and not is_struct(value) do
    # Sorted, because `serde_json::Map` is a `BTreeMap` and the Rust walk is therefore in
    # key order. An Elixir map's own iteration order would make this say different things
    # on two runs of the same fixture.
    sorted =
      value
      |> Enum.map(fn {key, entry} -> {to_string(key), entry} end)
      |> Enum.sort_by(&elem(&1, 0))

    index = Map.new(sorted)

    # Keep the fields transcript renderers understand even when a provider also includes a
    # large amount of opaque metadata before them.
    preferred =
      @preferred_fields
      |> Enum.filter(&Map.has_key?(index, &1))
      |> Enum.map(&{&1, Map.fetch!(index, &1)})

    case clone_entries(preferred, %{}, budget, depth) do
      {:halted, projected, budget} ->
        {:ok, insert_truncation(projected), budget}

      {:ok, projected, budget} ->
        remaining = Enum.reject(sorted, fn {key, _entry} -> Map.has_key?(projected, key) end)

        case clone_entries(remaining, projected, budget, depth) do
          {:halted, projected, budget} -> {:ok, insert_truncation(projected), budget}
          {:ok, projected, budget} -> {:ok, projected, budget}
        end
    end
  end

  defp clone_taken(value, budget, _depth), do: {:ok, value, budget}

  defp clone_list([], budget, _depth, acc), do: {acc, budget}

  defp clone_list([head | tail], budget, depth, acc) do
    if exhausted?(budget) do
      {[truncated_value() | acc], budget}
    else
      case clone_value(head, budget, depth + 1) do
        {:ok, projected, budget} -> clone_list(tail, budget, depth, [projected | acc])
        {:truncated, budget} -> {[truncated_value() | acc], budget}
      end
    end
  end

  defp clone_entries([], projected, budget, _depth), do: {:ok, projected, budget}

  defp clone_entries([{key, value} | rest], projected, budget, depth) do
    case clone_field(projected, key, value, budget, depth) do
      {:ok, projected, budget} -> clone_entries(rest, projected, budget, depth)
      {:error, budget} -> {:halted, projected, budget}
    end
  end

  defp clone_field(projected, key, value, budget, depth) do
    if exhausted?(budget) do
      {:error, budget}
    else
      case take_key(budget, key) do
        :error ->
          {:error, budget}

        {:ok, budget} ->
          case clone_value(value, budget, depth + 1) do
            {:ok, cloned, budget} -> {:ok, Map.put(projected, key, cloned), budget}
            {:truncated, budget} -> {:error, budget}
          end
      end
    end
  end

  defp take_node(%{nodes: 0}), do: :error
  defp take_node(%{nodes: nodes} = budget), do: {:ok, %{budget | nodes: nodes - 1}}

  defp take_key(%{bytes: bytes} = budget, key) do
    if byte_size(key) > bytes do
      :error
    else
      {:ok, %{budget | bytes: bytes - byte_size(key)}}
    end
  end

  defp take_string(%{bytes: bytes} = budget, text) do
    if byte_size(text) <= bytes do
      {text, %{budget | bytes: bytes - byte_size(text)}}
    else
      {bounded_copy(text, bytes, @text_truncation), %{budget | bytes: 0}}
    end
  end

  defp exhausted?(%{bytes: bytes, nodes: nodes}), do: bytes == 0 or nodes == 0

  defp truncated_value, do: %{"_truncated" => true}

  defp insert_truncation(projected) do
    if Map.has_key?(projected, "_truncated") do
      Map.put(projected, "_transcript_truncated", true)
    else
      Map.put(projected, "_truncated", true)
    end
  end
end
