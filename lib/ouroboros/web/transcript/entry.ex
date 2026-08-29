defmodule Ouroboros.Web.Transcript.Entry.Floor do
  @moduledoc "History at or below this sequence is no longer held by anyone."
  defstruct sequence: 0
  @type t :: %__MODULE__{sequence: non_neg_integer()}
end

defmodule Ouroboros.Web.Transcript.Entry.Gap do
  @moduledoc "Sequences this view is missing and has asked for."
  defstruct [:from, :to]
  @type t :: %__MODULE__{from: non_neg_integer(), to: non_neg_integer()}
end

defmodule Ouroboros.Web.Transcript.Entry.Note do
  @moduledoc """
  Something recorded in place among the events, by the stream or by this surface.

  * `{:lagged, dropped}` — frames the gateway discarded under backpressure.
  * `:client_dropped` — frames this process's mailbox could not take.
  * `:reconnected` — the subscription was re-established here.
  * `{:local, %Cell.Runtime{}}` — what one of the operator's *own* verbs answered, at the
    point in the conversation where they asked.
  * `{:image, %Cell.Image{}}` — an image that entered the conversation here.
  """

  alias Ouroboros.Web.Transcript.Cell

  defstruct [:note]

  @type note ::
          {:lagged, non_neg_integer()}
          | :client_dropped
          | :reconnected
          | {:local, Cell.Runtime.t()}
          | {:image, Cell.Image.t()}

  @type t :: %__MODULE__{note: note()}

  @doc "Says what happened, not what is being done about it."
  @spec text(note() | t()) :: String.t()
  def text(%__MODULE__{note: note}), do: text(note)
  def text({:lagged, dropped}), do: "the gateway dropped #{dropped} event frames here"
  def text(:client_dropped), do: "this client could not take some event frames here"
  def text(:reconnected), do: "the connection was re-established here"
  def text({:local, block}), do: Cell.Runtime.text(block)
  def text({:image, cell}), do: Cell.Image.label(cell)
end

defmodule Ouroboros.Web.Transcript.Entry.Event do
  @moduledoc "One durable event, in sequence."
  defstruct [:event]
  @type t :: %__MODULE__{event: map()}
end

defmodule Ouroboros.Web.Transcript.Entry.Ended do
  @moduledoc "No further events will arrive."
  defstruct status: ""
  @type t :: %__MODULE__{status: String.t()}
end

defmodule Ouroboros.Web.Transcript.Entry do
  @moduledoc """
  What a transcript renders, in order (`tui/src/ui/transcript.rs:717-731`).

  `Ouroboros.Web.Transcript.entries/2` builds these from a sequence-keyed event map. The
  interleaving rules — where a floor marker sits, when a gap is drawn, which notes belong
  before which event — exist once, here, so a page and an export cannot diverge on the
  frame nobody looked at.
  """

  alias Ouroboros.Web.Transcript.Entry

  @type t ::
          Entry.Floor.t()
          | Entry.Gap.t()
          | Entry.Note.t()
          | Entry.Event.t()
          | Entry.Ended.t()
end
