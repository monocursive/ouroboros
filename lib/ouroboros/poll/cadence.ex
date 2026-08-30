defmodule Ouroboros.Poll.Cadence do
  @moduledoc false

  # How often a session coordinator wakes up to ask its Harness session what changed.
  #
  # The coordinator learns about provider output by polling: there is no push seam in
  # `Jido.Harness` at the pinned ref — no `subscribe`, no owner message a consumer can
  # register for (`docs/proposals/jido-harness-push-subscription.md` records what is and
  # is not there). A fixed 25 ms interval is the right answer while a turn is running and
  # the wrong answer for the hours a conversation spends between turns, where it costs
  # forty wakeups a second — each one a full replay, a session info call, and a rewrite of
  # the whole session aggregate to the store — to observe that nothing happened.
  #
  # So the interval is fixed only in the state where it matters. This struct is the policy
  # and nothing else: no timers, no process, no clock. It answers one question — given
  # that the coordinator has just looked and found the session busy or idle, how long
  # until it looks again — which is what makes it testable without sleeping.
  #
  # ## Why doubling, and why this cap
  #
  # Decay is geometric from `fast_ms`, so a conversation that has just gone quiet is still
  # polled quickly (25, 50, 100 …) and only a conversation that has been quiet for a while
  # pays the cap. Reaching a 1 s cap from 25 ms takes six empty polls and about 1.5 s of
  # idleness.
  #
  # The cap is bounded by what can actually arrive while the coordinator is idle. "Idle"
  # here is a checkpoint the Harness session itself just supplied: no active turn, no
  # queued turn, no approval outstanding, no retry in flight. Every event that can follow
  # from that state is one this coordinator will itself cause — a message, a steer, an
  # answered approval, an interrupt, a close — and every one of those verbs arrives as a
  # call that resets the cadence before it returns, so none of them is delayed by the cap
  # at all. What the cap does bound is the staleness of an *out-of-band* change: the
  # provider process dying underneath an idle session. A second of lag before the
  # transcript says so is not something anybody is holding a stopwatch on, and it buys a
  # 40x cut in the idle cost of every open conversation on the node.
  #
  # Nothing here decays a *busy* session. An active turn stays at `fast_ms` on purpose:
  # streaming deltas are exactly the thing a human is watching arrive, and trading first
  # token latency for wakeups the turn was going to spend anyway is a bad bargain.

  @enforce_keys [:fast_ms, :idle_cap_ms, :interval_ms]
  defstruct [:fast_ms, :idle_cap_ms, :interval_ms]

  @type t :: %__MODULE__{
          fast_ms: pos_integer(),
          idle_cap_ms: pos_integer(),
          interval_ms: pos_integer()
        }

  @doc """
  A cadence that starts fast.

  `idle_cap_ms` is clamped up to `fast_ms`: a cap below the fast interval would describe a
  policy where going idle makes the coordinator poll *harder*, which is never intended.
  """
  @spec new(pos_integer(), pos_integer()) :: t()
  def new(fast_ms, idle_cap_ms)
      when is_integer(fast_ms) and fast_ms > 0 and is_integer(idle_cap_ms) and idle_cap_ms > 0 do
    %__MODULE__{
      fast_ms: fast_ms,
      idle_cap_ms: max(idle_cap_ms, fast_ms),
      interval_ms: fast_ms
    }
  end

  @doc "How long until the next wakeup."
  @spec interval(t()) :: pos_integer()
  def interval(%__MODULE__{interval_ms: interval_ms}), do: interval_ms

  @doc "True while the cadence is at its fast interval — the state an active turn is polled in."
  @spec fast?(t()) :: boolean()
  def fast?(%__MODULE__{fast_ms: fast_ms, interval_ms: interval_ms}), do: interval_ms == fast_ms

  @doc "True once the cadence has decayed all the way to its idle ceiling."
  @spec capped?(t()) :: boolean()
  def capped?(%__MODULE__{idle_cap_ms: cap, interval_ms: interval_ms}), do: interval_ms == cap

  @doc """
  Something is happening, or is about to: poll at the fast interval again.

  Called both when a poll returned events and when a verb that can make the provider emit
  has just been dispatched, so the reset is a prediction as much as an observation.
  """
  @spec busy(t()) :: t()
  def busy(%__MODULE__{fast_ms: fast_ms} = cadence), do: %{cadence | interval_ms: fast_ms}

  @doc "Nothing is happening and nothing is pending: wait twice as long, up to the cap."
  @spec idle(t()) :: t()
  def idle(%__MODULE__{interval_ms: interval_ms, idle_cap_ms: cap} = cadence),
    do: %{cadence | interval_ms: min(interval_ms * 2, cap)}

  @doc "`busy/1` or `idle/1`, for a caller holding the predicate as a boolean."
  @spec advance(t(), boolean()) :: t()
  def advance(cadence, true), do: idle(cadence)
  def advance(cadence, false), do: busy(cadence)
end
