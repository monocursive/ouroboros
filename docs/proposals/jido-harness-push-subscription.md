# Proposal: an event push seam for `jido_harness` sessions and runs

**Status:** draft, for filing upstream against `agentjido/jido_harness`
**Written against:** ref `8bf0d52f4fed0d8a9d2594000d8b3a775da16f8b` (`mix.exs` `@version "2.0.0"`), the
ref pinned in this repository's `mix.lock`
**Audience:** `jido_harness` maintainers
**Author's position:** downstream consumer (Ouroboros), not a maintainer of the library

---

## 1. Summary

`jido_harness` has no way for a consumer to learn that a session has produced new events.
The only route is to call `Jido.Harness.Session.replay/2` on a timer. That call is not
cheap on an empty result — it re-reads and re-JSON-decodes the entire session journal from
disk to discover that there is nothing new — so a consumer that wants low-latency output is
forced to pay an O(session lifetime) cost at whatever frequency it wants that latency.

This proposal asks for a push seam: an opt-in way to register a pid that receives a small
notification when a session appends events, so a consumer can call `replay/2` when there is
something to replay and not otherwise.

The proposal is deliberately narrow. It does not ask the library to deliver event payloads
to subscribers, and it does not ask it to hold any state on a subscriber's behalf. The
notification carries a sequence number and nothing else; `replay/2` remains the only way to
read events, and remains authoritative. That narrowness is what lets a consumer with a
strict durability discipline (see §6) adopt it without changing that discipline at all.

---

## 2. What exists today

Everything in this section was read at the pinned ref. Unless noted, paths are relative to
`deps/jido_harness/lib/jido_harness/` — so `journal.ex:80` is
`deps/jido_harness/lib/jido_harness/journal.ex:80`, and the two `mix.exs` and `guides/`
citations are relative to `deps/jido_harness/`.

### 2.1 There is no subscription

There is no `subscribe`, `unsubscribe`, `notify`, `monitor`, `watch`, or `await_event`
anywhere in `lib/`, and no consumer-pid registration of any kind. The library does not
depend on `phoenix_pubsub`, `jido_signal`, or any other broadcast library — its runtime
deps are `zoi`, `jason`, `telemetry`, and `erlexec` (`mix.exs:211-214`). The three
registries in `application.ex:9-11` are all `keys: :unique`, so they cannot be repurposed
as duplicate-key pub/sub.

`guides/detached_runs.md:54` states the pull-only model is deliberate — the stream "does
not subscribe the consumer process to an unbounded producer mailbox". This proposal takes
that constraint seriously rather than arguing with it; see §5.

### 2.2 The library's own streaming API is a 25 ms poll

`Session.stream/2` is not push. `CursorStream.build/4` (`lib/jido_harness/cursor_stream.ex:4`)
is a `Stream.resource` whose empty-result branch is:

```elixir
poll_interval = Keyword.get(options, :poll_interval_ms, 25)   # cursor_stream.ex:7
...
Process.sleep(poll_interval)                                  # cursor_stream.ex:23
```

So the supported way to follow a session live already performs the expensive call described
next, forty times a second, per session.

### 2.3 `replay/2` on an empty result costs a full journal rescan

`Session.replay/2` → `SessionManager.replay/2` → `GenServer.call(pid, {:replay, cursor, limit}, :infinity)`
→ `Session.EventStore.replay/3` (`session/event_store.ex:49-53`) → `EventLog.replay/4`
(`event_log.ex:47-56`).

`EventLog.replay/4` prefers the journal whenever the journal has not already failed:

```elixir
def replay(_buffer, %Journal{failed?: false} = journal, cursor, limit) do   # event_log.ex:47
```

The journal is opened unconditionally by the session worker, and `RetentionOptions`
(`retention_options.ex:6`) accepts only `[:journal_dir, :memory_bytes, :segment_bytes,
:disk_limit_bytes]` — there is no option to disable it. So the journal clause is the normal
path, and it is `Journal.replay/3` (`journal.ex:80-91`):

```elixir
state.dir
|> segment_paths()                                 # Path.wildcard over the segment dir
|> Stream.flat_map(&File.stream!(&1, :line, []))   # every line of every segment
|> Stream.map(&Jason.decode/1)                     # decode every line
|> Stream.filter(&match?({:ok, %{}}, &1))
|> Stream.map(fn {:ok, record} -> record end)
|> Stream.filter(&(Map.get(&1, "sequence", 0) > cursor))
|> Enum.take(limit)
```

When the cursor is already at the head, the `sequence > cursor` filter matches nothing, so
`Enum.take/2` can never short-circuit. The pipeline is forced to walk and JSON-decode every
event the session has ever emitted, then return `[]`. It runs inside the session
`GenServer`'s `handle_call`, so it also head-of-line blocks the worker against incoming
`{:session_adapter_event, …}` messages from the transport.

The practical shape of this: the cost of following a session grows linearly with the
session's own history, and is paid at the polling frequency whether or not anything
happened. A long conversation gets progressively more expensive to watch precisely because
it is a long conversation.

### 2.4 There is a cheap high-water mark

`SessionInfo` carries `output_cursor` (`session/info.ex:18`), populated at
`session/event_store.ex:69` from the monotonic append counter:

```elixir
output_cursor: state.sequence,
```

`EventStore.info/1` (`session/event_store.ex:57-74`) is pure in-memory struct construction —
field reads, a `:queue.len/1`, a `map_size/1`. No disk, no JSON, no list building.

This is a genuinely useful primitive and it already exists. A consumer can poll `info/1`
and call `replay/2` only when `output_cursor` has advanced. That removes the rescan without
requiring anything from upstream, and this repository treats it as the first-line fix (§7).
It does not remove the wakeups, which is what the rest of this proposal is about.

### 2.5 Every event already flows through a single `send/2`

The plumbing for push is already there; it is just hardwired.

`SessionAdapter.emit/2` is the single delivery primitive for transports
(`session/adapter.ex:30-33`):

```elixir
def emit(owner, %Event{} = event) when is_pid(owner) do
  send(owner, {:session_adapter_event, event})
  :ok
end
```

The consuming side is `SessionWorker.handle_info({:session_adapter_event, %Event{}}, state)`
(`session/worker.ex:276`), and the `owner` handed to transports is the worker itself —
`session/worker.ex:38` builds its transport context with `owner: self()`.

`SessionRequest` has no `owner`, `pid`, `subscriber`, or `notify` field: grepping
`session/request.ex` for any of those names returns nothing. So there is no supported way
for a consumer to put its own pid in that slot.

Ownership does not help either. `SessionWorker` is `use GenServer, restart: :temporary`
started under a `DynamicSupervisor` (`session/manager.ex:18-21`), and `Session.start/3`
returns a `session_id` string, not a pid — the caller holds no link, no monitor, and no
ownership relation. A consumer *can* `Registry.lookup(Jido.Harness.SessionRegistry, id)`
and `Process.monitor/1` the worker, but that yields `:DOWN` on death, not events.

### 2.6 Telemetry is the only existing push signal

`:telemetry.execute/3` fires in fifteen places. One of them is on every session append
(`session/event_store.ex:14-18`):

```elixir
:telemetry.execute([:jido, :harness, :session, :event], %{count: 1}, %{
  session_id: state.id,
  provider: state.provider,
  type: event.type
})
```

The run plane has the analogue, `[:jido, :harness, :run, :event]` (`run/worker.ex:239`).

This is a real edge trigger and a consumer can attach to it. Its limits as a substitute for
a subscription:

- Handlers run **synchronously inside the session worker's process**, so a slow or crashing
  handler degrades the session it is observing. `docs/telemetry.md:60-61` says as much, and
  `docs/telemetry.md:63-68` explicitly warns against reconstructing state from telemetry.
- Handler lookup is by event name, not by session. Every append invokes *every* attached
  handler, so N sessions each attaching their own handler is O(N²) work per event. A
  correct consumer must attach exactly one process-wide dispatcher and route by
  `session_id` itself.
- The metadata carries no sequence number, so a woken consumer still cannot tell how far
  behind it is without another call.
- It is documented as an observability surface. Building control flow on it means depending
  on something the library does not promise to keep stable.

A consumer *can* build push out of this today, and it is the best available answer at the
pinned ref. It should not have to.

---

## 3. Proposed API

Two functions on `Jido.Harness.Session`, and the mirror pair on `Jido.Harness.Run`.

```elixir
@spec subscribe(session_id :: String.t(), opts :: keyword()) ::
        {:ok, reference()} | {:error, term()}

@spec unsubscribe(session_id :: String.t(), reference()) :: :ok
```

`opts`:

| option | default | meaning |
| --- | --- | --- |
| `:pid` | `self()` | the process to notify |
| `:mode` | `:edge` | `:edge` (see §5); a strictly-every-append mode is deliberately not proposed — see §9 |

On success the subscriber receives, on each append and subject to the coalescing rules in
§5:

```elixir
{:jido_harness, :session_event, session_id :: String.t(), ref :: reference(),
 %{output_cursor: non_neg_integer()}}
```

and, when the session reaches a terminal state:

```elixir
{:jido_harness, :session_closed, session_id :: String.t(), ref :: reference(),
 %{output_cursor: non_neg_integer(), state: atom()}}
```

The run plane mirrors this exactly with `:run_event` / `:run_closed` and `run_id`.

### Why a cursor and not the event

Three reasons, in order of importance.

1. **It keeps `replay/2` authoritative.** A consumer that reads events from a push message
   and events from `replay/2` has two sources of truth and a reconciliation problem —
   including around `prepend_gap/4`, which synthesises gap markers for pruned ranges that a
   pushed event would not carry. A cursor-only notification has no such problem: it says
   "there is something past N", and the consumer reads it the one existing way.
2. **It bounds the message.** An event payload can be large; a cursor is a small integer.
   This matters directly for the mailbox concern in `guides/detached_runs.md:54`.
3. **It makes coalescing free and lossless.** Two notifications for sequences 41 and 42 are
   fully replaced by one notification for 42. That is not true of payload delivery, and it
   is what §5 leans on.

### Lifecycle

- The session monitors each subscriber and drops it on `:DOWN`. Subscriptions are process
  state, never journalled: a session restart loses them, exactly as a lost `:DOWN` would.
- `subscribe/2` returns the current `output_cursor` alongside the ref, or the consumer reads
  it from `info/1` — either way the consumer's first action is a `replay/2` from its own
  durable cursor, so **no backlog is implied or delivered**. Attaching mid-session is not a
  special case.
- `unsubscribe/2` is idempotent and safe on a dead session.

---

## 4. Implementation sketch

The change is small because §2.5 already routes every event through one point.

1. Add `subscribers: %{reference() => %{pid: pid, monitor: reference, pending: boolean}}` to
   `Jido.Harness.Session.State`.
2. Handle `{:subscribe, pid, opts}` / `{:unsubscribe, ref}` in `SessionWorker`, monitoring
   and demonitoring the subscriber pid.
3. In `Session.EventStore.append/2` — the function that already bumps `state.sequence` and
   already fires the telemetry event at `session/event_store.ex:14` — notify subscribers
   under the coalescing rule in §5. This is the only new call site.
4. Handle `{:DOWN, monitor, :process, _, _}` for a subscriber by dropping it.
5. Notify on the terminal transition in `session/lifecycle.ex` where
   `[:jido, :harness, :session, :stop]` is already emitted (`session/lifecycle.ex:166`).

`Run` mirrors it at `run/worker.ex:239` and `run/worker.ex:320`.

No change to `SessionRequest`, no change to any transport, no change to `replay/2`, no
change to the journal.

---

## 5. Backpressure

This is the part `guides/detached_runs.md:54` is right to worry about, and the design
answers it structurally rather than with a configuration knob.

**The rule: at most one un-consumed notification per subscriber at a time.**

Each subscriber record carries a `pending` flag.

- On append: if `pending` is already `true`, send nothing — the notification already in that
  subscriber's mailbox will, when read, cause a `replay/2` that returns this event too.
  Otherwise send the message and set `pending: true`.
- The consumer clears `pending` by calling `replay/2` (or `info/1`); the worker clears the
  flag when it serves that call for that subscriber.

The consequences are worth stating plainly:

- **A subscriber's mailbox cannot grow.** It holds at most one notification per
  subscription, regardless of how fast the provider emits. This is a hard structural bound,
  not a buffer size.
- **A slow consumer degrades only itself.** It gets fewer, later notifications, each of
  which resolves to a larger `replay/2` batch. It never slows the session and never slows
  another subscriber.
- **The producer does no unbounded work.** Notification is a `send/2` to at most one pid per
  subscriber per append, skipped entirely while a notification is outstanding.
- **Notifications are a hint, never a record.** A dropped, coalesced, or missed notification
  costs latency and nothing else, because the consumer's durable cursor plus `replay/2` is
  still the whole truth. This is what makes the feature safe to add: correctness does not
  depend on it.

A subscriber that wants a heartbeat regardless of provider activity keeps its own slow
timer. The library should not grow one.

---

## 6. How Ouroboros's checkpoint-before-broadcast discipline survives

This matters because it is the reason Ouroboros polls rather than streams today, and a push
seam that broke it would be unusable here.

`docs/ARCHITECTURE.md` describes the invariant for both planes: the coordinator "explicitly
polls `Jido.Harness.Run.replay/2`, persists cursor plus projected events in one checkpoint,
and only then broadcasts them", and `subscribe/2` snapshots the backlog inside that same
process to eliminate the replay-then-subscribe race.

The proposed seam does not touch any of that, because it changes only *when the coordinator
wakes up*:

| step | today | with push |
| --- | --- | --- |
| wake | 25 ms timer | notification message (timer kept as a slow backstop) |
| read | `Session.replay/2` from durable cursor | unchanged |
| checkpoint | cursor + projected events, one write | unchanged |
| broadcast | after the checkpoint succeeds | unchanged |

Specifically:

- **The durable cursor stays the only source of truth.** The pushed `output_cursor` is not
  written anywhere and is not compared against for correctness — at most it is used to skip
  a `replay/2` that would return nothing.
- **No event arrives out of band.** Since the notification carries no payload, there is no
  second path by which an event could reach a subscriber before it was checkpointed. This is
  the single most important property, and it is a consequence of the cursor-only shape
  rather than of any care taken by the consumer.
- **A lost notification is a latency event, not a correctness event.** The coordinator keeps
  a slow timer as a backstop, so the worst case of a missed or coalesced notification is
  that the events are drained on the next heartbeat instead of immediately.
- **Ordering is unchanged** because ordering was never the notification's job.

In other words the seam is adoptable here as a pure latency-and-cost improvement, with no
change to the durability argument. That is the property we would want reviewed hardest.

---

## 7. What this repository does in the meantime

Recorded so the proposal is honest about what it is and is not blocking.

At the pinned ref, with no upstream change, Ouroboros:

1. **Holds exactly one poll timer per coordinator** (`Ouroboros.Poll.Timer`). Several paths
   ask for a wakeup for the same reason at the same moment; armed naively each one became a
   self-perpetuating chain, so the real wakeup rate was the interval divided by the number
   of chains accumulated over the session's life.
2. **Decays the interval when a conversation is between turns** (`Ouroboros.Poll.Cadence`):
   25 ms while a turn is active or a poll returned events, doubling to a 1 s ceiling once
   the Harness session reports itself idle with nothing outstanding, and reset instantly by
   any verb that can make a provider emit. This cuts the idle cost of an open conversation
   by 40x and does not touch active-turn latency.
3. **Gates `replay/2` behind the `output_cursor` high-water mark** (§2.4) — every poll
   calls the cheap `info/1` first and skips the replay entirely unless the cursor has
   advanced past the coordinator's durable one, so a poll that finds nothing new no
   longer pays the §2.3 rescan at all, busy or idle. The failure surface moved with it:
   an unreachable session now reports `:harness_session_info_failed`
   (`:harness_info_failed` on the coding plane) where it used to report a replay
   failure, and the test doubles derive `info`'s cursor from their `replay` fixture so
   the two cannot disagree. The comparison itself was already trusted before the change:
   `mirrored_through_result?/1` in both coordinators compares the durable cursor against
   `output_cursor`.

So the journal rescan is now paid only when there are events to read. What remains is the
wakeups themselves — one in-memory `info/1` call per poll, once a second per idle open
conversation — a floor that no longer grows with conversation length, and that only a
push seam can remove.

---

## 8. Smaller asks, if the full seam is unwelcome

In descending order of value, any one of these would help materially:

1. **Document `[:jido, :harness, :session, :event]` as a supported control-plane signal**
   and add `sequence` to its metadata. This costs one map key and turns an observability
   surface into a usable — if awkward, see §2.6 — push edge.
2. **Make the journal optional in `RetentionOptions`.** A consumer that checkpoints every
   event durably on its own side (Ouroboros does) is paying for a second on-disk copy and
   then paying again to read it back. `failed?: true` already proves the buffer-only path
   works (`event_log.ex:53`).
3. **Short-circuit `Journal.replay/3` on an empty range.** Comparing the requested cursor
   against the in-memory `state.sequence` before touching the filesystem would make the
   common empty poll O(1) instead of O(session), for a few lines and no API change. This is
   the cheapest fix in this document and would benefit every consumer of `Session.stream/2`
   immediately.
4. **Expose the segment index** so `replay/2` can seek rather than rescan.

---

## 9. Open questions for maintainers

- Is the `pending`-flag coalescing in §5 acceptable, or is a strictly-every-event mode
  needed for some consumer? The proposal assumes not, and that assumption is load-bearing
  for the mailbox bound.
- Should `subscribe/2` return the cursor at subscription time, or should consumers always
  read it from `info/1`? Returning it removes a round trip and a race window.
- Should the run plane's terminal notification carry the `RunResult`, or stay symmetric with
  the session plane and carry only a cursor and state? Symmetry is proposed; convenience
  argues the other way.
- Is `:pg` (already in OTP, no new dependency) preferable to per-session monitored
  subscriber maps? It would make cross-node subscription free, but it loses the per-
  subscriber `pending` flag that §5 depends on.
