defmodule Ouroboros.Web.Commands do
  @moduledoc """
  Every verb this surface can run, as one list.

  The palette and the shortcut sheet read this rather than each keeping a list of their
  own. A verb added to the web is added here or it exists nowhere a reader can find it.

  ## S1: the wording comes from `priv/ui/commands.json`

  The heading, the label and the slash spelling of every row below are read out of that
  file at compile time, by id, and the terminal client's palette reads the same bytes
  (`tui/src/ui/app/overlays.rs`). What stays here is the *gate*, and the list itself —
  which verbs this surface has, and in what order it draws them. A row whose `web` block
  in the file is `null` is a verb the terminal client has and this one does not; a row
  named here that the file does not carry fails to compile.

  Where the two surfaces genuinely spell one verb differently — this deck's `session.end`
  ends but does not remove, its `conversation.details` opens one event rather than
  toggling a level, `/status` is a page here and a tab there, and `/keys` opens the only
  sheet this surface has — the file carries the terminal client's spelling and this one's
  beside it, with a `note` saying why. Everything else is written once.

  ## A gate is a question about the runtime, not a preference

  Each row carries a `gate`: a one-argument function of the deck's assigns that answers
  whether this verb can run *here, now*. Two different facts go into every one of them and
  neither is optional:

    * **does this build serve the method at this scope** — `Ouroboros.Web.Call.available?/2`,
      the same question `hello` answers for a terminal client. A read-scope endpoint lists
      no mutating verb, and a build without a method lists nothing that needs it.
    * **does the session's own state allow it** — an interrupt with no turn running, a
      delete of a session that has not ended, a steer into a transport that declared it
      cannot be steered.

  A row whose gate answers `false` is not drawn. That is the honesty invariant in its
  narrowest form: the palette is a list of things that will happen, not a menu of things
  that might be refused.

  ## The five groups, in one order

  `docs/proposals/ui-parity-plan.md` fixes them, and the same five head the TUI palette,
  the TUI `?` panel and this one. `groups/0` is the order; nothing sorts by anything else.

  ## Capabilities: silence is not a refusal

  Four keys of `info.options.capabilities` gate controls here — `steer`,
  `dynamic_model`, `dynamic_configuration` and (W3) `fork` — and all four are read the way
  `Capability::decode`/`Capability::offered` read them (`tui/src/model.rs:606-628`):

    * **boolean `false` is the only refusal.** It is the one value the runtime sends on
      purpose to say a transport cannot do this.
    * **a string is a mechanism, not a verdict.** `"native"`, `"managed"` — and, yes, a
      mechanism whose name happens to be `"false"` — are all declarations that it *can*.
    * **absence, `nil`, and a map this build cannot read are silence**, which keeps
      whatever the client did before the declaration existed. Hiding a working verb on
      silence would be this surface inventing a ceiling.

  The map crosses `Ouroboros.Gateway.Wire` with atom keys in-process and string keys
  through JSON, so both spellings are read. A missing map is silence for every key.

  A fifth key, `transport`, is read differently and on purpose: it is a *label* rather
  than a yes/no, so `native_transport?/1` compares it rather than asking whether it was
  refused. See that function.
  """

  alias Ouroboros.Web.Call
  alias Ouroboros.Web.Live.Composer
  alias Ouroboros.Web.Live.Rail
  alias Ouroboros.Web.Transcript.Cell
  alias Ouroboros.Web.Watch

  @type group :: :session | :turn | :conversation | :runtime | :client

  @type t :: %{
          id: String.t(),
          label: String.t(),
          group: group(),
          slash: String.t(),
          shortcut: String.t() | nil,
          gate: (map() -> boolean())
        }

  @groups [:session, :turn, :conversation, :runtime, :client]

  @group_labels %{
    session: "Session",
    turn: "Turn",
    conversation: "Conversation",
    runtime: "Runtime",
    client: "Client"
  }

  # S1. The shared catalogue, read at compile time.
  #
  # The *source* path, not `:code.priv_dir/1`: this is read while the module is being
  # compiled, when there is no built application to ask for a priv directory, and
  # `@external_resource` on the same path is what makes `mix` recompile this module when
  # the file changes. The bytes end up in the beam, so a release cannot ship a catalogue
  # that disagrees with the code that reads it.
  @catalogue_path Path.expand("../../../priv/ui/commands.json", __DIR__)
  @external_resource @catalogue_path

  # Not `String.to_existing_atom/1`: a group the file invents should stop the build with
  # the name it invented, rather than either minting an atom or failing in a way that
  # points at the reader instead of at the row.
  @group_atoms %{
    "session" => :session,
    "turn" => :turn,
    "conversation" => :conversation,
    "runtime" => :runtime,
    "client" => :client
  }

  # The web's half of every row that has one: the heading, the wording and the slash
  # spelling this surface draws. A row whose `web` block is `null` is a verb the terminal
  # client has and this one does not, and it is absent here for that reason. Gates stay in
  # `all/0` below, because whether a verb can run is a question about this runtime rather
  # than a fact about a catalogue.
  @catalogue (for %{"id" => id, "web" => web} = entry <-
                    @catalogue_path |> File.read!() |> Jason.decode!(),
                  is_map(web),
                  into: %{} do
                {id,
                 %{
                   label: web["label"] || entry["label"],
                   group: Map.fetch!(@group_atoms, entry["group"]),
                   slash: web["slash"] || entry["slash"]
                 }}
              end)

  @doc "The five groups, in the order every surface draws them."
  @spec groups() :: [group()]
  def groups, do: @groups

  @doc "One group's heading."
  @spec group_label(group()) :: String.t()
  def group_label(group) when group in @groups, do: Map.fetch!(@group_labels, group)

  @doc """
  The whole catalogue, in group order.

  Ungated: this is the list of verbs that exist, not the list that can run. Callers that
  draw a menu want `available/1`.
  """
  @spec all() :: [t()]
  def all do
    [
      # ------------------------------------------------------------------ Session
      command("session.new", "n", &serves?(&1, "interactive.start")),
      command("session.switch", "/", fn _assigns -> true end),
      command("session.rename", nil, &(open?(&1) and serves?(&1, "interactive.rename"))),
      command(
        "session.end",
        nil,
        &(open?(&1) and not ended?(&1) and serves?(&1, "interactive.close"))
      ),
      command(
        "session.delete",
        nil,
        &(open?(&1) and ended?(&1) and serves?(&1, "interactive.delete"))
      ),

      # ui-parity W3
      command("session.fork", nil, &forkable?/1),
      command(
        "session.handoff",
        nil,
        &(open?(&1) and not ended?(&1) and serves?(&1, "interactive.handoff") and
            native_transport?(&1))
      ),

      # --------------------------------------------------------------------- Turn
      command(
        "turn.send",
        "⏎",
        &(drafted?(&1) and not queueing?(&1) and serves?(&1, "interactive.send_message"))
      ),
      command(
        "turn.queue",
        "⏎",
        &(drafted?(&1) and queueing?(&1) and serves?(&1, "interactive.follow_up"))
      ),
      # Not `drafted?`: this row leads to the Steer button rather than pressing it, and
      # the words a steer carries must come from the form. See `command/2`.
      command("turn.steer", nil, &steerable?/1),
      command("turn.interrupt", "esc", &(working?(&1) and serves?(&1, "interactive.interrupt"))),
      command("turn.retry", nil, &(retryable?(&1) and serves?(&1, "interactive.retry_turn"))),
      command("turn.effort", nil, &reconfigurable?/1),
      command("turn.model", nil, &remodelable?/1),
      command("turn.plan", nil, &reconfigurable?/1),
      command(
        "turn.sandbox",
        nil,
        &(reconfigurable?(&1) and not is_nil(reported(&1, :sandbox_mode)))
      ),
      command(
        "turn.auto_approve",
        nil,
        &(open?(&1) and not ended?(&1) and serves?(&1, "interactive.respond_approval"))
      ),
      command(
        "turn.approval",
        nil,
        &(waiting?(&1) and serves?(&1, "interactive.respond_approval"))
      ),

      # ui-parity W3. `!` is a turn verb that is never a turn: the composer claims the
      # draft and `workspace.exec` runs it. Operate-scope by the method table, so a
      # read-scope endpoint never lists it.
      command("turn.shell", nil, &shell_offered?/1),

      # ------------------------------------------------------------- Conversation
      command("conversation.copy", nil, &(not is_nil(last_agent_message(&1)))),
      command("conversation.copy_source", nil, &(not is_nil(last_agent_message(&1)))),
      command("conversation.history", nil, &(Map.get(&1, :truncated, 0) > 0)),

      # ui-parity W3
      command(
        "conversation.details",
        nil,
        &(open?(&1) and serves?(&1, "interactive.event_detail"))
      ),
      command("conversation.export", nil, &(open?(&1) and serves?(&1, "interactive.replay"))),
      # Two verbs behind one row, and the row stands where either can run: a fork, or
      # putting an earlier message back in the composer. A dialog that could offer
      # neither is a list with nothing under it.
      command("conversation.backtrack", nil, &(open?(&1) and (forkable?(&1) or resendable?(&1)))),
      # Both verbs, because the row leads to a flow whose only act is the second one:
      # `interactive.rewind_points` is read-scope and `interactive.rewind` is not, so a
      # read-scope endpoint could otherwise draw two screens ending in a refusal.
      command(
        "conversation.rewind",
        nil,
        &(open?(&1) and not ended?(&1) and serves?(&1, "interactive.rewind_points") and
            serves?(&1, "interactive.rewind") and native_transport?(&1))
      ),
      command(
        "conversation.compact",
        nil,
        &(open?(&1) and not ended?(&1) and serves?(&1, "interactive.compact") and
            native_transport?(&1))
      ),
      # Every transport answers this one, with different amounts of truth, so it is
      # gated on the method alone (`tui/src/ui/app/native.rs:92-95`).
      command("conversation.context", nil, &(open?(&1) and serves?(&1, "interactive.context"))),

      # ------------------------------------------------------------------ Runtime
      command("runtime.status", nil, &serves?(&1, "runtime.status")),
      command("runtime.audit", nil, &serves?(&1, "audit.status")),

      # ui-parity W3. No session state in the gate because the verb has none to ask
      # about: with a session open it is routed to that session's node, and without one
      # it answers for this runtime, which is the only other machine there is to mean.
      command("runtime.mcp", nil, &serves?(&1, "mcp.list")),

      # ------------------------------------------------------------------- Client
      command("client.settings", nil, fn _assigns -> true end),
      command("client.theme", nil, fn _assigns -> true end),
      command("client.shortcuts", "?", fn _assigns -> true end),
      command("client.notifications", nil, fn _assigns -> true end)
    ]
  end

  # One row: the gate written above, joined to the heading, the wording and the slash
  # spelling `priv/ui/commands.json` gives the same id. An id the file does not carry —
  # or carries with no `web` block — raises here, and `catalogue_test.exs` reaches it
  # first.
  @spec command(String.t(), String.t() | nil, (map() -> boolean())) :: t()
  defp command(id, shortcut, gate) do
    %{label: label, group: group, slash: slash} = Map.fetch!(@catalogue, id)

    %{id: id, label: label, group: group, slash: slash, shortcut: shortcut, gate: gate}
  end

  @doc """
  The catalogue filtered to what can actually run, given the deck's assigns.

  This is the enforcement point for the honesty invariant, and it is the same function the
  palette's *run* handler consults before it does anything — so a row that went stale while
  the modal was open cannot be run by pressing Enter on it.
  """
  @spec available(map()) :: [t()]
  def available(assigns) when is_map(assigns) do
    Enum.filter(all(), fn command -> safe_gate(command, assigns) end)
  end

  @doc "Whether one command id is runnable right now."
  @spec available?(map(), String.t()) :: boolean()
  def available?(assigns, id) when is_map(assigns) and is_binary(id) do
    Enum.any?(available(assigns), &(&1.id == id))
  end

  @doc """
  Rows matching `query`, keeping group order.

  The match is over the label, the slash spelling and the group's own heading, so typing
  `turn` narrows to the Turn group exactly as the TUI palette does (review §2.2).
  """
  @spec search([t()], String.t() | nil) :: [t()]
  def search(commands, query) when is_list(commands) and query in [nil, ""], do: commands

  def search(commands, query) when is_list(commands) and is_binary(query) do
    case query |> String.trim() |> String.downcase() do
      "" ->
        commands

      needle ->
        Enum.filter(commands, fn command ->
          [command.label, command.slash, group_label(command.group), command.shortcut || ""]
          |> Enum.map_join(" ", &String.downcase/1)
          |> String.contains?(needle)
        end)
    end
  end

  @doc """
  Rows bucketed by group, in group order, with empty groups dropped.

  Returns `[{group, [command]}]` so a heading is drawn once and only where it has rows
  under it.
  """
  @spec grouped([t()]) :: [{group(), [t()]}]
  def grouped(commands) when is_list(commands) do
    for group <- @groups,
        rows = Enum.filter(commands, &(&1.group == group)),
        rows != [] do
      {group, rows}
    end
  end

  @doc """
  The newest agent message the deck is holding, as `{dom_id, markdown}`.

  `dom_id` is the stream row the browser can read the *rendered* text out of; `markdown`
  is what the model actually sent. Two different things to copy, and this is the one place
  either is found. `nil` where the drawn window holds no agent message.
  """
  @spec last_agent_message(map()) :: {String.t(), String.t()} | nil
  def last_agent_message(assigns) when is_map(assigns) do
    assigns
    |> Map.get(:cells, %{})
    |> case do
      cells when is_map(cells) -> Map.values(cells)
      _absent -> []
    end
    # `streaming: true` is a draft the model is still writing, which is why `cells.ex`
    # withholds the buttons from it. Copying half a sentence is not copying the message.
    |> Enum.filter(&match?(%{cell: %Cell.Message{speaker: :agent, streaming: false}}, &1))
    |> Enum.sort_by(& &1.index)
    |> List.last()
    |> case do
      nil -> nil
      item -> {"cells-#{item.id}", item.cell.text}
    end
  end

  # ------------------------------------------------------------------------------------
  # The facts a gate is allowed to ask about
  # ------------------------------------------------------------------------------------

  # A gate that raised on an assigns shape it did not expect would take the whole deck
  # down to draw a menu. It answers "not offered" instead, which is the safe direction:
  # a verb nobody can find is a bug, a verb that crashed the page is an outage.
  defp safe_gate(command, assigns) do
    command.gate.(assigns) == true
  rescue
    _error -> false
  end

  @doc false
  @spec serves?(map(), String.t()) :: boolean()
  def serves?(assigns, method) do
    case Map.get(assigns, :scope) do
      scope when scope in [:read, :operate] -> Call.available?(scope, method)
      _unknown -> false
    end
  end

  defp open?(assigns), do: match?({:interactive, _id}, Map.get(assigns, :open))

  # Two sources, and the watch is the fresher one: a `session_closed` in the held ledger
  # is three seconds ahead of the status poll, and for three seconds the palette would
  # otherwise keep offering verbs into a conversation that has ended.
  defp ended?(assigns) do
    watched =
      case Map.get(assigns, :watch) do
        %Watch{} = watch -> Watch.ended?(watch)
        _absent -> false
      end

    watched or Rail.terminal?(status(assigns))
  end

  # Three questions, not one. A session that has ended takes no configuration at all; a
  # transport that declared `dynamic_configuration: false` (or `dynamic_model: false`)
  # takes it for everything except the thing it named — which is exactly how the terminal
  # client reads the pair (`tui/src/ui/app/session.rs:1576-1580`).
  defp configurable?(assigns) do
    open?(assigns) and not ended?(assigns) and serves?(assigns, "interactive.configure")
  end

  defp reconfigurable?(assigns), do: configurable?(assigns, :configuration)
  defp remodelable?(assigns), do: configurable?(assigns, :model)

  @doc """
  Whether one half of `interactive.configure` can be used here, now.

  `:configuration` covers plan, effort and sandbox; `:model` covers the model alone,
  because the runtime declares `dynamic_model` and `dynamic_configuration` separately and
  a transport can serve one and refuse the other. Public for the same reason
  `steerable?/1` is: `Ouroboros.Web.Live.DeckLive` asks it again before it calls, so the
  catalogue row and the handler cannot answer differently.
  """
  @spec configurable?(map(), :configuration | :model) :: boolean()
  def configurable?(assigns, half) when is_map(assigns) and half in [:configuration, :model] do
    key = if half == :model, do: :dynamic_model, else: :dynamic_configuration

    configurable?(assigns) and capability_offered?(assigns, key)
  end

  defp drafted?(assigns) do
    open?(assigns) and not ended?(assigns) and
      String.trim(Map.get(assigns, :draft) || "") != ""
  end

  defp turn(assigns) do
    case Map.get(assigns, :turn) do
      %{running?: _} = turn -> turn
      _absent -> %{running?: false, spoke?: false, failed?: false, turn_id: nil, queued: 0}
    end
  end

  defp working?(assigns), do: open?(assigns) and Composer.working?(turn(assigns), status(assigns))

  defp queueing?(assigns),
    do: Composer.verb(turn(assigns), status(assigns)) == "interactive.follow_up"

  @doc """
  Whether a steer can happen here, now.

  Public because the handler asks it too. A steer is an injection into a call that is
  running *now*, so all four conditions are load-bearing: an open, unfinished session, a
  turn in flight, a runtime that serves the verb at this scope, and a transport that did
  not declare it cannot be steered. `Ouroboros.Web.Live.DeckLive` re-asks this before it
  sends — a form field is browser input, and the button that draws it is not a gate.
  """
  @spec steerable?(map()) :: boolean()
  def steerable?(assigns) when is_map(assigns) do
    open?(assigns) and not ended?(assigns) and working?(assigns) and
      serves?(assigns, "interactive.steer") and capability_offered?(assigns, :steer)
  end

  # ------------------------------------------------------------------------------------
  # ui-parity W3 — the gates the remaining verbs are asked through
  # ------------------------------------------------------------------------------------

  @doc """
  Whether this conversation is one the runtime holds itself.

  `options.capabilities.transport` is a **label**, not a yes/no, and this reads it exactly
  as `App::native_verb_offered` does (`tui/src/ui/app/native.rs:56-74`): `native` can,
  anything else named cannot, and **silence is offerable** — hiding a verb because a
  gateway never spoke about transports would be this surface inventing a ceiling. The
  atom `:native` and the string `"native"` are the same declaration, in-process and
  across JSON.

  Four verbs are gated on it — compact, handoff, rewind and the rewind's own points —
  because only a native session hands this runtime the conversation to work on.
  """
  @spec native_transport?(map()) :: boolean()
  def native_transport?(assigns) when is_map(assigns) do
    case assigns |> options() |> capabilities() |> declared(:transport) do
      nil -> true
      transport -> to_string(transport) == "native"
    end
  end

  @doc """
  Whether a fork can happen here, now.

  The backtrack dialog's second verb and the Session group's own row, asked the same way:
  the gateway serves `interactive.fork`, and the transport did not declare `fork: false`
  (`tui/src/ui/app/session.rs:946-948`). Not gated on the session having ended — branching
  a finished conversation is a thing an operator may well want, and whether this provider
  can is the runtime's answer rather than this surface's.
  """
  @spec forkable?(map()) :: boolean()
  def forkable?(assigns) when is_map(assigns) do
    open?(assigns) and serves?(assigns, "interactive.fork") and
      capability_offered?(assigns, :fork)
  end

  @doc """
  Whether an earlier message could be put back in the composer and sent again.

  The backtrack dialog's first verb. It removes nothing, so the only question is whether
  this conversation can still be spoken into at all.
  """
  @spec resendable?(map()) :: boolean()
  def resendable?(assigns) when is_map(assigns) do
    open?(assigns) and not ended?(assigns) and serves?(assigns, "interactive.send_message")
  end

  @doc """
  Whether `!` is offered — an operator command in the session's own workspace.

  `workspace.exec` is an operate-scope method, so a read-scope endpoint fails the first
  half and the row is never drawn. The session's posture is deliberately *not* part of
  this: a rule may permit the command and only the permission engine knows that, so the
  control is offered and the runtime's refusal is what is shown
  (`tui/src/ui/app/native.rs:96-101`).
  """
  @spec shell_offered?(map()) :: boolean()
  def shell_offered?(assigns) when is_map(assigns) do
    match?({:interactive, _id}, Map.get(assigns, :open)) and not ended?(assigns) and
      serves?(assigns, "workspace.exec")
  end

  @doc """
  Whether chrome depending on one declared capability stays on screen.

  Everything but a boolean `false`. See the moduledoc: this is `Capability::offered`
  (`tui/src/model.rs:626`) with the same reading of a string, of silence, and of a shape
  this build does not recognise.
  """
  @spec capability_offered?(map(), atom()) :: boolean()
  def capability_offered?(assigns, key) do
    assigns
    |> options()
    |> capabilities()
    |> declared(key)
    |> Kernel.!==(false)
  end

  defp capabilities(options) do
    case Map.get(options, :capabilities) || Map.get(options, "capabilities") do
      map when is_map(map) -> map
      _absent_or_unreadable -> %{}
    end
  end

  # Atom keys in-process, string keys across JSON. Neither spelling is the canonical one
  # and a key found under either is the runtime having spoken.
  defp declared(capabilities, key) do
    case Map.fetch(capabilities, key) do
      {:ok, value} -> value
      :error -> Map.get(capabilities, Atom.to_string(key))
    end
  end

  defp retryable?(assigns) do
    open?(assigns) and not working?(assigns) and
      match?(%{status: :idle, last_turn: %{status: :failed, retryable: true}}, assigns[:info])
  end

  defp waiting?(assigns) do
    case Map.get(assigns, :approvals) do
      [_first | _rest] -> true
      _none -> false
    end
  end

  @doc false
  @spec options(map()) :: map()
  def options(assigns) do
    case Map.get(assigns, :info) do
      %{options: options} when is_map(options) -> options
      _absent -> %{}
    end
  end

  @doc false
  @spec reported(map(), atom()) :: String.t() | nil
  def reported(assigns, key) do
    case assigns |> options() |> Map.get(key) do
      nil -> nil
      value -> to_string(value)
    end
  end

  # The session's status, preferring the vitals read over the three-second list.
  defp status(assigns) do
    from_info =
      case Map.get(assigns, :info) do
        %{status: status} -> status
        _absent -> nil
      end

    from_info || row_status(assigns)
  end

  defp row_status(assigns) do
    with {plane, id} <- Map.get(assigns, :open),
         rows when is_list(rows) <- Map.get(assigns, :rows),
         %Rail.Row{status: status} <- Enum.find(rows, &(&1.plane == plane and &1.id == id)) do
      status
    else
      _unknown -> nil
    end
  end
end
