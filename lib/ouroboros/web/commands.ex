defmodule Ouroboros.Web.Commands do
  @moduledoc """
  Every verb this surface can run, as one list.

  The palette, the shortcut sheet and (in a later slice) a shared `priv/ui/commands.json`
  all read this rather than each keeping a list of their own. A verb added to the web is
  added here or it exists nowhere a reader can find it.

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
      %{
        id: "session.new",
        label: "New session",
        group: :session,
        slash: "/new",
        shortcut: "n",
        gate: &serves?(&1, "interactive.start")
      },
      %{
        id: "session.switch",
        label: "Switch session",
        group: :session,
        slash: "/switch",
        shortcut: "/",
        gate: fn _assigns -> true end
      },
      %{
        id: "session.rename",
        label: "Rename this session",
        group: :session,
        slash: "/rename",
        shortcut: nil,
        gate: &(open?(&1) and serves?(&1, "interactive.rename"))
      },
      %{
        id: "session.end",
        label: "End this session",
        group: :session,
        slash: "/end",
        shortcut: nil,
        gate: &(open?(&1) and not ended?(&1) and serves?(&1, "interactive.close"))
      },
      %{
        id: "session.delete",
        label: "Delete this session",
        group: :session,
        slash: "/delete",
        shortcut: nil,
        gate: &(open?(&1) and ended?(&1) and serves?(&1, "interactive.delete"))
      },

      # ui-parity W3
      %{
        id: "session.fork",
        label: "Fork this session",
        group: :session,
        slash: "/fork",
        shortcut: nil,
        gate: &forkable?/1
      },
      %{
        id: "session.handoff",
        label: "Hand off to a new session",
        group: :session,
        slash: "/handoff",
        shortcut: nil,
        gate:
          &(open?(&1) and not ended?(&1) and serves?(&1, "interactive.handoff") and
              native_transport?(&1))
      },

      # --------------------------------------------------------------------- Turn
      %{
        id: "turn.send",
        label: "Send the draft",
        group: :turn,
        slash: "/send",
        shortcut: "⏎",
        gate: &(drafted?(&1) and not queueing?(&1) and serves?(&1, "interactive.send_message"))
      },
      %{
        id: "turn.queue",
        label: "Queue the draft",
        group: :turn,
        slash: "/queue",
        shortcut: "⏎",
        gate: &(drafted?(&1) and queueing?(&1) and serves?(&1, "interactive.follow_up"))
      },
      %{
        id: "turn.steer",
        label: "Steer the running turn",
        group: :turn,
        slash: "/steer",
        shortcut: nil,
        # Not `drafted?`: this row leads to the Steer button rather than pressing it, and
        # the words a steer carries must come from the form. See `command/2`.
        gate: &steerable?/1
      },
      %{
        id: "turn.interrupt",
        label: "Interrupt the running turn",
        group: :turn,
        slash: "/interrupt",
        shortcut: "esc",
        gate: &(working?(&1) and serves?(&1, "interactive.interrupt"))
      },
      %{
        id: "turn.retry",
        label: "Retry the last message",
        group: :turn,
        slash: "/retry",
        shortcut: nil,
        gate: &(retryable?(&1) and serves?(&1, "interactive.retry_turn"))
      },
      %{
        id: "turn.effort",
        label: "Thinking effort",
        group: :turn,
        slash: "/effort",
        shortcut: nil,
        gate: &reconfigurable?/1
      },
      %{
        id: "turn.model",
        label: "Change the model",
        group: :turn,
        slash: "/model",
        shortcut: nil,
        gate: &remodelable?/1
      },
      %{
        id: "turn.plan",
        label: "Plan mode",
        group: :turn,
        slash: "/plan",
        shortcut: nil,
        gate: &reconfigurable?/1
      },
      %{
        id: "turn.sandbox",
        label: "File access",
        group: :turn,
        slash: "/sandbox",
        shortcut: nil,
        gate: &(reconfigurable?(&1) and not is_nil(reported(&1, :sandbox_mode)))
      },
      %{
        id: "turn.auto_approve",
        label: "Automatic approvals for routine actions",
        group: :turn,
        slash: "/auto-approve",
        shortcut: nil,
        gate: &(open?(&1) and not ended?(&1) and serves?(&1, "interactive.respond_approval"))
      },
      %{
        id: "turn.approval",
        label: "Answer the waiting request",
        group: :turn,
        slash: "/approve",
        shortcut: nil,
        gate: &(waiting?(&1) and serves?(&1, "interactive.respond_approval"))
      },

      # ui-parity W3. `!` is a turn verb that is never a turn: the composer claims the
      # draft and `workspace.exec` runs it. Operate-scope by the method table, so a
      # read-scope endpoint never lists it.
      %{
        id: "turn.shell",
        label: "Run a command in the workspace",
        group: :turn,
        slash: "!",
        shortcut: nil,
        gate: &shell_offered?/1
      },

      # ------------------------------------------------------------- Conversation
      %{
        id: "conversation.copy",
        label: "Copy the last message",
        group: :conversation,
        slash: "/copy",
        shortcut: nil,
        gate: &(not is_nil(last_agent_message(&1)))
      },
      %{
        id: "conversation.copy_source",
        label: "Copy the last message's Markdown",
        group: :conversation,
        slash: "/copy source",
        shortcut: nil,
        gate: &(not is_nil(last_agent_message(&1)))
      },
      %{
        id: "conversation.history",
        label: "Load earlier messages",
        group: :conversation,
        slash: "/history",
        shortcut: nil,
        gate: &(Map.get(&1, :truncated, 0) > 0)
      },

      # ui-parity W3
      %{
        id: "conversation.details",
        label: "Event details",
        group: :conversation,
        slash: "/details",
        shortcut: nil,
        gate: &(open?(&1) and serves?(&1, "interactive.event_detail"))
      },
      %{
        id: "conversation.export",
        label: "Export this transcript",
        group: :conversation,
        slash: "/export",
        shortcut: nil,
        gate: &(open?(&1) and serves?(&1, "interactive.replay"))
      },
      %{
        id: "conversation.backtrack",
        label: "Go back to an earlier message",
        group: :conversation,
        slash: "/backtrack",
        shortcut: nil,
        # Two verbs behind one row, and the row stands where either can run: a fork, or
        # putting an earlier message back in the composer. A dialog that could offer
        # neither is a list with nothing under it.
        gate: &(open?(&1) and (forkable?(&1) or resendable?(&1)))
      },
      %{
        id: "conversation.rewind",
        label: "Rewind to an earlier turn",
        group: :conversation,
        slash: "/rewind",
        shortcut: nil,
        # Both verbs, because the row leads to a flow whose only act is the second one:
        # `interactive.rewind_points` is read-scope and `interactive.rewind` is not, so a
        # read-scope endpoint could otherwise draw two screens ending in a refusal.
        gate:
          &(open?(&1) and not ended?(&1) and serves?(&1, "interactive.rewind_points") and
              serves?(&1, "interactive.rewind") and native_transport?(&1))
      },
      %{
        id: "conversation.compact",
        label: "Compact this conversation",
        group: :conversation,
        slash: "/compact",
        shortcut: nil,
        gate:
          &(open?(&1) and not ended?(&1) and serves?(&1, "interactive.compact") and
              native_transport?(&1))
      },
      %{
        id: "conversation.context",
        label: "Context",
        group: :conversation,
        slash: "/context",
        shortcut: nil,
        # Every transport answers this one, with different amounts of truth, so it is
        # gated on the method alone (`tui/src/ui/app/native.rs:92-95`).
        gate: &(open?(&1) and serves?(&1, "interactive.context"))
      },

      # ------------------------------------------------------------------ Runtime
      %{
        id: "runtime.status",
        label: "Runtime status",
        group: :runtime,
        slash: "/status",
        shortcut: nil,
        gate: &serves?(&1, "runtime.status")
      },
      %{
        id: "runtime.audit",
        label: "Audit",
        group: :runtime,
        slash: "/audit",
        shortcut: nil,
        gate: &serves?(&1, "audit.status")
      },

      # ui-parity W3. No session state in the gate because the verb has none to ask
      # about: with a session open it is routed to that session's node, and without one
      # it answers for this runtime, which is the only other machine there is to mean.
      %{
        id: "runtime.mcp",
        label: "MCP servers",
        group: :runtime,
        slash: "/mcp",
        shortcut: nil,
        gate: &serves?(&1, "mcp.list")
      },

      # ------------------------------------------------------------------- Client
      %{
        id: "client.settings",
        label: "Settings",
        group: :client,
        slash: "/settings",
        shortcut: nil,
        gate: fn _assigns -> true end
      },
      %{
        id: "client.theme",
        label: "Switch theme",
        group: :client,
        slash: "/theme",
        shortcut: nil,
        gate: fn _assigns -> true end
      },
      %{
        id: "client.shortcuts",
        label: "Keyboard shortcuts",
        group: :client,
        slash: "/keys",
        shortcut: "?",
        gate: fn _assigns -> true end
      },
      %{
        id: "client.notifications",
        label: "Notify me when a session needs me",
        group: :client,
        slash: "/notify",
        shortcut: nil,
        gate: fn _assigns -> true end
      }
    ]
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
