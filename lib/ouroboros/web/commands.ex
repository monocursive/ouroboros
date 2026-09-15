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

  `steer` is read off `info.options.capabilities`, which the runtime derives from the
  provider spec. Only an explicit `false` hides the control — an absent key is an older
  gateway that never spoke about it, and hiding a working verb on silence would be this
  surface inventing a ceiling. That is exactly `Capability::offered` on the Rust side
  (`tui/src/model.rs:626`).
  """

  alias Ouroboros.Web.Call
  alias Ouroboros.Web.Live.Composer
  alias Ouroboros.Web.Live.Rail
  alias Ouroboros.Web.Transcript.Cell

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
        label: "Steer the running turn with the draft",
        group: :turn,
        slash: "/steer",
        shortcut: nil,
        gate: &(drafted?(&1) and steerable?(&1))
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
        gate: &configurable?/1
      },
      %{
        id: "turn.model",
        label: "Change the model",
        group: :turn,
        slash: "/model",
        shortcut: nil,
        gate: &configurable?/1
      },
      %{
        id: "turn.plan",
        label: "Plan mode",
        group: :turn,
        slash: "/plan",
        shortcut: nil,
        gate: &configurable?/1
      },
      %{
        id: "turn.sandbox",
        label: "File access",
        group: :turn,
        slash: "/sandbox",
        shortcut: nil,
        gate: &(configurable?(&1) and not is_nil(reported(&1, :sandbox_mode)))
      },
      %{
        id: "turn.auto_approve",
        label: "Automatic approvals for routine actions",
        group: :turn,
        slash: "/auto-approve",
        shortcut: nil,
        gate: &(open?(&1) and serves?(&1, "interactive.respond_approval"))
      },
      %{
        id: "turn.approval",
        label: "Answer the waiting request",
        group: :turn,
        slash: "/approve",
        shortcut: nil,
        gate: &(waiting?(&1) and serves?(&1, "interactive.respond_approval"))
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
      %{
        id: "runtime.settings",
        label: "Settings",
        group: :runtime,
        slash: "/settings",
        shortcut: nil,
        gate: fn _assigns -> true end
      },

      # ------------------------------------------------------------------- Client
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
    |> Enum.filter(&match?(%{cell: %Cell.Message{speaker: :agent}}, &1))
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

  defp ended?(assigns) do
    case status(assigns) do
      nil -> false
      status -> Rail.terminal?(status)
    end
  end

  defp configurable?(assigns), do: open?(assigns) and serves?(assigns, "interactive.configure")

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

  # A steer is offered while a turn is running, where the runtime serves the verb, and
  # where the session did not declare it cannot be steered. Silence is offered.
  defp steerable?(assigns) do
    working?(assigns) and serves?(assigns, "interactive.steer") and
      capability_offered?(assigns, :steer)
  end

  @doc false
  @spec capability_offered?(map(), atom()) :: boolean()
  def capability_offered?(assigns, key) do
    options(assigns)
    |> Map.get(:capabilities)
    |> case do
      map when is_map(map) -> Map.get(map, key, :undeclared)
      _absent -> :undeclared
    end
    |> then(&(&1 not in [false, "false"]))
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
