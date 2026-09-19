defmodule Ouroboros.Web.Live.DevicesLive do
  @moduledoc """
  `/devices`: the machines around this one, and putting Ouroboros on one of them.

  Two halves. The **list** is one read of `fleet.devices` — this deployment host's own
  identity, what its network client can see, this machine's members merged into it, and the
  operations its data directory holds journals for. The **drawer** is a state machine over
  one operation: fill a short form, verify the host, answer a password, approve a plan,
  watch it run, finish or recover.

  ## One list, one action per row

  Written against §5 of `docs/design-qa/fleet-ux-review-2026-09-18.md`: **a row is a device,
  a device has one state and one thing you can do about it.** The self row comes first and
  is labelled *This Mac* or *This machine* from `host.os`; members follow, then visible
  peers. Presence is a dot, a word and a relative time. The Ouroboros column is one of nine
  short phrases and the action column is one button or nothing at all. Search and the filter
  appear only past eight rows, because below that the list *is* the search. The words all
  come from `Ouroboros.Web.Live.Devices`.

  ## What the drawer no longer carries

  `docs/proposals/fleet-kiss.md` §10 takes three things out of this page, and each of them
  was a control an operator had to understand before they could use the one they wanted.

  **No plan digest.** The plan is the lines it shows (§6). There is nothing to canonicalise,
  nothing to hash and nothing behind a disclosure: what is on screen is what **Deploy**
  approves, and it approves it with `accept: true`.

  **No idempotency key.** Approval is answering a challenge, and a challenge is consumed when
  it is answered — a second click is `challenge_consumed`, which is the honest answer, rather
  than a replay of a recorded one.

  **No takeover and no per-tab binding.** A challenge is answered by whoever is an
  administrator on this runtime. A second tab, a reload, this page's own `?operation=`
  round trip and the restart a local setup performs all answer the prompt in front of them,
  where before each of those was a `challenge_not_bound` with a *Reconnect this setup to
  this tab* button behind it that the broker then refused.

  ## The work happens on the runtime's machine, not on this laptop

  Every fact on this page is about the machine hosting the runtime this browser is talking
  to: its SSH configuration, its keys, its agent, its network client. A browser cannot lend a
  laptop's SSH agent to a runtime three hops away. That is one quiet line under the title and
  the caption inside each drawer — the same fact, said once where it is needed.

  ## Where the secret is, and is not

  One event, `"authenticate"`, receives a password or a passphrase. It arrives only as the
  submission of the challenge's own form — the field carries no `phx-change`, so nothing
  streams keystrokes to this server — and it leaves in the same function call: the value is
  passed to `Ouroboros.Web.Call.call/4` and is never assigned, never logged, never put in the
  URL and never rendered back. The field is emptied afterwards by giving it a new DOM id, so
  the browser replaces the element rather than keeping the value the operator typed.

  The field uses `autocomplete="off"` rather than `new-password` so the browser is not
  invited to save the value. Browsers still sometimes offer a save; the emptied field and the
  nonce that replaces it are what this page can actually do about that.

  The secret's journey after that is `Ouroboros.Fleet.Deployment`'s, which documents it: the
  broker never sees it, and `Ouroboros.Gateway.AuditLine` redacts this one verb's parameters
  rather than digesting them.

  ## Closing this page does not cancel anything

  The port program calls `setsid`, ignores `SIGHUP` and `SIGPIPE`, and on stdin EOF finishes
  the operation and keeps writing its journal (§8). Closing the drawer unsubscribes and
  nothing else; the operation keeps its row, and reopening the page at
  `/devices?operation=<id>` reloads it by id. A lost connection is reported as exactly what
  it is — the result is unknown until the operation is queried again — and never as a
  failure, and never by starting a second setup.
  """

  use Phoenix.LiveView

  on_mount {Ouroboros.Web.NeedsYou, :bell}

  alias Ouroboros.Fleet.Deployment
  alias Ouroboros.Fleet.Deployment.Journal
  alias Ouroboros.Web.Call
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Layouts
  alias Ouroboros.Web.Live.Devices
  alias Ouroboros.Web.Presentation

  @inventory "fleet.devices"
  @status "fleet.deployment.status"
  @start "fleet.deployment.start"
  @respond "fleet.deployment.respond"
  @cancel "fleet.deployment.cancel"
  @resume "fleet.deployment.resume"
  @fleet "fleet.status"

  # A program that has just exited leaves the broker a moment behind it, and during that
  # moment a status read answers `worker_unavailable` rather than the journal. Bounded, so an
  # operation whose record really is unreadable stops rather than polling forever.
  @status_retries 8
  @status_retry_after 150
  @reload_burst 150

  # How many stopped operations the leftovers panel draws. A journal directory holds two
  # hundred, and every one of them was once a row an operator had to scroll past.
  @max_stopped 10

  # Past this many rows the list stops being its own index. Below it, a search box over four
  # devices is a control that costs more than it saves (§5.1).
  @search_rows 8

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Devices")
      |> assign(:refusal, nil)
      |> assign(:announced, 0)
      |> assign(:scope, Config.for_endpoint(socket.endpoint).scope)
      |> assign(:query, "")
      |> assign(:filter, "all")
      |> assign(:drawer, nil)
      |> assign(:announcement, "")

    {:ok, if(connected?(socket), do: load(socket), else: loading(socket))}
  end

  # ------------------------------------------------------------------------------------
  # Params
  # ------------------------------------------------------------------------------------

  @impl true
  def handle_params(%{"operation" => operation}, _uri, socket) when is_binary(operation) do
    cond do
      socket.assigns.drawer && socket.assigns.drawer.operation == operation ->
        {:noreply, socket}

      # An address bar is a text box. An id this runtime could not be holding is said so,
      # rather than carried into a status read and a `push_patch/2` that raises on it.
      operation_id(operation) != :ok ->
        {:noreply, refuse(socket, "That is not an operation this machine could be holding.")}

      true ->
        {:noreply, attach(socket, operation, nil)}
    end
  end

  # No operation in the address is not an instruction to close: the drawer's first step
  # exists before an operation does, and it is opened by an event rather than by the URL.
  def handle_params(_params, _uri, socket), do: {:noreply, socket}

  # ------------------------------------------------------------------------------------
  # List events
  # ------------------------------------------------------------------------------------

  @impl true
  def handle_event("refresh", _params, socket), do: {:noreply, load(socket)}

  def handle_event("search", %{"query" => query}, socket) when is_binary(query),
    do: {:noreply, assign(socket, :query, query)}

  def handle_event("filter", %{"filter" => filter}, socket)
      when filter in ["all", "fleet", "available"],
      do: {:noreply, assign(socket, :filter, filter)}

  # ------------------------------------------------------------------------------------
  # The drawer
  # ------------------------------------------------------------------------------------

  # Every mutating event below asks `allowed?/2` first, and none of them relies on the `:if`
  # that decided whether its control was drawn. A `phx-click` is a message a browser sends,
  # not a button a browser pressed: a console one-liner, a hostile page, a stale tab and a
  # rebuilt DOM all send the same frame, and the review proved this one — a hand-sent
  # `deploy-manual` plus `connect` started a real deployment and reached a real password
  # field on a cleartext `0.0.0.0` bind whose whole page said credential entry was refused.
  #
  # The gate is the same question the render asks, asked again where it cannot be skipped.
  # The gateway refuses these verbs on its own side too, and that is the boundary that
  # matters; this is the surface keeping its own word. `cancel-setup` asks `:cancel`, which
  # is availability of `fleet.deployment.cancel` and nothing else: a setup on a host that may
  # no longer start one still has to be stoppable.
  def handle_event("deploy", %{"address" => address}, socket) do
    with :ok <- allowed?(socket, :add),
         {:ok, device} <- deployable(socket, address) do
      {:noreply, open_drawer(socket, device, "add")}
    else
      {:refused, sentence} -> {:noreply, refuse(socket, sentence)}
    end
  end

  # "Add a device by address": the same form with the address editable and the name empty.
  def handle_event("deploy-manual", _params, socket) do
    case allowed?(socket, :add) do
      :ok -> {:noreply, open_drawer(socket, nil, "add")}
      {:refused, sentence} -> {:noreply, refuse(socket, sentence)}
    end
  end

  # "Set up this Mac": the first local fleet. No SSH, no account and no credential — this
  # machine configures itself.
  #
  # And *this* machine: the event carries an address, so it is held to the row whose state is
  # `this_device_without_profile`. Aimed at a peer it would ask the program to set that peer
  # up locally — a local setup bound to somebody else's address.
  def handle_event("setup-device", params, socket) do
    with :ok <- allowed?(socket, :setup),
         {:ok, device} <- local_target(socket, params["address"]) do
      {:noreply, open_drawer(socket, device, "setup")}
    else
      {:refused, sentence} -> {:noreply, refuse(socket, sentence)}
    end
  end

  # §5.4. Removal is a deployment like the others — it connects, it may be asked for a
  # password, it shows a plan — and it is reached from the member's own details panel rather
  # than from a button on its row, because it is not the thing a person came to this page
  # to do.
  def handle_event("leave-device", %{"address" => address}, socket) when is_binary(address) do
    with :ok <- allowed?(socket, :leave),
         {:ok, device} <- removable(socket, address) do
      {:noreply, open_drawer(socket, device, "leave")}
    else
      {:refused, sentence} -> {:noreply, refuse(socket, sentence)}
    end
  end

  def handle_event("leave-device", _params, socket), do: {:noreply, socket}

  def handle_event("drawer-close", _params, socket) do
    {:noreply,
     socket
     |> close_drawer()
     |> load()
     |> push_patch(to: "/devices", replace: true)}
  end

  def handle_event("connect-change", params, socket) do
    {:noreply, update_drawer(socket, &%{&1 | form: form(params, &1.form)})}
  end

  def handle_event("connect", params, %{assigns: %{drawer: %{operation: nil}}} = socket) do
    guarded(socket, fn ->
      socket =
        update_drawer(socket, &%{&1 | form: form(params, &1.form), error: nil, busy: :start})

      with :ok <- allowed?(socket, drawer_gate(socket)),
           :ok <- named?(socket),
           :ok <- local_setup_target(socket) do
        start_operation(socket)
      else
        {:refused, sentence} -> {:noreply, drawer_refused(socket, sentence)}
      end
    end)
  end

  # A second submission of a form whose operation already exists is not a second deployment.
  def handle_event("connect", _params, socket), do: {:noreply, socket}

  # The disclosure is bound to this assign and drawn from it, so a `phx-change` on the form
  # it lives in re-renders it open.
  def handle_event("advanced", %{"open" => open}, socket),
    do: {:noreply, update_drawer(socket, &%{&1 | advanced?: open == "true"})}

  @doc """
  The one event that carries a credential.

  `secret` is read out of the submitted parameters, handed to `Ouroboros.Web.Call.call/4`,
  and referenced nowhere afterwards. It is not assigned, not logged and not echoed; the
  field it came from is replaced with an empty one by the nonce below, because a value left
  in the DOM is a value the next person at this keyboard can read out of it.
  """
  @impl true
  def handle_event(
        "authenticate",
        %{"challenge" => challenge, "secret" => secret},
        %{assigns: %{drawer: %{operation: operation}}} = socket
      )
      when is_binary(operation) and is_binary(challenge) and is_binary(secret) do
    guarded(socket, fn ->
      with :ok <- secret_bind_ok?(socket),
           :ok <- allowed?(socket, drawer_gate(socket)) do
        result =
          operate(socket, @respond, %{
            "operation" => operation,
            "challenge" => challenge,
            "secret" => secret
          })

        # `reload/1` first, then `answered/3`. The other order is what the review proved:
        # reload's success clause sets `error: nil`, so a refusal set a moment earlier was
        # wiped before it could be drawn, and the only thing left saying a credential had
        # been rejected was the 1×1 pixel live region.
        {:noreply,
         socket
         |> update_drawer(&%{&1 | secret_nonce: &1.secret_nonce + 1, busy: nil})
         |> reload()
         |> answered(result, "The password was sent to the setup program.")}
      else
        {:refused, sentence} -> {:noreply, drawer_refused(socket, sentence)}
      end
    end)
  end

  def handle_event("authenticate", _params, socket), do: {:noreply, socket}

  def handle_event(
        "trust-host",
        %{"challenge" => challenge, "accept" => accept},
        %{assigns: %{drawer: %{operation: operation}}} = socket
      )
      when is_binary(operation) do
    guarded(socket, fn ->
      with :ok <- secret_bind_ok?(socket),
           :ok <- allowed?(socket, drawer_gate(socket)) do
        result =
          operate(socket, @respond, %{
            "operation" => operation,
            "challenge" => challenge,
            "accept" => accept == "true"
          })

        said =
          if accept == "true",
            do: "This host key is now trusted for this operation.",
            else: "The host was not trusted, and this attempt was refused."

        {:noreply, socket |> reload() |> answered(result, said)}
      else
        {:refused, sentence} -> {:noreply, drawer_refused(socket, sentence)}
      end
    end)
  end

  def handle_event("trust-host", _params, socket), do: {:noreply, socket}

  # Approval is answering the `review` challenge, and nothing more. §10 deletes the digest:
  # the plan is the lines the step is showing, so there is no second artefact to check the
  # click against — the challenge id is what says which plan is being approved, and a second
  # click on a consumed challenge is `challenge_consumed`.
  def handle_event(
        "approve",
        %{"challenge" => challenge},
        %{assigns: %{drawer: %{operation: operation}}} = socket
      )
      when is_binary(operation) and is_binary(challenge) do
    guarded(socket, fn ->
      with :ok <- secret_bind_ok?(socket),
           :ok <- allowed?(socket, drawer_gate(socket)) do
        result =
          operate(socket, @respond, %{
            "operation" => operation,
            "challenge" => challenge,
            "accept" => true
          })

        {:noreply, socket |> reload() |> answered(result, "The plan was approved.")}
      else
        {:refused, sentence} -> {:noreply, drawer_refused(socket, sentence)}
      end
    end)
  end

  def handle_event("approve", _params, socket), do: {:noreply, socket}

  def handle_event("cancel-setup", _params, %{assigns: %{drawer: %{operation: op}}} = socket)
      when is_binary(op) do
    case allowed?(socket, :cancel) do
      {:refused, sentence} ->
        {:noreply, drawer_refused(socket, sentence)}

      :ok ->
        case operate(socket, @cancel, %{"operation" => op}) do
          {:ok, reply} when is_map(reply) ->
            {:noreply,
             socket
             |> update_drawer(
               &%{&1 | residue: List.wrap(reply["residue"]), error: nil, cancelled?: true}
             )
             |> reload()
             |> announce("The setup was asked to stop at a safe boundary.")}

          refused ->
            {:noreply, drawer_refusal(socket, refused)}
        end
    end
  end

  # Cancel before an operation exists is the form's own Cancel: nothing has been started, so
  # there is nothing to stop and the drawer simply closes.
  def handle_event("cancel-setup", _params, socket) do
    {:noreply, socket |> close_drawer() |> push_patch(to: "/devices", replace: true)}
  end

  def handle_event("resume", %{"operation" => operation}, socket)
      when is_binary(operation) do
    with :ok <- operation_id(operation),
         :ok <- allowed?(socket, drawer_gate(socket)) do
      resume(socket, operation)
    else
      {:refused, sentence} -> {:noreply, drawer_refused(socket, sentence)}
    end
  end

  def handle_event("resume", _params, socket), do: {:noreply, socket}

  def handle_event("open-operation", %{"operation" => operation}, socket)
      when is_binary(operation) do
    case operation_id(operation) do
      :ok ->
        {:noreply,
         socket
         |> attach(operation, nil)
         |> push_patch(to: "/devices?operation=#{operation}", replace: true)}

      {:refused, sentence} ->
        {:noreply, refuse(socket, sentence)}
    end
  end

  def handle_event("open-operation", _params, socket), do: {:noreply, socket}

  def handle_event("inspect-device", %{"row" => row}, socket) when is_binary(row) do
    case Enum.find(devices(socket), &(&1["row_id"] == row)) do
      device when is_map(device) ->
        if Devices.inspectable?(device),
          do: {:noreply, open_inspect(socket, device)},
          else: {:noreply, socket}

      _unknown ->
        {:noreply, socket}
    end
  end

  def handle_event(_event, _params, socket), do: {:noreply, socket}

  # ------------------------------------------------------------------------------------
  # Frames from the program
  # ------------------------------------------------------------------------------------

  @impl true
  def handle_info({:ouroboros_fleet_deployment, operation, event}, socket) do
    if socket.assigns.drawer && socket.assigns.drawer.operation == operation do
      # Read, then speak. Log lines arrive in bursts; coalescing those is what this is for. A
      # challenge, a state change or a done frame is the thing the drawer is waiting to draw,
      # and it is reloaded immediately rather than 150 ms later.
      socket = schedule_reload(socket, operation, event)

      kind = socket.assigns.drawer.kind

      cond do
        event["event"] != "detached" -> {:noreply, announce(socket, said(event, kind))}
        lost?(socket.assigns.drawer) -> {:noreply, announce(socket, said(event, kind))}
        true -> {:noreply, socket}
      end
    else
      {:noreply, socket}
    end
  end

  def handle_info(
        {:DOWN, reference, :process, _pid, _reason},
        %{assigns: %{drawer: drawer}} = socket
      )
      when is_map(drawer) and drawer.monitor == reference do
    # Read first, then decide what to say. A worker process ending is not by itself bad news:
    # a finished operation's program exits too, so announcing "the result is unknown" on
    # every `:DOWN` overwrites the outcome an operator has just been given with a worry
    # about it.
    socket = socket |> update_drawer(&%{&1 | monitor: nil}) |> reload()

    if lost?(socket.assigns.drawer) do
      {:noreply, announce(socket, said(%{"event" => "detached"}, nil))}
    else
      {:noreply, socket}
    end
  end

  def handle_info({:devices_reload, operation}, socket) do
    if socket.assigns.drawer && socket.assigns.drawer.operation == operation do
      {:noreply,
       socket
       |> update_drawer(&%{&1 | reload_pending?: false})
       |> reload()}
    else
      {:noreply, socket}
    end
  end

  def handle_info(_other, socket), do: {:noreply, socket}

  # One sentence per frame, for the polite live region. A step is the one an operator is
  # actually following, so it is the one that names itself.
  defp said(%{"event" => "step"} = event, _kind) do
    {outcome, _tone} = Devices.outcome(event["state"])
    "#{Devices.step_label(event["step"])}: #{outcome}."
  end

  defp said(%{"event" => "state"} = event, _kind),
    do: Devices.operation_state(event["state"]) <> "."

  # The operation's kind too, because a challenge is announced in the same words the step
  # draws: a screen reader told "Ready to deploy." while the page says "Ready to remove" is
  # being told about a different operation.
  defp said(%{"event" => "challenge"} = event, kind),
    do: Devices.challenge_title(event["kind"], kind) <> "."

  defp said(%{"event" => "done"} = event, _kind) do
    case event["state"] do
      state when is_binary(state) -> Devices.operation_state(state) <> "."
      _absent -> "The setup stopped."
    end
  end

  defp said(%{"event" => "detached"}, _kind) do
    "This runtime is no longer watching the setup program. What it has done is unknown " <>
      "until the operation is read again; nothing was cancelled."
  end

  defp said(_other, _kind), do: ""

  defp start_operation(socket) do
    case operate(socket, @start, start_params(socket.assigns.drawer)) do
      {:ok, %{"operation" => operation}} ->
        {:noreply,
         socket
         |> attach(operation, socket.assigns.drawer.device)
         |> push_patch(to: "/devices?operation=#{operation}", replace: true)}

      refused ->
        {:noreply, drawer_refusal(socket, refused)}
    end
  end

  defp resume(socket, operation) do
    result = operate(socket, @resume, %{"operation" => operation})

    socket =
      socket
      |> attach(operation, nil)
      |> push_patch(to: "/devices?operation=#{operation}", replace: true)

    case result do
      {:ok, _reply} ->
        {:noreply, announce(socket, "The setup program was started again for this operation.")}

      refused ->
        {:noreply, drawer_refusal(socket, refused)}
    end
  end

  # ------------------------------------------------------------------------------------
  # Loading
  # ------------------------------------------------------------------------------------

  defp loading(socket) do
    socket
    |> assign(:availability, :loading)
    |> assign(:fleet, nil)
    |> assign(:fleet_error, nil)
    |> assign(:inventory, :loading)
    |> assign(:inventory_error, nil)
    |> assign(:operations, [])
  end

  defp load(socket) do
    socket
    |> assign(:refusal, nil)
    |> load_fleet()
    |> load_inventory()
  end

  # The membership subset every reader gets, administrator or not. It is the fallback for a
  # read endpoint and a non-administrator identity, and it is also the answer on an older
  # runtime that serves no inventory at all.
  defp load_fleet(socket) do
    case read(socket, @fleet) do
      {:ok, fleet} when is_map(fleet) ->
        socket |> assign(:fleet, fleet) |> assign(:fleet_error, nil)

      refused ->
        socket |> assign(:fleet, nil) |> assign(:fleet_error, Presentation.refusal(refused))
    end
  end

  defp load_inventory(socket) do
    availability = availability(socket.assigns.scope, @inventory)

    socket
    |> assign(:availability, availability)
    |> then(fn socket ->
      if availability == :available, do: read_inventory(socket), else: no_inventory(socket)
    end)
  end

  defp no_inventory(socket) do
    socket
    |> assign(:inventory, nil)
    |> assign(:inventory_error, nil)
    |> assign(:operations, [])
  end

  defp read_inventory(socket) do
    case read(socket, @inventory) do
      {:ok, inventory} when is_map(inventory) ->
        inventory =
          Map.update(inventory, "devices", [], fn rows ->
            rows
            |> Enum.filter(&is_map/1)
            |> Enum.map(&Map.put(&1, "row_id", Devices.row_id(&1)))
          end)

        socket
        |> assign(:inventory, inventory)
        |> assign(:inventory_error, nil)
        |> assign(:operations, operations(inventory))

      refused ->
        socket
        |> assign(:inventory, nil)
        |> assign(:inventory_error, Presentation.refusal(refused))
        |> assign(:operations, [])
    end
  end

  # Every operation this data directory holds a journal for, finished ones included. The
  # summary carries its own `target` — machine, address, account, port — which is what puts
  # it on the row it is about rather than on every row, and this page therefore reads no
  # operation's status until an operator opens one.
  #
  # Finished ones are kept because they are the freshest thing known about their device: an
  # inventory `state` is a *discovery* fact, and it will still say "nothing has inspected
  # this" for as long as it takes the network client to notice otherwise.
  defp operations(inventory) do
    inventory
    |> Map.get("operations", [])
    |> List.wrap()
    |> Enum.filter(&is_map/1)
  end

  # ------------------------------------------------------------------------------------
  # The drawer's own state
  # ------------------------------------------------------------------------------------

  defp open_drawer(socket, device, kind) do
    socket
    |> close_drawer()
    |> assign(:drawer, %{
      device: device,
      kind: kind,
      # A drawer with no device behind it is the manual path: the address is a thing to be
      # typed rather than a fact, and the name starts empty because nothing has suggested
      # one.
      manual?: is_nil(device),
      operation: nil,
      # What the operation itself says it is aimed at, from its journal summary. A drawer
      # opened from a row has the row; a drawer opened from an operation — Continue, or the
      # address bar — has only this.
      target: nil,
      status: nil,
      error: nil,
      residue: [],
      busy: nil,
      cancelled?: false,
      reloads: 0,
      monitor: nil,
      reload_pending?: false,
      advanced?: false,
      secret_nonce: 0,
      form: %{
        "address" => (device && device["address"]) || "",
        # Never `name`: `suggested_machine` is the member name for a machine already in this
        # fleet and a valid slug of the display name otherwise, and a display name is not a
        # machine name.
        "machine" => Devices.suggested_machine(device),
        "ssh_user" => "",
        "port" => "22",
        "identity_ref" => "",
        "install_path" => "",
        "data_dir" => "",
        "service" => "true"
      }
    })
  end

  defp open_inspect(socket, device) do
    socket
    |> close_drawer()
    |> assign(:drawer, %{
      device: device,
      kind: "inspect",
      manual?: false,
      operation: nil,
      target: nil,
      status: nil,
      error: nil,
      residue: [],
      busy: nil,
      cancelled?: false,
      reloads: 0,
      monitor: nil,
      reload_pending?: false,
      advanced?: false,
      secret_nonce: 0,
      form: %{}
    })
  end

  defp close_drawer(%{assigns: %{drawer: %{operation: operation} = drawer}} = socket)
       when is_binary(operation) do
    _ = Deployment.unsubscribe(operation)
    demonitor(drawer.monitor)
    forget_drawer(socket)
  end

  defp close_drawer(socket), do: forget_drawer(socket)

  # The live region belongs to the drawer, and a closed drawer has nothing to say. Left
  # behind, the last sentence of the last deployment is read out again the moment the next
  # drawer opens.
  defp forget_drawer(socket) do
    socket |> assign(:drawer, nil) |> assign(:announcement, "") |> assign(:announced, 0)
  end

  defp demonitor(nil), do: :ok
  defp demonitor(reference), do: Process.demonitor(reference, [:flush])

  # Attaching is the only way an operation gets into the drawer, whether it arrived from a
  # start, from a resume, from a row, or from the address bar after a reload.
  defp attach(socket, operation, device) do
    socket =
      case socket.assigns.drawer do
        %{operation: current} when is_binary(current) and current != operation ->
          close_drawer(socket)

        %{kind: "inspect"} ->
          close_drawer(socket)

        _same_or_empty ->
          socket
      end

    summary = Enum.find(socket.assigns.operations, &(&1["operation"] == operation))
    kind = (summary && summary["kind"]) || "add"
    drawer = socket.assigns.drawer || open_drawer(socket, device, kind).assigns.drawer

    # `subscribe/1` is the broker's, not a gateway method: there is no wire verb for "tell me
    # when this changes", and polling a deployment would be a page refreshing itself through
    # a credential prompt. A subscription to an operation no process is holding simply is not
    # one, which is a fact the journal-sourced snapshot below already states.
    _ = Deployment.subscribe(operation)
    demonitor(drawer.monitor)

    socket
    |> assign(:drawer, %{
      drawer
      | operation: operation,
        device: device || drawer.device,
        # The operation's own recorded target, which is the only thing a drawer opened by id
        # knows about the machine it is about. Kept where the summary has one, so a reload
        # that finds the journal gone does not blank a heading that was right.
        target: (summary && summary["target"]) || drawer.target,
        busy: nil,
        reloads: 0,
        monitor: monitor(operation)
    })
    |> reload()
  end

  # A subscription is not enough to notice a worker process dying: it broadcasts `detached`
  # from `terminate/2`, and a process that is killed rather than stopped never runs one. A
  # monitor notices either way, and a worker that goes unnoticed is a page showing an
  # operator a live setup this runtime is no longer watching.
  defp monitor(operation) do
    case Deployment.worker(operation) do
      {:ok, pid} -> Process.monitor(pid)
      _absent -> nil
    end
  end

  defp reload(%{assigns: %{drawer: %{operation: operation}}} = socket)
       when is_binary(operation) do
    case operate(socket, @status, %{"operation" => operation}) do
      {:ok, status} when is_map(status) ->
        update_drawer(socket, fn drawer ->
          %{drawer | kind: status["kind"] || drawer.kind, status: status, error: nil, reloads: 0}
        end)

      refused ->
        refused_status(socket, operation, refused)
    end
  end

  defp reload(socket), do: socket

  defp refused_status(socket, operation, refused) do
    case reason(refused) do
      # The program has gone and this runtime has not finished noticing. The durable journal
      # is the answer and it is a moment away, so this asks again — scheduled rather than
      # slept for, because a LiveView that blocks here stops drawing everything else on the
      # page, and bounded so a genuinely unreadable operation stops rather than polls.
      stale when stale in ["worker_unavailable", "no_worker"] ->
        socket = update_drawer(socket, &%{&1 | error: Presentation.refusal(refused)})

        if socket.assigns.drawer.reloads < @status_retries do
          Process.send_after(self(), {:devices_reload, operation}, @status_retry_after)
          update_drawer(socket, &%{&1 | reloads: &1.reloads + 1})
        else
          socket
        end

      _other ->
        update_drawer(socket, &%{&1 | error: Presentation.refusal(refused)})
    end
  end

  defp update_drawer(%{assigns: %{drawer: drawer}} = socket, fun) when is_map(drawer),
    do: assign(socket, :drawer, fun.(drawer))

  defp update_drawer(socket, _fun), do: socket

  defp schedule_reload(socket, operation, %{"event" => "log"}) do
    drawer = socket.assigns.drawer

    if is_map(drawer) and drawer[:reload_pending?] do
      socket
    else
      Process.send_after(self(), {:devices_reload, operation}, @reload_burst)
      update_drawer(socket, &%{&1 | reload_pending?: true})
    end
  end

  defp schedule_reload(socket, _operation, _event), do: reload(socket)

  # Never re-raise with the event params on the stack. OTP's LiveView crash report would
  # print the Phoenix message payload — the password, the host-trust answer — and
  # `filter_parameters` does not cover that translator.
  defp guarded(socket, fun) do
    _ = crash_point(socket)
    fun.()
  rescue
    _exception -> {:noreply, generic_drawer_error(socket)}
  catch
    _kind, _reason -> {:noreply, generic_drawer_error(socket)}
  end

  defp crash_point(%{assigns: %{crash_point: fun}}) when is_function(fun, 0), do: fun.()
  defp crash_point(_socket), do: :ok

  defp generic_drawer_error(socket) do
    sentence = "The setup could not complete that action."

    socket
    |> update_drawer(&%{&1 | error: sentence, busy: nil})
    |> announce(sentence)
  end

  # The runtime's answer can lag the bind this socket is actually on. Secret-carrying events
  # read the running endpoint, not a forwarded header and not a stale inventory.
  defp secret_bind_ok?(socket) do
    case Config.for_endpoint(socket.endpoint) do
      %{bind: bind} ->
        if Ouroboros.Web.Config.loopback?(bind),
          do: :ok,
          else: {:refused, Devices.deploy_blocker("cleartext_web_bind")}

      _missing ->
        {:refused, Devices.deploy_blocker("cleartext_web_bind")}
    end
  rescue
    _exception -> {:refused, Devices.deploy_blocker("cleartext_web_bind")}
  catch
    _kind, _reason -> {:refused, Devices.deploy_blocker("cleartext_web_bind")}
  end

  # ------------------------------------------------------------------------------------
  # The gate
  # ------------------------------------------------------------------------------------

  @doc """
  Whether this endpoint may start or continue work of this kind, right now.

  The same two questions the render asks — the deployment host's own `capabilities`, and
  whether this scope and identity may run the verb — asked where an event cannot skip them.

  One blocker is applied by kind rather than flatly, and it is the only one:
  `dev_runtime` stops a `setup` and nothing else, because a runtime started from a checkout
  cannot boot under a fleet profile, while an `add` or a `leave` from the same runtime acts
  on another machine's installation. `no_ca_key` is gone with the per-member certificate
  ceremony — every member holds the fleet's bundle, so every member can admit one.
  """
  @spec allowed?(Phoenix.LiveView.Socket.t(), :add | :setup | :leave | :cancel) ::
          :ok | {:refused, String.t()}
  def allowed?(socket, :setup) do
    if setup?(socket), do: :ok, else: {:refused, setup_blocked(socket)}
  end

  def allowed?(socket, :cancel) do
    if Call.available?(socket.assigns.scope, @cancel),
      do: :ok,
      else: {:refused, unavailable(socket, @cancel)}
  end

  # `:add` and `:leave` are one question: can this runtime run an operation against *another*
  # machine. Both are exempt from `dev_runtime` and from nothing else.
  def allowed?(socket, _add_or_leave) do
    if deploy?(socket), do: :ok, else: {:refused, deploy_blocked(socket)}
  end

  # Which gate the open drawer answers to.
  defp drawer_gate(%{assigns: %{drawer: %{kind: "setup"}}}), do: :setup
  defp drawer_gate(%{assigns: %{drawer: %{kind: "leave"}}}), do: :leave
  defp drawer_gate(_socket), do: :add

  # The row a `deploy` may be aimed at: one this listing says nothing has inspected. The
  # event carries an address, and an address is a string a client chose.
  defp deployable(socket, address) when is_binary(address) and address != "" do
    case Enum.find(devices(socket), &(&1["address"] == address)) do
      device when is_map(device) ->
        if Devices.deployable?(device) or left?(socket, device),
          do: {:ok, device},
          else: {:refused, "That device is not one this machine can add to the fleet."}

      _unknown ->
        {:refused, "This machine's inventory does not list that address."}
    end
  end

  defp deployable(_socket, _address),
    do: {:refused, "This machine's inventory does not list that address."}

  # A member this fleet has just removed is a machine it can add again, whatever discovery
  # still says: `fleet.devices` goes on calling it a member until the network client notices,
  # and the row offers **Add to fleet** on the strength of the completed `leave`. Without
  # this the button the row offers would refuse when pressed.
  defp left?(socket, device) do
    operation = latest_operation(socket.assigns.operations, device)

    operation["kind"] == "leave" and operation["state"] == "completed"
  end

  # And the row a `leave-device` may be aimed at: a member, named by this machine's own
  # profile rather than by what the device calls itself. `leave` takes a machine name, and a
  # peer wearing a member's name must not be able to have that member removed.
  defp removable(socket, address) do
    case Enum.find(devices(socket), &(&1["address"] == address)) do
      device when is_map(device) ->
        if Devices.removable?(device),
          do: {:ok, device},
          else: {:refused, "That device is not a member this fleet can remove."}

      _unknown ->
        {:refused, "This machine's inventory does not list that address."}
    end
  end

  # And the row a `setup-device` may be aimed at: this machine's own, and only while it has
  # no fleet profile. An address naming any other row is a request to set up *that* device
  # locally, which is not a thing this verb does.
  defp local_target(socket, address) when is_binary(address) do
    case Enum.find(devices(socket), &(&1["address"] == address)) do
      device when is_map(device) ->
        if Devices.setup?(device),
          do: {:ok, device},
          else:
            {:refused,
             "Setting up this machine configures the one this runtime is on. That address " <>
               "is another device — add it to the fleet instead."}

      _unknown ->
        {:refused, "This machine's inventory does not list that address."}
    end
  end

  defp local_target(socket, _absent), do: {:ok, local_device(socket)}

  # The same check again at submission, because the form's own address field is editable and
  # a setup drawer opened on the right row can still be submitted with the wrong one.
  defp local_setup_target(%{assigns: %{drawer: %{kind: "setup"} = drawer}} = socket) do
    case trimmed(drawer.form["address"]) do
      nil ->
        :ok

      address ->
        case Enum.find(devices(socket), &(&1["address"] == address)) do
          device when is_map(device) ->
            if Devices.setup?(device),
              do: :ok,
              else:
                {:refused,
                 "That address belongs to another device. A local setup binds this " <>
                   "machine's own address."}

          # An address the inventory does not list is this machine's to answer for: a
          # network client that cannot see may still know what this host binds.
          _unlisted ->
            :ok
        end
    end
  end

  defp local_setup_target(_socket), do: :ok

  # Refused on this side rather than three steps later by the program. `add` requires a
  # machine name; a `setup` may leave it empty — the runtime falls back to this host's own
  # name — but not fill it with something invalid.
  defp named?(%{assigns: %{drawer: %{kind: "leave"}}}), do: :ok

  defp named?(%{assigns: %{drawer: drawer}}) do
    name = trimmed(drawer.form["machine"])

    cond do
      is_nil(name) and drawer.kind == "setup" -> :ok
      is_nil(name) -> {:refused, Devices.machine_error(nil)}
      Devices.valid_machine?(name) -> :ok
      true -> {:refused, Devices.machine_error(name)}
    end
  end

  defp named?(_socket), do: :ok

  # An operation id reaches `push_patch/2`, which builds a URL out of it — and
  # `Phoenix.LiveView` raises on one it cannot put in an address, which takes the whole view
  # down. The journal's own validator is the right shape to hold it to.
  defp operation_id(operation) do
    case Journal.validate_operation(operation) do
      :ok ->
        :ok

      {:error, :invalid_operation} ->
        {:refused, "That is not an operation this machine could be holding."}
    end
  end

  # A refusal with no drawer to put it in: it belongs to the page.
  defp refuse(socket, sentence), do: socket |> assign(:refusal, sentence) |> announce(sentence)

  # And one with a drawer: the visible `role="alert"` box inside it.
  defp drawer_refused(socket, sentence) do
    socket |> update_drawer(&%{&1 | error: sentence, busy: nil}) |> announce(sentence)
  end

  defp drawer_refusal(socket, refused) do
    update_drawer(socket, &%{&1 | error: refusal_words(refused), busy: nil})
  end

  # The runtime enforces the deployment host's blockers on its own side, and names them. When
  # it does, the page says the same sentence it would have said itself rather than the
  # generic "the runtime refused this": one blocker, one wording, whichever side caught it.
  defp refusal_words(refused) do
    case {reason(refused), blocker_of(refused)} do
      {"deploy_blocked", blocker} when is_binary(blocker) -> Devices.deploy_blocker(blocker)
      _other -> Presentation.refusal(refused)
    end
  end

  defp blocker_of({:error, _code, _message, %{"blockers" => [first | _rest]}}), do: first
  defp blocker_of(_other), do: nil

  defp answered(socket, {:ok, _reply}, said), do: announce(socket, said)

  defp answered(socket, refused, _said) do
    message = refusal_words(refused)

    socket
    |> update_drawer(&%{&1 | error: message, busy: nil})
    |> announce(message)
  end

  defp announce(socket, ""), do: socket
  defp announce(socket, nil), do: socket

  # A live region announces a *change*. Two identical sentences in a row — two steps with the
  # same name, a credential refused twice — are one change to the DOM and therefore silence,
  # which is exactly the repetition an operator most needs to hear. The counter changes the
  # text node without changing what it says.
  defp announce(socket, said) do
    count = socket.assigns[:announced] || 0
    socket |> assign(:announced, count + 1) |> assign(:announcement, said)
  end

  defp form(params, previous) when is_map(params) do
    Map.merge(previous, Map.take(params, Map.keys(previous)))
  end

  @doc """
  The `fleet.deployment.start` document this drawer sends, and nothing else.

  Only what the method's parameters allow, and no secret among them: an identity is named by
  reference, and a password is answered to its own challenge rather than submitted here.
  Every field here becomes a word on the program's command line (§6), which is why nothing
  that could be a flag is ever put in one.

  Three shapes, because the verb has three. `setup` configures *this* machine and therefore
  takes no target and no account at all — sending one would be this page asking the program
  to SSH to itself. `add` names an address, and it names a machine too: without one the
  program takes the address as the machine name and refuses it after a connection, a host key
  and a password. `leave` names a *machine* rather than an address, because that name is the
  identity a peer cannot choose — aiming a removal at whatever answers at an address is not a
  thing this page will do.

  Public because it is the contract boundary this page owns.
  """
  @spec start_params(map()) :: map()
  def start_params(%{kind: "setup"} = drawer) do
    form = drawer.form

    %{"kind" => "setup", "service" => form["service"] == "true"}
    |> put_present("machine", trimmed(form["machine"]))
    |> put_present("address", trimmed(form["address"]))
  end

  def start_params(%{kind: "leave"} = drawer) do
    form = drawer.form
    machine = (drawer.device && drawer.device["machine"]) || trimmed(form["machine"])

    %{
      "kind" => "leave",
      "target" => %{"machine" => machine},
      "ssh_user" => trimmed(form["ssh_user"]) || "",
      "port" => port(form["port"])
    }
    |> put_present("identity", identity(form))
  end

  def start_params(drawer) do
    form = drawer.form

    %{
      "kind" => "add",
      "target" =>
        %{"address" => trimmed(form["address"]) || ""}
        |> put_present("machine", trimmed(form["machine"])),
      "ssh_user" => trimmed(form["ssh_user"]) || "",
      "port" => port(form["port"]),
      "service" => form["service"] == "true"
    }
    |> put_present("identity", identity(form))
    |> put_present("install_path", trimmed(form["install_path"]))
    |> put_present("data_dir", trimmed(form["data_dir"]))
  end

  # No authentication picker. The default identity is what the program uses, and a target
  # that asks for a password raises the `password` challenge the drawer already knows how to
  # answer — so the only thing left to choose is a *specific* key, and that is one field under
  # Advanced rather than a select every deployment had to read past.
  #
  # Which kind it is, is a property of the value: a path is a key file on this host, and
  # anything else is an agent identity's fingerprint. Never key material, on either.
  defp identity(form) do
    case trimmed(form["identity_ref"]) do
      nil -> nil
      ref -> %{"kind" => identity_kind(ref), "ref" => ref}
    end
  end

  # A path, or a fingerprint. Decided on how the value *starts*, never on whether a "/"
  # appears somewhere in it: OpenSSH prints a SHA256 fingerprint as base64, whose alphabet
  # includes "/", so about half of all real fingerprints contain one — and each of those
  # would have been sent as a key file's path and failed on a file that does not exist.
  defp identity_kind("SHA256:" <> _fingerprint), do: "agent"
  defp identity_kind("ssh-" <> _algorithm), do: "agent"

  defp identity_kind(ref) do
    if String.starts_with?(ref, ["/", "~", "./", "../"]), do: "key", else: "agent"
  end

  defp put_present(params, _key, nil), do: params
  defp put_present(params, key, value), do: Map.put(params, key, value)

  defp trimmed(value) when is_binary(value) do
    case String.trim(value) do
      "" -> nil
      trimmed -> trimmed
    end
  end

  defp trimmed(_other), do: nil

  defp port(value) when is_binary(value) do
    case Integer.parse(String.trim(value)) do
      {port, ""} -> port
      _unreadable -> 22
    end
  end

  defp port(_other), do: 22

  # ------------------------------------------------------------------------------------
  # Reading the runtime
  # ------------------------------------------------------------------------------------

  # `read/3` is the ordinary page read and `operate/3` is every `fleet.deployment.*` call.
  # They are the same call now: §10 deletes per-tab challenge binding, so there is no client
  # session for a deployment verb to carry and no reason for the two to differ. Both are
  # attributed to the browser session the cookie names, which is what correlates one browser
  # across requests in a log line.
  defp read(socket, method, params \\ %{}),
    do: Call.call(socket.assigns.scope, method, params, session: socket.assigns[:web_session])

  defp operate(socket, method, params), do: read(socket, method, params)

  # The `data.reason` a refusal carried, where it carried one. The reason codes are the
  # gateway's stable vocabulary and this page branches on exactly three of them.
  defp reason({:error, _code, _message, data}) when is_map(data), do: data["reason"]
  defp reason(_other), do: nil

  @doc """
  Why a method is not available here, distinguished rather than collapsed.

  `Ouroboros.Web.Call.available?/2` answers the yes/no this page gates on, and it answers it
  with one boolean for three different facts. The three have to stay apart: a build that does
  not serve the method at all, an endpoint whose scope may not run it, and an identity that
  is not an administrator are three different things for an operator to do something about.
  This asks the same two sources `available?/2` asks, in order, and names which one said no.
  """
  @spec availability(:read | :operate, String.t()) :: :available | :absent | :scope | :denied
  def availability(scope, method) do
    case Ouroboros.Gateway.Methods.fetch(method) do
      :error ->
        :absent

      {:ok, entry} ->
        cond do
          not Ouroboros.Gateway.Methods.permits?(scope, entry) -> :scope
          not Call.available?(scope, method) -> :denied
          true -> :available
        end
    end
  end

  defp devices(socket) do
    case socket.assigns.inventory do
      %{"devices" => devices} when is_list(devices) -> devices
      _absent -> []
    end
  end

  defp host(socket) do
    case socket.assigns.inventory do
      %{"host" => host} when is_map(host) -> host
      _absent -> nil
    end
  end

  # Acting on another machine is offered when the deployment host says it can *and* this
  # endpoint can run the verb that starts one. Two different questions, and a page that asked
  # only the first would draw a button a read-scope browser cannot press.
  #
  # Read from `capabilities.reasons` rather than from `capabilities.deploy`, because
  # `dev_runtime` is a reason that blocks a local setup and nothing else. The two are
  # otherwise the same question: the runtime computes `deploy` as `reasons == []`.
  defp deploy?(socket) do
    is_map(host(socket)) and Call.available?(socket.assigns.scope, @start) and
      Enum.all?(blockers(socket), &(&1 == "dev_runtime"))
  end

  defp cancel?(socket), do: Call.available?(socket.assigns.scope, @cancel)

  defp deploy_blocked(socket) do
    case Enum.reject(blockers(socket), &(&1 == "dev_runtime")) do
      [] -> unavailable(socket, @start)
      [first | _rest] -> Devices.deploy_blocker(first)
    end
  end

  defp standalone?(socket) do
    Enum.any?(devices(socket), &(&1["state"] == "this_device_without_profile"))
  end

  defp blockers(socket) do
    case host(socket) do
      host when is_map(host) -> List.wrap(get_in(host, ["capabilities", "reasons"]))
      _absent -> []
    end
  end

  @doc """
  Whether **this** machine can be set up locally, which is a different question from adding
  another one.

  Every blocker applies, `dev_runtime` included: a development runtime can build the fleet
  and then never start it. There is no exemption left to make — `no_ca_key` went with the
  per-member certificate ceremony, and it was the only one a local setup ever needed.
  """
  @spec setup?(map()) :: boolean()
  def setup?(socket) do
    is_map(host(socket)) and Call.available?(socket.assigns.scope, @start) and
      blockers(socket) == []
  end

  defp setup_blocked(socket) do
    case blockers(socket) do
      [] -> unavailable(socket, @start)
      [first | _rest] -> Devices.deploy_blocker(first)
    end
  end

  # The row for this machine, where the inventory has one. `deploy-manual` has no row, and
  # neither does a Set up pressed from a page whose inventory could not be read.
  defp local_device(socket) do
    Enum.find(devices(socket), &(&1["state"] == "this_device_without_profile"))
  end

  defp unavailable(socket, method),
    do: Devices.unavailable(availability(socket.assigns.scope, method), method)

  # ------------------------------------------------------------------------------------
  # Render
  # ------------------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    socket = assigns_socket(assigns)
    all = all_devices(assigns)

    assigns =
      assigns
      |> assign(:host, host(socket))
      |> assign(:deploy?, deploy?(socket))
      |> assign(:deploy_blocked, deploy_blocked(socket))
      |> assign(:setup?, setup?(socket))
      |> assign(:setup_blocked, setup_blocked(socket))
      |> assign(:cancel?, cancel?(socket))
      |> assign(:standalone?, standalone?(socket))
      # The row Set up is aimed at is the one with no fleet profile, which is not
      # necessarily the first self row the listing carries.
      |> assign(:setup_device, Enum.find(all, &Devices.setup?/1))
      |> assign(:rows, rows(assigns, all))
      # Keep active controls reachable even if a refresh shrinks the inventory.
      |> assign(
        :controls?,
        length(all) > @search_rows or assigns.query != "" or assigns.filter != "all"
      )
      |> then(fn assigns ->
        {shown, hidden} = orphans(assigns, all)

        assigns |> assign(:orphans, shown) |> assign(:orphans_hidden, hidden)
      end)

    ~H"""
    <div>
      <Layouts.topbar current={:devices} />

      <main class="ouro-page">
        <header class="ouro-header">
          <p class="ouro-subhead"><a href="/">Sessions</a> · Devices</p>
          <h1>Devices</h1>
          <%!-- One quiet line, not a box, and not repeated inside every drawer: a browser
                three hops away cannot lend its SSH agent to the runtime, and this is where
                that fact is said. --%>
          <p class="ouro-devices-host" data-ouro-deployment-host>{Devices.host_line(@host)}</p>
        </header>

        <p :if={@inventory == :loading} class="ouro-devices-empty" role="status">
          Loading devices…
        </p>

        <section :if={@availability not in [:available, :loading]} class="ouro-panel">
          <div class="ouro-panel-head">
            <h2>Setting a machine up is not available here</h2>
          </div>
          <p class="ouro-refusal">{Devices.unavailable(@availability, "fleet.devices")}</p>
          <.membership fleet={@fleet} error={@fleet_error} />
        </section>

        <p :if={@inventory_error} class="ouro-refusal">{@inventory_error}</p>

        <%!-- A refusal with no drawer to live in: an event this endpoint may not run, or one
              aimed at a device the inventory does not offer it for. --%>
        <p :if={@refusal} id="ouro-devices-refusal" class="ouro-refusal" role="alert">
          {@refusal}
        </p>

        <section :if={is_map(@inventory)} class="ouro-panel">
          <div class="ouro-panel-head">
            <%!-- The status line *is* the blocker sentence for a machine in no fleet, rather
                  than a heading with a paragraph under it repeating the same thing. --%>
            <h2 class="ouro-devices-status" data-standalone={to_string(@standalone?)}>
              <%!-- The devices, because a fleet with no name is named after the machine
                    holding it, and that machine is the self row. --%>
              {Devices.status_line(
                @fleet,
                @host && @host["os"],
                @standalone?,
                @inventory["devices"]
              )}
            </h2>
            <div class="ouro-devices-head-actions">
              <button
                :if={@standalone? and @setup?}
                type="button"
                class="ouro-button ouro-devices-primary"
                phx-click="setup-device"
                phx-value-address={@setup_device && @setup_device["address"]}
              >
                {Devices.setup_label(@host && @host["os"])}
              </button>
              <button type="button" class="ouro-quiet-button" phx-click="refresh">Refresh</button>
            </div>
          </div>

          <p :if={@standalone? and not @setup?} class="ouro-devices-blocked">{@setup_blocked}</p>

          <.discovery discovery={@inventory["discovery"]} />

          <form
            :if={@controls?}
            id="ouro-devices-search"
            class="ouro-devices-controls"
            phx-change="search"
            phx-submit="search"
          >
            <label class="ouro-new-label" for="devices-search">Search by name or address</label>
            <input
              id="devices-search"
              class="ouro-new-input"
              type="search"
              name="query"
              value={@query}
              autocomplete="off"
              phx-debounce="120"
            />
            <div class="ouro-devices-filters" role="group" aria-label="Which devices to show">
              <button
                :for={
                  {value, label} <-
                    [{"all", "All"}, {"fleet", "In the fleet"}, {"available", "Everything else"}]
                }
                type="button"
                class={["ouro-quiet-button", @filter == value && "ouro-devices-filter-on"]}
                phx-click="filter"
                phx-value-filter={value}
                aria-pressed={to_string(@filter == value)}
              >
                {label}
              </button>
            </div>
          </form>

          <p :if={@rows == []} class="ouro-devices-empty">
            No device matches. This machine's own row and its fleet's members are always here
            when the list is not filtered.
          </p>

          <ul :if={@rows != []} id="devices-list" class="ouro-devices-list">
            <.device_row
              :for={device <- @rows}
              device={device}
              host={@host}
              operations={@operations}
              deploy?={@deploy?}
              blocked={@deploy_blocked}
            />
          </ul>

          <p class="ouro-devices-manual">
            Not listed?
            <button
              type="button"
              class={["ouro-quiet-button", not @deploy? && "ouro-devices-unavailable"]}
              disabled={not @deploy?}
              aria-disabled={to_string(not @deploy?)}
              title={not @deploy? && @deploy_blocked}
              phx-click={@deploy? && "deploy-manual"}
            >
              Add a device by address
            </button>
          </p>

          <%!-- Why adding a machine is unavailable, whenever it is — including on a
                standalone host, where the status line says this machine is not in a fleet
                but not what that costs. The disabled controls point at this sentence by
                id, so it must exist whenever one of them does. --%>
          <p :if={not @deploy?} id="ouro-devices-blocked" class="ouro-devices-blocked">
            {@deploy_blocked}
          </p>
        </section>

        <%!-- Only the setups no row could claim. An operation whose journal names a machine
              this listing still has is drawn on that machine's row, which is where somebody
              looking for it would look. --%>
        <.orphan_operations
          :if={@orphans != []}
          operations={@orphans}
          hidden={@orphans_hidden}
        />

        <p class="ouro-subhead">
          <a href="/status">Runtime status — role, connected machines, live sessions →</a>
        </p>

        <.drawer
          :if={@drawer}
          drawer={@drawer}
          host={@host}
          announcement={@announcement}
          announced={@announced}
          can_operate?={@cancel?}
          operations={@operations}
        />
      </main>
    </div>
    """
  end

  # `render/1` receives assigns rather than the socket, and the helpers above read the
  # socket. This rebuilds the shape they read, which is the whole of what they use.
  defp assigns_socket(assigns) do
    %{
      assigns: %{
        inventory: assigns[:inventory],
        scope: assigns[:scope],
        availability: assigns[:availability]
      }
    }
  end

  defp all_devices(assigns) do
    case assigns[:inventory] do
      %{"devices" => devices} when is_list(devices) -> Enum.filter(devices, &is_map/1)
      _absent -> []
    end
  end

  # One list, in one order: this machine, then the fleet's members, then everything the
  # network client can see. `sort_by/2` is stable, so the runtime's own order survives
  # inside each of the three.
  defp rows(assigns, all) do
    all
    |> Enum.filter(&Devices.matches?(&1, assigns[:query] || ""))
    |> filtered(assigns[:filter] || "all")
    |> Enum.sort_by(&Devices.group/1)
  end

  defp filtered(devices, "fleet"), do: Enum.filter(devices, &Devices.fleet_row?/1)
  defp filtered(devices, "available"), do: Enum.reject(devices, &Devices.fleet_row?/1)
  defp filtered(devices, _all), do: devices

  # The setups no row could claim, capped — and how many the cap left out, because a prefix
  # drawn as if it were the whole is the thing `operations_total` exists to prevent.
  defp orphans(assigns, all) do
    loose =
      assigns[:operations]
      |> List.wrap()
      |> Enum.filter(&Devices.unfinished?(&1["state"]))
      |> Enum.reject(fn operation ->
        Enum.any?(all, &same_device?(operation["target"], &1))
      end)

    {Enum.take(loose, @max_stopped), max(length(loose) - @max_stopped, 0)}
  end

  # ------------------------------------------------------------------------------------
  # Components
  # ------------------------------------------------------------------------------------

  attr :fleet, :map, default: nil
  attr :error, :string, default: nil

  defp membership(assigns) do
    ~H"""
    <p :if={@error} class="ouro-refusal">{@error}</p>
    <dl :if={@fleet} class="ouro-facts">
      <div class="ouro-fact">
        <dt>Fleet</dt>
        <dd>{@fleet[:fleet_name] || "this machine is not in a named fleet"}</dd>
      </div>
      <div class="ouro-fact">
        <dt>Machines</dt>
        <dd class="ouro-mono">
          {get_in(@fleet, [:summary, :connected])} connected of {get_in(@fleet, [:summary, :expected])}
        </dd>
      </div>
    </dl>
    <ul :if={@fleet} class="ouro-devices-members">
      <li :for={machine <- List.wrap(@fleet[:machines])} data-state={machine[:state]}>
        <span class="ouro-devices-name">
          {machine[:machine] || Presentation.node_label(machine[:node])}
        </span>
        <span class="ouro-devices-presence">
          <span class="ouro-visually-hidden">Cluster state:</span>
          {member_state(machine[:state])}
        </span>
      </li>
    </ul>
    """
  end

  defp member_state(:local), do: "this machine"
  defp member_state(:connected), do: "connected to this runtime"
  defp member_state(:offline), do: "not connected to this runtime"
  defp member_state(other), do: "state not reported (#{inspect(other)})"

  attr :discovery, :map, default: nil

  # One inline notice in the client's own words, and never a claim about build age
  # (finding 1). `data-discovery` is the code, for a test that wants to name the branch.
  defp discovery(assigns) do
    code = assigns.discovery && assigns.discovery["code"]
    detail = assigns.discovery && assigns.discovery["detail"]

    assigns =
      assigns
      |> assign(:code, code)
      |> assign(:notice, Devices.discovery_notice(code, detail))

    ~H"""
    <p :if={@notice} class="ouro-devices-discovery" data-discovery={@code} role="status">
      {@notice}
    </p>
    """
  end

  attr :device, :map, required: true
  attr :host, :map, default: nil
  attr :operations, :list, required: true
  attr :deploy?, :boolean, required: true
  attr :blocked, :string, required: true

  # A row is a device, a device has one state and one thing you can do about it.
  defp device_row(assigns) do
    device = assigns.device
    operation = latest_operation(assigns.operations, device)
    state = operation["state"]

    assigns =
      assigns
      |> assign(:operation, operation)
      |> assign(:self?, Devices.self_row?(device))
      # The operation's `kind` and not only its state: a completed `leave` and a completed
      # `add` are the same state and opposite facts, and the row that read "set up just
      # now · Open" after a removal was this call throwing the difference away.
      |> assign(
        :words,
        if(
          device["state"] == "fleet_member_connected" and
            state in ["failed", "interrupted", "completed", "cancelled"],
          do:
            Devices.ouroboros_words(device) <>
              if(state in ["failed", "interrupted"],
                do:
                  " · " <>
                    if(operation["kind"] == "leave",
                      do: "removal failed",
                      else: "last setup stopped"
                    ),
                else: ""
              ),
          else:
            Devices.operation_words(state, operation["kind"]) || Devices.ouroboros_words(device)
        )
      )
      |> assign(
        :action,
        if(
          device["state"] == "fleet_member_connected" and
            (state in ["completed", "cancelled"] or
               (state in ["failed", "interrupted"] and operation["kind"] != "leave")),
          do: Devices.row_action(device, assigns.host && assigns.host["os"]),
          else:
            Devices.operation_action(state, operation["kind"]) ||
              Devices.row_action(device, assigns.host && assigns.host["os"])
        )
      )
      |> assign(:operation_id, operation["operation"])

    ~H"""
    <li
      class="ouro-devices-row"
      data-state={@device["state"]}
      data-operation-state={@operation["state"]}
      data-address={@device["address"]}
      data-machine={@device["machine"]}
    >
      <span :if={@self?} class="ouro-devices-label">{Devices.self_label(@host && @host["os"])}</span>
      <span class="ouro-devices-name">
        {Devices.name(@device["machine"], 96) || Devices.name(@device["name"], 96) ||
          Devices.this_device()}
      </span>
      <span class="ouro-devices-os">
        {Devices.plain(@device["os"], 48) || "platform not reported"}
      </span>
      <span class="ouro-devices-address ouro-mono">
        {Devices.plain(@device["address"], 64) || "no address"}
      </span>
      <span class="ouro-devices-presence">
        <span class="ouro-visually-hidden">Network presence:</span>
        <span aria-hidden="true" class="ouro-devices-dot">{Devices.presence_dot(@device)}</span>
        {Devices.presence_word(@device)}
      </span>
      <span class="ouro-devices-state">
        <span class="ouro-visually-hidden">Ouroboros:</span>
        {@words}
      </span>

      <span class="ouro-devices-action">
        <.row_button
          :if={@action}
          action={@action}
          device={@device}
          operation={@operation_id}
          deploy?={@deploy?}
          blocked={@blocked}
        />
        <%!-- A member whose latest operation just finished reads "set up just now · Open",
              and Open goes to the machines page — which left its details panel, and the
              Remove from fleet inside it, with no way in. The quiet second control keeps
              the panel reachable whenever the device has one and the primary is not it. --%>
        <button
          :if={Devices.inspectable?(@device) and elem(@action || {nil, nil}, 1) != "inspect-device"}
          type="button"
          class="ouro-quiet-button"
          phx-click="inspect-device"
          phx-value-row={@device["row_id"]}
        >
          Details
        </button>
      </span>

      <span :if={Devices.name_conflict(@device)} class="ouro-devices-note" role="note">
        {Devices.name_conflict(@device)}
      </span>
    </li>
    """
  end

  attr :action, :any, required: true
  attr :device, :map, required: true
  attr :operation, :string, default: nil
  attr :deploy?, :boolean, required: true
  attr :blocked, :string, required: true

  # One button, or a link where the destination is a page rather than a drawer.
  #
  # A control a blocker stands in front of keeps its name and reads as unavailable rather
  # than vanishing — an operator needs to know what is not available, not to find a gap
  # where it used to be — and it carries the reason rather than leaving it to a paragraph
  # somewhere below: as its `title`, and as `aria-describedby` pointing at the sentence the
  # page already draws, so a screen reader gets it too.
  #
  # This is a *host* blocker, not a device one. A device nothing can be done about has no
  # action at all (`Devices.row_action/2` answers `nil`), which is section 5.1's rule and a
  # different case from this one.
  defp row_button(assigns) do
    {label, event} = assigns.action
    blocked? = event == "deploy" and not assigns.deploy?

    assigns =
      assigns
      |> assign(:label, label)
      |> assign(:event, event)
      |> assign(:blocked?, blocked?)

    ~H"""
    <a :if={@event == "open-machines"} class="ouro-button" href="/status">{@label}</a>
    <button
      :if={@event != "open-machines"}
      type="button"
      class={["ouro-button", @blocked? && "ouro-devices-unavailable"]}
      disabled={@blocked?}
      aria-disabled={to_string(@blocked?)}
      title={@blocked? && @blocked}
      aria-describedby={@blocked? && "ouro-devices-blocked"}
      phx-click={not @blocked? && @event}
      phx-value-address={if @event == "deploy", do: @device["address"]}
      phx-value-row={if @event == "inspect-device", do: @device["row_id"]}
      phx-value-operation={@operation}
    >
      {@label}
    </button>
    """
  end

  # A row's operation is the unfinished-or-finished operation whose recorded target names
  # this device — by the address it was aimed at, or by the roster name it was to be called.
  defp latest_operation(operations, device) do
    Enum.find(List.wrap(operations), %{}, &same_device?(&1["target"], device))
  end

  # Address, or roster identity. Never the peer's own `name`: that field is what a *device*
  # calls itself, and a device that calls itself by a roster machine's name would otherwise
  # inherit that machine's operation — its row, its state, and a Continue button pointing at
  # somebody else's setup. `machine` is set by this machine's roster, which is the identity
  # a peer cannot choose.
  defp same_device?(target, device) when is_map(target) and is_map(device) do
    matches?(target["address"], device["address"]) or
      matches?(target["machine"], device["machine"])
  end

  defp same_device?(_target, _device), do: false

  defp matches?(left, right) when is_binary(left) and is_binary(right) and left != "",
    do: left == right

  defp matches?(_left, _right), do: false

  attr :operations, :list, required: true
  attr :hidden, :integer, default: 0

  defp orphan_operations(assigns) do
    ~H"""
    <section class="ouro-panel" aria-labelledby="devices-operations-title">
      <div class="ouro-panel-head">
        <h2 id="devices-operations-title">Setups with no device on this list</h2>
      </div>
      <p class="ouro-devices-quiet">
        This machine is holding these. Closing the page did not cancel them.
      </p>

      <ul class="ouro-devices-list">
        <li
          :for={operation <- @operations}
          class="ouro-devices-row"
          data-operation={operation["operation"]}
          data-state={operation["state"]}
        >
          <span class="ouro-devices-name ouro-mono">{operation["operation"]}</span>
          <span class="ouro-devices-state">
            <span class="ouro-visually-hidden">Setup state:</span>
            {Devices.operation_state(operation["state"])}
          </span>
          <span class="ouro-devices-action">
            <button
              type="button"
              class="ouro-button"
              phx-click="open-operation"
              phx-value-operation={operation["operation"]}
            >
              Continue
            </button>
          </span>
        </li>
      </ul>

      <p :if={@hidden > 0} class="ouro-devices-quiet">
        {@hidden} more are recorded on this machine and are not drawn here. They are in this
        data directory's deployment journals.
      </p>
    </section>
    """
  end

  # ------------------------------------------------------------------------------------
  # The drawer
  # ------------------------------------------------------------------------------------

  attr :drawer, :map, required: true
  attr :host, :map, default: nil
  attr :announcement, :string, required: true
  attr :announced, :integer, required: true
  attr :can_operate?, :boolean, required: true
  attr :operations, :list, default: []

  defp drawer(assigns) do
    assigns =
      assigns
      |> assign(:step, step(assigns.drawer))
      |> assign(:last_error, Devices.last_error((assigns.drawer.status || %{})["last_error"]))

    ~H"""
    <dialog
      id="ouro-deploy"
      class="ouro-session-dialog ouro-devices-drawer"
      aria-modal="true"
      aria-labelledby="ouro-deploy-title"
      phx-hook="Modal"
      data-cancel-event="drawer-close"
      data-step={@step}
      data-kind={@drawer.kind}
    >
      <div class="ouro-session-dialog-form">
        <h2 id="ouro-deploy-title">{drawer_title(@drawer, @host)}</h2>

        <%!-- The same fact the page states once, as the caption under the heading. --%>
        <p class="ouro-devices-caption" data-ouro-deployment-host>{Devices.host_line(@host)}</p>

        <%!-- The operation id, wherever the drawer is. It is what a row, a log line, this
              page's own address and the runtime's journal all name the same setup by, so an
              operator reading any of them can tell they are the same one. --%>
        <p :if={@drawer.operation} class="ouro-devices-quiet">
          Operation <span class="ouro-mono" data-ouro-operation>{@drawer.operation}</span>
        </p>

        <p
          id="ouro-deploy-live"
          class="ouro-visually-hidden"
          role="status"
          aria-live="polite"
          aria-atomic="true"
        >
          <span id={"ouro-deploy-announcement-#{@announced}"}>{@announcement}</span>
        </p>

        <p :if={@drawer.error} id="ouro-deploy-error" class="ouro-refusal" role="alert">
          {@drawer.error}
        </p>

        <%!-- A program that died before it could journal anything used to leave the
              operation sitting at "running" with nothing on screen, while the reason was in
              its own log the whole time. `last_error` is that reason — from the journal, or
              from this runtime's memory of the exit — and it comes with the one control that
              does anything about it. --%>
        <div
          :if={@last_error && @step != :finish}
          class="ouro-devices-takeover"
          data-ouro-last-error
        >
          <p id="ouro-deploy-last-error">{@last_error}</p>
          <button
            type="button"
            class="ouro-button"
            phx-click="resume"
            phx-value-operation={@drawer.operation}
            aria-describedby="ouro-deploy-last-error"
          >
            Retry
          </button>
        </div>

        <.details_step :if={@step == :inspect} drawer={@drawer} operations={@operations} />
        <.setup_step :if={@step == :select and @drawer.kind == "setup"} drawer={@drawer} host={@host} />
        <.leave_step :if={@step == :select and @drawer.kind == "leave"} drawer={@drawer} />
        <.connect_step
          :if={@step == :select and @drawer.kind not in ["setup", "leave"]}
          drawer={@drawer}
        />
        <.host_trust_step :if={@step == :host_trust} drawer={@drawer} />
        <.authenticate_step :if={@step == :authenticate} drawer={@drawer} />
        <.review_step :if={@step == :review} drawer={@drawer} />
        <.progress_step :if={@step in [:progress, :connecting]} drawer={@drawer} />
        <.finish_step :if={@step == :finish} drawer={@drawer} host={@host} />

        <.steps :if={@step not in [:select, :inspect]} drawer={@drawer} />

        <div class="ouro-devices-drawer-foot">
          <button type="button" class="ouro-quiet-button" phx-click="drawer-close">
            Close
          </button>
          <span
            :if={@drawer.operation && @step not in [:select, :inspect, :finish]}
            class="ouro-devices-quiet"
          >keeps running</span>
          <button
            :if={
              not is_nil(@drawer.operation) and @can_operate? and
                @step != :finish and Devices.unfinished?(state_of(@drawer))
            }
            type="button"
            class="ouro-quiet-button"
            phx-click="cancel-setup"
          >
            Cancel setup
          </button>
        </div>

        <p :if={@drawer.residue != []} class="ouro-devices-note">
          <strong>What this left behind:</strong>
          {Enum.map_join(@drawer.residue, "; ", &residue_line/1)}
        </p>
      </div>
    </dialog>
    """
  end

  defp residue_line(entry) when is_map(entry),
    do: Devices.plain(entry["detail"] || entry["name"] || entry)

  defp residue_line(entry) when is_binary(entry), do: Devices.plain(entry)
  defp residue_line(entry), do: Devices.plain(entry)

  # Which step the drawer is on. The challenge first, because an open challenge is the
  # program waiting for this operator and outranks whatever the last state frame said.
  #
  # There is one challenge, not a list: §8's program asks one question at a time and waits
  # for its answer, so `status.challenge` is the question in front of the operator and its
  # `kind` is which panel answers it.
  defp step(%{kind: "inspect"}), do: :inspect
  defp step(%{operation: nil}), do: :select
  defp step(%{status: nil}), do: :connecting

  defp step(drawer) do
    cond do
      challenge(drawer, ["host_trust"]) -> :host_trust
      challenge(drawer, ["password", "passphrase"]) -> :authenticate
      challenge(drawer, ["review"]) -> :review
      state_of(drawer) in ["completed", "failed", "cancelled"] -> :finish
      drawer.cancelled? -> :finish
      true -> :progress
    end
  end

  defp challenge(drawer, kinds) do
    case (drawer.status || %{})["challenge"] do
      %{"kind" => kind} = challenge -> if kind in kinds, do: challenge
      _none -> nil
    end
  end

  defp state_of(drawer), do: (drawer.status || %{})["state"]

  # Whether this runtime losing sight of the program leaves a question. A terminal state, or
  # a cancel this page asked for and the runtime acknowledged, is an answer; anything else
  # with nothing holding the operation is not.
  defp lost?(drawer) when is_map(drawer) do
    Devices.unfinished?(state_of(drawer)) and not drawer.cancelled?
  end

  defp lost?(_absent), do: false

  # Named after the machine, not after the procedure. "Deploy Ouroboros" was the heading on
  # every one of these, including the one that removes a machine.
  defp drawer_title(%{kind: "inspect"} = drawer, _host),
    do: drawer_machine(drawer) || "This device"

  defp drawer_title(%{kind: "setup"}, host),
    do: Devices.setup_label(host && host["os"])

  defp drawer_title(%{kind: "leave"} = drawer, _host),
    do: "Remove #{drawer_machine(drawer) || "this machine"} from the fleet"

  defp drawer_title(%{manual?: true, operation: nil}, _host), do: "Add a device by address"

  defp drawer_title(%{kind: "add"} = drawer, _host) do
    # An `add` reopened by id whose operation names no target: the row it came from is not
    # in this drawer, and "Add a device by address" would name a path the operator did not
    # take.
    "Add #{drawer_machine(drawer) || "a machine"} to your fleet"
  end

  defp drawer_title(drawer, _host) do
    case drawer_machine(drawer) do
      named when is_binary(named) -> "Add #{named} to your fleet"
      nil -> "Add a device by address"
    end
  end

  # The machine a drawer is about, best source first, or `nil` when it knows of none.
  #
  # The row it was opened from is the best: it carries the roster name and the display name.
  # But a drawer opened from an *operation* has no row — Continue on a row whose setup this
  # tab did not start, or `/devices?operation=…` after the tab that did was closed — and a
  # heading that fell straight through to "this machine" was the page failing to say which
  # machine an operator was about to remove.
  defp drawer_machine(drawer) do
    (drawer.device &&
       (Devices.name(drawer.device["machine"], 96) || Devices.name(drawer.device["name"], 96))) ||
      operation_machine(drawer)
  end

  # What the operation recorded it was aimed at: the roster name it names, or failing that
  # the address it was pointed at, which is still a thing an operator recognises.
  defp operation_machine(%{target: target}) when is_map(target),
    do: Devices.name(target["machine"], 96) || Devices.name(target["address"], 96)

  defp operation_machine(_no_target), do: nil

  # The machine a finished operation is about, from the plan where there is one and from the
  # form where there is not.
  defp target_name(drawer), do: target_machine(drawer) || "That machine"

  # Every name a heading might use, best first, and `nil` where none of them is a name.
  #
  # `Devices.name/2` rather than `Devices.plain/2` at each step, because this is a chain of
  # `||` and `plain/2` answers about text rather than about names: it says a boolean as
  # `"false"` and a string of invisible characters as `""`, both of which are truthy and
  # both of which stop the chain. That is the whole of the "false is in your fleet" bug.
  #
  # The plan is no longer one of the sources. §6 makes it the *lines* an operator approves
  # rather than a document with a `target.machine` in it, so what named the machine here is
  # the row, the form, or the operation's own recorded target — the last of which is all a
  # drawer opened by id has, and without it a resumed operation's ending read "That machine
  # is out of your fleet".
  defp target_machine(drawer) do
    (drawer.device &&
       (Devices.name(drawer.device["machine"]) || Devices.name(drawer.device["name"]))) ||
      Devices.name(drawer.form["machine"]) ||
      operation_machine(drawer)
  end

  attr :drawer, :map, required: true
  attr :operations, :list, default: []

  # §5.1: "the reason is in its details", and §5.4: Remove from fleet lives here.
  defp details_step(assigns) do
    device = assigns.drawer.device || %{}

    assigns =
      assigns
      |> assign(:device, device)
      |> assign(:operation, latest_operation(assigns.operations, device))

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-details-title">
      <h3 id="ouro-deploy-details-title">Details</h3>

      <dl class="ouro-facts">
        <div class="ouro-fact">
          <dt>Name in the fleet</dt>
          <dd>{Devices.plain(@device["machine"], 96) || "not on this fleet's roster"}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Name on the network</dt>
          <dd>{Devices.plain(@device["name"], 96) || "not reported"}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Address</dt>
          <dd class="ouro-mono">{Devices.plain(@device["address"], 64) || "no address"}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Ouroboros</dt>
          <dd>{Devices.ouroboros_words(@device)}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Route</dt>
          <dd>{Devices.path_words(@device["path"])}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Connected to this runtime</dt>
          <dd>{flag(@device["connected"])}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Compatible build</dt>
          <dd>{flag(@device["compatible"])}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Its runtime is running</dt>
          <dd>{flag(@device["runtime_running"])}</dd>
        </div>
        <%!-- The exact instant lives here and only here: §5.1 keeps ISO timestamps off the
              rows, and this is the panel somebody opened to ask for one. --%>
        <div class="ouro-fact">
          <dt>Last seen by the network client</dt>
          <dd class="ouro-mono">{Devices.exact_time(@device["last_seen"])}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Last answered this runtime</dt>
          <dd class="ouro-mono">{Devices.exact_time(@device["last_probe"])}</dd>
        </div>
      </dl>

      <p :if={Devices.blocked?(@device)} class="ouro-devices-blocked">
        {Devices.ouroboros_words(@device)} — so there is nothing to offer on its row.
        Refresh after it comes back.
      </p>

      <p :if={@operation != %{}} class="ouro-devices-quiet">
        Latest {if @operation["kind"] == "leave", do: "removal", else: "setup"}
        <span class="ouro-mono">{Devices.plain(@operation["operation"], 32)}</span>
        — {if @operation["kind"] == "leave",
          do: Devices.operation_words(@operation["state"], "leave"),
          else: Devices.operation_state(@operation["state"])}
      </p>

      <div class="ouro-devices-actions">
        <button
          :if={@operation["kind"] == "leave" and @operation["state"] in ["failed", "interrupted"]}
          type="button"
          class="ouro-button"
          phx-click="open-operation"
          phx-value-operation={@operation["operation"]}
        >
          Retry removal
        </button>
        <button
          :if={
            Devices.removable?(@device) and
              not (@operation["kind"] == "leave" and @operation["state"] in ["failed", "interrupted"])
          }
          type="button"
          class="ouro-quiet-button"
          phx-click="leave-device"
          phx-value-address={@device["address"]}
        >
          Remove from fleet
        </button>
        <button type="button" class="ouro-quiet-button" phx-click="refresh">Refresh</button>
      </div>
    </section>
    """
  end

  defp flag(true), do: "yes"
  defp flag(false), do: "no"
  defp flag(_unknown), do: "not reported"

  attr :drawer, :map, required: true
  attr :host, :map, default: nil

  # §5.3. This machine configures itself: no SSH, no account, no password.
  defp setup_step(assigns) do
    ~H"""
    <form id="ouro-deploy-setup" phx-change="connect-change" phx-submit="connect">
      <section class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="setup-machine">Name in the fleet</label>
        </div>
        <input
          id="setup-machine"
          class="ouro-new-input"
          type="text"
          name="machine"
          value={@drawer.form["machine"]}
          aria-describedby="setup-machine-hint"
          autocomplete="off"
        />
        <p id="setup-machine-hint" class="ouro-new-hint">
          Letters, digits and hyphens. This host's own name when left empty.
        </p>
      </section>

      <section class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="setup-address">Address</label>
        </div>
        <input
          id="setup-address"
          class="ouro-new-input ouro-mono"
          type="text"
          name="address"
          value={@drawer.form["address"]}
          readonly={@drawer.device && @drawer.device["address"] not in [nil, ""]}
          aria-describedby="setup-address-hint"
          autocomplete="off"
        />
        <p id="setup-address-hint" class="ouro-new-hint">
          The address this runtime will bind. Discovery filled this in; left empty, the setup
          stops and says so rather than guessing at one.
        </p>
      </section>

      <section class="ouro-new-field ouro-devices-check">
        <input type="hidden" name="service" value="false" />
        <input
          id="setup-service"
          type="checkbox"
          name="service"
          value="true"
          checked={@drawer.form["service"] == "true"}
        />
        <label class="ouro-new-label" for="setup-service">Start at login</label>
      </section>

      <p class="ouro-devices-quiet">
        Ouroboros restarts once during setup; this page reconnects by itself.
      </p>

      <div class="ouro-devices-actions">
        <button
          type="submit"
          class="ouro-button"
          disabled={@drawer.busy == :prepare}
          aria-describedby={@drawer.error && "ouro-deploy-error"}
        >
          Set up
        </button>
        <button type="button" class="ouro-quiet-button" phx-click="cancel-setup">Cancel</button>
      </div>
      <p class="ouro-new-hint">
        Reads this machine first. Nothing is configured or restarted until you approve a plan.
      </p>
    </form>
    """
  end

  attr :drawer, :map, required: true

  # §5.2. Name, address, SSH user — and everything else behind a disclosure that stays open.
  defp connect_step(assigns) do
    assigns =
      assigns
      |> assign(:name_error, typed_name_error(assigns.drawer.form["machine"]))
      |> assign(:target, target_words(assigns.drawer))

    ~H"""
    <form id="ouro-deploy-connect" phx-change="connect-change" phx-submit="connect">
      <section class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="deploy-machine">Name in the fleet</label>
        </div>
        <input
          id="deploy-machine"
          class="ouro-new-input"
          type="text"
          name="machine"
          value={@drawer.form["machine"]}
          required
          aria-invalid={@name_error && "true"}
          aria-describedby={
            if(@name_error,
              do: "deploy-machine-hint deploy-machine-error",
              else: "deploy-machine-hint"
            )
          }
          autocomplete="off"
        />
        <p id="deploy-machine-hint" class="ouro-new-hint">letters, digits, hyphens</p>
        <%!-- Said while it is still being typed, but only about something that *was*
              typed: an empty box on the manual form is not yet a mistake, and an error
              under it before the first keystroke is an accusation. Submitting empty is
              refused on the server, which is the check that actually holds. --%>
        <p :if={@name_error} id="deploy-machine-error" class="ouro-refusal" role="alert">
          {@name_error}
        </p>
      </section>

      <section class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="deploy-address">Address</label>
        </div>
        <%!-- Read-only when it came from the list: that address is a fact discovery
              established, and an editable copy of it is a way to aim this at something
              else by accident. Typed in by hand, it is the whole point of the form. --%>
        <input
          id="deploy-address"
          class="ouro-new-input ouro-mono"
          type="text"
          name="address"
          value={@drawer.form["address"]}
          readonly={not @drawer.manual?}
          required
          aria-describedby="deploy-address-hint"
          autocomplete="off"
        />
        <p id="deploy-address-hint" class="ouro-new-hint">
          {if @drawer.manual?,
            do: "The address this machine can reach the device at.",
            else: "From the list, and checked the same way as one typed in."}
        </p>
      </section>

      <section class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="deploy-ssh-user">SSH user</label>
        </div>
        <input
          id="deploy-ssh-user"
          class="ouro-new-input"
          type="text"
          name="ssh_user"
          value={@drawer.form["ssh_user"]}
          required
          aria-describedby="deploy-ssh-user-hint"
          autocomplete="off"
        />
        <p id="deploy-ssh-user-hint" class="ouro-new-hint">
          the account on {@target}
        </p>
      </section>

      <.advanced drawer={@drawer} paths?={true} />

      <div class="ouro-devices-actions">
        <button
          type="submit"
          class="ouro-button"
          disabled={@drawer.busy == :prepare}
          aria-describedby={@drawer.error && "ouro-deploy-error"}
        >
          Connect
        </button>
        <button type="button" class="ouro-quiet-button" phx-click="cancel-setup">Cancel</button>
      </div>
      <p class="ouro-new-hint">
        Reads the machine first. Nothing is installed until you approve a plan.
      </p>
    </form>
    """
  end

  # A name the operator has typed and got wrong, as opposed to one they have not typed yet.
  defp typed_name_error(value) do
    trimmed = if is_binary(value), do: String.trim(value), else: ""

    if trimmed != "" and not Devices.valid_machine?(trimmed),
      do: Devices.machine_error(trimmed)
  end

  # What the SSH-user hint calls the target. `Devices.name/2` for the same reason as
  # `target_machine/1`: on the manual "Add a device by address" form there is no device and
  # the address box is still empty, and `Devices.plain("", 64)` is `""` — truthy — so the
  # hint rendered as "the account on " with nothing after it until the first keystroke.
  defp target_words(drawer) do
    (drawer.device &&
       (Devices.name(drawer.device["name"]) || Devices.name(drawer.device["machine"]))) ||
      Devices.name(drawer.form["address"]) || "that machine"
  end

  attr :drawer, :map, required: true

  # §5.4. The same machinery as adding one, aimed the other way.
  defp leave_step(assigns) do
    machine = assigns.drawer.device && assigns.drawer.device["machine"]

    assigns = assign(assigns, :machine, machine)

    ~H"""
    <form id="ouro-deploy-leave" phx-change="connect-change" phx-submit="connect">
      <p>{Devices.leave_line(@machine)}</p>

      <section class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="leave-ssh-user">SSH user</label>
        </div>
        <input
          id="leave-ssh-user"
          class="ouro-new-input"
          type="text"
          name="ssh_user"
          value={@drawer.form["ssh_user"]}
          required
          aria-describedby="leave-ssh-user-hint"
          autocomplete="off"
        />
        <p id="leave-ssh-user-hint" class="ouro-new-hint">
          the account on {Devices.name(@machine) || "that machine"}
        </p>
      </section>

      <.advanced drawer={@drawer} paths?={false} />

      <div class="ouro-devices-actions">
        <button
          type="submit"
          class="ouro-button"
          disabled={@drawer.busy == :prepare}
          aria-describedby={@drawer.error && "ouro-deploy-error"}
        >
          Connect
        </button>
        <button type="button" class="ouro-quiet-button" phx-click="cancel-setup">Cancel</button>
      </div>
      <p class="ouro-new-hint">
        Reads the machine first. Nothing is changed until you approve a plan.
      </p>
      <%!-- The `fleet sessions forget` recipe used to be here, which meant this form
            opened by saying the machine "did not answer, so nothing on it was changed"
            before anything had been attempted. It is a repair for one failure, and it is
            now drawn on that failure — see `leave_fallback/2`. --%>
    </form>
    """
  end

  attr :drawer, :map, required: true
  attr :paths?, :boolean, default: true

  # Finding 6: `open` is bound to the assign, and the summary writes that assign. Before
  # this the element carried no `open` at all and the `advanced` event wrote a field nothing
  # read, so every keystroke in the form above it collapsed the disclosure.
  #
  # Deliberately *not* marked `data-ouro-disclosure`: that attribute tells `app.js` to carry
  # the DOM's own `open` across a patch, which would fight the assign rather than help it.
  defp advanced(assigns) do
    ~H"""
    <details class="ouro-devices-advanced" open={@drawer.advanced?}>
      <summary phx-click="advanced" phx-value-open={to_string(not @drawer.advanced?)}>
        Advanced — port, SSH key{if @paths?, do: ", install path, data directory, start at login"}
      </summary>

      <section class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="deploy-port">SSH port</label>
        </div>
        <input
          id="deploy-port"
          class="ouro-new-input ouro-mono"
          type="number"
          name="port"
          min="1"
          max="65535"
          value={@drawer.form["port"]}
        />
      </section>

      <section class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="deploy-identity-ref">SSH key</label>
          <span class="ouro-new-aside">Optional</span>
        </div>
        <input
          id="deploy-identity-ref"
          class="ouro-new-input ouro-mono"
          type="text"
          name="identity_ref"
          value={@drawer.form["identity_ref"]}
          aria-describedby="deploy-identity-ref-hint"
          autocomplete="off"
        />
        <p id="deploy-identity-ref-hint" class="ouro-new-hint">
          A key file's path on this machine, or an agent identity's SHA256 fingerprint. Left
          empty, the default identity is used and a machine that asks for a password asks
          here. No private key is exported, uploaded or forwarded.
        </p>
      </section>

      <section :if={@paths?} class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="deploy-install-path">Install path</label>
          <span class="ouro-new-aside">Optional</span>
        </div>
        <input
          id="deploy-install-path"
          class="ouro-new-input ouro-mono"
          type="text"
          name="install_path"
          value={@drawer.form["install_path"]}
          autocomplete="off"
        />
      </section>

      <section :if={@paths?} class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="deploy-data-dir">Data directory</label>
          <span class="ouro-new-aside">Optional</span>
        </div>
        <input
          id="deploy-data-dir"
          class="ouro-new-input ouro-mono"
          type="text"
          name="data_dir"
          value={@drawer.form["data_dir"]}
          autocomplete="off"
        />
      </section>

      <section :if={@paths?} class="ouro-new-field ouro-devices-check">
        <input type="hidden" name="service" value="false" />
        <input
          id="deploy-service"
          type="checkbox"
          name="service"
          value="true"
          checked={@drawer.form["service"] == "true"}
        />
        <label class="ouro-new-label" for="deploy-service">Start at login</label>
      </section>
    </details>
    """
  end

  attr :drawer, :map, required: true

  defp host_trust_step(assigns) do
    challenge = challenge(assigns.drawer, ["host_trust"])
    facts = Devices.metadata(challenge)

    assigns =
      assigns
      |> assign(:challenge, challenge)
      |> assign(:facts, facts)
      |> assign(:address, facts["address"] || assigns.drawer.form["address"])

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-trust-title">
      <h3 id="ouro-deploy-trust-title">{Devices.host_trust_title(@address)}</h3>

      <%!-- Every fact here is the worker's own `host_trust` metadata
            (`host_trust_metadata/5` in tui/src/fleet_setup/challenge.rs), with the form's
            answer only as a fallback where the worker reported nothing. --%>
      <dl class="ouro-facts">
        <div class="ouro-fact">
          <dt>Key algorithm</dt>
          <dd class="ouro-mono">{Devices.plain(@facts["algorithm"], 48) || "not reported"}</dd>
        </div>
        <div class="ouro-fact">
          <dt>SHA256</dt>
          <dd class="ouro-mono">
            {Devices.plain(@facts["sha256_fingerprint"], 96) || "not reported"}
          </dd>
        </div>
      </dl>

      <p id="ouro-deploy-trust-hint">
        Check this fingerprint on the device itself before continuing. Use the device's
        console or an already trusted SSH connection, then compare the SHA256 fingerprint.
        Nothing on this page can establish that trust for you.
      </p>
      <pre :if={Devices.host_key_command(@facts["algorithm"])} class="ouro-mono">{Devices.host_key_command(@facts["algorithm"])}</pre>

      <div class="ouro-devices-actions">
        <button
          type="button"
          class="ouro-button"
          phx-click="trust-host"
          phx-value-challenge={@challenge["challenge"]}
          phx-value-accept="true"
          aria-describedby="ouro-deploy-trust-hint"
        >
          Trust and continue
        </button>
        <button
          type="button"
          class="ouro-quiet-button"
          phx-click="trust-host"
          phx-value-challenge={@challenge["challenge"]}
          phx-value-accept="false"
        >
          Cancel
        </button>
      </div>
    </section>
    """
  end

  attr :drawer, :map, required: true

  defp authenticate_step(assigns) do
    challenge = challenge(assigns.drawer, ["password", "passphrase"])
    facts = Devices.metadata(challenge)

    assigns =
      assigns
      |> assign(:challenge, challenge)
      |> assign(:facts, facts)
      |> assign(:field, "ouro-deploy-secret-#{assigns.drawer.secret_nonce}")
      |> assign(
        :title,
        if(challenge["kind"] == "passphrase",
          do: Devices.challenge_title("passphrase"),
          else:
            Devices.password_title(
              facts["user"] || assigns.drawer.form["ssh_user"],
              facts["target"] || facts["address"] || assigns.drawer.form["address"]
            )
        )
      )

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-auth-title">
      <h3 id="ouro-deploy-auth-title">
        {@title}
        <%!-- "attempt 2 of 3", where the worker said so — `password_metadata/5` carries
              `attempt` and `max_attempts`, and a passphrase carries neither. --%>
        <span :if={Devices.attempt(@challenge)} class="ouro-devices-quiet">
          ({Devices.attempt(@challenge)})
        </span>
      </h3>

      <p :if={@facts["public_fingerprint"]} class="ouro-devices-quiet">
        Public fingerprint
        <span class="ouro-mono">{Devices.plain(@facts["public_fingerprint"], 96)}</span>
      </p>

      <%!-- No `phx-change`. A change event on this form would stream every keystroke of a
            password to this server, which is the one thing the secret-handling rules forbid
            by name. The field is submitted, once, in answer to its own challenge — and the
            id below changes afterwards so the browser replaces the element with an empty
            one rather than keeping what was typed. --%>
      <form id="ouro-deploy-auth" phx-submit="authenticate">
        <input type="hidden" name="challenge" value={@challenge["challenge"]} />

        <section class="ouro-new-field">
          <div class="ouro-new-label-row">
            <label class="ouro-new-label" for={@field}>{Devices.secret_label(@challenge)}</label>
          </div>
          <input
            id={@field}
            class="ouro-new-input"
            type="password"
            name="secret"
            value=""
            required
            autocomplete="off"
            spellcheck="false"
            data-ouro-secret
            aria-describedby="ouro-deploy-auth-hint"
            phx-mounted={Phoenix.LiveView.JS.focus()}
          />
          <p id="ouro-deploy-auth-hint" class="ouro-new-hint">
            Used once, for this connection, and discarded when it has been consumed. It is
            not stored, not remembered for a reconnection, and not reused for another
            machine.
          </p>
        </section>

        <div class="ouro-devices-actions">
          <button
            type="submit"
            class="ouro-button"
            aria-describedby={@drawer.error && "ouro-deploy-error"}
          >
            Continue
          </button>
        </div>
      </form>
    </section>
    """
  end

  attr :drawer, :map, required: true

  # §5.2 step 3, and §10's version of it: the plan's own lines, Deploy and Cancel.
  #
  # There is no digest and no disclosure holding a second copy of the plan. §6 makes the plan
  # a list of sentences, so there is nothing to canonicalise and nothing to hash: what this
  # section shows *is* what the button approves, and the challenge id is what says which
  # plan that is. A second click is `challenge_consumed` rather than a replay.
  #
  # The lines come from the challenge's own metadata where it carries them, and from the
  # operation's `plan` otherwise — the same lines, from the worker process's memory of the
  # challenge or from the journal.
  defp review_step(assigns) do
    challenge = challenge(assigns.drawer, ["review"])
    facts = Devices.metadata(challenge)
    status = assigns.drawer.status || %{}

    assigns =
      assigns
      |> assign(:challenge, challenge)
      |> assign(:lines, Devices.review_lines(facts["plan"] || status["plan"]))
      |> assign(:kind, assigns.drawer.kind)

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-review-title">
      <h3 id="ouro-deploy-review-title">{Devices.challenge_title("review", @kind)}</h3>

      <ul :if={@lines != []} id="ouro-deploy-plan" class="ouro-devices-plan-lines">
        <li :for={line <- @lines}>{line}</li>
      </ul>

      <p :if={@lines == []} class="ouro-devices-quiet">
        This operation sent no plan this page can read. Approving it would be approving
        something nobody has been shown, so read the steps below before you do.
      </p>

      <div class="ouro-devices-actions">
        <button
          type="button"
          class="ouro-button"
          phx-click="approve"
          phx-value-challenge={@challenge["challenge"]}
          aria-describedby="ouro-deploy-review-hint"
        >
          {Devices.approve_label(@kind)}
        </button>
        <button type="button" class="ouro-quiet-button" phx-click="cancel-setup">Cancel</button>
      </div>
      <p id="ouro-deploy-review-hint" class="ouro-new-hint">
        This applies exactly the plan above, on <span data-ouro-operation-inline>{@drawer.operation}</span>.
      </p>
    </section>
    """
  end

  attr :drawer, :map, required: true

  # The strip is `steps/1`; this is the sentence under it.
  defp progress_step(assigns) do
    assigns =
      assigns
      |> assign(:detail, current_detail(assigns.drawer))
      |> assign(:source, (assigns.drawer.status || %{})["source"])

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-progress-title">
      <h3 id="ouro-deploy-progress-title">
        {Devices.operation_state(state_of(@drawer))}
      </h3>
      <p :if={@detail} class="ouro-devices-detail">{@detail}</p>
      <p class="ouro-devices-quiet">{source_words(@source)}</p>
    </section>
    """
  end

  # The step the worker is on, in its own words — which is the line an operator watches.
  defp current_detail(drawer) do
    steps = List.wrap((drawer.status || %{})["steps"])

    running =
      Enum.find(Enum.reverse(steps), fn step ->
        is_map(step) and step["outcome"] == "started"
      end) || List.last(Enum.filter(steps, &is_map/1))

    case running do
      step when is_map(step) ->
        [Devices.step_label(step["step"]), Devices.plain(step["detail"])]
        |> Enum.reject(&is_nil/1)
        |> Enum.join(" — ")

      _none ->
        nil
    end
  end

  defp source_words("worker"),
    do: "A worker is attached, so this is what is happening now."

  defp source_words("journal"),
    do:
      "No worker is attached. This is what the journal durably recorded, which is not the " <>
        "same as what is happening now."

  defp source_words(_unreported), do: "This runtime did not say where this answer came from."

  attr :drawer, :map, required: true
  attr :host, :map, default: nil

  defp finish_step(assigns) do
    status = assigns.drawer.status || %{}

    assigns =
      assigns
      |> assign(:state, final_state(status, assigns.drawer))
      |> assign(:finished?, status["state"] == "completed")
      |> assign(:leave?, assigns.drawer.kind == "leave")
      |> assign(:summary, status["summary"])
      |> assign(:cause, cause(status))
      |> assign(:fallback, leave_fallback(assigns.drawer, status))
      |> assign(:name, target_name(assigns.drawer))

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-finish-title">
      <h3 id="ouro-deploy-finish-title">{finish_title(@state, @drawer.kind, @name)}</h3>

      <p :if={@summary}>{Devices.plain(@summary)}</p>
      <p :if={@cause} class="ouro-refusal">{@cause}</p>

      <%!-- §5.4's way out, on the one failure it is the way out of: the member never
            answered, so this machine's own members list is the only thing left to repair. --%>
      <p :if={@fallback} class="ouro-devices-note">{@fallback}</p>

      <%!-- Two things, not five. The review found a finished setup offering "Configure
            model" and "Run test task", both of which act on *this* runtime rather than on
            the machine that was just added.

            And on a removal, one: **Open** goes to the machines panel, which is the right
            place to look at a machine that has just joined and the wrong place to look for
            one that has just left. --%>
      <div :if={@finished?} class="ouro-devices-actions">
        <a :if={not @leave?} class="ouro-button" href="/status">Open</a>
        <button
          type="button"
          class={if @leave?, do: "ouro-button", else: "ouro-quiet-button"}
          phx-click="drawer-close"
        >
          Done
        </button>
      </div>

      <div :if={@state == "failed"} class="ouro-devices-actions">
        <button
          type="button"
          class="ouro-button"
          phx-click="resume"
          phx-value-operation={@drawer.operation}
        >
          Retry
        </button>
      </div>

      <p :if={@state == "cancelled"}>
        This setup stopped at a safe boundary. It does not undo anything that was already
        delivered to the other machine.
      </p>
    </section>
    """
  end

  # §5.4's fallback, drawn only on a removal that failed because the member could not be
  # reached. Every other failure has its own repair and this one would be wrong advice:
  # offering `ouro fleet forget` for an authentication refusal or a busy runtime is offering
  # to drop a machine that is still there. A leave records its steps as it goes, so an empty
  # history is what says the target was never reached at all.
  defp leave_fallback(%{kind: "leave"} = drawer, status) when is_map(status) do
    error = status["last_error"] || %{}

    if status["state"] == "failed" and Devices.unreachable?(error["reason"]) and
         List.wrap(status["steps"]) == [],
       do: Devices.leave_fallback(target_machine(drawer))
  end

  defp leave_fallback(_other, _status), do: nil

  # "<name> is in your fleet" — the sentence §5.2 asks for, and its opposite where the
  # operation was a removal rather than a join.
  defp finish_title("completed", "leave", name), do: "#{name} is out of your fleet"
  defp finish_title("completed", _kind, name), do: "#{name} is in your fleet"

  # `operation_state/1` is the add flow's vocabulary — it answers "Setup failed" — and a
  # removal that could not finish is not a setup that failed. Named after the machine here
  # too, because the heading is the first thing read and "Setup failed" says neither what was
  # being done nor to what.
  defp finish_title("failed", "leave", name), do: "#{name} was not removed"
  defp finish_title(state, _kind, _name), do: Devices.operation_state(state)

  @terminal ~w(completed failed cancelled)

  # Whether this operation has stopped, either way. A cancel this page asked for and the
  # runtime acknowledged counts, because the program may leave no further frame.
  defp finished?(drawer), do: state_of(drawer) in @terminal or drawer.cancelled?

  defp final_state(status, drawer) do
    cond do
      status["state"] in @terminal -> status["state"]
      drawer.cancelled? -> "cancelled"
      true -> status["state"]
    end
  end

  # What went wrong, in the program's own two fields. `Devices.last_error/1` turns the stable
  # code into a sentence and puts the detail after it; both halves go through
  # `Devices.plain/2` there, because the detail is whatever the program quoted — an `ssh`
  # diagnostic, a remote shell, a release filename — and a bidi override in one of those is a
  # sentence this page would otherwise render backwards. `Presentation.refusal/1` rewrites
  # the words and is not a sanitiser.
  defp cause(status) do
    Presentation.refusal(cause_text(Devices.last_error(status["last_error"])))
  end

  # `plain/2` answers `""` for a value that was nothing but invisible characters, and `""` is
  # truthy — a `||` chain written over it stops at nothing at all, which is the same trap
  # `Devices.name/2` exists for. A cause that sanitises away is not a cause.
  defp cause_text(value) do
    case Devices.plain(value, 2_000) do
      "" -> nil
      sanitized -> sanitized
    end
  end

  attr :drawer, :map, required: true

  # §5.2 step 4: one strip, one mark per step, and the program's log behind a disclosure.
  defp steps(assigns) do
    kind = assigns.drawer.kind

    reported =
      List.wrap((assigns.drawer.status || %{})["steps"])
      |> Enum.filter(&is_map/1)
      |> Enum.reverse()
      |> Enum.uniq_by(& &1["step"])
      |> Enum.reverse()
      |> Enum.map(fn step ->
        # A step the program said it had *attempted* and then stopped without finishing is a
        # step that failed, whatever the last frame to arrive happened to say.
        if step["state"] == "attempted" and finished?(assigns.drawer),
          do: Map.put(step, "state", "failed"),
          else: step
      end)

    named = Enum.map(Devices.stages(kind), &elem(&1, 0))

    assigns =
      assigns
      # §6 gives each kind its own steps, one stage each, in the order the engine records
      # them. A stage the program has reported nothing for says so; it does not read as done.
      |> assign(
        :stages,
        Enum.map(Devices.stages(kind), fn {key, label} ->
          {key, label, Enum.find(reported, &(&1["step"] == key))}
        end)
      )
      # And the steps that belong to none of this kind's — a name this build has not been
      # taught — under their own names rather than folded into a stage they are not part of.
      |> assign(:extra, Enum.reject(reported, &(&1["step"] in named)))
      # An operation that has stopped will report nothing more, so a stage it never reached
      # is not "not reported *yet*" — the yet is a promise the page cannot keep.
      |> assign(
        :unreported,
        if(finished?(assigns.drawer), do: "not checked", else: "not reported yet")
      )
      |> assign(:log, List.wrap((assigns.drawer.status || %{})["log"]))

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-steps-title">
      <h3 id="ouro-deploy-steps-title" class="ouro-visually-hidden">Steps</h3>

      <%!-- One strip: ✓ done, ● running, ○ not yet, ✗ failed. The mark is a summary of the
            words beside it rather than the only place the state is said, and each stage
            keeps the program's own detail under it — a failed step's reason is the thing an
            operator came here to read. --%>
      <ol class="ouro-devices-strip">
        <li :for={{key, label, step} <- @stages} data-step={key} data-outcome={step && step["state"]}>
          <span aria-hidden="true" class="ouro-devices-mark">
            {Devices.stage_mark(step && step["state"])}
          </span>
          <span class="ouro-devices-step-name">{label}</span>
          <span class="ouro-devices-step-outcome">
            <span class="ouro-visually-hidden">Outcome:</span>
            {if is_nil(step), do: @unreported, else: elem(Devices.outcome(step["state"]), 0)}
          </span>
          <span :if={step && step["detail"]} class="ouro-devices-detail">
            {Devices.plain(step["detail"])}
          </span>
        </li>
      </ol>

      <ul :if={@extra != []} class="ouro-devices-steps">
        <li :for={step <- @extra} data-step={step["step"]} data-outcome={step["state"]}>
          <span class="ouro-devices-step-name">{Devices.step_label(step["step"])}</span>
          <span class="ouro-devices-step-outcome">
            <span class="ouro-visually-hidden">Outcome:</span>
            {elem(Devices.outcome(step["state"]), 0)}
          </span>
          <span :if={step["detail"]} class="ouro-devices-detail">{Devices.plain(step["detail"])}</span>
        </li>
      </ul>

      <details :if={@log != []} class="ouro-devices-advanced">
        <summary>What the setup program reported</summary>
        <ul class="ouro-devices-log">
          <li :for={line <- @log} class="ouro-mono">
            {log_line(line)}
          </li>
        </ul>
      </details>
    </section>
    """
  end

  defp log_line(%{"line" => line}), do: Devices.plain(line)
  defp log_line(line) when is_binary(line), do: Devices.plain(line)
  defp log_line(other), do: Devices.plain(other)
end
