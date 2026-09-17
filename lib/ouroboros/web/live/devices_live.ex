defmodule Ouroboros.Web.Live.DevicesLive do
  @moduledoc """
  `/devices`: what this machine can see, and the deployment of Ouroboros onto one of it.

  Two halves. The **inventory** is one read of `fleet.devices` — this deployment host's own
  identity, what its network client can see, this machine's roster merged into it, and the
  deployment operations its data directory holds journals for. The **Deploy drawer** is a
  state machine over one operation: select and connect, verify the host, authenticate,
  review the plan, watch it run, finish or recover.

  ## The work happens on the runtime's machine, not on this laptop

  Every fact on this page is about the machine hosting the runtime this browser is talking
  to. Its SSH configuration, its keys, its agent, its network client. A browser cannot lend
  a laptop's SSH agent to a runtime three hops away, and this page never implies that it
  can: the deployment host's hostname and local account are drawn as a permanent header,
  from `fleet.devices`, before anything is typed.

  ## Where the secret is, and is not

  One event, `"authenticate"`, receives a password or a passphrase. It arrives only as the
  submission of the challenge's own form — the field carries no `phx-change`, so nothing
  streams keystrokes to this server — and it leaves in the same function call: the value is
  passed to `Ouroboros.Web.Call.call/4` and is never assigned, never logged, never put in
  the URL and never rendered back. The field is emptied afterwards by giving it a new DOM id,
  so the browser replaces the element rather than keeping the value the operator typed.

  The field uses `autocomplete="off"` rather than `new-password` so the browser is not
  invited to save the value. Browsers still sometimes offer a save; the emptied field and
  the nonce that replaces it are what this page can actually do about that.

  The secret's journey after that is `Ouroboros.Fleet.Deployment`'s, which documents it:
  the broker never sees it, and `Ouroboros.Gateway.AuditLine` redacts this one verb's
  parameters rather than digesting them.

  ## Closing this page does not cancel anything

  The worker is detached from this runtime, let alone from this socket. Closing the drawer
  unsubscribes and nothing else; the operation keeps its row, and reopening the page at
  `/devices?operation=<id>` reloads it by id. A lost connection is reported as exactly what
  it is — the result is unknown until the operation is queried again — and never as a
  failure, and never by starting a second deployment.
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
  @prepare "fleet.deployment.prepare"
  @authenticate "fleet.deployment.authenticate"
  @confirm_host "fleet.deployment.confirm_host"
  @start "fleet.deployment.start"
  @cancel "fleet.deployment.cancel"
  @resume "fleet.deployment.resume"
  @fleet "fleet.status"

  # A worker that has just died leaves the broker a moment behind it, and during that moment
  # a status read answers `worker_unavailable` rather than the journal. Bounded, so an
  # operation whose record really is unreadable stops rather than polling forever.
  # How many stopped operations this page draws. A journal directory holds two hundred, and
  # every one of them was once a row an operator had to scroll past the inventory to reach.
  @max_stopped 10

  @status_retries 8
  @status_retry_after 150
  @reload_burst 150

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:view_session, tab_session(socket))
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

  @doc """
  The id a deployment's credential challenges are bound to: **this browser tab's**.

  Seam S4 binds a challenge to the session that was attached when it was issued, and the two
  obvious ids are both wrong. The cookie's is one id every tab in the browser shares, so
  binding to it makes "a second tab cannot answer the first tab's prompt" false. A freshly
  minted per-*mount* id makes it too true: a refresh, a dropped socket, this page's own
  `?operation=` reload and — worst — the restart the first local setup performs on the
  runtime serving this page all remount, and every pending challenge becomes
  `challenge_not_bound` with nothing the operator can press.

  So the id belongs to the tab. `app.js` keeps one in `sessionStorage`, which is per tab by
  definition, and sends it as a connect parameter; this reads it, holds it to the shape it
  minted, and falls back to a fresh one when it is absent — a browser that refuses storage,
  or the dead render, which answers no events anyway. A tab that cannot be recognised is
  back where this page started rather than broken.

  Not trusted for anything but *which pending challenge this tab may answer*: the identity
  is the audited subject's and the gateway's, and a client-chosen id cannot widen it.
  """
  @spec tab_session(Phoenix.LiveView.Socket.t()) :: String.t()
  def tab_session(socket) do
    if connected?(socket) do
      socket |> get_connect_params() |> tab_id() || Call.view_session()
    else
      Call.view_session()
    end
  end

  defp tab_id(%{"_ouro_tab" => id}) when is_binary(id) do
    if String.match?(id, ~r/\A[0-9a-f]{32}\z/), do: id
  end

  defp tab_id(_absent), do: nil

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
  # Inventory events
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
  # is availability of `fleet.deployment.cancel` and nothing else: a local setup on a
  # machine with no CA key still has to be stoppable.
  def handle_event("deploy", %{"address" => address}, socket) do
    with :ok <- allowed?(socket, :add),
         {:ok, device} <- deployable(socket, address) do
      {:noreply, open_drawer(socket, device, "add")}
    else
      {:refused, sentence} -> {:noreply, refuse(socket, sentence)}
    end
  end

  def handle_event("deploy-manual", _params, socket) do
    case allowed?(socket, :add) do
      :ok -> {:noreply, open_drawer(socket, nil, "add")}
      {:refused, sentence} -> {:noreply, refuse(socket, sentence)}
    end
  end

  # "Set up this device": the first local fleet. No SSH, no account and no credential — this
  # machine configures itself, which is what the proposal's sixth observed state asks for.
  #
  # And *this* device: the event carries an address, so it is held to the row whose state is
  # `this_device_without_profile`. Aimed at a peer it would ask the worker to set that peer
  # up locally — a local setup bound to somebody else's address.
  def handle_event("setup-device", params, socket) do
    with :ok <- allowed?(socket, :setup),
         {:ok, device} <- local_target(socket, params["address"]) do
      {:noreply, open_drawer(socket, device, "setup")}
    else
      {:refused, sentence} -> {:noreply, refuse(socket, sentence)}
    end
  end

  def handle_event("drawer-close", _params, socket) do
    {:noreply,
     socket
     |> close_drawer()
     |> push_patch(to: "/devices", replace: true)}
  end

  def handle_event("connect-change", params, socket) do
    {:noreply, update_drawer(socket, &%{&1 | form: form(params, &1.form)})}
  end

  def handle_event("connect", params, %{assigns: %{drawer: %{operation: nil}}} = socket) do
    guarded(socket, fn ->
      socket =
        update_drawer(socket, &%{&1 | form: form(params, &1.form), error: nil, busy: :prepare})

      with :ok <- allowed?(socket, drawer_gate(socket)),
           :ok <- local_setup_target(socket) do
        start_inspection(socket)
      else
        {:refused, sentence} -> {:noreply, drawer_refused(socket, sentence)}
      end
    end)
  end

  # A second submission of a form whose operation already exists is not a second deployment.
  def handle_event("connect", _params, socket), do: {:noreply, socket}

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
          operate(socket, @authenticate, %{
            "operation_id" => operation,
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
         |> answered(result, "The credential was sent to the deployment worker.")}
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
          operate(socket, @confirm_host, %{
            "operation_id" => operation,
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

  def handle_event("approve", %{"digest" => digest}, socket) when is_binary(digest) do
    guarded(socket, fn ->
      drawer = socket.assigns.drawer

      with :ok <- secret_bind_ok?(socket),
           :ok <- allowed?(socket, drawer_gate(socket)),
           :ok <- approvable(socket, digest) do
        result =
          operate(socket, @start, %{
            "operation_id" => drawer.operation,
            "plan_digest" => digest,
            "idempotency_key" => drawer.approval_key
          })

        {:noreply,
         socket
         |> update_drawer(&%{&1 | approved: digest})
         |> reload()
         |> answered(result, "The plan was approved.")}
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
        case operate(socket, @cancel, %{"operation_id" => op}) do
          {:ok, reply} when is_map(reply) ->
            # The worker answered, so this page knows how the operation ended even if nothing
            # else ever tells it: the broker releases the socket once a cancel has been
            # acknowledged, and a fake or an old worker may leave no journal to read afterwards.
            # What is recorded here is what was observed — the worker said it was stopping — and
            # not a state invented on its behalf.
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

  def handle_event("cancel-setup", _params, socket), do: {:noreply, socket}

  def handle_event("resume", %{"operation" => operation} = params, socket)
      when is_binary(operation) do
    with :ok <- operation_id(operation),
         :ok <- allowed?(socket, drawer_gate(socket)) do
      resume(socket, operation, params["takeover"] == "true")
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

  def handle_event("inspect-device", %{"address" => address}, socket) when is_binary(address) do
    case Enum.find(devices(socket), &(&1["address"] == address)) do
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
  # Worker events
  # ------------------------------------------------------------------------------------

  @impl true
  def handle_info({:ouroboros_fleet_deployment, operation, event}, socket) do
    if socket.assigns.drawer && socket.assigns.drawer.operation == operation do
      # Read, then speak. The client broadcasts `disconnected` from its own `terminate/2`,
      # and it terminates normally the moment a cancel has been answered or an operation has
      # finished — so a page that announced the disconnect first replaced "asked to stop at a
      # safe boundary" with "the result is unknown", about a stop the operator had just asked
      # for and been told had happened.
      #
      # Log lines arrive in bursts; coalescing those is what this is for. A challenge, a
      # state change or a done frame is the thing the drawer is waiting to draw, and it is
      # reloaded immediately rather than 150 ms later.
      socket = schedule_reload(socket, operation, event)

      cond do
        event["event"] != "disconnected" -> {:noreply, announce(socket, said(event))}
        lost?(socket.assigns.drawer) -> {:noreply, announce(socket, said(event))}
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
    # Read first, then decide what to say. A connection ending is not by itself bad news: the
    # broker releases the socket as soon as a cancel has been answered, and a finished
    # operation's worker exits too, so announcing "the result is unknown" on every `:DOWN`
    # overwrites the outcome an operator has just been given with a worry about it.
    socket = socket |> update_drawer(&%{&1 | monitor: nil}) |> reload()

    if lost?(socket.assigns.drawer) do
      {:noreply, announce(socket, said(%{"event" => "disconnected"}))}
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

  # One sentence per event kind, for the polite live region. A step is the one an operator
  # is actually following, so it is the one that names itself.
  defp said(%{"event" => "step"} = event) do
    {outcome, _tone} = Devices.outcome(event["outcome"])
    "#{Devices.step_label(event["step"])} on #{event["machine"] || "this fleet"}: #{outcome}."
  end

  defp said(%{"event" => "state"} = event), do: Devices.operation_state(event["state"]) <> "."

  defp said(%{"event" => "challenge"} = event),
    do: Devices.challenge_title(event["kind"]) <> "."

  # A `done` frame from the engine's failure path carries no state at all, only `ok`, a
  # reason and a detail — so this reads the state where there is one and says what happened
  # where there is not, rather than announcing "State not reported".
  defp said(%{"event" => "done"} = event) do
    case event["state"] do
      state when is_binary(state) -> Devices.operation_state(state) <> "."
      _absent -> if event["ok"] == true, do: "Finished.", else: "The deployment stopped."
    end
  end

  defp said(%{"event" => "disconnected"}) do
    "The connection to the deployment worker was lost. What it has done is unknown until " <>
      "the operation is read again; nothing was cancelled."
  end

  defp said(_other), do: ""

  defp start_inspection(socket) do
    case operate(socket, @prepare, prepare_params(socket.assigns.drawer)) do
      {:ok, %{"operation_id" => operation}} ->
        {:noreply,
         socket
         |> attach(operation, socket.assigns.drawer.device)
         |> push_patch(to: "/devices?operation=#{operation}", replace: true)}

      refused ->
        {:noreply, drawer_refusal(socket, refused)}
    end
  end

  defp resume(socket, operation, takeover?) do
    result =
      operate(socket, @resume, %{"operation_id" => operation, "takeover" => takeover?})

    socket =
      socket
      |> attach(operation, nil)
      |> push_patch(to: "/devices?operation=#{operation}", replace: true)

    case {result, reason(result)} do
      {{:ok, _reply}, _reason} ->
        said =
          if takeover?,
            do:
              "This setup was taken over. Every credential prompt from here on is bound to " <>
                "this session, and the takeover is in this runtime's log.",
            else: "A new deployment worker was started for this operation."

        {:noreply, socket |> update_drawer(&%{&1 | takeover: nil, rebind: nil}) |> announce(said)}

      # Never silently. The operation belongs to another identity, and continuing it means
      # inheriting their credential prompt — so this asks, out loud, with the consequence
      # written next to the button.
      {_refused, "operation_not_yours"} ->
        {:noreply,
         socket
         |> update_drawer(&%{&1 | takeover: operation, error: nil})
         |> announce("This setup was started by another identity.")}

      {refused, _reason} ->
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

  # The membership subset every reader gets, administrator or not. It is the fallback the
  # proposal names for a read endpoint and a non-administrator identity, and it is also the
  # answer on an older runtime that serves no inventory at all.
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
        socket
        |> assign(:inventory, inventory)
        |> assign(:inventory_error, nil)
        |> assign(:operations, operations(socket, inventory))

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
  defp operations(_socket, inventory) do
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
      operation: nil,
      status: nil,
      error: nil,
      residue: [],
      busy: nil,
      takeover: nil,
      rebind: nil,
      cancelled?: false,
      approved: nil,
      reloads: 0,
      monitor: nil,
      reload_pending?: false,
      advanced?: false,
      secret_nonce: 0,
      approval_key: nil,
      form: %{
        "address" => (device && device["address"]) || "",
        "machine" => (device && (device["machine"] || device["name"])) || "",
        "ssh_user" => "",
        "port" => "22",
        "identity_kind" => "",
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
      operation: nil,
      status: nil,
      error: nil,
      residue: [],
      busy: nil,
      takeover: nil,
      rebind: nil,
      cancelled?: false,
      approved: nil,
      reloads: 0,
      monitor: nil,
      reload_pending?: false,
      advanced?: false,
      secret_nonce: 0,
      approval_key: nil,
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
  # `prepare`, from a `resume`, from a row, or from the address bar after a reload.
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

    # `subscribe/1` is the broker's, not a gateway method: there is no wire verb for "tell
    # me when this changes", and polling a deployment would be a page refreshing itself
    # through a credential prompt. A subscription to an operation with no attached worker
    # simply is not one, which is a fact the journal-sourced snapshot below already states.
    _ = Deployment.subscribe(operation)
    demonitor(drawer.monitor)

    socket
    |> assign(:drawer, %{
      drawer
      | operation: operation,
        device: device || drawer.device,
        busy: nil,
        reloads: 0,
        monitor: monitor(operation),
        approval_key: drawer.approval_key || approval_key()
    })
    |> reload()
  end

  # A subscription is not enough to notice a worker's connection dying. The client process
  # broadcasts `disconnected` from `terminate/2`, and a process that is killed rather than
  # stopped never runs one — which is exactly the shape of a worker that crashed. A monitor
  # notices either way, and a disconnect that goes unnoticed is a page showing an operator
  # a live deployment that is not there.
  defp monitor(operation) do
    case Deployment.client(operation) do
      {:ok, pid} -> Process.monitor(pid)
      _absent -> nil
    end
  end

  # Caller-owned and stable for the life of this drawer: the same key against the same
  # operation replays the recorded answer instead of starting a second deployment, which is
  # the whole reason the method demands one.
  defp approval_key, do: "web-" <> Base.encode16(:crypto.strong_rand_bytes(12), case: :lower)

  defp reload(%{assigns: %{drawer: %{operation: operation}}} = socket)
       when is_binary(operation) do
    case operate(socket, @status, %{"operation_id" => operation}) do
      {:ok, status} when is_map(status) ->
        update_drawer(socket, fn drawer ->
          %{
            drawer
            | kind: status["kind"] || drawer.kind,
              status: status,
              error: nil,
              takeover: nil,
              reloads: 0
          }
        end)

      refused ->
        refused_status(socket, operation, refused)
    end
  end

  defp reload(socket), do: socket

  defp refused_status(socket, operation, refused) do
    case reason(refused) do
      # Not an error to read past. The operation belongs to another identity, and the only
      # way forward is a decision this operator makes explicitly, with its consequence
      # written next to the button.
      "operation_not_yours" ->
        update_drawer(socket, &%{&1 | takeover: operation, error: nil})

      # The worker has gone and this runtime has not finished noticing. The durable journal
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
    sentence = "The deployment could not complete that action."

    socket
    |> update_drawer(&%{&1 | error: sentence, busy: nil})
    |> announce(sentence)
  end

  # The broker's answer can lag the bind this socket is actually on. Secret-carrying
  # events read the running endpoint, not a forwarded header and not a stale inventory.
  defp secret_bind_ok?(socket) do
    case Config.for_endpoint(socket.endpoint) do
      %{bind: bind} ->
        if Ouroboros.Web.Config.loopback?(bind),
          do: :ok,
          else: {:refused, Devices.deploy_blocker("cleartext_web_bind", posture(socket))}

      _missing ->
        {:refused, Devices.deploy_blocker("cleartext_web_bind", posture(socket))}
    end
  rescue
    _exception -> {:refused, Devices.deploy_blocker("cleartext_web_bind", posture(socket))}
  catch
    _kind, _reason -> {:refused, Devices.deploy_blocker("cleartext_web_bind", posture(socket))}
  end

  # ------------------------------------------------------------------------------------
  # The gate
  # ------------------------------------------------------------------------------------

  @doc """
  Whether this endpoint may start or continue work of this kind, right now.

  The same two questions the render asks — the deployment host's own `capabilities`, and
  whether this scope and identity may run the verb — asked where an event cannot skip them.
  `:setup` drops `no_ca_key` for the reason `setup?/1` gives: the first local setup is what
  creates that key.
  """
  @spec allowed?(Phoenix.LiveView.Socket.t(), :add | :setup | :cancel) ::
          :ok | {:refused, String.t()}
  def allowed?(socket, :setup) do
    if setup?(socket), do: :ok, else: {:refused, setup_blocked(socket)}
  end

  def allowed?(socket, :cancel) do
    if Call.available?(socket.assigns.scope, @cancel),
      do: :ok,
      else: {:refused, unavailable(socket, @cancel)}
  end

  def allowed?(socket, _add) do
    if deploy?(socket), do: :ok, else: {:refused, deploy_blocked(socket)}
  end

  # Which gate the open drawer answers to. A setup drawer is a local operation on a machine
  # that may hold no CA key yet; everything else is an SSH deployment.
  defp drawer_gate(%{assigns: %{drawer: %{kind: "setup"}}}), do: :setup
  defp drawer_gate(_socket), do: :add

  # The row a `deploy` may be aimed at: one this listing says nothing has inspected. The
  # event carries an address, and an address is a string a client chose.
  defp deployable(socket, address) do
    case Enum.find(devices(socket), &(&1["address"] == address)) do
      device when is_map(device) ->
        if Devices.deployable?(device),
          do: {:ok, device},
          else: {:refused, "That device is not one this machine can deploy to."}

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
             "Set up this device configures the machine this runtime is on. That address " <>
               "is another device — deploy to it instead."}

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

  # The digest is the only thing approval says about the plan, so it is checked against the
  # plan on the screen rather than forwarded because a click carried it.
  defp approvable(socket, digest) do
    drawer = socket.assigns.drawer
    plan = Devices.metadata(challenge(drawer, ["review"]))["plan"]

    cond do
      # The same digest again. A repeated approval is the point of the idempotency key — the
      # broker replays the recorded answer rather than starting a second deployment — and
      # refusing it here because the review challenge has been consumed would turn a double
      # click into a refusal. This is a digest this page already vouched for.
      drawer.approved == digest ->
        :ok

      not Devices.digest?(digest) ->
        {:refused,
         "That is not a plan digest. Approval sends a sha256 — sixty-four lowercase hex " <>
           "characters — and this page will not send anything else."}

      is_nil(Devices.plan_digest(plan)) ->
        {:refused,
         "This page could not compute a digest for the plan it is showing, so it cannot " <>
           "check that the one it is about to send is that plan's. Cancel this setup and " <>
           "start it again."}

      Devices.plan_digest(plan) != digest ->
        {:refused,
         "The digest this operation offered is not this page's own sha256 of the plan it " <>
           "showed you. Nothing was approved. Cancel this setup and start it again."}

      true ->
        :ok
    end
  end

  # An operation id reaches `push_patch/2`, which builds a URL out of it — and
  # `Phoenix.LiveView` raises on one it cannot put in an address, which takes the whole view
  # down. The journal's own validator is the right shape to hold it to: hex, because the id
  # also names a file and a Unix socket.
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
    update_drawer(socket, &%{&1 | error: refusal_words(socket, refused), busy: nil})
  end

  # The broker enforces the deployment host's blockers on its own side, and names them. When
  # it does, the page says the same sentence it would have said itself rather than the
  # generic "the runtime refused this": one blocker, one wording, whichever side caught it.
  defp refusal_words(socket, refused) do
    case {reason(refused), blocker_of(refused)} do
      {"deploy_blocked", blocker} when is_binary(blocker) ->
        Devices.deploy_blocker(blocker, posture(socket))

      _other ->
        Presentation.refusal(refused)
    end
  end

  defp blocker_of({:error, _code, _message, %{"blockers" => [first | _rest]}}), do: first
  defp blocker_of(_other), do: nil

  defp answered(socket, {:ok, _reply}, said) do
    socket |> update_drawer(&%{&1 | rebind: nil}) |> announce(said)
  end

  defp answered(socket, refused, _said) do
    message = refusal_words(socket, refused)

    socket
    |> update_drawer(&%{&1 | error: message, busy: nil, rebind: rebind(socket, refused)})
    |> announce(message)
  end

  # `challenge_not_bound` used to be a dead end: the prompt stayed on screen and the only
  # button under it was the one that had just been refused. With the binding per tab
  # (`tab_session/1`) a refresh or a reconnect in this tab keeps answering, so what is left
  # is the case the binding exists for — the prompt belongs to a *different* tab — and this
  # offers the one move that is actually available rather than nothing.
  defp rebind(socket, refused) do
    if reason(refused) == "challenge_not_bound", do: socket.assigns.drawer.operation
  end

  defp announce(socket, ""), do: socket
  defp announce(socket, nil), do: socket

  # A live region announces a *change*. Two identical sentences in a row — two steps with the
  # same name on two machines, a credential refused twice — are one change to the DOM and
  # therefore silence, which is exactly the repetition an operator most needs to hear. The
  # counter changes the text node without changing what it says.
  defp announce(socket, said) do
    count = socket.assigns[:announced] || 0
    socket |> assign(:announced, count + 1) |> assign(:announcement, said)
  end

  defp form(params, previous) when is_map(params) do
    Map.merge(previous, Map.take(params, Map.keys(previous)))
  end

  # Only what the method's parameters allow, and no secret among them: an identity is named
  # by reference, and a password is answered to its own challenge rather than submitted here.
  #
  # Two shapes, because the verb has two. `setup` configures *this* machine and therefore
  # takes no target and no account at all — sending one would be this page asking the worker
  # to SSH to itself.
  defp prepare_params(%{kind: "setup"} = drawer) do
    form = drawer.form

    %{"kind" => "setup", "service" => form["service"] == "true"}
    |> put_present("machine", trimmed(form["machine"]))
    |> put_present("address", trimmed(form["address"]))
  end

  defp prepare_params(drawer) do
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

  # `ref` only where the method requires one — an agent identity's public fingerprint, or a
  # key's path on the deployment host. Never key material, on either.
  defp identity(form) do
    case trimmed(form["identity_kind"]) do
      nil -> nil
      kind when kind in ["default", "password"] -> %{"kind" => kind}
      kind -> %{"kind" => kind, "ref" => trimmed(form["identity_ref"])}
    end
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

  # Two spellings of one call, and the difference is which session id travels with it.
  #
  # `read/3` is the ordinary page read, attributed to the browser session the cookie names,
  # so a log line still correlates one browser across requests. `operate/3` is every
  # `fleet.deployment.*` call, and it carries this *view's* id, because that is what a
  # credential challenge binds to.
  defp read(socket, method, params \\ %{}),
    do: Call.call(socket.assigns.scope, method, params, session: socket.assigns[:web_session])

  defp operate(socket, method, params),
    do:
      Call.call(socket.assigns.scope, method, params,
        session: socket.assigns[:web_session],
        client_session: socket.assigns.view_session
      )

  # The `data.reason` a refusal carried, where it carried one. The reason codes are the
  # gateway's stable vocabulary and this page branches on exactly one of them.
  defp reason({:error, _code, _message, data}) when is_map(data), do: data["reason"]
  defp reason(_other), do: nil

  @doc """
  Why a method is not available here, distinguished rather than collapsed.

  `Ouroboros.Web.Call.available?/2` answers the yes/no this page gates on, and it answers it
  with one boolean for three different facts. The proposal requires the three to stay apart:
  a build that does not serve the method at all, an endpoint whose scope may not run it, and
  an identity that is not an administrator are three different things for an operator to do
  something about. This asks the same two sources `available?/2` asks, in order, and names
  which one said no.
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

  # Deploy is offered when the deployment host says it can deploy *and* this endpoint can
  # run the verb that starts one. Two different questions, and a page that asked only the
  # first would draw a button a read-scope browser cannot press.
  defp deploy?(socket) do
    host = host(socket)

    is_map(host) and get_in(host, ["capabilities", "deploy"]) == true and
      Call.available?(socket.assigns.scope, @prepare)
  end

  defp cancel?(socket), do: Call.available?(socket.assigns.scope, @cancel)

  defp deploy_blocked(socket) do
    case blockers(socket) do
      [] -> unavailable(socket, @prepare)
      [first | _rest] -> Devices.deploy_blocker(first, posture(socket))
    end
  end

  # Whether this machine is in a fleet at all. `no_ca_key` means two different things either
  # side of that line — a joiner that should go to the issuer, and a machine nobody has set
  # up — and only one of them has a machine to send an operator to.
  #
  # Read from the inventory's own rows rather than from `fleet.status`: the row for this
  # machine is `this_device_without_profile` exactly when it has no fleet profile, which is
  # the fact `ouro` used to decide the row. A second source could disagree with the button
  # the page is drawing.
  defp posture(socket) do
    if Enum.any?(devices(socket), &(&1["state"] == "this_device_without_profile")),
      do: :standalone,
      else: :fleet
  end

  defp blockers(socket) do
    case host(socket) do
      host when is_map(host) -> List.wrap(get_in(host, ["capabilities", "reasons"]))
      _absent -> []
    end
  end

  @doc """
  Whether **this** machine can be set up locally, which is a different question from Deploy.

  `capabilities.deploy` is false without a fleet certificate authority key, and a machine
  with no fleet is exactly the machine "Set up this device" exists for: the first local
  setup is what *creates* that key. So this asks the same question with that one reason
  taken out, and every other blocker — no durable directory, no `ouro`, a cleartext bind —
  still stands, because each of those is a reason this runtime cannot run the operation at
  all rather than a reason it is not an issuer yet.
  """
  @spec setup?(map()) :: boolean()
  def setup?(socket) do
    Call.available?(socket.assigns.scope, @prepare) and
      Enum.all?(blockers(socket), &(&1 == "no_ca_key"))
  end

  defp setup_blocked(socket) do
    case Enum.reject(blockers(socket), &(&1 == "no_ca_key")) do
      [] -> unavailable(socket, @prepare)
      [first | _rest] -> Devices.deploy_blocker(first, posture(socket))
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
    assigns =
      assigns
      |> assign(:host, host(assigns_socket(assigns)))
      |> assign(:deploy?, deploy?(assigns_socket(assigns)))
      |> assign(:deploy_blocked, deploy_blocked(assigns_socket(assigns)))
      |> assign(:setup?, setup?(assigns_socket(assigns)))
      |> assign(:setup_blocked, setup_blocked(assigns_socket(assigns)))
      |> assign(:cancel?, cancel?(assigns_socket(assigns)))
      |> assign(:rows, rows(assigns))
      |> then(fn assigns ->
        unfinished = unfinished(assigns)

        assigns
        |> assign(:unfinished, unfinished)
        |> assign(:waiting, Enum.filter(unfinished, &Devices.waiting?(&1["state"])))
        |> assign(:stopped, Enum.reject(unfinished, &Devices.waiting?(&1["state"])))
      end)

    ~H"""
    <div>
      <Layouts.topbar current={:devices} />

      <main class="ouro-page">
        <header class="ouro-header">
          <p class="ouro-subhead"><a href="/">Sessions</a> · Devices</p>
          <h1>Devices</h1>
          <p>
            The machines this fleet knows about, and the ones the deployment host can see on
            its private network.
          </p>
        </header>

        <.deployment_host host={@host} availability={@availability} />

        <p :if={@inventory == :loading} class="ouro-devices-empty" role="status">
          Loading devices…
        </p>

        <section :if={@availability not in [:available, :loading]} class="ouro-panel">
          <div class="ouro-panel-head">
            <h2>Deployment is not available here</h2>
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

        <.operations
          :if={@availability == :available and @unfinished != []}
          waiting={@waiting}
          stopped={@stopped}
        />

        <section :if={is_map(@inventory)} class="ouro-panel">
          <div class="ouro-panel-head">
            <h2>Devices</h2>
            <button type="button" class="ouro-button" phx-click="refresh">Refresh</button>
          </div>

          <form
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
                  {value, label} <- [{"all", "All"}, {"fleet", "Fleet"}, {"available", "Available"}]
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

          <.section_rows
            :if={@filter in ["all", "fleet"]}
            id="fleet-devices"
            title="Fleet devices"
            rows={@rows.fleet}
            empty="This machine's roster names no members yet."
            deploy?={@deploy?}
            blocked={@deploy_blocked}
            setup?={@setup?}
            setup_blocked={@setup_blocked}
            operations={@operations}
          />

          <.discovery discovery={@inventory["discovery"]} />

          <.section_rows
            :if={@filter in ["all", "available"]}
            id="available-devices"
            title="Available on this network"
            rows={@rows.available}
            empty="No other device is visible to this machine's network client."
            deploy?={@deploy?}
            blocked={@deploy_blocked}
            setup?={@setup?}
            setup_blocked={@setup_blocked}
            operations={@operations}
          />

          <p :if={not @deploy?} class="ouro-devices-blocked">{@deploy_blocked}</p>

          <p class="ouro-devices-manual">
            A device that is not listed can be named directly.
            <button
              type="button"
              class={["ouro-quiet-button", not @deploy? && "ouro-devices-unavailable"]}
              disabled={not @deploy?}
              aria-disabled={to_string(not @deploy?)}
              title={not @deploy? && @deploy_blocked}
              phx-click={@deploy? && "deploy-manual"}
            >
              Deploy to an address
            </button>
          </p>

          <.legend />
        </section>

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

  # `render/1` receives assigns rather than the socket, and two of the helpers above read
  # the socket. This rebuilds the shape they read, which is the whole of what they use.
  defp assigns_socket(assigns) do
    %{
      assigns: %{
        inventory: assigns[:inventory],
        scope: assigns[:scope],
        availability: assigns[:availability]
      }
    }
  end

  defp unfinished(assigns) do
    Enum.filter(assigns[:operations] || [], &Devices.unfinished?(&1["state"]))
  end

  defp rows(assigns) do
    devices =
      case assigns[:inventory] do
        %{"devices" => devices} when is_list(devices) -> devices
        _absent -> []
      end
      |> Enum.filter(&Devices.matches?(&1, assigns[:query] || ""))

    %{
      fleet: Enum.filter(devices, &Devices.fleet_row?/1),
      available: Enum.reject(devices, &Devices.fleet_row?/1)
    }
  end

  # ------------------------------------------------------------------------------------
  # Components
  # ------------------------------------------------------------------------------------

  attr :host, :map, required: true
  attr :availability, :atom, required: true

  defp deployment_host(assigns) do
    ~H"""
    <p :if={@host} class="ouro-devices-host" data-ouro-deployment-host>
      <strong>
        Deploying from {Devices.plain(@host["hostname"], 96) || Devices.this_device()} · local user {Devices.plain(
          @host["user"],
          64
        ) ||
          "not reported"}
      </strong>
      <span>
        Discovery, SSH and certificate issuance run on that machine — the one hosting this
        runtime — and not on the computer showing this page. Its keys, its agent and its
        network client are the ones that apply.
      </span>
      <span :if={@host["os"]} class="ouro-mono">
        {@host["os"]} · {@host["arch"]} · {if @host["issuer"],
          do: "holds this fleet's certificate authority key",
          else: "does not hold a certificate authority key"}
      </span>
    </p>
    """
  end

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

  defp discovery(assigns) do
    code = assigns.discovery && assigns.discovery["code"]
    {headline, guidance} = Devices.discovery(code)

    assigns =
      assigns
      |> assign(:code, code)
      |> assign(:headline, headline)
      |> assign(:guidance, guidance)

    ~H"""
    <p
      :if={not Devices.discovered?(@code) or @code == "no_visible_peers"}
      class="ouro-devices-discovery"
      data-discovery={@code}
      role="status"
    >
      <strong>{@headline}</strong>
      <span :if={@guidance != ""}>{@guidance}</span>
      <span :if={@discovery && @discovery["detail"]} class="ouro-devices-detail">
        {Devices.plain(@discovery["detail"])}
      </span>
    </p>
    """
  end

  attr :id, :string, required: true
  attr :title, :string, required: true
  attr :rows, :list, required: true
  attr :empty, :string, required: true
  attr :deploy?, :boolean, required: true
  attr :blocked, :string, required: true
  attr :setup?, :boolean, required: true
  attr :setup_blocked, :string, required: true
  attr :operations, :list, required: true

  defp section_rows(assigns) do
    ~H"""
    <section class="ouro-devices-section" aria-labelledby={@id <> "-title"}>
      <h3 id={@id <> "-title"} class="ouro-devices-section-title">{@title}</h3>

      <p :if={@rows == []} class="ouro-devices-empty">{@empty}</p>

      <ul :if={@rows != []} id={@id} class="ouro-devices-list">
        <li
          :for={device <- @rows}
          class="ouro-devices-row"
          data-state={device["state"]}
          data-operation-state={latest_operation(@operations, device)["state"]}
          data-address={device["address"]}
        >
          <span class="ouro-devices-name">{Devices.plain(device["name"], 96) || Devices.this_device()}</span>
          <span class="ouro-devices-facts ouro-mono">
            <span>{Devices.plain(device["os"], 48) || "operating system not reported"}</span>
            <span>·</span>
            <span>{Devices.plain(device["address"], 64) || "no private address reported"}</span>
          </span>
          <span class="ouro-devices-presence">
            <span class="ouro-visually-hidden">Network presence:</span>
            {Devices.presence(device)}
          </span>
          <span class="ouro-devices-state">
            <span class="ouro-visually-hidden">Ouroboros state:</span>
            {row_state(@operations, device)}
          </span>

          <span class="ouro-devices-action">
            <button
              :for={{_words, label, event} <- [row_action(@operations, device)]}
              :if={operation_for(@operations, device)}
              type="button"
              class="ouro-button"
              phx-click={event}
              phx-value-operation={operation_for(@operations, device)}
              phx-value-address={device["address"]}
            >
              {label}
            </button>
            <%!-- An action a blocker stands in front of is drawn as unavailable rather than
                  as a button that refuses when pressed. The control keeps its name — an
                  operator needs to know what is not available, not to find a gap where it
                  used to be — and carries the reason as its own description rather than only
                  as a paragraph somewhere under the row. --%>
            <button
              :if={is_nil(operation_for(@operations, device)) and Devices.deployable?(device)}
              type="button"
              class={["ouro-button", not @deploy? && "ouro-devices-unavailable"]}
              disabled={not @deploy?}
              aria-disabled={to_string(not @deploy?)}
              title={not @deploy? && @blocked}
              aria-describedby={not @deploy? && "#{@id}-blocked-#{device["address"]}"}
              phx-click={@deploy? && "deploy"}
              phx-value-address={device["address"]}
            >
              Deploy Ouroboros
            </button>
            <button
              :if={is_nil(operation_for(@operations, device)) and Devices.setup?(device)}
              type="button"
              class={["ouro-button", not @setup? && "ouro-devices-unavailable"]}
              disabled={not @setup?}
              aria-disabled={to_string(not @setup?)}
              title={not @setup? && @setup_blocked}
              aria-describedby={not @setup? && "#{@id}-blocked-#{device["address"]}"}
              phx-click={@setup? && "setup-device"}
              phx-value-address={device["address"]}
            >
              Set up this device
            </button>
            <button
              :if={is_nil(operation_for(@operations, device)) and Devices.inspectable?(device)}
              type="button"
              class="ouro-button"
              phx-click="inspect-device"
              phx-value-address={device["address"]}
            >
              {Devices.state_action(device["state"])}
            </button>
            <span
              :if={
                is_nil(operation_for(@operations, device)) and not Devices.deployable?(device) and
                  not Devices.setup?(device) and not Devices.inspectable?(device)
              }
              class="ouro-devices-quiet"
            >
              {Devices.state_action(device["state"])}
            </span>
          </span>

          <span
            :if={
              is_nil(operation_for(@operations, device)) and Devices.deployable?(device) and
                not @deploy?
            }
            id={"#{@id}-blocked-#{device["address"]}"}
            class="ouro-devices-blocked"
          >
            {@blocked}
          </span>

          <span
            :if={
              is_nil(operation_for(@operations, device)) and Devices.setup?(device) and
                not @setup?
            }
            id={"#{@id}-blocked-#{device["address"]}"}
            class="ouro-devices-blocked"
          >
            {@setup_blocked}
          </span>

          <span :if={Devices.blocked?(device)} class="ouro-devices-blocked">
            Deployment is disabled for this device while that blocker stands. Refresh after
            the device comes back, or read its details.
          </span>

          <span :if={Devices.name_conflict(device)} class="ouro-devices-note" role="note">
            {Devices.name_conflict(device)}
          </span>
        </li>
      </ul>
    </section>
    """
  end

  # A row's operation is the unfinished operation whose recorded target names this device —
  # by the address it was aimed at, or by the roster name it was to be called. An operation
  # whose journal records neither leaves every row alone rather than being drawn on all of
  # them; it is still listed on its own, above the inventory.
  defp operation_for(operations, device) do
    Enum.find_value(operations, fn operation ->
      if same_device?(operation["target"], device), do: operation["operation"]
    end)
  end

  # Address, or roster identity. Never the peer's own `name`: that field is what a *device*
  # calls itself, and a device that calls itself by a roster machine's name would otherwise
  # inherit that machine's operation — its row, its state, and a Continue setup button
  # pointing at somebody else's deployment. `machine` is set by this machine's roster, which
  # is the identity a peer cannot choose.
  defp same_device?(target, device) when is_map(target) and is_map(device) do
    matches?(target["address"], device["address"]) or
      matches?(target["machine"], device["machine"])
  end

  defp same_device?(_target, _device), do: false

  # The row's own operation, where it has one — the list is the journal's, newest first.
  defp latest_operation(operations, device) do
    Enum.find(operations, %{}, &same_device?(&1["target"], device))
  end

  # What the row says about Ouroboros. An operation this machine holds for the device is the
  # fresher fact and wins; otherwise it is the inventory's discovery state, in the
  # proposal's words.
  defp row_state(operations, device) do
    case latest_operation(operations, device) do
      empty when empty == %{} ->
        Devices.state_words(device["state"])

      operation ->
        {words, _label, _event} = Devices.operation_row(operation["state"], operation["kind"])
        words
    end
  end

  defp row_action(operations, device) do
    case latest_operation(operations, device) do
      empty when empty == %{} -> {nil, Devices.state_action(device["state"]), "deploy"}
      operation -> Devices.operation_row(operation["state"], operation["kind"])
    end
  end

  defp matches?(left, right) when is_binary(left) and is_binary(right) and left != "",
    do: left == right

  defp matches?(_left, _right), do: false

  attr :waiting, :list, required: true
  attr :stopped, :list, required: true

  # Two different things, and this panel used to draw them as one list of every journal the
  # data directory has ever held. A deployment waiting for a credential is a thing to do
  # *now*; one that failed in March is a thing to clean up, and two hundred of them push the
  # inventory off the screen. So: what is waiting first, short by construction, and
  # everything stopped behind a disclosure with a cap.
  defp operations(assigns) do
    assigns =
      assigns
      |> assign(:shown, Enum.take(assigns.stopped, @max_stopped))
      |> assign(:hidden, max(length(assigns.stopped) - @max_stopped, 0))

    ~H"""
    <section class="ouro-panel" aria-labelledby="devices-operations-title">
      <div class="ouro-panel-head">
        <h2 id="devices-operations-title">Setups in progress</h2>
      </div>
      <p>
        This machine is holding these deployments. Closing the page did not cancel them.
      </p>

      <h3 :if={@waiting != []} class="ouro-devices-section-title">Waiting for you</h3>
      <ul :if={@waiting != []} class="ouro-devices-list">
        <.operation_row :for={operation <- @waiting} operation={operation} />
      </ul>

      <details :if={@shown != []} class="ouro-devices-advanced" open={@waiting == []}>
        <summary>Stopped or interrupted ({length(@stopped)})</summary>
        <ul class="ouro-devices-list">
          <.operation_row :for={operation <- @shown} operation={operation} />
        </ul>
        <p :if={@hidden > 0} class="ouro-devices-quiet">
          {@hidden} more are recorded on this machine and are not drawn here. They are in
          this data directory's deployment journals.
        </p>
      </details>
    </section>
    """
  end

  attr :operation, :map, required: true

  defp operation_row(assigns) do
    ~H"""
    <li
      class="ouro-devices-row"
      data-operation={@operation["operation"]}
      data-state={@operation["state"]}
    >
      <span class="ouro-devices-name ouro-mono">{@operation["operation"]}</span>
      <span class="ouro-devices-state">
        <span class="ouro-visually-hidden">Deployment state:</span>
        {Devices.operation_state(@operation["state"])}
      </span>
      <span class="ouro-devices-presence">
        {if @operation["attached"],
          do: "a worker is attached",
          else: "no worker is attached; this is what the journal recorded"}
      </span>
      <span class="ouro-devices-action">
        <button
          type="button"
          class="ouro-button"
          phx-click="open-operation"
          phx-value-operation={@operation["operation"]}
        >
          Continue setup
        </button>
      </span>
    </li>
    """
  end

  defp legend(assigns) do
    assigns = assign(assigns, :states, Devices.observed_states())

    ~H"""
    <details class="ouro-devices-legend">
      <summary>What each state means</summary>
      <table>
        <thead>
          <tr>
            <th scope="col">Observed state</th>
            <th scope="col">Primary action</th>
          </tr>
        </thead>
        <tbody>
          <tr :for={{observed, action} <- @states}>
            <td>{observed}</td>
            <td>{action}</td>
          </tr>
        </tbody>
      </table>
    </details>
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
    assigns = assign(assigns, :step, step(assigns.drawer))

    ~H"""
    <dialog
      id="ouro-deploy"
      class="ouro-session-dialog ouro-devices-drawer"
      aria-modal="true"
      aria-labelledby="ouro-deploy-title"
      phx-hook="Modal"
      data-cancel-event="drawer-close"
      data-step={@step}
    >
      <div class="ouro-session-dialog-form">
        <h2 id="ouro-deploy-title">{drawer_title(@drawer)}</h2>

        <p class="ouro-devices-host" data-ouro-deployment-host>
          <strong>
            Deploying from {Devices.plain(@host && @host["hostname"], 96) || Devices.this_device()} · local user {Devices.plain(
              @host && @host["user"],
              64
            ) ||
              "not reported"}
          </strong>
        </p>

        <p :if={@drawer.device} class="ouro-devices-target">
          To <strong>{Devices.plain(@drawer.device["name"], 96)}</strong>
          <span class="ouro-mono">{Devices.plain(@drawer.device["address"], 64)}</span>
        </p>

        <%!-- The operation id, wherever the drawer is. It is what a row, a log line, this
              page's own address and the runtime's journal all name the same deployment by,
              so an operator reading any of them can tell they are the same one. --%>
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
          <span>{@announcement}</span>
          <span class="ouro-visually-hidden">{@announced}</span>
        </p>

        <p :if={@drawer.error} id="ouro-deploy-error" class="ouro-refusal" role="alert">
          {@drawer.error}
        </p>

        <.takeover :if={taken_over?(@drawer)} drawer={@drawer} />
        <.rebind :if={@drawer.rebind && @drawer.rebind == @drawer.operation} drawer={@drawer} />

        <.inspect_step :if={@step == :inspect} drawer={@drawer} operations={@operations} />
        <.setup_step :if={@step == :select and @drawer.kind == "setup"} drawer={@drawer} />
        <.connect_step :if={@step == :select and @drawer.kind != "setup"} drawer={@drawer} />
        <.host_trust_step :if={@step == :host_trust} drawer={@drawer} />
        <.authenticate_step :if={@step == :authenticate} drawer={@drawer} />
        <.review_step :if={@step == :review} drawer={@drawer} />
        <.progress_step :if={@step in [:progress, :connecting]} drawer={@drawer} />
        <.finish_step :if={@step == :finish} drawer={@drawer} />

        <.steps :if={@step not in [:select, :inspect]} drawer={@drawer} />

        <div class="ouro-devices-drawer-foot">
          <button type="button" class="ouro-quiet-button" phx-click="drawer-close">
            Close
          </button>
          <span class="ouro-devices-quiet">
            Closing this does not cancel anything. The operation keeps its row.
          </span>
          <button
            :if={
              not is_nil(@drawer.operation) and @can_operate? and
                Devices.unfinished?(state_of(@drawer))
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

  attr :drawer, :map, required: true

  # What a refused answer leaves an operator: a way forward, or a sentence saying where the
  # way forward is. Not the same button again.
  defp rebind(assigns) do
    ~H"""
    <div
      class="ouro-devices-takeover"
      role="group"
      aria-labelledby="ouro-deploy-rebind-title"
      data-ouro-rebind
    >
      <h3 id="ouro-deploy-rebind-title">This prompt belongs to another tab</h3>
      <p id="ouro-deploy-rebind-hint">
        A credential prompt is answered by the tab it was issued to, so that a second tab
        cannot answer the first one's. Answer it in the tab that started this setup, or
        reconnect it here — which starts a fresh worker for this operation and asks again. A
        setup another tab is still holding cannot be reconnected until that tab lets go.
      </p>
      <button
        type="button"
        class="ouro-button"
        phx-click="resume"
        phx-value-operation={@drawer.operation}
        aria-describedby="ouro-deploy-rebind-hint"
      >
        Reconnect this setup to this tab
      </button>
    </div>
    """
  end

  attr :drawer, :map, required: true

  # Never silent, and never a button that simply works: an operation another identity
  # started is another identity's credential prompt, and continuing it means inheriting it.
  defp takeover(assigns) do
    ~H"""
    <div
      class="ouro-devices-takeover"
      role="group"
      aria-labelledby="ouro-deploy-takeover-title"
      data-ouro-takeover
    >
      <h3 id="ouro-deploy-takeover-title">This setup was started by another identity</h3>
      <p id="ouro-deploy-takeover-hint">
        Continuing it attaches a new worker under <em>your</em> identity, so every credential
        prompt from here on is asked of you rather than of whoever started it. The takeover is
        recorded in this runtime's log, naming who took what from whom.
      </p>
      <button
        type="button"
        class="ouro-button"
        phx-click="resume"
        phx-value-operation={@drawer.operation}
        phx-value-takeover="true"
        aria-describedby="ouro-deploy-takeover-hint"
      >
        Take over this setup
      </button>
    </div>
    """
  end

  defp residue_line(entry) when is_map(entry),
    do: Devices.plain(entry["detail"] || entry["name"] || entry)

  defp residue_line(entry) when is_binary(entry), do: Devices.plain(entry)
  defp residue_line(entry), do: Devices.plain(entry)

  # Which step the drawer is on. Challenges first, because an open challenge is the runtime
  # waiting for this operator and outranks whatever the last state event said.
  defp step(%{kind: "inspect"}), do: :inspect
  defp step(%{operation: nil}), do: :select
  defp step(%{status: nil}), do: :connecting

  defp step(drawer) do
    cond do
      challenge(drawer, ["host_trust"]) -> :host_trust
      challenge(drawer, ["password", "passphrase"]) -> :authenticate
      challenge(drawer, ["review"]) -> :review
      state_of(drawer) in ["completed", "failed", "cancelled", "interrupted"] -> :finish
      is_map(done_of(drawer)) -> :finish
      drawer.cancelled? -> :finish
      true -> :progress
    end
  end

  defp challenge(drawer, kinds) do
    drawer.status
    |> Kernel.||(%{})
    |> Map.get("challenges", [])
    |> List.wrap()
    |> Enum.find(&(&1["kind"] in kinds))
  end

  defp state_of(drawer), do: (drawer.status || %{})["state"]

  defp done_of(drawer), do: (drawer.status || %{})["done"]

  # Whether a worker going away leaves a question. A terminal state, a `done` frame, or a
  # cancel this page asked for and the worker acknowledged is an answer; anything else with
  # no worker behind it is not.
  defp lost?(drawer) when is_map(drawer) do
    Devices.unfinished?(state_of(drawer)) and is_nil(done_of(drawer)) and not drawer.cancelled?
  end

  defp lost?(_absent), do: false

  # Whether *this* operation is one another identity owns. Both fields are nil on a drawer
  # that has not prepared anything yet, and comparing them directly made `nil == nil` true —
  # which drew "this setup was started by another identity" over a device nobody had
  # touched. A takeover is a fact about an existing operation or it is not a fact.
  defp taken_over?(%{takeover: operation, operation: operation}) when is_binary(operation),
    do: true

  defp taken_over?(_drawer), do: false

  defp drawer_title(%{kind: "inspect"} = drawer),
    do: Devices.state_action(drawer.device && drawer.device["state"])

  defp drawer_title(%{kind: "setup"}), do: "Set up this device"
  defp drawer_title(_other), do: "Deploy Ouroboros"

  attr :drawer, :map, required: true
  attr :operations, :list, default: []

  defp inspect_step(assigns) do
    device = assigns.drawer.device || %{}
    operation = latest_operation(assigns.operations, device)

    assigns =
      assigns
      |> assign(:device, device)
      |> assign(:operation, operation)

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-inspect-title">
      <h3 id="ouro-deploy-inspect-title">{drawer_title(@drawer)}</h3>

      <dl class="ouro-facts">
        <div class="ouro-fact">
          <dt>Roster name</dt>
          <dd>{Devices.plain(@device["machine"], 96) || "not on this fleet's roster"}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Network name</dt>
          <dd>{Devices.plain(@device["name"], 96) || "not reported"}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Addresses</dt>
          <dd class="ouro-mono">
            {Devices.plain(@device["address"], 64) || "no private address reported"}
          </dd>
        </div>
        <div class="ouro-fact">
          <dt>Connected to this runtime</dt>
          <dd>{inspect_flag(@device["connected"])}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Compatible</dt>
          <dd>{inspect_flag(@device["compatible"])}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Runtime running</dt>
          <dd>{inspect_flag(@device["runtime_running"])}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Last probe</dt>
          <dd>{Devices.plain(@device["last_probe"], 64) || "not reported"}</dd>
        </div>
      </dl>

      <p :if={Devices.blocked?(@device)} class="ouro-devices-blocked">
        {Devices.state_words(@device["state"])}. Deployment is disabled while that blocker
        stands. Refresh after the device comes back.
      </p>

      <div :if={@operation != %{}} class="ouro-devices-note">
        <p>
          Latest operation <span class="ouro-mono">{Devices.plain(@operation["operation"], 32)}</span>
          — {Devices.operation_state(@operation["state"])}
          {if @operation["attached"], do: "(a worker is attached)", else: "(journal only)"}
        </p>
      </div>

      <div class="ouro-devices-actions">
        <button type="button" class="ouro-button" phx-click="refresh">Refresh</button>
      </div>
    </section>
    """
  end

  defp inspect_flag(true), do: "yes"
  defp inspect_flag(false), do: "no"
  defp inspect_flag(_unknown), do: "not reported"

  attr :drawer, :map, required: true

  # "Set up this device": no target, no account, no credential. The one fact this form asks
  # for that the host cannot supply on its own is the private address its runtime will bind,
  # and the worker refuses rather than guessing when nobody gives it one.
  defp setup_step(assigns) do
    ~H"""
    <form id="ouro-deploy-setup" phx-change="connect-change" phx-submit="connect">
      <p>
        This machine configures itself. No SSH connection is made to it, no account is asked
        for, and no credential is entered: the first fleet on a machine is a local operation.
      </p>

      <section class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="setup-machine">Name for this machine</label>
          <span class="ouro-new-aside">Optional</span>
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
          What this device is called in its own fleet, and in every other member's roster.
          This host's own name when left empty.
        </p>
      </section>

      <section class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="setup-address">Private address to bind</label>
        </div>
        <input
          id="setup-address"
          class="ouro-new-input ouro-mono"
          type="text"
          name="address"
          value={@drawer.form["address"]}
          aria-describedby="setup-address-hint"
          autocomplete="off"
        />
        <p id="setup-address-hint" class="ouro-new-hint">
          The overlay address this runtime will bind. Left empty, the setup stops and says so
          rather than guessing at one.
        </p>
      </section>

      <section class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="setup-service">Install a startup service</label>
        </div>
        <input type="hidden" name="service" value="false" />
        <input
          id="setup-service"
          type="checkbox"
          name="service"
          value="true"
          checked={@drawer.form["service"] == "true"}
        />
      </section>

      <p class="ouro-devices-note">
        <strong>This runtime restarts as part of this setup.</strong>
        The page will lose its connection and reconnect on its own; the operation keeps
        running, because the worker doing it is not a child of this runtime. When the page
        comes back it reloads this operation by its id.
      </p>

      <button
        type="submit"
        class="ouro-button"
        disabled={@drawer.busy == :prepare}
        aria-describedby={@drawer.error && "ouro-deploy-error"}
      >
        Inspect this device
      </button>
      <p class="ouro-new-hint">
        Inspection reads. Nothing is configured or restarted until a plan has been shown and
        approved.
      </p>
    </form>
    """
  end

  attr :drawer, :map, required: true

  defp connect_step(assigns) do
    ~H"""
    <form id="ouro-deploy-connect" phx-change="connect-change" phx-submit="connect">
      <section class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="deploy-address">Private address</label>
        </div>
        <input
          id="deploy-address"
          class="ouro-new-input ouro-mono"
          type="text"
          name="address"
          value={@drawer.form["address"]}
          required
          aria-describedby="deploy-address-hint"
          autocomplete="off"
        />
        <p id="deploy-address-hint" class="ouro-new-hint">
          The overlay address the deployment host can reach this device at. A device chosen
          from the list fills this in; an address typed here is checked the same way.
        </p>
      </section>

      <section class="ouro-new-field">
        <div class="ouro-new-label-row">
          <label class="ouro-new-label" for="deploy-ssh-user">SSH username on the target</label>
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
          Required, and never inferred from the network client's owner: the account on the
          target machine is not the account that registered it with the network.
        </p>
      </section>

      <details class="ouro-devices-advanced">
        <summary>Advanced — port, identity and paths</summary>

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
            <label class="ouro-new-label" for="deploy-identity-kind">Authentication method</label>
          </div>
          <select id="deploy-identity-kind" class="ouro-new-input" name="identity_kind">
            <option value="" selected={@drawer.form["identity_kind"] == ""}>
              Let the deployment host offer what it has
            </option>
            <option value="agent" selected={@drawer.form["identity_kind"] == "agent"}>
              An identity in the deployment host's SSH agent
            </option>
            <option value="key" selected={@drawer.form["identity_kind"] == "key"}>
              A private key file on the deployment host
            </option>
            <option value="password" selected={@drawer.form["identity_kind"] == "password"}>
              The target account's password
            </option>
          </select>
          <p class="ouro-new-hint">
            A key or agent identity is named by reference. No private key is exported,
            uploaded or forwarded, and nothing here is a password field.
          </p>
        </section>

        <section class="ouro-new-field">
          <div class="ouro-new-label-row">
            <label class="ouro-new-label" for="deploy-identity-ref">Which identity</label>
            <span class="ouro-new-aside">
              {if @drawer.form["identity_kind"] in ["agent", "key"], do: "Required", else: "Optional"}
            </span>
          </div>
          <input
            id="deploy-identity-ref"
            class="ouro-new-input ouro-mono"
            type="text"
            name="identity_ref"
            value={@drawer.form["identity_ref"]}
            required={@drawer.form["identity_kind"] in ["agent", "key"]}
            aria-describedby="deploy-identity-ref-hint"
            autocomplete="off"
          />
          <p id="deploy-identity-ref-hint" class="ouro-new-hint">
            An agent identity's public fingerprint, or a key file's path on the deployment
            host. Required for both; a password needs none, and neither does letting this
            host's own ssh configuration choose.
          </p>
        </section>

        <section class="ouro-new-field">
          <div class="ouro-new-label-row">
            <label class="ouro-new-label" for="deploy-install-path">Install path on the target</label>
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

        <section class="ouro-new-field">
          <div class="ouro-new-label-row">
            <label class="ouro-new-label" for="deploy-data-dir">Data directory on the target</label>
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

        <section class="ouro-new-field">
          <div class="ouro-new-label-row">
            <label class="ouro-new-label" for="deploy-service">Install a startup service</label>
          </div>
          <input type="hidden" name="service" value="false" />
          <input
            id="deploy-service"
            type="checkbox"
            name="service"
            value="true"
            checked={@drawer.form["service"] == "true"}
          />
        </section>
      </details>

      <button
        type="submit"
        class="ouro-button"
        disabled={@drawer.busy == :prepare}
        aria-describedby={@drawer.error && "ouro-deploy-error"}
      >
        Inspect this device
      </button>
      <p class="ouro-new-hint">
        Inspection connects over SSH and reads. Nothing is installed or changed until a plan
        has been shown and approved.
      </p>
    </form>
    """
  end

  attr :drawer, :map, required: true

  defp host_trust_step(assigns) do
    challenge = challenge(assigns.drawer, ["host_trust"])

    assigns =
      assigns
      |> assign(:challenge, challenge)
      |> assign(:facts, Devices.metadata(challenge))

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-trust-title">
      <h3 id="ouro-deploy-trust-title">{Devices.challenge_title("host_trust")}</h3>

      <%!-- Every fact here is the worker's own `host_trust` metadata
            (`host_trust_metadata/5` in tui/src/fleet_setup/challenge.rs), with the form's
            answer only as a fallback where the worker reported nothing. --%>
      <dl class="ouro-facts">
        <div class="ouro-fact">
          <dt>Device</dt>
          <dd>
            {(@drawer.device && Devices.plain(@drawer.device["name"], 96)) ||
              Devices.plain(@facts["address"], 64) || "the selected device"}
          </dd>
        </div>
        <div class="ouro-fact">
          <dt>Address and port</dt>
          <dd class="ouro-mono">
            {Devices.plain(@facts["address"], 64) || Devices.plain(@drawer.form["address"], 64)}:{Devices.plain(
              @facts["port"] || @drawer.form["port"],
              16
            )}
          </dd>
        </div>
        <div class="ouro-fact">
          <dt>Account</dt>
          <dd class="ouro-mono">
            {Devices.plain(@facts["user"], 64) || Devices.plain(@drawer.form["ssh_user"], 64)}
          </dd>
        </div>
        <div class="ouro-fact">
          <dt>Key algorithm</dt>
          <dd class="ouro-mono">{Devices.plain(@facts["algorithm"], 48) || "not reported"}</dd>
        </div>
        <div class="ouro-fact">
          <dt>SHA256 fingerprint</dt>
          <dd class="ouro-mono">
            {Devices.plain(@facts["sha256_fingerprint"], 96) || "not reported"}
          </dd>
        </div>
      </dl>

      <p id="ouro-deploy-trust-hint">
        Verify this fingerprint independently — on the device's own console, or from a
        record you already trust — before continuing. Discovery is not host-key
        authentication, and nothing on this page can tell you whether this key is the right
        one.
      </p>

      <div class="ouro-devices-actions">
        <button
          type="button"
          class="ouro-button"
          phx-click="trust-host"
          phx-value-challenge={@challenge["challenge"]}
          phx-value-accept="true"
          aria-describedby="ouro-deploy-trust-hint"
        >
          Trust this host and continue
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

    assigns =
      assigns
      |> assign(:challenge, challenge)
      |> assign(:facts, Devices.metadata(challenge))
      |> assign(:field, "ouro-deploy-secret-#{assigns.drawer.secret_nonce}")

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-auth-title">
      <h3 id="ouro-deploy-auth-title">{Devices.challenge_title(@challenge["kind"])}</h3>

      <%!-- "Attempt 2 of 3", where the worker said so — `password_metadata/5` carries
            `attempt` and `max_attempts`, and a passphrase carries neither. --%>
      <p :if={Devices.attempt(@challenge)} class="ouro-devices-quiet">
        {Devices.attempt(@challenge)}
      </p>
      <p :if={@facts["public_fingerprint"]} class="ouro-devices-quiet">
        Public fingerprint
        <span class="ouro-mono">{Devices.plain(@facts["public_fingerprint"], 96)}</span>
      </p>

      <%!-- No `phx-change`. A change event on this form would stream every keystroke of a
            password to this server, which is the one thing the proposal's secret-handling
            section forbids by name. The field is submitted, once, in answer to its own
            challenge — and the id below changes afterwards so the browser replaces the
            element with an empty one rather than keeping what was typed. --%>
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

        <button
          type="submit"
          class="ouro-button"
          aria-describedby={@drawer.error && "ouro-deploy-error"}
        >
          Send this credential
        </button>
      </form>
    </section>
    """
  end

  attr :drawer, :map, required: true

  defp review_step(assigns) do
    challenge = challenge(assigns.drawer, ["review"])

    facts = Devices.metadata(challenge)

    assigns =
      assigns
      |> assign(:challenge, challenge)
      |> assign(:plan, facts["plan"])
      |> assign(:digest, facts["plan_digest"])
      |> assign(:rows, Devices.plan_rows(facts["plan"]))
      |> assign(:grants, Devices.plan_grants(facts["plan"]))
      |> assign(:unread, Devices.plan_unread(facts["plan"]))

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-review-title">
      <h3 id="ouro-deploy-review-title">{Devices.challenge_title("review")}</h3>

      <%!-- The plan in the CLI's own labels and order (`Plan::render/0`), so the terminal
            and this page show one plan rather than two. The document's raw key names —
            `install_path`, `data_dir` — are not what an operator is shown. --%>
      <dl :if={@rows != []} class="ouro-facts ouro-devices-plan">
        <div :for={{label, value} <- @rows} class="ouro-fact">
          <dt>{label}</dt>
          <dd class="ouro-mono">{value}</dd>
        </div>
      </dl>

      <div :if={@grants != []} class="ouro-devices-note">
        <strong>What approving this grants:</strong>
        <ul>
          <li :for={grant <- @grants}>{grant}</li>
        </ul>
      </div>

      <p :if={@unread != []} class="ouro-devices-note">
        This plan also carries {Enum.join(@unread, ", ")}, which this page does not read.
        Nothing here was approved on the strength of them — the digest below covers the
        whole document.
      </p>

      <p :if={not is_map(@plan)} class="ouro-devices-quiet">
        This operation's worker sent no plan this page can read. Nothing will be approved
        without one.
      </p>

      <p class="ouro-devices-quiet">
        plan digest
        <span class="ouro-mono" data-ouro-plan-digest>{@digest || "no digest reported"}</span>
      </p>

      <p :if={is_nil(@digest)} class="ouro-refusal">
        The worker did not name a digest for this plan, so there is nothing to approve
        exactly. Cancel this setup and start it again.
      </p>

      <button
        :if={@digest}
        type="button"
        class="ouro-button"
        phx-click="approve"
        phx-value-digest={@digest}
      >
        Deploy Ouroboros
      </button>
      <p :if={@digest} class="ouro-new-hint">
        This applies exactly the plan above. A plan that has changed since it was shown is
        refused rather than applied.
      </p>
    </section>
    """
  end

  attr :drawer, :map, required: true

  defp progress_step(assigns) do
    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-progress-title">
      <h3 id="ouro-deploy-progress-title">
        {Devices.operation_state(state_of(@drawer))}
      </h3>
      <p class="ouro-devices-quiet">{source_words((@drawer.status || %{})["source"])}</p>
    </section>
    """
  end

  defp source_words("worker"),
    do: "A worker is attached, so this is what is happening now."

  defp source_words("journal"),
    do:
      "No worker is attached. This is what the journal durably recorded, which is not the " <>
        "same as what is happening now."

  defp source_words(_unreported), do: "This runtime did not say where this answer came from."

  attr :drawer, :map, required: true

  defp finish_step(assigns) do
    status = assigns.drawer.status || %{}
    done = status["done"] || %{}
    {readiness, offer_task?} = Devices.readiness(status["steps"], done)

    assigns =
      assigns
      # A `done` frame from the engine's failure path carries `ok: false`, a reason and a
      # detail and **no state at all** (`worker.rs`'s error arm), so the last `state` event
      # to arrive is still whatever the operation was doing when it stopped. A `done` frame
      # *is* the end of the operation and `ok` says which way, so it settles the reading
      # where the state has not — without overruling a state that already said so.
      |> assign(:state, final_state(status, done, assigns.drawer))
      |> assign(:done, done)
      |> assign(:finished?, done["ok"] == true)
      |> assign(:readiness, readiness)
      |> assign(:offer_task?, offer_task?)
      |> assign(:summary, done["summary"])
      |> assign(:next, done["next"])
      |> assign(:unknown, List.wrap(done["unknown"]))
      |> assign(:cause, cause(status, done))

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-finish-title">
      <h3 id="ouro-deploy-finish-title">{Devices.operation_state(@state)}</h3>

      <p :if={@summary}>{Devices.plain(@summary)}</p>
      <p :if={@cause} class="ouro-refusal">{@cause}</p>

      <%!-- "the next thing to do, which the proposal requires the final display to name"
            — the worker's own words, not this page's guess at them. --%>
      <p :if={@next} class="ouro-devices-note"><strong>Next:</strong> {Devices.plain(@next)}</p>

      <p :if={@finished?}>{@readiness}</p>

      <div :if={@unknown != []} class="ouro-devices-note">
        <strong>What this operation could not establish:</strong>
        <ul>
          <li :for={fact <- @unknown}>{Devices.plain(fact)}</li>
        </ul>
      </div>

      <div :if={@finished?} class="ouro-devices-actions">
        <a class="ouro-button" href="/status">Open device</a>
        <a class="ouro-quiet-button" href="/settings#providers">Configure model</a>
        <a :if={@offer_task?} class="ouro-quiet-button" href="/new">Run test task</a>
      </div>
      <p :if={@finished?} class="ouro-new-hint">
        Model credentials are node-local: this Settings page configures the runtime serving
        this browser, and the new member's own model setup is a step on that machine.
      </p>

      <div
        :if={@state in ["failed", "interrupted"] and not taken_over?(@drawer)}
        class="ouro-devices-actions"
      >
        <button
          type="button"
          class="ouro-button"
          phx-click="resume"
          phx-value-operation={@drawer.operation}
        >
          {if @state == "failed", do: "Retry", else: "Continue setup"}
        </button>
      </div>

      <p :if={@state == "cancelled"}>
        This setup stopped at a safe boundary. It does not undo anything that was already
        delivered to the other machine.
      </p>
    </section>
    """
  end

  @terminal ~w(completed failed cancelled interrupted)

  defp final_state(status, done, drawer) do
    cond do
      status["state"] in @terminal -> status["state"]
      done["ok"] == false -> "failed"
      done["ok"] == true -> "completed"
      drawer.cancelled? -> "cancelled"
      true -> status["state"]
    end
  end

  # What went wrong, in the worker's own sanitized words. `detail` is the failure arm's;
  # `last_error` is the broker's, for a frame that carried one. The `reason` beside them is
  # a stable code and stays out of the sentence.
  defp cause(status, done) do
    Presentation.refusal(status["last_error"] || Devices.plain(done["detail"]))
  end

  attr :drawer, :map, required: true

  defp steps(assigns) do
    reported = List.wrap((assigns.drawer.status || %{})["steps"])

    assigns =
      assigns
      |> assign(:reported, reported)
      # Each of the proposal's six stages, with every step the worker filed under it. A
      # stage the worker has reported nothing for says so; it does not read as done.
      |> assign(
        :stages,
        Enum.map(Devices.stages(), fn {key, label, _names} ->
          {key, label,
           Enum.filter(reported, &(is_map(&1) and Devices.stage_of(&1["step"]) == key))}
        end)
      )
      # And the steps that belong to none of the six — cooperative removal's, and the
      # explicit test task — under their own names rather than folded into a stage they
      # are not part of.
      |> assign(
        :extra,
        Enum.filter(reported, &(is_map(&1) and is_nil(Devices.stage_of(&1["step"]))))
      )
      |> assign(:log, List.wrap((assigns.drawer.status || %{})["log"]))

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-steps-title">
      <h3 id="ouro-deploy-steps-title">Steps</h3>

      <ol class="ouro-devices-steps">
        <li :for={{key, label, steps} <- @stages} data-step={key} data-outcome={stage_outcome(steps)}>
          <span class="ouro-devices-step-name">{label}</span>
          <span class="ouro-devices-step-outcome">
            <span class="ouro-visually-hidden">Outcome:</span>
            {if steps == [],
              do: "not reported yet",
              else: elem(Devices.outcome(stage_outcome(steps)), 0)}
          </span>
          <span :for={step <- steps} class="ouro-devices-detail">
            {Devices.step_label(step["step"])}{if step["machine"],
              do: " on #{Devices.plain(step["machine"], 64)}"} — {elem(
              Devices.outcome(step["outcome"]),
              0
            )}{if step["detail"],
              do: ": #{Devices.plain(step["detail"])}"}
          </span>
        </li>
      </ol>

      <ul :if={@extra != []} class="ouro-devices-steps">
        <li :for={step <- @extra} data-step={step["step"]} data-outcome={step["outcome"]}>
          <span class="ouro-devices-step-name">
            {Devices.step_label(step["step"])}{if step["machine"],
              do: " on #{Devices.plain(step["machine"], 64)}"}
          </span>
          <span class="ouro-devices-step-outcome">
            <span class="ouro-visually-hidden">Outcome:</span>
            {elem(Devices.outcome(step["outcome"]), 0)}
          </span>
          <span :if={step["detail"]} class="ouro-devices-detail">{Devices.plain(step["detail"])}</span>
        </li>
      </ul>

      <details :if={@log != []} class="ouro-devices-advanced">
        <summary>What the worker reported</summary>
        <ul class="ouro-devices-log">
          <li :for={line <- @log} class="ouro-mono">
            {log_line(line)}
          </li>
        </ul>
      </details>
    </section>
    """
  end

  # A stage is as done as its least finished step: one failure makes the stage failed, one
  # step still running makes it running, and a stage whose steps are all `ok` or `skipped`
  # is done. Never "done" because the last frame to arrive happened to say so.
  defp stage_outcome([]), do: nil

  defp stage_outcome(steps) do
    outcomes = Enum.map(steps, & &1["outcome"])

    cond do
      "failed" in outcomes -> "failed"
      "started" in outcomes -> "started"
      Enum.all?(outcomes, &(&1 in ["ok", "skipped"])) -> "ok"
      true -> List.last(outcomes)
    end
  end

  defp log_line(%{"line" => line}), do: Devices.plain(line)
  defp log_line(line) when is_binary(line), do: Devices.plain(line)
  defp log_line(other), do: Devices.plain(other)
end
