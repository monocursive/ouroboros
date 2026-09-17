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
  @status_retries 8
  @status_retry_after 150

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     # Once, in mount, and kept. Seam S4 binds a challenge to the session that was attached
     # when it was issued, and the session cookie is one id every tab in this browser
     # shares — so the binding that makes "a second tab cannot answer the first tab's
     # prompt" true has to be per *view*. `Ouroboros.Web.Call.view_session/0` mints it.
     |> assign(:view_session, Call.view_session())
     |> assign(:page_title, "Devices")
     |> assign(:scope, Config.for_endpoint(socket.endpoint).scope)
     |> assign(:query, "")
     |> assign(:filter, "all")
     |> assign(:drawer, nil)
     |> assign(:announcement, "")
     |> load()}
  end

  # ------------------------------------------------------------------------------------
  # Params
  # ------------------------------------------------------------------------------------

  @impl true
  def handle_params(%{"operation" => operation}, _uri, socket) when is_binary(operation) do
    if socket.assigns.drawer && socket.assigns.drawer.operation == operation do
      {:noreply, socket}
    else
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

  def handle_event("deploy", %{"address" => address}, socket) do
    device = Enum.find(devices(socket), &(&1["address"] == address))
    {:noreply, open_drawer(socket, device, "add")}
  end

  def handle_event("deploy-manual", _params, socket),
    do: {:noreply, open_drawer(socket, nil, "add")}

  # "Set up this device": the first local fleet. No SSH, no account and no credential — this
  # machine configures itself, which is what the proposal's sixth observed state asks for.
  def handle_event("setup-device", %{"address" => address}, socket) do
    device = Enum.find(devices(socket), &(&1["address"] == address))
    {:noreply, open_drawer(socket, device, "setup")}
  end

  def handle_event("setup-device", _params, socket),
    do: {:noreply, open_drawer(socket, local_device(socket), "setup")}

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
    socket =
      update_drawer(socket, &%{&1 | form: form(params, &1.form), error: nil, busy: :prepare})

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
    result =
      operate(socket, @authenticate, %{
        "operation_id" => operation,
        "challenge" => challenge,
        "secret" => secret
      })

    socket =
      socket
      |> update_drawer(&%{&1 | secret_nonce: &1.secret_nonce + 1, busy: nil})
      |> answered(result, "The credential was sent to the deployment worker.")

    {:noreply, reload(socket)}
  end

  def handle_event("authenticate", _params, socket), do: {:noreply, socket}

  def handle_event(
        "trust-host",
        %{"challenge" => challenge, "accept" => accept},
        %{assigns: %{drawer: %{operation: operation}}} = socket
      )
      when is_binary(operation) do
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

    {:noreply, socket |> answered(result, said) |> reload()}
  end

  def handle_event("approve", %{"digest" => digest}, socket)
      when is_binary(digest) and digest != "" do
    drawer = socket.assigns.drawer

    result =
      operate(socket, @start, %{
        "operation_id" => drawer.operation,
        "plan_digest" => digest,
        "idempotency_key" => drawer.approval_key
      })

    {:noreply, socket |> answered(result, "The plan was approved.") |> reload()}
  end

  def handle_event("approve", _params, socket), do: {:noreply, socket}

  def handle_event("cancel-setup", _params, %{assigns: %{drawer: %{operation: op}}} = socket)
      when is_binary(op) do
    case operate(socket, @cancel, %{"operation_id" => op}) do
      {:ok, reply} when is_map(reply) ->
        {:noreply,
         socket
         |> update_drawer(&%{&1 | residue: List.wrap(reply["residue"]), error: nil})
         |> announce("The setup was asked to stop at a safe boundary.")
         |> reload()}

      refused ->
        {:noreply, drawer_refusal(socket, refused)}
    end
  end

  def handle_event("cancel-setup", _params, socket), do: {:noreply, socket}

  def handle_event("resume", %{"operation" => operation} = params, socket)
      when is_binary(operation) do
    takeover? = params["takeover"] == "true"

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

        {:noreply, socket |> update_drawer(&%{&1 | takeover: nil}) |> announce(said)}

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

  def handle_event("open-operation", %{"operation" => operation}, socket)
      when is_binary(operation) do
    {:noreply,
     socket
     |> attach(operation, nil)
     |> push_patch(to: "/devices?operation=#{operation}", replace: true)}
  end

  # ------------------------------------------------------------------------------------
  # Worker events
  # ------------------------------------------------------------------------------------

  @impl true
  def handle_info({:ouroboros_fleet_deployment, operation, event}, socket) do
    if socket.assigns.drawer && socket.assigns.drawer.operation == operation do
      {:noreply, socket |> announce(said(event)) |> reload()}
    else
      {:noreply, socket}
    end
  end

  def handle_info(
        {:DOWN, reference, :process, _pid, _reason},
        %{assigns: %{drawer: drawer}} = socket
      )
      when is_map(drawer) and drawer.monitor == reference do
    {:noreply,
     socket
     |> update_drawer(&%{&1 | monitor: nil})
     |> announce(said(%{"event" => "disconnected"}))
     |> reload()}
  end

  def handle_info({:devices_reload, operation}, socket) do
    if socket.assigns.drawer && socket.assigns.drawer.operation == operation,
      do: {:noreply, reload(socket)},
      else: {:noreply, socket}
  end

  def handle_info(_other, socket), do: {:noreply, socket}

  # One sentence per event kind, for the polite live region. A step is the one an operator
  # is actually following, so it is the one that names itself.
  defp said(%{"event" => "step"} = event) do
    {outcome, _tone} = Devices.outcome(event["outcome"])
    "#{event["name"] || event["step"] || "A step"}: #{outcome}."
  end

  defp said(%{"event" => "state"} = event), do: Devices.operation_state(event["state"]) <> "."

  defp said(%{"event" => "challenge"} = event),
    do: Devices.challenge_title(event["kind"]) <> "."

  defp said(%{"event" => "done"} = event), do: Devices.operation_state(event["state"]) <> "."

  defp said(%{"event" => "disconnected"}) do
    "The connection to the deployment worker was lost. What it has done is unknown until " <>
      "the operation is read again; nothing was cancelled."
  end

  defp said(_other), do: ""

  # ------------------------------------------------------------------------------------
  # Loading
  # ------------------------------------------------------------------------------------

  defp load(socket) do
    socket
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

  # Every operation this data directory still holds open. The summary carries its own
  # `target` — machine, address, account, port — which is what puts it on the row it is
  # about rather than on every row, and this page therefore reads no operation's status
  # until an operator opens one.
  defp operations(_socket, inventory) do
    inventory
    |> Map.get("operations", [])
    |> List.wrap()
    |> Enum.filter(&Devices.unfinished?(&1["state"]))
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
      reloads: 0,
      monitor: nil,
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

  defp close_drawer(%{assigns: %{drawer: %{operation: operation} = drawer}} = socket)
       when is_binary(operation) do
    _ = Deployment.unsubscribe(operation)
    demonitor(drawer.monitor)
    assign(socket, :drawer, nil)
  end

  defp close_drawer(socket), do: assign(socket, :drawer, nil)

  defp demonitor(nil), do: :ok
  defp demonitor(reference), do: Process.demonitor(reference, [:flush])

  # Attaching is the only way an operation gets into the drawer, whether it arrived from a
  # `prepare`, from a `resume`, from a row, or from the address bar after a reload.
  defp attach(socket, operation, device) do
    drawer = socket.assigns.drawer || open_drawer(socket, device, "add").assigns.drawer

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
        update_drawer(socket, &%{&1 | status: status, error: nil, takeover: nil, reloads: 0})

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

  defp drawer_refusal(socket, refused) do
    update_drawer(socket, &%{&1 | error: Presentation.refusal(refused), busy: nil})
  end

  defp answered(socket, {:ok, _reply}, said), do: announce(socket, said)

  defp answered(socket, refused, _said) do
    message = Presentation.refusal(refused)

    socket
    |> update_drawer(&%{&1 | error: message, busy: nil})
    |> announce(message)
  end

  defp announce(socket, ""), do: socket
  defp announce(socket, said), do: assign(socket, :announcement, said)

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
        %{"address" => String.trim(form["address"] || "")}
        |> put_present("machine", trimmed(form["machine"])),
      "ssh_user" => String.trim(form["ssh_user"] || ""),
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

  defp deploy_blocked(socket) do
    case blockers(socket) do
      [] -> unavailable(socket, @prepare)
      [first | _rest] -> Devices.deploy_blocker(first)
    end
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
    assigns =
      assigns
      |> assign(:host, host(assigns_socket(assigns)))
      |> assign(:deploy?, deploy?(assigns_socket(assigns)))
      |> assign(:deploy_blocked, deploy_blocked(assigns_socket(assigns)))
      |> assign(:setup?, setup?(assigns_socket(assigns)))
      |> assign(:setup_blocked, setup_blocked(assigns_socket(assigns)))
      |> assign(:rows, rows(assigns))

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

        <section :if={@availability != :available} class="ouro-panel">
          <div class="ouro-panel-head">
            <h2>Deployment is not available here</h2>
          </div>
          <p class="ouro-refusal">{Devices.unavailable(@availability, "fleet.devices")}</p>
          <.membership fleet={@fleet} error={@fleet_error} />
        </section>

        <p :if={@inventory_error} class="ouro-refusal">{@inventory_error}</p>

        <.operations
          :if={@availability == :available and @operations != []}
          operations={@operations}
        />

        <section :if={@inventory} class="ouro-panel">
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

          <p :if={@deploy?} class="ouro-devices-manual">
            A device that is not listed can be named directly.
            <button type="button" class="ouro-quiet-button" phx-click="deploy-manual">
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
          can_operate?={@deploy?}
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
        Deploying from {@host["hostname"] || Devices.this_device()} · local user {@host["user"] ||
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
        {@discovery["detail"]}
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
          data-address={device["address"]}
        >
          <span class="ouro-devices-name">{device["name"] || Devices.this_device()}</span>
          <span class="ouro-devices-facts ouro-mono">
            <span>{device["os"] || "operating system not reported"}</span>
            <span>·</span>
            <span>{device["address"] || "no private address reported"}</span>
          </span>
          <span class="ouro-devices-presence">
            <span class="ouro-visually-hidden">Network presence:</span>
            {Devices.presence(device)}
          </span>
          <span class="ouro-devices-state">
            <span class="ouro-visually-hidden">Ouroboros state:</span>
            {Devices.state_words(device["state"])}
          </span>

          <span class="ouro-devices-action">
            <button
              :if={operation_for(@operations, device)}
              type="button"
              class="ouro-button"
              phx-click="open-operation"
              phx-value-operation={operation_for(@operations, device)}
            >
              Continue setup
            </button>
            <button
              :if={
                is_nil(operation_for(@operations, device)) and @deploy? and
                  Devices.deployable?(device)
              }
              type="button"
              class="ouro-button"
              phx-click="deploy"
              phx-value-address={device["address"]}
            >
              Deploy Ouroboros
            </button>
            <button
              :if={is_nil(operation_for(@operations, device)) and @setup? and Devices.setup?(device)}
              type="button"
              class="ouro-button"
              phx-click="setup-device"
              phx-value-address={device["address"]}
            >
              Set up this device
            </button>
            <span
              :if={
                is_nil(operation_for(@operations, device)) and not Devices.deployable?(device) and
                  not Devices.setup?(device)
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
            class="ouro-devices-blocked"
          >
            {@blocked}
          </span>

          <span
            :if={
              is_nil(operation_for(@operations, device)) and Devices.setup?(device) and
                not @setup?
            }
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

  defp same_device?(target, device) when is_map(target) and is_map(device) do
    matches?(target["address"], device["address"]) or
      matches?(target["machine"], device["machine"]) or
      matches?(target["machine"], device["name"])
  end

  defp same_device?(_target, _device), do: false

  defp matches?(left, right) when is_binary(left) and is_binary(right) and left != "",
    do: left == right

  defp matches?(_left, _right), do: false

  attr :operations, :list, required: true

  defp operations(assigns) do
    ~H"""
    <section class="ouro-panel" aria-labelledby="devices-operations-title">
      <div class="ouro-panel-head">
        <h2 id="devices-operations-title">Setups in progress</h2>
      </div>
      <p>
        This machine is holding these deployments. Closing the page did not cancel them.
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
            <span class="ouro-visually-hidden">Deployment state:</span>
            {Devices.operation_state(operation["state"])}
          </span>
          <span class="ouro-devices-presence">
            {if operation["attached"],
              do: "a worker is attached",
              else: "no worker is attached; this is what the journal recorded"}
          </span>
          <span class="ouro-devices-action">
            <button
              type="button"
              class="ouro-button"
              phx-click="open-operation"
              phx-value-operation={operation["operation"]}
            >
              Continue setup
            </button>
          </span>
        </li>
      </ul>
    </section>
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
  attr :can_operate?, :boolean, required: true

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
        <h2 id="ouro-deploy-title">
          {if @drawer.kind == "setup", do: "Set up this device", else: "Deploy Ouroboros"}
        </h2>

        <p class="ouro-devices-host" data-ouro-deployment-host>
          <strong>
            Deploying from {(@host && @host["hostname"]) || Devices.this_device()} · local user {(@host &&
                                                                                                    @host[
                                                                                                      "user"
                                                                                                    ]) ||
              "not reported"}
          </strong>
        </p>

        <p :if={@drawer.device} class="ouro-devices-target">
          To <strong>{@drawer.device["name"]}</strong>
          <span class="ouro-mono">{@drawer.device["address"]}</span>
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
          {@announcement}
        </p>

        <p :if={@drawer.error} id="ouro-deploy-error" class="ouro-refusal" role="alert">
          {@drawer.error}
        </p>

        <.takeover :if={@drawer.takeover == @drawer.operation} drawer={@drawer} />

        <.setup_step :if={@step == :select and @drawer.kind == "setup"} drawer={@drawer} />
        <.connect_step :if={@step == :select and @drawer.kind != "setup"} drawer={@drawer} />
        <.host_trust_step :if={@step == :host_trust} drawer={@drawer} />
        <.authenticate_step :if={@step == :authenticate} drawer={@drawer} />
        <.review_step :if={@step == :review} drawer={@drawer} />
        <.progress_step :if={@step in [:progress, :connecting]} drawer={@drawer} />
        <.finish_step :if={@step == :finish} drawer={@drawer} />

        <.steps :if={@step not in [:select]} drawer={@drawer} />

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
    do: entry["detail"] || entry["name"] || inspect(entry, limit: 5)

  defp residue_line(entry) when is_binary(entry), do: entry
  defp residue_line(entry), do: inspect(entry, limit: 5)

  # Which step the drawer is on. Challenges first, because an open challenge is the runtime
  # waiting for this operator and outranks whatever the last state event said.
  defp step(%{operation: nil}), do: :select
  defp step(%{status: nil}), do: :connecting

  defp step(drawer) do
    cond do
      challenge(drawer, ["host_trust"]) -> :host_trust
      challenge(drawer, ["password", "passphrase"]) -> :authenticate
      challenge(drawer, ["review"]) -> :review
      state_of(drawer) in ["completed", "failed", "cancelled", "interrupted"] -> :finish
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
    assigns = assign(assigns, :challenge, challenge(assigns.drawer, ["host_trust"]))

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-trust-title">
      <h3 id="ouro-deploy-trust-title">{Devices.challenge_title("host_trust")}</h3>

      <dl class="ouro-facts">
        <div class="ouro-fact">
          <dt>Device</dt>
          <dd>{@challenge["peer"] || @challenge["host"] || @drawer.device["name"]}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Address and port</dt>
          <dd class="ouro-mono">
            {@challenge["address"] || @drawer.form["address"]}:{@challenge["port"] ||
              @drawer.form["port"]}
          </dd>
        </div>
        <div class="ouro-fact">
          <dt>Account</dt>
          <dd class="ouro-mono">{@challenge["user"] || @drawer.form["ssh_user"]}</dd>
        </div>
        <div class="ouro-fact">
          <dt>Key algorithm</dt>
          <dd class="ouro-mono">{@challenge["algorithm"] || "not reported"}</dd>
        </div>
        <div class="ouro-fact">
          <dt>SHA256 fingerprint</dt>
          <dd class="ouro-mono">{@challenge["sha256_fingerprint"] || "not reported"}</dd>
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
      |> assign(:field, "ouro-deploy-secret-#{assigns.drawer.secret_nonce}")

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-auth-title">
      <h3 id="ouro-deploy-auth-title">{Devices.challenge_title(@challenge["kind"])}</h3>

      <p :if={@challenge["attempt"]} class="ouro-devices-quiet">
        Attempt {@challenge["attempt"]}{if @challenge["attempts_allowed"],
          do: " of #{@challenge["attempts_allowed"]}"}.
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

    assigns =
      assigns
      |> assign(:challenge, challenge)
      |> assign(:plan, challenge["plan"])
      |> assign(:digest, challenge["plan_digest"])

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-review-title">
      <h3 id="ouro-deploy-review-title">{Devices.challenge_title("review")}</h3>

      <dl :if={is_map(@plan)} class="ouro-facts">
        <div :for={{key, value} <- Enum.sort(@plan)} class="ouro-fact">
          <dt>{key}</dt>
          <dd class="ouro-mono">{plan_value(value)}</dd>
        </div>
      </dl>

      <p :if={not is_map(@plan)} class="ouro-devices-quiet">
        This operation's worker sent no plan this page can read. Nothing will be approved
        without one.
      </p>

      <p class="ouro-devices-quiet">
        <span class="ouro-visually-hidden">Plan digest:</span>
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

  defp plan_value(value) when is_binary(value), do: value
  defp plan_value(value) when is_number(value) or is_boolean(value), do: to_string(value)
  defp plan_value(nil), do: "not reported"
  defp plan_value(value) when is_list(value), do: Enum.map_join(value, ", ", &plan_value/1)

  defp plan_value(value) when is_map(value),
    do:
      Enum.map_join(Enum.sort(value), "; ", fn {key, inner} -> "#{key}: #{plan_value(inner)}" end)

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

    assigns =
      assigns
      |> assign(:state, status["state"])
      |> assign(:done, done)
      |> assign(:ready, done["ready"])
      |> assign(:cause, Presentation.refusal(status["last_error"] || done["error"]))

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-finish-title">
      <h3 id="ouro-deploy-finish-title">{Devices.operation_state(@state)}</h3>

      <p :if={@cause} class="ouro-refusal">{@cause}</p>

      <p :if={@state == "completed" and @ready == true}>This device reported that it is ready.</p>
      <p :if={@state == "completed" and @ready == false}>
        The deployment finished and this device did not report itself ready. What is missing
        is below.
      </p>
      <p :if={@state == "completed" and is_nil(@ready)}>
        The deployment finished. Readiness was not reported, so this page does not claim it.
      </p>

      <div :if={@state == "completed"} class="ouro-devices-actions">
        <a class="ouro-button" href="/status">Open device</a>
        <a class="ouro-quiet-button" href="/settings#providers">Configure model</a>
        <a :if={@ready != false} class="ouro-quiet-button" href="/new">Run test task</a>
      </div>
      <p :if={@state == "completed"} class="ouro-new-hint">
        Model credentials are node-local: this Settings page configures the runtime serving
        this browser, and the new member's own model setup is a step on that machine.
      </p>

      <div
        :if={@state in ["failed", "interrupted"] and @drawer.takeover != @drawer.operation}
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

  attr :drawer, :map, required: true

  defp steps(assigns) do
    reported = List.wrap((assigns.drawer.status || %{})["steps"])

    assigns =
      assigns
      |> assign(:reported, reported)
      |> assign(
        :stages,
        Enum.map(Devices.stages(), fn {key, label} ->
          {key, label, Enum.find(reported, &stage?(&1, key))}
        end)
      )
      |> assign(
        :extra,
        Enum.reject(reported, fn step ->
          Enum.any?(Devices.stages(), fn {key, _label} -> stage?(step, key) end)
        end)
      )
      |> assign(:log, List.wrap((assigns.drawer.status || %{})["log"]))

    ~H"""
    <section class="ouro-devices-step" aria-labelledby="ouro-deploy-steps-title">
      <h3 id="ouro-deploy-steps-title">Steps</h3>

      <ol class="ouro-devices-steps">
        <li
          :for={{key, label, step} <- @stages}
          data-step={key}
          data-outcome={step && step["outcome"]}
        >
          <span class="ouro-devices-step-name">{label}</span>
          <span class="ouro-devices-step-outcome">
            <span class="ouro-visually-hidden">Outcome:</span>
            {if step, do: elem(Devices.outcome(step["outcome"]), 0), else: "not reported yet"}
          </span>
          <span :if={step && step["detail"]} class="ouro-devices-detail">{step["detail"]}</span>
        </li>
      </ol>

      <ul :if={@extra != []} class="ouro-devices-steps">
        <li :for={step <- @extra} data-outcome={step["outcome"]}>
          <span class="ouro-devices-step-name">{step["name"] || step["step"] || "a step"}</span>
          <span class="ouro-devices-step-outcome">
            <span class="ouro-visually-hidden">Outcome:</span>
            {elem(Devices.outcome(step["outcome"]), 0)}
          </span>
          <span :if={step["detail"]} class="ouro-devices-detail">{step["detail"]}</span>
        </li>
      </ul>

      <details :if={@log != []} class="ouro-devices-advanced">
        <summary>What the worker reported</summary>
        <ul class="ouro-devices-log">
          <li :for={line <- @log} class="ouro-mono">{line["message"] || inspect(line, limit: 5)}</li>
        </ul>
      </details>
    </section>
    """
  end

  defp stage?(step, key) when is_map(step) do
    name = step["name"] || step["step"]
    is_binary(name) and String.starts_with?(String.downcase(name), key)
  end

  defp stage?(_step, _key), do: false
end
