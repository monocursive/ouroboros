defmodule Ouroboros.Web.Live.Devices do
  @moduledoc """
  Every word the Devices page says about a code the runtime sent it.

  `fleet.devices` and `fleet.deployment.status` answer in stable snake_case codes —
  `discovered_installation_unknown`, `signed_out`, `awaiting_host_trust`, `no_ca_key` — and
  none of them was addressed to a person. This module is the one place they become English,
  for the same reason `Ouroboros.Web.Presentation` exists: a phrase invented at the call
  site is a phrase the next call site spells differently.

  ## The observed-state table is the proposal's, verbatim

  `observed_states/0` is the table under "Devices UI and deployment experience › Inventory"
  copied word for word, and `state_words/1` and `state_action/1` answer out of it. That is
  deliberate: the table is the requirement, and a surface that paraphrased it would be
  deciding for itself what "do not label it uninstalled until inspected" meant.

  The codes themselves never reach a reader. They reach the markup as `data-state`, where a
  test can name a row without depending on its wording and a stylesheet can draw one without
  the wording carrying the meaning on its own — rule: no state by colour alone, and no state
  by code either.

  ## What this may not do

  Claim. Every sentence here describes what was reported, and where nothing was reported it
  says so. "Not connected" is not "powered off", "not inspected" is not "not installed", and
  a network client that could not answer is not a fleet with no members.
  """

  @this_device "this machine"

  # How much of one peer-controlled string this page will draw. The CLI's own sanitizer caps
  # at 300 for the same reason: one runaway remote must not own the screen.
  @max_text 300

  # The proposal's table, in its order, as written. `{observed state, primary action}`.
  @observed_states [
    {"Discovered peer; Ouroboros installation unknown",
     "Deploy Ouroboros opens preflight; do not label it uninstalled until inspected"},
    {"Known compatible fleet member",
     "View device with readiness, service state and explicit diagnostics"},
    {"Deployment waiting for input, interrupted or partially complete",
     "Continue setup for the existing operation"},
    {"Known member disconnected from this runtime",
     "Diagnose; disconnected does not establish that the host is powered off"},
    {"Peer offline, unsupported platform, or no usable IPv4",
     "Explain the blocker and offer refresh/details; disable deployment while the blocker is established"},
    {"Current device without a fleet profile",
     "Set up this device locally, without SSH to itself"}
  ]

  # `ouro fleet devices --json`'s `state` for a row, joined to the row of the table above it
  # is an instance of. `this_device` is the one code with no row of its own: the table names
  # the current device only in its unconfigured form, because a configured local machine is
  # an ordinary known member that happens to be here.
  @state_words %{
    "discovered_installation_unknown" => "Discovered peer; Ouroboros installation unknown",
    "fleet_member" => "Known compatible fleet member",
    "fleet_member_connected" => "Known compatible fleet member",
    "fleet_member_not_visible" => "Known member disconnected from this runtime",
    "peer_offline" => "Peer offline",
    "unsupported_platform" => "Unsupported platform for any Ouroboros release",
    "no_usable_ipv4" => "No usable IPv4 address",
    "this_device" => "This machine, already set up",
    "this_device_without_profile" => "Current device without a fleet profile"
  }

  @state_actions %{
    "discovered_installation_unknown" => "Deploy Ouroboros",
    "fleet_member" => "View device",
    "fleet_member_connected" => "View device",
    "fleet_member_not_visible" => "Diagnose",
    "peer_offline" => "Refresh or inspect",
    "unsupported_platform" => "Nothing to deploy",
    "no_usable_ipv4" => "Nothing to deploy",
    "this_device" => "View device",
    "this_device_without_profile" => "Set up this device"
  }

  # The two sections of the inventory. A code this build does not know is filed under
  # "Available on this network", which is the side that makes no claim about membership.
  @fleet_states ~w(this_device this_device_without_profile fleet_member fleet_member_connected
                   fleet_member_not_visible)

  # The blockers that must disable deployment while they stand (the table's fifth row).
  @blocked_states ~w(peer_offline unsupported_platform no_usable_ipv4)

  @doc """
  One string that came from somewhere this runtime does not control, made safe to read.

  HEEx escapes markup, which stops injection and nothing else. What it does not stop is a
  peer *lying about what it is called*: `U+202E` reverses the characters after it, a
  zero-width space splits a name into two that read as one, and a tab or a newline inside a
  table cell rearranges the row. A device names itself, and this page puts that name next to
  a Deploy button.

  So the same rule the CLI applies to remote text (`sanitize_remote_text/2` in
  `tui/src/fleet_setup/mod.rs`): whitespace collapses to single spaces, every control and
  format code point is dropped — C0, DEL, C1, the bidi overrides and isolates, the
  zero-width set, the soft hyphen and the byte-order mark — and the whole thing is capped.

  `nil` in, `nil` out, so a caller can keep testing for absence. A string that was *only*
  invisible characters comes back empty, which every reader here already treats as absent.
  """
  @spec plain(term()) :: String.t() | nil
  @spec plain(term(), pos_integer()) :: String.t() | nil
  def plain(value, limit \\ @max_text)

  def plain(value, limit) when is_binary(value) do
    value
    |> String.split()
    |> Enum.map(&visible/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.join(" ")
    |> cap(limit)
  end

  def plain(value, _limit) when is_number(value) or is_boolean(value), do: to_string(value)
  def plain(nil, _limit), do: nil
  def plain(value, limit), do: value |> inspect(limit: 5) |> plain(limit)

  defp visible(word) do
    word |> String.to_charlist() |> Enum.reject(&invisible?/1) |> List.to_string()
  end

  # Control and format code points, by range rather than by name: a table of names is a
  # table somebody has to remember to extend.
  defp invisible?(point) do
    point < 0x20 or point == 0x7F or point in 0x80..0x9F or point == 0xAD or point == 0x61C or
      point in 0x200B..0x200F or point in 0x202A..0x202E or point in 0x2060..0x2064 or
      point in 0x2066..0x2069 or point == 0xFEFF
  end

  defp cap(text, limit) do
    if String.length(text) <= limit, do: text, else: String.slice(text, 0, limit) <> "…"
  end

  @doc "The proposal's observed-state table, verbatim, as `{observed state, primary action}`."
  @spec observed_states() :: [{String.t(), String.t()}]
  def observed_states, do: @observed_states

  @doc "One device's Ouroboros state, in the table's words."
  @spec state_words(term()) :: String.t()
  def state_words(state) when is_binary(state),
    do: Map.get(@state_words, state, "State this build does not recognise: #{state}")

  def state_words(_absent), do: "State not reported"

  @doc "The primary action that state leads to, named as the table names it."
  @spec state_action(term()) :: String.t()
  def state_action(state) when is_binary(state), do: Map.get(@state_actions, state, "Details")
  def state_action(_absent), do: "Details"

  @doc "Whether a row belongs under **Fleet devices** rather than **Available on this network**."
  @spec fleet_row?(map()) :: boolean()
  def fleet_row?(device) when is_map(device), do: device["state"] in @fleet_states

  @doc """
  Whether a blocker this listing established stands between this device and a deployment.

  The table's fifth row: offline, unsupported platform and no usable IPv4 are facts the
  network client reported, and deployment is disabled while one of them stands rather than
  offered and then refused.
  """
  @spec blocked?(map()) :: boolean()
  def blocked?(device) when is_map(device), do: device["state"] in @blocked_states

  @doc "Whether this row's primary action is the read-only View device / Diagnose panel."
  @spec inspectable?(map()) :: boolean()
  def inspectable?(device) when is_map(device),
    do: state_action(device["state"]) in ["View device", "Diagnose"]

  def inspectable?(_other), do: false

  @doc "Whether this row is a device an SSH deployment can be aimed at."
  @spec deployable?(map()) :: boolean()
  def deployable?(device) when is_map(device) do
    device["state"] == "discovered_installation_unknown" and is_binary(device["address"])
  end

  @doc """
  Whether this row is **this machine, with no fleet profile of its own**.

  The proposal's sixth observed state, and the one action that is not a deployment: this
  machine configures itself, without SSH to itself.
  """
  @spec setup?(map()) :: boolean()
  def setup?(device) when is_map(device), do: device["state"] == "this_device_without_profile"

  @doc """
  Network presence, with the observation time the client gave.

  Three different facts, never collapsed: connected now, seen at a time and not connected
  now, and a client that reported no presence at all. The last is not "offline".
  """
  @spec presence(map()) :: String.t()
  def presence(device) when is_map(device) do
    [network_presence(device) | member_facts(device)] |> Enum.join(" · ")
  end

  defp network_presence(device) do
    case device["online"] do
      true -> "Connected now · " <> path_words(device["path"])
      false -> "Not connected · " <> last_seen(device["last_seen"])
      _unreported -> "Presence not reported by the network client"
    end
  end

  # A member row carries facts the network client knows nothing about: whether this runtime
  # is actually talking to it, whether their builds agree, whether its runtime is up, and
  # when it last answered. Each is `nil` where this build could not establish it, and `nil`
  # is said as nothing at all rather than read as "no".
  defp member_facts(device) do
    [
      fact(device, "connected", "connected to this runtime", "not connected to this runtime"),
      fact(device, "compatible", "compatible build", "incompatible build"),
      fact(device, "runtime_running", "its runtime is running", "its runtime is not running"),
      probe(device)
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp fact(device, key, yes, no) do
    case Map.fetch(device, key) do
      {:ok, true} -> yes
      {:ok, false} -> no
      {:ok, nil} -> nil
      :error -> nil
      {:ok, other} -> "#{key} reported as #{plain(other, 32)}"
    end
  end

  # When this runtime last had an answer from that machine — the cluster's own observation,
  # which is a different question from when the network client last saw the device.
  defp probe(device) do
    case plain(device["last_probe"], 64) do
      at when is_binary(at) and at != "" -> "last answered this runtime at " <> at
      _unreported -> nil
    end
  end

  defp last_seen(seen) when is_binary(seen) and seen != "" do
    case plain(seen, 64) do
      "" -> "the client did not say when it last saw this device"
      when_seen -> "last seen " <> when_seen
    end
  end

  defp last_seen(_absent), do: "the client did not say when it last saw this device"

  @doc "How the network client reached a device, where it observed a path at all."
  @spec path_words(term()) :: String.t()
  def path_words("direct"), do: "a direct route was observed"
  def path_words("relayed"), do: "the connection runs through a relay, which is a working route"
  def path_words(_unknown), do: "the route was not reported"

  @doc """
  The note a device that has taken a roster machine's name gets.

  Rendered beside the row and never merged into it: a device calling itself by a member's
  name at a different address is either a mistake worth fixing or an attempt to be mistaken
  for that member, and listing it as that member would say neither.
  """
  @spec name_conflict(map()) :: String.t() | nil
  def name_conflict(device) when is_map(device) do
    case device["name_conflicts_with_roster"] do
      machine when is_binary(machine) and machine != "" ->
        "This device calls itself #{plain(machine, 64)}, which is the name of a machine in " <>
          "this fleet at a different address. It is not that machine."

      _none ->
        nil
    end
  end

  @doc """
  What the network discovery answered, as a headline and a next step.

  Every failure the adapter distinguishes gets its own pair, because "no devices" and "no
  client" and "signed out" are three different things to do something about, and one empty
  state for all of them is the empty state that teaches nothing.
  """
  @spec discovery(term()) :: {String.t(), String.t()}
  def discovery("ok"), do: {"The network client answered.", ""}

  def discovery("client_missing") do
    {"No network client is installed on this deployment host.",
     "Install Tailscale on the machine running this Ouroboros, and sign it in to the network the fleet uses. Known fleet members are still listed below, from this machine's own roster."}
  end

  def discovery("signed_out") do
    {"The network client is installed and this deployment host is signed out.",
     "Sign this machine in to the network, then refresh. Known fleet members are still listed below, from this machine's own roster."}
  end

  def discovery("permission_denied") do
    {"The network client refused this runtime's account.",
     "The account Ouroboros runs as may not query the local client. Known fleet members are still listed below, from this machine's own roster."}
  end

  def discovery("unavailable") do
    {"The network client is installed and could not answer.",
     "It may be stopped, still starting, or answering something this build cannot read. This is not evidence that the fleet has no members."}
  end

  def discovery("no_visible_peers") do
    {"The network client answered and can see no other devices.",
     "Network policy may limit what this client is shown. This list is that client's visible peers, not every device registered with the coordination server."}
  end

  def discovery(nil),
    do: {"This runtime did not report a discovery result.", "Refresh, or read the runtime's log."}

  def discovery(code) when is_binary(code) do
    {"The network client answered with a result this build does not recognise.",
     "The runtime reported #{code}. Known fleet members are still listed below, from this machine's own roster."}
  end

  def discovery(_unreadable),
    do: {"This runtime did not report a discovery result.", "Refresh, or read the runtime's log."}

  @doc "Whether discovery reached the network client at all."
  @spec discovered?(term()) :: boolean()
  def discovered?(code), do: code in ["ok", "no_visible_peers"]

  @doc """
  Why Deploy is not offered on this deployment host, in words.

  The reason codes arrive in a fixed order and the surface says the first one, because the
  first is the one an operator has to deal with before any of the others can matter.

  `posture` is `:standalone` for a machine in no fleet at all and `:fleet` for one that is.
  It changes exactly one sentence; see `no_ca_key` below.
  """
  @spec deploy_blocker(term(), :standalone | :fleet | nil) :: String.t()
  def deploy_blocker(code, posture \\ nil)

  def deploy_blocker("no_data_dir", _posture) do
    "This runtime serves no durable data directory, so it has nowhere to record a deployment."
  end

  # The one blocker whose sentence depends on a second fact. Holding no CA key means two
  # completely different things: a machine that is in a fleet somebody else issues for is a
  # joiner and should go to the issuer, and a machine in no fleet at all has simply not been
  # set up — and the control it needs is on its own row. Telling a standalone operator to
  # "open Devices on the machine that created the fleet" names a machine that does not exist.
  def deploy_blocker("no_ca_key", :standalone) do
    "This machine is not set up yet — use Set up this device. It holds no fleet of its own, " <>
      "so there is no certificate authority here to admit another machine with."
  end

  def deploy_blocker("no_ca_key", _in_a_fleet) do
    "This machine does not hold the fleet's certificate authority key, so it can describe " <>
      "the fleet but cannot admit a member. Open Devices on the machine that created the fleet."
  end

  def deploy_blocker("ouro_path_unknown", _posture) do
    "This runtime cannot say where its own `ouro` executable is, so it cannot start a " <>
      "deployment worker. Start Ouroboros through its launcher and reload this page."
  end

  def deploy_blocker("cleartext_web_bind", _posture) do
    "This web endpoint is published on a non-loopback address with no TLS of its own, so " <>
      "credential entry is refused here. Reach it through a loopback bind, or through " <>
      "`tailscale serve` in front of one."
  end

  def deploy_blocker(code, _posture) when is_binary(code) do
    "This runtime reported that deployment is unavailable here: #{plain(code, 64)}."
  end

  def deploy_blocker(_absent, _posture) do
    "This runtime did not say why deployment is unavailable here."
  end

  @doc """
  Why the inventory or the deployment controls are not available to this reader.

  The three answers are different facts and the proposal requires them to stay different:
  a build that does not serve the method, an endpoint whose scope may not run it, and an
  identity that is not an administrator.
  """
  @spec unavailable(atom(), String.t()) :: String.t()
  def unavailable(:absent, method) do
    "This runtime does not serve #{method}. It is an older build than this page; fleet " <>
      "membership is shown below, and deployment is not available here."
  end

  def unavailable(:scope, method) do
    "This endpoint was started with OUROBOROS_WEB_SCOPE=read, which may not run #{method}. " <>
      "Fleet membership is shown below; a read-only endpoint cannot start a setup or answer " <>
      "a credential prompt."
  end

  # Reached only where the method is available and the deployment host still says no with no
  # reason of its own, which is a runtime this build cannot explain rather than a rule.
  def unavailable(:available, _method),
    do: "This runtime did not say why deployment is unavailable here."

  def unavailable(:denied, method) do
    "The identity this session is authenticated as is not an administrator, and #{method} " <>
      "is administrator-only: the network inventory is every machine on an operator's " <>
      "private network. Fleet membership is shown below."
  end

  @doc """
  One deployment state, as the operator reads it.

  The proposal fixes the eleven states; a state outside them is named rather than mapped
  onto the nearest one this build happens to know.
  """
  @spec operation_state(term()) :: String.t()
  # Two states before the proposal's eleven begin: the broker answers `prepare` as soon as
  # the connection process exists, so an operation is visible while its handshake with the
  # worker is still running.
  def operation_state("spawning"), do: "Starting the deployment worker"
  def operation_state("attaching"), do: "Connecting to the deployment worker"
  def operation_state("attached"), do: "Connected to the deployment worker"
  def operation_state("inspecting"), do: "Inspecting the target"
  def operation_state("awaiting_host_trust"), do: "Waiting for you to verify the host key"
  def operation_state("awaiting_auth"), do: "Waiting for a credential"
  def operation_state("awaiting_review"), do: "Waiting for you to approve the plan"
  def operation_state("deploying"), do: "Deploying"
  def operation_state("restarting_host"), do: "Restarting the runtime on this machine"
  def operation_state("checking_readiness"), do: "Checking readiness"
  def operation_state("completed"), do: "Completed"
  def operation_state("interrupted"), do: "Interrupted"
  def operation_state("failed"), do: "Failed"
  def operation_state("cancelled"), do: "Cancelled"
  def operation_state(nil), do: "State not reported"

  def operation_state(state) when is_binary(state),
    do: "State this build does not recognise: #{state}"

  def operation_state(_unreadable), do: "State not reported"

  @doc """
  Whether an operation can still be continued.

  The broker refuses a resume of a `completed` or `cancelled` operation, so those two are
  finished here as well; everything else — including `failed` — is something an operator can
  still pick up.
  """
  @spec unfinished?(term()) :: boolean()
  def unfinished?(state), do: state not in ["completed", "cancelled"]

  @doc """
  How a row reads once an operation has touched the device it names.

  A deployment that just finished is the most important fact about a row, and the
  inventory's own `state` is a *discovery* fact that will not catch up until the next
  refresh reaches the network client. So a row whose latest operation is finished says so —
  and says which way it finished — rather than going back to reading "nothing has inspected
  this device" the moment the drawer closes.

  Returns `{state words, action label, event}`.
  """
  @spec operation_row(term()) :: {String.t(), String.t(), String.t()}
  @spec operation_row(term(), term()) :: {String.t(), String.t(), String.t()}
  def operation_row(state, kind \\ "add")

  def operation_row("completed", _kind),
    do: {"Set up just now by this machine", "Open device", "open-operation"}

  def operation_row("failed", _kind), do: {"Setup failed", "Retry", "open-operation"}

  def operation_row("cancelled", "setup"),
    do: {"Setup cancelled", "Set up this device", "setup-device"}

  def operation_row("cancelled", _kind), do: {"Setup cancelled", "Deploy again", "deploy"}

  def operation_row(state, _kind),
    do:
      {"Deployment waiting for input, interrupted or partially complete — " <>
         String.downcase(operation_state(state)), "Continue setup", "open-operation"}

  @doc "Whether a state means the operation is waiting for this operator."
  @spec waiting?(term()) :: boolean()
  def waiting?(state),
    do: state in ["awaiting_host_trust", "awaiting_auth", "awaiting_review"]

  # The engine's step names, joined to the proposal's six stages. Taken from every
  # `step_event` and `finish_step` call in `tui/src/fleet_setup/engine.rs` rather than
  # guessed at by prefix: `install_binary` is not `install`, `issue` is not any of the six
  # words, and a list that matched on prefixes would file both wrongly and in silence.
  @stages [
    {"inspect", "Inspect the target", ~w(inspect)},
    {"install", "Install Ouroboros if it is missing", ~w(install_binary install)},
    {"membership", "Configure fleet membership",
     ~w(prepare issue roster member_preflight create)},
    {"startup", "Configure startup", ~w(service stop_runtime)},
    {"connect", "Connect", ~w(connect)},
    {"readiness", "Check readiness", ~w(readiness)}
  ]

  # A step in words. `leave` and `disable_service` belong to cooperative removal and
  # `test_task` is the explicit first-task check, so none of the three is filed under one of
  # the six stages — they are drawn under their own names instead.
  @step_labels %{
    "inspect" => "Inspect the target",
    "install_binary" => "Install the `ouro` binary",
    "install" => "Install Ouroboros",
    "prepare" => "Prepare the target's profile",
    "issue" => "Issue the new member's certificate",
    "roster" => "Update a roster",
    "member_preflight" => "Check an existing member",
    "create" => "Create the fleet on this machine",
    "service" => "Install the startup service",
    "stop_runtime" => "Stop this runtime for the transition",
    "connect" => "Connect",
    "readiness" => "Check readiness",
    "test_task" => "Run the test task",
    "disable_service" => "Disable the startup service",
    "leave" => "Leave the fleet"
  }

  @doc """
  The six stages a deployment runs through, in the proposal's order, each with the worker's
  own step names under it.

  Drawn as an outline rather than as claims: a stage the worker has not reported a step for
  reads "not reported yet", which is the honest thing for a surface whose only knowledge of
  the remote machine is what a worker told it.
  """
  @spec stages() :: [{String.t(), String.t(), [String.t()]}]
  def stages, do: @stages

  @doc "Which of the six stages a step name belongs to, or `nil` for one that belongs to none."
  @spec stage_of(term()) :: String.t() | nil
  def stage_of(step) when is_binary(step),
    do: Enum.find_value(@stages, fn {key, _label, names} -> if step in names, do: key end)

  def stage_of(_other), do: nil

  @doc "One step's own name in words, or the name itself where this build has none for it."
  @spec step_label(term()) :: String.t()
  def step_label(step) when is_binary(step), do: Map.get(@step_labels, step, step)
  def step_label(_absent), do: "a step"

  @doc """
  One step's outcome in words, and whether it is a failure.

  The worker's vocabulary is four words — `started`, `ok`, `skipped`, `failed`
  (`StepRecord` in `tui/src/fleet_setup/journal.rs`) — and anything else is shown as itself
  rather than mapped onto the nearest one this build happens to know.

  Returns `{words, tone}` where tone is `:ok`, `:failed`, `:running` or `:unknown`. The tone
  is never the only carrier of the fact — it picks a mark that sits *beside* the words.
  """
  @spec outcome(term()) :: {String.t(), :ok | :failed | :running | :unknown}
  def outcome("ok"), do: {"done", :ok}
  def outcome("failed"), do: {"failed", :failed}
  def outcome("skipped"), do: {"skipped", :ok}
  def outcome("started"), do: {"running", :running}
  def outcome(nil), do: {"no outcome reported", :unknown}
  def outcome(value) when is_binary(value), do: {value, :unknown}
  def outcome(_unreadable), do: {"no outcome reported", :unknown}

  @doc """
  The heading one challenge is rendered under.

  Read from the challenge's kind alone. A remote prompt is data, never a label: the
  proposal's rule is that challenge labels are normalized rather than rendered as trusted
  UI, so nothing the worker sends becomes the heading of the box a password is typed into.
  """
  @spec challenge_title(term()) :: String.t()
  def challenge_title("password"), do: "Password for this connection"
  def challenge_title("passphrase"), do: "Passphrase for the selected key"
  def challenge_title("host_trust"), do: "Verify this host before continuing"
  def challenge_title("review"), do: "Review this plan"
  def challenge_title(kind) when is_binary(kind), do: "The runtime is waiting for: #{kind}"

  def challenge_title(_unreadable),
    do: "The runtime is waiting for something this page cannot read"

  @doc """
  One challenge's kind-specific facts.

  **The broker's snapshot is this page's contract, not the worker's wire.** The worker sends
  a challenge's kind-specific fields one level down, under `metadata`
  (`challenge_event/2` in `tui/src/fleet_setup/worker.rs`), and
  `Ouroboros.Fleet.Deployment.Client` lifts them to the top of the challenge on the way
  through — seam S4 describes them as fields *of the challenge*, so `challenge["port"]` is
  where they are by the time a surface sees one. Reading them nested was reading the wrong
  side of that seam, and drew a host-trust panel with every field empty.

  The nested shape is still merged where it survives, so a snapshot from either side of
  that fix renders the same; a challenge this build cannot read at all is an empty map,
  which makes every field below read "not reported" rather than raising.
  """
  @spec metadata(term()) :: map()
  def metadata(challenge) when is_map(challenge) do
    case challenge["metadata"] do
      nested when is_map(nested) -> Map.merge(challenge, nested)
      _lifted -> challenge
    end
  end

  def metadata(_absent), do: %{}

  @doc """
  The label under a masked field, naming what the secret is for.

  The two kinds name different things, and the proposal requires that: a password belongs
  to an account on a target, and a passphrase belongs to a key. Both come out of the
  worker's own metadata (`password_metadata/5` and `passphrase_metadata/2` in
  `tui/src/fleet_setup/challenge.rs`).
  """
  @spec secret_label(map()) :: String.t()
  def secret_label(%{"kind" => "passphrase"} = challenge) do
    case plain(metadata(challenge)["key_label"], 96) do
      label when is_binary(label) and label != "" -> "Passphrase for the key #{label}"
      _unnamed -> "Passphrase for the selected key"
    end
  end

  def secret_label(challenge) when is_map(challenge) do
    facts = metadata(challenge)

    case {plain(facts["user"], 64), plain(facts["target"], 96)} do
      {user, target} when is_binary(user) and user != "" and is_binary(target) and target != "" ->
        "Password for #{user}@#{target}"

      {user, _target} when is_binary(user) and user != "" ->
        "Password for #{user}"

      _unnamed ->
        "Password for this connection"
    end
  end

  @doc """
  "Attempt 2 of 3", where the worker said which attempt this is.

  `nil` when it did not: the cap is the server's as well as the worker's, and inventing a
  count would be this page claiming to know one.
  """
  @spec attempt(map()) :: String.t() | nil
  def attempt(challenge) when is_map(challenge) do
    facts = metadata(challenge)

    case {facts["attempt"], facts["max_attempts"]} do
      {attempt, max} when is_integer(attempt) and is_integer(max) ->
        "Attempt #{attempt} of #{max}."

      {attempt, _max} when is_integer(attempt) ->
        "Attempt #{attempt}."

      _unreported ->
        nil
    end
  end

  @doc """
  What the operation said about readiness, as `{sentence, offer a test task?}`.

  There is no `ready` flag on the wire. The worker's `done` frame carries `ok`, a state, a
  summary, a next step and what it could not establish, so readiness is read from the
  `readiness` step's own outcome — and where that step says `skipped`, which is what the
  engine records today because the owner-local readiness methods answer for the runtime
  they are asked rather than for the new member, this says so rather than claiming either
  answer.
  """
  @spec readiness(term(), term()) :: {String.t(), boolean()}
  def readiness(steps, done) do
    step = Enum.find(List.wrap(steps), &(is_map(&1) and &1["step"] == "readiness"))
    finished? = is_map(done) and done["ok"] == true

    case {step && step["outcome"], finished?} do
      {"ok", _finished?} ->
        {"This device reported that it is ready.", true}

      {"failed", _finished?} ->
        {"This device did not report itself ready. What is missing is below.", false}

      {"skipped", _finished?} ->
        {"Readiness was not established from here. " <>
           (plain(step["detail"]) || "The steps below say what was and was not checked."), true}

      {_unreported, true} ->
        {"The deployment finished. Readiness was not reported, so this page does not claim it.",
         true}

      {_unreported, _unfinished} ->
        {"Readiness was not reported.", false}
    end
  end

  @plan_fields ~w(schema operation kind deployment_host target release service members restart
                  grants build)

  @doc """
  The reviewed plan, in the order and the words the CLI's own review uses.

  `Plan::render/0` in `tui/src/fleet_setup/plan.rs` is the terminal's version of this
  screen, and the proposal asks the two surfaces to show one plan rather than two: the
  labels below are its labels — operation, action, machine, address, ssh, identity, host
  key, node, executable, data dir, install, startup, members, restart, and the grants — and
  the order is its order. What the raw document calls `install_path` and `data_dir` is not
  what an operator is shown.

  A row whose fact the plan does not carry is left out rather than printed as "not
  reported", again following the CLI: the absence of an `ssh` line on a local setup is the
  fact, not a gap in it.
  """
  @spec plan_rows(term()) :: [{String.t(), String.t()}]
  def plan_rows(plan) when is_map(plan) do
    target = plan["target"] || %{}

    [
      {"operation", text(plan["operation"])},
      {"action", plan_action(plan["kind"])},
      {"machine", text(target["machine"])},
      {"address", text(target["address"])},
      {"ssh", ssh_line(target)},
      {"identity", if(present?(target["ssh_user"]), do: text(target["identity"]))},
      {"host key", text(target["host_fingerprint"])},
      {"node", text(target["node"])},
      {"executable", text(target["install_path"])},
      {"data dir", text(target["data_dir"])},
      {"install", install_line(plan["release"])},
      {"origin", origin_line(plan["release"])},
      {"startup", startup_line(plan["service"])},
      {"members", members_line(plan["members"])},
      {"restart", text(plan["restart"])}
    ]
    |> Enum.reject(fn {_label, value} -> is_nil(value) end)
  end

  def plan_rows(_absent), do: []

  @doc """
  What approving this plan grants, in the plan's own sentences.

  Separate from `plan_rows/1` because the CLI sets them apart too — each one prefixed `!`
  under the facts — and because "what accepting this gives away" is the part of a plan an
  operator most needs not to skim past.
  """
  @spec plan_grants(term()) :: [String.t()]
  def plan_grants(plan) when is_map(plan), do: plan["grants"] |> List.wrap() |> Enum.map(&text/1)
  def plan_grants(_absent), do: []

  @doc """
  Whether a digest is the shape seam S6 fixes: sha256, lowercase hex, sixty-four characters.

  A digest is the *only* thing approval sends about the plan, so a surface that forwarded
  whatever string arrived would be offering an operator a button whose meaning it had not
  checked. Anything else is refused before Approve is drawn.
  """
  @spec digest?(term()) :: boolean()
  def digest?(digest) when is_binary(digest), do: String.match?(digest, ~r/\A[0-9a-f]{64}\z/)
  def digest?(_other), do: false

  @doc """
  This runtime's own sha256 of a plan, computed the way the worker computes it.

  `Plan::digest/0` in `tui/src/fleet_setup/plan.rs` is sha256 over `canonical_json` of the
  plan document (`tui/src/fleet_setup/mod.rs`): every object's keys sorted at every depth,
  arrays in order, scalars as `serde_json` writes them, and no whitespace anywhere. This is
  that, in Elixir, so approval can check that the digest it is about to send is a digest *of
  the plan on the screen* rather than a string the worker asked it to repeat. That the two
  agree is proved against a real worker in
  `test/ouroboros/web/live/devices_plan_digest_test.exs`.

  Returns `nil` for a plan this build cannot canonicalise, which is a reason to say so
  rather than to approve.
  """
  @spec plan_digest(term()) :: String.t() | nil
  def plan_digest(plan) when is_map(plan) do
    :crypto.hash(:sha256, canonical(plan)) |> Base.encode16(case: :lower)
  rescue
    _unencodable -> nil
  end

  def plan_digest(_absent), do: nil

  # `JSON.encode!` is the same encoder the rest of this tree uses, and it writes exactly what
  # `serde_json` writes for a scalar. What it does not do is sort keys, so objects are walked
  # and rebuilt in order; everything else is encoded whole.
  defp canonical(value) when is_map(value) do
    body =
      value
      |> Enum.sort_by(fn {key, _value} -> to_string(key) end)
      |> Enum.map_join(",", fn {key, field} ->
        JSON.encode!(to_string(key)) <> ":" <> canonical(field)
      end)

    "{" <> body <> "}"
  end

  defp canonical(value) when is_list(value),
    do: "[" <> Enum.map_join(value, ",", &canonical/1) <> "]"

  defp canonical(value), do: JSON.encode!(value)

  @doc "Every top-level key of a plan this build does not read, so nothing is cut in silence."
  @spec plan_unread(term()) :: [String.t()]
  def plan_unread(plan) when is_map(plan),
    do: plan |> Map.keys() |> Kernel.--(@plan_fields) |> Enum.sort()

  def plan_unread(_absent), do: []

  defp plan_action("setup"), do: "setup — this machine becomes its own fleet"
  defp plan_action("add"), do: "add — this device joins this fleet"
  defp plan_action("remove"), do: "remove — this device leaves this fleet"
  defp plan_action(kind) when is_binary(kind), do: kind
  defp plan_action(_absent), do: nil

  # The CLI prints an `ssh` line only where there is an account to print; a local setup
  # never reaches one, which is the point rather than a missing fact.
  defp ssh_line(target) do
    if present?(target["ssh_user"]) do
      "#{plain(target["ssh_user"], 64)}@#{text(target["address"]) || "this device"} port #{plain(target["port"], 8) || 22}"
    end
  end

  defp install_line(release) when is_map(release) do
    digest = release["sha256"]

    digest =
      if is_binary(digest) and digest != "",
        do: " sha256 #{String.slice(digest, 0, 16)}",
        else: ""

    "ouro #{text(release["version"]) || "an unnamed version"} (#{text(release["target"]) || "an unnamed platform"})" <>
      digest
  end

  defp install_line(_absent), do: "not needed; the target already has ouro"

  defp origin_line(%{"official_origin" => false}),
    do: "a loopback test origin, not the official release"

  defp origin_line(_official), do: nil

  defp startup_line("managed"),
    do: "propose a user service (starts at login; not a pre-login daemon)"

  defp startup_line("manual"), do: "manual start, explicitly chosen"
  defp startup_line(other) when is_binary(other), do: other
  defp startup_line(_absent), do: nil

  defp members_line(members) when is_list(members) and members != [] do
    Enum.map_join(members, "; ", fn member ->
      "#{text(member["machine"]) || "an unnamed machine"} (#{text(member["host"]) || "no host"}, " <>
        "#{text(member["change"]) || "no change"}, via #{text(member["reached_by"]) || "an unnamed route"})"
    end)
  end

  defp members_line(_none), do: "none"

  defp present?(value), do: is_binary(value) and value != ""

  # Every value in a plan came from a worker quoting a remote machine, so it goes through
  # the same sanitizer a step detail does.
  defp text(value) when is_binary(value), do: if(value == "", do: nil, else: plain(value))
  defp text(value) when is_number(value) or is_boolean(value), do: to_string(value)
  defp text(nil), do: nil
  defp text(value), do: value |> inspect(limit: 5) |> plain()

  @doc "The word for a device nobody named, used wherever a row has no name of its own."
  @spec this_device() :: String.t()
  def this_device, do: @this_device

  @doc """
  Whether a device row matches a search.

  Name and address, case-insensitively, as the proposal's "search by name/address" says —
  not the state, because a reader typing "offline" is looking for a word in a name.
  """
  @spec matches?(map(), String.t()) :: boolean()
  def matches?(_device, ""), do: true

  def matches?(device, query) when is_map(device) and is_binary(query) do
    needle = query |> String.trim() |> String.downcase()

    needle == "" or
      Enum.any?([device["name"], device["machine"], device["address"]], fn value ->
        is_binary(value) and String.contains?(String.downcase(value), needle)
      end)
  end
end
