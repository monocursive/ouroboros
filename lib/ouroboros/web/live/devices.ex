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
    "fleet_member_not_visible" => "Diagnose",
    "peer_offline" => "Refresh or inspect",
    "unsupported_platform" => "Nothing to deploy",
    "no_usable_ipv4" => "Nothing to deploy",
    "this_device" => "View device",
    "this_device_without_profile" => "Set up this device"
  }

  # The two sections of the inventory. A code this build does not know is filed under
  # "Available on this network", which is the side that makes no claim about membership.
  @fleet_states ~w(this_device this_device_without_profile fleet_member fleet_member_not_visible)

  # The blockers that must disable deployment while they stand (the table's fifth row).
  @blocked_states ~w(peer_offline unsupported_platform no_usable_ipv4)

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
    case device["online"] do
      true -> "Connected now · " <> path_words(device["path"])
      false -> "Not connected · " <> last_seen(device["last_seen"])
      _unreported -> "Presence not reported by the network client"
    end
  end

  defp last_seen(seen) when is_binary(seen) and seen != "", do: "last seen " <> seen
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
        "This device calls itself #{machine}, which is the name of a machine in this " <>
          "fleet at a different address. It is not that machine."

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
  """
  @spec deploy_blocker(term()) :: String.t()
  def deploy_blocker("no_data_dir") do
    "This runtime serves no durable data directory, so it has nowhere to record a deployment."
  end

  def deploy_blocker("no_ca_key") do
    "This machine does not hold the fleet's certificate authority key, so it can describe " <>
      "the fleet but cannot admit a member. Open Devices on the machine that created the fleet."
  end

  def deploy_blocker("ouro_path_unknown") do
    "This runtime cannot say where its own `ouro` executable is, so it cannot start a " <>
      "deployment worker. Start Ouroboros through its launcher and reload this page."
  end

  def deploy_blocker("cleartext_web_bind") do
    "This web endpoint is published on a non-loopback address with no TLS of its own, so " <>
      "credential entry is refused here. Reach it through a loopback bind, or through " <>
      "`tailscale serve` in front of one."
  end

  def deploy_blocker(code) when is_binary(code) do
    "This runtime reported that deployment is unavailable here: #{code}."
  end

  def deploy_blocker(_absent) do
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

  @doc "Whether a state means the operation is waiting for this operator."
  @spec waiting?(term()) :: boolean()
  def waiting?(state),
    do: state in ["awaiting_host_trust", "awaiting_auth", "awaiting_review"]

  @doc """
  The six stages a deployment runs through, in the proposal's order.

  Drawn as an outline rather than as claims: a stage the worker has not reported a step for
  reads "not reported yet", which is the honest thing for a surface whose only knowledge of
  the remote machine is what a worker told it.
  """
  @spec stages() :: [{String.t(), String.t()}]
  def stages do
    [
      {"inspect", "Inspect the target"},
      {"install", "Install Ouroboros if it is missing"},
      {"membership", "Configure fleet membership"},
      {"startup", "Configure startup"},
      {"connect", "Connect"},
      {"readiness", "Check readiness"}
    ]
  end

  @doc """
  One step's outcome in words, and whether it is a failure.

  Returns `{words, tone}` where tone is `:ok`, `:failed`, `:running` or `:unknown`. The tone
  is never the only carrier of the fact — it picks a mark that sits *beside* the words.
  """
  @spec outcome(term()) :: {String.t(), :ok | :failed | :running | :unknown}
  def outcome(value) when value in ["ok", "success", "succeeded", "done", "completed"],
    do: {"done", :ok}

  def outcome(value) when value in ["failed", "error", "refused"], do: {"failed", :failed}
  def outcome("skipped"), do: {"skipped", :ok}

  def outcome(value) when value in ["running", "started", "in_progress"],
    do: {"running", :running}

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

  @doc "The label under a masked field, naming what the secret is for."
  @spec secret_label(map()) :: String.t()
  def secret_label(%{"kind" => "passphrase"} = challenge) do
    case challenge["key"] || challenge["identity"] do
      ref when is_binary(ref) and ref != "" -> "Passphrase for #{ref}"
      _unnamed -> "Passphrase for the selected key"
    end
  end

  def secret_label(challenge) when is_map(challenge) do
    case {challenge["user"], challenge["host"] || challenge["address"]} do
      {user, host} when is_binary(user) and is_binary(host) -> "Password for #{user}@#{host}"
      {user, _host} when is_binary(user) -> "Password for #{user}"
      _unnamed -> "Password for this connection"
    end
  end

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
