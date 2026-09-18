defmodule Ouroboros.Web.Live.Devices do
  @moduledoc """
  Every word the Devices page says about a code the runtime sent it.

  `fleet.devices` and `fleet.deployment.status` answer in stable snake_case codes —
  `discovered_installation_unknown`, `signed_out`, `awaiting_host_trust`, `no_ca_key` — and
  none of them was addressed to a person. This module is the one place they become English,
  for the same reason `Ouroboros.Web.Presentation` exists: a phrase invented at the call
  site is a phrase the next call site spells differently.

  ## The words are a person's, not the specification's

  Until the 2026-09-18 fleet review this module answered out of the proposal's
  observed-state table, verbatim — a row read "Discovered peer; Ouroboros installation
  unknown" and its button said "Deploy Ouroboros opens preflight". That table is a
  requirement written for the people building the thing, and rendering it as interface text
  made every row an instruction to its own implementer. §5 of
  `docs/design-qa/fleet-ux-review-2026-09-18.md` replaces the vocabulary, and this module is
  where the replacement lives: **a row is a device, a device has one state and one thing you
  can do about it.**

  The states themselves did not change and neither did their codes. What a row says about
  Ouroboros is now one of nine short phrases (`ouroboros_words/1`), what it offers is one of
  six button names (`row_action/1`) or nothing at all, and presence is a dot, a word and a
  *relative* time (`presence_word/2`, `relative_time/2`) rather than five facts joined with
  interpuncts. The exact instant goes in the details panel, where somebody who wants it has
  asked for it.

  The codes still never reach a reader. They reach the markup as `data-state`, where a test
  can name a row without depending on its wording and a stylesheet can draw one without the
  wording carrying the meaning on its own — rule: no state by colour alone, and no state by
  code either.

  ## What this may not do

  Claim. Every sentence here describes what was reported, and where nothing was reported it
  says so. "Not connected" is not "powered off", "not set up" is not "cannot be set up", and
  a network client that could not answer is not a fleet with no members.
  """

  @this_device "this machine"

  # How much of one peer-controlled string this page will draw. The CLI's own sanitizer caps
  # at 300 for the same reason: one runaway remote must not own the screen.
  @max_text 300

  # The longest a fleet machine name may be, which is also the cap §5.5 puts on the slug
  # `ouro fleet devices --json` derives for `suggested_machine`.
  @max_machine 40

  # What a row says about Ouroboros, from `ouro fleet devices --json`'s `state`. Nine
  # phrases, fixed by §5.1, and every one of them is something a person would say out loud.
  # `this_device` is the current machine already set up, which is an ordinary member that
  # happens to be here.
  @ouroboros_words %{
    "this_device" => "in the fleet",
    "this_device_without_profile" => "not set up",
    "fleet_member" => "in the fleet",
    "fleet_member_connected" => "in the fleet",
    "fleet_member_not_visible" => "in the fleet · not connected",
    "discovered_installation_unknown" => "not set up",
    "peer_offline" => "offline",
    "unsupported_platform" => "can't run Ouroboros",
    "no_usable_ipv4" => "can't run Ouroboros"
  }

  # One button per row, or none. The self row that is already a member opens the machines
  # panel; a member opens its own details, which is where Remove from fleet lives (§5.4); a
  # peer nothing has inspected is the one row that offers to add it. Everything else — a
  # peer that is offline, a platform with no release, an address family this build cannot
  # reach — offers nothing, because there is nothing it could do, and the reason is in the
  # words next to it rather than behind a button that refuses.
  @row_actions %{
    "this_device" => {"Open", "open-machines"},
    "fleet_member" => {"Details", "inspect-device"},
    "fleet_member_connected" => {"Details", "inspect-device"},
    "fleet_member_not_visible" => {"Details", "inspect-device"},
    "discovered_installation_unknown" => {"Add to fleet", "deploy"},
    # Nothing can be *done* to these — no release, no route, nothing answering — so none of
    # them offers an action. What they offer is the reason, which is what section 5.1's
    # "the reason is in its details" promises and what the row's one word can only summarise.
    "peer_offline" => {"Details", "inspect-device"},
    "unsupported_platform" => {"Details", "inspect-device"},
    "no_usable_ipv4" => {"Details", "inspect-device"}
  }

  # The rows that belong to this fleet rather than to the network around it. Used for the
  # ordering (§5.1: the self row, then members, then peers) and for the filter that appears
  # only past eight rows.
  @fleet_states ~w(this_device this_device_without_profile fleet_member fleet_member_connected
                   fleet_member_not_visible)

  # This machine's own row, whichever way round it is.
  @self_states ~w(this_device this_device_without_profile)

  # The blockers that stand between a device and any deployment. They are facts the network
  # client reported, and the row offers nothing while one of them stands rather than
  # offering something that refuses when pressed.
  @blocked_states ~w(peer_offline unsupported_platform no_usable_ipv4)

  @doc """
  One string that came from somewhere this runtime does not control, made safe to read.

  HEEx escapes markup, which stops injection and nothing else. What it does not stop is a
  peer *lying about what it is called*: `U+202E` reverses the characters after it, a
  zero-width space splits a name into two that read as one, and a tab or a newline inside a
  table cell rearranges the row. A device names itself, and this page puts that name next to
  an Add to fleet button.

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

  # ------------------------------------------------------------------------------------
  # The list
  # ------------------------------------------------------------------------------------

  @doc """
  What this machine is called on its own row: **This Mac** on a Mac, **This machine**
  everywhere else.

  From `host.os`, which is `:os.type/0`'s second element — `darwin` on macOS. A noun rather
  than an adjective, because the row labelled with it is the one an operator is standing in
  front of, and "this device" is what the review found on screen where a real name should
  have been.
  """
  @spec self_label(term()) :: String.t()
  def self_label("darwin"), do: "This Mac"
  def self_label(_other), do: "This machine"

  @doc "Whether this row is the machine the runtime is on, set up or not."
  @spec self_row?(map()) :: boolean()
  def self_row?(device) when is_map(device), do: device["state"] in @self_states
  def self_row?(_other), do: false

  @doc """
  Where a row sorts: this machine first, then the fleet's members, then everything else.

  One list, in one order, which is §5.1's first requirement. `Enum.sort_by/2` is stable, so
  within each of the three the runtime's own order survives — and the runtime's order is the
  network client's, which is the order the same devices appear in on the CLI.
  """
  @spec group(map()) :: 0 | 1 | 2
  def group(device) when is_map(device) do
    cond do
      self_row?(device) -> 0
      device["state"] in @fleet_states -> 1
      true -> 2
    end
  end

  @doc "Whether a row belongs to this fleet rather than to the network around it."
  @spec fleet_row?(map()) :: boolean()
  def fleet_row?(device) when is_map(device), do: device["state"] in @fleet_states

  @doc """
  What this row says about Ouroboros, in one short phrase.

  The nine of §5.1 and no others: `in the fleet`, `in the fleet · not connected`,
  `not set up`, `can't run Ouroboros`, `offline` — and, from an operation this machine is
  holding rather than from discovery, `setting up…`, `waiting for you`, `setup failed` and
  `set up just now` (`operation_words/1`).
  """
  @spec ouroboros_words(term()) :: String.t()
  def ouroboros_words(device) when is_map(device), do: ouroboros_words(device["state"])

  def ouroboros_words(state) when is_binary(state),
    do: Map.get(@ouroboros_words, state, "state not recognised")

  def ouroboros_words(_absent), do: "state not reported"

  @doc """
  The one button this row offers, as `{label, event}`, or `nil` for a row that offers none.

  §5.1: "A device that cannot be acted on shows no button; the reason is in its details."
  An offline peer, a platform with no release and an address family this build cannot reach
  all fall through to `nil` — there is no honest action, and a disabled button carrying an
  explanation was the shape the review found unreadable.
  """
  @spec row_action(map()) :: {String.t(), String.t()} | nil
  @spec row_action(map(), term()) :: {String.t(), String.t()} | nil
  def row_action(device, host_os \\ nil)

  # The machine with no fleet of its own offers nothing on its row: its one action is the
  # primary button beside the status line, which is where section 5.1 puts it and where an
  # operator who has just read "This Mac is not in a fleet yet" is already looking. Two
  # copies of one button is two things to decide between.
  def row_action(%{"state" => "this_device_without_profile"}, _host_os), do: nil

  def row_action(device, _host_os) when is_map(device), do: Map.get(@row_actions, device["state"])
  def row_action(_other, _host_os), do: nil

  @doc """
  The primary button's own name: **Set up this Mac**, or **Set up this machine**.

  Lower-cased after the verb, because "Set up This Mac" is a label nobody writes by hand.
  """
  @spec setup_label(term()) :: String.t()
  def setup_label(host_os),
    do: "Set up " <> String.replace_prefix(self_label(host_os), "This", "this")

  @doc """
  Whether a blocker this listing established stands between this device and a deployment.

  Offline, unsupported platform and no usable IPv4 are facts the network client reported,
  and they are why the row offers nothing.
  """
  @spec blocked?(map()) :: boolean()
  def blocked?(device) when is_map(device), do: device["state"] in @blocked_states

  @doc "Whether this row is a device an SSH deployment can be aimed at."
  @spec deployable?(map()) :: boolean()
  def deployable?(device) when is_map(device) do
    device["state"] == "discovered_installation_unknown" and is_binary(device["address"])
  end

  @doc "Whether this row has a details panel to open."
  @spec inspectable?(map()) :: boolean()
  def inspectable?(device) when is_map(device),
    do: device["state"] in ~w(fleet_member fleet_member_connected fleet_member_not_visible
                            peer_offline unsupported_platform no_usable_ipv4)

  def inspectable?(_other), do: false

  @doc """
  Whether this row is a member this fleet can be asked to remove (§5.4).

  The self row is not one: a machine does not take itself out of its own roster from its own
  Devices page, and the engine's `leave` names a *target* machine.
  """
  @spec removable?(map()) :: boolean()
  def removable?(device) when is_map(device) do
    device["state"] in ~w(fleet_member fleet_member_connected fleet_member_not_visible) and
      is_binary(device["machine"]) and device["machine"] != ""
  end

  def removable?(_other), do: false

  @doc """
  Whether this row is **this machine, with no fleet profile of its own**.

  The one action that is not a deployment: this machine configures itself, without SSH to
  itself.
  """
  @spec setup?(map()) :: boolean()
  def setup?(device) when is_map(device), do: device["state"] == "this_device_without_profile"

  @doc """
  The name to put in the setup form's *Name in the fleet* field, and never `name`.

  `suggested_machine` is §5.5's: the roster name for a member, otherwise the display name
  folded to a valid machine name, otherwise `null`. The review's finding 3 is what happens
  without it — both forms pre-filled with a display name ("Monocursive's MacBook Pro", or
  the placeholder "this device") and the web submitted it. So this reads exactly that field
  and falls back to an empty box rather than to something that looks like an answer.
  """
  @spec suggested_machine(term()) :: String.t()
  def suggested_machine(device) when is_map(device) do
    case plain(device["suggested_machine"], @max_machine) do
      name when is_binary(name) -> if valid_machine?(name), do: name, else: ""
      _absent -> ""
    end
  end

  def suggested_machine(_absent), do: ""

  @doc """
  Whether a string is a fleet machine name: letters, digits and hyphens, starting with a
  letter or a digit, at most #{@max_machine} characters.

  The worker refuses anything else, and the review's finding 2 is a form that let one
  through: the manual "Deploy to an address" had no name field at all, so the worker took
  the address as the name and refused it after a connection, a host key and a password.
  """
  @spec valid_machine?(term()) :: boolean()
  def valid_machine?(name) when is_binary(name) do
    String.length(name) <= @max_machine and String.match?(name, ~r/\A[a-zA-Z0-9][a-zA-Z0-9-]*\z/)
  end

  def valid_machine?(_other), do: false

  @doc "What to say under a *Name in the fleet* box that was left empty or filled wrongly."
  @spec machine_error(term()) :: String.t() | nil
  def machine_error(name) do
    trimmed = if is_binary(name), do: String.trim(name), else: ""

    cond do
      trimmed == "" -> "This machine needs a name in the fleet."
      valid_machine?(trimmed) -> nil
      true -> "Letters, digits and hyphens only, starting with a letter or a digit."
    end
  end

  # ------------------------------------------------------------------------------------
  # Presence
  # ------------------------------------------------------------------------------------

  @doc """
  The mark beside a presence word. Never the only thing saying it.

  A filled ring is connected, a hollow one is not, and a device the client reported nothing
  about gets a dash rather than either. The word next to it says the same thing, which is
  the rule: no state by colour, and none by shape either.
  """
  @spec presence_dot(map()) :: String.t()
  def presence_dot(device) when is_map(device) do
    case device["online"] do
      true -> "●"
      false -> "○"
      _unreported -> "–"
    end
  end

  @doc """
  Presence as a person reads it: a word, and a relative time where the client gave one.

  "online", "offline, seen 3 days ago", "offline" where the client saw it but never said
  when, and "presence not reported" where it said nothing at all — which is not "offline".
  The exact instant is `exact_time/1`, in the details panel, because §5.1 bans an ISO
  timestamp from a row and the review found one on every row with microseconds on it.
  """
  @spec presence_word(map()) :: String.t()
  @spec presence_word(map(), DateTime.t()) :: String.t()
  def presence_word(device, now \\ DateTime.utc_now())

  def presence_word(device, now) when is_map(device) do
    case device["online"] do
      true ->
        "online"

      false ->
        case relative_time(device["last_seen"], now) do
          ago when is_binary(ago) -> "offline, seen " <> ago
          nil -> "offline"
        end

      _unreported ->
        "presence not reported"
    end
  end

  @doc """
  An instant, as long ago as it was: "just now", "3 min ago", "2 hours ago", "3 days ago".

  `nil` for anything this build cannot read as a time, so a caller can fall back rather than
  print a placeholder that looks like an observation. A time in the future — two clocks that
  disagree, which is ordinary on a private network — reads as "just now" rather than as a
  negative age.

  `now` is an argument so that a test states the instant it is asking about instead of
  racing the wall clock.
  """
  @spec relative_time(term()) :: String.t() | nil
  @spec relative_time(term(), DateTime.t()) :: String.t() | nil
  def relative_time(value, now \\ DateTime.utc_now())

  def relative_time(value, now) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, at, _offset} -> ago(DateTime.diff(now, at, :second))
      _unreadable -> nil
    end
  end

  def relative_time(_absent, _now), do: nil

  defp ago(seconds) when seconds < 60, do: "just now"
  defp ago(seconds) when seconds < 3_600, do: count(div(seconds, 60), "min")
  defp ago(seconds) when seconds < 86_400, do: count(div(seconds, 3_600), "hour")
  defp ago(seconds), do: count(div(seconds, 86_400), "day")

  # "min" is already the abbreviation; "3 mins ago" is a word nobody needs.
  defp count(amount, "min"), do: "#{amount} min ago"
  defp count(1, unit), do: "1 #{unit} ago"
  defp count(amount, unit), do: "#{amount} #{unit}s ago"

  @doc "The exact instant the network client last saw a device, for the details panel only."
  @spec exact_time(term()) :: String.t()
  def exact_time(value), do: plain(value, 64) || "not reported"

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

  # ------------------------------------------------------------------------------------
  # The page's own lines
  # ------------------------------------------------------------------------------------

  @doc """
  The one quiet line under the title: where the work actually happens.

  The review's finding 9 is what this replaces — a three-line boxed paragraph on the page
  *and* again inside every drawer, explaining SSH to somebody who had not asked to do
  anything yet. The fact still matters, because a browser three hops away cannot lend its
  own SSH agent to the runtime, so it stays; it is one sentence, under the title, and the
  caption inside a drawer.
  """
  @spec host_line(term()) :: String.t()
  def host_line(host) when is_map(host) do
    machine = plain(host["hostname"], 96) || @this_device
    user = plain(host["user"], 64)

    case user do
      account when is_binary(account) -> "Actions run on #{machine} as #{account}."
      nil -> "Actions run on #{machine}."
    end
  end

  def host_line(_absent), do: "Actions run on the machine hosting this runtime."

  @doc """
  The status line above the list, and whether it is the standalone one.

  Two shapes, from §5.1. A machine in no fleet says so in the status line itself —
  "This Mac is not in a fleet yet" — with **Set up this Mac** beside it, and that sentence
  *is* the blocker notice rather than a second paragraph repeating it. A machine in a fleet
  names the fleet and counts its members.
  """
  @spec status_line(term(), term(), boolean()) :: String.t()
  def status_line(fleet, host_os, standalone?)

  def status_line(_fleet, host_os, true), do: "#{self_label(host_os)} is not in a fleet yet."

  def status_line(fleet, _host_os, false) when is_map(fleet) do
    name = plain(fleet[:fleet_name], 96)
    connected = get_in(fleet, [:summary, :connected])
    expected = get_in(fleet, [:summary, :expected])

    [
      # A fleet's name already reads as one ("studio's fleet"), so it stands alone.
      name || "This fleet is not named",
      machines_line(connected, expected)
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" · ")
  end

  def status_line(_fleet, _host_os, false), do: "This machine is in a fleet."

  defp machines_line(connected, expected)
       when is_integer(connected) and is_integer(expected),
       do: "#{connected} of #{expected} machines connected"

  defp machines_line(_connected, _expected), do: nil

  @doc """
  The discovery notice, in the network client's own words, or `nil` when it answered.

  §5.1: one inline notice quoting the runtime's `detail`, and **never a claim about build
  age**. The review's finding 1 is a Mac with the Tailscale app installed, where the client
  the runtime found printed "The Tailscale GUI failed to start" and exited 0 — and this page
  read that as "this build of Ouroboros may be older than the client", which is a guess
  about a version dressed as a diagnosis. The client said something; this says what it said.
  """
  @spec discovery_notice(term(), term()) :: String.t() | nil
  def discovery_notice(code, detail \\ nil)

  def discovery_notice("ok", _detail), do: nil

  # No discovery result at all is a fact about this runtime, not about the network client.
  # Saying "Tailscale did not answer" here would be the page claiming an observation nobody
  # made, which is the one thing this module may not do.
  def discovery_notice(nil, _detail) do
    "This runtime did not report a discovery result. Devices already in the fleet are " <>
      "still listed."
  end

  def discovery_notice("no_visible_peers", _detail) do
    "Tailscale answered and can see no other devices. Devices already in the fleet are " <>
      "still listed."
  end

  def discovery_notice(_code, detail) do
    case plain(detail, 200) do
      said when is_binary(said) and said != "" ->
        ~s{Tailscale did not answer from this runtime: "#{said}". } <>
          "Devices already in the fleet are still listed."

      _nothing ->
        "Tailscale did not answer from this runtime. Devices already in the fleet are " <>
          "still listed."
    end
  end

  @doc """
  Why the page is not offering to set a machine up, in words.

  The reason codes arrive in a fixed order and the surface says the first one, because the
  first is the one an operator has to deal with before any of the others can matter.

  `posture` is `:standalone` for a machine in no fleet at all and `:fleet` for one that is.
  It changes exactly one sentence; see `no_ca_key` below.
  """
  @spec deploy_blocker(term(), :standalone | :fleet | nil) :: String.t()
  def deploy_blocker(code, posture \\ nil)

  def deploy_blocker("no_data_dir", _posture) do
    "This runtime serves no durable data directory, so it has nowhere to record a setup."
  end

  # The one blocker whose sentence depends on a second fact. Holding no CA key means two
  # completely different things: a machine that is in a fleet somebody else issues for is a
  # joiner and should go to the issuer, and a machine in no fleet at all has simply not been
  # set up — and the control it needs is on its own row.
  def deploy_blocker("no_ca_key", :standalone) do
    "This machine is not in a fleet yet, so there is no authority here to admit another " <>
      "machine with. Set this machine up first."
  end

  def deploy_blocker("no_ca_key", _in_a_fleet) do
    "This machine does not hold the fleet's certificate authority key, so it can describe " <>
      "the fleet but cannot admit a member. Open Devices on the machine that created the fleet."
  end

  def deploy_blocker("ouro_path_unknown", _posture) do
    "This runtime cannot say where its own `ouro` executable is, so it cannot start a " <>
      "setup worker. Start Ouroboros through its launcher and reload this page."
  end

  def deploy_blocker("cleartext_web_bind", _posture) do
    "This web endpoint is published on a non-loopback address with no TLS of its own, so " <>
      "credential entry is refused here. Reach it through a loopback bind, or through " <>
      "`tailscale serve` in front of one."
  end

  # §5.5. A Mix dev runtime can build the fleet and then never start it: the LaunchAgent it
  # writes runs a binary that exits 1 with "built without an embedded release" (finding 8,
  # which was silent). It blocks `setup` and nothing else — adding a machine over SSH
  # installs a packaged release on the *target*, which this runtime's own shape says
  # nothing about.
  def deploy_blocker("dev_runtime", _posture) do
    "This is a development runtime; the packaged `ouro` is what sets a machine up."
  end

  def deploy_blocker(code, _posture) when is_binary(code) do
    "This runtime reported that setup is unavailable here: #{plain(code, 64)}."
  end

  def deploy_blocker(_absent, _posture) do
    "This runtime did not say why setup is unavailable here."
  end

  @doc """
  Why the inventory or the setup controls are not available to this reader.

  The three answers are different facts and they stay different: a build that does not serve
  the method, an endpoint whose scope may not run it, and an identity that is not an
  administrator.
  """
  @spec unavailable(atom(), String.t()) :: String.t()
  def unavailable(:absent, method) do
    "This runtime does not serve #{method}. It is an older build than this page; fleet " <>
      "membership is shown below, and setup is not available here."
  end

  def unavailable(:scope, method) do
    "This endpoint was started with OUROBOROS_WEB_SCOPE=read, which may not run #{method}. " <>
      "Fleet membership is shown below; a read-only endpoint cannot start a setup or answer " <>
      "a credential prompt."
  end

  # Reached only where the method is available and the deployment host still says no with no
  # reason of its own, which is a runtime this build cannot explain rather than a rule.
  def unavailable(:available, _method),
    do: "This runtime did not say why setup is unavailable here."

  def unavailable(:denied, method) do
    "The identity this session is authenticated as is not an administrator, and #{method} " <>
      "is administrator-only: the network inventory is every machine on an operator's " <>
      "private network. Fleet membership is shown below."
  end

  # ------------------------------------------------------------------------------------
  # Operations
  # ------------------------------------------------------------------------------------

  @doc """
  One deployment state, as the operator reads it.

  The eleven states are fixed by the proposal; a state outside them is named rather than
  mapped onto the nearest one this build happens to know.
  """
  @spec operation_state(term()) :: String.t()
  # Two states before the eleven begin: the broker answers `prepare` as soon as the
  # connection process exists, so an operation is visible while its handshake with the
  # worker is still running.
  def operation_state("spawning"), do: "Starting the setup worker"
  def operation_state("attaching"), do: "Connecting to the setup worker"
  def operation_state("attached"), do: "Connected to the setup worker"
  def operation_state("inspecting"), do: "Reading the machine"
  def operation_state("awaiting_host_trust"), do: "Waiting for you to check the host key"
  def operation_state("awaiting_auth"), do: "Waiting for a password"
  def operation_state("awaiting_review"), do: "Waiting for you to approve the plan"
  def operation_state("deploying"), do: "Setting up"
  def operation_state("restarting_host"), do: "Restarting Ouroboros on this machine"
  def operation_state("checking_readiness"), do: "Checking readiness"
  def operation_state("completed"), do: "Done"
  def operation_state("interrupted"), do: "Interrupted"
  def operation_state("failed"), do: "Setup failed"
  def operation_state("cancelled"), do: "Cancelled"
  def operation_state(nil), do: "State not reported"

  def operation_state(state) when is_binary(state),
    do: "A state this build does not recognise: #{plain(state, 64)}"

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
  What an operation this machine is holding makes its device's row say, or `nil`.

  A setup that is running, waiting or has just finished is the freshest thing known about a
  device, and it outranks the inventory's `state` — which is a *discovery* fact that will
  not catch up until the network client notices. `nil` means it does not: a cancelled setup
  left the device exactly as discovery found it, so the row goes back to saying what
  discovery says rather than carrying "Setup cancelled" for the life of the journal.
  """
  @spec operation_words(term()) :: String.t() | nil
  # No operation at all. `unfinished?/1` answers `true` for `nil` — an operation whose state
  # this build could not read is one an operator can still pick up — so without this clause
  # every row on the page read "setting up…" and offered Continue, which is exactly the
  # reading that would be wrong on all of them.
  def operation_words(nil), do: nil

  def operation_words(state) do
    cond do
      waiting?(state) -> "waiting for you"
      state in ["failed", "interrupted"] -> "setup failed"
      state == "completed" -> "set up just now"
      state == "cancelled" -> nil
      unfinished?(state) -> "setting up…"
      true -> nil
    end
  end

  @doc """
  The button an operation puts on its device's row, as `{label, event}`, or `nil`.

  Only while there is something to go back to: a finished setup leaves the row's own action
  (Open, or Details), and a cancelled one leaves the row offering to start again.
  """
  @spec operation_action(term()) :: {String.t(), String.t()} | nil
  def operation_action(nil), do: nil

  def operation_action(state) do
    cond do
      waiting?(state) -> {"Continue", "open-operation"}
      state in ["failed", "interrupted"] -> {"Retry", "open-operation"}
      # The machine is in the fleet now, whatever discovery still says, so the row opens
      # the machines panel. Falling through to the device's own action would offer to add
      # a machine that has just been added.
      state == "completed" -> {"Open", "open-machines"}
      state == "cancelled" -> nil
      unfinished?(state) -> {"Continue", "open-operation"}
      true -> nil
    end
  end

  @doc """
  What a worker that died without finishing left behind, in its own last words.

  §5.5: `fleet.deployment.status` carries `worker_exit` when the journal is unfinished, no
  `done` frame exists and the worker is gone. The review's finding 5 is the page without it
  — the worker's own log had the reason (a Unix socket path over 104 bytes), the broker
  logged `lost its worker: :normal`, and the operation sat at "inspecting" saying nothing.

  `nil` where there is no such record, so the ordinary "no worker is attached" reading
  stands rather than being overwritten by an empty accusation.
  """
  @spec worker_exit(term()) :: String.t() | nil
  def worker_exit(record) when is_map(record) do
    said =
      record["last_lines"]
      |> List.wrap()
      |> Enum.map(&plain(&1, 200))
      |> Enum.reject(&(is_nil(&1) or &1 == ""))
      |> Enum.join(" · ")

    case {said, record["code"]} do
      {"", code} when is_integer(code) -> "The setup worker stopped with status #{code}."
      {"", _no_code} -> nil
      {said, _code} -> "The setup worker stopped: " <> said
    end
  end

  def worker_exit(_absent), do: nil

  # The engine's step names, joined to the six stages. Taken from every `step_event` and
  # `finish_step` call in `tui/src/fleet_setup/engine.rs` rather than guessed at by prefix:
  # `install_binary` is not `install`, `issue` is not any of the six words, and a list that
  # matched on prefixes would file both wrongly and in silence.
  @stages [
    {"inspect", "Inspect", ~w(inspect)},
    {"install", "Install", ~w(install_binary install)},
    {"membership", "Join fleet", ~w(prepare issue roster member_preflight create)},
    {"startup", "Start at login", ~w(service stop_runtime)},
    {"connect", "Connect", ~w(connect)},
    {"readiness", "Ready", ~w(readiness)}
  ]

  # A step in words. `leave` and `disable_service` belong to cooperative removal and
  # `test_task` is the explicit first-task check, so none of the three is filed under one of
  # the six stages — they are drawn under their own names instead.
  @step_labels %{
    "inspect" => "Read the machine",
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
  The six stages a setup runs through, in order, each with the worker's own step names.

  Short names, because §5.2 draws them as one strip —
  `✓ Inspect · ✓ Install · ● Join fleet · ○ Start at login · ○ Connect · ○ Ready` — rather
  than as six headed sections with a sentence each.
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
  A step's outcome as `{word, tone}`, where the tone is for a stylesheet and the word is
  the one a reader gets.
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
  The mark a stage carries in the progress strip: done, running, or not yet.

  ✓, ● and ○ — and each of them sits beside the stage's name and its outcome in words, so
  the mark is a summary of something already said rather than the only place it is said.
  """
  @spec stage_mark(term()) :: String.t()
  def stage_mark("ok"), do: "✓"
  def stage_mark("skipped"), do: "✓"
  def stage_mark("failed"), do: "✗"
  def stage_mark("started"), do: "●"
  def stage_mark(_not_yet), do: "○"

  @doc """
  What a challenge is asking for, as its own heading.

  §5.2 names the first two after the thing they are about — the address a host key belongs
  to, the account a password is for — because "Verify this host before continuing" names a
  procedure and not a machine.
  """
  @spec challenge_title(term()) :: String.t()
  def challenge_title("password"), do: "Password"
  def challenge_title("passphrase"), do: "Passphrase for the selected key"
  def challenge_title("host_trust"), do: "First time connecting"
  def challenge_title("review"), do: "Ready to deploy"
  def challenge_title(kind) when is_binary(kind), do: "The runtime is waiting for: #{kind}"

  def challenge_title(_unreadable),
    do: "The runtime is waiting for something this page cannot name"

  @doc "A host-trust heading that names the address, where the worker reported one."
  @spec host_trust_title(term()) :: String.t()
  def host_trust_title(address) do
    case plain(address, 64) do
      at when is_binary(at) and at != "" -> "First time connecting to #{at}"
      _absent -> challenge_title("host_trust")
    end
  end

  @doc "A password heading that names the account, where the worker reported one."
  @spec password_title(term(), term()) :: String.t()
  def password_title(user, address) do
    account = plain(user, 64)
    at = plain(address, 64)

    cond do
      is_binary(account) and is_binary(at) -> "Password for #{account}@#{at}"
      is_binary(account) -> "Password for #{account}"
      true -> challenge_title("password")
    end
  end

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
  The label over the one masked field, naming what is being asked for and what for.

  A passphrase is for a key this operator chose; a password is for an account on a machine.
  Two different secrets, and a field labelled only "Password" is the one an operator types
  the wrong one into.
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
    user = plain(facts["user"], 64)
    target = plain(facts["target"] || facts["address"], 64)

    cond do
      present?(user) and present?(target) -> "Password for #{user}@#{target}"
      present?(user) -> "Password for #{user}"
      true -> "Password for this connection"
    end
  end

  @doc """
  "Attempt 2 of 3", where the worker said so.

  `password_metadata/5` carries `attempt` and `max_attempts`; a passphrase carries neither,
  and this answers `nil` rather than inventing a first attempt.
  """
  @spec attempt(map()) :: String.t() | nil
  def attempt(challenge) when is_map(challenge) do
    facts = metadata(challenge)

    case {facts["attempt"], facts["max_attempts"]} do
      {attempt, max} when is_integer(attempt) and is_integer(max) ->
        "attempt #{attempt} of #{max}"

      {attempt, _absent} when is_integer(attempt) ->
        "attempt #{attempt}"

      _none ->
        nil
    end
  end

  def attempt(_absent), do: nil

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
        {"This machine reported that it is ready.", true}

      {"failed", _finished?} ->
        {"This machine did not report itself ready. What is missing is below.", false}

      {"skipped", _finished?} ->
        {"Readiness was not established from here. " <>
           (plain(step["detail"]) || "The steps below say what was and was not checked."), true}

      {_unreported, true} ->
        {"The setup finished. Readiness was not reported, so this page does not claim it.", true}

      {_unreported, _unfinished} ->
        {"Readiness was not reported.", false}
    end
  end

  # ------------------------------------------------------------------------------------
  # The plan
  # ------------------------------------------------------------------------------------

  @plan_fields ~w(schema operation kind deployment_host target release service members restart
                  grants build)

  @doc """
  The plan as five plain lines, which is what §5.2's review step shows.

  `Install ouro 0.1.9 (Linux arm64) to ~/.local/bin/ouro`, `Join the fleet as raspberrypi`,
  `Start at login as a user service`, `Update 1 roster (this Mac)`, and the trust sentence.
  The whole document is still there — `plan_rows/1` draws every field of it behind a
  disclosure, and the digest covers the document rather than these five lines — but what an
  operator approves is a thing they can read in one breath.

  A line whose fact the plan does not carry is left out rather than printed as "not
  reported": the absence of a startup line on a plan that installs no service is the fact.
  """
  @spec review_lines(term()) :: [String.t()]
  def review_lines(plan) when is_map(plan) do
    target = plan["target"] || %{}

    [
      review_install(plan["release"], target["install_path"]),
      review_join(plan["kind"], target["machine"]),
      review_startup(plan["service"]),
      review_roster(plan["members"]),
      review_trust(plan["grants"])
    ]
    |> Enum.reject(&is_nil/1)
  end

  def review_lines(_absent), do: []

  defp review_install(release, install_path) when is_map(release) do
    version = text(release["version"])
    where = text(install_path)

    case {version, where} do
      {nil, _where} ->
        nil

      {version, nil} ->
        "Install ouro #{version} (#{release_words(release["target"])})"

      {version, where} ->
        "Install ouro #{version} (#{release_words(release["target"])}) to #{where}"
    end
  end

  defp review_install(_absent, _install_path), do: nil

  defp review_join("leave", machine) when is_binary(machine) and machine != "",
    do: "Take #{plain(machine, 64)} out of the fleet"

  defp review_join(_kind, machine) when is_binary(machine) and machine != "",
    do: "Join the fleet as #{plain(machine, 64)}"

  defp review_join(_kind, _absent), do: nil

  defp review_startup("managed"), do: "Start at login as a user service"
  defp review_startup("manual"), do: "Do not start at login; this machine is started by hand"
  defp review_startup(other) when is_binary(other), do: "Startup: #{plain(other, 64)}"
  defp review_startup(_absent), do: nil

  defp review_roster(members) when is_list(members) and members != [] do
    names =
      members
      |> Enum.map(fn member -> is_map(member) and text(member["machine"]) end)
      |> Enum.filter(&is_binary/1)

    count = length(members)
    noun = if count == 1, do: "roster", else: "rosters"

    case names do
      [] -> "Update #{count} #{noun}"
      named -> "Update #{count} #{noun} (#{Enum.join(named, ", ")})"
    end
  end

  defp review_roster(_none), do: nil

  # The grants are the part of a plan an operator most needs not to skim past, so they are
  # the last line rather than a list somewhere under it.
  defp review_trust(grants) do
    said = grants |> List.wrap() |> Enum.map(&text/1) |> Enum.reject(&is_nil/1)

    case said do
      [] -> nil
      lines -> Enum.join(lines, " ")
    end
  end

  @doc """
  A Rust target triple as the two words a person would use for it.

  `aarch64-unknown-linux-gnu` is "Linux arm64". A triple this build cannot read is printed
  as itself rather than guessed at: it is still the exact thing being installed.
  """
  @spec release_words(term()) :: String.t()
  def release_words(triple) when is_binary(triple) do
    system =
      cond do
        String.contains?(triple, "linux") -> "Linux"
        String.contains?(triple, "darwin") or String.contains?(triple, "apple") -> "macOS"
        String.contains?(triple, "windows") -> "Windows"
        true -> nil
      end

    arch =
      cond do
        String.contains?(triple, "aarch64") or String.contains?(triple, "arm64") -> "arm64"
        String.contains?(triple, "x86_64") -> "x86-64"
        true -> nil
      end

    case {system, arch} do
      {nil, _arch} -> plain(triple, 64)
      {_system, nil} -> plain(triple, 64)
      {system, arch} -> "#{system} #{arch}"
    end
  end

  def release_words(_absent), do: "platform not reported"

  @doc """
  What removing a member does, in one sentence (§5.4).

  Named after the machine, because a confirmation that says "this device" is one an operator
  reads on the wrong row.
  """
  @spec leave_line(term()) :: String.t()
  def leave_line(machine) do
    named = plain(machine, 64) || "this machine"

    "Stop Ouroboros on #{named}, retire its credentials, take it out of every roster. " <>
      "Its sessions and data stay on that machine."
  end

  @doc """
  What to do about a member that cannot be reached to be removed cooperatively.

  The engine's `leave` needs the machine to answer. When it will not, the roster still has
  to be cleaned up, and the recipe for that is the CLI's — named here rather than left as a
  failure with no way forward.
  """
  @spec leave_fallback(term()) :: String.t()
  def leave_fallback(machine) do
    named = plain(machine, 64) || "that machine"

    "#{named} did not answer, so nothing on it was changed. To take it out of this fleet's " <>
      "roster anyway, run `ouro fleet sessions forget #{named}` on this machine."
  end

  @doc """
  The reviewed plan, in the order and the words the CLI's own review uses.

  `Plan::render/0` in `tui/src/fleet_setup/plan.rs` is the terminal's version of this
  screen, and the two surfaces show one plan rather than two: the labels below are its
  labels and the order is its order. What the raw document calls `install_path` and
  `data_dir` is not what an operator is shown.

  Behind a disclosure since the 2026-09-18 review — `review_lines/1` is what the step leads
  with — because a fifteen-row table is a thing an operator scrolls past rather than reads,
  and the five lines above it say the same plan.
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
  """
  @spec digest?(term()) :: boolean()
  def digest?(digest) when is_binary(digest), do: String.match?(digest, ~r/\A[0-9a-f]{64}\z/)
  def digest?(_other), do: false

  @doc """
  This page's own sha256 of the plan it is showing.

  Seam S6: the digest a client approves is the digest the client computed, over the document
  it rendered, so that "approve exactly what was shown" is a property of this page rather
  than a promise from the other side.

  **Every object's keys are sorted, at every depth**, because `canonical_json` in
  `tui/src/fleet_setup/mod.rs` sorts them and the two have to agree byte for byte or no plan
  is ever approvable. Elixir's own map iteration is not that order: it coincides with it for
  a map of at most 32 keys and stops coinciding above, so a page that relied on it would
  agree with the worker on every plan anyone happened to test and disagree on a larger one,
  with "the digest this operation offered is not this page's own sha256" as the only symptom.
  """
  @spec plan_digest(term()) :: String.t() | nil
  def plan_digest(plan) when is_map(plan) do
    :sha256 |> :crypto.hash(canonical(plan)) |> Base.encode16(case: :lower)
  rescue
    _exception -> nil
  end

  def plan_digest(_absent), do: nil

  # `JSON.encode!` is the same encoder the rest of this tree uses, and it writes exactly what
  # `serde_json` writes for a scalar. What it does not do is sort keys, so every object is
  # sorted here — by the key as a string, which is the comparison the Rust side makes —
  # and everything else is encoded whole.
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
    do: plan |> Map.keys() |> Enum.map(&to_string/1) |> Kernel.--(@plan_fields) |> Enum.sort()

  def plan_unread(_absent), do: []

  defp plan_action("setup"), do: "setup — this machine becomes its own fleet"
  defp plan_action("add"), do: "add — this device joins this fleet"
  defp plan_action("leave"), do: "leave — this device is taken out of this fleet"
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

  Name, roster name and address, case-insensitively — not the state, because a reader typing
  "offline" is looking for a word in a name.
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
