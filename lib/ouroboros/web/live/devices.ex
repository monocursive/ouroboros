defmodule Ouroboros.Web.Live.Devices do
  @moduledoc """
  Every word the Devices page says about a code the runtime sent it.

  `fleet.devices` and `fleet.deployment.status` answer in stable snake_case codes —
  `discovered_installation_unknown`, `host_trust`, `cleartext_web_bind`, `worker_exited` —
  and none was addressed to a person. This module is the one place they become English,
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

  @doc "An independent host-key check, using only known OpenSSH key filenames."
  def host_key_command(algorithm) do
    file =
      case algorithm do
        algo when algo in ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"] ->
          "rsa"

        "ssh-ed25519" ->
          "ed25519"

        algo when algo in ["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"] ->
          "ecdsa"

        _ ->
          nil
      end

    if file, do: "ssh-keygen -lf /etc/ssh/ssh_host_#{file}_key.pub -E sha256"
  end

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

  @doc """
  A *name* from an untrusted field, or `nil` where there is nothing a reader could use.

  `plain/2` is the sanitiser and it answers about text in general: a boolean comes back as
  `"false"`, and a string that was only invisible characters comes back as `""`. Both are
  truthy, so a chain of `||` fallbacks written over `plain/2` stops at them — which is how
  the finish heading came to read "false is in your fleet", and how the manual form's hint
  came to read "the account on " with nothing after it.

  This is the reader for the one question "what is this machine called": only a binary can
  answer it, and an answer that sanitises to nothing is no answer. Every heading and hint
  that names a machine goes through here so that its `|| "that machine"` is reached.
  """
  @spec name(term()) :: String.t() | nil
  @spec name(term(), pos_integer()) :: String.t() | nil
  def name(value, limit \\ 64)

  def name(value, limit) when is_binary(value) do
    case plain(value, limit) do
      "" -> nil
      named -> named
    end
  end

  def name(_not_a_name, _limit), do: nil

  # ------------------------------------------------------------------------------------
  # The list
  # ------------------------------------------------------------------------------------

  @doc """
  A selection key for a web inventory row, independent of its deployment address.

  Network identity survives address and presence changes. Rows without any identity get a
  key scoped to this inventory read, rather than sharing an absent address with another row.
  This key is for Details only; deployment authorization still uses the address.
  """
  @spec row_id(map()) :: String.t()
  def row_id(device) do
    Enum.find_value(~w(stable_id node_key address machine), fn field ->
      case device[field] do
        value when is_binary(value) and value != "" -> field <> ":" <> value
        _absent -> nil
      end
    end) || "row:" <> Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
  end

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
  `set up just now`, or a removal's own `removing…`, `removal failed` and `removed just
  now` (`operation_words/2`).
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
  @spec status_line(term(), term(), boolean(), term()) :: String.t()
  def status_line(fleet, host_os, standalone?, devices \\ [])

  def status_line(_fleet, host_os, true, _devices),
    do: "#{self_label(host_os)} is not in a fleet yet."

  def status_line(fleet, _host_os, false, devices) when is_map(fleet) do
    connected = get_in(fleet, [:summary, :connected])
    expected = get_in(fleet, [:summary, :expected])

    [fleet_label(fleet, devices), machines_line(connected, expected)]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" · ")
  end

  def status_line(_fleet, _host_os, false, _devices), do: "This machine is in a fleet."

  # A fleet's name already reads as one ("studio's fleet"), so it stands alone; only a fleet
  # with *no* name is described by the machine that holds it, and it is described the way
  # `status_line/0` in `tui/src/ui/app/devices.rs` describes it. "This fleet is not named"
  # was the web saying which field was empty where the terminal said whose fleet it is.
  defp fleet_label(fleet, devices) do
    case name(fleet[:fleet_name], 96) do
      named when is_binary(named) -> named
      nil -> "Fleet of #{self_machine(devices)}"
    end
  end

  defp self_machine(devices) do
    devices
    |> List.wrap()
    |> Enum.find(&(is_map(&1) and self_row?(&1)))
    |> case do
      row when is_map(row) -> name(row["machine"], 96) || "this machine"
      _none -> "this machine"
    end
  end

  # Singular for a fleet of one, which is the fleet every first setup makes: "1 of 1
  # machines connected" is a plural about a single machine, and the terminal never said it.
  defp machines_line(connected, expected)
       when is_integer(connected) and is_integer(expected),
       do: "#{connected} of #{expected} machine#{if expected == 1, do: "", else: "s"} connected"

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

  def deploy_blocker("ouro_path_unknown", _posture) do
    "This runtime cannot say where its own `ouro` executable is, so it cannot run a " <>
      "setup. Start Ouroboros through its launcher and reload this page."
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

  Five states, fixed by §8 of `docs/proposals/fleet-kiss.md`: `running`, `waiting`,
  `completed`, `failed`, `cancelled`. A state outside them is named rather than mapped onto
  the nearest one this build happens to know.
  """
  @spec operation_state(term()) :: String.t()
  def operation_state("running"), do: "Setting up"
  def operation_state("waiting"), do: "Waiting for you"
  def operation_state("completed"), do: "Done"
  def operation_state("failed"), do: "Setup failed"
  def operation_state("cancelled"), do: "Cancelled"
  def operation_state(nil), do: "State not reported"

  def operation_state(state) when is_binary(state),
    do: "A state this build does not recognise: #{plain(state, 64)}"

  def operation_state(_unreadable), do: "State not reported"

  @doc """
  Whether an operation can still be continued.

  The runtime refuses a resume of a `completed` or `cancelled` operation, so those two are
  finished here as well; everything else — including `failed` — is something an operator can
  still pick up.
  """
  @spec unfinished?(term()) :: boolean()
  def unfinished?(state), do: state not in ["completed", "cancelled"]

  @doc "Whether a state means the operation is waiting for this operator."
  @spec waiting?(term()) :: boolean()
  def waiting?(state), do: state == "waiting"

  @doc """
  What an operation this machine is holding makes its device's row say, or `nil`.

  A setup that is running, waiting or has just finished is the freshest thing known about a
  device, and it outranks the inventory's `state` — which is a *discovery* fact that will
  not catch up until the network client notices. `nil` means it does not: a cancelled setup
  left the device exactly as discovery found it, so the row goes back to saying what
  discovery says rather than carrying "Setup cancelled" for the life of the journal.
  """
  @spec operation_words(term()) :: String.t() | nil
  @spec operation_words(term(), term()) :: String.t() | nil
  def operation_words(state, kind \\ nil)

  # No operation at all. `unfinished?/1` answers `true` for `nil` — an operation whose state
  # this build could not read is one an operator can still pick up — so without this clause
  # every row on the page read "setting up…" and offered Continue, which is exactly the
  # reading that would be wrong on all of them.
  def operation_words(nil, _kind), do: nil

  # A removal is not a setup, and a row that read "set up just now" after one had the words
  # exactly backwards: the machine had *left*. The state alone cannot say which — a
  # `completed` is a `completed` either way — so the operation's `kind` is what picks the
  # sentence, and this is the only place that decision is made.
  def operation_words(state, "leave") do
    cond do
      waiting?(state) -> "waiting for you"
      state == "failed" -> "removal failed"
      state == "completed" -> "removed just now"
      state == "cancelled" -> nil
      unfinished?(state) -> "removing…"
      true -> nil
    end
  end

  def operation_words(state, _kind) do
    cond do
      waiting?(state) -> "waiting for you"
      state == "failed" -> "setup failed"
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
  @spec operation_action(term(), term()) :: {String.t(), String.t()} | nil
  def operation_action(state, kind \\ nil)

  def operation_action(nil, _kind), do: nil

  # The other end of `operation_words/2`. A finished removal leaves a machine this fleet can
  # add again, so its row offers exactly that — **Open** would have sent an operator to the
  # machines panel to look for something that is no longer there.
  def operation_action(state, "leave") do
    cond do
      waiting?(state) -> {"Continue", "open-operation"}
      state == "failed" -> {"Retry", "open-operation"}
      state == "completed" -> {"Add to fleet", "deploy"}
      state == "cancelled" -> nil
      unfinished?(state) -> {"Continue", "open-operation"}
      true -> nil
    end
  end

  def operation_action(state, _kind) do
    cond do
      waiting?(state) -> {"Continue", "open-operation"}
      state == "failed" -> {"Retry", "open-operation"}
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
  What stopped an operation, in the runtime's own two fields, or `nil` where nothing did.

  §6's journal carries `last_error` as `{reason, detail}` — a stable snake_case code and a
  sentence — and §9's status answer passes it through from the journal or from the worker
  process. It replaces the old `worker_exit`: a program that dies before it can journal
  anything is now `worker_exited` with the exit status in the detail, and what it *printed*
  is in the operation's `log` rather than in a field of its own.
  """
  @spec last_error(term()) :: String.t() | nil
  def last_error(record) when is_map(record) do
    reason = plain(record["reason"], 64)
    detail = plain(record["detail"], 300)

    case {reason, detail} do
      {nil, nil} -> nil
      {nil, said} -> said
      {code, nil} -> error_words(code)
      {code, said} -> error_words(code) <> " " <> said
    end
  end

  def last_error(_absent), do: nil

  # The two codes this runtime itself produces read as sentences; everything else is the
  # program's own vocabulary and is printed as the code it is, because inventing an English
  # sentence for a code this build has never seen is how a page comes to describe something
  # that did not happen.
  defp error_words("worker_exited"), do: "The setup program stopped."

  defp error_words("worker_frame_too_large"),
    do: "The setup program wrote a frame too large to read."

  defp error_words("worker_answered_nothing"),
    do: "The setup program wrote something this page cannot read."

  defp error_words("challenge_expired"), do: "A prompt went unanswered for too long."
  defp error_words(code), do: "The setup stopped: #{code}."

  # §6's step names, one stage each, in the order the engine records them. Three lists
  # because there are three operations and they share only `inspect`; a single list would
  # have drawn "Install — not reported yet" on a removal that installs nothing, which is what
  # the 2026-09-18 review found.
  @add_stages [
    {"inspect", "Inspect"},
    {"install", "Install"},
    {"join", "Join fleet"},
    {"service", "Start at login"},
    {"start", "Start"},
    {"connect", "Connect"}
  ]

  @setup_stages [
    {"create", "Create fleet"},
    {"stop_runtime", "Stop"},
    {"service", "Start at login"},
    {"start", "Start"},
    {"ready", "Ready"}
  ]

  @leave_stages [
    {"stop", "Stop"},
    {"remove", "Remove"},
    {"forget", "Forget"}
  ]

  # A step in words, one sentence each.
  @step_labels %{
    "inspect" => "Read the machine",
    "install" => "Install Ouroboros",
    "join" => "Join the fleet",
    "service" => "Install the startup service",
    "start" => "Start Ouroboros",
    "connect" => "Connect",
    "create" => "Create the fleet on this machine",
    "stop_runtime" => "Stop this runtime for the transition",
    "ready" => "Check readiness",
    "stop" => "Stop Ouroboros there",
    "remove" => "Remove its fleet credentials",
    "forget" => "Forget it here"
  }

  @doc """
  The stages an operation of this kind runs through, in order.

  Short names, because §5.2 of the UX review draws them as one strip —
  `✓ Inspect · ✓ Install · ● Join fleet · ○ Start at login · ○ Start · ○ Connect` — rather
  than as six headed sections with a sentence each. `stages/0` is the add flow's, which is
  what an unqualified reading of "the stages" has always meant here.
  """
  @spec stages() :: [{String.t(), String.t()}]
  @spec stages(term()) :: [{String.t(), String.t()}]
  def stages(kind \\ nil)

  def stages("setup"), do: @setup_stages
  def stages("leave"), do: @leave_stages
  def stages(_add), do: @add_stages

  @doc "One step's own name in words, or the name itself where this build has none for it."
  @spec step_label(term()) :: String.t()
  def step_label(step) when is_binary(step), do: Map.get(@step_labels, step, step)
  def step_label(_absent), do: "a step"

  @doc """
  A step's state as `{word, tone}`, where the tone is for a stylesheet and the word is the
  one a reader gets.

  §6 fixes the four: `ok`, `failed`, `skipped`, `attempted`.
  """
  @spec outcome(term()) :: {String.t(), :ok | :failed | :running | :unknown}
  def outcome("ok"), do: {"done", :ok}
  def outcome("failed"), do: {"failed", :failed}
  def outcome("skipped"), do: {"skipped", :ok}
  def outcome("attempted"), do: {"running", :running}
  def outcome(nil), do: {"no outcome reported", :unknown}
  def outcome(value) when is_binary(value), do: {value, :unknown}
  def outcome(_unreadable), do: {"no outcome reported", :unknown}

  @doc """
  The mark a stage carries in the progress strip: done, running, or not yet.

  ✓, ● and ○ — and each of them sits beside the stage's name and its state in words, so the
  mark is a summary of something already said rather than the only place it is said.
  """
  @spec stage_mark(term()) :: String.t()
  def stage_mark("ok"), do: "✓"
  def stage_mark("skipped"), do: "✓"
  def stage_mark("failed"), do: "✗"
  def stage_mark("attempted"), do: "●"
  def stage_mark(_not_yet), do: "○"

  @doc """
  What a challenge is asking for, as its own heading.

  §5.2 names the first two after the thing they are about — the address a host key belongs
  to, the account a password is for — because "Verify this host before continuing" names a
  procedure and not a machine.
  """
  @spec challenge_title(term()) :: String.t()
  @spec challenge_title(term(), term()) :: String.t()
  def challenge_title(challenge_kind, operation_kind \\ nil)

  def challenge_title("password", _kind), do: "Password"
  def challenge_title("passphrase", _kind), do: "Passphrase for the selected key"
  def challenge_title("host_trust", _kind), do: "First time connecting"

  # The one challenge whose heading depends on what is being approved. "Ready to deploy"
  # over a plan that installs nothing and removes a machine was the page naming the wrong
  # procedure at the one step where an operator commits to it.
  def challenge_title("review", "leave"), do: "Ready to remove"
  def challenge_title("review", "setup"), do: "Ready to set up"
  def challenge_title("review", _add), do: "Ready to deploy"

  def challenge_title(kind, _operation_kind) when is_binary(kind),
    do: "The runtime is waiting for: #{kind}"

  def challenge_title(_unreadable, _operation_kind),
    do: "The runtime is waiting for something this page cannot name"

  @doc """
  The name on the button that approves a plan: **Deploy**, **Set up** or **Remove**.

  The same three words as `challenge_title("review", kind)`'s three headings, because a
  heading that says "Ready to remove" over a button that says "Deploy" is two answers to
  the one question an operator is being asked.
  """
  @spec approve_label(term()) :: String.t()
  def approve_label("leave"), do: "Remove"
  def approve_label("setup"), do: "Set up"
  def approve_label(_add), do: "Deploy"

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

  defp present?(value), do: is_binary(value) and value != ""

  @doc """
  "Attempt 2 of 3", where the program said so.

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
  What the operation said about readiness, as `{sentence, offer a test task?}`, where the
  sentence is `nil` when there is nothing worth saying.

  There is no `ready` flag on the wire. The worker's `done` frame carries `ok`, a state, a
  summary, a next step and what it could not establish, so readiness is read from the
  `readiness` step's own outcome — and where that step says `skipped`, which is what the
  engine records today because the owner-local readiness methods answer for the runtime
  they are asked rather than for the new member, this says so rather than claiming either
  answer.

  **Silence where the operation already answered.** A setup that finished with its
  `connect` step done has said what it did: the heading names the machine, the worker's
  summary says it joined and is connected. Following that with "The setup finished.
  Readiness was not reported, so this page does not claim it." is an epistemological
  disclaimer about a fact the two lines above just established — the 2026-09-18 live add
  showed all three stacked. So a completed operation whose connection is done says nothing
  more unless the `readiness` step itself reported and *failed*, which is the one case where
  the reader is being told something they do not already have.
  """
  @spec readiness(term(), term()) :: {String.t() | nil, boolean()}
  def readiness(steps, done) do
    steps = List.wrap(steps)
    step = Enum.find(steps, &(is_map(&1) and &1["step"] == "readiness"))
    finished? = is_map(done) and done["ok"] == true
    settled? = finished? and connected?(steps)

    case {step && step["outcome"], finished?, settled?} do
      {"failed", _finished?, _settled?} ->
        {"This machine did not report itself ready. What is missing is below.", false}

      {_any, _finished?, true} ->
        {nil, true}

      {"ok", _finished?, _settled?} ->
        {"This machine reported that it is ready.", true}

      {"skipped", _finished?, _settled?} ->
        {"Readiness was not established from here. " <>
           (plain(step["detail"]) || "The steps below say what was and was not checked."), true}

      {_unreported, true, _settled?} ->
        {"The setup finished. Readiness was not reported, so this page does not claim it.", true}

      {_unreported, _unfinished, _settled?} ->
        {"Readiness was not reported.", false}
    end
  end

  # Whether the operation got as far as connecting, from the `connect` step's own outcome.
  defp connected?(steps) do
    Enum.any?(steps, fn step ->
      is_map(step) and step["step"] == "connect" and step["outcome"] in ["ok", "skipped"]
    end)
  end

  # ------------------------------------------------------------------------------------
  # The plan
  # ------------------------------------------------------------------------------------

  @doc """
  The plan, as the lines an operator approves.

  §6 makes the plan a list of sentences — `Install ouro X (os arch) to PATH`, `Join FLEET as
  NAME`, `Start at login as a user service`, `Remember NAME on this machine` — rather than a
  document with a digest over it. There is nothing left to canonicalise, nothing to hash and
  nothing hidden behind a disclosure: what is shown *is* what is approved, and approving it
  is `fleet.deployment.respond` with `accept: true`.

  Every line came from a program quoting a remote machine, so each goes through the same
  sanitiser a step detail does, and anything that is not a line is dropped rather than
  inspected into one.
  """
  @spec review_lines(term()) :: [String.t()]
  def review_lines(plan) when is_list(plan) do
    plan
    |> Enum.take(50)
    |> Enum.map(&plain(&1, @max_text))
    |> Enum.reject(&(is_nil(&1) or &1 == ""))
  end

  def review_lines(_absent), do: []

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
  What removing a member does, in one sentence (§6).

  Named after the machine, because a confirmation that says "this device" is one an operator
  reads on the wrong row.
  """
  @spec leave_line(term()) :: String.t()
  def leave_line(machine) do
    named = plain(machine, 64) || "this machine"

    "Stop Ouroboros on #{named}, remove its fleet credentials and its startup service, " <>
      "forget it here. Its sessions and data stay on that machine."
  end

  @doc """
  What to do about a member that cannot be reached to be removed cooperatively.

  The engine's `leave` needs the machine to answer. When it will not, this machine's own
  members list still has to be cleaned up, and §5 gives that its own command: `ouro fleet
  forget NAME` removes NAME here and asks the runtime to retire NAME's session-owner
  evidence. The command name is the operator's statement, and there is no tombstone and no
  restore behind it.

  Only ever shown on a failure that describes an unreachable machine (`unreachable?/1`):
  printing a repair under a form nobody has submitted is a page reporting a failure before
  an attempt.
  """
  @spec leave_fallback(term()) :: String.t()
  def leave_fallback(machine) do
    named = plain(machine, 64) || "that machine"

    "#{named} did not answer, so nothing on it was changed. To take it out of this fleet " <>
      "anyway, run `ouro fleet forget #{named}` on this machine."
  end

  # These reasons can also occur after a session was established. Callers must additionally
  # establish from the recorded steps that the target was never reached before offering
  # the irreversible fallback. Authentication and host-key refusals have their own repairs.
  @unreachable ~w(ssh_unavailable ssh_timeout connection_lost)

  @doc """
  Whether a failure's stable reason can describe an unreachable member.

  The `reason` on `last_error`, which is a code rather than a sentence — the sentence beside
  it is the operator's, this is the page's.
  """
  @spec unreachable?(term()) :: boolean()
  def unreachable?(reason) when is_binary(reason), do: reason in @unreachable
  def unreachable?(_other), do: false

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
