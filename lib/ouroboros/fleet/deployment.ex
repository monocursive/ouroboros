defmodule Ouroboros.Fleet.Deployment do
  @moduledoc """
  The runtime-local broker for deploying Ouroboros onto another machine.

  A deployment is a long, interruptible, credential-carrying operation that must survive the
  page that started it, the listener that started it, and — during first local fleet setup —
  the runtime that started it. So the work does not happen here. It happens in a temporary
  Rust worker that `ouro fleet worker start` forks detached, with its own session and process
  group and its stdio on a private log, and which this runtime then *connects to*. This
  module is the connection, the operation registry beside it, and nothing else.

  What that buys, stated plainly: closing the drawer does not cancel the deployment, and
  stopping the BEAM does not either. What it costs: this runtime is never the authority on
  what happened. The worker's journal is (seam S5), and when no worker is alive this reads
  that journal — read-only, sanitized — rather than reporting its own last memory.

  ## The three seams

    * **S1, where `ouro` is.** `Ouroboros.Fleet.Deployment.Launcher`, which reads the
      absolute path the launcher exported and never `PATH`.
    * **S3, the wire.** NDJSON over a private Unix socket, one line per frame, a 1 MiB cap,
      first frame `attach` carrying the contents of the worker's own capability file. One
      `Ouroboros.Fleet.Deployment.Client` process per operation holds it.
    * **S5, the journal.** `Ouroboros.Fleet.Deployment.Journal`, opened for reading only.

  ## Where the secret is, and is not

  `authenticate/4` is the only function in this module that takes a credential, and it is the
  only one that does not run in the broker. It asks the broker for the operation's client
  *pid*, and then calls that process directly from the caller's own process. The broker is a
  named singleton: a secret that passed through it would sit in the mailbox and the crash
  dump of a process every deployment shares. This way the only two processes that ever hold
  those bytes are the one that received them from the wire and the one that writes them to
  the socket.

  The Rust worker ships with `ouro`. A runtime paired with an older executable that
  does not serve `fleet worker start` returns a stable refusal.
  """

  use GenServer

  require Logger

  alias Ouroboros.Fleet.Deployment.Client
  alias Ouroboros.Fleet.Deployment.Journal
  alias Ouroboros.Fleet.Deployment.Launcher

  @supervisor Ouroboros.Fleet.Deployment.ClientSupervisor

  # `ouro fleet devices --json` asks the local network client and returns; S10 fixes its
  # ceiling at ten seconds, which is above a slow client and well below the method's own.
  @devices_timeout 10_000
  # The worker's listen deadline is 20s (`LISTEN_DEADLINE` in the Rust worker). A 10s
  # ceiling SIGKILL'd the parent while the grandchild was still starting, then deleted the
  # request it was about to read. 25s is above that deadline with room for scheduling.
  @spawn_timeout 25_000
  @call_timeout 20_000

  # An operation id names a Unix socket path, and `sun_path` is 104 bytes on this platform.
  # Eight random bytes is 2^64 of identity in sixteen characters, which leaves a data
  # directory room to be somewhere a person chose.
  @operation_bytes 8

  # How many `ouro fleet devices --json` children may be in flight at once across this whole
  # runtime, and how many recent attach failures are kept so `status` can explain one.
  @max_devices 4
  @max_failures 32

  # A journal state the operation cannot be continued from.
  @terminal ~w(completed cancelled)

  @typedoc "Who is asking: the audited identity, and the browser or listener session."
  @type binding :: %{subject: String.t(), session: String.t()}

  @doc false
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  The supervised pair: the client supervisor, then the broker that starts children in it.

  In that order, because the broker starts children in the supervisor and so needs it first.
  They sit under `Ouroboros.Surface.Supervisor`, which is `:one_for_one` — so a broker crash
  does **not** restart the client supervisor beside it, and the connections it was tracking
  outlive the process that was tracking them. That is why `init/1` reaps them: the ordering
  is what a supervisor gives, and the adoption problem is solved in code rather than
  asserted in a comment.
  """
  @spec children() :: [Supervisor.child_spec() | {module(), keyword()}]
  def children do
    [
      {DynamicSupervisor, strategy: :one_for_one, name: @supervisor},
      __MODULE__
    ]
  end

  # ---------------------------------------------------------------------------
  # Reads

  @doc """
  The Devices inventory: this host, what its network client can see, and what it may do.

  Runs in the caller's process rather than in the broker, because it is a bounded read that
  must not queue behind somebody else's worker spawn — a ten-second external command inside
  a named singleton is a ten-second stall for every other operation.
  """
  @spec devices(keyword()) :: {:ok, map()} | {:error, term()}
  def devices(opts \\ []) do
    data_dir = Keyword.get(opts, :data_dir) || data_dir()
    timeout = Keyword.get(opts, :timeout, @devices_timeout)

    # Each call forks `ouro` and may hold half a megabyte of its output. Running in the
    # caller keeps a slow inventory from stalling every other operation, but it also means
    # nothing serialises these — a page that refreshes in a loop, or a client that retries,
    # would otherwise be able to fork as many children as it liked. The slot is released by
    # the broker on this process's `:DOWN`, so a caller that dies mid-call does not leak one.
    case acquire_devices() do
      :ok ->
        try do
          run_devices(timeout, data_dir)
        after
          release_devices()
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp run_devices(timeout, data_dir) do
    case Launcher.run(["fleet", "devices", "--json"], timeout) do
      {:ok, output} ->
        case JSON.decode(output) do
          {:ok, document} when is_map(document) -> {:ok, inventory(document, data_dir)}
          _unreadable -> {:error, :devices_unreadable}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp acquire_devices do
    GenServer.call(__MODULE__, :acquire_devices, @call_timeout)
  catch
    :exit, _reason -> {:error, :no_data_dir}
  end

  defp release_devices do
    GenServer.cast(__MODULE__, {:release_devices, self()})
  catch
    :exit, _reason -> :ok
  end

  # An allowlist rather than a merge. What `ouro` prints is a document this build reads three
  # named keys out of; a key it grows later is reported in `unknown` — the convention
  # `runtime.activity` already uses — rather than flowing into a reply whose shape nobody
  # here has checked.
  defp inventory(document, data_dir) do
    listed = operations(data_dir)
    devices = Journal.scrub_value(document["devices"]) || []

    %{
      "host" => host(data_dir),
      # The fleet's own name, for the line above the list. `fleet.status` carries it too,
      # but a surface that reads only this method — the terminal client — drew "Fleet of
      # <machine>" for a fleet that has a name of its own.
      "fleet_name" => fleet_name(data_dir),
      "discovery" => Journal.scrub_value(document["discovery"]),
      "devices" => merge_cluster(devices, cluster_facts()),
      "fleet_protocol_revision" => document["fleet_protocol_revision"],
      "operations" => elem(listed, 0),
      "operations_total" => elem(listed, 1),
      "unknown" =>
        document
        |> Map.keys()
        |> Kernel.--(["discovery", "devices", "fleet_protocol_revision"])
        |> Enum.sort()
    }
  end

  @doc """
  This deployment host's own identity and what it is currently able to do.

  `issuer` is whether the fleet CA *private* key is on this machine, which is what makes this
  runtime able to admit a new member at all rather than merely describe one. `capabilities`
  is the answer to "can Deploy be offered here", with every reason it cannot, so a surface
  renders a disabled action with a sentence instead of an action that fails when pressed.
  """
  @spec host(Path.t() | nil) :: map()
  def host(data_dir \\ nil) do
    dir = data_dir || data_dir()
    issuer? = issuer?(dir)
    reasons = deploy_blockers(dir, issuer?)

    %{
      "hostname" => hostname(),
      "user" => System.get_env("USER") || System.get_env("LOGNAME"),
      "os" => :os.type() |> elem(1) |> Atom.to_string(),
      "arch" => :erlang.system_info(:system_architecture) |> List.to_string(),
      "issuer" => issuer?,
      "capabilities" => %{"deploy" => reasons == [], "reasons" => reasons}
    }
  end

  # `:inet.gethostname/0` is specified to answer `{:ok, name}` and nothing else; matching it
  # is the honest shape rather than a fallback clause dialyzer can prove dead.
  @doc """
  This host's own name, which is what a first local setup calls this device by default.

  Public because `fleet.deployment.prepare` needs it for a `setup` the caller did not name a
  machine for: the worker requires one, and the honest default for "set up *this* device" is
  what this device is already called.
  """
  @spec host_name() :: String.t()
  def host_name do
    {:ok, name} = :inet.gethostname()
    List.to_string(name)
  end

  defp hostname, do: host_name()

  # A roster is a handful of `{machine, host, node}` triples. A profile larger than this is
  # not one, and it is refused rather than parsed.
  @max_profile_bytes 512 * 1024

  @doc "The fleet's name from this machine's profile, or `nil` for a standalone machine."
  @spec fleet_name(Path.t() | nil) :: String.t() | nil
  def fleet_name(data_dir \\ nil) do
    case profile_document(data_dir) do
      %{"name" => name} when is_binary(name) and name != "" -> Journal.scrub_value(name)
      _standalone -> nil
    end
  end

  # The profile as a document, bounded and read as the roster reads it; `nil` for a
  # standalone machine, an unreadable profile, or no data directory.
  defp profile_document(data_dir) do
    with dir when is_binary(dir) <- data_dir || data_dir(),
         profile = Path.join([dir, "fleet", "profile.json"]),
         {:ok, %File.Stat{type: :regular, size: size}} when size <= @max_profile_bytes <-
           File.lstat(profile),
         {:ok, body} <- File.read(profile),
         {:ok, document} when is_map(document) <- JSON.decode(body) do
      document
    else
      _none -> nil
    end
  end

  @doc """
  This machine's roster: every member of the fleet profile it holds, `machine` and `host`.

  Public because `fleet.deployment.prepare` needs it for a `leave`. The CLI reads the same
  file for the same reason (`leave_machine` in `tui/src/fleet_setup/cli.rs`): the operator
  names a member, and where that member *is* is a fact this machine already recorded when it
  admitted them. Asking the caller for the address instead would let one machine be removed
  from the roster while a different one was contacted.

  `[]` for a standalone machine, an unreadable profile, or no data directory — to a caller
  those are one fact, "this machine has no roster", and the refusal it produces says so.
  """
  @spec roster(Path.t() | nil) :: [%{optional(String.t()) => String.t()}]
  def roster(data_dir \\ nil) do
    with dir when is_binary(dir) <- data_dir || data_dir(),
         profile = Path.join([dir, "fleet", "profile.json"]),
         {:ok, %File.Stat{type: :regular, size: size}} when size <= @max_profile_bytes <-
           File.lstat(profile),
         {:ok, body} <- File.read(profile),
         {:ok, %{"members" => members}} when is_list(members) <- JSON.decode(body) do
      for %{"machine" => machine, "host" => host} <- members,
          is_binary(machine) and machine != "" and is_binary(host) and host != "",
          do: %{"machine" => machine, "host" => host}
    else
      _no_roster -> []
    end
  end

  @doc """
  The roster entry for one machine name, matched the way the rest of the fleet matches names.

  `tui/src/fleet.rs`'s `same_name/2` is `eq_ignore_ascii_case`, and an operator whose roster
  carries a mixed-case entry from an older build has to be able to name it.
  """
  @spec roster_member(String.t(), Path.t() | nil) :: {:ok, map()} | :error
  def roster_member(machine, data_dir \\ nil) when is_binary(machine) do
    wanted = String.downcase(machine)

    case Enum.find(roster(data_dir), &(String.downcase(&1["machine"]) == wanted)) do
      nil -> :error
      member -> {:ok, member}
    end
  end

  # The CA key is what an issuer has and a member does not (`tui/src/fleet.rs` writes
  # `ca-key.pem` only on the machine that created the fleet). `lstat` rather than `exists?`:
  # a symlink where the key should be is not this machine holding the key.
  defp issuer?(nil), do: false

  defp issuer?(data_dir) do
    case File.lstat(Path.join([data_dir, "fleet", "ca-key.pem"])) do
      {:ok, %File.Stat{type: :regular}} -> true
      _other -> false
    end
  end

  # Stable codes, in a fixed order, because a surface renders them and a test names them.
  # New codes are appended rather than inserted, for the same reason.
  defp deploy_blockers(data_dir, issuer?) do
    [
      if(is_nil(data_dir), do: "no_data_dir"),
      unless(issuer?, do: "no_ca_key"),
      case Launcher.executable() do
        {:ok, _path} -> nil
        {:error, {:ouro_path_unknown, _detail}} -> "ouro_path_unknown"
      end,
      if(cleartext_web_bind?(), do: "cleartext_web_bind"),
      if(dev_runtime?(), do: "dev_runtime")
    ]
    |> Enum.reject(&is_nil/1)
  end

  # A runtime started from this checkout rather than from a release — `ouro --dev`, and this
  # suite. Mix is what a release does not ship, so its presence is the question asked.
  #
  # It matters to exactly one operation. A `--dev` runtime cannot boot under a fleet profile,
  # so "Set up this device" from one writes a fleet, installs a service, and leaves an
  # operator with a machine whose runtime exits 1 on every start (review finding 8). Issuing
  # *from* a dev runtime is fine: `add` and `leave` act on another machine's installation,
  # and this one's inability to run a fleet says nothing about theirs.
  #
  # Overridable so a suite can exercise the setup path a packaged runtime has: absent, the
  # runtime answers for itself, which is what a person's machine always does.
  defp dev_runtime? do
    case Application.get_env(:ouroboros, :dev_runtime) do
      declared when is_boolean(declared) -> declared
      _unset -> Code.ensure_loaded?(Mix)
    end
  end

  # The spec decides credential entry on the endpoint's bind, the one transport fact this
  # server can verify: a loopback bind is safe whether the browser is local or reaching it
  # through `tailscale serve`, and a non-loopback bind under `OUROBOROS_WEB_ALLOW_REMOTE=1`
  # ships no TLS and is cleartext by definition. A forwarded header never enters this.
  #
  # The flag is a property of the *host*, not of the caller, so it is reported the same way
  # to a listener and to a browser: this runtime publishes a cleartext operator surface, and
  # a credential must not be typed into this deployment host while it does.
  defp cleartext_web_bind? do
    case running_endpoint_bind() do
      {:ok, bind} -> not loopback_bind?(bind)
      # The endpoint is up and this cannot read its bind: the honest answer to "may a
      # credential be typed into this host" is no, not a guess from a stale app env.
      :unreadable -> true
      :absent -> app_env_cleartext?()
    end
  end

  defp running_endpoint_bind do
    if Process.whereis(Ouroboros.Web.Endpoint) do
      try do
        case Ouroboros.Web.Config.for_endpoint(Ouroboros.Web.Endpoint) do
          %{bind: bind} -> {:ok, bind}
          _missing -> :unreadable
        end
      rescue
        _exception -> :unreadable
      catch
        _kind, _reason -> :unreadable
      end
    else
      :absent
    end
  end

  defp app_env_cleartext? do
    web = Application.get_env(:ouroboros, :web, [])

    if Keyword.get(web, :enabled, false),
      do: not loopback_bind?(Keyword.get(web, :bind)),
      else: false
  end

  # `config/runtime.exs` writes this key as a **string** at every site that sets it, so the
  # previous `is_tuple/1` guard meant the blocker never fired on a real deployment: a runtime
  # on `OUROBOROS_WEB_BIND=0.0.0.0 OUROBOROS_WEB_ALLOW_REMOTE=1` reported `deploy: true` and
  # invited a password into a cleartext endpoint (review F10). Both shapes are accepted now,
  # and anything this cannot resolve to a loopback address is treated as not loopback.
  #
  # Fail closed, deliberately. The question is "may a credential be typed into this host",
  # and the honest answer for a bind this build cannot parse is no.
  defp loopback_bind?(bind) when is_tuple(bind), do: Ouroboros.Web.Config.loopback?(bind)

  defp loopback_bind?(bind) when is_binary(bind) do
    case bind |> String.trim() |> String.to_charlist() |> :inet.parse_address() do
      {:ok, address} -> Ouroboros.Web.Config.loopback?(address)
      {:error, _reason} -> false
    end
  end

  defp loopback_bind?(_absent), do: false

  # `ouro fleet devices` merges this machine's roster with what the network client can see.
  # Neither of those is the runtime's own answer to "is that machine *here*, now" — so a
  # member whose runtime this one is connected to, and which `fleet doctor` reports as
  # connected and compatible, still rendered as "in the fleet, not visible on this network"
  # whenever the network client could not see it. Two different questions were being asked
  # and only one was being answered.
  #
  # The live facts are merged onto member rows by roster name, and they are kept separate
  # from discovery's: `online` and `path` stay the network's answer, `connected`,
  # `compatible` and `runtime_running` are the cluster's. A row where they disagree is a real
  # and useful thing to show — a machine reachable over BEAM but invisible to the network
  # client is a different problem from one that is neither.
  #
  # `null` throughout where this runtime cannot establish a fact, which includes every row
  # that is not a member: discovery sees devices that have never been in a fleet, and this
  # says nothing about those rather than reporting them as disconnected.
  defp merge_cluster(devices, facts) do
    Enum.map(devices, fn device ->
      case Map.fetch(facts, device["machine"]) do
        {:ok, live} ->
          device |> Map.merge(live) |> promote_state()

        :error ->
          Map.merge(device, %{
            "connected" => nil,
            "compatible" => nil,
            "runtime_running" => nil,
            "last_probe" => nil
          })
      end
    end)
  end

  # A member this runtime is connected to says so in its own state, rather than leaving the
  # row on discovery's word alone.
  defp promote_state(%{"connected" => true, "state" => state} = device)
       when state in ["fleet_member", "fleet_member_not_visible"],
       do: Map.put(device, "state", "fleet_member_connected")

  defp promote_state(device), do: device

  defp cluster_facts do
    %{machines: machines} = Ouroboros.Cluster.fleet_status()

    machines
    |> Enum.sort_by(&liveness/1)
    |> Map.new(fn machine ->
      {machine[:machine],
       %{
         "connected" => machine[:state] in [:connected, :local],
         "compatible" => compatible(machine[:compatibility]),
         "runtime_running" => machine[:runtime_running?],
         "last_probe" => machine[:last_seen_at]
       }}
    end)
  rescue
    # A runtime with no cluster surface answers about its network and says nothing about the
    # BEAM, which is the honest shape: `null`, not `false`.
    _unavailable -> %{}
  catch
    _kind, _reason -> %{}
  end

  # A name can appear more than once — a roster entry the monitor also sees as a live node —
  # and `Map.new/2` keeps whichever came last. Sorted so the liveliest entry is last and
  # therefore wins: a machine that is answering is not offline because a second row about it
  # says so.
  defp liveness(machine) do
    case machine[:state] do
      :local -> 2
      :connected -> 1
      _other -> 0
    end
  end

  defp compatible(:compatible), do: true
  defp compatible(:local), do: true
  defp compatible(:incompatible), do: false
  defp compatible(_unknown), do: nil

  @doc """
  Every operation this data directory holds a journal for, with whether a worker is attached.

  The list is the journal's, not this process's: an operation whose broker connection died
  with a previous runtime is still an operation, and it is exactly the one `resume/2` exists
  for.
  """
  @spec operations(Path.t() | nil) :: {[map()], non_neg_integer()}
  def operations(data_dir \\ nil) do
    case data_dir || data_dir() do
      nil ->
        {[], 0}

      dir ->
        attached = attached_operations()
        {summaries, total} = listed_journals(dir)

        {Enum.map(summaries, &Map.put(&1, "attached", &1["operation"] in attached)), total}
    end
  end

  defp listed_journals(dir) do
    GenServer.call(__MODULE__, {:journals, dir}, @call_timeout)
  catch
    :exit, _reason ->
      {summaries, total, _cache} = Journal.list(dir)
      {summaries, total}
  end

  defp attached_operations do
    GenServer.call(__MODULE__, :attached, @call_timeout)
  catch
    :exit, _reason -> []
  end

  @doc """
  One operation's sanitized snapshot: from its worker when one is attached, from its journal
  when none is.

  The two answers are marked — `source` is `worker` or `journal` — because the difference is
  the operator's whole question after an interruption. A journal says what was durably
  recorded; only a live worker can say what is happening now.

  A journal answer for an operation that is neither finished nor done also carries
  `worker_exit`, the sanitized tail of the worker's own stdio log — the one place a worker
  that died before it could record anything left its reason.

  Takes no binding. A challenge is bound to the session that was attached when it was issued
  (S4) and only a *response* is held to that; reading what an operation is doing is the
  administrator's read that the identity rule already gates, and making it fail for the
  second browser tab would be a restriction with no property behind it.
  """
  @spec status(String.t(), binding()) :: {:ok, map()} | {:error, term()}
  def status(operation, binding) when is_binary(operation) and is_map(binding) do
    with :ok <- Journal.validate_operation(operation),
         {:ok, snapshot} <- snapshot(operation),
         :ok <- readable_by?(snapshot, binding) do
      {:ok, snapshot}
    end
  end

  defp snapshot(operation) do
    case client(operation) do
      {:ok, pid} ->
        case Client.snapshot(pid) do
          # `worker_exit` is a journal-only field, and saying so on every answer is what
          # makes a missing key and a null one the same fact to a renderer.
          {:ok, snapshot} ->
            {:ok, reconcile_journal(snapshot, operation) |> Map.put("worker_exit", nil)}

          # The client process is gone. The broker has not necessarily handled its `:DOWN`
          # yet — a status call and a monitor message race each other — and answering
          # `worker_unavailable` for that window meant the first read after a worker went
          # away reported nothing at all where the journal already had the answer (review
          # finding 5). Falling through here is what makes the next `status` say
          # `source: "journal"` promptly instead.
          {:error, :worker_unavailable} ->
            without_worker(operation)

          {:error, reason} ->
            {:error, reason}
        end

      {:error, :no_worker} ->
        without_worker(operation)

      {:error, reason} ->
        {:error, reason}
    end
  end

  # A reattached worker only knows events since attachment. Keep durable progress,
  # including steps written without a broadcast, and use live details for progress
  # updates only when the journal agrees about the step's outcome.
  defp reconcile_journal(snapshot, operation) do
    case journal_status(operation) do
      {:ok, journal} ->
        live = List.wrap(snapshot["steps"])
        durable = List.wrap(journal["steps"])
        key = fn step -> {step["machine"], step["step"]} end

        steps =
          Enum.map(durable, fn step ->
            case Enum.find(live, &(key.(&1) == key.(step) and &1["outcome"] == step["outcome"])) do
              nil -> step
              event -> Map.merge(step, event)
            end
          end)

        extra = Enum.reject(live, fn step -> Enum.any?(durable, &(key.(&1) == key.(step))) end)

        journal
        |> Map.merge(snapshot)
        |> Map.put("owner", snapshot["owner"] || journal["owner"])
        |> Map.put("steps", steps ++ extra)
        |> Map.put("last_error", journal["last_error"] || snapshot["last_error"])

      _unavailable ->
        snapshot
    end
  end

  defp without_worker(operation) do
    case journal_status(operation) do
      # An operation whose handshake never completed has no journal and no worker. The
      # broker remembers why for a while, so this answers `attach_failed` rather than
      # the flatly wrong `no such operation`.
      {:error, :unknown_operation} -> attach_failure(operation)
      other -> other
    end
  end

  # The client's own give-up reason, passed through rather than wrapped when it is already a
  # stable code. A handshake that ran out of retries answers `worker_unreachable` carrying
  # what went wrong on the last attempt; anything else keeps `attach_failed`.
  defp attach_failure(operation) do
    case GenServer.call(__MODULE__, {:failure, operation}, @call_timeout) do
      {:ok, {:worker_unreachable, _last} = reason} -> {:error, reason}
      {:ok, reason} -> {:error, {:attach_failed, reason}}
      :error -> {:error, :unknown_operation}
    end
  catch
    :exit, _reason -> {:error, :unknown_operation}
  end

  # Seam S5's ownership check, applied to everything that reads or stops an operation.
  #
  # `nil` passes, and that is a decision rather than an oversight: a worker that does not
  # report an owner leaves this build unable to *establish* one, and refusing every read on a
  # runtime whose `ouro` predates the field would be a gate that protects nothing and breaks
  # recovery. What it does not do is let an unknown owner authorize a *takeover* — `resume/3`
  # holds the stricter rule, because that is the verb that inherits the credential prompt.
  # CLI operations use the local OS account as owner; a web administrator has a
  # gateway subject instead. They may read that same account's sanitized journal,
  # never its live worker or challenges. Resume/cancel keep the ownership gate.
  defp readable_by?(%{"source" => "journal", "owner" => owner}, binding)
       when is_binary(owner) do
    if owner == (System.get_env("USER") || System.get_env("LOGNAME")),
      do: :ok,
      else: owned_by?(owner, binding)
  end

  defp readable_by?(snapshot, binding), do: owned_by?(snapshot["owner"], binding)

  defp owned_by?(nil, _binding), do: :ok
  defp owned_by?(owner, %{subject: subject}) when owner == subject, do: :ok
  defp owned_by?(_owner, _binding), do: {:error, :operation_not_yours}

  defp journal_status(operation) do
    case data_dir() do
      nil ->
        {:error, :no_data_dir}

      dir ->
        with {:ok, document} <- Journal.read(dir, operation) do
          {:ok,
           document
           |> Map.put("operation", operation)
           |> Map.put("source", "journal")
           |> Map.put("attached", false)
           |> Map.put("worker_exit", worker_exit(dir, operation, document))}
        end
    end
  end

  # The tail of the worker's private stdio log, and only for the operation that needs it.
  #
  # A worker that dies before it can journal anything leaves an operation sitting at
  # `inspecting` with no error on it, which is a page that says nothing while the reason sat
  # on disk the whole time — a Unix socket path over 104 bytes, in the case that produced
  # this (review finding 5). The condition is narrow on purpose: a finished operation, a
  # cancelled one, and one that reported a `done` frame have all already said what happened,
  # and a log tail under those would be noise with a credential risk attached.
  #
  # `last_lines` may be empty. A worker that left no log is not a worker that left an empty
  # explanation, and the two are told apart by the list rather than by the field's absence.
  @worker_log_tail 8 * 1024
  @worker_log_lines 3
  @worker_log_width 300

  defp worker_exit(dir, operation, document) do
    if document["state"] not in @terminal and is_nil(document["done"]) do
      %{"last_lines" => worker_log_lines(Journal.log_path(dir, operation))}
    end
  end

  # Bounded before it is read, not after: the log is whatever the worker and everything it
  # forked printed, and a `set -x` shell or a chatty `ssh -vvv` can make it arbitrarily
  # large. Only the last 8 KiB is ever in memory, and only the last three lines of that
  # survive — each through the journal's own sanitizer, because nothing wrote this file
  # under a contract.
  defp worker_log_lines(path) do
    case File.open(path, [:read, :binary]) do
      {:ok, io} ->
        try do
          {:ok, size} = :file.position(io, :eof)
          {:ok, offset} = :file.position(io, {:bof, max(size - @worker_log_tail, 0)})

          case IO.binread(io, @worker_log_tail) do
            tail when is_binary(tail) -> tail_lines(tail, offset > 0)
            _eof_or_error -> []
          end
        after
          File.close(io)
        end

      {:error, _absent} ->
        []
    end
  end

  # A partial first line may have lost the label that makes a credential recognizable.
  # Never expose that fragment, even when it would otherwise fit the output width.
  defp tail_lines(tail, true) do
    case :binary.split(tail, "\n") do
      [_fragment, complete] -> tail_lines(complete, false)
      [_fragment] -> []
    end
  end

  defp tail_lines(tail, false) do
    tail
    |> :binary.split(["\n", "\r\n"], [:global])
    |> Enum.map(&Journal.scrub_line(&1, @worker_log_width))
    |> Enum.reject(&(&1 == ""))
    |> Enum.take(-@worker_log_lines)
  end

  # ---------------------------------------------------------------------------
  # Mutations

  @doc """
  Starts inspection of one target: mints an id, starts a client, and answers immediately.

  The client forks the worker and attaches in its own process. This used to wait out that
  handshake inside this call, which stalled every other verb on the named singleton for
  as long as `ouro fleet worker start` took. The answer is now `spawning`; `status` is
  what says when the handshake has caught up.
  """
  @spec prepare(map(), binding()) :: {:ok, map()} | {:error, term()}
  def prepare(request, binding) when is_map(request) and is_map(binding) do
    with :ok <- unblocked(request["kind"]) do
      GenServer.call(__MODULE__, {:prepare, request, binding}, @call_timeout)
    end
  end

  @doc """
  Whether this host may deploy at all, for the kind of operation being asked for.

  `fleet.devices` already answers this as `capabilities.deploy` so a surface can disable the
  action, but a disabled button is a *rendering*, not a boundary: a client that never drew
  it, or that ignores what it drew, reached `prepare` anyway and got as far as being asked
  for a password on a cleartext bind. The blockers are therefore checked here too, where the
  decision actually is.

  `setup` is exempt from `no_ca_key` and from that alone. The first local fleet is what
  *creates* the CA key, so refusing it for not having one yet would make the one operation
  that fixes the blocker impossible; every other blocker still applies to it, including the
  cleartext bind, because a setup is asked for no credential but still writes a fleet.

  `leave` is exempt from `no_ca_key` too, for the mirror-image reason: removing a member
  issues nothing, so a machine that cannot admit one can still take one out.

  `dev_runtime` runs the other way — it is the one blocker that applies to `setup` *only*.
  Every other kind is exempt from it, including the kinds this build cannot name, because a
  development runtime's inability to boot under a fleet profile is a fact about this machine
  and an `add` or a `leave` is about another one.

  Checked in the caller's process, so a refusal costs the broker nothing.
  """
  @spec unblocked(String.t() | nil) :: :ok | {:error, {:deploy_blocked, [String.t()]}}
  def unblocked(kind) do
    dir = data_dir()

    case dir |> deploy_blockers(issuer?(dir)) |> exempt(kind) do
      [] -> :ok
      blockers -> {:error, {:deploy_blocked, blockers}}
    end
  end

  @doc false
  @spec exempt([String.t()], String.t() | nil) :: [String.t()]
  def exempt(blockers, "setup"), do: blockers -- ["no_ca_key"]
  def exempt(blockers, "leave"), do: blockers -- ["no_ca_key", "dev_runtime"]
  def exempt(blockers, _other), do: blockers -- ["dev_runtime"]

  # The kind an operation already has, from the journal the worker writes when it opens one.
  # Durable, so it answers for an operation whose worker is long gone — which is exactly when
  # `resume` needs it.
  defp operation_kind(operation) do
    with dir when is_binary(dir) <- data_dir(),
         {:ok, document} <- Journal.read(dir, operation) do
      document["kind"]
    else
      _unknown -> nil
    end
  end

  @doc """
  Approves the plan the caller reviewed and lets the deployment run.

  `plan_digest` is the sha256 of the canonical plan (S6) and is not decoration: the worker
  refuses a digest that is not the plan it currently holds, so a plan that changed between
  review and approval comes back `plan_changed` rather than as a deployment nobody read.

  `idempotency_key` makes a lost answer safe to retry. The same key against the same
  operation replays the recorded answer without touching the worker; a different key while
  that operation is running is `operation_in_progress`, because two keys mean two intentions
  and only one of them was reviewed.
  """
  @spec start(String.t(), String.t(), String.t(), binding()) :: {:ok, map()} | {:error, term()}
  def start(operation, plan_digest, idempotency_key, binding)
      when is_binary(plan_digest) and is_binary(idempotency_key) do
    # Read the ledger, then look for the plan, then claim — in that order, and each step is
    # there for its own reason.
    #
    # Reading first is what makes a retry a retry: an answer that was already recorded is
    # replayed here without the worker being touched at all, and a start still in flight is
    # named as one. Looking for the plan before claiming is what stops a start sent a moment
    # too early from wedging the operation: claiming first meant it took the key, failed
    # `no_review_pending`, and left the ledger believing a start was in flight forever — the
    # same key then answered `start_in_flight` and a fresh one `operation_in_progress`, so
    # the plan could never be approved again (review F4). Claiming last keeps the claim
    # atomic against a second caller racing this one.
    with :ok <- Journal.validate_operation(operation),
         :ok <- unblocked(operation_kind(operation)),
         {:ok, pid} <- client(operation),
         :fresh <- peek(operation, idempotency_key),
         {:ok, challenge} <- review_challenge(pid),
         :ok <- claim(operation, idempotency_key) do
      case Client.respond(
             pid,
             challenge,
             ["review"],
             %{"approve" => true, "plan_digest" => plan_digest},
             binding
           ) do
        {:ok, _value} = success ->
          record(operation, idempotency_key, success)
          success

        {:error, _reason} = failure ->
          # A refusal is not an outcome to replay. The key goes back so the operator can
          # fix what the worker objected to and approve the same plan again.
          release(operation, idempotency_key)
          failure
      end
    else
      {:replay, result} -> result
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Answers a `password` or `passphrase` challenge.

  Runs in the caller's process on purpose; see the module note. The secret is an argument to
  exactly one more function call after this one — the frame encoder — and is referenced
  nowhere else in this tree.
  """
  @spec authenticate(String.t(), String.t(), String.t(), binding()) ::
          {:ok, map()} | {:error, term()}
  def authenticate(operation, challenge, secret, binding)
      when is_binary(challenge) and is_binary(secret) do
    with :ok <- unblocked(operation_kind(operation)),
         {:ok, pid} <- client(operation) do
      Client.respond(pid, challenge, ["password", "passphrase"], %{"secret" => secret}, binding)
    end
  end

  @doc "Accepts or refuses one unknown SSH host key, by its `host_trust` challenge."
  @spec confirm_host(String.t(), String.t(), boolean(), binding()) ::
          {:ok, map()} | {:error, term()}
  def confirm_host(operation, challenge, accept, binding)
      when is_binary(challenge) and is_boolean(accept) do
    with {:ok, pid} <- client(operation) do
      Client.respond(pid, challenge, ["host_trust"], %{"accept" => accept}, binding)
    end
  end

  @doc """
  Stops an operation at a safe boundary.

  This does not claim to undo anything. The worker finishes or reconciles the durable step it
  is inside, reaps its SSH children and reports its residue; a credential already delivered to
  another machine stays delivered.
  """
  @spec cancel(String.t(), binding()) :: {:ok, map()} | {:error, term()}
  def cancel(operation, binding) when is_binary(operation) and is_map(binding) do
    with {:ok, pid} <- client(operation),
         {:ok, snapshot} <- Client.snapshot(pid),
         :ok <- owned_by?(snapshot["owner"], binding),
         :ok <- still_running(snapshot),
         {:ok, reply} <- Client.cancel(pid) do
      # And then let go of the socket. A finished worker stays reachable for a minute so an
      # attached client can read its result, and it leaves as soon as nothing is attached —
      # so a broker that kept the connection after asking it to stop is the reason it would
      # sit there for the full minute with its socket and capability still on disk.
      #
      # The reply is already in hand, which is the result that linger exists to deliver.
      _ = GenServer.stop(pid, :normal, 5_000)
      {:ok, reply}
    end
  end

  defp still_running(%{"done" => done}) when is_map(done), do: {:error, :operation_finished}
  defp still_running(_snapshot), do: :ok

  @doc """
  Brings an interrupted operation back under a new worker.

  Refused when a worker is already attached — that is not a resume, that is a second worker
  for one operation — and refused when the journal says the operation reached a terminal
  state or cannot be read at all, because resuming an operation whose record is unreadable
  would be starting a second worker against a machine whose state nobody knows.
  """
  @spec resume(String.t(), binding(), boolean()) :: {:ok, map()} | {:error, term()}
  def resume(operation, binding, takeover? \\ false)
      when is_binary(operation) and is_map(binding) and is_boolean(takeover?) do
    with :ok <- Journal.validate_operation(operation),
         :ok <- unblocked(operation_kind(operation)) do
      retired = retire_finished_client(operation, binding)

      GenServer.call(__MODULE__, {:resume, operation, binding, takeover?, retired}, @call_timeout)
    end
  end

  @doc """
  Sends `{:ouroboros_fleet_deployment, operation, event}` to the caller for every event.

  A surface that binds credential challenges to a client session — a browser tab's id, a
  listener connection's — passes it here, and this process then *is* that session's presence
  for this operation. When it dies, the challenges bound to that session are unbound rather
  than left for a tab that no longer exists; `Ouroboros.Fleet.Deployment.Client`'s
  `release_session/2` has the whole of the reasoning.
  """
  @spec subscribe(String.t(), String.t() | nil) :: :ok | {:error, term()}
  def subscribe(operation, session \\ nil) do
    with {:ok, pid} <- client(operation), do: Client.subscribe(pid, self(), session)
  end

  @doc "Stops the caller's event subscription."
  @spec unsubscribe(String.t()) :: :ok | {:error, term()}
  def unsubscribe(operation) do
    with {:ok, pid} <- client(operation), do: Client.unsubscribe(pid, self())
  end

  @doc "The process holding this operation's socket, when one is attached."
  @spec client(String.t()) :: {:ok, pid()} | {:error, :no_worker | :invalid_operation}
  def client(operation) when is_binary(operation) do
    with :ok <- Journal.validate_operation(operation) do
      GenServer.call(__MODULE__, {:client, operation}, @call_timeout)
    end
  end

  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    supervisor = Keyword.get(opts, :supervisor, @supervisor)
    # A broker that restarted has forgotten every operation it was holding, and the client
    # processes under the supervisor beside it are connections nobody is tracking any more.
    # They are reaped here rather than left attached: an untracked socket to a worker is a
    # worker that cannot be resumed, because `resume/2` refuses an operation that already
    # has one.
    orphans(supervisor)

    {:ok,
     %{
       data_dir: Keyword.get(opts, :data_dir),
       launcher: Keyword.get(opts, :launcher, Launcher),
       supervisor: supervisor,
       clock: Keyword.get(opts, :clock, fn -> System.system_time(:second) end),
       # `operation => %{pid, ref, instance, key, result}`
       operations: %{},
       # `caller pid => monitor ref`, bounded by `@max_devices`.
       devices: %{},
       # `operation => reason`, bounded by `@max_failures`. Why a client stopped, kept just
       # long enough that `status` can say `attach_failed` rather than `no_worker` for an
       # operation whose handshake never completed — which since the handshake moved off the
       # broker's call is the only place that answer can come from.
       failures: %{},
       failure_order: [],
       # `{path, mtime, size} => summary`. `Journal.list/2` fills it; a file that has not
       # changed is not parsed again.
       journal_cache: %{}
     }, {:continue, :retain}}
  end

  @impl true
  def handle_continue(:retain, state), do: {:noreply, retain(state)}

  @impl true
  def handle_call(:attached, _from, state), do: {:reply, Map.keys(state.operations), state}

  def handle_call(:acquire_devices, {caller, _tag}, state) do
    cond do
      Map.has_key?(state.devices, caller) ->
        {:reply, :ok, state}

      map_size(state.devices) >= @max_devices ->
        {:reply, {:error, :devices_busy}, state}

      true ->
        {:reply, :ok, put_in(state.devices[caller], Process.monitor(caller))}
    end
  end

  def handle_call({:failure, operation}, _from, state),
    do: {:reply, Map.fetch(state.failures, operation), state}

  def handle_call({:client, operation}, _from, state) do
    case Map.fetch(state.operations, operation) do
      {:ok, %{pid: pid}} -> {:reply, {:ok, pid}, state}
      :error -> {:reply, {:error, :no_worker}, state}
    end
  end

  def handle_call({:prepare, request, binding}, _from, state) do
    operation = Base.encode16(:crypto.strong_rand_bytes(@operation_bytes), case: :lower)
    open(state, operation, request, binding)
  end

  def handle_call({:resume, operation, binding, takeover?, retired}, _from, state) do
    # Only remove the client this caller stopped. A concurrent resume may already have
    # replaced it, and its new worker must remain attached.
    state =
      case state.operations[operation] do
        %{pid: ^retired, ref: ref} when is_pid(retired) ->
          Process.demonitor(ref, [:flush])
          %{state | operations: Map.delete(state.operations, operation)}

        _other ->
          state
      end

    if Map.has_key?(state.operations, operation) do
      {:reply, {:error, :already_attached}, state}
    else
      case resumable(state, operation, binding, takeover?) do
        # The worker enforces the same rule on its side and records a `takeover` step, so
        # the flag travels with the attach rather than being a decision this side made alone.
        :ok -> open(state, operation, nil, Map.put(binding, :takeover?, takeover?))
        {:error, reason} -> {:reply, {:error, reason}, state}
      end
    end
  end

  def handle_call({:journals, dir}, _from, state) do
    {summaries, total, cache} = Journal.list(dir, state.journal_cache)
    {:reply, {summaries, total}, %{state | journal_cache: cache}}
  end

  # Read-only. Says what a start under this key would be without making it so.
  def handle_call({:peek, operation, key}, _from, state) do
    reply =
      case Map.fetch(state.operations, operation) do
        {:ok, %{key: nil}} -> :fresh
        {:ok, %{key: ^key, result: nil}} -> {:error, :start_in_flight}
        {:ok, %{key: ^key, result: result}} -> {:replay, result}
        {:ok, %{key: _other}} -> {:error, :operation_in_progress}
        :error -> {:error, :no_worker}
      end

    {:reply, reply, state}
  end

  def handle_call({:claim, operation, key}, _from, state) do
    case Map.fetch(state.operations, operation) do
      {:ok, %{key: nil} = entry} ->
        {:reply, :ok, put_in(state.operations[operation], %{entry | key: key})}

      {:ok, %{key: ^key, result: nil}} ->
        {:reply, {:error, :start_in_flight}, state}

      {:ok, %{key: ^key, result: result}} ->
        {:reply, {:replay, result}, state}

      {:ok, %{key: _other}} ->
        {:reply, {:error, :operation_in_progress}, state}

      :error ->
        {:reply, {:error, :no_worker}, state}
    end
  end

  def handle_call({:release, operation, key}, _from, state) do
    case Map.fetch(state.operations, operation) do
      {:ok, %{key: ^key, result: nil} = entry} ->
        {:reply, :ok, put_in(state.operations[operation], %{entry | key: nil})}

      _other ->
        {:reply, :ok, state}
    end
  end

  def handle_call({:record, operation, key, result}, _from, state) do
    case Map.fetch(state.operations, operation) do
      {:ok, %{key: ^key} = entry} ->
        {:reply, :ok, put_in(state.operations[operation], %{entry | result: result})}

      _other ->
        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_cast({:release_devices, caller}, state), do: {:noreply, drop_devices(state, caller)}

  @impl true
  def handle_info({:DOWN, ref, :process, pid, reason}, state) do
    state = drop_devices(state, pid)

    case Enum.find(state.operations, fn {_id, entry} -> entry.ref == ref end) do
      nil ->
        {:noreply, state}

      {operation, _entry} ->
        Logger.info("fleet deployment operation #{operation} lost its worker: #{inspect(reason)}")

        {:noreply,
         state
         |> Map.put(:operations, Map.delete(state.operations, operation))
         |> remember_failure(operation, reason)
         |> retain()}
    end
  end

  def handle_info(_other, state), do: {:noreply, state}

  # Runs in the caller, not the singleton: a client still spawning or handshaking can
  # take seconds to answer. Unrelated inventory and deployment calls must remain usable.
  defp retire_finished_client(operation, binding) do
    with {:ok, pid} <- client(operation),
         {:ok, snapshot} <- Client.snapshot(pid),
         :ok <- owned_by?(snapshot["owner"], binding),
         done when is_map(done) <- snapshot["done"] do
      # Closing this result reader lets the exact finished worker release its lock.
      :ok = GenServer.stop(pid, :normal, 5_000)
      pid
    else
      _live_or_not_owned -> nil
    end
  catch
    # Another caller may already have retired it. The broker still arbitrates resume
    # against its current entry; a failed stop never authorizes dropping that entry.
    :exit, _reason -> nil
  end

  defp drop_devices(state, pid) do
    case Map.pop(state.devices, pid) do
      {nil, _devices} ->
        state

      {ref, devices} ->
        Process.demonitor(ref, [:flush])
        %{state | devices: devices}
    end
  end

  # Only the reasons a client's own `terminate/2` produced, and only the ones an operator can
  # act on. A raw exit reason is never kept: it can carry call arguments, and this map is
  # read by `status`.
  defp remember_failure(state, operation, {:shutdown, {:attach_failed, reason}}) do
    order = [operation | state.failure_order -- [operation]]
    {order, failures} = trim_failures(order, Map.put(state.failures, operation, reason))
    %{state | failures: failures, failure_order: order}
  end

  defp remember_failure(state, _operation, _reason), do: state

  defp trim_failures(order, failures) when length(order) <= @max_failures, do: {order, failures}

  defp trim_failures(order, failures) do
    {kept, dropped} = Enum.split(order, @max_failures)
    {kept, Map.drop(failures, dropped)}
  end

  # ---------------------------------------------------------------------------

  # Mint, start the client, answer. The client forks and attaches in `handle_continue`, so
  # this call does not wait out `ouro fleet worker start` and every other verb stays
  # answerable. A spawn or handshake failure kills the client rather than this reply; the
  # broker learns it from the monitor, which is also what `status` consults for
  # `attach_failed`.
  defp open(state, operation, request, binding) do
    with {:ok, dir} <- resolve_data_dir(state),
         {:ok, pid} <- start_client(state, operation, binding, dir, request) do
      entry = %{
        pid: pid,
        ref: Process.monitor(pid),
        instance: nil,
        key: nil,
        result: nil
      }

      {:reply, {:ok, %{"operation_id" => operation, "state" => "spawning"}},
       put_in(state.operations[operation], entry)}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  # The exit is caught and the reason is *discarded*, not wrapped. A `DynamicSupervisor` that
  # is not running exits the caller rather than answering it, and that exit's reason carries
  # the child spec — which, once spawn lived here, carried the capability. The same shape as
  # the client's `call/3` (F1): an exit reason is an argument list. The broker also does not
  # die of a sibling that is restarting, which is the other half of why this is a catch.
  defp start_client(state, operation, binding, dir, request) do
    DynamicSupervisor.start_child(
      state.supervisor,
      {Client,
       [
         operation: operation,
         subject: binding[:subject],
         session: binding[:session],
         takeover?: binding[:takeover?] == true,
         clock: state.clock,
         launcher: state.launcher,
         data_dir: dir,
         request: request,
         spawn_timeout: @spawn_timeout
       ]}
    )
  catch
    :exit, _reason -> {:error, :client_supervisor_unavailable}
  end

  # Completed and cancelled journals older than 30 days, and more than the newest 50 of
  # those two states, are swept here rather than left to accumulate under `<data dir>/deploy/`.
  # Failed and interrupted stay: they are resumable. Live clients are skipped even when the
  # journal already says they finished.
  defp retain(state) do
    case resolve_data_dir(state) do
      {:ok, dir} ->
        Journal.prune(dir, attached: Map.keys(state.operations), now: state.clock.())
        state

      _absent ->
        state
    end
  end

  defp resumable(state, operation, binding, takeover?) do
    with {:ok, dir} <- resolve_data_dir(state),
         {:ok, document} <- Journal.read(dir, operation),
         :ok <- resumable_state(document["state"]),
         :ok <- resumable_owner(document["owner"], binding, operation, takeover?) do
      :ok
    end
  end

  defp resumable_state(recorded) when recorded in @terminal, do: {:error, :operation_finished}
  defp resumable_state(nil), do: {:error, :operation_state_unknown}
  defp resumable_state(_open), do: :ok

  # The strict half of the ownership rule, and the reason it is stricter than `status`'s.
  #
  # A resume attaches a *new* client under the resuming identity and session, so every
  # challenge the worker issues from then on is bound to the resumer. That is not reading
  # somebody else's operation; it is inheriting their credential prompt, which is exactly
  # what a second administrator did unchallenged before this existed (review F11).
  #
  # So: the owner matches, or the caller says `takeover: true` out loud. An *unknown* owner
  # does not pass — a journal this build cannot attribute is one it must not hand over on
  # its own say-so — and a takeover leaves its own audit line naming who took what from whom,
  # because the point is not to prevent it but to make it impossible to do quietly.
  defp resumable_owner(owner, %{subject: subject}, _operation, _takeover?)
       when is_binary(owner) and owner == subject,
       do: :ok

  defp resumable_owner(owner, binding, operation, true) do
    Logger.warning(
      "fleet deployment takeover operation=#{operation} " <>
        "actor=#{inspect(binding[:subject])} previous_owner=#{inspect(owner)}"
    )

    :ok
  end

  defp resumable_owner(_owner, _binding, _operation, false), do: {:error, :operation_not_yours}

  defp resolve_data_dir(state) do
    case state.data_dir || data_dir() do
      dir when is_binary(dir) and dir != "" -> {:ok, dir}
      _absent -> {:error, :no_data_dir}
    end
  end

  # Read at call time rather than cached at init: this process starts with the runtime, and
  # the durable directory it serves is application configuration that a test — and a future
  # reconfiguration — can move underneath it.
  defp data_dir, do: Application.get_env(:ouroboros, :data_dir)

  defp orphans(supervisor) do
    supervisor
    |> DynamicSupervisor.which_children()
    |> Enum.each(fn {_id, pid, _type, _modules} ->
      if is_pid(pid), do: DynamicSupervisor.terminate_child(supervisor, pid)
    end)
  catch
    :exit, _not_started -> :ok
  end

  defp peek(operation, key),
    do: GenServer.call(__MODULE__, {:peek, operation, key}, @call_timeout)

  defp claim(operation, key),
    do: GenServer.call(__MODULE__, {:claim, operation, key}, @call_timeout)

  defp record(operation, key, result),
    do: GenServer.call(__MODULE__, {:record, operation, key, result}, @call_timeout)

  defp release(operation, key),
    do: GenServer.call(__MODULE__, {:release, operation, key}, @call_timeout)

  # The open `review` challenge is a fact about the connection, so it is read from the client
  # rather than tracked a second time in the broker.
  defp review_challenge(pid) do
    with {:ok, snapshot} <- Client.snapshot(pid) do
      case Enum.find(snapshot["challenges"], &(&1["kind"] == "review")) do
        %{"challenge" => id} -> {:ok, id}
        nil -> {:error, :no_review_pending}
      end
    end
  end
end
