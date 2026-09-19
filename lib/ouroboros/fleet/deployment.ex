defmodule Ouroboros.Fleet.Deployment do
  @moduledoc """
  The runtime-local broker for putting Ouroboros onto a machine, or taking it off one.

  A registry and two reads, and nothing else. `operation → worker process` is the registry;
  `devices/1` answers the Devices inventory out of `ouro fleet devices --json` and this
  machine's own facts; `operations/1` answers out of the journal directory. The work itself
  belongs to `Ouroboros.Fleet.Deployment.Worker`, one process per running operation, which
  owns the port program that does it (§9).

  ## What went, and why it is not missed

  The detached worker, its Unix socket, its capability file, the attach retry, the request
  file, the operation `owner`, takeover and per-session challenge bindings are all deleted.
  They existed to let one runtime hand an operation to another, and to decide which of an
  operator's browser tabs owned a password prompt. §1 of the "fleet, simplified" record
  withdraws the first — the deployment program is an ordinary port program of the runtime
  that asked for it, because nothing it does needs to outlive a runtime except the local
  setup transition, which the journal already covers — and §10 withdraws the second: a
  challenge is answered by whoever is an administrator on this runtime.

  What survives of "survives" is §8's: the program calls `setsid`, ignores `SIGHUP` and
  `SIGPIPE`, and on stdin EOF finishes the operation and keeps writing its journal. So
  stopping this runtime mid-setup does not stop the setup; it stops this runtime watching it.

  ## Where the secret is, and is not

  `respond/3` is the only function here that can carry a credential, and it is the only one
  that does not run in the broker. It asks the broker for the operation's worker *pid*, and
  then calls that process directly from the caller's own process. The broker is a named
  singleton: a secret that passed through it would sit in the mailbox and the crash dump of a
  process every deployment shares. This way the only two processes that ever hold those bytes
  are the one that received them from the wire and the one that writes them to the pipe.
  """

  use GenServer

  require Logger

  alias Ouroboros.Fleet.Deployment.Journal
  alias Ouroboros.Fleet.Deployment.Launcher
  alias Ouroboros.Fleet.Deployment.Worker

  @supervisor Ouroboros.Fleet.Deployment.WorkerSupervisor

  # `ouro fleet devices --json` asks the local network client and returns; ten seconds is
  # above a slow client and well below the method's own ceiling.
  @devices_timeout 10_000
  @call_timeout 20_000

  # Eight random bytes is 2^64 of identity in sixteen characters, which is a name a journal
  # file, a log file and an address bar can all carry.
  @operation_bytes 8

  # How many `ouro fleet devices --json` children may be in flight at once across this whole
  # runtime, and how many recent program exits are kept so a journal answer can explain one.
  @max_devices 4
  @max_exits 32

  # A journal state an operation cannot be continued from.
  @terminal ~w(completed cancelled)

  # What a journal answer may read back out of the program's own stderr log. Bounded before
  # it is read, not after: the file is whatever the program and everything it forked printed.
  @log_tail 32 * 1024
  @log_lines 50
  @log_width 300

  @doc false
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  The supervised pair: the worker supervisor, then the broker that starts children in it.

  In that order, because the broker starts children in the supervisor and so needs it first.
  They sit under `Ouroboros.Surface.Supervisor`, which is `:one_for_one` — so a broker crash
  does **not** restart the worker supervisor beside it, and the port programs it was tracking
  outlive the process that was tracking them. `init/1` therefore reaps them: an untracked
  worker is a program nobody can answer a challenge to, and closing its port is what lets the
  program carry on to stdin EOF instead.
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
  must not queue behind somebody else's program start — a ten-second external command inside
  a named singleton is a ten-second stall for every other operation.
  """
  @spec devices(keyword()) :: {:ok, map()} | {:error, term()}
  def devices(opts \\ []) do
    data_dir = Keyword.get(opts, :data_dir) || data_dir()
    timeout = Keyword.get(opts, :timeout, @devices_timeout)

    # Each call forks `ouro` and may hold half a megabyte of its output. Running in the
    # caller keeps a slow inventory from stalling every other operation, but it also means
    # nothing serialises these — a page that refreshes in a loop would otherwise be able to
    # fork as many children as it liked. The slot is released by the broker on this process's
    # `:DOWN`, so a caller that dies mid-call does not leak one.
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

  # An allowlist rather than a merge. What `ouro` prints is a document this build reads two
  # named keys out of; a key it grows later is reported in `unknown` — the convention
  # `runtime.activity` already uses — rather than flowing into a reply whose shape nobody
  # here has checked.
  defp inventory(document, data_dir) do
    {listed, total} = operations(data_dir)
    devices = Journal.scrub_value(document["devices"]) || []

    %{
      "host" => host(data_dir),
      # The fleet's own name, for the line above the list. `fleet.status` carries it too,
      # but a surface that reads only this method drew "Fleet of <machine>" for a fleet that
      # has a name of its own.
      "fleet_name" => fleet_name(data_dir),
      "discovery" => Journal.scrub_value(document["discovery"]),
      "devices" => merge_cluster(devices, cluster_facts()),
      "operations" => listed,
      "operations_total" => total,
      "unknown" => document |> Map.keys() |> Kernel.--(["discovery", "devices"]) |> Enum.sort()
    }
  end

  @doc """
  This deployment host's own identity and what it is currently able to do.

  `capabilities` is the answer to "can a deployment be offered here", with every reason it
  cannot, so a surface renders a disabled action with a sentence instead of an action that
  fails when pressed.

  `issuer` is gone with the per-member PKI (§1): one fleet is one shared secret bundle held
  by every member, so "does this machine hold the CA key" stopped being the question that
  decides whether it can admit another machine.
  """
  @spec host(Path.t() | nil) :: map()
  def host(data_dir \\ nil) do
    reasons = deploy_blockers(data_dir || data_dir())

    %{
      "hostname" => hostname(),
      "user" => System.get_env("USER") || System.get_env("LOGNAME"),
      "os" => :os.type() |> elem(1) |> Atom.to_string(),
      "arch" => :erlang.system_info(:system_architecture) |> List.to_string(),
      "capabilities" => %{"deploy" => reasons == [], "reasons" => reasons}
    }
  end

  # `:inet.gethostname/0` is specified to answer `{:ok, name}` and nothing else; matching it
  # is the honest shape rather than a fallback clause dialyzer can prove dead.
  @doc """
  This host's own name, which is what a first local setup calls this device by default.

  Public because `fleet.deployment.start` needs it for a `setup` the caller did not name a
  machine for: the program requires one, and the honest default for "set up *this* device" is
  what this device is already called.
  """
  @spec host_name() :: String.t()
  def host_name do
    {:ok, name} = :inet.gethostname()
    List.to_string(name)
  end

  defp hostname, do: host_name()

  # A members list is a handful of `{machine, host, node}` triples. A profile larger than
  # this is not one, and it is refused rather than parsed.
  @max_profile_bytes 512 * 1024

  @doc "The fleet's name from this machine's profile, or `nil` for a standalone machine."
  @spec fleet_name(Path.t() | nil) :: String.t() | nil
  def fleet_name(data_dir \\ nil) do
    case profile_document(data_dir) do
      %{"name" => name} when is_binary(name) and name != "" -> Journal.scrub_value(name)
      _standalone -> nil
    end
  end

  # The profile as a document, bounded and read as the members list is read; `nil` for a
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
  This machine's members: every entry of the fleet profile it holds, `machine` and `host`.

  Public because `fleet.deployment.start` needs it for a `leave`: the operator names a member,
  and a name that is not in this profile is refused with the list printed. Where that member
  *is* stays the program's business — `ouro fleet leave --machine NAME` reads the same file
  (§5) — so nothing here is passed to it as an address.

  `[]` for a standalone machine, an unreadable profile, or no data directory — to a caller
  those are one fact, "this machine has no members", and the refusal it produces says so.
  """
  @spec roster(Path.t() | nil) :: [%{optional(String.t()) => String.t()}]
  def roster(data_dir \\ nil) do
    case profile_document(data_dir) do
      %{"members" => members} when is_list(members) ->
        for %{"machine" => machine, "host" => host} <- members,
            is_binary(machine) and machine != "" and is_binary(host) and host != "",
            do: %{"machine" => machine, "host" => host}

      _no_members ->
        []
    end
  end

  @doc """
  The members entry for one machine name, matched the way the rest of the fleet matches names.

  `tui/src/fleet.rs`'s `same_name/2` is `eq_ignore_ascii_case`, and an operator whose profile
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

  # Stable codes, in a fixed order, because a surface renders them and a test names them.
  # New codes are appended rather than inserted, for the same reason. `no_ca_key` is gone
  # with the per-member PKI: every member holds the bundle, so every member can admit one.
  defp deploy_blockers(data_dir) do
    [
      if(is_nil(data_dir), do: "no_data_dir"),
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
  # operator with a machine whose runtime exits 1 on every start. Issuing *from* a dev runtime
  # is fine: `add` and `leave` act on another machine's installation, and this one's inability
  # to run a fleet says nothing about theirs.
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

  # `config/runtime.exs` writes this key as a **string** at every site that sets it, so both
  # shapes are accepted, and anything this cannot resolve to a loopback address is treated as
  # not loopback. Fail closed, deliberately: the question is "may a credential be typed into
  # this host", and the honest answer for a bind this build cannot parse is no.
  defp loopback_bind?(bind) when is_tuple(bind), do: Ouroboros.Web.Config.loopback?(bind)

  defp loopback_bind?(bind) when is_binary(bind) do
    case bind |> String.trim() |> String.to_charlist() |> :inet.parse_address() do
      {:ok, address} -> Ouroboros.Web.Config.loopback?(address)
      {:error, _reason} -> false
    end
  end

  defp loopback_bind?(_absent), do: false

  # `ouro fleet devices` merges this machine's members with what the network client can see.
  # Neither of those is the runtime's own answer to "is that machine *here*, now" — so a
  # member whose runtime this one is connected to, and which `fleet doctor` reports as
  # connected and compatible, still rendered as "in the fleet, not visible on this network"
  # whenever the network client could not see it. Two different questions were being asked
  # and only one was being answered.
  #
  # The live facts are merged onto member rows by name, and they are kept separate from
  # discovery's: `online` and `path` stay the network's answer, `connected`, `compatible` and
  # `runtime_running` are the cluster's. A row where they disagree is a real and useful thing
  # to show.
  #
  # `null` throughout where this runtime cannot establish a fact, which includes every row
  # that is not a member.
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

  # A name can appear more than once — a profile entry the monitor also sees as a live node —
  # and `Map.new/2` keeps whichever came last. Sorted so the liveliest entry is last and
  # therefore wins.
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
  Every operation this data directory holds a journal for, and how many there are.

  The list is the journal directory's, not this process's: an operation whose worker died
  with a previous runtime is still an operation, and it is exactly the one `resume/1` exists
  for. `running` says whether a worker process is holding it here and now, which is the
  difference between "this is happening" and "this is what was last written down".
  """
  @spec operations(Path.t() | nil) :: {[map()], non_neg_integer()}
  def operations(data_dir \\ nil) do
    case data_dir || data_dir() do
      nil ->
        {[], 0}

      dir ->
        running = running_operations()
        {summaries, total} = listed_journals(dir)

        {Enum.map(summaries, &Map.put(&1, "running", &1["operation"] in running)), total}
    end
  end

  defp listed_journals(dir) do
    GenServer.call(__MODULE__, {:journals, dir}, @call_timeout)
  catch
    :exit, _reason ->
      {summaries, total, _cache} = Journal.list(dir)
      {summaries, total}
  end

  defp running_operations do
    GenServer.call(__MODULE__, :running, @call_timeout)
  catch
    :exit, _reason -> []
  end

  @doc """
  One operation's sanitized snapshot: from its worker process when one is alive, from its
  journal when none is.

  The two answers are marked — `source` is `worker` or `journal` — because the difference is
  the operator's whole question after an interruption. A journal says what was durably
  recorded; only a live process can say what is happening now.

  Takes no identity. Reading what an operation is doing is the administrator's read that the
  identity rule already gates (§9), and there is no second owner to check it against.
  """
  @spec status(String.t()) :: {:ok, map()} | {:error, term()}
  def status(operation) when is_binary(operation) do
    with :ok <- Journal.validate_operation(operation) do
      case worker(operation) do
        {:ok, pid} ->
          case Worker.snapshot(pid) do
            {:ok, snapshot} -> {:ok, snapshot}
            # The worker process is gone and the broker has not necessarily handled its
            # `:DOWN` yet — a status call and a monitor message race each other. Falling
            # through is what makes this answer the journal promptly instead of nothing.
            {:error, :worker_unavailable} -> journal_status(operation)
            {:error, reason} -> {:error, reason}
          end

        {:error, :no_worker} ->
          journal_status(operation)

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc """
  The §9 answer for an operation nothing is holding: the journal, projected and bounded.

  `log` is the tail of the program's own stderr file, because that is the only log a journal
  answer can have — the `log` frames went to a worker process that is no longer here. It is
  read through the journal's own sanitizer, because nothing wrote that file under a contract.
  """
  @spec journal_status(String.t()) :: {:ok, map()} | {:error, term()}
  def journal_status(operation) do
    case data_dir() do
      nil ->
        {:error, :no_data_dir}

      dir ->
        with {:ok, document} <- Journal.read(dir, operation) do
          {:ok,
           %{
             "operation" => operation,
             "kind" => document["kind"],
             "state" => document["state"],
             "steps" => List.wrap(document["steps"]),
             "challenge" => nil,
             "log" => log_tail(Journal.log_path(dir, operation)),
             "plan" => document["plan"],
             "summary" => nil,
             "last_error" => document["last_error"] || recorded_exit(operation, document),
             "running" => false,
             "source" => "journal"
           }}
        end
    end
  end

  # Why the program is not here, for an operation whose journal never got to say. A program
  # that dies before it can journal anything leaves an operation sitting at `running` with no
  # error on it, which is a page that says nothing while the reason sat in this runtime's
  # memory the whole time. Only for an unfinished operation: a completed or cancelled one has
  # already said what happened.
  defp recorded_exit(operation, document) do
    if document["state"] in @terminal do
      nil
    else
      recorded_exit(operation)
    end
  end

  defp recorded_exit(operation) do
    case GenServer.call(__MODULE__, {:exit, operation}, @call_timeout) do
      {:ok, status} ->
        %{
          "reason" => "worker_exited",
          "detail" => "the deployment program exited with status #{status}"
        }

      :error ->
        nil
    end
  catch
    :exit, _reason -> nil
  end

  defp log_tail(path) do
    case File.open(path, [:read, :binary]) do
      {:ok, io} ->
        try do
          {:ok, size} = :file.position(io, :eof)
          {:ok, offset} = :file.position(io, {:bof, max(size - @log_tail, 0)})

          case IO.binread(io, @log_tail) do
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
    |> Enum.map(&Journal.scrub_line(&1, @log_width))
    |> Enum.reject(&(&1 == ""))
    |> Enum.take(-@log_lines)
  end

  # ---------------------------------------------------------------------------
  # Mutations

  @doc """
  Starts one operation: mints an id, builds the argv, starts the worker, answers.

  `request` is the validated `fleet.deployment.start` document — a kind, a machine name, an
  address, an account, a port, paths and an identity named by *reference*. Every one of those
  is checked again here before it becomes a word on a command line, because §6 makes the
  request *be* the argv: nothing on it is a secret, and nothing on it may be a flag.
  """
  @spec start(map()) :: {:ok, map()} | {:error, term()}
  def start(request) when is_map(request) do
    operation = Base.encode16(:crypto.strong_rand_bytes(@operation_bytes), case: :lower)

    with :ok <- unblocked(request["kind"]),
         {:ok, argv} <- argv(request, operation) do
      GenServer.call(__MODULE__, {:start, operation, request["kind"], argv}, @call_timeout)
    end
  end

  @doc """
  Whether this host may run an operation at all, for the kind being asked for.

  `fleet.devices` already answers this as `capabilities.deploy` so a surface can disable the
  action, but a disabled button is a *rendering*, not a boundary: a client that never drew it,
  or that ignores what it drew, reaches the verb anyway. The blockers are therefore checked
  here too, where the decision actually is.

  `dev_runtime` applies to `setup` and to nothing else, including the kinds this build cannot
  name, because a development runtime's inability to boot under a fleet profile is a fact
  about this machine and an `add` or a `leave` is about another one.

  Checked in the caller's process, so a refusal costs the broker nothing.
  """
  @spec unblocked(String.t() | nil) :: :ok | {:error, {:deploy_blocked, [String.t()]}}
  def unblocked(kind) do
    case data_dir() |> deploy_blockers() |> exempt(kind) do
      [] -> :ok
      blockers -> {:error, {:deploy_blocked, blockers}}
    end
  end

  @doc false
  @spec exempt([String.t()], String.t() | nil) :: [String.t()]
  def exempt(blockers, "setup"), do: blockers
  def exempt(blockers, _other), do: blockers -- ["dev_runtime"]

  @doc """
  Answers the operation's open challenge.

  Runs in the caller's process on purpose; see the module note. A `secret` inside `response`
  is an argument to exactly one more function call after this one — the frame encoder — and
  is referenced nowhere else in this tree.
  """
  @spec respond(String.t(), String.t(), map()) :: {:ok, map()} | {:error, term()}
  def respond(operation, challenge, response)
      when is_binary(challenge) and is_map(response) do
    with :ok <- unblocked(operation_kind(operation)),
         {:ok, pid} <- worker(operation) do
      Worker.respond(pid, challenge, response)
    end
  end

  @doc """
  Stops an operation at a safe boundary.

  This does not claim to undo anything. The program finishes or reconciles the durable step it
  is inside, reaps its SSH children and reports its residue; a credential already delivered to
  another machine stays delivered.
  """
  @spec cancel(String.t()) :: {:ok, map()} | {:error, term()}
  def cancel(operation) when is_binary(operation) do
    with :ok <- Journal.validate_operation(operation),
         {:ok, pid} <- worker(operation) do
      Worker.cancel(pid)
    end
  end

  @doc """
  Runs an interrupted operation's program again, against the journal it left.

  `--operation ID` is the whole of resume (§6): a step recorded `ok` is not repeated, and an
  `install` onto a target that is already in this fleet as this machine is `skipped`. So the
  argv is the argv — this runtime's memory of the one it built, or, on a runtime that has
  forgotten because it restarted, the one the journal's own `kind`, `target` and `paths`
  rebuild. Nothing on it was ever a secret, which is what makes rebuilding it safe.

  Refused when a worker is already running the operation — that is not a resume, that is a
  second program for one operation — and refused when the journal says the operation reached
  a terminal state or cannot be read at all.
  """
  @spec resume(String.t()) :: {:ok, map()} | {:error, term()}
  def resume(operation) when is_binary(operation) do
    with :ok <- Journal.validate_operation(operation),
         :ok <- unblocked(operation_kind(operation)) do
      GenServer.call(__MODULE__, {:resume, operation}, @call_timeout)
    end
  end

  @doc """
  Sends `{:ouroboros_fleet_deployment, operation, frame}` to the caller for every frame.

  No session travels with it, and nothing is bound to the subscriber: §10 deletes per-tab
  binding, so a subscription is a subscription.
  """
  @spec subscribe(String.t()) :: :ok | {:error, term()}
  def subscribe(operation) do
    with {:ok, pid} <- worker(operation), do: Worker.subscribe(pid, self())
  end

  @doc "Stops the caller's frame subscription."
  @spec unsubscribe(String.t()) :: :ok | {:error, term()}
  def unsubscribe(operation) do
    with {:ok, pid} <- worker(operation), do: Worker.unsubscribe(pid, self())
  end

  @doc "The process holding this operation's port program, when one is running."
  @spec worker(String.t()) :: {:ok, pid()} | {:error, :no_worker | :invalid_operation}
  def worker(operation) when is_binary(operation) do
    with :ok <- Journal.validate_operation(operation) do
      GenServer.call(__MODULE__, {:worker, operation}, @call_timeout)
    end
  end

  # The kind an operation already has, from the journal the program writes when it opens one.
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

  # ---------------------------------------------------------------------------
  # The argv

  # The one place a request becomes a command line. Two rules hold it together: every value
  # is matched against the shape that value may have, and no value may begin with `-`. The
  # second is the one that matters — an address of `--data-dir` would otherwise be an option
  # this runtime did not mean to pass.
  @machine ~r/\A[a-zA-Z0-9][a-zA-Z0-9-]{0,39}\z/

  @doc """
  The exact argv this runtime execs for one request, or why it will not.

  Public because it is the contract boundary between this slice and the Rust one: what §8's
  program is asked for is this list and nothing else, and a test can name it directly rather
  than infer it from what a fake happened to receive.
  """
  @spec argv(map(), String.t()) :: {:ok, [String.t()]} | {:error, term()}
  def argv(request, operation) when is_map(request) and is_binary(operation) do
    with :ok <- Journal.validate_operation(operation) do
      case request["kind"] do
        "setup" -> setup_argv(request, operation)
        "add" -> add_argv(request, operation)
        "leave" -> leave_argv(request, operation)
        _other -> {:error, {:invalid_request, "kind must be setup, add or leave"}}
      end
    end
  end

  defp setup_argv(request, operation) do
    with {:ok, machine} <- machine_name(request["machine"]),
         {:ok, address} <- optional_word(request["address"], "address") do
      {:ok,
       ["fleet", "setup", "--machine", machine] ++
         flag("--address", address) ++
         service_flag(request) ++ frames(operation)}
    end
  end

  defp add_argv(request, operation) do
    with {:ok, machine} <- machine_name(request["machine"]),
         {:ok, address} <- word(request["address"], "address"),
         {:ok, ssh_user} <- word(request["ssh_user"], "ssh_user"),
         {:ok, port} <- port(request["port"]),
         {:ok, identity} <- identity(request["identity"]),
         {:ok, install_path} <- optional_word(request["install_path"], "install_path"),
         {:ok, data_dir} <- optional_word(request["data_dir"], "data_dir") do
      {:ok,
       ["fleet", "add", ssh_user <> "@" <> address, "--machine", machine, "--port", port] ++
         identity ++
         flag("--install-path", install_path) ++
         flag("--data-dir", data_dir) ++
         service_flag(request) ++ frames(operation)}
    end
  end

  defp leave_argv(request, operation) do
    with {:ok, machine} <- machine_name(request["machine"]),
         {:ok, ssh_user} <- word(request["ssh_user"], "ssh_user"),
         {:ok, port} <- port(request["port"]),
         {:ok, identity} <- identity(request["identity"]) do
      {:ok,
       ["fleet", "leave", "--machine", machine, "--user", ssh_user, "--port", port] ++
         identity ++ frames(operation)}
    end
  end

  defp frames(operation), do: ["--frames", "--operation", operation]

  # `--no-service` is the only shape the command line has for this: there is no `--service`,
  # because installing one is the default (§5).
  defp service_flag(%{"service" => false}), do: ["--no-service"]
  defp service_flag(_default), do: []

  defp flag(_name, nil), do: []
  defp flag(name, value), do: [name, value]

  defp machine_name(name) when is_binary(name) do
    if String.match?(name, @machine),
      do: {:ok, name},
      else: {:error, {:invalid_request, "machine must be letters, digits and hyphens"}}
  end

  defp machine_name(_absent), do: {:error, {:invalid_request, "machine is required"}}

  defp word(value, field) when is_binary(value) do
    trimmed = String.trim(value)

    cond do
      trimmed == "" ->
        {:error, {:invalid_request, "#{field} must not be empty"}}

      String.starts_with?(trimmed, "-") ->
        {:error, {:invalid_request, "#{field} is not a flag"}}

      String.contains?(trimmed, ["\n", "\r", "\0", " "]) ->
        {:error, {:invalid_request, "#{field} must be one word"}}

      true ->
        {:ok, trimmed}
    end
  end

  defp word(_absent, field), do: {:error, {:invalid_request, "#{field} is required"}}

  defp optional_word(nil, _field), do: {:ok, nil}
  defp optional_word("", _field), do: {:ok, nil}
  defp optional_word(value, field), do: word(value, field)

  defp port(nil), do: {:ok, "22"}

  defp port(value) when is_integer(value) and value >= 1 and value <= 65_535,
    do: {:ok, Integer.to_string(value)}

  defp port(_other), do: {:error, {:invalid_request, "port must be between 1 and 65535"}}

  # §5's three ways to name an identity, and never key material. `default` is whatever this
  # host's own ssh configuration selects, which is no flag at all; the engine raises a
  # `password` challenge when that identity is asked for a password, so nothing else is
  # needed to reach a password prompt.
  defp identity(nil), do: {:ok, []}
  defp identity(%{"kind" => "default"}), do: {:ok, []}
  defp identity(%{"kind" => "password"}), do: {:ok, ["--ask-password"]}

  defp identity(%{"kind" => "key", "ref" => ref}) do
    with {:ok, path} <- word(ref, "identity.ref"), do: {:ok, ["--key", path]}
  end

  defp identity(%{"kind" => "agent", "ref" => ref}) do
    with {:ok, print} <- word(ref, "identity.ref"), do: {:ok, ["--agent", print]}
  end

  defp identity(_other),
    do: {:error, {:invalid_request, "identity.kind must be default, password, key or agent"}}

  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    supervisor = Keyword.get(opts, :supervisor, @supervisor)
    # A broker that restarted has forgotten every operation it was holding, and the worker
    # processes under the supervisor beside it are ports nobody is tracking any more. Closing
    # them is what hands their programs the stdin EOF §8 tells them to finish on, rather than
    # leaving a port nobody can answer a challenge to.
    orphans(supervisor)

    {:ok,
     %{
       data_dir: Keyword.get(opts, :data_dir),
       supervisor: supervisor,
       executable: Keyword.get(opts, :executable, &Launcher.executable/0),
       clock: Keyword.get(opts, :clock, fn -> System.system_time(:second) end),
       # `operation => %{pid, ref, kind, argv}`
       operations: %{},
       # `caller pid => monitor ref`, bounded by `@max_devices`.
       devices: %{},
       # `operation => argv`, so a resume on this runtime is the same command line again
       # rather than a reconstruction of it.
       argv: %{},
       # `operation => exit status`, bounded by `@max_exits`. Why a program is not here, kept
       # just long enough that a journal answer can say so.
       exits: %{},
       exit_order: [],
       # `{path, mtime, size} => summary`. `Journal.list/2` fills it; a file that has not
       # changed is not parsed again.
       journal_cache: %{}
     }, {:continue, :retain}}
  end

  @impl true
  def handle_continue(:retain, state), do: {:noreply, retain(state)}

  @impl true
  def handle_call(:running, _from, state), do: {:reply, Map.keys(state.operations), state}

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

  def handle_call({:exit, operation}, _from, state),
    do: {:reply, Map.fetch(state.exits, operation), state}

  def handle_call({:worker, operation}, _from, state) do
    case Map.fetch(state.operations, operation) do
      {:ok, %{pid: pid}} -> {:reply, {:ok, pid}, state}
      :error -> {:reply, {:error, :no_worker}, state}
    end
  end

  def handle_call({:start, operation, kind, argv}, _from, state),
    do: open(state, operation, kind, argv)

  def handle_call({:resume, operation}, _from, state) do
    if Map.has_key?(state.operations, operation) do
      {:reply, {:error, :already_attached}, state}
    else
      with {:ok, dir} <- resolve_data_dir(state),
           {:ok, document} <- Journal.read(dir, operation),
           :ok <- resumable_state(document["state"]),
           {:ok, kind, argv} <- resume_argv(state, operation, document) do
        open(state, operation, kind, argv)
      else
        {:error, reason} -> {:reply, {:error, reason}, state}
      end
    end
  end

  def handle_call({:journals, dir}, _from, state) do
    {summaries, total, cache} = Journal.list(dir, state.journal_cache)
    {:reply, {summaries, total}, %{state | journal_cache: cache}}
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
         |> remember_exit(operation, reason)
         |> retain()}
    end
  end

  def handle_info(_other, state), do: {:noreply, state}

  defp drop_devices(state, pid) do
    case Map.pop(state.devices, pid) do
      {nil, _devices} ->
        state

      {ref, devices} ->
        Process.demonitor(ref, [:flush])
        %{state | devices: devices}
    end
  end

  # Only the program's own exit status, and only from the worker's own shutdown reason. A raw
  # exit reason is never kept: it can carry call arguments, and this map is read by `status`.
  defp remember_exit(state, operation, {:shutdown, {:exited, status}}) when is_integer(status) do
    order = [operation | state.exit_order -- [operation]]
    {order, exits} = trim_exits(order, Map.put(state.exits, operation, status))
    %{state | exits: exits, exit_order: order}
  end

  defp remember_exit(state, _operation, _reason), do: state

  defp trim_exits(order, exits) when length(order) <= @max_exits, do: {order, exits}

  defp trim_exits(order, exits) do
    {kept, dropped} = Enum.split(order, @max_exits)
    {kept, Map.drop(exits, dropped)}
  end

  # ---------------------------------------------------------------------------

  defp open(state, operation, kind, argv) do
    with {:ok, dir} <- resolve_data_dir(state),
         {:ok, ouro} <- resolve_executable(state),
         :ok <- private_deploy_dir(Journal.deploy_dir(dir)),
         {:ok, pid} <- start_worker(state, operation, kind, argv, dir, ouro) do
      entry = %{pid: pid, ref: Process.monitor(pid), kind: kind, argv: argv}

      {:reply, {:ok, %{"operation" => operation}},
       state
       |> put_in([:operations, operation], entry)
       |> put_in([:argv, operation], argv)
       |> Map.put(:exits, Map.delete(state.exits, operation))}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  # The exit is caught and the reason is *discarded*, not wrapped. A `DynamicSupervisor` that
  # is not running exits the caller rather than answering it, and that exit's reason carries
  # the child spec. The broker also does not die of a sibling that is restarting, which is the
  # other half of why this is a catch.
  defp start_worker(state, operation, kind, argv, dir, ouro) do
    DynamicSupervisor.start_child(
      state.supervisor,
      {Worker, [operation: operation, kind: kind, argv: argv, data_dir: dir, executable: ouro]}
    )
  catch
    :exit, _reason -> {:error, :client_supervisor_unavailable}
  end

  defp resolve_executable(state) do
    case state.executable.() do
      {:ok, path} -> {:ok, path}
      {:error, {:ouro_path_unknown, detail}} -> {:error, {:ouro_path_unknown, detail}}
    end
  end

  # `chmod` rather than a refusal: 0700 only ever *removes* access, the directory is this
  # uid's own, and both this runtime and the program create it. Narrowing is the one direction
  # a privacy repair is safe in without asking an operator first.
  defp private_deploy_dir(dir) do
    with :ok <- File.mkdir_p(dir), :ok <- File.chmod(dir, 0o700) do
      :ok
    else
      {:error, reason} -> {:error, {:worker_spawn_failed, {:deploy_dir_unwritable, reason}}}
    end
  end

  # This runtime's own memory of the command line first, because it is the one that ran.
  # Failing that the journal, which carries everything the argv needs except the two things
  # a resume does not decide again: the identity, which reaches a password prompt on its own,
  # and the service, whose step is either already recorded `ok` or is the default.
  defp resume_argv(state, operation, document) do
    kind = document["kind"]

    case Map.fetch(state.argv, operation) do
      {:ok, argv} ->
        {:ok, kind, argv}

      :error ->
        target = document["target"] || %{}
        paths = document["paths"] || %{}

        request = %{
          "kind" => kind,
          "machine" => target["machine"],
          "address" => target["address"],
          "ssh_user" => target["ssh_user"],
          "port" => target["port"],
          "install_path" => paths["install_path"],
          "data_dir" => paths["data_dir"]
        }

        with {:ok, argv} <- argv(request, operation), do: {:ok, kind, argv}
    end
  end

  defp resumable_state(recorded) when recorded in @terminal, do: {:error, :operation_finished}
  defp resumable_state(nil), do: {:error, :operation_state_unknown}
  defp resumable_state(_open), do: :ok

  # Completed and cancelled journals older than 30 days, and more than the newest 50 of those
  # two states, are swept here rather than left to accumulate under `<data dir>/deploy/`.
  # Failed and interrupted stay: they are resumable. Live workers are skipped even when the
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
end
