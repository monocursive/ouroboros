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

  ## Not yet shipped in a release

  The Rust worker this talks to is built alongside this module and is not in a released
  `ouro`. On a runtime whose `ouro` does not serve `fleet worker start`, every verb here
  answers a stable reason code rather than appearing to work.
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
  @spawn_timeout 10_000
  @call_timeout 20_000

  # An operation id names a Unix socket path, and `sun_path` is 104 bytes on this platform.
  # Eight random bytes is 2^64 of identity in sixteen characters, which leaves a data
  # directory room to be somewhere a person chose.
  @operation_bytes 8

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

  In that order, and under `:rest_for_one` where it is installed, so a broker that restarts
  never adopts client processes whose operations it has forgotten.
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

  # An allowlist rather than a merge. What `ouro` prints is a document this build reads three
  # named keys out of; a key it grows later is reported in `unknown` — the convention
  # `runtime.activity` already uses — rather than flowing into a reply whose shape nobody
  # here has checked.
  defp inventory(document, data_dir) do
    %{
      "host" => host(data_dir),
      "discovery" => Journal.scrub_value(document["discovery"]),
      "devices" => Journal.scrub_value(document["devices"]) || [],
      "fleet_protocol_revision" => document["fleet_protocol_revision"],
      "operations" => operations(data_dir),
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
  defp hostname do
    {:ok, name} = :inet.gethostname()
    List.to_string(name)
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
  defp deploy_blockers(data_dir, issuer?) do
    [
      if(is_nil(data_dir), do: "no_data_dir"),
      unless(issuer?, do: "no_ca_key"),
      case Launcher.executable() do
        {:ok, _path} -> nil
        {:error, {:ouro_path_unknown, _detail}} -> "ouro_path_unknown"
      end,
      if(cleartext_web_bind?(), do: "cleartext_web_bind")
    ]
    |> Enum.reject(&is_nil/1)
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
    web = Application.get_env(:ouroboros, :web, [])

    case {Keyword.get(web, :enabled, false), Keyword.get(web, :bind)} do
      {true, bind} when is_tuple(bind) -> not Ouroboros.Web.Config.loopback?(bind)
      _no_endpoint_or_no_bind -> false
    end
  end

  @doc """
  Every operation this data directory holds a journal for, with whether a worker is attached.

  The list is the journal's, not this process's: an operation whose broker connection died
  with a previous runtime is still an operation, and it is exactly the one `resume/2` exists
  for.
  """
  @spec operations(Path.t() | nil) :: [map()]
  def operations(data_dir \\ nil) do
    case data_dir || data_dir() do
      nil ->
        []

      dir ->
        attached = attached_operations()

        dir
        |> Journal.list()
        |> Enum.map(&Map.put(&1, "attached", &1["operation"] in attached))
    end
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

  Takes no binding. A challenge is bound to the session that was attached when it was issued
  (S4) and only a *response* is held to that; reading what an operation is doing is the
  administrator's read that the identity rule already gates, and making it fail for the
  second browser tab would be a restriction with no property behind it.
  """
  @spec status(String.t()) :: {:ok, map()} | {:error, term()}
  def status(operation) when is_binary(operation) do
    with :ok <- Journal.validate_operation(operation) do
      case client(operation) do
        {:ok, pid} -> Client.snapshot(pid)
        {:error, :no_worker} -> journal_status(operation)
      end
    end
  end

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
           |> Map.put("attached", false)}
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Mutations

  @doc """
  Starts inspection of one target: forks a worker, attaches to it, and answers its id.

  Answers as soon as the worker is attached, which is the point of the worker existing:
  inspection, host verification and authentication all happen behind the returned id rather
  than inside this call.
  """
  @spec prepare(map(), binding()) :: {:ok, map()} | {:error, term()}
  def prepare(request, binding) when is_map(request) and is_map(binding) do
    GenServer.call(__MODULE__, {:prepare, request, binding}, @call_timeout)
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
    with :ok <- Journal.validate_operation(operation),
         {:ok, pid} <- client(operation),
         :ok <- claim(operation, idempotency_key),
         {:ok, challenge} <- review_challenge(pid) do
      result =
        Client.respond(
          pid,
          challenge,
          ["review"],
          %{"approve" => true, "plan_digest" => plan_digest},
          binding
        )

      record(operation, idempotency_key, result)
      result
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
    with {:ok, pid} <- client(operation) do
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
  @spec cancel(String.t()) :: {:ok, map()} | {:error, term()}
  def cancel(operation) when is_binary(operation) do
    with {:ok, pid} <- client(operation), do: Client.cancel(pid)
  end

  @doc """
  Brings an interrupted operation back under a new worker.

  Refused when a worker is already attached — that is not a resume, that is a second worker
  for one operation — and refused when the journal says the operation reached a terminal
  state or cannot be read at all, because resuming an operation whose record is unreadable
  would be starting a second worker against a machine whose state nobody knows.
  """
  @spec resume(String.t(), binding()) :: {:ok, map()} | {:error, term()}
  def resume(operation, binding) when is_binary(operation) and is_map(binding) do
    with :ok <- Journal.validate_operation(operation) do
      GenServer.call(__MODULE__, {:resume, operation, binding}, @call_timeout)
    end
  end

  @doc "Sends `{:ouroboros_fleet_deployment, operation, event}` to the caller for every event."
  @spec subscribe(String.t()) :: :ok | {:error, term()}
  def subscribe(operation) do
    with {:ok, pid} <- client(operation), do: Client.subscribe(pid, self())
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
       operations: %{}
     }}
  end

  @impl true
  def handle_call(:attached, _from, state), do: {:reply, Map.keys(state.operations), state}

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

  def handle_call({:resume, operation, binding}, _from, state) do
    if Map.has_key?(state.operations, operation) do
      {:reply, {:error, :already_attached}, state}
    else
      case resumable(state, operation) do
        :ok -> open(state, operation, nil, binding)
        {:error, reason} -> {:reply, {:error, reason}, state}
      end
    end
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

  def handle_call({:record, operation, key, result}, _from, state) do
    case Map.fetch(state.operations, operation) do
      {:ok, %{key: ^key} = entry} ->
        {:reply, :ok, put_in(state.operations[operation], %{entry | result: result})}

      _other ->
        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, reason}, state) do
    case Enum.find(state.operations, fn {_id, entry} -> entry.ref == ref end) do
      nil ->
        {:noreply, state}

      {operation, _entry} ->
        Logger.info("fleet deployment operation #{operation} lost its worker: #{inspect(reason)}")
        {:noreply, %{state | operations: Map.delete(state.operations, operation)}}
    end
  end

  def handle_info(_other, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------

  # Spawn, then read the capability file, then connect. In that order because the worker
  # writes the capability file before its socket listens (S3): a capability that is not there
  # yet means a worker that is not listening yet, and connecting first would only make that
  # race harder to read.
  defp open(state, operation, request, binding) do
    with {:ok, dir} <- resolve_data_dir(state),
         {:ok, %{socket: socket, instance: instance}} <-
           state.launcher.spawn_worker(operation, dir, request, @spawn_timeout),
         {:ok, cap} <- read_capability(dir, operation),
         {:ok, pid} <- start_client(state, operation, instance, socket, cap, binding) do
      entry = %{
        pid: pid,
        ref: Process.monitor(pid),
        instance: instance,
        key: nil,
        result: nil
      }

      {:reply, {:ok, %{"operation_id" => operation, "instance" => instance}},
       put_in(state.operations[operation], entry)}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  defp start_client(state, operation, instance, socket, cap, binding) do
    DynamicSupervisor.start_child(
      state.supervisor,
      {Client,
       [
         operation: operation,
         instance: instance,
         socket_path: socket,
         cap: cap,
         subject: binding[:subject],
         session: binding[:session],
         clock: state.clock
       ]}
    )
  end

  # The capability is at least 32 hex characters in a 0600 file the worker removes when it
  # exits. Both facts are checked: a capability file anybody on this machine can read is not
  # a capability, and this refuses to present one rather than quietly accepting a weaker
  # boundary than the worker promised.
  defp read_capability(data_dir, operation) do
    path = Path.join(Journal.deploy_dir(data_dir), operation <> ".cap")

    with {:ok, %File.Stat{type: :regular, mode: mode, size: size}} when size <= 256 <-
           File.lstat(path),
         true <- Bitwise.band(mode, 0o077) == 0,
         {:ok, body} <- File.read(path),
         cap = String.trim(body),
         true <- String.match?(cap, ~r/\A[0-9a-fA-F]{32,128}\z/) do
      {:ok, cap}
    else
      {:error, :enoent} -> {:error, :capability_missing}
      false -> {:error, :capability_unusable}
      {:ok, %File.Stat{}} -> {:error, :capability_unusable}
      {:error, reason} -> {:error, {:capability_unreadable, reason}}
    end
  end

  defp resumable(state, operation) do
    with {:ok, dir} <- resolve_data_dir(state),
         {:ok, document} <- Journal.read(dir, operation) do
      case document["state"] do
        recorded when recorded in @terminal -> {:error, :operation_finished}
        nil -> {:error, :operation_state_unknown}
        _open -> :ok
      end
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

  defp claim(operation, key),
    do: GenServer.call(__MODULE__, {:claim, operation, key}, @call_timeout)

  defp record(operation, key, result),
    do: GenServer.call(__MODULE__, {:record, operation, key, result}, @call_timeout)

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
