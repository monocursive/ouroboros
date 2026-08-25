defmodule Ouroboros.Provider.Native.Subagent do
  @moduledoc """
  One child native session, owned by the parent session that spawned it (G3).

  A subagent is not a second interactive session. It is a *native session* — its own
  conversation, its own context window, its own checkpoint directory — running inside
  the parent's interactive session, under the parent's posture, reporting back as
  events of the parent. Nothing above the native provider learns that a child exists
  except through `provider_event` payloads of kind `subagent`, and nothing below it is
  special: the child is opened by the same `Ouroboros.Provider.Native.Session.open/2`
  any session is, and runs the same loop with the same permission engine, the same
  hooks, the same ledger.

  This process is the seam. It exists because three things have to be true at once and
  no single existing process can hold all three:

    * the child's events must be **collected and digested** rather than forwarded raw —
      a client that drew every event of every child would lose the parent's transcript
      in the noise;
    * a **background** child must outlive the parent's turn, so its owner cannot be the
      loop process, which ends with the turn;
    * a child that raises an approval must reach **the parent's** approval channel, so
      something has to translate a child request id into a parent one and back.

  ## The subscriber, and why there is exactly one

  Every message this process sends goes to one `subscriber` pid as
  `{:subagent, task_id, message}`:

      {:progress, payload}                     a bounded digest, at most @max_progress times
      {:approval, child_request_id, payload}   the child is asking; answer with respond/3
      {:settled, summary}                      terminal, once

  For a foreground child the subscriber is the **loop process**, because the loop is the
  only thing that can put an `approval_requested` in front of a person mid-turn and wait
  for the answer on its own mailbox. For a background child the subscriber is the
  **session process**, because the loop will be gone. The subscriber is monitored: a
  foreground child whose parent turn died has nobody to report to, and is stopped rather
  than left running against a workspace nobody is watching.

  A background child therefore has no way to reach a human, which is why
  `Ouroboros.Provider.Native.Tools.Agent` refuses to spawn one whose tools could ask.
  If one asks anyway — a rule engine that changed under it, an MCP tool that classifies
  as `:execute` — the request is **denied immediately with a legible reason** and counted
  in the digest, rather than left to hang until the child's approval deadline.

  ## Lifecycle, precisely

    * **Spawn.** `spawn/1` starts this process under
      `Jido.Harness.SessionTransportSupervisor` — the same supervisor the child session
      itself is started under, `:temporary` for the same reason — and opens the child
      session synchronously, bounded by `@open_timeout`. A failure to open is returned to
      the caller; nothing is left behind.
    * **Run.** The child runs exactly one turn. Its model round-trips are bounded by the
      `max_turns` the caller asked for (the child's `max_iterations`), and the whole child
      is bounded by a wall-clock deadline. The deadline fires here, not in the child: a
      child wedged inside a tool would never see its own.
    * **Settle.** The child's terminal turn event settles this process into
      `completed`/`failed`, the deadline settles it into `timed_out`, `stop/2` settles it
      into `stopped`. A settled subagent keeps its summary and stays alive so a later
      `agent_result` can collect it.
    * **End.** The parent session closing stops every subagent it tracks, settled or not,
      and a collected background child is stopped by its collector. On the way out the
      child session is closed and the worktree, if any, is retired — removed when clean,
      **kept and reported when it holds uncommitted work**, which is
      `Ouroboros.Workspace.Worktree`'s rule and not this module's to soften.

  ## A child on another node

  `spec.node` names the node the child runs on, and `node()` is the ordinary value of it.
  When it names another node, `spawn/1` sends `start_and_launch/1` there by `:erpc` and
  everything after that is unchanged: the returned pid is a remote pid, and
  `await/2`, `summary/1`, `stop/2`, `respond/3`, the `{:subagent, task_id, …}` messages
  and the subscriber monitor all work across the distribution link exactly as they do
  inside one VM. That is why this process, and not the loop, is what moves.

  **The launch runs on the child's node, and that is the whole design.**
  `Jido.Harness.SessionRequest.new/1` validates `File.dir?(cwd)`, and a git worktree is a
  directory on a disk: building either on the parent's node would answer a question about
  the target's filesystem by looking at the wrong one — the defect `docs/FLEET.md` records
  as F2. So the spec carries `request_attrs` (a plain map) and `worktree` (a boolean
  *request*), and this process turns them into a request, and possibly a worktree, where
  they mean something.

  What that buys, and what it costs, stated plainly:

    * the child is fenced by its own workspace root **on the target**, judged by the
      **target's** permission rules, engine, hooks and sandbox, and writes its transcript,
      its checkpoints and its effect-ledger entries **there**. A worktree, if one was asked
      for, is leased against the target's `workspace_allowed_roots`;
    * MCP tool names inherited through the parent's tool intersection resolve against the
      **target's** MCP configuration. A name the target does not serve is refused in-band
      there, as an ordinary failed tool result of the child, rather than at spawn;
    * `add_dirs` is empty for a remote child: a root of the parent's machine is not a root
      of the target's;
    * the parent's **posture** does travel, because it rides in `request_attrs` —
      `approval_mode`, the resolved `sandbox_mode`, the `plan` flag, the tool intersection,
      the model, `max_iterations`, the deadline;
    * approvals still reach the **parent's** human. The child raises one on the target,
      this process relays it to the subscriber pid on the parent node, the parent's loop
      puts it to a person, and the answer comes back by `respond/3`.

  The spec crosses the wire, so it must hold nothing that means only what this VM says it
  means. `Ouroboros.Provider.Native.Tools.Agent` scrubs funs, ports and references out of
  the harness context and the provider options before a remote spawn; pids are kept, since
  the subscriber is one and reaching back to it is the point.

  ## Bounds

  Every number here is a ceiling, and each is named where it is enforced:
  `@max_summary_bytes` on the summary the parent sees, `@max_text_bytes` on the child's
  final message inside it, `@max_files` on the changed-path list, `@max_progress` on how
  many progress events one child may produce, and the caller's deadline on the whole
  thing. The child's own events are bounded by exactly what bounds any native session's,
  because it is one. A remote spawn adds one more: `@remote_spawn_timeout`, so a node that
  accepted the connection and then went quiet fails the spawn instead of holding the turn.
  """

  use GenServer, restart: :temporary

  alias Jido.Harness.ApprovalResponse
  alias Jido.Harness.SessionRequest
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Session
  alias Ouroboros.Workspace.Worktree

  @open_timeout 30_000
  # The erpc bound on a remote spawn. It has to exceed the launch call it wraps
  # (`@open_timeout + 5_000`) by a margin, or a target that is merely slow would be
  # reported as unreachable while it is still opening a session.
  @remote_spawn_timeout @open_timeout + 20_000
  @remote_stop_timeout 15_000
  @registry Ouroboros.Provider.Native.Registry
  @max_summary_bytes 16 * 1024
  @max_text_bytes 12 * 1024
  @max_files 50
  @max_progress 64
  @max_description_bytes 200

  @typedoc "What a caller asks for when it spawns a child."
  @type spec :: %{
          required(:task_id) => String.t(),
          required(:prompt) => String.t(),
          required(:description) => String.t(),
          required(:subscriber) => pid(),
          required(:request_attrs) => map(),
          required(:context) => map(),
          optional(:node) => node(),
          optional(:remote) => boolean(),
          optional(:worktree) => boolean(),
          optional(:deadline_ms) => pos_integer(),
          optional(:background) => boolean(),
          optional(:depth) => non_neg_integer(),
          optional(:tools) => [String.t()]
        }

  # ---------------------------------------------------------------- api

  @doc """
  Starts a child session for `spec` and sends it its prompt.

  Returns
  `{:ok, %{pid:, task_id:, provider_session_id:, session_dir:, worktree:, workspace:, node:, remote:}}`,
  or `{:error, reason}`. The open is synchronous and bounded: a caller that got `:ok` has
  a child that is running, not one that may yet fail to start. A remote transport failure
  is explicitly reported as ambiguous if the target cannot be reconciled; it never claims
  that nothing ran after `:erpc` has admitted that the call may have been applied.

  `spec.node` places the child. When it names another node the whole start — this process,
  the worktree, the request, the session — happens **there**, and the `pid` that comes back
  is a remote one that every other function in this module accepts unchanged.
  """
  @spec spawn(spec()) :: {:ok, map()} | {:error, term()}
  def spawn(spec) do
    case Map.get(spec, :node) || node() do
      target when target == node() -> start_and_launch(spec)
      target -> spawn_remote(target, spec)
    end
  end

  @doc """
  Starts and launches one child **on this node**, for `spawn/1` and for its own `:erpc`.

  Public because `:erpc.call/5` needs a named function to call on the target, and private
  because nothing else should call it: `spawn/1` is the entry point that knows where a
  child belongs.
  """
  @spec start_and_launch(spec()) :: {:ok, map()} | {:error, term()}
  def start_and_launch(spec) do
    case DynamicSupervisor.start_child(
           Jido.Harness.SessionTransportSupervisor,
           {__MODULE__, spec}
         ) do
      {:ok, pid} ->
        case safe_call(pid, :launch, @open_timeout + 5_000) do
          {:ok, started} ->
            {:ok, Map.put(started, :pid, pid)}

          {:error, _reason} = error ->
            _ = stop_process(pid)
            error
        end

      {:error, {:already_started, pid}} ->
        recover_started(pid, spec)

      {:error, reason} ->
        {:error, {:subagent_unstartable, reason}}
    end
  end

  # `:erpc` documents timeout and connection loss as ambiguous: the target function may or
  # may not have been applied. `start_and_launch/1` is therefore idempotent by `task_id`, and
  # the second call is reconciliation rather than a second child. If both calls lose their
  # answer, say exactly that; the subscriber monitor still stops any applied child when the
  # parent turn/session disappears.
  defp spawn_remote(target, spec) do
    case remote_start_call(target, spec) do
      {:returned, result} -> remote_start_result(target, result)
      {:ambiguous, first} -> reconcile_remote_start(target, spec, first)
    end
  end

  defp reconcile_remote_start(target, spec, first) do
    case remote_start_call(target, spec) do
      {:returned, result} ->
        remote_start_result(target, result)

      {:ambiguous, second} ->
        {:error,
         {:subagent_unstartable, {:remote_start_ambiguous, target, spec.task_id, {first, second}}}}
    end
  end

  defp remote_start_call(target, spec) do
    {:returned, :erpc.call(target, __MODULE__, :start_and_launch, [spec], @remote_spawn_timeout)}
  catch
    :error, {:erpc, reason} -> {:ambiguous, reason}
    kind, reason -> {:ambiguous, {kind, reason}}
  end

  defp remote_start_result(_target, {:ok, started}), do: {:ok, started}
  defp remote_start_result(_target, {:error, _reason} = error), do: error

  defp remote_start_result(target, other),
    do: {:error, {:subagent_unstartable, {:remote_spawn_failed, target, other}}}

  defp recover_started(pid, spec) do
    provider_session_id = Map.get(spec.request_attrs, :provider_session_id)

    case safe_call(pid, {:recover_start, provider_session_id}, @open_timeout + 5_000) do
      {:ok, _started} = ok -> ok
      {:error, reason} -> {:error, {:subagent_unstartable, reason}}
    end
  end

  @doc "This child's summary now, whether or not it has settled."
  @spec summary(pid()) :: {:ok, map()} | {:error, term()}
  def summary(pid), do: safe_call(pid, :summary, 5_000)

  @doc """
  Waits up to `timeout_ms` for this child to settle and returns its summary.

  `{:error, :still_running}` is not a failure of the child: it is the honest answer that
  the wait this caller was allowed expired first, and the task id is still collectable.
  """
  @spec await(pid(), non_neg_integer()) :: {:ok, map()} | {:error, term()}
  def await(pid, timeout_ms) when is_integer(timeout_ms) and timeout_ms >= 0,
    do: safe_call(pid, {:await, timeout_ms}, timeout_ms + 5_000)

  @doc "Answers one approval this child raised, by the child's own request id."
  @spec respond(pid(), String.t(), ApprovalResponse.t()) :: :ok
  def respond(pid, child_request_id, %ApprovalResponse{} = response) do
    GenServer.cast(pid, {:respond, child_request_id, response})
  catch
    :exit, _reason -> :ok
  end

  @doc """
  Stops this child and settles it under `reason` if it has not settled already.

  `:stopped` is the reason a parent uses when it is going away; `:timed_out` is the
  deadline's. A child that had already completed keeps the status it earned — a stop
  after the fact does not rewrite what happened.
  """
  @spec stop(pid(), :stopped | :timed_out) :: {:ok, map()} | {:error, term()}
  def stop(pid, reason \\ :stopped) do
    result = safe_call(pid, {:settle, reason}, 10_000)
    _ = stop_process(pid)
    result
  end

  @doc "Renders one summary as the bounded text a tool result carries."
  @spec render(map()) :: String.t()
  def render(summary) do
    header =
      "Subagent #{summary.task_id} (#{summary.description}) #{summary.status}" <>
        where(summary) <>
        "." <>
        if(summary.error, do: " #{summary.error}", else: "")

    digest =
      "— #{summary.turns} model turn(s), #{summary.tool_calls} tool call(s), " <>
        "#{summary.files_changed_count} file(s) changed, " <>
        "#{summary.usage.input} in / #{summary.usage.output} out tokens" <>
        cost_text(summary.usage.cost)

    [
      header,
      "",
      clip(summary.text, @max_text_bytes),
      "",
      digest,
      files_line(summary.files_changed, summary.files_changed_count),
      worktree_line(summary.worktree),
      approvals_line(summary.approvals_denied),
      "Transcript: #{summary.provider_session_id}"
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join("\n")
    |> clip(@max_summary_bytes)
  end

  @doc false
  def start_link(spec),
    do: GenServer.start_link(__MODULE__, spec, name: via(spec.task_id))

  # ---------------------------------------------------------------- server

  # A local child's summary reads exactly as it always did. A remote one says where it ran,
  # because "completed" about a machine the reader did not pick is half a sentence.
  defp where(summary) do
    if Map.get(summary, :remote, false) and Map.get(summary, :node),
      do: " on #{summary.node}",
      else: ""
  end

  @impl GenServer
  def init(spec) do
    subscriber = spec.subscriber
    monitor = Process.monitor(subscriber)
    request_attrs = Map.get(spec, :request_attrs) || %{}

    # Which node the *parent* is on, read off the subscriber rather than carried in the
    # spec: the subscriber is the pid this child reports to, so it is the definition of
    # "the other end" and cannot drift from one.
    origin = if is_pid(subscriber), do: node(subscriber), else: node()

    {:ok,
     %{
       task_id: spec.task_id,
       description: clip(spec.description, @max_description_bytes),
       prompt: spec.prompt,
       request_attrs: request_attrs,
       request: nil,
       workspace: Map.get(request_attrs, :cwd),
       context: spec.context,
       origin: origin,
       remote?: node() != origin,
       worktree_requested?: Map.get(spec, :worktree) == true,
       worktree: nil,
       background?: Map.get(spec, :background, false),
       depth: Map.get(spec, :depth, 1),
       tools: Map.get(spec, :tools, []),
       deadline_ms: Map.get(spec, :deadline_ms, 300_000),
       subscriber: subscriber,
       subscriber_monitor: monitor,
       handle: nil,
       provider_session_id: nil,
       session_dir: nil,
       turn_id: nil,
       status: :starting,
       error: nil,
       turns: 0,
       tool_calls: 0,
       files: [],
       files_count: 0,
       approvals_denied: 0,
       open_approvals: MapSet.new(),
       progress_sent: 0,
       # `cost` starts as `nil` rather than `0.0`, and stays `nil` until some `usage`
       # payload actually carried a price. `Ouroboros.Provider.Native.Cost` omits
       # `cost_usd` for a model it cannot price, and a zero folded in on its behalf would
       # render in a footer as a free child.
       usage: %{input: 0, output: 0, cost: nil},
       text: "",
       deadline_timer: nil,
       waiters: []
     }}
  end

  @impl GenServer
  def handle_call(:launch, _from, %{status: :starting} = state) do
    case launch(state) do
      {:ok, state} ->
        {:reply, {:ok, started_of(state)}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:launch, _from, state), do: {:reply, {:error, :already_launched}, state}

  def handle_call({:recover_start, provider_session_id}, _from, state) do
    expected = Map.get(state.request_attrs, :provider_session_id)

    cond do
      provider_session_id != expected ->
        {:reply, {:error, {:subagent_task_id_collision, state.task_id}}, state}

      state.status == :starting ->
        {:reply, {:error, :subagent_still_starting}, state}

      true ->
        {:reply, {:ok, started_of(state)}, state}
    end
  end

  def handle_call(:summary, _from, state), do: {:reply, {:ok, summary_of(state)}, state}

  def handle_call({:await, _timeout}, _from, %{status: status} = state)
      when status in [:completed, :failed, :stopped, :timed_out],
      do: {:reply, {:ok, summary_of(state)}, state}

  def handle_call({:await, timeout_ms}, from, state) do
    timer = Process.send_after(self(), {:await_expired, from}, timeout_ms)
    {:noreply, %{state | waiters: [{from, timer} | state.waiters]}}
  end

  def handle_call({:settle, reason}, _from, state) do
    state = settle(state, reason, settle_note(reason))
    {:reply, {:ok, summary_of(state)}, state}
  end

  @impl GenServer
  def handle_cast({:respond, child_request_id, response}, state) do
    if state.handle && MapSet.member?(state.open_approvals, child_request_id) do
      _ = Session.respond_approval(state.handle, child_request_id, response)
      {:noreply, %{state | open_approvals: MapSet.delete(state.open_approvals, child_request_id)}}
    else
      {:noreply, state}
    end
  end

  @impl GenServer
  def handle_info({:session_adapter_event, event}, state), do: {:noreply, absorb(state, event)}

  def handle_info({:subagent_deadline, task_id}, %{task_id: task_id} = state),
    do: {:noreply, settle(state, :timed_out, "the child's wall-clock deadline expired")}

  def handle_info({:await_expired, from}, state) do
    case List.keytake(state.waiters, from, 0) do
      {{^from, timer}, rest} ->
        _ = timer && Process.cancel_timer(timer)
        GenServer.reply(from, {:error, :still_running})
        {:noreply, %{state | waiters: rest}}

      nil ->
        {:noreply, state}
    end
  end

  # The subscriber going away is terminal for this child. A foreground child's loop has
  # ended; a background child's session has closed. Either way there is nobody left to
  # report to, and a child that kept editing a workspace nobody is watching would be the
  # one thing a bounded runtime must not leave behind.
  def handle_info(
        {:DOWN, monitor, :process, _pid, _reason},
        %{subscriber_monitor: monitor} = state
      ) do
    {:stop, :normal, settle(state, :stopped, "the parent stopped watching this child")}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl GenServer
  def terminate(_reason, state) do
    _ = close_child(state)
    _ = retire_worktree(state)
    :ok
  rescue
    _error -> :ok
  end

  # ---------------------------------------------------------------- launch

  # Three steps, in this order, and every one of them a fact about **this** node's
  # filesystem: lease the worktree if one was asked for, validate the request against the
  # directory it names, open the session in it. On the parent's node for a local child; on
  # the target for a remote one, which is the only place any of the three is true.
  defp launch(state) do
    with {:ok, state} <- provision_worktree(state),
         {:ok, request} <- build_request(state) do
      open_child(%{state | request: request, workspace: request.cwd})
    end
  end

  # A refusal here is never a silent fall back to the parent's tree. A model that asked for
  # isolation and got the parent's working copy would make edits it believes are contained,
  # which is the worst of the three possible outcomes.
  # `Ouroboros.Provider.Native.Tools.Agent.start_refusal/1` says each of these in words.
  defp provision_worktree(%{worktree_requested?: false} = state), do: {:ok, state}

  defp provision_worktree(state) do
    root = Map.get(state.request_attrs, :cwd)

    if Worktree.admissible?() do
      case Worktree.create(root, worktree_id()) do
        {:ok, worktree} ->
          {:ok,
           %{
             state
             | worktree: Worktree.public(worktree),
               request_attrs: Map.put(state.request_attrs, :cwd, worktree.root)
           }}

        {:error, reason} ->
          {:error, {:subagent_worktree_unprovisionable, node(), reason}}
      end
    else
      {:error, {:subagent_worktree_root_not_admitted, node()}}
    end
  end

  # `new/1` rather than `new!/1`, because the validation that matters most here —
  # `File.dir?(cwd)` — is exactly the one a caller can get wrong, and a raise inside an
  # erpc would reach the parent as an exception instead of a sentence. The reason is
  # rendered to a binary before it travels: an exception struct from the target is a term
  # the parent has no reason to reconstruct.
  defp build_request(state) do
    case SessionRequest.new(state.request_attrs) do
      {:ok, request} ->
        {:ok, request}

      {:error, reason} ->
        {:error,
         {:subagent_request_invalid, node(), Map.get(state.request_attrs, :cwd), describe(reason)}}
    end
  end

  # The child's `owner` is **this** process and never the subscriber. A subscriber gets a
  # digest; the raw stream belongs here, where it is counted, bounded, and turned into one.
  # Pointing a child at the loop directly would also rename the parent's provider session,
  # because the harness worker adopts the `provider_session_id` of any adapter event it
  # receives.
  defp open_child(state) do
    case Session.open(state.request, Map.put(state.context, :owner, self())) do
      {:ok, handle} ->
        provider_session_id = state.request.provider_session_id
        turn_id = "sub_turn_" <> random(9)

        state = %{
          state
          | handle: handle,
            provider_session_id: provider_session_id,
            session_dir: session_dir(provider_session_id),
            turn_id: turn_id,
            status: :running,
            deadline_timer:
              Process.send_after(self(), {:subagent_deadline, state.task_id}, state.deadline_ms)
        }

        case Session.send(state.handle, TurnRequest.new!(state.prompt), turn_id) do
          :ok -> {:ok, state}
          other -> {:error, {:subagent_turn_refused, other}}
        end

      {:error, reason} ->
        {:error, {:subagent_session_unopenable, reason}}
    end
  end

  defp session_dir(provider_session_id) do
    case Paths.session_dir(provider_session_id) do
      {:ok, dir, _durable?} -> dir
      {:error, _reason} -> nil
    end
  end

  # ---------------------------------------------------------------- events

  # The child's stream, digested. Nothing here is forwarded verbatim: the parent's
  # transcript carries a summary and a bounded progress line, and the child's own
  # transcript — every event, every tool result — is on disk under its session
  # directory, addressable by the `provider_session_id` the spawn event names.
  defp absorb(%{status: status} = state, _event)
       when status in [:completed, :failed, :stopped, :timed_out],
       do: state

  defp absorb(state, %{type: :approval_requested} = event), do: relay_approval(state, event)

  defp absorb(state, %{type: :tool_call}),
    do: progress(%{state | tool_calls: state.tool_calls + 1})

  defp absorb(state, %{type: :tool_result}), do: progress(state)

  defp absorb(state, %{type: :usage, payload: payload}) when is_map(payload) do
    %{
      state
      | turns: state.turns + 1,
        usage: %{
          input: state.usage.input + number(payload, "input_tokens"),
          output: state.usage.output + number(payload, "output_tokens"),
          cost: add_cost(state.usage.cost, Map.get(payload, "cost_usd"))
        }
    }
    |> progress()
  end

  defp absorb(state, %{type: :file_change, payload: payload}) when is_map(payload) do
    paths =
      payload
      |> Map.get("changes", [])
      |> List.wrap()
      |> Enum.flat_map(&change_path/1)

    merged = Enum.uniq(state.files ++ paths)

    %{state | files: Enum.take(merged, @max_files), files_count: length(merged)}
  end

  defp absorb(state, %{type: :output_text_final, payload: %{"text" => text}})
       when is_binary(text),
       do: %{state | text: text}

  defp absorb(state, %{type: :turn_completed, payload: payload}),
    do: settle(%{state | turns: max(state.turns, iterations(payload))}, :completed, nil)

  defp absorb(state, %{type: :turn_failed, payload: payload}),
    do: settle(state, :failed, error_text(payload))

  defp absorb(state, %{type: :turn_interrupted}),
    do: settle(state, :stopped, "the child's turn was interrupted")

  defp absorb(state, _event), do: state

  defp change_path(%{"relative_path" => path}) when is_binary(path) and path != "", do: [path]
  defp change_path(%{"path" => path}) when is_binary(path) and path != "", do: [path]
  defp change_path(_unnamed), do: []

  defp iterations(%{"iterations" => n}) when is_integer(n) and n >= 0, do: n
  defp iterations(_payload), do: 0

  defp error_text(%{"error" => error}) when is_binary(error), do: clip(error, 500)
  defp error_text(_payload), do: "the child's turn failed"

  defp settle_note(:timed_out), do: "the child's wall-clock deadline expired"
  defp settle_note(_stopped), do: "the parent stopped this child"

  # A child's approval is the parent's approval. Forwarding it is the whole of the
  # translation: the loop mints a parent request id, puts it on the parent's own
  # approval channel, and hands the answer back to `respond/3`, which addresses the
  # child by the id the child minted. Two id spaces, one person.
  defp relay_approval(%{background?: true} = state, %{request_id: request_id})
       when is_binary(request_id) do
    _ = deny_unreachable(state, request_id)
    %{state | approvals_denied: state.approvals_denied + 1}
  end

  defp relay_approval(state, %{request_id: request_id, payload: payload})
       when is_binary(request_id) do
    notify(state, {:approval, request_id, payload})
    %{state | open_approvals: MapSet.put(state.open_approvals, request_id)}
  end

  defp relay_approval(state, _event), do: state

  defp deny_unreachable(%{handle: nil}, _request_id), do: :ok

  defp deny_unreachable(%{handle: handle}, request_id) do
    Session.respond_approval(
      handle,
      request_id,
      ApprovalResponse.new!(%{
        decision: :deny,
        scope: :once,
        reason:
          "this subagent runs in the background, where an approval has nobody to reach. " <>
            "Do the part that needs permission in the foreground, or ask the parent for it."
      })
    )
  catch
    :exit, _reason -> :ok
  end

  defp progress(%{progress_sent: sent} = state) when sent >= @max_progress, do: state

  defp progress(state) do
    notify(state, {:progress, progress_payload(state)})
    %{state | progress_sent: state.progress_sent + 1}
  end

  defp progress_payload(state) do
    %{
      "phase" => "progress",
      "task_id" => state.task_id,
      "description" => state.description,
      "provider_session_id" => state.provider_session_id,
      "turns" => state.turns,
      "tool_calls" => state.tool_calls,
      "files_changed" => state.files_count,
      "node" => Atom.to_string(node())
    }
  end

  defp notify(%{subscriber: subscriber, task_id: task_id}, message) when is_pid(subscriber),
    do: Kernel.send(subscriber, {:subagent, task_id, message})

  defp notify(_state, _message), do: :ok

  # ---------------------------------------------------------------- settling

  defp settle(%{status: status} = state, _reason, _error)
       when status in [:completed, :failed, :stopped, :timed_out],
       do: state

  defp settle(state, reason, error) do
    _ = state.deadline_timer && Process.cancel_timer(state.deadline_timer)

    state = %{
      state
      | status: reason,
        error: error || state.error,
        deadline_timer: nil,
        open_approvals: MapSet.new()
    }

    # The child session is closed *before* the summary goes out, so the transcript on
    # disk is at least as new as the digest that describes it — the same
    # checkpoint-before-broadcast ordering the session itself keeps.
    _ = close_child(state)
    state = %{state | worktree: retire_worktree(state), handle: nil}

    summary = summary_of(state)
    notify(state, {:settled, summary})
    reply_waiters(state, summary)
  end

  defp reply_waiters(state, summary) do
    Enum.each(state.waiters, fn {from, timer} ->
      _ = timer && Process.cancel_timer(timer)
      GenServer.reply(from, {:ok, summary})
    end)

    %{state | waiters: []}
  end

  defp close_child(%{handle: nil}), do: :ok

  defp close_child(%{handle: handle}) do
    if Process.alive?(handle), do: Session.close(handle), else: :ok
  catch
    :exit, _reason -> :ok
  end

  # A worktree that holds uncommitted work is kept and said so. This module never
  # deletes a change: `Ouroboros.Workspace.Worktree.remove/2` is the authority, and its
  # refusal to remove a dirty tree is reported as the child's own result rather than
  # worked around.
  defp retire_worktree(%{worktree: nil}), do: nil

  defp retire_worktree(%{worktree: %{"retired" => _already} = worktree}), do: worktree

  defp retire_worktree(%{worktree: worktree}) do
    case Worktree.remove(Map.fetch!(worktree, "path")) do
      {:ok, :removed} -> Map.put(worktree, "retired", "removed")
      {:ok, {:kept, _reason}} -> Map.put(worktree, "retired", "kept")
      {:error, _reason} -> Map.put(worktree, "retired", "kept")
    end
  rescue
    _error -> Map.put(worktree, "retired", "kept")
  end

  defp summary_of(state) do
    %{
      task_id: state.task_id,
      description: state.description,
      provider_session_id: state.provider_session_id,
      session_dir: state.session_dir,
      # The child's own turn id. It is in the summary because the parent's usage fold is
      # attributed to it: the tokens were spent in this turn, not in the parent's, and the
      # plane's per-turn accounting reads two reports of one turn as one being a re-report
      # of the other.
      turn_id: state.turn_id,
      status: state.status,
      error: state.error,
      turns: state.turns,
      tool_calls: state.tool_calls,
      files_changed: state.files,
      files_changed_count: state.files_count,
      approvals_denied: state.approvals_denied,
      usage: %{
        input: state.usage.input,
        output: state.usage.output,
        cost: state.usage.cost && Float.round(state.usage.cost / 1, 6)
      },
      text: clip(state.text, @max_text_bytes),
      worktree: state.worktree,
      workspace: state.workspace,
      # Where the work happened. `node` is this process's own node — the child's — and
      # `remote` is whether that differs from the node the subscriber is on, which is the
      # only definition of "remote" that stays true no matter who reads the summary.
      node: node(),
      remote: state.remote?,
      background: state.background?,
      depth: state.depth,
      tools: state.tools
    }
  end

  @doc "The digest a `provider_event` carries when a child settles."
  @spec settled_payload(map()) :: map()
  def settled_payload(summary) do
    %{
      "phase" => "settled",
      "task_id" => summary.task_id,
      "description" => summary.description,
      "provider_session_id" => summary.provider_session_id,
      "status" => Atom.to_string(summary.status),
      "turns" => summary.turns,
      "tool_calls" => summary.tool_calls,
      "files_changed" => summary.files_changed_count,
      "files" => summary.files_changed,
      "input_tokens" => summary.usage.input,
      "output_tokens" => summary.usage.output,
      "approvals_denied" => summary.approvals_denied,
      "summary_bytes" => byte_size(summary.text),
      # Defaulted rather than fetched: a summary minted by a parent that could not reach its
      # child at all still has to answer "where", and `node()` is the honest answer for one
      # this runtime never heard from.
      "node" => Atom.to_string(Map.get(summary, :node) || node()),
      "remote" => Map.get(summary, :remote, false)
    }
    |> maybe_put("cost_usd", summary.usage.cost)
    |> maybe_put("error", summary.error)
    |> maybe_put("worktree", summary.worktree)
  end

  # ---------------------------------------------------------------- helpers

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp cost_text(cost) when is_number(cost) and cost > 0, do: ", $#{Float.round(cost / 1, 6)}"
  defp cost_text(_cost), do: ""

  defp files_line([], _count), do: nil

  defp files_line(files, count) do
    suffix = if count > length(files), do: " (+#{count - length(files)} more)", else: ""
    "Files: " <> Enum.join(files, ", ") <> suffix
  end

  defp worktree_line(%{"path" => path, "retired" => "kept"}),
    do: "Worktree kept (it holds uncommitted work): #{path}"

  defp worktree_line(%{"path" => path}), do: "Worktree: #{path}"
  defp worktree_line(_absent), do: nil

  defp approvals_line(0), do: nil

  defp approvals_line(n),
    do:
      "#{n} approval(s) this child raised were denied: a background child has no way to " <>
        "reach a person."

  defp number(payload, key) do
    case Map.get(payload, key) do
      value when is_number(value) and value >= 0 -> value
      _absent -> 0
    end
  end

  defp add_cost(running, value) when is_number(value) and value >= 0, do: (running || 0.0) + value
  defp add_cost(running, _unpriced), do: running

  defp random(bytes), do: Base.url_encode64(:crypto.strong_rand_bytes(bytes), padding: false)

  defp started_of(state) do
    %{
      pid: self(),
      task_id: state.task_id,
      provider_session_id: state.provider_session_id,
      session_dir: state.session_dir,
      worktree: state.worktree,
      # The directory the child actually runs in, and the node it runs on, both settle on
      # the target rather than being guessed by a remote caller.
      workspace: state.workspace,
      node: node(),
      remote: state.remote?
    }
  end

  defp via(task_id), do: {:via, Registry, {@registry, {:subagent, task_id}}}

  # `Ouroboros.Workspace.Worktree` validates this as a directory name, so it is minted in
  # the shape that validator accepts rather than borrowed from a caller.
  defp worktree_id, do: "subagent-" <> random(9)

  defp describe(%{__exception__: true} = error), do: clip(Exception.message(error), 500)
  defp describe(reason) when is_binary(reason), do: clip(reason, 500)
  defp describe(reason), do: reason |> inspect() |> clip(500)

  defp clip(text, limit) when is_binary(text) and byte_size(text) <= limit, do: text
  defp clip(text, limit) when is_binary(text), do: binary_part(text, 0, limit) <> "…"
  defp clip(_text, _limit), do: ""

  defp safe_call(pid, message, timeout) do
    GenServer.call(pid, message, timeout)
  catch
    :exit, reason -> {:error, {:subagent_unreachable, reason}}
  end

  # `Jido.Harness.SessionTransportSupervisor` is a locally registered name, so terminating a
  # remote child has to happen **on its own node** — asking this node's supervisor about a
  # pid that was never its child answers `{:error, :not_found}` and leaves the child running
  # against a workspace nobody is watching, which is the one outcome this module exists to
  # prevent.
  defp stop_process(pid) do
    case node(pid) do
      target when target == node() ->
        DynamicSupervisor.terminate_child(Jido.Harness.SessionTransportSupervisor, pid)

      target ->
        :erpc.call(
          target,
          DynamicSupervisor,
          :terminate_child,
          [Jido.Harness.SessionTransportSupervisor, pid],
          @remote_stop_timeout
        )
    end
  catch
    _kind, _reason -> :ok
  end
end
