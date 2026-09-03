defmodule Ouroboros.Provider.Session.Service do
  @moduledoc """
  The file and terminal work an agent asks *this runtime* to do, and its ceilings.

  ACP is the one protocol here where the traffic runs both ways. An agent may call the
  client — `fs/read_text_file`, `fs/write_text_file`, `terminal/create` and the four
  verbs that follow it — and a client that declares those capabilities is promising to
  perform them. Ouroboros wants to be that client rather than let each agent reach the
  filesystem behind the runtime's back: an edit that arrives here becomes a real
  `file_change` with a unified diff, a command that arrives here runs under the same OS
  sandbox the native `bash` runs under, and both are decided before anything happens by
  the engine `config :ouroboros, :permissions_engine` names (W18, D27).

  Everything in this module runs **inside the `Session.Jsonl` process**. Nothing blocks:
  a terminal is a port owned by that process, its output arrives as ordinary messages,
  and `terminal/wait_for_exit` parks the agent's request id rather than the process. That
  is what keeps one agent's ten-minute build from stopping the session's own turn
  traffic.

  ## What each service is judged as

  | service | permission request | sandbox |
  |---|---|---|
  | `fs/read_text_file` | none — containment only | none |
  | `fs/write_text_file` | `tool: edit` (existing file) or `tool: write` (new), `mode: :write` | none |
  | `terminal/create` | `tool: bash`, `mode: :execute`, with the command line | the session's `sandbox_mode`, through `Native.Sandbox` |
  | `terminal/output` `wait_for_exit` `kill` `release` | none — they act on a terminal already decided | inherited |

  A read is containment-only on purpose. The agent is a child process of this node with
  the same filesystem credentials; serving its read adds no authority it did not have,
  and putting every file it opens through an `:ask` would produce a prompt per file and
  train the operator to stop reading them (`AGENT_EXPERIENCE` §2.5). A **write** is the
  opposite — the runtime performs it — so it is decided, and an `:ask` becomes an
  ordinary approval on the session's existing approval channel.

  ## The sandbox posture, stated rather than implied

  `terminal/create` gets exactly what `Ouroboros.Provider.Native.Tools.Bash` gets, from
  the same `Ouroboros.Provider.Native.Sandbox`: wrapped where the node has a backend,
  plain with the reason reported where `workspace_write` meets a node with none, and
  **refused** where `read_only` meets a node with none — because a terminal that cannot
  be made read-only under a read-only label is a lie about the label. There is no seccomp
  filter on Linux and no domain allowlist anywhere; see that module for the full list of
  what an OS sandbox here does not do.

  ## Bounds

  Every one of these is a hard ceiling, not a default:

    * a file read or write is at most #{div(1_048_576, 1024)} KiB;
    * a session holds at most #{8} live terminals;
    * a terminal retains at most #{div(1_048_576, 1024)} KiB of output — the most recent,
      with `truncated` set — whatever `outputByteLimit` asks for;
    * a terminal is killed #{div(600_000, 60_000)} minutes after it starts, which is the
      native shell's own ceiling;
    * a `wait_for_exit` is answered within that same window whatever the child does.
  """

  require Logger

  alias Ouroboros.Control.Permissions.Seam
  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Provider.Session.Diff
  alias Ouroboros.Workspace.Path, as: WorkspacePath

  @max_file_bytes 1_048_576
  @max_terminals 8
  @default_output_bytes 65_536
  @max_output_bytes 1_048_576
  @max_terminal_ms 600_000
  @max_command_bytes 4_096
  @max_env_vars 64
  @max_env_bytes 4_096
  @max_display_chars 200
  @digest_chars 16

  # JSON-RPC application codes. `-32602` is the standard "invalid params"; the two
  # negative-32000 codes are this runtime's own, and they are split because a client
  # rendering them means different things by each: one is the operator's rules, the other
  # is the machine.
  @invalid_params -32_602
  @refused -32_001
  @unavailable -32_002

  @typedoc """
  What this module hands back for the transport to do.

  `{:emit, …}` is the transport's own event action. `{:pending, id, reply}` answers a
  request id that was parked earlier — a `wait_for_exit` whose terminal has now exited,
  or one whose terminal was released out from under it. Both are the transport's to
  write; nothing here touches the socket.
  """
  @type reply :: {:result, map()} | {:error, integer(), String.t(), map()}
  @type action :: {:emit, atom(), map(), keyword()} | {:pending, term(), reply()}
  @type state :: map()

  @typedoc "What the caller has to tell this module about the session, per call."
  # `:turn_id` is what `provider_event/2` tags its emission with, and every caller has
  # always passed it. Leaving it out of a map type that lists every key it admits made
  # each `serve/4` and `resume/4` call read as a contract break, which cost `Jsonl` the
  # analysis of `run_service/4` entirely.
  @type context :: %{
          required(:root) => String.t() | nil,
          required(:sandbox_mode) => atom() | nil,
          optional(:rpc_id) => term(),
          optional(:turn_id) => term()
        }

  @doc "The empty service state one session starts with."
  @spec new() :: state()
  def new, do: %{terminals: %{}, next_terminal: 1, live: 0}

  @doc "Every ceiling this module enforces, for the docs and the tests that pin them."
  @spec limits() :: map()
  def limits do
    %{
      max_file_bytes: @max_file_bytes,
      max_terminals: @max_terminals,
      default_output_bytes: @default_output_bytes,
      max_output_bytes: @max_output_bytes,
      max_terminal_ms: @max_terminal_ms,
      max_command_bytes: @max_command_bytes
    }
  end

  # ----------------------------------------------------------------------- serve

  @doc """
  Performs one service request, or asks a human first.

  Returns `{:reply, reply, state, actions}` when the answer is known now,
  `{:approval, payload, stash, state}` when the permission engine left it to a person,
  and `{:defer, state, actions}` when the answer arrives later — today only
  `terminal/wait_for_exit`, whose reply comes back out of `handle_message/2`.
  """
  @spec serve(state(), atom(), map(), context()) ::
          {:reply, reply(), state(), [action()]}
          | {:approval, map(), map(), state()}
          | {:defer, state(), [action()]}
  def serve(state, operation, args, context)

  def serve(state, :fs_read, args, context) do
    with {:ok, path} <- contained(args[:path], context, :read) do
      case read_text(path, args[:line], args[:limit]) do
        {:ok, content} ->
          reply(
            state,
            {:result, %{"content" => content}},
            event(context, :fs_read, "ok", path: relative(path, context))
          )

        {:error, code, message} ->
          reply(
            state,
            {:error, code, message, %{"path" => relative(path, context)}},
            event(context, :fs_read, "failed", path: relative(path, context))
          )
      end
    else
      {:error, reply} -> refuse(state, reply, context, :fs_read, args)
    end
  end

  def serve(state, :fs_write, args, context) do
    with {:ok, path} <- contained(args[:path], context, :write),
         :ok <- writable_size(args[:content]) do
      decide_write(state, path, args[:content], context)
    else
      {:error, reply} -> refuse(state, reply, context, :fs_write, args)
    end
  end

  def serve(state, :terminal_create, args, context) do
    with :ok <- terminal_room(state),
         {:ok, command} <- command_line(args),
         {:ok, cwd} <- contained_dir(args[:cwd] || context.root, context) do
      decide_terminal(state, command, cwd, args, context)
    else
      {:error, reply} -> refuse(state, reply, context, :terminal_create, args)
    end
  end

  def serve(state, :terminal_output, args, context) do
    with {:ok, terminal} <- fetch_terminal(state, args[:terminal_id]) do
      reply(
        state,
        {:result, output_result(terminal)},
        event(context, :terminal_output, "ok", terminal: terminal.id)
      )
    else
      {:error, reply} -> refuse(state, reply, context, :terminal_output, args)
    end
  end

  def serve(state, :terminal_wait, args, context) do
    with {:ok, terminal} <- fetch_terminal(state, args[:terminal_id]) do
      case terminal.exit do
        nil ->
          park_wait(state, terminal, context)

        exit_status ->
          reply(
            state,
            {:result, exit_status},
            event(context, :terminal_wait, "ok", terminal: terminal.id)
          )
      end
    else
      {:error, reply} -> refuse(state, reply, context, :terminal_wait, args)
    end
  end

  def serve(state, :terminal_kill, args, context) do
    with {:ok, terminal} <- fetch_terminal(state, args[:terminal_id]) do
      state = put_terminal(state, kill_child(terminal))

      reply(state, {:result, %{}}, event(context, :terminal_kill, "ok", terminal: terminal.id))
    else
      {:error, reply} -> refuse(state, reply, context, :terminal_kill, args)
    end
  end

  def serve(state, :terminal_release, args, context) do
    with {:ok, terminal} <- fetch_terminal(state, args[:terminal_id]) do
      {state, orphaned} = release_terminal(state, terminal)

      {:reply, {:result, %{}}, state,
       orphaned ++ event(context, :terminal_release, "ok", terminal: terminal.id)}
    else
      {:error, reply} -> refuse(state, reply, context, :terminal_release, args)
    end
  end

  # A frame naming a session id this connection does not serve. Refused rather than
  # answered against whatever session the process happens to be: an agent that can reach
  # another conversation's workspace by naming its id is the hole this check exists for.
  def serve(state, :unknown_session, _args, _context),
    do:
      {:reply,
       {:error, @invalid_params, "that sessionId is not the one this connection serves", %{}},
       state, []}

  def serve(state, operation, _args, _context),
    do:
      {:reply,
       {:error, @invalid_params, "no such client service", %{"service" => to_string(operation)}},
       state, []}

  # --------------------------------------------------------------------- resume

  @doc """
  Finishes a service a human was asked about.

  A denial answers the agent with an error rather than an empty success: an ACP agent
  that was told a write succeeded and then reads the old bytes back has been lied to, and
  it will keep trying.
  """
  @spec resume(state(), map(), map(), context()) :: {:reply, reply(), state(), [action()]}
  def resume(state, %{service: %{operation: :fs_write} = fields} = stash, response, context) do
    if response.decision == :approve do
      perform_write(state, fields.path, stash[:content], context)
    else
      denied(state, fields, response, context)
    end
  end

  def resume(
        state,
        %{service: %{operation: :terminal_create} = fields} = stash,
        response,
        context
      ) do
    if response.decision == :approve do
      start_terminal(state, fields.command, stash[:cwd], stash[:args] || %{}, context)
    else
      denied(state, fields, response, context)
    end
  end

  def resume(state, stash, _response, _context),
    do:
      {:reply,
       {:error, @invalid_params, "unknown service approval",
        %{"stash" => inspect(Map.keys(stash))}}, state, []}

  defp denied(state, fields, response, context) do
    reason = response.reason || "refused by the operator"

    reply(
      state,
      {:error, @refused, "refused: " <> reason, %{"method" => fields.method}},
      event(context, fields.operation, "denied", digest_of(fields))
    )
  end

  # ------------------------------------------------------------------- messages

  @doc """
  Routes one port or timer message, if it belongs to a terminal this session owns.

  `:not_mine` for everything else, so the caller's own `handle_info/2` is unchanged for
  every session that never asked for a terminal — which is every non-ACP session.
  """
  @spec handle_message(state(), term()) :: {:ok, state(), [action()]} | :not_mine
  def handle_message(state, {port, {:data, data}}) when is_port(port) do
    case terminal_by_port(state, port) do
      nil -> :not_mine
      terminal -> {:ok, put_terminal(state, append_output(terminal, data)), []}
    end
  end

  def handle_message(state, {port, {:exit_status, status}}) when is_port(port) do
    case terminal_by_port(state, port) do
      nil ->
        :not_mine

      terminal ->
        exited = exited(terminal, %{"exitCode" => status, "signal" => nil})
        {state, pending} = resolve_waits(state, exited, {:result, exited.exit})
        {:ok, %{state | live: max(state.live - 1, 0)}, pending}
    end
  end

  def handle_message(state, {:ouroboros_service_lifetime, terminal_id}) do
    case Map.fetch(state.terminals, terminal_id) do
      {:ok, %{exit: nil} = terminal} ->
        Logger.warning("ACP terminal #{terminal_id} reached its ceiling and was killed")
        {:ok, put_terminal(state, kill_child(terminal)), []}

      _absent_or_done ->
        {:ok, state, []}
    end
  end

  def handle_message(state, {:ouroboros_service_wait, terminal_id, rpc_id}) do
    case Map.fetch(state.terminals, terminal_id) do
      {:ok, terminal} ->
        {waiting, rest} = Enum.split_with(terminal.waits, fn {id, _timer} -> id == rpc_id end)

        pending =
          Enum.map(waiting, fn {id, _timer} ->
            {:pending, id,
             {:error, @unavailable, "the terminal did not exit within its ceiling",
              %{"terminalId" => terminal_id}}}
          end)

        {:ok, put_terminal(state, %{terminal | waits: rest}), pending}

      :error ->
        {:ok, state, []}
    end
  end

  def handle_message(_state, _message), do: :not_mine

  # ---------------------------------------------------------------------- close

  @doc """
  Kills every terminal this session started, and reports what is still owed.

  Called from the transport's `close` and again from its `terminate/2`, so a session that
  ends any way at all — closed, crashed, or its provider process gone — leaves no child
  behind that Ouroboros started.
  """
  @spec close(state()) :: {state(), [action()]}
  def close(state) do
    Enum.reduce(Map.values(state.terminals), {state, []}, fn terminal, {state, pending} ->
      {state, more} = release_terminal(state, terminal)
      {state, pending ++ more}
    end)
  end

  # ------------------------------------------------------------------ fs: read

  defp read_text(path, line, limit) do
    case File.stat(path) do
      {:ok, %File.Stat{type: :regular, size: size}} when size > @max_file_bytes ->
        {:error, @refused,
         "that file is #{size} bytes; this runtime reads at most #{@max_file_bytes}"}

      {:ok, %File.Stat{type: :regular}} ->
        case File.read(path) do
          {:ok, content} ->
            {:ok, window(content, line, limit)}

          {:error, reason} ->
            {:error, @unavailable, "cannot read that file: #{:file.format_error(reason)}"}
        end

      {:ok, %File.Stat{type: type}} ->
        {:error, @invalid_params, "that path is a #{type}, not a regular file"}

      {:error, reason} ->
        {:error, @unavailable, "cannot read that file: #{:file.format_error(reason)}"}
    end
  end

  # ACP's `line` is 1-based and `limit` counts lines from it. Both are optional and either
  # may arrive alone; a `line` past the end is an empty window rather than an error,
  # because that is what reading past the end of a file gives.
  defp window(content, nil, nil), do: content

  defp window(content, line, limit) do
    lines = String.split(content, "\n")
    from = max((line || 1) - 1, 0)

    lines
    |> Enum.drop(from)
    |> take_lines(limit)
    |> Enum.join("\n")
  end

  defp take_lines(lines, nil), do: lines
  defp take_lines(lines, limit) when is_integer(limit) and limit >= 0, do: Enum.take(lines, limit)
  defp take_lines(lines, _limit), do: lines

  # ----------------------------------------------------------------- fs: write

  defp writable_size(content) when is_binary(content) and byte_size(content) <= @max_file_bytes,
    do: :ok

  defp writable_size(content) when is_binary(content),
    do:
      {:error,
       {:error, @refused,
        "that write is #{byte_size(content)} bytes; this runtime writes at most #{@max_file_bytes}",
        %{}}}

  defp writable_size(_content),
    do: {:error, {:error, @invalid_params, "`content` must be a string", %{}}}

  defp decide_write(state, path, content, context) do
    fields = write_fields(path, context)

    case Seam.decide_service(:acp, fields, approval_payload(fields, context)) do
      {:allow, _rule} ->
        perform_write(state, path, content, context)

      {:deny, rule} ->
        reply(
          state,
          {:error, @refused, Seam.refusal(rule), %{"path" => relative(path, context)}},
          event(context, :fs_write, "denied", path: relative(path, context))
        )

      {:ask, payload} ->
        {:approval, payload, %{service: Map.put(fields, :operation, :fs_write), content: content},
         state}
    end
  end

  defp write_fields(path, _context) do
    %{
      method: "fs/write_text_file",
      # An existing file is an edit and a new one is a write, so `Edit(…)` and `Write(…)`
      # each cover what an operator means by them.
      tool: if(File.regular?(path), do: "edit", else: "write"),
      mode: :write,
      command: nil,
      paths: [path],
      path: path
    }
  end

  defp perform_write(state, path, content, context) do
    old =
      case File.read(path) do
        {:ok, existing} -> existing
        {:error, _absent} -> nil
      end

    with :ok <- File.mkdir_p(Path.dirname(path)),
         :ok <- File.write(path, content) do
      change = Diff.change(relative(path, context), old, content)

      {:reply, {:result, %{}}, state,
       [
         {:emit, :file_change, %{"changes" => [change], "status" => "completed"}, []}
       ] ++ event(context, :fs_write, "ok", path: relative(path, context))}
    else
      {:error, reason} ->
        reply(
          state,
          {:error, @unavailable, "cannot write that file: #{:file.format_error(reason)}",
           %{"path" => relative(path, context)}},
          event(context, :fs_write, "failed", path: relative(path, context))
        )
    end
  end

  # ------------------------------------------------------------------ terminals

  defp terminal_room(%{live: live}) when live < @max_terminals, do: :ok

  defp terminal_room(_state),
    do:
      {:error,
       {:error, @refused,
        "this session already holds #{@max_terminals} terminals; release one first",
        %{"limit" => @max_terminals}}}

  # ACP hands over a program and an argv list; this runtime runs it through `/bin/sh -c`,
  # the same shape the native `bash` tool takes and the shape `Native.Sandbox` wraps. The
  # two are only equivalent if the argv survives the shell, so an argument that is not
  # already a bare word is quoted. Leaving them unquoted would turn one argument
  # containing a space into two, and one containing `;` into a second command — which is
  # the difference between running what the agent asked for and running something else.
  defp command_line(args) do
    command =
      [args[:command] | List.wrap(args[:args])]
      |> Enum.filter(&is_binary/1)
      |> Enum.map_join(" ", &shell_word/1)
      |> String.trim()

    cond do
      command == "" ->
        {:error, {:error, @invalid_params, "`command` must be a non-empty string", %{}}}

      byte_size(command) > @max_command_bytes ->
        {:error,
         {:error, @refused, "that command line is longer than #{@max_command_bytes} bytes", %{}}}

      true ->
        {:ok, command}
    end
  end

  # A bare word passes through unquoted so an operator's `Bash(git status *)` still reads
  # as the command line they wrote; anything else is single-quoted, with embedded single
  # quotes spliced the POSIX way.
  defp shell_word(word) do
    if Regex.match?(~r{\A[A-Za-z0-9_@%+=:,./-]+\z}, word),
      do: word,
      else: "'" <> String.replace(word, "'", "'\\''") <> "'"
  end

  defp decide_terminal(state, command, cwd, args, context) do
    fields = terminal_fields(command, cwd)

    case Seam.decide_service(:acp, fields, approval_payload(fields, context)) do
      {:allow, _rule} ->
        start_terminal(state, command, cwd, args, context)

      {:deny, rule} ->
        reply(
          state,
          {:error, @refused, Seam.refusal(rule), %{"command" => display(command)}},
          event(context, :terminal_create, "denied",
            digest: digest(command),
            command: display(command)
          )
        )

      {:ask, payload} ->
        {:approval, payload,
         %{service: Map.put(fields, :operation, :terminal_create), cwd: cwd, args: args}, state}
    end
  end

  # A terminal is a shell execution, so it is classified as one: an operator's
  # `Bash(git push *)` deny covers it exactly as it covers the native shell.
  defp terminal_fields(command, cwd) do
    %{
      method: "terminal/create",
      tool: "bash",
      mode: :execute,
      command: command,
      paths: [cwd] |> Enum.filter(&is_binary/1),
      cwd: cwd
    }
  end

  defp start_terminal(state, command, cwd, args, context) do
    scope = %{sandbox_mode: context.sandbox_mode, root: context.root, roots: [context.root]}
    detection = Sandbox.detect()

    case Sandbox.decide(scope, detection) do
      {:sandboxed, label, policy} ->
        spawn_sandboxed(state, command, cwd, args, context, scope, policy, detection, label)

      {:unsandboxed, _reason} ->
        spawn_terminal(state, command, cwd, args, context, "none", nil, nil, [])

      {:refused, reason} ->
        reply(
          state,
          {:error, @refused, Sandbox.no_backend_refusal(detection),
           %{"reason" => inspect(reason)}},
          event(context, :terminal_create, "refused",
            digest: digest(command),
            command: display(command)
          )
        )
    end
  end

  defp spawn_sandboxed(state, command, cwd, args, context, scope, policy, detection, label) do
    with {:ok, scratch} <- Sandbox.scratch(),
         policy = Sandbox.with_scratch(policy, scratch),
         {:ok, {executable, argv}} <-
           wrap_or_release({:shell, command}, scope, policy, detection, scratch) do
      spawn_terminal(
        state,
        {executable, argv},
        cwd,
        args,
        context,
        label,
        policy,
        scratch,
        Sandbox.env(policy)
      )
    else
      {:error, reason} ->
        reply(
          state,
          {:error, @unavailable, "the sandbox this session runs under could not be built",
           %{"reason" => inspect(reason)}},
          event(context, :terminal_create, "failed",
            digest: digest(command),
            command: display(command)
          )
        )
    end
  end

  defp wrap_or_release(command, scope, policy, detection, scratch) do
    case Sandbox.wrap(command, scope, policy, detection) do
      {:ok, _wrapped} = ok ->
        ok

      {:error, _reason} = error ->
        Sandbox.release(scratch)
        error
    end
  end

  defp spawn_terminal(state, command, cwd, args, context, label, _policy, scratch, sandbox_env) do
    {executable, argv} =
      case command do
        {executable, argv} -> {executable, argv}
        line when is_binary(line) -> {"/bin/sh", ["-c", line]}
      end

    display_command = display_of(command)

    with {:ok, wrapper} <- wrapper(),
         {:ok, port} <-
           open_port(wrapper, [executable | argv], cwd, sandbox_env ++ agent_env(args[:env])) do
      id = "term-#{state.next_terminal}"
      limit = output_limit(args[:output_byte_limit])

      os_pid =
        case Port.info(port, :os_pid) do
          {:os_pid, pid} -> pid
          _gone -> nil
        end

      terminal = %{
        id: id,
        port: port,
        os_pid: os_pid,
        label: label,
        scratch: scratch,
        command: display_command,
        buffer: "",
        limit: limit,
        truncated?: false,
        exit: nil,
        waits: [],
        lifetime: Process.send_after(self(), {:ouroboros_service_lifetime, id}, @max_terminal_ms)
      }

      state = %{
        state
        | terminals: Map.put(state.terminals, id, terminal),
          next_terminal: state.next_terminal + 1,
          live: state.live + 1
      }

      reply(
        state,
        {:result, %{"terminalId" => id}},
        event(context, :terminal_create, "ok",
          terminal: id,
          sandbox: label,
          digest: digest(display_command),
          command: display(display_command)
        )
      )
    else
      {:error, reason} ->
        Sandbox.release(scratch)

        reply(
          state,
          {:error, @unavailable, "this node cannot start a terminal",
           %{"reason" => inspect(reason)}},
          event(context, :terminal_create, "failed", digest: digest(display_command))
        )
    end
  end

  defp display_of({executable, argv}), do: Enum.join([executable | argv], " ")
  defp display_of(line) when is_binary(line), do: line

  # `Port.open/2` raises rather than returning an error for a missing executable or an
  # unreachable `cd`, and a session must not die because an agent asked for a terminal in
  # a directory that has just been removed.
  defp open_port(wrapper, args, cwd, env) do
    {:ok,
     Port.open({:spawn_executable, String.to_charlist(wrapper)}, port_options(args, cwd, env))}
  rescue
    error -> {:error, {:port_unavailable, Exception.message(error)}}
  end

  defp port_options(args, cwd, env) do
    [
      :binary,
      :exit_status,
      :use_stdio,
      :stderr_to_stdout,
      :hide,
      {:args, Enum.map(args, &String.to_charlist/1)}
    ]
    |> maybe_cd(cwd)
    |> maybe_env(env)
  end

  defp maybe_cd(options, path) when is_binary(path),
    do: [{:cd, String.to_charlist(path)} | options]

  defp maybe_cd(options, _other), do: options

  defp maybe_env(options, env) when is_list(env) and env != [] do
    converted =
      Enum.flat_map(env, fn
        {name, value} when is_binary(name) and is_binary(value) ->
          [{String.to_charlist(name), String.to_charlist(value)}]

        _other ->
          []
      end)

    if converted == [], do: options, else: [{:env, converted} | options]
  end

  defp maybe_env(options, _other), do: options

  # The agent's own environment additions, bounded in count and in size. Nothing is
  # removed from the inherited environment here: a terminal that could unset the
  # session's own variables would be a way to move the posture it runs under.
  defp agent_env(entries) when is_list(entries) do
    entries
    |> Enum.take(@max_env_vars)
    |> Enum.flat_map(fn
      %{"name" => name, "value" => value} when is_binary(name) and is_binary(value) ->
        env_pair(name, value)

      %{name: name, value: value} when is_binary(name) and is_binary(value) ->
        env_pair(name, value)

      _other ->
        []
    end)
  end

  defp agent_env(_entries), do: []

  defp env_pair(name, value) do
    if name != "" and byte_size(name) + byte_size(value) <= @max_env_bytes,
      do: [{name, value}],
      else: []
  end

  defp wrapper do
    with directory when is_list(directory) <- :code.priv_dir(:ouroboros),
         path = directory |> List.to_string() |> Path.join("provider-exec"),
         {:ok, %File.Stat{type: :regular, mode: mode}} <- File.lstat(path),
         true <- Bitwise.band(mode, 0o111) != 0 do
      {:ok, path}
    else
      failure -> {:error, {:wrapper_unavailable, failure}}
    end
  end

  defp output_limit(requested) when is_integer(requested) and requested > 0,
    do: min(requested, @max_output_bytes)

  defp output_limit(_unstated), do: @default_output_bytes

  defp fetch_terminal(state, id) when is_binary(id) do
    case Map.fetch(state.terminals, id) do
      {:ok, terminal} ->
        {:ok, terminal}

      :error ->
        {:error,
         {:error, @invalid_params, "no such terminal on this session", %{"terminalId" => id}}}
    end
  end

  defp fetch_terminal(_state, _id),
    do: {:error, {:error, @invalid_params, "`terminalId` must be a string", %{}}}

  defp terminal_by_port(state, port),
    do:
      Enum.find_value(state.terminals, fn {_id, terminal} -> terminal.port == port && terminal end)

  defp put_terminal(state, terminal),
    do: %{state | terminals: Map.put(state.terminals, terminal.id, terminal)}

  # The tail is kept rather than the head: an agent asking for output wants to see where
  # the command got to, and ACP's own `truncated` flag is what says bytes are missing.
  defp append_output(terminal, data) do
    combined = terminal.buffer <> data

    if byte_size(combined) > terminal.limit do
      kept = binary_part(combined, byte_size(combined) - terminal.limit, terminal.limit)
      %{terminal | buffer: trim_to_character(kept), truncated?: true}
    else
      %{terminal | buffer: combined}
    end
  end

  # A byte-exact tail can start in the middle of a multi-byte character; ACP asks for a
  # character boundary. At most three bytes are ever dropped, so this cannot loop.
  defp trim_to_character(binary) do
    if String.valid?(binary) do
      binary
    else
      case binary do
        <<_byte, rest::binary>> when byte_size(rest) > 0 -> trim_to_character(rest)
        _exhausted -> ""
      end
    end
  end

  defp output_result(terminal) do
    %{
      "output" => terminal.buffer,
      "truncated" => terminal.truncated?,
      "exitStatus" => terminal.exit
    }
  end

  defp park_wait(state, terminal, context) do
    rpc_id = Map.get(context, :rpc_id)

    timer =
      Process.send_after(self(), {:ouroboros_service_wait, terminal.id, rpc_id}, @max_terminal_ms)

    state = put_terminal(state, %{terminal | waits: [{rpc_id, timer} | terminal.waits]})
    {:defer, state, event(context, :terminal_wait, "waiting", terminal: terminal.id)}
  end

  defp exited(terminal, status) do
    _ = if terminal.lifetime, do: Process.cancel_timer(terminal.lifetime)
    Sandbox.release(terminal.scratch)
    %{terminal | exit: status, lifetime: nil, scratch: nil}
  end

  defp resolve_waits(state, terminal, reply) do
    pending =
      Enum.map(terminal.waits, fn {rpc_id, timer} ->
        _ = Process.cancel_timer(timer)
        {:pending, rpc_id, reply}
      end)

    {put_terminal(state, %{terminal | waits: []}), pending}
  end

  # TERM, then let the port's own closure take the rest. This is `Native.Exec`'s reaping
  # and it carries the same honest limit: a child that detaches from its process group
  # outlives the signal.
  defp kill_child(%{exit: nil, os_pid: os_pid} = terminal) when is_integer(os_pid) do
    _ = System.cmd("/bin/kill", ["-TERM", Integer.to_string(os_pid)], stderr_to_stdout: true)
    terminal
  rescue
    _error -> terminal
  end

  defp kill_child(terminal), do: terminal

  defp release_terminal(state, terminal) do
    terminal = kill_child(terminal)
    _ = if terminal.lifetime, do: Process.cancel_timer(terminal.lifetime)
    _ = if terminal.port && Port.info(terminal.port), do: Port.close(terminal.port)
    Sandbox.release(terminal.scratch)

    pending =
      Enum.map(terminal.waits, fn {rpc_id, timer} ->
        _ = Process.cancel_timer(timer)

        {:pending, rpc_id,
         {:error, @unavailable, "the terminal was released before it exited",
          %{"terminalId" => terminal.id}}}
      end)

    live = if is_nil(terminal.exit) and state.live > 0, do: state.live - 1, else: state.live

    {%{state | terminals: Map.delete(state.terminals, terminal.id), live: live}, pending}
  rescue
    _error -> {%{state | terminals: Map.delete(state.terminals, terminal.id)}, []}
  end

  # -------------------------------------------------------------- containment

  # The same rule the workspace itself is admitted under: canonicalise first, *then* ask
  # whether the answer is inside the root, so `link/../..` cannot name its way out. A
  # file that does not exist yet is canonicalised through its parent, because a write has
  # to be able to create one.
  defp contained(path, context, mode) do
    root = root_of(context)

    cond do
      not is_binary(path) or path == "" ->
        {:error, {:error, @invalid_params, "`path` must be a non-empty string", %{}}}

      not is_binary(root) ->
        {:error,
         {:error, @unavailable, "this session has no admitted workspace to serve from", %{}}}

      true ->
        resolve_within(Path.expand(path, root), root, mode)
    end
  end

  # The *root* is canonicalised too, and that is not belt and braces. A workspace often
  # arrives through a symlink — `/var/…` is `/private/var/…` on macOS, and a `git worktree`
  # under the data directory is reached the same way — so comparing a resolved candidate
  # against an unresolved root would refuse every path inside the session's own workspace.
  # Canonicalising both is the only comparison that means anything.
  defp root_of(%{root: root}) when is_binary(root) do
    case WorkspacePath.canonicalize(root) do
      {:ok, canonical} -> canonical
      {:error, _unreadable} -> root
    end
  end

  defp root_of(_context), do: nil

  defp resolve_within(absolute, root, mode) do
    case canonical_target(absolute, mode) do
      {:ok, canonical} ->
        if WorkspacePath.within?(canonical, root),
          do: {:ok, canonical},
          else: {:error, outside(canonical, root)}

      {:error, reason} ->
        {:error, {:error, @unavailable, "cannot resolve that path: #{inspect(reason)}", %{}}}
    end
  end

  # A read must name something that exists; a write may name something that does not, so
  # its *parent* is canonicalised and the basename appended. Either way the answer that
  # gets containment-checked is a real canonical path.
  defp canonical_target(absolute, :read), do: WorkspacePath.canonicalize_file(absolute)

  defp canonical_target(absolute, :write) do
    case WorkspacePath.canonicalize_file(absolute) do
      {:ok, canonical} ->
        {:ok, canonical}

      {:error, _absent} ->
        case WorkspacePath.canonicalize(Path.dirname(absolute)) do
          {:ok, parent} -> {:ok, Path.join(parent, Path.basename(absolute))}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp contained_dir(path, context) do
    root = root_of(context)

    cond do
      not is_binary(path) or path == "" ->
        {:error, {:error, @invalid_params, "`cwd` must be a non-empty string", %{}}}

      not is_binary(root) ->
        {:error, {:error, @unavailable, "this session has no admitted workspace to run in", %{}}}

      true ->
        case WorkspacePath.canonicalize(Path.expand(path, root)) do
          {:ok, canonical} ->
            if WorkspacePath.within?(canonical, root),
              do: {:ok, canonical},
              else: {:error, outside(canonical, root)}

          {:error, reason} ->
            {:error,
             {:error, @unavailable, "cannot resolve that directory: #{inspect(reason)}", %{}}}
        end
    end
  end

  defp outside(canonical, root) do
    {:error, @refused, "that path is outside this session's workspace",
     %{"path" => Path.basename(canonical), "workspace" => root}}
  end

  # ----------------------------------------------------------------- plumbing

  defp reply(state, reply, actions), do: {:reply, reply, state, actions}

  defp refuse(state, {:error, _code, _message, _data} = reply, context, operation, args) do
    {:reply, reply, state, event(context, operation, "refused", refusal_detail(operation, args))}
  end

  defp refusal_detail(:terminal_create, args),
    do: [digest: digest(to_string(args[:command] || ""))]

  defp refusal_detail(operation, args) when operation in [:fs_read, :fs_write],
    do: [path: Path.basename(to_string(args[:path] || ""))]

  defp refusal_detail(_operation, args), do: [terminal: args[:terminal_id]]

  # Content-minimised on purpose: the method, one bounded identifier, and what happened.
  # A transcript has to show what the agent asked this runtime to do without becoming a
  # second copy of the file it asked about.
  defp event(context, operation, outcome, detail) do
    payload =
      %{
        "kind" => "acp_service",
        "method" => method_of(operation),
        "outcome" => outcome
      }
      |> Map.merge(detail_payload(detail))

    [{:emit, :provider_event, payload, [turn_id: Map.get(context, :turn_id)]}]
  end

  defp detail_payload(detail) do
    detail
    |> Enum.reject(fn {_key, value} -> is_nil(value) or value == "" end)
    |> Map.new(fn {key, value} -> {to_string(key), value} end)
  end

  defp method_of(:fs_read), do: "fs/read_text_file"
  defp method_of(:fs_write), do: "fs/write_text_file"
  defp method_of(:terminal_create), do: "terminal/create"
  defp method_of(:terminal_output), do: "terminal/output"
  defp method_of(:terminal_wait), do: "terminal/wait_for_exit"
  defp method_of(:terminal_kill), do: "terminal/kill"
  defp method_of(:terminal_release), do: "terminal/release"
  defp method_of(other), do: to_string(other)

  defp digest_of(%{command: command}) when is_binary(command),
    do: [digest: digest(command), command: display(command)]

  defp digest_of(%{path: path}) when is_binary(path), do: [path: Path.basename(path)]
  defp digest_of(_fields), do: []

  defp digest(text) when is_binary(text) do
    :sha256 |> :crypto.hash(text) |> Base.encode16(case: :lower) |> binary_part(0, @digest_chars)
  end

  defp display(text) when is_binary(text), do: String.slice(text, 0, @max_display_chars)

  # Workspace-relative for the transcript, because an absolute path leaks the operator's
  # home directory into every event a client renders and into every replay of it.
  defp relative(path, context) do
    root = root_of(context)

    if is_binary(root) and WorkspacePath.within?(path, root) and path != root,
      do: Path.relative_to(path, root),
      else: path
  end

  # The shape the client's approval modal already renders: an ACP tool call with a name,
  # a title, and either a command or a location. Nothing new for A8 to learn.
  defp approval_payload(fields, context) do
    call =
      %{
        "name" => fields.tool,
        "kind" => if(fields.mode == :execute, do: "execute", else: "edit"),
        "title" => approval_title(fields, context)
      }
      |> put_unless_nil("command", fields[:command])
      |> put_locations(fields[:paths], context)

    %{
      "kind" => "acp_service",
      "method" => fields.method,
      "tool_call" => call,
      "options" => [
        %{"optionId" => "allow_once", "kind" => "allow_once", "name" => "Allow"},
        %{"optionId" => "reject_once", "kind" => "reject_once", "name" => "Deny"}
      ]
    }
  end

  defp approval_title(%{method: "terminal/create", command: command}, _context),
    do: "run " <> display(command)

  defp approval_title(%{path: path}, context), do: "write " <> relative(path, context)
  defp approval_title(%{method: method}, _context), do: method

  defp put_unless_nil(map, _key, nil), do: map
  defp put_unless_nil(map, key, value), do: Map.put(map, key, value)

  defp put_locations(map, paths, context) when is_list(paths) and paths != [],
    do: Map.put(map, "locations", Enum.map(paths, &%{"path" => relative(&1, context)}))

  defp put_locations(map, _paths, _context), do: map
end
