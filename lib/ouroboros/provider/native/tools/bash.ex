defmodule Ouroboros.Provider.Native.Tools.Bash do
  @moduledoc """
  Run one shell command in the session workspace, bounded in time and in output.

  ## The sandbox decides whether this runs at all

  `Ouroboros.Provider.Native.Sandbox` turns the session's `sandbox_mode` and the
  backend this node has into one of three answers, and this tool does exactly what it
  says (§7 Track C5):

    * **`read_only` with a backend** — the command runs inside it. macOS Seatbelt or
      Linux bubblewrap makes the whole filesystem read-only except a scratch `$TMPDIR`
      this call owns, and denies external network access. On macOS, loopback remains
      available for local IPC. This is what a read-only shell means; it is not "no
      shell" any more, because there is finally something that can hold the promise.
    * **`read_only` with no backend** — refused, as before, and the refusal now names
      what was missing. A shell that cannot be made read-only under a read-only label
      is a lie about the label.
    * **`workspace_write`** — runs sandboxed where a backend exists (workspace and
      declared roots writable, `.git` and `.ouroboros` beneath them read-only, the
      node's data directory and the user's ouroboros config read-only, no external
      network, with loopback retained for local IPC), and
      runs unsandboxed where none does. The second case is what this provider did
      before C5; it is reported rather than hidden, through `sandbox: "none"` on the
      tool call and through the provider's status.
    * **`unrestricted`** — runs with no OS sandbox on any node, because that is what the
      session asked for by name. `Sandbox.decide/2` logs it every time.

  When the sandbox stops a command, the result says which constraint was hit and what
  to ask a human for, so the model escalates instead of retrying (Cursor's rule, R3
  §11). When the *backend* fails — a profile that will not compile — the command is
  refused rather than re-run under a weaker posture, because a sandbox that silently
  is not there is worse than one that is absent and says so.

  ## The escalation offer

  A denial `Sandbox.escalatable?/3` says an operator could lift comes back as an
  `escalation:` key on the result, beside the output rather than inside it. This tool
  cannot ask anybody anything — only `Ouroboros.Provider.Native.Loop` owns an approval
  channel — so it describes the denial and says whether it is liftable, and the loop
  decides whether a human sees it and re-runs the command. That split is why a `bash`
  call made outside a loop reads exactly as honestly as one made inside: the guidance
  text never claims somebody is being asked.

  ## Everything else is unchanged

  Every child goes through `priv/provider-exec`, the same `umask 022` wrapper every
  Harness CLI child already crosses: the managed BEAM runs at `077` so journals stay
  private, and a workspace file a command creates should still be an ordinary `0644`.
  `sandbox-exec` and `bwrap` slot in *between* that wrapper and `/bin/sh`, and
  `sandbox-exec` `execve`s in place, so the pid the deadline reaps is still the shell's.

  Output follows the pattern Anthropic recommends and every leader implements
  (R3 §2, §8a): 30 KiB inline as head and tail with the middle elided, and the whole
  output written to a file under the session's own directory whose path is returned. A
  model that needs the rest can `read` it; the transcript does not carry it.
  """

  use Jido.Action,
    name: "bash",
    description:
      "Run a shell command in the workspace root. Under read_only and workspace_write " <>
        "it runs inside this node's OS sandbox where one is available; a sandbox denial " <>
        "reports the constraint that was hit. Output is truncated to 30 KiB; the full " <>
        "output is saved to a file whose path is returned.",
    schema: [
      command: [type: :string, required: true, doc: "The command line to run with `sh -c`."],
      timeout_ms: [
        type: :pos_integer,
        default: 120_000,
        doc: "Kill the command after this many milliseconds. Maximum 600000."
      ],
      description: [
        type: :string,
        default: "",
        doc: "A short description of what the command does, shown in the transcript."
      ]
    ]

  alias Ouroboros.Provider.Native.Exec
  alias Ouroboros.Provider.Native.Sandbox

  @max_timeout_ms 600_000
  @inline_bytes 30 * 1024
  @head_bytes 20 * 1024
  @tail_bytes 10 * 1024
  # A command that produces gigabytes must not take the node with it. The spill file is
  # capped and says where it stopped.
  @max_captured_bytes 64 * 1024 * 1024

  @impl true
  def run(params, context) do
    with {:ok, plan} <- plan(params.command, context.scope) do
      timeout = min(params.timeout_ms, @max_timeout_ms)

      try do
        finish(execute(plan, context.scope.root, timeout), plan, context, timeout)
      after
        Sandbox.release(plan.scratch)
      end
    else
      {:error, reason} -> {:ok, %{output: "bash refused: #{describe(reason)}", is_error: true}}
    end
  end

  # ------------------------------------------------------------------- planning

  # Fail closed, in both directions: a mode with no policy is refused, and a sandbox
  # that was decided on but could not be built is refused too. Neither falls back to
  # running the command with less containment than the session was told it had.
  defp plan(command, scope) do
    detection = Sandbox.detect()

    case Sandbox.decide(scope, detection) do
      {:sandboxed, label, policy} -> sandboxed(command, scope, policy, detection, label)
      {:unsandboxed, _reason} -> {:ok, plain(command)}
      {:refused, reason} -> {:error, reason}
    end
  end

  defp sandboxed(command, scope, policy, detection, label) do
    with {:ok, scratch} <- Sandbox.scratch(),
         policy = Sandbox.with_scratch(policy, scratch),
         {:ok, {executable, args}} <-
           wrap_or_release({:shell, command}, scope, policy, detection, scratch) do
      {:ok,
       %{
         label: label,
         command: command,
         executable: executable,
         args: args,
         env: Sandbox.env(policy),
         policy: policy,
         scratch: scratch
       }}
    else
      {:error, reason} -> {:error, {:sandbox_unavailable, label, reason}}
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

  defp plain(command) do
    %{
      label: "none",
      command: command,
      executable: "/bin/sh",
      args: ["-c", command],
      env: [],
      policy: nil,
      scratch: nil
    }
  end

  # -------------------------------------------------------------------- results

  defp finish({:ok, output, status, timed_out?}, plan, context, timeout) do
    case Sandbox.backend_failure(plan.label, output, status) do
      nil ->
        {inline, note} = present(output, context)
        {annotation, offer} = annotate(plan, output, status, timed_out?)

        {:ok,
         %{
           output: header(status, timed_out?, timeout) <> inline <> note <> annotation,
           is_error: timed_out? or status != 0,
           escalation: offer
         }}

      message ->
        {:ok,
         %{
           output: "bash refused: #{describe({:backend_failed, plan.label, message})}",
           is_error: true
         }}
    end
  end

  defp finish({:error, reason}, _plan, _context, _timeout),
    do: {:ok, %{output: "bash failed: #{describe(reason)}", is_error: true}}

  # A command killed by its own deadline was not stopped by the sandbox, whatever its
  # partial output happens to contain.
  defp annotate(_plan, _output, _status, true), do: {"", nil}
  defp annotate(%{policy: nil}, _output, _status, _live), do: {"", nil}

  # Returns the text appended to the tool result and, separately, the escalation *offer*
  # the loop acts on. They are two things and are kept apart on purpose: this tool cannot
  # ask anybody anything — only the loop process owns an approval channel — so all it does
  # is describe the denial accurately and say whether it is one an operator could lift.
  # A `bash` call made outside a loop therefore reads exactly as honestly as one inside.
  defp annotate(plan, output, status, _live) do
    case Sandbox.violation(plan.policy, output, status) do
      nil ->
        {"", nil}

      violation ->
        offered? = Sandbox.escalatable?(violation, plan.policy, plan.command)

        {Sandbox.escalation(violation, plan.policy, plan.label, offered: offered?),
         if(offered?, do: offer(violation, plan))}
    end
  end

  defp offer(violation, plan) do
    %{
      constraint: violation.constraint,
      evidence: violation.evidence,
      label: plan.label,
      mode: plan.policy.mode,
      reason: Sandbox.escalation_reason(violation, plan.policy, plan.label)
    }
  end

  # ------------------------------------------------------------------ execution

  defp execute(plan, cwd, timeout_ms) do
    case Exec.run(plan.executable, plan.args,
           cd: cwd,
           env: plan.env,
           timeout_ms: timeout_ms,
           max_bytes: @max_captured_bytes
         ) do
      {:ok, result} ->
        output =
          if result.truncated? do
            result.output <>
              "\n[command output truncated at #{@max_captured_bytes} bytes]\n"
          else
            result.output
          end

        {:ok, output, result.status, result.timed_out?}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp header(_status, true, timeout_ms),
    do: "Command timed out after #{timeout_ms} ms and was terminated.\n"

  defp header(0, false, _timeout_ms), do: ""
  defp header(status, false, _timeout_ms), do: "Command exited #{status}.\n"

  defp present(output, _context) when byte_size(output) <= @inline_bytes, do: {output, ""}

  defp present(output, context) do
    head = binary_part(output, 0, @head_bytes)
    tail = binary_part(output, byte_size(output) - @tail_bytes, @tail_bytes)
    elided = byte_size(output) - @head_bytes - @tail_bytes

    inline = head <> "\n… #{elided} bytes elided …\n" <> tail

    case spill(output, context) do
      {:ok, path} ->
        {inline,
         "\n(full output, #{byte_size(output)} bytes: #{path} — read it if you need the middle)"}

      {:error, _reason} ->
        {inline, "\n(#{elided} bytes could not be spilled to a file and are lost)"}
    end
  end

  defp spill(output, context) do
    case context[:session_dir] do
      dir when is_binary(dir) ->
        name =
          "bash-" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false) <> ".txt"

        path = Path.join([dir, "output", name])

        with :ok <- File.mkdir_p(Path.dirname(path)),
             :ok <- File.write(path, output),
             :ok <- File.chmod(path, 0o600) do
          {:ok, path}
        end

      _absent ->
        {:error, :no_session_dir}
    end
  end

  defp describe({:read_only_without_backend, detection}),
    do: Sandbox.no_backend_refusal(detection)

  defp describe({:unknown_sandbox_mode, mode}),
    do:
      "this session declares sandbox_mode: #{inspect(mode)}, which this provider has no " <>
        "sandbox policy for. A mode nobody wrote a policy for is refused rather than " <>
        "rounded to the nearest one that exists."

  defp describe({:sandbox_unavailable, label, reason}),
    do:
      "the OS sandbox (#{label}) could not be established: #{inspect(reason)}. The command " <>
        "was not run — a sandbox that fails to start does not become permission to run " <>
        "without one."

  defp describe({:backend_failed, label, message}),
    do:
      "#{label} could not apply this session's sandbox policy and the command did not run: " <>
        message

  defp describe({:wrapper_unavailable, failure}),
    do: "the priv/provider-exec umask wrapper is unusable: #{inspect(failure)}"

  defp describe({:spawn_failed, kind, reason}),
    do: "could not start the child process (#{kind}): #{inspect(reason)}"

  defp describe({:spawn_failed, message}) when is_binary(message), do: message

  defp describe({:spawn_failed, reason}),
    do: "could not start the child process: #{inspect(reason)}"

  defp describe(reason), do: inspect(reason)
end
