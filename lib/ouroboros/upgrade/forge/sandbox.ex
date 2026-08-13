defmodule Ouroboros.Upgrade.Forge.Sandbox do
  @moduledoc """
  The half of the forge that runs *inside* the build peer.

  Every function here is invoked through `:peer.call/5` from
  `Ouroboros.Upgrade.Forge.BuildPeer`, which means two things. It is the only place in
  the forge where agent-authored source is compiled and executed, and everything it
  returns crosses a `:peer` control connection, so results are plain serializable terms:
  no pids, references, funs, or exception structs. A compiler diagnostic becomes a map, a
  test failure becomes counts plus captured output.

  "Sandbox" names the isolation the peer provides — a separate OS process with no
  distribution, no EPMD, and no connection to the production cluster — not an OS-level
  jail. The compiled code runs with full authority *inside that peer*: it can write files
  the build user can write and open sockets the build host allows. Compiling untrusted
  source under a hostile-code threat model needs a container or VM around the peer.

  Exactly one module may come out of a capability source. A source whose compilation
  yields helper modules is rejected here, where the real compiler output is visible,
  rather than shipping an artifact whose single binary references names no target node
  has ever loaded.
  """

  @capture_limit 8_000

  @type report :: %{total: non_neg_integer(), failures: non_neg_integer()}

  @doc """
  Compiles `source`, then runs `test_source` against it, entirely inside this peer.

  Returns `{:ok, %{module: module, binary: binary, test_report: report, peer_runtime:
  runtime}}`. Failures are `{:error, {:compile_failed, diagnostics}}`,
  `{:error, {:unexpected_modules, names}}`, `{:error, {:test_compile_failed,
  diagnostics}}`, and `{:error, {:capability_tests_failed, summary}}`.
  """
  @spec compile_and_test(module(), String.t(), String.t() | nil) ::
          {:ok, map()} | {:error, term()}
  def compile_and_test(module, source, test_source)
      when is_atom(module) and is_binary(source) do
    with {:ok, binary} <- compile_capability(module, source),
         {:ok, report} <- run_tests(test_source) do
      {:ok,
       %{
         module: module,
         binary: binary,
         test_report: report,
         peer_runtime: peer_runtime()
       }}
    end
  end

  def compile_and_test(module, source, _test_source),
    do: {:error, {:invalid_compile_request, module, source}}

  @doc "Describes the runtime this peer is, so a caller can compare it with its targets."
  @spec peer_runtime() :: map()
  def peer_runtime do
    %{
      otp_release: to_string(:erlang.system_info(:otp_release)),
      elixir_version: System.version(),
      system_architecture: to_string(:erlang.system_info(:system_architecture)),
      distributed: :erlang.is_alive(),
      node: node()
    }
  end

  defp compile_capability(module, source) do
    filename = "capability/#{inspect(module)}.ex"

    case compile(source, filename) do
      {:ok, [{^module, binary}]} ->
        {:ok, binary}

      {:ok, compiled} ->
        {:error, {:unexpected_modules, Enum.map(compiled, &elem(&1, 0))}}

      {:error, diagnostics} ->
        {:error, {:compile_failed, diagnostics}}
    end
  end

  defp run_tests(nil), do: {:ok, %{total: 0, failures: 0, excluded: 0, skipped: 0, ran: false}}

  defp run_tests(test_source) when is_binary(test_source) do
    {result, output} =
      capture_io(fn ->
        with :ok <- start_ex_unit(),
             {:ok, _compiled} <- compile(test_source, "capability/test.exs") do
          run_ex_unit()
        end
      end)

    case result do
      {:ok, summary} ->
        if Map.get(summary, :failures, 1) == 0 do
          {:ok, Map.put(summary, :ran, true)}
        else
          {:error, {:capability_tests_failed, Map.put(summary, :output, truncate(output))}}
        end

      {:error, {:ex_unit_failed, reason}} ->
        {:error, {:ex_unit_failed, reason}}

      {:error, diagnostics} ->
        {:error, {:test_compile_failed, diagnostics}}
    end
  end

  defp run_tests(other), do: {:error, {:invalid_test_source, other}}

  defp start_ex_unit do
    ExUnit.start(autorun: false)
    :ok
  rescue
    error -> {:error, {:ex_unit_failed, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:ex_unit_failed, {kind, inspect(reason)}}}
  end

  defp run_ex_unit do
    {:ok, normalize_summary(ExUnit.run())}
  rescue
    error -> {:error, {:ex_unit_failed, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:ex_unit_failed, {kind, inspect(reason)}}}
  end

  defp normalize_summary(summary) when is_map(summary) do
    %{
      total: Map.get(summary, :total, 0),
      failures: Map.get(summary, :failures, 0),
      excluded: Map.get(summary, :excluded, 0),
      skipped: Map.get(summary, :skipped, 0)
    }
  end

  defp normalize_summary(_summary), do: %{total: 0, failures: 1, excluded: 0, skipped: 0}

  # `Code.with_diagnostics/1` keeps the compiler's own warnings and errors instead of the
  # single flattened message a rescued CompileError carries.
  defp compile(string, filename) do
    {result, diagnostics} =
      Code.with_diagnostics(fn ->
        try do
          {:ok, Code.compile_string(string, filename)}
        rescue
          error -> {:error, Exception.message(error)}
        catch
          kind, reason -> {:error, {kind, inspect(reason)}}
        end
      end)

    case result do
      {:ok, compiled} -> {:ok, compiled}
      {:error, message} -> {:error, %{message: message, diagnostics: sanitize(diagnostics)}}
    end
  end

  # Diagnostics carry stacktraces and spans. Keep the fields an operator reads and drop
  # everything whose shape is not guaranteed to survive the control connection.
  defp sanitize(diagnostics) when is_list(diagnostics) do
    Enum.map(diagnostics, fn diagnostic ->
      %{
        severity: Map.get(diagnostic, :severity),
        message: message(Map.get(diagnostic, :message, "")),
        file: message(Map.get(diagnostic, :file) || ""),
        position: position(Map.get(diagnostic, :position))
      }
    end)
  end

  defp sanitize(_diagnostics), do: []

  # A diagnostic message is a binary, iodata, or an exception struct depending on where
  # the compiler raised it. Only a binary is guaranteed to mean the same thing on the
  # other side of the control connection.
  defp message(message) when is_binary(message), do: message
  defp message(message) when is_exception(message), do: Exception.message(message)

  defp message(message) do
    to_string(message)
  rescue
    _error -> inspect(message)
  end

  defp position(line) when is_integer(line), do: line
  defp position({line, column}) when is_integer(line) and is_integer(column), do: {line, column}
  defp position(_position), do: 0

  # ExUnit formatters write to the group leader of the process that started ExUnit, so the
  # capture has to be in place before `ExUnit.start/1`. Without it the peer's test output
  # is forwarded over the control connection into the caller's terminal.
  defp capture_io(fun) do
    original = Process.group_leader()

    case StringIO.open("") do
      {:ok, device} ->
        Process.group_leader(self(), device)

        result =
          try do
            fun.()
          after
            Process.group_leader(self(), original)
          end

        {result, close(device)}

      {:error, reason} ->
        {fun.(), "output capture unavailable: #{inspect(reason)}"}
    end
  end

  defp close(device) do
    case StringIO.close(device) do
      {:ok, {_input, output}} -> output
      _other -> ""
    end
  end

  defp truncate(output) when is_binary(output) do
    if byte_size(output) > @capture_limit do
      binary_part(output, 0, @capture_limit) <> "\n... truncated"
    else
      output
    end
  end

  defp truncate(_output), do: ""
end
