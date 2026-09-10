# Run against each build with a fresh OUROBOROS_NATIVE_DATA_DIR; captures process
# topology and received timer wakeups under exactly the same no-network workload.
defmodule Ouroboros.J2WorkloadModel do
  @behaviour Ouroboros.Provider.Native.Model
  def available?, do: true
  def credential_report, do: []

  def stream(_request, _opts) do
    {:ok,
     Stream.map([{:text, "synthetic"}, {:finish, :stop}], fn chunk ->
       Process.sleep(250)
       chunk
     end)}
  end
end

root =
  System.get_env("J2_WORKLOAD_ROOT") ||
    Path.join(System.tmp_dir!(), "j2-workload-#{System.unique_integer([:positive])}")

File.mkdir_p!(root)
Application.put_env(:ouroboros, :native_data_dir, Path.join(root, "data"))
Application.put_env(:ouroboros, :native_model_module, Ouroboros.J2WorkloadModel)
Application.put_env(:ouroboros, :workspace_allowed_roots, [root])
{:ok, _} = Application.ensure_all_started(:ouroboros)

{:ok, ref} =
  Ouroboros.InteractiveSession.start(
    workspace: root,
    model: "scripted:baseline",
    runtime_exposure: false
  )

[{coordinator, _}] = Registry.lookup(Ouroboros.Interactive.Registry, ref.id)

count_received = fn duration ->
  :erlang.trace(coordinator, true, [:receive, {:tracer, self()}])
  Process.sleep(duration)
  :erlang.trace(coordinator, false, [:receive])

  collect = fn collect, messages ->
    receive do
      {:trace, ^coordinator, :receive, message} -> collect.(collect, [message | messages])
    after
      0 -> messages
    end
  end

  messages = collect.(collect, [])

  %{
    messages: length(messages),
    poll_wakeups: Enum.count(messages, &(&1 == :poll)),
    notification_wakeups: Enum.count(messages, &(is_tuple(&1) and elem(&1, 0) == :session_output))
  }
end

Process.sleep(1500)
IO.inspect(count_received.(2000), label: "idle_2000ms")
{:ok, turn} = Ouroboros.InteractiveSession.send_message(ref, "Synthetic workload")
IO.inspect(count_received.(800), label: "active_800ms")
{:ok, _result} = Ouroboros.InteractiveSession.await(ref, turn.id, 15_000)

sessions =
  Process.list()
  |> Enum.flat_map(fn pid ->
    case Process.info(pid, :dictionary) do
      {:dictionary, dictionary} ->
        case Keyword.get(dictionary, :"$initial_call") do
          {module, :init, _} ->
            name = Atom.to_string(module)

            if name in [
                 "Elixir.Ouroboros.Interactive.Task",
                 "Elixir.Jido.Harness.SessionWorker",
                 "Elixir.Ouroboros.Provider.Native.Session"
               ], do: [name], else: []

          _ ->
            []
        end

      _ ->
        []
    end
  end)

IO.inspect(Enum.frequencies(sessions), label: "session_processes")
{:ok, events} = Ouroboros.InteractiveSession.replay(ref, cursor: 0)
IO.inspect(Enum.map(events, & &1.type), label: "lifecycle")
Ouroboros.InteractiveSession.close(ref)
Application.stop(:ouroboros)
File.rm_rf!(root)
