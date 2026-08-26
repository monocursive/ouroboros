defmodule Ouroboros.Release.TestHandler do
  @behaviour Ouroboros.Release.HandlerAdapter

  use Agent

  def start_link(_opts) do
    Agent.start_link(fn -> initial() end, name: __MODULE__)
  end

  def reset, do: Agent.update(__MODULE__, fn _state -> initial() end)
  def calls, do: Agent.get(__MODULE__, &Enum.reverse(&1.calls))

  @impl true
  def package_path(package_name) do
    Agent.get(__MODULE__, fn state ->
      directory = state.package_directory || System.tmp_dir!()
      Path.join(directory, List.to_string(package_name) <> ".tar.gz")
    end)
  end

  def set_package_path(path),
    do: Agent.update(__MODULE__, &Map.put(&1, :package_directory, Path.dirname(path)))

  def set_before_unpack(callback),
    do: Agent.update(__MODULE__, &Map.put(&1, :before_unpack, callback))

  def set_releases(releases),
    do: Agent.update(__MODULE__, &Map.put(&1, :releases, releases))

  @impl true
  def which_releases, do: Agent.get(__MODULE__, & &1.releases)

  @impl true
  def unpack_release(package_name) do
    Agent.get_and_update(__MODULE__, fn state ->
      if state.before_unpack, do: state.before_unpack.()

      version = state.target_version
      releases = put_release(state.releases, version, :unpacked)
      package_name = List.to_string(package_name)
      staged_binary = File.read!(Path.join(state.package_directory, package_name <> ".tar.gz"))
      staged_sha256 = :crypto.hash(:sha256, staged_binary) |> Base.encode16(case: :lower)

      {{:ok, String.to_charlist(version)},
       record(state, {:unpack, package_name, staged_sha256}, releases)}
    end)
  end

  @impl true
  def check_install_release(version, []) do
    Agent.get_and_update(__MODULE__, fn state ->
      result = {:ok, ~c"0.1.0", ~c"checked"}
      {result, record(state, {:check_install, List.to_string(version)}, state.releases)}
    end)
  end

  @impl true
  def install_release(version, []) do
    Agent.get_and_update(__MODULE__, fn state ->
      version = List.to_string(version)

      releases =
        state.releases
        |> Enum.map(fn
          {name, release_version, libraries, status} when status in [:current, :permanent] ->
            {name, release_version, libraries, :old}

          release ->
            release
        end)
        |> put_release(version, :current)

      {{:ok, ~c"0.1.0", ~c"installed"}, record(state, {:install, version}, releases)}
    end)
  end

  @impl true
  def make_permanent(version) do
    Agent.get_and_update(__MODULE__, fn state ->
      version = List.to_string(version)

      releases =
        state.releases
        |> Enum.map(fn
          {name, release_version, libraries, :permanent} ->
            {name, release_version, libraries, :old}

          release ->
            release
        end)
        |> put_release(version, :permanent)

      {:ok, record(state, {:make_permanent, version}, releases)}
    end)
  end

  defp initial do
    %{
      target_version: "0.2.0",
      package_directory: nil,
      before_unpack: nil,
      calls: [],
      releases: [{~c"ouroboros", ~c"0.1.0", [~c"ouroboros-0.1.0"], :permanent}]
    }
  end

  defp record(state, call, releases),
    do: %{state | calls: [call | state.calls], releases: releases}

  defp put_release(releases, version, status) do
    release = {~c"ouroboros", String.to_charlist(version), [~c"ouroboros-0.2.0"], status}

    [
      release
      | Enum.reject(releases, fn {_name, release_version, _libraries, _status} ->
          List.to_string(release_version) == version
        end)
    ]
  end
end

defmodule Ouroboros.Release.TestAuthorizer do
  @behaviour Ouroboros.Release.Authorizer

  @impl true
  def authorize(_artifact, _actions, {:approved, "change-123"}), do: :ok
  def authorize(_artifact, _actions, _approval), do: {:error, :invalid_change_approval}
end

defmodule Ouroboros.Release.RuntimeTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Release.{Artifact, Journal, Runtime, TestHandler, TestPackage}

  @checkpoint_key {:ouroboros, :release_runtime, 1}

  setup_all do
    case Process.whereis(TestHandler) do
      nil -> start_supervised!(TestHandler)
      _pid -> :ok
    end

    :ok
  end

  setup do
    TestHandler.reset()
    path = TestPackage.create!()
    TestHandler.set_package_path(path)
    on_exit(fn -> File.rm_rf!(Path.dirname(path)) end)
    %{path: path}
  end

  test "default authorizer denies mutations before the adapter boundary", %{path: path} do
    runtime = start_runtime(authorizer: Ouroboros.Release.Authorizer.Deny)
    assert {:ok, artifact} = Runtime.inspect_package(runtime, path)

    assert {:error, {:authorization_denied, :release_authorization_required}} =
             Runtime.authorize(runtime, artifact, [:unpack], :anything)

    assert TestHandler.calls() == []
  end

  test "unpack stages and passes a content-addressed basename to the adapter", %{path: path} do
    runtime = start_runtime()
    assert {:ok, artifact} = Runtime.inspect_package(runtime, path)

    assert {:ok, capability} =
             Runtime.authorize(runtime, artifact, [:unpack], {:approved, "change-123"})

    assert {:ok, %{action: :unpack}} = Runtime.unpack(runtime, artifact, capability)

    assert TestHandler.calls() == [
             {:unpack, "ouroboros-release-sha256-#{artifact.sha256}", artifact.sha256}
           ]
  end

  test "a source swap at adapter entry cannot alter the staged authorized bytes", %{path: path} do
    runtime = start_runtime()
    assert {:ok, artifact} = Runtime.inspect_package(runtime, path)

    TestHandler.set_before_unpack(fn -> File.write!(path, "swapped after staging") end)

    assert {:ok, capability} =
             Runtime.authorize(runtime, artifact, [:unpack], {:approved, "change-123"})

    assert {:ok, %{action: :unpack}} = Runtime.unpack(runtime, artifact, capability)

    assert [{:unpack, _basename, staged_sha256}] = TestHandler.calls()
    assert staged_sha256 == artifact.sha256
    assert File.read!(path) == "swapped after staging"
  end

  test "malformed capability structs fail closed without terminating the runtime", %{path: path} do
    runtime = start_runtime()
    assert {:ok, artifact} = Runtime.inspect_package(runtime, path)

    malformed = [
      %Runtime.Capability{id: nil},
      %Runtime.Capability{id: 42},
      %Runtime.Capability{id: <<1, 2, 3>>}
    ]

    for capability <- malformed,
        mutate <- [
          &Runtime.unpack/3,
          &Runtime.check_install/3,
          &Runtime.install/3,
          &Runtime.make_permanent/3
        ] do
      assert {:error, :invalid_release_capability} = mutate.(runtime, artifact, capability)
      assert Runtime.status(runtime).mode == :ready
      assert Process.alive?(Process.whereis(runtime))
    end

    assert TestHandler.calls() == []
  end

  test "authorizing drops the capabilities that have run out", %{path: path} do
    runtime = start_runtime(capability_ttl_ms: 1)
    assert {:ok, artifact} = Runtime.inspect_package(runtime, path)

    assert {:ok, expiring} =
             Runtime.authorize(runtime, artifact, [:unpack], {:approved, "change-123"})

    assert Runtime.status(runtime).ephemeral_capability_count == 1
    Process.sleep(20)

    assert {:ok, _fresh} =
             Runtime.authorize(runtime, artifact, [:unpack], {:approved, "change-123"})

    # One live capability, not two: the expired grant is gone rather than retained for
    # the lifetime of the node.
    assert Runtime.status(runtime).ephemeral_capability_count == 1
    assert {:error, :invalid_release_capability} = Runtime.unpack(runtime, artifact, expiring)
  end

  test "executes the gated release lifecycle and journals idempotent state", %{path: path} do
    runtime = start_runtime()
    assert {:ok, artifact} = Runtime.inspect_package(runtime, path)

    assert {:ok, capability} =
             Runtime.authorize(
               runtime,
               artifact,
               [:unpack, :check_install, :install, :make_permanent],
               {:approved, "change-123"}
             )

    assert {:ok, %{action: :unpack}} = Runtime.unpack(runtime, artifact, capability)
    assert {:ok, %{action: :check_install}} = Runtime.check_install(runtime, artifact, capability)

    assert {:ok, %{action: :install, continuation: :ok}} =
             Runtime.install(runtime, artifact, capability)

    assert {:ok, %{action: :install, idempotent: true}} =
             Runtime.install(runtime, artifact, capability)

    assert {:ok, %{action: :make_permanent}} =
             Runtime.make_permanent(runtime, artifact, capability)

    assert {:ok, same_artifact} = Runtime.inspect_package(runtime, path)
    assert same_artifact.sha256 == artifact.sha256
    assert Runtime.status(runtime).artifacts[artifact.sha256].stage == :permanent

    assert {:ok, %{action: :install, idempotent: true}} =
             Runtime.install(runtime, same_artifact, capability)

    assert TestHandler.calls() == [
             {:unpack, "ouroboros-release-sha256-#{artifact.sha256}", artifact.sha256},
             {:check_install, "0.2.0"},
             {:install, "0.2.0"},
             {:make_permanent, "0.2.0"}
           ]

    status = Runtime.status(runtime)
    assert status.mode == :ready
    assert status.artifacts[artifact.sha256].stage == :permanent
    assert status.ephemeral_capability_count == 1
    refute contains_runtime_only_term?(status.artifacts)
    refute contains_runtime_only_term?(status.operations)
  end

  test "restart reconciles observable install completion and drops capabilities", %{path: path} do
    table = unique_table()
    storage = {Jido.Storage.ETS, table: table}
    runtime = start_runtime(storage: storage)
    assert {:ok, artifact} = Runtime.inspect_package(runtime, path)

    assert {:ok, capability} =
             Runtime.authorize(runtime, artifact, [:unpack], {:approved, "change-123"})

    assert {:ok, _result} = Runtime.unpack(runtime, artifact, capability)

    assert {:ok, journal} = Jido.Storage.ETS.get_checkpoint(@checkpoint_key, table: table)

    checked = Journal.advance(journal, artifact.sha256, :checked)

    pending =
      Journal.append(checked, :install, Artifact.summary(artifact), :pending, :write_ahead)

    assert :ok = Jido.Storage.ETS.put_checkpoint(@checkpoint_key, pending, table: table)

    TestHandler.set_releases([
      {~c"ouroboros", ~c"0.2.0", [~c"ouroboros-0.2.0"], :current},
      {~c"ouroboros", ~c"0.1.0", [~c"ouroboros-0.1.0"], :old}
    ])

    stop_supervised!(runtime_id(runtime))
    runtime = start_runtime(storage: storage)
    status = Runtime.status(runtime)

    assert status.mode == :ready
    assert status.artifacts[artifact.sha256].stage == :installed
    assert List.last(status.operations).outcome == :succeeded
    assert status.ephemeral_capability_count == 0

    assert {:error, :invalid_release_capability} = Runtime.install(runtime, artifact, capability)
  end

  test "restart quarantines an interrupted check because pre-PONR effects are unobservable", %{
    path: path
  } do
    table = unique_table()
    storage = {Jido.Storage.ETS, table: table}
    runtime = start_runtime(storage: storage)
    assert {:ok, artifact} = Runtime.inspect_package(runtime, path)

    assert {:ok, capability} =
             Runtime.authorize(runtime, artifact, [:unpack], {:approved, "change-123"})

    assert {:ok, _result} = Runtime.unpack(runtime, artifact, capability)
    assert {:ok, journal} = Jido.Storage.ETS.get_checkpoint(@checkpoint_key, table: table)

    pending =
      Journal.append(journal, :check_install, Artifact.summary(artifact), :pending, :write_ahead)

    assert :ok = Jido.Storage.ETS.put_checkpoint(@checkpoint_key, pending, table: table)
    stop_supervised!(runtime_id(runtime))

    runtime = start_runtime(storage: storage)
    status = Runtime.status(runtime)
    assert status.mode == :quarantined
    assert status.quarantine_reason == {:ambiguous_check_after_restart, 2}
  end

  test "a previously permanent release may become old after the next permanent rollout", %{
    path: path
  } do
    table = unique_table()
    storage = {Jido.Storage.ETS, table: table}
    runtime = start_runtime(storage: storage)
    assert {:ok, artifact} = Runtime.inspect_package(runtime, path)
    assert {:ok, journal} = Jido.Storage.ETS.get_checkpoint(@checkpoint_key, table: table)
    journal = Journal.advance(journal, artifact.sha256, :permanent)
    assert :ok = Jido.Storage.ETS.put_checkpoint(@checkpoint_key, journal, table: table)

    TestHandler.set_releases([
      {~c"ouroboros", ~c"0.3.0", [~c"ouroboros-0.3.0"], :permanent},
      {~c"ouroboros", ~c"0.2.0", [~c"ouroboros-0.2.0"], :old},
      {~c"other-release", ~c"0.2.0", [~c"other-release-0.2.0"], :current}
    ])

    stop_supervised!(runtime_id(runtime))
    runtime = start_runtime(storage: storage)
    assert Runtime.status(runtime).mode == :ready
  end

  test "an old historically-permanent release can be made permanent again", %{path: path} do
    runtime = start_runtime()
    assert {:ok, artifact} = Runtime.inspect_package(runtime, path)

    assert {:ok, capability} =
             Runtime.authorize(
               runtime,
               artifact,
               [:unpack, :check_install, :install, :make_permanent],
               {:approved, "change-123"}
             )

    assert {:ok, _} = Runtime.unpack(runtime, artifact, capability)
    assert {:ok, _} = Runtime.check_install(runtime, artifact, capability)
    assert {:ok, _} = Runtime.install(runtime, artifact, capability)
    assert {:ok, _} = Runtime.make_permanent(runtime, artifact, capability)

    TestHandler.set_releases([
      {~c"ouroboros", ~c"0.3.0", [~c"ouroboros-0.3.0"], :permanent},
      {~c"ouroboros", ~c"0.2.0", [~c"ouroboros-0.2.0"], :old}
    ])

    assert {:ok, %{action: :make_permanent, idempotent: false}} =
             Runtime.make_permanent(runtime, artifact, capability)

    assert List.last(TestHandler.calls()) == {:make_permanent, "0.2.0"}
  end

  test "journal validation rejects broken aggregate relationships", %{path: path} do
    runtime = start_runtime()
    assert {:ok, artifact} = Runtime.inspect_package(runtime, path)
    status = Runtime.status(runtime)
    assert status.mode == :ready

    journal =
      Journal.new()
      |> then(fn journal ->
        {:ok, journal} =
          Journal.put_artifact(journal, Artifact.summary(artifact), :validated)

        journal
      end)

    pending = Journal.append(journal, :unpack, Artifact.summary(artifact), :pending, :intent)
    assert Journal.valid?(pending)

    duplicate_pending =
      Journal.append(pending, :unpack, Artifact.summary(artifact), :pending, :duplicate)

    refute Journal.valid?(duplicate_pending)
    refute Journal.valid?(%{pending | next_sequence: pending.next_sequence + 3})

    [operation] = pending.operations
    refute Journal.valid?(%{pending | operations: [%{operation | sequence: 0}]})
    refute Journal.valid?(%{pending | artifacts: %{}})

    wrong_stage = Journal.advance(pending, artifact.sha256, :installed)
    refute Journal.valid?(wrong_stage)
  end

  defp start_runtime(overrides \\ []) do
    name = String.to_atom("release_runtime_#{System.unique_integer([:positive])}")
    id = {:release_runtime, name}

    opts =
      [
        name: name,
        adapter: TestHandler,
        authorizer: Ouroboros.Release.TestAuthorizer,
        storage: {Jido.Storage.ETS, table: unique_table()}
      ]
      |> Keyword.merge(overrides)

    start_supervised!(%{id: id, start: {Runtime, :start_link, [opts]}})
    Process.put({:release_runtime_id, name}, id)
    name
  end

  defp runtime_id(name), do: Process.get({:release_runtime_id, name})

  defp unique_table,
    do: String.to_atom("release_storage_#{System.unique_integer([:positive])}")

  defp contains_runtime_only_term?(term)
       when is_pid(term) or is_reference(term) or is_function(term),
       do: true

  defp contains_runtime_only_term?(term) when is_list(term),
    do: Enum.any?(term, &contains_runtime_only_term?/1)

  defp contains_runtime_only_term?(term) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.any?(&contains_runtime_only_term?/1)

  defp contains_runtime_only_term?(%_{} = term),
    do: term |> Map.from_struct() |> contains_runtime_only_term?()

  defp contains_runtime_only_term?(term) when is_map(term),
    do:
      Enum.any?(term, fn {key, value} ->
        contains_runtime_only_term?(key) or contains_runtime_only_term?(value)
      end)

  defp contains_runtime_only_term?(_term), do: false
end
