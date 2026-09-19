defmodule Ouroboros.Fleet.DeploymentRealWorkerTest do
  @moduledoc """
  The one test in this slice that talks to the real `ouro`.

  Everything else here runs against `test/support/fleet_frames_fake.sh`, which is a fake
  written to §8 — so it proves that this build reads §8 and not that `ouro` writes it. This
  closes that gap: it runs the packaged executable named by `OUROBOROS_TEST_OURO` as a port
  program, exactly as `Ouroboros.Fleet.Deployment.Worker` does, and checks that the first
  frames off its stdout decode as the events §8 names.

  `--dry-run` is what makes it safe to run anywhere: §5 gives `fleet setup` that flag, and a
  dry run changes nothing — not the data directory, not a journal, not a credential, not a
  members list, and not a recorded host key. The data directory it is pointed at is a
  throwaway one regardless.

  Excluded by default (`:real_worker`), because a checkout has no packaged `ouro` and the
  Rust slice that speaks `--frames` lands separately. Run it at integration:

      OUROBOROS_TEST_OURO=$PWD/dist/ouro mix test --include real_worker
  """

  use ExUnit.Case, async: false

  @moduletag :real_worker
  @moduletag :capture_log

  alias Ouroboros.Fleet.Deployment.Frame
  alias Ouroboros.Fleet.Deployment.Launcher

  # A real `fleet setup --dry-run` resolves a release, reads the network client and writes
  # nothing. Generous, because the first of those may go to the network.
  @deadline 60_000

  setup do
    ouro = System.get_env("OUROBOROS_TEST_OURO")

    if is_nil(ouro) or ouro == "" do
      flunk("OUROBOROS_TEST_OURO must name the packaged `ouro` to run this against")
    end

    root = Path.join(System.tmp_dir!(), "okdreal#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    File.chmod!(root, 0o700)
    on_exit(fn -> _ = File.rm_rf(root) end)

    %{ouro: ouro, root: root}
  end

  test "the first frames of a dry-run setup decode as the events §8 names", context do
    operation = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

    argv = [
      "fleet",
      "setup",
      "--machine",
      "realworker",
      "--dry-run",
      "--frames",
      "--operation",
      operation
    ]

    port =
      Port.open({:spawn_executable, context.ouro}, [
        :binary,
        :exit_status,
        :hide,
        {:line, Frame.max_bytes()},
        {:args, argv},
        {:env, Launcher.child_env(context.root)}
      ])

    frames = collect(port, System.monotonic_time(:millisecond) + @deadline, [])

    assert frames != [],
           "the real `ouro` wrote no frames to stdout for #{Enum.join(argv, " ")}"

    # Every line it wrote is a frame this build can decode, and every one of them is one of
    # the five events §8 fixes. A line that is not is exactly the drift this test exists for.
    for line <- frames do
      assert {:ok, frame} = Frame.decode(line), "not a frame: #{inspect(line)}"

      assert Frame.event(frame) in ~w(state step log challenge done),
             "not one of §8's events: #{inspect(frame)}"
    end

    decoded = Enum.map(frames, fn line -> elem(Frame.decode(line), 1) end)

    # A `state` frame is the first thing an operation says about itself, and its value is one
    # of the five §8 names rather than the eleven the socket protocol used.
    assert Enum.any?(decoded, &(Frame.event(&1) == "state"))

    for %{"state" => state} <- Enum.filter(decoded, &(Frame.event(&1) == "state")) do
      assert state in ~w(running waiting completed failed cancelled)
    end

    for challenge <- Enum.filter(decoded, &(Frame.event(&1) == "challenge")) do
      assert is_binary(challenge["challenge"])
      assert challenge["kind"] in ~w(host_trust password passphrase review)
    end

    for step <- Enum.filter(decoded, &(Frame.event(&1) == "step")) do
      assert is_binary(step["step"])
      assert step["state"] in ~w(ok failed skipped attempted)
    end
  end

  # Everything the program wrote before it exited or before the deadline, as whole lines. A
  # fragment — a line longer than the cap — is kept as one, because a test whose job is to
  # notice drift must not quietly drop the evidence of it.
  defp collect(port, deadline, lines) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, {:eol, line}}} ->
        collect(port, deadline, [line | lines])

      {^port, {:data, {:noeol, fragment}}} ->
        collect(port, deadline, [fragment | lines])

      {^port, {:exit_status, _status}} ->
        Enum.reverse(lines)
    after
      remaining ->
        _ = if Port.info(port), do: Port.close(port)
        Enum.reverse(lines)
    end
  end
end
