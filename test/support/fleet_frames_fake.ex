defmodule Ouroboros.Test.FleetFramesFake do
  @moduledoc """
  A real `ouro` executable that speaks the §8 frames protocol, for tests and the browser
  fixture.

  The broker finds `ouro` through `OUROBOROS_PROCESS_ID_HELPER` and runs it as a port
  program, so the honest way to test that is with a real executable file at a real absolute
  path — not with a function seam standing in for the whole mechanism. This copies
  `test/support/fleet_frames_fake.sh` into a directory nothing puts on `PATH` and returns
  where it landed. Copied rather than linked, because `Launcher.executable/0` refuses a
  symlink on purpose.

  What the program does is a **scenario**: a file of directives, one per line, that
  `write_scenario!/2` writes and the script reads. A test states the deployment it wants —
  host trust, then a password, then a plan, then steps, then done; or a failure two steps in;
  or a line that is not a frame — instead of a fake module growing a flag per case. The
  script's own header lists every directive.

  Three files record what happened, so a test can assert against the program rather than
  against its own expectations of it: `argv/1` is every argument the broker exec'd, and the
  `--frames --operation <id>` at the end of it is the contract the Rust slice is checked
  against; `responses/1` is every line the broker wrote to its stdin, verbatim, so a test
  that could not see a secret arrive could not prove it arrived; and the journal under
  `<data dir>/deploy/` is the durable record, which the script keeps writing after stdin
  closes exactly as §8 says.
  """

  @script Path.join(__DIR__, "fleet_frames_fake.sh")

  @typedoc "Where the fake and its scratch files live."
  @type fake :: %{bin: Path.t(), ouro: Path.t()}

  @doc """
  Writes the fake into `dir` and points the environment at it.

  Returns the absolute path of the executable. `:devices` is the JSON `fleet devices --json`
  prints; everything else is a scenario written separately.
  """
  @spec install!(Path.t(), keyword()) :: Path.t()
  def install!(dir, opts \\ []) do
    File.mkdir_p!(dir)

    ouro = Path.join(dir, "ouro")
    File.cp!(@script, ouro)
    File.chmod!(ouro, 0o755)

    # Both paths are files this fake owns. An earlier layout kept a directory of
    # scenarios at the second one, and a checkout that ran it keeps that directory in
    # its build tree, so each is cleared before it is written.
    File.rm_rf!(devices_path(dir))
    File.rm_rf!(scenario_path(dir))
    File.write!(devices_path(dir), Keyword.get(opts, :devices, "{}\n"))
    File.write!(scenario_path(dir), "")
    _ = File.rm(argv_path(dir))
    _ = File.rm(responses_path(dir))

    System.put_env("OUROBOROS_FAKE_DEVICES", devices_path(dir))
    System.put_env("OUROBOROS_FAKE_SCENARIO", scenario_path(dir))
    System.put_env("OUROBOROS_FAKE_ARGV", argv_path(dir))
    System.put_env("OUROBOROS_FAKE_RESPONSES", responses_path(dir))
    System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)

    ouro
  end

  @doc "Unsets everything `install!/2` set, so one test's fake is not the next one's."
  @spec uninstall!() :: :ok
  def uninstall! do
    for name <- ~w(
          OUROBOROS_FAKE_DEVICES OUROBOROS_FAKE_SCENARIO OUROBOROS_FAKE_ARGV
          OUROBOROS_FAKE_RESPONSES OUROBOROS_FAKE_EXPIRES OUROBOROS_FAKE_MACHINE
          OUROBOROS_FAKE_ADDRESS OUROBOROS_FAKE_USER OUROBOROS_FAKE_PORT
          OUROBOROS_PROCESS_ID_HELPER
        ) do
      System.delete_env(name)
    end

    :ok
  end

  @doc "Replaces the scenario the next run will follow."
  @spec write_scenario!(Path.t(), [String.t()] | String.t()) :: :ok
  def write_scenario!(dir, lines) when is_list(lines),
    do: write_scenario!(dir, Enum.join(lines, "\n") <> "\n")

  def write_scenario!(dir, body) when is_binary(body) do
    _ = File.rm_rf(scenario_path(dir))
    File.write!(scenario_path(dir), body)
  end

  @doc """
  Writes a *directory* of scenarios instead of one file, keyed the way the script looks them
  up: `<kind>-<machine>`, then `<kind>`, then `default`.

  What a fixture with one runtime and four deployments to script needs. `scenarios` is a map
  of that key to the directive lines.
  """
  @spec write_scenarios!(Path.t(), %{optional(String.t()) => [String.t()] | String.t()}) :: :ok
  def write_scenarios!(dir, scenarios) when is_map(scenarios) do
    path = scenario_path(dir)
    _ = File.rm_rf(path)
    File.mkdir_p!(path)

    Enum.each(scenarios, fn {key, lines} ->
      body = if is_list(lines), do: Enum.join(lines, "\n") <> "\n", else: lines
      File.write!(Path.join(path, key), body)
    end)
  end

  @doc "Replaces the inventory `fleet devices --json` prints."
  @spec write_devices!(Path.t(), map() | String.t()) :: :ok
  def write_devices!(dir, document) when is_map(document),
    do: write_devices!(dir, JSON.encode!(document) <> "\n")

  def write_devices!(dir, body) when is_binary(body), do: File.write!(devices_path(dir), body)

  @doc """
  The whole of a deployment that works: host trust, a password, a plan, six steps, done.

  The shape §8 fixes, in the order §6 runs it, with the step names of an `add`.
  """
  @spec happy_add() :: [String.t()]
  def happy_add do
    [
      "state running",
      "log connecting to 100.100.7.1",
      "state waiting",
      "challenge trust-1 host_trust {\"address\":\"100.100.7.1\",\"port\":22,\"algorithm\":\"ssh-ed25519\",\"sha256_fingerprint\":\"SHA256:fixtureFingerprintNotARealHostKey\",\"user\":\"deploy\"}",
      "await trust-1",
      "challenge secret-1 password {\"target\":\"100.100.7.1\",\"user\":\"deploy\",\"port\":22,\"attempt\":1,\"max_attempts\":3}",
      "await secret-1",
      "step inspect ok reachable, and no Ouroboros installed",
      "plan Install ouro 0.1.10 (Linux arm64) to /usr/local/bin/ouro",
      "plan Join fixture as fixture-target",
      "plan Start at login as a user service",
      "plan Remember fixture-target on this machine",
      "challenge review-1 review {}",
      "await review-1",
      "state running",
      "step install ok /usr/local/bin/ouro",
      "step join ok -",
      "step service ok an Ouroboros-owned user service",
      "step start ok -",
      "step connect ok -",
      "done completed fixture-target joined this fleet"
    ]
  end

  @doc "Every argument the broker last exec'd, in order."
  @spec argv(Path.t()) :: [String.t()]
  def argv(dir), do: lines(argv_path(dir))

  @doc "Every line the broker wrote to the program's stdin, verbatim and in order."
  @spec responses(Path.t()) :: [String.t()]
  def responses(dir), do: lines(responses_path(dir))

  @doc """
  The same, once one of them contains `needle`, or `[]` after the deadline.

  The file is written by another operating-system process at the far end of a pipe, so a
  read taken the instant after `respond/3` answers is a read taken before the program has
  been scheduled. "It is not there yet" and "it will never be there" are different facts,
  and asserting on the first of them is a test that passes on a fast machine.
  """
  @spec await_response(Path.t(), String.t(), pos_integer()) :: [String.t()]
  def await_response(dir, needle, timeout \\ 3_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    poll_response(dir, needle, deadline)
  end

  defp poll_response(dir, needle, deadline) do
    written = responses(dir)

    cond do
      Enum.any?(written, &String.contains?(&1, needle)) ->
        written

      System.monotonic_time(:millisecond) >= deadline ->
        written

      true ->
        Process.sleep(25)
        poll_response(dir, needle, deadline)
    end
  end

  @doc "The journal the program wrote for one operation, decoded, or `nil`."
  @spec journal(Path.t(), String.t()) :: map() | nil
  def journal(data_dir, operation) do
    with {:ok, body} <- File.read(Path.join([data_dir, "deploy", operation <> ".json"])),
         {:ok, document} <- JSON.decode(body) do
      document
    else
      _absent -> nil
    end
  end

  @doc false
  @spec devices_path(Path.t()) :: Path.t()
  def devices_path(dir), do: Path.join(dir, "devices.json")

  @doc false
  @spec scenario_path(Path.t()) :: Path.t()
  def scenario_path(dir), do: Path.join(dir, "scenario")

  @doc false
  @spec argv_path(Path.t()) :: Path.t()
  def argv_path(dir), do: Path.join(dir, "argv")

  @doc false
  @spec responses_path(Path.t()) :: Path.t()
  def responses_path(dir), do: Path.join(dir, "responses")

  defp lines(path) do
    case File.read(path) do
      {:ok, body} -> String.split(body, "\n", trim: true)
      {:error, _absent} -> []
    end
  end
end
