defmodule Ouroboros.Test.FleetOuroFake do
  @moduledoc """
  A fake `ouro` executable, for testing seam S1 the way it actually works.

  The broker finds `ouro` through `OUROBOROS_PROCESS_ID_HELPER` and never through `PATH`, so
  the honest way to test that is with a real executable file at a real absolute path — not
  with a function seam standing in for the whole mechanism. This writes that file into a
  directory nothing puts on `PATH`.

  Its `fleet worker start` arm does what the real one does with its argv: it reads the
  `--operation` the broker minted, writes that operation's capability file at 0600 under
  `<data dir>/fleet/deploy/`, records the id where the fake worker can read it, and prints
  the one JSON line naming the socket and the instance.

  Every argument it was run with is recorded in a sibling `argv` file, one per line, so a
  test can assert what the broker actually exec'd — including that nothing on that command
  line is a secret.
  """

  @doc """
  Writes a fake `ouro` into `dir` and returns its absolute path.

  Options:

    * `:spawn_line` — the single line `fleet worker start` prints.
    * `:cap` — the capability it writes to `<data dir>/fleet/deploy/<operation>.cap`.
    * `:cap_mode` — that file's octal mode; `0o600` by default, and `nil` writes no file at
      all, which is the "the worker has not published its capability yet" case.
    * `:devices` — the JSON `fleet devices --json` prints.
    * `:sleep` — seconds `fleet devices --json` sleeps first, for the ceiling test.
    * `:exit_status` — the status every subcommand exits with instead of 0.
  """
  @spec write!(Path.t(), keyword()) :: Path.t()
  def write!(dir, opts \\ []) do
    File.mkdir_p!(dir)

    spawn_file = Path.join(dir, "spawn-line")
    devices_file = Path.join(dir, "devices.json")
    argv_file = Path.join(dir, "argv")
    operation_file = operation_file(dir)

    File.write!(spawn_file, Keyword.get(opts, :spawn_line, "{}\n"))
    File.write!(devices_file, Keyword.get(opts, :devices, "{}\n"))
    File.write!(operation_file, "")

    status = Keyword.get(opts, :exit_status, 0)
    sleep = Keyword.get(opts, :sleep, 0)
    cap = Keyword.get(opts, :cap)
    cap_mode = Keyword.get(opts, :cap_mode, 0o600)

    capability =
      if cap && cap_mode do
        """
            mkdir -p "$data_dir/fleet/deploy"
            chmod 700 "$data_dir/fleet/deploy"
            printf '%s\\n' #{shell_quote(cap)} > "$data_dir/fleet/deploy/$operation.cap"
            chmod #{Integer.to_string(cap_mode, 8)} "$data_dir/fleet/deploy/$operation.cap"
        """
      else
        "        :\n"
      end

    script = """
    #!/bin/sh
    : > #{shell_quote(argv_file)}
    for arg in "$@"; do printf '%s\\n' "$arg" >> #{shell_quote(argv_file)}; done
    if [ #{status} -ne 0 ]; then
      echo "fake ouro refused: $*" >&2
      exit #{status}
    fi
    case "$1 $2 $3" in
      "fleet devices --json")
        [ #{sleep} -gt 0 ] && sleep #{sleep}
        cat #{shell_quote(devices_file)}
        ;;
      "fleet worker start")
        operation=""
        data_dir=""
        while [ $# -gt 0 ]; do
          case "$1" in
            --operation) operation="$2"; shift 2 ;;
            --data-dir) data_dir="$2"; shift 2 ;;
            *) shift ;;
          esac
        done
        printf '%s' "$operation" > #{shell_quote(operation_file)}
    #{capability}    cat #{shell_quote(spawn_file)}
        ;;
      *)
        echo "fake ouro was asked for something no test set up: $*" >&2
        exit 64
        ;;
    esac
    """

    path = Path.join(dir, "ouro")
    File.write!(path, script)
    File.chmod!(path, 0o755)
    path
  end

  @doc "Where the fake records the `--operation` it was last started for."
  @spec operation_file(Path.t()) :: Path.t()
  def operation_file(dir), do: Path.join(dir, "operation")

  @doc "Every argument the fake was last run with."
  @spec argv(Path.t()) :: [String.t()]
  def argv(dir) do
    case File.read(Path.join(dir, "argv")) do
      {:ok, body} -> String.split(body, "\n", trim: true)
      {:error, _reason} -> []
    end
  end

  @doc "Replaces the line `fleet worker start` prints, after the fake exists."
  @spec put_spawn_line!(Path.t(), String.t()) :: :ok
  def put_spawn_line!(dir, line), do: File.write!(Path.join(dir, "spawn-line"), line)

  # The script is generated, so the paths interpolated into it are quoted rather than trusted
  # to be well behaved: a temporary directory with a space in its name must not turn into a
  # broken test that looks like a broken broker.
  defp shell_quote(value), do: "'" <> String.replace(value, "'", "'\\''") <> "'"
end
