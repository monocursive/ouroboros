defmodule Ouroboros.Test.FleetOuroFake do
  @moduledoc """
  A fake `ouro` executable, for testing seam S1 the way it actually works.

  The broker finds `ouro` through `OUROBOROS_PROCESS_ID_HELPER` and never through `PATH`, so
  the honest way to test that is with a real executable file at a real absolute path — not
  with a function seam standing in for the whole mechanism. This writes that file into a
  directory nothing puts on `PATH`.

  Its `fleet worker start` arm does what the real one does with its argv: it reads the
  `--operation` the broker minted, writes that operation's capability file at 0600 under
  `<data dir>/deploy/`, records the id where the fake worker can read it, and prints
  the one JSON line naming the socket and the instance.

  It also stands in for the worker's side of the request file (seam S2): it records that
  file's mode and contents where a test can read them and then **unlinks it**, which is the
  real worker's job. That is what makes "gone after a successful launch" an assertion about
  the contract rather than about this script — and `keep_request: true` turns the unlink off,
  so a test can also prove the broker does *not* remove a file it has handed over.

  Every argument it was run with is recorded in a sibling `argv` file, one per line, so a
  test can assert what the broker actually exec'd — which, since that decision, is only the
  operation id and the data directory.
  """

  @doc """
  Writes a fake `ouro` into `dir` and returns its absolute path.

  Options:

    * `:spawn_line` — the single line `fleet worker start` prints.
    * `:cap` — the capability it writes to `<data dir>/deploy/<operation>.cap`.
    * `:cap_mode` — that file's octal mode; `0o600` by default, and `nil` writes no file at
      all, which is the "the worker has not published its capability yet" case.
    * `:devices` — the JSON `fleet devices --json` prints.
    * `:sleep` — seconds `fleet devices --json` sleeps first, for the ceiling test.
    * `:spawn_sleep` — seconds `fleet worker start` sleeps before publishing, for the
      broker-must-not-block test.
    * `:exit_status` — the status every subcommand exits with instead of 0.
    * `:keep_request` — true leaves the request file in place instead of unlinking it, the
      way a worker that died before reading it would.
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
    spawn_sleep = Keyword.get(opts, :spawn_sleep, 0)
    env_file = Path.join(dir, "env")
    cap = Keyword.get(opts, :cap)
    cap_mode = Keyword.get(opts, :cap_mode, 0o600)
    request_mode_file = Path.join(dir, "request-mode")
    request_body_file = Path.join(dir, "request-body")

    request_unlink =
      if Keyword.get(opts, :keep_request, false),
        do: "      :\n",
        else: "      rm -f \"$request\"\n"

    _ = File.rm(request_mode_file)
    _ = File.rm(request_body_file)

    capability =
      if cap && cap_mode do
        """
            mkdir -p "$data_dir/deploy"
            chmod 700 "$data_dir/deploy"
            printf '%s\\n' #{shell_quote(cap)} > "$data_dir/deploy/$operation.cap"
            chmod #{Integer.to_string(cap_mode, 8)} "$data_dir/deploy/$operation.cap"
        """
      else
        "        :\n"
      end

    script = """
    #!/bin/sh
    env > #{shell_quote(env_file)}
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
        [ #{spawn_sleep} -gt 0 ] && sleep #{spawn_sleep}
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
        request="$data_dir/deploy/$operation.request.json"
        if [ -f "$request" ]; then
          if mode=$(stat -c '%a' "$request" 2>/dev/null); then
            printf '%s\\n' "$mode" > #{shell_quote(request_mode_file)}
          else
            stat -f '%Lp' "$request" > #{shell_quote(request_mode_file)}
          fi
          cat "$request" > #{shell_quote(request_body_file)}
    #{request_unlink}    fi
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

  @doc "The mode the request file had when the fake read it, as an octal string, or nil."
  @spec request_mode(Path.t()) :: String.t() | nil
  def request_mode(dir) do
    case File.read(Path.join(dir, "request-mode")) do
      {:ok, body} -> String.trim(body)
      {:error, _reason} -> nil
    end
  end

  @doc "The exact bytes of the request file the fake read, or nil when there was none."
  @spec request_body(Path.t()) :: String.t() | nil
  def request_body(dir) do
    case File.read(Path.join(dir, "request-body")) do
      {:ok, body} -> body
      {:error, _reason} -> nil
    end
  end

  @doc "Replaces the line `fleet worker start` prints, after the fake exists."
  @spec put_spawn_line!(Path.t(), String.t()) :: :ok
  def put_spawn_line!(dir, line), do: File.write!(Path.join(dir, "spawn-line"), line)

  @doc "The environment the fake process saw, as `KEY=value` lines."
  @spec env(Path.t()) :: String.t()
  def env(dir) do
    case File.read(Path.join(dir, "env")) do
      {:ok, body} -> body
      {:error, _reason} -> ""
    end
  end

  # The script is generated, so the paths interpolated into it are quoted rather than trusted
  # to be well behaved: a temporary directory with a space in its name must not turn into a
  # broken test that looks like a broken broker.
  defp shell_quote(value), do: "'" <> String.replace(value, "'", "'\\''") <> "'"
end
