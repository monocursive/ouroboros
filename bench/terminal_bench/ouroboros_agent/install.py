"""The shell this agent runs inside a task container, as strings a test can read.

Nothing here executes anything. Each function returns a command line, so the install and
run steps can be asserted against fixtures without docker, a key, or a Linux dist — which
is the only kind of verification this repository can honestly claim for the adapter today.

Two rules shape all of it:

  * **Nothing is built in the container.** ERTS does not cross-compile and a task image
    is not a build host. The artifact is `make dist` run on a Linux machine, handed over
    as `OURO_LINUX_DIST`, uploaded by the agent and only unpacked here.
  * **Nothing is fetched.** No curl, no npm, no package index. Terminal-Bench tasks may
    run with the network policy closed, and an agent that needs a download to install
    itself is an agent that fails on those tasks for a reason that has nothing to do
    with the model.
"""

from __future__ import annotations

import shlex

#: Where the artifact is uploaded and unpacked. Under /opt so it survives a task that
#: works in the home directory, and so it is obviously not part of the task.
INSTALL_DIR = "/opt/ouroboros"
UPLOAD_PATH = "/opt/ouroboros-dist"
OURO = f"{INSTALL_DIR}/ouro"

#: The runtime's data directory. Explicit rather than derived, so that the daemon the
#: agent starts and the client the agent runs cannot disagree about where to look.
DATA_DIR = "/opt/ouroboros/data"


def is_tarball(path: str) -> bool:
    """Whether the dist artifact is an archive rather than the bare binary.

    `make dist` produces a single self-contained executable, but a release pipeline that
    ships it inside a `.tar.gz` is at least as likely, so both are accepted and the
    difference is one branch rather than a documented restriction.
    """
    lowered = path.lower()
    return lowered.endswith((".tar.gz", ".tgz", ".tar"))


def install_script(upload_path: str = UPLOAD_PATH, install_dir: str = INSTALL_DIR) -> str:
    """Unpack whatever was uploaded to `upload_path` into `install_dir` as `ouro`.

    Written so that it works for a bare binary and for an archive containing one, and so
    that it fails loudly rather than leaving a half-install: the last thing it does is
    run the binary, so a success means the client actually starts on this image.
    """
    up = shlex.quote(upload_path)
    dest = shlex.quote(install_dir)
    ouro = shlex.quote(f"{install_dir}/ouro")

    return " ".join(
        [
            "set -eu;",
            f"mkdir -p {dest};",
            f'if [ ! -s {up} ]; then echo "no dist artifact at {upload_path}" >&2; exit 1; fi;',
            # `file`/`tar -t` are not guaranteed on a minimal image, so the archive test
            # is the tar itself: if it lists, it is a tar.
            f"if tar -tf {up} > /dev/null 2>&1; then",
            f"  tar -xf {up} -C {dest};",
            # An archive may carry the binary at any depth and under a versioned name.
            f'  found=$(find {dest} -type f -name "ouro*" -perm -u+x | head -1);',
            f'  if [ -z "$found" ]; then found=$(find {dest} -type f -name "ouro*" | head -1); fi;',
            f'  if [ -z "$found" ]; then echo "no ouro binary inside the archive" >&2; exit 1; fi;',
            f'  if [ "$found" != {ouro} ]; then cp "$found" {ouro}; fi;',
            "else",
            f"  cp {up} {ouro};",
            "fi;",
            f"chmod 0755 {ouro};",
            f"{ouro} version",
        ]
    )


def daemon_command(
    ouro: str = OURO,
    data_dir: str = DATA_DIR,
    model_spec: str | None = None,
) -> str:
    """Start the packaged runtime and exit.

    `ouro --dev` is not available here: it runs `mix run --no-halt` in a checkout, and a
    task container has no checkout. The packaged binary carries the release inside it, so
    `ouro daemon` spawns, publishes `gateway.json`, and returns — which is exactly the
    shape a benchmark wants, one cold start rather than one per prompt.

    `OUROBOROS_NATIVE_MODEL` is set on the DAEMON, not on the client: it is read where the
    session is created. The key is not passed here — it is passed on the `ouro run` exec,
    so that the value spends as little time in a long-lived process environment as the
    design allows.
    """
    parts = [
        "set -eu;",
        f"mkdir -p {shlex.quote(data_dir)};",
        f"chmod 0700 {shlex.quote(data_dir)};",
        f"OUROBOROS_DATA_DIR={shlex.quote(data_dir)}",
    ]
    if model_spec:
        parts.append(f"OUROBOROS_NATIVE_MODEL={shlex.quote(model_spec)}")
    parts.append(f"{shlex.quote(ouro)} daemon")
    return " ".join(parts)


def run_command(
    instruction: str,
    workspace: str,
    timeout_secs: int,
    ouro: str = OURO,
    data_dir: str = DATA_DIR,
    stream_path: str | None = None,
) -> str:
    """One headless turn.

    `--approve-all` because there is no approver at a pipe and a benchmark that hung on
    a permission prompt would score zero for the wrong reason. `--stream-json` rather than
    `--json` because it is a superset: the normalised events *and* the result object, so
    the trajectory and the numbers come from one invocation and cannot disagree.
    `--timeout` because macOS has no `timeout(1)` and, more to the point, the client
    bounding itself is the bound that also interrupts the turn cleanly.

    The instruction is `shlex.quote`d, so a task whose text contains quotes, newlines,
    backticks or `$(…)` is passed through as data. That is the whole reason this returns
    a string from a function with a test rather than an f-string at the call site.
    """
    redirect = f" > {shlex.quote(stream_path)}" if stream_path else ""

    return (
        f"OUROBOROS_DATA_DIR={shlex.quote(data_dir)} "
        f"{shlex.quote(ouro)} run {shlex.quote(instruction)}"
        " --provider native"
        " --approve-all"
        " --stream-json"
        f" --workspace {shlex.quote(workspace)}"
        f" --timeout {int(timeout_secs)}"
        f"{redirect}"
    )


def stop_command(ouro: str = OURO, data_dir: str = DATA_DIR) -> str:
    """Stop the runtime this agent started, in the data dir it started it in.

    Scoped to `OUROBOROS_DATA_DIR` on purpose: an unscoped `ouro stop` looks for the
    default publication, which is a different runtime than the one we are responsible for.
    """
    return (
        f"OUROBOROS_DATA_DIR={shlex.quote(data_dir)} "
        f"{shlex.quote(ouro)} stop || true"
    )


def version_command(ouro: str = OURO) -> str:
    """What `BaseInstalledAgent` calls to fill in the agent version."""
    return f"{shlex.quote(ouro)} version"


def parse_version(output: str) -> str | None:
    """The client version out of `ouro version`.

    Tolerant by construction: the exact layout of that command's output is a client
    detail, and an agent that refused to run because a version line was reformatted would
    be trading a benchmark result for nothing.
    """
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        for token in stripped.replace("=", " ").replace(":", " ").split():
            candidate = token.lstrip("v")
            head = candidate.split(".", 1)[0]
            if head.isdigit() and "." in candidate:
                return candidate
    return None
