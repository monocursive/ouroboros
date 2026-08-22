"""`OuroborosAgent` — Ouroboros's native agent, as a Harbor installed agent.

    harbor run -d terminal-bench/terminal-bench-2-1 \
      --agent ouroboros_agent.agent:OuroborosAgent \
      -m anthropic/claude-opus-4-1

Terminal-Bench 2.x runs on Harbor (`harbor-framework/harbor`), not on the `terminal-bench`
package, whose last release predates 2.0 and whose `BaseAgent`/`AgentResult`/`TmuxSession`
API is 1.x only. This class targets Harbor's `BaseInstalledAgent`, whose contract is:

    @staticmethod
    def name() -> str
    def version(self) -> str | None
    async def install(self, environment) -> None          # BaseInstalledAgent adds this
    async def run(self, instruction, environment, context) -> None

`run` returns nothing; results are recorded by mutating `context` (an `AgentContext`)
in place. Scoring is not ours: after the agent stops, Harbor copies the task's `tests/`
into the container and runs `tests/test.sh`, which writes `/logs/verifier/reward.txt`.
This class therefore never reports pass or fail. Its whole obligation is to install
cleanly, hand the instruction over, not crash, and report what the turn cost.

**This file has never been executed.** No `harbor` install, no docker daemon, and no
Linux `ouro` dist were available where it was written; what has been verified is
everything under `ouroboros_agent/` that does not import Harbor, against fixtures
captured from a real `ouro run --stream-json`. See `../README.md` for exactly which
claims are which.
"""

from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath

from harbor.agents.installed.base import BaseInstalledAgent
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext

from ouroboros_agent import install as sh
from ouroboros_agent.model import native_model_spec, provider_key_env
from ouroboros_agent.result import parse_stream
from ouroboros_agent.trajectory import build_trajectory

#: Where the dist artifact comes from. Never built here: ERTS does not cross-compile, so
#: a Linux `ouro` is built on Linux — `make dist` on a Linux host or in CI — and handed
#: over as a path. A task image is not a build host and a benchmark is not the place to
#: discover that it isn't.
DIST_ENV = "OURO_LINUX_DIST"

#: The default working directory for a Terminal-Bench task container.
#: UNVERIFIED — inferred from the convention, not read out of a task image. Override with
#: `--ak workspace=/somewhere` if a task set uses another root.
DEFAULT_WORKSPACE = "/app"

#: One turn's budget. Harbor enforces its own `[agent].timeout_sec` from `task.toml`;
#: this is the client bounding itself a little sooner, so that a turn that overruns ends
#: as a `timeout` status with a trajectory rather than as a killed container with none.
DEFAULT_TIMEOUT_SECS = 900
TIMEOUT_MARGIN_SECS = 30


class OuroborosAgent(BaseInstalledAgent):
    """Ouroboros's `Provider.Native` loop, driven headless through `ouro run`."""

    #: Not claimed. `trajectory.json` is an Ouroboros-shaped summary and says so; the raw
    #: `trajectory.ndjson` beside it is the record. See `trajectory.py` for why labelling
    #: an unvalidated file `ATIF-v1.7` would be the wrong kind of convenient.
    SUPPORTS_ATIF = False

    def __init__(
        self,
        *args,
        workspace: str = DEFAULT_WORKSPACE,
        dist_path: str | None = None,
        timeout_secs: int = DEFAULT_TIMEOUT_SECS,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._workspace = workspace
        self._timeout_secs = int(timeout_secs)
        self._dist_path = dist_path or os.environ.get(DIST_ENV)
        self._version: str | None = None
        self._model_spec = native_model_spec(getattr(self, "_model_name", None))

    # ------------------------------------------------------------------ identity

    @staticmethod
    def name() -> str:
        return "ouroboros"

    def version(self) -> str | None:
        return self._version

    def get_version_command(self) -> str:
        return sh.version_command()

    def parse_version(self, output: str) -> str | None:
        return sh.parse_version(output)

    # ------------------------------------------------------------------ install

    async def install(self, environment: BaseEnvironment) -> None:
        """Upload the prebuilt Linux dist and unpack it. No network, no compiler.

        Raising here is correct: an agent that cannot install has nothing to say about
        the task, and a silent half-install would produce a zero that looks like a model
        failure.
        """
        if not self._dist_path:
            raise RuntimeError(
                f"{DIST_ENV} is unset. Build a Linux client with `make dist` on a Linux "
                "host (ERTS does not cross-compile) and point this at the artifact, or "
                "pass --ak dist_path=/path/to/ouro"
            )

        source = Path(self._dist_path)
        if not source.is_file():
            raise RuntimeError(f"{DIST_ENV}={self._dist_path} is not a file")

        await environment.upload_file(source, sh.UPLOAD_PATH)
        await self.exec_as_root(environment, command=sh.install_script())

        # The daemon is started at install time, once, so that the run step is one turn
        # and not one cold start per turn. `ouro daemon` spawns and exits, which is what
        # makes that safe to do from a command that must return.
        await self.exec_as_root(
            environment,
            command=sh.daemon_command(model_spec=self._model_spec),
        )

    # ------------------------------------------------------------------ run

    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
    ) -> None:
        """Hand the instruction to one headless turn, then record what it cost.

        Deliberately does not raise on a bad turn. A model that gives up, a tool that
        refuses, a turn that times out — those are outcomes the task's own tests are
        there to score. Turning them into an exception would replace a measured zero with
        an errored trial, which is a different and less honest number.
        """
        stream_path = (self.environment_logs_dir or PurePosixPath("/logs/agent")) / "stream.ndjson"

        command = sh.run_command(
            instruction=instruction,
            workspace=self._workspace,
            timeout_secs=self._timeout_secs,
            stream_path=str(stream_path),
        )

        exec_result = await environment.exec(
            command=command,
            cwd=self._workspace,
            env=self._model_env(),
            timeout_sec=self._timeout_secs + TIMEOUT_MARGIN_SECS,
        )

        # stdout is redirected to the container so that a very large stream never has to
        # come back through the exec channel; read it from the file, and fall back to
        # whatever `exec` captured if the redirect did not happen.
        stdout = await self._read_stream(environment, stream_path) or (exec_result.stdout or "")

        result = parse_stream(stdout, exit_code=exec_result.return_code)

        self._write_logs(stdout, instruction, result, exec_result)
        self._populate(context, result)

        # Best effort: leaving a runtime running would be harmless (the container is
        # discarded) but stopping it flushes journals, and a flushed journal is a better
        # artifact than a truncated one.
        try:
            await environment.exec(command=sh.stop_command(), timeout_sec=60)
        except Exception:  # noqa: BLE001 - teardown must never fail a trial
            pass

    def populate_context_post_run(self, context: AgentContext) -> None:
        """Nothing to add: `run` already populated the context as it went.

        Kept as an explicit no-op because the base class documents populating the context
        *during* execution so a timeout still carries numbers, and an empty override says
        that was done on purpose rather than forgotten.
        """
        return None

    # ------------------------------------------------------------------ internals

    def _model_env(self) -> dict[str, str]:
        """The model spec and exactly one key, forwarded from the host.

        One key, named by the provider the model spec chose, and only if the host has it.
        A container that gets every key in the operator's shell is a container one bad
        task can exfiltrate from.
        """
        env: dict[str, str] = {}
        if self._model_spec:
            env["OUROBOROS_NATIVE_MODEL"] = self._model_spec
            key_env = provider_key_env(self._model_spec)
            if key_env:
                value = os.environ.get(key_env)
                if value:
                    env[key_env] = value

        extra = getattr(self, "_extra_env", None)
        if isinstance(extra, dict):
            env.update(extra)
        return env

    async def _read_stream(self, environment: BaseEnvironment, path: PurePosixPath) -> str | None:
        try:
            read = await environment.exec(command=f"cat {path}", timeout_sec=120)
        except Exception:  # noqa: BLE001 - the fallback below is the point
            return None
        if read.return_code != 0:
            return None
        return read.stdout or None

    def _write_logs(self, stdout: str, instruction: str, result, exec_result) -> None:
        logs = Path(self.logs_dir)
        logs.mkdir(parents=True, exist_ok=True)

        # The raw stream is the trajectory of record: the golden-pinned event contract,
        # not a rendering of it.
        (logs / "trajectory.ndjson").write_text(stdout, encoding="utf-8")
        (logs / "trajectory.json").write_text(
            json.dumps(build_trajectory(stdout, instruction, self._model_spec), indent=2),
            encoding="utf-8",
        )
        (logs / "ouro-run.json").write_text(
            json.dumps(
                {
                    "return_code": exec_result.return_code,
                    "stderr": (exec_result.stderr or "")[-20000:],
                    "result": result.as_metadata(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def _populate(self, context: AgentContext, result) -> None:
        context.n_input_tokens = result.input_tokens
        context.n_output_tokens = result.output_tokens
        context.n_cache_tokens = result.cache_tokens
        context.cost_usd = result.cost_usd

        metadata = result.as_metadata()
        metadata["ouro_model"] = self._model_spec
        metadata["ouro_client_version"] = self._version
        metadata["ouro_agent_crashed"] = result.crashed
        context.metadata = {**(context.metadata or {}), **metadata}
