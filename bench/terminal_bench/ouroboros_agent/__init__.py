"""Ouroboros as a Terminal-Bench (Harbor) agent.

The package is split so that everything decidable without a container is decidable
without a container: `install`, `model`, `result` and `trajectory` are pure functions
over strings and dicts and import nothing from Harbor, and `agent` is the thin Harbor
subclass that calls them. The unit tests import only the pure half, which is why they
run with no docker, no model key, and no `harbor` on the path.

`agent` is deliberately NOT imported here, so that `import ouroboros_agent.result` does
not require Harbor to be installed.
"""

from ouroboros_agent.model import native_model_spec, provider_key_env
from ouroboros_agent.result import OuroRunResult, parse_stream
from ouroboros_agent.trajectory import build_trajectory

__all__ = [
    "OuroRunResult",
    "build_trajectory",
    "native_model_spec",
    "parse_stream",
    "provider_key_env",
]
