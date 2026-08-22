"""Translating Harbor's model naming into Ouroboros's, and finding the key it needs.

Harbor names a model `provider/model` (`-m anthropic/claude-opus-4-1`). Ouroboros names
it `provider:model`, because that is ReqLLM's spec syntax and
`Ouroboros.Provider.Native.Model.ReqLLM` passes it through untouched. One colon apart,
and getting it wrong is a session that refuses to start rather than a session that runs
the wrong model, which is the failure mode worth having.
"""

from __future__ import annotations

# `ReqLLM.Keys.env_var_name/1` owns the real list; this is the subset a benchmark run
# plausibly uses, and an unknown provider falls back to the conventional
# <PROVIDER>_API_KEY spelling rather than refusing.
_KEY_ENV = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "openai_codex": "OPENAI_API_KEY",
    "google": "GOOGLE_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "xai": "XAI_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "together": "TOGETHER_API_KEY",
    "cerebras": "CEREBRAS_API_KEY",
    "zai": "ZAI_API_KEY",
    # Ollama is local and needs no key; naming it here keeps it out of the fallback.
    "ollama": "",
}


def native_model_spec(model_name: str | None) -> str | None:
    """`anthropic/claude-opus-4-1` -> `anthropic:claude-opus-4-1`.

    A name that already carries a colon is passed through: an operator who wrote a
    ReqLLM spec meant it. Only the FIRST slash is translated, because a model id may
    contain further slashes (`openrouter/anthropic/claude-3.5` -> the provider is
    `openrouter` and the model is `anthropic/claude-3.5`).
    """
    if model_name is None:
        return None

    name = model_name.strip()
    if not name:
        return None
    if ":" in name:
        return name
    if "/" not in name:
        # No provider at all. Ouroboros would refuse this, and refusing here gives a
        # better message than a session start failure inside a container.
        raise ValueError(
            f"model {model_name!r} names no provider; "
            "pass provider/model (harbor) or provider:model (ReqLLM)"
        )

    provider, model = name.split("/", 1)
    return f"{provider}:{model}"


def provider_of(model_spec: str) -> str:
    """The provider half of a ReqLLM spec."""
    return model_spec.split(":", 1)[0]


def provider_key_env(model_spec: str) -> str | None:
    """The environment variable holding the key this model needs, or None if it needs none."""
    provider = provider_of(model_spec)
    if provider in _KEY_ENV:
        return _KEY_ENV[provider] or None
    return f"{provider.upper()}_API_KEY"
