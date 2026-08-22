"""Harbor's model naming versus Ouroboros's, and which key a spec needs."""

import unittest

from ouroboros_agent.model import native_model_spec, provider_key_env, provider_of


class ModelSpec(unittest.TestCase):
    def test_harbor_naming_becomes_reqllm_naming(self):
        self.assertEqual(
            native_model_spec("anthropic/claude-opus-4-1"), "anthropic:claude-opus-4-1"
        )
        self.assertEqual(native_model_spec("openai/gpt-5.5"), "openai:gpt-5.5")

    def test_only_the_first_slash_is_translated(self):
        # `openrouter/anthropic/claude-3.5`: the provider is openrouter and the model id
        # keeps its own slash. Splitting on every slash would name a model nobody serves.
        self.assertEqual(
            native_model_spec("openrouter/anthropic/claude-3.5"),
            "openrouter:anthropic/claude-3.5",
        )

    def test_a_reqllm_spec_passes_through(self):
        self.assertEqual(native_model_spec("anthropic:claude-opus-4-1"), "anthropic:claude-opus-4-1")

    def test_whitespace_and_absence(self):
        self.assertIsNone(native_model_spec(None))
        self.assertIsNone(native_model_spec("   "))
        self.assertEqual(native_model_spec("  openai/gpt-5.5 "), "openai:gpt-5.5")

    def test_a_bare_model_name_is_refused_here_rather_than_in_a_container(self):
        with self.assertRaises(ValueError) as caught:
            native_model_spec("gpt-5.5")
        self.assertIn("names no provider", str(caught.exception))


class Keys(unittest.TestCase):
    def test_known_providers(self):
        self.assertEqual(provider_key_env("anthropic:claude-opus-4-1"), "ANTHROPIC_API_KEY")
        self.assertEqual(provider_key_env("openai:gpt-5.5"), "OPENAI_API_KEY")
        self.assertEqual(provider_key_env("openrouter:x/y"), "OPENROUTER_API_KEY")

    def test_a_local_provider_needs_none(self):
        self.assertIsNone(provider_key_env("ollama:llama3"))

    def test_an_unknown_provider_falls_back_to_the_convention(self):
        self.assertEqual(provider_key_env("newthing:model-1"), "NEWTHING_API_KEY")

    def test_provider_of(self):
        self.assertEqual(provider_of("openrouter:anthropic/claude-3.5"), "openrouter")


if __name__ == "__main__":
    unittest.main()
