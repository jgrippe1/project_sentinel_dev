
import unittest
import os
import sys
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '..', '..', 'f:', 'Gravity', 'Project Sentinel', 'project_sentinel')))

from sentinel.cve_analyzer import HybridAnalyzer

# Mock Config
def make_config(enabled=True, provider="openai", base_url="", model=""):
    return {
        "options": {
            "llm_enabled": enabled,
            "llm_provider": provider,
            "llm_base_url": base_url,
            "llm_model": model,
            "llm_api_key": "sk-dummy"
        }
    }

class TestLLMConfig(unittest.TestCase):
    def test_openai_defaults(self):
        cfg = make_config(provider="openai")
        analyzer = HybridAnalyzer(cfg)
        self.assertEqual(analyzer.llm_base_url, "https://api.openai.com/v1")
        self.assertEqual(analyzer.llm_model, "gpt-3.5-turbo")

    def test_anthropic_defaults(self):
        cfg = make_config(provider="anthropic")
        analyzer = HybridAnalyzer(cfg)
        self.assertEqual(analyzer.llm_base_url, "https://api.anthropic.com/v1")
        self.assertEqual(analyzer.llm_model, "claude-3-haiku-20240307")

    def test_google_defaults(self):
        cfg = make_config(provider="google")
        analyzer = HybridAnalyzer(cfg)
        self.assertEqual(analyzer.llm_base_url, "https://generativelanguage.googleapis.com/v1beta/openai")
        self.assertEqual(analyzer.llm_model, "gemini-1.5-flash")

    def test_ollama_defaults(self):
        cfg = make_config(provider="ollama")
        analyzer = HybridAnalyzer(cfg)
        self.assertEqual(analyzer.llm_base_url, "http://homeassistant.local:11434/v1")
        self.assertEqual(analyzer.llm_model, "llama3")

    def test_custom_overrides(self):
        # User provides specific model for OpenAI
        cfg = make_config(provider="openai", model="gpt-4")
        analyzer = HybridAnalyzer(cfg)
        self.assertEqual(analyzer.llm_base_url, "https://api.openai.com/v1") # Default URL
        self.assertEqual(analyzer.llm_model, "gpt-4") # Override Model

        # User provides specific URL for Custom
        cfg = make_config(provider="custom", base_url="http://my-local-ai:8080/v1", model="my-model")
        analyzer = HybridAnalyzer(cfg)
        self.assertEqual(analyzer.llm_base_url, "http://my-local-ai:8080/v1")
        self.assertEqual(analyzer.llm_model, "my-model")

if __name__ == '__main__':
    unittest.main()
