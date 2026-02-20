import json
from sentinel.cve_analyzer import HybridAnalyzer
import logging
logging.basicConfig(level=logging.INFO)

config = {"options": {
    "llm_enabled": True,
    "llm_provider": "openai",
    "llm_model": "gemini-2.0-flash-exp",
    "llm_api_key": "dummy",
    "llm_base_url": "https://generativelanguage.googleapis.com/v1beta/openai"
}}

try:
    with open("project_sentinel/config.yaml") as f:
        for line in f.readlines():
            if "llm_api_key:" in line:
                key = line.split(":", 1)[1].strip().strip('"')
                if key: config["options"]["llm_api_key"] = key
except Exception as e:
    pass

analyzer = HybridAnalyzer(config)
print("Testing infer_device_metadata...")
res = analyzer.infer_device_metadata("Test Device", "test-host", "00:11:22:33:44:55", "Test OUI")
print("Result:", res)
