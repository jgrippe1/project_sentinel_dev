
import unittest
from unittest.mock import MagicMock, patch
import os
import sys
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '..', '..', 'f:', 'Gravity', 'Project Sentinel', 'project_sentinel')))

from sentinel.cve_analyzer import HybridAnalyzer
from sentinel.datastore import Datastore

# Configure logging
logging.basicConfig(level=logging.INFO)

class TestHybridAnalyzer(unittest.TestCase):
    def setUp(self):
        # Setup ephemeral DB
        self.db_path = "test_hybrid.db"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
            
        # Initialize DB with new schema
        os.environ["SENTINEL_DB_PATH"] = self.db_path
        self.db = Datastore()
        self.db._init_db() # Explicit init for test
        
        # Analyzer Config (LLM Enabled)
        self.config = {
            "options": {
                "llm_enabled": True,
                "llm_provider": "openai",
                "llm_api_key": "sk-mock-key",
                "llm_model": "gpt-3.5-turbo"
            }
        }
        self.analyzer = HybridAnalyzer(self.config)
        self.analyzer.db = self.db # Inject test DB

        # Test Asset
        self.asset = {
            "vendor": "ASUSTek Computer Inc.",
            "model": "RT-AX86U",
            "actual_fw_version": "3.0.0.4.388_24768"
        }

    def tearDown(self):
        if os.path.exists(self.db_path):
             os.remove(self.db_path)
        pass

    def test_regex_high_confidence(self):
        print("\n--- Test: High Confidence Regex ---")
        cve_id = "CVE-2013-6343" 
        # Description is clear: "earlier than 3.0.0.4.376"
        description = "The HTTP server on ASUS RT-AX86U devices earlier than 3.0.0.4.376 allows arbitrary code execution."
        
        result = self.analyzer.analyze(cve_id, description, self.asset)
        
        print(f"Result: {result}")
        self.assertEqual(result['result'], 'SAFE')
        self.assertEqual(result['method'], 'regex')
        self.assertGreaterEqual(result['confidence'], 80)

    @patch('requests.post')
    def test_llm_fallback(self, mock_post):
        print("\n--- Test: LLM Fallback (Low Confidence Regex) ---")
        cve_id = "CVE-COMPLEX-001"
        # Ambiguous description
        description = "Vulnerability in the web interface affects devices purchased before 2023."
        
        # Mock LLM Response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": '{"result": "SAFE", "confidence": 95, "reason": "Purchased date irrelevant to firmware version 388."}'
                }
            }]
        }
        mock_post.return_value = mock_response

        # Run Analysis
        result = self.analyzer.analyze(cve_id, description, self.asset)
        
        print(f"Result: {result}")
        self.assertEqual(result['result'], 'SAFE')
        self.assertEqual(result['method'], 'llm-openai')
        
        # Verify Cache logic by running again
        print("\n--- Test: Cache Hit (Should not call LLM) ---")
        mock_post.reset_mock()
        
        result_cached = self.analyzer.analyze(cve_id, description, self.asset)
        print(f"Cached Result: {result_cached}")
        
        self.assertEqual(result_cached['result'], 'SAFE')
        self.assertEqual(result_cached['method'], 'llm-openai') # Should persist original method
        mock_post.assert_not_called()

if __name__ == '__main__':
    unittest.main()
