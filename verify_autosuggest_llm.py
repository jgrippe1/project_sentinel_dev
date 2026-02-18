
import unittest
import json
import unittest.mock as mock
from sentinel.cve_analyzer import HybridAnalyzer
from sentinel.api import app

class TestAutosuggestLLM(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.mock_llm_response = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "vendor": "Sonos",
                        "model": "One",
                        "os": "Linux",
                        "device_type": "IoT"
                    })
                }
            }]
        }

    def test_autosuggest_api(self):
        # Mock requests.post in HybridAnalyzer
        with mock.patch('requests.post') as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = self.mock_llm_response
            
            # Enable LLM for this test
            with mock.patch("builtins.open", mock.mock_open(read_data='{}')):
                with mock.patch("os.path.exists", return_value=True):
                    with mock.patch.object(HybridAnalyzer, '__init__', return_value=None) as mock_init:
                        # We need to manually set attributes since we mocked init
                        from sentinel.api import analyzer
                        analyzer.llm_enabled = True
                analyzer.llm_enabled = True
                analyzer.llm_key = "mock_key"
                analyzer.llm_url = "http://mock-llm/v1/chat/completions"
                analyzer.llm_model = "gpt-4"

                # Simulate API Call
                payload = {
                    "name": "Kitchen Speaker",
                    "hostname": "Sonos-One",
                    "mac": "00:11:22:33:44:55"
                }
                
                response = self.client.post('/api/analyze/metadata', json=payload)
                data = response.get_json()
                
                print(f"\nAPI Response: {data}")
                
                self.assertEqual(response.status_code, 200)
                self.assertEqual(data['vendor'], "Sonos")
                self.assertEqual(data['model'], "One")
                self.assertEqual(data['device_type'], "IoT")

if __name__ == "__main__":
    unittest.main()
