
import unittest
from sentinel.version_utils import analyze_version_safety
from sentinel.cve_analyzer import HybridAnalyzer

class TestThreatLogic(unittest.TestCase):
    def test_asus_legacy_collision(self):
        # CVE-2011-2900 on Asus 3.0.0.4.388...
        # Description mentions Mongoose 3.0
        cve_id = "CVE-2011-2900"
        cve_desc = "Stack-based buffer overflow in the (1) put_dir function in mongoose.c in Mongoose 3.0, (2) put_dir function in yasslEWS.c in yaSSL Embedded Web Server (yasslEWS) 0.2, and (3) _shttpd_put_dir function in io_dir.c in Simple HTTPD (shttpd) 1.42 allows remote attackers to execute arbitrary code via an HTTP PUT request, as exploited in the wild in 2011."
        
        asset_context = {
            "vendor": "ASUSTeK Computer Inc.",
            "model": "RT-AX88U",
            "actual_fw_version": "3.0.0.4.388_24768"
        }
        
        # 1. Test Regex Relevance
        # It should still be relevant (we don't want to auto-dismiss if unclear), 
        # but analyze_version_safety might return INCONCLUSIVE or low confidence.
        result = analyze_version_safety(asset_context['actual_fw_version'], cve_desc, asset_context)
        print(f"\nRegex Result: {result}")
        
        # 2. Test LLM Prompt Generation (Mocking HybridAnalyzer)
        analyzer = HybridAnalyzer({'options': {'llm_enabled': True, 'llm_api_key': 'mock_key'}})
        
        # Capture the prompt by mocking the requests.post call or the internal _query_llm logic
        import unittest.mock as mock
        
        with mock.patch('requests.post') as mock_post:
            # We don't care about the response, just want to see the 'data' passed to post
            analyzer._query_llm(cve_id, cve_desc, asset_context, result)
            
            # Extract prompt from call arguments
            call_args = mock_post.call_args[1]
            prompt = call_args['json']['messages'][0]['content']
        
        print("\nGenerated LLM Prompt Snippet:")
        print("-" * 20)
        # Check for presence of new rules
        self.assertIn("ENTITY ISOLATION", prompt)
        self.assertIn("COLLISION AVOIDANCE", prompt)
        self.assertIn("LEGACY COMPONENT RESOLUTION", prompt)
        print(prompt[:500] + "...")
        print("-" * 20)

    def test_vendor_mismatch(self):
        cve_desc = "Vulnerability in InterWorx 6.0 and earlier..."
        asset_context = {
            "vendor": "ASUS",
            "model": "Router",
            "actual_fw_version": "3.0"
        }
        result = analyze_version_safety("3.0", cve_desc, asset_context)
        print(f"\nVendor Mismatch Result: {result}")
        self.assertEqual(result['result'], 'SAFE')
        self.assertIn("Vendor/Product mismatch", result['reason'])

if __name__ == "__main__":
    unittest.main()
