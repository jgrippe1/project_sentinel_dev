
import unittest
import sqlite3
import os
from sentinel.datastore import Datastore
from sentinel.cve_analyzer import HybridAnalyzer
import unittest.mock as mock

class TestMetadataUpdate(unittest.TestCase):
    def setUp(self):
        # Use a temporary DB for testing
        self.test_db = "test_metadata.db"
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        self.db = Datastore(self.test_db)

    def tearDown(self):
        self.db.close() # Ensure connection is closed
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def test_manual_metadata_save(self):
        mac = "00:11:22:33:44:55"
        self.db.upsert_asset(mac, "192.168.1.100")
        
        # Simulate manual update via API (which calls update_asset_governance)
        self.db.update_asset_governance(
            mac, 
            custom_name="Living Room TV",
            model="OLED65",
            os="WebOS",
            vendor="LG"
        )
        
        # Verify DB content
        conn = sqlite3.connect(self.test_db)
        c = conn.cursor()
        c.execute("SELECT custom_name, model, os, vendor FROM assets WHERE mac_address=?", (mac,))
        row = c.fetchone()
        conn.close()
        
        print(f"\nDB Row: {row}")
        self.assertEqual(row[0], "Living Room TV")
        self.assertEqual(row[1], "OLED65")
        self.assertEqual(row[2], "WebOS")
        self.assertEqual(row[3], "LG")

    def test_llm_context_injection(self):
        # Mock asset context from DB
        asset_context = {
            "vendor": "LG",
            "model": "OLED65",
            "actual_fw_version": "5.0.0",
            "custom_name": "Living Room TV"
        }
        
        analyzer = HybridAnalyzer({'options': {'llm_enabled': True, 'llm_api_key': 'mock_key'}})
        
        with mock.patch('requests.post') as mock_post:
            analyzer._query_llm("CVE-2023-1234", "Buffer overflow in WebOS", asset_context, {'result': 'INCONCLUSIVE', 'reason': 'Regex failed'})
            
            call_args = mock_post.call_args[1]
            prompt = call_args['json']['messages'][0]['content']
            
            print("\nGenerated Prompt Snippet with Context:")
            print("-" * 20)
            print(prompt[:500] + "...")
            print("-" * 20)
            
            self.assertIn("Target Asset Name: Living Room TV", prompt)
            self.assertIn("Target Asset: LG OLED65", prompt)

if __name__ == "__main__":
    unittest.main()
