
import unittest
import sqlite3
import os
import json
from sentinel.datastore import Datastore

class TestDiscrepancyLogic(unittest.TestCase):
    def setUp(self):
        self.test_db = "test_discrepancy.db"
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        self.db = Datastore(self.test_db)
        self.mac = "00:11:22:33:44:55"
        self.db.upsert_asset(self.mac, "192.168.1.100")

    def tearDown(self):
        # Handle lack of explicit close method by relying on garbage collection or ensuring connection is closed in methods
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def test_dismiss_update(self):
        # 1. Initial State
        self.db.update_asset_governance(self.mac, model="Pixel", vendor="Google", actual_fw_version="1.0")
        
        # 2. Simulate User Dismissing a "New Detection"
        # User clicks "Dismiss" on Vendor "Google Inc." -> dismissed_vendor = "Google Inc."
        self.db.update_asset_governance(self.mac, dismissed_vendor="Google Inc.")
        
        # 3. Verify Persistence
        conn = sqlite3.connect(self.test_db)
        c = conn.cursor()
        c.execute("SELECT vendor, dismissed_vendor FROM assets WHERE mac_address=?", (self.mac,))
        row = c.fetchone()
        conn.close()
        
        print(f"\nVendor Row: {row}")
        self.assertEqual(row[0], "Google")
        self.assertEqual(row[1], "Google Inc.")

    def test_dismiss_fw_update(self):
        # 1. Dismiss specific FW
        self.db.update_asset_governance(self.mac, dismissed_fw_version="2.0.0")
        
        conn = sqlite3.connect(self.test_db)
        c = conn.cursor()
        c.execute("SELECT actual_fw_version, dismissed_fw_version FROM assets WHERE mac_address=?", (self.mac,))
        row = c.fetchone()
        conn.close()
        
        print(f"\nFW Row: {row}")
        self.assertEqual(row[1], "2.0.0")

if __name__ == "__main__":
    unittest.main()
