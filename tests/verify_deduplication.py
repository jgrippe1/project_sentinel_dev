
import os
import sys
import sqlite3
import datetime

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '..', '..', 'f:', 'Gravity', 'Project Sentinel', 'project_sentinel')))

# Manually setting path for test
os.environ["SENTINEL_DB_PATH"] = "test_sentinel.db"

from sentinel.datastore import Datastore

def test_deduplication():
    # 1. Setup
    if os.path.exists("test_sentinel.db"):
        os.remove("test_sentinel.db")
    
    db = Datastore("test_sentinel.db")
    ip = "192.168.1.100"
    placeholder_mac = f"mac_{ip.replace('.', '_')}"
    real_mac = "AA:BB:CC:DD:EE:FF"
    
    print(f"--- Test Case 1: Placeholder exists, real MAC arrives ---")
    
    # 2. Insert Placeholder
    db.upsert_asset(placeholder_mac, ip, hostname="Placeholder-Host")
    db.upsert_service(placeholder_mac, 80, "tcp", "http", "Test Banner", "1.0")
    db.upsert_vulnerability(placeholder_mac, "CVE-0000-0001", 7.5, "Test Vuln")
    db.update_asset_governance(placeholder_mac, custom_name="Old Name", location="Living Room")
    
    print("Placeholder created with service and vulnerability.")
    
    # 3. Upsert Real MAC
    db.upsert_asset(real_mac, ip, hostname="Real-Host")
    
    # 4. Verify
    asset_placeholder = db.get_asset(placeholder_mac)
    # MUST fetch real asset AFTER merge to see updated metadata
    asset_real = db.get_asset(real_mac)
    
    if asset_placeholder:
        print("FAILED: Placeholder still exists!")
    else:
        print("SUCCESS: Placeholder removed.")
        
    if not asset_real:
        print("FAILED: Real MAC not found!")
        return

    # Check services
    services = db.get_assets_with_services()
    real_services = [s for s in services if s['mac_address'] == real_mac][0]['services']
    if len(real_services) == 1 and real_services[0]['port'] == 80:
        print("SUCCESS: Service migrated.")
    else:
        print(f"FAILED: Service migration issue. Found: {real_services}")
        
    # Check vulnerabilities
    vulns = db.get_all_vulnerabilities()
    real_vulns = [v for v in vulns if v['mac_address'] == real_mac]
    if len(real_vulns) == 1 and real_vulns[0]['cve_id'] == "CVE-0000-0001":
        print("SUCCESS: Vulnerability migrated.")
    else:
        print(f"FAILED: Vulnerability migration issue. Found: {real_vulns}")

    # Check governance
    if asset_real['custom_name'] == "Old Name" and asset_real['location'] == "Living Room":
         print("SUCCESS: Governance metadata migrated.")
    else:
         print(f"FAILED: Metadata migration issue. Name={asset_real['custom_name']}, Loc={asset_real['location']}")

    print("\n--- Test Case 2: Conflict handling ---")
    # Add another service to real MAC
    db.upsert_service(real_mac, 443, "tcp", "https", "Secure Banner", "2.0")
    
    # Re-create a placeholder with a conflicting service (different banner/version)
    # Note: We simulate a placeholder creation manually since upsert_asset with placeholder won't trigger merge
    db.upsert_asset(placeholder_mac, ip, hostname="Placeholder-Conflict")
    db.upsert_service(placeholder_mac, 443, "tcp", "https", "Old Banner", "1.0")
    
    # Upsert real MAC again to trigger merge
    db.upsert_asset(real_mac, ip)
    
    # Verify 443 service is still the "Secure Banner" one (target should win)
    conn = sqlite3.connect("test_sentinel.db")
    c = conn.cursor()
    c.execute("SELECT banner FROM services WHERE mac_address=? AND port=443", (real_mac,))
    banner = c.fetchone()[0]
    conn.close()
    
    if banner == "Secure Banner":
        print("SUCCESS: Conflict handled correctly (favored target).")
    else:
        print(f"FAILED: Conflict handling issue. Banner={banner}")

    # Cleanup
    if os.path.exists("test_sentinel.db"):
        os.remove("test_sentinel.db")

if __name__ == "__main__":
    test_deduplication()
