
import sqlite3
import os
import logging
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '..', '..', 'f:', 'Gravity', 'Project Sentinel', 'project_sentinel')))

from sentinel.datastore import Datastore

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DBVerification")

def verify_db():
    db = Datastore()
    mac = "10:7C:61:84:CF:C0"
    
    # 1. Verify Asset Update
    conn = sqlite3.connect("sentinel.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute("SELECT actual_fw_version, fw_verified_at FROM assets WHERE mac_address=?", (mac,))
    row = c.fetchone()
    
    if row:
        logger.info(f"Asset {mac}: Actual Firmware = {row['actual_fw_version']}, Verified At = {row['fw_verified_at']}")
    else:
        logger.error(f"Asset {mac} not found!")

    # 2. Verify CVE Suppression
    target_cves = [
        "CVE-2013-6343", 
        "CVE-2011-2900", 
        "CVE-2011-5284", 
        "CVE-2007-4589", 
        "CVE-2011-5283"
    ]
    
    logger.info("Verifying CVE Status:")
    for cve in target_cves:
        c.execute("SELECT status, suppression_reason, suppression_logic FROM vulnerabilities WHERE mac_address=? AND cve_id=?", (mac, cve))
        vuln_row = c.fetchone()
        if vuln_row:
             logger.info(f"  {cve}: Status={vuln_row['status']}, Logic={vuln_row['suppression_logic']}")
        else:
             logger.warning(f"  {cve}: Not found based on current DB state (might have been cleaned up if not active)")
             
    conn.close()

if __name__ == "__main__":
    verify_db()
