
import os
import sys
import sqlite3
import logging

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '..', '..', 'f:', 'Gravity', 'Project Sentinel', 'project_sentinel')))

from sentinel.datastore import Datastore
from sentinel.version_utils import parse_version

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FirmwareVerification")

def verify_and_cleanup():
    db = Datastore()
    mac = "10:7C:61:84:CF:C0"
    verified_version = "3.0.0.4.388_24768"
    
    # 0. Ensure Asset Exists (for manual runs/dev)
    if not db.get_asset(mac):
        logger.info(f"Asset {mac} not found. Creating it...")
        db.upsert_asset(mac=mac, ip="192.168.50.1", hostname="ASUS-Router", vendor="ASUSTek Computer Inc.")

    # 1. Update Asset with Verified Firmware
    logger.info(f"Updating asset {mac} with verified firmware: {verified_version}")
    db.update_asset_governance(mac, actual_fw_version=verified_version)
    
    # 2. Parse Major Version
    # ASUS format: 3.0.0.4.388_24768 -> Major is 388 (index 4)
    # v_parts: [3, 0, 0, 4, 388, 24768]
    v_parts = parse_version(verified_version)
    if len(v_parts) >= 5:
        major_version = v_parts[4]
        logger.info(f"Detected Major Version: {major_version}")
    else:
        logger.error(f"Could not parse major version from {verified_version}")
        return

    # 3. Vulnerability Cleanup
    target_cves = [
        "CVE-2013-6343", 
        "CVE-2011-2900", 
        "CVE-2011-5284", 
        "CVE-2007-4589", 
        "CVE-2011-5283"
    ]
    
    # 2.5 Seed Vulnerabilities (Simulate Active State for Verification)
    for cve_id in target_cves:
        db.upsert_vulnerability(
            mac=mac, 
            cve_id=cve_id, 
            cvss_score=9.8, 
            description="Legacy Vulnerability", 
            status='active'
        )

    fixed_major_version = 376
    
    if major_version > fixed_major_version:
        logger.info(f"Firmware is compliant: {major_version} > {fixed_major_version}")
        
        for cve_id in target_cves:
            reason = f"Firmware version {verified_version} exceeds the vulnerability scope (Patched in 3.0.0.4.376)."
            logic = f"Manual Verification: {major_version} > {fixed_major_version}"
            
            logger.info(f"Suppressing {cve_id}...")
            db.suppress_vulnerability(
                mac=mac,
                cve_id=cve_id,
                reason=reason,
                logic=logic,
                user_ver=verified_version
            )
            
    else:
        logger.warning(f"Firmware is NOT compliant: {major_version} <= {fixed_major_version}")

if __name__ == "__main__":
    verify_and_cleanup()
