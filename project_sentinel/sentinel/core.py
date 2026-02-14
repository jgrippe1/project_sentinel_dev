import time
import json
import os
import sys
import logging
from sentinel.scanner import scan_subnet
from sentinel.analysis import grab_banner, analyze_banner
from sentinel.datastore import Datastore
from sentinel.nvd_client import NVDClient

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SentinelCore")

OPTIONS_PATH = "/data/options.json"

def load_config():
    config = {
        "scan_interval": 15,
        "subnets": [],
        "log_level": "info",
        "nvd_api_key": ""
    }
    if os.path.exists(OPTIONS_PATH):
        try:
            with open(OPTIONS_PATH, 'r') as f:
                options = json.load(f)
                config.update(options)
        except Exception as e:
            logger.error(f"Failed to load options: {e}")
    return config

def main():
    logger.info("Starting Project Sentinel Core...")
    db = Datastore()
    
    while True:
        config = load_config()
        interval = config.get("scan_interval", 15)
        subnets = config.get("subnets", [])
        nvd_api_key = config.get("nvd_api_key", "")
        
        nvd = NVDClient(api_key=nvd_api_key if nvd_api_key else None)
        
        # Auto-detect subnet if empty (Re-using logic from PoC for now)
        if not subnets:
            # Basic fallback
            subnets = ["192.168.1.0/24"] 
            # TODO: Better auto-detection in container environment

        logger.info(f"Starting scan cycle. Target Subnets: {subnets}")
        
        for subnet in subnets:
            try:
                # 1. Discovery
                hosts = scan_subnet(subnet)
                logger.info(f"Discovered {len(hosts)} hosts in {subnet}")
                
                for ip, ports in hosts.items():
                    mac_placeholder = f"mac_{ip.replace('.', '_')}" 
                    db.upsert_asset(mac=mac_placeholder, ip=ip)
                    
                    # 2. Enrichment
                    for port in ports:
                        banner = grab_banner(ip, port)
                        product, version = analyze_banner(banner)
                        
                        db.upsert_service(
                            mac=mac_placeholder,
                            port=port,
                            proto="tcp",
                            service_name="unknown",
                            banner=banner,
                            version_string=version
                        )
                        
                        if product and version:
                            logger.info(f"Identified {product} {version} on {ip}:{port}")
                            
                            # 3. Vulnerability Lookup
                            logger.info(f"Querying NVD for {product} {version}...")
                            vulnerabilities = nvd.lookup_cpe(product, version)
                            
                            for item in vulnerabilities:
                                cve = item.get('cve', {})
                                cve_id = cve.get('id')
                                descriptions = cve.get('descriptions', [{}])
                                description = descriptions[0].get('value', 'No description')
                                
                                # Extract CVSS score (checking for v3.1, then v3.0, then v2)
                                metrics = cve.get('metrics', {})
                                cvss_score = 0
                                if 'cvssMetricV31' in metrics:
                                    cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                                elif 'cvssMetricV30' in metrics:
                                    cvss_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                                elif 'cvssMetricV2' in metrics:
                                    cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                                
                                db.upsert_vulnerability(
                                    mac=mac_placeholder,
                                    cve_id=cve_id,
                                    cvss_score=cvss_score,
                                    description=description
                                )
                                logger.info(f"Logged vulnerability {cve_id} (Score: {cvss_score}) for {ip}")
                            
            except Exception as e:
                logger.error(f"Error during scan of {subnet}: {e}")

        logger.info(f"Scan cycle complete. Sleeping for {interval} minutes.")
        time.sleep(interval * 60)

if __name__ == "__main__":
    main()
