import time
import json
import os
import sys
import logging
from sentinel.scanner import scan_subnet
from sentinel.analysis import grab_banner, analyze_banner
from sentinel.datastore import Datastore
# from sentinel.nvd_client import NVDClient

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SentinelCore")

OPTIONS_PATH = "/data/options.json"

def load_config():
    config = {
        "scan_interval": 15,
        "subnets": [],
        "log_level": "info"
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
                    # For now, using IP as MAC placeholder if we can't resolve it yet.
                    # In a real Add-on with host networking, we would do ARP lookup here.
                    mac_placeholder = f"mac_{ip.replace('.', '_')}" 
                    
                    db.upsert_asset(mac=mac_placeholder, ip=ip)
                    
                    # 2. Enrichment
                    for port in ports:
                        banner = grab_banner(ip, port)
                        product, version = analyze_banner(banner)
                        
                        db.upsert_service(
                            mac=mac_placeholder,
                            port=port,
                            proto="tcp", # Assuming TCP for now
                            service_name="unknown",
                            banner=banner,
                            version=version
                        )
                        
                        if product and version:
                            logger.info(f"Identified {product} {version} on {ip}:{port}")
                            # TODO: Queue NVD Lookup
                            
            except Exception as e:
                logger.error(f"Error during scan of {subnet}: {e}")

        logger.info(f"Scan cycle complete. Sleeping for {interval} minutes.")
        time.sleep(interval * 60)

if __name__ == "__main__":
    main()
