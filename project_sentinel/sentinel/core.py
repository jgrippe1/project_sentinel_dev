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
        "nvd_api_key": "",
        "router_host": "192.168.50.1",
        "router_port": 22,
        "router_username": "",
        "router_password": "",
        "router_ssh_key": ""
    }
    if os.path.exists(OPTIONS_PATH):
        try:
            with open(OPTIONS_PATH, 'r') as f:
                options = json.load(f)
                config.update(options)
        except Exception as e:
            logger.error(f"Failed to load options: {e}")
    return config

def process_host(ip, mac, ports, db, nvd):
    """
    Performs service enrichment and vulnerability lookup for a single host.
    """
    for port in ports:
        banner = grab_banner(ip, port)
        product, version = analyze_banner(banner)
        
        db.upsert_service(
            mac=mac,
            port=port,
            proto="tcp",
            service_name="unknown",
            banner=banner,
            version_string=version
        )
        
        # 2.5 SSL Certificate Check (Certificate Sentinel)
        if port in [443, 8443, 8123]: # Common SSL ports
            from sentinel.analysis import get_ssl_expiry
            expiry = get_ssl_expiry(ip, port)
            if expiry:
                db.upsert_service(
                    mac=mac,
                    port=port,
                    proto="tcp",
                    service_name="unknown",
                    banner=banner,
                    version_string=version,
                    cert_expiry=expiry
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
                    mac=mac,
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    description=description
                )
                logger.info(f"Logged vulnerability {cve_id} (Score: {cvss_score}) for {ip}")

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
                # 0. Optional Router Discovery (Seeding)
                router_host = config.get("router_host")
                router_user = config.get("router_username")
                
                router_assets = []
                if router_user:
                    from sentinel.scanner import RouterDiscovery
                    rd = RouterDiscovery(
                        host=router_host,
                        port=config.get("router_port", 22),
                        username=router_user,
                        password=config.get("router_password"),
                        ssh_key=config.get("router_ssh_key")
                    )
                    router_assets = rd.get_asus_clients()
                    logger.info(f"Router discovery found {len(router_assets)} devices.")

                # 1. Active Discovery
                scanned_hosts = scan_subnet(subnet)
                logger.info(f"Active scan discovered {len(scanned_hosts)} hosts in {subnet}")
                
                # 2. Merge and Process
                # Track processed MACs to avoid redundant scans in same cycle
                processed_macs = set()

                # Process Router Assets first (Best MAC/IP mapping)
                for asset in router_assets:
                    mac = asset['mac']
                    ip = asset['ip']
                    interface = asset.get('interface')
                    # Router discovery knows the 'parent' (the router itself)
                    db.upsert_asset(mac=mac, ip=ip, interface=interface, parent_mac=router_host)
                    processed_macs.add(mac)
                    
                    # If active scan also found it, use its ports
                    ports = scanned_hosts.get(ip, [80, 443, 22, 8080]) 
                    process_host(ip, mac, ports, db, nvd)

                # Process remaining active hosts (those not seen by router)
                for ip, ports in scanned_hosts.items():
                    # Create placeholder if we don't have a real MAC
                    mac_placeholder = f"mac_{ip.replace('.', '_')}"
                    if mac_placeholder not in processed_macs:
                        db.upsert_asset(mac=mac_placeholder, ip=ip)
                        process_host(ip, mac_placeholder, ports, db, nvd)

            except Exception as e:
                logger.error(f"Error during scan of {subnet}: {e}")

        logger.info(f"Scan cycle complete. Sleeping for {interval} minutes.")
        time.sleep(interval * 60)

if __name__ == "__main__":
    main()
