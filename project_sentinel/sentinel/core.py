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
    Aggregates high-fidelity intelligence (OS, Model, Firmware) across ports.
    """
    aggregated_intel = {
        'os': None,
        'model': None,
        'fw_version': None,
        'vendor': None
    }

    for port in ports:
        banner = grab_banner(ip, port)
        if banner:
            logger.info(f"DEBUG: Raw Banner from {ip}:{port} -> {banner[:100]}...")
        
        product, version, os_found = analyze_banner(banner)
        
        # 2.5a Advanced Intelligence Mining
        from sentinel.analysis import analyze_device_intelligence
        device_intel = analyze_device_intelligence(banner)
        
        # Merge intelligence
        if os_found and not aggregated_intel['os']: 
            aggregated_intel['os'] = os_found
            logger.info(f"Mined High-Fidelity OS for {ip}: {os_found}")
            
        if device_intel.get('model') and not aggregated_intel['model']: 
            aggregated_intel['model'] = device_intel['model']
            logger.info(f"Mined High-Fidelity Model for {ip}: {device_intel['model']}")
            
        if device_intel.get('fw_version') and not aggregated_intel['fw_version']: 
            aggregated_intel['fw_version'] = device_intel['fw_version']
            logger.info(f"Mined High-Fidelity Firmware for {ip}: {device_intel['fw_version']}")
            
        if device_intel.get('vendor') and not aggregated_intel['vendor']: 
            aggregated_intel['vendor'] = device_intel['vendor']
            logger.info(f"Mined High-Fidelity Vendor for {ip}: {device_intel['vendor']}")

        db.upsert_service(
            mac=mac,
            port=port,
            proto="tcp",
            service_name="unknown",
            banner=banner,
            version_string=version
        )
        
        # 2.5b SSL Certificate Check (Certificate Sentinel)
        if port in [443, 8443, 8123]: # Common SSL ports
            from sentinel.analysis import get_ssl_expiry
            expiry = get_ssl_expiry(ip, port)
            if expiry:
                db.upsert_service(
                    mac=mac,
                    port=port,
                    proto="tcp",
                    service_name="ssl-cert",
                    banner=f"SSL Certificate Expiry: {expiry}",
                    version_string=None,
                    cert_expiry=expiry.isoformat()
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
                
                # Extract CVSS score
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
    
    # Final step: Merge base intelligence with mining results
    from sentinel.analysis import get_vendor_from_mac, OUI_MAP
    oui_vendor = get_vendor_from_mac(mac)
    
    # Enhanced Logging for OUI
    if oui_vendor:
        prefix = mac[:8].upper()
        if prefix in OUI_MAP:
            logger.info(f"OUI Intelligence (Local Map) for {ip}: {oui_vendor}")
        else:
            logger.info(f"OUI Intelligence (Global API) for {ip}: {oui_vendor}")

    final_vendor = aggregated_intel['vendor'] or oui_vendor
    if final_vendor:
        logger.info(f"Final Intelligence Baseline for {ip}: Vendor={final_vendor}, Model={aggregated_intel['model']}, OS={aggregated_intel['os']}")

    # Commit to database
    db.upsert_asset(
        mac=mac, 
        ip=ip, 
        os=aggregated_intel['os'], 
        model=aggregated_intel['model'], 
        fw_version=aggregated_intel['fw_version'],
        vendor=final_vendor,
        oui_vendor=oui_vendor
    )

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
                # Track processed MACs and IPs to avoid duplicates
                processed_macs = set()
                processed_ips = {} # ip -> mac

                # Process Router Assets first (Best MAC/IP mapping)
                for asset in router_assets:
                    mac = asset['mac']
                    ip = asset['ip']
                    interface = asset.get('interface')
                    hostname = asset.get('hostname')
                    original_type = asset.get('type')
                    
                    # Deduplication Cleanup: If a placeholder exists for this IP, remove it
                    placeholder = f"mac_{ip.replace('.', '_')}"
                    if db.get_asset(placeholder):
                        logger.info(f"Deduplication: Merging placeholder {placeholder} into real MAC {mac} for {ip}")
                        db.delete_asset(placeholder)

                    db.upsert_asset(mac=mac, ip=ip, hostname=hostname, interface=interface, parent_mac=router_host, original_device_type=original_type)
                    processed_macs.add(mac)
                    processed_ips[ip] = mac
                    
                    # If active scan also found it, use its ports
                    ports = scanned_hosts.get(ip, [80, 443, 22, 8080]) 
                    process_host(ip, mac, ports, db, nvd)

                # Process remaining active hosts (those not seen by router)
                from sentinel.scanner import resolve_mac
                for ip, ports in scanned_hosts.items():
                    if ip in processed_ips:
                        continue # Already handled via router discovery

                    # 1. Check if we already have a real MAC for this IP in the DB (from previous runs)
                    stored_asset = db.get_asset_by_ip(ip)
                    if stored_asset and not stored_asset['mac_address'].startswith('mac_'):
                        mac = stored_asset['mac_address']
                        logger.debug(f"Discovery: Mapping {ip} to existing real MAC {mac}")
                    else:
                        # 2. Try to resolve MAC locally (ARP/Neighbor)
                        resolved_mac = resolve_mac(ip)
                        if resolved_mac:
                            mac = resolved_mac
                            logger.info(f"Discovery: Resolved {ip} to local MAC {mac}")
                        else:
                            mac = f"mac_{ip.replace('.', '_')}"
                    
                    if mac not in processed_macs:
                        db.upsert_asset(mac=mac, ip=ip)
                        process_host(ip, mac, ports, db, nvd)
                        processed_macs.add(mac)
                        processed_ips[ip] = mac

            except Exception as e:
                logger.error(f"Error during scan of {subnet}: {e}")

        logger.info(f"Scan cycle complete. Sleeping for {interval} minutes.")
        time.sleep(interval * 60)

if __name__ == "__main__":
    main()
