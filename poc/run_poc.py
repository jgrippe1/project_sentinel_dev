
import sys
import os

# Add parent directory to path to import sentinel package
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.scanner import scan_subnet
from sentinel.analysis import grab_banner, analyze_banner
from sentinel.nvd_client import NVDClient

def get_local_ip():
    """Attempt to determine the local IP to guess the subnet."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't need to be reachable
        s.connect(('8.8.8.8', 1)) 
        IP = s.getsockname()[0]
        s.close()
        return IP
    except Exception:
        return '127.0.0.1'

import socket

def derive_subnet(ip):
    # Very basic /24 assumption for PoC
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

def main():
    print("Project Sentinel - Proof of Concept")
    print("===================================")
    
    # 1. Determine Subnet
    local_ip = get_local_ip()
    subnet = derive_subnet(local_ip)
    print(f"Detected Local IP: {local_ip}")
    print(f"Scanning Subnet: {subnet}")
    
    # 2. Scanner
    print("\n[Phase 1] Discovery: Scanning for active hosts...")
    # Determine ports to scan.
    # User mentioned 80/443, we can add common ones.
    target_ports = [80, 443, 8080, 22] 
    active_hosts = scan_subnet(subnet, ports=target_ports, max_threads=50) # Reduced threads for safety
    
    if not active_hosts:
        print("No active hosts found (or firewall blocking).")
        return

    print(f"Found {len(active_hosts)} hosts.")

    # 3. Enrichment & 4. Security
    client = NVDClient()
    
    print("\n[Phase 2 & 3] Enrichment & Analysis...")
    for ip, open_ports in active_hosts.items():
        print(f"\nHost: {ip}")
        for port in open_ports:
            print(f"  - Port {port}: Open")
            
            # Banner Grab
            banner = grab_banner(ip, port)
            if banner:
                print(f"    Banner: {banner[:100]}..." if len(banner) > 100 else f"    Banner: {banner}")
                product, version = analyze_banner(banner)
                
                if product and version:
                    print(f"    Identified: {product} {version}")
                    
                    # NVD Lookup
                    print(f"    Querying NVD for {product} {version}...")
                    vulnerabilities = client.lookup_cve(f"{product} {version}", limit=3)
                    
                    if vulnerabilities:
                        print(f"    [!] Found {len(vulnerabilities)} potential Critical/High CVEs (showing top 3):")
                        for item in vulnerabilities:
                            cve = item.get('cve', {})
                            cve_id = cve.get('id')
                            # Try to extract Score
                            metrics = cve.get('metrics', {})
                            # V3.1 or V3.0 or V2
                            cvss_data = {}
                            if 'cvssMetricV31' in metrics:
                                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                            elif 'cvssMetricV30' in metrics:
                                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                            
                            score = cvss_data.get('baseScore', 'N/A')
                            print(f"      - {cve_id} (CVSS: {score})")
                    else:
                         print("    [+] No direct CVE matches found.")
                else:
                    print("    [-] Could not extract version info.")
            else:
                print("    [-] No banner retrieved.")

if __name__ == "__main__":
    main()
