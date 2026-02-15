import re
import ssl
import socket
import datetime
from datetime import timezone

def grab_banner(ip, port, timeout=2):
    """
    Connects to an IP and port to grab the banner.
    Returns the banner string/bytes or None.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            
            # Send a basic HTTP request if port implies HTTP to trigger a response
            if port in [80, 8080, 443]:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            
            try:
                banner = s.recv(2048) # Increased buffer
                return banner.decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                return None
    except Exception as e:
        return None

def analyze_banner(banner):
    """
    Parses a banner to extract product, version, and OS intelligence.
    """
    if not banner:
        return None, None, None

    product, version, os_found = None, None, None

    # HTTP Server Header: "Server: Apache/2.4.41 (Ubuntu)"
    http_match = re.search(r'Server:\s*([^/\s\r\n]+)(?:/([^\s\r\n(]+))?(?:\s*\(([^)]+)\))?', banner, re.IGNORECASE)
    if http_match:
        product = http_match.group(1)
        version = http_match.group(2)
        os_info = http_match.group(3)
        if os_info:
            if any(x in os_info.lower() for x in ['ubuntu', 'debian', 'linux']): os_found = "Linux"
            if 'win' in os_info.lower(): os_found = "Windows"
            if 'macos' in os_info.lower(): os_found = "macOS"

    # SSH Banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    if not product:
        ssh_match = re.search(r'(?:SSH-\d\.\d-)([^_\s-]+)_([^\s-]+)(?:\s+([^_\s-]+))?', banner)
        if ssh_match:
            product = ssh_match.group(1)
            version = ssh_match.group(2)
            os_raw = ssh_match.group(3)
            if os_raw:
                if 'ubuntu' in os_raw.lower() or 'debian' in os_raw.lower(): os_found = "Linux"

    # FTP/Generic: "220 (vsFTPd 3.0.3)" or "220-FileZilla Server 0.9.60 beta"
    if not product:
        ftp_match = re.search(r'(?:220[\s-].*?)([^/\s\r\n()]+)\s+([0-9.]+[^\s\r\n]*)', banner)
        if ftp_match:
            product = ftp_match.group(1)
            version = ftp_match.group(2)

    # Generic Product/Version: "Product v1.2.3" or "Product 1.2.3"
    if not product:
        generic_match = re.search(r'^([a-zA-Z._-]+)[/\s]v?([0-9]+\.[0-9.]+[a-zA-Z0-9-]*)', banner)
        if generic_match:
            product = generic_match.group(1)
            version = generic_match.group(2)
            
    return product, version, os_found

def analyze_device_intelligence(banner):
    """
    Specifically looks for Hardware/Model/Firmware details in banners.
    Used for high-fidelity mining.
    """
    if not banner: return {}
    intel = {}

    # ASUS Router Detection
    if "asus" in banner.lower():
        model_match = re.search(r'(RT-[A-Z0-9-]+|GT-[A-Z0-9-]+)', banner, re.IGNORECASE)
        if model_match: intel['model'] = model_match.group(1).upper()
    
    # Synology Detection
    if "synology" in banner.lower():
        intel['vendor'] = "Synology"
        model_match = re.search(r'(DS\d+[a-z+]*)', banner, re.IGNORECASE)
        if model_match: intel['model'] = model_match.group(1).upper()

    # TP-Link Detection
    if "tp-link" in banner.lower():
        intel['vendor'] = "TP-Link"
        model_match = re.search(r'(Archer\s?[A-Z\d]+|RE\d+|TL-[A-Z\d-]+)', banner, re.IGNORECASE)
        if model_match: intel['model'] = model_match.group(1)

    # Generic Firmware Version patterns
    fw_match = re.search(r'Firmware[:\s]+v?([0-9]+\.[0-9.]+[a-zA-Z0-9-]*)', banner, re.IGNORECASE)
    if fw_match: intel['fw_version'] = fw_match.group(1)

    return intel

def get_ssl_expiry(ip, port, timeout=3):
    """
    Attempts to retrieve the SSL certificate expiry date for a given IP and port.
    Returns a datetime object or None.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert_dict = ssock.getpeercert()
                if cert_dict and 'notAfter' in cert_dict:
                    expiry_str = cert_dict['notAfter']
                    # Example: 'Aug 21 12:00:00 2026 GMT'
                    return datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
        
    except Exception:
        pass
    return None
