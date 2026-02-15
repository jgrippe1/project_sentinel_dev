import re
import ssl
import socket
import datetime
from datetime import timezone

# Common IEEE OUIs (Manufacturer Prefixes)
OUI_MAP = {
    "08:3A:8D": "ASUSTek Computer Inc.",
    "B0:4E:26": "TP-Link",
    "EC:08:6B": "TP-Link",
    "C4:AD:34": "TP-Link",
    "4C:ED:FB": "TP-Link",
    "70:4F:57": "Ubiquiti",
    "F4:92:BF": "Ubiquiti",
    "74:AC:B9": "Ubiquiti",
    "80:2A:A8": "Ubiquiti",
    "DC:9F:DB": "Ubiquiti",
    "00:11:32": "Synology",
    "00:08:9B": "Synology",
    "D8:3B:BF": "Synology",
    "8C:CE:4E": "Synology",
    "E8:DB:84": "Shelly / Allterco",
    "84:F3:EB": "Shelly / Allterco",
    "3C:61:05": "Shelly / Allterco",
    "D4:D4:DA": "Shelly / Allterco",
    "C8:2B:96": "Shelly / Allterco",
    "A8:48:FA": "Shelly / Allterco",
    "CA:97:0B": "Shelly / Allterco",
    "48:3F:DA": "Shelly / Allterco",
    "B4:E6:2D": "Shelly / Allterco",
    "00:E0:4C": "Realtek (IoT Module)",
    "24:A1:60": "Espressif (ESPHome/Tasmota)",
    "30:AE:A4": "Espressif (ESPHome/Tasmota)",
    "A4:CF:12": "Espressif (ESPHome/Tasmota)",
    "C8:2B:96": "Espressif (ESPHome/Tasmota)",
    "D8:F1:5B": "Espressif (ESPHome/Tasmota)",
    "EC:FA:BC": "Espressif (ESPHome/Tasmota)",
    "00:21:2F": "Sonos",
    "5C:AA:FD": "Sonos",
    "94:9F:3E": "Sonos",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "00:17:88": "Philips Hue",
    "EC:B5:FA": "Philips Hue",
}

def get_vendor_from_mac(mac):
    """Returns a manufacturer name based on the MAC OUI."""
    if not mac or len(mac) < 8: return None
    prefix = mac[:8].upper()
    return OUI_MAP.get(prefix)

def grab_banner(ip, port, timeout=3):
    """
    Connects to an IP and port to grab the banner.
    Supports SSL for port 443.
    """
    try:
        if port == 443:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    # For HTTPS, try HEAD first, then GET/ if generic
                    ssock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    banner = ssock.recv(2048).decode('utf-8', errors='ignore').strip()
                    if not banner or "HTTP/1.1" in banner and "Server:" not in banner:
                        ssock.sendall(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
                        banner = ssock.recv(4096).decode('utf-8', errors='ignore').strip()
                    return banner
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            
            if port in [80, 8080, 8123]:
                # Try HEAD first
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                banner = s.recv(2048).decode('utf-8', errors='ignore').strip()
                
                # If banner is generic or empty, try a full GET /
                if not banner or ("HTTP/1.1" in banner and "Server:" not in banner):
                    # Reconnect for GET
                    s.close()
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    s.connect((ip, port))
                    s.sendall(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
                    banner = s.recv(4096).decode('utf-8', errors='ignore').strip()
                return banner
            
            banner = s.recv(2048).decode('utf-8', errors='ignore').strip()
            return banner
    except Exception:
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
            os_info_l = os_info.lower()
            if any(x in os_info_l for x in ['ubuntu', 'debian', 'linux', 'centos', 'fedora']): os_found = "Linux"
            if any(x in os_info_l for x in ['win32', 'win64', 'windows']): os_found = "Windows"
            if 'macos' in os_info_l or 'darwin' in os_info_l: os_found = "macOS"
            if 'freebsd' in os_info_l: os_found = "FreeBSD"
            if 'openbsd' in os_info_l: os_found = "OpenBSD"

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
    Includes aggressive hunting in HTML body if present.
    """
    if not banner: return {}
    intel = {}
    banner_l = banner.lower()

    # Specialized Manufacturer Hunters
    if "asus" in banner_l:
        model_match = re.search(r'(RT-[A-Z0-9-]+|GT-[A-Z0-9-]+)', banner, re.IGNORECASE)
        if model_match: intel['model'] = model_match.group(1).upper()
    
    if "synology" in banner_l:
        intel['vendor'] = "Synology"
        model_match = re.search(r'(DS\d+[a-z+]*)', banner, re.IGNORECASE)
        if model_match: intel['model'] = model_match.group(1).upper()

    if "tp-link" in banner_l:
        intel['vendor'] = "TP-Link"
        model_match = re.search(r'(Archer\s?[A-Z\d]+|RE\d+|TL-[A-Z\d-]+)', banner, re.IGNORECASE)
        if model_match: intel['model'] = model_match.group(1)

    if "ubiquiti" in banner_l or "unifi" in banner_l:
        intel['vendor'] = "Ubiquiti"
        if "uap" in banner_l or "unifi ap" in banner_l: intel['model'] = "UniFi AP"

    # IoT Platform Detection
    if "mongoose" in banner_l:
        intel['vendor'] = "Mongoose"
        if "mongoose/6." in banner_l: intel['fw_version'] = "6.x"
        
    if "esphome" in banner_l: intel['os'] = "ESPHome"
    if "tasmota" in banner_l: intel['os'] = "Tasmota"
    if "shelly" in banner_l: 
        intel['vendor'] = "Shelly"
        intel['os'] = "ShellyOS"
        
    # HTML Body / Title Hunting
    title_match = re.search(r'<title>([^<]+)</title>', banner, re.IGNORECASE)
    if title_match:
        title = title_match.group(1).strip()
        if not intel.get('model') and any(v in title.lower() for v in ['router', 'modem', 'gateway', 'storage']):
            intel['model'] = title # Fallback to page title if it looks like a model/type
        
        # OS Detection via Title
        if "home assistant" in title.lower(): intel['os'] = "Home Assistant OS"
        if "adguard" in title.lower(): intel['os'] = "AdGuard Home"

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
