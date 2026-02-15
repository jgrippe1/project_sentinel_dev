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
    Parses a banner to extract product and version.
    Uses regex to handle common service patterns.
    """
    if not banner:
        return None, None

    # HTTP Server Header: "Server: Apache/2.4.41 (Ubuntu)"
    http_match = re.search(r'Server:\s*([^/\s\r\n]+)(?:/([^\s\r\n(]+))?', banner, re.IGNORECASE)
    if http_match:
        return http_match.group(1), http_match.group(2)

    # SSH Banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    ssh_match = re.search(r'(?:SSH-\d\.\d-)([^_\s-]+)_([^\s-]+)', banner)
    if ssh_match:
        return ssh_match.group(1), ssh_match.group(2)

    # FTP/Generic: "220 (vsFTPd 3.0.3)" or "220-FileZilla Server 0.9.60 beta"
    ftp_match = re.search(r'(?:220[\s-].*?)([^/\s\r\n()]+)\s+([0-9.]+[^\s\r\n]*)', banner)
    if ftp_match:
        return ftp_match.group(1), ftp_match.group(2)

    # Generic Product/Version: "Product v1.2.3" or "Product 1.2.3"
    generic_match = re.search(r'^([a-zA-Z._-]+)[/\s]v?([0-9]+\.[0-9.]+[a-zA-Z0-9-]*)', banner)
    if generic_match:
        return generic_match.group(1), generic_match.group(2)
            
    return None, None

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
