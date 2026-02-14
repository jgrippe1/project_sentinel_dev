
import socket

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
            if port in [80, 8080]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            
            try:
                banner = s.recv(1024)
                return banner.decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                return None
    except Exception as e:
        # print(f"Error grabbing banner for {ip}:{port} - {e}")
        return None

def analyze_banner(banner):
    """
    Parses a banner to extract product and version.
    Very basic implementation for PoC.
    """
    if not banner:
        return None, None
        
    # Example simplistic parsing
    # "Server: Apache/2.4.41 (Ubuntu)"
    lines = banner.split('\r\n')
    for line in lines:
        if "Server:" in line:
            parts = line.split("Server:")[1].strip().split(" ")
            if parts:
                product_part = parts[0]
                if "/" in product_part:
                    product, version = product_part.split("/", 1)
                    return product, version
                return product_part, None
    
    # Check for SSH
    # "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    if "SSH-" in banner:
        parts = banner.split("-")
        if len(parts) > 2:
            return "OpenSSH", parts[2].split(" ")[0] # Very rough
            
    return None, None
