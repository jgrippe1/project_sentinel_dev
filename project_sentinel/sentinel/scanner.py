
import socket
import ipaddress
import concurrent.futures
import time

def check_port(ip, port, timeout=1):
    """
    Checks if a specific port is open on an IP address.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((str(ip), port))
            if result == 0:
                return True
    except Exception:
        pass
    return False

def scan_host(ip, ports=[80, 443, 22, 8080, 53, 445, 5000, 8123, 8000]):
    """
    Scans a single host for specified ports.
    """
    open_ports = []
    for port in ports:
        if check_port(ip, port):
            open_ports.append(port)
    return open_ports

def scan_subnet(cidr, ports=[80, 443, 22, 8080], max_threads=100):
    """
    Scans a subnet for active hosts with open ports.
    """
    active_hosts = {}
    network = ipaddress.ip_network(cidr)
    
    print(f"Scanning {cidr} for ports {ports}...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_ip = {executor.submit(scan_host, ip, ports): ip for ip in network.hosts()}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                open_ports = future.result()
                if open_ports:
                    active_hosts[str(ip)] = open_ports
                    print(f"Found {ip} with open ports: {open_ports}")
            except Exception as e:
                print(f"Error scanning {ip}: {e}")
                
    return active_hosts

if __name__ == "__main__":
    # Test
    results = scan_subnet("192.168.1.0/24", ports=[80])
    print(results)
