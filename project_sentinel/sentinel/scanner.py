import socket
import ipaddress
import concurrent.futures
import time
import logging

logger = logging.getLogger(__name__)

try:
    import paramiko
except ImportError:
    paramiko = None

class RouterDiscovery:
    def __init__(self, host, username, password=None, ssh_key=None, port=22):
        self.host = host
        self.username = username
        self.password = password
        self.ssh_key = ssh_key
        self.port = port

    def get_asus_clients(self):
        """
        Fetches clients from ASUS router via SSH.
        Returns a list of dicts with ip and mac.
        """
        if not paramiko:
            logger.error("Paramiko is not installed. SSH discovery unavailable.")
            return []

        if not self.username:
            return []

        clients = []
        wireless_macs = set()

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            if self.ssh_key:
                logger.debug(f"Connecting to router {self.host} with SSH key")
                ssh.connect(self.host, port=self.port, username=self.username, key_filename=self.ssh_key, timeout=10)
            else:
                logger.debug(f"Connecting to router {self.host} with password")
                ssh.connect(self.host, port=self.port, username=self.username, password=self.password, timeout=10)

            # 1. Get Wireless Clients
            interfaces = ["wl0", "wl1", "wl2", "eth1", "eth2", "eth3", "eth4", "eth5", "eth6"]
            for iface in interfaces:
                try:
                    stdin, stdout, stderr = ssh.exec_command(f"wl -i {iface} assoclist")
                    output = stdout.read().decode().strip()
                    if output and "usage" not in output.lower():
                        for line in output.splitlines():
                            mac = line.strip().upper()
                            if ":" in mac and len(mac) == 17:
                                wireless_macs.add(mac)
                except Exception:
                    continue

            # 2. Get ARP Table
            stdin, stdout, stderr = ssh.exec_command("cat /proc/net/arp")
            arp_output = stdout.read().decode().splitlines()
            for line in arp_output[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    mac = parts[3].upper()
                    if mac != "00:00:00:00:00:00":
                        clients.append({
                            "ip": ip,
                            "mac": mac,
                            "interface": "Wireless" if mac in wireless_macs else "Wired"
                        })
            
            ssh.close()
            logger.info(f"Successfully fetched {len(clients)} clients from router.")
        except Exception as e:
            logger.error(f"Failed to fetch clients from router: {e}")
        
        return clients

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
    
    logger.info(f"Scanning {cidr} for ports {ports}...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_ip = {executor.submit(scan_host, ip, ports): ip for ip in network.hosts()}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                open_ports = future.result()
                if open_ports:
                    active_hosts[str(ip)] = open_ports
                    logger.debug(f"Found {ip} with open ports: {open_ports}")
            except Exception as e:
                logger.error(f"Error scanning {ip}: {e}")
                
    return active_hosts
