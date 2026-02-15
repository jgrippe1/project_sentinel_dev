import socket
import ipaddress
import concurrent.futures
import logging
import os

logger = logging.getLogger(__name__)

try:
    import paramiko
except ImportError:
    paramiko = None

class RouterDiscovery:
    def __init__(self, host, username, password=None, ssh_key=None, port=22):
        self.host = host.strip() if host else host
        self.username = username.strip() if username else username
        self.password = password.strip() if password else password
        self.ssh_key = ssh_key.strip() if ssh_key else ssh_key
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

        # Pre-check connectivity
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                if s.connect_ex((self.host, self.port)) != 0:
                    logger.error(f"Network Error: Port {self.port} on {self.host} is unreachable or closed.")
                    return []
                else:
                    logger.debug(f"Port {self.port} on {self.host} is open. Proceeding with SSH...")
        except Exception as e:
            logger.error(f"Connectivity check failed: {e}")
            return []

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            if self.ssh_key:
                if not os.path.exists(self.ssh_key):
                    logger.error(f"SSH Key file not found at: {self.ssh_key}")
                    # If password exists, try falling back
                    if not self.password:
                        return []
                else:
                    logger.debug(f"Connecting to router {self.host} with SSH key: {self.ssh_key}")
                    ssh.connect(self.host, port=self.port, username=self.username, key_filename=self.ssh_key, timeout=10)
            
            if not self.ssh_key or (self.password and not ssh.get_transport()):
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

            # 2. Get DHCP / Client List (Often has names/types on ASUS)
            # Try /tmp/client_list first (Merlin/Stock ASUS)
            stdin, stdout, stderr = ssh.exec_command("cat /tmp/client_list")
            client_output = stdout.read().decode().strip()
            
            # Format is often: Interface>MAC>IP>Name>Type>...
            router_metadata = {}
            if client_output and "No such file" not in client_output:
                for line in client_output.splitlines():
                    parts = line.split('>')
                    if len(parts) >= 5:
                        mac = parts[1].upper()
                        name = parts[3]
                        dev_type = parts[4] # This is often an icon ID or type name
                        router_metadata[mac] = {"name": name, "type": dev_type}

            # 3. Get ARP Table
            stdin, stdout, stderr = ssh.exec_command("cat /proc/net/arp")
            arp_output = stdout.read().decode().splitlines()
            for line in arp_output[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    mac = parts[3].upper()
                    if mac != "00:00:00:00:00:00":
                        meta = router_metadata.get(mac, {})
                        clients.append({
                            "ip": ip,
                            "mac": mac,
                            "interface": "Wireless" if mac in wireless_macs else "Wired",
                            "hostname": meta.get("name"),
                            "type": meta.get("type")
                        })
            
            ssh.close()
            logger.info(f"Successfully fetched {len(clients)} clients from router with metadata.")
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

def resolve_mac(ip):
    """
    Attempts to resolve the MAC address for an IP address using local system tables.
    1. Parses /proc/net/arp (Linux standard)
    2. Fallback: Executes 'ip neighbor show'
    """
    ip_str = str(ip)
    
    # 1. Try /proc/net/arp
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:] # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip_str:
                        mac = parts[3].upper()
                        if mac != "00:00:00:00:00:00":
                            return mac
        except Exception as e:
            logger.debug(f"Failed to read /proc/net/arp: {e}")

    # 2. Try 'ip neighbor show' command (Requires iproute2)
    try:
        import subprocess
        output = subprocess.check_output(["ip", "neighbor", "show", ip_str], timeout=2).decode()
        # Format: 192.168.1.100 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
        if "lladdr" in output:
            parts = output.split()
            for i, p in enumerate(parts):
                if p == "lladdr" and i + 1 < len(parts):
                    mac = parts[i+1].upper()
                    if ":" in mac and len(mac) == 17:
                        return mac
    except Exception as e:
        logger.debug(f"Failed to run ip neighbor: {e}")

    return None

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
