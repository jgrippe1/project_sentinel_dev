import logging
import time
import uuid

logger = logging.getLogger(__name__)

try:
    from pysnmp.hlapi import *
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False
    logger.warning("pysnmp is not installed. Layer 2 topology mapping will be limited.")

class SNMPClient:
    def __init__(self, community="public", timeout=2, retries=1):
        self.community = community
        self.timeout = timeout
        self.retries = retries

    def walk(self, ip, base_oid):
        if not PYSNMP_AVAILABLE:
            return []
            
        results = []
        try:
            iterator = nextCmd(
                SnmpEngine(),
                CommunityData(self.community, mpModel=1), # v2c
                UdpTransportTarget((ip, 161), timeout=self.timeout, retries=self.retries),
                ContextData(),
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False
            )

            for errorIndication, errorStatus, errorIndex, varBinds in iterator:
                if errorIndication or errorStatus:
                    break
                for varBind in varBinds:
                    oid_str = str(varBind[0])
                    val = varBind[1]
                    results.append((oid_str, val))
        except Exception as e:
            logger.debug(f"SNMP Walk error on {ip} for {base_oid}: {e}")
        return results

    def get_fdb_table(self, ip):
        """
        Polls dot1dTpFdbPort (1.3.6.1.2.1.17.4.3.1.2) to get MAC to BridgePort
        Returns dict: { "mac_address": bridge_port }
        """
        results = {}
        # dot1dTpFdbPort
        base_oid = "1.3.6.1.2.1.17.4.3.1.2"
        data = self.walk(ip, base_oid)
        for oid, val in data:
            try:
                # OID is 1.3.6.1.2.1.17.4.3.1.2.DEC.DEC.DEC.DEC.DEC.DEC
                mac_decimals = oid.replace(base_oid + ".", "").split('.')
                if len(mac_decimals) == 6:
                    mac = ":".join([f"{int(x):02x}" for x in mac_decimals]).upper()
                    results[mac] = int(val)
            except Exception:
                continue
        return results

    def get_arp_table(self, ip):
        """
        Polls ipNetToMediaPhysAddress (1.3.6.1.2.1.4.22.1.2) to get IP to MAC
        Returns dict: { "ip_address": "mac_address" }
        """
        results = {}
        base_oid = "1.3.6.1.2.1.4.22.1.2"
        data = self.walk(ip, base_oid)
        for oid, val in data:
            try:
                # OID is 1.3.6.1.2.1.4.22.1.2.ifIndex.IP.IP.IP.IP
                parts = oid.replace(base_oid + ".", "").split('.')
                if len(parts) >= 4:
                    ip_addr = ".".join(parts[-4:])
                    # MAC is usually hex string in val
                    mac_hex = val.asOctets().hex()
                    if len(mac_hex) == 12:
                        mac = ":".join([mac_hex[i:i+2] for i in range(0, 12, 2)]).upper()
                        results[ip_addr] = mac
            except Exception:
                continue
        return results

    def get_lldp_neighbors(self, ip):
        """
        Polls lldpRemSysName (1.0.8802.1.1.2.1.4.1.1.9)
        Returns dict: { local_port: "neighbor_name" }
        """
        results = {}
        base_oid = "1.0.8802.1.1.2.1.4.1.1.9"
        data = self.walk(ip, base_oid)
        for oid, val in data:
            try:
                # OID is 1.0.8802.1.1.2.1.4.1.1.9.timeMark.localPortNum.index
                parts = oid.replace(base_oid + ".", "").split('.')
                if len(parts) >= 3:
                    local_port = parts[-2]
                    results[local_port] = str(val)
            except Exception:
                continue
        return results


class TopologyMapper:
    def __init__(self, db, config):
        self.db = db
        community = config.get("options", {}).get("snmp_community", "public")
        self.snmp = SNMPClient(community=community)

    def scan_network_topology(self):
        """
        Main topology scan routine:
        1. Find all potential switches (devices with SNMP open, or known switches).
        2. Query FDB to find which MACs are on which ports.
        3. Infer unmanaged switches based on dense endpoint clusters.
        """
        logger.info("Starting Layer 2 Topology Scan...")
        
        assets = self.db.get_assets_with_services()
        switches = []
        for a in assets:
            mac = a.get("mac_address")
            ip = a.get("ip_address")
            # Determine if managed switch by checking for SNMP service
            # In a production environment, we could specifically check for port 161.
            has_snmp = any(s.get("port") == 161 for s in a.get("services", []))
            # Also fallback to trying if device type is 'Switch' or tags say so
            if has_snmp or a.get("device_type") == "Switch":
                if ip:
                    switches.append((ip, mac))

        if not switches:
            logger.debug("No managed switches identified for topology mapping.")
            return

        for ip, switch_mac in switches:
            logger.info(f"Querying FDB on Switch: {ip} ({switch_mac})")
            
            # Fetch FDB Map: MAC -> Port Layer 2 ID
            fdb_map = self.snmp.get_fdb_table(ip)
            if not fdb_map:
                logger.debug(f"No FDB entries found on {ip}")
                continue

            # Invert to Port -> List[MAC]
            port_to_macs = {}
            for target_mac, port_id in fdb_map.items():
                if port_id not in port_to_macs:
                    port_to_macs[port_id] = []
                port_to_macs[port_id].append(target_mac)

            # Fetch LLDP Neighbors to verify if port is an infrastructure link
            lldp_neighbors = self.snmp.get_lldp_neighbors(ip)

            # Analyze Ports and Infer Unmanaged Switches
            for port_id, mac_list in port_to_macs.items():
                # Filter out MACs that belong to the switch itself or broadcast
                valid_macs = [m for m in mac_list if ":" in m and m != switch_mac]
                
                if len(valid_macs) == 0:
                    continue

                if len(valid_macs) == 1:
                    # Direct connection
                    target_mac = valid_macs[0]
                    self._update_asset_connection(target_mac, switch_mac, port_id, "wired")
                else:
                    str_port = str(port_id)
                    if str_port in lldp_neighbors:
                        # This port connects to an LLDP neighbor (AP or managed switch)
                        # All MACs here are just downstream. Map them to the switch port.
                        # Wait for the infrastructure device to map its own ports if it's a switch.
                        neighbor_name = lldp_neighbors[str_port]
                        logger.debug(f"Port {port_id} has LLDP neighbor {neighbor_name}, treating as infrastructure link.")
                        for target_mac in valid_macs:
                            self._update_asset_connection(target_mac, switch_mac, port_id, "infrastructure")
                    else:
                        # Multiple MACs on one port without LLDP
                        # Infer an unmanaged switch.
                        unmanaged_switch_mac = self._get_or_create_unmanaged_switch(switch_mac, port_id)
                        
                        # Tie the dumb switch to the managed switch
                        self._update_asset_connection(unmanaged_switch_mac, switch_mac, port_id, "wired")
    
                        # Tie the endpoints to the dumb switch
                        for target_mac in valid_macs:
                            if target_mac == unmanaged_switch_mac:
                                continue
                            self._update_asset_connection(target_mac, unmanaged_switch_mac, "auto", "inferred_switch")

        logger.info("Topology mapping scan complete.")

    def _get_or_create_unmanaged_switch(self, parent_mac, parent_port):
        """
        Creates or retrieves a deterministic pseudo-MAC for an unmanaged switch
        based on the parent managed switch and port.
        """
        pseudo_mac = f"unmanaged_{parent_mac.replace(':', '')}_{parent_port}"
        
        # Check if exists
        asset = self.db.get_asset(pseudo_mac)
        if not asset:
            logger.info(f"Inferred new Unmanaged Switch on {parent_mac} port {parent_port}")
            self.db.upsert_asset(
                mac=pseudo_mac,
                ip=None,
                hostname=f"Unmanaged Switch (Port {parent_port})",
                vendor="Generic inferred",
                original_device_type="Switch"
            )
        return pseudo_mac

    def _update_asset_connection(self, mac, connected_to_mac, connected_port, connection_type):
        """
        Update the topology fields of a specific asset.
        """
        asset = self.db.get_asset(mac)
        if asset:
            self.db.upsert_asset(
                mac=mac,
                ip=asset.get("ip_address"),
                # Preserve existing fields
                hostname=asset.get("hostname"),
                vendor=asset.get("vendor"),
                interface=asset.get("interface"),
                parent_mac=asset.get("parent_mac"),
                original_device_type=asset.get("original_device_type"),
                hw_version=asset.get("hw_version"),
                fw_version=asset.get("fw_version"),
                model=asset.get("model"),
                os=asset.get("os"),
                oui_vendor=asset.get("oui_vendor"),
                # Update topology fields
                connected_to_mac=connected_to_mac,
                connected_port=str(connected_port),
                connection_type=connection_type
            )
        else:
            # We see a MAC in FDB that we haven't discovered yet via active scanning
            logger.debug(f"Topology Mapper discovered new MAC {mac} not yet in assets db. Registering it.")
            self.db.upsert_asset(
                mac=mac,
                ip=None,
                connected_to_mac=connected_to_mac,
                connected_port=str(connected_port),
                connection_type=connection_type
            )

