import os
import sqlite3
import logging
from sentinel.datastore import Datastore
from sentinel.topology import TopologyMapper

logging.basicConfig(level=logging.INFO)

print("--- Testing DB Migration ---")
# Use a test DB to avoid corrupting real DB
if os.path.exists("test_topo.db"):
    os.remove("test_topo.db")

# Force DB init and migration path
db = Datastore(db_path="test_topo.db")

# Add some dummy assets
db.upsert_asset("00:11:22:33:44:55", "192.168.1.10", "ManagedSwitch", original_device_type="Switch")
db.upsert_asset("AA:BB:CC:DD:EE:FF", "192.168.1.50", "Desktop PC")
db.upsert_asset("11:22:33:44:55:66", "192.168.1.51", "IoT Bulb 1")
db.upsert_asset("11:22:33:44:55:77", "192.168.1.52", "IoT Bulb 2")
# Add SNMP service to the switch
db.upsert_service("00:11:22:33:44:55", 161, "udp", "snmp", "test", "v2c")

print("--- Testing TopologyMapper Integration (Mocked) ---")
config = {"options": {"snmp_community": "public", "topology_polling_interval": 60}}
topo = TopologyMapper(db, config)

# Mock the snmp client to return test FDB and LLDP data
class MockSNMP:
    def get_fdb_table(self, ip):
        return {
             "AA:BB:CC:DD:EE:FF": 1,  # Port 1 (Direct)
             "11:22:33:44:55:66": 2,  # Port 2 (Dumb switch)
             "11:22:33:44:55:77": 2   # Port 2 (Dumb switch)
        }
    def get_lldp_neighbors(self, ip):
        return {} # No managed neighbors

topo.snmp = MockSNMP()

print("Running Topology Scan...")
topo.scan_network_topology()

print("--- Verifying Results ---")
assets = db.get_assets()
for a in assets:
    mac = a["mac_address"]
    name = a["hostname"] or a["mac_address"]
    conn_mac = a["connected_to_mac"]
    conn_port = a["connected_port"]
    conn_type = a["connection_type"]
    if conn_mac:
        print(f"[{name}] is connected to [{conn_mac}] on port [{conn_port}] via [{conn_type}]")
    else:
        print(f"[{name}] has no upstream connection")

print("Verification complete.")
