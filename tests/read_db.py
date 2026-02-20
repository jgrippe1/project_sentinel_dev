import sqlite3
import json

db_path = "f:/Gravity/Project Sentinel/sentinel.db"
try:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT custom_name, hostname, mac_address, parent_mac, connected_to_mac, connected_port, connection_type FROM assets")
    rows = c.fetchall()
    
    print(f"Total assets in local DB: {len(rows)}")
    for r in rows:
        print(dict(r))
        
    conn.close()
except Exception as e:
    print(f"Error reading DB: {e}")
