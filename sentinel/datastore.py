import sqlite3
import datetime
import os

DB_PATH = "/data/sentinel.db"
# Fallback for local testing if not running in Add-on environment
if not os.path.exists("/data"):
    DB_PATH = "sentinel.db"

class Datastore:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Assets Table
        c.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT,
                hostname TEXT,
                vendor TEXT,
                first_seen DATETIME,
                last_seen DATETIME,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # Services Table
        c.execute('''
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT,
                port INTEGER,
                proto TEXT,
                service_name TEXT,
                banner TEXT,
                version_string TEXT,
                last_seen DATETIME,
                FOREIGN KEY(mac_address) REFERENCES assets(mac_address),
                UNIQUE(mac_address, port, proto)
            )
        ''')
        
        # Vulnerabilities Table
        c.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT,
                mac_address TEXT,
                cvss_score REAL,
                description TEXT,
                last_synced DATETIME,
                FOREIGN KEY(mac_address) REFERENCES assets(mac_address),
                PRIMARY KEY (cve_id, mac_address)
            )
        ''')
        
        conn.commit()
        conn.close()

    def upsert_asset(self, mac, ip, hostname=None, vendor=None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = datetime.datetime.now()
        
        # Check if exists
        c.execute("SELECT first_seen FROM assets WHERE mac_address=?", (mac,))
        row = c.fetchone()
        
        if row:
            c.execute('''
                UPDATE assets 
                SET ip_address=?, last_seen=?, status='active'
                WHERE mac_address=?
            ''', (ip, now, mac))
            if hostname:
                 c.execute("UPDATE assets SET hostname=? WHERE mac_address=?", (hostname, mac))
            if vendor:
                 c.execute("UPDATE assets SET vendor=? WHERE mac_address=?", (vendor, mac))
        else:
            c.execute('''
                INSERT INTO assets (mac_address, ip_address, hostname, vendor, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (mac, ip, hostname, vendor, now, now))
            
        conn.commit()
        conn.close()

    def upsert_service(self, mac, port, proto, service_name, banner, version):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = datetime.datetime.now()
        
        c.execute('''
            INSERT INTO services (mac_address, port, proto, service_name, banner, version_string, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac_address, port, proto) DO UPDATE SET
            banner=excluded.banner,
            version_string=excluded.version_string,
            last_seen=excluded.last_seen
        ''', (mac, port, proto, service_name, banner, version, now))
        
        conn.commit()
        conn.close()

    def get_assets(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM assets")
        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return rows
