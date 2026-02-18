import sqlite3
import datetime
import os

DB_PATH = os.getenv("SENTINEL_DB_PATH", "/data/sentinel.db")
# Fallback for local testing if not running in Add-on environment
if not os.path.exists("/data") and "SENTINEL_DB_PATH" not in os.environ:
    DB_PATH = "sentinel.db"

class Datastore:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()
        self._migrate_db()

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
                interface TEXT,
                approved INTEGER DEFAULT 0,
                tags TEXT DEFAULT '[]',
                custom_name TEXT,
                location TEXT,
                device_type TEXT,
                original_device_type TEXT,
                parent_mac TEXT,
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
                cert_expiry DATETIME,
                last_seen DATETIME,
                FOREIGN KEY(mac_address) REFERENCES assets(mac_address),
                UNIQUE(mac_address, port, proto)
            )
        ''')
        
        # Hybrid Verification Cache
        c.execute('''
            CREATE TABLE IF NOT EXISTS cve_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                version_string TEXT,
                vendor TEXT,
                model TEXT,
                analysis_result TEXT,
                confidence INTEGER,
                method TEXT,
                reasoning TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(cve_id, version_string, vendor, model)
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

    def _migrate_db(self):
        """
        Handles schema migrations for existing databases.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Check for 'interface' column in 'assets' table
        c.execute("PRAGMA table_info(assets)")
        columns = [info[1] for info in c.fetchall()]
        
        if 'interface' not in columns:
            print("Migrating database: Adding 'interface' column to 'assets' table.")
            try:
                c.execute("ALTER TABLE assets ADD COLUMN interface TEXT")
            except Exception as e:
                print(f"Migration error (interface): {e}")

        new_columns = {
            'approved': 'INTEGER DEFAULT 0',
            'tags': "TEXT DEFAULT '[]'",
            'owner': 'TEXT',
            'location': 'TEXT',
            'device_type': 'TEXT',
            'parent_mac': 'TEXT'
        }

        new_columns = {
            'approved': 'INTEGER DEFAULT 0',
            'tags': "TEXT DEFAULT '[]'",
            'custom_name': 'TEXT',
            'location': 'TEXT',
            'device_type': 'TEXT',
            'original_device_type': 'TEXT',
            'parent_mac': 'TEXT',
            'confirmed_integrations': "TEXT DEFAULT '[]'",
            'dismissed_integrations': "TEXT DEFAULT '[]'"
        }

        for col, col_type in new_columns.items():
            if col not in columns:
                print(f"Migrating database: Adding '{col}' column to 'assets' table.")
                try:
                    c.execute(f"ALTER TABLE assets ADD COLUMN {col} {col_type}")
                    if col == 'approved':
                        c.execute("UPDATE assets SET approved = 1")
                except Exception as e:
                    print(f"Migration error ({col}): {e}")

        # Check for 'original_device_type' in 'assets' table
        if 'original_device_type' not in columns:
            print("Migrating database: Adding 'original_device_type' column to 'assets' table.")
            try:
                c.execute("ALTER TABLE assets ADD COLUMN original_device_type TEXT")
            except Exception as e:
                print(f"Migration error (original_device_type): {e}")

        # Phase 30: Advanced Asset Intelligence
        new_cols = {
            'hw_version': 'TEXT',
            'fw_version': 'TEXT',
            'model': 'TEXT',
            'os': 'TEXT',
            'oui_vendor': 'TEXT'
        }
        for col, col_type in new_cols.items():
            if col not in columns:
                print(f"Migrating database: Adding '{col}' column to 'assets' table.")
                try:
                    c.execute(f"ALTER TABLE assets ADD COLUMN {col} {col_type}")
                except Exception as e:
                    print(f"Migration error ({col}): {e}")

        # Check for 'custom_name' in 'assets' table
        if 'custom_name' not in columns:
            print("Migrating database: Adding 'custom_name' column to 'assets' table.")
            try:
                c.execute("ALTER TABLE assets ADD COLUMN custom_name TEXT")
                # If 'owner' exists, we can migrate it
                if 'owner' in columns:
                    c.execute("UPDATE assets SET custom_name = owner")
            except Exception as e:
                print(f"Migration error (custom_name): {e}")

        # Check for 'cert_expiry' in 'services' table
        c.execute("PRAGMA table_info(services)")
        service_columns = [info[1] for info in c.fetchall()]
        if 'cert_expiry' not in service_columns:
            print("Migrating database: Adding 'cert_expiry' column to 'services' table.")
            try:
                c.execute("ALTER TABLE services ADD COLUMN cert_expiry DATETIME")
            except Exception as e:
                print(f"Migration error (cert_expiry): {e}")

        # Phase 40: Firmware Verification & Suppression
        # Assets Update
        c.execute("PRAGMA table_info(assets)")
        asset_columns = [info[1] for info in c.fetchall()]
        if 'actual_fw_version' not in asset_columns:
            print("Migrating database: Adding actual_fw_version to assets.")
            c.execute("ALTER TABLE assets ADD COLUMN actual_fw_version TEXT")
            c.execute("ALTER TABLE assets ADD COLUMN fw_verified_at DATETIME")
            
        # Vulnerabilities Update
        c.execute("PRAGMA table_info(vulnerabilities)")
        vuln_columns = [info[1] for info in c.fetchall()]
        if 'status' not in vuln_columns:
            print("Migrating database: Adding 'status' column to 'vulnerabilities' table.")
            c.execute("ALTER TABLE vulnerabilities ADD COLUMN status TEXT DEFAULT 'active'")
        if 'suppression_reason' not in vuln_columns:
            print("Migrating database: Adding suppression fields to vulnerabilities.")
            c.execute("ALTER TABLE vulnerabilities ADD COLUMN suppression_reason TEXT")
            c.execute("ALTER TABLE vulnerabilities ADD COLUMN suppression_logic TEXT")
            c.execute("ALTER TABLE vulnerabilities ADD COLUMN user_version TEXT")

        # Hybrid Verification Cache Update
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_verifications'")
        if not c.fetchone():
            print("Migrating database: Creating 'cve_verifications' table.")
            c.execute('''
                CREATE TABLE IF NOT EXISTS cve_verifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT,
                    version_string TEXT,
                    vendor TEXT,
                    model TEXT,
                    analysis_result TEXT,
                    confidence INTEGER,
                    method TEXT,
                    reasoning TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(cve_id, version_string, vendor, model)
                )
            ''')
            print("Migrating database: Adding suppression fields to vulnerabilities.")
            c.execute("ALTER TABLE vulnerabilities ADD COLUMN status TEXT DEFAULT 'active'")
            c.execute("ALTER TABLE vulnerabilities ADD COLUMN suppression_reason TEXT")
            c.execute("ALTER TABLE vulnerabilities ADD COLUMN suppression_logic TEXT")
            c.execute("ALTER TABLE vulnerabilities ADD COLUMN user_version TEXT")
        
        conn.commit()
        conn.close()

    def upsert_asset(self, mac, ip, hostname=None, vendor=None, interface=None, parent_mac=None, original_device_type=None, hw_version=None, fw_version=None, model=None, os=None, oui_vendor=None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = datetime.datetime.now()
        
        # --- Deduplication Logic ---
        # If this is a real MAC, check if a placeholder exists for this IP
        if mac and not mac.startswith('mac_'):
            placeholder_mac = f"mac_{ip.replace('.', '_')}"
            c.execute("SELECT mac_address FROM assets WHERE mac_address=?", (placeholder_mac,))
            if c.fetchone():
                print(f"Datastore: Triggering merge of placeholder {placeholder_mac} into real MAC {mac}")
                conn.close() # Close to allow merge_assets to open its own connection or refactor to share
                self.merge_assets(mac, placeholder_mac)
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
        # ---------------------------

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
            if interface:
                 c.execute("UPDATE assets SET interface=? WHERE mac_address=?", (interface, mac))
            if parent_mac:
                 c.execute("UPDATE assets SET parent_mac=? WHERE mac_address=?", (parent_mac, mac))
            if original_device_type:
                 c.execute("UPDATE assets SET original_device_type=? WHERE mac_address=?", (original_device_type, mac))
            if hw_version:
                 c.execute("UPDATE assets SET hw_version=? WHERE mac_address=?", (hw_version, mac))
            if fw_version:
                 c.execute("UPDATE assets SET fw_version=? WHERE mac_address=?", (fw_version, mac))
            if model:
                 c.execute("UPDATE assets SET model=? WHERE mac_address=?", (model, mac))
            if os:
                 c.execute("UPDATE assets SET os=? WHERE mac_address=?", (os, mac))
            if oui_vendor:
                 c.execute("UPDATE assets SET oui_vendor=? WHERE mac_address=?", (oui_vendor, mac))
        else:
            c.execute('''
                INSERT INTO assets (mac_address, ip_address, hostname, vendor, interface, parent_mac, original_device_type, hw_version, fw_version, model, os, oui_vendor, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (mac, ip, hostname, vendor, interface, parent_mac, original_device_type, hw_version, fw_version, model, os, oui_vendor, now, now))
            
        conn.commit()
        conn.close()

    def merge_assets(self, target_mac, source_mac):
        """
        Merges source_mac (usually a placeholder) into target_mac (real MAC).
        Migrates services and vulnerabilities.
        """
        if target_mac == source_mac:
            return

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        print(f"Merging {source_mac} into {target_mac}...")

        # 1. Migrate Services
        # Handle UNIQUE(mac_address, port, proto) constraint
        c.execute("SELECT port, proto FROM services WHERE mac_address=?", (target_mac,))
        existing_services = set((row['port'], row['proto']) for row in c.fetchall())
        
        c.execute("SELECT id, port, proto FROM services WHERE mac_address=?", (source_mac,))
        source_services = c.fetchall()
        
        for row in source_services:
            service_id, port, proto = row['id'], row['port'], row['proto']
            if (port, proto) in existing_services:
                # Conflict: Target already has this service. Delete the source one.
                c.execute("DELETE FROM services WHERE id=?", (service_id,))
            else:
                # No conflict: Update mac_address
                c.execute("UPDATE services SET mac_address=? WHERE id=?", (target_mac, service_id))

        # 2. Migrate Vulnerabilities
        # Handle PRIMARY KEY (cve_id, mac_address)
        c.execute("SELECT cve_id FROM vulnerabilities WHERE mac_address=?", (target_mac,))
        existing_vulns = set(row['cve_id'] for row in c.fetchall())
        
        c.execute("SELECT cve_id FROM vulnerabilities WHERE mac_address=?", (source_mac,))
        source_vulns = c.fetchall()
        
        for row in source_vulns:
            cve_id = row['cve_id']
            if cve_id in existing_vulns:
                # Conflict: Target already has this vulnerability. Delete the source one.
                c.execute("DELETE FROM vulnerabilities WHERE cve_id=? AND mac_address=?", (cve_id, source_mac))
            else:
                # No conflict: Update mac_address
                c.execute("UPDATE vulnerabilities SET mac_address=? WHERE cve_id=? AND mac_address=?", (target_mac, cve_id, source_mac))

        # 3. Migrate Governance/Metadata if target is empty but source has data
        c.execute("SELECT custom_name, location, device_type, tags FROM assets WHERE mac_address=?", (source_mac,))
        source_meta = c.fetchone()
        if source_meta:
            c.execute("SELECT custom_name, location, device_type, tags FROM assets WHERE mac_address=?", (target_mac,))
            target_meta = c.fetchone()
            
            updates = []
            params = []
            if source_meta['custom_name'] and (not target_meta or not target_meta['custom_name']):
                updates.append("custom_name=?")
                params.append(source_meta['custom_name'])
            if source_meta['location'] and (not target_meta or not target_meta['location']):
                updates.append("location=?")
                params.append(source_meta['location'])
            if source_meta['device_type'] and (not target_meta or not target_meta['device_type']):
                updates.append("device_type=?")
                params.append(source_meta['device_type'])
            if (source_meta['tags'] and source_meta['tags'] != '[]') and (not target_meta or target_meta['tags'] == '[]'):
                updates.append("tags=?")
                params.append(source_meta['tags'])
            
            if updates:
                params.append(target_mac)
                c.execute(f"UPDATE assets SET {', '.join(updates)} WHERE mac_address=?", tuple(params))

        # 4. Delete Source Asset
        c.execute("DELETE FROM assets WHERE mac_address=?", (source_mac,))
        
        conn.commit()
        conn.close()
        print(f"Successfully merged {source_mac} into {target_mac}")

    def approve_asset(self, mac):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE assets SET approved=1 WHERE mac_address=?", (mac,))
        conn.commit()
        conn.close()

    def delete_asset(self, mac):
        """
        Deletes an asset and its associated vulnerabilities and services.
        Used for deduplication/merging.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM assets WHERE mac_address=?", (mac,))
        c.execute("DELETE FROM services WHERE mac_address=?", (mac,))
        c.execute("DELETE FROM vulnerabilities WHERE mac_address=?", (mac,))
        conn.commit()
        conn.close()

    def update_asset_governance(self, mac, custom_name=None, location=None, device_type=None, tags=None, confirmed_integrations=None, dismissed_integrations=None, actual_fw_version=None, model=None, os=None, vendor=None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        if custom_name is not None:
            c.execute("UPDATE assets SET custom_name=? WHERE mac_address=?", (custom_name, mac))
        if location is not None:
            c.execute("UPDATE assets SET location=? WHERE mac_address=?", (location, mac))
        if device_type is not None:
            c.execute("UPDATE assets SET device_type=? WHERE mac_address=?", (device_type, mac))
        if confirmed_integrations is not None:
            c.execute("UPDATE assets SET confirmed_integrations=? WHERE mac_address=?", (confirmed_integrations, mac))
        if dismissed_integrations is not None:
            c.execute("UPDATE assets SET dismissed_integrations=? WHERE mac_address=?", (dismissed_integrations, mac))
        if actual_fw_version is not None:
            now = datetime.datetime.now()
            c.execute("UPDATE assets SET actual_fw_version=?, fw_verified_at=? WHERE mac_address=?", (actual_fw_version, now, mac))
        if model is not None:
            c.execute("UPDATE assets SET model=? WHERE mac_address=?", (model, mac))
        if os is not None:
            c.execute("UPDATE assets SET os=? WHERE mac_address=?", (os, mac))
        if vendor is not None:
            c.execute("UPDATE assets SET vendor=? WHERE mac_address=?", (vendor, mac))
        if tags is not None:
            import json
            c.execute("UPDATE assets SET tags=? WHERE mac_address=?", (json.dumps(tags), mac))
        conn.commit()
        conn.close()

    def upsert_service(self, mac, port, proto, service_name, banner, version_string, cert_expiry=None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = datetime.datetime.now()
        
        c.execute('''
            INSERT INTO services (mac_address, port, proto, service_name, banner, version_string, cert_expiry, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac_address, port, proto) DO UPDATE SET
            banner=excluded.banner,
            version_string=excluded.version_string,
            cert_expiry=excluded.cert_expiry,
            last_seen=excluded.last_seen
        ''', (mac, port, proto, service_name, banner, version_string, cert_expiry, now))
        
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

    def get_asset(self, mac):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM assets WHERE mac_address=?", (mac,))
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_asset_by_ip(self, ip):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM assets WHERE ip_address=?", (ip,))
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None

    def upsert_vulnerability(self, mac, cve_id, cvss_score, description, status='active', suppression_reason=None, suppression_logic=None, user_version=None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = datetime.datetime.now()
        
        c.execute('''
            INSERT INTO vulnerabilities (cve_id, mac_address, cvss_score, description, status, suppression_reason, suppression_logic, user_version, last_synced)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id, mac_address) DO UPDATE SET
            cvss_score=excluded.cvss_score,
            description=excluded.description,
            status=COALESCE(excluded.status, vulnerabilities.status),
            suppression_reason=COALESCE(excluded.suppression_reason, vulnerabilities.suppression_reason),
            suppression_logic=COALESCE(excluded.suppression_logic, vulnerabilities.suppression_logic),
            user_version=COALESCE(excluded.user_version, vulnerabilities.user_version),
            last_synced=excluded.last_synced
        ''', (cve_id, mac, cvss_score, description, status, suppression_reason, suppression_logic, user_version, now))
        
        conn.commit()
        conn.close()

    def suppress_vulnerability(self, mac, cve_id, reason, logic=None, user_ver=None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            UPDATE vulnerabilities 
            SET status='suppressed', suppression_reason=?, suppression_logic=?, user_version=?
            WHERE mac_address=? AND cve_id=?
        ''', (reason, logic, user_ver, mac, cve_id))
        conn.commit()
        conn.close()

    def get_assets_with_services(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get all assets
        c.execute("SELECT * FROM assets")
        assets = [dict(row) for row in c.fetchall()]
        
        # For each asset, get its services
        for asset in assets:
            c.execute("SELECT * FROM services WHERE mac_address=?", (asset['mac_address'],))
            asset['services'] = [dict(row) for row in c.fetchall()]
            
        conn.close()
        return assets

    def get_all_vulnerabilities(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('''
            SELECT v.*, a.ip_address 
            FROM vulnerabilities v
            JOIN assets a ON v.mac_address = a.mac_address
            ORDER BY v.cvss_score DESC
        ''')
        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return rows

    def get_verification_result(self, cve_id, version_string, vendor, model):
        """Retrieves a cached verification result."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("""
            SELECT analysis_result, confidence, method, reasoning 
            FROM cve_verifications 
            WHERE cve_id=? AND version_string=? AND (vendor=? OR vendor IS NULL) AND (model=? OR model IS NULL)
        """, (cve_id, version_string, vendor, model))
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None

    def save_verification_result(self, cve_id, version_string, vendor, model, result, confidence, method, reasoning):
        """Caches a verification result."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute("""
                INSERT OR REPLACE INTO cve_verifications 
                (cve_id, version_string, vendor, model, analysis_result, confidence, method, reasoning)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (cve_id, version_string, vendor, model, result, confidence, method, reasoning))
            conn.commit()
        except Exception as e:
            print(f"Error caching verification result: {e}")
        finally:
            conn.close()
