"""Datastore — SQLite persistence layer for assets, services, vulnerabilities, and caches."""
import sqlite3
import datetime
import os
import json
import logging

logger = logging.getLogger("Datastore")

DB_PATH = os.getenv("SENTINEL_DB_PATH", "/data/sentinel.db")
# Fallback for local testing if not running in Add-on environment
if not os.path.exists("/data") and "SENTINEL_DB_PATH" not in os.environ:
    DB_PATH = "sentinel.db"

# Default CVE cache TTL in hours (7 days)
CVE_CACHE_TTL_HOURS = 168

class Datastore:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()
        self._migrate_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
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
                    status TEXT DEFAULT 'active',
                    connected_to_mac TEXT,
                    connected_port TEXT,
                    connection_type TEXT,
                    manual_parent_mac TEXT
                )
            ''')

            # OUI Cache
            c.execute('''
                CREATE TABLE IF NOT EXISTS oui_cache (
                    prefix TEXT PRIMARY KEY,
                    vendor TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # CVE Cache
            c.execute('''
                CREATE TABLE IF NOT EXISTS cve_cache (
                    product TEXT,
                    version TEXT,
                    json_data TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (product, version)
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
        finally:
            conn.close()

    def _migrate_db(self):
        """Handles schema migrations for existing databases."""
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            
            # Cache PRAGMA results once instead of calling 3+ times
            c.execute("PRAGMA table_info(assets)")
            columns = [info[1] for info in c.fetchall()]
            
            if 'interface' not in columns:
                logger.info("Migrating database: Adding 'interface' column to 'assets' table.")
                try:
                    c.execute("ALTER TABLE assets ADD COLUMN interface TEXT")
                except Exception as e:
                    logger.warning(f"Migration error (interface): {e}")

            # Column names & types are developer-controlled constants.
            # DDL does not support parameterized queries, so f-strings are used intentionally.
            new_columns = {
                'approved': 'INTEGER DEFAULT 0',
                'tags': "TEXT DEFAULT '[]'",
                'custom_name': 'TEXT',
                'location': 'TEXT',
                'device_type': 'TEXT',
                'original_device_type': 'TEXT',
                'parent_mac': 'TEXT',
                'confirmed_integrations': "TEXT DEFAULT '[]'",
                'dismissed_integrations': "TEXT DEFAULT '[]'",
                'hw_version': 'TEXT',
                'fw_version': 'TEXT',
                'model': 'TEXT',
                'os': 'TEXT',
                'oui_vendor': 'TEXT',
                'actual_fw_version': 'TEXT',
                'fw_verified_at': 'DATETIME',
                'dismissed_fw_version': 'TEXT',
                'dismissed_vendor': 'TEXT',
                'connected_to_mac': 'TEXT',
                'connected_port': 'TEXT',
                'connection_type': 'TEXT',
                'manual_parent_mac': 'TEXT'
            }

            for col, col_type in new_columns.items():
                if col not in columns:
                    logger.info(f"Migrating database: Adding '{col}' column to 'assets' table.")
                    try:
                        c.execute(f"ALTER TABLE assets ADD COLUMN {col} {col_type}")
                        if col == 'approved':
                            c.execute("UPDATE assets SET approved = 1")
                    except Exception as e:
                        logger.warning(f"Migration error ({col}): {e}")

            # Migrate custom_name from legacy 'owner' column
            if 'owner' in columns and 'custom_name' in columns:
                try:
                    c.execute("UPDATE assets SET custom_name = owner WHERE custom_name IS NULL AND owner IS NOT NULL")
                except Exception as e:
                    logger.warning(f"Migration error (owner->custom_name): {e}")

            # Check for 'cert_expiry' in 'services' table
            c.execute("PRAGMA table_info(services)")
            service_columns = [info[1] for info in c.fetchall()]
            if 'cert_expiry' not in service_columns:
                logger.info("Migrating database: Adding 'cert_expiry' column to 'services' table.")
                try:
                    c.execute("ALTER TABLE services ADD COLUMN cert_expiry DATETIME")
                except Exception as e:
                    logger.warning(f"Migration error (cert_expiry): {e}")

            # Vulnerabilities Update
            c.execute("PRAGMA table_info(vulnerabilities)")
            vuln_columns = [info[1] for info in c.fetchall()]
            vuln_migrations = {
                'status': "TEXT DEFAULT 'active'",
                'suppression_reason': 'TEXT',
                'suppression_logic': 'TEXT',
                'user_version': 'TEXT'
            }
            for col, col_type in vuln_migrations.items():
                if col not in vuln_columns:
                    logger.info(f"Migrating database: Adding '{col}' to vulnerabilities.")
                    try:
                        c.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {col} {col_type}")
                    except Exception as e:
                        logger.warning(f"Migration error ({col}): {e}")

            # Hybrid Verification Cache Update
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_verifications'")
            if not c.fetchone():
                logger.info("Migrating database: Creating 'cve_verifications' table.")
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

            conn.commit()
        finally:
            conn.close()

    def upsert_asset(self, mac, ip, hostname=None, vendor=None, interface=None, parent_mac=None, original_device_type=None, hw_version=None, fw_version=None, model=None, os=None, oui_vendor=None, connected_to_mac=None, connected_port=None, connection_type=None, manual_parent_mac=None):
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            now = datetime.datetime.now()
            
            # --- Deduplication Logic ---
            if mac and ip and not mac.startswith('mac_'):
                placeholder_mac = f"mac_{ip.replace('.', '_')}"
                c.execute("SELECT mac_address FROM assets WHERE mac_address=?", (placeholder_mac,))
                if c.fetchone():
                    logger.info(f"Datastore: Triggering merge of placeholder {placeholder_mac} into real MAC {mac}")
                    conn.close()
                    self.merge_assets(mac, placeholder_mac)
                    conn = sqlite3.connect(self.db_path)
                    c = conn.cursor()

            # Check if exists
            c.execute("SELECT first_seen FROM assets WHERE mac_address=?", (mac,))
            row = c.fetchone()
            
            if row:
                # Build a single UPDATE with dynamic SET clauses
                updates = ['ip_address=?', 'last_seen=?', "status='active'"]
                params = [ip, now]
                
                # Use `is not None` to allow empty strings and 0 as valid updates
                optional_fields = [
                    ('hostname', hostname), ('vendor', vendor), ('interface', interface),
                    ('parent_mac', parent_mac), ('original_device_type', original_device_type),
                    ('hw_version', hw_version), ('fw_version', fw_version), ('model', model),
                    ('os', os), ('oui_vendor', oui_vendor)
                ]
                for col_name, val in optional_fields:
                    if val is not None:
                        updates.append(f"{col_name}=?")
                        params.append(val)
                
                # These also use 'is not None' because empty string has meaning (clear value)
                none_check_fields = [
                    ('connected_to_mac', connected_to_mac), ('connected_port', connected_port),
                    ('connection_type', connection_type)
                ]
                for col_name, val in none_check_fields:
                    if val is not None:
                        updates.append(f"{col_name}=?")
                        params.append(val)
                
                if manual_parent_mac is not None:
                    updates.append("manual_parent_mac=?")
                    params.append(None if manual_parent_mac == "" else manual_parent_mac)
                
                params.append(mac)
                c.execute(f"UPDATE assets SET {', '.join(updates)} WHERE mac_address=?", tuple(params))
            else:
                c.execute('''
                    INSERT INTO assets (mac_address, ip_address, hostname, vendor, interface, parent_mac, original_device_type, hw_version, fw_version, model, os, oui_vendor, connected_to_mac, connected_port, connection_type, manual_parent_mac, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (mac, ip, hostname, vendor, interface, parent_mac, original_device_type, hw_version, fw_version, model, os, oui_vendor, connected_to_mac, connected_port, connection_type, manual_parent_mac, now, now))
                
            conn.commit()
        finally:
            conn.close()

    def merge_assets(self, target_mac, source_mac):
        """
        Merges source_mac (usually a placeholder) into target_mac (real MAC).
        Migrates services and vulnerabilities.
        """
        if target_mac == source_mac:
            return

        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            logger.info(f"Merging {source_mac} into {target_mac}...")

            # 1. Migrate Services
            c.execute("SELECT port, proto FROM services WHERE mac_address=?", (target_mac,))
            existing_services = set((row['port'], row['proto']) for row in c.fetchall())
            
            c.execute("SELECT id, port, proto FROM services WHERE mac_address=?", (source_mac,))
            source_services = c.fetchall()
            
            for row in source_services:
                service_id, port, proto = row['id'], row['port'], row['proto']
                if (port, proto) in existing_services:
                    c.execute("DELETE FROM services WHERE id=?", (service_id,))
                else:
                    c.execute("UPDATE services SET mac_address=? WHERE id=?", (target_mac, service_id))

            # 2. Migrate Vulnerabilities
            c.execute("SELECT cve_id FROM vulnerabilities WHERE mac_address=?", (target_mac,))
            existing_vulns = set(row['cve_id'] for row in c.fetchall())
            
            c.execute("SELECT cve_id FROM vulnerabilities WHERE mac_address=?", (source_mac,))
            source_vulns = c.fetchall()
            
            for row in source_vulns:
                cve_id = row['cve_id']
                if cve_id in existing_vulns:
                    c.execute("DELETE FROM vulnerabilities WHERE cve_id=? AND mac_address=?", (cve_id, source_mac))
                else:
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
            logger.info(f"Successfully merged {source_mac} into {target_mac}")
        finally:
            conn.close()

    def approve_asset(self, mac):
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            c.execute("UPDATE assets SET approved=1 WHERE mac_address=?", (mac,))
            conn.commit()
        finally:
            conn.close()

    def delete_asset(self, mac):
        """Deletes an asset and its associated vulnerabilities and services."""
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            c.execute("DELETE FROM assets WHERE mac_address=?", (mac,))
            c.execute("DELETE FROM services WHERE mac_address=?", (mac,))
            c.execute("DELETE FROM vulnerabilities WHERE mac_address=?", (mac,))
            conn.commit()
        finally:
            conn.close()

    def update_asset_governance(self, mac, custom_name=None, location=None, device_type=None, tags=None, confirmed_integrations=None, dismissed_integrations=None, actual_fw_version=None, model=None, os=None, vendor=None, dismissed_fw_version=None, dismissed_vendor=None, manual_parent_mac=None):
        """Single dynamic UPDATE instead of up to 13 individual queries."""
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            updates = []
            params = []

            simple_fields = [
                ('custom_name', custom_name), ('location', location),
                ('device_type', device_type), ('model', model),
                ('os', os), ('vendor', vendor),
                ('confirmed_integrations', confirmed_integrations),
                ('dismissed_integrations', dismissed_integrations),
                ('dismissed_fw_version', dismissed_fw_version),
                ('dismissed_vendor', dismissed_vendor)
            ]
            for col_name, val in simple_fields:
                if val is not None:
                    updates.append(f"{col_name}=?")
                    params.append(val)

            if actual_fw_version is not None:
                updates.append("actual_fw_version=?")
                params.append(actual_fw_version)
                updates.append("fw_verified_at=?")
                params.append(datetime.datetime.now())

            if tags is not None:
                updates.append("tags=?")
                params.append(json.dumps(tags))

            if manual_parent_mac is not None:
                updates.append("manual_parent_mac=?")
                params.append(None if manual_parent_mac == "" else manual_parent_mac)

            if updates:
                params.append(mac)
                c.execute(f"UPDATE assets SET {', '.join(updates)} WHERE mac_address=?", tuple(params))
            conn.commit()
        finally:
            conn.close()

    def upsert_service(self, mac, port, proto, service_name, banner, version_string, cert_expiry=None):
        conn = sqlite3.connect(self.db_path)
        try:
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
        finally:
            conn.close()

    def get_assets(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM assets")
            return [dict(row) for row in c.fetchall()]
        finally:
            conn.close()

    def get_asset(self, mac):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM assets WHERE mac_address=?", (mac,))
            row = c.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_asset_by_ip(self, ip):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM assets WHERE ip_address=?", (ip,))
            row = c.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def upsert_vulnerability(self, mac, cve_id, cvss_score, description, status='active', suppression_reason=None, suppression_logic=None, user_version=None):
        """
        Insert or update a vulnerability record.
        Always overwrites status to support un-suppression on re-scan.
        Only preserves suppression fields when explicit values are provided.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            now = datetime.datetime.now()
            
            c.execute('''
                INSERT INTO vulnerabilities (cve_id, mac_address, cvss_score, description, status, suppression_reason, suppression_logic, user_version, last_synced)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id, mac_address) DO UPDATE SET
                cvss_score=excluded.cvss_score,
                description=excluded.description,
                status=excluded.status,
                suppression_reason=excluded.suppression_reason,
                suppression_logic=excluded.suppression_logic,
                user_version=excluded.user_version,
                last_synced=excluded.last_synced
            ''', (cve_id, mac, cvss_score, description, status, suppression_reason, suppression_logic, user_version, now))
            
            conn.commit()
        finally:
            conn.close()

    def suppress_vulnerability(self, mac, cve_id, reason, logic=None, user_ver=None):
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            c.execute('''
                UPDATE vulnerabilities 
                SET status='suppressed', suppression_reason=?, suppression_logic=?, user_version=?
                WHERE mac_address=? AND cve_id=?
            ''', (reason, logic, user_ver, mac, cve_id))
            conn.commit()
        finally:
            conn.close()

    def get_assets_with_services(self):
        """Fetch all assets and services in two queries, then merge in-memory."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            c.execute("SELECT * FROM assets")
            assets = [dict(row) for row in c.fetchall()]
            
            # Bulk fetch all services and group by MAC
            c.execute("SELECT * FROM services")
            services_by_mac = {}
            for row in c.fetchall():
                svc = dict(row)
                mac = svc['mac_address']
                if mac not in services_by_mac:
                    services_by_mac[mac] = []
                services_by_mac[mac].append(svc)
            
            for asset in assets:
                asset['services'] = services_by_mac.get(asset['mac_address'], [])
                
            return assets
        finally:
            conn.close()

    def get_all_vulnerabilities(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('''
                SELECT v.*, a.ip_address 
                FROM vulnerabilities v
                JOIN assets a ON v.mac_address = a.mac_address
                ORDER BY v.cvss_score DESC
            ''')
            return [dict(row) for row in c.fetchall()]
        finally:
            conn.close()

    def get_verification_result(self, cve_id, version_string, vendor, model):
        """Retrieves a cached verification result."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("""
                SELECT analysis_result, confidence, method, reasoning 
                FROM cve_verifications 
                WHERE cve_id=? AND version_string=? 
                AND (vendor IS NULL OR vendor=?) 
                AND (model IS NULL OR model=?)
                ORDER BY timestamp DESC LIMIT 1
            """, (cve_id, version_string, vendor, model))
            
            row = c.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_oui_cache(self, prefix):
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            c.execute("SELECT vendor FROM oui_cache WHERE prefix=?", (prefix,))
            row = c.fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def set_oui_cache(self, prefix, vendor):
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            c.execute("INSERT OR REPLACE INTO oui_cache (prefix, vendor) VALUES (?, ?)", (prefix, vendor))
            conn.commit()
        finally:
            conn.close()

    def get_vulnerability(self, mac, cve_id):
        """Targeted single-vulnerability lookup."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM vulnerabilities WHERE mac_address=? AND cve_id=?", (mac, cve_id))
            row = c.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_vulnerabilities_for_asset(self, mac):
        """Targeted query for all vulns on a single asset."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM vulnerabilities WHERE mac_address=?", (mac,))
            return [dict(row) for row in c.fetchall()]
        finally:
            conn.close()

    def get_cve_cache(self, product, version):
        """Returns cached CVE data if within TTL, otherwise None to trigger refresh."""
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            c.execute("SELECT json_data, timestamp FROM cve_cache WHERE product=? AND version=?", (product, version))
            row = c.fetchone()
            if row:
                # Check TTL — stale cache returns None to trigger NVD refresh
                try:
                    cached_time = datetime.datetime.fromisoformat(row[1])
                    age_hours = (datetime.datetime.now() - cached_time).total_seconds() / 3600
                    if age_hours > CVE_CACHE_TTL_HOURS:
                        logger.debug(f"CVE cache expired for {product} {version} (age: {age_hours:.0f}h)")
                        return None
                except (ValueError, TypeError):
                    pass  # If timestamp parse fails, use cached data anyway
                
                try:
                    return json.loads(row[0])
                except (json.JSONDecodeError, ValueError):
                    return None
            return None
        finally:
            conn.close()

    def set_cve_cache(self, product, version, data):
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            json_str = json.dumps(data)
            c.execute("INSERT OR REPLACE INTO cve_cache (product, version, json_data) VALUES (?, ?, ?)", (product, version, json_str))
            conn.commit()
        finally:
            conn.close()

    def save_verification_result(self, cve_id, version_string, vendor, model, result, confidence, method, reasoning):
        """Caches a verification result."""
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            c.execute("""
                INSERT OR REPLACE INTO cve_verifications 
                (cve_id, version_string, vendor, model, analysis_result, confidence, method, reasoning)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (cve_id, version_string, vendor, model, result, confidence, method, reasoning))
            conn.commit()
        except Exception as e:
            logger.warning(f"Error caching verification result: {e}")
        finally:
            conn.close()

    def update_asset_topology(self, mac, connected_to_mac, connected_port, connection_type):
        """Targeted topology update — updates only connection fields without full row rewrite."""
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            c.execute("""
                UPDATE assets 
                SET connected_to_mac=?, connected_port=?, connection_type=?
                WHERE mac_address=?
            """, (connected_to_mac, str(connected_port), connection_type, mac))
            conn.commit()
        finally:
            conn.close()
