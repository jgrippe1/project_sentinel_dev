import logging
import sqlite3
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import Entity
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the sensor platform."""
    db_path = hass.data[DOMAIN]["db_path"]
    
    add_entities([
        SentinelDeviceCount(db_path),
        SentinelVulnerabilityCount(db_path),
        SentinelLastScan(db_path)
    ], True)

class SentinelBaseSensor(Entity):
    def __init__(self, db_path):
        self.db_path = db_path
        self._state = None
        self._attr = {}

    def _query(self, query):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute(query)
            result = c.fetchone()
            conn.close()
            return result
        except Exception as e:
            _LOGGER.error(f"DB Query Error: {e}")
            return None

    @property
    def should_poll(self):
        return True

class SentinelDeviceCount(SentinelBaseSensor):
    @property
    def name(self):
        return "Sentinel Device Count"

    @property
    def unique_id(self):
        return "sentinel_device_count"

    @property
    def state(self):
        return self._state

    @property
    def icon(self):
        return "mdi:router-network"

    def update(self):
        row = self._query("SELECT COUNT(*) FROM assets WHERE status='active'")
        self._state = row[0] if row else 0

class SentinelVulnerabilityCount(SentinelBaseSensor):
    @property
    def name(self):
        return "Sentinel Vulnerabilities"
        
    @property
    def unique_id(self):
        return "sentinel_vulnerability_count"

    @property
    def state(self):
        return self._state

    @property
    def icon(self):
        return "mdi:shield-alert"

    def update(self):
        # Join with assets to ensure we only count active devices if needed, 
        # but for now just count total known vulns
        row = self._query("SELECT COUNT(*) FROM vulnerabilities")
        self._state = row[0] if row else 0

class SentinelLastScan(SentinelBaseSensor):
    @property
    def name(self):
        return "Sentinel Last Scan"
        
    @property
    def unique_id(self):
        return "sentinel_last_scan"

    @property
    def state(self):
        return self._state

    @property
    def icon(self):
        return "mdi:clock-check"

    def update(self):
        row = self._query("SELECT MAX(last_seen) FROM assets")
        self._state = row[0] if row else "Unknown"
