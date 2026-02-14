import logging
import sqlite3
from homeassistant.core import HomeAssistant
from homeassistant.components.binary_sensor import BinarySensorEntity, BinarySensorDeviceClass
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the binary sensor platform."""
    db_path = hass.data[DOMAIN]["db_path"]
    
    add_entities([
        SentinelCriticalAlert(db_path)
    ], True)

class SentinelCriticalAlert(BinarySensorEntity):
    def __init__(self, db_path):
        self.db_path = db_path
        self._is_on = False

    @property
    def name(self):
        return "Sentinel Critical Alert"

    @property
    def unique_id(self):
        return "sentinel_critical_alert"

    @property
    def device_class(self):
        return BinarySensorDeviceClass.PROBLEM

    @property
    def is_on(self):
        return self._is_on

    def update(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            # Check for any vulnerability with score >= 9.0 (Critical)
            c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cvss_score >= 9.0")
            row = c.fetchone()
            conn.close()
            
            count = row[0] if row else 0
            self._is_on = count > 0
        except Exception as e:
            _LOGGER.error(f"DB Error: {e}")
            self._is_on = False
