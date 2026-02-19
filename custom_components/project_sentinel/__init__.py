import logging
import os
import sqlite3
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, CONF_DB_PATH

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["sensor", "binary_sensor"]

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """
    Set up Project Sentinel from a config entry.
    
    This function initializes the integration. It sets up the `DataUpdateCoordinator`
    to periodically poll the SQLite database for new statistics.
    
    The coordinator is then stored in `hass.data[DOMAIN]` for access by other platforms
    (like sensor.py), and the platforms are forwarded for setup.
    """
    db_path = entry.data.get(CONF_DB_PATH)

    async def async_update_data():
        """Fetch data from SQLite."""
        try:
            return await hass.async_add_executor_job(fetch_sentinel_data, db_path)
        except Exception as err:
            raise UpdateFailed(f"Error communicating with Sentinel DB: {err}")

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name="sentinel_data",
        update_method=async_update_data,
        update_interval=timedelta(minutes=1),
    )

    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok

def fetch_sentinel_data(db_path):
    """
    Query data from the SQLite database.
    
    This runs in an executor job (sync context) to avoid blocking the event loop 
    with database I/O.
    
    It aggregates high-level metrics:
    - Total Device Count
    - Total Vulnerability Count
    - Critical Vulnerabilities (CVSS >= 9.0)
    - Last Scan Timestamp
    
    Args:
        db_path (str): Filesystem path to the shared sqlite database (e.g. /share/sentinel.db).
        
    Returns:
        dict: A dictionary of aggregated metrics.
    """
    data = {}
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Get active devices
        c.execute("SELECT COUNT(*) FROM assets WHERE status='active'")
        data["device_count"] = c.fetchone()[0]
        
        # Get total vulnerabilities
        c.execute("SELECT COUNT(*) FROM vulnerabilities")
        data["vulnerability_count"] = c.fetchone()[0]

        # Get critical vulnerabilities (Score >= 9.0)
        c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cvss_score >= 9.0")
        data["critical_vulnerability_count"] = c.fetchone()[0]
        
        # Get last scan time
        c.execute("SELECT MAX(last_seen) FROM assets")
        data["last_scan"] = c.fetchone()[0] or "Unknown"

        conn.close()
    except Exception as e:
        _LOGGER.error(f"Failed to query Sentinel DB at {db_path}: {e}")
        raise e
        
    return data
