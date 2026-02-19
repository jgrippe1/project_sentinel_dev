import logging
from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass, entry, async_add_entities):
    """
    Set up the sensor platform from a config entry.

    This function is called by Home Assistant when the integration is set up.
    It retrieves the DataUpdateCoordinator from the global `hass.data` store
    and initializes the sensors with it.

    Args:
        hass (HomeAssistant): The Home Assistant class instance.
        entry (ConfigEntry): The integration configuration entry.
        async_add_entities (Callable): The callback to add entities to HA.
    """
    coordinator = hass.data[DOMAIN][entry.entry_id]
    
    async_add_entities([
        SentinelDeviceCount(coordinator),
        SentinelVulnerabilityCount(coordinator),
        SentinelLastScan(coordinator)
    ])

class SentinelBaseSensor(CoordinatorEntity, SensorEntity):
    """
    Base class for Project Sentinel sensors.
    
    Inherits from CoordinatorEntity to automatically update when the 
    coordinator fetches new data.
    """
    def __init__(self, coordinator):
        super().__init__(coordinator)
        self._attr_has_entity_name = True

class SentinelDeviceCount(SentinelBaseSensor):
    """
    Sensor that reports the total number of active devices managed by Project Sentinel.
    """
    _attr_name = "Device Count"
    _attr_unique_id = "sentinel_device_count"
    _attr_icon = "mdi:router-network"

    @property
    def native_value(self):
        """Return the state of the sensor (number of devices)."""
        return self.coordinator.data.get("device_count", 0)

class SentinelVulnerabilityCount(SentinelBaseSensor):
    """
    Sensor that reports the total number of unmitigated vulnerabilities found across all active devices.
    """
    _attr_name = "Vulnerabilities"
    _attr_unique_id = "sentinel_vulnerability_count"
    _attr_icon = "mdi:shield-alert"

    @property
    def native_value(self):
        """Return the state of the sensor (number of vulnerabilities)."""
        return self.coordinator.data.get("vulnerability_count", 0)

class SentinelLastScan(SentinelBaseSensor):
    """
    Sensor that reports the timestamp of the most recent network scan or update.
    """
    _attr_name = "Last Scan"
    _attr_unique_id = "sentinel_last_scan"
    _attr_icon = "mdi:clock-check"

    @property
    def native_value(self):
        """Return the state of the sensor (last seen timestamp)."""
        return self.coordinator.data.get("last_scan", "Unknown")
