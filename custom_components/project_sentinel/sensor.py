import logging
from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass, entry, async_add_entities):
    """Set up the sensor platform from a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    
    async_add_entities([
        SentinelDeviceCount(coordinator),
        SentinelVulnerabilityCount(coordinator),
        SentinelLastScan(coordinator)
    ])

class SentinelBaseSensor(CoordinatorEntity, SensorEntity):
    """Base class for Project Sentinel sensors."""
    def __init__(self, coordinator):
        super().__init__(coordinator)
        self._attr_has_entity_name = True

class SentinelDeviceCount(SentinelBaseSensor):
    _attr_name = "Device Count"
    _attr_unique_id = "sentinel_device_count"
    _attr_icon = "mdi:router-network"

    @property
    def native_value(self):
        """Return the state of the sensor."""
        return self.coordinator.data.get("device_count", 0)

class SentinelVulnerabilityCount(SentinelBaseSensor):
    _attr_name = "Vulnerabilities"
    _attr_unique_id = "sentinel_vulnerability_count"
    _attr_icon = "mdi:shield-alert"

    @property
    def native_value(self):
        """Return the state of the sensor."""
        return self.coordinator.data.get("vulnerability_count", 0)

class SentinelLastScan(SentinelBaseSensor):
    _attr_name = "Last Scan"
    _attr_unique_id = "sentinel_last_scan"
    _attr_icon = "mdi:clock-check"

    @property
    def native_value(self):
        """Return the state of the sensor."""
        return self.coordinator.data.get("last_scan", "Unknown")
