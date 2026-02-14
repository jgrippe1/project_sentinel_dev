import logging
from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass, entry, async_add_entities):
    """Set up the binary sensor platform from a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    
    async_add_entities([
        SentinelCriticalAlert(coordinator)
    ])

class SentinelCriticalAlert(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor for critical vulnerability alerts."""
    _attr_name = "Critical Security Alert"
    _attr_unique_id = "sentinel_critical_alert"
    _attr_device_class = BinarySensorDeviceClass.PROBLEM

    def __init__(self, coordinator):
        super().__init__(coordinator)
        self._attr_has_entity_name = True

    @property
    def is_on(self):
        """Return true if critical vulnerabilities are present."""
        critical_count = self.coordinator.data.get("critical_vulnerability_count", 0)
        return critical_count > 0
