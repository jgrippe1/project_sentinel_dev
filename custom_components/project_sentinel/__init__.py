import logging
import os
import sqlite3
from datetime import timedelta

import voluptuous as vol
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.event import track_time_interval
from homeassistant.const import CONF_SCAN_INTERVAL
import homeassistant.helpers.config_validation as cv

from .const import DOMAIN, DEFAULT_DB_PATH, CONF_DB_PATH

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Optional(CONF_DB_PATH, default=DEFAULT_DB_PATH): cv.string,
                vol.Optional(CONF_SCAN_INTERVAL, default=timedelta(minutes=1)): cv.time_period,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)

def setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the Project Sentinel integration."""
    conf = config.get(DOMAIN, {})
    db_path = conf.get(CONF_DB_PATH, DEFAULT_DB_PATH)
    scan_interval = conf.get(CONF_SCAN_INTERVAL, timedelta(minutes=1))

    if not os.path.exists(db_path) and not os.path.exists("sentinel.db"):
        # Fallback for dev/testing if configured path invalid but local exists
         if os.path.exists("sentinel.db"):
             db_path = "sentinel.db"
         else:
            _LOGGER.warning(f"Sentinel DB not found at {db_path}. Sensors may be empty.")

    hass.data[DOMAIN] = {
        "db_path": db_path
    }

    # We are using platform setup for sensors
    hass.helpers.discovery.load_platform(hass, "sensor", DOMAIN, {}, config)
    hass.helpers.discovery.load_platform(hass, "binary_sensor", DOMAIN, {}, config)

    return True
