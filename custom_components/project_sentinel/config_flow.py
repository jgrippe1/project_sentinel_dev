import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
import homeassistant.helpers.config_validation as cv

from .const import DOMAIN, DEFAULT_DB_PATH, CONF_DB_PATH

class SentinelConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Project Sentinel."""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        if user_input is not None:
            # We could add validation here to check if the file exists, 
            # but since it might be in a shared volume not yet mounted, 
            # we'll stick to basic validation for now.
            return self.async_create_entry(title="Project Sentinel", data=user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_DB_PATH, default=DEFAULT_DB_PATH): cv.string,
                }
            ),
            errors=errors,
        )
