"""Custom integration to integrate akuvox with Home Assistant.

For more details about this integration, please refer to
https://github.com/jul-sh/akuvox
"""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .config_flow import AkuvoxOptionsFlowHandler
from .api import AkuvoxApiClient
from .const import (
    DOMAIN,
    LOGGER
)
from .coordinator import AkuvoxDataUpdateCoordinator

PLATFORMS: list[Platform] = [
    Platform.CAMERA,
    Platform.BUTTON,
    Platform.SENSOR
]

# https://developers.home-assistant.io/docs/config_entries_index/#setting-up-an-entry
async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up this integration using UI."""
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator = AkuvoxDataUpdateCoordinator(
        hass=hass,
        client=AkuvoxApiClient(
            session=async_get_clientsession(hass),
            hass=hass,
            entry=entry,
        ),
    )
    await async_update_configuration(hass=hass, entry=entry)

    # https://developers.home-assistant.io/docs/integration_fetching_data#coordinated-single-api-poll-for-data-for-all-entities
    await coordinator.async_config_entry_first_refresh()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))

    # Register services
    await async_setup_services(hass)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Handle removal of an entry."""
    await async_stop_polling(hass)
    if unloaded := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)
    return unloaded


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry."""
    await async_stop_polling(hass)
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
    await async_update_configuration(hass, entry)
    await async_start_polling(hass)

# Polling

async def async_stop_polling(hass: HomeAssistant):
    """Stop polling the personal door log API."""
    api_client: AkuvoxApiClient = get_api_client(hass=hass) # type: ignore
    await api_client.async_stop_polling()

async def async_start_polling(hass: HomeAssistant):
    """Stop polling the personal door log API."""
    api_client: AkuvoxApiClient = get_api_client(hass=hass) # type: ignore
    await api_client.async_start_polling_personal_door_log()

def get_api_client(hass: HomeAssistant):
    """Akuvox API Client."""
    for _key, value in hass.data[DOMAIN].items():
        coordinator: AkuvoxDataUpdateCoordinator = value
        return coordinator.client

# Integration options

async def async_options(self, entry: ConfigEntry):
    """Present current configuration options for modification."""
    # Create an options flow handler and return it
    return AkuvoxOptionsFlowHandler(entry)

async def async_options_updated(self, entry: ConfigEntry):
    """Handle updated configuration options and update the entry."""
    # Handle the updated configuration options
    updated_options = entry.options

    # Print the updated options
    LOGGER.debug("Updated Options: %s", str(updated_options))

# Update

async def async_update_configuration(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Update stored values from configuration."""
    try:
        if entry.options:
            updated_options: dict = entry.options.copy()

            # Wait for image URL?
            updated_options["wait_for_image_url"] = bool(updated_options.get("event_screenshot_options", "") == "wait")

            # Update API & data classes
            coordinator: AkuvoxDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]
            client: AkuvoxApiClient = coordinator.client

            LOGGER.debug("Configured values:")
            for key, value in updated_options.items():
                #                           value=value)
                if value:
                    client.update_data(key, value)
                    str_value: str = str(value)
                    if key in ["auth_token", "token"]:
                        length: int = len(str_value)
                        str_value = f"{str_value[0:3]}{'*'*int(length-6)}{str_value[int(length-3):length]}" # type: ignore
                    LOGGER.debug(" - %s = %s", key, str_value)
    except Exception as error:
        LOGGER.warning("Unable to update configuration: %s", str(error))

# Services

async def async_setup_services(hass: HomeAssistant) -> None:
    """Set up services for the Akuvox integration."""
    
    async def async_update_tokens_service(call):
        """Handle the update_tokens service call."""
        entry_id = call.data.get("entry_id")
        token = call.data.get("token")
        refresh_token = call.data.get("refresh_token", "")
        
        if not entry_id or not token:
            LOGGER.error("❌ Service call missing required parameters: entry_id and token")
            return
        
        # Find the coordinator for the entry
        if DOMAIN not in hass.data or entry_id not in hass.data[DOMAIN]:
            LOGGER.error("❌ Entry ID %s not found", entry_id)
            return
        
        coordinator: AkuvoxDataUpdateCoordinator = hass.data[DOMAIN][entry_id]
        client: AkuvoxApiClient = coordinator.client
        
        try:
            # Update tokens
            old_token = client._data.token[:10] + "..." if len(client._data.token) > 10 else client._data.token
            client._data.token = token
            if refresh_token:
                client._data.refresh_token = refresh_token
            
            # Store updated tokens
            await client._data.async_set_stored_data_for_key("token", token)
            if refresh_token:
                await client._data.async_set_stored_data_for_key("refresh_token", refresh_token)
            
            new_token = client._data.token[:10] + "..." if len(client._data.token) > 10 else client._data.token
            
            LOGGER.info("✅ Tokens updated successfully via service call")
            LOGGER.debug("   Old token: %s", old_token)
            LOGGER.debug("   New token: %s", new_token)
            
            # Test the new tokens by retrieving user data
            if await client.async_retrieve_user_data():
                LOGGER.info("✅ Token validation successful - user data retrieved")
            else:
                LOGGER.warning("⚠️  Token validation failed - unable to retrieve user data")
            
        except Exception as error:
            LOGGER.error("❌ Failed to update tokens: %s", error)
    
    async def async_refresh_tokens_service(call):
        """Handle the refresh_tokens service call."""
        entry_id = call.data.get("entry_id")
        
        if not entry_id:
            LOGGER.error("❌ Service call missing required parameter: entry_id")
            return
        
        # Find the coordinator for the entry
        if DOMAIN not in hass.data or entry_id not in hass.data[DOMAIN]:
            LOGGER.error("❌ Entry ID %s not found", entry_id)
            return
        
        coordinator: AkuvoxDataUpdateCoordinator = hass.data[DOMAIN][entry_id]
        client: AkuvoxApiClient = coordinator.client
        
        try:
            if await client.async_refresh_token():
                LOGGER.info("✅ Tokens refreshed successfully via service call")
            else:
                LOGGER.error("❌ Token refresh failed")
        except Exception as error:
            LOGGER.error("❌ Failed to refresh tokens: %s", error)
    
    # Register services
    hass.services.async_register(
        DOMAIN,
        "update_tokens",
        async_update_tokens_service,
        schema=None
    )
    
    hass.services.async_register(
        DOMAIN,
        "refresh_tokens",
        async_refresh_tokens_service,
        schema=None
    )

