"""Adds config flow for Akuvox."""
from __future__ import annotations

from homeassistant import config_entries
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

import voluptuous as vol
from .api import AkuvoxApiClient
from .coordinator import AkuvoxDataUpdateCoordinator

from .const import (
    DOMAIN,
    LOGGER,
    LOCATIONS_DICT,
    COUNTRY_PHONE,
    SUBDOMAINS_LIST,
)
from .helpers import AkuvoxHelpers

helpers = AkuvoxHelpers()

class AkuvoxFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for Akuvox."""

    VERSION = 1
    data: dict = {}
    rest_server_data: dict = {}
    akuvox_api_client: AkuvoxApiClient = None  # type: ignore

    @staticmethod
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> config_entries.OptionsFlow:
        """Create the options flow."""
        return AkuvoxOptionsFlowHandler(config_entry)

    async def async_step_user(self, user_input=None):
        """Redirect the user to the SMS sign-in step."""

        # Initialize the API client
        if self.akuvox_api_client is None:
            coordinator: AkuvoxDataUpdateCoordinator = None # type: ignore
            if DOMAIN in self.hass.data:
                for _key, value in self.hass.data[DOMAIN].items():
                    coordinator = value
            if coordinator:
                self.akuvox_api_client = coordinator.client
            else:
                self.akuvox_api_client = AkuvoxApiClient(
                    session=async_get_clientsession(self.hass),
                    hass=self.hass,
                    entry=None)

        return await self.async_step_sms_sign_in(user_input)


    async def async_step_sms_sign_in(self, user_input=None):
        """Step 1b: User enters their mobile phone country code and number.

        Args:
            user_input (dict): User-provided input data.

        Returns:
            dict: A dictionary representing the next step or an entry creation.

        """

        data_schema = self.get_sms_sign_in_schema(user_input)

        if user_input is not None:
            country_code = helpers.get_country_phone_code_from_name(user_input.get("country_code"))
            phone_number = user_input.get(
                "phone_number", "").replace("-", "").replace(" ", "")
            subdomain: str = user_input.get("subdomain", "Default")
            subdomain = subdomain if subdomain != "Default" else helpers.get_subdomain_from_country_code(country_code)

            location_dict = helpers.get_location_dict(country_code)
            LOGGER.debug("User will use the API subdomain '%s' for %s", subdomain, location_dict.get("country"))

            self.data = {
                "full_phone_number": f"(+{country_code}) {phone_number}",
                "country_code": country_code,
                "phone_number": phone_number,
                "subdomain": subdomain
            }

            if len(country_code) > 0 and len(phone_number) > 0: # type: ignore
                # Request SMS code for login
                request_sms_code = await self.akuvox_api_client.async_send_sms(self.hass, country_code, phone_number, subdomain)
                if request_sms_code:
                    return await self.async_step_verify_sms_code()
                else:
                    return self.async_show_form(
                        step_id="sms_sign_in",
                        data_schema=vol.Schema(data_schema),
                        description_placeholders=user_input,
                        last_step=False,
                        errors={
                            "base": "SMS code request failed. Check your phone number."
                        }
                    )

            return self.async_show_form(
                step_id="sms_sign_in",
                data_schema=vol.Schema(data_schema),
                description_placeholders=user_input,
                last_step=False,
                errors={
                    "base": "Please enter a valid country code and phone number."
                }
            )

        return self.async_show_form(
            step_id="sms_sign_in",
            data_schema=vol.Schema(data_schema),
            description_placeholders=user_input,
            last_step=False,
        )


    async def async_step_verify_sms_code(self, user_input=None):
        """Step 2: User enters the SMS code received on their phone for verifiation.

        Args:
            user_input (dict): User-provided input data.

        Returns:
            dict: A dictionary representing the next step or an entry creation.

        """

        data_schema = {
            vol.Required(
                "sms_code",
                msg=None,
                description="Enter the code from the SMS you received on your device."): str,
        }

        if user_input is not None and user_input:
            sms_code = user_input.get("sms_code")
            country_code = self.data["country_code"]
            phone_number = self.data["phone_number"]

            # Validate SMS code
            sign_in_response = await self.akuvox_api_client.async_sms_sign_in(
                phone_number,
                country_code,
                sms_code)
            if sign_in_response is True:
                data_model = self.akuvox_api_client._data
                if data_model is not None:
                    if data_model.token:
                        await data_model.async_set_stored_data_for_key("token", data_model.token)
                    if data_model.auth_token:
                        await data_model.async_set_stored_data_for_key("auth_token", data_model.auth_token)
                    if data_model.refresh_token:
                        await data_model.async_set_stored_data_for_key("refresh_token", data_model.refresh_token)

                devices_json = self.akuvox_api_client.get_devices_json()
                self.data.update(devices_json)

                ################################
                ### Create integration entry ###
                ################################
                return self.async_create_entry(
                    title=self.akuvox_api_client.get_title(),
                    data=self.data
                )

            user_input = None
            return self.async_show_form(
                step_id="verify_sms_code",
                data_schema=vol.Schema(data_schema),
                description_placeholders=user_input,
                last_step=True,
                errors={
                    "sms_code": "Invalid SMS code. Please enter the correct code."
                }
            )

        return self.async_show_form(
            step_id="verify_sms_code",
            data_schema=vol.Schema(data_schema),
            description_placeholders=user_input,
            last_step=True
        )

    def get_sms_sign_in_schema(self, user_input):
        """Get the schema for sms_sign_in step."""
        user_input = user_input or {}

        # List of countries
        default_country_name_code = helpers.find_country_name_code(str(COUNTRY_PHONE.get(self.hass.config.country,"")))
        default_country_name = LOCATIONS_DICT.get(default_country_name_code, {}).get("country") # type: ignore
        country_names_list:list = helpers.get_country_names_list()

        return {
            vol.Required("country_code",
                         default=default_country_name,
                         description="Your phone's international calling code prefix"):
                         selector.SelectSelector(
                             selector.SelectSelectorConfig(
                                 options=country_names_list,
                                 mode=selector.SelectSelectorMode.DROPDOWN,
                                 custom_value=False),
                                 ),
            vol.Required(
                "phone_number",
                msg=None,
                default=user_input.get("phone_number"),  # type: ignore
                description="Your phone number"): str,
            vol.Optional("subdomain",
                default="Default", # type: ignore
                description="Manually set the regional API subdomain"):
                selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=SUBDOMAINS_LIST,
                        mode=selector.SelectSelectorMode.DROPDOWN,
                        custom_value=True),
                        )
        }

class AkuvoxOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for Akuvox integration."""

    akuvox_api_client: AkuvoxApiClient = None  # type: ignore

    def __init__(self, config_entry: config_entries.ConfigEntry):
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """Initialize the options flow."""
        # Define the options schema
        config_data = dict(self.config_entry.data)

        event_screenshot_options = {
            "asap": "Receive events once generated, without waiting for camera screenshot URLs.",
            "wait": "Wait for camera screenshot URLs to become available before triggering the event (typically adds a delay of 0-3 seconds)."
        }

        default_country_name_code = helpers.find_country_name_code(config_data.get('country_code', self.hass.config.country))
        default_country_name = LOCATIONS_DICT.get(default_country_name_code, {}).get("country") # type: ignore
        default_subdomain = LOCATIONS_DICT.get(default_country_name_code, {}).get("subdomain") # type: ignore
        subdomain_list = list(SUBDOMAINS_LIST)
        del subdomain_list[0]
        current_subdomain = self.get_data_key_value("subdomain") or default_subdomain

        country_names_list:list = []
        for _country, country_dict in LOCATIONS_DICT.items():
            country_names_list.append(country_dict.get("country"))

        options_schema = vol.Schema({
            vol.Optional("country",
                         default=default_country_name,
                         description="Your country code"):
                         selector.SelectSelector(
                             selector.SelectSelectorConfig(
                                 options=country_names_list,
                                 mode=selector.SelectSelectorMode.DROPDOWN,
                                 custom_value=False),
                                 ),
            vol.Optional("subdomain",
                default=current_subdomain, # type: ignore
                description="Manually set the regional API subdomain"):
                selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=subdomain_list,
                        mode=selector.SelectSelectorMode.DROPDOWN,
                        custom_value=True),
                        ),
            vol.Required("event_screenshot_options",
                         default=self.get_data_key_value("event_screenshot_options", "asap") # type: ignore
            ): vol.In(event_screenshot_options),
        })

        # Show the form with the current options
        if user_input is None:
            return self.async_show_form(
                step_id="init",
                data_schema=options_schema,
                description_placeholders=user_input,
                last_step=True
            )

        wait_for_image_url = user_input.get("event_screenshot_options", "asap") == "wait"

        # API client
        if self.akuvox_api_client is None:
            coordinator: AkuvoxDataUpdateCoordinator
            for _key, value in self.hass.data[DOMAIN].items():
                coordinator = value
            self.akuvox_api_client = coordinator.client

        self.akuvox_api_client._data.subdomain = user_input.get("subdomain", current_subdomain) # type: ignore
        self.akuvox_api_client._data.wait_for_image_url = wait_for_image_url # type: ignore

        LOGGER.debug("Updating configuration...")
        return self.async_create_entry(
            data=user_input, # type: ignore
            title="",
        )

    def get_data_key_value(self, key, placeholder=None):
        """Get the value for a given key. Options flow 1st, Config flow 2nd."""
        dicts = [dict(self.config_entry.options), dict(self.config_entry.data)]
        for p_dict in dicts:
            if key in p_dict:
                return p_dict[key]
        return placeholder
