"""Adds config flow for Akuvox."""
from __future__ import annotations

from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    selector
)

import voluptuous as vol
from .api import AkuvoxApiClient
from .const import (
    DOMAIN,
    DEFAULT_COUNTRY_CODE,
    DEFAULT_PHONE_NUMBER,
    DEFAULT_TOKEN,
    DEFAULT_APP_TOKEN,
    LOGGER
)

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
        """Step 0: User selects sign-in method."""

        # Initialize the API client
        if self.akuvox_api_client is None:
            self.akuvox_api_client = AkuvoxApiClient(
                session=async_get_clientsession(self.hass),
                hass=self.hass,
                entry=None,
            )

        return self.async_show_menu(
            step_id="user",
            menu_options=["sms_sign_in_warning", "app_tokens_sign_in"],
            description_placeholders=user_input,
        )

    async def async_step_sms_sign_in_warning(self, user_input=None):
        """Step 1a: Warning before continuing with login via SMS Verification."""
        errors = {}
        sms_sign_in = "Continue sign-in via SMS Verification"
        app_tokens_sign_in = "Sign-in via app tokens"
        data_schema = {
            "warning_option_selection": selector({
                "select": {
                    "options": [sms_sign_in, app_tokens_sign_in],
                }
            })
        }
        if user_input is not None:
            if "warning_option_selection" in user_input:
                selection = user_input["warning_option_selection"]
                if selection == sms_sign_in:
                    return self.async_show_form(
                        step_id="sms_sign_in",
                        data_schema=vol.Schema(self.get_sms_sign_in_schema()),
                        description_placeholders=user_input,
                        last_step=False,
                        errors=None
                    )
                if selection == app_tokens_sign_in:
                    return self.async_show_form(
                        step_id="app_tokens_sign_in",
                        data_schema=vol.Schema(self.get_app_tokens_sign_in_schema()),
                        description_placeholders=user_input,
                        last_step=False,
                        errors=None
                    )
                errors["base"] = "Please choose a sign-in option."
            else:
                errors["base"] = "Please choose a valid sign-in option."

        return self.async_show_form(
            step_id="sms_sign_in_warning",
            data_schema=vol.Schema(data_schema),
            description_placeholders=user_input,
            last_step=False,
            errors=errors
        )


    async def async_step_sms_sign_in(self, user_input=None):
        """Step 1b: User enters their mobile phone country code and number.

        Args:
            user_input (dict): User-provided input data.

        Returns:
            dict: A dictionary representing the next step or an entry creation.
        """

        data_schema = self.get_sms_sign_in_schema()

        if user_input is not None:
            country_code = user_input.get(
                "country_code", "").replace("+", "").replace(" ", "")
            phone_number = user_input.get(
                "phone_number", "").replace("-", "").replace(" ", "")

            subdomain = self.get_subdomain_from_country_code(country_code)
            LOGGER.debug("🌍 User will use the API from subdomain %s", subdomain)

            self.data = {
                "full_phone_number": f"(+{country_code}) {phone_number}",
                "country_code": country_code,
                "phone_number": phone_number,
                "subdomain": subdomain
            }

            if len(country_code) > 0 and len(phone_number) > 0:
                # Request SMS code for login
                self.akuvox_api_client.init_api_with_data(subdomain=subdomain)
                await self.akuvox_api_client.async_init_api_data()
                request_sms_code = await self.akuvox_api_client.send_sms(country_code, phone_number, subdomain)
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


    async def async_step_app_tokens_sign_in(self, user_input=None):
        """Step 1c: User enters app tokens and phone number to sign in."""
        data_schema = self.get_app_tokens_sign_in_schema()
        if user_input is not None:
            country_code = user_input.get(
                "country_code", "").replace("+", "").replace(" ", "")
            phone_number = user_input.get(
                "phone_number", "").replace("-", "").replace(" ", "")
            token = user_input.get("token", "")
            auth_token = user_input.get("auth_token", "")
            subdomain = self.get_subdomain_from_country_code(country_code)

            self.data = {
                "full_phone_number": f"(+{country_code}) {phone_number}",
                "country_code": country_code,
                "phone_number": phone_number,
                "token": token,
                "auth_token": auth_token,
                "subdomain": subdomain
            }

            # Perform login via auth_token, token and phone number
            if all(len(value) > 0 for value in (country_code, phone_number, token, auth_token)):
                # Retrieve ervers_list data.
                self.akuvox_api_client.init_api_with_data(subdomain=subdomain)
                await self.akuvox_api_client.async_init_api_data()
                login_successful = await self.akuvox_api_client.async_make_servers_list_request(
                    auth_token, token, phone_number)
                if login_successful is True:
                    # Retrieve connected device data
                    await self.akuvox_api_client.async_retrieve_user_data()
                    devices_json = self.akuvox_api_client.get_devices_json()
                    self.data.update(devices_json)

                    ################################
                    ### Create integration entry ###
                    ################################
                    return self.async_create_entry(
                        title=self.akuvox_api_client.get_title(),
                        data=self.data
                    )

                return self.async_show_form(
                    step_id="app_tokens_sign_in",
                    data_schema=vol.Schema(self.get_app_tokens_sign_in_schema()),
                    description_placeholders=user_input,
                    last_step=True,
                    errors={
                        "base": "Sign in failed. Please check the values entered and try again."
                    }
                )

            return self.async_show_form(
                step_id="app_tokens_sign_in",
                data_schema=vol.Schema(data_schema),
                description_placeholders=user_input,
                last_step=True,
                errors={
                    "base": "Please check the values enterted and try again."
                }
            )

        return self.async_show_form(
            step_id="app_tokens_sign_in",
            data_schema=vol.Schema(data_schema),
            description_placeholders=user_input,
            last_step=True,
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

    def get_sms_sign_in_schema(self):
        """Get the schema for sms_sign_in step."""
        return {
            vol.Required(
                "country_code",
                msg=None,
                default=DEFAULT_COUNTRY_CODE,  # type: ignore
                description="Your phone's international calling code prefix, eg: +1"): str,
            vol.Required(
                "phone_number",
                msg=None,
                default=DEFAULT_PHONE_NUMBER,  # type: ignore
                description="Your phone number"): str,
        }

    def get_app_tokens_sign_in_schema(self):
        """Get the schema for app_tokens_sign_in step."""
        return {
            vol.Required(
                "country_code",
                msg=None,
                default=DEFAULT_COUNTRY_CODE,  # type: ignore
                description="Your phone's international calling code prefix"): str,
            vol.Required(
                "phone_number",
                msg=None,
                default=DEFAULT_PHONE_NUMBER,  # type: ignore
                description="Your phone number"): str,
            vol.Required(
                "auth_token",
                msg=None,
                default=DEFAULT_APP_TOKEN,  # type: ignore
                description="Your SmartPlus account's auth_token string"): str,
            vol.Required(
                "token",
                msg=None,
                default=DEFAULT_TOKEN,  # type: ignore
                description="Your SmartPlus account's token string"): str,
        }

    def get_subdomain_from_country_code(self, country_code):
        """Correlate the subdomain to the user's country code number."""
        # Australia
        if country_code == "61":
            return "aucloud"
        # China
        if country_code == "86":
            return "ccloud"
        # Japan
        if country_code == "81":
            return "jcloud"
        if country_code == "7":
            return "rucloud"
        # Singapore
        if country_code == "65":
            return "scloud"
        # United States
        if country_code == "1":
            return "ucloud"
        # Europe
        return "ecloud"


class AkuvoxOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for Akuvox integration."""

    akuvox_api_client: AkuvoxApiClient = None  # type: ignore

    def __init__(self, config_entry: config_entries.ConfigEntry):
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """Initialize the options flow."""

        # Define the options schema
        config_options = dict(self.config_entry.options)
        config_data = dict(self.config_entry.data)

        event_screenshot_options = {
            "asap": "Receive events once generated, without waiting for camera screenshot URLs.",
            "wait": "Wait for camera screenshot URLs to become available before triggering the event (typically adds a delay of 0-3 seconds)."
        }
        options_schema = vol.Schema({
            vol.Required("override",
                         default=self.get_data_key_value("override", False) # type: ignore
            ): bool,
            vol.Optional("auth_token",
                         default=self.get_data_key_value("auth_token", False) # type: ignore
            ): str,
            vol.Optional("token",
                         default=self.get_data_key_value("token", False) # type: ignore
            ): str,
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

        wait_for_image_url = True if user_input.get("event_screenshot_options", "asap") == "wait" else False

        # Initialize the API client
        if self.akuvox_api_client is None:
            self.akuvox_api_client = AkuvoxApiClient(
                session=async_get_clientsession(self.hass),
                hass=self.hass,
                entry={
                    "configured" : {
                        "host": self.get_data_key_value("host", None),
                        "auth_token": self.get_data_key_value("auth_token", None),
                        "token": self.get_data_key_value("token", None),
                        "phone_number": self.get_data_key_value("phone_number", None),
                        "wait_for_image_url": wait_for_image_url
                    }
                }
            )

        # User wishes to use other SmartLife account tokens
        if user_input.get("override", False) is True:
            LOGGER.debug("Use custom token strings...")
            await self.akuvox_api_client.async_init_api_data()

            # Retrieve device data
            await self.akuvox_api_client.async_retrieve_user_data_with_tokens(
                user_input["auth_token"],
                user_input["token"])
            devices_json = self.akuvox_api_client.get_devices_json()
            if devices_json is not None and all(key in devices_json for key in (
                "camera_data",
                "door_relay_data",
                "door_keys_data")
            ):
                camera_data = devices_json["camera_data"]
                door_relay_data = devices_json["door_relay_data"]
                door_keys_data = devices_json["door_keys_data"]
                options_schema = vol.Schema({
                    vol.Required("override",
                                    default=config_options.get("override", None)): bool,
                    vol.Required("token", default=config_options.get("token", None)): str,
                    vol.Optional("camera_data", default=camera_data): dict,
                    vol.Optional("door_relay_data", default=door_relay_data): dict,
                    vol.Optional("door_keys_data", default=door_keys_data): dict,
                })
            else:
                data_schema = {
                    vol.Required(
                        "override",
                        msg=None,
                        default=user_input.get("override", False),
                        description={
                            "auth_token": f"Current auth_token: {config_data['auth_token']}",
                            "token": f"Current token: {config_data['token']}",
                        },
                    ): bool,
                    vol.Optional(
                        "auth_token",
                        msg=None,
                        default=user_input.get("auth_token", ""),
                        description="Your SmartPlus user's auth_token."
                    ): str,
                    vol.Optional(
                        "token",
                        msg=None,
                        default=user_input.get("token", ""),
                        description="Your SmartPlus user's token."
                    ): str,
                    vol.Required(
                        "wait_for_image_url",
                        msg=None,
                        default=bool(wait_for_image_url) # type: ignore
                    ): bool
                }
                return self.async_show_form(
                    step_id="init",
                    data_schema=vol.Schema(data_schema),
                    errors={"token": ("Unable to receive device list. Check your token.")}
                )

        # User input is valid, update the options
        LOGGER.debug("Updating configuration...")
        # user_input = None
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
