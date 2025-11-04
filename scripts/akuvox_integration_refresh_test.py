#!/usr/bin/env python3
"""
Manual integration-level test replicating the end-to-end Akuvox refresh flow.

Example:
    python3 scripts/akuvox_integration_refresh_test.py --country-code 1 --phone 2121239876 --subdomain ucloud --sms-code 123456

This uses the integration's own `AkuvoxApiClient` to:
1. Resolve the REST gateway for the supplied subdomain.
2. Exchange the SMS code for auth/refresh/session tokens.
3. Perform three refresh cycles, ensuring each rotates the token pair.
4. Trigger a door open action with the final session token.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, field
from pathlib import Path
import logging
import sys
from typing import Any, Dict, Tuple

import aiohttp
from homeassistant.core import HomeAssistant

# Ensure the repository root (containing custom_components) is importable.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from custom_components.akuvox.api import AkuvoxApiClient
from custom_components.akuvox.const import LOGGER

logging.basicConfig(level=logging.DEBUG)
LOGGER.setLevel(logging.DEBUG)


@dataclass
class _DummyEntry:
    """Minimal config entry stand-in for manual testing."""

    data: Dict[str, Any] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)


async def _run_flow(
    *,
    country_code: str,
    phone: str,
    subdomain: str,
    sms_code: str,
    refresh_count: int,
) -> Tuple[AkuvoxApiClient, Dict[str, Any]]:
    """
    Execute the integration's login, refresh, and door-open workflow.

    Returns the API client alongside the final door-open response.
    """
    config_dir = Path.cwd() / ".homeassistant_akuvox_test"
    config_dir.mkdir(parents=True, exist_ok=True)

    hass = HomeAssistant()
    loop = asyncio.get_running_loop()
    hass.loop = loop
    hass.config.config_dir = str(config_dir)
    hass.config.country = "US" if country_code == "1" else hass.config.country

    entry = _DummyEntry(
        data={
            "phone_number": phone,
            "subdomain": subdomain,
            "token": "",
            "auth_token": "",
            "refresh_token": "",
        },
        options={"override": False},
    )

    session = aiohttp.ClientSession()
    client = AkuvoxApiClient(session=session, hass=hass, entry=entry)
    client.init_api_with_data(
        hass=hass,
        subdomain=subdomain,
        phone_number=phone,
        auth_token="",
        token="",
    )
    client._data.subdomain = subdomain  # type: ignore[attr-defined]

    try:
        LOGGER.debug("🔍 Resolving REST server via integration client...")
        if not await client.async_fetch_rest_server():
            raise RuntimeError("Failed to resolve REST server.")

        LOGGER.debug("🔐 Performing SMS login via integration client...")
        login_response = await client.async_validate_sms_code(
            phone_number=phone,
            country_code=country_code,
            sms_code=sms_code,
        )
        if login_response is None:
            raise RuntimeError("SMS login failed.")

        client._data.parse_sms_login_response(login_response)  # type: ignore[attr-defined]
        await client._data.async_set_stored_data_for_key(
            "refresh_token", client._data.refresh_token
        )  # type: ignore[attr-defined]
        await client._data.async_set_stored_data_for_key("token", client._data.token)  # type: ignore[attr-defined]

        LOGGER.debug("📡 Retrieving initial device data via integration workflow...")
        if not await client.async_retrieve_user_data():
            raise RuntimeError("Failed to retrieve user data after login.")

        LOGGER.debug("🔁 Running %d refresh cycle(s)...", refresh_count)
        for idx in range(1, refresh_count + 1):
            if not await client.async_refresh_token():
                raise RuntimeError(f"Refresh #{idx} failed")
            LOGGER.debug(
                "Refresh #%d -> token=%s refresh_token=%s",
                idx,
                client._data.token,  # type: ignore[attr-defined]
                client._data.refresh_token,  # type: ignore[attr-defined]
            )

        if not client._data.door_relay_data:  # type: ignore[attr-defined]
            raise RuntimeError("No door relay data available after login.")

        door = client._data.door_relay_data[0]  # type: ignore[attr-defined]
        relay_mac = door["mac"]
        relay_id = str(door["relay_id"])
        door_name = door.get("door_name") or door.get("name", "Unknown door")

        host = client._data.host  # type: ignore[attr-defined]
        payload = f"mac={relay_mac}&relay={relay_id}"
        LOGGER.debug(
            "🚪 Opening door '%s' (mac=%s relay=%s)...", door_name, relay_mac, relay_id
        )
        # Execute the blocking call in a worker thread to mimic HA behavior.
        door_response = await hass.async_add_executor_job(
            lambda: client.make_opendoor_request(
                name=door_name,
                host=host,
                token=client._data.token,  # type: ignore[attr-defined]
                data=payload,
            )
        )

        return client, door_response or {}
    finally:
        await session.close()
        await hass.async_stop()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the Akuvox integration end-to-end refresh test.",
    )
    parser.add_argument("--country-code", required=True, help="Dialing code (e.g. 1).")
    parser.add_argument(
        "--phone", required=True, help="Plain phone number (digits only)."
    )
    parser.add_argument(
        "--subdomain", required=True, help="Akuvox deployment subdomain."
    )
    parser.add_argument(
        "--sms-code", required=True, help="SMS verification code from Akuvox."
    )
    parser.add_argument(
        "--refresh-count",
        type=int,
        default=3,
        help="Number of refresh iterations to perform (default: 3).",
    )
    args = parser.parse_args()

    try:
        client, door_response = asyncio.run(
            _run_flow(
                country_code=args.country_code,
                phone=args.phone,
                subdomain=args.subdomain,
                sms_code=args.sms_code,
                refresh_count=args.refresh_count,
            )
        )

        print("Final token state:")
        print(f"  token         = {client._data.token}")  # type: ignore[attr-defined]
        print(f"  refresh_token = {client._data.refresh_token}")  # type: ignore[attr-defined]
        print("Door open response:")
        print(door_response)

        if str(door_response.get("err_code")) != "0":
            print("Door open request failed.", file=sys.stderr)
            return 1

        print("✅ Integration refresh test completed successfully.")
        return 0
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Integration refresh test failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
