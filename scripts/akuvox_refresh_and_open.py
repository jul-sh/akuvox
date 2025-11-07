#!/usr/bin/env python3
"""Complete Akuvox login + refresh + door open workflow.

Example:
    python3 scripts/akuvox_refresh_and_open.py --country-code 1 --phone 2121239876 --subdomain ucloud --sms-code 123456

Steps performed:
1. Resolve the regional REST host and send `sms_login` with the supplied code.
2. Rotate the session token three times using the refresh API.
3. Fetch the device configuration to locate a door relay.
4. Issue an `opendoor` request using the latest token.

"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any

import requests

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)


REST_SERVER_ENDPOINT = "https://gate.{subdomain}.akuvox.com:8600/rest_server"
SMS_LOGIN_ENDPOINT = (
    "https://gate.{subdomain}.akuvox.com:8600/"
    "sms_login?phone={phone}&code={code}&area_code={area_code}"
)
REFRESH_ENDPOINT = "https://gate.{subdomain}.akuvox.com:8600/refresh_token"
USERCONF_PATH = "userconf"
OPENDOOR_PATH = "opendoor"


def _resolve_rest_host(subdomain: str) -> str:
    """Return the HTTPS rest host for the supplied subdomain."""
    url = REST_SERVER_ENDPOINT.format(subdomain=subdomain)
    headers = {
        "api-version": "6.0",
        "accept": "application/json",
    }
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()

    payload: dict[str, Any] = response.json()
    rest_host = (payload.get("datas") or {}).get("rest_server_https")
    if not rest_host:
        raise RuntimeError(f"rest_server response missing host: {payload}")

    if ".subdomain." in rest_host:
        rest_host = rest_host.replace(".subdomain.", f".{subdomain}.")

    return rest_host


def _obfuscate_phone(phone: str) -> str:
    """Apply Akuvox digit obfuscation (add 3 modulo 10)."""
    transformed = "".join(str((int(ch) + 3) % 10) for ch in phone)
    return transformed


def _perform_sms_login(
    subdomain: str, country_code: str, phone: str, sms_code: str
) -> tuple[str, str, str]:
    """Exchange SMS code for tokens."""
    obfuscated = _obfuscate_phone(phone)
    url = SMS_LOGIN_ENDPOINT.format(
        subdomain=subdomain,
        phone=obfuscated,
        code=sms_code,
        area_code=country_code,
    )
    headers = {
        "api-version": "6.6",
        "User-Agent": "VBell/6.61.2 (iPhone; iOS 16.6; Scale/3.00)",
        "accept": "application/json",
    }
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()

    payload: dict[str, Any] = response.json()
    if str(payload.get("result")) != "0":
        raise RuntimeError(f"sms_login failed: {payload}")

    datas = payload.get("datas") or {}
    auth_token = datas.get("auth_token")
    refresh_token = datas.get("refresh_token")
    token = datas.get("token")
    if not all([auth_token, refresh_token, token]):
        raise RuntimeError(f"Missing tokens in sms_login response: {payload}")

    return auth_token, refresh_token, token


def _refresh_tokens(subdomain: str, token: str, refresh_token: str) -> tuple[str, str]:
    """Call the refresh endpoint and return the rotated token pair."""
    headers = {
        "content-type": "application/json",
        "accept": "application/json",
        "accept-language": "en-US,en;q=0.9",
        "user-agent": "VBell/7.20.5 (iPhone; iOS 26.1; Scale/2.00)",
        "api-version": "6.8",
        "x-auth-token": token,
    }
    payload = {
        "refresh_token": refresh_token,
    }
    response = requests.post(
        REFRESH_ENDPOINT.format(subdomain=subdomain),
        headers=headers,
        json=payload,
        timeout=10,
    )
    response.raise_for_status()

    refresh_payload: dict[str, Any] = response.json()
    if str(refresh_payload.get("err_code")) != "0":
        raise RuntimeError(f"refresh_token failed: {refresh_payload}")

    datas = refresh_payload.get("datas") or {}
    new_refresh = datas.get("refresh_token")
    new_token = datas.get("token")
    if not new_refresh or not new_token:
        raise RuntimeError(f"refresh_token response missing data: {refresh_payload}")

    return new_token, new_refresh


def _fetch_door_target(rest_host: str, token: str) -> tuple[str, str]:
    """Retrieve the first available door relay target.

    Returns (mac, relay_id).
    """
    url = f"https://{rest_host}/{USERCONF_PATH}?token={token}"
    headers = {
        "Host": rest_host,
        "X-AUTH-TOKEN": token,
        "Connection": "keep-alive",
        "api-version": "6.5",
        "Accept": "*/*",
        "User-Agent": "VBell/6.61.2 (iPhone; iOS 16.6; Scale/3.00)",
        "Accept-Language": "en-AU;q=1, he-AU;q=0.9, ru-RU;q=0.8",
        "x-cloud-lang": "en",
    }
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()

    payload: dict[str, Any] = response.json()
    if str(payload.get("err_code")) != "0":
        raise RuntimeError(f"userconf failed: {payload}")

    datas = payload.get("datas") or {}
    for dev in datas.get("dev_list", []):
        for relay in dev.get("relay", []):
            mac = dev.get("mac")
            relay_id = relay.get("relay_id")
            if mac and relay_id is not None:
                return mac, str(relay_id)

    raise RuntimeError("No door relay found in user configuration.")


def _open_door(rest_host: str, token: str, mac: str, relay: str) -> dict[str, Any]:
    """Invoke the `opendoor` endpoint."""
    url = f"https://{rest_host}/{OPENDOOR_PATH}?token={token}"
    headers = {
        "Host": rest_host,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-AUTH-TOKEN": token,
        "api-version": "4.3",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Accept": "*/*",
        "User-Agent": "VBell/6.61.2 (iPhone; iOS 16.6; Scale/3.00)",
        "Accept-Language": "en-AU;q=1, he-AU;q=0.9, ru-RU;q=0.8",
        "x-cloud-lang": "en",
    }
    payload = {
        "mac": mac,
        "relay": relay,
    }
    response = requests.post(url, headers=headers, data=payload, timeout=10)
    response.raise_for_status()
    return response.json()


def main() -> int:
    """CLI entry point for refreshing tokens and opening an Akuvox door."""
    parser = argparse.ArgumentParser(
        description="Complete the Akuvox login flow, refresh tokens, and open a door."
    )
    parser.add_argument(
        "--country-code",
        required=True,
        help="International dialing code (digits only).",
    )
    parser.add_argument(
        "--phone",
        required=True,
        help="Plain phone number (digits only).",
    )
    parser.add_argument(
        "--subdomain",
        required=True,
        help="Akuvox deployment subdomain (e.g. ucloud, ecloud).",
    )
    parser.add_argument(
        "--sms-code",
        required=True,
        help="SMS verification code received from Akuvox.",
    )
    parser.add_argument(
        "--door-mac",
        help="Optional door MAC address to open; defaults to the first available.",
    )
    parser.add_argument(
        "--door-relay",
        help="Optional door relay id to open; defaults to the first available.",
    )
    args = parser.parse_args()

    try:
        rest_host = _resolve_rest_host(args.subdomain)
        LOGGER.info("Resolved REST host: %s", rest_host)

        auth_token, refresh_token, token = _perform_sms_login(
            subdomain=args.subdomain,
            country_code=args.country_code,
            phone=args.phone,
            sms_code=args.sms_code,
        )
        LOGGER.info("Login tokens acquired:")
        LOGGER.info("  auth_token    = %s", auth_token)
        LOGGER.info("  refresh_token = %s", refresh_token)
        LOGGER.info("  token         = %s", token)

        for idx in range(1, 4):
            token, refresh_token = _refresh_tokens(
                subdomain=args.subdomain,
                token=token,
                refresh_token=refresh_token,
            )
            LOGGER.info(
                "Refresh #%d -> token=%s, refresh_token=%s",
                idx,
                token,
                refresh_token,
            )

        mac: str | None = args.door_mac
        relay: str | None = args.door_relay

        if not mac or relay is None:
            mac, relay = _fetch_door_target(rest_host=rest_host, token=token)
            LOGGER.info("Selected door relay mac=%s relay=%s", mac, relay)

        response = _open_door(
            rest_host=rest_host,
            token=token,
            mac=mac,
            relay=relay,
        )
        LOGGER.info("Door open response: %s", response)
        if str(response.get("err_code")) != "0":
            LOGGER.error("Door open request failed with payload: %s", response)
            return 1
        LOGGER.info("✅ Door opened successfully with the refreshed token.")
        return 0
    except Exception as exc:  # pylint: disable=broad-except
        LOGGER.exception("Workflow failed: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
