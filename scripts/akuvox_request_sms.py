#!/usr/bin/env python3
"""Utility script to trigger the Akuvox SMS login flow.

Example:
    python3 scripts/akuvox_request_sms.py --country-code 1 --phone 2121239876 --subdomain ucloud

It resolves the regional REST host and then calls `send_mobile_checkcode`
so the Akuvox backend sends a verification code to the configured phone.

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
SMS_ENDPOINT_PATH = "send_mobile_checkcode"


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
        # General placeholder replacement used in some API responses.
        rest_host = rest_host.replace(".subdomain.", f".{subdomain}.")

    return rest_host


def _trigger_sms(rest_host: str, country_code: str, phone: str) -> dict[str, Any]:
    """Invoke the `send_mobile_checkcode` endpoint for the given phone."""
    url = f"https://{rest_host}/{SMS_ENDPOINT_PATH}"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "VBell/6.61.2 (iPhone; iOS 16.6; Scale/3.00)",
        "Accept": "*/*",
        "Connection": "keep-alive",
        "x-cloud-lang": "en",
    }
    payload = {
        "AreaCode": country_code,
        "MobileNumber": phone,
        "Type": "0",
    }
    response = requests.post(url, headers=headers, data=payload, timeout=10)
    response.raise_for_status()
    return response.json()


def main() -> int:
    """CLI entry point for triggering the Akuvox SMS verification flow."""
    parser = argparse.ArgumentParser(
        description="Trigger the Akuvox SMS verification flow."
    )
    parser.add_argument(
        "--country-code",
        required=True,
        help="International dialing code (digits only), e.g. 1 for the US.",
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
    args = parser.parse_args()

    try:
        rest_host = _resolve_rest_host(args.subdomain)
        LOGGER.info("Resolved REST host: %s", rest_host)

        result = _trigger_sms(
            rest_host=rest_host,
            country_code=args.country_code,
            phone=args.phone,
        )
        LOGGER.info("SMS request response: %s", result)
        if str(result.get("err_code")) != "0":
            LOGGER.error("SMS request returned error payload: %s", result)
            return 1
        LOGGER.info("✅ SMS verification code requested successfully.")
        return 0
    except Exception as exc:  # pylint: disable=broad-except
        LOGGER.exception("Error while requesting SMS code: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
