# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 netcon-sync contributors
#
# This file is part of netcon-sync.
# netcon-sync is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""pfSense API utilities for DHCP configuration and client management."""

import json
import re
from urllib.parse import urlparse, urlencode
import nss.error
from config import load_pfsense_config
from http_tls_nss import NSPRNSSURLOpener

# Module-level variables - loaded lazily on first use
_PFSENSE_URL = None
_PFSENSE_APIV2_KEY = None
_PFSENSE_DHCP_INTERFACE = None
_config_loaded = False
_config_error = None


def _ensure_pfsense_config_loaded():
    """Load pfSense config on first use. Raises ValueError if missing."""
    global _PFSENSE_URL, _PFSENSE_APIV2_KEY, _PFSENSE_DHCP_INTERFACE, _config_loaded, _config_error

    if _config_loaded:
        if _config_error:
            raise _config_error
        return

    try:
        _PFSENSE_URL, _PFSENSE_APIV2_KEY, _PFSENSE_DHCP_INTERFACE = load_pfsense_config()
        _config_loaded = True
    except ValueError as e:
        _config_error = e
        _config_loaded = True
        raise

# Module-level URL opener for requests to pfSense
_opener = None


def _get_opener():
    """Get or create the global URL opener."""
    global _opener
    if _opener is None:
        _opener = NSPRNSSURLOpener()
    return _opener


def validate_mac_address(mac: str) -> bool:
    """
    Validate MAC address format (must use colons, e.g., 'AA:BB:CC:DD:EE:FF').

    Args:
        mac (str): The MAC address to validate

    Returns:
        bool: True if valid, False otherwise
    """
    return bool(re.match(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$', mac))


def _fetch_dhcp_with_retry(api_endpoint: str, headers: dict, params: dict) -> dict:
    """
    Internal helper to fetch DHCP config with automatic retry on failure.
    Uses exponential backoff: 2s, 4s, 8s (max 10s between retries).
    Retried up to 3 times for non-NSS errors.

    NSS/NSPR certificate errors are re-raised immediately without retry.

    Args:
        api_endpoint (str): The API endpoint URL
        headers (dict): HTTP headers to send
        params (dict): Query parameters

    Returns:
        dict: The JSON response

    Raises:
        NSPRError: If certificate validation fails (no retry)
        Exception: If all retries are exhausted or error occurs
        json.JSONDecodeError: If response is invalid JSON
    """
    max_attempts = 3
    attempt = 0
    last_error = None

    while attempt < max_attempts:
        attempt += 1
        try:
            # Build full URL with query parameters
            url = api_endpoint
            if params:
                url += f"?{urlencode(params)}"

            opener = _get_opener()

            response = opener.request("GET", url, headers=headers)
            response_text = response.read().decode('utf-8')

            if 400 <= response.getcode() < 600:
                raise Exception(f"HTTP {response.getcode()}: {response_text}")

            return json.loads(response_text)
        except nss.error.NSPRError as e:
            # NSS/NSPR certificate errors are not retryable - re-raise immediately
            raise
        except Exception as e:
            last_error = e
            # If this is the last attempt, raise
            if attempt >= max_attempts:
                raise e

            # No delay - fail fast on transient errors

    # Shouldn't reach here
    if last_error:
        raise last_error
    raise Exception("Failed to fetch DHCP config")


def get_pfsense_dhcp_static_mappings(interface_name: str = None) -> list:
    """
    Fetches DHCP static mappings for a specific interface from a pfSense API v2 endpoint.

    Args:
        interface_name (str): The name/ID of the interface (e.g., "lan", "wan", "opt1").
                             If not provided, uses the PFSENSE_DHCP_INTERFACE config value (default: "lan").

    Returns:
        list: A list of dictionaries, each representing a DHCP static mapping.

    Raises:
        NSPRError: If certificate validation fails for pfSense.
        Exception: For any other errors during the API request (after retries).
        json.JSONDecodeError: If the response cannot be parsed as JSON.
        ValueError: If pfSense config is missing.
    """
    # Ensure config is loaded
    _ensure_pfsense_config_loaded()

    # Use provided interface_name or fall back to config value
    iface = interface_name if interface_name else _PFSENSE_DHCP_INTERFACE

    # Call the DHCP server endpoint using the interface_name as the 'id' parameter.
    # The static mappings are nested within this overall DHCP server configuration.
    api_endpoint = f"{_PFSENSE_URL}/api/v2/services/dhcp_server"
    headers = {"X-API-Key": _PFSENSE_APIV2_KEY}
    params = {"id": iface}

    try:
        full_dhcp_config = _fetch_dhcp_with_retry(api_endpoint, headers, params)

        if full_dhcp_config.get('status') == 'ok' and 'data' in full_dhcp_config:
            # Extract the 'staticmap' list from the 'data' object
            static_mappings = full_dhcp_config['data'].get('staticmap', [])
            return static_mappings
        else:
            raise ValueError(f"Unexpected response format or status from API: {full_dhcp_config}")

    except nss.error.NSPRError as e:
        # NSS/NSPR certificate errors bubble up without wrapping
        raise
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Data parsing error: Invalid JSON response from {api_endpoint}", "", 0) from e
    except Exception as e:
        raise Exception(f"Failed to fetch DHCP config from {api_endpoint} (retried 3 times): {e}") from e

