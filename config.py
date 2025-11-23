# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 netcon-sync contributors
#
# This file is part of netcon-sync.
# netcon-sync is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""
Centralized configuration management for netcon-sync projects.

Environment variables are loaded and validated separately for UniFi and pfSense.
UniFi variables are required for all scripts. pfSense variables are optional.

Example (UniFi-only scripts like unifi_list_clients.py):
    from config import UNIFI_NETWORK_URL, UNIFI_USERNAME, UNIFI_PASSWORD, UNIFI_SITE_ID

Example (pfSense2UniFi sync scripts):
    from config import (
        UNIFI_NETWORK_URL, UNIFI_USERNAME, UNIFI_PASSWORD, UNIFI_SITE_ID,
        PFSENSE_URL, PFSENSE_APIV2_KEY, PFSENSE_DHCP_INTERFACE
    )
"""

import os
import sys


def _validate_unifi_config() -> dict:
    """
    Load and validate UniFi-specific environment variables.
    Required for all scripts.
    
    Returns:
        dict: Configuration dictionary with UniFi values
    
    Raises:
        ValueError: If required UniFi variables are missing
    """
    config = {
        "UNIFI_NETWORK_URL": os.getenv("UNIFI_NETWORK_URL"),
        "UNIFI_USERNAME": os.getenv("UNIFI_USERNAME"),
        "UNIFI_PASSWORD": os.getenv("UNIFI_PASSWORD"),
        "UNIFI_SITE_ID": os.getenv("UNIFI_SITE_ID", "default"),
    }
    
    missing_vars = [var for var in ["UNIFI_NETWORK_URL", "UNIFI_USERNAME", "UNIFI_PASSWORD"] 
                    if not config[var]]
    
    if missing_vars:
        raise ValueError(f"Missing required UniFi environment variables: {', '.join(missing_vars)}")
    
    return config


def _validate_pfsense_config() -> dict:
    """
    Load and validate pfSense-specific environment variables.
    Only required for pfSense sync scripts.
    
    Returns:
        dict: Configuration dictionary with pfSense values (None values allowed)
    
    Raises:
        ValueError: If required pfSense variables are missing
    """
    config = {
        "PFSENSE_URL": os.getenv("PFSENSE_URL"),
        "PFSENSE_APIV2_KEY": os.getenv("PFSENSE_APIV2_KEY"),
        "PFSENSE_DHCP_INTERFACE": os.getenv("PFSENSE_DHCP_INTERFACE", "lan"),
    }
    
    missing_vars = [var for var in ["PFSENSE_URL", "PFSENSE_APIV2_KEY"] if not config[var]]
    
    if missing_vars:
        raise ValueError(f"Missing required pfSense environment variables: {', '.join(missing_vars)}")
    
    return config


# Always load UniFi config (required for all scripts)
try:
    _unifi_config = _validate_unifi_config()
    UNIFI_NETWORK_URL = _unifi_config["UNIFI_NETWORK_URL"]
    UNIFI_USERNAME = _unifi_config["UNIFI_USERNAME"]
    UNIFI_PASSWORD = _unifi_config["UNIFI_PASSWORD"]
    UNIFI_SITE_ID = _unifi_config["UNIFI_SITE_ID"]
except ValueError as e:
    # Re-raise to let the importing script handle it with proper error display
    raise


# Load pfSense config only when explicitly requested
_pfsense_config = None
_pfsense_error = None


def load_pfsense_config():
    """
    Explicitly load and validate pfSense configuration.
    Call this from scripts that need pfSense access (e.g., pfsense2unifi.py).
    
    Returns:
        tuple: (PFSENSE_URL, PFSENSE_APIV2_KEY, PFSENSE_DHCP_INTERFACE)
    
    Raises:
        ValueError: If required pfSense variables are missing
    """
    global _pfsense_config, _pfsense_error
    if _pfsense_config is None and _pfsense_error is None:
        try:
            _pfsense_config = _validate_pfsense_config()
        except ValueError as e:
            _pfsense_error = str(e)
    if _pfsense_error:
        raise ValueError(_pfsense_error)
    return (_pfsense_config["PFSENSE_URL"], _pfsense_config["PFSENSE_APIV2_KEY"], _pfsense_config["PFSENSE_DHCP_INTERFACE"])


def print_config_summary():
    """
    Print a summary of loaded configuration (for debugging).
    Hides sensitive values like passwords and keys.
    """
    print("Configuration Summary:")
    print(f"  UNIFI_NETWORK_URL: {UNIFI_NETWORK_URL}")
    print(f"  UNIFI_SITE_ID: {UNIFI_SITE_ID}")
    print(f"  UNIFI_USERNAME: {UNIFI_USERNAME}")
    try:
        pfsense_url, _, pfsense_dhcp_interface = load_pfsense_config()
        print(f"  PFSENSE_URL: {pfsense_url}")
        print(f"  PFSENSE_DHCP_INTERFACE: {pfsense_dhcp_interface}")
    except ValueError:
        print("  (pfSense variables not configured)")
    print("  (Sensitive values hidden)")
