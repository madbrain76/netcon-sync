# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 netcon-sync contributors
#
# This file is part of netcon-sync.
# netcon-sync is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""UniFi Controller API utilities for client management and authentication."""

import datetime
import socket
import json
import re
import sys
import nss.error
from config import UNIFI_NETWORK_URL, UNIFI_USERNAME, UNIFI_PASSWORD, UNIFI_SITE_ID
from http_tls_nss import NSPRNSSURLOpener

# Module-level URL opener for session state across requests
_opener = None


def _get_opener():
    """Get or create the global URL opener."""
    global _opener
    if _opener is None:
        _opener = NSPRNSSURLOpener()
    return _opener


def cleanup():
    """Close the opener. Call this on application shutdown."""
    global _opener
    if _opener is not None:
        _opener = None


def validate_mac_address(mac: str) -> bool:
    """
    Validate MAC address format (must use colons, e.g., 'AA:BB:CC:DD:EE:FF').
    
    Args:
        mac (str): The MAC address to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    return bool(re.match(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$', mac))


def _check_env_vars() -> None:
    """
    Checks if essential UniFi environment variables are set.
    Configuration is already validated when config.py is imported,
    so this is now just a compatibility check.
    """
    if not all([UNIFI_NETWORK_URL, UNIFI_USERNAME, UNIFI_PASSWORD, UNIFI_SITE_ID]):
        raise ValueError("UniFi configuration incomplete. Check config.py for details.")


def _is_retryable_error(exc):
    """Check if an exception is retryable. NSS errors are not retryable."""
    return not isinstance(exc, nss.error.NSPRError)


def make_unifi_api_call(method: str, endpoint: str, return_raw: bool = False, **kwargs):
    """
    Handles common UniFi API request logic, including URL construction,
    error handling, and JSON parsing. Automatically retries on failure with exponential backoff.
    
    Does NOT retry NSS/NSPR certificate errors - these are raised immediately.
    
    Session state is delegated to NSPRNSSURLOpener (transparent to caller).
    Certificate validation uses NSS database.

    Args:
        method (str): HTTP method (e.g., "GET", "POST", "PUT").
        endpoint (str): The specific API endpoint (e.g., "/api/login", "/api/s/{site_id}/rest/user").
        return_raw (bool): If True, return raw bytes instead of parsing JSON (for binary downloads).
        **kwargs: Additional keyword arguments (headers, json, data, etc.)

    Returns:
        dict or bytes: The JSON response data (dict) or raw bytes if return_raw=True.

    Raises:
        NSPRError: For NSS/NSPR certificate validation errors (no retry).
        Exception: For network or API errors (after 3 retries).
    """
    max_attempts = 3
    attempt = 0
    last_error = None
    
    while attempt < max_attempts:
        attempt += 1
        try:
            opener = _get_opener()
            url = f"{UNIFI_NETWORK_URL}{endpoint}"
            
            # Prepare headers
            headers = kwargs.get('headers', {}).copy() if 'headers' in kwargs else {}
            
            # Prepare body
            body = kwargs.get('body')
            json_data = kwargs.get('json')
            
            if json_data:
                headers['Content-Type'] = 'application/json'
                body = json.dumps(json_data).encode('utf-8')
            
            # opener.request handles session state internally
            response = opener.request(method, url, data=body, headers=headers)
            
            # Read response data
            response_bytes = response.read()
            
            # Check HTTP status
            if 400 <= response.getcode() < 600:
                error_msg = response_bytes.decode('utf-8', errors='replace')
                raise Exception(f"HTTP {response.getcode()}: {error_msg}")
            
            # Return raw bytes if requested (for binary downloads)
            if return_raw:
                return response_bytes
            
            # Parse and return JSON response
            response_text = response_bytes.decode('utf-8')
            response_data = json.loads(response_text) if response_text else {}
            return response_data.get("data", {}) if "stat" in endpoint or "rest" in endpoint or "cmd" in endpoint else response_data
            
        except nss.error.NSPRError as e:
            # NSS/NSPR errors are not retryable - raise immediately
            raise
        except Exception as e:
            last_error = e
            # Check if this error is retryable
            if not _is_retryable_error(e):
                raise
            
            # If this is the last attempt, raise the error
            if attempt >= max_attempts:
                raise Exception(f"Network or API error during {method} {endpoint}: {e}")
            
            # No delay - fail fast on transient errors
    
    # Shouldn't reach here, but just in case
    if last_error:
        raise Exception(f"Network or API error during {method} {endpoint}: {last_error}")
    raise Exception(f"Network or API error during {method} {endpoint}: Unknown error")


def login() -> None:
    """
    Logs into the UniFi controller and establishes a session.
    Raises an exception if login fails or required environment variables are missing.
    """
    _check_env_vars()

    login_url = "/api/login"
    login_data = {"username": UNIFI_USERNAME, "password": UNIFI_PASSWORD}
    
    make_unifi_api_call("POST", login_url, json=login_data)


def get_devices() -> list:
    """
    Retrieves all devices (APs, switches, gateways, etc.) for the configured site.
    
    Returns:
        list: List of device dictionaries, including type, MAC, name, IP, and other properties.
    """
    endpoint = f"/api/s/{UNIFI_SITE_ID}/stat/device"
    
    try:
        devices_data = make_unifi_api_call("GET", endpoint)
        return devices_data if isinstance(devices_data, list) else []
    except Exception as e:
        print(f"Error retrieving devices: {e}", file=__import__('sys').stderr)
        return []


def _derive_band_from_channel(channel) -> str:
    """
    Derive WiFi band (2.4, 5, 6) from channel number.
    """
    if channel == "N/A" or channel == "":
        return "N/A"
    try:
        ch = int(channel)
        if 1 <= ch <= 14:
            return "2.4"
        elif 36 <= ch <= 165:
            return "5"
        elif 1 <= ch <= 233:  # 6 GHz band
            return "6"
    except (ValueError, TypeError):
        pass
    return "N/A"


def _derive_wifi_generation_from_proto(proto) -> str:
    """
    Derive WiFi generation (1-7) from protocol string.
    Proto values from UniFi: 'a', 'b', 'g', 'n', 'ac', 'ax', 'be', 'ng', 'na', etc.
    
    The proto value reflects what the CLIENT is actually using, not AP capabilities.
    The actual band (2.4/5/6 GHz) is determined by the channel, not the proto.
    
    Proto mappings:
    'a'  = 802.11a (WiFi 2, 5 GHz only)
    'b'  = 802.11b (WiFi 1, 2.4 GHz only)
    'g'  = 802.11g (WiFi 3, 2.4 GHz only)
    'n'  = 802.11n (WiFi 4, can operate on 2.4 or 5 GHz)
    'ng' = 802.11n (WiFi 4, explicitly 2.4 GHz)
    'na' = 802.11n (WiFi 4, explicitly 5 GHz)
    'ac' = 802.11ac (WiFi 5, 5 GHz only)
    'ax' = 802.11ax (WiFi 6, can operate on 2.4, 5, or 6 GHz)
    'be' = 802.11be (WiFi 7, can operate on 2.4, 5, or 6 GHz)
    """
    if not proto or proto == "N/A":
        return "N/A"
    
    proto_lower = str(proto).lower()
    
    # Map protocol to WiFi generation (numerical only)
    proto_map = {
        "a": "2",
        "b": "1",
        "g": "3",
        "n": "4",
        "ng": "4",      # 802.11n on 2.4GHz
        "na": "4",      # 802.11n on 5GHz
        "ac": "5",
        "ax": "6",
        "be": "7",
    }
    
    return proto_map.get(proto_lower, "N/A")


def _derive_ieee_version_from_proto(proto) -> str:
    """
    Derive IEEE 802.11 version from protocol string.
    Proto values from UniFi: 'a', 'b', 'g', 'n', 'ac', 'ax', 'be', 'ng', 'na', etc.
    
    The actual band (2.4/5/6 GHz) is determined by the channel, not the proto.
    802.11n, 802.11ax, and 802.11be can operate on multiple bands.
    """
    if not proto or proto == "N/A":
        return "N/A"
    
    proto_lower = str(proto).lower()
    
    # Map protocol to IEEE version
    ieee_map = {
        "a": "802.11a",
        "b": "802.11b",
        "g": "802.11g",
        "n": "802.11n",
        "ng": "802.11n",     # 802.11n on 2.4GHz
        "na": "802.11n",     # 802.11n on 5GHz
        "ac": "802.11ac",
        "ax": "802.11ax",
        "be": "802.11be",
    }
    
    return ieee_map.get(proto_lower, "N/A")


def get_unifi_clients_fast() -> dict:
    """
    Fast lightweight fetch of UniFi clients WITHOUT DNS lookups.
    Returns a simple dict mapping MAC -> raw client data.
    For batch operations that don't need display formatting.
    """
    all_known_clients = make_unifi_api_call("GET", f"/api/s/{UNIFI_SITE_ID}/rest/user")
    return {client.get("mac", "").lower(): client for client in all_known_clients if "mac" in client}


def get_all_unifi_clients() -> list:
    """
    Fetches and processes all known and currently connected clients from the UniFi controller,
    including signal strength, connected AP name, connected AP MAC for live clients,
    and AP locking status.
    """
    processed_clients = []

    # Fetch all known clients (contains configured fixed AP and general client info)
    all_known_clients = make_unifi_api_call("GET", f"/api/s/{UNIFI_SITE_ID}/rest/user")

    # Fetch live connected clients (contains active fixed AP status, current IP, signal, etc.)
    live_clients_data = make_unifi_api_call("GET", f"/api/s/{UNIFI_SITE_ID}/stat/sta")
    
    # Fetch UniFi devices (APs) to map MACs to names
    devices_data = make_unifi_api_call("GET", f"/api/s/{UNIFI_SITE_ID}/stat/device")
    
    # Create a map from AP MAC (lowercase) to AP Name for easy lookup
    ap_mac_to_name_map = {}
    for device in devices_data:
        if device.get("type") == "uap" and device.get("mac"):
            normalized_device_mac = device["mac"].lower()
            ap_name = device.get("name") or device.get("model", "Unnamed AP")
            ap_mac_to_name_map[normalized_device_mac] = ap_name

    # Create a map from client MAC (lowercase) to live client data for efficient lookups
    live_clients_map = {client["mac"].lower(): client for client in live_clients_data if "mac" in client}
    # Create a map from client MAC (lowercase) to known client data (from rest/user) for efficient lookups
    known_clients_map = {client["mac"].lower(): client for client in all_known_clients if "mac" in client}


    for client in all_known_clients: # Iterate through all known clients for comprehensive list
        mac = client.get("mac")
        if not mac:
            continue
        
        normalized_mac = mac.lower()

        # Start with a copy of the raw client data from /rest/user for display purposes
        merged_client = client.copy()
        
        # Initialize fields to default/N/A for consistent display
        merged_client["is_connected_live"] = False
        merged_client["live_ip"] = "N/A"
        merged_client["live_ap_mac"] = "N/A"
        merged_client["connected_ap_name"] = "N/A"
        merged_client["live_signal"] = "N/A"
        merged_client["live_uptime"] = "N/A"
        merged_client["live_channel"] = "N/A"
        merged_client["live_band"] = "N/A"
        merged_client["live_wifi_generation"] = "N/A"
        merged_client["live_ieee_version"] = "N/A"
        merged_client["live_ssid"] = "N/A"
        merged_client["is_ap_locked"] = False
        merged_client["locked_ap_name"] = "N/A"
        merged_client["locked_ap_mac"] = "N/A"
        merged_client["tx_retries"] = "N/A" # Raw tx_retries for sorting/filtering
        merged_client["tx_retries_display"] = "N/A" # Formatted for display

        live_data = live_clients_map.get(normalized_mac)

        if live_data:
            merged_client["is_connected_live"] = True
            merged_client["live_ip"] = live_data.get("ip")
            merged_client["live_signal"] = live_data.get("signal")
            merged_client["live_uptime"] = live_data.get("uptime")
            merged_client["tx_retries"] = live_data.get("tx_retries", "N/A")
            merged_client["tx_retries_display"] = str(live_data.get("tx_retries")) if live_data.get("tx_retries") is not None else "N/A"
            merged_client["live_channel"] = live_data.get("channel", "N/A")
            merged_client["live_ssid"] = live_data.get("essid", live_data.get("ssid", "N/A"))
            
            # Derive band, WiFi generation, and IEEE version from channel and proto
            channel = live_data.get("channel", "N/A")
            proto = live_data.get("radio_proto", "N/A")  # e.g., "a", "b", "g", "n", "ac", "ax", "be", "ng", "na"
            
            merged_client["live_band"] = _derive_band_from_channel(channel)
            merged_client["live_wifi_generation"] = _derive_wifi_generation_from_proto(proto)
            merged_client["live_ieee_version"] = _derive_ieee_version_from_proto(proto)
            
            live_ap_mac = live_data.get("ap_mac")
            if live_ap_mac:
                merged_client["live_ap_mac"] = live_ap_mac
                resolved_ap_name = ap_mac_to_name_map.get(live_ap_mac.lower(), "Unknown AP")
                merged_client["connected_ap_name"] = resolved_ap_name
            else:
                merged_client["live_ap_mac"] = "N/A"
                merged_client["connected_ap_name"] = "N/A"

            if live_data.get("last_seen"):
                merged_client["last_seen"] = live_data["last_seen"]
            
            # Use live data for AP locking status if client is online
            # Note: 'fixed_ap_enabled' comes from /stat/sta, 'ap_fixed' from /rest/user
            if live_data.get("fixed_ap_enabled"):
                merged_client["is_ap_locked"] = True
                live_fixed_ap_mac = live_data.get("fixed_ap_mac")
                if live_fixed_ap_mac:
                    merged_client["locked_ap_mac"] = live_fixed_ap_mac.upper() # Store the MAC
                    merged_client["locked_ap_name"] = ap_mac_to_name_map.get(live_fixed_ap_mac.lower(), "Unknown AP (Locked - Live)")
                else:
                    merged_client["locked_ap_name"] = "Unknown AP (Locked - Live, MAC Missing)"
        else:
            # If client is offline, still check for fixed AP configuration from known_clients (rest/user)
            # Note: UniFi uses 'ap_fixed' boolean and 'fixed_ap_mac' string in rest/user endpoint
            if client.get("ap_fixed"): # This flag indicates if it's configured to be locked
                merged_client["is_ap_locked"] = True
                configured_fixed_ap_mac = client.get("fixed_ap_mac")
                if configured_fixed_ap_mac:
                    merged_client["locked_ap_mac"] = configured_fixed_ap_mac.upper() # Store the MAC
                    merged_client["locked_ap_name"] = ap_mac_to_name_map.get(configured_fixed_ap_mac.lower(), "Configured AP (Offline)")


        # Determine IP address for display/DNS lookup
        ip_address = "N/A"
        if merged_client.get("is_connected_live"):
            ip_address = merged_client.get("live_ip", "N/A")
        else:
            ip_address = client.get("ip", "N/A") # Fallback to known IP if not live

        if ip_address == "0.0.0.0":
            ip_address = "N/A"
        merged_client["display_ip"] = ip_address

        # Perform reverse DNS lookup
        dns_name = "N/A"
        if ip_address != "N/A":
            try:
                dns_name = socket.gethostbyaddr(ip_address)[0]
            except (socket.herror, socket.gaierror):
                dns_name = "No reverse DNS"
            except Exception as dns_e:
                dns_name = f"DNS Error: {dns_e}"
        merged_client["dns_name"] = dns_name

        # Process last seen timestamp
        last_seen_str = "N/A"
        # Prioritize live_data's last_seen if available, otherwise use known_client's
        last_seen_timestamp_ms = live_data.get("last_seen") if live_data else client.get("last_seen")
        
        if isinstance(last_seen_timestamp_ms, (int, float)):
            try:
                if last_seen_timestamp_ms > 100000000000: # Check if timestamp is in milliseconds
                    dt_object = datetime.datetime.fromtimestamp(last_seen_timestamp_ms / 1000)
                    last_seen_str = dt_object.strftime('%Y-%m-%d %H:%M:%S')
                elif last_seen_timestamp_ms > 0: # Assume seconds if smaller but still positive
                    dt_object = datetime.datetime.fromtimestamp(last_seen_timestamp_ms)
                    last_seen_str = dt_object.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    last_seen_str = "Not Seen Recently"
            except (TypeError, ValueError):
                last_seen_str = "Timestamp Error"
        merged_client["last_seen_formatted"] = last_seen_str
        
        # Add description logic
        description = client.get("name")
        if not description or description == client.get("hostname"):
            description = client.get("note")
        if not description:
            description = "No description set in UniFi"
        merged_client["description"] = description

        processed_clients.append(merged_client)

    # Sort clients:
    processed_clients.sort(key=lambda c: (
        (c.get("dns_name", "zzzzzz").lower() if c.get("dns_name") not in ["N/A", "No reverse DNS"] else "zzzzzz"),
        c.get("hostname", "").lower(),
        c.get("mac", "").lower()
    ))

    return processed_clients

def _get_single_client_data_by_mac(client_mac: str) -> dict | None:
    """
    Internal helper to fetch the full RAW data for a single client from the /rest/user endpoint.
    """
    all_clients_data = make_unifi_api_call("GET", f"/api/s/{UNIFI_SITE_ID}/rest/user")

    for client in all_clients_data:
        if client.get("mac") and client.get("mac").lower() == client_mac.lower():
            return client
    return None


def get_client_id_by_mac(client_mac: str) -> str | None:
    """
    Retrieves a client's internal _id from their MAC address by fetching all known clients.
    This _id is required for PUT operations on client properties.
    """
    client_data = _get_single_client_data_by_mac(client_mac)
    return client_data.get("_id") if client_data else None


def get_ap_mac_by_name(ap_name: str) -> str | None:
    """
    Retrieves an AP's MAC address from its name.
    """
    devices_data = make_unifi_api_call("GET", f"/api/s/{UNIFI_SITE_ID}/stat/device")

    for device in devices_data:
        # Check 'name' first, then 'model' if 'name' is missing, then fallback to MAC itself
        current_ap_name = device.get("name") or device.get("model")
        if current_ap_name and current_ap_name.lower() == ap_name.lower() and device.get("mac"):
            return device["mac"]
    return None


def build_client_payload(original_client_data: dict) -> dict:
    """
    Constructs a clean payload for UniFi client PUT requests,
    including only the essential and writable fields, specifically targeting
    what seems to be allowed by the /rest/user endpoint for updates.
    This version aligns closely with the provided working script's payload structure.
    """
    payload = {
        "_id": original_client_data.get("_id"),
        "display_name": original_client_data.get("display_name", original_client_data.get("hostname") or original_client_data.get("mac", "Unnamed Client")),
        "local_dns_record_enabled": original_client_data.get("local_dns_record_enabled", False),
        "local_dns_record": original_client_data.get("local_dns_record", ""),
        "virtual_network_override_enabled": original_client_data.get("virtual_network_override_enabled", False),
        "virtual_network_override_id": original_client_data.get("virtual_network_override_id", ""),
        "usergroup_id": original_client_data.get("usergroup_id", ""),
        "use_fixedip": original_client_data.get("use_fixedip", False),
        "fixed_ip": original_client_data.get("fixed_ip", ""),
        "fixed_ap_enabled": original_client_data.get("fixed_ap_enabled", False)
        # 'fixed_ap_mac' is NOT included here by default. It will be added by lock_client_to_ap,
        # and explicitly removed/omitted by unlock_client_from_ap.
        # 'ap_fixed' is read-only and is NOT included.
        # 'note' is not included to align with the working script's unlock payload.
    }

    # Conditionally add 'name' if it exists in the original data, replicating the working script's logic
    if original_client_data.get("name"):
        payload["name"] = original_client_data["name"]

    # Cleanup: handle None and empty string values for various fields
    for key, value in list(payload.items()): # Use list() to avoid RuntimeError: dictionary changed size during iteration
        if value is None:
            # Pop keys that should be absent rather than null, or set to default if applicable
            # Boolean fields where None means False
            if key in ["local_dns_record_enabled", "virtual_network_override_enabled", "use_fixedip", "fixed_ap_enabled"]:
                payload[key] = False
            # String fields where None means empty string
            elif key in ["fixed_ip", "local_dns_record", "virtual_network_override_id", "usergroup_id", "name", "display_name"]:
                payload[key] = ""
            # _id should always be present and not None. If it is, something's wrong.
            elif key == "_id":
                pass # _id is critical and should be handled by the caller if missing
            else:
                payload.pop(key) # Remove any other unexpected None fields
        # Ensure empty strings for string fields that might otherwise be just whitespace
        elif isinstance(value, str) and value.strip() == "":
            payload[key] = ""
        
    # Re-evaluate display_name if it became empty after cleanup (e.g., if original was None or empty)
    if not payload.get("display_name"):
        if original_client_data.get("name"):
            payload["display_name"] = original_client_data["name"]
        elif original_client_data.get("hostname"):
            payload["display_name"] = original_client_data["hostname"]
        else:
            payload["display_name"] = original_client_data.get("mac", "Unnamed Client")

    # Critical: If use_fixedip is false, ensure fixed_ip is an empty string
    if not payload.get("use_fixedip"):
        payload["fixed_ip"] = ""

    return payload


def lock_client_to_ap(client_mac: str, ap_mac: str) -> bool:
    """
    Locks a specific client (by MAC address) to a specific AP (by MAC address)
    using a PUT request to the /rest/user endpoint. Sets fixed_ap_mac and fixed_ap_enabled to true.
    """
    original_client_data = _get_single_client_data_by_mac(client_mac)
    if not original_client_data:
        return False

    client_id = original_client_data.get("_id")
    if not client_id:
        return False

    endpoint = f"/api/s/{UNIFI_SITE_ID}/rest/user/{client_id}"
    
    payload = build_client_payload(original_client_data)

    # Specific changes for locking:
    payload["fixed_ap_mac"] = ap_mac.lower() # Add the specific AP MAC for locking
    payload["fixed_ap_enabled"] = True # Set to true for locking

    try:
        make_unifi_api_call("PUT", endpoint, json=payload)
        return True
    except (Exception, json.JSONDecodeError):
        return False

def unlock_client_from_ap(client_mac: str) -> bool:
    """
    Unlocks a specific client (by MAC address) from a fixed AP using a PUT request
    to the /rest/user endpoint. Sets fixed_ap_enabled to false and ensures fixed_ap_mac is omitted.
    """
    original_client_data = _get_single_client_data_by_mac(client_mac)
    if not original_client_data:
        return False

    client_id = original_client_data.get("_id")
    if not client_id:
        return False

    endpoint = f"/api/s/{UNIFI_SITE_ID}/rest/user/{client_id}"
    
    payload = build_client_payload(original_client_data)
    
    # Specific changes for unlocking:
    # CRITICAL: fixed_ap_mac MUST BE ABSENT, not null, for unlock to work.
    if "fixed_ap_mac" in payload:
        del payload["fixed_ap_mac"]    

    payload["fixed_ap_enabled"] = False # Set to false for unlocking

    try:
        make_unifi_api_call("PUT", endpoint, json=payload)
        return True
    except (Exception, json.JSONDecodeError):
        return False

def forget_client(mac: str) -> bool:
    """
    Instructs the UniFi controller to "forget" a client by its MAC address.
    Forgetting a client removes it from the known client list and history.
    
    Args:
        mac (str): The MAC address of the client to forget (e.g., "11:22:33:44:55:66").

    Returns:
        bool: True if the client was successfully forgotten, False otherwise.
    """
    if not mac:
        return False

    endpoint = f"/api/s/{UNIFI_SITE_ID}/cmd/stamgr"
    # UniFi API for 'forget-sta' typically expects 'macs' to be a list, even for a single MAC.
    payload = {"cmd": "forget-sta", "macs": [mac.lower()]}    

    try:
        # Use make_unifi_api_call for consistency
        make_unifi_api_call("POST", endpoint, json=payload)
        return True
    except (Exception, json.JSONDecodeError):
        return False

def forget_clients_batch(macs: list) -> dict:
    """
    Instructs the UniFi controller to "forget" multiple clients in a single API call.
    This is much faster than calling forget_client() repeatedly.
    
    UniFi's forget-sta command sometimes silently fails for certain client types or states,
    especially those without descriptions. If batch delete fails or devices still exist,
    falls back to individual forget calls.
    
    Args:
        macs (list): List of MAC addresses to forget (e.g., ["11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"]).
    
    Returns:
        dict: Results with keys:
            - "total": Total MAC addresses provided
            - "sent": Number of MACs sent to the controller
            - "success": True if all clients were successfully forgotten
    """
    results = {"total": len(macs), "sent": 0, "success": False}
    
    if not macs:
        return results
    
    # Filter out empty strings and convert to lowercase
    mac_list = [mac.lower() for mac in macs if mac]
    results["sent"] = len(mac_list)
    
    if not mac_list:
        return results
    
    endpoint = f"/api/s/{UNIFI_SITE_ID}/cmd/stamgr"
    payload = {"cmd": "forget-sta", "macs": mac_list}
    
    try:
        # Try batch forget first (faster)
        make_unifi_api_call("POST", endpoint, json=payload)
        
        # Verify that the clients were actually forgotten
        # Some UniFi versions silently fail for certain device types
        remaining_clients = get_unifi_clients_fast()
        remaining_macs = {mac.lower() for mac in remaining_clients.keys()}
        
        still_present = [mac for mac in mac_list if mac in remaining_macs]
        
        if still_present:
            # Batch delete didn't work for some devices, fall back to individual deletes
            import sys
            print(f"[WARN] Batch forget incomplete ({len(still_present)} devices still exist), falling back to individual forgets...", file=sys.stderr)
            
            success_count = 0
            for mac in still_present:
                try:
                    if forget_client(mac):
                        success_count += 1
                except Exception:
                    pass
            
            # If all were deleted now, mark as success
            if success_count == len(still_present):
                results["success"] = True
            else:
                # Some still couldn't be deleted
                results["success"] = False
        else:
            # Batch delete succeeded, all clients are gone
            results["success"] = True
            
        return results
        
    except (Exception, json.JSONDecodeError) as e:
        # If batch call itself fails, fall back to individual forgets
        import sys
        print(f"[WARN] Batch forget failed ({e}), falling back to individual forgets...", file=sys.stderr)
        
        success_count = 0
        for mac in mac_list:
            try:
                if forget_client(mac):
                    success_count += 1
            except Exception:
                pass
        
        # If at least most succeeded, mark as success
        if success_count == len(mac_list):
            results["success"] = True
        return results

def block_client(mac: str) -> bool:
    """
    Blocks a specific client (by MAC address) from the UniFi network.
    This prevents the client from associating with any UniFi APs.

    Args:
        mac (str): The MAC address of the client to block (e.g., "11:22:33:44:55:66").

    Returns:
        bool: True if the client was successfully blocked, False otherwise.
    """
    if not mac:
        return False

    endpoint = f"/api/s/{UNIFI_SITE_ID}/cmd/stamgr"
    # The 'block-sta' command expects a single 'mac' parameter.
    payload = {"cmd": "block-sta", "mac": mac.lower()}

    try:
        # Use make_unifi_api_call for consistency
        make_unifi_api_call("POST", endpoint, json=payload)
        return True
    except (Exception, json.JSONDecodeError):
        # Catches network errors, connection failures, or bad JSON responses
        return False

def unblock_client(mac: str) -> bool:
    """
    Unblocks a previously blocked client (by MAC address) on the UniFi network.
    This allows the client to reauthenticate and connect.

    Args:
        mac (str): The MAC address of the client to unblock (e.g., "11:22:33:44:55:66").

    Returns:
        bool: True if the client was successfully unblocked, False otherwise.
    """
    if not mac:
        return False

    endpoint = f"/api/s/{UNIFI_SITE_ID}/cmd/stamgr"
    # The 'unblock-sta' command expects a single 'mac' parameter.
    payload = {"cmd": "unblock-sta", "mac": mac.lower()}

    try:
        # Use make_unifi_api_call for consistency
        make_unifi_api_call("POST", endpoint, json=payload)
        return True
    except (Exception, json.JSONDecodeError):
        # Catches network errors, connection failures, or bad JSON responses
        return False

def reconnect_client(mac: str) -> bool:
    """
    Forces a specific client (by MAC address) to reconnect to the UniFi network.
    This is achieved by sending a "kick-sta" command, which disconnects the client,
    prompting it to reauthenticate and reassociate.

    Args:
        mac (str): The MAC address of the client to reconnect (e.g., "11:22:33:44:55:66").

    Returns:
        bool: True if the client was successfully kicked (and should attempt to reconnect), False otherwise.
    """
    if not mac:
        return False

    endpoint = f"/api/s/{UNIFI_SITE_ID}/cmd/stamgr"
    # The 'kick-sta' command expects a single 'mac' parameter.
    payload = {"cmd": "kick-sta", "mac": mac.lower()}

    try:
        # Use make_unifi_api_call for consistency
        make_unifi_api_call("POST", endpoint, json=payload)
        return True
    except (Exception, json.JSONDecodeError):
        return False

def add_client(mac: str, name: str | None = None, note: str | None = None) -> bool:
    """
    Adds or updates a client record in the UniFi controller's "Known Clients" list.
    This is equivalent to manually adding a client via the UI.
    If a client with the given MAC already exists, its 'name' and 'note' will be updated.
    If the client does not exist, a new entry will be created.

    Args:
        mac (str): The MAC address of the client to add/update (e.g., "11:22:33:44:55:66").
                   Must use colon delimiters. This is a required field.
        name (str | None): The name to assign to the client. If None, the existing name
                           will be kept if updating, or no name will be set if new.
        note (str | None): A descriptive note for the client. If None, the existing note
                           will be kept if updating, or no note will be set if new.

    Returns:
        bool: True if the API call succeeded (client was sent to UniFi), False otherwise.
              Note: This does not verify the client was actually created. Use batch verification
              at the end of a sync for better performance.
    """
    import sys
    
    if not mac:
        print("Error: MAC address is required to add/update a client.", file=sys.stderr)
        return False
    
    # Validate MAC address format
    if not validate_mac_address(mac):
        print(f"Error: Invalid MAC address format: '{mac}'. Must use colon delimiters (e.g., 'AA:BB:CC:DD:EE:FF').", file=sys.stderr)
        return False

    normalized_mac = mac.lower()
    
    # First, try to get existing client data to see if it's an update or new creation
    existing_client = _get_single_client_data_by_mac(normalized_mac)

    endpoint = f"/api/s/{UNIFI_SITE_ID}/rest/user"

    if existing_client:
        # This is an update operation (PUT request)
        client_id = existing_client.get("_id")
        if not client_id:
            print(f"Error: Existing client with MAC {mac} found, but no _id. Cannot update.", file=sys.stderr)
            return False
        
        endpoint = f"/api/s/{UNIFI_SITE_ID}/rest/user/{client_id}"
        method = "PUT"
        
        # Start with the existing data and apply updates
        payload = build_client_payload(existing_client) # Use the existing build_client_payload
                                                         # to ensure consistent payload structure
        
        # Apply new name and note, respecting None
        if name is not None:
            payload["name"] = name
            payload["display_name"] = name # UniFi often uses 'display_name' for the primary label
        if note is not None:
            payload["note"] = note
            
    else:
        # This is a new client creation (POST request)
        method = "POST"
        payload = {
            "mac": normalized_mac,
            "blocked": False, # Default to not blocked
            "display_name": name if name is not None else "", # Use name as display_name if provided
            "name": name if name is not None else "",
            "note": note if note is not None else "",
            # Other fields can be set to their defaults or omitted
            "usergroup_id": "",
            "use_fixedip": False,
            "fixed_ip": "",
            "local_dns_record_enabled": False,
            "local_dns_record": "",
            "virtual_network_override_enabled": False,
            "virtual_network_override_id": "",
            "fixed_ap_enabled": False # Not locked to AP by default
        }
        # Clean up empty strings for properties that should be omitted if empty
        for key in ["name", "display_name", "note", "fixed_ip", "local_dns_record", "virtual_network_override_id", "usergroup_id"]:
            if payload.get(key) == "":
                payload.pop(key)
        
    try:
        make_unifi_api_call(method, endpoint, json=payload)
        return True
    except (Exception, json.JSONDecodeError) as e:
        print(f"Failed to add/update client {mac}: {e}", file=sys.stderr)
        return False

def restart_ap(ap_mac: str) -> bool:
    """
    Restarts a specific access point (by MAC address).
    
    Args:
        ap_mac (str): The MAC address of the AP to restart (e.g., "aa:bb:cc:dd:ee:ff").
    
    Returns:
        bool: True if the restart command was successfully sent, False otherwise.
    """
    if not ap_mac:
        return False
    
    endpoint = f"/api/s/{UNIFI_SITE_ID}/cmd/devmgr"
    # The 'restart' command expects a single 'mac' parameter
    payload = {"cmd": "restart", "mac": ap_mac.lower()}
    
    try:
        response = make_unifi_api_call("POST", endpoint, json=payload)
        return True
    except (Exception, json.JSONDecodeError):
        return False


def get_ssids() -> list:
    """
    Fetches all wireless networks (SSIDs) configured in UniFi.
    
    Returns:
        list: A list of SSID objects, each containing:
            - _id: UniFi ID
            - name: SSID name
            - enabled: True if enabled, False if disabled
            - security: Security mode
            - Other UniFi WLAN configuration fields
    """
    try:
        endpoint = f"/api/s/{UNIFI_SITE_ID}/rest/wlanconf"
        return make_unifi_api_call("GET", endpoint)
    except Exception:
        return []


def disable_ssid(ssid_name: str) -> bool:
    """
    Disables a wireless network (SSID) by name.
    
    Args:
        ssid_name (str): The name of the SSID to disable.
    
    Returns:
        bool: True if the SSID was successfully disabled, False otherwise.
    """
    if not ssid_name:
        return False
    
    try:
        # Get all SSIDs
        ssids = get_ssids()
        
        # Find matching SSID (case-insensitive)
        matching_ssid = None
        for ssid in ssids:
            if ssid.get("name", "").lower() == ssid_name.lower():
                matching_ssid = ssid
                break
        
        if not matching_ssid:
            return False
        
        # Check if already disabled
        if not matching_ssid.get("enabled", True):
            return True  # Already disabled
        
        # Update SSID with enabled=false
        ssid_id = matching_ssid.get("_id")
        if not ssid_id:
            return False
        
        endpoint = f"/api/s/{UNIFI_SITE_ID}/rest/wlanconf/{ssid_id}"
        payload = matching_ssid.copy()
        payload["enabled"] = False
        
        make_unifi_api_call("PUT", endpoint, json=payload)
        return True
        
    except (Exception, json.JSONDecodeError):
        return False


def enable_ssid(ssid_name: str) -> bool:
    """
    Enables a wireless network (SSID) by name.
    
    Args:
        ssid_name (str): The name of the SSID to enable.
    
    Returns:
        bool: True if the SSID was successfully enabled, False otherwise.
    """
    if not ssid_name:
        return False
    
    try:
        # Get all SSIDs
        ssids = get_ssids()
        
        # Find matching SSID (case-insensitive)
        matching_ssid = None
        for ssid in ssids:
            if ssid.get("name", "").lower() == ssid_name.lower():
                matching_ssid = ssid
                break
        
        if not matching_ssid:
            return False
        
        # Check if already enabled
        if matching_ssid.get("enabled", False):
            return True  # Already enabled
        
        # Update SSID with enabled=true
        ssid_id = matching_ssid.get("_id")
        if not ssid_id:
            return False
        
        endpoint = f"/api/s/{UNIFI_SITE_ID}/rest/wlanconf/{ssid_id}"
        payload = matching_ssid.copy()
        payload["enabled"] = True
        
        make_unifi_api_call("PUT", endpoint, json=payload)
        return True
        
    except (Exception, json.JSONDecodeError):
        return False


def disable_ap(ap_mac: str) -> bool:
    """
    Disables an access point by MAC address.
    Sets the device's disabled flag to prevent it from being managed.
    
    Args:
        ap_mac (str): The MAC address of the AP to disable (e.g., "aa:bb:cc:dd:ee:ff").
    
    Returns:
        bool: True if the AP was successfully disabled, False otherwise.
    """
    if not ap_mac:
        return False
    
    try:
        # Get all devices
        devices = get_devices()
        
        # Find matching AP (case-insensitive MAC)
        matching_ap = None
        target_mac_lower = ap_mac.lower().replace(':', '').replace('-', '')
        for device in devices:
            if device.get("type") == "uap":
                device_mac = device.get("mac", "").lower().replace(':', '').replace('-', '')
                if device_mac == target_mac_lower:
                    matching_ap = device
                    break
        
        if not matching_ap:
            return False
        
        # Check if already disabled
        if matching_ap.get("disabled", False):
            return True  # Already disabled
        
        # Update device with disabled=true
        device_id = matching_ap.get("_id")
        if not device_id:
            return False
        
        endpoint = f"/api/s/{UNIFI_SITE_ID}/rest/device/{device_id}"
        payload = matching_ap.copy()
        payload["disabled"] = True
        
        make_unifi_api_call("PUT", endpoint, json=payload)
        return True
        
    except (Exception, json.JSONDecodeError):
        return False


def enable_ap(ap_mac: str) -> bool:
    """
    Enables an access point by MAC address.
    Clears the device's disabled flag to allow it to be managed.
    
    Args:
        ap_mac (str): The MAC address of the AP to enable (e.g., "aa:bb:cc:dd:ee:ff").
    
    Returns:
        bool: True if the AP was successfully enabled, False otherwise.
    """
    if not ap_mac:
        return False
    
    try:
        # Get all devices
        devices = get_devices()
        
        # Find matching AP (case-insensitive MAC)
        matching_ap = None
        target_mac_lower = ap_mac.lower().replace(':', '').replace('-', '')
        for device in devices:
            if device.get("type") == "uap":
                device_mac = device.get("mac", "").lower().replace(':', '').replace('-', '')
                if device_mac == target_mac_lower:
                    matching_ap = device
                    break
        
        if not matching_ap:
            return False
        
        # Check if already enabled
        if not matching_ap.get("disabled", False):
            return True  # Already enabled
        
        # Update device with disabled=false
        device_id = matching_ap.get("_id")
        if not device_id:
            return False
        
        endpoint = f"/api/s/{UNIFI_SITE_ID}/rest/device/{device_id}"
        payload = matching_ap.copy()
        payload["disabled"] = False
        
        make_unifi_api_call("PUT", endpoint, json=payload)
        return True
        
    except (Exception, json.JSONDecodeError):
        return False


def _get_ap_state_description(state):
    """Convert AP state to human-readable description. 
    Note: get_ap_state() now returns strings directly, but this function
    provides backward compatibility for integer codes if needed.
    """
    if isinstance(state, str):
        # If already a string from get_ap_state(), return as-is
        return state
    
    # Backward compatibility for integer state codes
    state_map = {
        0: "DISCONNECTED",
        1: "CONNECTING/INITIALIZING",
        2: "CONNECTED (but not fully ready)",
        3: "RUNNING",
    }
    return state_map.get(state, f"UNKNOWN")


def get_ap_state(ap_mac: str) -> str:
    """
    Get the current state of an AP by MAC address.
    Uses intelligent inference from multiple fields (adoption, upgrade status, uptime).
    
    The controller sets upgrade_triggered_by to the username when a user initiates an upgrade.
    This reliably distinguishes UPGRADING from UPGRADABLE states.
    
    Args:
        ap_mac (str): The MAC address of the AP
        
    Returns:
        str: AP state description:
             - "UPGRADING": upgrade_triggered_by is set (user initiated upgrade)
             - "UPGRADABLE": upgradable=true but not triggered
             - "RUNNING": adopted and has uptime
             - "DISCONNECTED": not adopted
             - "UNKNOWN": AP not found
    """
    try:
        devices = get_devices()
        target_mac_lower = ap_mac.lower().replace(':', '').replace('-', '')
        
        for device in devices:
            if device.get("type") == "uap":
                device_mac = device.get("mac", "").lower().replace(':', '').replace('-', '')
                if device_mac == target_mac_lower:
                    # Check if AP is adopted (adopted=true means it's connected to controller)
                    is_adopted = device.get("adopted", False)
                    if not is_adopted:
                        return "DISCONNECTED"
                    
                    # Check version-based state (ignore upgrade_triggered_by, it's unreliable)
                    current_version = device.get("version")
                    target_version = device.get("upgrade_to_firmware")
                    upgrade_progress = device.get("upgrade_progress")
                    upgrade_state = device.get("upgrade_state")
                    upgradable = device.get("upgradable", False)
                    
                    # 1. If versions differ, check if actively upgrading or just available
                    if current_version and target_version and current_version != target_version:
                        # Check for active upgrade activity
                        if (upgrade_progress and upgrade_progress > 0) or (upgrade_state and upgrade_state > 0):
                            return "UPGRADING"
                        # Otherwise just available
                        if upgradable:
                            return "UPGRADABLE"
                    
                    # 2. Versions match, check if upgradable (shouldn't happen, but just in case)
                    if upgradable:
                        return "UPGRADABLE"
                    
                    # 3. Check uptime - if uptime > 0, AP is running normally
                    uptime_seconds = device.get("uptime", 0)
                    if uptime_seconds and uptime_seconds > 0:
                        return "RUNNING"
                    
                    # 4. Check if recently seen (within last 30 seconds)
                    import time
                    current_time = time.time()
                    last_seen = device.get("last_seen", 0)
                    if last_seen and (current_time - last_seen) < 30:
                        return "RUNNING"
                    
                    # 5. If adopted but no uptime/recent activity, might be initializing
                    if is_adopted:
                        return "CONNECTING/INITIALIZING"
                    
                    return "DISCONNECTED"
        
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def check_ap_health_before_upgrade(aps_to_upgrade: list, max_wait_seconds: int = 300) -> dict:
    """
    Pre-upgrade health check: Verify all APs are in a state ready for upgrade.
    
    Checks that all APs are either idle (RUNNING, no active upgrade) or already upgrading.
    APs already upgrading are returned separately so they are NOT re-initiated.
    If any AP is in "CONNECTING/INITIALIZING" state (getting ready), waits for it to
    transition to RUNNING state before proceeding.
    
    Args:
        aps_to_upgrade (list): List of AP dicts with at least 'mac' and 'name' fields
        max_wait_seconds (int): Maximum time to wait for APs to reach RUNNING state (default 300s = 5 min)
    
    Returns:
        dict: {
            "success": bool,
            "ready_aps": list of APs ready for NEW upgrade (in original order),
            "already_upgrading": list of APs already upgrading (should not re-initiate),
            "unhealthy_aps": list of APs that never reached RUNNING state or in bad states,
            "message": str describing the result
        }
    """
    import time
    
    if not aps_to_upgrade:
        return {
            "success": True,
            "healthy_aps": [],
            "unhealthy_aps": [],
            "message": "No APs to check"
        }
    
    print("\n[PRE-UPGRADE HEALTH CHECK]")
    print(f"Verifying {len(aps_to_upgrade)} AP(s) are ready for upgrade...\n")
    
    # Get full device list to check upgrade states
    all_devices = get_devices()
    device_map = {}  # MAC -> full device dict
    for device in all_devices:
        if device.get("type") == "uap":
            device_map[device.get("mac", "").lower()] = device
    
    # Track status by MAC address to preserve original order in final result
    ap_status = {}  # MAC -> {'ap': ap_dict, 'category': 'ready'|'already_upgrading'|'unhealthy'|'waiting'}
    aps_needing_wait = []
    
    # First pass: identify which APs need waiting
    for ap in aps_to_upgrade:
        ap_mac = ap.get("mac")
        ap_name = ap.get("name") or ap.get("model", "Unknown AP")
        
        if not ap_mac:
            continue
        
        # Get full device data to check upgrade state
        device = device_map.get(ap_mac.lower())
        if not device:
            print(f"  [WARN] {ap_name}: Device not found")
            ap_status[ap_mac] = {'ap': ap, 'category': 'unhealthy'}
            continue
        
        # Check if already upgrading
        # Mark as upgrading if upgrade_progress > 0 (actively downloading/installing)
        # We don't check upgrade_to_firmware here because it can be set from previous attempts
        upgrade_progress = device.get("upgrade_progress", 0)
        current_version = device.get("version", "")
        upgrade_to_version = device.get("upgrade_to_firmware", "")
        
        is_already_upgrading = upgrade_progress and upgrade_progress > 0
        
        if is_already_upgrading:
            # Store the upgrade details in the AP dict for later display
            ap_status[ap_mac] = {'ap': ap, 'category': 'already_upgrading'}
            
            ap_state = get_ap_state(ap_mac)
            print(f"  [SKIP] {ap_name}: Already upgrading (state={ap_state}, progress={upgrade_progress}%)")
            # Mark as already upgrading - DO NOT re-initiate upgrades on these
            continue
        
        # Check if adopted and has uptime (means it's running)
        is_adopted = device.get("adopted", False)
        uptime_seconds = device.get("uptime", 0)
        
        if not is_adopted:
            print(f"  [WARN] {ap_name}: Not adopted (disconnected)")
            ap_status[ap_mac] = {'ap': ap, 'category': 'unhealthy'}
        elif uptime_seconds and uptime_seconds > 0:
            print(f"  [OK] {ap_name}: RUNNING (ready for upgrade)")
            ap_status[ap_mac] = {'ap': ap, 'category': 'ready'}
        else:
            # Adopted but no uptime - likely initializing
            print(f"  [WAIT] {ap_name}: INITIALIZING (waiting to be ready...)")
            ap_status[ap_mac] = {'ap': ap, 'category': 'waiting'}
            aps_needing_wait.append(ap_mac)
    
    # If any APs are still initializing, wait for them
    if aps_needing_wait:
        print(f"\nWaiting for {len(aps_needing_wait)} AP(s) to complete initialization (max {max_wait_seconds}s)...\n")
        
        start_time = time.time()
        
        while aps_needing_wait and (time.time() - start_time) < max_wait_seconds:
            still_waiting = []
            
            # Re-fetch device data to get latest upgrade states
            all_devices = get_devices()
            device_map = {}
            for device in all_devices:
                if device.get("type") == "uap":
                    device_map[device.get("mac", "").lower()] = device
            
            for ap_mac in aps_needing_wait:
                ap = ap_status[ap_mac]['ap']
                ap_name = ap.get("name") or ap.get("model", "Unknown AP")
                
                device = device_map.get(ap_mac.lower())
                if not device:
                    print(f"  [FAIL] {ap_name}: Device not found")
                    ap_status[ap_mac]['category'] = 'unhealthy'
                    continue
                
                elapsed = int(time.time() - start_time)
                
                # Check if it started upgrading while waiting
                # Mark as upgrading if upgrade_progress > 0 (actively downloading/installing)
                upgrade_progress = device.get("upgrade_progress", 0)
                current_version = device.get("version", "")
                upgrade_to_version = device.get("upgrade_to_firmware", "")
                
                is_upgrading = upgrade_progress and upgrade_progress > 0
                
                if is_upgrading:
                    print(f"  [SKIP] {ap_name}: Started upgrading while waiting ({elapsed}s)")
                    ap_status[ap_mac]['category'] = 'already_upgrading'
                    continue
                
                # Check if it now has uptime (ready to upgrade)
                uptime_seconds = device.get("uptime", 0)
                
                if uptime_seconds and uptime_seconds > 0:
                    print(f"  [OK] {ap_name}: Ready ({elapsed}s)")
                    ap_status[ap_mac]['category'] = 'ready'
                else:
                    # Still waiting for uptime
                    still_waiting.append(ap_mac)
            
            aps_needing_wait = still_waiting
            
            if aps_needing_wait:
                # Print status line (without newline) to show waiting
                ap_names = ", ".join(ap_status[mac]['ap'].get("name") or ap_status[mac]['ap'].get("model", "Unknown") for mac in aps_needing_wait)
                elapsed = int(time.time() - start_time)
                print(f"  Still waiting: {ap_names} ({elapsed}s of {max_wait_seconds}s)...", end="\r", flush=True)
                time.sleep(5)
        
        # Clear the waiting message line
        if aps_needing_wait:
            print("  " * 50, end="\r")  # Clear the line
        
        # Any remaining APs that didn't transition are considered unhealthy
        if aps_needing_wait:
            ap_names = ", ".join(ap_status[mac]['ap'].get("name") or ap_status[mac]['ap'].get("model", "Unknown") for mac in aps_needing_wait)
            print(f"  [TIMEOUT] {ap_names} did not reach RUNNING state after {max_wait_seconds}s")
            for ap_mac in aps_needing_wait:
                ap_status[ap_mac]['category'] = 'unhealthy'
    
    print()  # Blank line for readability
    
    # Build result lists preserving original order
    ready_aps = []
    already_upgrading = []
    unhealthy_aps = []
    
    for ap in aps_to_upgrade:
        ap_mac = ap.get("mac")
        if ap_mac in ap_status:
            category = ap_status[ap_mac]['category']
            if category == 'ready':
                ready_aps.append(ap)
            elif category == 'already_upgrading':
                already_upgrading.append(ap)
            else:
                unhealthy_aps.append(ap)
    
    # Summary
    if unhealthy_aps:
        ap_names = ", ".join(ap.get("name") or ap.get("model", "Unknown") for ap in unhealthy_aps)
        return {
            "success": False,
            "ready_aps": ready_aps,
            "already_upgrading": already_upgrading,
            "unhealthy_aps": unhealthy_aps,
            "message": f"Health check failed: {len(unhealthy_aps)} AP(s) not ready for upgrade: {ap_names}"
        }
    else:
        total_healthy = len(ready_aps) + len(already_upgrading)
        msg = f"Health check passed: {len(ready_aps)} ready for upgrade"
        if already_upgrading:
            msg += f", {len(already_upgrading)} already upgrading"
        return {
            "success": True,
            "ready_aps": ready_aps,
            "already_upgrading": already_upgrading,
            "unhealthy_aps": [],
            "message": msg
        }


def check_ap_upgrade_status(ap_mac: str) -> dict:
    """
    Check the upgrade status and health of an AP.
    Useful for debugging why an upgrade might have failed.
    
    Args:
        ap_mac (str): The MAC address of the AP to check
    
    Returns:
        dict: Diagnostic information about the AP's upgrade status
    """
    try:
        devices = get_devices()
        matching_ap = None
        target_mac_lower = ap_mac.lower().replace(':', '').replace('-', '')
        
        for device in devices:
            if device.get("type") == "uap":
                device_mac = device.get("mac", "").lower().replace(':', '').replace('-', '')
                if device_mac == target_mac_lower:
                    matching_ap = device
                    break
        
        if not matching_ap:
            return {
                "found": False,
                "message": f"AP with MAC {ap_mac} not found"
            }
        
        ap_name = matching_ap.get("name") or matching_ap.get("model", "Unknown AP")
        ap_state = matching_ap.get("state")
        
        diagnostics = {
            "found": True,
            "name": ap_name,
            "mac": matching_ap.get("mac"),
            "current_version": matching_ap.get("version"),
            "upgrade_to_firmware": matching_ap.get("upgrade_to_firmware"),
            "upgradable": matching_ap.get("upgradable"),
            "state": ap_state,
            "state_description": _get_ap_state_description(ap_state),
            "adopted": matching_ap.get("adopted"),
            "uptime_seconds": matching_ap.get("uptime"),
            "uptime_days": matching_ap.get("uptime", 0) // 86400 if matching_ap.get("uptime") else 0,
            "last_seen": matching_ap.get("last_seen"),
            "model": matching_ap.get("model"),
            "serial": matching_ap.get("serial"),
        }
        
        # Check for potential issues
        issues = []
        
        # State should be RUNNING
        if ap_state != "RUNNING":
            issues.append(f"AP is not in RUNNING state (current: {ap_state}). AP may need to finish boot/initialization before upgrade.")
        
        if not matching_ap.get("adopted"):
            issues.append("AP is not adopted by the controller")
        
        if not matching_ap.get("upgradable"):
            issues.append("AP is marked as not upgradable")
        
        # Check if firmware is same as upgrade_to_firmware (already upgraded)
        if matching_ap.get("version") == matching_ap.get("upgrade_to_firmware"):
            issues.append("AP version matches upgrade_to_firmware (may already be upgraded or same version)")
        
        diagnostics["issues"] = issues
        return diagnostics
        
    except Exception as e:
        return {
            "found": False,
            "message": f"Error checking AP status: {e}"
        }


def upgrade_ap_firmware(ap_mac: str, dry_run: bool = False, skip_health_check: bool = False) -> dict:
    """
    Upgrades the firmware on an access point to the latest version available
    for its configured firmware channel in the controller.
    
    Args:
        ap_mac (str): The MAC address of the AP to upgrade (e.g., "aa:bb:cc:dd:ee:ff").
        dry_run (bool): If True, show what would be upgraded without actually upgrading.
                       Defaults to False.
        skip_health_check (bool): If True, skip checking if AP is in a healthy state.
                                 Used for retries when an upgrade was dropped by the controller.
                                 Defaults to False.
    
    Returns:
        dict: A dictionary containing:
            - "success" (bool): Whether the operation succeeded
            - "current_version" (str): Current firmware version
            - "new_version" (str): New firmware version (if available)
            - "message" (str): Status message
    """
    if not ap_mac:
        return {
            "success": False,
            "current_version": None,
            "new_version": None,
            "message": "No AP MAC address provided"
        }
    
    try:
        # Get all devices
        devices = get_devices()
        
        # Find matching AP (case-insensitive MAC)
        matching_ap = None
        target_mac_lower = ap_mac.lower().replace(':', '').replace('-', '')
        for device in devices:
            if device.get("type") == "uap":
                device_mac = device.get("mac", "").lower().replace(':', '').replace('-', '')
                if device_mac == target_mac_lower:
                    matching_ap = device
                    break
        
        if not matching_ap:
            return {
                "success": False,
                "current_version": None,
                "new_version": None,
                "message": f"AP with MAC {ap_mac} not found"
            }
        
        # Extract current firmware version and AP name
        # Try multiple field names for firmware version (UniFi uses "version" in device objects)
        current_version = matching_ap.get("version") or matching_ap.get("firmware") or matching_ap.get("fw_version")
        if not current_version:
            current_version = "Unknown"
        
        ap_name = matching_ap.get("name") or matching_ap.get("model", "Unnamed AP")
        upgrade_to_firmware = matching_ap.get("upgrade_to_firmware")
        
        # Check if an upgrade is already actively in progress (version mismatch + active progress)
        # We check is_ap_actively_upgrading() instead of just upgrade_triggered_by because
        # the latter is unreliable (persists across channel switches and other operations)
        if is_ap_actively_upgrading(ap_mac):
            # AP already has an external upgrade in progress - don't re-initiate
            # But return success so it can be monitored by the upgrade loop
            return {
                "success": True,
                "current_version": current_version,
                "new_version": upgrade_to_firmware,  # Return the target version for monitoring
                "message": f"{ap_name} already upgrading externally - monitoring only",
                "skip_initiation": True  # Flag to indicate we didn't send an upgrade command
            }
        
        # Get the firmware channel (default to "release" if not set)
        firmware_channel = matching_ap.get("fw_channel") or matching_ap.get("update_channel", "release")
        
        # Fetch available firmware information from the controller
        try:
            firmware_data = make_unifi_api_call("GET", f"/api/s/{UNIFI_SITE_ID}/stat/firmware")
        except Exception as e:
            # If firmware endpoint doesn't work, use device's upgrade_to_firmware field instead
            firmware_data = []
        
        # Find the latest firmware for this AP model/channel
        device_model = matching_ap.get("model", "")
        new_version = None
        
        # Handle different response formats from firmware endpoint
        if isinstance(firmware_data, dict):
            # Sometimes firmware_data might be wrapped differently
            if "_id" in firmware_data:
                # Single firmware entry
                firmware_list = [firmware_data]
            else:
                firmware_list = firmware_data.get("firmware", []) if isinstance(firmware_data, dict) else []
        elif isinstance(firmware_data, list):
            firmware_list = firmware_data
        else:
            firmware_list = []
        
        # Try to find matching firmware by model and channel
        if firmware_list:
            for fw in firmware_list:
                fw_model = fw.get("model", "")
                fw_channel = fw.get("channel", "release")
                
                # Match by model and channel
                if fw_model == device_model and fw_channel == firmware_channel:
                    new_version = fw.get("version")
                    break
        
        # If we couldn't find firmware info from the controller, try using device's upgrade_to_firmware field
        # This field is populated by UniFi when an upgrade is available
        if not new_version and upgrade_to_firmware:
            new_version = upgrade_to_firmware
        
        # If we still couldn't find firmware info from the controller, assume already on latest
        if not new_version:
            # When no upgrade is available, set new_version to current_version
            # This way display logic will show "(already latest)"
            new_version = current_version
        
        # Check if already on the latest version
        if current_version == new_version:
            return {
                "success": True,
                "current_version": current_version,
                "new_version": new_version,
                "message": f"{ap_name} is already on the latest firmware version {current_version}"
            }
        
        # Handle dry run
        if dry_run:
            return {
                "success": True,
                "current_version": current_version,
                "new_version": new_version,
                "message": f"[DRY RUN] {ap_name} ({ap_mac}): Would upgrade from {current_version} to {new_version}"
            }
        
        # Perform the actual firmware upgrade
        endpoint = f"/api/s/{UNIFI_SITE_ID}/cmd/devmgr"
        payload = {
            "cmd": "upgrade",
            "mac": ap_mac.lower()
        }
        
        try:
            response = make_unifi_api_call("POST", endpoint, json=payload)
            
            # Valid responses are:
            # - Empty list [] (common for device commands like upgrade/restart)
            # - Dict with rc="ok"
            is_valid_response = (
                isinstance(response, list) and len(response) == 0 or
                isinstance(response, dict) and response.get("rc") == "ok"
            )
            
            if not is_valid_response:
                return {
                    "success": False,
                    "current_version": current_version,
                    "new_version": new_version,
                    "message": f"Failed to initiate firmware upgrade for {ap_name}: API returned unexpected response - {response}"
                }
            
            return {
                "success": True,
                "current_version": current_version,
                "new_version": new_version,
                "message": f"{ap_name} ({ap_mac}): Firmware upgrade initiated from {current_version} to {new_version}"
            }
        except Exception as e:
            # Some UniFi controllers return HTTP 400 after successfully queuing the upgrade
            error_str = str(e).lower()
            if "http error 400" in error_str:
                return {
                    "success": True,
                    "current_version": current_version,
                    "new_version": new_version,
                    "message": f"{ap_name} ({ap_mac}): Firmware upgrade initiated"
                }
            
            return {
                "success": False,
                "current_version": current_version,
                "new_version": new_version,
                "message": f"Failed to initiate firmware upgrade for {ap_name}: {e}"
            }
        
    except (Exception, json.JSONDecodeError) as e:
        return {
            "success": False,
            "current_version": None,
            "new_version": None,
            "message": f"Error during firmware upgrade operation: {e}"
        }


def retry_upgrade_until_active(ap_mac: str, max_retries: int = 8, retry_interval: int = 15) -> dict:
    """
    Continuously attempt to trigger an upgrade on an AP, retrying every retry_interval seconds
    if the AP remains in UPGRADABLE state (indicating the previous request was ignored).
    
    This handles race conditions where the controller receives the upgrade request but
    doesn't process it due to timing issues or other transient problems.
    
    Args:
        ap_mac (str): The MAC address of the AP
        max_retries (int): Maximum number of upgrade attempts (default: 8 = ~2 minutes with 15s interval)
        retry_interval (int): Seconds to wait between retries (default: 15)
    
    Returns:
        dict: {
            "success": bool - True if upgrade was activated or already complete,
            "state": str - Final state of the AP (UPGRADING, RUNNING, UPGRADABLE, etc.),
            "attempts": int - Number of upgrade requests sent,
            "message": str - Status message
        }
    """
    import time
    
    attempt = 0
    start_time = time.time()
    
    while attempt < max_retries:
        attempt += 1
        
        # Send upgrade request
        result = upgrade_ap_firmware(ap_mac, dry_run=False)
        
        if not result['success']:
            # upgrade_ap_firmware failed to send the request
            return {
                "success": False,
                "state": "UNKNOWN",
                "attempts": attempt,
                "message": f"Failed to send upgrade request: {result.get('message', 'Unknown error')}"
            }
        
        # Wait for the retry_interval seconds to see if AP transitions to UPGRADING
        print(f"  [ATT {attempt}] Waiting {retry_interval}s to detect upgrade activity...", end="", flush=True)
        time.sleep(retry_interval)
        
        # Check current state
        current_state = get_ap_state(ap_mac)
        
        if current_state == "UPGRADING":
            # Success! AP is now actively upgrading
            elapsed = int(time.time() - start_time)
            print(f" ACTIVE (took {attempt} attempt{'s' if attempt > 1 else ''}, {elapsed}s total)")
            return {
                "success": True,
                "state": "UPGRADING",
                "attempts": attempt,
                "message": f"Upgrade activated on attempt {attempt}"
            }
        elif current_state == "RUNNING":
            # Check if upgrade completed successfully or failed
            device_mac = ap_mac.lower()
            devices = get_devices()
            for device in devices:
                if device.get("mac", "").lower() == device_mac:
                    current_version = device.get("version")
                    target_version = device.get("upgrade_to_firmware")
                    
                    # Success: both version fields must be set and match
                    if current_version and target_version and current_version == target_version:
                        # Versions match - upgrade completed successfully
                        elapsed = int(time.time() - start_time)
                        print(f" COMPLETE (took {elapsed}s)")
                        return {
                            "success": True,
                            "state": "RUNNING",
                            "attempts": attempt,
                            "message": f"Upgrade completed successfully to {current_version}"
                        }
                    # Failure: target_version is set AND current_version is set AND they don't match
                    elif current_version and target_version and current_version != target_version:
                        # target_version is set but version hasn't changed = upgrade FAILED
                        elapsed = int(time.time() - start_time)
                        print(f" FAILED")
                        return {
                            "success": False,
                            "state": "RUNNING",
                            "attempts": attempt,
                            "message": f"Upgrade failed: AP in RUNNING state but version unchanged ({current_version} still set, target was {target_version})"
                        }
                    # else: incomplete data, maybe still being processed - continue retrying
                    break
            # Still running without complete info, continue retrying
            print(f" waiting...")
        elif current_state == "UPGRADABLE":
            # AP is still UPGRADABLE - the upgrade request was ignored, retry
            print(f" still UPGRADABLE, retrying...")
            if attempt >= max_retries:
                elapsed = int(time.time() - start_time)
                return {
                    "success": False,
                    "state": "UPGRADABLE",
                    "attempts": attempt,
                    "message": f"AP remained UPGRADABLE after {attempt} retry attempts ({elapsed}s). Upgrade request may be blocked by controller."
                }
            # Continue to next retry
        else:
            # Some other state
            elapsed = int(time.time() - start_time)
            print(f" {current_state}")
            return {
                "success": False,
                "state": current_state,
                "attempts": attempt,
                "message": f"AP in unexpected state: {current_state} after attempt {attempt}"
            }
    
    # Max retries exceeded
    elapsed = int(time.time() - start_time)
    return {
        "success": False,
        "state": get_ap_state(ap_mac),
        "attempts": attempt,
        "message": f"Max retries ({max_retries}) exceeded in {elapsed}s. AP may have network issues or controller may be rejecting upgrades."
    }


def verify_upgrade_initiated(ap_mac: str, initial_state: str) -> dict:
    """
    Checks if the upgrade initiation request was accepted by the controller.
    
    NOTE: Due to controller limitations, this cannot definitively prove an upgrade is actually
    progressing - it can only verify that upgrade_triggered_by was set by the controller,
    indicating the request was accepted.
    
    Real upgrade progress is detected in the monitoring loop via version changes or completion status.
    
    Args:
        ap_mac (str): The MAC address of the AP
        initial_state (str): The AP state before the upgrade was initiated
        
    Returns:
        dict: {
            "success": bool - Whether initiation request was accepted,
            "message": str - Status message,
            "final_state": str - AP state after checking
        }
    """
    import time
    
    # Get initial version for reference
    initial_version = get_ap_current_version(ap_mac)
    
    # Wait a moment for controller to register the upgrade request
    time.sleep(2)
    
    # Check AP state - if it shows UPGRADING, the initiation was accepted
    current_ap_state = get_ap_state(ap_mac)
    
    # If version already changed, upgrade completed immediately (unlikely but possible)
    current_version = get_ap_current_version(ap_mac)
    if current_version and current_version != initial_version:
        return {
            "success": True,
            "message": "Upgrade completed immediately (version changed)",
            "final_state": current_ap_state
        }
    
    # Check if upgrade_triggered_by is set (means controller accepted the request)
    try:
        devices = get_devices()
        for device in devices:
            if device.get("mac", "").lower() == ap_mac.lower():
                upgrade_triggered_by = device.get("upgrade_triggered_by")
                if upgrade_triggered_by:
                    return {
                        "success": True,
                        "message": f"Upgrade request accepted by controller (triggered_by={upgrade_triggered_by})",
                        "final_state": current_ap_state
                    }
                else:
                    # No upgrade_triggered_by set - request was rejected or not processed
                    return {
                        "success": False,
                        "message": "Upgrade request not accepted by controller (upgrade_triggered_by not set)",
                        "final_state": current_ap_state
                    }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error checking upgrade status: {e}",
            "final_state": initial_state
        }


def get_ap_current_version(ap_mac: str) -> str:
    """
    Get the current firmware version of an AP.
    
    Args:
        ap_mac (str): The MAC address of the AP
    
    Returns:
        str: The current firmware version, or None if not found
    """
    try:
        devices = get_devices()
        for device in devices:
            if device.get("mac", "").lower() == ap_mac.lower():
                return device.get("version")
        return None
    except Exception:
        return None


def is_ap_actively_upgrading(ap_mac: str) -> bool:
    """
    Check if an AP has an upgrade actively in progress.
    
    Uses version mismatch + upgrade progress to detect active upgrades.
    Ignores upgrade_triggered_by field as it's unreliable (persists across
    channel switches and other operations).
    
    Args:
        ap_mac (str): The MAC address of the AP
    
    Returns:
        bool: True if upgrade is actively in progress (version mismatch + active progress)
    """
    try:
        devices = get_devices()
        for device in devices:
            if device.get("mac", "").lower() == ap_mac.lower():
                # Check if versions differ
                current_version = device.get("version")
                target_version = device.get("upgrade_to_firmware")
                
                if current_version and target_version and current_version != target_version:
                    # Versions differ - check if actively upgrading
                    upgrade_progress = device.get("upgrade_progress")
                    upgrade_state = device.get("upgrade_state")
                    
                    if (upgrade_progress and upgrade_progress > 0) or (upgrade_state and upgrade_state > 0):
                        return True  # Actively upgrading
                
                return False
        return False
    except Exception:
        return False
