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


def _make_unifi_api_call(method: str, endpoint: str, **kwargs) -> dict:
    """
    Handles common UniFi API request logic, including URL construction,
    error handling, and JSON parsing. Automatically retries on failure with exponential backoff.
    
    Does NOT retry NSS/NSPR certificate errors - these are raised immediately.
    
    Session state is delegated to NSPRNSSURLOpener (transparent to caller).
    Certificate validation uses NSS database.

    Args:
        method (str): HTTP method (e.g., "GET", "POST", "PUT").
        endpoint (str): The specific API endpoint (e.g., "/api/login", "/api/s/{site_id}/rest/user").
        **kwargs: Additional keyword arguments (headers, json, data, etc.)

    Returns:
        dict: The JSON response data.

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
            
            response_text = response.read().decode('utf-8')
            
            # Check HTTP status
            if 400 <= response.getcode() < 600:
                raise Exception(f"HTTP {response.getcode()}: {response_text}")
            
            # Parse and return response
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
    
    _make_unifi_api_call("POST", login_url, json=login_data)


def get_devices() -> list:
    """
    Retrieves all devices (APs, switches, gateways, etc.) for the configured site.
    
    Returns:
        list: List of device dictionaries, including type, MAC, name, IP, and other properties.
    """
    endpoint = f"/api/s/{UNIFI_SITE_ID}/stat/device"
    
    try:
        devices_data = _make_unifi_api_call("GET", endpoint)
        return devices_data if isinstance(devices_data, list) else []
    except Exception as e:
        print(f"Error retrieving devices: {e}", file=__import__('sys').stderr)
        return []


def _get_unifi_clients_fast() -> dict:
    """
    Fast lightweight fetch of UniFi clients WITHOUT DNS lookups.
    Returns a simple dict mapping MAC -> raw client data.
    For batch operations that don't need display formatting.
    """
    all_known_clients = _make_unifi_api_call("GET", f"/api/s/{UNIFI_SITE_ID}/rest/user")
    return {client.get("mac", "").lower(): client for client in all_known_clients if "mac" in client}


def get_all_unifi_clients() -> list:
    """
    Fetches and processes all known and currently connected clients from the UniFi controller,
    including signal strength, connected AP name, connected AP MAC for live clients,
    and AP locking status.
    """
    processed_clients = []

    # Fetch all known clients (contains configured fixed AP and general client info)
    all_known_clients = _make_unifi_api_call("GET", f"/api/s/{UNIFI_SITE_ID}/rest/user")

    # Fetch live connected clients (contains active fixed AP status, current IP, signal, etc.)
    live_clients_data = _make_unifi_api_call("GET", f"/api/s/{UNIFI_SITE_ID}/stat/sta")
    
    # Fetch UniFi devices (APs) to map MACs to names
    devices_data = _make_unifi_api_call("GET", f"/api/s/{UNIFI_SITE_ID}/stat/device")
    
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
    all_clients_data = _make_unifi_api_call("GET", f"/api/s/{UNIFI_SITE_ID}/rest/user")

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
    devices_data = _make_unifi_api_call("GET", f"/api/s/{UNIFI_SITE_ID}/stat/device")

    for device in devices_data:
        # Check 'name' first, then 'model' if 'name' is missing, then fallback to MAC itself
        current_ap_name = device.get("name") or device.get("model")
        if current_ap_name and current_ap_name.lower() == ap_name.lower() and device.get("mac"):
            return device["mac"]
    return None


def _build_client_payload(original_client_data: dict) -> dict:
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
    
    payload = _build_client_payload(original_client_data)

    # Specific changes for locking:
    payload["fixed_ap_mac"] = ap_mac.lower() # Add the specific AP MAC for locking
    payload["fixed_ap_enabled"] = True # Set to true for locking

    try:
        _make_unifi_api_call("PUT", endpoint, json=payload)
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
    
    payload = _build_client_payload(original_client_data)
    
    # Specific changes for unlocking:
    # CRITICAL: fixed_ap_mac MUST BE ABSENT, not null, for unlock to work.
    if "fixed_ap_mac" in payload:
        del payload["fixed_ap_mac"]    

    payload["fixed_ap_enabled"] = False # Set to false for unlocking

    try:
        _make_unifi_api_call("PUT", endpoint, json=payload)
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
        # Use _make_unifi_api_call for consistency
        _make_unifi_api_call("POST", endpoint, json=payload)
        return True
    except (Exception, json.JSONDecodeError):
        return False

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
        # Use _make_unifi_api_call for consistency
        _make_unifi_api_call("POST", endpoint, json=payload)
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
        # Use _make_unifi_api_call for consistency
        _make_unifi_api_call("POST", endpoint, json=payload)
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
        # Use _make_unifi_api_call for consistency
        _make_unifi_api_call("POST", endpoint, json=payload)
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
        payload = _build_client_payload(existing_client) # Use the existing _build_client_payload
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
        _make_unifi_api_call(method, endpoint, json=payload)
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
        _make_unifi_api_call("POST", endpoint, json=payload)
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
        return _make_unifi_api_call("GET", endpoint)
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
        
        _make_unifi_api_call("PUT", endpoint, json=payload)
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
        
        _make_unifi_api_call("PUT", endpoint, json=payload)
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
        
        _make_unifi_api_call("PUT", endpoint, json=payload)
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
        
        _make_unifi_api_call("PUT", endpoint, json=payload)
        return True
        
    except (Exception, json.JSONDecodeError):
        return False


def upgrade_ap_firmware(ap_mac: str, dry_run: bool = False) -> dict:
    """
    Upgrades the firmware on an access point to the latest version available
    for its configured firmware channel in the controller.
    
    Args:
        ap_mac (str): The MAC address of the AP to upgrade (e.g., "aa:bb:cc:dd:ee:ff").
        dry_run (bool): If True, show what would be upgraded without actually upgrading.
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
        
        # Get the firmware channel (default to "release" if not set)
        firmware_channel = matching_ap.get("fw_channel") or matching_ap.get("update_channel", "release")
        
        # First, check if the device itself has the upgrade-to firmware version
        # This field is populated by the UniFi controller when an upgrade is available
        upgrade_to_firmware = matching_ap.get("upgrade_to_firmware")
        
        # Fetch available firmware information from the controller
        try:
            firmware_data = _make_unifi_api_call("GET", f"/api/s/{UNIFI_SITE_ID}/stat/firmware")
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
        
        # If we still couldn't find firmware info from the controller, provide informational response
        if not new_version:
            if dry_run:
                return {
                    "success": True,
                    "current_version": current_version,
                    "new_version": "Unknown (not available from controller)",
                    "message": f"[DRY RUN] {ap_name} ({ap_mac}): Would check for firmware updates on '{firmware_channel}' channel"
                }
            else:
                return {
                    "success": False,
                    "current_version": current_version,
                    "new_version": None,
                    "message": f"No firmware information available for {ap_name} (model:{device_model}) on '{firmware_channel}' channel"
                }
        
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
            _make_unifi_api_call("POST", endpoint, json=payload)
            return {
                "success": True,
                "current_version": current_version,
                "new_version": new_version,
                "message": f"{ap_name} ({ap_mac}): Firmware upgrade initiated from {current_version} to {new_version}"
            }
        except Exception as e:
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
