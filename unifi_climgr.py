#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 netcon-sync contributors
#
# This file is part of netcon-sync.
# netcon-sync is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""UniFi network management CLI - comprehensive client and network management."""

import os
import sys
import site
import glob

# Auto-activate the project's isolated venv
_VENV_PATH = os.path.expanduser("~/.venv-netcon-sync")
if os.path.exists(_VENV_PATH):
    # Find site-packages (works across Python versions)
    _SITE_PACKAGES_DIRS = glob.glob(os.path.join(_VENV_PATH, "lib/python*/site-packages"))
    if _SITE_PACKAGES_DIRS:
        _SITE_PACKAGES = _SITE_PACKAGES_DIRS[0]
        site.addsitedir(_SITE_PACKAGES)
        sys.path.insert(0, _SITE_PACKAGES)

import argparse
import json
from datetime import datetime, timedelta
from collections import defaultdict
import nss.error

# Import shared modules - config might fail if env vars are missing
UNIFI_NETWORK_URL = None
UNIFI_SITE_ID = None
_config_error = None

try:
    import unifi_utils
    from config import UNIFI_NETWORK_URL, UNIFI_SITE_ID
    from trust import handle_trust_server_url, handle_trust_ca_cert, format_nss_error
    from urllib.parse import urlparse
except ModuleNotFoundError as e:
    print(f"ERROR: Missing required dependency: {e}")
    print("\nPlease run the setup script:")
    print("  ./install_deps.sh")
    sys.exit(1)
except ValueError as e:
    # Store config error - we'll show help + error in main()
    _config_error = e
    UNIFI_NETWORK_URL = None
    UNIFI_SITE_ID = None

# ==============================================================================
# COLUMN SCHEMAS - Centralized column definitions for clients and APs
# ==============================================================================

# Client columns
CLIENT_COLUMN_SCHEMA = {
    "mac": ("MAC Address", 17),
    "hostname": ("Hostname", 10),
    "description": ("Description", 10),
    "status": ("Status", 8),
    "ip": ("IP Address", 15),
    "dns_name": ("DNS Name", 10),
    "connected_ap_name": ("Connected AP name", 10),
    "connected_ap_mac": ("Connected AP MAC", 17),
    "signal": ("Signal", 7),
    "retries": ("Retries", 9),
    "locked": ("Locked to AP?", 12),
    "locked_ap_name": ("Locked AP Name", 15),
    "locked_ap_mac": ("Locked AP MAC", 17),
    "last_seen": ("Last Seen", 19),
}

CLIENT_COLUMN_NAMES = list(CLIENT_COLUMN_SCHEMA.keys())

# AP columns
AP_COLUMN_SCHEMA = {
    "name": ("Device Name", 15),
    "mac": ("MAC Address", 17),
    "ip": ("IP Address", 15),
    "version": ("Firmware", 10),
    "uptime": ("Uptime", 12),
    "connection": ("Connection", 10),
    "enabled": ("Enabled", 9),
    "uplink_ap_name": ("Uplink AP Name", 15),
    "uplink_ap_mac": ("Uplink AP MAC", 17),
}

AP_COLUMN_NAMES = list(AP_COLUMN_SCHEMA.keys())

# SSID columns
SSID_COLUMN_SCHEMA = {
    "name": ("SSID Name", 20),
    "enabled": ("Enabled", 9),
    "security": ("Security", 10),
    "band": ("Band", 15),
}

SSID_COLUMN_NAMES = list(SSID_COLUMN_SCHEMA.keys())

# Legacy reference for backward compatibility
COLUMN_SCHEMA = CLIENT_COLUMN_SCHEMA
ALL_COLUMN_NAMES = CLIENT_COLUMN_NAMES

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def _build_client_row(client: dict) -> dict:
    """
    Build a display row for a single client.
    Consolidates all display value transformations in one place.
    Returns a dict with all column values ready for display.
    """
    status_text = "Online" if client.get("is_connected_live", False) else "Offline"
    signal_display = (
        f"{client.get('live_signal')} dBm"
        if client.get('is_connected_live') and client.get('live_signal') is not None
        else "N/A"
    )
    tx_retries_display = (
        str(client.get('tx_retries'))
        if client.get('is_connected_live') and client.get('tx_retries') is not None
        else "N/A"
    )
    locked_ap_status_display = "Yes" if client.get("is_ap_locked", False) else "No"
    
    # Normalize MAC addresses to lowercase
    locked_ap_mac_val = client.get("locked_ap_mac", "N/A")
    locked_ap_mac_display = locked_ap_mac_val.lower() if locked_ap_mac_val != "N/A" else "N/A"
    live_ap_mac_val = client.get("live_ap_mac", "N/A")
    live_ap_mac_display = live_ap_mac_val.lower() if live_ap_mac_val != "N/A" else "N/A"
    
    return {
        "mac": client.get("mac", "N/A").lower() if client.get("mac") else "N/A",
        "hostname": client.get("hostname") or "Unknown Host",
        "description": client.get("description", "N/A"),
        "status": status_text,
        "ip": client.get("display_ip", "N/A"),
        "dns_name": client.get("dns_name", "N/A"),
        "connected_ap_name": client.get("connected_ap_name", "N/A"),
        "connected_ap_mac": live_ap_mac_display,
        "signal": signal_display,
        "retries": tx_retries_display,
        "locked": locked_ap_status_display,
        "locked_ap_name": client.get("locked_ap_name", "N/A"),
        "locked_ap_mac": locked_ap_mac_display,
        "last_seen": client.get("last_seen_formatted", "N/A"),
    }

def _format_security_display(ssid: dict) -> str:
    """
    Convert UniFi security info to human-readable format.
    Uses wpa_mode field to determine WPA version, handles WPA2/WPA3 transitions.
    """
    # Check for WPA2/WPA3 transition (mutual support)
    if ssid.get("wpa3_transition", False):
        return "WPA2/WPA3"
    
    # Get WPA mode (wpa, wpa2, wpa3, open, etc.)
    wpa_mode = ssid.get("wpa_mode", "").lower()
    
    # Direct mapping of wpa_mode values
    wpa_mode_map = {
        "wpa": "WPA",
        "wpa2": "WPA2",
        "wpa3": "WPA3",
        "open": "Open",
        "": "Open",
    }
    
    if wpa_mode in wpa_mode_map:
        return wpa_mode_map[wpa_mode]
    
    # Fallback to security field if wpa_mode is not recognized
    security_raw = ssid.get("security", "")
    if not security_raw:
        return "Open"
    
    sec_lower = security_raw.lower()
    
    security_map = {
        "open": "Open",
        "wpapsk": "WPA",
        "wpa2psk": "WPA2",
        "wpa3psk": "WPA3",
        "wep": "WEP",
    }
    
    if sec_lower in security_map:
        return security_map[sec_lower]
    
    # Fallback: capitalize if unknown
    return security_raw.upper()

def _calculate_mesh_hops(ap: dict, all_devices: list) -> int:
    """
    Calculate the number of mesh hops for an AP.
    Hops = number of AP-to-AP mesh connections from this AP to a wired AP.
    
    For example:
    - Wired AP = 0 hops
    - AP connected directly to wired AP = 1 hop
    - AP connected to an AP that is connected to wired = 2 hops
    - etc.
    
    Returns the hop count, or 0 if unable to determine.
    """
    visited = set()  # Prevent infinite loops
    current_ap = ap
    hop_count = 0
    
    while True:
        # Check if current AP is wired
        is_wired = current_ap.get('wired')
        if is_wired is True:
            return hop_count
        
        raw_uplink_type = current_ap.get('uplink', {}).get('type')
        if raw_uplink_type == 'wire':
            return hop_count
        
        # Get the uplink AP MAC
        uplink_mac = current_ap.get('uplink_ap_mac') or current_ap.get('last_uplink', {}).get('uplink_mac')
        
        if not uplink_mac or uplink_mac == "N/A":
            # No uplink found, return what we have
            return hop_count
        
        # Prevent infinite loops
        if uplink_mac in visited:
            return hop_count
        visited.add(uplink_mac)
        
        # Find the uplink AP device
        uplink_ap = None
        for device in all_devices:
            if device.get('mac') == uplink_mac and device.get('type') == 'uap':
                uplink_ap = device
                break
        
        if not uplink_ap:
            # Can't find the uplink AP, return what we have
            return hop_count
        
        # Move to uplink AP and increment hop count
        current_ap = uplink_ap
        hop_count += 1

def _build_ssid_row(ssid: dict) -> dict:
    """
    Build a display row for a single SSID.
    Returns a dict with all column values ready for display.
    
    Band is determined from wlan_bands field (array of "2g", "5g", "6g").
    Falls back to wlan_band if wlan_bands not available.
    Security is determined from wpa_mode with fallback to security field.
    """
    enabled_display = "Yes" if ssid.get("enabled", False) else "No"
    security_display = _format_security_display(ssid)
    
    # Get band from wlan_bands array or wlan_band string
    bands = []
    wlan_bands = ssid.get("wlan_bands", [])
    
    if wlan_bands:
        # wlan_bands is an array like ["5g"] or ["2g", "5g"]
        for band in wlan_bands:
            if band.lower() == "2g":
                bands.append("2.4GHz")
            elif band.lower() == "5g":
                bands.append("5GHz")
            elif band.lower() == "6g":
                bands.append("6GHz")
    else:
        # Fallback to wlan_band single string
        wlan_band = ssid.get("wlan_band", "").lower()
        if wlan_band == "2g":
            bands.append("2.4GHz")
        elif wlan_band == "5g":
            bands.append("5GHz")
        elif wlan_band == "6g":
            bands.append("6GHz")
    
    band_display = ", ".join(bands) if bands else "N/A"
    
    return {
        "name": ssid.get("name", "N/A"),
        "enabled": enabled_display,
        "security": security_display,
        "band": band_display,
    }

def _build_ap_row(ap: dict, all_devices: list) -> dict:
    """
    Build a display row for a single AP.
    Consolidates all AP display value transformations in one place.
    """
    ap_name = ap.get("name") or ap.get("model", "Unknown AP")
    mac_address = ap.get("mac", "N/A")
    ip_address = ap.get("ip", "N/A")
    version = ap.get("version", "N/A")
    uptime_seconds = ap.get("uptime", 0)
    
    # Determine connection type (wired vs mesh)
    connection_type_display = "N/A"
    is_wired_status = ap.get('wired')
    
    if is_wired_status is True:
        connection_type_display = "wired"
    elif is_wired_status is False:
        connection_type_display = "mesh"
    else:
        raw_uplink_type = ap.get('uplink', {}).get('type')
        if raw_uplink_type == 'wire':
            connection_type_display = "wired"
        elif raw_uplink_type in ['mesh', 'wireless']:
            connection_type_display = "mesh"
    
    # For mesh APs, calculate hop count
    if connection_type_display == "mesh":
        hops = _calculate_mesh_hops(ap, all_devices)
        hop_label = "hop" if hops == 1 else "hops"
        connection_type_display = f"mesh ({hops}-{hop_label})"
    
    # Determine uplink AP name and MAC for mesh APs
    uplink_ap_name_display = "N/A"
    uplink_ap_mac_display = "N/A"
    
    if "mesh" in connection_type_display:
        uplink_mac = ap.get('uplink_ap_mac') or ap.get('last_uplink', {}).get('uplink_mac')
        
        if uplink_mac and uplink_mac != "N/A":
            uplink_ap_mac_display = uplink_mac
            # Look up the uplink AP's name
            for device in all_devices:
                if device.get('mac') == uplink_mac and device.get('type') == 'uap':
                    uplink_ap_name_display = device.get('name') or device.get('model', 'Unknown')
                    break
            else:
                uplink_ap_name_display = "Unknown"
        else:
            uplink_ap_name_display = "No Uplink"
            uplink_ap_mac_display = "No Uplink"
    
    # Format uptime
    if uptime_seconds:
        uptime_delta = timedelta(seconds=uptime_seconds)
        uptime_str = str(uptime_delta).split('.')[0]
    else:
        uptime_str = "N/A"
    
    return {
        "name": ap_name,
        "mac": mac_address,
        "ip": ip_address,
        "version": version,
        "uptime": uptime_str,
        "connection": connection_type_display,
        "enabled": "Yes" if not ap.get("disabled", False) else "No",
        "uplink_ap_name": uplink_ap_name_display,
        "uplink_ap_mac": uplink_ap_mac_display,
    }

def print_ssid_table(ssids: list, enabled_columns: list):
    """
    Prints a formatted table of SSID data based on enabled columns.
    """
    # Build the list of columns to display
    display_column_definitions = []
    for col_key in enabled_columns:
        if col_key in SSID_COLUMN_SCHEMA:
            header, default_width = SSID_COLUMN_SCHEMA[col_key]
            display_column_definitions.append((header, col_key, default_width))
    
    if not display_column_definitions:
        print("Error: No columns are enabled for display.")
        return
    
    # Calculate dynamic column widths based on data
    max_widths = {header: max(len(header), default_width) for header, _, default_width in display_column_definitions}
    
    for ssid in ssids:
        row_data = _build_ssid_row(ssid)
        for header, key_name, _ in display_column_definitions:
            val = str(row_data.get(key_name, "N/A"))
            max_widths[header] = max(max_widths[header], len(val))
    
    # Add padding to final widths
    final_widths = {h: w + 2 for h, w in max_widths.items()}
    total_width = sum(final_widths[h] for h, _, _ in display_column_definitions) + (len(display_column_definitions) * 3) - 3
    
    # Print header
    print("-" * total_width)
    header_line = ""
    for header, _, _ in display_column_definitions:
        header_line += f"{header:<{final_widths[header]}} | "
    print(header_line.rstrip(" |"))
    print("-" * total_width)
    
    # Print data rows
    for ssid in ssids:
        row_data = _build_ssid_row(ssid)
        data_line = ""
        for header, key_name, _ in display_column_definitions:
            val = str(row_data.get(key_name, "N/A"))
            width = final_widths[header]
            data_line += f"{val:<{width}.{width}} | "
        print(data_line.rstrip(" |"))
    
    print("-" * total_width)

def print_ap_table(aps: list, all_devices: list, enabled_columns: list):
    """
    Prints a formatted table of AP data based on enabled columns.
    """
    # Build the list of columns to display
    display_column_definitions = []
    for col_key in enabled_columns:
        if col_key in AP_COLUMN_SCHEMA:
            header, default_width = AP_COLUMN_SCHEMA[col_key]
            display_column_definitions.append((header, col_key, default_width))
    
    if not display_column_definitions:
        print("Error: No columns are enabled for display.")
        return
    
    # Calculate dynamic column widths based on data
    max_widths = {header: max(len(header), default_width) for header, _, default_width in display_column_definitions}
    
    for ap in aps:
        row_data = _build_ap_row(ap, all_devices)
        for header, key_name, _ in display_column_definitions:
            val = str(row_data.get(key_name, "N/A"))
            max_widths[header] = max(max_widths[header], len(val))
    
    # Add padding to final widths
    final_widths = {h: w + 2 for h, w in max_widths.items()}
    total_width = sum(final_widths[h] for h, _, _ in display_column_definitions) + (len(display_column_definitions) * 3) - 3
    
    # Print header
    print("-" * total_width)
    header_line = ""
    for header, _, _ in display_column_definitions:
        header_line += f"{header:<{final_widths[header]}} | "
    print(header_line.rstrip(" |"))
    print("-" * total_width)
    
    # Print data rows
    for ap in aps:
        row_data = _build_ap_row(ap, all_devices)
        data_line = ""
        for header, key_name, _ in display_column_definitions:
            val = str(row_data.get(key_name, "N/A"))
            width = final_widths[header]
            data_line += f"{val:<{width}.{width}} | "
        print(data_line.rstrip(" |"))
    
    print("-" * total_width)

def _build_ap_branch_aps(target_ap: dict, all_devices: list) -> list:
    """
    Returns a list of APs representing the path from the root (wired AP) to the target AP.
    Used for displaying only the relevant branch when filtering a single mesh AP.
    """
    branch_aps = [target_ap]
    current_ap = target_ap
    
    # Walk up the chain to find all ancestors
    visited = set([current_ap.get('mac')])
    while True:
        uplink_mac = current_ap.get('uplink_ap_mac') or current_ap.get('last_uplink', {}).get('uplink_mac')
        if not uplink_mac or uplink_mac == "N/A":
            break
        
        # Prevent infinite loops
        if uplink_mac in visited:
            break
        visited.add(uplink_mac)
        
        # Find the uplink AP
        uplink_ap = None
        for device in all_devices:
            if device.get('mac') == uplink_mac and device.get('type') == 'uap':
                uplink_ap = device
                break
        
        if not uplink_ap:
            break
        
        branch_aps.insert(0, uplink_ap)
        
        # Check if this AP is wired
        is_wired = uplink_ap.get('wired') is True or uplink_ap.get('uplink', {}).get('type') == 'wire'
        if is_wired:
            break
        
        current_ap = uplink_ap
    
    return branch_aps

def display_ap_tree(aps: list, all_devices: list):
    """
    Displays the AP network as a tree structure showing mesh topology.
    """
    print("\n" + "="*80)
    print("## AP Network Tree View (ASCII)")
    print("="*80 + "\n")
    
    ap_by_mac = {ap['mac']: ap for ap in aps if 'mac' in ap}
    wired_roots = []
    mesh_children_map = defaultdict(list)
    printed_macs = set()
    
    # Classify APs as wired roots or mesh children
    for ap in aps:
        connection_type = 'N/A'
        is_wired_status = ap.get('wired')
        
        if is_wired_status is True:
            connection_type = 'wired'
        elif is_wired_status is False:
            connection_type = 'mesh'
        else:
            raw_uplink_type = ap.get('uplink', {}).get('type')
            if raw_uplink_type == 'wire':
                connection_type = 'wired'
            elif raw_uplink_type in ['mesh', 'wireless']:
                connection_type = 'mesh'
        
        if connection_type == 'wired':
            wired_roots.append(ap)
        elif connection_type == 'mesh':
            uplink_mac = ap.get('uplink_ap_mac') or ap.get('last_uplink', {}).get('uplink_mac')
            if uplink_mac and uplink_mac != 'N/A' and uplink_mac in ap_by_mac:
                mesh_children_map[uplink_mac].append(ap)
    
    # Recursive function to print tree nodes
    def _print_node_recursive(ap_node, prefix=""):
        if ap_node['mac'] in printed_macs:
            return
        
        node_name = ap_node.get('name') or ap_node.get('model', 'Unknown AP')
        
        if not prefix:  # Root node
            print(f"{node_name} (Wired Uplink)")
        else:
            print(f"{prefix}{node_name}")
        
        printed_macs.add(ap_node['mac'])
        
        children = mesh_children_map.get(ap_node['mac'], [])
        children.sort(key=lambda x: x.get('name', '').lower())
        
        for i, child in enumerate(children):
            is_last = (i == len(children) - 1)
            child_prefix_segment = "+-- " if is_last else "|-- "
            
            new_prefix = ""
            if not prefix:  # Direct children of root
                new_prefix = "  " + child_prefix_segment
            else:
                # Extend parent's prefix
                if prefix.endswith("|-- "):
                    new_prefix = prefix[:-4] + "|   " + child_prefix_segment
                elif prefix.endswith("+-- "):
                    new_prefix = prefix[:-4] + "    " + child_prefix_segment
                else:
                    new_prefix = prefix + child_prefix_segment
            
            _print_node_recursive(child, new_prefix)
    
    # Print the tree
    wired_roots.sort(key=lambda x: x.get('name', '').lower())
    
    if not wired_roots:
        print("No wired APs found. Network topology might be entirely mesh.")
    else:
        for root_ap in wired_roots:
            _print_node_recursive(root_ap)
    
    # Print orphan mesh APs
    orphan_mesh_aps = [
        ap for ap in aps
        if ap.get('mac') not in printed_macs and ap.get('wired') is False and
           (ap.get('uplink_ap_mac') or ap.get('last_uplink', {}).get('uplink_mac'))
    ]
    
    if orphan_mesh_aps:
        print("\n---")
        print("## Orphan Mesh APs (Uplink not traceable)")
        print("---")
        orphan_mesh_aps.sort(key=lambda x: x.get('name', '').lower())
        for ap in orphan_mesh_aps:
            ap_name = ap.get('name') or ap.get('model', 'Unknown AP')
            uplink_mac = ap.get('uplink_ap_mac') or ap.get('last_uplink', {}).get('uplink_mac', 'N/A')
            print(f"- {ap_name} (Uplink MAC: {uplink_mac})")
    
    print("\n" + "="*80)

def calculate_ap_mesh_depths(aps: list) -> dict:
    """
    Calculate the depth of each AP in the mesh hierarchy (0 = wired root, 1+ = mesh children).
    Returns a dict mapping AP MAC addresses to their depths.
    """
    ap_by_mac = {ap.get('mac'): ap for ap in aps if ap.get('mac')}
    depths = {}
    
    # First pass: identify wired roots (depth 0)
    for ap in aps:
        is_wired = ap.get('wired')
        uplink_type = ap.get('uplink', {}).get('type')
        
        is_root = is_wired is True or uplink_type == 'wire'
        
        if is_root:
            depths[ap.get('mac')] = 0
    
    # Second pass: calculate depths for mesh APs using BFS (breadth-first search)
    # This ensures we get correct depths even in complex multi-layer mesh topologies
    max_iterations = len(aps)  # Prevent infinite loops
    iteration = 0
    
    while len(depths) < len(aps) and iteration < max_iterations:
        iteration += 1
        for ap in aps:
            ap_mac = ap.get('mac')
            if ap_mac in depths:
                continue  # Already calculated
            
            # Find parent AP
            uplink_mac = ap.get('uplink_ap_mac') or ap.get('last_uplink', {}).get('uplink_mac')
            
            if uplink_mac and uplink_mac in depths:
                # Parent depth is known, so this AP's depth is parent's depth + 1
                depths[ap_mac] = depths[uplink_mac] + 1
    
    # Any remaining APs without known uplink get depth -1 (orphans)
    for ap in aps:
        ap_mac = ap.get('mac')
        if ap_mac not in depths:
            depths[ap_mac] = -1
    
    return depths

def handle_forget_action_batch(clients: list):
    """Forgets a batch of clients in a single, efficient API call."""
    if not clients:
        return
    mac_list = [c.get("mac") for c in clients if c.get("mac")]
    if not mac_list:
        return
    print(f"\nSending batch 'forget' command for {len(mac_list)} clients at once...")
    
    # Use constants from config module
    if not UNIFI_NETWORK_URL:
        print("\nERROR: UNIFI_NETWORK_URL is not defined. Cannot proceed.")
        return

    # Construct the single API call with all MACs.
    try:
        payload = {"cmd": "forget-sta", "macs": [mac.lower() for mac in mac_list]}
        unifi_utils._make_unifi_api_call(
            "POST", 
            f"/api/s/{UNIFI_SITE_ID}/cmd/stamgr",
            headers={"Content-Type": "application/json"},
            body=json.dumps(payload).encode('utf-8')
        )
    except Exception as e:
        print(f"Error during batch forget operation: {e}")
    print("Batch forget command has been issued to the controller.")

def print_action_results_table(clients_data: list, action_type: str, results: dict):
    """
    Prints a formatted table of action results (lock, unlock, reconnect, etc.)
    
    Args:
        clients_data: List of client dicts
        action_type: Type of action ('reconnect', 'lock', 'unlock', 'block', 'unblock')
        results: Dict mapping MAC address to success (True/False)
    """
    # Build display rows
    rows = []
    for client in clients_data:
        mac = client.get("mac", "N/A").lower() if client.get("mac") else "N/A"
        friendly_name = client.get("name") or "Unknown"
        success = results.get(mac, False)
        status_symbol = "OK" if success else "FAIL"
        rows.append({
            "name": friendly_name,
            "mac": mac,
            "status": status_symbol
        })
    
    if not rows:
        return
    
    # Calculate column widths
    name_width = max(len("Device Name"), max(len(row["name"]) for row in rows))
    mac_width = max(len("MAC Address"), 17)
    status_width = max(len("Result"), len("OK"))
    
    # Print header
    print()
    total_width = name_width + mac_width + status_width + 8
    print("-" * total_width)
    header_line = f"{'Device Name':<{name_width}}  {'MAC Address':<{mac_width}}  {'Result':<{status_width}}"
    print(header_line)
    print("-" * total_width)
    
    # Print data rows
    for row in rows:
        data_line = f"{row['name']:<{name_width}}  {row['mac']:<{mac_width}}  {row['status']:<{status_width}}"
        print(data_line)
    
    print("-" * total_width)
    print()

def print_clients_table(clients_data: list, enabled_columns: list):
    """
    Prints a formatted table of client data based on enabled columns.
    """
    # Build the list of columns to display with their headers and initial widths
    display_column_definitions = []
    for col_key in enabled_columns:
        if col_key in COLUMN_SCHEMA:
            header, default_width = COLUMN_SCHEMA[col_key]
            display_column_definitions.append((header, col_key, default_width))
    
    if not display_column_definitions:
        print("Error: No columns are enabled for display.")
        return
    
    # Calculate dynamic column widths based on data
    max_widths = {header: max(len(header), default_width) for header, _, default_width in display_column_definitions}
    
    for client in clients_data:
        row_data = _build_client_row(client)
        for header, key_name, _ in display_column_definitions:
            val = str(row_data.get(key_name, "N/A"))
            max_widths[header] = max(max_widths[header], len(val))
    
    # Add padding to final widths
    final_widths = {h: w + 2 for h, w in max_widths.items()}
    
    # Ensure "Status" and "Locked to AP?" have enough space for their values
    if "Status" in final_widths:
        final_widths["Status"] = max(final_widths["Status"], len("Online") + 2)
    if "Locked to AP?" in final_widths:
        final_widths["Locked to AP?"] = max(final_widths["Locked to AP?"], len("Yes") + 2)
    
    total_width = sum(final_widths[h] for h, _, _ in display_column_definitions) + (len(display_column_definitions) * 3) - 3
    
    # Print header
    print("-" * total_width)
    header_line = ""
    for header, _, _ in display_column_definitions:
        header_line += f"{header:<{final_widths[header]}} | "
    print(header_line.rstrip(" |"))
    print("-" * total_width)
    
    # Print data rows
    for client in clients_data:
        row_data = _build_client_row(client)
        data_line = ""
        for header, key_name, _ in display_column_definitions:
            val = str(row_data.get(key_name, "N/A"))
            width = final_widths[header]
            data_line += f"{val:<{width}.{width}} | "
        print(data_line.rstrip(" |"))
    
    print("-" * total_width)

def get_sort_key(client: dict, col: str):
# ... (rest of the get_sort_key function is unchanged) ...
    """
    Provides a sort key for client data based on the column name.
    Adjusted to use client dictionary keys as provided by unifi_utils.
    """
    if col == "number":
        return int(client.get("number", 0))
    if col == "mac":
        return client.get("mac", "").lower()
    if col == "hostname":
        return client.get("hostname") or ""
    if col == "description":
        return client.get("description") or ""
    if col == "status":
        return 0 if client.get("is_connected_live", False) else 1 # Online first
    if col == "ip":
        return client.get("display_ip") or ""
    if col == "dns_name":
        return client.get("dns_name") or ""
    if col == "connected_ap_name":
        return client.get("connected_ap_name") or ""
    if col == "connected_ap_mac":
        return client.get("live_ap_mac") or ""
    if col == "signal":
        try:
            # Signal values are negative, so sorting by -sig will put stronger signals (closer to 0) first
            sig = int(client.get("live_signal", -999)) # Default to a very low signal if not available
        except (TypeError, ValueError):
            sig = -999
        return -sig
    if col == "retries":
        try:
            ret = int(client.get("tx_retries", -1)) # Default to -1 if not available
        except (TypeError, ValueError):
            ret = -1
        return ret
    if col == "locked":
        return not client.get("is_ap_locked", False) # Sort 'True' (locked) first
    if col == "locked_ap_name":
        return client.get("locked_ap_name") or ""
    if col == "locked_ap_mac":
        return client.get("locked_ap_mac") or ""
    if col == "last_seen":
        return client.get("last_seen_formatted") or "" # Sort by formatted string
    return ""

def parse_column_switches(args_list: list, column_names: list) -> tuple[list, str | None]:
    """
    Parses column display switches (+column, -column) for a given set of column names.
    Returns a list of enabled column keys and an error message (or None).
    Validates that all specified columns are valid for the current action.
    """
    positive_mode = False
    negative_mode = False
    enabled_cols_explicit = []
    disabled_cols_explicit = []
    
    # Parse ALL column switches to check for mixing and invalid columns
    all_column_switch_args = [
        arg
        for arg in args_list
        if len(arg) > 1 and (arg.startswith('+') or arg.startswith('-'))
    ]
    
    # First pass: check for mixing positive and negative, and validate columns
    for arg in all_column_switch_args:
        col = arg[1:]
        if arg.startswith("+"):
            positive_mode = True
            if col not in column_names:
                return [], f"Column '{col}' is not valid for this action."
            if col in enabled_cols_explicit:
                return [], f"Duplicate +column specified: {col}"
            enabled_cols_explicit.append(col)
        elif arg.startswith("-"):
            negative_mode = True
            if col not in column_names:
                return [], f"Column '{col}' is not valid for this action."
            if col in disabled_cols_explicit:
                return [], f"Duplicate -column specified: {col}"
            disabled_cols_explicit.append(col)
    
    if positive_mode and negative_mode:
        return [], "Cannot mix positive (+) and negative (-) switches for column display."
    
    if positive_mode:
        if not enabled_cols_explicit:
            return [], "No +columns specified, but positive mode was indicated."
        return enabled_cols_explicit, None
    else:
        # Default behavior: all columns enabled, unless explicitly disabled
        enabled_final = [col for col in column_names if col not in disabled_cols_explicit]
        if not enabled_final and (negative_mode or not all_column_switch_args):
            return [], "All columns disabled, nothing to show."
        return enabled_final, None

def add_filter_arguments(parser):
    """Add common filtering arguments to a subparser."""
    filter_group_status = parser.add_mutually_exclusive_group()
    filter_group_status.add_argument(
        "--filter_online",
        action="store_true",
        help="Filter clients currently online."
    )
    filter_group_status.add_argument(
        "--filter_offline",
        action="store_true",
        help="Filter clients currently offline."
    )
    filter_group_locked_status = parser.add_mutually_exclusive_group()
    filter_group_locked_status.add_argument(
        "--filter_locked",
        action="store_true",
        help="Filter clients locked to an AP."
    )
    filter_group_locked_status.add_argument(
        "--filter_unlocked",
        action="store_true",
        help="Filter clients NOT locked to an AP."
    )
    parser.add_argument(
        "--filter_ip",
        type=str,
        help="Filter clients by exact IP address match."
    )
    parser.add_argument(
        "--filter_dns_name",
        type=str,
        help="Filter clients by exact DNS name match."
    )
    parser.add_argument(
        "--filter_hostname",
        type=str,
        help="Filter clients by exact hostname match."
    )
    parser.add_argument(
        "--filter_mac",
        type=str,
        help="Filter clients by MAC address (substring match)."
    )
    parser.add_argument(
        "--filter_signal_above",
        type=int,
        help="Filter clients with signal strength strictly ABOVE this value (e.g., -60 means > -60)."
    )
    parser.add_argument(
        "--filter_signal_below",
        type=int,
        help="Filter clients with signal strength strictly BELOW this value (e.g., -30 means < -30)."
    )

def add_filter_arguments_for_list(parser):
    """Add filtering arguments for list command (supports both clients and APs).
    
    For clients: All standard filters apply.
    For APs: Only --filter_online, --filter_offline, --filter_ip, --filter_mac apply.
    """
    # Status filters (works for both clients and APs)
    filter_group_status = parser.add_mutually_exclusive_group()
    filter_group_status.add_argument(
        "--filter_online",
        action="store_true",
        help="Filter devices currently online (clients and APs)."
    )
    filter_group_status.add_argument(
        "--filter_offline",
        action="store_true",
        help="Filter devices currently offline (clients and APs)."
    )
    
    # Locked status filters (clients only)
    filter_group_locked_status = parser.add_mutually_exclusive_group()
    filter_group_locked_status.add_argument(
        "--filter_locked",
        action="store_true",
        help="Filter clients locked to an AP (clients only)."
    )
    filter_group_locked_status.add_argument(
        "--filter_unlocked",
        action="store_true",
        help="Filter clients NOT locked to an AP (clients only)."
    )
    
    # IP and MAC filters (works for both clients and APs)
    parser.add_argument(
        "--filter_ip",
        type=str,
        help="Filter devices by exact IP address match (clients and APs)."
    )
    parser.add_argument(
        "--filter_mac",
        type=str,
        help="Filter devices by MAC address (substring match - clients and APs)."
    )
    
    # DNS and hostname filters (clients only)
    parser.add_argument(
        "--filter_dns_name",
        type=str,
        help="Filter clients by exact DNS name match (clients only)."
    )
    parser.add_argument(
        "--filter_hostname",
        type=str,
        help="Filter clients by exact hostname match (clients only)."
    )
    
    # Signal strength filters (clients only)
    parser.add_argument(
        "--filter_signal_above",
        type=int,
        help="Filter clients with signal strength strictly ABOVE this value in dBm (clients only, e.g., -60)."
    )
    parser.add_argument(
        "--filter_signal_below",
        type=int,
        help="Filter clients with signal strength strictly BELOW this value in dBm (clients only, e.g., -30)."
    )

class HelpArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser that shows full help page on invalid arguments."""
    def error(self, message):
        """Override error to print help page instead of just error message."""
        sys.stderr.write(f"ERROR: {message}\n\n")
        self.print_help(sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    # Initialize NSS database at startup (before any HTTPS connections)
    import nss.nss as nss_core
    from pathlib import Path
    import subprocess
    
    nss_db_dir = Path.home() / ".netcon-sync"
    nss_db_dir.mkdir(parents=True, exist_ok=True)
    
    # Create NSS database if it doesn't exist
    cert_db = nss_db_dir / "cert9.db"
    if not cert_db.exists():
        try:
            subprocess.run(
                ["certutil", "-N", "-d", str(nss_db_dir), "-f", "/dev/null"],
                check=True,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            print(f"Error creating NSS database: {e.stderr.decode() if e.stderr else e}", file=sys.stderr)
            sys.exit(1)
    
    # Initialize NSS
    try:
        nss_core.nss_init(str(nss_db_dir))
    except Exception as e:
        print(f"Error initializing NSS: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Check for config errors from import phase
    if _config_error:
        print(f"ERROR: Configuration Error: {_config_error}", file=sys.stderr)
        print("\nTo fix this, set the required environment variables:", file=sys.stderr)
        print("  export UNIFI_NETWORK_URL='https://your-unifi-host:8443'", file=sys.stderr)
        print("  export UNIFI_USERNAME='your-username'", file=sys.stderr)
        print("  export UNIFI_PASSWORD='your-password'", file=sys.stderr)
        print("  export UNIFI_SITE_ID='default'  # (optional, defaults to 'default')", file=sys.stderr)
        print("\nThen run your command again.", file=sys.stderr)
        sys.exit(1)
    
    # Reminder about backup before any modifications
    if len(sys.argv) > 1 and sys.argv[1] not in ("--help", "-h", "trust"):
        print("WARNING: Please backup your UniFi configuration before making changes!")
        print("   Use UniFi's built-in backup feature in System Settings > Backup & Restore")
        print()
    
    # Handle "trust" command first (non-standard argument parsing)
    if len(sys.argv) > 1 and sys.argv[1] == "trust":
        if len(sys.argv) < 3:
            print("Usage: unifi_climgr.py trust (--ca <CERT_PATH> | --server <HTTPS_URL>)")
            print()
            print("Examples:")
            print("  # Trust a CA certificate")
            print("  unifi_climgr.py trust --ca /path/to/rootCA.pem")
            print()
            print("  # Trust a server certificate (with interactive verification)")
            print("  unifi_climgr.py trust --server https://192.168.1.100:8443")
            sys.exit(1)
        
        # Parse trust command options
        if sys.argv[2] == "--ca":
            if len(sys.argv) < 4:
                print("ERROR: --ca requires a certificate path")
                sys.exit(1)
            cert_path = sys.argv[3]
            handle_trust_ca_cert(cert_path)
        elif sys.argv[2] == "--server":
            if len(sys.argv) < 4:
                print("ERROR: --server requires a URL")
                sys.exit(1)
            server_url = sys.argv[3]
            handle_trust_server_url(server_url)
        else:
            # For backwards compatibility: trust <URL> (without --server flag)
            # Only if it looks like a URL (contains ://)
            if "://" in sys.argv[2]:
                handle_trust_server_url(sys.argv[2])
            else:
                print(f"ERROR: Invalid trust option: {sys.argv[2]}")
                print("Use either --ca <CERT_PATH> or --server <HTTPS_URL>")
                sys.exit(1)
    
    # Separate column switches from other arguments BEFORE passing to argparse
    # Accept CLIENT, AP, and SSID columns, validation happens per-action later
    all_args = sys.argv[1:]

    argparse_args = []
    column_control_args = []
    all_valid_columns = set(CLIENT_COLUMN_NAMES) | set(AP_COLUMN_NAMES) | set(SSID_COLUMN_NAMES)
    
    for arg in all_args:
        is_column_control = False
        if len(arg) > 1 and (arg.startswith('+') or arg.startswith('-')):
            column_name = arg[1:]
            if column_name in all_valid_columns:
                is_column_control = True
        if is_column_control:
            column_control_args.append(arg)
        else:
            argparse_args.append(arg)

    parser = HelpArgumentParser(
        description="UniFi Network Manager - Manage clients, access points, and SSIDs.",
        formatter_class=argparse.RawTextHelpFormatter,
        allow_abbrev=False,
        epilog="""
AVAILABLE ACTIONS:

  list        List clients, SSIDs, and/or access points
              Usage: list (--clients | --ssids | --aps) [column switches] [filters]
              Options:
                --clients              List all connected clients
                --ssids                List all wireless networks (SSIDs)
                --aps                  List all access points with mesh topology tree
              Column Switches: +column, -column (e.g., +mac +hostname -description)
              
              CLIENT COLUMNS (for --clients):
                number                 Sequential numbering
                mac                    MAC address
                hostname               Device hostname
                description            Device description
                status                 Online/Offline status
                ip                     IP address
                dns_name               DNS name
                connected_ap_name      Name of currently connected AP
                connected_ap_mac       MAC of currently connected AP
                signal                 Signal strength (dBm)
                retries                TX retries count
                locked                 AP lock status (Yes/No)
                locked_ap_name         Name of locked AP
                locked_ap_mac          MAC of locked AP
                last_seen              Last seen timestamp
              
              SSID COLUMNS (for --ssids):
                name                   SSID name
                enabled                Enabled/Disabled status (Yes/No)
                security               Security type (Open, WPA, WPA2, WPA3, WPA2/WPA3)
                band                   Frequency band (2.4GHz, 5GHz, 6GHz, or combinations)
              
              AP COLUMNS (for --aps):
                name                   AP device name
                mac                    AP MAC address
                ip                     AP IP address
                version                Firmware version
                uptime                 System uptime
                connection             Connection type (wired/mesh)
                uplink_ap_name         Name of uplink AP (for mesh)
                uplink_ap_mac          MAC of uplink AP (for mesh)
              
              CLIENT FILTERS (for --clients):
                --filter_online, --filter_offline (show online/offline clients)
                --filter_locked, --filter_unlocked (show locked/unlocked clients)
                --filter_ip <IP>, --filter_mac <MAC> (exact/substring match)
                --filter_dns_name <DNS>, --filter_hostname <NAME> (exact match)
                --filter_signal_above <dBm>, --filter_signal_below <dBm> (signal range)
              
              SSID FILTERS (for --ssids):
                --filter_name <NAME>   Filter by SSID name (substring match)
              
              AP FILTERS (for --aps):
                --filter_online, --filter_offline (show online/offline APs)
                --filter_ip <IP>, --filter_mac <MAC> (substring match)

  lock_client Lock clients to a specific access point
              Usage: lock_client (--ap_mac <MAC> | --ap_name <NAME> | --connected_ap) [filters]
              Options:
                --ap_mac <MAC>         Lock to AP by MAC address
                --ap_name <NAME>       Lock to AP by name
                --connected_ap         Lock each client to its currently connected AP
              Filters: --filter_online, --filter_offline, --filter_locked, --filter_unlocked,
                       --filter_ip, --filter_dns_name, --filter_hostname, --filter_mac,
                       --filter_signal_above, --filter_signal_below

  unlock_client Unlock clients from access points
              Usage: unlock_client [filters]
              Filters: --filter_online, --filter_offline, --filter_locked, --filter_unlocked,
                       --filter_ip, --filter_dns_name, --filter_hostname, --filter_mac,
                       --filter_signal_above, --filter_signal_below

  reconnect_client Force clients to reconnect
              Usage: reconnect_client [filters]
              Filters: --filter_online, --filter_offline, --filter_locked, --filter_unlocked,
                       --filter_ip, --filter_dns_name, --filter_hostname, --filter_mac,
                       --filter_signal_above, --filter_signal_below

  forget      Forget clients from the controller (removes device entirely)
              Usage: forget --clients [filters]
              Filters: --filter_online, --filter_offline, --filter_locked, --filter_unlocked,
                       --filter_ip, --filter_dns_name, --filter_hostname, --filter_mac,
                       --filter_signal_above, --filter_signal_below

  block_client Block clients (prevents connection)
              Usage: block_client [filters]
              Filters: --filter_online, --filter_offline, --filter_locked, --filter_unlocked,
                       --filter_ip, --filter_dns_name, --filter_hostname, --filter_mac,
                       --filter_signal_above, --filter_signal_below

  unblock_client Unblock clients (allows connection)
              Usage: unblock_client [filters]
              Filters: --filter_online, --filter_offline, --filter_locked, --filter_unlocked,
                       --filter_ip, --filter_dns_name, --filter_hostname, --filter_mac,
                       --filter_signal_above, --filter_signal_below

  add_client  Add or update a client
              Usage: add_client <MAC_ADDRESS> [--name <NAME>] [--note <NOTE>]
              Arguments:
                <MAC_ADDRESS>          MAC address of client (required, positional)
              Options:
                --name <NAME>          Client name (optional)
                --note <NOTE>          Client note/description (optional)

  restart_ap  Restart access points
              Usage: restart_ap [--ap_mac <MAC> | --ap_name <NAME>]
              Options:
                --ap_mac <MAC>         Restart AP by MAC address
                --ap_name <NAME>       Restart AP by name
              If neither --ap_mac nor --ap_name is specified, restarts all APs (use with caution!)
              For mesh networks, APs restart in mesh order (leaf to parent) with 5s delay between layers

  enable      Enable wireless networks (SSIDs) or access points (APs)
              Usage: enable (--ssids | --aps) [<NAME> | --filter_name <NAME>] [--filter_mac <MAC>]
              Options:
                --ssids                Enable SSID(s)
                --aps                  Enable AP(s)
                <NAME>                 Name of the SSID or AP to enable (optional, positional)
                --filter_name <NAME>   Enable SSIDs/APs matching this name (substring match)
                --filter_mac <MAC>     Enable AP by MAC address (substring match, APs only)
              Note: Omit filters to enable ALL SSIDs or APs

  disable     Disable wireless networks (SSIDs) or access points (APs)
              Usage: disable (--ssids | --aps) [<NAME> | --filter_name <NAME>] [--filter_mac <MAC>]
              Options:
                --ssids                Disable SSID(s)
                --aps                  Disable AP(s)
                <NAME>                 Name of the SSID or AP to disable (optional, positional)
                --filter_name <NAME>   Disable SSIDs/APs matching this name (substring match)
                --filter_mac <MAC>     Disable AP by MAC address (substring match, APs only)
              Note: Omit filters to disable ALL SSIDs or APs

EXAMPLES:

  # List all clients
  ./unifi_climgr.py list --clients

  # List only specific columns for clients
  ./unifi_climgr.py list --clients +mac +hostname +status

  # List all SSIDs
  ./unifi_climgr.py list --ssids

  # List SSIDs with only name and security columns
  ./unifi_climgr.py list --ssids +name +security

  # Filter SSIDs by name (substring match)
  ./unifi_climgr.py list --ssids --filter_name "guest"

  # List access points with mesh topology
  ./unifi_climgr.py list --aps

  # Lock all online clients to a specific AP by MAC
  ./unifi_climgr.py lock_client --ap_mac aa:bb:cc:dd:ee:ff --filter_online

  # Lock only offline clients to an AP by name
  ./unifi_climgr.py lock_client --ap_name "Living Room AP" --filter_offline

  # Lock each client to its currently connected AP
  ./unifi_climgr.py lock_client --connected_ap

  # Unlock all locked clients
  ./unifi_climgr.py unlock_client --filter_locked

  # Force all clients with weak signal to reconnect
  ./unifi_climgr.py reconnect_client --filter_signal_below -50

  # Block a specific client by MAC
  ./unifi_climgr.py block_client --filter_mac aa:bb:cc

  # Forget clients matching a hostname pattern
  ./unifi_climgr.py forget --clients --filter_hostname "test-device"

  # Unblock a specific client by MAC
  ./unifi_climgr.py unblock_client --filter_mac aa:bb:cc

  # Add a new client with name and note
  ./unifi_climgr.py add_client aa:bb:cc:dd:ee:ff --name "My Device" --note "Test device"

  # Restart a specific AP by MAC
  ./unifi_climgr.py restart_ap --ap_mac aa:bb:cc:dd:ee:ff

  # Restart a specific AP by name
  ./unifi_climgr.py restart_ap --ap_name "Living Room AP"

  # Restart all APs (WARNING: network disruption! Mesh networks restart in order)
  ./unifi_climgr.py restart_ap

  # Enable an SSID
  ./unifi_climgr.py enable --ssids "My WiFi Network"

  # Enable all SSIDs matching a pattern (substring match)
  ./unifi_climgr.py enable --ssids --filter_name "guest"

  # Enable ALL SSIDs
  ./unifi_climgr.py enable --ssids

  # Enable a specific AP by name
  ./unifi_climgr.py enable --aps "Living Room AP"

  # Enable all APs matching a pattern (substring match)
  ./unifi_climgr.py enable --aps --filter_name "bedroom"

  # Enable all APs with a specific MAC (substring match)
  ./unifi_climgr.py enable --aps --filter_mac aa:bb:cc

  # Enable ALL APs
  ./unifi_climgr.py enable --aps

  # Disable an SSID
  ./unifi_climgr.py disable --ssids "Guest Network"

  # Disable all SSIDs matching a pattern (substring match)
  ./unifi_climgr.py disable --ssids --filter_name "test"

  # Disable ALL SSIDs
  ./unifi_climgr.py disable --ssids

  # Disable a specific AP by name
  ./unifi_climgr.py disable --aps "Garage AP"

  # Disable all APs matching a pattern (substring match)
  ./unifi_climgr.py disable --aps --filter_name "outdoor"

  # Disable all APs with a specific MAC (substring match)
  ./unifi_climgr.py disable --aps --filter_mac aa:bb:cc

  # Disable ALL APs
  ./unifi_climgr.py disable --aps

CERTIFICATE MANAGEMENT:

  # Trust a self-signed certificate
  ./unifi_climgr.py trust https://192.168.1.100:8443
        """
    )
    
    # Create subparsers for actions
    subparsers = parser.add_subparsers(dest='action', required=False)

    # ============================================================================
    # LIST action
    # ============================================================================
    list_parser = subparsers.add_parser(
        'list',
        help='List clients, access points, and SSIDs',
        formatter_class=argparse.RawTextHelpFormatter,
        allow_abbrev=False,
        epilog="""
USAGE:
  list --clients [column switches] [filters]
  list --aps [column switches] [filters]
  list --ssids [column switches] [filters]

FILTERS FOR --clients:
  Status Filters (mutually exclusive):
    --filter_online              Show only online clients
    --filter_offline             Show only offline clients
  
  Lock Status Filters (mutually exclusive):
    --filter_locked              Show only clients locked to an AP
    --filter_unlocked            Show only clients NOT locked to an AP
  
  Specific Value Filters:
    --filter_ip <IP>             Exact IP address match
    --filter_mac <MAC>           MAC address substring match
    --filter_dns_name <DNS>      Exact DNS name match
    --filter_hostname <NAME>     Exact hostname match
  
  Signal Strength Filters:
    --filter_signal_above <dBm>  Signal strength > dBm (e.g., -60)
    --filter_signal_below <dBm>  Signal strength < dBm (e.g., -30)

FILTERS FOR --aps:
  Status Filters (mutually exclusive):
    --filter_online              Show only online APs
    --filter_offline             Show only offline APs
  
  Specific Value Filters:
    --filter_ip <IP>             Exact IP address match
    --filter_mac <MAC>           MAC address substring match

FILTERS FOR --ssids:
  --filter_name <NAME>           SSID name substring match (case-insensitive)

COLUMN SWITCHES (for --clients, --aps, and --ssids):
  +column                        Include column in output
  -column                        Exclude column from output
  
  Example: list --clients +mac +hostname -description

EXAMPLES:
  # List all clients with default columns
  ./unifi_climgr.py list --clients

  # List all SSIDs
  ./unifi_climgr.py list --ssids

  # Filter SSIDs by name (substring match)
  ./unifi_climgr.py list --ssids --filter_name "guest"

  # List only online clients
  ./unifi_climgr.py list --clients --filter_online

  # List only MAC and hostname for offline clients
  ./unifi_climgr.py list --clients --filter_offline +mac +hostname -ip

  # List locked clients with specific columns
  ./unifi_climgr.py list --clients --filter_locked +hostname +locked_ap_name

  # List APs with weak signal clients connected
  ./unifi_climgr.py list --aps

  # List online APs only
  ./unifi_climgr.py list --aps --filter_online

  # List APs on specific IP subnet
  ./unifi_climgr.py list --aps --filter_ip 192.168.1
        """
    )
    list_target = list_parser.add_mutually_exclusive_group(required=True)
    list_target.add_argument('--clients', action='store_true', help='List all connected clients')
    list_target.add_argument('--aps', action='store_true', help='List all access points')
    list_target.add_argument('--ssids', action='store_true', help='List all wireless networks (SSIDs)')
    # Add filter arguments for list command
    add_filter_arguments_for_list(list_parser)
    # Add name filter for SSIDs and APs
    list_parser.add_argument(
        "--filter_name",
        type=str,
        help="Filter SSIDs/APs by name (substring match, case-insensitive)."
    )

    # ============================================================================
    # LOCK_CLIENT action
    # ============================================================================
    lock_client_parser = subparsers.add_parser(
        'lock_client',
        help='Lock clients to an access point',
        allow_abbrev=False
    )
    lock_target = lock_client_parser.add_mutually_exclusive_group(required=True)
    lock_target.add_argument('--ap_mac', type=str, help='Lock to AP by MAC address')
    lock_target.add_argument('--ap_name', type=str, help='Lock to AP by name')
    lock_target.add_argument('--connected_ap', action='store_true', help='Lock to currently connected AP')
    add_filter_arguments(lock_client_parser)

    # ============================================================================
    # UNLOCK_CLIENT action
    # ============================================================================
    unlock_client_parser = subparsers.add_parser(
        'unlock_client',
        help='Unlock clients from access points',
        allow_abbrev=False
    )
    add_filter_arguments(unlock_client_parser)
    # ============================================================================
    # RECONNECT_CLIENT action
    # ============================================================================
    reconnect_client_parser = subparsers.add_parser(
        'reconnect_client',
        help='Force clients to reconnect',
        allow_abbrev=False
    )
    add_filter_arguments(reconnect_client_parser)

    # ============================================================================
    # FORGET action
    # ============================================================================
    forget_parser = subparsers.add_parser(
        'forget',
        help='Forget clients from the controller',
        allow_abbrev=False
    )
    forget_parser.add_argument('--clients', action='store_true', required=True, help='Forget clients')
    add_filter_arguments(forget_parser)

    # ============================================================================
    # BLOCK_CLIENT action
    # ============================================================================
    block_client_parser = subparsers.add_parser(
        'block_client',
        help='Block clients',
        allow_abbrev=False
    )
    add_filter_arguments(block_client_parser)

    # ============================================================================
    # UNBLOCK_CLIENT action
    # ============================================================================
    unblock_client_parser = subparsers.add_parser(
        'unblock_client',
        help='Unblock clients',
        allow_abbrev=False
    )
    add_filter_arguments(unblock_client_parser)

    # ============================================================================
    # ADD_CLIENT action
    # ============================================================================
    add_client_parser = subparsers.add_parser(
        'add_client',
        help='Add or update a client',
        allow_abbrev=False
    )
    add_client_parser.add_argument('mac_address', help='MAC address of the client to add')
    add_client_parser.add_argument('--name', type=str, help='Client name (optional)')
    add_client_parser.add_argument('--note', type=str, help='Client note/description (optional)')

    # ============================================================================
    # RESTART_AP action
    # ============================================================================
    restart_ap_parser = subparsers.add_parser(
        'restart_ap',
        help='Restart access points',
        allow_abbrev=False
    )
    restart_ap_target = restart_ap_parser.add_mutually_exclusive_group(required=False)
    restart_ap_target.add_argument('--ap_mac', type=str, help='Restart AP by MAC address')
    restart_ap_target.add_argument('--ap_name', type=str, help='Restart AP by name')

    # ============================================================================
    # ENABLE action
    # ============================================================================
    enable_parser = subparsers.add_parser(
        'enable',
        help='Enable a wireless network (SSID) or access point (AP)',
        allow_abbrev=False
    )
    enable_target = enable_parser.add_mutually_exclusive_group(required=True)
    enable_target.add_argument('--ssids', action='store_true', help='Enable SSID(s)')
    enable_target.add_argument('--aps', action='store_true', help='Enable AP(s)')
    enable_parser.add_argument('name', nargs='?', default=None, help='Name of the SSID or AP to enable')
    enable_parser.add_argument('--filter_name', type=str, help='Enable SSIDs/APs matching this name (substring match)')
    enable_parser.add_argument('--filter_mac', type=str, help='Enable AP by MAC address (substring match, APs only)')

    # ============================================================================
    # DISABLE action
    # ============================================================================
    disable_parser = subparsers.add_parser(
        'disable',
        help='Disable a wireless network (SSID) or access point (AP)',
        allow_abbrev=False
    )
    disable_target = disable_parser.add_mutually_exclusive_group(required=True)
    disable_target.add_argument('--ssids', action='store_true', help='Disable SSID(s)')
    disable_target.add_argument('--aps', action='store_true', help='Disable AP(s)')
    disable_parser.add_argument('name', nargs='?', default=None, help='Name of the SSID or AP to disable')
    disable_parser.add_argument('--filter_name', type=str, help='Disable SSIDs/APs matching this name (substring match)')
    disable_parser.add_argument('--filter_mac', type=str, help='Disable AP by MAC address (substring match, APs only)')

    # Parse arguments
    args = parser.parse_args(argparse_args)
    
    # If no action provided, show help
    if not args.action:
        parser.print_help()
        sys.exit(0)
    
    # Validate that --clients is provided for client-related actions
    # (but not for lock_client, unlock_client, reconnect_client, enable, disable, add, restart which have different requirements)
    client_actions_needing_flag = ['forget', 'block', 'unblock']
    if args.action in client_actions_needing_flag:
        if hasattr(args, 'clients') and not args.clients:
            parser.error("--clients is required for this action")

    # Determine column display mode based on action
    if args.action == 'list':
        if args.aps:
            mode_column_names = AP_COLUMN_NAMES
        elif args.ssids:
            mode_column_names = SSID_COLUMN_NAMES
        else:
            mode_column_names = CLIENT_COLUMN_NAMES
    else:
        # For action commands, default to client columns (but not really used for display)
        mode_column_names = CLIENT_COLUMN_NAMES
    
    # Handle column switches
    enabled_columns, err = parse_column_switches(column_control_args, mode_column_names)
    if err:
        if not enabled_columns:
            print(err)
            sys.exit(0)
        else:
            print(f"Error: {err}", file=sys.stderr)
            parser.print_help(sys.stderr)
            sys.exit(1)

    try:
        print("Logging into UniFi controller...")
        unifi_utils.login()
        print("Login successful.")

        # =====================================================================
        # LIST action
        # =====================================================================
        if args.action == 'list':
            if args.aps:
                print("Fetching UniFi devices...")
                all_devices = unifi_utils.get_devices()
                aps = [device for device in all_devices if device.get("type") == "uap"]
                if not aps:
                    print("No Access Points found.")
                    sys.exit(0)
                
                # Apply AP filters
                filtered_aps = []
                for ap in aps:
                    match = True
                    
                    # Status filters (online/offline)
                    if hasattr(args, 'filter_online') and args.filter_online:
                        if not ap.get("adoptable_when_online", ap.get("state") == "online"):
                            match = False
                    elif hasattr(args, 'filter_offline') and args.filter_offline:
                        if ap.get("adoptable_when_online", ap.get("state") == "online"):
                            match = False
                    
                    # IP filter
                    if hasattr(args, 'filter_ip') and args.filter_ip:
                        ap_ip = ap.get("ip", "")
                        if args.filter_ip.lower() not in ap_ip.lower():
                            match = False
                    
                    # MAC filter
                    if hasattr(args, 'filter_mac') and args.filter_mac:
                        ap_mac = ap.get("mac", "")
                        if args.filter_mac.lower() not in ap_mac.lower():
                            match = False
                    
                    # Name filter (substring match, case-insensitive)
                    if hasattr(args, 'filter_name') and args.filter_name:
                        ap_name = ap.get("name", "")
                        if args.filter_name.lower() not in ap_name.lower():
                            match = False
                    
                    if match:
                        filtered_aps.append(ap)
                
                if not filtered_aps:
                    print("No Access Points found matching the specified filters.")
                    sys.exit(0)
                
                print(f"\nFound {len(filtered_aps)} Access Point(s):")
                print_ap_table(filtered_aps, all_devices, enabled_columns)
                
                # Determine whether to show tree view for filtered APs
                show_tree = False
                tree_aps = filtered_aps
                
                if len(filtered_aps) == 1:
                    # Single AP: show tree only if it's mesh, showing only the branch to that AP
                    ap = filtered_aps[0]
                    is_wired = ap.get('wired') is True or ap.get('uplink', {}).get('type') == 'wire'
                    if not is_wired:
                        show_tree = True
                        tree_aps = _build_ap_branch_aps(ap, all_devices)
                elif len(filtered_aps) > 1:
                    # Multiple APs: show tree only if at least one is mesh, and use full network
                    has_mesh = any(
                        ap.get('wired') is False or ap.get('uplink', {}).get('type') in ['mesh', 'wireless']
                        for ap in filtered_aps
                    )
                    if has_mesh:
                        show_tree = True
                        tree_aps = [d for d in all_devices if d.get("type") == "uap"]  # Use all APs for tree
                
                if show_tree:
                    display_ap_tree(tree_aps, all_devices)
            elif args.ssids:
                print("Fetching UniFi SSIDs...")
                ssids = unifi_utils.get_ssids()
                if not ssids:
                    print("No SSIDs found.")
                    sys.exit(0)
                
                # Apply SSID filters
                filtered_ssids = []
                for ssid in ssids:
                    match = True
                    
                    # Name filter (substring match, case-insensitive)
                    if hasattr(args, 'filter_name') and args.filter_name:
                        ssid_name = ssid.get("name", "")
                        if args.filter_name.lower() not in ssid_name.lower():
                            match = False
                    
                    if match:
                        filtered_ssids.append(ssid)
                
                if not filtered_ssids:
                    print("No SSIDs found matching the specified filters.")
                    sys.exit(0)
                
                print(f"\nFound {len(filtered_ssids)} SSID(s):")
                if enabled_columns:
                    print_ssid_table(filtered_ssids, enabled_columns)
            elif args.clients:
                # args.clients
                print("Fetching UniFi clients...")
                clients = unifi_utils.get_all_unifi_clients()
                if not clients:
                    print("No clients found.")
                    sys.exit(0)
                
                # Add "number" key for numbering (before filtering)
                for i, client in enumerate(clients):
                    client["number"] = i + 1
                
                # Apply client filters
                filtered_clients = []
                for client in clients:
                    match = True
                    
                    # Status filters (online/offline)
                    if hasattr(args, 'filter_online') and args.filter_online and not client.get("is_connected_live", False):
                        match = False
                    elif hasattr(args, 'filter_offline') and args.filter_offline and client.get("is_connected_live", False):
                        match = False
                    
                    # Lock status filters
                    if hasattr(args, 'filter_locked') and args.filter_locked and not client.get("is_ap_locked", False):
                        match = False
                    elif hasattr(args, 'filter_unlocked') and args.filter_unlocked and client.get("is_ap_locked", False):
                        match = False
                    
                    # IP filter
                    if hasattr(args, 'filter_ip') and args.filter_ip:
                        if client.get("display_ip") != args.filter_ip:
                            match = False
                    
                    # MAC filter
                    if hasattr(args, 'filter_mac') and args.filter_mac:
                        client_mac = client.get("mac", "")
                        if args.filter_mac.lower() not in client_mac.lower():
                            match = False
                    
                    # DNS name filter
                    if hasattr(args, 'filter_dns_name') and args.filter_dns_name:
                        if client.get("dns_name") != args.filter_dns_name:
                            match = False
                    
                    # Hostname filter
                    if hasattr(args, 'filter_hostname') and args.filter_hostname:
                        if client.get("hostname") != args.filter_hostname:
                            match = False
                    
                    # Signal strength filters
                    if hasattr(args, 'filter_signal_above') and args.filter_signal_above is not None:
                        signal = client.get("live_signal")
                        if not client.get("is_connected_live", False) or signal is None or signal <= args.filter_signal_above:
                            match = False
                    if hasattr(args, 'filter_signal_below') and args.filter_signal_below is not None:
                        signal = client.get("live_signal")
                        if not client.get("is_connected_live", False) or signal is None or signal >= args.filter_signal_below:
                            match = False
                    
                    if match:
                        filtered_clients.append(client)
                
                if not filtered_clients:
                    print("No clients found matching the specified filters.")
                    sys.exit(0)
                
                # Re-number filtered clients
                for i, client in enumerate(filtered_clients):
                    client["number"] = i + 1
                
                print(f"\nFound {len(filtered_clients)} Client(s):")
                if enabled_columns:
                    print_clients_table(filtered_clients, enabled_columns)
            sys.exit(0)
        
        # =====================================================================
        # ADD action
        # =====================================================================
        if args.action == 'add_client':
            mac_to_add = args.mac_address
            client_name = args.name
            client_note = args.note
            print(f"\nAttempting to add/update client {mac_to_add}...")
            if unifi_utils.add_client(mac_to_add, client_name, client_note):
                print(f"Client {mac_to_add} successfully added/updated.")
            else:
                print(f"Failed to add/update client {mac_to_add}. Check logs for details.")
            sys.exit(0)
        
        # =====================================================================
        # RESTART action
        # =====================================================================
        if args.action == 'restart_ap':
            print("Fetching UniFi devices...")
            all_devices = unifi_utils.get_devices()
            aps = [device for device in all_devices if device.get("type") == "uap"]
            
            if not aps:
                print("No Access Points found.")
                sys.exit(0)
            
            aps_to_restart = []
            
            if args.ap_mac:
                # Restart specific AP by MAC
                target_mac = args.ap_mac.lower()
                matching_aps = [ap for ap in aps if ap.get("mac", "").lower() == target_mac]
                if not matching_aps:
                    print(f"Error: No AP found with MAC {args.ap_mac}")
                    sys.exit(1)
                aps_to_restart = matching_aps
            elif args.ap_name:
                # Restart specific AP by name
                matching_aps = [ap for ap in aps if (ap.get("name") or ap.get("model", "")).lower() == args.ap_name.lower()]
                if not matching_aps:
                    print(f"Error: No AP found with name '{args.ap_name}'")
                    sys.exit(1)
                aps_to_restart = matching_aps
            else:
                # Restart all APs
                aps_to_restart = aps
            
            # Check if there are any mesh APs (depth >= 1)
            depths = calculate_ap_mesh_depths(aps_to_restart)
            has_mesh_aps = any(depth >= 1 for depth in depths.values())
            
            # Use mesh-ordered restart if there are mesh APs and we're restarting all APs (not a specific one)
            use_mesh_order = (has_mesh_aps and not args.ap_mac and not args.ap_name)
            
            if use_mesh_order and not args.ap_mac and not args.ap_name:
                import time
                print(f"\nRestarting {len(aps_to_restart)} AP(s) in mesh order (leaf to parent)...\n")
                
                # Group APs by depth
                aps_by_depth = defaultdict(list)
                for ap in aps_to_restart:
                    ap_mac = ap.get("mac")
                    depth = depths.get(ap_mac, -1)
                    aps_by_depth[depth].append(ap)
                
                # Sort depths (deepest/highest numbers first, which means leaf to parent)
                sorted_depths = sorted(aps_by_depth.keys(), reverse=True)
                
                for i, depth in enumerate(sorted_depths):
                    layer_aps = aps_by_depth[depth]
                    
                    if depth == -1:
                        depth_label = "Orphan"
                    elif depth == 0:
                        depth_label = "Wired Root"
                    else:
                        depth_label = f"Mesh Depth {depth}"
                    
                    print(f"Layer {i+1}: {depth_label} ({len(layer_aps)} AP{'s' if len(layer_aps) != 1 else ''})")
                    
                    for ap in layer_aps:
                        ap_name = ap.get("name") or ap.get("model", "Unknown AP")
                        ap_mac = ap.get("mac")
                        if ap_mac:
                            print(f"  {ap_name}... ", end="", flush=True)
                            if unifi_utils.restart_ap(ap_mac):
                                print("[OK]")
                            else:
                                print("[FAIL]")
                    
                    # Add 5-second delay between layers (but not after the last layer)
                    if i < len(sorted_depths) - 1:
                        print("  Waiting 5 seconds before next layer...\n")
                        time.sleep(5)
                
                print("\nAll APs restarted in mesh order.")
            else:
                # Standard restart without mesh ordering
                
                print(f"\nRestarting {len(aps_to_restart)} AP(s)...")
                for ap in aps_to_restart:
                    ap_name = ap.get("name") or ap.get("model", "Unknown AP")
                    ap_mac = ap.get("mac")
                    if ap_mac:
                        print(f"  {ap_name}... ", end="")
                        if unifi_utils.restart_ap(ap_mac):
                            print("[OK]")
                        else:
                            print("[FAIL]")
            sys.exit(0)
        
        # =====================================================================
        # ENABLE action
        # =====================================================================
        if args.action == 'enable':
            if args.ssids:
                # =====================================================================
                # ENABLE SSID action
                # =====================================================================
                print("Fetching UniFi SSIDs...")
                ssids = unifi_utils.get_ssids()
                if not ssids:
                    print("No SSIDs found.")
                    sys.exit(0)
                
                # Find matching SSIDs
                matching_ssids = []
                if args.name:
                    # Exact match by name
                    matching_ssids = [ssid for ssid in ssids if ssid.get("name", "").lower() == args.name.lower()]
                elif args.filter_name:
                    # Substring match
                    matching_ssids = [ssid for ssid in ssids if args.filter_name.lower() in ssid.get("name", "").lower()]
                else:
                    # No specific SSID or filter: enable ALL SSIDs
                    matching_ssids = ssids
                
                if not matching_ssids:
                    print(f"No SSIDs found matching the specified criteria.")
                    sys.exit(0)
                
                print(f"\nEnabling {len(matching_ssids)} SSID(s)...")
                for ssid in matching_ssids:
                    ssid_name = ssid.get("name", "Unknown")
                    is_enabled_before = "Yes" if ssid.get("enabled", False) else "No"
                    print(f"  {ssid_name} (enabled: {is_enabled_before} → ", end="", flush=True)
                    if unifi_utils.enable_ssid(ssid_name):
                        print(f"Yes)... [OK]")
                    else:
                        print(f"?)... [FAIL]")
                sys.exit(0)
            
            elif args.aps:
                # =====================================================================
                # ENABLE AP action
                # =====================================================================
                print("Fetching UniFi devices...")
                all_devices = unifi_utils.get_devices()
                aps = [device for device in all_devices if device.get("type") == "uap"]
                
                if not aps:
                    print("No Access Points found.")
                    sys.exit(0)
                
                # Find matching APs
                matching_aps = []
                if args.name:
                    # Exact match by name
                    matching_aps = [ap for ap in aps if (ap.get("name") or ap.get("model", "")).lower() == args.name.lower()]
                elif args.filter_name:
                    # Substring match by name
                    matching_aps = [ap for ap in aps if args.filter_name.lower() in (ap.get("name") or ap.get("model", "")).lower()]
                elif args.filter_mac:
                    # Substring match by MAC
                    filter_mac_lower = args.filter_mac.lower()
                    matching_aps = [ap for ap in aps if filter_mac_lower in ap.get("mac", "").lower()]
                else:
                    # No specific AP or filter: enable ALL APs
                    matching_aps = aps
                
                if not matching_aps:
                    print(f"No Access Points found matching the specified criteria.")
                    sys.exit(0)
                
                print(f"\nEnabling {len(matching_aps)} AP(s)...")
                for ap in matching_aps:
                    ap_name = ap.get("name") or ap.get("model", "Unknown AP")
                    ap_mac = ap.get("mac", "N/A")
                    is_enabled_before = "Yes" if not ap.get("disabled", False) else "No"
                    print(f"  {ap_name} (enabled: {is_enabled_before} → ", end="", flush=True)
                    if unifi_utils.enable_ap(ap_mac):
                        print(f"Yes)... [OK]")
                    else:
                        print(f"?)... [FAIL]")
                sys.exit(0)
        
        # =====================================================================
        # DISABLE action
        # =====================================================================
        if args.action == 'disable':
            if args.ssids:
                # =====================================================================
                # DISABLE SSID action
                # =====================================================================
                print("Fetching UniFi SSIDs...")
                ssids = unifi_utils.get_ssids()
                if not ssids:
                    print("No SSIDs found.")
                    sys.exit(0)
                
                # Find matching SSIDs
                matching_ssids = []
                if args.name:
                    # Exact match by name
                    matching_ssids = [ssid for ssid in ssids if ssid.get("name", "").lower() == args.name.lower()]
                elif args.filter_name:
                    # Substring match
                    matching_ssids = [ssid for ssid in ssids if args.filter_name.lower() in ssid.get("name", "").lower()]
                else:
                    # No specific SSID or filter: disable ALL SSIDs
                    matching_ssids = ssids
                
                if not matching_ssids:
                    print(f"No SSIDs found matching the specified criteria.")
                    sys.exit(0)
                
                print(f"\nDisabling {len(matching_ssids)} SSID(s)...")
                for ssid in matching_ssids:
                    ssid_name = ssid.get("name", "Unknown")
                    is_enabled_before = "Yes" if ssid.get("enabled", False) else "No"
                    print(f"  {ssid_name} (enabled: {is_enabled_before} → ", end="", flush=True)
                    if unifi_utils.disable_ssid(ssid_name):
                        print(f"No)... [OK]")
                    else:
                        print(f"?)... [FAIL]")
                sys.exit(0)
            
            elif args.aps:
                # =====================================================================
                # DISABLE AP action
                # =====================================================================
                print("Fetching UniFi devices...")
                all_devices = unifi_utils.get_devices()
                aps = [device for device in all_devices if device.get("type") == "uap"]
                
                if not aps:
                    print("No Access Points found.")
                    sys.exit(0)
                
                # Find matching APs
                matching_aps = []
                if args.name:
                    # Exact match by name
                    matching_aps = [ap for ap in aps if (ap.get("name") or ap.get("model", "")).lower() == args.name.lower()]
                elif args.filter_name:
                    # Substring match by name
                    matching_aps = [ap for ap in aps if args.filter_name.lower() in (ap.get("name") or ap.get("model", "")).lower()]
                elif args.filter_mac:
                    # Substring match by MAC
                    filter_mac_lower = args.filter_mac.lower()
                    matching_aps = [ap for ap in aps if filter_mac_lower in ap.get("mac", "").lower()]
                else:
                    # No specific AP or filter: disable ALL APs
                    matching_aps = aps
                
                if not matching_aps:
                    print(f"No Access Points found matching the specified criteria.")
                    sys.exit(0)
                
                print(f"\nDisabling {len(matching_aps)} AP(s)...")
                for ap in matching_aps:
                    ap_name = ap.get("name") or ap.get("model", "Unknown AP")
                    ap_mac = ap.get("mac", "N/A")
                    is_enabled_before = "Yes" if not ap.get("disabled", False) else "No"
                    print(f"  {ap_name} (enabled: {is_enabled_before} → ", end="", flush=True)
                    if unifi_utils.disable_ap(ap_mac):
                        print(f"No)... [OK]")
                    else:
                        print(f"?)... [FAIL]")
                sys.exit(0)
        
        # =====================================================================
        # ACTION commands (lock, unlock, reconnect, forget, block, unblock)
        # For all these actions, fetch and filter clients
        # =====================================================================
        print("Fetching UniFi clients...")
        clients = unifi_utils.get_all_unifi_clients()
        if not clients:
            print("No clients found.")
            sys.exit(0)

        # Add "number" key for numbering (before filtering)
        for i, client in enumerate(clients):
            client["number"] = i + 1

        # Apply filters using hasattr to check for filter arguments
        filtered_clients = []
        for client in clients:
            match = True
            if hasattr(args, 'filter_online') and args.filter_online and not client.get("is_connected_live", False):
                match = False
            elif hasattr(args, 'filter_offline') and args.filter_offline and client.get("is_connected_live", False):
                match = False
            if hasattr(args, 'filter_ip') and args.filter_ip:
                if client.get("display_ip") != args.filter_ip:
                    match = False
            if hasattr(args, 'filter_dns_name') and args.filter_dns_name:
                if client.get("dns_name") != args.filter_dns_name:
                    match = False
            if hasattr(args, 'filter_hostname') and args.filter_hostname:
                if client.get("hostname") != args.filter_hostname:
                    match = False
            if hasattr(args, 'filter_mac') and args.filter_mac:
                client_mac = client.get("mac", "")
                if args.filter_mac.lower() not in client_mac.lower():
                    match = False
            if hasattr(args, 'filter_signal_above') and args.filter_signal_above is not None:
                signal = client.get("live_signal")
                if not client.get("is_connected_live", False) or signal is None or signal <= args.filter_signal_above:
                    match = False
            if hasattr(args, 'filter_signal_below') and args.filter_signal_below is not None:
                signal = client.get("live_signal")
                if not client.get("is_connected_live", False) or signal is None or signal >= args.filter_signal_below:
                    match = False
            if hasattr(args, 'filter_locked') and args.filter_locked and not client.get("is_ap_locked", False):
                match = False
            elif hasattr(args, 'filter_unlocked') and args.filter_unlocked and client.get("is_ap_locked", False):
                match = False
            if match:
                filtered_clients.append(client)

        # Re-number filtered clients
        for i, client in enumerate(filtered_clients):
            client["number"] = i + 1

        if not filtered_clients:
            print("No clients found matching the specified filters.")
            sys.exit(0)

        print(f"\n{len(filtered_clients)} client(s) matched the filter.")

        # Execute action
        if args.action == 'lock_client':
            if args.ap_mac:
                ap_mac = args.ap_mac.replace(':', '').replace('-', '').lower()
                target_desc = f"AP MAC {ap_mac}"
            elif args.ap_name:
                ap_mac = unifi_utils.get_ap_mac_by_name(args.ap_name)
                if not ap_mac:
                    print(f"Error: Could not find AP with name '{args.ap_name}'.")
                    sys.exit(1)
                target_desc = f"AP {args.ap_name}"
            else:  # connected_ap
                print("Locking each client to its currently connected AP...")
                results = {}
                for client in filtered_clients:
                    mac = client.get("mac")
                    live_ap_mac = client.get("live_ap_mac")
                    if client.get("is_connected_live") and live_ap_mac and mac:
                        results[mac.lower()] = unifi_utils.lock_client_to_ap(mac, live_ap_mac)
                print_action_results_table(filtered_clients, "lock", results)
                sys.exit(0)
            
            # Lock to specific AP
            print(f"Locking to {target_desc}...")
            results = {}
            for client in filtered_clients:
                mac = client.get("mac")
                if mac:
                    results[mac.lower()] = unifi_utils.lock_client_to_ap(mac, ap_mac)
            print_action_results_table(filtered_clients, "lock", results)
        
        elif args.action == 'unlock_client':
            print("Unlocking clients...")
            results = {}
            for client in filtered_clients:
                mac = client.get("mac")
                if mac:
                    results[mac.lower()] = unifi_utils.unlock_client_from_ap(mac)
            print_action_results_table(filtered_clients, "unlock", results)
        
        elif args.action == 'reconnect_client':
            print("Reconnecting clients...")
            results = {}
            for client in filtered_clients:
                mac = client.get("mac")
                if mac:
                    results[mac.lower()] = unifi_utils.reconnect_client(mac)
            print_action_results_table(filtered_clients, "reconnect", results)
        
        elif args.action == 'forget':
            handle_forget_action_batch(filtered_clients)
        
        elif args.action == 'block_client':
            print("Blocking clients...")
            results = {}
            for client in filtered_clients:
                mac = client.get("mac")
                if mac:
                    results[mac.lower()] = unifi_utils.block_client(mac)
            print_action_results_table(filtered_clients, "block", results)
        
        elif args.action == 'unblock_client':
            print("Unblocking clients...")
            results = {}
            for client in filtered_clients:
                mac = client.get("mac")
                if mac:
                    results[mac.lower()] = unifi_utils.unblock_client(mac)
            print_action_results_table(filtered_clients, "unblock", results)

    except nss.error.NSPRError as e:
        # Certificate validation error - provide helpful guidance
        error_msg = format_nss_error("UniFi Controller", UNIFI_NETWORK_URL, e, sys.argv[0])
        print(error_msg, file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        # Catch any exception and print an informative error message
        print(f"An error occurred: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        # Ensure the opener is cleaned up on exit
        unifi_utils.cleanup()
