#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 netcon-sync contributors
# 
# This file is part of netcon-sync.
# netcon-sync is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# netcon-sync is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

"""
pfsense2unifi - Sync DHCP reservations from pfSense to UniFi Controller

This script syncs DHCP static mappings from a pfSense router to a UniFi
controller, creating or updating known clients in UniFi based on pfSense
DHCP reservations.

Features:
  - Filters clients by description suffix
  - Supports custom suffix via CLI argument
  - Handles certificate trust via NSS database
  - Supports both CA-based and server certificate trust
  - Orphan detection and optional deletion
"""

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

import json
import requests
import argparse
import nss.error
import sys
from pathlib import Path

# Import configuration - UniFi is always required at import
# pfSense config will be loaded later in main()
UNIFI_NETWORK_URL = None
UNIFI_SITE_ID = None
_unifi_import_error = None

try:
    from config import UNIFI_NETWORK_URL, UNIFI_SITE_ID, load_pfsense_config
except ImportError as e:
    print(f"ERROR: Failed to import config: {e}")
    print("Please run: ./install_deps.sh")
    sys.exit(1)
except ValueError as e:
    # Store the error - we'll show help + error in main()
    _unifi_import_error = e
    UNIFI_NETWORK_URL = None
    UNIFI_SITE_ID = None

# Global variables - will be set in main() after parser is ready
PFSENSE_URL = None
PFSENSE_APIV2_KEY = None
PFSENSE_DHCP_INTERFACE = None

# Import functions from the provided utility files
try:
    from pfsense_utils import get_pfsense_dhcp_static_mappings, validate_mac_address
    from unifi_utils import login, add_client, get_all_unifi_clients, forget_client, forget_clients_batch
    from trust import handle_trust_ca_cert, handle_trust_server_url, format_nss_error, ensure_nss_db
    from urllib.parse import urlparse
except ModuleNotFoundError as e:
    print(f"ERROR: Missing required dependency: {e}")
    print("\nPlease run the setup script:")
    print("  ./install_deps.sh")
    sys.exit(1)
except ValueError as e:
    # Store config error from pfsense_utils import chain
    _unifi_import_error = e

def handle_orphaned_clients(synced_macs: set, delete_orphans: bool = False) -> dict:
    """
    Detects clients in UniFi that were not updated by the sync process.
    Optionally deletes them if delete_orphans flag is set.

    Args:
        synced_macs (set): Set of MAC addresses that were synced from pfSense
        delete_orphans (bool): If True, delete orphaned clients; if False, just report them

    Returns:
        dict: Results of orphan detection/deletion
    """
    from unifi_utils import get_unifi_clients_fast

    orphan_results = {
        "found": [],
        "deleted": [],
        "failed_to_delete": []
    }

    print("\nChecking for orphaned clients in UniFi...")
    unifi_clients_by_mac = get_unifi_clients_fast()

    # Normalize synced MACs to lowercase for comparison
    synced_macs_lower = {mac.lower() for mac in synced_macs}

    # Find clients in UniFi that aren't in our synced list
    for mac, client in unifi_clients_by_mac.items():
        if mac not in synced_macs_lower:
            client_name = client.get("name") or client.get("hostname") or mac
            orphan_results["found"].append({
                "mac": mac,
                "name": client_name,
                "hostname": client.get("hostname"),
                "note": client.get("note")
            })

    if not orphan_results["found"]:
        print("No orphaned clients found.")
        return orphan_results

    print(f"Found {len(orphan_results['found'])} orphaned clients in UniFi:")
    for client in orphan_results["found"]:
        print(f"  - {client['mac']}: {client['name']}")

    if delete_orphans:
        print("\nDeleting orphaned clients (batch operation)...")
        orphan_macs = [client["mac"] for client in orphan_results["found"]]

        # Use batch forget for efficiency (single API call instead of one per client)
        batch_result = forget_clients_batch(orphan_macs)

        if batch_result["success"]:
            orphan_results["deleted"] = orphan_results["found"]
            print(f"  [OK] Deleted {batch_result['sent']} orphaned clients in single API call")
        else:
            orphan_results["failed_to_delete"] = orphan_results["found"]
            print(f"  [FAIL] Failed to delete orphaned clients")

        print(f"\nDeleted {len(orphan_results['deleted'])}/{len(orphan_results['found'])} orphaned clients")
        if orphan_results["failed_to_delete"]:
            print(f"WARNING: Failed to delete {len(orphan_results['failed_to_delete'])} clients")
    else:
        print("\nUse --delete-orphans flag to delete these orphaned clients.")

    return orphan_results


def sync_pfsense_dhcp_to_unifi(delete_orphans: bool = False, suffix: str = None):
    """
    Fetches DHCP static mappings from pfSense (filtered by description ending in suffix),
    strips the suffix, and attempts to add/update them as known clients in UniFi with
    their modified descriptions as names and pfSense hostname as notes.

    Optimized to fetch client list ONCE and send API calls directly,
    avoiding repeated full-list fetches per client.

    Args:
        delete_orphans (bool): Whether to delete orphaned clients
        suffix (str): Description suffix to filter by (defaults to " - Wifi")
    """

    print("WARNING: Please backup your UniFi configuration before migration!")
    print("   Use UniFi's built-in backup feature in System Settings > Backup & Restore")
    print()

    from unifi_utils import make_unifi_api_call, build_client_payload, get_unifi_clients_fast
    import time

    # Use provided suffix or default to " - Wifi"
    # Special case: "NONE" means no filtering (sync all clients)
    client_suffix = suffix if suffix else " - Wifi"
    no_suffix_filter = (client_suffix == "NONE")

    # Track results
    results = {
        "created": [],
        "updated": [],
        "failed": [],
        "filtered_out": [],
        "invalid_mac": []
    }

    # Track synced MACs for orphan detection
    synced_macs = set()

    try:
        # STEP 1: Fetch DHCP static mappings from pfSense FIRST
        print("Fetching DHCP static mappings from pfSense...")
        try:
            pfsense_mappings = get_pfsense_dhcp_static_mappings()
        except nss.error.NSPRError as e:
            error_msg = format_nss_error("pfSense", PFSENSE_URL, e, sys.argv[0])
            print(error_msg, file=sys.stderr)
            sys.exit(1)

        if not pfsense_mappings:
            print("No DHCP static mappings found in pfSense. Nothing to sync.")
            return

        print(f"Found {len(pfsense_mappings)} static mappings in pfSense.")

        # STEP 2: Login to UniFi
        print("Attempting to log into UniFi Controller...")
        login()
        print("UniFi login successful.")

        # STEP 3: Pre-fetch all UniFi clients ONCE (the only time we fetch the full list)
        print("\nPre-fetching all UniFi clients...")
        unifi_clients_by_mac = get_unifi_clients_fast()
        print(f"Found {len(unifi_clients_by_mac)} existing clients in UniFi.")

        # STEP 4: Process pfSense mappings and send API calls directly
        print(f"\nProcessing {len(pfsense_mappings)} pfSense DHCP mappings...")

        for i, client_data in enumerate(pfsense_mappings, 1):
            loop_start = time.time()
            mac = client_data.get("mac")
            descr = client_data.get("descr")
            hostname = client_data.get("hostname")

            # Validate MAC
            if not mac or not validate_mac_address(mac):
                invalid_mac_str = mac if mac else "(missing)"
                print(f"  [{i}/{len(pfsense_mappings)}] Skipping invalid MAC: '{invalid_mac_str}'")
                results["invalid_mac"].append({
                    "mac": invalid_mac_str,
                    "description": descr or "(no description)",
                    "hostname": hostname or "(no hostname)"
                })
                continue

            # Strip trailing/leading whitespace from description for matching
            descr_stripped = descr.strip() if descr else ""

            # Apply filtering (skip if no_suffix_filter is True)
            if not no_suffix_filter:
                if not descr_stripped or not descr_stripped.endswith(client_suffix):
                    results["filtered_out"].append({
                        "mac": mac,
                        "description": descr or "(no description)",
                        "hostname": hostname or "(no hostname)"
                    })
                    continue

            # Build client name and note
            if no_suffix_filter:
                # No suffix filtering: use description as-is, or hostname if no description
                unifi_client_name = descr_stripped if descr_stripped else (hostname if hostname else f"AP (MAC: {mac})")
                unifi_note = hostname if hostname else ""
            else:
                # With suffix filtering: strip the suffix from description
                unifi_client_name = descr_stripped[:-len(client_suffix)].strip()
                if not unifi_client_name:
                    unifi_client_name = hostname if hostname else f"AP (MAC: {mac})"
                unifi_note = hostname if hostname else ""

            normalized_mac = mac.lower()
            existing_client = unifi_clients_by_mac.get(normalized_mac)

            try:
                if existing_client:
                    # UPDATE: Use existing client data
                    client_id = existing_client.get("_id")
                    if not client_id:
                        print(f"  [{i}/{len(pfsense_mappings)}] [FAIL] {mac}: No _id found")
                        results["failed"].append({"mac": mac, "name": unifi_client_name, "note": unifi_note})
                        continue

                    # Extract old values from existing client
                    old_name = existing_client.get("name") or ""
                    old_note = existing_client.get("note") or ""

                    # Determine new values
                    new_name = unifi_client_name
                    new_note = unifi_note or ""

                    # Check if anything actually changed
                    fields_changed = (
                        old_name != new_name or
                        old_note != new_note
                    )

                    if fields_changed:
                        # Only send API call if something actually changed
                        prep_start = time.time()
                        payload = build_client_payload(existing_client)
                        payload["name"] = unifi_client_name
                        payload["display_name"] = unifi_client_name
                        payload["note"] = new_note  # Always set note (even if empty)
                        prep_time = time.time() - prep_start

                        endpoint = f"/api/s/{UNIFI_SITE_ID}/rest/user/{client_id}"
                        api_start = time.time()
                        make_unifi_api_call("PUT", endpoint, json=payload)
                        api_time = time.time() - api_start

                        results["updated"].append({
                            "mac": mac,
                            "old_name": old_name,
                            "new_name": new_name,
                            "old_note": old_note,
                            "new_note": new_note
                        })
                else:
                    # CREATE: New client
                    payload = {
                        "mac": normalized_mac,
                        "blocked": False,
                        "display_name": unifi_client_name,
                        "name": unifi_client_name,
                        "note": unifi_note if unifi_note else "",
                        "usergroup_id": "",
                        "use_fixedip": False,
                        "fixed_ip": "",
                        "local_dns_record_enabled": False,
                        "local_dns_record": "",
                        "virtual_network_override_enabled": False,
                        "virtual_network_override_id": "",
                        "fixed_ap_enabled": False
                    }
                    # Remove empty strings
                    payload = {k: v for k, v in payload.items() if v != ""}

                    endpoint = f"/api/s/{UNIFI_SITE_ID}/rest/user"
                    api_start = time.time()
                    make_unifi_api_call("POST", endpoint, json=payload)
                    api_time = time.time() - api_start

                    results["created"].append({
                        "mac": mac,
                        "name": unifi_client_name,
                        "note": unifi_note or ""
                    })

                synced_macs.add(normalized_mac)
                loop_time = time.time() - loop_start
                debug_str = f" (api:{api_time:.2f}s total:{loop_time:.2f}s)" if loop_time > 0.2 else ""
                print(f"  [{i}/{len(pfsense_mappings)}] [OK] {mac}: {unifi_client_name}{debug_str}")
                sys.stdout.flush()  # Real-time display

            except Exception as e:
                results["failed"].append({
                    "mac": mac,
                    "name": unifi_client_name,
                    "note": unifi_note,
                    "error": str(e)
                })
                print(f"  [{i}/{len(pfsense_mappings)}] [FAIL] {mac}: {unifi_client_name} - {e}")
                sys.stdout.flush()
                sys.stdout.flush()  # Real-time display

        # FINAL: Verify clients at end (no DNS lookups needed)
        all_modified = results["created"] + results["updated"]
        if all_modified:
            print("\nVerifying clients in UniFi (batch check)...")
            unifi_clients_final = get_unifi_clients_fast()
            unifi_macs_final = set(unifi_clients_final.keys())
            verified_count = 0
            unverified = []

            for client_info in all_modified:
                if client_info["mac"].lower() in unifi_macs_final:
                    verified_count += 1
                else:
                    unverified.append(client_info)

            if unverified:
                results["failed"].extend(unverified)
                # Remove unverified from created and updated
                results["created"] = [c for c in results["created"] if c not in unverified]
                results["updated"] = [c for c in results["updated"] if c not in unverified]

            print(f"Verified {verified_count}/{len(all_modified)} clients in UniFi")

        # Print summary
        print("\n" + "="*70)
        print("SYNC SUMMARY")
        print("="*70)
        print(f"Total pfSense clients retrieved: {len(pfsense_mappings)}")
        print(f"  - Clients with invalid MAC format: {len(results['invalid_mac'])}")
        if no_suffix_filter:
            print(f"  - Suffix filtering: NONE (syncing all clients)")
        else:
            print(f"  - Clients filtered out (not ending in '{client_suffix}'): {len(results['filtered_out'])}")
        print(f"  - Clients successfully created in UniFi: {len(results['created'])}")
        print(f"  - Clients successfully updated in UniFi (fields changed): {len(results['updated'])}")
        print(f"  - Clients failed to add/update: {len(results['failed'])}")
        print("="*70)

        # Display created clients
        if results["created"]:
            print("\nADDED CLIENTS:")
            for client in results["created"]:
                print(f"  {client['mac']} ({client['name']})... [OK]")

        # Display updated clients (only those with changed fields)
        if results["updated"]:
            print("\nUPDATED CLIENTS (fields changed):")
            for client in results["updated"]:
                changes = []
                if client["old_name"] != client["new_name"]:
                    changes.append(f"name: {client['old_name']} -> {client['new_name']}")
                if client["old_note"] != client["new_note"]:
                    changes.append(f"note: {client['old_note']} -> {client['new_note']}")
                if changes:
                    change_str = ", ".join(changes)
                    print(f"  {client['mac']} ({change_str})... [OK]")

        if results["failed"]:
            print("\nFAILED CLIENTS:")
            for client in results["failed"]:
                error_msg = client.get("error", "Unknown error")
                print(f"  - {client['mac']}: {client['name']} - {error_msg}")

        if results["invalid_mac"]:
            print("\nINVALID MAC ADDRESSES:")
            for client in results["invalid_mac"]:
                print(f"  - {client['mac']}: {client['hostname']}")

        # Handle orphaned clients
        if synced_macs:
            orphan_results = handle_orphaned_clients(synced_macs, delete_orphans)
            if orphan_results["failed_to_delete"]:
                print("\nWARNING: Failed to delete some orphaned clients")
                sys.exit(1)

        if results["failed"] or results["invalid_mac"]:
            sys.exit(1)

    except nss.error.NSPRError as e:
        error_msg = format_nss_error("UniFi Controller", UNIFI_NETWORK_URL, e, sys.argv[0])
        print(error_msg, file=sys.stderr)
        sys.exit(1)
    except (ValueError, requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"An error occurred during sync: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        pass


class CustomFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom formatter that renames 'positional arguments' to 'commands'."""
    def start_section(self, heading):
        if heading == "positional arguments":
            heading = "commands"
        super().start_section(heading)

class HelpArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser that shows full help page on invalid arguments."""
    def error(self, message):
        """Override error to print help page instead of just error message."""
        sys.stderr.write(f"ERROR: {message}\n\n")
        self.print_help(sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    parser = HelpArgumentParser(
        description="Sync DHCP reservations from pfSense to UniFi controller",
        formatter_class=CustomFormatter,
        epilog=f"""ENVIRONMENT VARIABLES (REQUIRED):
  UNIFI_NETWORK_URL         UniFi controller URL (e.g., https://192.168.1.100:8443)
  UNIFI_USERNAME            UniFi admin username
  UNIFI_PASSWORD            UniFi admin password
  PFSENSE_URL               pfSense API endpoint (e.g., https://192.168.1.1)
  PFSENSE_APIV2_KEY         pfSense APIv2 key

ENVIRONMENT VARIABLES (OPTIONAL):
  UNIFI_SITE_ID             UniFi site ID (default: "default")
  PFSENSE_DHCP_INTERFACE    pfSense DHCP interface (default: "lan")

EXAMPLES:
  # Basic sync with default suffix " - Wifi"
  %(prog)s sync

  # Sync only clients ending in " - Wired"
  %(prog)s sync --suffix " - Wired"

  # Sync all clients without filtering
  %(prog)s sync --suffix NONE

  # Sync with custom suffix and delete orphans
  %(prog)s sync --suffix "@unifi" --delete-orphans

  # Trust a certificate before syncing
  %(prog)s trust --ca /path/to/ca_cert.pem
  %(prog)s trust --server https://pfsense.example.com"""
    )

    # Global options (appear in main help)
    parser.add_argument(
        "--delete-orphans",
        action="store_true",
        help="Delete UniFi clients not found in pfSense (for sync command only)"
    )
    parser.add_argument(
        "--suffix",
        metavar="SUFFIX",
        default=None,
        help="Client description suffix to filter by (for sync command only, default: ' - Wifi'). Use --suffix NONE to sync all clients without filtering"
    )

    # Trust certificate options (appear in main help)
    trust_options_group = parser.add_mutually_exclusive_group()
    trust_options_group.add_argument(
        "--ca",
        metavar="PATH",
        help="Import and trust a CA certificate from file (for trust command only, PEM or DER format)"
    )
    trust_options_group.add_argument(
        "--server",
        metavar="URL",
        help="Connect to a server URL and trust its certificate (for trust command only, e.g., https://example.com:8443)"
    )

    subparsers = parser.add_subparsers(dest="action", help="")

    # Sync subcommand
    sync_parser = subparsers.add_parser(
        "sync",
        help="Sync DHCP reservations from pfSense to UniFi"
    )
    sync_parser.add_argument(
        "--delete-orphans",
        action="store_true",
        help="Delete UniFi clients not found in pfSense. By default, performs merge: adds new clients, updates existing ones, leaves others alone. Use this flag to remove clients from UniFi that don't exist in pfSense."
    )
    sync_parser.add_argument(
        "--suffix",
        metavar="SUFFIX",
        default=None,
        help="Client description suffix to filter by (default: ' - Wifi'). Use --suffix NONE to sync all clients"
    )

    # Trust subcommand
    trust_parser = subparsers.add_parser(
        "trust",
        help="Trust a certificate for HTTPS connections (requires --ca or --server)"
    )
    trust_subgroup = trust_parser.add_mutually_exclusive_group(required=True)
    trust_subgroup.add_argument(
        "--ca",
        metavar="PATH",
        help="Import and trust a CA certificate from file (PEM or DER format)"
    )
    trust_subgroup.add_argument(
        "--server",
        metavar="URL",
        help="Connect to a server URL and trust its certificate (e.g., https://example.com:8443)"
    )

    args = parser.parse_args()

    # Check if UniFi config failed to load
    if _unifi_import_error:
        print(f"ERROR: Configuration Error: {_unifi_import_error}", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    # Initialize NSS database at startup (before any HTTPS connections)
    import nss.nss as nss_core

    nss_db_dir = Path.home() / ".netcon-sync"

    # Create NSS database if it doesn't exist
    try:
        ensure_nss_db(nss_db_dir)
    except RuntimeError as e:
        print(f"Error initializing NSS database: {e}", file=sys.stderr)
        sys.exit(1)

    # Initialize NSS
    try:
        nss_core.nss_init(str(nss_db_dir))
    except Exception as e:
        print(f"Error initializing NSS: {e}", file=sys.stderr)
        sys.exit(1)

    # Show help if no action specified
    if not args.action:
        # If --ca or --server provided without command, auto-run trust
        if args.ca or args.server:
            args.action = "trust"
        else:
            parser.print_help()
            sys.exit(0)

    # Load pfSense config when needed
    if args.action == "sync":
        try:
            PFSENSE_URL, PFSENSE_APIV2_KEY, PFSENSE_DHCP_INTERFACE = load_pfsense_config()
        except ValueError as e:
            print(f"ERROR: Configuration Error: {e}", file=sys.stderr)
            parser.print_help()
            sys.exit(1)
        sync_pfsense_dhcp_to_unifi(delete_orphans=args.delete_orphans, suffix=args.suffix)
    elif args.action == "trust":
        nss_db_dir = Path.home() / ".netcon-sync"
        if args.ca:
            handle_trust_ca_cert(nss_db_dir, args.ca)
        elif args.server:
            handle_trust_server_url(nss_db_dir, args.server)
