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
pfsense_dhcp - Backup and restore pfSense DHCP configuration

This script authenticates to pfSense web interface and manages DHCP
server configuration using the built-in backup/restore features.
Uses NSS/NSPR for secure TLS connections with certificate validation.

Features:
  - Form-based authentication to pfSense web interface
  - Backup DHCP configuration via backup feature
  - Restore DHCP configuration via restore feature
  - NSS database-backed certificate verification
  - Certificate trust management (trust CA or server cert)
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

import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlencode
import nss.error
import nss.nss as nss_core

# Import project utilities
try:
    from http_tls_nss import NSPRNSSURLOpener
    from trust import ensure_nss_db, format_nss_error, handle_trust_ca_cert, handle_trust_server_url
except ModuleNotFoundError as e:
    print(f"ERROR: Missing required dependency: {e}")
    print("\nPlease run the setup script:")
    print("  ./install_deps.sh")
    sys.exit(1)

# Load credentials from environment variables
PFSENSE_URL = os.getenv("PFSENSE_URL")
PFSENSE_USERNAME = os.getenv("PFSENSE_USERNAME")
PFSENSE_PASSWORD = os.getenv("PFSENSE_PASSWORD")


class PfSenseClient:
    """Client for pfSense backup/restore operations using NSS/NSPR for TLS."""

    def __init__(self, base_url, username, password):
        """
        Initialize pfSense client.

        Args:
            base_url (str): pfSense base URL (with https://)
            username (str): pfSense web UI username
            password (str): pfSense web UI password
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.opener = NSPRNSSURLOpener()
        self.csrf_token = None

    def login(self):
        """
        Authenticate to pfSense web interface using form-based login.

        Returns:
            bool: True if login successful

        Raises:
            Exception: If login fails
        """
        print(f"Authenticating to pfSense at {self.base_url}...")

        # Step 1: GET the login page to extract CSRF token
        login_page_url = f"{self.base_url}/index.php"
        try:
            response = self.opener.request("GET", login_page_url)
            html = response.read().decode('utf-8')

            # Extract CSRF token from the form
            csrf_start = html.find("name='__csrf_magic'")
            if csrf_start > 0:
                value_start = html.find("value=\"", csrf_start)
                if value_start > 0:
                    value_start += 7  # len('value="')
                    value_end = html.find("\"", value_start)
                    if value_end > 0:
                        self.csrf_token = html[value_start:value_end]
        except Exception as e:
            raise Exception(f"Failed to fetch login page: {e}")

        # Step 2: POST credentials to login
        login_data = {
            "__csrf_magic": self.csrf_token or "",
            "usernamefld": self.username,
            "passwordfld": self.password,
            "login": "Sign In"
        }

        login_post_data = urlencode(login_data).encode('utf-8')
        login_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": login_page_url
        }

        try:
            response = self.opener.request(
                "POST",
                login_page_url,
                data=login_post_data,
                headers=login_headers
            )

            response_text = response.read().decode('utf-8')

            # Check if login was successful
            if "Username or Password incorrect" in response_text:
                raise Exception("Login failed: Invalid username or password")

            # Successful login redirects or shows dashboard
            if "Dashboard" in response_text or response.getcode() in (200, 302):
                print("OK: Authentication successful")
                return True

            raise Exception("Login failed: Unexpected response")

        except Exception as e:
            if "Username or Password incorrect" in str(e):
                raise
            raise Exception(f"Failed to authenticate: {e}")

    def backup_dhcp_config(self, interface="lan", debug=False):
        """
        Backup DHCP configuration using pfSense backup feature.

        Args:
            interface (str): Interface name (e.g., "lan", "wan", "opt1")
            debug (bool): Enable debug output

        Returns:
            str: XML configuration data

        Raises:
            Exception: If backup download fails
        """
        print(f"Fetching DHCP configuration for interface '{interface}'...")

        backup_url = f"{self.base_url}/diag_backup.php"

        # Step 1: GET the backup page to get fresh CSRF token
        try:
            response = self.opener.request("GET", backup_url)
            html = response.read().decode('utf-8')

            if debug:
                with open("backup_form.html", "w") as f:
                    f.write(html)
                print("DEBUG: Saved backup form HTML to backup_form.html")

            # Extract fresh CSRF token
            import re
            csrf_patterns = [
                r"name=['\"]__csrf_magic['\"].*?value=['\"]([^'\"]+)['\"]",
                r"value=['\"]([^'\"]+)['\"].*?name=['\"]__csrf_magic['\"]",
            ]

            fresh_csrf_token = None
            for pattern in csrf_patterns:
                match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
                if match:
                    fresh_csrf_token = match.group(1)
                    break

            if fresh_csrf_token:
                self.csrf_token = fresh_csrf_token

        except Exception as e:
            print(f"Warning: Could not fetch backup page for CSRF token: {e}")

        # Step 2: POST backup request
        backup_data = {
            "download": "Download configuration as XML",
            "donotbackuprrd": "yes",
            "backuparea": "dhcpd"
        }

        if self.csrf_token:
            backup_data["__csrf_magic"] = self.csrf_token

        if debug:
            print(f"DEBUG: Posting data: {backup_data}")

        backup_post_data = urlencode(backup_data).encode('utf-8')
        backup_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": backup_url
        }

        try:
            response = self.opener.request(
                "POST",
                backup_url,
                data=backup_post_data,
                headers=backup_headers
            )

            config_xml = response.read().decode('utf-8')

            if debug:
                print(f"DEBUG: Received {len(config_xml)} bytes")

            # Verify we got XML
            config_xml_stripped = config_xml.strip()
            if not (config_xml_stripped.startswith("<?xml") or config_xml_stripped.startswith("<dhcpd")):
                if "<html" in config_xml.lower():
                    raise Exception("Received HTML instead of XML - possibly not authenticated")
                raise Exception("Invalid response format (not XML)")

            print("OK: Configuration downloaded successfully")
            return config_xml

        except Exception as e:
            raise Exception(f"Failed to fetch backup configuration: {e}")

    def restore_dhcp_config(self, xml_data, debug=False):
        """
        Restore DHCP configuration using pfSense restore feature.

        Args:
            xml_data (str): XML configuration data to restore
            debug (bool): Enable debug output

        Returns:
            dict: Restore result with status and message

        Raises:
            Exception: If restore fails
        """
        print(f"Preparing to restore DHCP configuration...")

        restore_url = f"{self.base_url}/diag_backup.php"

        # Step 1: GET the restore page to get fresh CSRF token
        try:
            response = self.opener.request("GET", restore_url)
            html = response.read().decode('utf-8')

            if debug:
                with open("restore_form.html", "w") as f:
                    f.write(html)
                print("DEBUG: Saved restore form HTML to restore_form.html")

            # Extract fresh CSRF token
            import re
            csrf_patterns = [
                r"name=['\"]__csrf_magic['\"].*?value=['\"]([^'\"]+)['\"]",
                r"value=['\"]([^'\"]+)['\"].*?name=['\"]__csrf_magic['\"]",
            ]

            fresh_csrf_token = None
            for pattern in csrf_patterns:
                match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
                if match:
                    fresh_csrf_token = match.group(1)
                    break

            if fresh_csrf_token:
                self.csrf_token = fresh_csrf_token
                if debug:
                    print(f"DEBUG: Using CSRF token: {self.csrf_token[:20]}...")

        except Exception as e:
            print(f"Warning: Could not fetch restore page for CSRF token: {e}")

        # Step 2: Prepare multipart form data
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        parts = []

        # Add CSRF token
        if self.csrf_token:
            parts.append(f'--{boundary}')
            parts.append('Content-Disposition: form-data; name="__csrf_magic"')
            parts.append('')
            parts.append(self.csrf_token)

        # Add restorearea parameter
        parts.append(f'--{boundary}')
        parts.append('Content-Disposition: form-data; name="restorearea"')
        parts.append('')
        parts.append('dhcpd')

        # Add configuration file
        parts.append(f'--{boundary}')
        parts.append('Content-Disposition: form-data; name="conffile"; filename="config.xml"')
        parts.append('Content-Type: application/xml')
        parts.append('')
        parts.append(xml_data)

        # Add restore button
        parts.append(f'--{boundary}')
        parts.append('Content-Disposition: form-data; name="restore"')
        parts.append('')
        parts.append('Restore Configuration')

        # Final boundary
        parts.append(f'--{boundary}--')
        parts.append('')

        multipart_data = '\r\n'.join(parts).encode('utf-8')

        if debug:
            print(f"DEBUG: Multipart data size: {len(multipart_data)} bytes")

        restore_headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Referer": restore_url
        }

        # Step 3: POST restore request
        print("Uploading configuration to pfSense...")
        try:
            response = self.opener.request(
                "POST",
                restore_url,
                data=multipart_data,
                headers=restore_headers
            )

            response_text = response.read().decode('utf-8')

            if debug:
                with open("restore_response.html", "w") as f:
                    f.write(response_text)
                print("DEBUG: Saved restore response to restore_response.html")

            # Check for success/error indicators
            success_messages = [
                "configuration area has been restored",
                "successfully restored",
                "restore completed"
            ]

            error_messages = [
                "error",
                "failed",
                "invalid",
                "could not restore"
            ]

            response_lower = response_text.lower()

            if any(msg in response_lower for msg in success_messages):
                print("OK: Configuration restored successfully")
                print("\nNOTE: pfSense configuration has been updated.")
                print("      Changes may require services to be restarted.")
                print("      Check pfSense web UI for any warnings or required actions.")
                return {"success": True, "message": "Configuration restored successfully"}

            if any(msg in response_lower for msg in error_messages):
                import re
                error_pattern = r'<div[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>([^<]+)</div>'
                error_match = re.search(error_pattern, response_text, re.IGNORECASE)
                if error_match:
                    error_msg = error_match.group(1).strip()
                    raise Exception(f"Restore failed: {error_msg}")
                else:
                    raise Exception("Restore failed (error detected but not parsed)")

            print("WARNING: Restore request completed but success unclear")
            print("  Please check pfSense web UI to verify restore status")
            return {"success": None, "message": "Restore request completed - verify in pfSense UI"}

        except Exception as e:
            if "Restore failed:" in str(e):
                raise
            raise Exception(f"Failed to restore configuration: {e}")


def parse_dhcp_config(xml_data, interface="lan"):
    """
    Parse DHCP configuration from pfSense config XML.

    Args:
        xml_data (str): XML configuration data
        interface (str): Interface to extract (e.g., "lan", or None for all)

    Returns:
        dict or list: Parsed DHCP configuration
    """
    try:
        # Add XML declaration for parsing if missing
        xml_for_parsing = xml_data
        if not xml_data.strip().startswith("<?xml"):
            xml_for_parsing = '<?xml version="1.0"?>\n' + xml_data

        root = ET.fromstring(xml_for_parsing)

        # Handle two XML structures
        if root.tag == "pfsense":
            dhcpd = root.find("dhcpd")
            if dhcpd is None:
                return {"error": "No DHCP configuration found in backup"}
        elif root.tag == "dhcpd":
            dhcpd = root
        else:
            return {"error": f"Unexpected root element: {root.tag}"}

        # Get all interfaces or specific one
        configs = []
        interfaces_to_show = []

        if interface:
            interface_config = dhcpd.find(interface)
            if interface_config is not None:
                interfaces_to_show.append((interface, interface_config))
            else:
                available = [elem.tag for elem in dhcpd]
                return {
                    "error": f"Interface '{interface}' not found",
                    "available_interfaces": available
                }
        else:
            interfaces_to_show = [(elem.tag, elem) for elem in dhcpd]

        for iface_name, iface_config in interfaces_to_show:
            config = {
                "interface": iface_name,
                "enabled": iface_config.find("enable") is not None,
                "range_from": _get_elem_text(iface_config, "range/from"),
                "range_to": _get_elem_text(iface_config, "range/to"),
                "gateway": _get_elem_text(iface_config, "gateway"),
                "domain": _get_elem_text(iface_config, "domain"),
                "dnsserver": [],
                "static_mappings": []
            }

            # Extract DNS servers
            for dns in iface_config.findall("dnsserver"):
                if dns.text:
                    config["dnsserver"].append(dns.text)

            # Extract static mappings
            for mapping in iface_config.findall("staticmap"):
                static = {
                    "mac": _get_elem_text(mapping, "mac"),
                    "ipaddr": _get_elem_text(mapping, "ipaddr"),
                    "hostname": _get_elem_text(mapping, "hostname"),
                    "descr": _get_elem_text(mapping, "descr"),
                    "arp_table_static_entry": _get_elem_text(mapping, "arp_table_static_entry"),
                    "dnsserver": [],
                    "domain": _get_elem_text(mapping, "domain"),
                    "gateway": _get_elem_text(mapping, "gateway"),
                    "domainsearchlist": _get_elem_text(mapping, "domainsearchlist"),
                    "defaultleasetime": _get_elem_text(mapping, "defaultleasetime"),
                    "maxleasetime": _get_elem_text(mapping, "maxleasetime"),
                }

                for dns in mapping.findall("dnsserver"):
                    if dns.text:
                        static["dnsserver"].append(dns.text)

                config["static_mappings"].append(static)

            configs.append(config)

        return configs if len(configs) > 1 else configs[0]

    except ET.ParseError as e:
        return {"error": f"Failed to parse XML: {e}"}
    except Exception as e:
        return {"error": f"Failed to parse configuration: {e}"}


def _get_elem_text(parent, path):
    """Helper to safely extract element text."""
    elem = parent.find(path)
    return elem.text if elem is not None and elem.text else ""


def validate_dhcp_xml(xml_data):
    """Validate XML structure."""
    try:
        xml_for_parsing = xml_data
        if not xml_data.strip().startswith("<?xml"):
            xml_for_parsing = '<?xml version="1.0"?>\n' + xml_data

        root = ET.fromstring(xml_for_parsing)

        if root.tag == "dhcpd":
            interfaces = [elem.tag for elem in root]
            return {
                "valid": True,
                "type": "DHCP-only backup",
                "interfaces": interfaces,
                "message": f"Valid DHCP configuration for interfaces: {', '.join(interfaces)}"
            }
        elif root.tag == "pfsense":
            dhcpd = root.find("dhcpd")
            if dhcpd is not None:
                interfaces = [elem.tag for elem in dhcpd]
                return {
                    "valid": True,
                    "type": "Full backup (contains DHCP)",
                    "interfaces": interfaces,
                    "message": f"Valid full configuration with DHCP for interfaces: {', '.join(interfaces)}"
                }
            else:
                return {"valid": False, "message": "No DHCP configuration found"}
        else:
            return {"valid": False, "message": f"Unexpected root element: {root.tag}"}

    except ET.ParseError as e:
        return {"valid": False, "message": f"Invalid XML: {e}"}
    except Exception as e:
        return {"valid": False, "message": f"Validation error: {e}"}


def print_dhcp_config(config, verbose=False):
    """Pretty-print DHCP configuration."""
    if isinstance(config, dict) and "error" in config:
        print(f"\nERROR: {config['error']}")
        if "available_interfaces" in config:
            print(f"Available interfaces: {', '.join(config['available_interfaces'])}")
        return

    # Handle single config or list of configs
    configs = [config] if isinstance(config, dict) else config

    print(f"\n{'='*60}")
    print(f"DHCP Server Configuration")
    print(f"{'='*60}")

    for cfg in configs:
        print(f"\nInterface: {cfg['interface']}")
        print(f"  Status: {'Enabled' if cfg['enabled'] else 'Disabled'}")
        print(f"  Range: {cfg['range_from']} - {cfg['range_to']}")
        print(f"  Gateway: {cfg['gateway']}")
        print(f"  Domain: {cfg['domain']}")

        if cfg['dnsserver']:
            print(f"  DNS Servers: {', '.join(cfg['dnsserver'])}")

        print(f"  Static Mappings: {len(cfg['static_mappings'])}")

        if verbose and cfg['static_mappings']:
            print(f"\n  Static DHCP Mappings:")
            print(f"  {'-'*56}")
            for i, mapping in enumerate(cfg['static_mappings'], 1):
                print(f"\n  [{i}] {mapping['hostname'] or '(no hostname)'}")
                print(f"      MAC:         {mapping['mac']}")
                print(f"      IP Address:  {mapping['ipaddr']}")
                print(f"      Description: {mapping['descr'] or '(none)'}")
                if mapping.get('dnsserver'):
                    print(f"      DNS Servers: {', '.join(mapping['dnsserver'])}")
                if mapping.get('domain'):
                    print(f"      Domain:      {mapping['domain']}")
                if mapping.get('gateway'):
                    print(f"      Gateway:     {mapping['gateway']}")
                if mapping.get('domainsearchlist'):
                    print(f"      Search List: {mapping['domainsearchlist']}")
                if mapping.get('defaultleasetime'):
                    print(f"      Lease Time:  {mapping['defaultleasetime']}s (default)")
                if mapping.get('maxleasetime'):
                    print(f"      Max Lease:   {mapping['maxleasetime']}s")
                if mapping['arp_table_static_entry']:
                    print(f"      ARP Static:  Yes")

    print(f"\n{'='*60}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Backup and restore pfSense DHCP configuration with NSS-based SSL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables (Required):
  PFSENSE_URL       pfSense base URL (e.g., https://pfsense.local)
  PFSENSE_USERNAME  pfSense web UI username
  PFSENSE_PASSWORD  pfSense web UI password

Examples:
  # Backup DHCP configuration
  %(prog)s backup --output dhcp_lan.xml
  %(prog)s backup --output dhcp_lan.xml --interface lan --verbose

  # Restore DHCP configuration
  %(prog)s restore --input dhcp_lan.xml
  %(prog)s restore --input dhcp_lan.xml --dry-run

  # Trust pfSense certificate
  %(prog)s trust --server
  %(prog)s trust --ca <ca-file.crt>
        """
    )

    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    subparsers = parser.add_subparsers(dest="command", required=True, help="Commands")

    # Backup command
    backup_parser = subparsers.add_parser("backup", help="Backup DHCP configuration")
    backup_parser.add_argument("--interface", default="lan", help="DHCP interface (default: lan)")
    backup_parser.add_argument("--output", required=True, help="Output XML filename")
    backup_parser.add_argument("--verbose", action="store_true", help="Show detailed static mappings")

    # Restore command
    restore_parser = subparsers.add_parser("restore", help="Restore DHCP configuration")
    restore_parser.add_argument("--input", required=True, help="Input XML configuration file")
    restore_parser.add_argument("--interface", help="Specific interface to restore (default: all)")
    restore_parser.add_argument("--dry-run", action="store_true", help="Preview without restoring")

    # Trust command
    trust_parser = subparsers.add_parser("trust", help="Trust pfSense certificate")
    trust_group = trust_parser.add_mutually_exclusive_group(required=True)
    trust_group.add_argument("--server", action="store_true", help="Trust server certificate")
    trust_group.add_argument("--ca", metavar="CA_FILE", help="Trust CA certificate file")

    args = parser.parse_args()

    # Validate environment variables (not needed for trust command)
    if args.command != "trust":
        if not PFSENSE_URL or not PFSENSE_USERNAME or not PFSENSE_PASSWORD:
            missing = []
            if not PFSENSE_URL:
                missing.append("PFSENSE_URL")
            if not PFSENSE_USERNAME:
                missing.append("PFSENSE_USERNAME")
            if not PFSENSE_PASSWORD:
                missing.append("PFSENSE_PASSWORD")

            print(f"ERROR: Missing environment variables: {', '.join(missing)}", file=sys.stderr)
            print("\nSet required environment variables:", file=sys.stderr)
            print("  export PFSENSE_URL='https://pfsense.local'", file=sys.stderr)
            print("  export PFSENSE_USERNAME='admin'", file=sys.stderr)
            print("  export PFSENSE_PASSWORD='your_password'", file=sys.stderr)
            return 1

    # Initialize NSS database
    nss_db_dir = Path.home() / ".netcon-sync"
    ensure_nss_db(nss_db_dir)

    try:
        nss_core.nss_init(str(nss_db_dir))
    except Exception as e:
        print(f"Error initializing NSS: {e}", file=sys.stderr)
        return 1

    # Handle trust command
    if args.command == "trust":
        try:
            nss_db_dir = Path.home() / ".netcon-sync"
            if args.server:
                handle_trust_server_url(nss_db_dir, PFSENSE_URL)
            elif args.ca:
                handle_trust_ca_cert(nss_db_dir, args.ca)
            print("Certificate trust operation completed successfully")
            return 0
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1

    # Create client
    try:
        client = PfSenseClient(PFSENSE_URL, PFSENSE_USERNAME, PFSENSE_PASSWORD)

        # Handle backup command
        if args.command == "backup":
            client.login()
            xml_data = client.backup_dhcp_config(args.interface, debug=args.debug)

            # Save XML
            output_path = Path(args.output)
            output_path.write_text(xml_data)
            print(f"OK: Configuration saved to: {output_path}")

            # Parse and display
            config = parse_dhcp_config(xml_data, args.interface)
            print_dhcp_config(config, verbose=args.verbose)
            return 0

        # Handle restore command
        elif args.command == "restore":
            # Read XML file
            input_path = Path(args.input)
            if not input_path.exists():
                print(f"ERROR: Input file not found: {args.input}", file=sys.stderr)
                return 1

            xml_data = input_path.read_text()
            print(f"Loaded configuration from: {input_path}")

            # Validate XML
            validation = validate_dhcp_xml(xml_data)
            if not validation.get("valid", False):
                print(f"ERROR: Invalid configuration: {validation['message']}", file=sys.stderr)
                return 1

            print(f"OK: Configuration validated: {validation['type']}")
            if "interfaces" in validation:
                print(f"  Interfaces: {', '.join(validation['interfaces'])}")

            # Preview configuration
            config = parse_dhcp_config(xml_data, args.interface)
            print_dhcp_config(config, verbose=True)

            # Dry-run mode
            if args.dry_run:
                print("\nOK: Dry-run mode: No changes made to pfSense")
                return 0

            # Confirm restore
            print("\nWARNING: This will REPLACE the current DHCP configuration!")
            print("           Make sure you have a backup before proceeding.")
            response = input("\nProceed with restore? (yes/no): ").strip().lower()

            if response not in ("yes", "y"):
                print("Restore cancelled")
                return 0

            # Login and restore
            client.login()
            result = client.restore_dhcp_config(xml_data, debug=args.debug)

            return 0 if result.get("success") else 1

    except nss.error.NSPRError as e:
        error_msg = format_nss_error("pfSense", PFSENSE_URL, e, sys.argv[0])
        print(error_msg, file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
