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
test_https_nss - Test and demo script for http_tls_nss and trust modules

This script demonstrates the NSS/NSPR-based HTTPS client capabilities:
  - NSS database initialization
  - Certificate trust management (CA and server certs)
  - HTTPS requests with certificate validation
  
This is a standalone test tool to verify the HTTP/TLS/NSS infrastructure.
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
from pathlib import Path
import nss.error
import nss.nss as nss_core

# Import project utilities
try:
    from http_tls_nss import NSPRNSSURLOpener, get_server_certificate
    from trust import format_nss_error, handle_trust_ca_cert, handle_trust_server_url, ensure_nss_db
except ModuleNotFoundError as e:
    print(f"ERROR: Missing required dependency: {e}")
    print("\nPlease run the setup script:")
    print("  ./install_deps.sh")
    sys.exit(1)


def init_nss_db(nss_db_dir):
    """
    Initialize NSS database.
    
    Args:
        nss_db_dir (Path): Path to NSS database directory
    
    Returns:
        bool: True if successful
    """
    print(f"Initializing NSS database at: {nss_db_dir}")
    
    try:
        # Check filesystem type - NSS doesn't work well on network filesystems
        import subprocess
        try:
            df_result = subprocess.run(
                ["df", "-T", str(nss_db_dir)],
                capture_output=True,
                text=True,
                timeout=5
            )
            if "cifs" in df_result.stdout.lower() or "nfs" in df_result.stdout.lower():
                print("⚠  WARNING: NSS databases may not work properly on network filesystems (CIFS/NFS)")
                print("   Consider using a local path like ~/nss_test_db")
        except:
            pass  # Ignore if df check fails
        
        # Check if database already exists
        cert_db = Path(nss_db_dir) / "cert9.db"
        
        if cert_db.exists():
            print(f"  NSS database already exists at: {nss_db_dir}")
            # Test that it can be initialized
            nss_core.nss_init(str(nss_db_dir))
            print("✓ NSS database verified successfully")
            return True
        
        # Create new NSS database using trust module
        print(f"  Creating new NSS database...")
        try:
            ensure_nss_db(nss_db_dir)
        except RuntimeError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            if "certutil not found" in str(e):
                print("Please install NSS tools: sudo apt-get install libnss3-tools", file=sys.stderr)
            return False
        
        print(f"  Database created successfully")
        
        # Initialize NSS to verify
        nss_core.nss_init(str(nss_db_dir))
        print("✓ NSS database initialized successfully")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to initialize NSS database: {e}", file=sys.stderr)
        return False


def trust_ca_certificate(nss_db_dir, ca_file):
    """
    Trust a CA certificate.
    
    Args:
        nss_db_dir (Path): Path to NSS database directory
        ca_file (str): Path to CA certificate file (PEM or DER)
    
    Returns:
        bool: True if successful
    """
    print(f"\nTrusting CA certificate: {ca_file}")
    
    ca_path = Path(ca_file)
    if not ca_path.exists():
        print(f"ERROR: CA certificate file not found: {ca_file}", file=sys.stderr)
        return False
    
    try:
        handle_trust_ca_cert(nss_db_dir, ca_file)
        print("✓ CA certificate trusted successfully")
        return True
    except Exception as e:
        print(f"ERROR: Failed to trust CA certificate: {e}", file=sys.stderr)
        return False


def trust_server_certificate(nss_db_dir, url):
    """
    Trust a server certificate from URL.
    
    Args:
        nss_db_dir (Path): Path to NSS database directory
        url (str): HTTPS URL to fetch certificate from
    
    Returns:
        bool: True if successful
    """
    print(f"\nTrusting server certificate from: {url}")
    
    if not url.startswith("https://"):
        print("ERROR: URL must start with https://", file=sys.stderr)
        return False
    
    try:
        handle_trust_server_url(nss_db_dir, url)
        print("✓ Server certificate trusted successfully")
        return True
    except Exception as e:
        print(f"ERROR: Failed to trust server certificate: {e}", file=sys.stderr)
        return False


def fetch_https_url(url, show_headers=False, max_content=1000):
    """
    Fetch an HTTPS URL using NSS/NSPR.
    
    Args:
        url (str): HTTPS URL to fetch
        show_headers (bool): Show response headers
        max_content (int): Maximum content bytes to display
    
    Returns:
        bool: True if successful
    """
    print(f"\nFetching URL: {url}")
    
    if not url.startswith("https://"):
        print("ERROR: URL must start with https://", file=sys.stderr)
        return False
    
    try:
        opener = NSPRNSSURLOpener()
        response = opener.request("GET", url)
        
        # Get response info
        status_code = response.getcode()
        headers = response.info()
        content = response.read()
        
        print(f"✓ Request successful")
        print(f"  Status Code: {status_code}")
        print(f"  Content Length: {len(content)} bytes")
        print(f"  Content Type: {headers.get('Content-Type', 'unknown')}")
        
        if show_headers:
            print(f"\n  Response Headers:")
            for key, value in headers.items():
                print(f"    {key}: {value}")
        
        # Display content preview
        content_str = content.decode('utf-8', errors='replace')
        if len(content_str) > max_content:
            print(f"\n  Content Preview (first {max_content} chars):")
            print(f"  {'-'*60}")
            print(content_str[:max_content])
            print(f"  ... ({len(content_str) - max_content} more chars)")
        else:
            print(f"\n  Content:")
            print(f"  {'-'*60}")
            print(content_str)
        
        print(f"  {'-'*60}")
        
        return True
        
    except nss.error.NSPRError as e:
        error_msg = format_nss_error("HTTPS", url, e, sys.argv[0])
        print(error_msg, file=sys.stderr)
        return False
    except Exception as e:
        print(f"ERROR: Failed to fetch URL: {e}", file=sys.stderr)
        return False


def run_demo_workflow(nss_db_dir):
    """
    Run a complete demo workflow showing all features.
    
    Args:
        nss_db_dir (Path): Path to NSS database directory
    """
    print("="*70)
    print("NSS/NSPR HTTPS Client Demo Workflow")
    print("="*70)
    
    # Step 1: Initialize NSS database
    print("\n[Step 1] Initializing NSS database")
    if not init_nss_db(nss_db_dir):
        return False
    
    # Step 2: Fetch a well-known HTTPS URL (should work with standard CAs)
    print("\n[Step 2] Fetching public HTTPS URL (should work with system CAs)")
    test_url = "https://www.google.com"
    fetch_https_url(test_url, show_headers=False, max_content=500)
    
    print("\n[Demo Complete]")
    print("="*70)
    print("\nNext steps to test with your own server:")
    print("  1. Trust your server certificate:")
    print("     ./test_https_nss.py trust-server --url https://your-server.local")
    print("\n  2. Or trust your CA certificate:")
    print("     ./test_https_nss.py trust-ca --ca-file your-ca.crt")
    print("\n  3. Fetch from your server:")
    print("     ./test_https_nss.py fetch --url https://your-server.local")
    print(f"\nNSS database location: {nss_db_dir}")
    print("="*70)
    
    return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test and demo script for NSS/NSPR HTTPS client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  init              Initialize NSS database only
  trust-ca          Trust a CA certificate file
  trust-server      Trust a server certificate from URL
  fetch             Fetch an HTTPS URL
  demo              Run full demo workflow

Examples:
  # Initialize NSS database (default location: ~/nss_test_db)
  %(prog)s init
  %(prog)s init --nss-db /path/to/nss/db

  # Trust a CA certificate
  %(prog)s trust-ca --ca-file /path/to/ca.crt

  # Trust a server certificate by connecting to it
  %(prog)s trust-server --url https://pfsense.local

  # Fetch an HTTPS URL
  %(prog)s fetch --url https://www.google.com
  %(prog)s fetch --url https://pfsense.local --show-headers

  # Run complete demo
  %(prog)s demo

  # Use custom NSS database location
  %(prog)s --nss-db /tmp/my_nss_db fetch --url https://www.google.com

Typical Workflow:
  1. Run 'init' to create NSS database
  2. Run 'trust-server' or 'trust-ca' to trust certificates
  3. Run 'fetch' to test HTTPS connections

Environment Variables:
  NSS_DB_PATH       NSS database directory (default: ~/nss_test_db)

Note: NSS databases must be on local filesystems (not CIFS/NFS)
        """
    )
    
    parser.add_argument(
        "--nss-db",
        help="NSS database directory (default: $NSS_DB_PATH or ~/nss_test_db)"
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Command to run")
    
    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize NSS database")
    
    # Trust CA command
    trust_ca_parser = subparsers.add_parser("trust-ca", help="Trust CA certificate")
    trust_ca_parser.add_argument("--ca-file", required=True, help="CA certificate file (PEM or DER)")
    
    # Trust server command
    trust_server_parser = subparsers.add_parser("trust-server", help="Trust server certificate")
    trust_server_parser.add_argument("--url", required=True, help="HTTPS URL to fetch certificate from")
    
    # Fetch command
    fetch_parser = subparsers.add_parser("fetch", help="Fetch HTTPS URL")
    fetch_parser.add_argument("--url", required=True, help="HTTPS URL to fetch")
    fetch_parser.add_argument("--show-headers", action="store_true", help="Show response headers")
    fetch_parser.add_argument("--max-content", type=int, default=1000, help="Max content bytes to display (default: 1000)")
    
    # Demo command
    demo_parser = subparsers.add_parser("demo", help="Run complete demo workflow")
    
    args = parser.parse_args()
    
    # Determine NSS database path
    if args.nss_db:
        nss_db_dir = Path(args.nss_db)
    elif os.getenv("NSS_DB_PATH"):
        nss_db_dir = Path(os.getenv("NSS_DB_PATH"))
    else:
        nss_db_dir = Path.home() / "nss_test_db"
    
    # Handle init command
    if args.command == "init":
        return 0 if init_nss_db(nss_db_dir) else 1
    
    # Handle demo command
    elif args.command == "demo":
        return 0 if run_demo_workflow(nss_db_dir) else 1
    
    # All other commands need NSS initialized first
    try:
        if not nss_db_dir.exists():
            print(f"ERROR: NSS database not found at: {nss_db_dir}", file=sys.stderr)
            print(f"\nTry running: {sys.argv[0]} init --nss-db {nss_db_dir}", file=sys.stderr)
            return 1
        
        nss_core.nss_init(str(nss_db_dir))
    except Exception as e:
        print(f"ERROR: Failed to initialize NSS database: {e}", file=sys.stderr)
        print(f"\nTry running: {sys.argv[0]} init --nss-db {nss_db_dir}", file=sys.stderr)
        return 1
    
    # Handle trust-ca command
    if args.command == "trust-ca":
        return 0 if trust_ca_certificate(nss_db_dir, args.ca_file) else 1
    
    # Handle trust-server command
    elif args.command == "trust-server":
        return 0 if trust_server_certificate(nss_db_dir, args.url) else 1
    
    # Handle fetch command
    elif args.command == "fetch":
        return 0 if fetch_https_url(args.url, args.show_headers, args.max_content) else 1
    
    return 1


if __name__ == "__main__":
    sys.exit(main())
