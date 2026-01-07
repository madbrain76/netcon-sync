#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 netcon-sync contributors
#
# This file is part of netcon-sync.
# netcon-sync is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""
Certificate handling for NSS database-backed HTTPS verification.

Pure library functions - no CLI code. The CLI tools (pfsense2unifi.py, etc.)
handle certificate trust operations via their own arguments.
"""

import subprocess
import tempfile
import sys
from pathlib import Path
from urllib.parse import urlparse
from http_tls_nss import get_server_certificate
import nss.error

def ensure_nss_db(nss_db_dir):
    """
    Ensure the NSS database directory and files exist.
    
    Args:
        nss_db_dir: Path to NSS database directory
    """
    nss_db_dir = Path(nss_db_dir)
    nss_db_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize NSS db if it doesn't exist
    if not (nss_db_dir / "cert9.db").exists():
        # Create empty database using certutil
        try:
            subprocess.run(
                ["certutil", "-N", "-d", str(nss_db_dir), "-f", "/dev/null"],
                check=True,
                capture_output=True,
                timeout=10
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to initialize NSS database: {e}")
        except FileNotFoundError:
            raise RuntimeError("certutil not found. Install nss-tools package.")


def get_cert_fingerprints(hostname: str, port: int = 443) -> dict:
    """
    Retrieve SHA-1 and SHA-256 fingerprints for a server's SSL certificate.
    
    Uses NSS/NSPR socket layer for consistent TLS handling.
    
    Args:
        hostname (str): The hostname or IP address
        port (int): The port number (default: 443)
    
    Returns:
        dict: Contains 'sha1' and 'sha256' fingerprint strings and 'der' certificate data
    
    Raises:
        Exception: If unable to retrieve the certificate
    """
    return get_server_certificate(hostname, port)


def is_cert_trusted(nss_db_dir, hostname: str, port: int = 443) -> bool:
    """
    Check if a server certificate is trusted in the NSS database (non-interactive).
    
    Checks the trust attributes using certutil.
    
    Args:
        nss_db_dir: Path to NSS database directory
        hostname (str): The hostname or IP address
        port (int): The port number (default: 443)
    
    Returns:
        bool: True if the certificate is trusted, False otherwise
    """
    ensure_nss_db(nss_db_dir)
    nss_db_dir = Path(nss_db_dir)
    
    try:
        nickname = f"{hostname}:{port}"
        
        # Use certutil to list all certificates and find ours
        result = subprocess.run(
            ["certutil", "-L", "-d", str(nss_db_dir)],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        if result.returncode == 0:
            # Look for the nickname in the output
            # The trust attributes are shown with the nickname, like "P,,"
            # Check if our nickname appears with trust bit 'P' (peer/server)
            for line in result.stdout.split('\n'):
                if nickname in line:
                    # Check if trust bits contain 'P' (trusted peer certificate for TLS server)
                    return 'P' in line or 'C' in line
        
        return False
        
    except Exception:
        return False


def _cert_exists(nss_db_dir, nickname: str) -> bool:
    """
    Check if a certificate with the given nickname exists in the NSS database.
    
    Args:
        nss_db_dir: Path to NSS database directory
        nickname (str): Certificate nickname to check
    
    Returns:
        bool: True if certificate exists, False otherwise
    """
    nss_db_dir = Path(nss_db_dir)
    try:
        result = subprocess.run(
            ["certutil", "-L", "-d", str(nss_db_dir)],
            capture_output=True,
            timeout=10,
            text=True
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if nickname in line:
                    return True
        
        return False
    except Exception:
        return False


def import_ca_cert(nss_db_dir, cert_path: str, nickname: str = None) -> tuple:
    """
    Import a CA certificate (DER or PEM) into the NSS database.
    
    Checks if a certificate with the same nickname already exists.
    If it does, returns without importing (idempotent).
    
    Args:
        nss_db_dir: Path to NSS database directory
        cert_path (str): Path to certificate file (DER or PEM)
        nickname (str): Nickname for the certificate in NSS (optional)
    
    Returns:
        tuple: (nickname, was_newly_imported) where was_newly_imported is bool
    
    Raises:
        FileNotFoundError: If certificate file not found
        RuntimeError: If import fails
    """
    ensure_nss_db(nss_db_dir)
    nss_db_dir = Path(nss_db_dir)
    
    cert_file = Path(cert_path)
    if not cert_file.exists():
        raise FileNotFoundError(f"Certificate file not found: {cert_path}")
    
    # Use provided nickname or derive from filename
    if nickname is None:
        nickname = cert_file.stem
    
    # Check if certificate already exists
    if _cert_exists(nss_db_dir, nickname):
        return (nickname, False)
    
    try:
        subprocess.run(
            [
                "certutil",
                "-A",
                "-d", str(nss_db_dir),
                "-n", nickname,
                "-t", "CT,,",  # CT = Trusted CA certificate
                "-i", str(cert_file)
            ],
            check=True,
            capture_output=True,
            timeout=10
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to import certificate: {e.stderr.decode()}")
    
    return (nickname, True)


def import_server_cert(nss_db_dir, hostname: str, port: int = 443, nickname: str = None) -> str:
    """
    Fetch and import a server's certificate into the NSS database.
    
    Args:
        nss_db_dir: Path to NSS database directory
        hostname (str): The hostname or IP address
        port (int): The port number (default: 443)
        nickname (str): Nickname for the certificate (optional)
    
    Returns:
        str: The nickname used in the database
    
    Raises:
        Exception: If certificate retrieval or import fails
    """
    ensure_nss_db(nss_db_dir)
    nss_db_dir = Path(nss_db_dir)
    
    # Use provided nickname or derive from hostname:port
    if nickname is None:
        nickname = f"{hostname}:{port}"
    
    try:
        fingerprints = get_cert_fingerprints(hostname, port)
        
        # Write DER data to temporary file (certutil needs file input)
        with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as tmp:
            tmp.write(fingerprints["der"])
            tmp_path = tmp.name
        
        try:
            # Import the certificate from the temporary file
            subprocess.run(
                [
                    "certutil",
                    "-A",
                    "-d", str(nss_db_dir),
                    "-n", nickname,
                    "-t", "P,,",  # P = Trusted peer certificate
                    "-i", tmp_path
                ],
                check=True,
                capture_output=True,
                timeout=10
            )
        finally:
            # Clean up the temporary file
            Path(tmp_path).unlink(missing_ok=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to import server certificate: {e.stderr.decode()}")
    
    return nickname


def interactive_trust_server_cert(nss_db_dir, hostname: str, port: int = 443) -> bool:
    """
    Interactively prompt user to trust a server certificate.
    
    Checks if the certificate is already trusted. If yes, informs user and returns.
    Otherwise, fetches the certificate, displays PKI details (SHA-1 and SHA-256 fingerprints),
    asks for user confirmation, and imports if approved.
    
    This function encapsulates all PKI display logic and user interaction.
    
    Args:
        nss_db_dir: Path to NSS database directory
        hostname (str): The hostname or IP address
        port (int): The port number (default: 443)
    
    Returns:
        bool: True if certificate is trusted (already or newly imported), False if rejected
    
    Raises:
        Exception: If certificate retrieval or import fails
    """
    ensure_nss_db(nss_db_dir)
    
    # Check if certificate is already trusted
    if is_cert_trusted(nss_db_dir, hostname, port):
        print(f"[OK] Certificate for {hostname}:{port} is already trusted.")
        return True
    
    try:
        # Fetch fingerprints
        fingerprints = get_cert_fingerprints(hostname, port)
        
        # Display certificate details to user
        print("\n" + "="*70)
        print("CERTIFICATE DETAILS")
        print("="*70)
        print(f"Hostname: {hostname}")
        print(f"Port:     {port}")
        print()
        print(f"SHA-1:   {fingerprints['sha1']}")
        print(f"SHA-256: {fingerprints['sha256']}")
        print("="*70)
        
        # Ask for confirmation
        print("\nPlease verify these fingerprints match your server's certificate.")
        response = input("Do you trust this certificate? (type 'yes' or 'y' to accept): ").strip().lower()
        
        if response not in ('yes', 'y'):
            print("Certificate rejected.")
            return False
        
        # Import the certificate
        nickname = import_server_cert(nss_db_dir, hostname, port)
        print(f"\n[OK] Certificate imported as '{nickname}' and added to trusted store.")
        return True
        
    except Exception as e:
        raise


# ==============================================================================
# ERROR FORMATTING - Certificate error messages
# ==============================================================================

def format_nss_error(server_name: str, server_url: str, error: Exception, prog_name: str) -> str:
    """
    Format NSS certificate errors with helpful context and suggestions.
    
    Args:
        server_name (str): Human-readable name (e.g., "UniFi Controller", "pfSense")
        server_url (str): Full server URL
        error (Exception): The NSS error
        prog_name (str): Program name (usually sys.argv[0])
    
    Returns:
        str: Formatted error message with suggestion
    """
    error_str = str(error)
    
    if isinstance(error, nss.error.NSPRError):
        # Extract error code (e.g., SEC_ERROR_UNTRUSTED_ISSUER)
        error_code = error_str.split(")")[0].strip("(") if "(" in error_str else "UNKNOWN"
        
        message = f"""
ERROR: CERTIFICATE NOT TRUSTED: {server_name}

URL: {server_url}
Error: {error_str}

This means the {server_name}'s certificate is not trusted.

To fix this, you have two options:

OPTION 1 (Preferred, if the certificate was issued by a separate CA, and you have the CA certificate file):
  If you have the trusted CA certificate (ASCII PEM or binary DER format), run:
  {prog_name} trust --ca /path/to/[ca_cert.pem|ca_cert.der]
  
  This will trust all certificates signed by that CA.

OPTION 2 (Trust the server certificate directly):
  If you don't have the CA file, or the server certificate is self-signed or self-issued, run:
  {prog_name} trust --server {server_url}
  
  This will fetch the certificate, display its fingerprint for verification,
  and add it to the trusted certificate store.
"""
        return message.strip()
    else:
        return str(error)


# ==============================================================================
# CLI HANDLERS - Used by pfsense2unifi.py and unifi_climgr.py
# ==============================================================================

def handle_trust_ca_cert(nss_db_dir, cert_path: str) -> None:
    """
    CLI handler: Import a CA certificate from file into NSS database.
    Prints status messages and exits with appropriate code.
    
    Args:
        nss_db_dir: Path to NSS database directory
        cert_path (str): Path to certificate file (DER or PEM format)
    
    This function exits with code 0 on success, 1 on failure.
    """
    try:
        nickname, was_newly_imported = import_ca_cert(nss_db_dir, cert_path)
        if was_newly_imported:
            print(f"[OK] CA certificate imported as '{nickname}'")
        else:
            print(f"[OK] CA certificate '{nickname}' is already imported.")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


def handle_trust_server_url(nss_db_dir, server_url: str) -> None:
    """
    CLI handler: Interactively trust a server certificate from URL.
    Parses the URL, fetches the certificate, displays details, and imports if approved.
    
    Args:
        nss_db_dir: Path to NSS database directory
        server_url (str): Server URL (e.g., https://example.com:8443)
    
    This function exits with code 0 on success, 1 on failure.
    """
    try:
        parsed = urlparse(server_url)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        if not hostname:
            print(f"ERROR: Invalid URL: {server_url}", file=sys.stderr)
            sys.exit(1)
        
        # Let trust module handle all PKI details and user interaction
        if interactive_trust_server_cert(nss_db_dir, hostname, port):
            sys.exit(0)
        else:
            sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
