#!/usr/bin/env python3
"""
Find the controller support file endpoint for UniFi Network 10.x
"""

import sys
from pathlib import Path

# Initialize NSS
import nss.nss as nss_core
from trust import ensure_nss_db

nss_db_dir = Path.home() / ".netcon-sync"
ensure_nss_db(nss_db_dir)
nss_core.nss_init(str(nss_db_dir))

import unifi_utils
from config import UNIFI_SITE_ID

# Login
print("Logging in...")
unifi_utils.login()
print("[OK] Logged in\n")

# Trigger generation
print("Triggering support file generation...")
endpoint = f'/api/s/{UNIFI_SITE_ID}/cmd/system'
payload = {'cmd': 'gen-support-file'}
response = unifi_utils.make_unifi_api_call('POST', endpoint, json=payload)
print(f"[OK] Generation triggered: {response}\n")

# Try newer UniFi Network 10.x style endpoints
print("Testing UniFi Network 10.x endpoints:")

test_urls = [
    # New unified controller endpoints (10.x)
    '/proxy/network/v2/api/site/default/support',
    '/proxy/network/api/site/default/support',
    '/api/site/default/support',
    '/v2/api/site/default/support',

    # Try without site
    '/proxy/network/v2/api/support',
    '/proxy/network/api/support',
    '/api/support',
    '/v2/api/support',

    # Old endpoints that might still work
    '/dl/support',
    f'/api/s/{UNIFI_SITE_ID}/dl/support',
]

import time
time.sleep(5)  # Give it time to generate

for url in test_urls:
    print(f"\nTrying: {url}")
    try:
        response = unifi_utils.make_unifi_api_call('GET', url, stream=True)
        chunk = response.read(100)
        response.close()

        if chunk:
            print(f"  [OK] Got {len(chunk)} bytes")
            print(f"  Magic bytes: {chunk[:10].hex()}")

            # Check if it's gzip
            if chunk[:2] == b'\x1f\x8b':
                print(f"  ✓ FOUND IT! This is a gzip file!")
                print(f"\n**Working endpoint: {url}**")
                break
            else:
                print(f"  Content starts with: {chunk[:50]}")
    except Exception as e:
        error_str = str(e)
        # Shorten long errors
        if len(error_str) > 100:
            error_str = error_str[:100] + "..."
        print(f"  [FAIL] {error_str}")
