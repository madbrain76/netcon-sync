#!/usr/bin/env python3
"""
Script to discover the correct SSID disable/enable API endpoint in UniFi 10.x
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
from config import UNIFI_SITE_ID, UNIFI_NETWORK_URL
import http.client

print("=" * 80)
print("Discovering SSID Disable API Endpoint")
print("=" * 80)

# Login
print("\n[1] Logging in...")
unifi_utils.login()
print("    [OK] Logged in\n")

ssid_id = "693e9a1ce1668f2c23ebec50"
site_id = "default"

# Get the full SSID object for reference
ssids = unifi_utils.get_ssids()
ssid_data = None
for s in ssids:
    if s['_id'] == ssid_id:
        ssid_data = s.copy()
        break

if ssid_data:
    print(f"[2] SSID data:")
    print(f"    Name: {ssid_data.get('name')}")
    print(f"    Enabled: {ssid_data.get('enabled')}")
    print(f"    _id: {ssid_data.get('_id')}")
    print()

# Make a direct request to see the actual error response
print("[3] Making direct request to see actual error response:")
opener = unifi_utils._get_opener()
url = f"{UNIFI_NETWORK_URL}/api/s/{site_id}/rest/wlanconf/{ssid_id}"
payload = {"enabled": False}
import json
body = json.dumps(payload).encode('utf-8')
headers = {'Content-Type': 'application/json'}

try:
    response = opener.request("PUT", url, data=body, headers=headers)
    print(f"    Status: {response.getcode()}")
    error_body = response.read().decode('utf-8', errors='replace')
    print(f"    Response body: {error_body}")
except Exception as e:
    print(f"    Error: {e}")

# Try different payload formats
print("\n[4] Testing different payload formats:")
payloads = [
    ("Minimal", {"enabled": False}),
    ("With name", {"enabled": False, "name": ssid_data.get("name")}),
    ("With _id", {"_id": ssid_id, "enabled": False}),
    ("Full object", ssid_data.copy()),
    ("Full with enabled", {**ssid_data, "enabled": False}),
    ("Only enabled field", {"enabled": False}),
]

for name, payload in payloads:
    body = json.dumps(payload).encode('utf-8')
    try:
        response = opener.request("PUT", url, data=body, headers=headers)
        print(f"    [{name}] Status: {response.getcode()}")
        error_body = response.read().decode('utf-8', errors='replace')
        print(f"           Body: {error_body}")
    except Exception as e:
        print(f"    [{name}] Error: {e}")

# Also try PATCH
print("\n[5] Testing PATCH method:")
body = json.dumps({"enabled": False}).encode('utf-8')
try:
    response = opener.request("PATCH", url, data=body, headers=headers)
    print(f"    Status: {response.getcode()}")
    error_body = response.read().decode('utf-8', errors='replace')
    print(f"    Body: {error_body}")
except Exception as e:
    print(f"    Error: {e}")

print("\n" + "=" * 80)
