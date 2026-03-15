#!/usr/bin/env python3
"""
Test controller support file download to diagnose issues.
"""

import sys
import time
from pathlib import Path

# Initialize NSS before any imports that use it
import nss.nss as nss_core
from trust import ensure_nss_db

nss_db_dir = Path.home() / ".netcon-sync"
ensure_nss_db(nss_db_dir)
nss_core.nss_init(str(nss_db_dir))

# Now import unifi_utils and config
import unifi_utils
from config import UNIFI_SITE_ID

def test_controller_download():
    """Test controller support file download with diagnostics."""

    print("="*80)
    print("Testing Controller Support File Download")
    print("="*80)

    # Login
    print("\n[1] Logging in to controller...")
    try:
        unifi_utils.login()
        print("    [OK] Logged in successfully")
    except Exception as e:
        print(f"    [FAIL] Login failed: {e}")
        return False

    # Get controller version
    print("\n[2] Getting controller version...")
    try:
        status_endpoint = f'/api/s/{UNIFI_SITE_ID}/stat/sysinfo'
        status = unifi_utils.make_unifi_api_call('GET', status_endpoint)
        if isinstance(status, list) and len(status) > 0:
            sysinfo = status[0]
            version = sysinfo.get('version', 'unknown')
            print(f"    [OK] Controller version: {version}")
    except Exception as e:
        print(f"    [WARN] Could not get version: {e}")

    # Trigger support file generation
    print("\n[3] Triggering support file generation...")
    endpoint = f'/api/s/{UNIFI_SITE_ID}/cmd/system'
    payload = {'cmd': 'gen-support-file'}

    try:
        gen_start = time.time()
        response = unifi_utils.make_unifi_api_call('POST', endpoint, json=payload)
        gen_time = time.time() - gen_start
        print(f"    [OK] Generation command sent ({gen_time:.2f}s)")
        if response:
            print(f"    Response: {response}")
    except Exception as e:
        print(f"    [FAIL] Generation failed: {e}")
        return False

    # Wait for generation to complete (controllers may need time)
    print("\n[4] Waiting for file generation to complete...")
    for wait_time in [5, 10, 15]:
        print(f"    Waiting {wait_time}s...")
        time.sleep(wait_time)

        # Try downloading from each endpoint
        print(f"\n[5] Testing download endpoints (after {wait_time}s wait)...")

        download_urls = [
            '/dl/support',
            f'/api/s/{UNIFI_SITE_ID}/dl/support',
            f'/api/s/{UNIFI_SITE_ID}/dl/support.tar.gz',
            '/dl/support.tar.gz',
            f'/proxy/network/api/s/{UNIFI_SITE_ID}/dl/support',
            f'/proxy/network/dl/support',
            f'/api/download/support',
            f'/dl/autobackup/support.tar.gz',
        ]

    output_dir = Path('.')

    # Wait for generation to complete (controllers may need time)
    print("\n[4] Waiting for file generation to complete...")

    success = False
    for wait_time in [5, 10, 15]:
        if success:
            break

        print(f"    Waiting {wait_time}s...")
        time.sleep(wait_time)

        # Try downloading from each endpoint
        print(f"\n[5] Testing download endpoints (after {wait_time}s total wait)...")

        download_urls = [
            '/dl/support',
            f'/api/s/{UNIFI_SITE_ID}/dl/support',
            f'/api/s/{UNIFI_SITE_ID}/dl/support.tar.gz',
            '/dl/support.tar.gz',
            f'/proxy/network/api/s/{UNIFI_SITE_ID}/dl/support',
            f'/proxy/network/dl/support',
            f'/api/download/support',
            f'/dl/autobackup/support.tar.gz',
        ]

    for i, url in enumerate(download_urls, 1):
        print(f"\n    [{i}/{len(download_urls)}] Trying: {url}")

        try:
            download_start = time.time()
            response = unifi_utils.make_unifi_api_call('GET', url, stream=True)

            # Read first chunk to check
            chunk = response.read(1024)
            response.close()

            download_time = time.time() - download_start

            if len(chunk) > 0:
                print(f"        [OK] Got response ({len(chunk)} bytes in first chunk, {download_time:.2f}s)")
                print(f"        First bytes: {chunk[:50]}")

                # If it looks like a tar.gz file, try full download
                if chunk[:2] == b'\x1f\x8b':  # gzip magic bytes
                    print(f"        [OK] Appears to be a valid gzip file!")
                    print(f"\n[SUCCESS] Found working endpoint: {url}")
                    print(f"           After {wait_time}s wait time")

                    timestamp = time.strftime('%Y%m%d-%H%M%S')
                    filename = f"test_controller_support_{timestamp}.tar.gz"
                    file_path = output_dir / filename

                    print(f"\n[6] Downloading full file...")
                    download_start = time.time()
                    response = unifi_utils.make_unifi_api_call('GET', url, stream=True)

                    total_bytes = 0
                    chunk_size = 1024 * 1024
                    with open(file_path, 'wb') as f:
                        while True:
                            chunk = response.read(chunk_size)
                            if not chunk:
                                break
                            f.write(chunk)
                            total_bytes += len(chunk)
                            # Show progress for large files
                            if total_bytes % (10 * 1024 * 1024) == 0:
                                print(f"        Downloaded: {total_bytes / (1024*1024):.1f} MB...")

                    response.close()
                    download_time = time.time() - download_start
                    speed_mbps = (total_bytes / (1024 * 1024)) / download_time if download_time > 0 else 0

                    print(f"\n[SUCCESS] Downloaded {total_bytes} bytes in {download_time:.1f}s ({speed_mbps:.1f} MB/s)")
                    print(f"           File saved: {filename}")
                    success = True
                    break
                else:
                    print(f"        [WARN] Response doesn't look like gzip (first 2 bytes: {chunk[:2]})")
            else:
                print(f"        [FAIL] Empty response")

        except Exception as e:
            print(f"        [FAIL] {e}")
            continue

    if not success:
        print("\n[FAIL] None of the endpoints worked even after waiting")
        return False

    return True

if __name__ == '__main__':
    success = test_controller_download()
    sys.exit(0 if success else 1)
