#!/usr/bin/env python3
"""
Manual diagnostic for controller support file download with UniFi Network 10.x.
"""

import sys
import time
from pathlib import Path


def main() -> int:
    # Initialize NSS
    import nss.nss as nss_core
    from trust import ensure_nss_db

    nss_db_dir = Path.home() / ".netcon-sync"
    ensure_nss_db(nss_db_dir)
    nss_core.nss_init(str(nss_db_dir))

    import unifi_utils
    from config import UNIFI_SITE_ID

    print("=" * 80)
    print("Testing Controller Support File with UniFi Network 10.x Format")
    print("=" * 80)

    print("\n[1] Logging in...")
    unifi_utils.login()
    print("    [OK] Logged in\n")

    print("[2] Triggering support file generation (UniFi Network 10.x format)...")
    endpoint = f"/api/s/{UNIFI_SITE_ID}/cmd/system"
    payload = {
        "cmd": "support",
        "userAgent": "unifi-climgr/1.0",
        "language": "en-US",
    }

    response = unifi_utils.make_unifi_api_call("POST", endpoint, json=payload)
    print("    [OK] Generation triggered")
    print(f"    Response: {response}\n")

    print("[3] Attempting download from /dl/support (no wait)...")
    try:
        response = unifi_utils.make_unifi_api_call("GET", "/dl/support", stream=True)
        chunk = response.read(100)
        response.close()

        if chunk and chunk[:2] == b"\x1f\x8b":
            print("    [SUCCESS] Got gzip file immediately!\n")

            print("[4] Downloading full file...")
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"test_controller_10x_{timestamp}.tar.gz"

            download_start = time.time()
            response = unifi_utils.make_unifi_api_call("GET", "/dl/support", stream=True)

            total_bytes = 0
            with open(filename, "wb") as f:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    total_bytes += len(chunk)

            response.close()
            download_time = time.time() - download_start
            speed_mbps = (total_bytes / (1024 * 1024)) / download_time if download_time > 0 else 0

            print(f"\n[SUCCESS] Downloaded {total_bytes} bytes in {download_time:.1f}s ({speed_mbps:.1f} MB/s)")
            print(f"           File saved: {filename}")
            return 0

        print("    [FAIL] Response not a gzip file")
    except Exception as e:
        print(f"    [FAIL] {e}")

    print("\n[FAIL] Download failed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
