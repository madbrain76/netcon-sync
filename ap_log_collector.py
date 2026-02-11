#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 netcon-sync contributors
#
# This file is part of netcon-sync.

"""
Shared module for collecting logs from UniFi Access Points via SSH/SCP.
Used by unifi_climgr.py collect-ap-logs command.
"""

import time
import sys
import re
import json
import tarfile
import shutil
from pathlib import Path
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

import paramiko
from scp import SCPClient

import unifi_utils
from config import UNIFI_SITE_ID

# Thread-safe print lock for parallel operations
print_lock = Lock()


def get_ssh_credentials():
    """
    Retrieve SSH credentials from UniFi controller.
    
    Returns:
        tuple: (username, password) or (None, None) if not found
    """
    endpoint = f"/api/s/{UNIFI_SITE_ID}/rest/setting/mgmt"
    try:
        settings = unifi_utils.make_unifi_api_call("GET", endpoint)
        if isinstance(settings, dict) and 'data' in settings:
            settings = settings['data']
        
        if isinstance(settings, list) and len(settings) > 0:
            mgmt_settings = settings[0]
            username = mgmt_settings.get('x_ssh_username', 'ubnt')
            password = mgmt_settings.get('x_ssh_password', '')
            
            if username and password:
                print(f"[OK] Retrieved SSH credentials (username: {username})")
                return username, password
    except Exception as e:
        print(f"Warning: Could not retrieve SSH credentials from settings: {e}")
    
    # Fallback: try sysinfo endpoint
    endpoint = f"/api/s/{UNIFI_SITE_ID}/stat/sysinfo"
    try:
        sysinfo = unifi_utils.make_unifi_api_call("GET", endpoint)
        if isinstance(sysinfo, dict) and 'data' in sysinfo:
            sysinfo_data = sysinfo['data'][0] if isinstance(sysinfo['data'], list) else sysinfo['data']
            username = sysinfo_data.get('x_ssh_username', 'ubnt')
            password = sysinfo_data.get('x_ssh_password', '')
            
            if username and password:
                print(f"[OK] Retrieved SSH credentials from sysinfo (username: {username})")
                return username, password
    except Exception as e:
        print(f"Warning: Could not retrieve SSH credentials from sysinfo: {e}")
    
    return None, None


def collect_ap_support_bundle(ssh_client, ap_name):
    """
    Generate support bundle on AP using 'supp' command.
    
    Args:
        ssh_client: Active SSH client connection
        ap_name: AP name for logging
    
    Returns:
        tuple: (success, bundle_path, size_str) or (False, None, None)
    """
    try:
        print(f"[{ap_name}] Generating support info bundle...")
        print(f"[{ap_name}]   Trying 'supp' command...")
        
        start_time = time.time()
        stdin, stdout, stderr = ssh_client.exec_command('supp', timeout=120)
        output = stdout.read().decode('utf-8', errors='replace')
        stderr.read()  # Consume stderr
        elapsed = time.time() - start_time
        
        print(f"[{ap_name}]   supp command took {elapsed:.1f} seconds")
        
        # Check if file exists
        stdin, stdout, stderr = ssh_client.exec_command('ls -lh /tmp/support.tgz')
        ls_stdout = stdout.read().decode('utf-8')
        
        if 'support.tgz' in ls_stdout:
            size_match = re.search(r'(\d+(?:\.\d+)?[KMG]?)\s+\w+\s+\d+\s+[\d:]+\s+/tmp/support\.tgz', ls_stdout)
            size_str = size_match.group(1) if size_match else 'unknown size'
            print(f"[{ap_name}] [OK] Support bundle generated: /tmp/support.tgz ({size_str})")
            return True, '/tmp/support.tgz', size_str
        else:
            print(f"[{ap_name}]   supp: file not found after command completed")
            return False, None, None
            
    except Exception as e:
        print(f"[{ap_name}]   supp command failed: {e}")
        return False, None, None


def collect_logs_from_ap(ap_ip, ap_name, ap_mac, ssh_username, ssh_password, output_dir, timeout=60):
    """
    Collect diagnostic logs from a single AP via SSH/SCP.
    
    Args:
        ap_ip: AP IP address
        ap_name: AP display name
        ap_mac: AP MAC address
        ssh_username: SSH username
        ssh_password: SSH password
        output_dir: Local directory to save files
        timeout: SSH timeout in seconds
    
    Returns:
        dict: Collection result with success status, files, errors, timing
    """
    result = {
        'success': False,
        'ap_name': ap_name,
        'ap_mac': ap_mac,
        'ap_ip': ap_ip,
        'files': [],
        'error': None,
        'elapsed_time': 0,
        'start_timestamp': None,
        'end_timestamp': None
    }
    
    ssh_client = None
    start_time = time.time()
    start_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    result['start_timestamp'] = start_timestamp
    
    # Create AP-specific directory
    safe_ap_name = ap_name.replace('/', '_').replace(' ', '_')
    ap_dir = output_dir / f"{safe_ap_name}_{ap_mac.replace(':', '-')}"
    ap_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        with print_lock:
            print(f"\n{'='*60}")
            print(f"[{ap_name}] [{start_timestamp}] Connecting to {ap_ip}...")
        
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh_client.connect(
                hostname=ap_ip,
                username=ssh_username,
                password=ssh_password,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=30  # Increase banner timeout for slow APs
            )
        except paramiko.ssh_exception.AuthenticationException as e:
            result['error'] = f"Authentication failed: {e}"
            with print_lock:
                print(f"[{ap_name}] [FAIL] Authentication failed")
                print(f"[{ap_name}] Check: Settings > System > Advanced > Device SSH Authentication")
            return result
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            result['error'] = f"SSH connection refused: {e}"
            with print_lock:
                print(f"[{ap_name}] [FAIL] SSH connection refused on port 22")
                print(f"[{ap_name}] Possible causes:")
                print(f"[{ap_name}]   - SSH not enabled on controller")
                print(f"[{ap_name}]   - AP firmware doesn't support SSH")
                print(f"[{ap_name}]   - Firewall blocking port 22")
            return result
        except paramiko.ssh_exception.SSHException as e:
            result['error'] = f"SSH protocol error: {e}"
            with print_lock:
                print(f"[{ap_name}] [FAIL] SSH protocol error: {e}")
            return result
        except Exception as e:
            result['error'] = f"SSH connection error: {e}"
            with print_lock:
                print(f"[{ap_name}] [FAIL] SSH connection error: {e}")
            return result
        
        with print_lock:
            print(f"[{ap_name}] [OK] Connected")
        
        # Generate support bundle
        success, bundle_path, size_str = collect_ap_support_bundle(ssh_client, ap_name)
        
        if success and bundle_path:
            # Download via SCP
            local_path = ap_dir / Path(bundle_path).name
            with print_lock:
                print(f"[{ap_name}]   Downloading {Path(bundle_path).name} ({size_str})...", end="", flush=True)
            
            try:
                with SCPClient(ssh_client.get_transport()) as scp:
                    scp.get(bundle_path, str(local_path))
                
                actual_size = local_path.stat().st_size
                with print_lock:
                    print(f" [OK]")
                
                result['files'].append({
                    'remote_path': bundle_path,
                    'local_path': str(local_path),
                    'size': actual_size,
                    'type': 'support_bundle'
                })
                
                # Clean up remote file
                try:
                    stdin, stdout, stderr = ssh_client.exec_command(f'rm -f {bundle_path}')
                    stdout.read()
                except:
                    pass
            except Exception as e:
                with print_lock:
                    print(f" [FAIL]: {e}")
        
        # Collect log files from /var/log/
        with print_lock:
            print(f"[{ap_name}] Collecting individual log files...")
        
        stdin, stdout, stderr = ssh_client.exec_command(
            r'find /var/log -type f \( -name "*.log" -o -name "messages" -o -name "syslog" \) 2>/dev/null | head -20'
        )
        log_files = stdout.read().decode('utf-8').strip().split('\n')
        log_files = [f.strip() for f in log_files if f.strip()]
        
        if log_files:
            with print_lock:
                print(f"[{ap_name}] Found {len(log_files)} log file(s)")
            
            for remote_path in log_files:
                filename = Path(remote_path).name
                local_path = ap_dir / filename
                
                if local_path.exists():
                    continue
                
                with print_lock:
                    print(f"[{ap_name}]   Downloading {filename}...", end="", flush=True)
                
                try:
                    with SCPClient(ssh_client.get_transport()) as scp:
                        scp.get(remote_path, str(local_path))
                    
                    actual_size = local_path.stat().st_size
                    with print_lock:
                        print(f" [OK] ({actual_size:,} bytes)")
                    
                    result['files'].append({
                        'remote_path': remote_path,
                        'local_path': str(local_path),
                        'size': actual_size,
                        'type': 'log_file'
                    })
                except Exception as e:
                    with print_lock:
                        print(f" [FAIL]: {e}")
        
        if result['files']:
            result['success'] = True
            with print_lock:
                print(f"[{ap_name}] [OK] Downloaded {len(result['files'])} file(s) to {ap_dir}")
        else:
            result['error'] = "No log files collected"
            with print_lock:
                print(f"[{ap_name}] WARNING: No log files were collected")
    
    except Exception as e:
        result['error'] = str(e)
        with print_lock:
            print(f"[{ap_name}] [FAIL] Error: {e}")
    finally:
        if ssh_client:
            try:
                ssh_client.close()
            except:
                pass
        
        result['elapsed_time'] = time.time() - start_time
        completion_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        result['end_timestamp'] = completion_timestamp
        
        with print_lock:
            if result['success']:
                print(f"[{ap_name}] [{completion_timestamp}] [OK] Completed in {result['elapsed_time']:.1f}s")
            else:
                print(f"[{ap_name}] [{completion_timestamp}] [FAIL] Failed after {result['elapsed_time']:.1f}s")
    
    return result


def collect_controller_support_file(output_dir):
    """
    Collect support file from UniFi controller.
    
    Args:
        output_dir: Directory to save the support file
    
    Returns:
        dict: Result with success status, file path, size, timing
    """
    result = {
        'success': False,
        'file_path': None,
        'size': 0,
        'error': None,
        'elapsed_time': 0,
        'start_timestamp': None,
        'end_timestamp': None
    }
    
    start_time = time.time()
    start_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    result['start_timestamp'] = start_timestamp
    
    try:
        with print_lock:
            print(f"\n[CONTROLLER] [{start_timestamp}] Generating network support file...")
        
        # Trigger support file generation
        endpoint = f'/api/s/{UNIFI_SITE_ID}/cmd/system'
        payload = {'cmd': 'gen-support-file'}
        
        try:
            response = unifi_utils.make_unifi_api_call('POST', endpoint, json=payload)
            with print_lock:
                print("[CONTROLLER] [OK] Support file generation initiated")
                # Debug: show response to understand controller behavior
                if response:
                    print(f"[CONTROLLER] Response: {response}")
        except Exception as e:
            result['error'] = f"Failed to initiate support file generation: {e}"
            with print_lock:
                print(f"[CONTROLLER] [FAIL] Failed to initiate generation: {e}")
            result['elapsed_time'] = time.time() - start_time
            return result
        
        # Get controller version for diagnostics
        try:
            status_endpoint = f'/api/s/{UNIFI_SITE_ID}/stat/sysinfo'
            status = unifi_utils.make_unifi_api_call('GET', status_endpoint)
            if isinstance(status, list) and len(status) > 0:
                sysinfo = status[0]
                version = sysinfo.get('version', 'unknown')
                with print_lock:
                    print(f"[CONTROLLER] Detected UniFi Network version: {version}")
        except Exception as e:
            with print_lock:
                print(f"[CONTROLLER] Could not get version info: {e}")
        
        # Download the support file - try multiple endpoints (controllers have different paths across versions)
        # After controller upgrades, generation may be synchronous, so try download immediately
        # Modern controllers (v8+) use /dl/support as primary endpoint
        download_urls = [
            '/dl/support',                               # Primary endpoint (works with modern controllers)
            f'/api/s/{UNIFI_SITE_ID}/dl/support',       # Alternative API path
            f'/api/s/{UNIFI_SITE_ID}/dl/support.tar.gz', # Explicit filename
            '/dl/support.tar.gz',                        # Legacy with filename
            f'/proxy/network/api/s/{UNIFI_SITE_ID}/dl/support', # UniFi OS path (UDM/UDR)
            f'/proxy/network/dl/support',                # UniFi OS simplified
            f'/api/download/support',                    # Alternative API path
            f'/dl/autobackup/support.tar.gz',            # Autobackup path (some versions)
        ]
        
        timestamp = time.strftime('%Y%m%d-%H%M%S')
        filename = f"controller_support_{timestamp}.tar.gz"
        file_path = output_dir / filename
        
        download_success = False
        total_bytes = 0
        
        # Try each endpoint with brief retries in case generation needs a moment
        # Modern controllers generate synchronously, so usually works on first try
        max_retries = 2
        retry_delay = 3  # Wait 3 seconds between retries if needed
        
        for retry in range(max_retries):
            if download_success:
                break
                
            if retry > 0:
                with print_lock:
                    print(f"[CONTROLLER] Retry {retry}/{max_retries-1} after {retry_delay}s delay...")
                time.sleep(retry_delay)
            
            for url in download_urls:
                try:
                    with print_lock:
                        print(f"[CONTROLLER] Trying download URL: {url}")
                        sys.stdout.flush()
                    
                    download_start = time.time()
                    total_bytes = 0  # Reset for this attempt
                    
                    response = unifi_utils.make_unifi_api_call('GET', url, stream=True)
                    
                    chunk_size = 1024 * 1024  # 1MB chunks
                    with open(file_path, 'wb') as f:
                        while True:
                            chunk = response.read(chunk_size)
                            if not chunk:
                                break
                            f.write(chunk)
                            total_bytes += len(chunk)
                    
                    response.close()
                    
                    # Validate downloaded file (support files should be at least 100KB)
                    if total_bytes < 102400:
                        raise Exception(f"Downloaded file too small ({total_bytes} bytes), likely not a valid support file")
                    
                    download_time = time.time() - download_start
                    speed_mbps = (total_bytes / (1024 * 1024)) / download_time if download_time > 0 else 0
                    
                    with print_lock:
                        print(f"[CONTROLLER] [OK] Downloaded support file ({total_bytes} bytes) in {download_time:.1f}s ({speed_mbps:.1f} MB/s)")
                        sys.stdout.flush()
                    
                    download_success = True
                    break
                except Exception as e:
                    error_msg = str(e)
                    with print_lock:
                        print(f"[CONTROLLER]   Failed: {error_msg}")
                        sys.stdout.flush()
                    if file_path.exists():
                        file_path.unlink()
                    continue
        
        if not download_success:
            attempted_urls = '\n    '.join(download_urls)
            result['error'] = f"Could not download support file from any known endpoint.\nAttempted URLs:\n    {attempted_urls}\n\nYou can manually download the support file from:\nSettings > System > Maintenance > Download Support File"
            with print_lock:
                print(f"[CONTROLLER] [FAIL] Could not download support file from any endpoint")
                print(f"[CONTROLLER] Attempted {len(download_urls)} different endpoints across {max_retries} retries")
                print(f"[CONTROLLER] You can manually download from: Settings > System > Maintenance > Download Support File")
            result['elapsed_time'] = time.time() - start_time
            return result
        
        result['success'] = True
        result['file_path'] = str(file_path)
        result['size'] = total_bytes
        result['elapsed_time'] = time.time() - start_time
        
        size_mb = total_bytes / (1024 * 1024)
        with print_lock:
            print(f"[CONTROLLER] [OK] Saved to {filename} ({size_mb:.1f} MB)")
            sys.stdout.flush()
    
    except Exception as e:
        result['error'] = f"Unexpected error: {e}"
        with print_lock:
            print(f"[CONTROLLER] [FAIL] Error: {e}")
    
    if result['elapsed_time'] == 0:
        result['elapsed_time'] = time.time() - start_time
    
    completion_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    result['end_timestamp'] = completion_timestamp
    
    with print_lock:
        if result['success']:
            print(f"[CONTROLLER] [{completion_timestamp}] [OK] Completed in {result['elapsed_time']:.1f}s")
        else:
            print(f"[CONTROLLER] [{completion_timestamp}] [FAIL] Failed after {result['elapsed_time']:.1f}s")
    
    return result


def collect_all_ap_logs(output_dir, aps, ssh_username, ssh_password, parallel=0, timeout=60, include_controller=True):
    """
    Collect logs from multiple APs in parallel.
    
    Args:
        output_dir: Base output directory
        aps: List of AP dictionaries from UniFi API
        ssh_username: SSH username
        ssh_password: SSH password
        parallel: Number of parallel workers (0 = unlimited)
        timeout: SSH timeout in seconds
        include_controller: Whether to collect controller support file
    
    Returns:
        tuple: (ap_results, controller_result, collection_info)
    """
    # Create unique collection subdirectory
    timestamp = time.strftime('%Y%m%d-%H%M%S')
    collection_dir = output_dir / f"collection_{timestamp}"
    collection_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Output directory: {output_dir.absolute()}")
    print(f"Collection directory: {collection_dir.name}\n")
    
    collection_start_time = time.time()
    collection_start_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    
    # Determine worker count
    if parallel > 0:
        max_workers = parallel + 1  # +1 for controller
    else:
        max_workers = len(aps) + 1  # All APs + controller
    
    print(f"Using parallel collection with {max_workers} worker(s)\n")
    
    results = []
    
    def collect_with_info(ap_info):
        i, total, ap = ap_info
        ap_name = ap.get("name", "Unknown")
        ap_mac = ap.get("mac", "unknown")
        ap_ip = ap.get("ip")
        
        with print_lock:
            print(f"{'='*60}")
            print(f"[{i}/{total}] {ap_name} ({ap_ip}) - {ap.get('state_name', 'unknown')}")
            print(f"{'='*60}\n")
        
        if not ap_ip:
            with print_lock:
                print(f"WARNING: Skipping {ap_name}: No IP address")
            return {
                'ap_name': ap_name,
                'success': False,
                'error': 'No IP address'
            }
        
        return collect_logs_from_ap(
            ap_ip=ap_ip,
            ap_name=ap_name,
            ap_mac=ap_mac,
            ssh_username=ssh_username,
            ssh_password=ssh_password,
            output_dir=collection_dir,
            timeout=timeout
        )
    
    # Execute parallel collection
    ap_infos = [(i, len(aps), ap) for i, ap in enumerate(aps, 1)]
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit controller task if requested
        controller_future = None
        if include_controller:
            controller_future = executor.submit(collect_controller_support_file, collection_dir)
        
        # Submit all AP tasks
        future_to_ap = {executor.submit(collect_with_info, ap_info): ap_info for ap_info in ap_infos}
        
        # Collect AP results as they complete
        for future in as_completed(future_to_ap):
            result = future.result()
            results.append(result)
        
        # Wait for controller result
        controller_result = controller_future.result() if controller_future else None
    
    collection_end_time = time.time()
    collection_end_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    collection_elapsed = collection_end_time - collection_start_time
    
    collection_info = {
        'start_timestamp': collection_start_timestamp,
        'end_timestamp': collection_end_timestamp,
        'elapsed_time': collection_elapsed,
        'collection_dir': collection_dir,
        'timestamp': timestamp
    }
    
    return results, controller_result, collection_info
