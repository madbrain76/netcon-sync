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
unifi_collect_ap_logs - Collect logs from all UniFi Access Points

This script:
1. Logs into the UniFi controller
2. Retrieves SSH credentials from the controller
3. Enumerates all access points
4. Connects to each AP via SSH
5. Collects log files
6. Downloads logs via SSH (using cat) to a local directory

Requires paramiko for SSH operations.
No SFTP subsystem required - uses SSH command execution for file transfer.

Version: 2025-02-10-v20 (streaming controller download for faster performance)
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
import json
import time
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from scp import SCPClient
import nss.error
import nss.nss as nss_core

try:
    import paramiko
except ModuleNotFoundError:
    print("ERROR: paramiko module not found")
    print("\nPlease install paramiko:")
    print("  pip install paramiko")
    sys.exit(1)

try:
    import unifi_utils
    from config import UNIFI_NETWORK_URL, UNIFI_SITE_ID
    from trust import handle_trust_server_url, handle_trust_ca_cert, format_nss_error, ensure_nss_db
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


def get_ssh_credentials():
    """
    Retrieve SSH credentials from the UniFi controller.
    
    The SSH credentials are stored in the controller's settings and used
    for device management.
    
    Returns:
        tuple: (username, password) or (None, None) if not found
    """
    print("Retrieving SSH credentials from controller...")
    
    # Try the settings endpoint first
    endpoint = f"/api/s/{UNIFI_SITE_ID}/get/setting/mgmt"
    try:
        settings = unifi_utils.make_unifi_api_call("GET", endpoint)
        if isinstance(settings, dict) and 'data' in settings:
            settings = settings['data']
        
        if isinstance(settings, list) and len(settings) > 0:
            mgmt_settings = settings[0]
            username = mgmt_settings.get('x_ssh_username', 'ubnt')
            password = mgmt_settings.get('x_ssh_password', '')
            
            if username and password:
                print(f"✓ Retrieved SSH credentials (username: {username})")
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
                print(f"✓ Retrieved SSH credentials from sysinfo (username: {username})")
                return username, password
    except Exception as e:
        print(f"Warning: Could not retrieve SSH credentials from sysinfo: {e}")
    
    print("Warning: Could not retrieve SSH credentials from controller")
    print("Using default username 'ubnt' - you may need to provide password manually")
    return 'ubnt', None


def execute_ssh_command(ssh_client, command, timeout=30, read_output=True, binary=False):
    """
    Execute SSH command and properly handle channels to prevent broken pipes.
    
    Args:
        ssh_client: Paramiko SSH client
        command: Command to execute
        timeout: Command timeout in seconds
        read_output: Whether to read and return output
        binary: If True, return binary data instead of decoded strings
    
    Returns:
        tuple: (stdout_output, stderr_output, exit_code) if read_output=True
               None if read_output=False
    """
    channel = None
    try:
        # Get a new channel
        transport = ssh_client.get_transport()
        channel = transport.open_session(timeout=timeout)
        channel.settimeout(timeout)
        
        # Execute command
        channel.exec_command(command)
        
        if not read_output:
            return None
        
        # Read both stdout and stderr to prevent deadlocks
        stdout_data = b''
        stderr_data = b''
        
        # Read until channel is closed
        while True:
            # Check if channel is ready to be closed
            if channel.exit_status_ready():
                # Read any remaining data
                while channel.recv_ready():
                    chunk = channel.recv(65536)
                    if not chunk:
                        break
                    stdout_data += chunk
                while channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(65536)
                    if not chunk:
                        break
                    stderr_data += chunk
                break
            
            # Read available data
            if channel.recv_ready():
                chunk = channel.recv(65536)
                if chunk:
                    stdout_data += chunk
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(65536)
                if chunk:
                    stderr_data += chunk
            
            # Small delay to prevent busy-waiting
            if not channel.recv_ready() and not channel.recv_stderr_ready():
                time.sleep(0.01)
        
        exit_code = channel.recv_exit_status()
        
        if binary:
            return stdout_data, stderr_data, exit_code
        
        return (
            stdout_data.decode('utf-8', errors='replace'),
            stderr_data.decode('utf-8', errors='replace'),
            exit_code
        )
    finally:
        # Always close the channel
        if channel:
            try:
                channel.close()
            except:
                pass


def collect_logs_from_ap(ap_ip, ap_name, ap_mac, ssh_username, ssh_password, output_dir, timeout=30):
    """
    Connect to an AP via SSH and collect log files.
    
    Args:
        ap_ip (str): AP IP address
        ap_name (str): AP name for logging
        ap_mac (str): AP MAC address
        ssh_username (str): SSH username
        ssh_password (str): SSH password
        output_dir (Path): Directory to save logs
        timeout (int): SSH connection timeout in seconds
    
    Returns:
        dict: Status and file list, or error information
    """
    result = {
        'ap_name': ap_name,
        'ap_mac': ap_mac,
        'ap_ip': ap_ip,
        'success': False,
        'files': [],
        'error': None,
        'elapsed_time': 0
    }
    
    start_time = time.time()
    start_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    ssh_client = None
    
    try:
        print(f"\n[{ap_name}] [{start_timestamp}] Connecting to {ap_ip}...")
        
        # Create SSH client
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect
        try:
            ssh_client.connect(
                hostname=ap_ip,
                username=ssh_username,
                password=ssh_password,
                timeout=timeout,
                look_for_keys=False,
                allow_agent=False
            )
        except paramiko.ssh_exception.AuthenticationException as e:
            result['error'] = f"Authentication failed: {e}"
            print(f"[{ap_name}] ✗ Authentication failed - ABORTING")
            return result
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            result['error'] = f"Connection failed: {e}"
            print(f"[{ap_name}] ✗ Connection failed - ABORTING")
            return result
        except Exception as e:
            result['error'] = f"SSH connection error: {e}"
            print(f"[{ap_name}] ✗ SSH connection error - ABORTING")
            return result
        
        print(f"[{ap_name}] ✓ Connected")
        
        # Verify we can execute commands
        try:
            stdout, stderr, exit_code = execute_ssh_command(ssh_client, 'echo "test"', timeout=10)
            if stdout.strip() != "test":
                result['error'] = "SSH command execution verification failed"
                print(f"[{ap_name}] ✗ Command execution failed - ABORTING")
                return result
            print(f"[{ap_name}] ✓ Command execution verified")
        except Exception as e:
            result['error'] = f"Command execution failed: {e}"
            print(f"[{ap_name}] ✗ Command execution failed - ABORTING")
            return result
        
        # Create AP-specific directory (include MAC address for uniqueness)
        # Format: "AP_Name_xx-xx-xx-xx-xx-xx"
        safe_ap_name = ap_name.replace('/', '_').replace(' ', '_')
        ap_dir_name = f"{safe_ap_name}_{ap_mac.replace(':', '-')}"
        ap_dir = output_dir / ap_dir_name
        ap_dir.mkdir(parents=True, exist_ok=True)
        
        # Check what diagnostic commands are available on this AP
        print(f"[{ap_name}] Checking available diagnostic commands...")
        available_commands = []
        for cmd in ['supp', 'info', 'syswrapper.sh', 'ubnt-systool', 'ubnt-tools', 'mca-cli-op', 'mca-dump', 'get-support', 'logread']:
            try:
                stdout, stderr, exit_code = execute_ssh_command(
                    ssh_client, 
                    f'which {cmd.split()[0]} 2>/dev/null',
                    timeout=5
                )
                if stdout.strip():
                    available_commands.append(cmd)
            except:
                pass
        
        if available_commands:
            print(f"[{ap_name}]   Available commands: {', '.join(available_commands)}")
        else:
            print(f"[{ap_name}]   No standard diagnostic commands found")
        
        # Try to generate support info bundle (UniFi APs have tools for this)
        print(f"[{ap_name}] Generating support info bundle...")
        support_bundle_generated = False
        support_bundle_path = None
        
        # Method 0: Try supp command (most comprehensive - generates /tmp/support.tgz)
        # This is the official UniFi support bundle generator, takes 30-60 seconds
        if not support_bundle_generated and 'supp' in available_commands:
            try:
                import re
                print(f"[{ap_name}]   Trying 'supp' command...")
                start_time = time.time()
                stdout, stderr, exit_code = execute_ssh_command(
                    ssh_client,
                    'supp 2>&1',
                    timeout=120  # Can take up to 60 seconds
                )
                elapsed = time.time() - start_time
                print(f"[{ap_name}]   supp command took {elapsed:.1f} seconds")
                
                # supp command always outputs to /tmp/support.tgz
                if 'Output: /tmp/support.tgz' in stdout or 'support.tgz' in stdout:
                    # Verify file exists
                    ls_stdout, ls_stderr, ls_exit = execute_ssh_command(
                        ssh_client,
                        'ls -lh /tmp/support.tgz 2>&1',
                        timeout=10
                    )
                    
                    if '/tmp/support.tgz' in ls_stdout and 'No such file' not in ls_stdout:
                        support_bundle_path = '/tmp/support.tgz'
                        support_bundle_generated = True
                        # Extract size from ls output
                        size_match = re.search(r'(\d+(?:\.\d+)?[KMG]?)\s+\w+\s+\d+\s+[\d:]+\s+/tmp/support\.tgz', ls_stdout)
                        size_str = size_match.group(1) if size_match else 'unknown size'
                        print(f"[{ap_name}] ✓ Support bundle generated: {support_bundle_path} ({size_str})")
                    else:
                        print(f"[{ap_name}]   supp: file not found after command completed")
                else:
                    print(f"[{ap_name}]   supp: command completed but no output file indicated (first 200 chars: {stdout[:200]}...)")
            except Exception as e:
                elapsed = time.time() - start_time if 'start_time' in locals() else 0
                print(f"[{ap_name}]   supp command failed after {elapsed:.1f}s: {e}")
        
        # Method 0A: Try syswrapper.sh get-support (most comprehensive on newer firmware)
        if not support_bundle_generated and 'syswrapper.sh' in available_commands:
            try:
                print(f"[{ap_name}]   Trying 'syswrapper.sh get-support'...")
                start_time = time.time()
                stdin, stdout, stderr = ssh_client.exec_command(
                    'time syswrapper.sh get-support 2>&1',
                    timeout=180  # Can take 2-3 minutes
                )
                output = stdout.read().decode('utf-8')
                elapsed = time.time() - start_time
                print(f"[{ap_name}]   syswrapper.sh get-support took {elapsed:.1f} seconds")
                
                # Look for generated file path
                import re
                match = re.search(r'(/(?:var/)?tmp/[^\s]+\.tar[^\s]*)', output)
                if match:
                    support_bundle_path = match.group(1)
                    support_bundle_generated = True
                    print(f"[{ap_name}] ✓ Support bundle generated: {support_bundle_path}")
                else:
                    # Check for recently created files (last 3 minutes)
                    stdin2, stdout2, stderr2 = ssh_client.exec_command(
                        'find /tmp /var/tmp -name "support*.tar*" -o -name "syswrapper*.tar*" -mmin -3 2>/dev/null | head -1',
                        timeout=10
                    )
                    file_path = stdout2.read().decode('utf-8').strip()
                    
                    if file_path:
                        support_bundle_path = file_path
                        support_bundle_generated = True
                        print(f"[{ap_name}] ✓ Support bundle generated: {support_bundle_path}")
                    else:
                        print(f"[{ap_name}]   syswrapper.sh get-support: no output file found")
                        print(f"[{ap_name}]   Output (first 300 chars): {output[:300]}...")
            except Exception as e:
                print(f"[{ap_name}]   syswrapper.sh get-support failed: {e}")
        
        # Method 0B: Try ubnt-systool support (comprehensive on older firmware)
        if not support_bundle_generated and 'ubnt-systool' in available_commands:
            try:
                print(f"[{ap_name}]   Trying 'ubnt-systool support'...")
                start_time = time.time()
                stdin, stdout, stderr = ssh_client.exec_command(
                    'time ubnt-systool support 2>&1',
                    timeout=180
                )
                output = stdout.read().decode('utf-8')
                elapsed = time.time() - start_time
                print(f"[{ap_name}]   ubnt-systool support took {elapsed:.1f} seconds")
                
                # Look for generated file path
                import re
                match = re.search(r'(/(?:var/)?tmp/[^\s]+\.tar[^\s]*)', output)
                if match:
                    support_bundle_path = match.group(1)
                    support_bundle_generated = True
                    print(f"[{ap_name}] ✓ Support bundle generated: {support_bundle_path}")
                else:
                    # Check for recently created files
                    stdin2, stdout2, stderr2 = ssh_client.exec_command(
                        'find /tmp /var/tmp -name "support*.tar*" -o -name "ubnt*.tar*" -mmin -3 2>/dev/null | head -1',
                        timeout=10
                    )
                    file_path = stdout2.read().decode('utf-8').strip()
                    
                    if file_path:
                        support_bundle_path = file_path
                        support_bundle_generated = True
                        print(f"[{ap_name}] ✓ Support bundle generated: {support_bundle_path}")
                    else:
                        print(f"[{ap_name}]   ubnt-systool support: no output file found")
                        print(f"[{ap_name}]   Output (first 300 chars): {output[:300]}...")
            except Exception as e:
                print(f"[{ap_name}]   ubnt-systool support failed: {e}")
        
        # Method 0C: Try other comprehensive commands
        if not support_bundle_generated:
            for cmd in ['info support', 'get-info', 'support-info']:
                try:
                    print(f"[{ap_name}]   Trying '{cmd}'...")
                    stdin, stdout, stderr = ssh_client.exec_command(
                        f'{cmd} 2>&1',
                        timeout=120
                    )
                    output = stdout.read().decode('utf-8')
                    
                    # Check if it generated a file
                    import re
                    match = re.search(r'(/(?:var/)?tmp/[^\s]+\.tar[^\s]*)', output)
                    if match:
                        support_bundle_path = match.group(1)
                        support_bundle_generated = True
                        print(f"[{ap_name}] ✓ Support bundle generated: {support_bundle_path}")
                        break
                    else:
                        # Check for recently created support files
                        stdin2, stdout2, stderr2 = ssh_client.exec_command(
                            'ls -1t /tmp/support*.tar* /tmp/info*.tar* /tmp/*support*.tar* 2>/dev/null | head -1',
                            timeout=10
                        )
                        file_path = stdout2.read().decode('utf-8').strip()
                        
                        if file_path:
                            # Verify recent (last 3 minutes)
                            stdin3, stdout3, stderr3 = ssh_client.exec_command(
                                f'find {file_path} -mmin -3 2>/dev/null',
                                timeout=10
                            )
                            recent_file = stdout3.read().decode('utf-8').strip()
                            
                            if recent_file:
                                support_bundle_path = file_path
                                support_bundle_generated = True
                                print(f"[{ap_name}] ✓ Support bundle generated: {support_bundle_path}")
                                break
                except Exception as e:
                    print(f"[{ap_name}]   '{cmd}' failed: {e}")
                    continue
        
        # Method 1: Try mca-dump (UniFi OS diagnostic dump - comprehensive and takes time)
        if not support_bundle_generated:
            try:
                print(f"[{ap_name}]   Trying 'mca-dump'...")
                stdin, stdout, stderr = ssh_client.exec_command(
                    'mca-dump 2>&1',
                    timeout=120
                )
                output = stdout.read().decode('utf-8')
                
                # mca-dump outputs JSON directly to stdout (not a file)
                if output.strip().startswith('{') and len(output) > 100:
                    # Save JSON output directly
                    timestamp = time.strftime('%Y%m%d-%H%M%S')
                    local_filename = f'mca-dump-{timestamp}.json'
                    local_path = ap_dir / local_filename
                    
                    print(f"[{ap_name}]   Saving mca-dump output...", end='', flush=True)
                    with open(local_path, 'w') as f:
                        f.write(output)
                    
                    output_size = len(output.encode('utf-8'))
                    print(f" ✓ ({output_size:,} bytes)")
                    
                    result['files'].append({
                        'remote_path': 'mca-dump (stdout)',
                        'local_path': str(local_path),
                        'size': output_size,
                        'type': 'mca-dump-json'
                    })
                    
                    # Don't set support_bundle_generated - mca-dump JSON is complementary
                    # We still want to collect tar-based bundles from other methods
                    print(f"[{ap_name}] ✓ mca-dump output saved: {local_filename}")
                else:
                    # Maybe it's a file-based version, check for file path
                    import re
                    match = re.search(r'(/(?:var/)?tmp/[^\s]+\.tar[^\s]*)', output)
                    if match:
                        support_bundle_path = match.group(1)
                        support_bundle_generated = True
                        print(f"[{ap_name}] ✓ Support bundle generated: {support_bundle_path}")
                    else:
                        print(f"[{ap_name}]   mca-dump: unexpected output format (first 100 chars: {output[:100]}...)")
            except Exception as e:
                print(f"[{ap_name}]   mca-dump command failed: {e}")
        
        # Method 2: Try get-support (standalone command on some APs)
        if not support_bundle_generated:
            try:
                print(f"[{ap_name}]   Trying 'get-support'...")
                stdin, stdout, stderr = ssh_client.exec_command(
                    'get-support 2>&1',
                    timeout=120
                )
                output = stdout.read().decode('utf-8')
                
                # Look for output file path in the command output
                import re
                match = re.search(r'(/(?:var/)?tmp/[^\s]+\.tar[^\s]*)', output)
                if match:
                    support_bundle_path = match.group(1)
                    support_bundle_generated = True
                    print(f"[{ap_name}] ✓ Support bundle generated: {support_bundle_path}")
                else:
                    # Check for common support bundle file patterns
                    stdin2, stdout2, stderr2 = ssh_client.exec_command(
                        'ls -1t /tmp/support*.tar* /tmp/info*.tar* /var/tmp/support*.tar* 2>/dev/null | head -1',
                        timeout=10
                    )
                    file_path = stdout2.read().decode('utf-8').strip()
                    
                    if file_path:
                        # Verify file is recent (created in last 5 minutes)
                        stdin3, stdout3, stderr3 = ssh_client.exec_command(
                            f'find {file_path} -mmin -5 2>/dev/null',
                            timeout=10
                        )
                        recent_file = stdout3.read().decode('utf-8').strip()
                        
                        if recent_file:
                            support_bundle_path = file_path
                            support_bundle_generated = True
                            print(f"[{ap_name}] ✓ Support bundle generated: {support_bundle_path}")
                        else:
                            print(f"[{ap_name}]   get-support: found old file, not using it")
                    else:
                        print(f"[{ap_name}]   get-support: no output file found (output: {output[:100]}...)")
            except Exception as e:
                print(f"[{ap_name}]   get-support command failed: {e}")
        
        # Method 3: Try mca-cli-op info (UniFi OS devices)
        if not support_bundle_generated:
            try:
                print(f"[{ap_name}]   Trying 'mca-cli-op info'...")
                
                # Generate bundle with timestamp
                timestamp = time.strftime('%Y%m%d-%H%M%S')
                stdin, stdout, stderr = ssh_client.exec_command(
                    f'mca-cli-op info > /tmp/mca-info-{timestamp}.txt 2>&1 && tar czf /tmp/ap-mca-{timestamp}.tar.gz /tmp/mca-info-{timestamp}.txt /var/log 2>/dev/null && echo /tmp/ap-mca-{timestamp}.tar.gz',
                    timeout=120
                )
                tar_output = stdout.read().decode('utf-8').strip()
                
                # Check if tar path was printed (last line should be the path)
                lines = tar_output.split('\n')
                tar_path = lines[-1] if lines else ''
                
                if tar_path and tar_path.startswith('/tmp/') and '.tar.gz' in tar_path:
                    # Verify file exists
                    stdin2, stdout2, stderr2 = ssh_client.exec_command(f'test -f {tar_path} && echo "EXISTS"', timeout=10)
                    exists = stdout2.read().decode('utf-8').strip()
                    
                    if exists == "EXISTS":
                        support_bundle_path = tar_path
                        support_bundle_generated = True
                        print(f"[{ap_name}] ✓ Support bundle generated: {support_bundle_path}")
                    else:
                        print(f"[{ap_name}]   mca-cli-op: tar file not found at {tar_path}")
                else:
                    print(f"[{ap_name}]   mca-cli-op: couldn't create tar bundle")
            except Exception as e:
                print(f"[{ap_name}]   mca-cli-op command failed: {e}")
        
        # Method 4: Try info command with compress (common on UniFi APs)
        if not support_bundle_generated:
            try:
                print(f"[{ap_name}]   Trying 'info' command...")
                stdin, stdout, stderr = ssh_client.exec_command(
                    'info > /tmp/info.txt 2>&1 && tar czf /tmp/ap-info-$(date +%Y%m%d-%H%M%S).tar.gz /tmp/info.txt /var/log 2>/dev/null',
                    timeout=120
                )
                stdout.read()  # Wait for completion
                
                # Check if file was created
                stdin, stdout, stderr = ssh_client.exec_command('ls -1 /tmp/ap-info-*.tar.gz 2>/dev/null | head -1')
                file_path = stdout.read().decode('utf-8').strip()
                
                if file_path:
                    support_bundle_path = file_path
                    support_bundle_generated = True
                    print(f"[{ap_name}] ✓ Support bundle generated: {support_bundle_path}")
            except Exception as e:
                print(f"[{ap_name}]   info command failed: {e}")
        
        # Method 5: Try syswrapper.sh get-support (newer UniFi OS)
        if not support_bundle_generated:
            try:
                print(f"[{ap_name}]   Trying 'syswrapper.sh get-support'...")
                stdin, stdout, stderr = ssh_client.exec_command(
                    'syswrapper.sh get-support 2>&1',
                    timeout=120  # Support bundle can take a while
                )
                output = stdout.read().decode('utf-8')
                
                # Look for the generated file path in output
                if 'support' in output.lower() or '/tmp/' in output:
                    # Find the file path
                    import re
                    match = re.search(r'(/tmp/[^\s]+\.tar[^\s]*)', output)
                    if match:
                        support_bundle_path = match.group(1)
                        support_bundle_generated = True
                        print(f"[{ap_name}] ✓ Support bundle generated: {support_bundle_path}")
            except Exception as e:
                print(f"[{ap_name}]   syswrapper.sh not available or failed: {e}")
        
        # Method 6: Try ubnt-systool (older UniFi)
        if not support_bundle_generated:
            try:
                print(f"[{ap_name}]   Trying 'ubnt-systool support'...")
                stdin, stdout, stderr = ssh_client.exec_command(
                    'ubnt-systool support 2>&1',
                    timeout=120
                )
                output = stdout.read().decode('utf-8')
                
                if '/tmp/' in output:
                    import re
                    match = re.search(r'(/tmp/[^\s]+\.tar[^\s]*)', output)
                    if match:
                        support_bundle_path = match.group(1)
                        support_bundle_generated = True
                        print(f"[{ap_name}] ✓ Support bundle generated: {support_bundle_path}")
            except Exception as e:
                print(f"[{ap_name}]   ubnt-systool not available or failed: {e}")
        
        # Method 5: Manual collection - gather all logs and info into tar
        if not support_bundle_generated:
            try:
                print(f"[{ap_name}]   Creating manual log archive...")
                timestamp = time.strftime('%Y%m%d-%H%M%S')
                archive_name = f'/tmp/ap-logs-{timestamp}.tar.gz'
                
                stdin, stdout, stderr = ssh_client.exec_command(
                    f'tar czf {archive_name} /var/log 2>/dev/null',
                    timeout=120
                )
                stdout.read()  # Wait for completion
                
                # Verify file exists and has size
                stdin, stdout, stderr = ssh_client.exec_command(f'test -f {archive_name} && stat -c %s {archive_name}')
                size_str = stdout.read().decode('utf-8').strip()
                
                if size_str and int(size_str) > 0:
                    support_bundle_path = archive_name
                    support_bundle_generated = True
                    print(f"[{ap_name}] ✓ Manual log archive created: {support_bundle_path}")
            except Exception as e:
                print(f"[{ap_name}]   Manual archive creation failed: {e}")
        
        # Download files using SCP (more reliable than SSH cat)
        def download_file_via_scp(remote_path, local_path, file_type='file'):
            """Download a file using SCP protocol."""
            try:
                # Get file size first
                size_stdout, size_stderr, size_exit = execute_ssh_command(
                    ssh_client,
                    f'stat -c %s "{remote_path}" 2>/dev/null || wc -c < "{remote_path}"',
                    timeout=10
                )
                size_str = size_stdout.strip()
                try:
                    expected_size = int(size_str)
                except:
                    expected_size = None
                
                filename = Path(remote_path).name
                
                # Show expected size
                if expected_size:
                    if expected_size > 1024*1024:
                        size_display = f"{expected_size/1024/1024:.1f} MB"
                    elif expected_size > 1024:
                        size_display = f"{expected_size/1024:.1f} KB"
                    else:
                        size_display = f"{expected_size} bytes"
                    print(f"[{ap_name}]   Downloading {filename} ({size_display})...", end='', flush=True)
                else:
                    print(f"[{ap_name}]   Downloading {filename}...", end='', flush=True)
                
                # Use SCP to download the file
                with SCPClient(ssh_client.get_transport()) as scp:
                    scp.get(remote_path, str(local_path))
                
                actual_size = Path(local_path).stat().st_size
                print(f" ✓")
                
                # Append to result dict
                result['files'].append({
                    'remote_path': remote_path,
                    'local_path': str(local_path),
                    'size': actual_size,
                    'type': file_type
                })
                return True
                    
            except Exception as e:
                print(f" ✗ Failed: {e}")
                return False
        
        # Download the support bundle if generated
        if support_bundle_generated and support_bundle_path:
            filename = Path(support_bundle_path).name
            local_path = ap_dir / filename
            
            if download_file_via_scp(support_bundle_path, local_path, 'support_bundle'):
                # Clean up remote file
                try:
                    stdin, stdout, stderr = ssh_client.exec_command(f'rm -f {support_bundle_path}')
                    stdout.read()  # Wait for completion
                except:
                    pass  # Ignore cleanup errors
        
        # Also collect individual log files from /var/log/
        print(f"[{ap_name}] Collecting individual log files...")
        stdin, stdout, stderr = ssh_client.exec_command(
            r'find /var/log -type f \( -name "*.log" -o -name "messages" -o -name "syslog" \) 2>/dev/null | head -20'
        )
        log_files = stdout.read().decode('utf-8').strip().split('\n')
        log_files = [f.strip() for f in log_files if f.strip()]
        
        if log_files:
            print(f"[{ap_name}] Found {len(log_files)} log file(s)")
            
            # Download each log file
            for remote_path in log_files:
                filename = Path(remote_path).name
                local_path = ap_dir / filename
                
                # Skip if already exists (e.g., from support bundle)
                if local_path.exists():
                    continue
                
                download_file_via_scp(remote_path, local_path, 'log_file')
        else:
            print(f"[{ap_name}]   No individual log files found")
        
        # Check if we got any files at all
        if not result['files']:
            result['error'] = "No log files collected"
            print(f"[{ap_name}] ⚠ No log files were collected")
        else:
            result['success'] = True
            print(f"[{ap_name}] ✓ Downloaded {len(result['files'])} file(s) to {ap_dir}")
        
    except Exception as e:
        result['error'] = str(e)
        print(f"[{ap_name}] ✗ Error: {e}")
    finally:
        if ssh_client:
            try:
                ssh_client.close()
            except:
                pass
        
        # Calculate elapsed time and add completion timestamp
        result['elapsed_time'] = time.time() - start_time
        completion_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        
        if result['success']:
            print(f"[{ap_name}] [{completion_timestamp}] ✓ Completed in {result['elapsed_time']:.1f}s")
        else:
            print(f"[{ap_name}] [{completion_timestamp}] ✗ Failed after {result['elapsed_time']:.1f}s")
    
    # Add timestamps to result
    result['start_timestamp'] = start_timestamp
    result['end_timestamp'] = completion_timestamp
    
    return result


def collect_controller_support_file(output_dir):
    """
    Collect support file from the UniFi controller.
    
    Args:
        output_dir (Path): Directory to save the support file
    
    Returns:
        dict: Status and file information
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
        print(f"\n[CONTROLLER] [{start_timestamp}] Generating network support file...")
        
        # Trigger support file generation
        endpoint = f'/api/s/{UNIFI_SITE_ID}/cmd/system'
        payload = {'cmd': 'gen-support-file'}
        
        try:
            gen_result = unifi_utils.make_unifi_api_call('POST', endpoint, json=payload)
            print("[CONTROLLER] ✓ Support file generation initiated")
        except Exception as e:
            result['error'] = f"Failed to initiate support file generation: {e}"
            print(f"[CONTROLLER] ✗ Failed to initiate generation: {e}")
            result['elapsed_time'] = time.time() - start_time
            return result
        
        # Wait a moment for file generation to start
        print("[CONTROLLER] Waiting for file generation...")
        time.sleep(5)  # Increased wait time for large support files
        
        # Try downloading from common support file endpoints
        # Use streaming download to avoid loading entire file into memory
        download_urls = [
            f'/api/s/{UNIFI_SITE_ID}/dl/support',
            '/dl/support',
            f'/api/s/{UNIFI_SITE_ID}/dl/support.tar.gz',
        ]
        
        # Save to file with timestamp
        timestamp = time.strftime('%Y%m%d-%H%M%S')
        filename = f"controller_support_{timestamp}.tar.gz"
        file_path = output_dir / filename
        
        download_success = False
        total_bytes = 0
        
        for url in download_urls:
            try:
                print(f"[CONTROLLER] Trying download URL: {url}")
                sys.stdout.flush()
                
                # Time the download
                download_start = time.time()
                
                # Stream download directly to file (don't load into memory)
                response = unifi_utils.make_unifi_api_call('GET', url, stream=True)
                
                # Read and write in 1MB chunks for efficiency
                chunk_size = 1024 * 1024  # 1MB chunks
                with open(file_path, 'wb') as f:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        total_bytes += len(chunk)
                
                response.close()
                
                download_time = time.time() - download_start
                speed_mbps = (total_bytes / (1024 * 1024)) / download_time if download_time > 0 else 0
                
                print(f"[CONTROLLER] ✓ Downloaded support file ({total_bytes} bytes) in {download_time:.1f}s ({speed_mbps:.1f} MB/s)")
                sys.stdout.flush()
                
                download_success = True
                break
            except Exception as e:
                print(f"[CONTROLLER]   Failed: {e}")
                sys.stdout.flush()
                # Clean up partial file on error
                if file_path.exists():
                    file_path.unlink()
                continue
        
        if not download_success:
            result['error'] = "Could not download support file from any known endpoint"
            print(f"[CONTROLLER] ✗ {result['error']}")
            result['elapsed_time'] = time.time() - start_time
            return result
        
        result['success'] = True
        result['file_path'] = str(file_path)
        result['size'] = total_bytes
        result['elapsed_time'] = time.time() - start_time
        
        size_mb = total_bytes / (1024 * 1024)
        print(f"[CONTROLLER] ✓ Saved to {filename} ({size_mb:.1f} MB)")
        sys.stdout.flush()
        
    except Exception as e:
        result['error'] = f"Unexpected error: {e}"
        print(f"[CONTROLLER] ✗ Error: {e}")
    
    # Ensure elapsed_time is always set
    if result['elapsed_time'] == 0:
        result['elapsed_time'] = time.time() - start_time
    
    # Print completion timestamp
    completion_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    result['end_timestamp'] = completion_timestamp
    
    if result['success']:
        print(f"[CONTROLLER] [{completion_timestamp}] ✓ Completed in {result['elapsed_time']:.1f}s")
    else:
        print(f"[CONTROLLER] [{completion_timestamp}] ✗ Failed after {result['elapsed_time']:.1f}s")
    
    return result


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Collect logs from all UniFi Access Points via SSH/SCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect logs from all APs (parallel, default)
  %(prog)s
  
  # Collect logs sequentially (slower but more controlled)
  %(prog)s --parallel 1
  
  # Collect with maximum parallelism
  %(prog)s --parallel 0
  
  # Collect logs to specific directory
  %(prog)s --output /tmp/ap-logs
  
  # Collect from specific APs only (by name pattern)
  %(prog)s --filter-name "Office"
  
  # Collect from specific APs only (by IP pattern)
  %(prog)s --filter-ip "192.168.1"
  
  # Collect only from online APs
  %(prog)s --online-only
  
  # Use custom SSH credentials
  %(prog)s --ssh-username admin --ssh-password secret
  
  # Trust controller certificate first (if needed)
  %(prog)s trust --server

Certificate Trust:
  If you encounter certificate verification errors, use:
    %(prog)s trust --server
  or:
    %(prog)s trust --ca <ca-file.crt>
        """
    )
    
    # Trust subcommand
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    trust_parser = subparsers.add_parser(
        "trust",
        help="Trust UniFi controller certificate or CA"
    )
    
    trust_group = trust_parser.add_mutually_exclusive_group(required=True)
    trust_group.add_argument(
        "--server",
        action="store_true",
        help="Trust the UniFi controller server certificate"
    )
    trust_group.add_argument(
        "--ca",
        metavar="CA_FILE",
        help="Trust a CA certificate file (PEM or DER format)"
    )
    
    # Main command arguments
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path.home() / "ap-logs",
        help="Output directory for collected logs (default: ~/ap-logs/)"
    )
    
    parser.add_argument(
        "--filter-name",
        help="Filter APs by name (case-insensitive substring match)"
    )
    
    parser.add_argument(
        "--filter-ip",
        help="Filter APs by IP address (substring match)"
    )
    
    parser.add_argument(
        "--filter-mac",
        help="Filter APs by MAC address (substring match)"
    )
    
    parser.add_argument(
        "--online-only",
        action="store_true",
        help="Collect logs only from online APs"
    )
    
    parser.add_argument(
        "--ssh-username",
        help="SSH username (default: retrieved from controller)"
    )
    
    parser.add_argument(
        "--ssh-password",
        help="SSH password (default: retrieved from controller)"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="SSH connection timeout in seconds (default: 30)"
    )
    
    parser.add_argument(
        "--parallel",
        "-p",
        type=int,
        metavar="N",
        default=0,
        help="Collect from N APs in parallel (default: 0 = unlimited, all APs at once)"
    )
    
    args = parser.parse_args()
    
    # Print version for debugging
    print("unifi_collect_ap_logs - Version: 2025-02-10-v20")
    print()
    
    # Handle config errors
    if 'UNIFI_NETWORK_URL' not in globals() or UNIFI_NETWORK_URL is None:
        if '_config_error' in globals():
            print(f"Configuration Error: {_config_error}\n", file=sys.stderr)
        parser.print_help(sys.stderr)
        sys.exit(1)
    
    # Handle trust command
    if args.command == "trust":
        from pathlib import Path as PathLib
        nss_db_dir = PathLib.home() / ".netcon-sync"
        
        try:
            if args.server:
                handle_trust_server_url(UNIFI_NETWORK_URL, nss_db_dir)
            elif args.ca:
                handle_trust_ca_cert(args.ca, nss_db_dir)
            print("Certificate trust operation completed successfully")
            return 0
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
    
    # Initialize NSS database
    nss_db_dir = Path.home() / ".netcon-sync"
    ensure_nss_db(nss_db_dir)
    
    try:
        nss_core.nss_init(str(nss_db_dir))
    except Exception as e:
        print(f"Error initializing NSS: {e}", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Login to controller
        print("Logging into UniFi controller...")
        unifi_utils.login()
        print("✓ Login successful")
        
        # Get SSH credentials
        ssh_username = args.ssh_username
        ssh_password = args.ssh_password
        
        if not ssh_username or not ssh_password:
            cred_username, cred_password = get_ssh_credentials()
            if not ssh_username:
                ssh_username = cred_username
            if not ssh_password:
                ssh_password = cred_password
        
        if not ssh_password:
            import getpass
            ssh_password = getpass.getpass(f"SSH password for {ssh_username}: ")
        
        # Get all devices
        print("\nFetching UniFi devices...")
        all_devices = unifi_utils.get_devices()
        
        # Filter for APs
        aps = [device for device in all_devices if device.get("type") == "uap"]
        
        if not aps:
            print("No Access Points found")
            return 0
        
        print(f"Found {len(aps)} Access Point(s)")
        
        # Apply filters
        filtered_aps = []
        for ap in aps:
            match = True
            
            # Online filter
            if args.online_only:
                if ap.get("state") != 1:  # 1 = connected/online
                    match = False
            
            # Name filter
            if args.filter_name:
                ap_name = ap.get("name", "")
                if args.filter_name.lower() not in ap_name.lower():
                    match = False
            
            # IP filter
            if args.filter_ip:
                ap_ip = ap.get("ip", "")
                if args.filter_ip not in ap_ip:
                    match = False
            
            # MAC filter
            if args.filter_mac:
                ap_mac = ap.get("mac", "")
                if args.filter_mac.lower() not in ap_mac.lower():
                    match = False
            
            if match:
                filtered_aps.append(ap)
        
        if not filtered_aps:
            print("No Access Points match the specified filters")
            return 0
        
        print(f"Collecting logs from {len(filtered_aps)} AP(s)...")
        
        # Create output directory
        args.output.mkdir(parents=True, exist_ok=True)
        print(f"Output directory: {args.output.absolute()}")
        
        # Create unique collection subdirectory
        timestamp = time.strftime('%Y%m%d-%H%M%S')
        collection_dir = args.output / f"collection_{timestamp}"
        collection_dir.mkdir(parents=True, exist_ok=True)
        
        # Collect logs from each AP
        results = []
        print_lock = Lock()  # For thread-safe printing
        
        def collect_with_info(ap_info):
            """Wrapper to collect logs with AP info tuple."""
            i, total, ap = ap_info
            ap_name = ap.get("name", ap.get("mac", "unknown"))
            ap_mac = ap.get("mac", "unknown")
            ap_ip = ap.get("ip")
            ap_state = "online" if ap.get("state") == 1 else "offline"
            
            with print_lock:
                print(f"\n{'='*60}")
                print(f"[{i}/{total}] {ap_name} ({ap_ip}) - {ap_state}")
                print(f"{'='*60}")
            
            if not ap_ip:
                with print_lock:
                    print(f"⚠ Skipping {ap_name}: No IP address")
                return {
                    'ap_name': ap_name,
                    'ap_mac': ap_mac,
                    'ap_ip': None,
                    'success': False,
                    'error': 'No IP address'
                }
            
            if ap.get("state") != 1:
                with print_lock:
                    print(f"⚠ Warning: AP is {ap_state}")
            
            result = collect_logs_from_ap(
                ap_ip=ap_ip,
                ap_name=ap_name,
                ap_mac=ap_mac,
                ssh_username=ssh_username,
                ssh_password=ssh_password,
                output_dir=collection_dir,
                timeout=args.timeout
            )
            
            return result
        
        # Parallel collection
        # Calculate workers: all APs + 1 for controller (to ensure true parallelism)
        if args.parallel > 0:
            max_workers = args.parallel + 1  # Add 1 for controller support file
        else:
            max_workers = len(filtered_aps) + 1  # All APs + controller
        print(f"Using parallel collection with {max_workers} worker(s)\n")
        
        # Track overall collection timing
        collection_start_time = time.time()
        collection_start_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Create AP info tuples with index
        ap_infos = [(i, len(filtered_aps), ap) for i, ap in enumerate(filtered_aps, 1)]
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit controller support file collection task
            controller_future = executor.submit(collect_controller_support_file, collection_dir)
            
            # Submit all AP tasks
            future_to_ap = {executor.submit(collect_with_info, ap_info): ap_info for ap_info in ap_infos}
            
            # Collect results as they complete
            for future in as_completed(future_to_ap):
                result = future.result()
                results.append(result)
            
            # Wait for controller support file collection
            controller_result = controller_future.result()
        
        # Track overall collection timing
        collection_end_time = time.time()
        collection_end_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        collection_elapsed = collection_end_time - collection_start_time
        
        # Print summary
        print(f"\n{'='*60}")
        print("SUMMARY")
        print(f"{'='*60}")
        
        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]
        
        print(f"Total APs: {len(results)}")
        print(f"Successful: {len(successful)}")
        print(f"Failed: {len(failed)}")
        
        total_files = sum(len(r.get('files', [])) for r in successful)
        total_size = sum(
            sum(f['size'] for f in r.get('files', []))
            for r in successful
        )
        
        # Calculate average file size
        avg_size = total_size / total_files if total_files > 0 else 0
        
        print(f"\n" + "="*60)
        print(f"COLLECTION SUMMARY")
        print(f"="*60)
        print(f"Collection start: {collection_start_timestamp}")
        print(f"Collection end:   {collection_end_timestamp}")
        print(f"Total collection time: {collection_elapsed:.1f}s")
        print(f"\nTotal APs processed: {len(results)}")
        print(f"  ✓ Successful: {len(successful)}")
        print(f"  ✗ Failed: {len(failed)}")
        print(f"\nTotal files collected: {total_files}")
        print(f"Total size: {total_size:,} bytes ({total_size / 1024 / 1024:.2f} MB)")
        if total_files > 0:
            print(f"Average file size: {avg_size:,.0f} bytes ({avg_size / 1024:.1f} KB)")
        
        # Show per-AP breakdown
        print(f"\nPer-AP breakdown:")
        for r in successful:
            num_files = len(r.get('files', []))
            ap_size = sum(f['size'] for f in r.get('files', []))
            ap_name = r['ap_name']
            ap_mac = r.get('ap_mac', 'unknown')
            elapsed = r.get('elapsed_time', 0)
            start_ts = r.get('start_timestamp', 'N/A')
            end_ts = r.get('end_timestamp', 'N/A')
            # Format directory name the same way as it's created
            safe_ap_name = ap_name.replace('/', '_').replace(' ', '_')
            dir_name = f"{safe_ap_name}_{ap_mac.replace(':', '-')}"
            print(f"  • {dir_name}: {num_files} file(s), {ap_size:,} bytes ({ap_size / 1024:.1f} KB), {elapsed:.1f}s")
            print(f"    Start: {start_ts}  End: {end_ts}")
        
        if failed:
            print(f"\nFailed APs:")
            for r in failed:
                print(f"  • {r['ap_name']} ({r['ap_ip']}): {r.get('error', 'Unknown error')}")
        
        # Show controller support file status
        if controller_result['success']:
            ctrl_size = controller_result['size']
            ctrl_elapsed = controller_result.get('elapsed_time', 0)
            ctrl_start = controller_result.get('start_timestamp', 'N/A')
            ctrl_end = controller_result.get('end_timestamp', 'N/A')
            if ctrl_size > 1024*1024:
                size_display = f"{ctrl_size/1024/1024:.1f} MB"
            elif ctrl_size > 1024:
                size_display = f"{ctrl_size/1024:.1f} KB"
            else:
                size_display = f"{ctrl_size} bytes"
            print(f"\nController support file: {Path(controller_result['file_path']).name} ({size_display}, {ctrl_elapsed:.1f}s)")
            print(f"  Start: {ctrl_start}  End: {ctrl_end}")
        else:
            print(f"\n⚠ Controller support file collection failed: {controller_result.get('error', 'Unknown error')}")
        
        # Save summary to JSON
        summary_file = collection_dir / "collection_summary.json"
        summary_data = {
            'timestamp': datetime.now().isoformat(),
            'total_aps': len(results),
            'successful': len(successful),
            'failed': len(failed),
            'total_files': total_files,
            'total_size_bytes': total_size,
            'controller_support_file': controller_result,
            'results': results
        }
        
        with open(summary_file, 'w') as f:
            json.dump(summary_data, f, indent=2)
        
        print(f"\n✓ Summary saved to: {summary_file}")
        
        # Create tarball of all collected files in output directory
        print(f"\nCreating tarball...")
        tarball_start_time = time.time()
        tarball_name = f"ap-log-{timestamp}.tgz"
        tarball_path = args.output / tarball_name
        
        import tarfile
        import shutil
        try:
            with tarfile.open(tarball_path, 'w:gz') as tar:
                tar.add(collection_dir, arcname=collection_dir.name)
            
            tarball_size = tarball_path.stat().st_size
            if tarball_size > 1024*1024:
                size_display = f"{tarball_size/1024/1024:.1f} MB"
            elif tarball_size > 1024:
                size_display = f"{tarball_size/1024:.1f} KB"
            else:
                size_display = f"{tarball_size} bytes"
            
            print(f"✓ Created {tarball_path} ({size_display})")
            
            # Delete collection directory after successful tarball creation
            shutil.rmtree(collection_dir)
            print(f"✓ Cleaned up collection directory")
            
            tarball_elapsed = time.time() - tarball_start_time
            print(f"\nTarball creation took {tarball_elapsed:.1f}s")
        except Exception as e:
            print(f"⚠ Failed to create tarball: {e}")
        
        return 0 if len(failed) == 0 else 1
        
    except nss.error.NSPRError as e:
        error_msg = format_nss_error("UniFi", UNIFI_NETWORK_URL, e, sys.argv[0])
        print(error_msg, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 130
    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
