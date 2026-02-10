# unifi_collect_ap_logs - Collect Logs from UniFi Access Points

## Overview

`unifi_collect_ap_logs.py` is a tool that automates the collection of log files from all UniFi Access Points in your network. It connects to each AP via SSH, retrieves log files, and downloads them using SSH file transfer (no SFTP required).

## Features

- **Parallel Collection**: Collect from multiple APs simultaneously (default: 5 workers)
- **Automatic SSH Credential Retrieval**: Gets SSH credentials from the UniFi controller
- **Mass Log Collection**: Collects logs from all APs automatically
- **Official Support Bundles**: Uses `supp` command for comprehensive diagnostics
- **Flexible Filtering**: Filter APs by name, IP, MAC, or online status
- **Organized Storage**: Creates separate directories for each AP
- **Progress Display**: Shows real-time progress for each AP
- **Summary Report**: Generates JSON summary of collection results
- **Error Handling**: Gracefully handles connection failures and continues
- **Certificate Trust Management**: Built-in trust subcommand for NSS certificates
- **No SFTP Required**: Uses SSH cat for file transfer (more reliable)

## Requirements

- Python 3.6+
- paramiko library for SSH
- UniFi Network Controller with configured SSH credentials
- Network access to APs via SSH (port 22)
- **No SFTP required** - uses SSH command execution for file transfer

## Installation

```bash
# Install dependencies
pip install paramiko

# Or use the project setup
./install_deps.sh
```

## Configuration

The tool uses the same configuration as other UniFi tools:

```bash
# config.py
UNIFI_NETWORK_URL = "https://unifi.example.com"
UNIFI_SITE_ID = "default"
```

SSH credentials are automatically retrieved from the controller's management settings.

## Usage

### Basic Usage

```bash
# Collect logs from all APs (default: 5 parallel workers)
./unifi_collect_ap_logs.py

# Logs are saved to ./ap-logs/ by default
```

### Parallel Collection

The tool collects logs from multiple APs simultaneously for faster processing:

```bash
# Use default parallel collection (5 workers)
./unifi_collect_ap_logs.py

# Collect from 10 APs in parallel
./unifi_collect_ap_logs.py --parallel 10

# Use maximum parallelism (all APs at once)
./unifi_collect_ap_logs.py --parallel 0

# Disable parallel collection (sequential, slower but more controlled)
./unifi_collect_ap_logs.py --parallel 1
```

**Performance**:
- **Sequential** (--parallel 1): ~45 seconds per AP (10 APs = ~7.5 minutes)
- **Parallel** (--parallel 5): ~45 seconds total for 5 APs at a time (10 APs = ~1.5 minutes)
- **Maximum** (--parallel 0): ~45 seconds total for all APs (10 APs = ~45 seconds)

**Note**: The `supp` command on each AP takes 40-50 seconds to generate comprehensive diagnostics, so parallel collection provides significant time savings when collecting from multiple APs.

### Custom Output Directory

```bash
# Save logs to specific directory
./unifi_collect_ap_logs.py --output /var/log/unifi-ap-logs
```

### Filter by AP Name

```bash
# Collect from APs matching "Office"
./unifi_collect_ap_logs.py --filter-name "Office"

# Collect from specific AP
./unifi_collect_ap_logs.py --filter-name "AP-Kitchen"
```

### Filter by IP or MAC

```bash
# Collect from APs in specific subnet
./unifi_collect_ap_logs.py --filter-ip "192.168.1"

# Collect from specific AP by MAC
./unifi_collect_ap_logs.py --filter-mac "aa:bb:cc:dd:ee:ff"
```

### Online APs Only

```bash
# Only collect from currently online APs
./unifi_collect_ap_logs.py --online-only
```

### Custom SSH Credentials

```bash
# Override controller-provided credentials
./unifi_collect_ap_logs.py --ssh-username admin --ssh-password secret

# Prompt for password (username from controller)
./unifi_collect_ap_logs.py --ssh-username admin
```

### Custom Timeout

```bash
# Use 60-second timeout for slow connections
./unifi_collect_ap_logs.py --timeout 60
```

### Certificate Trust

```bash
# Trust the UniFi controller certificate (first time setup)
./unifi_collect_ap_logs.py trust --server

# Or trust a CA certificate
./unifi_collect_ap_logs.py trust --ca /path/to/ca.crt
```

## Output Structure

The tool creates a directory structure like this:

```
ap-logs/
├── AP-Office/
│   ├── messages
│   ├── syslog.log
│   └── wpa_supplicant.log
├── AP-Kitchen/
│   ├── messages
│   └── syslog.log
├── AP-Bedroom/
│   ├── messages
│   └── syslog.log
└── collection_summary.json
```

### Summary JSON

The `collection_summary.json` file contains:

```json
{
  "timestamp": "2025-01-15T10:30:45.123456",
  "total_aps": 3,
  "successful": 3,
  "failed": 0,
  "total_files": 9,
  "total_size_bytes": 1234567,
  "results": [
    {
      "ap_name": "AP-Office",
      "ap_ip": "192.168.1.10",
      "success": true,
      "files": [
        {
          "remote_path": "/var/log/messages",
          "local_path": "ap-logs/AP-Office/messages",
          "size": 123456
        }
      ]
    }
  ]
}
```

## Collected Files

### Support Bundle (Primary)

When successful, you'll get a comprehensive support bundle file:
- **Filename**: `support-YYYYMMDD-HHMMSS.tar.gz` or `info-YYYYMMDD.tar`
- **Contents**: Complete system diagnostic information
- **Size**: Typically 1-10 MB
- **Includes**: All logs, configs, stats, process info

### Individual Log Files (Fallback/Supplementary)

If support bundle generation fails, or as supplementary data:

- **messages**: System messages and general logs
- **syslog**: System log entries  
- **wpa_supplicant.log**: WiFi authentication logs (if mesh AP)
- **hostapd.log**: Access point daemon logs (if present)
- **ubnt-discover.log**: UniFi discovery protocol logs (if present)
- **kernel.log**: Kernel messages (if present)
- **daemon.log**: System daemon logs (if present)

**Note**: The support bundle is preferred as it contains more comprehensive data than individual log files.

## Workflow

1. **Login**: Authenticates to UniFi controller
2. **Retrieve Credentials**: Gets SSH username/password from controller settings
3. **Enumerate APs**: Fetches all access points from controller
4. **Filter**: Applies any name/IP/MAC/status filters
5. **For each AP**:
   - **Connect**: Establishes SSH connection (aborts AP on failure)
   - **Verify**: Tests command execution (aborts AP on failure)
   - **Generate Support Bundle**: Runs `syswrapper.sh get-support` or `ubnt-systool support` (10-120 seconds)
   - **Download Bundle**: Uses `cat` over SSH to transfer file (no SFTP needed)
   - **Collect Individual Logs**: Downloads individual files from `/var/log/` using `cat`
   - **Cleanup**: Removes remote support bundle file
6. **Summary**: Generates collection summary JSON

## File Transfer Method

The tool uses SSH command execution (`cat`) to transfer files instead of SFTP:

```bash
# Get file size
stat -c %s "/tmp/support-bundle.tar.gz"

# Transfer file content
cat "/tmp/support-bundle.tar.gz"
```

This approach:
- **More Reliable**: Works on all UniFi APs with SSH enabled
- **No SFTP Required**: SFTP subsystem not needed (often disabled)
- **Simpler**: Just needs SSH access, no additional protocols
- **Robust**: Direct file content transfer via stdout

## Log Collection Process

The tool uses two methods to collect logs from each AP:

### 1. Support Bundle Generation (Preferred)

The tool tries multiple methods to generate comprehensive diagnostic information, in this order:

#### Method 0: supp (Official UniFi Support Bundle - MOST COMPREHENSIVE)
```bash
supp
```
- **THE official UniFi support bundle generator**
- **Most comprehensive** diagnostic collection available
- Takes 30-60 seconds (shows progress during collection)
- Always outputs to `/tmp/support.tgz` (typically 500KB-1MB)
- Collects:
  - base, board, pids, pcaps, ubus, system, config, logs
  - mtd, network, lldp, ethernet, wireless, mcad
- **Automatically censors sensitive information** (passwords, keys, PSKs)
- This is what Ubiquiti support requests when troubleshooting
- **Use this if available** - it's the gold standard

#### Method 0A: syswrapper.sh get-support (Newer firmware alternative)
```bash
syswrapper.sh get-support
```
- Generates `/tmp/support-*.tar.gz`
- Comprehensive diagnostic bundle for newer firmware
- Takes 10-120 seconds

#### Method 0B: ubnt-systool support (Older firmware alternative)
```bash
ubnt-systool support
```
- Generates `/tmp/support-*.tar.gz`  
- Comprehensive diagnostic bundle for older firmware
- Takes 10-120 seconds

#### Method 0C: info support / get-info / support-info
```bash
info support    # or
get-info        # or
support-info
```
- Alternative diagnostic commands
- Takes 10-120 seconds
- May create `/tmp/support-*.tar*` or `/tmp/info-*.tar*` files

#### Method 1: mca-dump (UniFi OS comprehensive diagnostic)
```bash
mca-dump
```
- **Most comprehensive** diagnostic collection
- Takes 10-120 seconds depending on AP
- **Outputs JSON directly to stdout** (not a file)
- Contains: active channels, wireless stats, client info, system status, network config, and more
- The script captures this JSON output and saves it as `mca-dump-YYYYMMDD-HHMMSS.json`
- **This is complementary data** - the script continues to collect tar-based bundles after saving mca-dump output

#### Method 2: get-support (Standalone support command)
```bash
get-support
```
- Dedicated support bundle generation command
- Takes 10-60 seconds
- Generates comprehensive diagnostic bundle
- **Detection**: Parses command output, or searches for recent files matching `/tmp/support*.tar*` or `/tmp/info*.tar*` created in last 5 minutes

#### Method 3: mca-cli-op info (UniFi OS devices)
```bash
mca-cli-op info > /tmp/mca-info.txt
tar czf /tmp/ap-mca-*.tar.gz /tmp/mca-info.txt /var/log
```
- Used on newer UniFi OS-based devices
- Generates comprehensive system info
- Packages with all logs

#### Method 4: info command (Common on all UniFi APs)
```bash
info > /tmp/info.txt
tar czf /tmp/ap-info-*.tar.gz /tmp/info.txt /var/log
```
- Standard UniFi AP command
- Shows detailed AP information
- Packages with /var/log contents

#### Method 5: syswrapper.sh get-support (Newer firmware)
```bash
syswrapper.sh get-support
```
- Generates `/tmp/support-*.tar.gz`
- Comprehensive diagnostic bundle

#### Method 6: ubnt-systool support (Older firmware)
```bash
ubnt-systool support
```
- Generates `/tmp/info-*.tar`
- Older diagnostic method

#### Method 7: Manual log archive (Fallback)
```bash
tar czf /tmp/ap-logs-*.tar.gz /var/log
```
- Used if no diagnostic commands available
- Simple archive of all logs

The tool automatically detects which commands are available on each AP and tries them in order until one succeeds.

**Note**: 
- The tool first checks which diagnostic commands are available on each AP
- It shows "Available commands: info, syswrapper.sh, ..." for each AP
- Support bundle generation takes 10-120 seconds per AP depending on:
  - AP model and firmware version
  - Amount of log data
  - Current AP load
  - Which diagnostic method succeeds

### 2. Individual Log File Collection (Fallback)

If support bundle generation fails or isn't available, the tool collects individual files:

```bash
find /var/log -type f \( -name "*.log" -o -name "messages" -o -name "syslog" \) 2>/dev/null
```

This captures standard log files like:
- `/var/log/messages` - System messages
- `/var/log/syslog` - System log
- `/var/log/*.log` - Various application logs

## SSH Credentials

The tool retrieves SSH credentials from the controller's management settings:

1. First tries `/api/s/{site}/get/setting/mgmt` (preferred)
2. Falls back to `/api/s/{site}/stat/sysinfo`
3. Uses default username "ubnt" if not found
4. Prompts for password if not found in controller

You can override with `--ssh-username` and `--ssh-password`.

## Error Handling

The tool has strict error checking and fails fast per-AP:

- **Connection timeouts**: Aborts that AP, continues to next
- **Authentication failures**: Aborts that AP immediately, continues to next
- **Command execution failures**: Aborts that AP, continues to next
- **SFTP connection failures**: Aborts that AP, continues to next
- **Missing log files**: Reports warning but continues if support bundle succeeded
- **Offline APs**: Can skip entirely with `--online-only`
- **No IP address**: Skips AP automatically

**Important**: If SSH connection or authentication fails for an AP, collection for that AP is aborted immediately. The tool then continues to the next AP. This ensures you don't waste time on unreachable APs.

Failed APs are listed in the summary at the end with specific error messages.

## Performance

- **Sequential**: Collects from one AP at a time (current implementation)
- **Time per AP**: 
  - Support bundle generation: 10-120 seconds (varies by AP model/firmware)
  - File download: 1-5 seconds (depends on bundle size)
  - Total per AP: ~15-125 seconds
- **Large deployments**: For 10 APs, expect 3-20 minutes total
- **Future**: `--parallel N` option planned for concurrent collection

**Why so long?** The support bundle generation (`syswrapper.sh get-support`) is a comprehensive process that:
- Collects all system logs
- Generates system statistics
- Captures configuration snapshots
- Packages everything into a tar archive

This is the same process UniFi support uses for troubleshooting.

## Examples

### Collect All Logs

```bash
# Simple collection from all APs
./unifi_collect_ap_logs.py
```

### Collect from Office APs Only

```bash
# Filter by name pattern
./unifi_collect_ap_logs.py --filter-name "Office" --output /tmp/office-ap-logs
```

### Collect from Online APs with Custom Timeout

```bash
# Good for large deployments with slow APs
./unifi_collect_ap_logs.py --online-only --timeout 60
```

### Troubleshooting Specific AP

```bash
# Collect from one AP by name
./unifi_collect_ap_logs.py --filter-name "AP-Kitchen"

# Or by IP
./unifi_collect_ap_logs.py --filter-ip "192.168.1.10"
```

### Scheduled Collection

```bash
# Cron job to collect daily
0 2 * * * /path/to/unifi_collect_ap_logs.py --output /var/log/unifi-ap-logs/$(date +\%Y-\%m-\%d)
```

## Exit Codes

- **0**: All APs collected successfully
- **1**: One or more APs failed (but some succeeded)
- **130**: Interrupted by user (Ctrl+C)

## Troubleshooting

### Certificate Verification Errors

```bash
# Trust the controller certificate first
./unifi_collect_ap_logs.py trust --server
```

### SSH Authentication Failures

```bash
# Verify credentials work manually
ssh ubnt@<ap-ip>

# Or provide credentials explicitly
./unifi_collect_ap_logs.py --ssh-username admin --ssh-password yourpassword
```

### No SSH Credentials Found

If the controller doesn't return SSH credentials:

1. Verify SSH credentials are set in controller: Settings → System → Advanced → Device Authentication
2. Provide credentials manually: `--ssh-username ubnt --ssh-password`

### "No Log Files Found" or Empty Directories

If directories are empty or you see "No log files collected":

1. **Check SSH credentials**:
   ```bash
   # Test manually
   ssh ubnt@<ap-ip>
   
   # Verify credentials in controller
   # Settings → System → Advanced → Device Authentication
   ```

2. **Check support bundle generation**:
   ```bash
   # SSH to AP and run manually
   ssh ubnt@<ap-ip>
   syswrapper.sh get-support
   # Should generate /tmp/support-*.tar.gz
   
   # Or try older method
   ubnt-systool support
   ```

3. **Check file permissions**:
   ```bash
   # SSH to AP
   ls -la /var/log/
   # Logs should be readable
   ```

4. **Check AP firmware version**:
   - Older firmware may use different commands
   - Consider updating AP firmware via controller

5. **Look for errors in output**:
   - The tool shows detailed progress for each AP
   - Error messages indicate exactly what failed
   - Check "collection_summary.json" for failure details

### Connection Timeouts

```bash
# Increase timeout for slow connections
./unifi_collect_ap_logs.py --timeout 60
```

### "No Log Files Found"

Some APs may not have standard log files. This is usually due to:
- Log rotation has cleared old logs
- Custom firmware
- Different UniFi OS version

## Security Considerations

- SSH passwords are retrieved securely from controller
- Passwords are not logged or displayed
- SSH connections use paramiko's security features
- Host key verification uses AutoAddPolicy (trusts on first connect)

## Integration

### With unifi_climgr.py

```bash
# First identify problematic APs
./unifi_climgr.py list --aps --filter-offline

# Then collect their logs
./unifi_collect_ap_logs.py --filter-name "problematic-ap"
```

### With Monitoring Systems

```bash
# Collect logs when alert triggers
./unifi_collect_ap_logs.py --filter-name "$AP_NAME" --output "/var/log/incidents/$TICKET_ID"
```

## Future Enhancements

- Parallel collection with `--parallel N`
- Log analysis and parsing
- Automatic incident detection
- Integration with logging systems (syslog, elasticsearch)
- Support for filtering by model or firmware version

## See Also

- `unifi_climgr.py` - Main UniFi client management tool
- `pfsense2unifi.py` - Synchronize pfSense DHCP to UniFi clients
- UniFi API documentation

## License

GPL-3.0-or-later

## Author

netcon-sync contributors
