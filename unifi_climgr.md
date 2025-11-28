# unifi_climgr - UniFi Client & AP Management Tool

Command-line interface for comprehensive UniFi network management operations.

## Overview

UniFi Network application is GUI-based and not suited for batch operations. This CLI tool provides advanced management capabilities for UniFi clients and access points, including:

- Batch client disconnect/kick operations
- AP mesh topology visualization
- AP restart sequencing in proper mesh order
- Mesh recovery after power outages
- Client connectivity improvements via forced roaming
- Client locking and unlocking to/from specific APs
- Block/unblock clients from your network

### Use Cases

**Mesh Recovery & Optimization**
- Recover mesh APs after power outages by kicking client connections
- Forces clients to reconnect, improving roaming to nearest AP
- Solves issues where mesh APs can't come up when overwhelmed with clients

**Large-Scale Management**
- Manage 100+ connected clients with single commands
- Batch restart APs in correct hierarchy order
- Automate repetitive management tasks

---

## Quick Start

**Reminder**: Always backup your UniFi configuration before making changes! The tool will remind you before any modification command.

```bash
./unifi_climgr.py --help          # Show main help
./unifi_climgr.py COMMAND --help  # Show help for specific command
```

---

## Configuration

### Required Environment Variables

```bash
# UniFi Controller
export UNIFI_NETWORK_URL="https://192.168.1.100:8443"
export UNIFI_USERNAME="email@domain.com"
export UNIFI_PASSWORD="your_password"
```

### Optional Environment Variables

```bash
export UNIFI_SITE_ID="default"              # UniFi site ID (default: "default")
```

---

## List Command

The `list` command shows information about clients, access points, or SSIDs in your UniFi network.

### Basic Syntax

```bash
./unifi_climgr.py list --clients      # List all connected clients
./unifi_climgr.py list --aps          # List all access points
./unifi_climgr.py list --ssids        # List all wireless networks
```

### List Clients

**Purpose**: Show all wireless devices currently connected (or known) to your UniFi network.

```bash
./unifi_climgr.py list --clients
```

**What you see**: A table with one row per device showing MAC address, hostname, connection status, signal strength, and other details.

**Useful for**: Seeing what devices are connected, checking their signal strength, finding devices with poor connectivity.

#### Client Filters

Use these options to show only specific clients:

**Online/Offline Status:**
```bash
./unifi_climgr.py list --clients --filter_online       # Only show devices currently connected
./unifi_climgr.py list --clients --filter_offline       # Only show devices NOT currently connected
```
*Use when:* You want to troubleshoot why a device isn't showing up, or see all devices even if they're not currently connected.

**Lock Status:**
```bash
./unifi_climgr.py list --clients --filter_locked        # Show only clients LOCKED to a specific AP
./unifi_climgr.py list --clients --filter_unlocked      # Show only clients NOT locked to any AP
```
*Use when:* You're managing device roaming - locked devices won't switch to a different AP even if signal is better.

**Signal Strength:**
```bash
./unifi_climgr.py list --clients --filter_signal_above -60    # Only show devices with STRONGER signal than -60 dBm
./unifi_climgr.py list --clients --filter_signal_below -30    # Only show devices with WEAKER signal than -30 dBm
```
*Use when:* You want to find devices with poor signal quality. Signal values are negative - closer to 0 is stronger. For example, `-30 dBm` is good, `-80 dBm` is poor.

**IP Address:**
```bash
./unifi_climgr.py list --clients --filter_ip 192.168.1.50
```
*Use when:* You want to look up a specific device by its IP address. This is an EXACT match.

**MAC Address:**
```bash
./unifi_climgr.py list --clients --filter_mac aa:bb:cc
```
*Use when:* You want to search for devices by MAC address. This is a SUBSTRING match - `aa:bb:cc` will match any device with those characters in the MAC address.

**DNS Name:**
```bash
./unifi_climgr.py list --clients --filter_dns_name router.local
```
*Use when:* Your device has a registered DNS name. This is an EXACT match.

**Hostname:**
```bash
./unifi_climgr.py list --clients --filter_hostname my-laptop
```
*Use when:* You want to filter by the device's hostname. This is an EXACT match.

#### Combining Filters

You can combine filters to narrow down your search:

```bash
# Find all OFFLINE devices with poor signal
./unifi_climgr.py list --clients --filter_offline --filter_signal_below -60

# Find all ONLINE devices locked to an AP with strong signal
./unifi_climgr.py list --clients --filter_online --filter_locked --filter_signal_above -50

# Find a specific device by partial MAC and online status
./unifi_climgr.py list --clients --filter_mac aa:bb --filter_online
```

### List Access Points (APs)

**Purpose**: Show all your UniFi WiFi access points with details about their connection status and mesh relationships.

```bash
./unifi_climgr.py list --aps
```

**What you see**: 
- A table showing each AP's name, MAC address, IP, firmware version, uptime, and connection type
- An ASCII tree diagram showing how your mesh network is structured
  - Wired APs (connected via Ethernet) are shown as roots
  - Mesh APs (connected via WiFi) are shown as children with their parent AP

**Useful for**: Understanding your mesh topology, checking if all APs are online, seeing firmware versions.

#### AP Filters

**Online/Offline:**
```bash
./unifi_climgr.py list --aps --filter_online        # Only show APs that are reachable
./unifi_climgr.py list --aps --filter_offline       # Only show APs that are NOT reachable
```
*Use when:* You suspect an AP is down and want to verify.

**IP Address:**
```bash
./unifi_climgr.py list --aps --filter_ip 192.168.1.100
```
*Use when:* You want to find APs on a specific subnet. This is a SUBSTRING match.

**MAC Address:**
```bash
./unifi_climgr.py list --aps --filter_mac aa:bb:cc
```
*Use when:* You want to look up an AP by its MAC address. This is a SUBSTRING match.

**Name (Substring Match):**
```bash
./unifi_climgr.py list --aps --filter_name "bedroom"
```
*Use when:* You want to find all APs with "bedroom" in their name. Case-insensitive, substring match.

### List SSIDs (Wireless Networks)

**Purpose**: Show all your wireless networks (SSIDs) with their security settings and frequency bands.

```bash
./unifi_climgr.py list --ssids
```

**What you see**: A table showing each network's name, whether it's enabled, security type (Open, WPA2, WPA3, etc.), and which frequency bands it broadcasts on (2.4GHz, 5GHz, 6GHz).

**Useful for**: Seeing your WiFi network configuration, checking which networks are active.

#### SSID Filters

**Name (Substring Match):**
```bash
./unifi_climgr.py list --ssids --filter_name "guest"
```
*Use when:* You have many SSIDs and want to find ones matching a pattern. Case-insensitive, substring match.

---

## Client Management Commands

These commands modify individual clients in your network.

### Lock Client to AP

**Purpose**: Force a client to only connect to one specific access point. The device will not roam to other APs even if signal is better elsewhere.

```bash
# Lock to a specific AP by MAC address
./unifi_climgr.py lock_client --ap_mac aa:bb:cc:dd:ee:ff

# Lock to a specific AP by name
./unifi_climgr.py lock_client --ap_name "Living Room AP"

# Lock each client to its currently connected AP (useful for sticky devices)
./unifi_climgr.py lock_client --connected_ap
```

**Use when**: 
- You want to prevent a device from roaming around your mesh network
- You have a device that keeps jumping between APs
- You want to ensure a device stays on a specific AP for testing

**Combining with Filters**: By default, locks ALL clients. Use filters to be selective:

```bash
# Lock only ONLINE devices with weak signal to a specific AP
./unifi_climgr.py lock_client --ap_name "Basement AP" --filter_online --filter_signal_below -60

# Lock only devices that are currently UNLOCKED
./unifi_climgr.py lock_client --ap_mac aa:bb:cc:dd:ee:ff --filter_unlocked
```

### Unlock Client

**Purpose**: Remove any AP lock on a client. The device can now freely roam between all access points based on signal strength.

```bash
./unifi_climgr.py unlock_client
```

**Use when**: You previously locked a client and now want it to roam freely again.

**Combining with Filters**: By default, unlocks ALL clients. Use filters to target specific devices:

```bash
# Unlock only locked clients
./unifi_climgr.py unlock_client --filter_locked

# Unlock only offline clients
./unifi_climgr.py unlock_client --filter_offline

# Unlock only clients with a specific MAC
./unifi_climgr.py unlock_client --filter_mac aa:bb:cc
```

### Reconnect Client

**Purpose**: Force a client to disconnect and reconnect to the network. Useful when a client isn't performing well or needs a fresh connection.

```bash
./unifi_climgr.py reconnect_client
```

**What happens**: The UniFi controller sends a disconnect command to the client, forcing it to log off and log back on. Usually takes 5-10 seconds.

**Use when**:
- A client has poor connectivity and needs a "kick"
- You want to force a client to reassociate and possibly roam to a better AP
- You're troubleshooting network connectivity issues

**Combining with Filters**: By default, reconnects ALL clients. Use filters to target specific devices:

```bash
# Reconnect only ONLINE clients with weak signal (good for fixing poor connectivity)
./unifi_climgr.py reconnect_client --filter_online --filter_signal_below -70

# Reconnect only devices on a specific AP
./unifi_climgr.py reconnect_client --filter_mac aa:bb:cc
```

### Block Client

**Purpose**: Prevent a client from connecting to your network by its MAC address. The device will be blocked at the network level.

```bash
./unifi_climgr.py block_client
```

**Use when**:
- You want to isolate a device for testing (e.g., "does this brand of device cause issues?")
- You're troubleshooting network problems and need to eliminate a device
- You want to temporarily prevent a device from connecting

**Combining with Filters**: By default, blocks ALL clients. Use filters to target specific devices:

```bash
# Block only a specific device by MAC
./unifi_climgr.py block_client --filter_mac aa:bb:cc:dd:ee:ff

# Block all devices with poor signal
./unifi_climgr.py block_client --filter_signal_below -80
```

### Unblock Client

**Purpose**: Remove a block on a client. The device can now connect again.

```bash
./unifi_climgr.py unblock_client
```

**Combining with Filters**: By default, unblocks ALL clients. Use filters if needed:

```bash
# Unblock a specific device by MAC
./unifi_climgr.py unblock_client --filter_mac aa:bb:cc:dd:ee:ff

# Unblock a device by hostname
./unifi_climgr.py unblock_client --filter_hostname "test-device"
```

### Forget Client

**Purpose**: Completely remove a client from your UniFi controller. The device is deleted and all its history is erased.

```bash
./unifi_climgr.py forget --clients
```

**Important**: This is a DESTRUCTIVE operation. The client will be completely forgotten by UniFi.

**Use when**:
- You permanently removed a device from your network
- You want to clean up old devices no longer in use
- You're starting fresh with a device (forget it, then add it again)

**Combining with Filters**: By default, forgets ALL clients. Use filters to target specific devices:

```bash
# Forget only OFFLINE clients (devices that haven't been seen in a while)
./unifi_climgr.py forget --clients --filter_offline

# Forget clients matching a specific MAC pattern
./unifi_climgr.py forget --clients --filter_mac aa:bb:cc

# Forget devices with a specific hostname
./unifi_climgr.py forget --clients --filter_hostname "old-device"
```

### Add Client

**Purpose**: Manually create a new client entry or update an existing one in your UniFi controller.

```bash
./unifi_climgr.py add_client aa:bb:cc:dd:ee:ff

# Add with a friendly name
./unifi_climgr.py add_client aa:bb:cc:dd:ee:ff --name "My Smart Light"

# Add with both name and description
./unifi_climgr.py add_client aa:bb:cc:dd:ee:ff --name "Garage Door" --note "Controls garage entrance"
```

**Use when**:
- You want to pre-create a client entry before the device joins the network
- You want to add a friendly name and description to a device
- You're setting up a new device and want to organize it

---

## Access Point Commands

These commands manage your wireless access points.

### Restart AP

**Purpose**: Reboot one or more access points. This is useful for troubleshooting connectivity issues or applying configuration changes.

```bash
# Restart a specific AP by MAC address
./unifi_climgr.py restart_ap --ap_mac aa:bb:cc:dd:ee:ff

# Restart a specific AP by name
./unifi_climgr.py restart_ap --ap_name "Living Room AP"

# Restart ALL APs (WARNING: disrupts all WiFi connections!)
./unifi_climgr.py restart_ap
```

**Important for Mesh Networks**: When you restart all APs without specifying a particular one, the tool automatically restarts them in **mesh order** to minimize disruption:
1. Leaf APs (furthest from root) restart first
2. After 5 seconds, the next layer restarts
3. This continues until root (wired) APs restart last

This prevents mesh APs from losing their uplink connection prematurely.

**Use when**:
- An AP is misbehaving or has poor connectivity
- You need to apply firmware updates or configuration changes
- You're troubleshooting network issues
- After a power outage, to restore mesh connectivity in the proper order

**Mesh Restart Details**:
- For mesh APs: Restarts happen layer by layer from leaf to root, with 5-second delays between layers
- For wired APs: Restart immediately (they have no uplink to lose)
- For mixed networks: This ordering ensures mesh APs don't lose their parent AP mid-restart

---

## SSID Management Commands

These commands enable/disable your wireless networks.

### Enable SSID

**Purpose**: Turn on a wireless network so devices can see and connect to it.

```bash
# Enable a specific SSID
./unifi_climgr.py enable --ssids "My WiFi Network"

# Enable multiple SSIDs matching a pattern (substring match)
./unifi_climgr.py enable --ssids --filter_name "guest"

# Enable ALL SSIDs
./unifi_climgr.py enable --ssids
```

**Use when**:
- You temporarily disabled a network and want to re-enable it
- You're testing network availability
- You're bringing up a new network configuration

### Disable SSID

**Purpose**: Turn off a wireless network so devices cannot see or connect to it.

```bash
# Disable a specific SSID
./unifi_climgr.py disable --ssids "Guest Network"

# Disable multiple SSIDs matching a pattern (substring match)
./unifi_climgr.py disable --ssids --filter_name "test"

# Disable ALL SSIDs (WARNING: all WiFi becomes unavailable!)
./unifi_climgr.py disable --ssids
```

**Use when**:
- You want to temporarily disable a guest network
- You're testing or maintaining your network
- You want to force all devices off a specific network

---

## Column Display Guide

For `list` commands, you can customize which columns appear in the output.

### Syntax

```bash
# Show ONLY specific columns
./unifi_climgr.py list --clients +mac +hostname +status

# Hide specific columns (show all others)
./unifi_climgr.py list --clients -ip -dns_name -retries
```

**Rules**:
- Use `+` to INCLUDE a column (positive mode)
- Use `-` to EXCLUDE a column (negative mode)
- You cannot mix `+` and `-` in the same command
- If you use `+`, you're explicitly saying "show ONLY these columns"
- If you use `-`, you're saying "hide these columns from the default set"

### Available Columns for Clients

When using `list --clients`:

```bash
number            # Sequential numbering (1, 2, 3, etc.)
mac               # Device MAC address
hostname          # Device hostname
description       # Device description
status            # Online/Offline
ip                # IP address
dns_name          # DNS name
uptime            # How long the device has been connected
connected_ap_name # Name of the AP it's connected to
connected_ap_mac  # MAC of the AP it's connected to
channel           # Wireless channel the device is using
band              # WiFi band (2.4 GHz, 5 GHz, 6 GHz)
wifi_generation   # WiFi generation (WiFi 1, 2, 3, 4, 5, 6, 7)
ieee_version      # IEEE standard (802.11a, b, g, n, ac, ax, be)
ssid              # Network SSID the device is connected to
signal            # Signal strength in dBm
retries           # TX retry count
locked            # Yes/No - whether it's locked to an AP
locked_ap_name    # Name of the AP it's locked to
locked_ap_mac     # MAC of the AP it's locked to
last_seen         # Last time it was seen
```

**Sorting Note**: N/A values always sort to the end, regardless of column or sort direction.

**Examples**:

```bash
# Show only MAC and hostname (clean, minimal output)
./unifi_climgr.py list --clients +mac +hostname

# Show all columns except DNS name and retries
./unifi_climgr.py list --clients -dns_name -retries

# Show signal strength info only
./unifi_climgr.py list --clients +hostname +signal +connected_ap_name

# Show channel and SSID information
./unifi_climgr.py list --clients +hostname +channel +ssid +signal

# Show WiFi generation and IEEE version
./unifi_climgr.py list --clients +hostname +band +wifi_generation +ieee_version

# Show all wireless info
./unifi_climgr.py list --clients +hostname +channel +band +wifi_generation +ieee_version +ssid +signal
```

### Available Columns for APs

When using `list --aps`:

```bash
name              # AP device name
mac               # AP MAC address
ip                # AP IP address
version           # Firmware version
uptime            # How long the AP has been running
connection        # wired/mesh(N-hops)
enabled           # Yes/No
uplink_ap_name    # For mesh APs: name of parent AP
uplink_ap_mac     # For mesh APs: MAC of parent AP
```

### Available Columns for SSIDs

When using `list --ssids`:

```bash
name              # SSID name
enabled           # Yes/No
security          # Open, WPA, WPA2, WPA3, WPA2/WPA3
band              # 2.4GHz, 5GHz, 6GHz, or combinations
```

---

## Filtering Guide

This section summarizes all available filters and when to use them.

### Filter Types

**Status Filters** (mutually exclusive - pick ONE):
- `--filter_online` - Currently connected to network
- `--filter_offline` - NOT currently connected

**Lock Filters** (clients only, mutually exclusive):
- `--filter_locked` - Locked to a specific AP
- `--filter_unlocked` - NOT locked to any AP

**Value Filters** (exact or substring match):
- `--filter_ip <IP>` - Exact IP address match (clients: exact, APs: substring)
- `--filter_mac <MAC>` - Substring match on MAC address
- `--filter_dns_name <DNS>` - Exact DNS name match (clients only)
- `--filter_hostname <NAME>` - Exact hostname match (clients only)
- `--filter_name <NAME>` - Substring match on name (SSIDs: yes, APs: yes)

**Signal Filters** (clients only):
- `--filter_signal_above <dBm>` - Signal strength GREATER than value (e.g., -60)
- `--filter_signal_below <dBm>` - Signal strength LESS than value (e.g., -30)

**Remember**: Signal values are negative. `-30 dBm` is STRONG, `-80 dBm` is WEAK.

### Common Filter Combinations

**Network Troubleshooting:**
```bash
# Find devices with poor connectivity
./unifi_climgr.py list --clients --filter_online --filter_signal_below -70

# Find devices that haven't been seen recently
./unifi_climgr.py list --clients --filter_offline

# Find devices on a specific AP
./unifi_climgr.py list --clients --filter_mac "aa:bb:cc:dd:ee:ff"
```

**Mesh Network Management:**
```bash
# See which APs are online
./unifi_climgr.py list --aps --filter_online

# Find AP with specific name pattern
./unifi_climgr.py list --aps --filter_name "bedroom"

# Check which APs are on wired or mesh uplink
./unifi_climgr.py list --aps
```

**Device Management:**
```bash
# Reconnect only problematic devices
./unifi_climgr.py reconnect_client --filter_online --filter_signal_below -60

# Lock weak-signal devices to nearest AP
./unifi_climgr.py lock_client --connected_ap --filter_signal_below -70

# Forget old devices
./unifi_climgr.py forget --clients --filter_offline
```

---

## Certificate Management

Before using any commands, you may need to trust your UniFi controller's certificate if it uses self-signed or custom CA certificates.

```bash
# Trust the UniFi controller
./unifi_climgr.py trust https://192.168.1.100:8443

# Trust via CA certificate
./unifi_climgr.py trust --ca /path/to/ca_cert.pem
```

See [README.md](README.md) for detailed certificate setup instructions.

---

## Quick Reference

### Most Common Commands

```bash
# See all devices
./unifi_climgr.py list --clients

# See all APs and mesh topology
./unifi_climgr.py list --aps

# Fix poor connectivity
./unifi_climgr.py reconnect_client --filter_signal_below -70

# Force all clients to reconnect (mesh recovery)
./unifi_climgr.py reconnect_client

# Lock a device to its current AP
./unifi_climgr.py lock_client --connected_ap

# Restart all APs in mesh order
./unifi_climgr.py restart_ap
```

---

## Troubleshooting

### Configuration Error on Startup

Make sure all required environment variables are set:
```bash
echo $UNIFI_NETWORK_URL $UNIFI_USERNAME $UNIFI_PASSWORD
```

### Certificate Errors

If you get certificate validation errors:

**Option 1: Trust the server directly**
```bash
./unifi_climgr.py trust --server https://192.168.1.100:8443
```

**Option 2: Trust a CA certificate**
```bash
./unifi_climgr.py trust --ca /path/to/ca.pem
```

### Connection Issues

- Verify UniFi URL is reachable
- Check firewall rules allow access to UniFi (8443) port
- Ensure network connectivity before running operations
- Verify credentials are correct for your UniFi account

### No Output After Command

- Ensure you're running from the netcon-sync directory
- Check environment variables are exported (not just set)
- Verify Python venv is activated if using one

---

## Known Limitations

- Only U6-LR and NanoHD Unifi APs have been tested. Other Unifi APs, switches and gateways have not been tested, because the author doesn't currently own any.
- Tested only with Unifi Network 9.5.21 GA
- Not tested with Unifi OS. No API token support as a result.
- No UniFi gateway or mesh router management (AP-only currently)

## Future Plans

- Test scripts. The main reason they aren't available yet is because the CLI interface is too new to be considered stable.
- Sample real-world scripts I use.
- Support for automatic firmware updates of Unifi APs in proper mesh order, since Ubiquiti can't figure this out in their own GUI
- Support for additional Unifi device types
- Expanded filtering and selection options

---

## For More Information

- See [README.md](README.md) for general setup and prerequisites
- See [pfsense2unifi.md](pfsense2unifi.md) for DHCP synchronization tool documentation
