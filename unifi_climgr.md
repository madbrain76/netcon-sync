# unifi_climgr - UniFi Client & AP Management Tool

Command-line interface for comprehensive UniFi network management operations.

## Overview

UniFi Network application is GUI-based and not suited for batch operations. This CLI tool provides advanced management capabilities for UniFi clients and access points, including:

- Batch client disconnect/kick operations
- AP mesh topology visualization (ASCII art)
- AP restart sequencing in proper mesh order
- Mesh recovery after power outages
- Client connectivity improvements via forced roaming

### Use Cases

- Can force all clients to reconnect, improving roaming to nearest AP
- Selectively kick clients that have erroneously roamed to distant AP, based on poor signal (low dBm)
- Manage 100+ connected clients with single commands
- Batch restart APs in correct mesh hierarchy order
- Automate repetitive management tasks
- Selectively block/unblock devices based on MAC to isolate certain brand / device models when troubleshooting
- Works around issues where mesh APs can't come up when uplinks are overwhelmed with too many clients

## Configuration

See README.md Configuration section.

## Usage

### Help & Options

```bash
./unifi_climgr.py --help          # Main help
./unifi_climgr.py COMMAND --help  # Command-specific help
```

### Client Management

See full help :
```bash
./unifi_climgr.py --help
```

The tool displays AP mesh relationships, hop depth, and parent/child connections.

## Features

- **Batch Client Disconnect** - Kick all or filtered clients in one operation
- **AP Restart Sequencing** - Restart APs in proper mesh hierarchy order (deepest hops first)
- **Mesh Topology Display** - ASCII visualization of AP connections (something Ubiquiti regularly breaks in their GUI)
- **Selective Operations** - Filter by SSID, client type, or other criteria
- **Confirmation Prompts** - Safety confirmations before destructive operations
- **Detailed Reporting** - Clear feedback on operations performed

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

## Known Limitations

- Only U6-LR and NanoHD Unifi APs have been tested. Other Unifi APs, switches and gateways have not been tested, because the author doesn't currently own any.
- Tested only with Unifi Network 9.5.21 GA
- Not tested with Unifi OS. No API token support as a result.
- No UniFi gateway or mesh router management (AP-only currently)

## Future Plans

- Support for automatic firmware updates of Unifi APs in proper mesh order, since Ubiquiti can't figure this out in their own GUI
- Support for additional Unifi device types
- Expanded filtering and selection options

## For More Information

- See [README.md](README.md) for general setup and prerequisites
- See [pfsense2unifi.md](pfsense2unifi.md) for DHCP synchronization tool documentation
