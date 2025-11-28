# pfsense2unifi - DHCP Synchronization Tool

Synchronize DHCP static mappings from pfSense to UniFi controller.

## Overview

This tool automates the export of client lists from pfSense to UniFi. It reads DHCP static mappings from your pfSense DHCP table (MAC, IPv4 reservation, hostname, and description), filters by description suffix, and synchronizes them to your UniFi controller as known clients.

## How It Works

### Phase 1: Configuration & Certificate Setup
- Loads UniFi and pfSense credentials from environment
- Initializes NSS database for secure HTTPS connections
- Transparently verifies server certificates using NSS/NSPR

### Phase 2: Fetch & Filter
1. Authenticates with pfSense API
2. Retrieves DHCP static mappings
3. Filters by description suffix (configurable, default: ` - Wifi`)
4. Validates MAC address format

### Phase 3: Sync to UniFi
1. For each filtered client:
   - Sets the MAC address
   - Sets UniFi client name to pfSense description (suffix removed)
   - Sets UniFi client note to pfSense hostname
   - Creates new client or updates existing
2. Retries failures with exponential backoff
3. Batch-verifies all clients were created or updated

### Phase 4: Orphan Management (Optional)
1. Identifies UniFi clients not in pfSense sync
2. Reports found orphans
3. Optionally deletes orphaned clients
4. Tracks success/failures

## Configuration

Please see the READMe.md Configuration section .

## Flags & Options

### Sync Command Flags

#### `--suffix SUFFIX`
- **Default:** `" - Wifi"`
- **Description:** Filter clients by description suffix. Only pfSense clients whose description ends with this suffix will be synced to UniFi.
- **Special Value:** Use `--suffix NONE` to sync all clients without filtering by suffix.
- **Example:** `--suffix "@unifi"` syncs only clients ending in "@unifi"
- **Example:** `--suffix NONE` syncs all DHCP clients

#### `--delete-orphans`
- **Default:** Not set (merge mode)
- **Description:** Delete UniFi clients not found in pfSense. Without this flag, the sync performs a merge: adds new clients, updates existing ones, leaves others alone. With this flag, also removes clients from UniFi that don't exist in pfSense.
- **Example:** `--delete-orphans`

## Usage

### Basic Sync (Merge Mode)

Adds new clients and updates existing ones. Does not delete any existing Unifi clients.

```bash
./pfsense2unifi.py sync
```

### Custom Filtering

By default, only clients with pfSense descriptions ending in ` - Wifi` are synced:

```bash
./pfsense2unifi.py sync --suffix " - Wired"
./pfsense2unifi.py sync --suffix "@unifi"
./pfsense2unifi.py sync --suffix " - Home"
```

### Sync All Clients (No Filtering)

To migrate every DHCP client without filtering by suffix:

```bash
./pfsense2unifi.py sync --suffix NONE
```

This is useful when migrating all clients from pfSense to UniFi, regardless of their description.

### Delete Orphaned Clients

**Flag:** `--delete-orphans`

Remove clients from UniFi that weren't present in the pfSense DHCP table. By default, the sync performs a merge operation (adds new clients, updates existing ones, leaves others alone). Use this flag to also delete orphaned clients:

```bash
./pfsense2unifi.py sync --delete-orphans
```

Combined with custom filtering:

```bash
./pfsense2unifi.py sync --suffix "@unifi" --delete-orphans
```

### Help & Options

```bash
./pfsense2unifi.py --help          # Main help (lists subcommands)
./pfsense2unifi.py sync --help     # Sync subcommand options (includes --delete-orphans)
./pfsense2unifi.py trust --help    # Certificate options
```

## MAC Address Format

All MAC addresses in pfSense must use colon delimiters :

✓ Valid: `AA:BB:CC:DD:EE:FF`, `aa:bb:cc:dd:ee:ff`  
✗ Invalid: `AABBCCDDEEFF`, `AA-BB-CC-DD-EE-FF`, `AA.BB.CC.DD.EE.FF`

## Example Output

### Configuration Error
```
❌ Configuration Error: Missing required UniFi environment variables: UNIFI_NETWORK_URL, UNIFI_USERNAME, UNIFI_PASSWORD
usage: pfsense2unifi.py [-h] {sync,trust} ...

Sync DHCP reservations from pfSense to UniFi controller
...
```

### Successful Sync
```
Fetching DHCP static mappings from pfSense...
Found 12 static mappings in pfSense.

Attempting to log into UniFi Controller...
UniFi login successful.

Pre-fetching all UniFi clients...
Found 8 existing clients in UniFi.

Processing 12 pfSense DHCP mappings...
  [1/12] ✓ aa:bb:cc:dd:ee:01: MyLaptop
  [2/12] ✓ aa:bb:cc:dd:ee:02: MyPhone
  ...

Verifying clients in UniFi (batch check)...
✓ Verified 10/10 clients in UniFi

======================================================================
SYNC SUMMARY
======================================================================
Total pfSense clients retrieved: 12
  - Clients with invalid MAC format: 0
  - Clients filtered out (not ending in ' - Wifi'): 2
  - Clients successfully created in UniFi: 8
  - Clients successfully updated in UniFi (fields changed): 0
  - Clients failed to add/update: 0
======================================================================
```

## Troubleshooting

### Configuration Error on Startup

Make sure all required environment variables are set:
```bash
echo $UNIFI_NETWORK_URL $UNIFI_USERNAME $UNIFI_PASSWORD $PFSENSE_URL $PFSENSE_APIV2_KEY
```

### Certificate Errors

If you get certificate validation errors:

**Option 1: Trust the CA (recommended)**
```bash
./pfsense2unifi.py trust --ca /path/to/ca.pem
```

Expected formats: `[ca_cert.pem|ca_cert.der]` - or the server certificate is self-signed or self-issued

**Option 2: Trust the server directly**
```bash
./pfsense2unifi.py trust --server https://pfsense.example.com
```

### No Clients Synced

- Verify pfSense DHCP descriptions end with the configured suffix (default: ` - Wifi`)
- Check MAC addresses use colon delimiters (`AA:BB:CC:DD:EE:FF`)
- Verify credentials have API access
- Check pfSense API key is valid and has correct permissions

### Connection Issues

- Verify both UniFi and pfSense URLs are reachable
- Check firewall rules allow access to UniFi (8443) and pfSense (443) ports
- Ensure network connectivity before running sync

## Known Limitations

- Exports only in one direction, from pfSense to Unifi, not the other way around
- IP addresses from pfSense DHCP reservations are currently not exported to Unifi. This is because the test environment doesn't have a router, and these reservations don't apply. The feature could be easily added for someone migrating from pfSense to Unifi, rather than co-existing like mine. This feature was not added due to being unable to test it.
- Tested only with pfSense+ 25.07.1, pfSense APIv2, and Unifi Network 9.5.21 GA
- Not tested with Unifi OS. No API token support as a result.
- Opnsense not supported

## For More Information

- See [README.md](README.md) for general setup and prerequisites
- See [unifi_climgr.md](unifi_climgr.md) for UniFi client and AP management
