# netcon-sync - Network Configuration Synchronization tool
Author : Julien Pierre, with the help of Code Rhapsody

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A comprehensive Python utility suite for synchronizing network configuration.
Currently supports pfSense router, and UniFi controllers. Includes DHCP reservation sync, certificate management, and network client administration.

## Background

I maintain a very large smart home network, with hundreds of IOT devices. I use pfSense as a router rather than a Unifi gateway, and Ubiquiti Unifi access points, as many others do.
The main reason I use pfSense is that my router is in my home office, and I need a 100% silent fanless 10 Gbe router. Ubiquiti does not produce one. Thus, I built my own fanless PC,
with an AMD 5700G APU, X470 motherboard, NH-D15 CPU cooler, and X550-T2 dual 10 Gbe NIC. It has been my router for the last few years, and is completely silent.

Given this split between pfSense and Unifi, I chose the "source of truth" for my clients is the DHCP reservation table in pfSense, specifically the MAC, IPv4 reservation, hostname, and description.
In order to best utilize, Unifi Network (controller) appilcation, I decided to automate the export of the client lists from pfSense to Unifi.
Hence, the creation of pfsense2unifi .

Due to lack of pre-existing Ethernet wiring, and the difficulty, cost, and unsightliness that would result from addiing wiring, I currently use a mesh network, with only two wired APs, and 8 wireless mesh APs.
9 of the APs are U6-LR, and one is NanoHD (but will be replaced with U6-LR eventually). I currently have 302 Wifi clients, 95% of which are IOT 2.4 GHz 802.11n / Wifi 4 clients.

The Unifi APs I own unfortunately do not meet their advertised specs in terms of maximum number of clients. They choke around 120 clients on a single AP. At that point, no more clients can connect.
Worse, mesh APs can sometimes no longer connect either when the client limit is hit. In power outage scenarios, the mesh APs come up long after the wired AP, especially in a mesh chain with more than one hop.
The IOT devices come online much more quickly, and can easily overwhelm the two wired APs, preventing the mesh APs from coming up.
One workaround for this issue is to repeatedly "kick" out all the IOT clients from the wired APs, until all the mesh APs have come up. I wanted to automate this.
Kicking all the clients also has another use - it often forces to reconnect, often roaming to the nearest AP, and improves connectivity.
The Unifi controller unfortunately is a GUI, and not suited to kicking 300+ clients at once. This requires a CLI.
Hence, the creation of unifi_climgr.py . A vast number of functions were added, that can function in batch, unlike a GUI.

Among other things, it can restart all APs in a mesh network automatically in the right order, from AP depth with the most hops, all the way to the root wired APs, in a single invocation.
It displays the AP mesh topology properly in ASCII as well, something Ubiquiti regularly breaks in their GUI.

## Features

- 🔄 **DHCP Sync** - Exports DHCP static mappings from pfSense to UniFi as known clients
- 🔐 **NSS/NSPR TLS** - Enterprise-grade certificate handling with NSS database
- 📋 **Flexible Filtering** - Configurable client description suffix matching
- ✅ **Batch Verification** - Confirm clients were created in UniFi
- 🗑️ **Orphan Management** - Detect and optionally delete Unifi clients that are not present in pfSense
- 🔄 **Automatic Retry** - Exponential backoff for transient failures
- ✔️ **MAC Validation** - Strict format validation (colon delimiters)
- 📊 **Detailed Reporting** - Clear breakdown of success/failed/filtered clients

## Prerequisites

- Python 3.7+
- `requests` library
- `pyasn1` library (for certificate parsing)
- NSS/NSPR libraries (for secure TLS)
- NSS tools (for certificate management)

## Installation

### Quick Start

1. Clone the repository:
```bash
git clone https://github.com/madbrain76/netcon-sync.git
cd netcon-sync
```

2. Run the installer to create an isolated virtual environment:
```bash
./install_deps.sh
```

This creates a Python venv at `~/.venv-netcon-sync` with all dependencies.

3. Configure environment variables (see Configuration below)

4. Run a sync:
```bash
./pfsense2unifi.py sync
```

## Configuration

### Required Environment Variables

```bash
# UniFi Controller
export UNIFI_NETWORK_URL="https://192.168.1.100:8443"
export UNIFI_USERNAME="email@domain.com"
export UNIFI_PASSWORD="your_password"

# pfSense (for sync operations)
export PFSENSE_URL="https://192.168.1.1"
export PFSENSE_APIV2_KEY="your_api_key"
```

### Optional Environment Variables

```bash
export UNIFI_SITE_ID="default"              # UniFi site ID (default: "default")
export PFSENSE_DHCP_INTERFACE="lan"         # pfSense interface (default: "lan")
```

### Certificate Management

Trust a CA certificate:
```bash
./pfsense2unifi.py trust --ca /path/to/ca_cert.pem
```

Trust a server certificate:
```bash
./pfsense2unifi.py trust --server $UNIFI_NETWORK_URL
./unifi_climgr trust --server $PFSENSE_URL

## Usage

### Basic Sync (Merge Mode)

Adds new clients and updates existing ones. Does not delete any clients.

```bash
./pfsense2unifi.py sync
```

### Custom Filtering

By default, only clients with descriptions ending in ` - Wifi` are synced:

```bash
./pfsense2unifi.py sync --suffix " - Wired"
./pfsense2unifi.py sync --suffix "@unifi"
./pfsense2unifi.py sync --suffix " - Home"
```

### Delete Orphaned Clients

Remove clients from UniFi that weren't in the pfSense sync:

```bash
./pfsense2unifi.py sync --delete-orphans
```

## How It Works

### Phase 1: Configuration & Certificate Setup
- Loads UniFi and pfSense credentials from environment
- Initializes NSS database for secure HTTPS connections
- Transparently verifies server certificates using NSS/NSPR

### Phase 2: Fetch & Filter
1. Authenticates with pfSense API
2. Retrieves DHCP static mappings
3. Filters by description suffix (configurable)
4. Validates MAC address format

### Phase 3: Sync to UniFi
1. For each filtered client:
   - Sets UniFi client name to pfSense description (suffix removed)
   - Sets UniFi client note to pfSense hostname
   - Creates new client or updates existing
2. Retries failures with exponential backoff
3. Batch-verifies all clients were created

### Phase 4: Orphan Management (Optional)
1. Identifies UniFi clients not in pfSense sync
2. Reports found orphans
3. Optionally deletes orphaned clients
4. Tracks success/failures

## Example Output

```
❌ Configuration Error: Missing required UniFi environment variables: UNIFI_NETWORK_URL, UNIFI_USERNAME, UNIFI_PASSWORD
usage: pfsense2unifi.py [-h] {sync,trust} ...

Sync DHCP reservations from pfSense to UniFi controller
...
```

With configuration set:

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

## MAC Address Format

All MAC addresses must use colon delimiters:

✓ Valid: `AA:BB:CC:DD:EE:FF`, `aa:bb:cc:dd:ee:ff`  
✗ Invalid: `AABBCCDDEEFF`, `AA-BB-CC-DD-EE-FF`, `AA.BB.CC.DD.EE.FF`

## Certificate Handling

This tool uses NSS/NSPR for enterprise-grade certificate handling:

- Maintains an NSS certificate database at `~/.netcon-sync/`
- Supports CA-based trust (trust all certs signed by a CA)
- Supports direct server certificate trust
- Automatic certificate validation for all HTTPS connections

## Project Structure

```
.
├── pfsense2unifi.py           # Main orchestration script
├── pfsense_utils.py           # pfSense API utilities
├── unifi_utils.py             # UniFi API utilities
├── unifi_network_manager.py    # Comprehensive network management CLI
├── config.py                  # Configuration management
├── trust.py                   # Certificate handling
├── http_tls_nss.py            # NSS/NSPR HTTP client
├── install_deps.sh            # Dependency installer
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── LICENSE                    # GPL-3.0 license
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

**Option 2: Trust the server directly**
```bash
./pfsense2unifi.py trust --server https://pfsense.example.com
```

### No Clients Synced

- Verify pfSense DHCP descriptions end with the configured suffix (default: ` - Wifi`)
- Check MAC addresses use colon delimiters (`AA:BB:CC:DD:EE:FF`)
- Verify credentials have API access

### Help & Options

```bash
./pfsense2unifi.py --help          # Main help
./pfsense2unifi.py sync --help     # Sync options
./pfsense2unifi.py trust --help    # Certificate options
```

## Known limitations
- Exports only in one direction, from pfSense to Unifi, not the other way around
- IP reservations are currently not exported from pfSense to Unifi. This is because my Unifi setup doesn't have a router, and these reservations don't apply.
This could be easily added for someone migrating from pfSense to Unifi, rather than co-existing like mine
- Tested only with pfSense+ 25.07 and pfSense APIv2
- Tested only with Unifi Network 9.5.21 .
- Not tested with Unifi OS . No API token support as a result.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool directly modifies network configurations. Always:
- **⚠️ BACKUP YOUR UNIFI CONFIGURATION BEFORE ANY MIGRATION** - Use UniFi's built-in backup feature or export your configuration
- Test in a non-production environment first
- Maintain backups of your configurations
- Review changes before running in production
- Understand what `--delete-orphans` does before using it
- Only U6-LR and NanoHD Unifi APs have been tested. Other Unifi APs, switches and gateways have not been tested, because I don't currently own any. The main reason I don't own them is that most 10 Gbe Unifi devices have small fans with high RPM that are very noisy. Only 100% fanless solutions are suitable for my home.

## Support

For issues or feature requests, please open a GitHub issue.

---

**Made with ❤️ for network administrators**

